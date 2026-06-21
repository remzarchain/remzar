#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{PeerId, identity};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::{p2p_008_broadcast::REGISTER_TOPIC_STR, p2p_011_peerbook::PeerBook},
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{
        p2p_001_sync_builders::{
            P2pSync, PendingBatchRequest, REGISTRATION_TOPIC, REMZAR_HASH_BYTES_LEN,
            RemzarHashBytes,
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
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

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
        "remzar_p2p_001_sync_builders_tests_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn test_peer_id() -> PeerId {
    let keypair = identity::Keypair::generate_ed25519();
    PeerId::from(keypair.public())
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

fn assert_initial_sync_state(sync: &P2pSync) {
    assert!(!sync.has_synced());
    assert!(sync.is_syncing());
    assert_eq!(sync.total_to_download, 0);
    assert_eq!(sync.downloaded, 0);
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
fn p2p_01_001_sync_builders_registration_topic_matches_broadcast_constant() -> TestResult {
    assert_eq!(REGISTRATION_TOPIC, REGISTER_TOPIC_STR);
    Ok(())
}

#[test]
fn p2p_02_001_sync_builders_hash_len_is_64_bytes() -> TestResult {
    assert_eq!(REMZAR_HASH_BYTES_LEN, 64usize);
    Ok(())
}

#[test]
fn p2p_03_001_sync_builders_remzar_hash_bytes_alias_holds_64_bytes() -> TestResult {
    let hash: RemzarHashBytes = filled_hash(0x11);

    assert_eq!(hash.len(), REMZAR_HASH_BYTES_LEN);
    assert!(hash.iter().all(|byte| *byte == 0x11));
    Ok(())
}

#[test]
fn p2p_04_001_sync_builders_pending_batch_hash_bound_request_keeps_fields() -> TestResult {
    let peer = test_peer_id();
    let expected_hash = filled_hash(0x22);

    let request = PendingBatchRequest {
        peer,
        idx: 7,
        retries_left: 3,
        expected_block_hash: Some(expected_hash),
    };

    assert_eq!(request.peer, peer);
    assert_eq!(request.idx, 7);
    assert_eq!(request.retries_left, 3);
    assert_eq!(request.expected_block_hash, Some(expected_hash));
    Ok(())
}

#[test]
fn p2p_05_001_sync_builders_pending_batch_legacy_index_request_keeps_none_hash() -> TestResult {
    let peer = test_peer_id();

    let request = PendingBatchRequest {
        peer,
        idx: 8,
        retries_left: 0,
        expected_block_hash: None,
    };

    assert_eq!(request.peer, peer);
    assert_eq!(request.idx, 8);
    assert_eq!(request.retries_left, 0);
    assert!(request.expected_block_hash.is_none());
    Ok(())
}

#[test]
fn p2p_06_001_sync_builders_pending_batch_clone_preserves_all_fields() -> TestResult {
    let peer = test_peer_id();
    let expected_hash = filled_hash(0x33);

    let original = PendingBatchRequest {
        peer,
        idx: 44,
        retries_left: 2,
        expected_block_hash: Some(expected_hash),
    };
    let cloned = original.clone();

    assert_eq!(cloned.peer, original.peer);
    assert_eq!(cloned.idx, original.idx);
    assert_eq!(cloned.retries_left, original.retries_left);
    assert_eq!(cloned.expected_block_hash, original.expected_block_hash);
    Ok(())
}

#[test]
fn p2p_07_001_sync_builders_pending_batch_debug_contains_struct_name() -> TestResult {
    let request = PendingBatchRequest {
        peer: test_peer_id(),
        idx: 1,
        retries_left: 1,
        expected_block_hash: None,
    };

    let text = format!("{request:?}");

    assert!(text.contains("PendingBatchRequest"));
    Ok(())
}

#[test]
fn p2p_08_001_sync_builders_pending_batch_vector_indices_roundtrip() -> TestResult {
    let peer = test_peer_id();
    let indices = [0u64, 1u64, 2u64, 100u64, u64::MAX];

    for idx in indices {
        let request = PendingBatchRequest {
            peer,
            idx,
            retries_left: 3,
            expected_block_hash: None,
        };

        assert_eq!(request.idx, idx);
    }

    Ok(())
}

#[test]
fn p2p_09_001_sync_builders_pending_batch_vector_retries_roundtrip() -> TestResult {
    let peer = test_peer_id();

    for retries_left in 0u8..=6u8 {
        let request = PendingBatchRequest {
            peer,
            idx: u64::from(retries_left),
            retries_left,
            expected_block_hash: Some(filled_hash(retries_left)),
        };

        assert_eq!(request.retries_left, retries_left);
        assert_eq!(request.expected_block_hash, Some(filled_hash(retries_left)));
    }

    Ok(())
}

#[test]
fn p2p_10_001_sync_builders_pending_batch_fuzz_hash_bytes_are_preserved() -> TestResult {
    let peer = test_peer_id();

    for byte in 0u8..=63u8 {
        let hash = filled_hash(byte);
        let request = PendingBatchRequest {
            peer,
            idx: u64::from(byte),
            retries_left: 1,
            expected_block_hash: Some(hash),
        };

        assert_eq!(request.expected_block_hash, Some(hash));
    }

    Ok(())
}

#[test]
fn p2p_11_001_sync_builders_constructor_builds_real_sync_engine() -> TestResult {
    let harness = build_sync_harness("p2p_11")?;

    assert_initial_sync_state(&harness.sync);
    assert!(harness.data_dir.exists());
    Ok(())
}

#[test]
fn p2p_12_001_sync_builders_constructor_keeps_expected_genesis_hash() -> TestResult {
    let harness = build_sync_harness("p2p_12")?;

    assert_eq!(
        harness.sync.expected_genesis_hash.as_deref(),
        Some(GlobalConfiguration::GENESIS_HASH_HEX)
    );
    Ok(())
}

#[test]
fn p2p_13_001_sync_builders_constructor_has_no_last_synced_pointer_without_genesis() -> TestResult {
    let harness = build_sync_harness("p2p_13")?;

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_14_001_sync_builders_constructor_can_issue_pq_requests_when_empty() -> TestResult {
    let harness = build_sync_harness("p2p_14")?;

    assert!(harness.sync.can_issue_more_pq_requests());
    Ok(())
}

#[test]
fn p2p_15_001_sync_builders_pq_ready_false_for_unknown_peer() -> TestResult {
    let harness = build_sync_harness("p2p_15")?;
    let peer = test_peer_id();

    assert!(!harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_16_001_sync_builders_mark_pq_ready_sets_peer_ready() -> TestResult {
    let mut harness = build_sync_harness("p2p_16")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    assert!(harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.pq_ready_peers.contains(&peer));
    Ok(())
}

#[test]
fn p2p_17_001_sync_builders_clear_pq_peer_state_removes_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("p2p_17")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.clear_pq_peer_state(&peer);

    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(!harness.sync.pq_ready_peers.contains(&peer));
    Ok(())
}

#[test]
fn p2p_18_001_sync_builders_clear_pq_peer_state_is_idempotent_for_unknown_peer() -> TestResult {
    let mut harness = build_sync_harness("p2p_18")?;
    let peer = test_peer_id();

    harness.sync.clear_pq_peer_state(&peer);
    harness.sync.clear_pq_peer_state(&peer);

    assert!(!harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_19_001_sync_builders_pq_ready_multiple_peers_are_tracked() -> TestResult {
    let mut harness = build_sync_harness("p2p_19")?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);

    assert!(harness.sync.is_pq_ready(&first));
    assert!(harness.sync.is_pq_ready(&second));
    assert_eq!(harness.sync.pq_ready_peers.len(), 2usize);
    Ok(())
}

#[test]
fn p2p_20_001_sync_builders_pq_ready_mark_same_peer_twice_is_deduped() -> TestResult {
    let mut harness = build_sync_harness("p2p_20")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.mark_pq_ready(peer);

    assert!(harness.sync.is_pq_ready(&peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_21_001_sync_builders_has_background_work_false_initially() -> TestResult {
    let harness = build_sync_harness("p2p_21")?;

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_22_001_sync_builders_block_queue_sets_background_work_true() -> TestResult {
    let mut harness = build_sync_harness("p2p_22")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 1, 3));

    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_23_001_sync_builders_batch_queue_sets_background_work_true() -> TestResult {
    let mut harness = build_sync_harness("p2p_23")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 1, 3));

    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_24_001_sync_builders_background_work_clears_after_queues_clear() -> TestResult {
    let mut harness = build_sync_harness("p2p_24")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 1, 3));
    harness.sync.batch_queue.push_back((peer, 1, 3));

    assert!(harness.sync.has_background_sync_work());

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_25_001_sync_builders_update_sync_state_stays_syncing_without_genesis() -> TestResult {
    let mut harness = build_sync_harness("p2p_25")?;

    harness.sync.update_sync_state();

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_26_001_sync_builders_sync_percent_zero_when_not_synced_and_total_zero() -> TestResult {
    let mut harness = build_sync_harness("p2p_26")?;

    harness.sync.has_synced = false;
    harness.sync.total_to_download = 0;
    harness.sync.downloaded = 0;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_27_001_sync_builders_sync_percent_hundred_when_synced_and_total_zero() -> TestResult {
    let mut harness = build_sync_harness("p2p_27")?;

    harness.sync.has_synced = true;
    harness.sync.total_to_download = 0;
    harness.sync.downloaded = 0;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");
    Ok(())
}

#[test]
fn p2p_28_001_sync_builders_sync_percent_twenty_five_percent() -> TestResult {
    let mut harness = build_sync_harness("p2p_28")?;

    harness.sync.has_synced = false;
    harness.sync.total_to_download = 200;
    harness.sync.downloaded = 50;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
    Ok(())
}

#[test]
fn p2p_29_001_sync_builders_sync_percent_caps_at_hundred() -> TestResult {
    let mut harness = build_sync_harness("p2p_29")?;

    harness.sync.has_synced = false;
    harness.sync.total_to_download = 3;
    harness.sync.downloaded = 10;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");
    Ok(())
}

#[test]
fn p2p_30_001_sync_builders_sync_percent_vector_cases() -> TestResult {
    let mut harness = build_sync_harness("p2p_30")?;

    let cases = [
        (1u64, 0u64, "0.00"),
        (4u64, 1u64, "25.00"),
        (4u64, 2u64, "50.00"),
        (4u64, 3u64, "75.00"),
        (4u64, 4u64, "100.00"),
        (4u64, 5u64, "100.00"),
    ];

    for (total, downloaded, expected) in cases {
        harness.sync.total_to_download = total;
        harness.sync.downloaded = downloaded;

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), expected);
    }

    Ok(())
}

#[test]
fn p2p_31_001_sync_builders_update_sync_pointers_without_blocks_keeps_none() -> TestResult {
    let mut harness = build_sync_harness("p2p_31")?;

    harness.sync.update_sync_pointers();

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_32_001_sync_builders_expected_genesis_hash_can_be_none() -> TestResult {
    let data_dir = unique_data_dir("p2p_32");
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
        None,
        reorg_manager,
    );

    assert!(sync.expected_genesis_hash.is_none());
    Ok(())
}

#[test]
fn p2p_33_001_sync_builders_mempool_arc_is_wired() -> TestResult {
    let harness = build_sync_harness("p2p_33")?;

    let cloned = Arc::clone(&harness.sync.mempool);

    assert_eq!(Arc::strong_count(&cloned), 2usize);
    Ok(())
}

#[test]
fn p2p_34_001_sync_builders_db_arc_is_wired() -> TestResult {
    let harness = build_sync_harness("p2p_34")?;

    let before = Arc::strong_count(&harness.sync.db);
    let cloned = Arc::clone(&harness.sync.db);
    let after = Arc::strong_count(&harness.sync.db);

    assert!(before >= 1usize);
    assert_eq!(after, before.saturating_add(1usize));

    drop(cloned);

    assert_eq!(Arc::strong_count(&harness.sync.db), before);
    Ok(())
}

#[test]
fn p2p_35_001_sync_builders_load_multiple_sync_engines_use_unique_dirs() -> TestResult {
    let first = build_sync_harness("p2p_35_first")?;
    let second = build_sync_harness("p2p_35_second")?;

    assert_ne!(first.data_dir, second.data_dir);
    assert_initial_sync_state(&first.sync);
    assert_initial_sync_state(&second.sync);
    Ok(())
}

#[test]
fn p2p_36_001_sync_builders_load_ten_sync_engines_construct_cleanly() -> TestResult {
    let mut built = 0usize;

    for index in 0usize..10usize {
        let harness = build_sync_harness(&format!("p2p_36_{index}"))?;
        assert_initial_sync_state(&harness.sync);

        built = built
            .checked_add(1usize)
            .ok_or_else(|| "sync engine build counter overflow".to_string())?;
    }

    assert_eq!(built, 10usize);
    Ok(())
}

#[test]
fn p2p_37_001_sync_builders_fuzz_many_peers_mark_and_clear_pq_ready() -> TestResult {
    let mut harness = build_sync_harness("p2p_37")?;
    let mut peers = Vec::new();

    for _ in 0usize..32usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        peers.push(peer);
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 32usize);

    for peer in peers {
        harness.sync.clear_pq_peer_state(&peer);
        assert!(!harness.sync.is_pq_ready(&peer));
    }

    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_38_001_sync_builders_adversarial_clear_unknown_peers_after_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("p2p_38")?;
    let real_peer = test_peer_id();

    harness.sync.mark_pq_ready(real_peer);

    for _ in 0usize..32usize {
        let unknown_peer = test_peer_id();
        harness.sync.clear_pq_peer_state(&unknown_peer);
    }

    assert!(harness.sync.is_pq_ready(&real_peer));

    harness.sync.clear_pq_peer_state(&real_peer);
    assert!(!harness.sync.is_pq_ready(&real_peer));
    Ok(())
}

#[test]
fn p2p_39_001_sync_builders_adversarial_large_queue_backlog_reports_work() -> TestResult {
    let mut harness = build_sync_harness("p2p_39")?;
    let peer = test_peer_id();

    for index in 0u64..256u64 {
        harness.sync.block_queue.push_back((peer, index, 3));
        harness.sync.batch_queue.push_back((peer, index, 3));
    }

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 256usize);
    assert_eq!(harness.sync.batch_queue.len(), 256usize);
    Ok(())
}

#[test]
fn p2p_40_001_sync_builders_stress_sync_percent_many_vectors() -> TestResult {
    let mut harness = build_sync_harness("p2p_40")?;
    let mut checked = 0usize;

    for total in 1u64..=40u64 {
        for downloaded in 0u64..=total.saturating_add(2u64) {
            harness.sync.total_to_download = total;
            harness.sync.downloaded = downloaded;

            let percent = harness.sync.sync_percent();

            assert!(percent >= 0.0);
            assert!(percent <= 100.0);

            checked = checked
                .checked_add(1usize)
                .ok_or_else(|| "sync percent vector counter overflow".to_string())?;
        }
    }

    assert!(checked > 40usize);
    Ok(())
}

#[test]
fn p2p_41_001_sync_builders_multiple_sync_engines_start_independent() -> TestResult {
    let first = build_sync_harness("p2p_41_first")?;
    let second = build_sync_harness("p2p_41_second")?;

    assert_ne!(first.data_dir, second.data_dir);
    assert_initial_sync_state(&first.sync);
    assert_initial_sync_state(&second.sync);
    Ok(())
}

#[test]
fn p2p_42_001_sync_builders_pq_clear_first_peer_leaves_second_ready() -> TestResult {
    let mut harness = build_sync_harness("p2p_42")?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);
    harness.sync.clear_pq_peer_state(&first);

    assert!(!harness.sync.is_pq_ready(&first));
    assert!(harness.sync.is_pq_ready(&second));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_43_001_sync_builders_pq_clear_middle_peer_preserves_others() -> TestResult {
    let mut harness = build_sync_harness("p2p_43")?;
    let first = test_peer_id();
    let second = test_peer_id();
    let third = test_peer_id();

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);
    harness.sync.mark_pq_ready(third);
    harness.sync.clear_pq_peer_state(&second);

    assert!(harness.sync.is_pq_ready(&first));
    assert!(!harness.sync.is_pq_ready(&second));
    assert!(harness.sync.is_pq_ready(&third));
    assert_eq!(harness.sync.pq_ready_peers.len(), 2usize);
    Ok(())
}

#[test]
fn p2p_44_001_sync_builders_pq_clear_unknown_peer_does_not_change_ready_set() -> TestResult {
    let mut harness = build_sync_harness("p2p_44")?;
    let ready_peer = test_peer_id();
    let unknown_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness.sync.clear_pq_peer_state(&unknown_peer);

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.is_pq_ready(&unknown_peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_45_001_sync_builders_block_queue_only_counts_as_background_work() -> TestResult {
    let mut harness = build_sync_harness("p2p_45")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 41u64, 3u8));

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert!(harness.sync.batch_queue.is_empty());
    Ok(())
}

#[test]
fn p2p_46_001_sync_builders_batch_queue_only_counts_as_background_work() -> TestResult {
    let mut harness = build_sync_harness("p2p_46")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 42u64, 3u8));

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert!(harness.sync.block_queue.is_empty());
    Ok(())
}

#[test]
fn p2p_47_001_sync_builders_block_queue_preserves_fifo_order() -> TestResult {
    let mut harness = build_sync_harness("p2p_47")?;
    let peer = test_peer_id();

    for index in 0u64..8u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
    }

    for expected_index in 0u64..8u64 {
        let (_, actual_index, retries_left) = harness
            .sync
            .block_queue
            .pop_front()
            .ok_or_else(|| "missing queued block request".to_string())?;

        assert_eq!(actual_index, expected_index);
        assert_eq!(retries_left, 3u8);
    }

    assert!(harness.sync.block_queue.is_empty());
    Ok(())
}

#[test]
fn p2p_48_001_sync_builders_batch_queue_preserves_fifo_order() -> TestResult {
    let mut harness = build_sync_harness("p2p_48")?;
    let peer = test_peer_id();

    for index in 0u64..8u64 {
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    for expected_index in 0u64..8u64 {
        let (_, actual_index, retries_left) = harness
            .sync
            .batch_queue
            .pop_front()
            .ok_or_else(|| "missing queued batch request".to_string())?;

        assert_eq!(actual_index, expected_index);
        assert_eq!(retries_left, 2u8);
    }

    assert!(harness.sync.batch_queue.is_empty());
    Ok(())
}

#[test]
fn p2p_49_001_sync_builders_clearing_only_block_queue_removes_work_when_batch_empty() -> TestResult
{
    let mut harness = build_sync_harness("p2p_49")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 1u64, 3u8));
    assert!(harness.sync.has_background_sync_work());

    harness.sync.block_queue.clear();
    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_50_001_sync_builders_clearing_block_queue_keeps_work_when_batch_remains() -> TestResult {
    let mut harness = build_sync_harness("p2p_50")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 1u64, 3u8));
    harness.sync.batch_queue.push_back((peer, 1u64, 3u8));

    harness.sync.block_queue.clear();

    assert!(harness.sync.has_background_sync_work());
    assert!(harness.sync.block_queue.is_empty());
    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_51_001_sync_builders_sync_percent_one_third_truncates_to_33_33() -> TestResult {
    let mut harness = build_sync_harness("p2p_51")?;

    harness.sync.total_to_download = 3u64;
    harness.sync.downloaded = 1u64;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "33.33");
    Ok(())
}

#[test]
fn p2p_52_001_sync_builders_sync_percent_two_thirds_truncates_to_66_66() -> TestResult {
    let mut harness = build_sync_harness("p2p_52")?;

    harness.sync.total_to_download = 3u64;
    harness.sync.downloaded = 2u64;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "66.66");
    Ok(())
}

#[test]
fn p2p_53_001_sync_builders_sync_percent_large_numbers_stay_in_range() -> TestResult {
    let mut harness = build_sync_harness("p2p_53")?;

    harness.sync.total_to_download = u64::MAX;
    harness.sync.downloaded = u64::MAX / 2u64;

    let percent = harness.sync.sync_percent();

    assert!(percent >= 0.0);
    assert!(percent <= 100.0);
    Ok(())
}

#[test]
fn p2p_54_001_sync_builders_sync_percent_u64_max_download_caps_at_100() -> TestResult {
    let mut harness = build_sync_harness("p2p_54")?;

    harness.sync.total_to_download = 10u64;
    harness.sync.downloaded = u64::MAX;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");
    Ok(())
}

#[test]
fn p2p_55_001_sync_builders_has_synced_method_reflects_public_flag_false() -> TestResult {
    let mut harness = build_sync_harness("p2p_55")?;

    harness.sync.has_synced = false;

    assert!(!harness.sync.has_synced());
    Ok(())
}

#[test]
fn p2p_56_001_sync_builders_has_synced_method_reflects_public_flag_true() -> TestResult {
    let mut harness = build_sync_harness("p2p_56")?;

    harness.sync.has_synced = true;

    assert!(harness.sync.has_synced());
    Ok(())
}

#[test]
fn p2p_57_001_sync_builders_is_syncing_true_without_genesis_after_update() -> TestResult {
    let mut harness = build_sync_harness("p2p_57")?;

    harness.sync.update_sync_state();

    assert!(harness.sync.is_syncing());
    assert!(!harness.sync.has_synced());
    Ok(())
}

#[test]
fn p2p_58_001_sync_builders_download_counters_are_mutable_and_readable() -> TestResult {
    let mut harness = build_sync_harness("p2p_58")?;

    harness.sync.total_to_download = 123u64;
    harness.sync.downloaded = 45u64;

    assert_eq!(harness.sync.total_to_download, 123u64);
    assert_eq!(harness.sync.downloaded, 45u64);
    Ok(())
}

#[test]
fn p2p_59_001_sync_builders_chain_initial_balances_are_empty() -> TestResult {
    let harness = build_sync_harness("p2p_59")?;

    assert!(harness.sync.chain.get_balances().is_empty());
    Ok(())
}

#[test]
fn p2p_60_001_sync_builders_chain_initial_blocks_are_empty() -> TestResult {
    let harness = build_sync_harness("p2p_60")?;

    assert!(harness.sync.chain.get_blocks().is_empty());
    Ok(())
}

#[test]
fn p2p_61_001_sync_builders_chain_initial_latest_height_is_zero() -> TestResult {
    let harness = build_sync_harness("p2p_61")?;

    assert_eq!(harness.sync.chain.latest_block_height(), 0usize);
    Ok(())
}

#[test]
fn p2p_62_001_sync_builders_chain_get_block_zero_fails_when_empty() -> TestResult {
    let harness = build_sync_harness("p2p_62")?;

    assert!(harness.sync.chain.get_block_by_index(0usize).is_err());
    Ok(())
}

#[test]
fn p2p_63_001_sync_builders_db_tip_height_initializes_to_zero() -> TestResult {
    let harness = build_sync_harness("p2p_63")?;
    let height = harness.sync.db.get_tip_height().map_err(fmt_err)?;

    assert_eq!(height, 0u64);
    Ok(())
}

#[test]
fn p2p_64_001_sync_builders_last_synced_pointer_methods_remain_none_without_blocks() -> TestResult {
    let mut harness = build_sync_harness("p2p_64")?;

    harness.sync.update_sync_pointers();

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_65_001_sync_builders_pending_batch_debug_includes_idx_field_name() -> TestResult {
    let request = PendingBatchRequest {
        peer: test_peer_id(),
        idx: 65u64,
        retries_left: 1u8,
        expected_block_hash: None,
    };

    let debug_text = format!("{request:?}");

    assert!(debug_text.contains("idx"));
    assert!(debug_text.contains("retries_left"));
    Ok(())
}

#[test]
fn p2p_66_001_sync_builders_pending_batch_clone_none_hash_preserved() -> TestResult {
    let request = PendingBatchRequest {
        peer: test_peer_id(),
        idx: 66u64,
        retries_left: 2u8,
        expected_block_hash: None,
    };

    let cloned = request.clone();

    assert_eq!(cloned.idx, request.idx);
    assert_eq!(cloned.retries_left, request.retries_left);
    assert!(cloned.expected_block_hash.is_none());
    Ok(())
}

#[test]
fn p2p_67_001_sync_builders_many_pending_batch_requests_use_unique_peers() -> TestResult {
    let mut peer_texts = std::collections::BTreeSet::new();

    for index in 0u64..32u64 {
        let peer = test_peer_id();
        let request = PendingBatchRequest {
            peer,
            idx: index,
            retries_left: 3u8,
            expected_block_hash: Some(filled_hash(u8::try_from(index).map_err(fmt_err)?)),
        };

        let inserted = peer_texts.insert(request.peer.to_string());
        assert!(inserted);
    }

    assert_eq!(peer_texts.len(), 32usize);
    Ok(())
}

#[test]
fn p2p_68_001_sync_builders_pending_batch_none_hash_and_zero_hash_are_distinct() -> TestResult {
    let peer = test_peer_id();

    let legacy = PendingBatchRequest {
        peer,
        idx: 68u64,
        retries_left: 3u8,
        expected_block_hash: None,
    };

    let hash_bound = PendingBatchRequest {
        peer,
        idx: 68u64,
        retries_left: 3u8,
        expected_block_hash: Some([0u8; REMZAR_HASH_BYTES_LEN]),
    };

    assert_ne!(legacy.expected_block_hash, hash_bound.expected_block_hash);
    Ok(())
}

#[test]
fn p2p_69_001_sync_builders_pending_batch_zero_hash_is_preserved_when_explicit() -> TestResult {
    let zero_hash = [0u8; REMZAR_HASH_BYTES_LEN];

    let request = PendingBatchRequest {
        peer: test_peer_id(),
        idx: 69u64,
        retries_left: 3u8,
        expected_block_hash: Some(zero_hash),
    };

    assert_eq!(request.expected_block_hash, Some(zero_hash));
    Ok(())
}

#[test]
fn p2p_70_001_sync_builders_pending_batch_fuzz_patterned_hashes() -> TestResult {
    for byte in 0u8..40u8 {
        let mut hash = [0u8; REMZAR_HASH_BYTES_LEN];

        for (offset, slot) in hash.iter_mut().enumerate() {
            let offset_byte = u8::try_from(offset).map_err(fmt_err)?;
            *slot = byte.wrapping_add(offset_byte);
        }

        let request = PendingBatchRequest {
            peer: test_peer_id(),
            idx: u64::from(byte),
            retries_left: byte % 4u8,
            expected_block_hash: Some(hash),
        };

        assert_eq!(request.expected_block_hash, Some(hash));
    }

    Ok(())
}

#[test]
fn p2p_71_001_sync_builders_load_many_sync_engines_and_mark_one_peer_each() -> TestResult {
    let mut built = 0usize;

    for index in 0usize..12usize {
        let mut harness = build_sync_harness(&format!("p2p_71_{index}"))?;
        let peer = test_peer_id();

        harness.sync.mark_pq_ready(peer);

        assert!(harness.sync.is_pq_ready(&peer));
        built = built
            .checked_add(1usize)
            .ok_or_else(|| "sync build counter overflow".to_string())?;
    }

    assert_eq!(built, 12usize);
    Ok(())
}

#[test]
fn p2p_72_001_sync_builders_stress_mark_eighty_peers_ready() -> TestResult {
    let mut harness = build_sync_harness("p2p_72")?;

    for _ in 0usize..80usize {
        harness.sync.mark_pq_ready(test_peer_id());
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 80usize);
    Ok(())
}

#[test]
fn p2p_73_001_sync_builders_adversarial_repeated_mark_clear_same_peer() -> TestResult {
    let mut harness = build_sync_harness("p2p_73")?;
    let peer = test_peer_id();

    for _ in 0usize..50usize {
        harness.sync.mark_pq_ready(peer);
        assert!(harness.sync.is_pq_ready(&peer));

        harness.sync.clear_pq_peer_state(&peer);
        assert!(!harness.sync.is_pq_ready(&peer));
    }

    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_74_001_sync_builders_adversarial_large_block_queue_backlog() -> TestResult {
    let mut harness = build_sync_harness("p2p_74")?;
    let peer = test_peer_id();

    for index in 0u64..512u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
    }

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 512usize);
    Ok(())
}

#[test]
fn p2p_75_001_sync_builders_adversarial_large_batch_queue_backlog() -> TestResult {
    let mut harness = build_sync_harness("p2p_75")?;
    let peer = test_peer_id();

    for index in 0u64..512u64 {
        harness.sync.batch_queue.push_back((peer, index, 3u8));
    }

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.batch_queue.len(), 512usize);
    Ok(())
}

#[test]
fn p2p_76_001_sync_builders_fuzz_sync_percent_many_small_vectors() -> TestResult {
    let mut harness = build_sync_harness("p2p_76")?;
    let mut checked = 0usize;

    for total in 1u64..=24u64 {
        for downloaded in 0u64..=total.saturating_add(3u64) {
            harness.sync.total_to_download = total;
            harness.sync.downloaded = downloaded;

            let percent = harness.sync.sync_percent();

            assert!(percent >= 0.0);
            assert!(percent <= 100.0);

            checked = checked
                .checked_add(1usize)
                .ok_or_else(|| "sync percent check counter overflow".to_string())?;
        }
    }

    assert!(checked > 100usize);
    Ok(())
}

#[test]
fn p2p_77_001_sync_builders_queue_pop_until_empty_removes_background_work() -> TestResult {
    let mut harness = build_sync_harness("p2p_77")?;
    let peer = test_peer_id();

    for index in 0u64..16u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 3u8));
    }

    while harness.sync.block_queue.pop_front().is_some() {}
    while harness.sync.batch_queue.pop_front().is_some() {}

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_78_001_sync_builders_property_arc_strong_counts_are_nonzero() -> TestResult {
    let harness = build_sync_harness("p2p_78")?;

    assert!(Arc::strong_count(&harness.sync.db) >= 1usize);
    assert!(Arc::strong_count(&harness.sync.mempool) >= 1usize);
    Ok(())
}

#[test]
fn p2p_79_001_sync_builders_property_peer_id_texts_are_unique_for_ready_set() -> TestResult {
    let mut harness = build_sync_harness("p2p_79")?;
    let mut peer_texts = std::collections::BTreeSet::new();

    for _ in 0usize..64usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);

        let inserted = peer_texts.insert(peer.to_string());
        assert!(inserted);
    }

    assert_eq!(peer_texts.len(), 64usize);
    assert_eq!(harness.sync.pq_ready_peers.len(), 64usize);
    Ok(())
}

#[test]
fn p2p_80_001_sync_builders_stress_mixed_queue_and_pq_state() -> TestResult {
    let mut harness = build_sync_harness("p2p_80")?;
    let queue_peer = test_peer_id();

    for index in 0u64..128u64 {
        harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
        harness.sync.mark_pq_ready(test_peer_id());
    }

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 128usize);
    assert_eq!(harness.sync.batch_queue.len(), 128usize);
    assert_eq!(harness.sync.pq_ready_peers.len(), 128usize);

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();

    assert!(!harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.pq_ready_peers.len(), 128usize);
    Ok(())
}

#[test]
fn p2p_81_001_sync_builders_expected_genesis_hash_empty_string_is_stored() -> TestResult {
    let data_dir = unique_data_dir("p2p_81");
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
        Some(String::new()),
        reorg_manager,
    );

    assert_eq!(sync.expected_genesis_hash.as_deref(), Some(""));
    assert!(!sync.has_synced());
    assert!(sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_82_001_sync_builders_expected_genesis_hash_malformed_string_is_stored_not_validated()
-> TestResult {
    let data_dir = unique_data_dir("p2p_82");
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
        Some("not-a-real-genesis-hash".to_string()),
        reorg_manager,
    );

    assert_eq!(
        sync.expected_genesis_hash.as_deref(),
        Some("not-a-real-genesis-hash")
    );
    assert!(!sync.has_synced());
    assert!(sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_83_001_sync_builders_pending_batch_u64_max_index_is_preserved() -> TestResult {
    let request = PendingBatchRequest {
        peer: test_peer_id(),
        idx: u64::MAX,
        retries_left: u8::MAX,
        expected_block_hash: Some(filled_hash(0xff)),
    };

    assert_eq!(request.idx, u64::MAX);
    assert_eq!(request.retries_left, u8::MAX);
    assert_eq!(request.expected_block_hash, Some(filled_hash(0xff)));
    Ok(())
}

#[test]
fn p2p_84_001_sync_builders_pending_batch_hash_first_and_last_bytes_preserved() -> TestResult {
    let mut hash = [0u8; REMZAR_HASH_BYTES_LEN];
    hash[0] = 0xaa;
    hash[REMZAR_HASH_BYTES_LEN - 1usize] = 0xbb;

    let request = PendingBatchRequest {
        peer: test_peer_id(),
        idx: 84u64,
        retries_left: 1u8,
        expected_block_hash: Some(hash),
    };

    let stored = request
        .expected_block_hash
        .ok_or_else(|| "expected hash missing".to_string())?;

    assert_eq!(stored[0], 0xaa);
    assert_eq!(stored[REMZAR_HASH_BYTES_LEN - 1usize], 0xbb);
    Ok(())
}

#[test]
fn p2p_85_001_sync_builders_vector_pending_batch_hash_patterns() -> TestResult {
    let patterns = [0x00u8, 0x01u8, 0x7fu8, 0x80u8, 0xffu8];

    for pattern in patterns {
        let request = PendingBatchRequest {
            peer: test_peer_id(),
            idx: u64::from(pattern),
            retries_left: pattern % 4u8,
            expected_block_hash: Some(filled_hash(pattern)),
        };

        assert_eq!(request.expected_block_hash, Some(filled_hash(pattern)));
    }

    Ok(())
}

#[test]
fn p2p_86_001_sync_builders_vector_sync_percent_exact_quarters() -> TestResult {
    let mut harness = build_sync_harness("p2p_86")?;

    let cases = [
        (4u64, 0u64, "0.00"),
        (4u64, 1u64, "25.00"),
        (4u64, 2u64, "50.00"),
        (4u64, 3u64, "75.00"),
        (4u64, 4u64, "100.00"),
    ];

    for (total, downloaded, expected) in cases {
        harness.sync.total_to_download = total;
        harness.sync.downloaded = downloaded;

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), expected);
    }

    Ok(())
}

#[test]
fn p2p_87_001_sync_builders_vector_sync_percent_exact_tenths() -> TestResult {
    let mut harness = build_sync_harness("p2p_87")?;

    for downloaded in 0u64..=10u64 {
        harness.sync.total_to_download = 10u64;
        harness.sync.downloaded = downloaded;

        let expected_whole = downloaded
            .checked_mul(10u64)
            .ok_or_else(|| "expected percent overflow".to_string())?;
        let expected = format!("{expected_whole}.00");

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), expected);
    }

    Ok(())
}

#[test]
fn p2p_88_001_sync_builders_edge_sync_percent_total_one() -> TestResult {
    let mut harness = build_sync_harness("p2p_88")?;

    harness.sync.total_to_download = 1u64;
    harness.sync.downloaded = 0u64;
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");

    harness.sync.downloaded = 1u64;
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");

    harness.sync.downloaded = 2u64;
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");

    Ok(())
}

#[test]
fn p2p_89_001_sync_builders_edge_sync_percent_downloaded_zero_for_large_total() -> TestResult {
    let mut harness = build_sync_harness("p2p_89")?;

    harness.sync.total_to_download = u64::MAX;
    harness.sync.downloaded = 0u64;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_90_001_sync_builders_edge_sync_percent_downloaded_equals_total_large() -> TestResult {
    let mut harness = build_sync_harness("p2p_90")?;

    let large_total = u64::MAX / 10_000u64;

    harness.sync.total_to_download = large_total;
    harness.sync.downloaded = large_total;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");
    Ok(())
}

#[test]
fn p2p_91_001_sync_builders_queue_vectors_mixed_retry_values_preserved() -> TestResult {
    let mut harness = build_sync_harness("p2p_91")?;
    let peer = test_peer_id();

    for retry in 0u8..=10u8 {
        harness
            .sync
            .block_queue
            .push_back((peer, u64::from(retry), retry));
        harness
            .sync
            .batch_queue
            .push_back((peer, u64::from(retry), retry));
    }

    for retry in 0u8..=10u8 {
        let (_, block_index, block_retry) = harness
            .sync
            .block_queue
            .pop_front()
            .ok_or_else(|| "missing block queue entry".to_string())?;
        let (_, batch_index, batch_retry) = harness
            .sync
            .batch_queue
            .pop_front()
            .ok_or_else(|| "missing batch queue entry".to_string())?;

        assert_eq!(block_index, u64::from(retry));
        assert_eq!(batch_index, u64::from(retry));
        assert_eq!(block_retry, retry);
        assert_eq!(batch_retry, retry);
    }

    Ok(())
}

#[test]
fn p2p_92_001_sync_builders_queue_accepts_u64_max_indices() -> TestResult {
    let mut harness = build_sync_harness("p2p_92")?;
    let peer = test_peer_id();

    harness
        .sync
        .block_queue
        .push_back((peer, u64::MAX, u8::MAX));
    harness
        .sync
        .batch_queue
        .push_back((peer, u64::MAX, u8::MAX));

    assert!(harness.sync.has_background_sync_work());

    let (_, block_index, block_retry) = harness
        .sync
        .block_queue
        .pop_front()
        .ok_or_else(|| "missing max block queue entry".to_string())?;
    let (_, batch_index, batch_retry) = harness
        .sync
        .batch_queue
        .pop_front()
        .ok_or_else(|| "missing max batch queue entry".to_string())?;

    assert_eq!(block_index, u64::MAX);
    assert_eq!(batch_index, u64::MAX);
    assert_eq!(block_retry, u8::MAX);
    assert_eq!(batch_retry, u8::MAX);
    Ok(())
}

#[test]
fn p2p_93_001_sync_builders_pq_ready_set_survives_queue_operations() -> TestResult {
    let mut harness = build_sync_harness("p2p_93")?;
    let ready_peer = test_peer_id();
    let queue_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);

    for index in 0u64..20u64 {
        harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
    }

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_94_001_sync_builders_public_hash_alias_can_be_used_in_collections() -> TestResult {
    let mut hashes = std::collections::BTreeSet::new();

    for byte in 0u8..16u8 {
        hashes.insert(filled_hash(byte));
    }

    assert_eq!(hashes.len(), 16usize);
    assert!(hashes.contains(&filled_hash(0u8)));
    assert!(hashes.contains(&filled_hash(15u8)));
    Ok(())
}

#[test]
fn p2p_95_001_sync_builders_public_hash_alias_vector_sorting_is_deterministic() -> TestResult {
    let mut hashes = vec![
        filled_hash(9u8),
        filled_hash(1u8),
        filled_hash(7u8),
        filled_hash(3u8),
    ];

    hashes.sort();

    assert_eq!(
        hashes,
        vec![
            filled_hash(1u8),
            filled_hash(3u8),
            filled_hash(7u8),
            filled_hash(9u8),
        ]
    );
    Ok(())
}

#[test]
fn p2p_96_001_sync_builders_load_create_twenty_engines_and_check_initial_percent() -> TestResult {
    let mut built = 0usize;

    for index in 0usize..20usize {
        let harness = build_sync_harness(&format!("p2p_96_{index}"))?;

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");

        built = built
            .checked_add(1usize)
            .ok_or_else(|| "engine counter overflow".to_string())?;
    }

    assert_eq!(built, 20usize);
    Ok(())
}

#[test]
fn p2p_97_001_sync_builders_load_large_pq_ready_set_then_clear_all() -> TestResult {
    let mut harness = build_sync_harness("p2p_97")?;
    let mut peers = Vec::new();

    for _ in 0usize..160usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        peers.push(peer);
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 160usize);

    for peer in peers {
        harness.sync.clear_pq_peer_state(&peer);
    }

    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_98_001_sync_builders_adversarial_alternate_queue_push_clear_cycles() -> TestResult {
    let mut harness = build_sync_harness("p2p_98")?;
    let peer = test_peer_id();

    for cycle in 0u64..25u64 {
        harness.sync.block_queue.push_back((peer, cycle, 3u8));
        harness.sync.batch_queue.push_back((peer, cycle, 2u8));

        assert!(harness.sync.has_background_sync_work());

        harness.sync.block_queue.clear();
        harness.sync.batch_queue.clear();

        assert!(!harness.sync.has_background_sync_work());
    }

    Ok(())
}

#[test]
fn p2p_99_001_sync_builders_adversarial_sync_percent_extreme_vectors_stay_bounded() -> TestResult {
    let mut harness = build_sync_harness("p2p_99")?;
    let cases = [
        (1u64, u64::MAX),
        (2u64, u64::MAX),
        (u64::MAX / 2u64, u64::MAX),
        (u64::MAX, u64::MAX / 3u64),
        (u64::MAX, u64::MAX - 1u64),
    ];

    for (total, downloaded) in cases {
        harness.sync.total_to_download = total;
        harness.sync.downloaded = downloaded;

        let percent = harness.sync.sync_percent();

        assert!(percent >= 0.0);
        assert!(percent <= 100.0);
    }

    Ok(())
}

#[test]
fn p2p_100_001_sync_builders_end_to_end_public_state_stress() -> TestResult {
    let mut harness = build_sync_harness("p2p_100")?;
    let queue_peer = test_peer_id();
    let mut pq_peers = Vec::new();

    for index in 0u64..100u64 {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        pq_peers.push(peer);

        harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 100usize);
    assert_eq!(harness.sync.block_queue.len(), 100usize);
    assert_eq!(harness.sync.batch_queue.len(), 100usize);
    assert!(harness.sync.has_background_sync_work());

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();

    assert!(!harness.sync.has_background_sync_work());

    for peer in pq_peers {
        harness.sync.clear_pq_peer_state(&peer);
    }

    assert!(harness.sync.pq_ready_peers.is_empty());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}
