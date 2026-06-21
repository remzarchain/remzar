#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{PeerId, identity};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::{p2p_006_reqresp::Hash, p2p_011_peerbook::PeerBook},
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{p2p_001_sync_builders::P2pSync, p2p_006_sync_runtime::NodeOpts},
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
        "remzar_p2p_002_sync_handlers_tests_{}_{}_{}_{}",
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

fn test_peer_id() -> PeerId {
    let keypair = identity::Keypair::generate_ed25519();
    PeerId::from(keypair.public())
}

fn filled_hash(byte: u8) -> Hash {
    [byte; 64]
}

fn patterned_hash(seed: u8) -> TestResult<Hash> {
    let mut hash = [0u8; 64];

    for (index, slot) in hash.iter_mut().enumerate() {
        let index_byte = u8::try_from(index).map_err(fmt_err)?;
        *slot = seed.wrapping_add(index_byte);
    }

    Ok(hash)
}

fn unknown_fork_error(sync: &mut P2pSync, hash: Hash) -> TestResult<String> {
    match sync.handle_fork(hash) {
        Ok(()) => Err("unknown fork hash unexpectedly returned Ok(())".to_string()),
        Err(err) => Ok(err),
    }
}

fn assert_unknown_fork_error_shape(err: &str) {
    assert!(err.contains("handle_fork"));
    assert!(err.contains("unknown block hash"));
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
fn p2p_01_002_sync_handlers_constructs_real_sync_for_handler_tests() -> TestResult {
    let harness = build_sync_harness("p2p_01")?;

    assert_initial_public_state(&harness.sync);
    assert!(harness.data_dir.exists());
    Ok(())
}

#[test]
fn p2p_02_002_sync_handlers_handle_fork_unknown_zero_hash_errors() -> TestResult {
    let mut harness = build_sync_harness("p2p_02")?;
    let err = unknown_fork_error(&mut harness.sync, filled_hash(0u8))?;

    assert_unknown_fork_error_shape(&err);
    Ok(())
}

#[test]
fn p2p_03_002_sync_handlers_handle_fork_unknown_ff_hash_errors() -> TestResult {
    let mut harness = build_sync_harness("p2p_03")?;
    let err = unknown_fork_error(&mut harness.sync, filled_hash(0xff))?;

    assert_unknown_fork_error_shape(&err);
    Ok(())
}

#[test]
fn p2p_04_002_sync_handlers_handle_fork_unknown_pattern_hash_errors() -> TestResult {
    let mut harness = build_sync_harness("p2p_04")?;
    let err = unknown_fork_error(&mut harness.sync, patterned_hash(4u8)?)?;

    assert_unknown_fork_error_shape(&err);
    Ok(())
}

#[test]
fn p2p_05_002_sync_handlers_error_mentions_requested_hash_bytes() -> TestResult {
    let mut harness = build_sync_harness("p2p_05")?;
    let hash = filled_hash(0x05);
    let err = unknown_fork_error(&mut harness.sync, hash)?;

    assert!(err.contains("05"));
    assert_unknown_fork_error_shape(&err);
    Ok(())
}

#[test]
fn p2p_06_002_sync_handlers_same_unknown_hash_returns_same_error_text() -> TestResult {
    let mut harness = build_sync_harness("p2p_06")?;
    let hash = filled_hash(0x06);

    let first = unknown_fork_error(&mut harness.sync, hash)?;
    let second = unknown_fork_error(&mut harness.sync, hash)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_07_002_sync_handlers_different_unknown_hashes_return_different_error_text() -> TestResult {
    let mut harness = build_sync_harness("p2p_07")?;

    let first = unknown_fork_error(&mut harness.sync, filled_hash(0x07))?;
    let second = unknown_fork_error(&mut harness.sync, filled_hash(0x08))?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn p2p_08_002_sync_handlers_unknown_fork_does_not_set_has_synced() -> TestResult {
    let mut harness = build_sync_harness("p2p_08")?;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x08))?;

    assert!(!harness.sync.has_synced());
    Ok(())
}

#[test]
fn p2p_09_002_sync_handlers_unknown_fork_keeps_node_syncing_without_genesis() -> TestResult {
    let mut harness = build_sync_harness("p2p_09")?;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x09))?;

    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_10_002_sync_handlers_unknown_fork_preserves_download_counters() -> TestResult {
    let mut harness = build_sync_harness("p2p_10")?;

    harness.sync.total_to_download = 123u64;
    harness.sync.downloaded = 45u64;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x0a))?;

    assert_eq!(harness.sync.total_to_download, 123u64);
    assert_eq!(harness.sync.downloaded, 45u64);
    Ok(())
}

#[test]
fn p2p_11_002_sync_handlers_unknown_fork_preserves_expected_genesis_hash() -> TestResult {
    let mut harness = build_sync_harness("p2p_11")?;

    let before = harness.sync.expected_genesis_hash.clone();
    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x0b))?;

    assert_eq!(harness.sync.expected_genesis_hash, before);
    Ok(())
}

#[test]
fn p2p_12_002_sync_handlers_unknown_fork_preserves_tried_genesis_flag() -> TestResult {
    let mut harness = build_sync_harness("p2p_12")?;

    harness.sync.tried_genesis = true;
    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x0c))?;

    assert!(harness.sync.tried_genesis);
    Ok(())
}

#[test]
fn p2p_13_002_sync_handlers_unknown_fork_preserves_pq_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("p2p_13")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x0d))?;

    assert!(harness.sync.is_pq_ready(&peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_14_002_sync_handlers_unknown_fork_preserves_multiple_pq_ready_peers() -> TestResult {
    let mut harness = build_sync_harness("p2p_14")?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.mark_pq_ready(first);
    harness.sync.mark_pq_ready(second);

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x0e))?;

    assert!(harness.sync.is_pq_ready(&first));
    assert!(harness.sync.is_pq_ready(&second));
    assert_eq!(harness.sync.pq_ready_peers.len(), 2usize);
    Ok(())
}

#[test]
fn p2p_15_002_sync_handlers_unknown_fork_preserves_block_queue() -> TestResult {
    let mut harness = build_sync_harness("p2p_15")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 15u64, 3u8));

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x0f))?;

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_16_002_sync_handlers_unknown_fork_preserves_batch_queue() -> TestResult {
    let mut harness = build_sync_harness("p2p_16")?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 16u64, 2u8));

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x10))?;

    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_17_002_sync_handlers_unknown_fork_preserves_both_queues() -> TestResult {
    let mut harness = build_sync_harness("p2p_17")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 17u64, 3u8));
    harness.sync.batch_queue.push_back((peer, 17u64, 2u8));

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x11))?;

    assert_eq!(harness.sync.block_queue.len(), 1usize);
    assert_eq!(harness.sync.batch_queue.len(), 1usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_18_002_sync_handlers_unknown_fork_preserves_pending_versions() -> TestResult {
    let mut harness = build_sync_harness("p2p_18")?;
    let before = harness.sync.pending_versions.len();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x12))?;

    assert_eq!(harness.sync.pending_versions.len(), before);
    Ok(())
}

#[test]
fn p2p_19_002_sync_handlers_unknown_fork_preserves_pending_pq() -> TestResult {
    let mut harness = build_sync_harness("p2p_19")?;
    let before = harness.sync.pending_pq.len();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x13))?;

    assert_eq!(harness.sync.pending_pq.len(), before);
    Ok(())
}

#[test]
fn p2p_20_002_sync_handlers_unknown_fork_preserves_pending_blocks() -> TestResult {
    let mut harness = build_sync_harness("p2p_20")?;
    let before = harness.sync.pending_blocks.len();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x14))?;

    assert_eq!(harness.sync.pending_blocks.len(), before);
    Ok(())
}

#[test]
fn p2p_21_002_sync_handlers_unknown_fork_preserves_pending_batches() -> TestResult {
    let mut harness = build_sync_harness("p2p_21")?;
    let before = harness.sync.pending_batches.len();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x15))?;

    assert_eq!(harness.sync.pending_batches.len(), before);
    Ok(())
}

#[test]
fn p2p_22_002_sync_handlers_unknown_fork_keeps_last_synced_index_none() -> TestResult {
    let mut harness = build_sync_harness("p2p_22")?;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x16))?;

    assert!(harness.sync.last_synced_index().is_none());
    Ok(())
}

#[test]
fn p2p_23_002_sync_handlers_unknown_fork_keeps_last_synced_hash_none() -> TestResult {
    let mut harness = build_sync_harness("p2p_23")?;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x17))?;

    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_24_002_sync_handlers_unknown_fork_does_not_create_db_block() -> TestResult {
    let mut harness = build_sync_harness("p2p_24")?;
    let hash = filled_hash(0x18);

    let _err = unknown_fork_error(&mut harness.sync, hash)?;

    assert!(harness.sync.db.get_block_by_hash(&hash).is_none());
    Ok(())
}

#[test]
fn p2p_25_002_sync_handlers_unknown_fork_does_not_change_tip_height() -> TestResult {
    let mut harness = build_sync_harness("p2p_25")?;
    let before = harness.sync.db.get_tip_height().map_err(fmt_err)?;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x19))?;

    let after = harness.sync.db.get_tip_height().map_err(fmt_err)?;
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn p2p_26_002_sync_handlers_unknown_fork_does_not_change_addr_index_height() -> TestResult {
    let mut harness = build_sync_harness("p2p_26")?;
    let before = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x1a))?;

    let after = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn p2p_27_002_sync_handlers_unknown_fork_does_not_change_chain_blocks() -> TestResult {
    let mut harness = build_sync_harness("p2p_27")?;
    let before = harness.sync.chain.get_blocks().len();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x1b))?;

    assert_eq!(harness.sync.chain.get_blocks().len(), before);
    Ok(())
}

#[test]
fn p2p_28_002_sync_handlers_unknown_fork_does_not_change_chain_balances() -> TestResult {
    let mut harness = build_sync_harness("p2p_28")?;
    let before = harness.sync.chain.get_balances().len();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x1c))?;

    assert_eq!(harness.sync.chain.get_balances().len(), before);
    Ok(())
}

#[test]
fn p2p_29_002_sync_handlers_vector_unknown_hashes_all_error() -> TestResult {
    let mut harness = build_sync_harness("p2p_29")?;

    for byte in 0u8..16u8 {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(byte))?;
        assert_unknown_fork_error_shape(&err);
    }

    Ok(())
}

#[test]
fn p2p_30_002_sync_handlers_vector_pattern_hashes_all_error() -> TestResult {
    let mut harness = build_sync_harness("p2p_30")?;

    for seed in 16u8..32u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);
    }

    Ok(())
}

#[test]
fn p2p_31_002_sync_handlers_property_error_strings_unique_for_unique_filled_hashes() -> TestResult {
    let mut harness = build_sync_harness("p2p_31")?;
    let mut errors = BTreeSet::new();

    for byte in 1u8..=24u8 {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(byte))?;
        let inserted = errors.insert(err);

        assert!(inserted);
    }

    assert_eq!(errors.len(), 24usize);
    Ok(())
}

#[test]
fn p2p_32_002_sync_handlers_property_error_strings_unique_for_pattern_hashes() -> TestResult {
    let mut harness = build_sync_harness("p2p_32")?;
    let mut errors = BTreeSet::new();

    for seed in 32u8..48u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        let inserted = errors.insert(err);

        assert!(inserted);
    }

    assert_eq!(errors.len(), 16usize);
    Ok(())
}

#[test]
fn p2p_33_002_sync_handlers_adversarial_repeated_unknown_hash_does_not_grow_queues() -> TestResult {
    let mut harness = build_sync_harness("p2p_33")?;
    let hash = filled_hash(0x33);

    for _ in 0usize..50usize {
        let _err = unknown_fork_error(&mut harness.sync, hash)?;
    }

    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_34_002_sync_handlers_adversarial_many_unknown_hashes_do_not_grow_queues() -> TestResult {
    let mut harness = build_sync_harness("p2p_34")?;

    for byte in 0u8..64u8 {
        let _err = unknown_fork_error(&mut harness.sync, patterned_hash(byte)?)?;
    }

    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_35_002_sync_handlers_adversarial_unknown_hashes_do_not_mark_pq_ready() -> TestResult {
    let mut harness = build_sync_harness("p2p_35")?;

    for byte in 0u8..32u8 {
        let _err = unknown_fork_error(&mut harness.sync, filled_hash(byte))?;
    }

    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_36_002_sync_handlers_load_one_engine_handles_128_unknown_forks() -> TestResult {
    let mut harness = build_sync_harness("p2p_36")?;
    let mut handled = 0usize;

    for byte in 0u8..=127u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(byte)?)?;
        assert_unknown_fork_error_shape(&err);

        handled = handled
            .checked_add(1usize)
            .ok_or_else(|| "unknown fork counter overflow".to_string())?;
    }

    assert_eq!(handled, 128usize);
    assert!(!harness.sync.has_synced());
    Ok(())
}

#[test]
fn p2p_37_002_sync_handlers_load_many_engines_each_handle_unknown_fork() -> TestResult {
    let mut built = 0usize;

    for index in 0usize..20usize {
        let mut harness = build_sync_harness(&format!("p2p_37_{index}"))?;
        let hash = patterned_hash(u8::try_from(index).map_err(fmt_err)?)?;
        let err = unknown_fork_error(&mut harness.sync, hash)?;

        assert_unknown_fork_error_shape(&err);

        built = built
            .checked_add(1usize)
            .ok_or_else(|| "engine counter overflow".to_string())?;
    }

    assert_eq!(built, 20usize);
    Ok(())
}

#[test]
fn p2p_38_002_sync_handlers_unknown_fork_after_sync_percent_setup_preserves_percent() -> TestResult
{
    let mut harness = build_sync_harness("p2p_38")?;

    harness.sync.total_to_download = 400u64;
    harness.sync.downloaded = 100u64;

    let before = format!("{:.2}", harness.sync.sync_percent());
    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x38))?;
    let after = format!("{:.2}", harness.sync.sync_percent());

    assert_eq!(before, "25.00");
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn p2p_39_002_sync_handlers_unknown_fork_after_background_work_preserves_background_work()
-> TestResult {
    let mut harness = build_sync_harness("p2p_39")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 39u64, 3u8));

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x39))?;

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.block_queue.len(), 1usize);
    Ok(())
}

#[test]
fn p2p_40_002_sync_handlers_end_to_end_unknown_fork_state_stress() -> TestResult {
    let mut harness = build_sync_harness("p2p_40")?;
    let queue_peer = test_peer_id();

    harness.sync.total_to_download = 1_000u64;
    harness.sync.downloaded = 250u64;
    harness.sync.mark_pq_ready(test_peer_id());

    for index in 0u64..32u64 {
        harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
    }

    for seed in 0u8..64u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);
    }

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
    assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
    assert_eq!(harness.sync.block_queue.len(), 32usize);
    assert_eq!(harness.sync.batch_queue.len(), 32usize);
    assert!(harness.sync.has_background_sync_work());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_41_002_sync_handlers_hash_type_is_exactly_64_bytes() -> TestResult {
    assert_eq!(std::mem::size_of::<Hash>(), 64usize);
    Ok(())
}

#[test]
fn p2p_42_002_sync_handlers_filled_hash_helper_outputs_64_bytes() -> TestResult {
    let hash = filled_hash(0x42);

    assert_eq!(hash.len(), 64usize);
    assert!(hash.iter().all(|byte| *byte == 0x42));
    Ok(())
}

#[test]
fn p2p_43_002_sync_handlers_patterned_hash_helper_outputs_non_uniform_hash() -> TestResult {
    let hash = patterned_hash(0x43)?;
    let unique: BTreeSet<u8> = hash.iter().copied().collect();

    assert_eq!(hash.len(), 64usize);
    assert!(unique.len() > 1usize);
    Ok(())
}

#[test]
fn p2p_44_002_sync_handlers_unknown_zero_hash_is_idempotent_for_state() -> TestResult {
    let mut harness = build_sync_harness("p2p_44")?;

    for _ in 0usize..5usize {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(0x00))?;
        assert_unknown_fork_error_shape(&err);
    }

    assert_initial_public_state(&harness.sync);
    Ok(())
}

#[test]
fn p2p_45_002_sync_handlers_unknown_max_hash_is_idempotent_for_state() -> TestResult {
    let mut harness = build_sync_harness("p2p_45")?;

    for _ in 0usize..5usize {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(0xff))?;
        assert_unknown_fork_error_shape(&err);
    }

    assert_initial_public_state(&harness.sync);
    Ok(())
}

#[test]
fn p2p_46_002_sync_handlers_vector_low_byte_hashes_all_fail_cleanly() -> TestResult {
    let mut harness = build_sync_harness("p2p_46")?;

    for byte in 0u8..=15u8 {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(byte))?;
        assert_unknown_fork_error_shape(&err);
    }

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_47_002_sync_handlers_vector_high_byte_hashes_all_fail_cleanly() -> TestResult {
    let mut harness = build_sync_harness("p2p_47")?;

    for byte in 240u8..=255u8 {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(byte))?;
        assert_unknown_fork_error_shape(&err);
    }

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_48_002_sync_handlers_vector_pattern_hashes_near_wraparound_fail_cleanly() -> TestResult {
    let mut harness = build_sync_harness("p2p_48")?;

    for seed in 240u8..=255u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);
    }

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_49_002_sync_handlers_error_text_contains_handler_path_for_many_hashes() -> TestResult {
    let mut harness = build_sync_harness("p2p_49")?;

    for seed in 1u8..=20u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert!(err.contains("handle_fork"));
    }

    Ok(())
}

#[test]
fn p2p_50_002_sync_handlers_error_text_contains_unknown_block_hash_for_many_hashes() -> TestResult {
    let mut harness = build_sync_harness("p2p_50")?;

    for seed in 21u8..=40u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert!(err.contains("unknown block hash"));
    }

    Ok(())
}

#[test]
fn p2p_51_002_sync_handlers_error_text_contains_handle_fork_for_many_hashes() -> TestResult {
    let mut harness = build_sync_harness("p2p_51")?;

    for seed in 41u8..=60u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert!(err.contains("handle_fork"));
    }

    Ok(())
}

#[test]
fn p2p_52_002_sync_handlers_unknown_fork_preserves_sync_percent_zero() -> TestResult {
    let mut harness = build_sync_harness("p2p_52")?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x52))?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
    Ok(())
}

#[test]
fn p2p_53_002_sync_handlers_unknown_fork_preserves_sync_percent_half() -> TestResult {
    let mut harness = build_sync_harness("p2p_53")?;

    harness.sync.total_to_download = 200u64;
    harness.sync.downloaded = 100u64;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x53))?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "50.00");
    Ok(())
}

#[test]
fn p2p_54_002_sync_handlers_unknown_fork_preserves_sync_percent_hundred_when_overdownloaded()
-> TestResult {
    let mut harness = build_sync_harness("p2p_54")?;

    harness.sync.total_to_download = 10u64;
    harness.sync.downloaded = 20u64;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x54))?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");
    Ok(())
}

#[test]
fn p2p_55_002_sync_handlers_unknown_fork_preserves_manually_set_has_synced_true() -> TestResult {
    let mut harness = build_sync_harness("p2p_55")?;

    harness.sync.has_synced = true;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x55))?;

    assert!(harness.sync.has_synced());
    Ok(())
}

#[test]
fn p2p_56_002_sync_handlers_update_sync_state_after_unknown_fork_restores_unsynced_without_genesis()
-> TestResult {
    let mut harness = build_sync_harness("p2p_56")?;

    harness.sync.has_synced = true;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x56))?;
    harness.sync.update_sync_state();

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_57_002_sync_handlers_unknown_fork_preserves_single_ready_peer_after_update_state()
-> TestResult {
    let mut harness = build_sync_harness("p2p_57")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x57))?;
    harness.sync.update_sync_state();

    assert!(harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_58_002_sync_handlers_unknown_fork_preserves_ready_peer_set_after_clear_unrelated()
-> TestResult {
    let mut harness = build_sync_harness("p2p_58")?;
    let ready_peer = test_peer_id();
    let unrelated_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness.sync.clear_pq_peer_state(&unrelated_peer);

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x58))?;

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert!(!harness.sync.is_pq_ready(&unrelated_peer));
    Ok(())
}

#[test]
fn p2p_59_002_sync_handlers_unknown_fork_preserves_many_ready_peers() -> TestResult {
    let mut harness = build_sync_harness("p2p_59")?;
    let mut peers = Vec::new();

    for _ in 0usize..32usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        peers.push(peer);
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x59))?;

    for peer in peers {
        assert!(harness.sync.is_pq_ready(&peer));
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 32usize);
    Ok(())
}

#[test]
fn p2p_60_002_sync_handlers_unknown_fork_preserves_block_queue_fifo_content() -> TestResult {
    let mut harness = build_sync_harness("p2p_60")?;
    let peer = test_peer_id();

    for index in 0u64..10u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x60))?;

    for expected_index in 0u64..10u64 {
        let (_, actual_index, retries_left) = harness
            .sync
            .block_queue
            .pop_front()
            .ok_or_else(|| "missing block queue item after unknown fork".to_string())?;

        assert_eq!(actual_index, expected_index);
        assert_eq!(retries_left, 3u8);
    }

    Ok(())
}

#[test]
fn p2p_61_002_sync_handlers_unknown_fork_preserves_batch_queue_fifo_content() -> TestResult {
    let mut harness = build_sync_harness("p2p_61")?;
    let peer = test_peer_id();

    for index in 0u64..10u64 {
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x61))?;

    for expected_index in 0u64..10u64 {
        let (_, actual_index, retries_left) = harness
            .sync
            .batch_queue
            .pop_front()
            .ok_or_else(|| "missing batch queue item after unknown fork".to_string())?;

        assert_eq!(actual_index, expected_index);
        assert_eq!(retries_left, 2u8);
    }

    Ok(())
}

#[test]
fn p2p_62_002_sync_handlers_unknown_fork_preserves_large_block_queue_len() -> TestResult {
    let mut harness = build_sync_harness("p2p_62")?;
    let peer = test_peer_id();

    for index in 0u64..256u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x62))?;

    assert_eq!(harness.sync.block_queue.len(), 256usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_63_002_sync_handlers_unknown_fork_preserves_large_batch_queue_len() -> TestResult {
    let mut harness = build_sync_harness("p2p_63")?;
    let peer = test_peer_id();

    for index in 0u64..256u64 {
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x63))?;

    assert_eq!(harness.sync.batch_queue.len(), 256usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_64_002_sync_handlers_unknown_fork_preserves_mixed_queues_len() -> TestResult {
    let mut harness = build_sync_harness("p2p_64")?;
    let peer = test_peer_id();

    for index in 0u64..128u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x64))?;

    assert_eq!(harness.sync.block_queue.len(), 128usize);
    assert_eq!(harness.sync.batch_queue.len(), 128usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_65_002_sync_handlers_unknown_fork_after_queue_clear_has_no_background_work() -> TestResult {
    let mut harness = build_sync_harness("p2p_65")?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 1u64, 3u8));
    harness.sync.batch_queue.push_back((peer, 1u64, 2u8));
    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x65))?;

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_66_002_sync_handlers_unknown_fork_preserves_db_tip_across_many_calls() -> TestResult {
    let mut harness = build_sync_harness("p2p_66")?;
    let before = harness.sync.db.get_tip_height().map_err(fmt_err)?;

    for seed in 0u8..50u8 {
        let _err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
    }

    let after = harness.sync.db.get_tip_height().map_err(fmt_err)?;
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn p2p_67_002_sync_handlers_unknown_fork_preserves_addr_index_height_across_many_calls()
-> TestResult {
    let mut harness = build_sync_harness("p2p_67")?;
    let before = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;

    for seed in 50u8..100u8 {
        let _err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
    }

    let after = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn p2p_68_002_sync_handlers_unknown_fork_never_creates_matching_block_for_vectors() -> TestResult {
    let mut harness = build_sync_harness("p2p_68")?;

    for seed in 100u8..120u8 {
        let hash = patterned_hash(seed)?;
        let _err = unknown_fork_error(&mut harness.sync, hash)?;

        assert!(harness.sync.db.get_block_by_hash(&hash).is_none());
    }

    Ok(())
}

#[test]
fn p2p_69_002_sync_handlers_unknown_fork_never_creates_chain_blocks_for_vectors() -> TestResult {
    let mut harness = build_sync_harness("p2p_69")?;

    for seed in 120u8..140u8 {
        let _err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
    }

    assert!(harness.sync.chain.get_blocks().is_empty());
    Ok(())
}

#[test]
fn p2p_70_002_sync_handlers_unknown_fork_never_creates_chain_balances_for_vectors() -> TestResult {
    let mut harness = build_sync_harness("p2p_70")?;

    for seed in 140u8..160u8 {
        let _err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
    }

    assert!(harness.sync.chain.get_balances().is_empty());
    Ok(())
}

#[test]
fn p2p_71_002_sync_handlers_fuzz_all_single_byte_filled_hashes_error() -> TestResult {
    let mut harness = build_sync_harness("p2p_71")?;
    let mut handled = 0usize;

    for byte in 0u8..=255u8 {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(byte))?;
        assert_unknown_fork_error_shape(&err);

        handled = handled
            .checked_add(1usize)
            .ok_or_else(|| "filled hash fuzz counter overflow".to_string())?;
    }

    assert_eq!(handled, 256usize);
    Ok(())
}

#[test]
fn p2p_72_002_sync_handlers_fuzz_pattern_hashes_full_byte_range_error() -> TestResult {
    let mut harness = build_sync_harness("p2p_72")?;
    let mut handled = 0usize;

    for seed in 0u8..=255u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);

        handled = handled
            .checked_add(1usize)
            .ok_or_else(|| "pattern hash fuzz counter overflow".to_string())?;
    }

    assert_eq!(handled, 256usize);
    Ok(())
}

#[test]
fn p2p_73_002_sync_handlers_property_repeated_error_string_stable_after_state_changes() -> TestResult
{
    let mut harness = build_sync_harness("p2p_73")?;
    let hash = patterned_hash(0x73)?;
    let first = unknown_fork_error(&mut harness.sync, hash)?;

    harness.sync.total_to_download = 500u64;
    harness.sync.downloaded = 125u64;
    harness.sync.mark_pq_ready(test_peer_id());

    let second = unknown_fork_error(&mut harness.sync, hash)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn p2p_74_002_sync_handlers_property_error_uniqueness_for_64_pattern_hashes() -> TestResult {
    let mut harness = build_sync_harness("p2p_74")?;
    let mut errors = BTreeSet::new();

    for seed in 0u8..64u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        let inserted = errors.insert(err);

        assert!(inserted);
    }

    assert_eq!(errors.len(), 64usize);
    Ok(())
}

#[test]
fn p2p_75_002_sync_handlers_property_error_uniqueness_for_64_filled_hashes() -> TestResult {
    let mut harness = build_sync_harness("p2p_75")?;
    let mut errors = BTreeSet::new();

    for seed in 0u8..64u8 {
        let err = unknown_fork_error(&mut harness.sync, filled_hash(seed))?;
        let inserted = errors.insert(err);

        assert!(inserted);
    }

    assert_eq!(errors.len(), 64usize);
    Ok(())
}

#[test]
fn p2p_76_002_sync_handlers_adversarial_unknown_fork_with_max_download_counters() -> TestResult {
    let mut harness = build_sync_harness("p2p_76")?;

    harness.sync.total_to_download = u64::MAX;
    harness.sync.downloaded = u64::MAX;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x76))?;

    assert_eq!(harness.sync.total_to_download, u64::MAX);
    assert_eq!(harness.sync.downloaded, u64::MAX);
    Ok(())
}

#[test]
fn p2p_77_002_sync_handlers_adversarial_unknown_fork_with_max_queue_indices() -> TestResult {
    let mut harness = build_sync_harness("p2p_77")?;
    let peer = test_peer_id();

    harness
        .sync
        .block_queue
        .push_back((peer, u64::MAX, u8::MAX));
    harness
        .sync
        .batch_queue
        .push_back((peer, u64::MAX, u8::MAX));

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x77))?;

    let (_, block_idx, block_retries) = harness
        .sync
        .block_queue
        .pop_front()
        .ok_or_else(|| "missing max block queue entry".to_string())?;
    let (_, batch_idx, batch_retries) = harness
        .sync
        .batch_queue
        .pop_front()
        .ok_or_else(|| "missing max batch queue entry".to_string())?;

    assert_eq!(block_idx, u64::MAX);
    assert_eq!(batch_idx, u64::MAX);
    assert_eq!(block_retries, u8::MAX);
    assert_eq!(batch_retries, u8::MAX);
    Ok(())
}

#[test]
fn p2p_78_002_sync_handlers_adversarial_unknown_fork_does_not_clear_pq_ready_set() -> TestResult {
    let mut harness = build_sync_harness("p2p_78")?;

    for _ in 0usize..100usize {
        harness.sync.mark_pq_ready(test_peer_id());
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x78))?;

    assert_eq!(harness.sync.pq_ready_peers.len(), 100usize);
    Ok(())
}

#[test]
fn p2p_79_002_sync_handlers_adversarial_unknown_fork_does_not_mutate_empty_pending_maps()
-> TestResult {
    let mut harness = build_sync_harness("p2p_79")?;

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x79))?;

    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    Ok(())
}

#[test]
fn p2p_80_002_sync_handlers_load_create_many_engines_and_handle_unknown_fork() -> TestResult {
    let mut built = 0usize;

    for index in 0usize..30usize {
        let mut harness = build_sync_harness(&format!("p2p_80_{index}"))?;
        let seed = u8::try_from(index).map_err(fmt_err)?;
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;

        assert_unknown_fork_error_shape(&err);

        built = built
            .checked_add(1usize)
            .ok_or_else(|| "engine build counter overflow".to_string())?;
    }

    assert_eq!(built, 30usize);
    Ok(())
}

#[test]
fn p2p_81_002_sync_handlers_load_one_engine_handles_512_unknown_forks() -> TestResult {
    let mut harness = build_sync_harness("p2p_81")?;
    let mut handled = 0usize;

    for round in 0usize..2usize {
        for seed in 0u8..=255u8 {
            let mut hash = patterned_hash(seed)?;
            hash[0] = hash[0].wrapping_add(u8::try_from(round).map_err(fmt_err)?);

            let err = unknown_fork_error(&mut harness.sync, hash)?;
            assert_unknown_fork_error_shape(&err);

            handled = handled
                .checked_add(1usize)
                .ok_or_else(|| "unknown fork load counter overflow".to_string())?;
        }
    }

    assert_eq!(handled, 512usize);
    assert!(!harness.sync.has_synced());
    Ok(())
}

#[test]
fn p2p_82_002_sync_handlers_load_unknown_forks_with_background_queue() -> TestResult {
    let mut harness = build_sync_harness("p2p_82")?;
    let peer = test_peer_id();

    for index in 0u64..64u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
    }

    for seed in 0u8..128u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);
    }

    assert_eq!(harness.sync.block_queue.len(), 64usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_83_002_sync_handlers_load_unknown_forks_with_pq_ready_peers() -> TestResult {
    let mut harness = build_sync_harness("p2p_83")?;

    for _ in 0usize..64usize {
        harness.sync.mark_pq_ready(test_peer_id());
    }

    for seed in 0u8..128u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 64usize);
    Ok(())
}

#[test]
fn p2p_84_002_sync_handlers_handle_fork_keeps_can_issue_pq_requests_true_when_empty() -> TestResult
{
    let mut harness = build_sync_harness("p2p_84")?;

    assert!(harness.sync.can_issue_more_pq_requests());

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x84))?;

    assert!(harness.sync.can_issue_more_pq_requests());
    Ok(())
}

#[test]
fn p2p_85_002_sync_handlers_handle_fork_keeps_last_synced_pointers_none_after_many_calls()
-> TestResult {
    let mut harness = build_sync_harness("p2p_85")?;

    for seed in 0u8..64u8 {
        let _err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
    }

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_86_002_sync_handlers_handle_fork_after_update_sync_pointers_keeps_none_without_blocks()
-> TestResult {
    let mut harness = build_sync_harness("p2p_86")?;

    harness.sync.update_sync_pointers();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x86))?;

    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    Ok(())
}

#[test]
fn p2p_87_002_sync_handlers_handle_fork_after_update_sync_state_keeps_unsynced_without_blocks()
-> TestResult {
    let mut harness = build_sync_harness("p2p_87")?;

    harness.sync.update_sync_state();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x87))?;

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}

#[test]
fn p2p_88_002_sync_handlers_handle_fork_does_not_change_expected_genesis_none() -> TestResult {
    let data_dir = unique_data_dir("p2p_88");
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

    let mut sync = P2pSync::new(
        chain,
        Arc::clone(&db),
        mempool,
        peerbook,
        data_dir.join(GlobalConfiguration::PEER_LIST_DIR),
        None,
        reorg_manager,
    );

    let _err = unknown_fork_error(&mut sync, filled_hash(0x88))?;

    assert!(sync.expected_genesis_hash.is_none());
    Ok(())
}

#[test]
fn p2p_89_002_sync_handlers_handle_fork_does_not_change_expected_genesis_malformed() -> TestResult {
    let data_dir = unique_data_dir("p2p_89");
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

    let mut sync = P2pSync::new(
        chain,
        Arc::clone(&db),
        mempool,
        peerbook,
        data_dir.join(GlobalConfiguration::PEER_LIST_DIR),
        Some("malformed-genesis-hash".to_string()),
        reorg_manager,
    );

    let _err = unknown_fork_error(&mut sync, filled_hash(0x89))?;

    assert_eq!(
        sync.expected_genesis_hash.as_deref(),
        Some("malformed-genesis-hash")
    );
    Ok(())
}

#[test]
fn p2p_90_002_sync_handlers_handle_fork_preserves_arc_db_liveness() -> TestResult {
    let mut harness = build_sync_harness("p2p_90")?;

    let before = Arc::strong_count(&harness.sync.db);
    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x90))?;
    let after = Arc::strong_count(&harness.sync.db);

    assert_eq!(after, before);
    assert!(after >= 1usize);
    Ok(())
}

#[test]
fn p2p_91_002_sync_handlers_handle_fork_preserves_arc_mempool_liveness() -> TestResult {
    let mut harness = build_sync_harness("p2p_91")?;

    let before = Arc::strong_count(&harness.sync.mempool);
    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x91))?;
    let after = Arc::strong_count(&harness.sync.mempool);

    assert_eq!(after, before);
    assert!(after >= 1usize);
    Ok(())
}

#[test]
fn p2p_92_002_sync_handlers_handle_fork_after_clone_db_arc_preserves_clone() -> TestResult {
    let mut harness = build_sync_harness("p2p_92")?;
    let cloned_db = Arc::clone(&harness.sync.db);
    let before = Arc::strong_count(&harness.sync.db);

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x92))?;

    assert_eq!(Arc::strong_count(&harness.sync.db), before);
    assert!(Arc::strong_count(&cloned_db) >= 2usize);
    Ok(())
}

#[test]
fn p2p_93_002_sync_handlers_handle_fork_after_clone_mempool_arc_preserves_clone() -> TestResult {
    let mut harness = build_sync_harness("p2p_93")?;
    let cloned_mempool = Arc::clone(&harness.sync.mempool);
    let before = Arc::strong_count(&harness.sync.mempool);

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x93))?;

    assert_eq!(Arc::strong_count(&harness.sync.mempool), before);
    assert!(Arc::strong_count(&cloned_mempool) >= 2usize);
    Ok(())
}

#[test]
fn p2p_94_002_sync_handlers_handle_fork_after_clearing_pq_ready_set() -> TestResult {
    let mut harness = build_sync_harness("p2p_94")?;

    for _ in 0usize..20usize {
        harness.sync.mark_pq_ready(test_peer_id());
    }

    harness.sync.pq_ready_peers.clear();

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x94))?;

    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_95_002_sync_handlers_handle_fork_after_queue_pop_to_empty() -> TestResult {
    let mut harness = build_sync_harness("p2p_95")?;
    let peer = test_peer_id();

    for index in 0u64..20u64 {
        harness.sync.block_queue.push_back((peer, index, 3u8));
        harness.sync.batch_queue.push_back((peer, index, 2u8));
    }

    while harness.sync.block_queue.pop_front().is_some() {}
    while harness.sync.batch_queue.pop_front().is_some() {}

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x95))?;

    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_96_002_sync_handlers_handle_fork_with_interleaved_state_mutations() -> TestResult {
    let mut harness = build_sync_harness("p2p_96")?;
    let queue_peer = test_peer_id();

    for seed in 0u8..30u8 {
        harness.sync.mark_pq_ready(test_peer_id());
        harness
            .sync
            .block_queue
            .push_back((queue_peer, u64::from(seed), 3u8));

        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);
    }

    assert_eq!(harness.sync.pq_ready_peers.len(), 30usize);
    assert_eq!(harness.sync.block_queue.len(), 30usize);
    assert!(harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_97_002_sync_handlers_handle_fork_stress_then_clear_state() -> TestResult {
    let mut harness = build_sync_harness("p2p_97")?;
    let queue_peer = test_peer_id();

    for index in 0u64..100u64 {
        harness.sync.mark_pq_ready(test_peer_id());
        harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
    }

    let _err = unknown_fork_error(&mut harness.sync, filled_hash(0x97))?;

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();
    harness.sync.pq_ready_peers.clear();

    assert!(!harness.sync.has_background_sync_work());
    assert!(harness.sync.pq_ready_peers.is_empty());
    Ok(())
}

#[test]
fn p2p_98_002_sync_handlers_handle_fork_end_to_end_vector_state_preservation() -> TestResult {
    let mut harness = build_sync_harness("p2p_98")?;
    let queue_peer = test_peer_id();
    let ready_peer = test_peer_id();

    harness.sync.total_to_download = 800u64;
    harness.sync.downloaded = 200u64;
    harness.sync.tried_genesis = true;
    harness.sync.mark_pq_ready(ready_peer);

    for index in 0u64..16u64 {
        harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
    }

    let _err = unknown_fork_error(&mut harness.sync, patterned_hash(0x98)?)?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
    assert!(harness.sync.tried_genesis);
    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert_eq!(harness.sync.block_queue.len(), 16usize);
    assert_eq!(harness.sync.batch_queue.len(), 16usize);
    Ok(())
}

#[test]
fn p2p_99_002_sync_handlers_handle_fork_extreme_hash_patterns() -> TestResult {
    let mut harness = build_sync_harness("p2p_99")?;

    let mut alternating = [0u8; 64];
    for (index, slot) in alternating.iter_mut().enumerate() {
        *slot = if index % 2usize == 0usize { 0xaa } else { 0x55 };
    }

    let mut ascending = [0u8; 64];
    for (index, slot) in ascending.iter_mut().enumerate() {
        *slot = u8::try_from(index).map_err(fmt_err)?;
    }

    let mut descending = [0u8; 64];
    for (index, slot) in descending.iter_mut().enumerate() {
        let index_byte = u8::try_from(index).map_err(fmt_err)?;
        *slot = 63u8.saturating_sub(index_byte);
    }

    for hash in [alternating, ascending, descending] {
        let err = unknown_fork_error(&mut harness.sync, hash)?;
        assert_unknown_fork_error_shape(&err);
    }

    Ok(())
}

#[test]
fn p2p_100_002_sync_handlers_final_public_handler_stress_state_invariants() -> TestResult {
    let mut harness = build_sync_harness("p2p_100")?;
    let queue_peer = test_peer_id();

    harness.sync.total_to_download = 1_000u64;
    harness.sync.downloaded = 500u64;

    for index in 0u64..100u64 {
        harness.sync.mark_pq_ready(test_peer_id());
        harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
    }

    for seed in 0u8..=127u8 {
        let err = unknown_fork_error(&mut harness.sync, patterned_hash(seed)?)?;
        assert_unknown_fork_error_shape(&err);
    }

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "50.00");
    assert_eq!(harness.sync.pq_ready_peers.len(), 100usize);
    assert_eq!(harness.sync.block_queue.len(), 100usize);
    assert_eq!(harness.sync.batch_queue.len(), 100usize);
    assert!(harness.sync.has_background_sync_work());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    Ok(())
}
