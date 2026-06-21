#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{PeerId, identity};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::p2p_011_peerbook::PeerBook,
    reorganization::{
        reorg_001_block_index::ReorgBlockIndex, reorg_002_chain_view::ReorgChainView,
        reorg_004_batch_index::ReorgBatchIndex, reorg_006_manager::ReorgManager,
    },
    runtime::{
        p2p_001_sync_builders::{P2pSync, REMZAR_HASH_BYTES_LEN, RemzarHashBytes},
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicSyncSnapshot {
    has_synced: bool,
    is_syncing: bool,
    sync_percent: String,
    last_synced_index: Option<u64>,
    last_synced_hash: Option<RemzarHashBytes>,
    total_to_download: u64,
    downloaded: u64,
    block_queue_len: usize,
    batch_queue_len: usize,
    pq_ready_len: usize,
    has_background_sync_work: bool,
    expected_genesis_hash: Option<String>,
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
        "remzar_e2e_p2p_002_sync_handlers_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn test_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
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

fn snapshot(sync: &P2pSync) -> PublicSyncSnapshot {
    PublicSyncSnapshot {
        has_synced: sync.has_synced(),
        is_syncing: sync.is_syncing(),
        sync_percent: format!("{:.2}", sync.sync_percent()),
        last_synced_index: sync.last_synced_index(),
        last_synced_hash: sync.last_synced_hash(),
        total_to_download: sync.total_to_download,
        downloaded: sync.downloaded,
        block_queue_len: sync.block_queue.len(),
        batch_queue_len: sync.batch_queue.len(),
        pq_ready_len: sync.pq_ready_peers.len(),
        has_background_sync_work: sync.has_background_sync_work(),
        expected_genesis_hash: sync.expected_genesis_hash.clone(),
    }
}

fn filled_hash(byte: u8) -> RemzarHashBytes {
    [byte; REMZAR_HASH_BYTES_LEN]
}

fn patterned_hash(seed: u8) -> RemzarHashBytes {
    let mut out = [0u8; REMZAR_HASH_BYTES_LEN];

    for (idx, byte) in out.iter_mut().enumerate() {
        let i = u8::try_from(idx).unwrap_or(0);
        *byte = seed
            .wrapping_add(i.wrapping_mul(31))
            .wrapping_add(7)
            .rotate_left(u32::from(i % 7));
    }

    out
}

fn reverse_patterned_hash(seed: u8) -> RemzarHashBytes {
    let mut out = patterned_hash(seed);
    out.reverse();
    out
}

fn alternating_hash(a: u8, b: u8) -> RemzarHashBytes {
    let mut out = [0u8; REMZAR_HASH_BYTES_LEN];

    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = if idx % 2 == 0 { a } else { b };
    }

    out
}

fn first_64_values_hash() -> RemzarHashBytes {
    let mut out = [0u8; REMZAR_HASH_BYTES_LEN];

    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = u8::try_from(idx).unwrap_or(0);
    }

    out
}

fn genesis_hash_bytes() -> TestResult<RemzarHashBytes> {
    let decoded = hex::decode(GlobalConfiguration::GENESIS_HASH_HEX).map_err(fmt_err)?;

    if decoded.len() != REMZAR_HASH_BYTES_LEN {
        return Err(format!(
            "GENESIS_HASH_HEX decoded to {} bytes, expected {}",
            decoded.len(),
            REMZAR_HASH_BYTES_LEN
        ));
    }

    let mut out = [0u8; REMZAR_HASH_BYTES_LEN];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn assert_unknown_fork_error(sync: &mut P2pSync, hash: RemzarHashBytes) -> String {
    let err = sync
        .handle_fork(hash)
        .expect_err("unknown hash must return Err from handle_fork");

    assert!(
        err.contains("handle_fork"),
        "error should identify handle_fork path, got: {err}"
    );

    assert!(
        err.contains("unknown block hash"),
        "error should identify unknown block hash, got: {err}"
    );

    err
}

fn assert_corrupt_block_index_rejected(
    harness: &SyncHarness,
    hash: RemzarHashBytes,
    bytes: &[u8],
) -> String {
    let err = harness
        .sync
        .db
        .index_block_by_hash(&hash, bytes)
        .expect_err("corrupt block bytes must be rejected before hash indexing");

    let text = format!("{err:?}");

    assert!(
        text.contains("SerializationError") || text.contains("ValidationError"),
        "corrupt block index rejection should be serialization/validation related, got: {text}"
    );

    text
}

fn assert_no_known_block_or_batch(harness: &SyncHarness, hash: RemzarHashBytes) -> TestResult {
    let block_index = ReorgBlockIndex::new(Arc::clone(&harness.sync.db));
    let batch_index = ReorgBatchIndex::new(Arc::clone(&harness.sync.db));

    assert!(!block_index.has_block(&hash));
    assert!(block_index.get_meta(&hash).map_err(fmt_err)?.is_none());
    assert!(
        batch_index
            .get_batch_by_block_hash(&hash)
            .map_err(fmt_err)?
            .is_none()
    );

    Ok(())
}

fn assert_empty_chain_view(harness: &SyncHarness) -> TestResult {
    let chain_view = ReorgChainView::new(Arc::clone(&harness.sync.db));

    assert!(chain_view.get_tip().map_err(fmt_err)?.is_none());
    assert!(chain_view.get_tip_hash().map_err(fmt_err)?.is_none());
    assert!(chain_view.get_tip_height().map_err(fmt_err)?.is_none());
    assert!(
        chain_view
            .get_tip_with_legacy_fallback()
            .map_err(fmt_err)?
            .is_none()
    );

    Ok(())
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

#[tokio::test]
async fn e2e_01_real_sync_handler_boots_with_empty_public_fork_surface() -> TestResult {
    let harness = build_sync_harness("e2e_01")?;

    assert!(harness.data_dir.exists());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    assert!(harness.sync.last_synced_index().is_none());
    assert!(harness.sync.last_synced_hash().is_none());
    assert_empty_chain_view(&harness)?;

    Ok(())
}

#[tokio::test]
async fn e2e_02_handle_fork_rejects_unknown_zero_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_02")?;
    let before = snapshot(&harness.sync);

    let hash = filled_hash(0x00);
    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_03_handle_fork_rejects_unknown_all_ones_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_03")?;
    let before = snapshot(&harness.sync);

    let hash = filled_hash(0x01);
    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_04_handle_fork_rejects_unknown_genesis_hash_when_block_not_stored() -> TestResult {
    let mut harness = build_sync_harness("e2e_04")?;
    let before = snapshot(&harness.sync);

    let hash = genesis_hash_bytes()?;
    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_05_handle_fork_rejects_unknown_patterned_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_05")?;
    let before = snapshot(&harness.sync);

    let hash = patterned_hash(0x22);
    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_06_handle_fork_rejects_unknown_max_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_06")?;
    let before = snapshot(&harness.sync);

    let hash = filled_hash(0xff);
    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_07_handle_fork_rejects_many_distinct_unknown_hashes() -> TestResult {
    let mut harness = build_sync_harness("e2e_07")?;
    let before = snapshot(&harness.sync);

    for seed in 0u8..16u8 {
        let hash = patterned_hash(seed);
        let _ = assert_unknown_fork_error(&mut harness.sync, hash);
    }

    assert_eq!(snapshot(&harness.sync), before);
    assert_empty_chain_view(&harness)?;

    Ok(())
}

#[tokio::test]
async fn e2e_08_repeated_same_unknown_fork_is_idempotent() -> TestResult {
    let mut harness = build_sync_harness("e2e_08")?;
    let before = snapshot(&harness.sync);
    let hash = patterned_hash(0x33);

    for _ in 0usize..20usize {
        let _ = assert_unknown_fork_error(&mut harness.sync, hash);
        assert_eq!(snapshot(&harness.sync), before);
    }

    Ok(())
}

#[tokio::test]
async fn e2e_09_unknown_fork_error_completes_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_09")?;
    let hash = patterned_hash(0x44);

    timeout(Duration::from_millis(250), async {
        let _ = assert_unknown_fork_error(&mut harness.sync, hash);
    })
    .await
    .map_err(|_| "handle_fork unknown hash timed out".to_string())?;

    Ok(())
}

#[tokio::test]
async fn e2e_10_unknown_fork_error_message_mentions_handler_path() -> TestResult {
    let mut harness = build_sync_harness("e2e_10")?;
    let err = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x55));

    assert!(err.contains("handle_fork"));
    assert!(err.contains("unknown block hash"));

    Ok(())
}

#[tokio::test]
async fn e2e_11_unknown_fork_error_message_mentions_unknown_block_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_11")?;
    let err = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x66));

    assert!(err.contains("unknown block hash"));

    Ok(())
}

#[tokio::test]
async fn e2e_12_unknown_fork_does_not_create_block_index_entry() -> TestResult {
    let mut harness = build_sync_harness("e2e_12")?;
    let hash = patterned_hash(0x77);

    let block_index = ReorgBlockIndex::new(Arc::clone(&harness.sync.db));
    assert!(!block_index.has_block(&hash));

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert!(!block_index.has_block(&hash));
    assert!(block_index.get_meta(&hash).map_err(fmt_err)?.is_none());

    Ok(())
}

#[tokio::test]
async fn e2e_13_unknown_fork_does_not_create_reorg_metadata() -> TestResult {
    let mut harness = build_sync_harness("e2e_13")?;
    let hash = patterned_hash(0x88);

    let block_index = ReorgBlockIndex::new(Arc::clone(&harness.sync.db));

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert!(block_index.get_meta(&hash).map_err(fmt_err)?.is_none());

    Ok(())
}

#[tokio::test]
async fn e2e_14_unknown_fork_does_not_create_batch_by_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_14")?;
    let hash = patterned_hash(0x99);

    let batch_index = ReorgBatchIndex::new(Arc::clone(&harness.sync.db));

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert!(
        batch_index
            .get_batch_by_block_hash(&hash)
            .map_err(fmt_err)?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn e2e_15_unknown_fork_does_not_create_canonical_tip() -> TestResult {
    let mut harness = build_sync_harness("e2e_15")?;
    let hash = patterned_hash(0xaa);

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_empty_chain_view(&harness)?;

    Ok(())
}

#[tokio::test]
async fn e2e_16_unknown_fork_does_not_create_canonical_height_mapping() -> TestResult {
    let mut harness = build_sync_harness("e2e_16")?;
    let hash = patterned_hash(0xbb);
    let chain_view = ReorgChainView::new(Arc::clone(&harness.sync.db));

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    for height in 0u64..8u64 {
        assert!(
            chain_view
                .get_hash_at_height(height)
                .map_err(fmt_err)?
                .is_none()
        );
    }

    Ok(())
}

#[tokio::test]
async fn e2e_17_unknown_fork_preserves_sync_download_counters() -> TestResult {
    let mut harness = build_sync_harness("e2e_17")?;

    harness.sync.total_to_download = 100;
    harness.sync.downloaded = 25;

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0xcc));

    assert_eq!(snapshot(&harness.sync), before);
    assert_eq!(harness.sync.total_to_download, 100);
    assert_eq!(harness.sync.downloaded, 25);

    Ok(())
}

#[tokio::test]
async fn e2e_18_unknown_fork_preserves_last_synced_pointers() -> TestResult {
    let mut harness = build_sync_harness("e2e_18")?;

    harness.sync.update_sync_pointers();

    let before_index = harness.sync.last_synced_index();
    let before_hash = harness.sync.last_synced_hash();

    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0xdd));

    assert_eq!(harness.sync.last_synced_index(), before_index);
    assert_eq!(harness.sync.last_synced_hash(), before_hash);

    Ok(())
}

#[tokio::test]
async fn e2e_19_unknown_fork_preserves_single_pq_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_19")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0xee));

    assert_eq!(snapshot(&harness.sync), before);
    assert!(harness.sync.is_pq_ready(&peer));

    Ok(())
}

#[tokio::test]
async fn e2e_20_unknown_fork_preserves_many_pq_ready_peers() -> TestResult {
    let mut harness = build_sync_harness("e2e_20")?;
    let mut peers = Vec::new();

    for _ in 0usize..32usize {
        let peer = test_peer_id();
        harness.sync.mark_pq_ready(peer);
        peers.push(peer);
    }

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0xef));

    assert_eq!(snapshot(&harness.sync), before);

    for peer in peers {
        assert!(harness.sync.is_pq_ready(&peer));
    }

    Ok(())
}

#[tokio::test]
async fn e2e_21_unknown_fork_preserves_block_queue_backlog() -> TestResult {
    let mut harness = build_sync_harness("e2e_21")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 10, 16, 3);

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x21));

    assert_eq!(snapshot(&harness.sync), before);
    assert_eq!(harness.sync.block_queue.len(), 16);
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_22_unknown_fork_preserves_batch_queue_backlog() -> TestResult {
    let mut harness = build_sync_harness("e2e_22")?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 20, 16, 2);

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x22));

    assert_eq!(snapshot(&harness.sync), before);
    assert_eq!(harness.sync.batch_queue.len(), 16);
    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_23_unknown_fork_preserves_mixed_block_and_batch_backlog() -> TestResult {
    let mut harness = build_sync_harness("e2e_23")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 30, 12, 3);
    push_batch_backlog(&mut harness.sync, peer, 40, 12, 2);

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x23));

    assert_eq!(snapshot(&harness.sync), before);
    assert!(harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_24_unknown_fork_preserves_no_background_work_when_queues_are_empty() -> TestResult {
    let mut harness = build_sync_harness("e2e_24")?;

    assert!(!harness.sync.has_background_sync_work());

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x24));

    assert_eq!(snapshot(&harness.sync), before);
    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_25_unknown_fork_preserves_expected_genesis_hash_configuration() -> TestResult {
    let mut harness = build_sync_harness("e2e_25")?;

    let before = harness.sync.expected_genesis_hash.clone();
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x25));

    assert_eq!(harness.sync.expected_genesis_hash, before);
    assert_eq!(
        harness.sync.expected_genesis_hash.as_deref(),
        Some(GlobalConfiguration::GENESIS_HASH_HEX)
    );

    Ok(())
}

#[tokio::test]
async fn e2e_26_unknown_fork_preserves_manually_synced_flag() -> TestResult {
    let mut harness = build_sync_harness("e2e_26")?;

    harness.sync.has_synced = true;

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x26));

    assert_eq!(snapshot(&harness.sync), before);
    assert!(harness.sync.has_synced());

    Ok(())
}

#[tokio::test]
async fn e2e_27_unknown_fork_preserves_fractional_sync_percent() -> TestResult {
    let mut harness = build_sync_harness("e2e_27")?;

    harness.sync.total_to_download = 400;
    harness.sync.downloaded = 125;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "31.25");

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x27));

    assert_eq!(snapshot(&harness.sync), before);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "31.25");

    Ok(())
}

#[tokio::test]
async fn e2e_28_unknown_fork_preserves_capped_sync_percent() -> TestResult {
    let mut harness = build_sync_harness("e2e_28")?;

    harness.sync.total_to_download = 5;
    harness.sync.downloaded = 999;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x28));

    assert_eq!(snapshot(&harness.sync), before);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "100.00");

    Ok(())
}

#[tokio::test]
async fn e2e_29_unknown_fork_after_update_sync_state_preserves_public_state() -> TestResult {
    let mut harness = build_sync_harness("e2e_29")?;

    harness.sync.update_sync_state();

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x29));

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_30_unknown_fork_after_update_sync_pointers_preserves_public_state() -> TestResult {
    let mut harness = build_sync_harness("e2e_30")?;

    harness.sync.update_sync_pointers();

    let before = snapshot(&harness.sync);
    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x30));

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_31_corrupt_hash_indexed_bytes_are_rejected_before_handler() -> TestResult {
    let mut harness = build_sync_harness("e2e_31")?;
    let hash = patterned_hash(0x31);

    let before = snapshot(&harness.sync);
    let err = assert_corrupt_block_index_rejected(&harness, hash, b"not a valid serialized block");

    assert!(
        err.contains("Block data too short")
            || err.contains("Deserialize block")
            || err.contains("SerializationError"),
        "unexpected corrupt index rejection: {err}"
    );

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_32_corrupt_hash_index_rejection_does_not_clear_existing_backlog() -> TestResult {
    let mut harness = build_sync_harness("e2e_32")?;
    let hash = patterned_hash(0x32);
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 1, 8, 3);
    push_batch_backlog(&mut harness.sync, peer, 1, 8, 3);

    let before = snapshot(&harness.sync);
    let _ = assert_corrupt_block_index_rejected(&harness, hash, b"\x01\x02\x03");

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_eq!(harness.sync.block_queue.len(), 8);
    assert_eq!(harness.sync.batch_queue.len(), 8);

    Ok(())
}

#[tokio::test]
async fn e2e_33_many_corrupt_hash_index_attempts_are_rejected_without_poisoning_handler_state()
-> TestResult {
    let mut harness = build_sync_harness("e2e_33")?;
    let before = snapshot(&harness.sync);

    for seed in 0u8..24u8 {
        let hash = patterned_hash(seed.wrapping_add(0x33));
        let bytes = vec![seed, seed.wrapping_add(1)];

        let _ = assert_corrupt_block_index_rejected(&harness, hash, &bytes);
        let _ = assert_unknown_fork_error(&mut harness.sync, hash);
    }

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_34_empty_hash_indexed_bytes_are_rejected_before_handler() -> TestResult {
    let mut harness = build_sync_harness("e2e_34")?;
    let hash = patterned_hash(0x34);

    let before = snapshot(&harness.sync);
    let err = assert_corrupt_block_index_rejected(&harness, hash, &[]);

    assert!(
        err.contains("Block data too short") || err.contains("SerializationError"),
        "empty bytes should be rejected as too short/corrupt, got: {err}"
    );

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_35_large_invalid_hash_indexed_bytes_are_rejected_before_handler() -> TestResult {
    let mut harness = build_sync_harness("e2e_35")?;
    let hash = patterned_hash(0x35);
    let junk = vec![0x5au8; 4096];

    let before = snapshot(&harness.sync);
    let err = assert_corrupt_block_index_rejected(&harness, hash, &junk);

    assert!(
        err.contains("Deserialize block")
            || err.contains("SerializationError")
            || err.contains("ValidationError"),
        "large invalid bytes should fail validation/deserialization, got: {err}"
    );

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    assert_eq!(snapshot(&harness.sync), before);
    assert_no_known_block_or_batch(&harness, hash)?;

    Ok(())
}

#[tokio::test]
async fn e2e_36_repeated_corrupt_index_rejections_complete_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_36")?;
    let before = snapshot(&harness.sync);

    timeout(Duration::from_millis(1_000), async {
        for seed in 0u8..32u8 {
            let hash = patterned_hash(seed.wrapping_add(0x36));
            let bytes = vec![seed; 16];

            let _ = assert_corrupt_block_index_rejected(&harness, hash, &bytes);
            let _ = assert_unknown_fork_error(&mut harness.sync, hash);
        }

        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "repeated corrupt index rejection flow timed out".to_string())??;

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_37_two_real_sync_engines_keep_unknown_fork_errors_isolated() -> TestResult {
    let mut first = build_sync_harness("e2e_37_first")?;
    let mut second = build_sync_harness("e2e_37_second")?;

    let first_before = snapshot(&first.sync);
    let second_before = snapshot(&second.sync);

    let _ = assert_unknown_fork_error(&mut first.sync, patterned_hash(0x37));

    assert_eq!(snapshot(&first.sync), first_before);
    assert_eq!(snapshot(&second.sync), second_before);

    let _ = assert_unknown_fork_error(&mut second.sync, patterned_hash(0x38));

    assert_eq!(snapshot(&first.sync), first_before);
    assert_eq!(snapshot(&second.sync), second_before);

    Ok(())
}

#[tokio::test]
async fn e2e_38_two_real_sync_engines_preserve_independent_pq_state_after_errors() -> TestResult {
    let mut first = build_sync_harness("e2e_38_first")?;
    let mut second = build_sync_harness("e2e_38_second")?;

    let first_peer = test_peer_id();
    let second_peer = test_peer_id();

    first.sync.mark_pq_ready(first_peer);
    second.sync.mark_pq_ready(second_peer);

    let _ = assert_unknown_fork_error(&mut first.sync, patterned_hash(0x39));
    let _ = assert_unknown_fork_error(&mut second.sync, patterned_hash(0x3a));

    assert!(first.sync.is_pq_ready(&first_peer));
    assert!(!first.sync.is_pq_ready(&second_peer));

    assert!(second.sync.is_pq_ready(&second_peer));
    assert!(!second.sync.is_pq_ready(&first_peer));

    Ok(())
}

#[tokio::test]
async fn e2e_39_same_unknown_hash_on_two_engines_returns_error_on_both() -> TestResult {
    let mut first = build_sync_harness("e2e_39_first")?;
    let mut second = build_sync_harness("e2e_39_second")?;
    let hash = patterned_hash(0x3b);

    let err_first = assert_unknown_fork_error(&mut first.sync, hash);
    let err_second = assert_unknown_fork_error(&mut second.sync, hash);

    assert!(err_first.contains("unknown block hash"));
    assert!(err_second.contains("unknown block hash"));

    Ok(())
}

#[tokio::test]
async fn e2e_40_burst_of_unknown_forks_completes_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_40")?;
    let before = snapshot(&harness.sync);

    timeout(Duration::from_millis(1_000), async {
        for seed in 0u8..64u8 {
            let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(seed));
        }
    })
    .await
    .map_err(|_| "burst unknown fork handling timed out".to_string())?;

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_41_handler_hash_width_is_always_sixty_four_bytes() -> TestResult {
    assert_eq!(REMZAR_HASH_BYTES_LEN, 64);

    for seed in 0u8..20u8 {
        assert_eq!(patterned_hash(seed).len(), REMZAR_HASH_BYTES_LEN);
        assert_eq!(filled_hash(seed).len(), REMZAR_HASH_BYTES_LEN);
        assert_eq!(reverse_patterned_hash(seed).len(), REMZAR_HASH_BYTES_LEN);
    }

    Ok(())
}

#[tokio::test]
async fn e2e_42_mutating_caller_hash_copy_does_not_change_prior_handler_result() -> TestResult {
    let mut harness = build_sync_harness("e2e_42")?;
    let original_hash = patterned_hash(0x42);
    let mut mutated_hash = original_hash;

    let before = snapshot(&harness.sync);
    let original_err = assert_unknown_fork_error(&mut harness.sync, original_hash);

    mutated_hash[0] = mutated_hash[0].wrapping_add(1);
    mutated_hash[63] = mutated_hash[63].wrapping_add(2);

    let mutated_err = assert_unknown_fork_error(&mut harness.sync, mutated_hash);

    assert!(original_err.contains("unknown block hash"));
    assert!(mutated_err.contains("unknown block hash"));
    assert_ne!(original_hash, mutated_hash);
    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_43_distinct_unknown_hashes_deduplicate_in_ordered_collection() -> TestResult {
    let mut set = BTreeSet::<RemzarHashBytes>::new();

    for seed in [4u8, 1, 4, 3, 2, 3, 9, 1] {
        set.insert(patterned_hash(seed));
    }

    assert_eq!(set.len(), 5);

    let mut harness = build_sync_harness("e2e_43")?;
    let before = snapshot(&harness.sync);

    for hash in set {
        let _ = assert_unknown_fork_error(&mut harness.sync, hash);
    }

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_44_reversed_pattern_hash_is_rejected_without_state_mutation() -> TestResult {
    let mut harness = build_sync_harness("e2e_44")?;
    let before = snapshot(&harness.sync);

    let _ = assert_unknown_fork_error(&mut harness.sync, reverse_patterned_hash(0x44));

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_45_alternating_hash_is_rejected_without_state_mutation() -> TestResult {
    let mut harness = build_sync_harness("e2e_45")?;
    let before = snapshot(&harness.sync);

    let _ = assert_unknown_fork_error(&mut harness.sync, alternating_hash(0xaa, 0x55));

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_46_first_64_byte_values_hash_is_rejected_without_state_mutation() -> TestResult {
    let mut harness = build_sync_harness("e2e_46")?;
    let before = snapshot(&harness.sync);

    let _ = assert_unknown_fork_error(&mut harness.sync, first_64_values_hash());

    assert_eq!(snapshot(&harness.sync), before);

    Ok(())
}

#[tokio::test]
async fn e2e_47_unknown_fork_does_not_create_batch_projection_for_same_height() -> TestResult {
    let mut harness = build_sync_harness("e2e_47")?;
    let hash = patterned_hash(0x47);
    let batch_index = ReorgBatchIndex::new(Arc::clone(&harness.sync.db));

    let _ = assert_unknown_fork_error(&mut harness.sync, hash);

    for height in 0u64..5u64 {
        assert!(
            batch_index
                .get_canonical_batch_at_height(height)
                .map_err(fmt_err)?
                .is_none()
        );
    }

    Ok(())
}

#[tokio::test]
async fn e2e_48_update_sync_state_after_unknown_fork_keeps_engine_safely_syncing_without_genesis()
-> TestResult {
    let mut harness = build_sync_harness("e2e_48")?;

    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x48));

    harness.sync.update_sync_state();

    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());

    Ok(())
}

#[tokio::test]
async fn e2e_49_peer_state_can_still_be_updated_after_unknown_fork_error() -> TestResult {
    let mut harness = build_sync_harness("e2e_49")?;
    let peer = test_peer_id();

    let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(0x49));

    harness.sync.mark_pq_ready(peer);
    assert!(harness.sync.is_pq_ready(&peer));

    sleep(Duration::from_millis(5)).await;

    harness.sync.clear_pq_peer_state(&peer);
    assert!(!harness.sync.is_pq_ready(&peer));

    Ok(())
}

#[tokio::test]
async fn e2e_50_full_public_handler_lifecycle_unknown_forks_backlog_cleanup_and_recovery()
-> TestResult {
    let mut harness = build_sync_harness("e2e_50")?;

    let first_peer = test_peer_id();
    let second_peer = test_peer_id();

    harness.sync.mark_pq_ready(first_peer);
    harness.sync.mark_pq_ready(second_peer);

    push_block_backlog(&mut harness.sync, first_peer, 0, 10, 3);
    push_batch_backlog(&mut harness.sync, second_peer, 100, 10, 2);

    assert!(harness.sync.has_background_sync_work());
    assert!(harness.sync.is_pq_ready(&first_peer));
    assert!(harness.sync.is_pq_ready(&second_peer));

    for seed in 0u8..10u8 {
        let _ = assert_unknown_fork_error(&mut harness.sync, patterned_hash(seed.wrapping_add(50)));
    }

    assert!(harness.sync.has_background_sync_work());
    assert!(harness.sync.is_pq_ready(&first_peer));
    assert!(harness.sync.is_pq_ready(&second_peer));
    assert_eq!(harness.sync.block_queue.len(), 10);
    assert_eq!(harness.sync.batch_queue.len(), 10);

    harness.sync.block_queue.clear();
    harness.sync.batch_queue.clear();
    harness.sync.clear_pq_peer_state(&first_peer);
    harness.sync.clear_pq_peer_state(&second_peer);

    harness.sync.update_sync_state();

    assert!(!harness.sync.has_background_sync_work());
    assert!(!harness.sync.is_pq_ready(&first_peer));
    assert!(!harness.sync.is_pq_ready(&second_peer));
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());

    Ok(())
}
