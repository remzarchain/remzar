#![allow(clippy::too_many_lines)]

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::{BlockStore, Mode, RockDBManager};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), Box<dyn Error>>;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestDb {
    manager: Option<RockDBManager>,
    root: PathBuf,
}

impl TestDb {
    fn manager(&self) -> Result<&RockDBManager, Box<dyn Error>> {
        self.manager
            .as_ref()
            .ok_or_else(|| boxed_error("test database manager is not available"))
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        drop(self.manager.take());

        if let Err(_cleanup_error) = std::fs::remove_dir_all(&self.root) {
            // Best-effort cleanup only. Tests must not fail during Drop.
        }
    }
}

fn boxed_error(message: &str) -> Box<dyn Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        message.to_owned(),
    ))
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_rocksdb_005_manager_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> Result<String, Box<dyn Error>> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn node_opts(root: &Path) -> Result<NodeOpts, Box<dyn Error>> {
    Ok(NodeOpts {
        identity_file: path_to_string(&root.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "error".to_owned(),
        data_dir: path_to_string(root)?,
        wallet_address: wallet(1),
        founder: false,
    })
}

fn new_blockchain_db(label: &str) -> Result<TestDb, Box<dyn Error>> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path)?;

    let manager = RockDBManager::new_blockchain(&opts, &blockchain_path_string)?;

    Ok(TestDb {
        manager: Some(manager),
        root,
    })
}

fn new_cli_db(label: &str) -> Result<TestDb, Box<dyn Error>> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let manager = RockDBManager::new(&opts)?;

    Ok(TestDb {
        manager: Some(manager),
        root,
    })
}

fn new_log_db(label: &str) -> Result<TestDb, Box<dyn Error>> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let log_path = root.join(GlobalConfiguration::LOG_DATABASE_DIR);
    let log_path_string = path_to_string(&log_path)?;
    let manager = RockDBManager::new_log(&opts, &log_path_string)?;

    Ok(TestDb {
        manager: Some(manager),
        root,
    })
}

fn fixed_hash(seed: u8) -> Hash {
    let mut out = [seed; 64];
    if seed == 0 {
        out[0] = 1;
    }
    out
}

fn test_metadata(index: u64, previous_hash: Hash) -> BlockMetadata {
    let timestamp = 1_800_000_000u64.saturating_add(index);
    let seed = u8::try_from(index.saturating_add(1).rem_euclid(251)).unwrap_or(1);
    let merkle_root = fixed_hash(seed);

    let mut guardian_signature = [0u8; GlobalConfiguration::GUARDIAN_SIG_LEN];
    if index > 0 {
        let sig_seed = u8::try_from(index.rem_euclid(251))
            .unwrap_or(1)
            .saturating_add(1);
        guardian_signature.fill(sig_seed);
    }

    BlockMetadata::new(
        index,
        timestamp,
        previous_hash,
        merkle_root,
        guardian_signature,
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    )
}

fn test_block(index: u64, previous_hash: Hash) -> Result<Block, ErrorDetection> {
    let miner = if index == 0 {
        String::new()
    } else {
        wallet(index.saturating_add(10))
    };

    let batch_key = if index == 0 {
        None
    } else {
        Some(format!("tx_batch_{index:010}"))
    };

    Block::new(test_metadata(index, previous_hash), batch_key, miner, index)
}

fn test_chain(count: usize) -> Result<Vec<Block>, ErrorDetection> {
    let mut blocks = Vec::with_capacity(count);
    let mut previous_hash = [0u8; 64];

    for idx in 0..count {
        let index = u64::try_from(idx).map_err(|_| ErrorDetection::ValidationError {
            message: "test index does not fit into u64".to_owned(),
            tx_id: None,
        })?;

        let block = test_block(index, previous_hash)?;
        previous_hash = block.block_hash;
        blocks.push(block);
    }

    Ok(blocks)
}

fn store_block(manager: &RockDBManager, block: &Block) -> Result<(), ErrorDetection> {
    let bytes = block.serialize_for_storage()?;
    manager.store_latest_block(&bytes, block.metadata.index)?;
    manager.index_block_by_hash(&block.block_hash, &bytes)
}

fn store_chain(manager: &RockDBManager, count: usize) -> Result<Vec<Block>, ErrorDetection> {
    let blocks = test_chain(count)?;
    for block in &blocks {
        store_block(manager, block)?;
    }
    Ok(blocks)
}

fn get_vec_item<T: Clone>(items: &[T], index: usize) -> Result<T, Box<dyn Error>> {
    items
        .get(index)
        .cloned()
        .ok_or_else(|| boxed_error("test vector item missing"))
}

fn assert_some_vec(value: Option<Vec<u8>>, expected: &[u8]) -> TestResult {
    let actual = value.ok_or_else(|| boxed_error("expected Some(Vec<u8>)"))?;
    assert_eq!(actual, expected);
    Ok(())
}

fn assert_some_block(value: Option<Block>, expected: &Block) -> TestResult {
    let actual = value.ok_or_else(|| boxed_error("expected Some(Block)"))?;
    assert_eq!(&actual, expected);
    Ok(())
}

#[test]
fn test_001_blockchain_manager_initializes_in_blockchain_mode() -> TestResult {
    let db = new_blockchain_db("init_blockchain")?;
    assert_eq!(db.manager()?.mode, Mode::Blockchain);
    assert!(db.manager()?.directory.blockchain_path.exists());
    Ok(())
}

#[test]
fn test_002_cli_manager_initializes_in_cli_mode() -> TestResult {
    let db = new_cli_db("init_cli")?;
    assert_eq!(db.manager()?.mode, Mode::CLI);
    assert!(db.manager()?.directory.db_path.exists());
    Ok(())
}

#[test]
fn test_003_log_manager_initializes_in_log_mode() -> TestResult {
    let db = new_log_db("init_log")?;
    assert_eq!(db.manager()?.mode, Mode::Log);
    assert!(db.manager()?.directory.log_path.exists());
    Ok(())
}

#[test]
fn test_004_open_db_blockchain_returns_initialized_handle() -> TestResult {
    let db = new_blockchain_db("open_blockchain")?;
    let handle = db.manager()?.open_db_blockchain()?;
    assert!(
        handle
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .is_some()
    );
    Ok(())
}

#[test]
fn test_005_open_db_blockchain_errors_without_initialized_handle() -> TestResult {
    let db = new_cli_db("open_blockchain_error")?;
    let result = db.manager()?.open_db_blockchain();
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_006_store_and_get_metadata_round_trip_blockchain_mode() -> TestResult {
    let db = new_blockchain_db("metadata_round_trip")?;
    db.manager()?
        .store_metadata("network_magic", b"remzar-test")?;
    assert_some_vec(db.manager()?.get_metadata("network_magic")?, b"remzar-test")
}

#[test]
fn test_007_store_and_get_metadata_round_trip_cli_mode() -> TestResult {
    let db = new_cli_db("metadata_round_trip_cli")?;
    db.manager()?.store_metadata("cli_key", b"cli-value")?;
    assert_some_vec(db.manager()?.get_metadata("cli_key")?, b"cli-value")
}

#[test]
fn test_008_metadata_rejects_accountmodel_mode() -> TestResult {
    let db = new_blockchain_db("metadata_accountmodel_reject")?;
    let mut manager = db.manager()?.clone();
    manager.mode = Mode::AccountModel;

    let result = manager.store_metadata("bad", b"bad");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_009_set_latest_block_index_writes_both_latest_and_tip() -> TestResult {
    let db = new_blockchain_db("latest_block_index")?;
    db.manager()?.set_latest_block_index(42)?;

    assert_eq!(db.manager()?.get_latest_block_index()?, 42);
    assert_eq!(db.manager()?.get_tip_height()?, 42);
    Ok(())
}

#[test]
fn test_010_latest_block_index_defaults_to_zero_when_missing() -> TestResult {
    let db = new_blockchain_db("latest_default_zero")?;
    assert_eq!(db.manager()?.get_latest_block_index()?, 0);
    Ok(())
}

#[test]
fn test_011_set_tip_height_overrides_tip_without_latest_index() -> TestResult {
    let db = new_blockchain_db("tip_height")?;
    db.manager()?.set_tip_height(77)?;

    assert_eq!(db.manager()?.get_tip_height()?, 77);
    assert_eq!(db.manager()?.get_latest_block_index()?, 0);
    Ok(())
}

#[test]
fn test_012_addr_index_height_round_trip() -> TestResult {
    let db = new_blockchain_db("addr_index_height")?;
    db.manager()?.set_addr_index_height(1234)?;

    assert_eq!(db.manager()?.get_addr_index_height()?, 1234);
    Ok(())
}

#[test]
fn test_013_addr_index_height_defaults_to_zero_when_missing() -> TestResult {
    let db = new_blockchain_db("addr_index_default")?;
    assert_eq!(db.manager()?.get_addr_index_height()?, 0);
    Ok(())
}

#[test]
fn test_014_generic_write_read_delete_round_trip() -> TestResult {
    let db = new_blockchain_db("generic_write_read_delete")?;
    let key = b"peer-alpha";
    let value = b"127.0.0.1:36213";

    db.manager()?
        .write(GlobalConfiguration::NETWORK_COLUMN_NAME, key, value)?;
    assert_some_vec(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, key)?,
        value,
    )?;

    db.manager()?
        .delete(GlobalConfiguration::NETWORK_COLUMN_NAME, key)?;
    assert!(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn test_015_generic_write_rejects_accountmodel_mode() -> TestResult {
    let db = new_blockchain_db("generic_write_reject_accountmodel")?;
    let mut manager = db.manager()?.clone();
    manager.mode = Mode::AccountModel;

    let result = manager.write(GlobalConfiguration::NETWORK_COLUMN_NAME, b"k", b"v");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_016_read_rejects_unknown_column_family() -> TestResult {
    let db = new_blockchain_db("unknown_column_read")?;
    let result = db.manager()?.read("not_a_real_column_family", b"k");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_017_iterate_column_returns_written_entries() -> TestResult {
    let db = new_blockchain_db("iterate_column")?;

    db.manager()?
        .write(GlobalConfiguration::NETWORK_COLUMN_NAME, b"peer-a", b"a")?;
    db.manager()?
        .write(GlobalConfiguration::NETWORK_COLUMN_NAME, b"peer-b", b"b")?;

    let mut found = 0usize;
    for item in db
        .manager()?
        .iterate_column(GlobalConfiguration::NETWORK_COLUMN_NAME)?
    {
        let (key, _value) = item?;
        if key == b"peer-a" || key == b"peer-b" {
            found = found.saturating_add(1);
        }
    }

    assert_eq!(found, 2);
    Ok(())
}

#[test]
fn test_018_wallet_balance_round_trip() -> TestResult {
    let db = new_blockchain_db("wallet_balance")?;
    let address = wallet(88);
    let balance_bytes = 500u64.to_be_bytes();

    db.manager()?
        .store_wallet_balance(&address, &balance_bytes)?;
    assert_some_vec(db.manager()?.get_wallet_balance(&address)?, &balance_bytes)
}

#[test]
fn test_019_wallet_balance_rejects_log_mode() -> TestResult {
    let db = new_blockchain_db("wallet_balance_log_reject")?;
    let mut manager = db.manager()?.clone();
    manager.mode = Mode::Log;

    let result = manager.store_wallet_balance(&wallet(89), b"balance");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_020_peer_register_get_remove_round_trip() -> TestResult {
    let db = new_blockchain_db("peer_register_remove")?;

    db.manager()?.register_peer("peer-1", b"peer-data")?;
    assert_some_vec(db.manager()?.get_peer_info("peer-1")?, b"peer-data")?;

    db.manager()?.remove_peer("peer-1")?;
    assert!(db.manager()?.get_peer_info("peer-1")?.is_none());

    Ok(())
}

#[test]
fn test_021_peer_register_rejects_accountmodel_mode() -> TestResult {
    let db = new_blockchain_db("peer_register_reject")?;
    let mut manager = db.manager()?.clone();
    manager.mode = Mode::AccountModel;

    let result = manager.register_peer("peer-bad", b"data");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_022_store_batch_bytes_round_trip_by_index() -> TestResult {
    let db = new_blockchain_db("batch_bytes")?;
    let batch = TransactionBatch::new(5, 1_800_000_005, Vec::new())?;
    let bytes = batch.serialize_for_storage()?;

    db.manager()?.store_batch_bytes(5, &bytes)?;
    assert_some_vec(db.manager()?.get_batch_bytes_by_index(5)?, &bytes)
}

#[test]
fn test_023_get_tx_batch_bytes_by_index_matches_batch_bytes_lookup() -> TestResult {
    let db = new_blockchain_db("tx_batch_bytes")?;
    let batch = TransactionBatch::new(6, 1_800_000_006, Vec::new())?;
    let bytes = batch.serialize_for_storage()?;

    db.manager()?.store_batch_bytes(6, &bytes)?;

    let first = db.manager()?.get_batch_bytes_by_index(6)?;
    let second = db.manager()?.get_tx_batch_bytes_by_index(6)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn test_024_missing_batch_bytes_returns_none() -> TestResult {
    let db = new_blockchain_db("missing_batch")?;
    assert!(db.manager()?.get_batch_bytes_by_index(999)?.is_none());
    assert!(db.manager()?.get_tx_batch_bytes_by_index(999)?.is_none());
    Ok(())
}

#[test]
fn test_025_store_latest_block_and_get_block_bytes_by_index() -> TestResult {
    let db = new_blockchain_db("store_latest_block_bytes")?;
    let block = test_block(0, [0u8; 64])?;
    let bytes = block.serialize_for_storage()?;

    db.manager()?.store_latest_block(&bytes, 0)?;

    assert_some_vec(db.manager()?.get_block_bytes_by_index(0)?, &bytes)
}

#[test]
fn test_026_store_latest_block_rejects_oversized_block() -> TestResult {
    let db = new_blockchain_db("oversized_block")?;
    let cap = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)?;
    let oversized_len = cap.saturating_add(1);
    let oversized = vec![0u8; oversized_len];

    let result = db.manager()?.store_latest_block(&oversized, 1);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_027_get_block_by_index_round_trip() -> TestResult {
    let db = new_blockchain_db("get_block_by_index")?;
    let block = test_block(0, [0u8; 64])?;

    store_block(db.manager()?, &block)?;

    assert_some_block(db.manager()?.get_block_by_index(0)?, &block)
}

#[test]
fn test_028_get_block_hash_by_index_returns_stored_hash() -> TestResult {
    let db = new_blockchain_db("get_hash_by_index")?;
    let block = test_block(0, [0u8; 64])?;

    store_block(db.manager()?, &block)?;

    assert_eq!(db.manager()?.get_block_hash_by_index(0)?, block.block_hash);
    Ok(())
}

#[test]
fn test_029_get_latest_block_and_hash_return_highest_block() -> TestResult {
    let db = new_blockchain_db("latest_block")?;
    let blocks = store_chain(db.manager()?, 3)?;
    let expected = get_vec_item(&blocks, 2)?;

    assert_some_block(db.manager()?.get_latest_block()?, &expected)?;
    assert_eq!(db.manager()?.get_latest_block_hash()?, expected.block_hash);

    Ok(())
}

#[test]
fn test_030_get_latest_block_hash_errors_when_no_blocks_exist() -> TestResult {
    let db = new_blockchain_db("latest_hash_empty")?;
    let result = db.manager()?.get_latest_block_hash();

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_031_index_block_by_hash_and_get_block_by_hash_round_trip() -> TestResult {
    let db = new_blockchain_db("block_hash_index")?;
    let block = test_block(0, [0u8; 64])?;
    let bytes = block.serialize_for_storage()?;

    db.manager()?
        .index_block_by_hash(&block.block_hash, &bytes)?;

    assert!(db.manager()?.has_block_by_hash(&block.block_hash));

    let found = db
        .manager()?
        .get_block_by_hash(&block.block_hash)
        .ok_or_else(|| boxed_error("indexed block missing"))?;

    assert_eq!(found, block);
    Ok(())
}

#[test]
fn test_032_get_block_by_hash_returns_none_for_unknown_hash() -> TestResult {
    let db = new_blockchain_db("unknown_hash")?;
    assert!(db.manager()?.get_block_by_hash(&[99u8; 64]).is_none());
    assert!(!db.manager()?.has_block_by_hash(&[99u8; 64]));
    Ok(())
}

#[test]
fn test_033_list_block_indices_returns_canonical_keys() -> TestResult {
    let db = new_blockchain_db("list_block_indices")?;
    let _blocks = store_chain(db.manager()?, 3)?;

    let keys = db.manager()?.list_block_indices()?;

    assert!(keys.contains(&"block_0000000000".to_owned()));
    assert!(keys.contains(&"block_0000000001".to_owned()));
    assert!(keys.contains(&"block_0000000002".to_owned()));

    Ok(())
}

#[test]
fn test_034_get_last_blocks_respects_count() -> TestResult {
    let db = new_blockchain_db("get_last_blocks")?;
    let _blocks = store_chain(db.manager()?, 5)?;

    let last = db.manager()?.get_last_blocks(2)?;

    assert_eq!(last.len(), 2);
    Ok(())
}

#[test]
fn test_035_remove_block_by_index_deletes_block_batch_and_hash_mapping() -> TestResult {
    let db = new_blockchain_db("remove_block")?;
    let blocks = store_chain(db.manager()?, 2)?;
    let target = get_vec_item(&blocks, 1)?;

    let batch = TransactionBatch::new(1, 1_800_000_001, Vec::new())?;
    let batch_bytes = batch.serialize_for_storage()?;
    db.manager()?.store_batch_bytes(1, &batch_bytes)?;

    assert!(db.manager()?.has_block_by_hash(&target.block_hash));
    assert!(db.manager()?.get_batch_bytes_by_index(1)?.is_some());

    db.manager()?.remove_block_by_index(1)?;

    assert!(db.manager()?.get_block_by_index(1)?.is_none());
    assert!(!db.manager()?.has_block_by_hash(&target.block_hash));
    assert!(db.manager()?.get_batch_bytes_by_index(1)?.is_none());

    Ok(())
}

#[test]
fn test_036_remove_block_by_index_errors_for_missing_block() -> TestResult {
    let db = new_blockchain_db("remove_missing_block")?;
    let result = db.manager()?.remove_block_by_index(777);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_037_store_state_and_load_state_round_trip() -> TestResult {
    let db = new_blockchain_db("state_round_trip")?;
    let mut state = AccountModelTree::with_manager(db.manager()?.clone());
    let alice = wallet(200);
    let bob = wallet(201);

    state.set_balance(&alice, 123);
    state.set_balance(&bob, 456);

    db.manager()?.store_state(&state)?;

    let loaded = db.manager()?.load_state()?;

    assert_eq!(loaded.get_balance(&alice), 123);
    assert_eq!(loaded.get_balance(&bob), 456);

    Ok(())
}

#[test]
fn test_038_set_account_balance_updates_state_and_account_column() -> TestResult {
    let db = new_blockchain_db("set_account_balance")?;
    let account = wallet(300);

    db.manager()?.set_account_balance(&account, 999)?;
    assert_eq!(db.manager()?.get_account_balance(&account)?, 999);
    assert!(db.manager()?.get_wallet_balance(&account)?.is_some());

    Ok(())
}

#[test]
fn test_039_blockstore_get_blocks_between_returns_linear_range() -> TestResult {
    let db = new_blockchain_db("blocks_between")?;
    let blocks = store_chain(db.manager()?, 5)?;

    let ancestor = get_vec_item(&blocks, 1)?;
    let tip = get_vec_item(&blocks, 4)?;

    let between = db
        .manager()?
        .get_blocks_between(ancestor.block_hash, tip.block_hash)
        .map_err(|e| boxed_error(&e))?;

    assert_eq!(between.len(), 3);

    let first = between
        .first()
        .ok_or_else(|| boxed_error("missing first block between ancestor and tip"))?;
    let last = between
        .last()
        .ok_or_else(|| boxed_error("missing last block between ancestor and tip"))?;

    assert_eq!(first.metadata.index, 2);
    assert_eq!(last.metadata.index, 4);

    Ok(())
}

#[test]
fn test_040_vectors_edges_fuzz_property_adversarial_and_load_sweep() -> TestResult {
    let db = new_blockchain_db("sweep")?;

    let vector_heights = [0u64, 1, 2, 7, 42, 255, 1024];
    for height in vector_heights {
        db.manager()?.set_latest_block_index(height)?;
        assert_eq!(db.manager()?.get_latest_block_index()?, height);
        assert_eq!(db.manager()?.get_tip_height()?, height);
    }

    db.manager()?.store_metadata("empty-value", b"")?;
    assert_some_vec(db.manager()?.get_metadata("empty-value")?, b"")?;

    let long_key = "k".repeat(256);
    db.manager()?.store_metadata(&long_key, b"long-key-value")?;
    assert_some_vec(db.manager()?.get_metadata(&long_key)?, b"long-key-value")?;

    assert!(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"unknown-key")?
            .is_none()
    );

    let mut seed = 0xA5A5_1234_9876_FEDCu64;
    for round in 0..128u64 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);

        let key = format!("fuzz-key-{round}-{seed:016x}");
        let value = seed.to_be_bytes();

        db.manager()?.write(
            GlobalConfiguration::NETWORK_COLUMN_NAME,
            key.as_bytes(),
            &value,
        )?;

        let loaded = db
            .manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, key.as_bytes())?
            .ok_or_else(|| boxed_error("fuzz value missing after write"))?;

        assert_eq!(loaded, value);
    }

    for peer_index in 0..64u64 {
        let peer = format!("peer-{peer_index:04}");
        let first = format!("addr-old-{peer_index}");
        let second = format!("addr-new-{peer_index}");

        db.manager()?.register_peer(&peer, first.as_bytes())?;
        db.manager()?.register_peer(&peer, second.as_bytes())?;

        assert_some_vec(db.manager()?.get_peer_info(&peer)?, second.as_bytes())?;

        if peer_index.rem_euclid(3) == 0 {
            db.manager()?.remove_peer(&peer)?;
            assert!(db.manager()?.get_peer_info(&peer)?.is_none());
        }
    }

    for batch_index in 0..96u64 {
        let batch = TransactionBatch::new(
            batch_index,
            1_800_010_000u64.saturating_add(batch_index),
            Vec::new(),
        )?;
        let bytes = batch.serialize_for_storage()?;

        db.manager()?.store_batch_bytes(batch_index, &bytes)?;
        assert_some_vec(db.manager()?.get_batch_bytes_by_index(batch_index)?, &bytes)?;
    }

    let blocks = store_chain(db.manager()?, 16)?;
    for block in &blocks {
        assert!(db.manager()?.has_block_by_hash(&block.block_hash));
        assert_some_block(
            db.manager()?.get_block_by_index(block.metadata.index)?,
            block,
        )?;
        assert_eq!(
            db.manager()?
                .get_block_hash_by_index(block.metadata.index)?,
            block.block_hash
        );
    }

    let ancestor = get_vec_item(&blocks, 5)?;
    let tip = get_vec_item(&blocks, 15)?;
    let between = db
        .manager()?
        .get_blocks_between(ancestor.block_hash, tip.block_hash)
        .map_err(|e| boxed_error(&e))?;

    assert_eq!(between.len(), 10);

    let same_height_result = db
        .manager()?
        .get_blocks_between(tip.block_hash, ancestor.block_hash);

    assert!(same_height_result.is_err());

    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let readonly = RockDBManager::from_existing_readonly(
        &opts,
        db.manager()?.directory.blockchain_path.clone(),
    )?;

    assert_eq!(readonly.get_latest_block_index()?, 1024);

    Ok(())
}

#[test]
fn test_041_directory_from_node_opts_uses_supplied_base_dir() -> TestResult {
    let root = unique_root("dir_from_node_opts");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_node_opts(&opts)?;

    assert_eq!(
        directory.wallets_path,
        root.join(GlobalConfiguration::WALLETS_DIR)
    );
    assert_eq!(
        directory.db_path,
        root.join(GlobalConfiguration::DATABASE_DIR_NAME)
    );
    assert_eq!(
        directory.blockchain_path,
        root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
    assert_eq!(
        directory.registry_path,
        root.join(GlobalConfiguration::REGISTRY_DIR_NAME)
    );
    assert_eq!(
        directory.log_path,
        root.join(GlobalConfiguration::LOG_DATABASE_DIR)
    );

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_042_directory_from_base_dir_maps_all_paths() -> TestResult {
    let root = unique_root("dir_from_base_dir");
    std::fs::create_dir_all(&root)?;

    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    assert_eq!(
        directory.accountmodel_path,
        root.join(GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR)
    );
    assert_eq!(
        directory.sidechain_path,
        root.join(GlobalConfiguration::SIDECHAIN_DATABASE_DIR)
    );
    assert_eq!(
        directory.audit_reports_path,
        root.join(GlobalConfiguration::AUDIT_REPORTS_DIR)
    );
    assert_eq!(
        directory.peerlist_path,
        root.join(GlobalConfiguration::PEER_LIST_DIR)
    );

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_043_directory_as_ref_points_to_cli_db_path() -> TestResult {
    let root = unique_root("dir_as_ref");
    std::fs::create_dir_all(&root)?;

    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    assert_eq!(directory.as_ref(), directory.db_path.as_path());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_044_create_wallets_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_wallets_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_wallets_directory()?;

    assert!(directory.wallets_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_045_create_db_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_db_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_db_directory()?;

    assert!(directory.db_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_046_create_blockchain_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_blockchain_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_blockchain_directory()?;

    assert!(directory.blockchain_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_047_create_registry_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_registry_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_registry_directory()?;

    assert!(directory.registry_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_048_create_accountmodel_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_accountmodel_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_accountmodel_directory()?;

    assert!(directory.accountmodel_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_049_create_sidechain_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_sidechain_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_sidechain_directory()?;

    assert!(directory.sidechain_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_050_create_log_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_log_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_log_directory()?;

    assert!(directory.log_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_051_create_audit_reports_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_audit_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_audit_reports_directory()?;

    assert!(directory.audit_reports_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_052_create_peerlist_directory_creates_expected_path() -> TestResult {
    let root = unique_root("create_peerlist_dir");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_peerlist_directory()?;

    assert!(directory.peerlist_path.exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_053_setup_database_accepts_each_known_directory_target() -> TestResult {
    let root = unique_root("setup_each_known_target");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    let targets = [
        directory.wallets_path.clone(),
        directory.db_path.clone(),
        directory.blockchain_path.clone(),
        directory.registry_path.clone(),
        directory.accountmodel_path.clone(),
        directory.sidechain_path.clone(),
        directory.log_path.clone(),
        directory.audit_reports_path.clone(),
        directory.peerlist_path.clone(),
    ];

    for target in targets {
        directory.setup_database(&target)?;
        assert!(target.exists());
    }

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_054_setup_database_rejects_unknown_target() -> TestResult {
    let root = unique_root("setup_unknown_target");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;
    let unknown = root.join("not_a_configured_database_dir");

    let result = directory.setup_database(&unknown);

    assert!(result.is_err());

    if root.exists() {
        std::fs::remove_dir_all(root)?;
    }

    Ok(())
}

#[test]
fn test_055_validate_directories_errors_when_directories_missing() -> TestResult {
    let root = unique_root("validate_missing_dirs");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    let result = directory.validate_directories();

    assert!(result.is_err());

    if root.exists() {
        std::fs::remove_dir_all(root)?;
    }

    Ok(())
}

#[test]
fn test_056_validate_directories_succeeds_after_all_dirs_created() -> TestResult {
    let root = unique_root("validate_all_dirs");
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

    directory.create_wallets_directory()?;
    directory.create_db_directory()?;
    directory.create_blockchain_directory()?;
    directory.create_registry_directory()?;
    directory.create_accountmodel_directory()?;
    directory.create_sidechain_directory()?;
    directory.create_log_directory()?;
    directory.create_audit_reports_directory()?;
    directory.create_peerlist_directory()?;

    directory.validate_directories()?;

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_057_cf_descriptors_include_default_and_all_configured_cfs() -> TestResult {
    let descriptors =
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors();

    let names: Vec<String> = descriptors
        .iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect();

    assert!(names.contains(&"default".to_owned()));
    assert!(names.contains(&GlobalConfiguration::META_DATA_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::GLOBAL_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::ACCOUNT_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::NETWORK_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::SIDECHAIN_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::STATE_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::TRANSACTION_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::REWARD_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::REWARD_BATCH_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::LOGS_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::TX_TO_HASH_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::IDENTITY_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME.to_owned()));
    assert!(names.contains(&GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME.to_owned()));

    Ok(())
}

#[test]
fn test_058_cf_descriptor_count_matches_expected_full_schema_count() -> TestResult {
    let descriptors =
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors();

    let expected = GlobalConfiguration::TOTAL_COLUMNS.saturating_add(1);

    assert_eq!(descriptors.len(), expected);
    Ok(())
}

#[test]
fn test_059_cf_descriptor_names_are_unique() -> TestResult {
    let descriptors =
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors();

    let mut names: Vec<String> = descriptors
        .iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect();

    names.sort();
    names.dedup();

    assert_eq!(names.len(), descriptors.len());
    Ok(())
}

#[test]
fn test_060_clone_column_family_descriptor_preserves_name() -> TestResult {
    let descriptors =
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors();

    for descriptor in &descriptors {
        let cloned =
            remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::clone_column_family_descriptor(
                descriptor,
            );

        assert_eq!(cloned.name(), descriptor.name());
    }

    Ok(())
}

#[test]
fn test_061_rocksdb_config_default_constructs() -> TestResult {
    let config = remzar::storage::rocksdb_004_config::RockSDBConfig::default();

    let _options_ref = config.get_options();

    Ok(())
}

#[test]
fn test_062_rocksdb_config_new_constructs() -> TestResult {
    let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();

    let _options_ref = config.get_options();

    Ok(())
}

#[test]
fn test_063_rocksdb_config_open_db_multi_cf_creates_all_cfs() -> TestResult {
    let root = unique_root("config_open_multi_cf");
    std::fs::create_dir_all(&root)?;

    let db_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let path = path_to_string(&db_path)?;

    {
        let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();
        let (db, batch) = config.open_db_multi_cf(&path)?;

        for descriptor in
            remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors()
        {
            assert!(db.cf_handle(descriptor.name()).is_some());
        }

        drop(batch);
        drop(db);
    }

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_064_rocksdb_config_open_blockchain_db_wraps_multi_cf_open() -> TestResult {
    let root = unique_root("config_open_blockchain");
    std::fs::create_dir_all(&root)?;

    let db_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let path = path_to_string(&db_path)?;

    {
        let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();
        let (db, batch) = config.open_db_blockchain(&path)?;

        assert!(
            db.cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
                .is_some()
        );
        assert!(
            db.cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
                .is_some()
        );

        drop(batch);
        drop(db);
    }

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_065_rocksdb_config_open_accountmodel_db_uses_blockchain_schema() -> TestResult {
    let root = unique_root("config_open_accountmodel");
    std::fs::create_dir_all(&root)?;

    let db_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let path = path_to_string(&db_path)?;

    {
        let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();
        let (db, batch) = config.open_db_accountmodel(&path)?;

        assert!(
            db.cf_handle(GlobalConfiguration::STATE_COLUMN_NAME)
                .is_some()
        );
        assert!(
            db.cf_handle(GlobalConfiguration::ACCOUNT_COLUMN_NAME)
                .is_some()
        );

        drop(batch);
        drop(db);
    }

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_066_rocksdb_config_open_registry_db_uses_full_schema() -> TestResult {
    let root = unique_root("config_open_registry");
    std::fs::create_dir_all(&root)?;

    let db_path = root.join(GlobalConfiguration::REGISTRY_DIR_NAME);
    let path = path_to_string(&db_path)?;

    {
        let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();
        let (db, batch) = config.open_db_registry(&path)?;

        assert!(
            db.cf_handle(GlobalConfiguration::NETWORK_COLUMN_NAME)
                .is_some()
        );
        assert!(
            db.cf_handle(GlobalConfiguration::IDENTITY_COLUMN_NAME)
                .is_some()
        );

        drop(batch);
        drop(db);
    }

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_067_rocksdb_config_open_cli_db_creates_default_database() -> TestResult {
    let root = unique_root("config_open_cli");
    std::fs::create_dir_all(&root)?;

    let db_path = root.join(GlobalConfiguration::DATABASE_DIR_NAME);
    let path = path_to_string(&db_path)?;

    {
        let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();
        let (db, batch) = config.open_db_cli(&path)?;

        db.put(b"cli-key", b"cli-value")?;
        let loaded = db
            .get(b"cli-key")?
            .ok_or_else(|| boxed_error("default CLI key missing"))?;

        assert_eq!(loaded, b"cli-value");

        drop(batch);
        drop(db);
    }

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_068_manager_new_blockchain_uses_default_path_when_db_path_not_absolute_target() -> TestResult
{
    let root = unique_root("manager_default_blockchain_path");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let manager = RockDBManager::new_blockchain(&opts, "relative_ignored_path")?;

    assert_eq!(
        manager.directory.blockchain_path,
        root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
    assert!(manager.directory.blockchain_path.exists());

    drop(manager);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_069_manager_new_log_uses_default_path_when_db_path_not_absolute_target() -> TestResult {
    let root = unique_root("manager_default_log_path");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let manager = RockDBManager::new_log(&opts, "relative_ignored_path")?;

    assert_eq!(
        manager.directory.log_path,
        root.join(GlobalConfiguration::LOG_DATABASE_DIR)
    );
    assert!(manager.directory.log_path.exists());

    drop(manager);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_070_manager_new_accountmodel_uses_default_blockchain_path_when_db_path_not_absolute_target()
-> TestResult {
    let root = unique_root("manager_accountmodel_default_path");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let manager = RockDBManager::new_accountmodel(&opts, "relative_ignored_path")?;

    assert_eq!(manager.mode, Mode::AccountModel);
    assert_eq!(
        manager.directory.blockchain_path,
        root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
    assert!(manager.directory.blockchain_path.exists());

    drop(manager);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_071_manager_new_cli_accepts_existing_stale_lock_file() -> TestResult {
    let root = unique_root("manager_cli_lock");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_node_opts(&opts)?;
    directory.create_db_directory()?;
    let lock_path = directory.db_path.join("LOCK");
    std::fs::write(&lock_path, b"stale-lock-file")?;

    let manager = RockDBManager::new(&opts)?;

    assert_eq!(manager.mode, Mode::CLI);
    assert_eq!(manager.directory.db_path, directory.db_path);
    assert!(manager.directory.db_path.exists());
    assert!(lock_path.exists());

    drop(manager);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_072_manager_new_log_accepts_existing_stale_lock_file() -> TestResult {
    let root = unique_root("manager_log_lock");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_node_opts(&opts)?;
    directory.create_log_directory()?;
    let lock_path = directory.log_path.join("LOCK");
    std::fs::write(&lock_path, b"stale-lock-file")?;

    let path = path_to_string(&directory.log_path)?;
    let manager = RockDBManager::new_log(&opts, &path)?;

    assert_eq!(manager.mode, Mode::Log);
    assert_eq!(manager.directory.log_path, directory.log_path);
    assert!(manager.directory.log_path.exists());
    assert!(lock_path.exists());

    drop(manager);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_073_manager_new_accountmodel_accepts_existing_stale_lock_file() -> TestResult {
    let root = unique_root("manager_accountmodel_lock");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_node_opts(&opts)?;
    directory.create_blockchain_directory()?;
    let lock_path = directory.blockchain_path.join("LOCK");
    std::fs::write(&lock_path, b"stale-lock-file")?;

    let path = path_to_string(&directory.blockchain_path)?;
    let manager = RockDBManager::new_accountmodel(&opts, &path)?;

    assert_eq!(manager.mode, Mode::AccountModel);
    assert_eq!(manager.directory.blockchain_path, directory.blockchain_path);
    assert!(manager.directory.blockchain_path.exists());
    assert!(lock_path.exists());

    drop(manager);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_074_from_existing_readonly_rejects_missing_path() -> TestResult {
    let root = unique_root("readonly_missing");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let missing = root.join("missing_blockchain_db");

    let result = RockDBManager::from_existing_readonly(&opts, &missing);

    assert!(result.is_err());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_075_from_existing_readonly_reads_existing_blockchain_metadata() -> TestResult {
    let mut db = new_blockchain_db("readonly_existing")?;

    db.manager()?.set_latest_block_index(333)?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let readonly = RockDBManager::from_existing_readonly(&opts, &blockchain_path)?;

    assert_eq!(readonly.get_latest_block_index()?, 333);

    drop(readonly);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_076_list_column_families_in_blockchain_mode_contains_full_schema() -> TestResult {
    let db = new_blockchain_db("list_cf_blockchain")?;

    let cfs = db.manager()?.list_column_families()?;

    assert!(cfs.contains(&"default".to_owned()));
    assert!(cfs.contains(&GlobalConfiguration::GLOBAL_COLUMN_NAME.to_owned()));
    assert!(cfs.contains(&GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME.to_owned()));
    assert!(cfs.contains(&GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME.to_owned()));

    Ok(())
}

#[test]
fn test_077_list_column_families_rejects_sidechain_mode() -> TestResult {
    let db = new_blockchain_db("list_cf_sidechain_reject")?;
    let mut manager = db.manager()?.clone();

    manager.mode = Mode::Sidechain;

    let result = manager.list_column_families();

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_078_fuzz_directory_base_paths_are_deterministic() -> TestResult {
    for index in 0..64u64 {
        let root = unique_root(&format!("fuzz_dir_base_{index}"));
        let directory = remzar::storage::rocksdb_000_directory::DirectoryDB::from_base_dir(&root)?;

        assert!(
            directory
                .wallets_path
                .ends_with(GlobalConfiguration::WALLETS_DIR)
        );
        assert!(
            directory
                .db_path
                .ends_with(GlobalConfiguration::DATABASE_DIR_NAME)
        );
        assert!(
            directory
                .blockchain_path
                .ends_with(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
        );
        assert!(
            directory
                .log_path
                .ends_with(GlobalConfiguration::LOG_DATABASE_DIR)
        );
        assert!(
            directory
                .peerlist_path
                .ends_with(GlobalConfiguration::PEER_LIST_DIR)
        );
    }

    Ok(())
}

#[test]
fn test_079_property_cf_schema_has_no_empty_names_and_all_names_reopenable() -> TestResult {
    let descriptors =
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors();

    for descriptor in &descriptors {
        assert!(!descriptor.name().trim().is_empty());

        let cloned =
            remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::clone_column_family_descriptor(
                descriptor,
            );

        assert_eq!(cloned.name(), descriptor.name());
    }

    Ok(())
}

#[test]
fn test_080_load_open_write_flush_reopen_read_across_schema_components() -> TestResult {
    let mut db = new_blockchain_db("load_open_write_flush_reopen")?;

    for index in 0..128u64 {
        let key = format!("load-key-{index:04}");
        let value = index.to_be_bytes();

        db.manager()?.write(
            GlobalConfiguration::NETWORK_COLUMN_NAME,
            key.as_bytes(),
            &value,
        )?;
    }

    db.manager()?.set_latest_block_index(128)?;
    db.manager()?.set_addr_index_height(64)?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    assert_eq!(reopened.get_latest_block_index()?, 128);
    assert_eq!(reopened.get_addr_index_height()?, 64);

    for index in 0..128u64 {
        let key = format!("load-key-{index:04}");
        let expected = index.to_be_bytes();

        assert_some_vec(
            reopened.read(GlobalConfiguration::NETWORK_COLUMN_NAME, key.as_bytes())?,
            &expected,
        )?;
    }

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_081_edge_empty_metadata_key_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_empty_metadata_key")?;

    db.manager()?.store_metadata("", b"empty-key-value")?;

    assert_some_vec(db.manager()?.get_metadata("")?, b"empty-key-value")
}

#[test]
fn test_082_edge_binary_metadata_value_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_binary_metadata_value")?;
    let value = [0u8, 1, 2, 3, 255, 254, 128, 64];

    db.manager()?.store_metadata("binary-value", &value)?;

    assert_some_vec(db.manager()?.get_metadata("binary-value")?, &value)
}

#[test]
fn test_083_edge_zero_length_generic_value_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_zero_len_generic_value")?;

    db.manager()?.write(
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        b"empty-value",
        b"",
    )?;

    assert_some_vec(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"empty-value")?,
        b"",
    )
}

#[test]
fn test_084_edge_zero_length_generic_key_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_zero_len_generic_key")?;

    db.manager()?
        .write(GlobalConfiguration::NETWORK_COLUMN_NAME, b"", b"empty-key")?;

    assert_some_vec(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"")?,
        b"empty-key",
    )
}

#[test]
fn test_085_edge_delete_missing_key_is_ok() -> TestResult {
    let db = new_blockchain_db("edge_delete_missing_key")?;

    db.manager()?
        .delete(GlobalConfiguration::NETWORK_COLUMN_NAME, b"does-not-exist")?;

    assert!(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"does-not-exist")?
            .is_none()
    );

    Ok(())
}

#[test]
fn test_086_edge_store_batch_empty_bytes_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_empty_batch_bytes")?;

    db.manager()?.store_batch_bytes(44, b"")?;

    assert_some_vec(db.manager()?.get_batch_bytes_by_index(44)?, b"")
}

#[test]
fn test_087_edge_batch_index_u64_max_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_batch_u64_max")?;
    let value = b"max-index-batch";

    db.manager()?.store_batch_bytes(u64::MAX, value)?;

    assert_some_vec(db.manager()?.get_batch_bytes_by_index(u64::MAX)?, value)
}

#[test]
fn test_088_edge_tip_height_u64_max_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_tip_u64_max")?;

    db.manager()?.set_tip_height(u64::MAX)?;

    assert_eq!(db.manager()?.get_tip_height()?, u64::MAX);
    Ok(())
}

#[test]
fn test_089_edge_latest_block_index_u64_max_round_trip() -> TestResult {
    let db = new_blockchain_db("edge_latest_index_u64_max")?;

    db.manager()?.set_latest_block_index(u64::MAX)?;

    assert_eq!(db.manager()?.get_latest_block_index()?, u64::MAX);
    assert_eq!(db.manager()?.get_tip_height()?, u64::MAX);

    Ok(())
}

#[test]
fn test_090_vector_cf_descriptor_order_starts_with_default() -> TestResult {
    let descriptors =
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors();

    let first = descriptors
        .first()
        .ok_or_else(|| boxed_error("CF descriptor vector is empty"))?;

    assert_eq!(first.name(), "default");
    Ok(())
}

#[test]
fn test_091_vector_cf_descriptor_names_match_global_configuration_order() -> TestResult {
    let descriptors =
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors();

    let actual: Vec<String> = descriptors
        .iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect();

    let expected = vec![
        "default".to_owned(),
        GlobalConfiguration::META_DATA_COLUMN_NAME.to_owned(),
        GlobalConfiguration::GLOBAL_COLUMN_NAME.to_owned(),
        GlobalConfiguration::ACCOUNT_COLUMN_NAME.to_owned(),
        GlobalConfiguration::NETWORK_COLUMN_NAME.to_owned(),
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME.to_owned(),
        GlobalConfiguration::STATE_COLUMN_NAME.to_owned(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME.to_owned(),
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME.to_owned(),
        GlobalConfiguration::REWARD_COLUMN_NAME.to_owned(),
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME.to_owned(),
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME.to_owned(),
        GlobalConfiguration::LOGS_COLUMN_NAME.to_owned(),
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME.to_owned(),
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME.to_owned(),
        GlobalConfiguration::IDENTITY_COLUMN_NAME.to_owned(),
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME.to_owned(),
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME.to_owned(),
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME.to_owned(),
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME.to_owned(),
    ];

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn test_092_schema_each_declared_cf_is_open_on_blockchain_db() -> TestResult {
    let db = new_blockchain_db("schema_each_cf_open")?;
    let handle = db.manager()?.open_db_blockchain()?;

    for descriptor in
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors()
    {
        assert!(
            handle.cf_handle(descriptor.name()).is_some(),
            "missing column family {}",
            descriptor.name()
        );
    }

    Ok(())
}

#[test]
fn test_093_schema_list_column_families_contains_every_descriptor() -> TestResult {
    let db = new_blockchain_db("schema_list_every_descriptor")?;
    let listed = db.manager()?.list_column_families()?;

    for descriptor in
        remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors()
    {
        assert!(
            listed.contains(&descriptor.name().to_owned()),
            "missing listed column family {}",
            descriptor.name()
        );
    }

    Ok(())
}

#[test]
fn test_094_schema_rocksdb_config_multi_cf_reopen_preserves_schema() -> TestResult {
    let root = unique_root("schema_config_reopen_preserves");
    std::fs::create_dir_all(&root)?;

    let path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let path_string = path_to_string(&path)?;

    {
        let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();
        let (db, batch) = config.open_db_multi_cf(&path_string)?;

        assert!(
            db.cf_handle(GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME)
                .is_some()
        );

        drop(batch);
        drop(db);
    }

    {
        let config = remzar::storage::rocksdb_004_config::RockSDBConfig::new();
        let (db, batch) = config.open_db_multi_cf(&path_string)?;

        for descriptor in
            remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors()
        {
            assert!(db.cf_handle(descriptor.name()).is_some());
        }

        drop(batch);
        drop(db);
    }

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_095_edge_readonly_reopen_after_drop_preserves_metadata_and_cf_schema() -> TestResult {
    let mut db = new_blockchain_db("readonly_preserves_schema")?;

    db.manager()?
        .store_metadata("schema-key", b"schema-value")?;
    db.manager()?.set_addr_index_height(91)?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let readonly = RockDBManager::from_existing_readonly(&opts, &blockchain_path)?;

    assert_some_vec(readonly.get_metadata("schema-key")?, b"schema-value")?;
    assert_eq!(readonly.get_addr_index_height()?, 91);

    let cfs = readonly.list_column_families()?;
    assert!(cfs.contains(&GlobalConfiguration::STATE_COLUMN_NAME.to_owned()));
    assert!(cfs.contains(&GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME.to_owned()));

    drop(readonly);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_096_vector_mode_restrictions_sidechain_rejects_read_iterate_and_write() -> TestResult {
    let db = new_blockchain_db("sidechain_mode_restrictions")?;
    let mut manager = db.manager()?.clone();

    manager.mode = Mode::Sidechain;

    assert!(
        manager
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"k")
            .is_err()
    );
    assert!(
        manager
            .iterate_column(GlobalConfiguration::NETWORK_COLUMN_NAME)
            .is_err()
    );
    assert!(
        manager
            .write(GlobalConfiguration::NETWORK_COLUMN_NAME, b"k", b"v")
            .is_err()
    );
    assert!(
        manager
            .delete(GlobalConfiguration::NETWORK_COLUMN_NAME, b"k")
            .is_err()
    );

    Ok(())
}

#[test]
fn test_097_property_overwrite_same_key_last_write_wins() -> TestResult {
    let db = new_blockchain_db("property_last_write_wins")?;

    for index in 0..100u64 {
        let value = index.to_be_bytes();

        db.manager()?.write(
            GlobalConfiguration::NETWORK_COLUMN_NAME,
            b"same-key",
            &value,
        )?;

        assert_some_vec(
            db.manager()?
                .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"same-key")?,
            &value,
        )?;
    }

    Ok(())
}

#[test]
fn test_098_property_batch_sparse_indices_are_independent() -> TestResult {
    let db = new_blockchain_db("property_sparse_batches")?;
    let indices = [0u64, 1, 2, 10, 99, 1_000, u64::from(u32::MAX)];

    for index in indices {
        let value = format!("batch-value-{index}").into_bytes();

        db.manager()?.store_batch_bytes(index, &value)?;

        assert_some_vec(db.manager()?.get_batch_bytes_by_index(index)?, &value)?;
    }

    assert!(db.manager()?.get_batch_bytes_by_index(3)?.is_none());
    assert!(db.manager()?.get_batch_bytes_by_index(98)?.is_none());

    Ok(())
}

#[test]
fn test_099_load_many_metadata_keys_survive_flush_and_reopen() -> TestResult {
    let mut db = new_blockchain_db("load_metadata_reopen")?;

    for index in 0..150u64 {
        let key = format!("metadata-load-{index:04}");
        let value = index.to_be_bytes();

        db.manager()?.store_metadata(&key, &value)?;
    }

    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    for index in 0..150u64 {
        let key = format!("metadata-load-{index:04}");
        let expected = index.to_be_bytes();

        assert_some_vec(reopened.get_metadata(&key)?, &expected)?;
    }

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_100_final_schema_vector_edge_and_load_sweep() -> TestResult {
    let mut db = new_blockchain_db("final_schema_vector_edge_load")?;

    {
        let listed = db.manager()?.list_column_families()?;
        let handle = db.manager()?.open_db_blockchain()?;

        for descriptor in
            remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors::get_cf_descriptors()
        {
            assert!(listed.contains(&descriptor.name().to_owned()));
            assert!(handle.cf_handle(descriptor.name()).is_some());
        }

        drop(handle);
    }

    let height_vectors = [0u64, 1, 2, 63, 64, 255, 256, u64::from(u32::MAX)];
    for height in height_vectors {
        db.manager()?.set_latest_block_index(height)?;
        assert_eq!(db.manager()?.get_latest_block_index()?, height);
        assert_eq!(db.manager()?.get_tip_height()?, height);
    }

    db.manager()?
        .write(GlobalConfiguration::NETWORK_COLUMN_NAME, b"", b"")?;
    assert_some_vec(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"")?,
        b"",
    )?;

    db.manager()?.write(
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        b"bin",
        &[0, 255, 1, 254],
    )?;
    assert_some_vec(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"bin")?,
        &[0, 255, 1, 254],
    )?;

    db.manager()?.write(
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        b"bin",
        b"replacement",
    )?;
    assert_some_vec(
        db.manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, b"bin")?,
        b"replacement",
    )?;

    for index in 0..80u64 {
        let peer = format!("final-peer-{index:04}");
        let peer_data = format!("final-peer-data-{index:04}");
        db.manager()?.register_peer(&peer, peer_data.as_bytes())?;
        assert_some_vec(db.manager()?.get_peer_info(&peer)?, peer_data.as_bytes())?;

        let address = wallet(10_000u64.saturating_add(index));
        let balance = index.saturating_mul(10).to_be_bytes();
        db.manager()?.store_wallet_balance(&address, &balance)?;
        assert_some_vec(db.manager()?.get_wallet_balance(&address)?, &balance)?;
    }

    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    assert_eq!(reopened.get_latest_block_index()?, u64::from(u32::MAX));

    for index in 0..80u64 {
        let peer = format!("final-peer-{index:04}");
        let peer_data = format!("final-peer-data-{index:04}");
        assert_some_vec(reopened.get_peer_info(&peer)?, peer_data.as_bytes())?;

        let address = wallet(10_000u64.saturating_add(index));
        let balance = index.saturating_mul(10).to_be_bytes();
        assert_some_vec(reopened.get_wallet_balance(&address)?, &balance)?;
    }

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_101_accountmodel_manager_opens_and_reuses_initialized_handle() -> TestResult {
    let root = unique_root("accountmodel_reuses_handle");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path)?;

    let manager = RockDBManager::new_accountmodel(&opts, &blockchain_path_string)?;

    assert_eq!(manager.mode, Mode::AccountModel);

    let first = manager.open_db_accountmodel()?;
    let second = manager.open_db_accountmodel()?;

    assert!(
        first
            .cf_handle(GlobalConfiguration::STATE_COLUMN_NAME)
            .is_some()
    );
    assert!(
        second
            .cf_handle(GlobalConfiguration::ACCOUNT_COLUMN_NAME)
            .is_some()
    );

    drop(first);
    drop(second);
    drop(manager);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_102_from_blockchain_for_accountmodel_reuses_existing_blockchain_handle() -> TestResult {
    let db = new_blockchain_db("from_blockchain_for_accountmodel")?;

    let accountmodel = RockDBManager::from_blockchain_for_accountmodel(db.manager()?)?;

    assert_eq!(accountmodel.mode, Mode::AccountModel);

    let handle = accountmodel.open_db_accountmodel()?;
    assert!(
        handle
            .cf_handle(GlobalConfiguration::STATE_COLUMN_NAME)
            .is_some()
    );
    assert!(
        handle
            .cf_handle(GlobalConfiguration::ACCOUNT_COLUMN_NAME)
            .is_some()
    );

    Ok(())
}

#[test]
fn test_103_accountmodel_mode_can_write_state_column_but_rejects_network_column() -> TestResult {
    let db = new_blockchain_db("accountmodel_write_column_policy")?;
    let accountmodel = RockDBManager::from_blockchain_for_accountmodel(db.manager()?)?;

    accountmodel.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        b"state-test-key",
        b"state-ok",
    )?;

    assert_some_vec(
        accountmodel.read(GlobalConfiguration::STATE_COLUMN_NAME, b"state-test-key")?,
        b"state-ok",
    )?;

    let result = accountmodel.write(GlobalConfiguration::NETWORK_COLUMN_NAME, b"bad", b"bad");
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_104_accountmodel_mode_can_write_account_column() -> TestResult {
    let db = new_blockchain_db("accountmodel_write_account_column")?;
    let accountmodel = RockDBManager::from_blockchain_for_accountmodel(db.manager()?)?;

    let account = wallet(104);
    let balance = 1040u64.to_be_bytes();

    accountmodel.write(
        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
        account.as_bytes(),
        &balance,
    )?;

    assert_some_vec(
        accountmodel.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, account.as_bytes())?,
        &balance,
    )?;

    Ok(())
}

#[test]
fn test_105_accountmodel_store_state_and_load_state_round_trip_using_reused_handle() -> TestResult {
    let db = new_blockchain_db("accountmodel_state_round_trip_reused")?;
    let accountmodel = RockDBManager::from_blockchain_for_accountmodel(db.manager()?)?;

    let mut state = AccountModelTree::with_manager(accountmodel.clone());
    let alice = wallet(105);
    let bob = wallet(106);

    state.set_balance(&alice, 1050);
    state.set_balance(&bob, 1060);

    accountmodel.store_state(&state)?;

    let loaded = accountmodel.load_state()?;

    assert_eq!(loaded.get_balance(&alice), 1050);
    assert_eq!(loaded.get_balance(&bob), 1060);

    Ok(())
}

#[test]
fn test_106_new_accountmodel_state_round_trip_without_second_db_open() -> TestResult {
    let root = unique_root("new_accountmodel_state_round_trip");
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path)?;

    let manager = RockDBManager::new_accountmodel(&opts, &blockchain_path_string)?;

    let mut state = AccountModelTree::with_manager(manager.clone());
    let account = wallet(107);

    state.set_balance(&account, 1070);
    manager.store_state(&state)?;

    let loaded = manager.load_state()?;

    assert_eq!(loaded.get_balance(&account), 1070);

    // Windows keeps RocksDB files locked while cloned managers/state trees live.
    drop(loaded);
    drop(state);
    drop(manager);

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn test_107_get_last_blocks_rejects_request_above_guarded_cap() -> TestResult {
    let db = new_blockchain_db("get_last_blocks_cap")?;

    let result = db.manager()?.get_last_blocks(4_097);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_108_get_last_blocks_allows_request_at_guarded_cap() -> TestResult {
    let db = new_blockchain_db("get_last_blocks_at_cap")?;

    let blocks = db.manager()?.get_last_blocks(4_096)?;

    assert!(blocks.is_empty());
    Ok(())
}

#[test]
fn test_109_accountmodel_delete_rejects_network_column() -> TestResult {
    let db = new_blockchain_db("accountmodel_delete_reject_network")?;
    let accountmodel = RockDBManager::from_blockchain_for_accountmodel(db.manager()?)?;

    let result = accountmodel.delete(GlobalConfiguration::NETWORK_COLUMN_NAME, b"peer-x");

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_110_accountmodel_delete_rejects_account_column_without_mutation() -> TestResult {
    let db = new_blockchain_db("accountmodel_delete_account_column")?;
    let accountmodel = RockDBManager::from_blockchain_for_accountmodel(db.manager()?)?;

    let account = wallet(110);
    let balance = 1100u64.to_be_bytes();

    accountmodel.write(
        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
        account.as_bytes(),
        &balance,
    )?;

    assert_some_vec(
        accountmodel.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, account.as_bytes())?,
        &balance,
    )?;

    let result = accountmodel.delete(GlobalConfiguration::ACCOUNT_COLUMN_NAME, account.as_bytes());

    assert!(result.is_err());

    // Delete is rejected in AccountModel mode, so the value must still exist.
    assert_some_vec(
        accountmodel.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, account.as_bytes())?,
        &balance,
    )?;

    Ok(())
}
