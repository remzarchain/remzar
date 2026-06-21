use fips204::ml_dsa_65;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::{BlockStore, Mode, RockDBManager};
use remzar::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const UNIX_2000: u64 = 946_684_800;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestDb {
    manager: Option<RockDBManager>,
    root: PathBuf,
}

impl TestDb {
    fn manager(&self) -> &RockDBManager {
        self.manager
            .as_ref()
            .expect("test DB manager must still be available")
    }

    fn manager_clone(&self) -> RockDBManager {
        self.manager().clone()
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        drop(self.manager.take());

        if std::fs::remove_dir_all(&self.root).is_err() {
            // Best-effort cleanup only.
        }
    }
}

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp())
        .unwrap_or(UNIX_2000)
        .max(UNIX_2000)
}

fn valid_timestamp(seed: u64) -> u64 {
    let now = now_secs();
    let span = now.saturating_sub(UNIX_2000).saturating_add(1);

    UNIX_2000.saturating_add(seed % span)
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_rocksdb_manager_prop_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> String {
    path.to_str()
        .expect("test path must be valid UTF-8")
        .to_owned()
}

fn wallet(seed: u64) -> String {
    format!("r{:0128x}", seed)
}

fn node_opts(root: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: path_to_string(&root.join("identity.key")),
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "error".to_owned(),
        data_dir: path_to_string(root),
        wallet_address: wallet(1),
        founder: false,
    }
}

fn new_test_db(label: &str) -> TestDb {
    let root = unique_root(label);

    std::fs::create_dir_all(&root).expect("test root directory should be created");

    let opts = node_opts(&root);
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path);

    let manager = RockDBManager::new_blockchain(&opts, &blockchain_path_string)
        .expect("test blockchain RocksDB manager should initialize");

    TestDb {
        manager: Some(manager),
        root,
    }
}

fn new_cli_manager(label: &str) -> (RockDBManager, PathBuf) {
    let root = unique_root(label);

    std::fs::create_dir_all(&root).expect("test root directory should be created");

    let opts = node_opts(&root);
    let manager = RockDBManager::new(&opts).expect("CLI manager should initialize");

    (manager, root)
}

fn new_account_manager(label: &str) -> (RockDBManager, PathBuf) {
    let root = unique_root(label);

    std::fs::create_dir_all(&root).expect("test root directory should be created");

    let opts = node_opts(&root);
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path);

    let manager = RockDBManager::new_accountmodel(&opts, &blockchain_path_string)
        .expect("AccountModel manager should initialize");

    (manager, root)
}

fn hash64(tag: u8, seed: u64) -> Hash {
    let fill = match tag {
        0 => 1,
        0xFF => 0xFE,
        value => value,
    };

    let mut out = [fill; 64];
    out[..8].copy_from_slice(&seed.to_be_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    if out == [0xFFu8; 64] {
        out[63] = 0xFE;
    }

    out
}

fn distinct_hash64(tag: u8, seed: u64, other: Hash) -> Hash {
    let mut out = hash64(tag, seed);

    if out == other {
        out[63] ^= 1;

        if out == [0u8; 64] || out == [0xFFu8; 64] {
            out[63] = 0x7F;
        }
    }

    out
}

fn signature(seed: u64, tag: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    let base = u8::try_from(seed % 200).expect("seed modulo 200 must fit into u8");
    let byte = base.saturating_add(tag.max(1));

    [byte; ml_dsa_65::SIG_LEN]
}

fn block_with_parent(height: u64, parent_hash: Hash, seed: u64, tag: u8) -> Block {
    if height == 0 {
        assert_eq!(
            parent_hash, [0u8; 64],
            "height zero test block must use zero previous_hash"
        );
    } else {
        assert_ne!(
            parent_hash, [0u8; 64],
            "non-genesis test block must use nonzero previous_hash"
        );
    }

    let mut merkle_root = hash64(tag.wrapping_add(0x80), seed.wrapping_add(1));

    if merkle_root == parent_hash {
        merkle_root[63] ^= 1;
    }

    let metadata = BlockMetadata::new(
        height,
        valid_timestamp(seed),
        parent_hash,
        merkle_root,
        signature(seed, tag),
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_rocksdb_manager_{height}_{seed}_{tag}")),
        wallet(seed.wrapping_add(u64::from(tag))),
        0,
    )
    .expect("generated valid RocksDB-manager test block should construct")
}

fn genesis_block(seed: u64, tag: u8) -> Block {
    block_with_parent(0, [0u8; 64], seed, tag)
}

fn child_block(parent: &Block, seed: u64, tag: u8) -> Block {
    block_with_parent(
        parent.metadata.index.saturating_add(1),
        parent.block_hash,
        seed,
        tag,
    )
}

fn block_bytes(block: &Block) -> Vec<u8> {
    block
        .serialize_for_storage()
        .expect("generated block must serialize for storage")
}

fn batch_bytes(tag: u8, seed: u64, len: usize) -> Vec<u8> {
    let size = len.max(1);
    let mut out = Vec::with_capacity(size);

    for i in 0..size {
        let index = u64::try_from(i).expect("test byte index must fit u64");
        let byte = seed
            .wrapping_add(index)
            .wrapping_add(u64::from(tag))
            .to_le_bytes()[0];

        out.push(byte);
    }

    out
}

fn fork_meta(
    parent_hash: Hash,
    height: u64,
    cumulative_score: u128,
    status: ForkBlockStatus,
    received_at_unix_secs: u64,
) -> ForkBlockMeta {
    ForkBlockMeta {
        parent_hash,
        height,
        cumulative_score,
        status,
        received_at_unix_secs,
    }
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_blockchain_initializes_blockchain_mode_and_open_handle(
        _case in any::<u8>(),
    ) {
        let db = new_test_db("init_blockchain");

        prop_assert_eq!(&db.manager().mode, &Mode::Blockchain);
        prop_assert!(db.manager().directory.blockchain_path.exists());
        prop_assert!(db.manager().open_db_blockchain().is_ok());
    }

    // 02/25
    #[test]
    fn test_002_new_cli_initializes_cli_mode_and_directory_without_blockchain_handle(
        _case in any::<u8>(),
    ) {
        let (manager, root) = new_cli_manager("init_cli");

        prop_assert_eq!(&manager.mode, &Mode::CLI);
        prop_assert!(manager.directory.db_path.exists());

        prop_assert!(
            manager.open_db_blockchain().is_err(),
            "CLI manager must not expose a blockchain handle"
        );

        drop(manager);
        let _ = std::fs::remove_dir_all(root);
    }

    // 03/25
    #[test]
    fn test_003_new_accountmodel_initializes_account_mode_and_can_load_empty_state(
        _case in any::<u8>(),
    ) {
        let (manager, root) = new_account_manager("init_accountmodel");

        prop_assert_eq!(&manager.mode, &Mode::AccountModel);
        prop_assert!(manager.directory.blockchain_path.exists());

        let state = manager
            .load_state()
            .expect("empty AccountModel DB should load a new state tree");

        prop_assert_eq!(state.latest_block_height(), 0);

        drop(manager);
        let _ = std::fs::remove_dir_all(root);
    }

    // 04/25
    #[test]
    fn test_004_blockchain_clone_shares_same_underlying_handle_and_data(
        key_seed in any::<u64>(),
        value in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("clone_shared_handle");
        let cloned = db.manager_clone();

        let key = format!("clone_key_{key_seed}");

        db.manager()
            .store_metadata(&key, &value)
            .expect("metadata write through original should succeed");

        prop_assert_eq!(
            cloned
                .read(GlobalConfiguration::GLOBAL_COLUMN_NAME, key.as_bytes())
                .expect("metadata read through clone should succeed"),
            Some(value),
            "cloned blockchain manager must see writes from original manager"
        );
    }

    // 05/25
    #[test]
    fn test_005_store_metadata_roundtrips_exact_bytes_and_overwrites_same_key(
        key_seed in any::<u64>(),
        first in proptest::collection::vec(any::<u8>(), 1..256),
        second in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("metadata_roundtrip");

        let key = format!("meta_key_{key_seed}");

        db.manager()
            .store_metadata(&key, &first)
            .expect("first metadata write should succeed");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::GLOBAL_COLUMN_NAME, key.as_bytes())
                .expect("metadata read should succeed"),
            Some(first),
            "metadata must roundtrip exact first bytes"
        );

        db.manager()
            .store_metadata(&key, &second)
            .expect("second metadata write should overwrite");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::GLOBAL_COLUMN_NAME, key.as_bytes())
                .expect("metadata read after overwrite should succeed"),
            Some(second),
            "same metadata key must be overwritten by the latest value"
        );
    }

    // 06/25
    #[test]
    fn test_006_generic_write_read_delete_roundtrips_and_removes_network_column_entry(
        key_seed in any::<u64>(),
        value in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("generic_crud");

        let key = format!("network_key_{key_seed}");

        db.manager()
            .write(
                GlobalConfiguration::NETWORK_COLUMN_NAME,
                key.as_bytes(),
                &value,
            )
            .expect("generic write to NETWORK CF should succeed");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::NETWORK_COLUMN_NAME, key.as_bytes())
                .expect("generic read should succeed"),
            Some(value),
            "generic write/read must preserve exact bytes"
        );

        db.manager()
            .delete(GlobalConfiguration::NETWORK_COLUMN_NAME, key.as_bytes())
            .expect("generic delete should succeed");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::NETWORK_COLUMN_NAME, key.as_bytes())
                .expect("read after delete should succeed"),
            None,
            "delete must remove the exact key"
        );
    }

    // 07/25
    #[test]
    fn test_007_read_unknown_key_returns_none_without_error(
        key_seed in any::<u64>(),
    ) {
        let db = new_test_db("read_unknown");

        let key = format!("missing_key_{key_seed}");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::GLOBAL_COLUMN_NAME, key.as_bytes())
                .expect("unknown key read should succeed"),
            None,
            "unknown key must return None, not an error"
        );
    }

    // 08/25
    #[test]
    fn test_008_read_and_write_unknown_column_family_fail_safely(
        key in proptest::collection::vec(any::<u8>(), 1..64),
        value in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let db = new_test_db("unknown_cf");

        prop_assert!(
            db.manager().read("definitely_not_a_real_cf", &key).is_err(),
            "read from unknown CF must fail safely"
        );

        prop_assert!(
            db.manager().write("definitely_not_a_real_cf", &key, &value).is_err(),
            "write to unknown CF must fail safely"
        );
    }

    // 09/25
    #[test]
    fn test_009_register_peer_and_remove_peer_write_and_delete_network_data(
        peer_seed in any::<u64>(),
        data in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("peer_register_remove");

        let peer_id = format!("peer_{peer_seed}");

        db.manager()
            .register_peer(&peer_id, &data)
            .expect("register_peer should write NETWORK CF data");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::NETWORK_COLUMN_NAME, peer_id.as_bytes())
                .expect("registered peer read should succeed"),
            Some(data),
            "register_peer must store exact peer data"
        );

        db.manager()
            .remove_peer(&peer_id)
            .expect("remove_peer should delete NETWORK CF data");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::NETWORK_COLUMN_NAME, peer_id.as_bytes())
                .expect("removed peer read should succeed"),
            None,
            "remove_peer must remove exact peer id"
        );
    }

    // 10/25
    #[test]
    fn test_010_store_wallet_balance_writes_exact_account_cf_bytes(
        wallet_seed in any::<u64>(),
        balance_bytes in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let db = new_test_db("wallet_balance");

        let wallet_address = wallet(wallet_seed);

        db.manager()
            .store_wallet_balance(&wallet_address, &balance_bytes)
            .expect("store_wallet_balance should write ACCOUNT CF bytes");

        prop_assert_eq!(
            db.manager()
                .read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, wallet_address.as_bytes())
                .expect("wallet balance read should succeed"),
            Some(balance_bytes),
            "store_wallet_balance must preserve exact caller bytes"
        );
    }

    // 11/30
    #[test]
    fn test_011_set_account_balance_mirrors_postcard_u64_to_account_column(
        wallet_seed in any::<u64>(),
        balance in 0u64..=GlobalConfiguration::MAX_SUPPLY,
    ) {
        let db = new_test_db("set_account_balance");

        let wallet_address = wallet(wallet_seed);

        db.manager()
            .set_account_balance(&wallet_address, balance)
            .expect("set_account_balance should update state and ACCOUNT CF mirror");

        let raw = db.manager()
            .read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, wallet_address.as_bytes())
            .expect("ACCOUNT CF read should succeed")
            .expect("ACCOUNT CF balance should exist");

        let decoded: u64 = postcard::from_bytes(&raw)
            .expect("ACCOUNT CF mirror should be postcard-encoded u64");

        prop_assert_eq!(
            decoded,
            balance,
            "set_account_balance must mirror the exact valid u64 balance to ACCOUNT CF"
        );

        prop_assert_eq!(
            db.manager()
                .get_account_balance(&wallet_address)
                .expect("state balance getter should succeed"),
            balance,
            "set_account_balance must also persist the same value in account state"
        );
    }

    // 12/25
    #[test]
    fn test_012_set_latest_block_index_updates_both_latest_index_and_tip_height_metadata(
        height in any::<u64>(),
    ) {
        let db = new_test_db("latest_index_tip_height");

        db.manager()
            .set_latest_block_index(height)
            .expect("set_latest_block_index should write metadata");

        prop_assert_eq!(
            db.manager()
                .get_latest_block_index()
                .expect("latest block index read should succeed"),
            height,
            "latest_block_index metadata must match the written height"
        );

        prop_assert_eq!(
            db.manager()
                .get_tip_height()
                .expect("tip height read should succeed"),
            height,
            "tip_height metadata must be kept in sync with latest_block_index"
        );
    }

    // 13/25
    #[test]
    fn test_013_store_latest_block_and_get_block_by_index_roundtrip_exact_block(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("block_by_index_roundtrip");

        let block = genesis_block(seed, 0x21);
        let bytes = block_bytes(&block);

        db.manager()
            .store_latest_block(&bytes, block.metadata.index)
            .expect("store_latest_block should store canonical block projection");

        let fetched = db.manager()
            .get_block_by_index(block.metadata.index)
            .expect("get_block_by_index should succeed")
            .expect("stored block by index should exist");

        prop_assert_eq!(
            &fetched,
            &block,
            "block_{height} projection must deserialize to the exact stored block",
            height = block.metadata.index
        );
    }

    // 14/25
    #[test]
    fn test_014_get_latest_block_and_hash_return_highest_stored_block(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("latest_block_highest");

        let genesis = genesis_block(seed, 0x22);
        let child = child_block(&genesis, seed.wrapping_add(1), 0x23);

        db.manager()
            .store_latest_block(&block_bytes(&genesis), genesis.metadata.index)
            .expect("genesis store should succeed");

        db.manager()
            .store_latest_block(&block_bytes(&child), child.metadata.index)
            .expect("child store should succeed");

        let latest = db.manager()
            .get_latest_block()
            .expect("latest block lookup should succeed")
            .expect("latest block should exist");

        prop_assert_eq!(
            &latest,
            &child,
            "get_latest_block must return highest block_{{index}} entry"
        );

        prop_assert_eq!(
            db.manager()
                .get_latest_block_hash()
                .expect("latest block hash should read"),
            child.block_hash,
            "get_latest_block_hash must return the latest block's hash"
        );
    }

    // 15/25
    #[test]
    fn test_015_store_latest_block_rejects_oversized_block_data_without_writing_index(
        height in 0u64..64u64,
    ) {
        let db = new_test_db("oversized_block_reject");

        let max_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
            .unwrap_or(usize::MAX.saturating_sub(1));

        let oversized = vec![0xAB; max_size.saturating_add(1)];

        prop_assert!(
            db.manager().store_latest_block(&oversized, height).is_err(),
            "store_latest_block must reject block_data larger than MAX_BLOCK_SIZE"
        );

        prop_assert!(
            db.manager()
                .get_block_by_index(height)
                .expect("block lookup after rejected oversized write should succeed")
                .is_none(),
            "rejected oversized block must not create block_{{height}} projection"
        );
    }

    // 16/25
    #[test]
    fn test_016_delete_block_removes_exact_canonical_block_key(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("delete_block");

        let block = genesis_block(seed, 0x24);

        db.manager()
            .store_latest_block(&block_bytes(&block), block.metadata.index)
            .expect("block projection store should succeed");

        let key = format!("block_{:010}", block.metadata.index);

        db.manager()
            .delete_block(key.as_bytes())
            .expect("delete_block should delete exact block key");

        prop_assert!(
            db.manager()
                .get_block_by_index(block.metadata.index)
                .expect("block lookup after delete should succeed")
                .is_none(),
            "delete_block must remove the canonical block projection"
        );
    }

    // 17/25
    #[test]
    fn test_017_index_block_by_hash_canonicalizes_and_get_block_by_hash_roundtrips(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("block_by_hash_roundtrip");

        let block = genesis_block(seed, 0x25);
        let bytes = block_bytes(&block);

        db.manager()
            .index_block_by_hash(&block.block_hash, &bytes)
            .expect("index_block_by_hash should store canonicalized block bytes");

        prop_assert!(
            db.manager().has_block_by_hash(&block.block_hash),
            "has_block_by_hash must be true after indexing"
        );

        let fetched = db.manager()
            .get_block_by_hash(&block.block_hash)
            .expect("block indexed by hash should be readable");

        prop_assert_eq!(
            &fetched,
            &block,
            "get_block_by_hash must deserialize the exact indexed block"
        );
    }

    // 18/25
    #[test]
    fn test_018_index_block_by_hash_rejects_corrupt_bytes_and_does_not_create_entry(
        hash_seed in any::<u64>(),
        corrupt in proptest::collection::vec(any::<u8>(), 0..8),
    ) {
        let db = new_test_db("block_by_hash_corrupt_reject");

        let hash = hash64(0x26, hash_seed);

        prop_assert!(
            db.manager().index_block_by_hash(&hash, &corrupt).is_err(),
            "corrupt or too-short block bytes must be rejected by defensive canonicalization"
        );

        prop_assert!(
            !db.manager().has_block_by_hash(&hash),
            "failed corrupt indexing must not create readable hash-indexed block"
        );
    }

    // 19/25
    #[test]
    fn test_019_batch_by_block_hash_roundtrips_exact_bytes_and_presence(
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("batch_by_hash");

        let hash = hash64(0x27, hash_seed);

        db.manager()
            .store_batch_by_block_hash(&hash, &bytes)
            .expect("batch-by-block-hash store should succeed");

        prop_assert!(
            db.manager()
                .has_batch_by_block_hash(&hash)
                .expect("batch-by-hash presence check should succeed"),
            "has_batch_by_block_hash must become true after store"
        );

        prop_assert_eq!(
            db.manager()
                .get_batch_by_block_hash(&hash)
                .expect("batch-by-hash read should succeed"),
            Some(bytes),
            "batch-by-block-hash must preserve exact bytes"
        );
    }

    // 20/25
    #[test]
    fn test_020_canonical_batch_projection_roundtrips_and_overwrites_by_height(
        height in 0u64..128u64,
        first in proptest::collection::vec(any::<u8>(), 1..256),
        second in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("canonical_batch_projection");

        db.manager()
            .store_batch_bytes(height, &first)
            .expect("first canonical batch projection should store");

        prop_assert_eq!(
            db.manager()
                .get_batch_bytes_by_index(height)
                .expect("canonical batch lookup should succeed"),
            Some(first),
            "first canonical tx_batch projection must roundtrip"
        );

        db.manager()
            .store_batch_bytes(height, &second)
            .expect("second canonical batch projection should overwrite");

        prop_assert_eq!(
            db.manager()
                .get_batch_bytes_by_index(height)
                .expect("canonical batch lookup after overwrite should succeed"),
            Some(second),
            "canonical tx_batch projection at same height must overwrite"
        );
    }

    // 21/25
    #[test]
    fn test_021_canonical_height_to_hash_set_get_delete_range_is_inclusive(
        base in 0u64..64u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("canonical_hash_range");

        let h0 = base;
        let h1 = base.saturating_add(1);
        let h2 = base.saturating_add(2);

        let hash0 = hash64(0x28, seed);
        let hash1 = hash64(0x29, seed);
        let hash2 = hash64(0x2A, seed);

        db.manager().set_canonical_hash_at_height(h0, &hash0).expect("h0 canonical hash should set");
        db.manager().set_canonical_hash_at_height(h1, &hash1).expect("h1 canonical hash should set");
        db.manager().set_canonical_hash_at_height(h2, &hash2).expect("h2 canonical hash should set");

        prop_assert_eq!(
            db.manager().get_canonical_hash_at_height(h1).expect("h1 canonical hash should read"),
            Some(hash1)
        );

        db.manager()
            .delete_canonical_hash_range(h1, h2)
            .expect("delete_canonical_hash_range should delete inclusively");

        prop_assert_eq!(
            db.manager().get_canonical_hash_at_height(h0).expect("h0 canonical hash should read"),
            Some(hash0),
            "delete range must preserve heights below range"
        );

        prop_assert_eq!(
            db.manager().get_canonical_hash_at_height(h1).expect("h1 canonical hash should read"),
            None,
            "delete range must remove start height"
        );

        prop_assert_eq!(
            db.manager().get_canonical_hash_at_height(h2).expect("h2 canonical hash should read"),
            None,
            "delete range must remove end height"
        );
    }

    // 22/25
    #[test]
    fn test_022_canonical_tip_roundtrips_hash_and_height_and_syncs_tip_height(
        height in 0u64..1_000_000u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("canonical_tip");

        let hash = hash64(0x2B, seed);

        db.manager()
            .set_canonical_tip(&hash, height)
            .expect("canonical tip should set");

        let tip = db.manager()
            .get_canonical_tip()
            .expect("canonical tip read should succeed")
            .expect("canonical tip should exist");

        prop_assert_eq!(tip.tip_hash, hash);
        prop_assert_eq!(tip.tip_height, height);

        prop_assert_eq!(
            db.manager()
                .get_canonical_tip_hash()
                .expect("canonical tip hash should read"),
            Some(hash)
        );

        prop_assert_eq!(
            db.manager()
                .get_canonical_tip_height()
                .expect("canonical tip height should read"),
            Some(height)
        );

        prop_assert_eq!(
            db.manager().get_tip_height().expect("legacy tip height should read"),
            height,
            "set_canonical_tip must keep legacy tip_height metadata in sync"
        );
    }

    // 23/25
    #[test]
    fn test_023_block_meta_by_hash_roundtrips_and_status_update_changes_only_status(
        hash_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 0u64..1_000_000u64,
        score in any::<u128>(),
    ) {
        let db = new_test_db("block_meta_by_hash");

        let hash = hash64(0x2C, hash_seed);
        let parent = distinct_hash64(0x2D, parent_seed, hash);

        let meta = fork_meta(
            parent,
            height,
            score,
            ForkBlockStatus::SideBranch,
            valid_timestamp(height),
        );

        db.manager()
            .store_block_meta_by_hash(&hash, &meta)
            .expect("block meta by hash should store");

        prop_assert!(
            db.manager()
                .has_block_meta_by_hash(&hash)
                .expect("block meta presence should read"),
            "has_block_meta_by_hash must be true after store"
        );

        prop_assert_eq!(
            db.manager()
                .get_block_meta_by_hash(&hash)
                .expect("block meta lookup should succeed"),
            Some(meta.clone()),
            "block meta by hash must roundtrip all fields"
        );

        db.manager()
            .set_block_meta_status(&hash, ForkBlockStatus::Canonical)
            .expect("block meta status update should succeed");

        let updated = db.manager()
            .get_block_meta_by_hash(&hash)
            .expect("updated block meta lookup should succeed")
            .expect("updated block meta should exist");

        prop_assert_eq!(updated.parent_hash, meta.parent_hash);
        prop_assert_eq!(updated.height, meta.height);
        prop_assert_eq!(updated.cumulative_score, meta.cumulative_score);
        prop_assert_eq!(updated.received_at_unix_secs, meta.received_at_unix_secs);
        prop_assert_eq!(updated.status, ForkBlockStatus::Canonical);
    }

    // 24/25
    #[test]
    fn test_024_public_delete_paths_remove_block_projection_batch_projection_and_hash_index(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("public_delete_paths");

        let block = genesis_block(seed, 0x2E);
        let bytes = block_bytes(&block);
        let batch = batch_bytes(0xB1, seed, 32);

        db.manager()
            .store_latest_block(&bytes, block.metadata.index)
            .expect("canonical block projection should store");

        db.manager()
            .index_block_by_hash(&block.block_hash, &bytes)
            .expect("block hash index should store");

        db.manager()
            .store_batch_bytes(block.metadata.index, &batch)
            .expect("canonical batch projection should store");

        prop_assert!(db.manager().has_block_by_hash(&block.block_hash));
        prop_assert!(db.manager().get_block_by_index(block.metadata.index).expect("block by index should read").is_some());
        prop_assert!(db.manager().get_batch_bytes_by_index(block.metadata.index).expect("batch by index should read").is_some());

        let block_key = format!("block_{:010}", block.metadata.index);
        let batch_key = format!("tx_batch_{:010}", block.metadata.index);

        db.manager()
            .delete_block(block_key.as_bytes())
            .expect("delete_block should remove canonical block projection");

        db.manager()
            .delete(
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                batch_key.as_bytes(),
            )
            .expect("generic delete should remove canonical batch projection");

        db.manager()
            .delete(
                GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
                &block.block_hash,
            )
            .expect("generic delete should remove block-by-hash mapping");

        prop_assert!(
            !db.manager().has_block_by_hash(&block.block_hash),
            "generic delete from BLOCK_TO_HASH CF must delete block hash mapping"
        );

        prop_assert!(
            db.manager()
                .get_block_by_index(block.metadata.index)
                .expect("block by index after removal should read")
                .is_none(),
            "delete_block must delete canonical block projection"
        );

        prop_assert!(
            db.manager()
                .get_batch_bytes_by_index(block.metadata.index)
                .expect("batch by index after removal should read")
                .is_none(),
            "generic delete from TRANSACTION_BATCH CF must delete canonical batch projection"
        );
    }

    // 25/25
    #[test]
    fn test_025_blockstore_common_ancestor_and_blocks_between_follow_stored_canonical_chain(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("blockstore_trait");

        let genesis = genesis_block(seed, 0x2F);
        let b1 = child_block(&genesis, seed.wrapping_add(1), 0x30);
        let b2 = child_block(&b1, seed.wrapping_add(2), 0x31);

        for block in [&genesis, &b1, &b2] {
            let bytes = block_bytes(block);

            db.manager()
                .store_latest_block(&bytes, block.metadata.index)
                .expect("canonical block projection should store");

            db.manager()
                .index_block_by_hash(&block.block_hash, &bytes)
                .expect("hash-indexed block should store");
        }

        prop_assert_eq!(
            db.manager().find_common_ancestor(b2.block_hash),
            Some(b2.block_hash),
            "find_common_ancestor must return the queried hash when it is already locally indexed"
        );

        let between = db.manager()
            .get_blocks_between(genesis.block_hash, b2.block_hash)
            .expect("get_blocks_between should return contiguous canonical blocks");

        prop_assert_eq!(
            between,
            vec![b1, b2],
            "get_blocks_between must return ancestor-exclusive, tip-inclusive ordered blocks"
        );
    }

    // 26/30
    #[test]
    fn test_026_getter_wrappers_return_metadata_peer_and_wallet_values(
        seed in any::<u64>(),
        meta_value in proptest::collection::vec(any::<u8>(), 1..256),
        peer_value in proptest::collection::vec(any::<u8>(), 1..256),
        wallet_value in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let db = new_test_db("getter_wrappers");

        let meta_key = format!("meta_getter_{seed}");
        let peer_id = format!("peer_getter_{seed}");
        let wallet_address = wallet(seed);

        db.manager()
            .store_metadata(&meta_key, &meta_value)
            .expect("metadata should store");

        db.manager()
            .register_peer(&peer_id, &peer_value)
            .expect("peer should register");

        db.manager()
            .store_wallet_balance(&wallet_address, &wallet_value)
            .expect("wallet balance bytes should store");

        prop_assert_eq!(
            db.manager()
                .get_metadata(&meta_key)
                .expect("metadata getter should succeed"),
            Some(meta_value),
            "get_metadata must return exact metadata bytes"
        );

        prop_assert_eq!(
            db.manager()
                .get_peer_info(&peer_id)
                .expect("peer getter should succeed"),
            Some(peer_value),
            "get_peer_info must return exact peer bytes"
        );

        prop_assert_eq!(
            db.manager()
                .get_wallet_balance(&wallet_address)
                .expect("wallet getter should succeed"),
            Some(wallet_value),
            "get_wallet_balance must return exact wallet bytes"
        );
    }

    // 27/30
    #[test]
    fn test_027_list_column_families_contains_core_blockchain_columns(
        _case in any::<u8>(),
    ) {
        let db = new_test_db("list_column_families");

        let cfs = db.manager()
            .list_column_families()
            .expect("list_column_families should succeed for Blockchain mode");

        prop_assert!(
            cfs.iter().any(|cf| cf == GlobalConfiguration::GLOBAL_COLUMN_NAME),
            "GLOBAL CF must exist"
        );

        prop_assert!(
            cfs.iter().any(|cf| cf == GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME),
            "BLOCKMINT_DATA CF must exist"
        );

        prop_assert!(
            cfs.iter().any(|cf| cf == GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME),
            "TRANSACTION_BATCH CF must exist"
        );

        prop_assert!(
            cfs.iter().any(|cf| cf == GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME),
            "BLOCK_TO_HASH CF must exist"
        );

        prop_assert!(
            cfs.iter().any(|cf| cf == GlobalConfiguration::ACCOUNT_COLUMN_NAME),
            "ACCOUNT CF must exist"
        );
    }

    // 28/30
    #[test]
    fn test_028_block_bytes_hash_indices_and_last_blocks_roundtrip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("block_bytes_hash_indices_last_blocks");

        let genesis = genesis_block(seed, 0x32);
        let b1 = child_block(&genesis, seed.wrapping_add(1), 0x33);
        let b2 = child_block(&b1, seed.wrapping_add(2), 0x34);

        let genesis_bytes = block_bytes(&genesis);
        let b1_bytes = block_bytes(&b1);
        let b2_bytes = block_bytes(&b2);

        for (block, bytes) in [
            (&genesis, &genesis_bytes),
            (&b1, &b1_bytes),
            (&b2, &b2_bytes),
        ] {
            db.manager()
                .store_latest_block(bytes, block.metadata.index)
                .expect("canonical block projection should store");

            db.manager()
                .index_block_by_hash(&block.block_hash, bytes)
                .expect("hash index should store");
        }

        prop_assert_eq!(
            db.manager()
                .get_block_hash_by_index(b1.metadata.index)
                .expect("block hash by index should read"),
            b1.block_hash,
            "get_block_hash_by_index must return stored block hash"
        );

        prop_assert_eq!(
            db.manager()
                .get_block_bytes_by_index(b2.metadata.index)
                .expect("block bytes by index should read"),
            Some(b2_bytes),
            "get_block_bytes_by_index must return exact stored bytes"
        );

        prop_assert_eq!(
            db.manager()
                .list_block_indices()
                .expect("list_block_indices should succeed"),
            vec![
                format!("block_{:010}", genesis.metadata.index),
                format!("block_{:010}", b1.metadata.index),
                format!("block_{:010}", b2.metadata.index),
            ],
            "list_block_indices must return canonical block keys in ascending key order"
        );

        let last_two = db.manager()
            .get_last_blocks(2)
            .expect("get_last_blocks should succeed");

        prop_assert_eq!(
            last_two,
            vec![b2, b1],
            "get_last_blocks(2) must return newest blocks first"
        );
    }

    // 29/30
    #[test]
    fn test_029_tx_batch_alias_lookup_and_addr_index_height_roundtrip(
        height in 0u64..1_000_000u64,
        seed in any::<u64>(),
        len in 1usize..512usize,
    ) {
        let db = new_test_db("tx_batch_alias_addr_index_height");

        let bytes = batch_bytes(0xB2, seed, len);

        db.manager()
            .store_batch_bytes(height, &bytes)
            .expect("canonical batch bytes should store");

        prop_assert_eq!(
            db.manager()
                .get_batch_bytes_by_index(height)
                .expect("get_batch_bytes_by_index should succeed"),
            Some(bytes.clone()),
            "get_batch_bytes_by_index must return exact stored batch bytes"
        );

        prop_assert_eq!(
            db.manager()
                .get_tx_batch_bytes_by_index(height)
                .expect("get_tx_batch_bytes_by_index should succeed"),
            Some(bytes),
            "get_tx_batch_bytes_by_index must match canonical batch lookup"
        );

        db.manager()
            .set_addr_index_height(height)
            .expect("addr_index_height should store");

        prop_assert_eq!(
            db.manager()
                .get_addr_index_height()
                .expect("addr_index_height should read"),
            height,
            "addr_index_height must roundtrip exact height"
        );
    }

    // 30/30
    #[test]
    fn test_030_remove_block_by_index_removes_block_batch_and_hash_mapping(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("remove_block_by_index_full_cleanup");

        let block = genesis_block(seed, 0x35);
        let block_bytes = block_bytes(&block);
        let batch = batch_bytes(0xB3, seed, 64);

        db.manager()
            .store_latest_block(&block_bytes, block.metadata.index)
            .expect("canonical block projection should store");

        db.manager()
            .index_block_by_hash(&block.block_hash, &block_bytes)
            .expect("block hash mapping should store");

        db.manager()
            .store_batch_bytes(block.metadata.index, &batch)
            .expect("canonical batch projection should store");

        prop_assert!(
            db.manager()
                .get_block_by_index(block.metadata.index)
                .expect("block lookup before remove should succeed")
                .is_some(),
            "block must exist before remove_block_by_index"
        );

        prop_assert!(
            db.manager()
                .get_batch_bytes_by_index(block.metadata.index)
                .expect("batch lookup before remove should succeed")
                .is_some(),
            "batch must exist before remove_block_by_index"
        );

        prop_assert!(
            db.manager().has_block_by_hash(&block.block_hash),
            "hash mapping must exist before remove_block_by_index"
        );

        db.manager()
            .remove_block_by_index(block.metadata.index)
            .expect("remove_block_by_index should remove block, batch, and hash mapping");

        prop_assert!(
            db.manager()
                .get_block_by_index(block.metadata.index)
                .expect("block lookup after remove should succeed")
                .is_none(),
            "remove_block_by_index must delete canonical block projection"
        );

        prop_assert!(
            db.manager()
                .get_batch_bytes_by_index(block.metadata.index)
                .expect("batch lookup after remove should succeed")
                .is_none(),
            "remove_block_by_index must delete canonical tx_batch projection"
        );

        prop_assert!(
            !db.manager().has_block_by_hash(&block.block_hash),
            "remove_block_by_index must delete block hash mapping"
        );
    }
}
