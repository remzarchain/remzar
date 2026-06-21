use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::reorganization::reorg_001_block_index::ReorgBlockIndex;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

type BlockHash = [u8; 64];

const UNIX_2000: u64 = 946_684_800;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestDb {
    manager: Option<Arc<RockDBManager>>,
    root: PathBuf,
}

impl TestDb {
    fn manager(&self) -> Arc<RockDBManager> {
        Arc::clone(
            self.manager
                .as_ref()
                .expect("test database manager must be available"),
        )
    }

    fn index(&self) -> ReorgBlockIndex {
        ReorgBlockIndex::new(self.manager())
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

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_reorg_block_index_prop_{label}_{pid}_{id}"))
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
        manager: Some(Arc::new(manager)),
        root,
    }
}

fn hash64(tag: u8, seed: u64) -> BlockHash {
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

fn distinct_hash64(tag: u8, seed: u64, other: BlockHash) -> BlockHash {
    let mut out = hash64(tag, seed);

    if out == other {
        out[63] ^= 1;

        if out == [0u8; 64] || out == [0xFFu8; 64] {
            out[63] = 0x7F;
        }
    }

    out
}

fn valid_timestamp(seed: u64) -> u64 {
    UNIX_2000.saturating_add(seed % 900_000_000)
}

fn signature(seed: u64) -> [u8; ml_dsa_65::SIG_LEN] {
    let byte = u8::try_from(seed % 254)
        .expect("seed modulo 254 must fit into u8")
        .saturating_add(1);

    [byte; ml_dsa_65::SIG_LEN]
}

fn status_from_seed(seed: u8) -> ForkBlockStatus {
    match seed % 6 {
        0 => ForkBlockStatus::HeaderOnly,
        1 => ForkBlockStatus::BlockStored,
        2 => ForkBlockStatus::Validated,
        3 => ForkBlockStatus::Canonical,
        4 => ForkBlockStatus::SideBranch,
        _ => ForkBlockStatus::Orphan,
    }
}

fn block_with_parent(height: u64, parent_hash: BlockHash, seed: u64) -> Block {
    let merkle_root = distinct_hash64(0xA5, seed.wrapping_add(1), parent_hash);

    let metadata = BlockMetadata::new(
        height,
        valid_timestamp(seed),
        parent_hash,
        merkle_root,
        signature(seed),
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_reorg_{height}_{seed}")),
        wallet(seed),
        0,
    )
    .expect("generated valid reorg test block should construct")
}

fn child_block(parent: &Block, seed: u64) -> Block {
    block_with_parent(
        parent.metadata.index.saturating_add(1),
        parent.block_hash,
        seed,
    )
}

fn fork_meta(
    parent_hash: BlockHash,
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

fn meta_for_block(block: &Block, cumulative_score: u128, status: ForkBlockStatus) -> ForkBlockMeta {
    fork_meta(
        block.metadata.previous_hash,
        block.metadata.index,
        cumulative_score,
        status,
        valid_timestamp(block.metadata.index),
    )
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_reorg_block_index_keeps_the_exact_shared_db_arc(
        _case in any::<u8>(),
    ) {
        let db = new_test_db("new_arc");
        let manager = db.manager();
        let index = ReorgBlockIndex::new(Arc::clone(&manager));

        prop_assert!(
            Arc::ptr_eq(index.db(), &manager),
            "ReorgBlockIndex::new must keep the exact shared RockDBManager Arc"
        );
    }

    // 02/25
    #[test]
    fn test_002_empty_index_returns_none_or_false_for_unknown_hash(
        hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("empty_queries");
        let index = db.index();
        let hash = hash64(0x11, hash_seed);

        prop_assert!(
            !index.has_block(&hash),
            "empty index must not report unknown block hash as present"
        );

        prop_assert!(
            !index.has_meta(&hash).expect("empty metadata lookup should succeed"),
            "empty index must not report unknown metadata as present"
        );

        prop_assert!(
            index.get_block(&hash).expect("empty block lookup should succeed").is_none(),
            "empty index must return None for missing block"
        );

        prop_assert!(
            index.get_meta(&hash).expect("empty meta lookup should succeed").is_none(),
            "empty index must return None for missing metadata"
        );
    }

    // 03/25
    #[test]
    fn test_003_put_meta_roundtrips_all_fork_block_meta_fields(
        hash_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        score in any::<u128>(),
        status_seed in any::<u8>(),
        received_seed in any::<u64>(),
    ) {
        let db = new_test_db("put_meta_roundtrip");
        let index = db.index();

        let hash = hash64(0x12, hash_seed);
        let meta = fork_meta(
            hash64(0x13, parent_seed),
            height,
            score,
            status_from_seed(status_seed),
            valid_timestamp(received_seed),
        );

        index.put_meta(&hash, &meta)
            .expect("put_meta should store metadata");

        let fetched = index.get_meta(&hash)
            .expect("get_meta should read stored metadata")
            .expect("metadata should exist after put_meta");

        prop_assert_eq!(
            &fetched,
            &meta,
            "put_meta/get_meta must preserve every ForkBlockMeta field"
        );

        prop_assert!(
            index.has_meta(&hash).expect("has_meta should succeed"),
            "has_meta must become true after put_meta"
        );
    }

    // 04/25
    #[test]
    fn test_004_put_block_bytes_stores_valid_serialized_block_bytes_and_rejects_corrupt_bytes(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
        corrupt_hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("put_block_bytes");
        let index = db.index();

        let parent_hash = hash64(0x14, parent_seed);
        let block = block_with_parent(height, parent_hash, block_seed);
        let block_bytes = block
            .serialize_for_storage()
            .expect("generated block must serialize for storage");

        let hash = block.block_hash;
        let corrupt_hash = distinct_hash64(0x15, corrupt_hash_seed, hash);

        index.put_block_bytes(&hash, &block_bytes)
            .expect("put_block_bytes should store valid serialized block bytes");

        prop_assert!(
            index.has_block(&hash),
            "has_block must be true after valid serialized block bytes are stored"
        );

        let fetched = index.get_block(&hash)
            .expect("get_block should succeed after valid put_block_bytes")
            .expect("block should exist after valid put_block_bytes");

        prop_assert_eq!(
            &fetched,
            &block,
            "put_block_bytes/get_block must preserve the canonical decoded block"
        );

        let corrupt_bytes = vec![0x85u8, 0x70u8];

        prop_assert!(
            index.put_block_bytes(&corrupt_hash, &corrupt_bytes).is_err(),
            "put_block_bytes must reject corrupt/truncated block bytes"
        );

        prop_assert!(
            !index.has_block(&corrupt_hash),
            "failed corrupt put_block_bytes must not create a readable block entry"
        );
    }

    // 05/25
    #[test]
    fn test_005_put_block_and_get_block_roundtrip_preserves_block_hash_and_metadata(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
    ) {
        let db = new_test_db("put_block_roundtrip");
        let index = db.index();

        let block = block_with_parent(height, hash64(0x16, parent_seed), block_seed);
        let hash = block.block_hash;

        index.put_block(&block)
            .expect("put_block should serialize and store block");

        prop_assert!(
            index.has_block(&hash),
            "has_block must be true after put_block"
        );

        let fetched = index.get_block(&hash)
            .expect("get_block should succeed")
            .expect("block should exist after put_block");

        prop_assert_eq!(
            &fetched,
            &block,
            "put_block/get_block must preserve full block"
        );
    }

    // 06/25
    #[test]
    fn test_006_put_block_and_meta_stores_block_and_metadata_together(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
        score in any::<u128>(),
        status_seed in any::<u8>(),
    ) {
        let db = new_test_db("put_block_and_meta");
        let index = db.index();

        let block = block_with_parent(height, hash64(0x17, parent_seed), block_seed);
        let meta = meta_for_block(&block, score, status_from_seed(status_seed));

        index.put_block_and_meta(&block, &meta)
            .expect("put_block_and_meta should store both records");

        prop_assert!(index.has_block(&block.block_hash));
        prop_assert!(index.has_meta(&block.block_hash).expect("has_meta should succeed"));

        let fetched_meta = index.get_meta(&block.block_hash)
            .expect("get_meta should succeed")
            .expect("metadata should be stored");

        prop_assert_eq!(&fetched_meta, &meta);
    }

    // 07/25
    #[test]
    fn test_007_ingest_validated_block_with_batch_stores_block_meta_and_exact_batch_bytes(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
        batch in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let db = new_test_db("ingest_with_batch");
        let index = db.index();

        let block = block_with_parent(height, hash64(0x18, parent_seed), block_seed);
        let meta = meta_for_block(&block, u128::from(height), ForkBlockStatus::Validated);

        index.ingest_validated_block(&block, meta.clone(), Some(&batch))
            .expect("ingest_validated_block should store block, meta, and batch bytes");

        prop_assert!(index.has_block(&block.block_hash));
        prop_assert!(index.has_meta(&block.block_hash).expect("has_meta should succeed"));

        let stored_batch = index.db()
            .get_batch_by_block_hash(&block.block_hash)
            .expect("batch lookup by block hash should succeed")
            .expect("batch bytes should exist after ingest");

        prop_assert_eq!(
            &stored_batch,
            &batch,
            "ingest_validated_block must preserve exact batch bytes"
        );

        let stored_meta = index.get_meta(&block.block_hash)
            .expect("get_meta should succeed")
            .expect("metadata should exist");

        prop_assert_eq!(&stored_meta, &meta);
    }

    // 08/25
    #[test]
    fn test_008_ingest_validated_block_without_batch_does_not_create_batch_record(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
    ) {
        let db = new_test_db("ingest_without_batch");
        let index = db.index();

        let block = block_with_parent(height, hash64(0x19, parent_seed), block_seed);
        let meta = meta_for_block(&block, u128::from(height), ForkBlockStatus::Validated);

        index.ingest_validated_block(&block, meta, None)
            .expect("ingest_validated_block should allow missing batch bytes");

        prop_assert!(index.has_block(&block.block_hash));
        prop_assert!(index.has_meta(&block.block_hash).expect("has_meta should succeed"));

        prop_assert!(
            index.db()
                .get_batch_by_block_hash(&block.block_hash)
                .expect("batch lookup should succeed")
                .is_none(),
            "ingest without batch must not create a batch-by-block-hash record"
        );
    }

    // 09/25
    #[test]
    fn test_009_make_height_meta_copies_block_linkage_height_status_and_uses_height_as_score(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
        status_seed in any::<u8>(),
    ) {
        let db = new_test_db("make_height_meta");
        let index = db.index();

        let block = block_with_parent(height, hash64(0x1A, parent_seed), block_seed);
        let status = status_from_seed(status_seed);
        let meta = index.make_height_meta(&block, status);

        prop_assert_eq!(meta.parent_hash, block.metadata.previous_hash);
        prop_assert_eq!(meta.height, block.metadata.index);
        prop_assert_eq!(meta.cumulative_score, u128::from(block.metadata.index));
        prop_assert_eq!(meta.status, status);
        prop_assert!(
            meta.received_at_unix_secs >= UNIX_2000,
            "received_at_unix_secs should be a nonzero modern UNIX timestamp"
        );
    }

    // 10/25
    #[test]
    fn test_010_make_scored_meta_copies_block_linkage_height_status_and_explicit_score(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
        score in any::<u128>(),
        status_seed in any::<u8>(),
    ) {
        let db = new_test_db("make_scored_meta");
        let index = db.index();

        let block = block_with_parent(height, hash64(0x1B, parent_seed), block_seed);
        let status = status_from_seed(status_seed);
        let meta = index.make_scored_meta(&block, score, status);

        prop_assert_eq!(meta.parent_hash, block.metadata.previous_hash);
        prop_assert_eq!(meta.height, block.metadata.index);
        prop_assert_eq!(meta.cumulative_score, score);
        prop_assert_eq!(meta.status, status);
        prop_assert!(
            meta.received_at_unix_secs >= UNIX_2000,
            "received_at_unix_secs should be a nonzero modern UNIX timestamp"
        );
    }

    // 11/25
    #[test]
    fn test_011_parent_height_and_status_helpers_return_none_without_metadata(
        hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("helper_none");
        let index = db.index();
        let hash = hash64(0x1C, hash_seed);

        prop_assert!(
            index.parent_hash(&hash).expect("parent_hash should succeed").is_none(),
            "parent_hash helper must return None when metadata is missing"
        );

        prop_assert!(
            index.height_of(&hash).expect("height_of should succeed").is_none(),
            "height_of helper must return None when metadata is missing"
        );

        prop_assert!(
            index.status_of(&hash).expect("status_of should succeed").is_none(),
            "status_of helper must return None when metadata is missing"
        );
    }

    // 12/25
    #[test]
    fn test_012_parent_height_and_status_helpers_return_metadata_fields_after_put_meta(
        hash_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        score in any::<u128>(),
        status_seed in any::<u8>(),
    ) {
        let db = new_test_db("helper_some");
        let index = db.index();

        let hash = hash64(0x1D, hash_seed);
        let parent = hash64(0x1E, parent_seed);
        let status = status_from_seed(status_seed);
        let meta = fork_meta(parent, height, score, status, valid_timestamp(height));

        index.put_meta(&hash, &meta)
            .expect("put_meta should succeed");

        prop_assert_eq!(
            index.parent_hash(&hash).expect("parent_hash should succeed"),
            Some(parent)
        );

        prop_assert_eq!(
            index.height_of(&hash).expect("height_of should succeed"),
            Some(height)
        );

        prop_assert_eq!(
            index.status_of(&hash).expect("status_of should succeed"),
            Some(status)
        );
    }

    // 13/25
    #[test]
    fn test_013_set_status_changes_only_status_and_preserves_other_metadata_fields(
        hash_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
        score in any::<u128>(),
        old_status_seed in any::<u8>(),
        new_status_seed in any::<u8>(),
    ) {
        let db = new_test_db("set_status");
        let index = db.index();

        let hash = hash64(0x1F, hash_seed);
        let parent = hash64(0x20, parent_seed);
        let old_status = status_from_seed(old_status_seed);
        let new_status = status_from_seed(new_status_seed);
        let received = valid_timestamp(height);
        let meta = fork_meta(parent, height, score, old_status, received);

        index.put_meta(&hash, &meta)
            .expect("put_meta should succeed");

        index.set_status(&hash, new_status)
            .expect("set_status should update existing metadata");

        let updated = index.get_meta(&hash)
            .expect("get_meta should succeed")
            .expect("metadata should still exist");

        prop_assert_eq!(updated.parent_hash, parent);
        prop_assert_eq!(updated.height, height);
        prop_assert_eq!(updated.cumulative_score, score);
        prop_assert_eq!(updated.received_at_unix_secs, received);
        prop_assert_eq!(updated.status, new_status);
    }

    // 14/25
    #[test]
    fn test_014_mark_status_helpers_set_canonical_side_branch_and_orphan(
        hash_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
    ) {
        let db = new_test_db("mark_helpers");
        let index = db.index();

        let hash = hash64(0x21, hash_seed);
        let meta = fork_meta(
            hash64(0x22, parent_seed),
            height,
            u128::from(height),
            ForkBlockStatus::Validated,
            valid_timestamp(height),
        );

        index.put_meta(&hash, &meta)
            .expect("put_meta should succeed");

        index.mark_canonical(&hash)
            .expect("mark_canonical should set canonical status");

        prop_assert_eq!(
            index.status_of(&hash).expect("status_of should succeed"),
            Some(ForkBlockStatus::Canonical)
        );

        index.mark_side_branch(&hash)
            .expect("mark_side_branch should set side branch status");

        prop_assert_eq!(
            index.status_of(&hash).expect("status_of should succeed"),
            Some(ForkBlockStatus::SideBranch)
        );

        index.mark_orphan(&hash)
            .expect("mark_orphan should set orphan status");

        prop_assert_eq!(
            index.status_of(&hash).expect("status_of should succeed"),
            Some(ForkBlockStatus::Orphan)
        );
    }

    // 15/25
    #[test]
    fn test_015_status_update_on_missing_metadata_returns_error_and_does_not_create_meta(
        hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("missing_set_status");
        let index = db.index();
        let hash = hash64(0x23, hash_seed);

        prop_assert!(
            index.set_status(&hash, ForkBlockStatus::Canonical).is_err(),
            "set_status must fail when metadata is missing"
        );

        prop_assert!(
            !index.has_meta(&hash).expect("has_meta should succeed"),
            "failed set_status must not create metadata"
        );
    }

    // 16/25
    #[test]
    fn test_016_has_known_parent_returns_false_when_child_metadata_is_missing(
        hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("known_parent_missing_child");
        let index = db.index();
        let hash = hash64(0x24, hash_seed);

        prop_assert!(
            !index.has_known_parent(&hash).expect("has_known_parent should succeed"),
            "missing child metadata means parent cannot be known"
        );
    }

    // 17/25
    #[test]
    fn test_017_has_known_parent_treats_zero_parent_hash_as_known_root_boundary(
        hash_seed in any::<u64>(),
        height in 0u64..1_000_000u64,
    ) {
        let db = new_test_db("known_parent_zero");
        let index = db.index();

        let hash = hash64(0x25, hash_seed);
        let meta = fork_meta(
            [0u8; 64],
            height,
            u128::from(height),
            ForkBlockStatus::Validated,
            valid_timestamp(height),
        );

        index.put_meta(&hash, &meta)
            .expect("put_meta should succeed");

        prop_assert!(
            index.has_known_parent(&hash).expect("has_known_parent should succeed"),
            "all-zero parent hash must be treated as known root boundary"
        );
    }

    // 18/25
    #[test]
    fn test_018_has_known_parent_distinguishes_missing_nonzero_parent_from_stored_parent(
        child_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
    ) {
        let db = new_test_db("known_parent_nonzero");
        let index = db.index();

        let child_hash = hash64(0x26, child_seed);
        let parent_hash = distinct_hash64(0x27, parent_seed, child_hash);
        let child_meta = fork_meta(
            parent_hash,
            height,
            u128::from(height),
            ForkBlockStatus::Validated,
            valid_timestamp(height),
        );

        index.put_meta(&child_hash, &child_meta)
            .expect("child metadata should store");

        prop_assert!(
            !index.has_known_parent(&child_hash).expect("has_known_parent should succeed"),
            "nonzero parent hash without parent metadata must be unknown"
        );

        let parent_meta = fork_meta(
            [0u8; 64],
            height.saturating_sub(1),
            u128::from(height.saturating_sub(1)),
            ForkBlockStatus::Canonical,
            valid_timestamp(height.saturating_sub(1)),
        );

        index.put_meta(&parent_hash, &parent_meta)
            .expect("parent metadata should store");

        prop_assert!(
            index.has_known_parent(&child_hash).expect("has_known_parent should succeed"),
            "parent metadata presence must make nonzero parent known"
        );
    }

    // 19/25
    #[test]
    fn test_019_get_parent_block_returns_none_for_missing_child_meta_and_zero_parent_boundary(
        hash_seed in any::<u64>(),
        height in 0u64..1_000_000u64,
    ) {
        let db = new_test_db("parent_block_none");
        let index = db.index();

        let hash = hash64(0x28, hash_seed);

        prop_assert!(
            index.get_parent_block(&hash)
                .expect("get_parent_block should succeed")
                .is_none(),
            "missing child metadata must return None for parent block"
        );

        let root_meta = fork_meta(
            [0u8; 64],
            height,
            u128::from(height),
            ForkBlockStatus::Canonical,
            valid_timestamp(height),
        );

        index.put_meta(&hash, &root_meta)
            .expect("root metadata should store");

        prop_assert!(
            index.get_parent_block(&hash)
                .expect("get_parent_block should succeed")
                .is_none(),
            "zero parent root boundary must return None for parent block"
        );
    }

    // 20/25
    #[test]
    fn test_020_get_parent_block_returns_stored_parent_block_by_parent_hash(
        parent_height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        child_seed in any::<u64>(),
        grandparent_seed in any::<u64>(),
    ) {
        let db = new_test_db("parent_block_some");
        let index = db.index();

        let grandparent_hash = hash64(0x30, grandparent_seed);
        let parent = block_with_parent(parent_height, grandparent_hash, parent_seed);
        let child = child_block(&parent, child_seed);

        let parent_meta = meta_for_block(
            &parent,
            u128::from(parent.metadata.index),
            ForkBlockStatus::Canonical,
        );

        let child_meta = meta_for_block(
            &child,
            u128::from(child.metadata.index),
            ForkBlockStatus::Validated,
        );

        index.put_block_and_meta(&parent, &parent_meta)
            .expect("parent block/meta should store");

        index.put_block_and_meta(&child, &child_meta)
            .expect("child block/meta should store");

        let fetched_parent = index.get_parent_block(&child.block_hash)
            .expect("get_parent_block should succeed")
            .expect("stored parent block should be returned");

        prop_assert_eq!(
            &fetched_parent,
            &parent,
            "get_parent_block must resolve parent_hash through block index"
        );
    }

    // 21/25
    #[test]
    fn test_021_get_parent_meta_returns_stored_parent_metadata_by_parent_hash(
        parent_height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        child_seed in any::<u64>(),
    ) {
        let db = new_test_db("parent_meta_some");
        let index = db.index();

        let grandparent_hash = hash64(0x2F, child_seed);
        let parent = block_with_parent(parent_height, grandparent_hash, parent_seed);
        let child = child_block(&parent, child_seed);

        let parent_meta = meta_for_block(
            &parent,
            u128::from(parent.metadata.index),
            ForkBlockStatus::Canonical,
        );

        let child_meta = meta_for_block(
            &child,
            u128::from(child.metadata.index),
            ForkBlockStatus::Validated,
        );

        index
            .put_meta(&parent.block_hash, &parent_meta)
            .expect("parent metadata should store");

        index
            .put_meta(&child.block_hash, &child_meta)
            .expect("child metadata should store");

        let fetched_parent_meta = index
            .get_parent_meta(&child.block_hash)
            .expect("get_parent_meta should succeed")
            .expect("stored parent metadata should be returned");

        prop_assert_eq!(
            &fetched_parent_meta,
            &parent_meta,
            "get_parent_meta must resolve parent_hash through metadata index"
        );
    }

    // 22/25
    #[test]
    fn test_022_build_path_from_tip_returns_empty_for_missing_start_or_zero_depth(
        hash_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
    ) {
        let db = new_test_db("path_empty");
        let index = db.index();

        let hash = hash64(0x29, hash_seed);

        prop_assert!(
            index.build_path_from_tip(&hash, 8)
                .expect("path walk should succeed")
                .is_empty(),
            "missing start metadata must produce empty path"
        );

        let meta = fork_meta(
            [0u8; 64],
            height,
            u128::from(height),
            ForkBlockStatus::Canonical,
            valid_timestamp(height),
        );

        index.put_meta(&hash, &meta)
            .expect("metadata should store");

        prop_assert!(
            index.build_path_from_tip(&hash, 0)
                .expect("zero-depth path walk should succeed")
                .is_empty(),
            "max_depth=0 must produce empty path even when metadata exists"
        );
    }

    // 23/25
    #[test]
    fn test_023_build_path_from_tip_walks_tip_to_parent_to_root_and_respects_max_depth(
        root_height in 1u64..1_000_000u64,
        root_seed in any::<u64>(),
        child_seed in any::<u64>(),
        grandchild_seed in any::<u64>(),
    ) {
        let db = new_test_db("path_walk");
        let index = db.index();

        let root_parent_hash = hash64(0x31, root_seed);
        let root = block_with_parent(root_height, root_parent_hash, root_seed);
        let child = child_block(&root, child_seed);
        let grandchild = child_block(&child, grandchild_seed);

        let root_meta = fork_meta(
            [0u8; 64],
            root.metadata.index,
            u128::from(root.metadata.index),
            ForkBlockStatus::Canonical,
            valid_timestamp(root.metadata.index),
        );

        let child_meta = meta_for_block(
            &child,
            u128::from(child.metadata.index),
            ForkBlockStatus::SideBranch,
        );

        let grandchild_meta = meta_for_block(
            &grandchild,
            u128::from(grandchild.metadata.index),
            ForkBlockStatus::Validated,
        );

        index
            .put_meta(&root.block_hash, &root_meta)
            .expect("root meta should store");

        index
            .put_meta(&child.block_hash, &child_meta)
            .expect("child meta should store");

        index
            .put_meta(&grandchild.block_hash, &grandchild_meta)
            .expect("grandchild meta should store");

        let limited = index
            .build_path_from_tip(&grandchild.block_hash, 2)
            .expect("limited path walk should succeed");

        prop_assert_eq!(
            limited,
            vec![
                (grandchild.metadata.index, grandchild.block_hash),
                (child.metadata.index, child.block_hash),
            ],
            "path walk must start at tip and respect max_depth"
        );

        let full = index
            .build_path_from_tip(&grandchild.block_hash, 8)
            .expect("full path walk should succeed");

        prop_assert_eq!(
            full,
            vec![
                (grandchild.metadata.index, grandchild.block_hash),
                (child.metadata.index, child.block_hash),
                (root.metadata.index, root.block_hash),
            ],
            "path walk must continue through parents and stop at zero-parent root metadata"
        );
    }

    // 24/25
    #[test]
    fn test_024_first_missing_ancestor_detects_missing_start_missing_parent_and_complete_rooted_chain(
        start_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
    ) {
        let db = new_test_db("missing_ancestor");
        let index = db.index();

        let start_hash = hash64(0x2A, start_seed);
        let parent_hash = distinct_hash64(0x2B, parent_seed, start_hash);

        prop_assert_eq!(
            index.first_missing_ancestor(&start_hash, 8)
                .expect("missing ancestor query should succeed"),
            Some(start_hash),
            "missing start metadata must report start hash as first missing ancestor"
        );

        let child_meta = fork_meta(
            parent_hash,
            height,
            u128::from(height),
            ForkBlockStatus::Validated,
            valid_timestamp(height),
        );

        index.put_meta(&start_hash, &child_meta)
            .expect("child metadata should store");

        prop_assert_eq!(
            index.first_missing_ancestor(&start_hash, 8)
                .expect("missing parent query should succeed"),
            Some(parent_hash),
            "known child with unknown nonzero parent must report parent hash as missing"
        );

        let parent_meta = fork_meta(
            [0u8; 64],
            height.saturating_sub(1),
            u128::from(height.saturating_sub(1)),
            ForkBlockStatus::Canonical,
            valid_timestamp(height.saturating_sub(1)),
        );

        index.put_meta(&parent_hash, &parent_meta)
            .expect("parent metadata should store");

        prop_assert_eq!(
            index.first_missing_ancestor(&start_hash, 8)
                .expect("complete rooted chain query should succeed"),
            None,
            "complete metadata path to zero-parent root must have no missing ancestor"
        );
    }

    // 25/25
    #[test]
    fn test_025_validate_block_meta_consistency_accepts_matching_records_and_rejects_mismatches(
        height in 1u64..1_000_000u64,
        parent_seed in any::<u64>(),
        block_seed in any::<u64>(),
        wrong_seed in any::<u64>(),
    ) {
        let db = new_test_db("consistency");
        let index = db.index();

        let block = block_with_parent(height, hash64(0x2C, parent_seed), block_seed);
        let correct_meta = meta_for_block(&block, u128::from(height), ForkBlockStatus::Validated);

        index.put_block_and_meta(&block, &correct_meta)
            .expect("matching block/meta should store");

        prop_assert!(
            index.validate_block_meta_consistency(&block.block_hash).is_ok(),
            "matching block hash, height, and parent linkage must validate"
        );

        let mut wrong_height_meta = correct_meta.clone();
        wrong_height_meta.height = wrong_height_meta.height.saturating_add(1);

        index.put_meta(&block.block_hash, &wrong_height_meta)
            .expect("wrong-height metadata should overwrite for negative check");

        prop_assert!(
            index.validate_block_meta_consistency(&block.block_hash).is_err(),
            "height mismatch between block and metadata must be rejected"
        );

        let mut wrong_parent_meta = correct_meta.clone();
        wrong_parent_meta.parent_hash = distinct_hash64(
            0x2D,
            wrong_seed,
            block.metadata.previous_hash,
        );

        index.put_meta(&block.block_hash, &wrong_parent_meta)
            .expect("wrong-parent metadata should overwrite for negative check");

        prop_assert!(
            index.validate_block_meta_consistency(&block.block_hash).is_err(),
            "parent mismatch between block and metadata must be rejected"
        );

        index.put_meta(&block.block_hash, &correct_meta)
            .expect("correct metadata should be restored");

        let wrong_key = distinct_hash64(0x2E, wrong_seed.wrapping_add(1), block.block_hash);
        let encoded = block.serialize_for_storage()
            .expect("valid block must serialize for hash mismatch check");

        index.put_block_bytes(&wrong_key, &encoded)
            .expect("same block bytes should be storable under wrong key");

        let wrong_key_meta = fork_meta(
            block.metadata.previous_hash,
            block.metadata.index,
            u128::from(block.metadata.index),
            ForkBlockStatus::Validated,
            valid_timestamp(block.metadata.index),
        );

        index.put_meta(&wrong_key, &wrong_key_meta)
            .expect("metadata under wrong key should store");

        prop_assert!(
            index.validate_block_meta_consistency(&wrong_key).is_err(),
            "block.block_hash differing from lookup key must be rejected"
        );
    }
}
