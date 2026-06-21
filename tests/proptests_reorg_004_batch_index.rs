use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::reorganization::reorg_004_batch_index::{BlockHash, ReorgBatchIndex};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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

    fn index(&self) -> ReorgBatchIndex {
        ReorgBatchIndex::new(self.manager())
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

    std::env::temp_dir().join(format!("remzar_reorg_batch_index_prop_{label}_{pid}_{id}"))
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

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_batch_index_keeps_exact_shared_db_arc(
        _case in any::<u8>(),
    ) {
        let db = new_test_db("new_arc");
        let manager = db.manager();
        let index = ReorgBatchIndex::new(Arc::clone(&manager));

        prop_assert!(
            Arc::ptr_eq(index.db(), &manager),
            "ReorgBatchIndex::new must keep the exact shared RockDBManager Arc"
        );
    }

    // 02/25
    #[test]
    fn test_002_empty_batch_index_returns_none_or_false_for_unknown_hash_and_height(
        hash_seed in any::<u64>(),
        height in 0u64..128u64,
    ) {
        let db = new_test_db("empty_queries");
        let index = db.index();
        let hash = hash64(0x11, hash_seed);

        prop_assert!(
            !index
                .has_batch_by_block_hash(&hash)
                .expect("empty has_batch_by_block_hash should succeed"),
            "empty index must not report unknown batch-by-hash as present"
        );

        prop_assert!(
            index
                .get_batch_by_block_hash(&hash)
                .expect("empty batch-by-hash lookup should succeed")
                .is_none(),
            "empty index must return None for unknown batch-by-hash"
        );

        prop_assert!(
            index
                .get_canonical_batch_at_height(height)
                .expect("empty canonical batch lookup should succeed")
                .is_none(),
            "empty index must return None for missing canonical batch projection"
        );

        prop_assert!(
            index
                .get_canonical_batch_with_fallback(height)
                .expect("empty fallback lookup should succeed")
                .is_none(),
            "empty fallback lookup must return None when both views are missing"
        );
    }

    // 03/25
    #[test]
    fn test_003_put_batch_by_block_hash_roundtrips_exact_bytes(
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("put_hash_roundtrip");
        let index = db.index();
        let hash = hash64(0x12, hash_seed);

        index
            .put_batch_by_block_hash(&hash, &bytes)
            .expect("put_batch_by_block_hash should store exact bytes");

        prop_assert!(
            index
                .has_batch_by_block_hash(&hash)
                .expect("has_batch_by_block_hash should succeed after put"),
            "has_batch_by_block_hash must become true after put"
        );

        let fetched = index
            .get_batch_by_block_hash(&hash)
            .expect("get_batch_by_block_hash should succeed after put")
            .expect("batch bytes should exist after put");

        prop_assert_eq!(
            &fetched,
            &bytes,
            "batch-by-hash storage must preserve exact bytes"
        );
    }

    // 04/25
    #[test]
    fn test_004_put_batch_by_block_hash_overwrites_same_hash_without_touching_other_hash(
        hash_seed in any::<u64>(),
        other_seed in any::<u64>(),
        byte_seed in any::<u64>(),
        len in 1usize..256usize,
    ) {
        let db = new_test_db("put_hash_overwrite");
        let index = db.index();

        let hash = hash64(0x13, hash_seed);
        let other_hash = distinct_hash64(0x14, other_seed, hash);

        let first = batch_bytes(0xA1, byte_seed, len);
        let second = batch_bytes(0xA2, byte_seed, len.saturating_add(1));
        let other = batch_bytes(0xA3, byte_seed, len.saturating_add(2));

        index.put_batch_by_block_hash(&hash, &first).expect("first put should succeed");
        index.put_batch_by_block_hash(&other_hash, &other).expect("other put should succeed");
        index.put_batch_by_block_hash(&hash, &second).expect("overwrite put should succeed");

        prop_assert_eq!(
            index.get_batch_by_block_hash(&hash).expect("hash lookup should succeed"),
            Some(second),
            "second write under same hash must overwrite previous batch bytes"
        );

        prop_assert_eq!(
            index.get_batch_by_block_hash(&other_hash).expect("other hash lookup should succeed"),
            Some(other),
            "overwriting one hash must not touch another hash"
        );
    }

    // 05/25
    #[test]
    fn test_005_batch_by_block_hash_isolated_between_distinct_hashes(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        bytes_a in proptest::collection::vec(any::<u8>(), 1..256),
        bytes_b in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("hash_isolation");
        let index = db.index();

        let hash_a = hash64(0x15, seed_a);
        let hash_b = distinct_hash64(0x16, seed_b, hash_a);

        index.put_batch_by_block_hash(&hash_a, &bytes_a).expect("hash_a put should succeed");
        index.put_batch_by_block_hash(&hash_b, &bytes_b).expect("hash_b put should succeed");

        prop_assert_eq!(
            index.get_batch_by_block_hash(&hash_a).expect("hash_a lookup should succeed"),
            Some(bytes_a),
            "hash_a must return only hash_a bytes"
        );

        prop_assert_eq!(
            index.get_batch_by_block_hash(&hash_b).expect("hash_b lookup should succeed"),
            Some(bytes_b),
            "hash_b must return only hash_b bytes"
        );
    }

    // 06/25
    #[test]
    fn test_006_set_canonical_batch_at_height_roundtrips_exact_projection_bytes(
        height in 0u64..128u64,
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("canonical_height_roundtrip");
        let index = db.index();

        index
            .set_canonical_batch_at_height(height, &bytes)
            .expect("set_canonical_batch_at_height should store projection bytes");

        let fetched = index
            .get_canonical_batch_at_height(height)
            .expect("canonical projection lookup should succeed")
            .expect("canonical projection should exist after set");

        prop_assert_eq!(
            &fetched,
            &bytes,
            "canonical batch projection must preserve exact bytes"
        );
    }

    // 07/25
    #[test]
    fn test_007_set_canonical_batch_at_height_overwrites_same_height_without_touching_other_height(
        height in 0u64..128u64,
        byte_seed in any::<u64>(),
        len in 1usize..256usize,
    ) {
        let db = new_test_db("canonical_height_overwrite");
        let index = db.index();

        let other_height = height.saturating_add(1);

        let first = batch_bytes(0xB1, byte_seed, len);
        let second = batch_bytes(0xB2, byte_seed, len.saturating_add(1));
        let other = batch_bytes(0xB3, byte_seed, len.saturating_add(2));

        index.set_canonical_batch_at_height(height, &first).expect("first projection set should succeed");
        index.set_canonical_batch_at_height(other_height, &other).expect("other projection set should succeed");
        index.set_canonical_batch_at_height(height, &second).expect("overwrite projection set should succeed");

        prop_assert_eq!(
            index.get_canonical_batch_at_height(height).expect("height lookup should succeed"),
            Some(second),
            "second canonical write at same height must overwrite previous projection"
        );

        prop_assert_eq!(
            index.get_canonical_batch_at_height(other_height).expect("other height lookup should succeed"),
            Some(other),
            "overwriting one canonical height must not touch another height"
        );
    }

    // 08/25
    #[test]
    fn test_008_get_canonical_batch_with_fallback_prefers_hash_truth_over_projection(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        byte_seed in any::<u64>(),
        len in 1usize..256usize,
    ) {
        let db = new_test_db("fallback_prefers_hash_truth");
        let index = db.index();

        let hash = hash64(0x17, hash_seed);
        let canonical_projection = batch_bytes(0xC1, byte_seed, len);
        let hash_truth = batch_bytes(0xC2, byte_seed, len.saturating_add(1));

        index
            .set_canonical_batch_at_height(height, &canonical_projection)
            .expect("canonical projection should store");

        index
            .put_batch_by_block_hash(&hash, &hash_truth)
            .expect("batch-by-hash truth should store");

        index
            .db()
            .set_canonical_hash_at_height(height, &hash)
            .expect("canonical hash mapping should store");

        let fetched = index
            .get_canonical_batch_with_fallback(height)
            .expect("fallback lookup should succeed")
            .expect("fallback lookup should find hash truth");

        prop_assert_eq!(
            &fetched,
            &hash_truth,
            "fallback lookup must prefer canonical hash -> batch_by_block_hash over tx_batch projection"
        );
    }

    // 09/25
    #[test]
    fn test_009_get_canonical_batch_with_fallback_returns_projection_when_hash_mapping_missing(
        height in 0u64..128u64,
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("fallback_projection_no_hash");
        let index = db.index();

        index
            .set_canonical_batch_at_height(height, &bytes)
            .expect("canonical projection should store");

        let fetched = index
            .get_canonical_batch_with_fallback(height)
            .expect("fallback lookup should succeed")
            .expect("fallback should use tx_batch projection");

        prop_assert_eq!(
            &fetched,
            &bytes,
            "fallback lookup must return projection when canonical hash mapping is missing"
        );
    }

    // 10/25
    #[test]
    fn test_010_get_canonical_batch_with_fallback_returns_projection_when_hash_truth_missing(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("fallback_projection_missing_truth");
        let index = db.index();

        let hash = hash64(0x18, hash_seed);

        index
            .db()
            .set_canonical_hash_at_height(height, &hash)
            .expect("canonical hash mapping should store");

        index
            .set_canonical_batch_at_height(height, &bytes)
            .expect("canonical projection should store");

        let fetched = index
            .get_canonical_batch_with_fallback(height)
            .expect("fallback lookup should succeed")
            .expect("fallback should use projection when hash truth is missing");

        prop_assert_eq!(
            &fetched,
            &bytes,
            "fallback lookup must fall back to projection when mapped hash has no batch_by_hash"
        );
    }

    // 11/25
    #[test]
    fn test_011_ingest_canonical_batch_stores_both_hash_truth_and_canonical_projection(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("ingest_canonical");
        let index = db.index();
        let hash = hash64(0x19, hash_seed);

        index
            .ingest_canonical_batch(&hash, height, &bytes)
            .expect("ingest_canonical_batch should store both views");

        prop_assert_eq!(
            index.get_batch_by_block_hash(&hash).expect("hash truth lookup should succeed"),
            Some(bytes.clone()),
            "canonical ingest must store batch-by-hash truth"
        );

        prop_assert_eq!(
            index.get_canonical_batch_at_height(height).expect("projection lookup should succeed"),
            Some(bytes),
            "canonical ingest must store canonical tx_batch projection"
        );
    }

    // 12/25
    #[test]
    fn test_012_ingest_side_branch_batch_stores_hash_truth_without_canonical_projection(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("ingest_side_branch");
        let index = db.index();
        let hash = hash64(0x1A, hash_seed);

        index
            .ingest_side_branch_batch(&hash, &bytes)
            .expect("ingest_side_branch_batch should store only batch-by-hash truth");

        prop_assert_eq!(
            index.get_batch_by_block_hash(&hash).expect("hash truth lookup should succeed"),
            Some(bytes),
            "side-branch ingest must store batch-by-hash truth"
        );

        prop_assert!(
            index
                .get_canonical_batch_at_height(height)
                .expect("projection lookup should succeed")
                .is_none(),
            "side-branch ingest must not write canonical projection at arbitrary height"
        );
    }

    // 13/25
    #[test]
    fn test_013_remap_canonical_batch_to_height_copies_hash_truth_into_projection(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("remap_one");
        let index = db.index();
        let hash = hash64(0x1B, hash_seed);

        index
            .put_batch_by_block_hash(&hash, &bytes)
            .expect("batch-by-hash truth should store");

        index
            .remap_canonical_batch_to_height(height, &hash)
            .expect("remap should copy hash truth into projection");

        prop_assert_eq!(
            index.get_canonical_batch_at_height(height).expect("projection lookup should succeed"),
            Some(bytes),
            "remap must copy exact batch-by-hash bytes into canonical projection"
        );
    }

    // 14/25
    #[test]
    fn test_014_remap_canonical_batch_to_height_errors_when_hash_truth_missing_and_preserves_projection(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        existing_bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("remap_missing");
        let index = db.index();
        let missing_hash = hash64(0x1C, hash_seed);

        index
            .set_canonical_batch_at_height(height, &existing_bytes)
            .expect("existing projection should store");

        prop_assert!(
            index.remap_canonical_batch_to_height(height, &missing_hash).is_err(),
            "strict remap must error when batch-by-hash truth is missing"
        );

        prop_assert_eq!(
            index.get_canonical_batch_at_height(height).expect("projection lookup should succeed"),
            Some(existing_bytes),
            "failed strict remap must preserve existing projection"
        );
    }

    // 15/25
    #[test]
    fn test_015_remap_canonical_batches_for_attach_steps_remaps_all_steps_in_order(
        base in 0u64..64u64,
        seed in any::<u64>(),
        len in 1usize..128usize,
    ) {
        let db = new_test_db("remap_attach_steps");
        let index = db.index();

        let h0 = base;
        let h1 = base.saturating_add(1);
        let h2 = base.saturating_add(2);

        let hash0 = hash64(0x1D, seed);
        let hash1 = distinct_hash64(0x1E, seed.wrapping_add(1), hash0);
        let hash2 = distinct_hash64(0x1F, seed.wrapping_add(2), hash1);

        let batch0 = batch_bytes(0xD0, seed, len);
        let batch1 = batch_bytes(0xD1, seed, len.saturating_add(1));
        let batch2 = batch_bytes(0xD2, seed, len.saturating_add(2));

        index.put_batch_by_block_hash(&hash0, &batch0).expect("hash0 batch should store");
        index.put_batch_by_block_hash(&hash1, &batch1).expect("hash1 batch should store");
        index.put_batch_by_block_hash(&hash2, &batch2).expect("hash2 batch should store");

        let steps = vec![(h0, hash0), (h1, hash1), (h2, hash2)];

        index
            .remap_canonical_batches_for_attach_steps(&steps)
            .expect("strict attach remap should remap all steps");

        prop_assert_eq!(index.get_canonical_batch_at_height(h0).expect("h0 lookup should succeed"), Some(batch0));
        prop_assert_eq!(index.get_canonical_batch_at_height(h1).expect("h1 lookup should succeed"), Some(batch1));
        prop_assert_eq!(index.get_canonical_batch_at_height(h2).expect("h2 lookup should succeed"), Some(batch2));
    }

    // 16/25
    #[test]
    fn test_016_strict_attach_step_remap_errors_at_first_missing_batch_but_keeps_prior_remaps(
        base in 0u64..64u64,
        seed in any::<u64>(),
        existing_bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("strict_remap_partial");
        let index = db.index();

        let h0 = base;
        let h1 = base.saturating_add(1);

        let present_hash = hash64(0x20, seed);
        let missing_hash = distinct_hash64(0x21, seed.wrapping_add(1), present_hash);

        index
            .put_batch_by_block_hash(&present_hash, &existing_bytes)
            .expect("present batch should store");

        let steps = vec![(h0, present_hash), (h1, missing_hash)];

        prop_assert!(
            index.remap_canonical_batches_for_attach_steps(&steps).is_err(),
            "strict attach remap must fail when any attached hash is missing batch truth"
        );

        prop_assert_eq!(
            index.get_canonical_batch_at_height(h0).expect("h0 lookup should succeed"),
            Some(existing_bytes),
            "strict remap must preserve successful earlier remaps before later error"
        );

        prop_assert!(
            index
                .get_canonical_batch_at_height(h1)
                .expect("h1 lookup should succeed")
                .is_none(),
            "strict remap must not create projection for missing batch"
        );
    }

    // 17/25
    #[test]
    fn test_017_best_effort_remap_skips_missing_batches_and_remaps_existing_batches(
        base in 0u64..64u64,
        seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("best_effort_remap");
        let index = db.index();

        let h0 = base;
        let h1 = base.saturating_add(1);

        let present_hash = hash64(0x22, seed);
        let missing_hash = distinct_hash64(0x23, seed.wrapping_add(1), present_hash);

        index
            .put_batch_by_block_hash(&present_hash, &bytes)
            .expect("present batch should store");

        let steps = vec![(h0, present_hash), (h1, missing_hash)];

        index
            .remap_canonical_batches_best_effort(&steps)
            .expect("best-effort remap must not fail for missing batch");

        prop_assert_eq!(
            index.get_canonical_batch_at_height(h0).expect("h0 lookup should succeed"),
            Some(bytes),
            "best-effort remap must write projection for existing batch"
        );

        prop_assert!(
            index
                .get_canonical_batch_at_height(h1)
                .expect("h1 lookup should succeed")
                .is_none(),
            "best-effort remap must skip missing batch without projection"
        );
    }

    // 18/25
    #[test]
    fn test_018_validate_canonical_batch_consistency_accepts_matching_hash_truth_and_projection(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let db = new_test_db("validate_ok");
        let index = db.index();

        let hash = hash64(0x24, hash_seed);

        index.db()
            .set_canonical_hash_at_height(height, &hash)
            .expect("canonical hash should store");

        index.put_batch_by_block_hash(&hash, &bytes).expect("hash truth should store");
        index.set_canonical_batch_at_height(height, &bytes).expect("projection should store");

        prop_assert!(
            index.validate_canonical_batch_consistency(height).is_ok(),
            "matching canonical hash truth and projection must validate"
        );
    }

    // 19/25
    #[test]
    fn test_019_validate_canonical_batch_consistency_errors_when_canonical_hash_missing(
        height in 0u64..128u64,
        bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("validate_missing_hash");
        let index = db.index();

        index
            .set_canonical_batch_at_height(height, &bytes)
            .expect("projection should store");

        prop_assert!(
            index.validate_canonical_batch_consistency(height).is_err(),
            "validation must error when canonical hash mapping is missing"
        );
    }

    // 20/25
    #[test]
    fn test_020_validate_canonical_batch_consistency_errors_when_hash_truth_missing(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("validate_missing_hash_truth");
        let index = db.index();

        let hash = hash64(0x25, hash_seed);

        index.db()
            .set_canonical_hash_at_height(height, &hash)
            .expect("canonical hash should store");

        index
            .set_canonical_batch_at_height(height, &bytes)
            .expect("projection should store");

        prop_assert!(
            index.validate_canonical_batch_consistency(height).is_err(),
            "validation must error when batch-by-hash truth is missing"
        );
    }

    // 21/25
    #[test]
    fn test_021_validate_canonical_batch_consistency_errors_when_projection_missing(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("validate_missing_projection");
        let index = db.index();

        let hash = hash64(0x26, hash_seed);

        index.db()
            .set_canonical_hash_at_height(height, &hash)
            .expect("canonical hash should store");

        index
            .put_batch_by_block_hash(&hash, &bytes)
            .expect("hash truth should store");

        prop_assert!(
            index.validate_canonical_batch_consistency(height).is_err(),
            "validation must error when canonical projection is missing"
        );
    }

    // 22/25
    #[test]
    fn test_022_validate_canonical_batch_consistency_errors_when_projection_differs_from_hash_truth(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        byte_seed in any::<u64>(),
        len in 1usize..256usize,
    ) {
        let db = new_test_db("validate_mismatch");
        let index = db.index();

        let hash = hash64(0x27, hash_seed);
        let expected = batch_bytes(0xE1, byte_seed, len);
        let actual = batch_bytes(0xE2, byte_seed, len.saturating_add(1));

        index.db()
            .set_canonical_hash_at_height(height, &hash)
            .expect("canonical hash should store");

        index.put_batch_by_block_hash(&hash, &expected).expect("hash truth should store");
        index.set_canonical_batch_at_height(height, &actual).expect("projection should store");

        prop_assert!(
            index.validate_canonical_batch_consistency(height).is_err(),
            "validation must reject canonical projection that differs from batch-by-hash truth"
        );
    }

    // 23/25
    #[test]
    fn test_023_first_inconsistent_canonical_batch_returns_none_for_reversed_or_clean_range(
        base in 0u64..64u64,
        hash_seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("first_inconsistent_none");
        let index = db.index();

        let hash = hash64(0x28, hash_seed);

        prop_assert_eq!(
            index.first_inconsistent_canonical_batch(base.saturating_add(1), base)
                .expect("reversed range scan should succeed"),
            None,
            "reversed range must be clean by definition"
        );

        index.db()
            .set_canonical_hash_at_height(base, &hash)
            .expect("canonical hash should store");

        index.put_batch_by_block_hash(&hash, &bytes).expect("hash truth should store");
        index.set_canonical_batch_at_height(base, &bytes).expect("projection should store");

        prop_assert_eq!(
            index.first_inconsistent_canonical_batch(base, base)
                .expect("clean range scan should succeed"),
            None,
            "clean single-height range must have no inconsistency"
        );
    }

    // 24/25
    #[test]
    fn test_024_first_inconsistent_canonical_batch_returns_earliest_bad_height(
        base in 0u64..64u64,
        seed in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let db = new_test_db("first_inconsistent_some");
        let index = db.index();

        let h0 = base;
        let h1 = base.saturating_add(1);
        let h2 = base.saturating_add(2);

        let hash0 = hash64(0x29, seed);
        let hash2 = distinct_hash64(0x2A, seed.wrapping_add(1), hash0);

        index.db()
            .set_canonical_hash_at_height(h0, &hash0)
            .expect("h0 canonical hash should store");

        index.put_batch_by_block_hash(&hash0, &bytes).expect("h0 hash truth should store");
        index.set_canonical_batch_at_height(h0, &bytes).expect("h0 projection should store");

        index.db()
            .set_canonical_hash_at_height(h2, &hash2)
            .expect("h2 canonical hash should store");

        index.put_batch_by_block_hash(&hash2, &bytes).expect("h2 hash truth should store");
        index.set_canonical_batch_at_height(h2, &bytes).expect("h2 projection should store");

        prop_assert_eq!(
            index.first_inconsistent_canonical_batch(h0, h2)
                .expect("range scan should succeed"),
            Some(h1),
            "scan must return the earliest height whose canonical batch consistency fails"
        );
    }

    // 25/25
    #[test]
    fn test_025_backfill_and_rebuild_migration_helpers_copy_between_projection_and_hash_truth(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
        byte_seed in any::<u64>(),
        len in 1usize..256usize,
    ) {
        let db = new_test_db("migration_helpers");
        let index = db.index();

        let hash = hash64(0x2B, hash_seed);
        let original_projection = batch_bytes(0xF1, byte_seed, len);
        let repaired_projection = batch_bytes(0xF2, byte_seed, len.saturating_add(1));

        index.db()
            .set_canonical_hash_at_height(height, &hash)
            .expect("canonical hash should store");

        index
            .set_canonical_batch_at_height(height, &original_projection)
            .expect("legacy canonical projection should store");

        prop_assert!(
            !index
                .has_batch_by_block_hash(&hash)
                .expect("hash truth presence check should succeed"),
            "test setup must start without batch-by-hash truth"
        );

        index
            .backfill_batch_by_hash_from_canonical_range(height, height)
            .expect("backfill from canonical projection should succeed");

        prop_assert_eq!(
            index.get_batch_by_block_hash(&hash).expect("hash truth lookup should succeed"),
            Some(original_projection.clone()),
            "backfill must copy canonical projection into batch-by-hash truth"
        );

        index
            .set_canonical_batch_at_height(height, &repaired_projection)
            .expect("projection should be deliberately changed before rebuild");

        prop_assert!(
            index.validate_canonical_batch_consistency(height).is_err(),
            "deliberately changed projection must be inconsistent before rebuild"
        );

        index
            .rebuild_canonical_projection_from_hash_range(height, height)
            .expect("rebuild from hash truth should succeed");

        prop_assert_eq!(
            index.get_canonical_batch_at_height(height).expect("projection lookup should succeed"),
            Some(original_projection),
            "rebuild must restore canonical projection from batch-by-hash truth"
        );

        prop_assert!(
            index.validate_canonical_batch_consistency(height).is_ok(),
            "projection rebuilt from hash truth must validate"
        );
    }
}
