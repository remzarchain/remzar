use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::reorganization::reorg_002_chain_view::{BlockHash, ReorgChainView};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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

    fn view(&self) -> ReorgChainView {
        ReorgChainView::new(self.manager())
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

    std::env::temp_dir().join(format!("remzar_reorg_chain_view_prop_{label}_{pid}_{id}"))
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

fn signature(seed: u64) -> [u8; ml_dsa_65::SIG_LEN] {
    let byte = u8::try_from(seed % 254)
        .expect("seed modulo 254 must fit into u8")
        .saturating_add(1);

    [byte; ml_dsa_65::SIG_LEN]
}

fn block_with_parent(height: u64, parent_hash: BlockHash, seed: u64) -> Block {
    let mut merkle_root = hash64(0xA5, seed.wrapping_add(1));

    if merkle_root == parent_hash {
        merkle_root[63] ^= 1;
    }

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
        Some(format!("tx_batch_reorg_chain_view_{height}_{seed}")),
        wallet(seed),
        0,
    )
    .expect("generated valid chain-view test block should construct")
}

fn chain_blocks(len: usize, seed: u64) -> Vec<Block> {
    let mut out = Vec::with_capacity(len);
    let mut parent_hash = [0u8; 64];

    for height in 0..len {
        let h = u64::try_from(height).expect("test height must fit u64");
        let block = block_with_parent(h, parent_hash, seed.wrapping_add(h));
        parent_hash = block.block_hash;
        out.push(block);
    }

    out
}

fn store_legacy_block_by_height(manager: &RockDBManager, block: &Block) {
    let bytes = block
        .serialize_for_storage()
        .expect("generated block must serialize for legacy storage");

    manager
        .store_latest_block(&bytes, block.metadata.index)
        .expect("store_latest_block should store block by legacy height");
}

fn index_block_by_hash(manager: &RockDBManager, block: &Block) {
    let bytes = block
        .serialize_for_storage()
        .expect("generated block must serialize for hash indexing");

    manager
        .index_block_by_hash(&block.block_hash, &bytes)
        .expect("index_block_by_hash should store valid canonical block bytes");
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

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_chain_view_keeps_exact_shared_db_arc(
        _case in any::<u8>(),
    ) {
        let db = new_test_db("new_arc");
        let manager = db.manager();
        let view = ReorgChainView::new(Arc::clone(&manager));

        prop_assert!(
            Arc::ptr_eq(view.db(), &manager),
            "ReorgChainView::new must keep the exact shared RockDBManager Arc"
        );
    }

    // 02/25
    #[test]
    fn test_002_empty_chain_view_has_no_height_mapping_and_no_explicit_tip(
        height in 0u64..64u64,
    ) {
        let db = new_test_db("empty_view");
        let view = db.view();

        prop_assert!(
            !view.has_height(height).expect("empty has_height should succeed"),
            "empty view must not report canonical height mapping"
        );

        prop_assert!(
            view.get_hash_at_height(height)
                .expect("empty height lookup should succeed")
                .is_none(),
            "empty view must return None for missing canonical height"
        );

        prop_assert!(
            view.get_tip().expect("empty tip lookup should succeed").is_none(),
            "empty view must not have explicit canonical tip"
        );

        prop_assert!(
            view.get_tip_hash().expect("empty tip hash lookup should succeed").is_none(),
            "empty view must not have canonical tip hash"
        );

        prop_assert!(
            view.get_tip_height().expect("empty tip height lookup should succeed").is_none(),
            "empty view must not have canonical tip height"
        );
    }

    // 03/25
    #[test]
    fn test_003_set_and_get_hash_at_height_roundtrips_exact_hash_and_sets_has_height(
        height in 0u64..128u64,
        hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("set_get_height");
        let view = db.view();
        let hash = hash64(0x11, hash_seed);

        view.set_hash_at_height(height, &hash)
            .expect("set_hash_at_height should store canonical hash");

        prop_assert!(
            view.has_height(height).expect("has_height should succeed after set"),
            "has_height must become true after set_hash_at_height"
        );

        prop_assert_eq!(
            view.get_hash_at_height(height)
                .expect("get_hash_at_height should succeed after set"),
            Some(hash),
            "get_hash_at_height must return exact stored hash"
        );
    }

    // 04/25
    #[test]
    fn test_004_set_hash_at_height_overwrites_existing_height_without_touching_other_height(
        height in 0u64..128u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        other_seed in any::<u64>(),
    ) {
        let db = new_test_db("overwrite_height");
        let view = db.view();

        let first = hash64(0x12, seed_a);
        let second = distinct_hash64(0x13, seed_b, first);
        let other_height = height.saturating_add(1);
        let other_hash = distinct_hash64(0x14, other_seed, second);

        view.set_hash_at_height(height, &first)
            .expect("initial height set should succeed");

        view.set_hash_at_height(other_height, &other_hash)
            .expect("other height set should succeed");

        view.set_hash_at_height(height, &second)
            .expect("overwrite height set should succeed");

        prop_assert_eq!(
            view.get_hash_at_height(height).expect("height lookup should succeed"),
            Some(second),
            "second write at same height must replace first hash"
        );

        prop_assert_eq!(
            view.get_hash_at_height(other_height).expect("other height lookup should succeed"),
            Some(other_hash),
            "overwriting one height must not touch another height"
        );
    }

    // 05/25
    #[test]
    fn test_005_delete_height_range_with_reversed_bounds_is_noop(
        from_height in 1u64..128u64,
        hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("delete_reversed");
        let view = db.view();

        let height = from_height;
        let hash = hash64(0x15, hash_seed);

        view.set_hash_at_height(height, &hash)
            .expect("set before reversed delete should succeed");

        view.delete_height_range(height.saturating_add(1), height)
            .expect("delete with reversed bounds should be no-op");

        prop_assert_eq!(
            view.get_hash_at_height(height).expect("height lookup should succeed"),
            Some(hash),
            "reversed delete range must preserve existing mapping"
        );
    }

    // 06/25
    #[test]
    fn test_006_delete_height_range_is_inclusive_and_preserves_outside_bounds(
        base in 0u64..32u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("delete_inclusive");
        let view = db.view();

        let h0 = base;
        let h1 = base.saturating_add(1);
        let h2 = base.saturating_add(2);
        let h3 = base.saturating_add(3);

        let hash0 = hash64(0x16, seed);
        let hash1 = hash64(0x17, seed);
        let hash2 = hash64(0x18, seed);
        let hash3 = hash64(0x19, seed);

        view.set_hash_at_height(h0, &hash0).expect("h0 set should succeed");
        view.set_hash_at_height(h1, &hash1).expect("h1 set should succeed");
        view.set_hash_at_height(h2, &hash2).expect("h2 set should succeed");
        view.set_hash_at_height(h3, &hash3).expect("h3 set should succeed");

        view.delete_height_range(h1, h2)
            .expect("inclusive delete should succeed");

        prop_assert_eq!(view.get_hash_at_height(h0).expect("h0 lookup should succeed"), Some(hash0));
        prop_assert_eq!(view.get_hash_at_height(h1).expect("h1 lookup should succeed"), None);
        prop_assert_eq!(view.get_hash_at_height(h2).expect("h2 lookup should succeed"), None);
        prop_assert_eq!(view.get_hash_at_height(h3).expect("h3 lookup should succeed"), Some(hash3));
    }

    // 07/25
    #[test]
    fn test_007_set_tip_roundtrips_tip_view_hash_height_and_legacy_tip_metadata(
        tip_height in 0u64..128u64,
        hash_seed in any::<u64>(),
    ) {
        let db = new_test_db("set_tip");
        let manager = db.manager();
        let view = db.view();

        let tip_hash = hash64(0x1A, hash_seed);

        view.set_tip(&tip_hash, tip_height)
            .expect("set_tip should persist canonical tip");

        let tip = view.get_tip()
            .expect("get_tip should succeed")
            .expect("canonical tip should exist");

        prop_assert_eq!(tip.tip_hash, tip_hash);
        prop_assert_eq!(tip.tip_height, tip_height);

        prop_assert_eq!(
            view.get_tip_hash().expect("get_tip_hash should succeed"),
            Some(tip_hash),
            "get_tip_hash must return stored tip hash"
        );

        prop_assert_eq!(
            view.get_tip_height().expect("get_tip_height should succeed"),
            Some(tip_height),
            "get_tip_height must return stored tip height"
        );

        prop_assert_eq!(
            manager.get_tip_height().expect("legacy tip height should be updated"),
            tip_height,
            "set_tip must keep legacy tip height metadata in sync"
        );

        prop_assert_eq!(
            manager.get_latest_block_index().expect("legacy latest index should be updated"),
            tip_height,
            "set_tip must keep legacy latest block index in sync"
        );
    }

    // 08/25
    #[test]
    fn test_008_get_tip_with_legacy_fallback_prefers_explicit_tip_over_legacy_projection(
        explicit_height in 0u64..64u64,
        legacy_seed in any::<u64>(),
        explicit_seed in any::<u64>(),
    ) {
        let db = new_test_db("fallback_prefers_explicit");
        let manager = db.manager();
        let view = db.view();

        let legacy_block = chain_blocks(1, legacy_seed)
            .pop()
            .expect("one generated legacy block should exist");

        store_legacy_block_by_height(&manager, &legacy_block);

        let explicit_hash = distinct_hash64(0x1B, explicit_seed, legacy_block.block_hash);

        view.set_tip(&explicit_hash, explicit_height)
            .expect("explicit tip should store");

        let tip = view.get_tip_with_legacy_fallback()
            .expect("fallback lookup should succeed")
            .expect("explicit tip should be returned");

        prop_assert_eq!(
            tip.tip_hash,
            explicit_hash,
            "explicit canonical tip must be preferred over legacy fallback"
        );

        prop_assert_eq!(
            tip.tip_height,
            explicit_height,
            "explicit canonical tip height must be preferred over legacy fallback"
        );
    }

    // 09/25
    #[test]
    fn test_009_get_tip_with_legacy_fallback_returns_legacy_block_when_explicit_tip_missing(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("fallback_legacy");
        let manager = db.manager();
        let view = db.view();

        let block = chain_blocks(1, seed)
            .pop()
            .expect("one generated legacy block should exist");

        store_legacy_block_by_height(&manager, &block);

        let fallback = view.get_tip_with_legacy_fallback()
            .expect("legacy fallback should succeed")
            .expect("legacy fallback should find stored block");

        prop_assert_eq!(fallback.tip_hash, block.block_hash);
        prop_assert_eq!(fallback.tip_height, block.metadata.index);
    }

    // 10/25
    #[test]
    fn test_010_canonical_hashes_up_to_returns_hashes_in_height_order_when_complete(
        len in 1usize..16usize,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("hashes_up_to_complete");
        let view = db.view();

        let hashes: Vec<BlockHash> = (0..len)
            .map(|i| hash64(0x20, seed.wrapping_add(u64::try_from(i).expect("i fits u64"))))
            .collect();

        for (height, hash) in hashes.iter().enumerate() {
            view.set_hash_at_height(
                u64::try_from(height).expect("height fits u64"),
                hash,
            )
            .expect("canonical hash set should succeed");
        }

        let tip_height = u64::try_from(len.saturating_sub(1)).expect("tip fits u64");

        let out = view.canonical_hashes_up_to(tip_height)
            .expect("complete canonical hashes should read");

        prop_assert_eq!(
            &out,
            &hashes,
            "canonical_hashes_up_to must return hashes from 0..=tip in order"
        );
    }

    // 11/25
    #[test]
    fn test_011_canonical_hashes_up_to_errors_when_any_height_is_missing(
        tip_height in 1u64..32u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("hashes_up_to_missing");
        let view = db.view();

        view.set_hash_at_height(0, &hash64(0x21, seed))
            .expect("height zero set should succeed");

        prop_assert!(
            view.canonical_hashes_up_to(tip_height).is_err(),
            "canonical_hashes_up_to must fail when any height in 0..=tip is missing"
        );
    }

    // 12/25
    #[test]
    fn test_012_canonical_steps_up_to_returns_height_hash_pairs_in_order(
        len in 1usize..16usize,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("steps_up_to");
        let view = db.view();

        let mut expected = Vec::new();

        for height in 0..len {
            let h = u64::try_from(height).expect("height fits u64");
            let hash = hash64(0x22, seed.wrapping_add(h));

            view.set_hash_at_height(h, &hash)
                .expect("canonical hash set should succeed");

            expected.push((h, hash));
        }

        let tip_height = u64::try_from(len.saturating_sub(1)).expect("tip fits u64");

        let out = view.canonical_steps_up_to(tip_height)
            .expect("complete canonical steps should read");

        prop_assert_eq!(
            &out,
            &expected,
            "canonical_steps_up_to must return ordered height/hash pairs"
        );
    }

    // 13/25
    #[test]
    fn test_013_canonical_steps_in_range_returns_empty_for_reversed_bounds(
        from_height in 1u64..128u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("range_reversed");
        let view = db.view();

        view.set_hash_at_height(from_height, &hash64(0x23, seed))
            .expect("height set should succeed");

        let out = view.canonical_steps_in_range(from_height.saturating_add(1), from_height)
            .expect("reversed canonical range should succeed");

        prop_assert!(
            out.is_empty(),
            "canonical_steps_in_range must return empty vector for from_height > to_height"
        );
    }

    // 14/25
    #[test]
    fn test_014_canonical_steps_in_range_returns_exact_inclusive_subrange(
        start in 0u64..32u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("range_inclusive");
        let view = db.view();

        let h0 = start;
        let h1 = start.saturating_add(1);
        let h2 = start.saturating_add(2);
        let h3 = start.saturating_add(3);

        let hash0 = hash64(0x24, seed);
        let hash1 = hash64(0x25, seed);
        let hash2 = hash64(0x26, seed);
        let hash3 = hash64(0x27, seed);

        view.set_hash_at_height(h0, &hash0).expect("h0 set should succeed");
        view.set_hash_at_height(h1, &hash1).expect("h1 set should succeed");
        view.set_hash_at_height(h2, &hash2).expect("h2 set should succeed");
        view.set_hash_at_height(h3, &hash3).expect("h3 set should succeed");

        let out = view.canonical_steps_in_range(h1, h2)
            .expect("complete canonical subrange should read");

        prop_assert_eq!(
            out,
            vec![(h1, hash1), (h2, hash2)],
            "canonical_steps_in_range must include both endpoints and only the requested subrange"
        );
    }

    // 15/25
    #[test]
    fn test_015_canonical_steps_in_range_errors_when_middle_height_is_missing(
        start in 0u64..32u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("range_missing");
        let view = db.view();

        let h0 = start;
        let h1 = start.saturating_add(1);
        let h2 = start.saturating_add(2);

        view.set_hash_at_height(h0, &hash64(0x28, seed))
            .expect("h0 set should succeed");

        view.set_hash_at_height(h2, &hash64(0x29, seed))
            .expect("h2 set should succeed");

        prop_assert!(
            view.canonical_steps_in_range(h0, h2).is_err(),
            "canonical_steps_in_range must fail when a requested middle height is missing"
        );

        prop_assert!(
            view.get_hash_at_height(h1).expect("h1 lookup should succeed").is_none(),
            "test setup must leave middle height missing"
        );
    }

    // 16/25
    #[test]
    fn test_016_canonical_block_at_height_returns_none_when_height_mapping_is_missing(
        height in 0u64..64u64,
    ) {
        let db = new_test_db("canonical_block_no_mapping");
        let view = db.view();

        prop_assert!(
            view.canonical_block_at_height(height)
                .expect("canonical_block_at_height should succeed without mapping")
                .is_none(),
            "canonical_block_at_height must return None when no canonical hash exists at height"
        );
    }

    // 17/25
    #[test]
    fn test_017_canonical_block_at_height_returns_none_when_hash_mapping_points_to_missing_block(
        height in 0u64..64u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("canonical_block_missing_hash");
        let view = db.view();
        let hash = hash64(0x2A, seed);

        view.set_hash_at_height(height, &hash)
            .expect("canonical mapping should set");

        prop_assert!(
            view.canonical_block_at_height(height)
                .expect("canonical_block_at_height should succeed")
                .is_none(),
            "canonical_block_at_height must return None when mapped hash has no block_by_hash record"
        );
    }

    // 18/25
    #[test]
    fn test_018_canonical_block_at_height_resolves_hash_mapping_to_stored_block(
        height in 0u64..32u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("canonical_block_some");
        let manager = db.manager();
        let view = db.view();

        let parent_hash = if height == 0 {
            [0u8; 64]
        } else {
            hash64(0x2B, seed)
        };

        let block = block_with_parent(height, parent_hash, seed);

        index_block_by_hash(&manager, &block);

        view.set_hash_at_height(height, &block.block_hash)
            .expect("canonical mapping should set");

        let fetched = view.canonical_block_at_height(height)
            .expect("canonical block lookup should succeed")
            .expect("block_by_hash record should be resolved");

        prop_assert_eq!(
            &fetched,
            &block,
            "canonical_block_at_height must resolve canonical hash to exact stored block"
        );
    }

    // 19/25
    #[test]
    fn test_019_backfill_from_legacy_projection_rebuilds_canonical_hashes_and_tip_until_legacy_tip(
        len in 1usize..12usize,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("backfill_complete");
        let manager = db.manager();
        let view = db.view();

        let blocks = chain_blocks(len, seed);

        for block in &blocks {
            store_legacy_block_by_height(&manager, block);
        }

        let expected_tip_height = u64::try_from(len.saturating_sub(1)).expect("tip fits u64");

        manager
            .set_tip_height(expected_tip_height)
            .expect("legacy tip height should set");

        let backfilled = view.backfill_from_legacy_projection()
            .expect("backfill should succeed")
            .expect("backfill should produce a tip when legacy blocks exist");

        let expected_tip = blocks
            .last()
            .expect("blocks must be nonempty");

        prop_assert_eq!(backfilled.tip_height, expected_tip_height);
        prop_assert_eq!(backfilled.tip_hash, expected_tip.block_hash);

        for block in &blocks {
            prop_assert_eq!(
                view.get_hash_at_height(block.metadata.index)
                    .expect("backfilled height lookup should succeed"),
                Some(block.block_hash),
                "backfill must set canonical hash for every available legacy height"
            );
        }

        prop_assert_eq!(
            view.get_tip_height().expect("explicit tip height should exist after backfill"),
            Some(expected_tip_height)
        );
    }

    // 20/25
    #[test]
    fn test_020_backfill_from_legacy_projection_stops_at_first_missing_legacy_height(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("backfill_gap");
        let manager = db.manager();
        let view = db.view();

        let blocks = chain_blocks(3, seed);

        store_legacy_block_by_height(&manager, &blocks[0]);
        store_legacy_block_by_height(&manager, &blocks[2]);

        manager
            .set_tip_height(2)
            .expect("legacy tip height should set above gap");

        let backfilled = view.backfill_from_legacy_projection()
            .expect("backfill with gap should not error")
            .expect("height zero should become last backfilled tip");

        prop_assert_eq!(backfilled.tip_height, 0);
        prop_assert_eq!(backfilled.tip_hash, blocks[0].block_hash);

        prop_assert_eq!(
            view.get_hash_at_height(0).expect("height 0 lookup should succeed"),
            Some(blocks[0].block_hash)
        );

        prop_assert_eq!(
            view.get_hash_at_height(1).expect("height 1 lookup should succeed"),
            None,
            "backfill must stop at first missing legacy height"
        );

        prop_assert_eq!(
            view.get_hash_at_height(2).expect("height 2 lookup should succeed"),
            None,
            "backfill must not skip over a missing legacy height"
        );
    }

    // 21/25
    #[test]
    fn test_021_ensure_initialized_returns_existing_tip_without_backfilling_legacy_view(
        explicit_height in 0u64..64u64,
        explicit_seed in any::<u64>(),
        legacy_seed in any::<u64>(),
    ) {
        let db = new_test_db("ensure_existing");
        let manager = db.manager();
        let view = db.view();

        let legacy_block = chain_blocks(1, legacy_seed)
            .pop()
            .expect("one legacy block should exist");

        store_legacy_block_by_height(&manager, &legacy_block);

        let explicit_hash = distinct_hash64(0x2C, explicit_seed, legacy_block.block_hash);

        view.set_tip(&explicit_hash, explicit_height)
            .expect("explicit tip should store");

        let ensured = view.ensure_initialized()
            .expect("ensure_initialized should succeed")
            .expect("existing explicit tip should be returned");

        prop_assert_eq!(ensured.tip_hash, explicit_hash);
        prop_assert_eq!(ensured.tip_height, explicit_height);

        prop_assert_eq!(
            view.get_hash_at_height(legacy_block.metadata.index)
                .expect("legacy height lookup should succeed"),
            None,
            "ensure_initialized must not backfill when explicit tip already exists"
        );
    }

    // 22/25
    #[test]
    fn test_022_choose_better_tip_prefers_higher_height_rejects_lower_height_and_obeys_equal_tiebreak(
        current_seed in any::<u64>(),
        candidate_seed in any::<u64>(),
        height in 1u64..1_000_000u64,
    ) {
        let db = new_test_db("choose_tip");
        let view = db.view();

        let current = hash64(0x30, current_seed);
        let candidate = distinct_hash64(0x31, candidate_seed, current);

        prop_assert_eq!(
            view.choose_better_tip(&current, height, &candidate, height.saturating_add(1), false)
                .expect("higher candidate choice should succeed"),
            candidate,
            "candidate with higher height must win"
        );

        prop_assert_eq!(
            view.choose_better_tip(&current, height, &candidate, height.saturating_sub(1), true)
                .expect("lower candidate choice should succeed"),
            current,
            "candidate with lower height must lose"
        );

        let expected_equal_no_tiebreak = current;

        prop_assert_eq!(
            view.choose_better_tip(&current, height, &candidate, height, false)
                .expect("equal-height no-tiebreak choice should succeed"),
            expected_equal_no_tiebreak,
            "equal height without tiebreak must keep current tip"
        );

        let expected_equal_tiebreak = if candidate < current {
            candidate
        } else {
            current
        };

        prop_assert_eq!(
            view.choose_better_tip(&current, height, &candidate, height, true)
                .expect("equal-height tiebreak choice should succeed"),
            expected_equal_tiebreak,
            "equal height with tiebreak must choose lexicographically lower hash"
        );
    }

    // 23/25
    #[test]
    fn test_023_summarize_tip_reports_missing_meta_or_stored_meta_fields(
        hash_seed in any::<u64>(),
        parent_seed in any::<u64>(),
        height in 0u64..128u64,
        score in any::<u128>(),
    ) {
        let db = new_test_db("summarize_tip");
        let manager = db.manager();
        let view = db.view();

        let hash = hash64(0x32, hash_seed);

        let missing_summary = view.summarize_tip(&hash)
            .expect("missing summary should succeed");

        prop_assert!(
            missing_summary.contains("<missing-meta>"),
            "summarize_tip must clearly mark missing metadata"
        );

        let parent = hash64(0x33, parent_seed);
        let meta = fork_meta(
            parent,
            height,
            score,
            ForkBlockStatus::SideBranch,
            valid_timestamp(height),
        );

        manager
            .store_block_meta_by_hash(&hash, &meta)
            .expect("metadata should store for summary");

        let summary = view.summarize_tip(&hash)
            .expect("stored summary should succeed");

        prop_assert!(
            summary.contains(&format!("height={height}")),
            "summary must include height"
        );

        prop_assert!(
            summary.contains("status=SideBranch"),
            "summary must include status"
        );

        prop_assert!(
            summary.contains(&format!("score={score}")),
            "summary must include cumulative score"
        );
    }

    // 24/25
    #[test]
    fn test_024_apply_canonical_attach_empty_is_noop_and_nonempty_sets_all_hashes_and_last_tip(
        base in 0u64..32u64,
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_attach");
        let view = db.view();

        view.apply_canonical_attach(&[])
            .expect("empty attach should be no-op");

        prop_assert!(
            view.get_tip().expect("tip lookup should succeed after empty attach").is_none(),
            "empty attach must not create a tip"
        );

        let h0 = base;
        let h1 = base.saturating_add(1);
        let h2 = base.saturating_add(2);

        let hash0 = hash64(0x34, seed);
        let hash1 = hash64(0x35, seed);
        let hash2 = hash64(0x36, seed);

        let steps = vec![(h0, hash0), (h1, hash1), (h2, hash2)];

        view.apply_canonical_attach(&steps)
            .expect("nonempty attach should set mappings and tip");

        prop_assert_eq!(view.get_hash_at_height(h0).expect("h0 lookup should succeed"), Some(hash0));
        prop_assert_eq!(view.get_hash_at_height(h1).expect("h1 lookup should succeed"), Some(hash1));
        prop_assert_eq!(view.get_hash_at_height(h2).expect("h2 lookup should succeed"), Some(hash2));

        let tip = view.get_tip()
            .expect("tip lookup should succeed")
            .expect("tip must exist after nonempty attach");

        prop_assert_eq!(tip.tip_height, h2);
        prop_assert_eq!(tip.tip_hash, hash2);
    }

    // 25/25
    #[test]
    fn test_025_switch_canonical_range_deletes_detached_range_attaches_new_steps_and_sets_new_tip(
        base in 0u64..32u64,
        old_seed in any::<u64>(),
        new_seed in any::<u64>(),
    ) {
        let db = new_test_db("switch_range");
        let view = db.view();

        let h0 = base;
        let h1 = base.saturating_add(1);
        let h2 = base.saturating_add(2);
        let h3 = base.saturating_add(3);

        let old0 = hash64(0x40, old_seed);
        let old1 = hash64(0x41, old_seed);
        let old2 = hash64(0x42, old_seed);
        let old3 = hash64(0x43, old_seed);

        view.apply_canonical_attach(&[
            (h0, old0),
            (h1, old1),
            (h2, old2),
            (h3, old3),
        ])
        .expect("initial canonical attach should succeed");

        let new2 = hash64(0x50, new_seed);
        let new3 = hash64(0x51, new_seed);

        view.switch_canonical_range(
            Some(h2),
            Some(h3),
            &[
                (h2, new2),
                (h3, new3),
            ],
        )
        .expect("canonical switch should delete range then attach new steps");

        prop_assert_eq!(
            view.get_hash_at_height(h0).expect("h0 lookup should succeed"),
            Some(old0),
            "switch must preserve heights below detach range"
        );

        prop_assert_eq!(
            view.get_hash_at_height(h1).expect("h1 lookup should succeed"),
            Some(old1),
            "switch must preserve heights below detach range"
        );

        prop_assert_eq!(
            view.get_hash_at_height(h2).expect("h2 lookup should succeed"),
            Some(new2),
            "switch must attach new hash at detached height"
        );

        prop_assert_eq!(
            view.get_hash_at_height(h3).expect("h3 lookup should succeed"),
            Some(new3),
            "switch must attach new tip hash"
        );

        let tip = view.get_tip()
            .expect("tip lookup should succeed")
            .expect("tip must exist after switch");

        prop_assert_eq!(tip.tip_height, h3);
        prop_assert_eq!(tip.tip_hash, new3);
    }
}
