use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::reorganization::reorg_001_block_index::ReorgBlockIndex;
use remzar::reorganization::reorg_002_chain_view::ReorgChainView;
use remzar::reorganization::reorg_005_fork_choice::{
    BlockHash, ForkAction, ReFork, ReForkConfig, ReorgPlan, ReorgStep,
};
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

    fn block_index(&self) -> ReorgBlockIndex {
        ReorgBlockIndex::new(self.manager())
    }

    fn chain_view(&self) -> ReorgChainView {
        ReorgChainView::new(self.manager())
    }

    fn refork(&self, cfg: ReForkConfig) -> ReFork {
        ReFork::new(self.manager(), cfg)
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

    std::env::temp_dir().join(format!("remzar_refork_prop_{label}_{pid}_{id}"))
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

fn signature(seed: u64, tag: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    let byte = u8::try_from(seed % 200)
        .expect("seed modulo 200 must fit into u8")
        .saturating_add(tag.max(1));

    [byte; ml_dsa_65::SIG_LEN]
}

fn block_with_parent(height: u64, parent_hash: BlockHash, seed: u64, tag: u8) -> Block {
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

    let mut merkle_root = hash64(tag.wrapping_add(0xA0), seed.wrapping_add(1));

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
        Some(format!("tx_batch_refork_{height}_{seed}_{tag}")),
        wallet(seed.wrapping_add(u64::from(tag))),
        0,
    )
    .expect("generated valid fork-choice test block should construct")
}

fn child_block(parent: &Block, seed: u64, tag: u8) -> Block {
    block_with_parent(
        parent.metadata.index.saturating_add(1),
        parent.block_hash,
        seed,
        tag,
    )
}

fn genesis_block(seed: u64, tag: u8) -> Block {
    block_with_parent(0, [0u8; 64], seed, tag)
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
        valid_timestamp(block.metadata.index.saturating_add(cumulative_score as u64)),
    )
}

fn store_block_and_meta(
    index: &ReorgBlockIndex,
    block: &Block,
    cumulative_score: u128,
    status: ForkBlockStatus,
) {
    let meta = meta_for_block(block, cumulative_score, status);

    index
        .put_block_and_meta(block, &meta)
        .expect("test block and metadata should store");
}

fn store_block_only(index: &ReorgBlockIndex, block: &Block) {
    index
        .put_block(block)
        .expect("test block should store by hash");
}

fn store_legacy_block_by_height(manager: &RockDBManager, block: &Block) {
    let bytes = block
        .serialize_for_storage()
        .expect("generated block must serialize for legacy storage");

    manager
        .store_latest_block(&bytes, block.metadata.index)
        .expect("store_latest_block should store block by legacy height");
}

fn set_current_tip(db: &TestDb, block: &Block) {
    db.chain_view()
        .set_tip(&block.block_hash, block.metadata.index)
        .expect("canonical tip should set");
}

fn default_cfg() -> ReForkConfig {
    ReForkConfig::default()
}

fn equal_height_cfg() -> ReForkConfig {
    ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: true,
        prefer_cumulative_por: false,
    }
}

fn cumulative_cfg() -> ReForkConfig {
    ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    }
}

fn step(block: &Block) -> ReorgStep {
    ReorgStep {
        height: block.metadata.index,
        hash: block.block_hash,
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
    fn test_001_default_refork_config_is_conservative_height_only_policy(
        _case in any::<u8>(),
    ) {
        let cfg = ReForkConfig::default();

        prop_assert_eq!(cfg.max_reorg_depth, 64);
        prop_assert!(!cfg.allow_equal_height_reorg);
        prop_assert!(!cfg.prefer_cumulative_por);
    }

    // 02/25
    #[test]
    fn test_002_reorg_plan_noop_and_height_helpers_report_empty_or_ordered_steps(
        old_height in 1u64..1_000_000u64,
        seed in any::<u64>(),
    ) {
        let common_hash = hash64(0x11, seed);

        let noop = ReorgPlan {
            old_tip_height: old_height,
            old_tip_hash: common_hash,
            new_tip_height: old_height,
            new_tip_hash: common_hash,
            common_ancestor_height: old_height,
            common_ancestor_hash: common_hash,
            detach: Vec::new(),
            attach: Vec::new(),
        };

        prop_assert!(noop.is_noop());
        prop_assert!(noop.detach_heights().is_empty());
        prop_assert!(noop.attach_heights().is_empty());

        let h1 = old_height.saturating_add(1);
        let h2 = old_height.saturating_add(2);

        let plan = ReorgPlan {
            old_tip_height: h2,
            old_tip_hash: hash64(0x12, seed),
            new_tip_height: h2,
            new_tip_hash: hash64(0x13, seed),
            common_ancestor_height: old_height,
            common_ancestor_hash: common_hash,
            detach: vec![
                ReorgStep { height: h2, hash: hash64(0x14, seed) },
                ReorgStep { height: h1, hash: hash64(0x15, seed) },
            ],
            attach: vec![
                ReorgStep { height: h1, hash: hash64(0x16, seed) },
                ReorgStep { height: h2, hash: hash64(0x17, seed) },
            ],
        };

        prop_assert!(!plan.is_noop());
        prop_assert_eq!(plan.detach_heights(), vec![h2, h1]);
        prop_assert_eq!(plan.attach_heights(), vec![h1, h2]);
    }

    // 03/25
    #[test]
    fn test_003_mainnet_default_and_new_error_when_canonical_tip_is_missing(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("missing_tip");
        let refork = ReFork::mainnet_default(db.manager());

        let block = genesis_block(seed, 0x21);

        prop_assert!(
            refork.on_new_block(&block).is_err(),
            "on_new_block must error when canonical tip view cannot be loaded"
        );
    }

    // 04/25
    #[test]
    fn test_004_new_block_extending_current_tip_returns_stay_without_reorg(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("extends_tip");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x22);
        let child = child_block(&genesis, seed.wrapping_add(1), 0x23);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        set_current_tip(&db, &genesis);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&child)
            .expect("happy path extending current tip should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "direct child of current canonical tip must return Stay"),
        }
    }

    // 05/25
    #[test]
    fn test_005_lower_height_side_branch_candidate_returns_stay(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("lower_height_stay");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x24);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x25);
        let old2 = child_block(&old1, seed.wrapping_add(2), 0x26);
        let side1 = child_block(&genesis, seed.wrapping_add(3), 0x27);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old2, 2, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &side1, 1, ForkBlockStatus::SideBranch);

        set_current_tip(&db, &old2);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&side1)
            .expect("lower-height side branch decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "lower-height candidate must not trigger reorg"),
        }
    }

    // 06/25
    #[test]
    fn test_006_equal_height_candidate_without_equal_height_reorg_returns_stay(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("equal_height_no_tiebreak");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x28);
        let sibling_a = child_block(&genesis, seed.wrapping_add(1), 0x29);
        let sibling_b = child_block(&genesis, seed.wrapping_add(2), 0x2A);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &sibling_a, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &sibling_b, 1, ForkBlockStatus::SideBranch);

        set_current_tip(&db, &sibling_a);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&sibling_b)
            .expect("equal-height no-tiebreak decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "equal-height candidate must stay when equal-height reorg is disabled"),
        }
    }

    // 07/25
    #[test]
    fn test_007_equal_height_candidate_with_lower_hash_reorgs_when_equal_height_reorg_enabled(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("equal_height_lower_hash_reorg");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x2B);
        let sibling_a = child_block(&genesis, seed.wrapping_add(1), 0x2C);
        let sibling_b = child_block(&genesis, seed.wrapping_add(2), 0x2D);

        let (current, candidate) = if sibling_a.block_hash < sibling_b.block_hash {
            (sibling_b, sibling_a)
        } else {
            (sibling_a, sibling_b)
        };

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &current, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &candidate, 1, ForkBlockStatus::SideBranch);

        set_current_tip(&db, &current);

        let refork = db.refork(equal_height_cfg());

        match refork
            .on_new_block(&candidate)
            .expect("equal-height lower-hash decision should succeed")
        {
            ForkAction::Reorg(plan) => {
                prop_assert_eq!(plan.old_tip_hash, current.block_hash);
                prop_assert_eq!(plan.new_tip_hash, candidate.block_hash);
                prop_assert_eq!(plan.common_ancestor_hash, genesis.block_hash);
                prop_assert_eq!(plan.detach_heights(), vec![1]);
                prop_assert_eq!(plan.attach_heights(), vec![1]);
            }
            _ => prop_assert!(false, "lower-hash equal-height candidate must trigger reorg when enabled"),
        }
    }

    // 08/25
    #[test]
    fn test_008_equal_height_candidate_with_higher_hash_stays_even_when_equal_height_reorg_enabled(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("equal_height_higher_hash_stay");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x2E);
        let sibling_a = child_block(&genesis, seed.wrapping_add(1), 0x2F);
        let sibling_b = child_block(&genesis, seed.wrapping_add(2), 0x30);

        let (current, candidate) = if sibling_a.block_hash < sibling_b.block_hash {
            (sibling_a, sibling_b)
        } else {
            (sibling_b, sibling_a)
        };

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &current, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &candidate, 1, ForkBlockStatus::SideBranch);

        set_current_tip(&db, &current);

        let refork = db.refork(equal_height_cfg());

        match refork
            .on_new_block(&candidate)
            .expect("equal-height higher-hash decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "higher-hash equal-height candidate must not replace lower current hash"),
        }
    }

    // 09/25
    #[test]
    fn test_009_taller_complete_side_branch_returns_reorg_plan_with_correct_common_ancestor(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("taller_reorg_plan");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x31);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x32);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x33);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x34);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::SideBranch);
        store_block_and_meta(&index, &new2, 2, ForkBlockStatus::Validated);

        set_current_tip(&db, &old1);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&new2)
            .expect("taller complete side branch should produce decision")
        {
            ForkAction::Reorg(plan) => {
                prop_assert_eq!(plan.old_tip_height, 1);
                prop_assert_eq!(plan.old_tip_hash, old1.block_hash);
                prop_assert_eq!(plan.new_tip_height, 2);
                prop_assert_eq!(plan.new_tip_hash, new2.block_hash);
                prop_assert_eq!(plan.common_ancestor_height, 0);
                prop_assert_eq!(plan.common_ancestor_hash, genesis.block_hash);
                prop_assert_eq!(plan.detach, vec![step(&old1)]);
                prop_assert_eq!(plan.attach, vec![step(&new1), step(&new2)]);
            }
            _ => prop_assert!(false, "taller complete branch must trigger reorg"),
        }
    }

    // 10/25
    #[test]
    fn test_010_reorg_plan_detach_is_descending_and_attach_is_ascending_for_deeper_fork(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("deeper_fork_order");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x35);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x36);
        let old2 = child_block(&old1, seed.wrapping_add(2), 0x37);
        let new1 = child_block(&genesis, seed.wrapping_add(3), 0x38);
        let new2 = child_block(&new1, seed.wrapping_add(4), 0x39);
        let new3 = child_block(&new2, seed.wrapping_add(5), 0x3A);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&old2, 2, ForkBlockStatus::Canonical),
            (&new1, 1, ForkBlockStatus::SideBranch),
            (&new2, 2, ForkBlockStatus::SideBranch),
            (&new3, 3, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        set_current_tip(&db, &old2);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&new3)
            .expect("deeper fork should produce decision")
        {
            ForkAction::Reorg(plan) => {
                prop_assert_eq!(
                    &plan.detach,
                    &vec![step(&old2), step(&old1)],
                    "detach steps must be descending from old tip toward ancestor"
                );

                prop_assert_eq!(
                    &plan.attach,
                    &vec![step(&new1), step(&new2), step(&new3)],
                    "attach steps must be ascending from ancestor child toward new tip"
                );

                prop_assert_eq!(plan.detach_heights(), vec![2, 1]);
                prop_assert_eq!(plan.attach_heights(), vec![1, 2, 3]);
            }
            _ => prop_assert!(false, "deeper taller branch must trigger reorg"),
        }
    }

    // 11/25
    #[test]
    fn test_011_reorg_is_refused_when_no_common_ancestor_is_found_within_available_paths(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("no_common_ancestor");
        let index = db.block_index();

        let old_root = genesis_block(seed, 0x3B);
        let old1 = child_block(&old_root, seed.wrapping_add(1), 0x3C);

        let new_root = genesis_block(seed.wrapping_add(99), 0x3D);
        let new1 = child_block(&new_root, seed.wrapping_add(100), 0x3E);
        let new2 = child_block(&new1, seed.wrapping_add(101), 0x3F);

        for (block, score, status) in [
            (&old_root, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&new_root, 0, ForkBlockStatus::SideBranch),
            (&new1, 1, ForkBlockStatus::SideBranch),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        set_current_tip(&db, &old1);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&new2)
            .expect("no-common-ancestor decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "fork without common ancestor must be refused"),
        }
    }

    // 12/25
    #[test]
    fn test_012_reorg_is_refused_when_depth_limit_is_too_small_to_build_common_path(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("depth_limit_refusal");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x40);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x41);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x42);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x43);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&new1, 1, ForkBlockStatus::SideBranch),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        set_current_tip(&db, &old1);

        let refork = db.refork(ReForkConfig {
            max_reorg_depth: 0,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        });

        match refork
            .on_new_block(&new2)
            .expect("depth-limited decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "reorg must be refused when depth limit prevents safe path planning"),
        }
    }

    // 13/25
    #[test]
    fn test_013_missing_new_branch_parent_block_returns_need_more_data(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("missing_new_parent_block");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x44);
        let missing_parent = hash64(0x45, seed);
        let candidate = block_with_parent(2, missing_parent, seed.wrapping_add(1), 0x46);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &candidate, 2, ForkBlockStatus::Validated);

        set_current_tip(&db, &genesis);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&candidate)
            .expect("missing parent block should return NeedMoreData")
        {
            ForkAction::NeedMoreData {
                missing_hash,
                context,
            } => {
                prop_assert_eq!(missing_hash, missing_parent);
                prop_assert_eq!(context, "missing_block_for_parent_hash");
            }
            _ => prop_assert!(false, "missing parent block must request more data"),
        }
    }

    // 14/25
    #[test]
    fn test_014_missing_new_branch_parent_meta_returns_need_more_data(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("missing_new_parent_meta");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x47);
        let parent = child_block(&genesis, seed.wrapping_add(1), 0x48);
        let candidate = child_block(&parent, seed.wrapping_add(2), 0x49);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_only(&index, &parent);
        store_block_and_meta(&index, &candidate, 2, ForkBlockStatus::Validated);

        set_current_tip(&db, &genesis);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&candidate)
            .expect("missing parent meta should return NeedMoreData")
        {
            ForkAction::NeedMoreData {
                missing_hash,
                context,
            } => {
                prop_assert_eq!(missing_hash, parent.block_hash);
                prop_assert_eq!(context, "missing_meta_for_parent_hash");
            }
            _ => prop_assert!(false, "missing parent metadata must request more data"),
        }
    }

    // 15/25
    #[test]
    fn test_015_missing_canonical_branch_parent_data_returns_need_more_data(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("missing_old_parent_data");
        let index = db.block_index();

        let old_parent_missing = hash64(0x4A, seed);
        let old_tip = block_with_parent(2, old_parent_missing, seed.wrapping_add(1), 0x4B);

        let genesis = genesis_block(seed.wrapping_add(2), 0x4C);
        let new1 = child_block(&genesis, seed.wrapping_add(3), 0x4D);
        let new2 = child_block(&new1, seed.wrapping_add(4), 0x4E);
        let new3 = child_block(&new2, seed.wrapping_add(5), 0x4F);

        store_block_and_meta(&index, &old_tip, 2, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::SideBranch);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::SideBranch);
        store_block_and_meta(&index, &new2, 2, ForkBlockStatus::SideBranch);
        store_block_and_meta(&index, &new3, 3, ForkBlockStatus::Validated);

        set_current_tip(&db, &old_tip);

        let refork = db.refork(default_cfg());

        match refork
            .on_new_block(&new3)
            .expect("missing canonical parent data should return NeedMoreData")
        {
            ForkAction::NeedMoreData {
                missing_hash,
                context,
            } => {
                prop_assert_eq!(missing_hash, old_parent_missing);
                prop_assert_eq!(context, "missing_block_for_parent_hash");
            }
            _ => prop_assert!(false, "missing canonical ancestry must request more data"),
        }
    }

    // 16/25
    #[test]
    fn test_016_cumulative_por_mode_can_choose_shorter_branch_with_higher_score(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("cumulative_por_shorter_wins");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x50);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x51);
        let old2 = child_block(&old1, seed.wrapping_add(2), 0x52);
        let new1 = child_block(&genesis, seed.wrapping_add(3), 0x53);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 10, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old2, 20, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1_000_000, ForkBlockStatus::Validated);

        set_current_tip(&db, &old2);

        let refork = db.refork(cumulative_cfg());

        match refork
            .on_new_block(&new1)
            .expect("cumulative-PoR fork choice should succeed")
        {
            ForkAction::Reorg(plan) => {
                prop_assert_eq!(plan.old_tip_hash, old2.block_hash);
                prop_assert_eq!(plan.new_tip_hash, new1.block_hash);
                prop_assert_eq!(plan.detach, vec![step(&old2), step(&old1)]);
                prop_assert_eq!(plan.attach, vec![step(&new1)]);
            }
            _ => prop_assert!(false, "higher cumulative-PoR candidate must trigger reorg in cumulative mode"),
        }
    }

    // 17/25
    #[test]
    fn test_017_apply_reorg_noop_calls_no_callbacks_and_keeps_existing_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_noop");
        let index = db.block_index();
        let chain = db.chain_view();

        let genesis = genesis_block(seed, 0x54);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        set_current_tip(&db, &genesis);

        let plan = ReorgPlan {
            old_tip_height: 0,
            old_tip_hash: genesis.block_hash,
            new_tip_height: 0,
            new_tip_hash: genesis.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: Vec::new(),
            attach: Vec::new(),
        };

        let refork = db.refork(default_cfg());
        let mut reverted = Vec::<ReorgStep>::new();
        let mut applied = Vec::<ReorgStep>::new();

        refork
            .apply_reorg(
                &plan,
                |height, hash| {
                    reverted.push(ReorgStep { height, hash });
                    Ok(())
                },
                |height, hash| {
                    applied.push(ReorgStep { height, hash });
                    Ok(())
                },
            )
            .expect("noop apply should succeed");

        prop_assert!(reverted.is_empty());
        prop_assert!(applied.is_empty());

        let tip = chain.get_tip()
            .expect("tip lookup should succeed")
            .expect("tip should still exist");

        prop_assert_eq!(tip.tip_height, 0);
        prop_assert_eq!(tip.tip_hash, genesis.block_hash);
    }

    // 18/25
    #[test]
    fn test_018_apply_reorg_calls_revert_callbacks_in_detach_order_and_marks_detached_meta_side_branch(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_revert_order");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x55);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x56);
        let old2 = child_block(&old1, seed.wrapping_add(2), 0x57);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old2, 2, ForkBlockStatus::Canonical);

        set_current_tip(&db, &old2);

        let plan = ReorgPlan {
            old_tip_height: 2,
            old_tip_hash: old2.block_hash,
            new_tip_height: 0,
            new_tip_hash: genesis.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: vec![step(&old2), step(&old1)],
            attach: Vec::new(),
        };

        let refork = db.refork(default_cfg());
        let mut reverted = Vec::<ReorgStep>::new();

        refork
            .apply_reorg(
                &plan,
                |height, hash| {
                    reverted.push(ReorgStep { height, hash });
                    Ok(())
                },
                |_height, _hash| Ok(()),
            )
            .expect("detach-only apply should succeed");

        prop_assert_eq!(reverted, vec![step(&old2), step(&old1)]);

        prop_assert_eq!(
            index.status_of(&old1.block_hash).expect("old1 status lookup should succeed"),
            Some(ForkBlockStatus::SideBranch)
        );

        prop_assert_eq!(
            index.status_of(&old2.block_hash).expect("old2 status lookup should succeed"),
            Some(ForkBlockStatus::SideBranch)
        );
    }

    // 19/25
    #[test]
    fn test_019_apply_reorg_errors_when_attach_block_is_missing(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_missing_attach");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x58);
        let missing_hash = hash64(0x59, seed);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        set_current_tip(&db, &genesis);

        let plan = ReorgPlan {
            old_tip_height: 0,
            old_tip_hash: genesis.block_hash,
            new_tip_height: 1,
            new_tip_hash: missing_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: Vec::new(),
            attach: vec![ReorgStep {
                height: 1,
                hash: missing_hash,
            }],
        };

        let refork = db.refork(default_cfg());

        prop_assert!(
            refork.apply_reorg(&plan, |_h, _x| Ok(()), |_h, _x| Ok(())).is_err(),
            "apply_reorg must error when an attach block is missing from block_by_hash"
        );
    }

    // 20/25
    #[test]
    fn test_020_apply_reorg_errors_when_attach_step_height_disagrees_with_stored_block_height(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_height_mismatch");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x5A);
        let child = child_block(&genesis, seed.wrapping_add(1), 0x5B);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &child, 1, ForkBlockStatus::Validated);

        set_current_tip(&db, &genesis);

        let plan = ReorgPlan {
            old_tip_height: 0,
            old_tip_hash: genesis.block_hash,
            new_tip_height: 2,
            new_tip_hash: child.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: Vec::new(),
            attach: vec![ReorgStep {
                height: 2,
                hash: child.block_hash,
            }],
        };

        let refork = db.refork(default_cfg());

        prop_assert!(
            refork.apply_reorg(&plan, |_h, _x| Ok(()), |_h, _x| Ok(())).is_err(),
            "apply_reorg must reject attach step whose planned height differs from block.metadata.index"
        );
    }

    // 21/25
    #[test]
    fn test_021_apply_reorg_attaches_new_branch_updates_canonical_hashes_legacy_blocks_tip_and_callbacks(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_full_switch");
        let index = db.block_index();
        let chain = db.chain_view();
        let manager = db.manager();

        let genesis = genesis_block(seed, 0x5C);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x5D);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x5E);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x5F);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&new1, 1, ForkBlockStatus::Validated),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        chain.set_hash_at_height(0, &genesis.block_hash).expect("h0 mapping should set");
        chain.set_hash_at_height(1, &old1.block_hash).expect("old h1 mapping should set");
        set_current_tip(&db, &old1);

        let plan = ReorgPlan {
            old_tip_height: 1,
            old_tip_hash: old1.block_hash,
            new_tip_height: 2,
            new_tip_hash: new2.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: vec![step(&old1)],
            attach: vec![step(&new1), step(&new2)],
        };

        let refork = db.refork(default_cfg());
        let mut reverted = Vec::<ReorgStep>::new();
        let mut applied = Vec::<ReorgStep>::new();

        refork
            .apply_reorg(
                &plan,
                |height, hash| {
                    reverted.push(ReorgStep { height, hash });
                    Ok(())
                },
                |height, hash| {
                    applied.push(ReorgStep { height, hash });
                    Ok(())
                },
            )
            .expect("full reorg apply should succeed");

        prop_assert_eq!(reverted, vec![step(&old1)]);
        prop_assert_eq!(applied, vec![step(&new1), step(&new2)]);

        prop_assert_eq!(
            chain.get_hash_at_height(1).expect("h1 mapping lookup should succeed"),
            Some(new1.block_hash)
        );

        prop_assert_eq!(
            chain.get_hash_at_height(2).expect("h2 mapping lookup should succeed"),
            Some(new2.block_hash)
        );

        let tip = chain.get_tip()
            .expect("tip lookup should succeed")
            .expect("tip must exist after apply");

        prop_assert_eq!(tip.tip_height, 2);
        prop_assert_eq!(tip.tip_hash, new2.block_hash);

        let legacy_new2 = manager
            .get_block_by_index(2)
            .expect("legacy block lookup should succeed")
            .expect("legacy block at new tip height must exist");

        prop_assert_eq!(&legacy_new2, &new2);

        prop_assert_eq!(
            index.status_of(&new1.block_hash).expect("new1 status should read"),
            Some(ForkBlockStatus::Canonical)
        );

        prop_assert_eq!(
            index.status_of(&new2.block_hash).expect("new2 status should read"),
            Some(ForkBlockStatus::Canonical)
        );
    }

    // 22/25
    #[test]
    fn test_022_apply_reorg_deletes_detached_canonical_height_range_above_common_ancestor(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_delete_range");
        let index = db.block_index();
        let chain = db.chain_view();

        let genesis = genesis_block(seed, 0x60);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x61);
        let old2 = child_block(&old1, seed.wrapping_add(2), 0x62);
        let new1 = child_block(&genesis, seed.wrapping_add(3), 0x63);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&old2, 2, ForkBlockStatus::Canonical),
            (&new1, 1, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        chain.set_hash_at_height(0, &genesis.block_hash).expect("h0 mapping should set");
        chain.set_hash_at_height(1, &old1.block_hash).expect("old h1 mapping should set");
        chain.set_hash_at_height(2, &old2.block_hash).expect("old h2 mapping should set");
        set_current_tip(&db, &old2);

        let plan = ReorgPlan {
            old_tip_height: 2,
            old_tip_hash: old2.block_hash,
            new_tip_height: 1,
            new_tip_hash: new1.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: vec![step(&old2), step(&old1)],
            attach: vec![step(&new1)],
        };

        let refork = db.refork(default_cfg());

        refork
            .apply_reorg(&plan, |_h, _x| Ok(()), |_h, _x| Ok(()))
            .expect("apply should succeed");

        prop_assert_eq!(
            chain.get_hash_at_height(1).expect("h1 lookup should succeed"),
            Some(new1.block_hash),
            "attached height should be rewritten"
        );

        prop_assert_eq!(
            chain.get_hash_at_height(2).expect("h2 lookup should succeed"),
            None,
            "detached height above new tip must be removed from canonical view"
        );
    }

    // 23/25
    #[test]
    fn test_023_apply_reorg_preserves_detached_legacy_block_in_block_hash_index(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("preserve_detached_hash_index");
        let index = db.block_index();
        let manager = db.manager();

        let genesis = genesis_block(seed, 0x64);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x65);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);

        store_legacy_block_by_height(&manager, &old1);

        let old1_meta = meta_for_block(&old1, 1, ForkBlockStatus::Canonical);
        index
            .put_meta(&old1.block_hash, &old1_meta)
            .expect("old1 metadata should store without block-by-hash");

        set_current_tip(&db, &genesis);

        let plan = ReorgPlan {
            old_tip_height: 1,
            old_tip_hash: old1.block_hash,
            new_tip_height: 0,
            new_tip_hash: genesis.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: vec![step(&old1)],
            attach: Vec::new(),
        };

        let refork = db.refork(default_cfg());

        refork
            .apply_reorg(&plan, |_h, _x| Ok(()), |_h, _x| Ok(()))
            .expect("detach should preserve old legacy block by hash");

        prop_assert!(
            index.has_block(&old1.block_hash),
            "detached old canonical block must be preserved in block_by_hash index"
        );

        let fetched = index.get_block(&old1.block_hash)
            .expect("detached block lookup should succeed")
            .expect("detached block must exist by hash");

        prop_assert_eq!(&fetched, &old1);
    }

    // 24/25
    #[test]
    fn test_024_apply_reorg_propagates_revert_callback_error_before_attach_phase(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("revert_error");
        let index = db.block_index();
        let chain = db.chain_view();

        let genesis = genesis_block(seed, 0x66);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x67);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x68);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::Validated);

        chain.set_hash_at_height(1, &old1.block_hash).expect("old h1 mapping should set");
        set_current_tip(&db, &old1);

        let plan = ReorgPlan {
            old_tip_height: 1,
            old_tip_hash: old1.block_hash,
            new_tip_height: 1,
            new_tip_hash: new1.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: vec![step(&old1)],
            attach: vec![step(&new1)],
        };

        let refork = db.refork(default_cfg());

        let result = refork.apply_reorg(
            &plan,
            |_h, _x| {
                Err(remzar::utility::alpha_002_error_detection_system::ErrorDetection::BlockchainError {
                    details: "intentional revert callback failure".to_string(),
                })
            },
            |_h, _x| Ok(()),
        );

        prop_assert!(
            result.is_err(),
            "apply_reorg must propagate revert callback error"
        );

        prop_assert_eq!(
            chain.get_hash_at_height(1).expect("h1 lookup should succeed"),
            Some(old1.block_hash),
            "attach phase must not run after revert callback error"
        );
    }

    // 25/25
    #[test]
    fn test_025_apply_reorg_propagates_apply_callback_error_after_canonical_attach_has_been_written(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_error");
        let index = db.block_index();
        let chain = db.chain_view();

        let genesis = genesis_block(seed, 0x69);
        let new1 = child_block(&genesis, seed.wrapping_add(1), 0x6A);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::Validated);

        set_current_tip(&db, &genesis);

        let plan = ReorgPlan {
            old_tip_height: 0,
            old_tip_hash: genesis.block_hash,
            new_tip_height: 1,
            new_tip_hash: new1.block_hash,
            common_ancestor_height: 0,
            common_ancestor_hash: genesis.block_hash,
            detach: Vec::new(),
            attach: vec![step(&new1)],
        };

        let refork = db.refork(default_cfg());

        let result = refork.apply_reorg(
            &plan,
            |_h, _x| Ok(()),
            |_h, _x| {
                Err(remzar::utility::alpha_002_error_detection_system::ErrorDetection::BlockchainError {
                    details: "intentional apply callback failure".to_string(),
                })
            },
        );

        prop_assert!(
            result.is_err(),
            "apply_reorg must propagate apply callback error"
        );

        prop_assert_eq!(
            chain.get_hash_at_height(1).expect("h1 lookup should succeed"),
            Some(new1.block_hash),
            "canonical hash mapping is written before apply callback error is returned"
        );

        prop_assert_eq!(
            index.status_of(&new1.block_hash).expect("new1 status lookup should succeed"),
            Some(ForkBlockStatus::Canonical),
            "attach metadata is marked canonical before apply callback error is returned"
        );
    }
}
