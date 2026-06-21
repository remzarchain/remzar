use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::reorganization::reorg_001_block_index::ReorgBlockIndex;
use remzar::reorganization::reorg_002_chain_view::ReorgChainView;
use remzar::reorganization::reorg_004_batch_index::ReorgBatchIndex;
use remzar::reorganization::reorg_005_fork_choice::{
    BlockHash, ForkAction, ReForkConfig, ReorgPlan, ReorgStep,
};
use remzar::reorganization::reorg_006_manager::ReorgManager;
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

    fn batch_index(&self) -> ReorgBatchIndex {
        ReorgBatchIndex::new(self.manager())
    }

    fn manager_default(&self) -> ReorgManager {
        ReorgManager::mainnet_default(self.manager())
    }

    fn manager_with_cfg(&self, cfg: ReForkConfig) -> ReorgManager {
        ReorgManager::new(self.manager(), cfg)
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

    std::env::temp_dir().join(format!("remzar_reorg_manager_prop_{label}_{pid}_{id}"))
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

fn account_tree(db: &TestDb) -> AccountModelTree {
    let manager = db.manager();
    AccountModelTree::with_manager((*manager).clone())
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
    let base = u8::try_from(seed % 200).expect("seed modulo 200 must fit into u8");
    let byte = base.saturating_add(tag.max(1));

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
        Some(format!("tx_batch_reorg_manager_{height}_{seed}_{tag}")),
        wallet(seed.wrapping_add(u64::from(tag))),
        0,
    )
    .expect("generated valid reorg-manager test block should construct")
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

fn empty_batch_bytes(height: u64) -> Vec<u8> {
    TransactionBatch::new(height, valid_timestamp(height), Vec::new())
        .expect("empty test batch should construct")
        .serialize()
        .expect("empty test batch should serialize")
}

fn store_legacy_block_by_height(manager: &RockDBManager, block: &Block) {
    let bytes = block
        .serialize_for_storage()
        .expect("generated block must serialize for legacy storage");

    manager
        .store_latest_block(&bytes, block.metadata.index)
        .expect("store_latest_block should store block by legacy height");
}

fn store_canonical_block_projection(db: &TestDb, block: &Block) {
    store_legacy_block_by_height(db.manager().as_ref(), block);

    db.chain_view()
        .set_hash_at_height(block.metadata.index, &block.block_hash)
        .expect("canonical height-to-hash mapping should store");

    if block.metadata.index > 0 {
        let bytes = empty_batch_bytes(block.metadata.index);

        db.batch_index()
            .set_canonical_batch_at_height(block.metadata.index, &bytes)
            .expect("canonical batch projection should store");
    }
}

fn store_batch_by_hash(db: &TestDb, block: &Block) {
    let bytes = empty_batch_bytes(block.metadata.index);

    db.batch_index()
        .put_batch_by_block_hash(&block.block_hash, &bytes)
        .expect("batch-by-block-hash should store");
}

fn set_current_tip(db: &TestDb, block: &Block) {
    db.chain_view()
        .set_tip(&block.block_hash, block.metadata.index)
        .expect("canonical tip should set");
}

fn step(block: &Block) -> ReorgStep {
    ReorgStep {
        height: block.metadata.index,
        hash: block.block_hash,
    }
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

fn plan_to_tip(
    old_tip: &Block,
    new_tip: &Block,
    common: &Block,
    detach: Vec<ReorgStep>,
    attach: Vec<ReorgStep>,
) -> ReorgPlan {
    ReorgPlan {
        old_tip_height: old_tip.metadata.index,
        old_tip_hash: old_tip.block_hash,
        new_tip_height: new_tip.metadata.index,
        new_tip_hash: new_tip.block_hash,
        common_ancestor_height: common.metadata.index,
        common_ancestor_hash: common.block_hash,
        detach,
        attach,
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
    fn test_001_mainnet_default_fork_engine_errors_safely_when_tip_view_is_missing(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("missing_tip_default");
        let manager = db.manager_default();
        let block = genesis_block(seed, 0x11);

        prop_assert!(
            manager.fork_engine().on_new_block(&block).is_err(),
            "fork_engine must surface missing canonical tip errors safely"
        );
    }

    // 02/25
    #[test]
    fn test_002_handle_new_block_returns_stay_for_direct_child_of_current_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("handle_direct_child_stay");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x12);
        let child = child_block(&genesis, seed.wrapping_add(1), 0x13);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_canonical_block_projection(&db, &genesis);
        set_current_tip(&db, &genesis);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&child, &mut chain, None)
            .expect("direct child decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "direct child of current tip must stay and not apply a reorg"),
        }

        let tip = db.chain_view()
            .get_tip()
            .expect("tip lookup should succeed")
            .expect("tip should remain present");

        prop_assert_eq!(tip.tip_hash, genesis.block_hash);
        prop_assert_eq!(tip.tip_height, 0);
    }

    // 03/25
    #[test]
    fn test_003_handle_new_block_returns_stay_for_lower_height_side_branch_and_preserves_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("lower_side_branch_stay");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x14);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x15);
        let old2 = child_block(&old1, seed.wrapping_add(2), 0x16);
        let side1 = child_block(&genesis, seed.wrapping_add(3), 0x17);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&old2, 2, ForkBlockStatus::Canonical),
            (&side1, 1, ForkBlockStatus::SideBranch),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_canonical_block_projection(&db, &old2);
        set_current_tip(&db, &old2);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&side1, &mut chain, None)
            .expect("lower side branch decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "lower-height side branch must not trigger reorg"),
        }

        let tip = db.chain_view()
            .get_tip()
            .expect("tip lookup should succeed")
            .expect("tip should remain present");

        prop_assert_eq!(tip.tip_hash, old2.block_hash);
        prop_assert_eq!(tip.tip_height, 2);
    }

    // 04/25
    #[test]
    fn test_004_handle_new_block_equal_height_stays_when_equal_height_reorg_is_disabled(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("equal_height_disabled");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x18);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x19);
        let side1 = child_block(&genesis, seed.wrapping_add(2), 0x1A);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &side1, 1, ForkBlockStatus::SideBranch);

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        set_current_tip(&db, &old1);

        let manager = db.manager_with_cfg(default_cfg());
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&side1, &mut chain, None)
            .expect("equal-height disabled decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "equal-height fork must stay when equal-height reorg is disabled"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(old1.block_hash)
        );
    }

    // 05/25
    #[test]
    fn test_005_handle_new_block_equal_height_lower_hash_reorgs_when_enabled_and_batches_exist(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("equal_height_enabled_lower");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x1B);
        let sibling_a = child_block(&genesis, seed.wrapping_add(1), 0x1C);
        let sibling_b = child_block(&genesis, seed.wrapping_add(2), 0x1D);

        let (old1, new1) = if sibling_a.block_hash < sibling_b.block_hash {
            (sibling_b, sibling_a)
        } else {
            (sibling_a, sibling_b)
        };

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::SideBranch);

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_batch_by_hash(&db, &new1);
        set_current_tip(&db, &old1);

        let manager = db.manager_with_cfg(equal_height_cfg());
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&new1, &mut chain, None)
            .expect("equal-height lower-hash reorg should succeed")
        {
            ForkAction::Reorg(plan) => {
                prop_assert_eq!(plan.old_tip_hash, old1.block_hash);
                prop_assert_eq!(plan.new_tip_hash, new1.block_hash);
                prop_assert_eq!(plan.common_ancestor_hash, genesis.block_hash);
                prop_assert_eq!(plan.detach_heights(), vec![1]);
                prop_assert_eq!(plan.attach_heights(), vec![1]);
            }
            _ => prop_assert!(false, "lower-hash equal-height branch must reorg when enabled"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(new1.block_hash)
        );

        prop_assert_eq!(
            chain.latest_block_height(),
            1,
            "manager must reload account tree to the new canonical tip height"
        );
    }

    // 06/25
    #[test]
    fn test_006_handle_new_block_taller_complete_branch_applies_reorg_and_reload(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("taller_reorg_handle");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x1E);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x1F);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x20);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x21);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&new1, 1, ForkBlockStatus::SideBranch),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_batch_by_hash(&db, &new1);
        store_batch_by_hash(&db, &new2);
        set_current_tip(&db, &old1);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&new2, &mut chain, None)
            .expect("taller branch should reorg and reload")
        {
            ForkAction::Reorg(plan) => {
                prop_assert_eq!(plan.detach_heights(), vec![1]);
                prop_assert_eq!(plan.attach_heights(), vec![1, 2]);
                prop_assert_eq!(plan.new_tip_hash, new2.block_hash);
            }
            _ => prop_assert!(false, "taller complete branch must apply reorg"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_height().expect("tip height should read"),
            Some(2)
        );

        prop_assert_eq!(
            db.chain_view().get_hash_at_height(1).expect("h1 should read"),
            Some(new1.block_hash)
        );

        prop_assert_eq!(
            db.chain_view().get_hash_at_height(2).expect("h2 should read"),
            Some(new2.block_hash)
        );

        prop_assert_eq!(chain.latest_block_height(), 2);
    }

    // 07/25
    #[test]
    fn test_007_handle_new_block_need_more_data_for_missing_new_parent_block_does_not_mutate_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("need_more_new_parent");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x22);
        let missing_parent = hash64(0x23, seed);
        let candidate = block_with_parent(2, missing_parent, seed.wrapping_add(1), 0x24);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &candidate, 2, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        set_current_tip(&db, &genesis);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&candidate, &mut chain, None)
            .expect("missing parent should return NeedMoreData")
        {
            ForkAction::NeedMoreData {
                missing_hash,
                context,
            } => {
                prop_assert_eq!(missing_hash, missing_parent);
                prop_assert_eq!(context, "missing_block_for_parent_hash");
            }
            _ => prop_assert!(false, "missing parent block must return NeedMoreData"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(genesis.block_hash)
        );

        prop_assert_eq!(chain.latest_block_height(), 0);
    }

    // 08/25
    #[test]
    fn test_008_handle_new_block_need_more_data_for_missing_new_parent_meta_does_not_mutate_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("need_more_parent_meta");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x25);
        let parent = child_block(&genesis, seed.wrapping_add(1), 0x26);
        let candidate = child_block(&parent, seed.wrapping_add(2), 0x27);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_only(&index, &parent);
        store_block_and_meta(&index, &candidate, 2, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        set_current_tip(&db, &genesis);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&candidate, &mut chain, None)
            .expect("missing parent metadata should return NeedMoreData")
        {
            ForkAction::NeedMoreData {
                missing_hash,
                context,
            } => {
                prop_assert_eq!(missing_hash, parent.block_hash);
                prop_assert_eq!(context, "missing_meta_for_parent_hash");
            }
            _ => prop_assert!(false, "missing parent metadata must return NeedMoreData"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(genesis.block_hash)
        );
    }

    // 09/25
    #[test]
    fn test_009_handle_new_block_cumulative_por_config_can_reorg_to_shorter_higher_score_branch(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("cumulative_por_handle");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x28);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x29);
        let old2 = child_block(&old1, seed.wrapping_add(2), 0x2A);
        let new1 = child_block(&genesis, seed.wrapping_add(3), 0x2B);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 10, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old2, 20, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1_000_000, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_canonical_block_projection(&db, &old2);
        store_batch_by_hash(&db, &new1);
        set_current_tip(&db, &old2);

        let manager = db.manager_with_cfg(cumulative_cfg());
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&new1, &mut chain, None)
            .expect("cumulative-PoR manager decision should succeed")
        {
            ForkAction::Reorg(plan) => {
                prop_assert_eq!(plan.detach_heights(), vec![2, 1]);
                prop_assert_eq!(plan.attach_heights(), vec![1]);
                prop_assert_eq!(plan.new_tip_hash, new1.block_hash);
            }
            _ => prop_assert!(false, "higher cumulative-PoR branch must reorg in cumulative mode"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(new1.block_hash)
        );

        prop_assert_eq!(chain.latest_block_height(), 1);
    }

    // 10/25
    #[test]
    fn test_010_apply_reorg_plan_noop_still_reloads_account_tree_to_existing_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_noop_reload");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x2C);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_canonical_block_projection(&db, &genesis);
        set_current_tip(&db, &genesis);

        let plan = plan_to_tip(&genesis, &genesis, &genesis, Vec::new(), Vec::new());

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("noop manager apply should reload to existing genesis tip");

        prop_assert_eq!(chain.latest_block_height(), 0);

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(genesis.block_hash)
        );
    }

    // 11/25
    #[test]
    fn test_011_apply_reorg_plan_noop_errors_when_account_reload_cannot_find_tip_block(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_noop_missing_reload_block");

        let phantom = genesis_block(seed, 0x2D);
        let plan = plan_to_tip(&phantom, &phantom, &phantom, Vec::new(), Vec::new());

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        prop_assert!(
            manager.apply_reorg_plan(&plan, &mut chain, None).is_err(),
            "manager apply must fail safely when AccountModelTree replay cannot load canonical block"
        );
    }

    // 12/25
    #[test]
    fn test_012_apply_reorg_plan_attach_only_remaps_batch_and_reloads_chain_to_new_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_attach_only");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x2E);
        let new1 = child_block(&genesis, seed.wrapping_add(1), 0x2F);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        store_batch_by_hash(&db, &new1);
        set_current_tip(&db, &genesis);

        let plan = plan_to_tip(
            &genesis,
            &new1,
            &genesis,
            Vec::new(),
            vec![step(&new1)],
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("attach-only manager apply should succeed");

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(new1.block_hash)
        );

        prop_assert!(
            db.batch_index()
                .get_canonical_batch_at_height(1)
                .expect("canonical batch lookup should succeed")
                .is_some(),
            "manager must remap attached block batch into canonical tx_batch projection"
        );

        prop_assert_eq!(chain.latest_block_height(), 1);
    }

    // 13/25
    #[test]
    fn test_013_apply_reorg_plan_errors_when_attached_block_is_missing_by_hash(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_missing_attach_block");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x30);
        let missing_hash = hash64(0x31, seed);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_canonical_block_projection(&db, &genesis);
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

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        prop_assert!(
            manager.apply_reorg_plan(&plan, &mut chain, None).is_err(),
            "manager apply must fail safely when ReFork cannot attach missing block"
        );
    }

    // 14/25
    #[test]
    fn test_014_apply_reorg_plan_errors_when_attached_block_height_mismatches_plan(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_height_mismatch");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x32);
        let child = child_block(&genesis, seed.wrapping_add(1), 0x33);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &child, 1, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        store_batch_by_hash(&db, &child);
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

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        prop_assert!(
            manager.apply_reorg_plan(&plan, &mut chain, None).is_err(),
            "manager apply must reject attach step whose planned height differs from block height"
        );
    }

    // 15/25
    #[test]
    fn test_015_apply_reorg_plan_fails_reload_when_attached_non_genesis_batch_is_missing(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("apply_missing_batch_reload");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x34);
        let child = child_block(&genesis, seed.wrapping_add(1), 0x35);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &child, 1, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        set_current_tip(&db, &genesis);

        let plan = plan_to_tip(
            &genesis,
            &child,
            &genesis,
            Vec::new(),
            vec![step(&child)],
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        prop_assert!(
            manager.apply_reorg_plan(&plan, &mut chain, None).is_err(),
            "best-effort batch remap can skip missing batch, but AccountModelTree replay must reject missing non-genesis batch"
        );

        prop_assert!(
            db.batch_index()
                .get_canonical_batch_at_height(1)
                .expect("canonical batch lookup should succeed")
                .is_none(),
            "missing batch-by-hash must not create canonical batch projection"
        );
    }

    // 16/25
    #[test]
    fn test_016_apply_reorg_plan_detach_only_to_genesis_deletes_old_height_mapping_and_marks_side_branch(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("detach_only_to_genesis");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x36);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x37);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        set_current_tip(&db, &old1);

        let plan = plan_to_tip(
            &old1,
            &genesis,
            &genesis,
            vec![step(&old1)],
            Vec::new(),
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("detach-only manager apply should succeed");

        prop_assert_eq!(
            db.chain_view().get_hash_at_height(1).expect("height lookup should succeed"),
            None,
            "detach-only reorg must delete canonical height mapping above common ancestor"
        );

        prop_assert_eq!(
            index.status_of(&old1.block_hash).expect("old1 status should read"),
            Some(ForkBlockStatus::SideBranch),
            "detached metadata must be marked SideBranch"
        );

        prop_assert_eq!(chain.latest_block_height(), 0);
    }

    // 17/25
    #[test]
    fn test_017_apply_reorg_plan_marks_attached_metadata_canonical(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("attach_marks_canonical");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x38);
        let new1 = child_block(&genesis, seed.wrapping_add(1), 0x39);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::SideBranch);

        store_canonical_block_projection(&db, &genesis);
        store_batch_by_hash(&db, &new1);
        set_current_tip(&db, &genesis);

        let plan = plan_to_tip(
            &genesis,
            &new1,
            &genesis,
            Vec::new(),
            vec![step(&new1)],
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("attach manager apply should succeed");

        prop_assert_eq!(
            index.status_of(&new1.block_hash).expect("new1 status should read"),
            Some(ForkBlockStatus::Canonical),
            "attached metadata must be marked Canonical"
        );
    }

    // 18/25
    #[test]
    fn test_018_apply_reorg_plan_rewrites_legacy_active_block_projection_for_attached_heights(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("rewrite_legacy_projection");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x3A);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x3B);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x3C);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_batch_by_hash(&db, &new1);
        set_current_tip(&db, &old1);

        let plan = plan_to_tip(
            &old1,
            &new1,
            &genesis,
            vec![step(&old1)],
            vec![step(&new1)],
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("projection rewrite apply should succeed");

        let legacy_block = db
            .manager()
            .get_block_by_index(1)
            .expect("legacy block lookup should succeed")
            .expect("legacy block at attached height must exist");

        prop_assert_eq!(
            &legacy_block,
            &new1,
            "manager apply must rewrite canonical active block projection"
        );
    }

    // 19/25
    #[test]
    fn test_019_apply_reorg_plan_remaps_multiple_attached_batches_before_account_reload(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("multiple_batch_remap");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x3D);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x3E);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x3F);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x40);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::Validated);
        store_block_and_meta(&index, &new2, 2, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_batch_by_hash(&db, &new1);
        store_batch_by_hash(&db, &new2);
        set_current_tip(&db, &old1);

        let expected_h1 = db.batch_index()
            .get_batch_by_block_hash(&new1.block_hash)
            .expect("new1 batch-by-hash lookup should succeed")
            .expect("new1 batch-by-hash should exist");

        let expected_h2 = db.batch_index()
            .get_batch_by_block_hash(&new2.block_hash)
            .expect("new2 batch-by-hash lookup should succeed")
            .expect("new2 batch-by-hash should exist");

        let plan = plan_to_tip(
            &old1,
            &new2,
            &genesis,
            vec![step(&old1)],
            vec![step(&new1), step(&new2)],
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("multi-attach manager apply should succeed");

        prop_assert_eq!(
            db.batch_index().get_canonical_batch_at_height(1).expect("h1 batch lookup should succeed"),
            Some(expected_h1),
            "attached h1 batch must be remapped from batch-by-hash"
        );

        prop_assert_eq!(
            db.batch_index().get_canonical_batch_at_height(2).expect("h2 batch lookup should succeed"),
            Some(expected_h2),
            "attached h2 batch must be remapped from batch-by-hash"
        );

        prop_assert_eq!(chain.latest_block_height(), 2);
    }

    // 20/25
    #[test]
    fn test_020_apply_reorg_plan_preserves_detached_legacy_block_in_block_hash_index(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("preserve_detached_hash");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x41);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x42);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);

        store_legacy_block_by_height(db.manager().as_ref(), &old1);

        index
            .put_meta(
                &old1.block_hash,
                &meta_for_block(&old1, 1, ForkBlockStatus::Canonical),
            )
            .expect("old1 metadata should store without block-by-hash");

        store_canonical_block_projection(&db, &genesis);

        db.chain_view()
            .set_hash_at_height(1, &old1.block_hash)
            .expect("old1 canonical mapping should set");

        set_current_tip(&db, &old1);

        let plan = plan_to_tip(
            &old1,
            &genesis,
            &genesis,
            vec![step(&old1)],
            Vec::new(),
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("detach should preserve legacy block in hash index");

        prop_assert!(
            index.has_block(&old1.block_hash),
            "detached legacy active block must be indexed by hash before removal from canonical projection"
        );

        let fetched = index.get_block(&old1.block_hash)
            .expect("detached hash lookup should succeed")
            .expect("detached block should exist by hash");

        prop_assert_eq!(&fetched, &old1);
    }

    // 21/25
    #[test]
    fn test_021_handle_new_block_reorg_failure_from_missing_batch_returns_error_after_canonical_db_switch_attempt(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("handle_missing_batch_error");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x43);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x44);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x45);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x46);

        store_block_and_meta(&index, &genesis, 0, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &old1, 1, ForkBlockStatus::Canonical);
        store_block_and_meta(&index, &new1, 1, ForkBlockStatus::SideBranch);
        store_block_and_meta(&index, &new2, 2, ForkBlockStatus::Validated);

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);

        set_current_tip(&db, &old1);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        prop_assert!(
            manager.handle_new_block(&new2, &mut chain, None).is_err(),
            "handle_new_block must surface AccountModelTree replay failure when attached branch batch data is missing"
        );

        prop_assert_eq!(
            db.chain_view()
                .get_tip_hash()
                .expect("tip hash lookup should succeed"),
            Some(new2.block_hash),
            "ReFork canonical DB switch is attempted before AccountModelTree replay reports the missing batch"
        );

        prop_assert_eq!(
            db.chain_view()
                .get_hash_at_height(1)
                .expect("height 1 canonical hash lookup should succeed"),
            Some(new1.block_hash),
            "canonical height 1 should have switched to the attached branch before replay failure"
        );

        prop_assert_eq!(
            db.chain_view()
                .get_hash_at_height(2)
                .expect("height 2 canonical hash lookup should succeed"),
            Some(new2.block_hash),
            "canonical height 2 should have switched to the attached tip before replay failure"
        );

        prop_assert!(
            db.batch_index()
                .get_canonical_batch_at_height(2)
                .expect("canonical batch lookup should succeed")
                .is_none(),
            "missing batch-by-hash for attached height 2 must not create a canonical batch projection"
        );

        prop_assert_eq!(
            chain.latest_block_height(),
            0,
            "AccountModelTree must not successfully reload to the failed new tip"
        );
    }

    // 22/25
    #[test]
    fn test_022_handle_new_block_refuses_reorg_when_depth_limit_is_too_small_and_keeps_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("depth_limit_keep_tip");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x46);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x47);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x48);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x49);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&new1, 1, ForkBlockStatus::SideBranch),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_batch_by_hash(&db, &new1);
        store_batch_by_hash(&db, &new2);
        set_current_tip(&db, &old1);

        let manager = db.manager_with_cfg(ReForkConfig {
            max_reorg_depth: 0,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        });

        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&new2, &mut chain, None)
            .expect("depth-limited decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "depth-limited reorg must be refused"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(old1.block_hash)
        );
    }

    // 23/25
    #[test]
    fn test_023_handle_new_block_refuses_fork_without_common_ancestor_and_keeps_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("no_common_ancestor_manager");
        let index = db.block_index();

        let old_root = genesis_block(seed, 0x4A);
        let old1 = child_block(&old_root, seed.wrapping_add(1), 0x4B);

        let new_root = genesis_block(seed.wrapping_add(100), 0x4C);
        let new1 = child_block(&new_root, seed.wrapping_add(101), 0x4D);
        let new2 = child_block(&new1, seed.wrapping_add(102), 0x4E);

        for (block, score, status) in [
            (&old_root, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&new_root, 0, ForkBlockStatus::SideBranch),
            (&new1, 1, ForkBlockStatus::SideBranch),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        store_canonical_block_projection(&db, &old_root);
        store_canonical_block_projection(&db, &old1);
        store_batch_by_hash(&db, &new1);
        store_batch_by_hash(&db, &new2);
        set_current_tip(&db, &old1);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        match manager
            .handle_new_block(&new2, &mut chain, None)
            .expect("no-common-ancestor decision should succeed")
        {
            ForkAction::Stay => {}
            _ => prop_assert!(false, "fork without common ancestor must be refused"),
        }

        prop_assert_eq!(
            db.chain_view().get_tip_hash().expect("tip hash should read"),
            Some(old1.block_hash)
        );
    }

    // 24/25
    #[test]
    fn test_024_apply_reorg_plan_keeps_heights_below_common_ancestor_unchanged(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("preserve_below_common");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x4F);
        let common1 = child_block(&genesis, seed.wrapping_add(1), 0x50);
        let old2 = child_block(&common1, seed.wrapping_add(2), 0x51);
        let new2 = child_block(&common1, seed.wrapping_add(3), 0x52);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&common1, 1, ForkBlockStatus::Canonical),
            (&old2, 2, ForkBlockStatus::Canonical),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &common1);
        store_canonical_block_projection(&db, &old2);
        store_batch_by_hash(&db, &new2);
        set_current_tip(&db, &old2);

        let plan = plan_to_tip(
            &old2,
            &new2,
            &common1,
            vec![step(&old2)],
            vec![step(&new2)],
        );

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        manager
            .apply_reorg_plan(&plan, &mut chain, None)
            .expect("same-depth switch above common ancestor should succeed");

        prop_assert_eq!(
            db.chain_view().get_hash_at_height(0).expect("h0 lookup should succeed"),
            Some(genesis.block_hash),
            "height below common ancestor must remain unchanged"
        );

        prop_assert_eq!(
            db.chain_view().get_hash_at_height(1).expect("h1 lookup should succeed"),
            Some(common1.block_hash),
            "common ancestor height must remain unchanged"
        );

        prop_assert_eq!(
            db.chain_view().get_hash_at_height(2).expect("h2 lookup should succeed"),
            Some(new2.block_hash),
            "height above common ancestor must be replaced"
        );

        prop_assert_eq!(chain.latest_block_height(), 2);
    }

    // 25/25
    #[test]
    fn test_025_handle_new_block_reorg_returns_plan_clone_matching_persisted_new_tip(
        seed in any::<u64>(),
    ) {
        let db = new_test_db("returned_plan_matches_persisted_tip");
        let index = db.block_index();

        let genesis = genesis_block(seed, 0x53);
        let old1 = child_block(&genesis, seed.wrapping_add(1), 0x54);
        let new1 = child_block(&genesis, seed.wrapping_add(2), 0x55);
        let new2 = child_block(&new1, seed.wrapping_add(3), 0x56);

        for (block, score, status) in [
            (&genesis, 0, ForkBlockStatus::Canonical),
            (&old1, 1, ForkBlockStatus::Canonical),
            (&new1, 1, ForkBlockStatus::SideBranch),
            (&new2, 2, ForkBlockStatus::Validated),
        ] {
            store_block_and_meta(&index, block, score, status);
        }

        store_canonical_block_projection(&db, &genesis);
        store_canonical_block_projection(&db, &old1);
        store_batch_by_hash(&db, &new1);
        store_batch_by_hash(&db, &new2);
        set_current_tip(&db, &old1);

        let manager = db.manager_default();
        let mut chain = account_tree(&db);

        let returned_plan = match manager
            .handle_new_block(&new2, &mut chain, None)
            .expect("manager should apply reorg and return cloned plan")
        {
            ForkAction::Reorg(plan) => plan,
            _ => {
                prop_assert!(false, "taller branch must return ForkAction::Reorg");
                return Ok(());
            }
        };

        let tip_hash = db.chain_view()
            .get_tip_hash()
            .expect("tip hash should read")
            .expect("tip hash should exist");

        let tip_height = db.chain_view()
            .get_tip_height()
            .expect("tip height should read")
            .expect("tip height should exist");

        prop_assert_eq!(
            returned_plan.new_tip_hash,
            tip_hash,
            "returned cloned plan must match persisted canonical tip hash"
        );

        prop_assert_eq!(
            returned_plan.new_tip_height,
            tip_height,
            "returned cloned plan must match persisted canonical tip height"
        );

        prop_assert_eq!(
            returned_plan.attach_heights(),
            vec![1, 2],
            "returned cloned plan must preserve attach ordering"
        );

        prop_assert_eq!(chain.latest_block_height(), 2);
    }
}
