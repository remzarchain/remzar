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
use remzar::storage::rocksdb_006_manager_ext::ForkBlockStatus;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), ErrorDetection>;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestNode {
    manager: ReorgManager,
    block_index: ReorgBlockIndex,
    chain_view: ReorgChainView,
    batch_index: ReorgBatchIndex,
    db: Arc<RockDBManager>,
    chain: AccountModelTree,
}

fn storage_error(message: String) -> ErrorDetection {
    ErrorDetection::StorageError { message }
}

fn database_error(details: String) -> ErrorDetection {
    ErrorDetection::DatabaseError { details }
}

fn required<T>(value: Option<T>, resource: &str) -> Result<T, ErrorDetection> {
    value.ok_or_else(|| ErrorDetection::NotFound {
        resource: resource.to_owned(),
    })
}

fn path_to_string(path: &Path) -> Result<String, ErrorDetection> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| database_error(format!("test path is not valid UTF-8: {}", path.display())))
}

fn fresh_node(label: &str, cfg: ReForkConfig) -> Result<TestNode, ErrorDetection> {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "remzar_reorg_006_manager_{label}_{}_{}",
        std::process::id(),
        id
    ));

    if base.exists() {
        std::fs::remove_dir_all(&base).map_err(|e| {
            storage_error(format!(
                "failed to clear stale test directory {}: {e}",
                base.display()
            ))
        })?;
    }

    let blockchain_path = base.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let data_dir = path_to_string(&base)?;
    let db_path = path_to_string(&blockchain_path)?;

    let opts = NodeOpts {
        identity_file: path_to_string(&base.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "error".to_owned(),
        data_dir,
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder: false,
    };

    let db = Arc::new(RockDBManager::new_blockchain(&opts, &db_path)?);
    let manager = ReorgManager::new(Arc::clone(&db), cfg);
    let block_index = ReorgBlockIndex::new(Arc::clone(&db));
    let chain_view = ReorgChainView::new(Arc::clone(&db));
    let batch_index = ReorgBatchIndex::new(Arc::clone(&db));
    let chain = AccountModelTree::with_manager((*db).clone());

    Ok(TestNode {
        manager,
        block_index,
        chain_view,
        batch_index,
        db,
        chain,
    })
}

fn default_node(label: &str) -> Result<TestNode, ErrorDetection> {
    fresh_node(label, ReForkConfig::default())
}

fn deterministic_hash(seed: u64) -> BlockHash {
    std::array::from_fn(|idx| {
        let idx_u64 = match u64::try_from(idx) {
            Ok(v) => v,
            Err(_) => 0,
        };
        let value = seed
            .wrapping_mul(37)
            .wrapping_add(idx_u64.wrapping_mul(17))
            .wrapping_add(11);
        let bytes = value.to_le_bytes();
        match bytes.first() {
            Some(byte) => *byte,
            None => 0,
        }
    })
}

fn timestamp_at(height: u64) -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS
        .saturating_add(1_000)
        .saturating_add(height.saturating_mul(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS))
}

fn make_metadata(height: u64, parent_hash: BlockHash, tag: u64) -> BlockMetadata {
    let merkle_seed = 10_000u64
        .saturating_add(height.saturating_mul(1_000))
        .saturating_add(tag);

    let merkle_root = deterministic_hash(merkle_seed);
    let guardian_signature = if height == 0 {
        [0u8; ml_dsa_65::SIG_LEN]
    } else {
        [7u8; ml_dsa_65::SIG_LEN]
    };

    BlockMetadata::new(
        height,
        timestamp_at(height),
        parent_hash,
        merkle_root,
        guardian_signature,
        None,
        512,
    )
}

fn make_block(height: u64, parent_hash: BlockHash, tag: u64) -> Result<Block, ErrorDetection> {
    let metadata = make_metadata(height, parent_hash, tag);
    let batch_key = Some(format!("tx_batch_{height:010}"));

    Block::new(
        metadata,
        batch_key,
        GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        0,
    )
}

fn make_batch_bytes(height: u64, salt: u64) -> Result<Vec<u8>, ErrorDetection> {
    let batch = TransactionBatch {
        index: height,
        timestamp: timestamp_at(height).saturating_add(salt),
        transactions: Vec::new(),
        guardian_signature: None,
    };

    batch.serialize()
}

fn make_linear_chain(len: u64, branch_tag: u64) -> Result<Vec<Block>, ErrorDetection> {
    let mut blocks = Vec::new();
    let mut parent_hash = [0u8; 64];

    for height in 0..len {
        let tag = branch_tag.saturating_add(height);
        let block = make_block(height, parent_hash, tag)?;
        parent_hash = block.block_hash;
        blocks.push(block);
    }

    Ok(blocks)
}

fn make_fork_from_parent(
    parent: &Block,
    extra_len: u64,
    branch_tag: u64,
) -> Result<Vec<Block>, ErrorDetection> {
    let mut blocks = Vec::new();
    let mut parent_hash = parent.block_hash;
    let start_height = parent.metadata.index.saturating_add(1);

    for offset in 0..extra_len {
        let height = start_height.saturating_add(offset);
        let tag = branch_tag.saturating_add(offset);
        let block = make_block(height, parent_hash, tag)?;
        parent_hash = block.block_hash;
        blocks.push(block);
    }

    Ok(blocks)
}

fn block_at(blocks: &[Block], pos: usize) -> Result<&Block, ErrorDetection> {
    blocks.get(pos).ok_or_else(|| ErrorDetection::NotFound {
        resource: format!("block at test vector position {pos}"),
    })
}

fn last_block(blocks: &[Block]) -> Result<&Block, ErrorDetection> {
    blocks.last().ok_or_else(|| ErrorDetection::NotFound {
        resource: "last block in test chain".to_owned(),
    })
}

fn ingest_block(
    node: &TestNode,
    block: &Block,
    status: ForkBlockStatus,
    score: u128,
    batch_salt: u64,
) -> TestResult {
    let meta = node.block_index.make_scored_meta(block, score, status);
    let batch = make_batch_bytes(block.metadata.index, batch_salt)?;

    node.block_index
        .ingest_validated_block(block, meta, Some(batch.as_slice()))?;

    if matches!(status, ForkBlockStatus::Canonical) {
        node.db
            .store_latest_block(&block.serialize_for_storage()?, block.metadata.index)?;
        node.chain_view
            .set_hash_at_height(block.metadata.index, &block.block_hash)?;
        node.batch_index
            .set_canonical_batch_at_height(block.metadata.index, &batch)?;
        node.block_index.mark_canonical(&block.block_hash)?;
    }

    Ok(())
}

fn ingest_canonical_chain(node: &TestNode, blocks: &[Block]) -> TestResult {
    for block in blocks {
        ingest_block(
            node,
            block,
            ForkBlockStatus::Canonical,
            u128::from(block.metadata.index),
            block.metadata.index,
        )?;
    }

    let tip = last_block(blocks)?;
    node.chain_view
        .set_tip(&tip.block_hash, tip.metadata.index)?;
    Ok(())
}

fn ingest_side_branch(node: &TestNode, blocks: &[Block], base_score: u128) -> TestResult {
    for block in blocks {
        ingest_block(
            node,
            block,
            ForkBlockStatus::SideBranch,
            base_score.saturating_add(u128::from(block.metadata.index)),
            base_score.saturating_add(u128::from(block.metadata.index)) as u64,
        )?;
        node.block_index.mark_side_branch(&block.block_hash)?;
    }

    Ok(())
}

fn reorg_step(block: &Block) -> ReorgStep {
    ReorgStep {
        height: block.metadata.index,
        hash: block.block_hash,
    }
}

fn make_plan(
    old_tip: &Block,
    new_tip: &Block,
    ancestor: &Block,
    detach: Vec<ReorgStep>,
    attach: Vec<ReorgStep>,
) -> ReorgPlan {
    ReorgPlan {
        old_tip_height: old_tip.metadata.index,
        old_tip_hash: old_tip.block_hash,
        new_tip_height: new_tip.metadata.index,
        new_tip_hash: new_tip.block_hash,
        common_ancestor_height: ancestor.metadata.index,
        common_ancestor_hash: ancestor.block_hash,
        detach,
        attach,
    }
}

fn noop_plan(hash: BlockHash) -> ReorgPlan {
    ReorgPlan {
        old_tip_height: 0,
        old_tip_hash: hash,
        new_tip_height: 0,
        new_tip_hash: hash,
        common_ancestor_height: 0,
        common_ancestor_hash: hash,
        detach: Vec::new(),
        attach: Vec::new(),
    }
}

fn assert_stay(action: ForkAction) {
    assert!(matches!(action, ForkAction::Stay));
}

fn assert_reorg(action: ForkAction) -> ReorgPlan {
    match action {
        ForkAction::Reorg(plan) => plan,
        ForkAction::Stay | ForkAction::NeedMoreData { .. } => {
            panic!("expected ForkAction::Reorg")
        }
    }
}

fn assert_need_more_data(action: ForkAction, expected_missing_hash: BlockHash) {
    match action {
        ForkAction::NeedMoreData { missing_hash, .. } => {
            assert_eq!(missing_hash, expected_missing_hash);
        }
        ForkAction::Stay | ForkAction::Reorg(_) => {
            panic!("expected ForkAction::NeedMoreData")
        }
    }
}

fn assert_not_found<T>(result: Result<T, ErrorDetection>) {
    assert!(matches!(result, Err(ErrorDetection::NotFound { .. })));
}

fn assert_validation_error<T>(result: Result<T, ErrorDetection>) {
    assert!(matches!(
        result,
        Err(ErrorDetection::ValidationError { .. })
    ));
}

fn assert_blockchain_error<T>(result: Result<T, ErrorDetection>) {
    assert!(matches!(
        result,
        Err(ErrorDetection::BlockchainError { .. })
    ));
}

fn find_ordered_equal_height_pair(
    parent: &Block,
    seed_base: u64,
) -> Result<(Block, Block), ErrorDetection> {
    let height = parent.metadata.index.saturating_add(1);
    let first = make_block(height, parent.block_hash, seed_base)?;

    let mut lower = first.clone();
    let mut higher = first;

    for offset in 1u64..4096u64 {
        let block = make_block(height, parent.block_hash, seed_base.saturating_add(offset))?;

        if block.block_hash < lower.block_hash {
            lower = block.clone();
        }

        if block.block_hash > higher.block_hash {
            higher = block;
        }

        if lower.block_hash < higher.block_hash {
            return Ok((lower, higher));
        }
    }

    Err(storage_error(
        "could not find ordered equal-height block pair".to_owned(),
    ))
}

// ─────────────────────────────────────────────────────────────
// 1–20: constructors, basic vectors, and no-tip behavior
// ─────────────────────────────────────────────────────────────

#[test]
fn test_001_config_default_max_reorg_depth_vector() {
    let cfg = ReForkConfig::default();
    assert_eq!(cfg.max_reorg_depth, 64);
}

#[test]
fn test_002_config_default_equal_height_disabled_vector() {
    let cfg = ReForkConfig::default();
    assert!(!cfg.allow_equal_height_reorg);
}

#[test]
fn test_003_config_default_por_disabled_vector() {
    let cfg = ReForkConfig::default();
    assert!(!cfg.prefer_cumulative_por);
}

#[test]
fn test_004_custom_config_fields_preserved_vector() {
    let cfg = ReForkConfig {
        max_reorg_depth: 7,
        allow_equal_height_reorg: true,
        prefer_cumulative_por: true,
    };

    assert_eq!(cfg.max_reorg_depth, 7);
    assert!(cfg.allow_equal_height_reorg);
    assert!(cfg.prefer_cumulative_por);
}

#[test]
fn test_005_manager_new_constructs_vector() -> TestResult {
    let _node = default_node("test_005_manager_new_constructs_vector")?;
    Ok(())
}

#[test]
fn test_006_manager_mainnet_default_constructs_vector() -> TestResult {
    let node = default_node("test_006_manager_mainnet_default_constructs_vector")?;
    let _manager = ReorgManager::mainnet_default(Arc::clone(&node.db));
    Ok(())
}

#[test]
fn test_007_fork_engine_reference_is_usable_vector() -> TestResult {
    let node = default_node("test_007_fork_engine_reference_is_usable_vector")?;
    let block = make_block(0, [0u8; 64], 700)?;

    assert_not_found(node.manager.fork_engine().on_new_block(&block));
    Ok(())
}

#[test]
fn test_008_handle_new_block_without_tip_returns_not_found_edge() -> TestResult {
    let mut node = default_node("test_008_handle_new_block_without_tip_returns_not_found_edge")?;
    let block = make_block(0, [0u8; 64], 800)?;

    assert_not_found(node.manager.handle_new_block(&block, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_009_apply_noop_plan_on_empty_db_returns_validation_error_vector() -> TestResult {
    let mut node =
        default_node("test_009_apply_noop_plan_on_empty_db_returns_validation_error_vector")?;
    let plan = noop_plan(deterministic_hash(9));

    assert_validation_error(node.manager.apply_reorg_plan(&plan, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_010_apply_noop_plan_on_empty_db_does_not_create_tip_vector() -> TestResult {
    let mut node = default_node("test_010_apply_noop_plan_on_empty_db_does_not_create_tip_vector")?;
    let plan = noop_plan(deterministic_hash(10));

    assert_validation_error(node.manager.apply_reorg_plan(&plan, &mut node.chain, None));

    assert!(node.chain_view.get_tip()?.is_none());
    Ok(())
}

#[test]
fn test_011_seed_canonical_genesis_sets_tip_vector() -> TestResult {
    let node = default_node("test_011_seed_canonical_genesis_sets_tip_vector")?;
    let chain = make_linear_chain(1, 1100)?;

    ingest_canonical_chain(&node, &chain)?;

    let genesis = block_at(&chain, 0)?;
    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "tip hash")?,
        genesis.block_hash
    );
    assert_eq!(
        required(node.chain_view.get_tip_height()?, "tip height")?,
        0
    );
    Ok(())
}

#[test]
fn test_012_seed_canonical_two_blocks_sets_tip_vector() -> TestResult {
    let node = default_node("test_012_seed_canonical_two_blocks_sets_tip_vector")?;
    let chain = make_linear_chain(2, 1200)?;

    ingest_canonical_chain(&node, &chain)?;

    let tip = last_block(&chain)?;
    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "tip hash")?,
        tip.block_hash
    );
    assert_eq!(
        required(node.chain_view.get_tip_height()?, "tip height")?,
        1
    );
    Ok(())
}

#[test]
fn test_013_chain_reload_empty_genesis_batch_succeeds_vector() -> TestResult {
    let mut node = default_node("test_013_chain_reload_empty_genesis_batch_succeeds_vector")?;
    let chain = make_linear_chain(1, 1300)?;

    ingest_canonical_chain(&node, &chain)?;
    node.chain.reload_from_db_to_height(0)?;

    assert_eq!(node.chain.latest_block_height(), 0);
    Ok(())
}

#[test]
fn test_014_chain_reload_two_empty_batches_succeeds_vector() -> TestResult {
    let mut node = default_node("test_014_chain_reload_two_empty_batches_succeeds_vector")?;
    let chain = make_linear_chain(2, 1400)?;

    ingest_canonical_chain(&node, &chain)?;
    node.chain.reload_from_db_to_height(1)?;

    assert_eq!(node.chain.latest_block_height(), 1);
    Ok(())
}

#[test]
fn test_015_chain_reload_missing_height_errors_vector() -> TestResult {
    let mut node = default_node("test_015_chain_reload_missing_height_errors_vector")?;
    let chain = make_linear_chain(1, 1500)?;

    ingest_canonical_chain(&node, &chain)?;

    assert_validation_error(node.chain.reload_from_db_to_height(1));
    Ok(())
}

#[test]
fn test_016_chain_reload_missing_non_genesis_batch_errors_vector() -> TestResult {
    let mut node = default_node("test_016_chain_reload_missing_non_genesis_batch_errors_vector")?;
    let chain = make_linear_chain(2, 1600)?;

    for block in &chain {
        node.block_index.put_block(block)?;
        node.db
            .store_latest_block(&block.serialize_for_storage()?, block.metadata.index)?;
        node.chain_view
            .set_hash_at_height(block.metadata.index, &block.block_hash)?;
    }

    assert_validation_error(node.chain.reload_from_db_to_height(1));
    Ok(())
}

#[test]
fn test_017_manager_apply_noop_plan_reloads_to_plan_new_tip_height_vector() -> TestResult {
    let mut node =
        default_node("test_017_manager_apply_noop_plan_reloads_to_plan_new_tip_height_vector")?;
    let chain = make_linear_chain(2, 1700)?;

    ingest_canonical_chain(&node, &chain)?;
    node.chain.reload_from_db_to_height(1)?;

    let plan = noop_plan(last_block(&chain)?.block_hash);
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.latest_block_height(), 0);
    assert_eq!(
        required(node.chain_view.get_tip_height()?, "tip height")?,
        1
    );
    Ok(())
}

#[test]
fn test_018_mainnet_default_fork_engine_on_missing_tip_returns_not_found_vector() -> TestResult {
    let node = default_node(
        "test_018_mainnet_default_fork_engine_on_missing_tip_returns_not_found_vector",
    )?;
    let manager = ReorgManager::mainnet_default(Arc::clone(&node.db));
    let block = make_block(0, [0u8; 64], 1800)?;

    assert_not_found(manager.fork_engine().on_new_block(&block));
    Ok(())
}

#[test]
fn test_019_custom_por_manager_constructs_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    };
    let _node = fresh_node("test_019_custom_por_manager_constructs_vector", cfg)?;
    Ok(())
}

#[test]
fn test_020_custom_equal_height_manager_constructs_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: true,
        prefer_cumulative_por: false,
    };
    let _node = fresh_node(
        "test_020_custom_equal_height_manager_constructs_vector",
        cfg,
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 21–40: handle_new_block behavior
// ─────────────────────────────────────────────────────────────

#[test]
fn test_021_handle_direct_extension_returns_stay_vector() -> TestResult {
    let mut node = default_node("test_021_handle_direct_extension_returns_stay_vector")?;
    let chain = make_linear_chain(2, 2100)?;
    ingest_canonical_chain(&node, &chain)?;

    let tip = last_block(&chain)?;
    let next = make_block(2, tip.block_hash, 2102)?;
    ingest_block(&node, &next, ForkBlockStatus::Validated, 2, 2)?;

    assert_stay(
        node.manager
            .handle_new_block(&next, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_022_handle_shorter_side_branch_returns_stay_vector() -> TestResult {
    let mut node = default_node("test_022_handle_shorter_side_branch_returns_stay_vector")?;
    let canonical = make_linear_chain(4, 2200)?;
    ingest_canonical_chain(&node, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let side = make_block(2, parent.block_hash, 2210)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 2, 20)?;

    assert_stay(
        node.manager
            .handle_new_block(&side, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_023_handle_equal_height_side_branch_stays_by_default_vector() -> TestResult {
    let mut node =
        default_node("test_023_handle_equal_height_side_branch_stays_by_default_vector")?;
    let canonical = make_linear_chain(3, 2300)?;
    ingest_canonical_chain(&node, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let side = make_block(2, parent.block_hash, 2310)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 2, 23)?;

    assert_stay(
        node.manager
            .handle_new_block(&side, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_024_handle_longer_side_branch_reorgs_and_applies_vector() -> TestResult {
    let mut node = default_node("test_024_handle_longer_side_branch_reorgs_and_applies_vector")?;
    let canonical = make_linear_chain(3, 2400)?;
    ingest_canonical_chain(&node, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let branch = make_fork_from_parent(parent, 3, 2410)?;
    ingest_side_branch(&node, &branch, 100)?;

    let new_tip = last_block(&branch)?;
    let plan = assert_reorg(
        node.manager
            .handle_new_block(new_tip, &mut node.chain, None)?,
    );

    assert_eq!(plan.new_tip_hash, new_tip.block_hash);
    assert_eq!(
        required(
            node.chain_view.get_tip_hash()?,
            "tip hash after manager reorg"
        )?,
        new_tip.block_hash
    );
    assert_eq!(node.chain.latest_block_height(), 4);
    Ok(())
}

#[test]
fn test_025_handle_reorg_from_genesis_applies_vector() -> TestResult {
    let mut node = default_node("test_025_handle_reorg_from_genesis_applies_vector")?;
    let canonical = make_linear_chain(2, 2500)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 2510)?;
    ingest_side_branch(&node, &branch, 100)?;

    let tip = last_block(&branch)?;
    let plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);

    assert_eq!(plan.common_ancestor_height, 0);
    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "new tip")?,
        tip.block_hash
    );
    Ok(())
}

#[test]
fn test_026_handle_missing_new_tip_meta_need_more_data_vector() -> TestResult {
    let mut node = default_node("test_026_handle_missing_new_tip_meta_need_more_data_vector")?;
    let canonical = make_linear_chain(2, 2600)?;
    ingest_canonical_chain(&node, &canonical)?;

    let parent = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(parent, 3, 2610)?;
    for block in &branch {
        node.block_index.put_block(block)?;
    }

    let tip = last_block(&branch)?;
    assert_need_more_data(
        node.manager.handle_new_block(tip, &mut node.chain, None)?,
        tip.block_hash,
    );
    Ok(())
}

#[test]
fn test_027_handle_missing_parent_block_need_more_data_vector() -> TestResult {
    let mut node = default_node("test_027_handle_missing_parent_block_need_more_data_vector")?;
    let canonical = make_linear_chain(2, 2700)?;
    ingest_canonical_chain(&node, &canonical)?;

    let missing_parent = deterministic_hash(2701);
    let child = make_block(3, missing_parent, 2710)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 100, 27)?;

    assert_need_more_data(
        node.manager
            .handle_new_block(&child, &mut node.chain, None)?,
        missing_parent,
    );
    Ok(())
}

#[test]
fn test_028_handle_missing_parent_meta_need_more_data_vector() -> TestResult {
    let mut node = default_node("test_028_handle_missing_parent_meta_need_more_data_vector")?;
    let canonical = make_linear_chain(2, 2800)?;
    ingest_canonical_chain(&node, &canonical)?;

    let parent = make_block(2, last_block(&canonical)?.block_hash, 2810)?;
    let child = make_block(3, parent.block_hash, 2811)?;
    node.block_index.put_block(&parent)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 100, 28)?;

    assert_need_more_data(
        node.manager
            .handle_new_block(&child, &mut node.chain, None)?,
        parent.block_hash,
    );
    Ok(())
}

#[test]
fn test_029_handle_cumulative_por_mode_reorgs_lower_height_high_score_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    };
    let mut node = fresh_node(
        "test_029_handle_cumulative_por_mode_reorgs_lower_height_high_score_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(4, 2900)?;
    ingest_canonical_chain(&node, &canonical)?;

    let old_tip = last_block(&canonical)?;
    let old_meta = node
        .block_index
        .make_scored_meta(old_tip, 1, ForkBlockStatus::Canonical);
    node.block_index.put_meta(&old_tip.block_hash, &old_meta)?;

    let parent = block_at(&canonical, 1)?;
    let side = make_block(2, parent.block_hash, 2910)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 999, 29)?;

    let plan = assert_reorg(
        node.manager
            .handle_new_block(&side, &mut node.chain, None)?,
    );
    assert_eq!(plan.new_tip_hash, side.block_hash);
    Ok(())
}

#[test]
fn test_030_handle_height_only_ignores_higher_por_vector() -> TestResult {
    let mut node = default_node("test_030_handle_height_only_ignores_higher_por_vector")?;
    let canonical = make_linear_chain(4, 3000)?;
    ingest_canonical_chain(&node, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let side = make_block(2, parent.block_hash, 3010)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 999, 30)?;

    assert_stay(
        node.manager
            .handle_new_block(&side, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_031_handle_equal_height_lower_hash_reorg_when_enabled_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: true,
        prefer_cumulative_por: false,
    };
    let mut node = fresh_node(
        "test_031_handle_equal_height_lower_hash_reorg_when_enabled_vector",
        cfg,
    )?;

    let genesis = make_block(0, [0u8; 64], 3100)?;
    let parent = make_block(1, genesis.block_hash, 3101)?;
    let (lower, higher) = find_ordered_equal_height_pair(&parent, 3110)?;

    let canonical = vec![genesis, parent, higher.clone()];
    ingest_canonical_chain(&node, &canonical)?;
    ingest_block(&node, &lower, ForkBlockStatus::SideBranch, 2, 31)?;

    let plan = assert_reorg(
        node.manager
            .handle_new_block(&lower, &mut node.chain, None)?,
    );
    assert_eq!(plan.new_tip_hash, lower.block_hash);
    Ok(())
}

#[test]
fn test_032_handle_equal_height_higher_hash_stays_when_lower_tiebreak_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: true,
        prefer_cumulative_por: false,
    };
    let mut node = fresh_node(
        "test_032_handle_equal_height_higher_hash_stays_when_lower_tiebreak_vector",
        cfg,
    )?;

    let genesis = make_block(0, [0u8; 64], 3200)?;
    let parent = make_block(1, genesis.block_hash, 3201)?;
    let (lower, higher) = find_ordered_equal_height_pair(&parent, 3210)?;

    let canonical = vec![genesis, parent, lower.clone()];
    ingest_canonical_chain(&node, &canonical)?;
    ingest_block(&node, &higher, ForkBlockStatus::SideBranch, 2, 32)?;

    assert_stay(
        node.manager
            .handle_new_block(&higher, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_033_handle_reorg_missing_side_batch_fails_during_reload_vector() -> TestResult {
    let mut node =
        default_node("test_033_handle_reorg_missing_side_batch_fails_during_reload_vector")?;
    let canonical = make_linear_chain(2, 3300)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 3310)?;
    for block in &branch {
        let meta = node
            .block_index
            .make_scored_meta(block, 100, ForkBlockStatus::SideBranch);
        node.block_index.put_block_and_meta(block, &meta)?;
    }

    let tip = last_block(&branch)?;
    assert_validation_error(node.manager.handle_new_block(tip, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_034_handle_reorg_updates_canonical_batch_projection_vector() -> TestResult {
    let mut node = default_node("test_034_handle_reorg_updates_canonical_batch_projection_vector")?;
    let canonical = make_linear_chain(2, 3400)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 3410)?;
    ingest_side_branch(&node, &branch, 100)?;

    let tip = last_block(&branch)?;
    let _plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);

    assert!(node.batch_index.get_canonical_batch_at_height(3)?.is_some());
    Ok(())
}

#[test]
fn test_035_handle_reorg_old_tip_becomes_side_branch_vector() -> TestResult {
    let mut node = default_node("test_035_handle_reorg_old_tip_becomes_side_branch_vector")?;
    let canonical = make_linear_chain(3, 3500)?;
    ingest_canonical_chain(&node, &canonical)?;

    let old_tip = last_block(&canonical)?;
    let ancestor = block_at(&canonical, 1)?;
    let branch = make_fork_from_parent(ancestor, 3, 3510)?;
    ingest_side_branch(&node, &branch, 100)?;

    let _plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);

    assert_eq!(
        required(
            node.block_index.status_of(&old_tip.block_hash)?,
            "old tip status"
        )?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_036_handle_reorg_new_tip_becomes_canonical_vector() -> TestResult {
    let mut node = default_node("test_036_handle_reorg_new_tip_becomes_canonical_vector")?;
    let canonical = make_linear_chain(3, 3600)?;
    ingest_canonical_chain(&node, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let branch = make_fork_from_parent(ancestor, 3, 3610)?;
    ingest_side_branch(&node, &branch, 100)?;
    let new_tip = last_block(&branch)?;

    let _plan = assert_reorg(
        node.manager
            .handle_new_block(new_tip, &mut node.chain, None)?,
    );

    assert_eq!(
        required(
            node.block_index.status_of(&new_tip.block_hash)?,
            "new tip status"
        )?,
        ForkBlockStatus::Canonical
    );
    Ok(())
}

#[test]
fn test_037_handle_after_reorg_same_tip_stays_vector() -> TestResult {
    let mut node = default_node("test_037_handle_after_reorg_same_tip_stays_vector")?;
    let canonical = make_linear_chain(2, 3700)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 3710)?;
    ingest_side_branch(&node, &branch, 100)?;
    let tip = last_block(&branch)?;

    let _plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);
    assert_stay(node.manager.handle_new_block(tip, &mut node.chain, None)?);
    Ok(())
}

#[test]
fn test_038_handle_direct_extension_after_manager_reorg_stays_vector() -> TestResult {
    let mut node =
        default_node("test_038_handle_direct_extension_after_manager_reorg_stays_vector")?;
    let canonical = make_linear_chain(2, 3800)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 3810)?;
    ingest_side_branch(&node, &branch, 100)?;
    let tip = last_block(&branch)?;

    let _plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);

    let next = make_block(4, tip.block_hash, 3820)?;
    ingest_block(&node, &next, ForkBlockStatus::Validated, 4, 38)?;

    assert_stay(
        node.manager
            .handle_new_block(&next, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_039_handle_reorg_respects_zero_depth_bound_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 0,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: false,
    };
    let mut node = fresh_node(
        "test_039_handle_reorg_respects_zero_depth_bound_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(2, 3900)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 3910)?;
    ingest_side_branch(&node, &branch, 100)?;

    assert_stay(
        node.manager
            .handle_new_block(last_block(&branch)?, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_040_handle_reorg_at_depth_limit_succeeds_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 4,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: false,
    };
    let mut node = fresh_node("test_040_handle_reorg_at_depth_limit_succeeds_vector", cfg)?;
    let canonical = make_linear_chain(2, 4000)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 4, 4010)?;
    ingest_side_branch(&node, &branch, 100)?;

    let plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);
    assert_eq!(plan.attach.len(), 4);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 41–60: direct apply_reorg_plan behavior
// ─────────────────────────────────────────────────────────────

#[test]
fn test_041_apply_attach_only_plan_sets_tip_vector() -> TestResult {
    let mut node = default_node("test_041_apply_attach_only_plan_sets_tip_vector")?;
    let canonical = make_linear_chain(1, 4100)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 4101)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 10, 41)?;

    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "tip hash")?,
        child.block_hash
    );
    assert_eq!(node.chain.latest_block_height(), 1);
    Ok(())
}

#[test]
fn test_042_apply_attach_only_marks_canonical_vector() -> TestResult {
    let mut node = default_node("test_042_apply_attach_only_marks_canonical_vector")?;
    let canonical = make_linear_chain(1, 4200)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 4201)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 10, 42)?;

    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(
            node.block_index.status_of(&child.block_hash)?,
            "child status"
        )?,
        ForkBlockStatus::Canonical
    );
    Ok(())
}

#[test]
fn test_043_apply_detach_only_back_to_genesis_vector() -> TestResult {
    let mut node = default_node("test_043_apply_detach_only_back_to_genesis_vector")?;
    let canonical = make_linear_chain(2, 4300)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let old_tip = block_at(&canonical, 1)?;
    let plan = make_plan(
        old_tip,
        genesis,
        genesis,
        vec![reorg_step(old_tip)],
        Vec::new(),
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_tip_height()?, "tip height")?,
        0
    );
    assert_eq!(node.chain.latest_block_height(), 0);
    Ok(())
}

#[test]
fn test_044_apply_detach_only_marks_side_branch_vector() -> TestResult {
    let mut node = default_node("test_044_apply_detach_only_marks_side_branch_vector")?;
    let canonical = make_linear_chain(2, 4400)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let old_tip = block_at(&canonical, 1)?;
    let plan = make_plan(
        old_tip,
        genesis,
        genesis,
        vec![reorg_step(old_tip)],
        Vec::new(),
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(
            node.block_index.status_of(&old_tip.block_hash)?,
            "old tip status"
        )?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_045_apply_detach_and_attach_updates_height_mapping_vector() -> TestResult {
    let mut node = default_node("test_045_apply_detach_and_attach_updates_height_mapping_vector")?;
    let canonical = make_linear_chain(3, 4500)?;
    ingest_canonical_chain(&node, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let old_tip = block_at(&canonical, 2)?;
    let side = make_block(2, ancestor.block_hash, 4510)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 100, 45)?;

    let plan = make_plan(
        old_tip,
        &side,
        ancestor,
        vec![reorg_step(old_tip)],
        vec![reorg_step(&side)],
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_hash_at_height(2)?, "height 2 hash")?,
        side.block_hash
    );
    Ok(())
}

#[test]
fn test_046_apply_multiple_attach_steps_vector() -> TestResult {
    let mut node = default_node("test_046_apply_multiple_attach_steps_vector")?;
    let canonical = make_linear_chain(1, 4600)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 4610)?;
    ingest_side_branch(&node, &branch, 100)?;

    let tip = last_block(&branch)?;
    let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
    let plan = make_plan(genesis, tip, genesis, Vec::new(), attach);

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_tip_height()?, "tip height")?,
        3
    );
    assert_eq!(node.chain.latest_block_height(), 3);
    Ok(())
}

#[test]
fn test_047_apply_multiple_detach_steps_vector() -> TestResult {
    let mut node = default_node("test_047_apply_multiple_detach_steps_vector")?;
    let canonical = make_linear_chain(4, 4700)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let old_tip = last_block(&canonical)?;
    let detach = canonical
        .iter()
        .skip(1)
        .rev()
        .map(reorg_step)
        .collect::<Vec<_>>();
    let plan = make_plan(old_tip, genesis, genesis, detach, Vec::new());

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.latest_block_height(), 0);
    Ok(())
}

#[test]
fn test_048_apply_missing_attach_block_returns_not_found_vector() -> TestResult {
    let mut node = default_node("test_048_apply_missing_attach_block_returns_not_found_vector")?;
    let canonical = make_linear_chain(1, 4800)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let fake = make_block(1, genesis.block_hash, 4801)?;
    let plan = make_plan(
        genesis,
        &fake,
        genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: deterministic_hash(4802),
        }],
    );

    assert_not_found(node.manager.apply_reorg_plan(&plan, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_049_apply_attach_height_mismatch_returns_blockchain_error_vector() -> TestResult {
    let mut node =
        default_node("test_049_apply_attach_height_mismatch_returns_blockchain_error_vector")?;
    let canonical = make_linear_chain(1, 4900)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 4901)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 10, 49)?;

    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 2,
            hash: child.block_hash,
        }],
    );

    assert_blockchain_error(node.manager.apply_reorg_plan(&plan, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_050_apply_missing_batch_for_attached_non_genesis_returns_validation_error_vector()
-> TestResult {
    let mut node = default_node(
        "test_050_apply_missing_batch_for_attached_non_genesis_returns_validation_error_vector",
    )?;
    let canonical = make_linear_chain(1, 5000)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 5001)?;
    let meta = node
        .block_index
        .make_scored_meta(&child, 10, ForkBlockStatus::SideBranch);
    node.block_index.put_block_and_meta(&child, &meta)?;

    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );

    assert_validation_error(node.manager.apply_reorg_plan(&plan, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_051_apply_remaps_batch_for_attach_vector() -> TestResult {
    let mut node = default_node("test_051_apply_remaps_batch_for_attach_vector")?;
    let canonical = make_linear_chain(1, 5100)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 5101)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 10, 51)?;
    let expected = required(
        node.batch_index
            .get_batch_by_block_hash(&child.block_hash)?,
        "side branch batch",
    )?;

    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(
            node.batch_index.get_canonical_batch_at_height(1)?,
            "canonical batch"
        )?,
        expected
    );
    Ok(())
}

#[test]
fn test_052_apply_overwrites_stale_canonical_batch_projection_vector() -> TestResult {
    let mut node =
        default_node("test_052_apply_overwrites_stale_canonical_batch_projection_vector")?;
    let canonical = make_linear_chain(1, 5200)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 5201)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 10, 52)?;
    node.batch_index
        .set_canonical_batch_at_height(1, b"stale-batch")?;

    let expected = required(
        node.batch_index
            .get_batch_by_block_hash(&child.block_hash)?,
        "truth batch",
    )?;
    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(
            node.batch_index.get_canonical_batch_at_height(1)?,
            "projection"
        )?,
        expected
    );
    Ok(())
}

#[test]
fn test_053_apply_deletes_old_hash_slot_above_ancestor_vector() -> TestResult {
    let mut node = default_node("test_053_apply_deletes_old_hash_slot_above_ancestor_vector")?;
    let canonical = make_linear_chain(3, 5300)?;
    ingest_canonical_chain(&node, &canonical)?;

    let ancestor = block_at(&canonical, 0)?;
    let old_tip = block_at(&canonical, 2)?;
    let side = make_block(1, ancestor.block_hash, 5310)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 100, 53)?;

    let plan = make_plan(
        old_tip,
        &side,
        ancestor,
        vec![reorg_step(old_tip), reorg_step(block_at(&canonical, 1)?)],
        vec![reorg_step(&side)],
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert!(node.chain_view.get_hash_at_height(2)?.is_none());
    Ok(())
}

#[test]
fn test_054_apply_preserves_prefix_hash_slot_vector() -> TestResult {
    let mut node = default_node("test_054_apply_preserves_prefix_hash_slot_vector")?;
    let canonical = make_linear_chain(3, 5400)?;
    ingest_canonical_chain(&node, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let old_tip = block_at(&canonical, 2)?;
    let side = make_block(2, ancestor.block_hash, 5410)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 100, 54)?;

    let plan = make_plan(
        old_tip,
        &side,
        ancestor,
        vec![reorg_step(old_tip)],
        vec![reorg_step(&side)],
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_hash_at_height(1)?, "prefix hash")?,
        ancestor.block_hash
    );
    Ok(())
}

#[test]
fn test_055_apply_reloads_chain_to_new_tip_height_vector() -> TestResult {
    let mut node = default_node("test_055_apply_reloads_chain_to_new_tip_height_vector")?;
    let canonical = make_linear_chain(2, 5500)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 4, 5510)?;
    ingest_side_branch(&node, &branch, 100)?;
    let tip = last_block(&branch)?;

    let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
    let plan = make_plan(
        last_block(&canonical)?,
        tip,
        genesis,
        vec![reorg_step(last_block(&canonical)?)],
        attach,
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.latest_block_height(), 4);
    Ok(())
}

#[test]
fn test_056_apply_reloads_chain_tip_block_vector() -> TestResult {
    let mut node = default_node("test_056_apply_reloads_chain_tip_block_vector")?;
    let canonical = make_linear_chain(1, 5600)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 2, 5610)?;
    ingest_side_branch(&node, &branch, 100)?;
    let tip = last_block(&branch)?;

    let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
    let plan = make_plan(genesis, tip, genesis, Vec::new(), attach);

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.get_block_by_index(2)?, *tip);
    Ok(())
}

#[test]
fn test_057_apply_noop_after_seed_keeps_balances_empty_vector() -> TestResult {
    let mut node = default_node("test_057_apply_noop_after_seed_keeps_balances_empty_vector")?;
    let canonical = make_linear_chain(2, 5700)?;
    ingest_canonical_chain(&node, &canonical)?;

    let plan = noop_plan(last_block(&canonical)?.block_hash);
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert!(node.chain.get_balances().is_empty());
    Ok(())
}

#[test]
fn test_058_apply_attach_genesis_only_vector() -> TestResult {
    let mut node = default_node("test_058_apply_attach_genesis_only_vector")?;
    let genesis = make_block(0, [0u8; 64], 5800)?;
    ingest_block(&node, &genesis, ForkBlockStatus::SideBranch, 0, 58)?;

    let plan = make_plan(
        &genesis,
        &genesis,
        &genesis,
        Vec::new(),
        vec![reorg_step(&genesis)],
    );
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.latest_block_height(), 0);
    assert_eq!(
        required(node.chain_view.get_hash_at_height(0)?, "genesis hash")?,
        genesis.block_hash
    );
    Ok(())
}

#[test]
fn test_059_apply_attach_without_meta_still_loads_projection_vector() -> TestResult {
    let mut node =
        default_node("test_059_apply_attach_without_meta_still_loads_projection_vector")?;
    let canonical = make_linear_chain(1, 5900)?;
    ingest_canonical_chain(&node, &canonical)?;
    let genesis = block_at(&canonical, 0)?;

    let child = make_block(1, genesis.block_hash, 5901)?;
    node.block_index.put_block(&child)?;
    let batch = make_batch_bytes(1, 59)?;
    node.batch_index
        .put_batch_by_block_hash(&child.block_hash, &batch)?;

    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.get_block_by_index(1)?, child);
    Ok(())
}

#[test]
fn test_060_apply_detach_without_meta_still_reloads_vector() -> TestResult {
    let mut node = default_node("test_060_apply_detach_without_meta_still_reloads_vector")?;
    let canonical = make_linear_chain(2, 6000)?;
    ingest_canonical_chain(&node, &canonical)?;
    let genesis = block_at(&canonical, 0)?;
    let old_tip = block_at(&canonical, 1)?;

    let plan = make_plan(
        old_tip,
        genesis,
        genesis,
        vec![ReorgStep {
            height: old_tip.metadata.index,
            hash: deterministic_hash(6001),
        }],
        Vec::new(),
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.latest_block_height(), 0);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 61–80: property, edge, adversarial behavior
// ─────────────────────────────────────────────────────────────

#[test]
fn test_061_property_direct_extensions_stay_for_many_heights() -> TestResult {
    let mut node = default_node("test_061_property_direct_extensions_stay_for_many_heights")?;
    let mut chain = make_linear_chain(1, 6100)?;
    ingest_canonical_chain(&node, &chain)?;

    for height in 1u64..8u64 {
        let tip = last_block(&chain)?;
        let next = make_block(height, tip.block_hash, 6100u64.saturating_add(height))?;
        ingest_block(
            &node,
            &next,
            ForkBlockStatus::Validated,
            u128::from(height),
            height,
        )?;

        assert_stay(
            node.manager
                .handle_new_block(&next, &mut node.chain, None)?,
        );

        chain.push(next);
        ingest_canonical_chain(&node, &chain)?;
    }

    Ok(())
}

#[test]
fn test_062_property_shorter_side_branches_stay_for_many_parents() -> TestResult {
    let mut node = default_node("test_062_property_shorter_side_branches_stay_for_many_parents")?;
    let canonical = make_linear_chain(8, 6200)?;
    ingest_canonical_chain(&node, &canonical)?;

    for parent_pos in 0usize..6usize {
        let parent = block_at(&canonical, parent_pos)?;
        let height = parent.metadata.index.saturating_add(1);
        let pos_u64 = u64::try_from(parent_pos)
            .map_err(|e| storage_error(format!("failed to convert parent_pos to u64: {e}")))?;
        let side = make_block(height, parent.block_hash, 6210u64.saturating_add(pos_u64))?;
        ingest_block(
            &node,
            &side,
            ForkBlockStatus::SideBranch,
            u128::from(height),
            height,
        )?;

        assert_stay(
            node.manager
                .handle_new_block(&side, &mut node.chain, None)?,
        );
    }

    Ok(())
}

#[test]
fn test_063_property_longer_branches_reorg_for_lengths_two_to_five() -> TestResult {
    for len in 2u64..6u64 {
        let label =
            format!("test_063_property_longer_branches_reorg_for_lengths_two_to_five_{len}");
        let mut node = default_node(&label)?;
        let canonical = make_linear_chain(2, 6300u64.saturating_add(len))?;
        ingest_canonical_chain(&node, &canonical)?;

        let genesis = block_at(&canonical, 0)?;
        let branch = make_fork_from_parent(genesis, len, 6310u64.saturating_add(len))?;
        ingest_side_branch(&node, &branch, 100)?;

        let plan = assert_reorg(node.manager.handle_new_block(
            last_block(&branch)?,
            &mut node.chain,
            None,
        )?);
        assert_eq!(
            plan.attach.len(),
            usize::try_from(len)
                .map_err(|e| storage_error(format!("failed to convert len to usize: {e}")))?
        );
    }

    Ok(())
}

#[test]
fn test_064_property_apply_attach_paths_many_heights() -> TestResult {
    for target_height in 1u64..6u64 {
        let label = format!("test_064_property_apply_attach_paths_many_heights_{target_height}");
        let mut node = default_node(&label)?;
        let canonical = make_linear_chain(1, 6400)?;
        ingest_canonical_chain(&node, &canonical)?;
        let genesis = block_at(&canonical, 0)?;

        let branch = make_fork_from_parent(
            genesis,
            target_height,
            6400u64.saturating_add(target_height),
        )?;
        ingest_side_branch(&node, &branch, 100)?;

        let tip = last_block(&branch)?;
        let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
        let plan = make_plan(genesis, tip, genesis, Vec::new(), attach);

        node.manager
            .apply_reorg_plan(&plan, &mut node.chain, None)?;

        assert_eq!(
            required(
                node.chain_view.get_hash_at_height(target_height)?,
                "attached target height"
            )?,
            tip.block_hash
        );
        assert_eq!(
            node.chain.latest_block_height(),
            usize::try_from(target_height).map_err(|e| {
                storage_error(format!("failed to convert target_height to usize: {e}"))
            })?
        );
    }

    Ok(())
}

#[test]
fn test_065_property_reorg_batches_remap_for_many_branch_lengths() -> TestResult {
    for len in 2u64..5u64 {
        let label = format!("test_065_property_reorg_batches_remap_for_many_branch_lengths_{len}");
        let mut node = default_node(&label)?;
        let canonical = make_linear_chain(1, 6500)?;
        ingest_canonical_chain(&node, &canonical)?;

        let genesis = block_at(&canonical, 0)?;
        let branch = make_fork_from_parent(genesis, len, 6510u64.saturating_add(len))?;
        ingest_side_branch(&node, &branch, 100)?;

        let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
        let plan = make_plan(genesis, last_block(&branch)?, genesis, Vec::new(), attach);
        node.manager
            .apply_reorg_plan(&plan, &mut node.chain, None)?;

        for block in &branch {
            assert!(
                node.batch_index
                    .get_canonical_batch_at_height(block.metadata.index)?
                    .is_some()
            );
        }
    }

    Ok(())
}

#[test]
fn test_066_property_noop_plans_many_hashes_succeed_after_genesis_seed() -> TestResult {
    let mut node =
        default_node("test_066_property_noop_plans_many_hashes_succeed_after_genesis_seed")?;
    let canonical = make_linear_chain(1, 6600)?;
    ingest_canonical_chain(&node, &canonical)?;

    for seed in 0u64..16u64 {
        let plan = noop_plan(deterministic_hash(6600u64.saturating_add(seed)));
        node.manager
            .apply_reorg_plan(&plan, &mut node.chain, None)?;
        assert_eq!(node.chain.latest_block_height(), 0);
    }

    Ok(())
}

#[test]
fn test_067_adversarial_missing_canonical_tip_block_returns_not_found_vector() -> TestResult {
    let mut node =
        default_node("test_067_adversarial_missing_canonical_tip_block_returns_not_found_vector")?;
    let fake_tip = deterministic_hash(67);
    node.chain_view.set_tip(&fake_tip, 1)?;

    let block = make_block(2, fake_tip, 6710)?;

    assert_not_found(node.manager.handle_new_block(&block, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_068_adversarial_reorg_beyond_depth_stays_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 1,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: false,
    };
    let mut node = fresh_node("test_068_adversarial_reorg_beyond_depth_stays_vector", cfg)?;
    let canonical = make_linear_chain(4, 6800)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 4, 6810)?;
    ingest_side_branch(&node, &branch, 100)?;

    assert_stay(
        node.manager
            .handle_new_block(last_block(&branch)?, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_069_adversarial_high_por_short_branch_wins_in_por_mode_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    };
    let mut node = fresh_node(
        "test_069_adversarial_high_por_short_branch_wins_in_por_mode_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(4, 6900)?;
    ingest_canonical_chain(&node, &canonical)?;

    let old_tip = last_block(&canonical)?;
    let old_meta = node
        .block_index
        .make_scored_meta(old_tip, 1, ForkBlockStatus::Canonical);
    node.block_index.put_meta(&old_tip.block_hash, &old_meta)?;

    let parent = block_at(&canonical, 1)?;
    let side = make_block(2, parent.block_hash, 6910)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 999, 69)?;

    let plan = assert_reorg(
        node.manager
            .handle_new_block(&side, &mut node.chain, None)?,
    );
    assert_eq!(plan.new_tip_hash, side.block_hash);
    Ok(())
}

#[test]
fn test_070_adversarial_equal_height_reorg_disabled_blocks_lower_hash_vector() -> TestResult {
    let mut node =
        default_node("test_070_adversarial_equal_height_reorg_disabled_blocks_lower_hash_vector")?;

    let genesis = make_block(0, [0u8; 64], 7000)?;
    let parent = make_block(1, genesis.block_hash, 7001)?;
    let (lower, higher) = find_ordered_equal_height_pair(&parent, 7010)?;

    let canonical = vec![genesis, parent, higher.clone()];
    ingest_canonical_chain(&node, &canonical)?;
    ingest_block(&node, &lower, ForkBlockStatus::SideBranch, 2, 70)?;

    assert_stay(
        node.manager
            .handle_new_block(&lower, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_071_adversarial_stale_batch_projection_healed_by_manager_vector() -> TestResult {
    let mut node =
        default_node("test_071_adversarial_stale_batch_projection_healed_by_manager_vector")?;
    let canonical = make_linear_chain(1, 7100)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 7101)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 100, 71)?;
    node.batch_index
        .set_canonical_batch_at_height(1, b"stale")?;

    let truth = required(
        node.batch_index
            .get_batch_by_block_hash(&child.block_hash)?,
        "truth batch",
    )?;
    let plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );
    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(
            node.batch_index.get_canonical_batch_at_height(1)?,
            "projection"
        )?,
        truth
    );
    Ok(())
}

#[test]
fn test_072_adversarial_apply_plan_with_duplicate_attach_height_last_projection_wins_vector()
-> TestResult {
    let mut node = default_node(
        "test_072_adversarial_apply_plan_with_duplicate_attach_height_last_projection_wins_vector",
    )?;
    let canonical = make_linear_chain(1, 7200)?;
    ingest_canonical_chain(&node, &canonical)?;
    let genesis = block_at(&canonical, 0)?;

    let first = make_block(1, genesis.block_hash, 7201)?;
    let second = make_block(1, genesis.block_hash, 7202)?;
    ingest_block(&node, &first, ForkBlockStatus::SideBranch, 10, 721)?;
    ingest_block(&node, &second, ForkBlockStatus::SideBranch, 20, 722)?;

    let plan = make_plan(
        genesis,
        &second,
        genesis,
        Vec::new(),
        vec![reorg_step(&first), reorg_step(&second)],
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_hash_at_height(1)?, "duplicate height")?,
        second.block_hash
    );
    Ok(())
}

#[test]
fn test_073_adversarial_attach_out_of_order_still_replays_when_no_gap_vector() -> TestResult {
    let mut node =
        default_node("test_073_adversarial_attach_out_of_order_still_replays_when_no_gap_vector")?;
    let canonical = make_linear_chain(1, 7300)?;
    ingest_canonical_chain(&node, &canonical)?;
    let genesis = block_at(&canonical, 0)?;

    let branch = make_fork_from_parent(genesis, 2, 7310)?;
    ingest_side_branch(&node, &branch, 100)?;
    let one = block_at(&branch, 0)?;
    let two = block_at(&branch, 1)?;

    let plan = make_plan(
        genesis,
        two,
        genesis,
        Vec::new(),
        vec![reorg_step(two), reorg_step(one)],
    );

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_hash_at_height(1)?, "height one")?,
        one.block_hash
    );
    assert_eq!(
        required(node.chain_view.get_hash_at_height(2)?, "height two")?,
        two.block_hash
    );
    assert_eq!(node.chain.latest_block_height(), 2);
    Ok(())
}

#[test]
fn test_074_adversarial_plan_new_tip_height_lower_than_attach_tip_sets_plan_tip_vector()
-> TestResult {
    let mut node = default_node(
        "test_074_adversarial_plan_new_tip_height_lower_than_attach_tip_sets_plan_tip_vector",
    )?;
    let canonical = make_linear_chain(1, 7400)?;
    ingest_canonical_chain(&node, &canonical)?;
    let genesis = block_at(&canonical, 0)?;
    let child = make_block(1, genesis.block_hash, 7401)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 10, 74)?;

    let mut plan = make_plan(
        genesis,
        &child,
        genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );
    plan.new_tip_height = 0;
    plan.new_tip_hash = genesis.block_hash;

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_tip_height()?, "plan tip height")?,
        0
    );
    Ok(())
}

#[test]
fn test_075_adversarial_plan_with_missing_prefix_reload_fails_vector() -> TestResult {
    let mut node =
        default_node("test_075_adversarial_plan_with_missing_prefix_reload_fails_vector")?;
    let genesis = make_block(0, [0u8; 64], 7500)?;
    let child = make_block(1, genesis.block_hash, 7501)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 10, 75)?;

    let plan = make_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![reorg_step(&child)],
    );

    assert_validation_error(node.manager.apply_reorg_plan(&plan, &mut node.chain, None));
    Ok(())
}

#[test]
fn test_076_property_apply_reorg_preserves_empty_balances_for_many_lengths() -> TestResult {
    for len in 1u64..5u64 {
        let label = format!(
            "test_076_property_apply_reorg_preserves_empty_balances_for_many_lengths_{len}"
        );
        let mut node = default_node(&label)?;
        let canonical = make_linear_chain(1, 7600)?;
        ingest_canonical_chain(&node, &canonical)?;
        let genesis = block_at(&canonical, 0)?;

        let branch = make_fork_from_parent(genesis, len, 7610u64.saturating_add(len))?;
        ingest_side_branch(&node, &branch, 100)?;
        let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
        let plan = make_plan(genesis, last_block(&branch)?, genesis, Vec::new(), attach);

        node.manager
            .apply_reorg_plan(&plan, &mut node.chain, None)?;
        assert!(node.chain.get_balances().is_empty());
    }

    Ok(())
}

#[test]
fn test_077_property_apply_reorg_latest_projection_matches_tip_for_many_lengths() -> TestResult {
    for len in 1u64..5u64 {
        let label = format!(
            "test_077_property_apply_reorg_latest_projection_matches_tip_for_many_lengths_{len}"
        );
        let mut node = default_node(&label)?;
        let canonical = make_linear_chain(1, 7700)?;
        ingest_canonical_chain(&node, &canonical)?;
        let genesis = block_at(&canonical, 0)?;

        let branch = make_fork_from_parent(genesis, len, 7710u64.saturating_add(len))?;
        ingest_side_branch(&node, &branch, 100)?;
        let tip = last_block(&branch)?;
        let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
        let plan = make_plan(genesis, tip, genesis, Vec::new(), attach);

        node.manager
            .apply_reorg_plan(&plan, &mut node.chain, None)?;
        let projected = required(
            node.db.get_block_by_index(tip.metadata.index)?,
            "projected tip",
        )?;
        assert_eq!(projected, *tip);
    }

    Ok(())
}

#[test]
fn test_078_property_handle_new_block_reorg_sets_tip_for_many_lengths() -> TestResult {
    for len in 2u64..5u64 {
        let label =
            format!("test_078_property_handle_new_block_reorg_sets_tip_for_many_lengths_{len}");
        let mut node = default_node(&label)?;
        let canonical = make_linear_chain(2, 7800)?;
        ingest_canonical_chain(&node, &canonical)?;
        let genesis = block_at(&canonical, 0)?;

        let branch = make_fork_from_parent(genesis, len, 7810u64.saturating_add(len))?;
        ingest_side_branch(&node, &branch, 100)?;
        let tip = last_block(&branch)?;

        let _plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);
        assert_eq!(
            required(node.chain_view.get_tip_hash()?, "tip hash")?,
            tip.block_hash
        );
    }

    Ok(())
}

#[test]
fn test_079_adversarial_need_more_data_does_not_change_tip_vector() -> TestResult {
    let mut node = default_node("test_079_adversarial_need_more_data_does_not_change_tip_vector")?;
    let canonical = make_linear_chain(2, 7900)?;
    ingest_canonical_chain(&node, &canonical)?;
    let old_tip = last_block(&canonical)?.block_hash;

    let missing_parent = deterministic_hash(7901);
    let child = make_block(3, missing_parent, 7910)?;
    ingest_block(&node, &child, ForkBlockStatus::SideBranch, 100, 79)?;

    assert_need_more_data(
        node.manager
            .handle_new_block(&child, &mut node.chain, None)?,
        missing_parent,
    );
    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "unchanged tip")?,
        old_tip
    );
    Ok(())
}

#[test]
fn test_080_adversarial_stay_does_not_change_tip_vector() -> TestResult {
    let mut node = default_node("test_080_adversarial_stay_does_not_change_tip_vector")?;
    let canonical = make_linear_chain(3, 8000)?;
    ingest_canonical_chain(&node, &canonical)?;
    let old_tip = last_block(&canonical)?.block_hash;

    let parent = block_at(&canonical, 0)?;
    let side = make_block(1, parent.block_hash, 8010)?;
    ingest_block(&node, &side, ForkBlockStatus::SideBranch, 1, 80)?;

    assert_stay(
        node.manager
            .handle_new_block(&side, &mut node.chain, None)?,
    );
    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "unchanged tip")?,
        old_tip
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 81–100: fuzz-style and load tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_081_load_handle_reorg_32_block_branch_vector() -> TestResult {
    let mut node = default_node("test_081_load_handle_reorg_32_block_branch_vector")?;
    let canonical = make_linear_chain(2, 8100)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 32, 8110)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let tip = last_block(&branch)?;
    let plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);

    assert_eq!(plan.attach.len(), 32);
    assert_eq!(node.chain.latest_block_height(), 32);
    Ok(())
}

#[test]
fn test_082_load_apply_reorg_32_attach_steps_vector() -> TestResult {
    let mut node = default_node("test_082_load_apply_reorg_32_attach_steps_vector")?;
    let canonical = make_linear_chain(1, 8200)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 32, 8210)?;
    ingest_side_branch(&node, &branch, 100)?;

    let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
    let tip = last_block(&branch)?;
    let plan = make_plan(genesis, tip, genesis, Vec::new(), attach);

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(
        required(node.chain_view.get_tip_height()?, "tip height")?,
        32
    );
    Ok(())
}

#[test]
fn test_083_load_apply_reorg_32_detach_steps_vector() -> TestResult {
    let mut node = default_node("test_083_load_apply_reorg_32_detach_steps_vector")?;
    let canonical = make_linear_chain(33, 8300)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let old_tip = last_block(&canonical)?;
    let detach = canonical
        .iter()
        .skip(1)
        .rev()
        .map(reorg_step)
        .collect::<Vec<_>>();
    let plan = make_plan(old_tip, genesis, genesis, detach, Vec::new());

    node.manager
        .apply_reorg_plan(&plan, &mut node.chain, None)?;

    assert_eq!(node.chain.latest_block_height(), 0);
    Ok(())
}

#[test]
fn test_084_load_reorg_64_attach_steps_at_default_limit_vector() -> TestResult {
    let mut node = default_node("test_084_load_reorg_64_attach_steps_at_default_limit_vector")?;
    let canonical = make_linear_chain(2, 8400)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 64, 8410)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let tip = last_block(&branch)?;
    let plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);

    assert_eq!(plan.attach.len(), 64);
    assert_eq!(node.chain.latest_block_height(), 64);
    Ok(())
}

#[test]
fn test_085_load_reorg_65_attach_steps_beyond_default_limit_stays_vector() -> TestResult {
    let mut node =
        default_node("test_085_load_reorg_65_attach_steps_beyond_default_limit_stays_vector")?;
    let canonical = make_linear_chain(2, 8500)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 65, 8510)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    assert_stay(
        node.manager
            .handle_new_block(last_block(&branch)?, &mut node.chain, None)?,
    );
    Ok(())
}

#[test]
fn test_086_load_custom_128_depth_allows_65_attach_steps_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 128,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: false,
    };
    let mut node = fresh_node(
        "test_086_load_custom_128_depth_allows_65_attach_steps_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(2, 8600)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 65, 8610)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);
    assert_eq!(plan.attach.len(), 65);
    Ok(())
}

#[test]
fn test_087_fuzz_many_noop_plans_after_seed_vector() -> TestResult {
    let mut node = default_node("test_087_fuzz_many_noop_plans_after_seed_vector")?;
    let canonical = make_linear_chain(2, 8700)?;
    ingest_canonical_chain(&node, &canonical)?;

    for seed in 0u64..32u64 {
        let plan = noop_plan(deterministic_hash(8700u64.saturating_add(seed)));
        node.manager
            .apply_reorg_plan(&plan, &mut node.chain, None)?;
        assert_eq!(node.chain.latest_block_height(), 0);
    }

    assert_eq!(
        required(node.chain_view.get_tip_height()?, "canonical tip height")?,
        1
    );
    Ok(())
}

#[test]
fn test_088_fuzz_repeated_short_side_branches_stay_vector() -> TestResult {
    let mut node = default_node("test_088_fuzz_repeated_short_side_branches_stay_vector")?;
    let canonical = make_linear_chain(6, 8800)?;
    ingest_canonical_chain(&node, &canonical)?;
    let old_tip = last_block(&canonical)?.block_hash;

    for seed in 0u64..16u64 {
        let parent = block_at(&canonical, 1)?;
        let side = make_block(2, parent.block_hash, 8810u64.saturating_add(seed))?;
        ingest_block(&node, &side, ForkBlockStatus::SideBranch, 2, seed)?;
        assert_stay(
            node.manager
                .handle_new_block(&side, &mut node.chain, None)?,
        );
    }

    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "old tip")?,
        old_tip
    );
    Ok(())
}

#[test]
fn test_089_fuzz_apply_reorg_different_branch_tags_vector() -> TestResult {
    for tag in 8900u64..8904u64 {
        let label = format!("test_089_fuzz_apply_reorg_different_branch_tags_vector_{tag}");
        let mut node = default_node(&label)?;
        let canonical = make_linear_chain(1, tag)?;
        ingest_canonical_chain(&node, &canonical)?;
        let genesis = block_at(&canonical, 0)?;

        let branch = make_fork_from_parent(genesis, 3, tag.saturating_add(100))?;
        ingest_side_branch(&node, &branch, 100)?;
        let attach = branch.iter().map(reorg_step).collect::<Vec<_>>();
        let plan = make_plan(genesis, last_block(&branch)?, genesis, Vec::new(), attach);
        node.manager
            .apply_reorg_plan(&plan, &mut node.chain, None)?;

        assert_eq!(node.chain.latest_block_height(), 3);
    }

    Ok(())
}

#[test]
fn test_090_fuzz_por_scores_choose_high_score_branches_vector() -> TestResult {
    for score in 10u128..14u128 {
        let cfg = ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: true,
        };
        let label = format!("test_090_fuzz_por_scores_choose_high_score_branches_vector_{score}");
        let mut node = fresh_node(&label, cfg)?;
        let canonical = make_linear_chain(3, 9000)?;
        ingest_canonical_chain(&node, &canonical)?;

        let old_tip = last_block(&canonical)?;
        let old_meta = node
            .block_index
            .make_scored_meta(old_tip, 1, ForkBlockStatus::Canonical);
        node.block_index.put_meta(&old_tip.block_hash, &old_meta)?;

        let parent = block_at(&canonical, 1)?;
        let score_u64 = u64::try_from(score)
            .map_err(|e| storage_error(format!("failed to convert score to u64: {e}")))?;
        let side = make_block(2, parent.block_hash, 9010u64.saturating_add(score_u64))?;
        ingest_block(&node, &side, ForkBlockStatus::SideBranch, score, score_u64)?;

        let plan = assert_reorg(
            node.manager
                .handle_new_block(&side, &mut node.chain, None)?,
        );
        assert_eq!(plan.new_tip_hash, side.block_hash);
    }

    Ok(())
}

#[test]
fn test_091_load_canonical_batches_after_32_block_reorg_vector() -> TestResult {
    let mut node = default_node("test_091_load_canonical_batches_after_32_block_reorg_vector")?;
    let canonical = make_linear_chain(2, 9100)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 32, 9110)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let tip = last_block(&branch)?;
    let _plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);

    for block in &branch {
        assert!(
            node.batch_index
                .get_canonical_batch_at_height(block.metadata.index)?
                .is_some()
        );
    }

    Ok(())
}

#[test]
fn test_092_load_new_branch_blocks_canonical_after_32_block_reorg_vector() -> TestResult {
    let mut node =
        default_node("test_092_load_new_branch_blocks_canonical_after_32_block_reorg_vector")?;
    let canonical = make_linear_chain(2, 9200)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 32, 9210)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let _plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);

    for block in &branch {
        assert_eq!(
            required(
                node.block_index.status_of(&block.block_hash)?,
                "branch status"
            )?,
            ForkBlockStatus::Canonical
        );
    }

    Ok(())
}

#[test]
fn test_093_load_old_branch_side_after_32_block_reorg_vector() -> TestResult {
    let mut node = default_node("test_093_load_old_branch_side_after_32_block_reorg_vector")?;
    let canonical = make_linear_chain(8, 9300)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 32, 9310)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let _plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);

    for block in canonical.iter().skip(1) {
        assert_eq!(
            required(node.block_index.status_of(&block.block_hash)?, "old status")?,
            ForkBlockStatus::SideBranch
        );
    }

    Ok(())
}

#[test]
fn test_094_load_reorg_rebuilds_chain_blocks_to_new_tip_vector() -> TestResult {
    let mut node = default_node("test_094_load_reorg_rebuilds_chain_blocks_to_new_tip_vector")?;
    let canonical = make_linear_chain(2, 9400)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 16, 9410)?;
    ingest_side_branch(&node, &branch, 1_000)?;
    let tip = last_block(&branch)?;

    let _plan = assert_reorg(node.manager.handle_new_block(tip, &mut node.chain, None)?);

    assert_eq!(node.chain.get_block_by_index(16)?, *tip);
    Ok(())
}

#[test]
fn test_095_load_reorg_then_reload_again_is_idempotent_vector() -> TestResult {
    let mut node = default_node("test_095_load_reorg_then_reload_again_is_idempotent_vector")?;
    let canonical = make_linear_chain(2, 9500)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 16, 9510)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let _plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);
    node.chain.reload_from_db_to_height(16)?;

    assert_eq!(node.chain.latest_block_height(), 16);
    Ok(())
}

#[test]
fn test_096_load_reorg_preserves_zero_balances_after_reload_vector() -> TestResult {
    let mut node = default_node("test_096_load_reorg_preserves_zero_balances_after_reload_vector")?;
    let canonical = make_linear_chain(2, 9600)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 16, 9610)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let _plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);

    assert!(node.chain.get_balances().is_empty());
    Ok(())
}

#[test]
fn test_097_end_to_end_manager_executes_plan_not_only_logs_vector() -> TestResult {
    let mut node = default_node("test_097_end_to_end_manager_executes_plan_not_only_logs_vector")?;
    let canonical = make_linear_chain(3, 9700)?;
    ingest_canonical_chain(&node, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let branch = make_fork_from_parent(ancestor, 3, 9710)?;
    ingest_side_branch(&node, &branch, 1_000)?;
    let new_tip = last_block(&branch)?;

    let plan = assert_reorg(
        node.manager
            .handle_new_block(new_tip, &mut node.chain, None)?,
    );

    assert_eq!(plan.new_tip_hash, new_tip.block_hash);
    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "executed tip")?,
        new_tip.block_hash
    );
    assert_eq!(
        node.chain.latest_block_height(),
        new_tip.metadata.index as usize
    );
    Ok(())
}

#[test]
fn test_098_end_to_end_manager_remaps_batches_and_reloads_state_vector() -> TestResult {
    let mut node =
        default_node("test_098_end_to_end_manager_remaps_batches_and_reloads_state_vector")?;
    let canonical = make_linear_chain(2, 9800)?;
    ingest_canonical_chain(&node, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 4, 9810)?;
    ingest_side_branch(&node, &branch, 1_000)?;
    let new_tip = last_block(&branch)?;

    let _plan = assert_reorg(
        node.manager
            .handle_new_block(new_tip, &mut node.chain, None)?,
    );

    assert!(
        node.batch_index
            .get_canonical_batch_at_height(new_tip.metadata.index)?
            .is_some()
    );
    assert_eq!(node.chain.latest_block_height(), 4);
    Ok(())
}

#[test]
fn test_099_end_to_end_manager_keeps_canonical_prefix_vector() -> TestResult {
    let mut node = default_node("test_099_end_to_end_manager_keeps_canonical_prefix_vector")?;
    let canonical = make_linear_chain(5, 9900)?;
    ingest_canonical_chain(&node, &canonical)?;

    let ancestor = block_at(&canonical, 2)?;
    let branch = make_fork_from_parent(ancestor, 4, 9910)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let _plan = assert_reorg(node.manager.handle_new_block(
        last_block(&branch)?,
        &mut node.chain,
        None,
    )?);

    for block in canonical.iter().take(3) {
        assert_eq!(
            required(
                node.chain_view.get_hash_at_height(block.metadata.index)?,
                "canonical prefix"
            )?,
            block.block_hash
        );
    }

    Ok(())
}

#[test]
fn test_100_end_to_end_full_reorg_manager_flow_vector() -> TestResult {
    let mut node = default_node("test_100_end_to_end_full_reorg_manager_flow_vector")?;
    let canonical = make_linear_chain(5, 10_000)?;
    ingest_canonical_chain(&node, &canonical)?;

    let ancestor = block_at(&canonical, 2)?;
    let branch = make_fork_from_parent(ancestor, 4, 10_100)?;
    ingest_side_branch(&node, &branch, 1_000)?;

    let old_tip = last_block(&canonical)?;
    let new_tip = last_block(&branch)?;
    let action = node
        .manager
        .handle_new_block(new_tip, &mut node.chain, None)?;
    let plan = assert_reorg(action);

    assert_eq!(plan.old_tip_hash, old_tip.block_hash);
    assert_eq!(plan.new_tip_hash, new_tip.block_hash);
    assert_eq!(plan.common_ancestor_hash, ancestor.block_hash);
    assert_eq!(plan.detach_heights(), vec![4, 3]);
    assert_eq!(plan.attach_heights(), vec![3, 4, 5, 6]);

    assert_eq!(
        required(node.chain_view.get_tip_hash()?, "final tip hash")?,
        new_tip.block_hash
    );
    assert_eq!(
        required(node.chain_view.get_tip_height()?, "final tip height")?,
        6
    );
    assert_eq!(node.chain.latest_block_height(), 6);
    assert_eq!(
        required(
            node.block_index.status_of(&new_tip.block_hash)?,
            "final status"
        )?,
        ForkBlockStatus::Canonical
    );

    Ok(())
}
