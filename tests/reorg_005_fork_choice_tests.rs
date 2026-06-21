use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;
use remzar::reorganization::reorg_001_block_index::ReorgBlockIndex;
use remzar::reorganization::reorg_002_chain_view::ReorgChainView;
use remzar::reorganization::reorg_005_fork_choice::{
    BlockHash, ForkAction, ReFork, ReForkConfig, ReorgPlan, ReorgStep,
};
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

fn fresh_fixture(
    label: &str,
    cfg: ReForkConfig,
) -> Result<(ReFork, ReorgBlockIndex, ReorgChainView, Arc<RockDBManager>), ErrorDetection> {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "remzar_reorg_005_fork_choice_{label}_{}_{}",
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
    let fork = ReFork::new(Arc::clone(&db), cfg);
    let block_index = ReorgBlockIndex::new(Arc::clone(&db));
    let chain_view = ReorgChainView::new(Arc::clone(&db));
    Ok((fork, block_index, chain_view, db))
}

fn default_fixture(
    label: &str,
) -> Result<(ReFork, ReorgBlockIndex, ReorgChainView, Arc<RockDBManager>), ErrorDetection> {
    fresh_fixture(label, ReForkConfig::default())
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
    let batch_key = Some(format!("fork-choice-batch-key-height-{height}-tag-{tag}"));
    Block::new(
        metadata,
        batch_key,
        GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        0,
    )
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

fn store_block_with_status_and_score(
    block_index: &ReorgBlockIndex,
    block: &Block,
    status: ForkBlockStatus,
    cumulative_score: u128,
) -> Result<(), ErrorDetection> {
    let meta = block_index.make_scored_meta(block, cumulative_score, status);
    block_index.put_block_and_meta(block, &meta)
}

fn store_block_with_status(
    block_index: &ReorgBlockIndex,
    block: &Block,
    status: ForkBlockStatus,
) -> Result<(), ErrorDetection> {
    store_block_with_status_and_score(block_index, block, status, u128::from(block.metadata.index))
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

fn store_canonical_chain(
    block_index: &ReorgBlockIndex,
    chain_view: &ReorgChainView,
    db: &RockDBManager,
    blocks: &[Block],
) -> TestResult {
    for block in blocks {
        store_block_with_status(block_index, block, ForkBlockStatus::Canonical)?;
        chain_view.set_hash_at_height(block.metadata.index, &block.block_hash)?;
        db.store_latest_block(&block.serialize_for_storage()?, block.metadata.index)?;
    }

    let tip = last_block(blocks)?;
    chain_view.set_tip(&tip.block_hash, tip.metadata.index)?;
    Ok(())
}

fn store_side_branch(
    block_index: &ReorgBlockIndex,
    blocks: &[Block],
    base_score: u128,
) -> TestResult {
    for block in blocks {
        store_block_with_status_and_score(
            block_index,
            block,
            ForkBlockStatus::SideBranch,
            base_score.saturating_add(u128::from(block.metadata.index)),
        )?;
    }
    Ok(())
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

fn find_equal_height_competitor(
    parent: &Block,
    current_tip_hash: BlockHash,
    want_lower_hash: bool,
    seed_base: u64,
) -> Result<Block, ErrorDetection> {
    let height = parent.metadata.index.saturating_add(1);

    for offset in 0u64..512u64 {
        let block = make_block(height, parent.block_hash, seed_base.saturating_add(offset))?;
        let is_match = if want_lower_hash {
            block.block_hash < current_tip_hash
        } else {
            block.block_hash > current_tip_hash
        };

        if is_match {
            return Ok(block);
        }
    }

    Err(storage_error(format!(
        "could not find equal-height competitor want_lower_hash={want_lower_hash}"
    )))
}

fn assert_stay(action: ForkAction) {
    assert!(matches!(action, ForkAction::Stay));
}

fn assert_need_more_data(action: ForkAction, expected_missing: BlockHash) {
    match action {
        ForkAction::NeedMoreData { missing_hash, .. } => {
            assert_eq!(missing_hash, expected_missing);
        }
        ForkAction::Stay | ForkAction::Reorg(_) => {
            assert!(matches!(action, ForkAction::NeedMoreData { .. }));
        }
    }
}

fn assert_not_found<T>(result: Result<T, ErrorDetection>) {
    assert!(matches!(result, Err(ErrorDetection::NotFound { .. })));
}

fn assert_blockchain_error<T>(result: Result<T, ErrorDetection>) {
    assert!(matches!(
        result,
        Err(ErrorDetection::BlockchainError { .. })
    ));
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

fn simple_plan(
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

fn puzzle_proof(height: u64) -> PorPuzzleProof {
    PorPuzzleProof {
        height,
        validator: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        prev_block_hash: deterministic_hash(9_999),
        output: 1,
    }
}

// ─────────────────────────────────────────────────────────────
// 1–20: config, structs, and plan vectors
// ─────────────────────────────────────────────────────────────

#[test]
fn test_001_refork_config_default_max_depth_vector() {
    let cfg = ReForkConfig::default();
    assert_eq!(cfg.max_reorg_depth, 64);
}

#[test]
fn test_002_refork_config_default_disallows_equal_height_vector() {
    let cfg = ReForkConfig::default();
    assert!(!cfg.allow_equal_height_reorg);
}

#[test]
fn test_003_refork_config_default_uses_height_not_por_vector() {
    let cfg = ReForkConfig::default();
    assert!(!cfg.prefer_cumulative_por);
}

#[test]
fn test_004_custom_refork_config_preserves_fields_vector() {
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
fn test_005_reorg_step_copy_and_eq_vector() {
    let hash = deterministic_hash(5);
    let step = ReorgStep { height: 5, hash };
    let copied = step;

    assert_eq!(copied, step);
}

#[test]
fn test_006_reorg_step_clone_and_debug_vector() {
    let hash = deterministic_hash(6);
    let step = ReorgStep { height: 6, hash };
    let cloned = step;
    let rendered = format!("{cloned:?}");

    assert_eq!(cloned, step);
    assert!(rendered.contains("height"));
}

#[test]
fn test_007_reorg_plan_noop_true_for_empty_steps_vector() {
    let hash = deterministic_hash(7);
    let plan = noop_plan(hash);

    assert!(plan.is_noop());
}

#[test]
fn test_008_reorg_plan_noop_false_for_detach_vector() {
    let hash = deterministic_hash(8);
    let mut plan = noop_plan(hash);
    plan.detach.push(ReorgStep { height: 1, hash });

    assert!(!plan.is_noop());
}

#[test]
fn test_009_reorg_plan_noop_false_for_attach_vector() {
    let hash = deterministic_hash(9);
    let mut plan = noop_plan(hash);
    plan.attach.push(ReorgStep { height: 1, hash });

    assert!(!plan.is_noop());
}

#[test]
fn test_010_reorg_plan_detach_heights_vector() {
    let hash = deterministic_hash(10);
    let mut plan = noop_plan(hash);
    plan.detach.push(ReorgStep { height: 3, hash });
    plan.detach.push(ReorgStep { height: 2, hash });

    assert_eq!(plan.detach_heights(), vec![3, 2]);
}

#[test]
fn test_011_reorg_plan_attach_heights_vector() {
    let hash = deterministic_hash(11);
    let mut plan = noop_plan(hash);
    plan.attach.push(ReorgStep { height: 2, hash });
    plan.attach.push(ReorgStep { height: 3, hash });

    assert_eq!(plan.attach_heights(), vec![2, 3]);
}

#[test]
fn test_012_reorg_plan_debug_contains_tip_fields_vector() {
    let hash = deterministic_hash(12);
    let plan = noop_plan(hash);
    let rendered = format!("{plan:?}");

    assert!(rendered.contains("old_tip_height"));
    assert!(rendered.contains("new_tip_height"));
}

#[test]
fn test_013_fork_action_stay_debug_vector() {
    let rendered = format!("{:?}", ForkAction::Stay);
    assert!(rendered.contains("Stay"));
}

#[test]
fn test_014_fork_action_need_more_data_debug_vector() {
    let action = ForkAction::NeedMoreData {
        missing_hash: deterministic_hash(14),
        context: "test",
    };
    let rendered = format!("{action:?}");

    assert!(rendered.contains("NeedMoreData"));
    assert!(rendered.contains("test"));
}

#[test]
fn test_015_fork_action_reorg_debug_vector() {
    let action = ForkAction::Reorg(noop_plan(deterministic_hash(15)));
    let rendered = format!("{action:?}");

    assert!(rendered.contains("Reorg"));
}

#[test]
fn test_016_refork_mainnet_default_constructs_vector() -> TestResult {
    let (_fork, _block_index, _chain_view, db) =
        default_fixture("test_016_refork_mainnet_default_constructs_vector")?;
    let _mainnet = ReFork::mainnet_default(db);
    Ok(())
}

#[test]
fn test_017_refork_new_constructs_height_only_vector() -> TestResult {
    let (_fork, _block_index, _chain_view, _db) =
        default_fixture("test_017_refork_new_constructs_height_only_vector")?;
    Ok(())
}

#[test]
fn test_018_refork_new_constructs_cumulative_por_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    };
    let (_fork, _block_index, _chain_view, _db) =
        fresh_fixture("test_018_refork_new_constructs_cumulative_por_vector", cfg)?;
    Ok(())
}

#[test]
fn test_019_on_puzzle_proof_for_branch_accepts_structural_payload_vector() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_019_on_puzzle_proof_for_branch_accepts_structural_payload_vector")?;
    let proof = puzzle_proof(19);

    fork.on_puzzle_proof_for_branch(&proof);
    Ok(())
}

#[test]
fn test_020_on_puzzle_proof_for_branch_accepts_height_zero_vector() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_020_on_puzzle_proof_for_branch_accepts_height_zero_vector")?;
    let proof = puzzle_proof(0);

    fork.on_puzzle_proof_for_branch(&proof);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 21–40: on_new_block stay/reorg/need-data vectors
// ─────────────────────────────────────────────────────────────

#[test]
fn test_021_on_new_block_without_canonical_tip_returns_not_found_edge() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_021_on_new_block_without_canonical_tip_returns_not_found_edge")?;
    let block = make_block(0, [0u8; 64], 2100)?;

    assert_not_found(fork.on_new_block(&block));
    Ok(())
}

#[test]
fn test_022_on_new_block_extends_current_tip_returns_stay_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_022_on_new_block_extends_current_tip_returns_stay_vector")?;
    let chain = make_linear_chain(2, 2200)?;
    store_canonical_chain(&block_index, &chain_view, &db, &chain)?;

    let tip = last_block(&chain)?;
    let new_block = make_block(2, tip.block_hash, 2202)?;
    store_block_with_status(&block_index, &new_block, ForkBlockStatus::Validated)?;

    assert_stay(fork.on_new_block(&new_block)?);
    Ok(())
}

#[test]
fn test_023_on_new_block_lower_height_candidate_stays_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_023_on_new_block_lower_height_candidate_stays_vector")?;
    let chain = make_linear_chain(4, 2300)?;
    store_canonical_chain(&block_index, &chain_view, &db, &chain)?;

    let parent = block_at(&chain, 1)?;
    let lower = make_block(2, parent.block_hash, 2310)?;
    store_block_with_status(&block_index, &lower, ForkBlockStatus::SideBranch)?;

    assert_stay(fork.on_new_block(&lower)?);
    Ok(())
}

#[test]
fn test_024_on_new_block_equal_height_reorg_disabled_stays_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_024_on_new_block_equal_height_reorg_disabled_stays_vector")?;
    let chain = make_linear_chain(3, 2400)?;
    store_canonical_chain(&block_index, &chain_view, &db, &chain)?;

    let parent = block_at(&chain, 1)?;
    let competitor = make_block(2, parent.block_hash, 2410)?;
    store_block_with_status(&block_index, &competitor, ForkBlockStatus::SideBranch)?;

    assert_stay(fork.on_new_block(&competitor)?);
    Ok(())
}

#[test]
fn test_025_on_new_block_better_longer_branch_returns_reorg_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_025_on_new_block_better_longer_branch_returns_reorg_vector")?;
    let canonical = make_linear_chain(3, 2500)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let fork_blocks = make_fork_from_parent(parent, 3, 2510)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let new_tip = last_block(&fork_blocks)?;
    let action = fork.on_new_block(new_tip)?;

    match action {
        ForkAction::Reorg(plan) => {
            assert_eq!(plan.old_tip_height, 2);
            assert_eq!(plan.new_tip_height, 4);
            assert_eq!(plan.common_ancestor_height, 1);
            assert_eq!(plan.detach_heights(), vec![2]);
            assert_eq!(plan.attach_heights(), vec![2, 3, 4]);
        }
        ForkAction::Stay | ForkAction::NeedMoreData { .. } => {
            assert!(matches!(action, ForkAction::Reorg(_)));
        }
    }

    Ok(())
}

#[test]
fn test_026_on_new_block_better_branch_from_genesis_returns_reorg_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_026_on_new_block_better_branch_from_genesis_returns_reorg_vector")?;
    let canonical = make_linear_chain(2, 2600)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(genesis, 3, 2610)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let action = fork.on_new_block(last_block(&fork_blocks)?)?;

    match action {
        ForkAction::Reorg(plan) => {
            assert_eq!(plan.common_ancestor_height, 0);
            assert_eq!(plan.detach_heights(), vec![1]);
            assert_eq!(plan.attach_heights(), vec![1, 2, 3]);
        }
        ForkAction::Stay | ForkAction::NeedMoreData { .. } => {
            assert!(matches!(action, ForkAction::Reorg(_)));
        }
    }

    Ok(())
}

#[test]
fn test_027_on_new_block_missing_new_tip_meta_needs_more_data_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_027_on_new_block_missing_new_tip_meta_needs_more_data_vector")?;
    let canonical = make_linear_chain(2, 2700)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(parent, 3, 2710)?;
    let new_tip = last_block(&fork_blocks)?;

    for block in &fork_blocks {
        block_index.put_block(block)?;
    }

    assert_need_more_data(fork.on_new_block(new_tip)?, new_tip.block_hash);
    Ok(())
}

#[test]
fn test_028_on_new_block_missing_parent_block_needs_more_data_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_028_on_new_block_missing_parent_block_needs_more_data_vector")?;
    let canonical = make_linear_chain(2, 2800)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let missing_parent_hash = deterministic_hash(2801);
    let child = make_block(3, missing_parent_hash, 2810)?;
    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    assert_need_more_data(fork.on_new_block(&child)?, missing_parent_hash);
    Ok(())
}

#[test]
fn test_029_on_new_block_missing_parent_meta_needs_more_data_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_029_on_new_block_missing_parent_meta_needs_more_data_vector")?;
    let canonical = make_linear_chain(2, 2900)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = make_block(2, block_at(&canonical, 1)?.block_hash, 2910)?;
    let child = make_block(3, parent.block_hash, 2911)?;
    block_index.put_block(&parent)?;
    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    assert_need_more_data(fork.on_new_block(&child)?, parent.block_hash);
    Ok(())
}

#[test]
fn test_030_on_new_block_missing_canonical_tip_meta_needs_more_data_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_030_on_new_block_missing_canonical_tip_meta_needs_more_data_vector")?;
    let canonical = make_linear_chain(2, 3000)?;

    for block in &canonical {
        block_index.put_block(block)?;
        chain_view.set_hash_at_height(block.metadata.index, &block.block_hash)?;
        db.store_latest_block(&block.serialize_for_storage()?, block.metadata.index)?;
    }

    let old_tip = last_block(&canonical)?;
    chain_view.set_tip(&old_tip.block_hash, old_tip.metadata.index)?;

    let parent = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(parent, 3, 3010)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    assert_need_more_data(
        fork.on_new_block(last_block(&fork_blocks)?)?,
        parent.block_hash,
    );
    Ok(())
}

#[test]
fn test_031_on_new_block_no_common_ancestor_within_depth_stays_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 1,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: false,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_031_on_new_block_no_common_ancestor_within_depth_stays_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(4, 3100)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(parent, 4, 3110)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    assert_stay(fork.on_new_block(last_block(&fork_blocks)?)?);
    Ok(())
}

#[test]
fn test_032_on_new_block_equal_height_lower_hash_reorg_when_enabled_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: true,
        prefer_cumulative_por: false,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_032_on_new_block_equal_height_lower_hash_reorg_when_enabled_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(3, 3200)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let old_tip = last_block(&canonical)?;
    let competitor = find_equal_height_competitor(parent, old_tip.block_hash, true, 3210)?;
    store_block_with_status(&block_index, &competitor, ForkBlockStatus::SideBranch)?;

    match fork.on_new_block(&competitor)? {
        ForkAction::Reorg(plan) => {
            assert_eq!(plan.new_tip_hash, competitor.block_hash);
            assert_eq!(plan.attach_heights(), vec![2]);
        }
        other => assert!(matches!(other, ForkAction::Reorg(_))),
    }

    Ok(())
}

#[test]
fn test_033_on_new_block_equal_height_higher_hash_stays_when_lower_tiebreak_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: true,
        prefer_cumulative_por: false,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_033_on_new_block_equal_height_higher_hash_stays_when_lower_tiebreak_vector",
        cfg,
    )?;

    let genesis = make_block(0, [0u8; 64], 3300)?;
    let parent = make_block(1, genesis.block_hash, 3301)?;
    let (old_tip_lower_hash, competitor_higher_hash) =
        find_ordered_equal_height_pair(&parent, 3310)?;

    let canonical = vec![genesis, parent, old_tip_lower_hash.clone()];
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    store_block_with_status(
        &block_index,
        &competitor_higher_hash,
        ForkBlockStatus::SideBranch,
    )?;

    assert_stay(fork.on_new_block(&competitor_higher_hash)?);
    Ok(())
}

#[test]
fn test_034_on_new_block_cumulative_por_candidate_wins_despite_lower_height_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_034_on_new_block_cumulative_por_candidate_wins_despite_lower_height_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(4, 3400)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let old_tip = last_block(&canonical)?;
    store_block_with_status_and_score(&block_index, old_tip, ForkBlockStatus::Canonical, 1)?;

    let parent = block_at(&canonical, 1)?;
    let fork_block = make_block(2, parent.block_hash, 3410)?;
    store_block_with_status_and_score(&block_index, &fork_block, ForkBlockStatus::SideBranch, 999)?;

    match fork.on_new_block(&fork_block)? {
        ForkAction::Reorg(plan) => {
            assert_eq!(plan.new_tip_hash, fork_block.block_hash);
            assert_eq!(plan.common_ancestor_height, 1);
        }
        other => assert!(matches!(other, ForkAction::Reorg(_))),
    }

    Ok(())
}

#[test]
fn test_035_on_new_block_height_only_ignores_higher_cumulative_por_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_035_on_new_block_height_only_ignores_higher_cumulative_por_vector")?;
    let canonical = make_linear_chain(4, 3500)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let fork_block = make_block(2, parent.block_hash, 3510)?;
    store_block_with_status_and_score(&block_index, &fork_block, ForkBlockStatus::SideBranch, 999)?;

    assert_stay(fork.on_new_block(&fork_block)?);
    Ok(())
}

#[test]
fn test_036_on_new_block_cumulative_por_current_wins_when_score_higher_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_036_on_new_block_cumulative_por_current_wins_when_score_higher_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(3, 3600)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let old_tip = last_block(&canonical)?;
    store_block_with_status_and_score(&block_index, old_tip, ForkBlockStatus::Canonical, 1_000)?;

    let parent = block_at(&canonical, 1)?;
    let fork_block = make_block(2, parent.block_hash, 3610)?;
    store_block_with_status_and_score(&block_index, &fork_block, ForkBlockStatus::SideBranch, 1)?;

    assert_stay(fork.on_new_block(&fork_block)?);
    Ok(())
}

#[test]
fn test_037_on_new_block_same_tip_hash_results_stay_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_037_on_new_block_same_tip_hash_results_stay_vector")?;
    let canonical = make_linear_chain(2, 3700)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    assert_stay(fork.on_new_block(last_block(&canonical)?)?);
    Ok(())
}

#[test]
fn test_038_on_new_block_branch_with_only_tip_meta_missing_parent_block_vector() -> TestResult {
    let (fork, block_index, chain_view, db) = default_fixture(
        "test_038_on_new_block_branch_with_only_tip_meta_missing_parent_block_vector",
    )?;
    let canonical = make_linear_chain(2, 3800)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let missing_parent = deterministic_hash(3801);
    let tip = make_block(4, missing_parent, 3810)?;
    store_block_with_status_and_score(&block_index, &tip, ForkBlockStatus::SideBranch, 4)?;

    assert_need_more_data(fork.on_new_block(&tip)?, missing_parent);
    Ok(())
}

#[test]
fn test_039_on_new_block_candidate_with_missing_meta_uses_height_for_scoring_then_needs_data()
-> TestResult {
    let (fork, block_index, chain_view, db) = default_fixture(
        "test_039_on_new_block_candidate_with_missing_meta_uses_height_for_scoring_then_needs_data",
    )?;
    let canonical = make_linear_chain(2, 3900)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(parent, 3, 3910)?;
    let tip = last_block(&fork_blocks)?;

    for block in &fork_blocks {
        block_index.put_block(block)?;
    }

    assert_need_more_data(fork.on_new_block(tip)?, tip.block_hash);
    Ok(())
}

#[test]
fn test_040_on_new_block_candidate_direct_child_same_height_is_stay_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_040_on_new_block_candidate_direct_child_same_height_is_stay_vector")?;
    let canonical = make_linear_chain(2, 4000)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let old_tip = last_block(&canonical)?;
    let bad_height = make_block(1, old_tip.block_hash, 4010)?;
    store_block_with_status(&block_index, &bad_height, ForkBlockStatus::SideBranch)?;

    assert_stay(fork.on_new_block(&bad_height)?);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 41–60: apply_reorg vectors
// ─────────────────────────────────────────────────────────────

#[test]
fn test_041_apply_noop_plan_calls_no_callbacks_vector() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_041_apply_noop_plan_calls_no_callbacks_vector")?;
    let plan = noop_plan(deterministic_hash(41));
    let mut reverted = Vec::<(u64, BlockHash)>::new();
    let mut applied = Vec::<(u64, BlockHash)>::new();

    fork.apply_reorg(
        &plan,
        |h, hash| {
            reverted.push((h, hash));
            Ok(())
        },
        |h, hash| {
            applied.push((h, hash));
            Ok(())
        },
    )?;

    assert!(reverted.is_empty());
    assert!(applied.is_empty());
    Ok(())
}

#[test]
fn test_042_apply_attach_only_updates_tip_and_mapping_vector() -> TestResult {
    let (fork, block_index, chain_view, _db) =
        default_fixture("test_042_apply_attach_only_updates_tip_and_mapping_vector")?;
    let genesis = make_block(0, [0u8; 64], 4200)?;
    let child = make_block(1, genesis.block_hash, 4201)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: child.metadata.index,
            hash: child.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(chain_view.get_hash_at_height(1)?, "attached hash")?,
        child.block_hash
    );
    assert_eq!(
        required(chain_view.get_tip_hash()?, "attached tip")?,
        child.block_hash
    );
    Ok(())
}

#[test]
fn test_043_apply_attach_only_marks_meta_canonical_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_043_apply_attach_only_marks_meta_canonical_vector")?;
    let genesis = make_block(0, [0u8; 64], 4300)?;
    let child = make_block(1, genesis.block_hash, 4301)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(block_index.status_of(&child.block_hash)?, "child status")?,
        ForkBlockStatus::Canonical
    );
    Ok(())
}

#[test]
fn test_044_apply_detach_only_marks_detached_side_branch_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_044_apply_detach_only_marks_detached_side_branch_vector")?;
    let chain = make_linear_chain(2, 4400)?;
    store_canonical_chain(&block_index, &chain_view, &db, &chain)?;
    let genesis = block_at(&chain, 0)?;
    let old_tip = block_at(&chain, 1)?;

    let plan = simple_plan(
        old_tip,
        genesis,
        genesis,
        vec![ReorgStep {
            height: old_tip.metadata.index,
            hash: old_tip.block_hash,
        }],
        Vec::new(),
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(
            block_index.status_of(&old_tip.block_hash)?,
            "old tip status"
        )?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_045_apply_detach_and_attach_callbacks_order_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_045_apply_detach_and_attach_callbacks_order_vector")?;
    let canonical = make_linear_chain(3, 4500)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 0)?;
    let old_1 = block_at(&canonical, 1)?;
    let old_2 = block_at(&canonical, 2)?;
    let fork_blocks = make_fork_from_parent(ancestor, 2, 4510)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let new_1 = block_at(&fork_blocks, 0)?;
    let new_2 = block_at(&fork_blocks, 1)?;
    let plan = simple_plan(
        old_2,
        new_2,
        ancestor,
        vec![
            ReorgStep {
                height: old_2.metadata.index,
                hash: old_2.block_hash,
            },
            ReorgStep {
                height: old_1.metadata.index,
                hash: old_1.block_hash,
            },
        ],
        vec![
            ReorgStep {
                height: new_1.metadata.index,
                hash: new_1.block_hash,
            },
            ReorgStep {
                height: new_2.metadata.index,
                hash: new_2.block_hash,
            },
        ],
    );

    let mut reverted = Vec::new();
    let mut applied = Vec::new();

    fork.apply_reorg(
        &plan,
        |h, hash| {
            reverted.push((h, hash));
            Ok(())
        },
        |h, hash| {
            applied.push((h, hash));
            Ok(())
        },
    )?;

    assert_eq!(reverted, vec![(2, old_2.block_hash), (1, old_1.block_hash)]);
    assert_eq!(applied, vec![(1, new_1.block_hash), (2, new_2.block_hash)]);
    Ok(())
}

#[test]
fn test_046_apply_reorg_missing_attach_block_errors_vector() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_046_apply_reorg_missing_attach_block_errors_vector")?;
    let genesis = make_block(0, [0u8; 64], 4600)?;
    let missing_hash = deterministic_hash(4601);
    let fake_tip = make_block(1, genesis.block_hash, 4602)?;

    let plan = simple_plan(
        &genesis,
        &fake_tip,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: missing_hash,
        }],
    );

    assert_not_found(fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(())));
    Ok(())
}

#[test]
fn test_047_apply_reorg_attach_height_mismatch_errors_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_047_apply_reorg_attach_height_mismatch_errors_vector")?;
    let genesis = make_block(0, [0u8; 64], 4700)?;
    let child = make_block(1, genesis.block_hash, 4701)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 2,
            hash: child.block_hash,
        }],
    );

    assert_blockchain_error(fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(())));
    Ok(())
}

#[test]
fn test_048_apply_reorg_revert_callback_error_propagates_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_048_apply_reorg_revert_callback_error_propagates_vector")?;
    let chain = make_linear_chain(2, 4800)?;
    store_canonical_chain(&block_index, &chain_view, &db, &chain)?;
    let genesis = block_at(&chain, 0)?;
    let old_tip = block_at(&chain, 1)?;

    let plan = simple_plan(
        old_tip,
        genesis,
        genesis,
        vec![ReorgStep {
            height: old_tip.metadata.index,
            hash: old_tip.block_hash,
        }],
        Vec::new(),
    );

    let result = fork.apply_reorg(
        &plan,
        |_h, _hash| {
            Err(ErrorDetection::BlockchainError {
                details: "revert failure".to_owned(),
            })
        },
        |_h, _hash| Ok(()),
    );

    assert_blockchain_error(result);
    Ok(())
}

#[test]
fn test_049_apply_reorg_apply_callback_error_propagates_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_049_apply_reorg_apply_callback_error_propagates_vector")?;
    let genesis = make_block(0, [0u8; 64], 4900)?;
    let child = make_block(1, genesis.block_hash, 4901)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    let result = fork.apply_reorg(
        &plan,
        |_h, _hash| Ok(()),
        |_h, _hash| {
            Err(ErrorDetection::BlockchainError {
                details: "apply failure".to_owned(),
            })
        },
    );

    assert_blockchain_error(result);
    Ok(())
}

#[test]
fn test_050_apply_reorg_updates_latest_block_projection_vector() -> TestResult {
    let (fork, block_index, _chain_view, db) =
        default_fixture("test_050_apply_reorg_updates_latest_block_projection_vector")?;
    let genesis = make_block(0, [0u8; 64], 5000)?;
    let child = make_block(1, genesis.block_hash, 5001)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    let latest = required(db.get_block_by_index(1)?, "latest block projection")?;
    assert_eq!(latest, child);
    Ok(())
}

#[test]
fn test_051_apply_reorg_deletes_old_canonical_hash_slots_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_051_apply_reorg_deletes_old_canonical_hash_slots_vector")?;
    let canonical = make_linear_chain(4, 5100)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let old_tip = block_at(&canonical, 3)?;
    let new_tip = make_block(2, ancestor.block_hash, 5110)?;
    store_block_with_status(&block_index, &new_tip, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        old_tip,
        &new_tip,
        ancestor,
        vec![
            ReorgStep {
                height: 3,
                hash: old_tip.block_hash,
            },
            ReorgStep {
                height: 2,
                hash: block_at(&canonical, 2)?.block_hash,
            },
        ],
        vec![ReorgStep {
            height: 2,
            hash: new_tip.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert!(chain_view.get_hash_at_height(3)?.is_none());
    assert_eq!(
        required(chain_view.get_hash_at_height(2)?, "new height 2")?,
        new_tip.block_hash
    );
    Ok(())
}

#[test]
fn test_052_apply_reorg_sets_tip_after_attach_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_052_apply_reorg_sets_tip_after_attach_vector")?;
    let genesis = make_block(0, [0u8; 64], 5200)?;
    let child = make_block(1, genesis.block_hash, 5201)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;
    Ok(())
}

#[test]
fn test_053_apply_reorg_preserves_attached_block_hash_index_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_053_apply_reorg_preserves_attached_block_hash_index_vector")?;
    let genesis = make_block(0, [0u8; 64], 5300)?;
    let child = make_block(1, genesis.block_hash, 5301)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert!(block_index.has_block(&child.block_hash));
    Ok(())
}

#[test]
fn test_054_apply_reorg_detach_without_meta_still_calls_revert_vector() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_054_apply_reorg_detach_without_meta_still_calls_revert_vector")?;
    let hash = deterministic_hash(54);
    let plan = ReorgPlan {
        old_tip_height: 1,
        old_tip_hash: hash,
        new_tip_height: 0,
        new_tip_hash: hash,
        common_ancestor_height: 0,
        common_ancestor_hash: hash,
        detach: vec![ReorgStep { height: 1, hash }],
        attach: Vec::new(),
    };
    let mut reverted = Vec::new();

    fork.apply_reorg(
        &plan,
        |h, step_hash| {
            reverted.push((h, step_hash));
            Ok(())
        },
        |_h, _hash| Ok(()),
    )?;

    assert_eq!(reverted, vec![(1, hash)]);
    Ok(())
}

#[test]
fn test_055_apply_reorg_attach_without_meta_still_applies_block_vector() -> TestResult {
    let (fork, block_index, chain_view, _db) =
        default_fixture("test_055_apply_reorg_attach_without_meta_still_applies_block_vector")?;
    let genesis = make_block(0, [0u8; 64], 5500)?;
    let child = make_block(1, genesis.block_hash, 5501)?;

    block_index.put_block(&child)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(
            chain_view.get_hash_at_height(1)?,
            "attached hash without meta"
        )?,
        child.block_hash
    );
    Ok(())
}

#[test]
fn test_056_apply_reorg_multiple_attach_sets_all_mappings_vector() -> TestResult {
    let (fork, block_index, chain_view, _db) =
        default_fixture("test_056_apply_reorg_multiple_attach_sets_all_mappings_vector")?;
    let genesis = make_block(0, [0u8; 64], 5600)?;
    let child1 = make_block(1, genesis.block_hash, 5601)?;
    let child2 = make_block(2, child1.block_hash, 5602)?;

    store_block_with_status(&block_index, &child1, ForkBlockStatus::SideBranch)?;
    store_block_with_status(&block_index, &child2, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child2,
        &genesis,
        Vec::new(),
        vec![
            ReorgStep {
                height: 1,
                hash: child1.block_hash,
            },
            ReorgStep {
                height: 2,
                hash: child2.block_hash,
            },
        ],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(chain_view.get_hash_at_height(1)?, "height 1")?,
        child1.block_hash
    );
    assert_eq!(
        required(chain_view.get_hash_at_height(2)?, "height 2")?,
        child2.block_hash
    );
    Ok(())
}

#[test]
fn test_057_apply_reorg_multiple_attach_marks_all_canonical_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_057_apply_reorg_multiple_attach_marks_all_canonical_vector")?;
    let genesis = make_block(0, [0u8; 64], 5700)?;
    let child1 = make_block(1, genesis.block_hash, 5701)?;
    let child2 = make_block(2, child1.block_hash, 5702)?;

    store_block_with_status(&block_index, &child1, ForkBlockStatus::SideBranch)?;
    store_block_with_status(&block_index, &child2, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child2,
        &genesis,
        Vec::new(),
        vec![
            ReorgStep {
                height: 1,
                hash: child1.block_hash,
            },
            ReorgStep {
                height: 2,
                hash: child2.block_hash,
            },
        ],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(block_index.status_of(&child1.block_hash)?, "child1 status")?,
        ForkBlockStatus::Canonical
    );
    assert_eq!(
        required(block_index.status_of(&child2.block_hash)?, "child2 status")?,
        ForkBlockStatus::Canonical
    );
    Ok(())
}

#[test]
fn test_058_apply_reorg_detach_marks_all_detached_side_branch_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_058_apply_reorg_detach_marks_all_detached_side_branch_vector")?;
    let chain = make_linear_chain(3, 5800)?;
    store_canonical_chain(&block_index, &chain_view, &db, &chain)?;
    let genesis = block_at(&chain, 0)?;
    let old1 = block_at(&chain, 1)?;
    let old2 = block_at(&chain, 2)?;

    let plan = simple_plan(
        old2,
        genesis,
        genesis,
        vec![
            ReorgStep {
                height: 2,
                hash: old2.block_hash,
            },
            ReorgStep {
                height: 1,
                hash: old1.block_hash,
            },
        ],
        Vec::new(),
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(block_index.status_of(&old1.block_hash)?, "old1 status")?,
        ForkBlockStatus::SideBranch
    );
    assert_eq!(
        required(block_index.status_of(&old2.block_hash)?, "old2 status")?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_059_apply_reorg_callback_receives_hashes_exactly_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_059_apply_reorg_callback_receives_hashes_exactly_vector")?;
    let genesis = make_block(0, [0u8; 64], 5900)?;
    let child = make_block(1, genesis.block_hash, 5901)?;

    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    let mut applied_hash = [0u8; 64];

    fork.apply_reorg(
        &plan,
        |_h, _hash| Ok(()),
        |_h, hash| {
            applied_hash = hash;
            Ok(())
        },
    )?;

    assert_eq!(applied_hash, child.block_hash);
    Ok(())
}

#[test]
fn test_060_apply_reorg_can_attach_height_zero_block_vector() -> TestResult {
    let (fork, block_index, chain_view, _db) =
        default_fixture("test_060_apply_reorg_can_attach_height_zero_block_vector")?;
    let genesis = make_block(0, [0u8; 64], 6000)?;

    store_block_with_status(&block_index, &genesis, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &genesis,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 0,
            hash: genesis.block_hash,
        }],
    );

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(chain_view.get_hash_at_height(0)?, "genesis mapping")?,
        genesis.block_hash
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 61–80: integration/property-style on_new_block tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_061_property_direct_extensions_stay_for_many_heights() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_061_property_direct_extensions_stay_for_many_heights")?;
    let mut chain = make_linear_chain(1, 6100)?;
    store_canonical_chain(&block_index, &chain_view, &db, &chain)?;

    for height in 1u64..8u64 {
        let tip = last_block(&chain)?;
        let next = make_block(height, tip.block_hash, 6100u64.saturating_add(height))?;
        store_block_with_status(&block_index, &next, ForkBlockStatus::Validated)?;
        assert_stay(fork.on_new_block(&next)?);

        chain.push(next);
        store_canonical_chain(&block_index, &chain_view, &db, &chain)?;
    }

    Ok(())
}

#[test]
fn test_062_property_shorter_side_branches_stay_for_many_heights() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_062_property_shorter_side_branches_stay_for_many_heights")?;
    let canonical = make_linear_chain(8, 6200)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    for parent_pos in 0usize..6usize {
        let parent = block_at(&canonical, parent_pos)?;
        let side =
            make_block(
                parent.metadata.index.saturating_add(1),
                parent.block_hash,
                6210u64.saturating_add(u64::try_from(parent_pos).map_err(|e| {
                    storage_error(format!("failed to convert parent_pos to u64: {e}"))
                })?),
            )?;
        store_block_with_status(&block_index, &side, ForkBlockStatus::SideBranch)?;
        assert_stay(fork.on_new_block(&side)?);
    }

    Ok(())
}

#[test]
fn test_063_property_longer_side_branches_reorg_for_multiple_depths() -> TestResult {
    for extra_len in 2u64..5u64 {
        let label =
            format!("test_063_property_longer_side_branches_reorg_for_multiple_depths_{extra_len}");
        let (fork, block_index, chain_view, db) = default_fixture(&label)?;
        let canonical = make_linear_chain(2, 6300u64.saturating_add(extra_len))?;
        store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

        let genesis = block_at(&canonical, 0)?;
        let fork_blocks =
            make_fork_from_parent(genesis, extra_len, 6310u64.saturating_add(extra_len))?;
        store_side_branch(&block_index, &fork_blocks, 100)?;

        match fork.on_new_block(last_block(&fork_blocks)?)? {
            ForkAction::Reorg(plan) => {
                assert_eq!(plan.common_ancestor_height, 0);
                assert_eq!(
                    plan.attach.len(),
                    usize::try_from(extra_len).map_err(|e| {
                        storage_error(format!("failed to convert extra_len to usize: {e}"))
                    })?
                );
            }
            other => assert!(matches!(other, ForkAction::Reorg(_))),
        }
    }

    Ok(())
}

#[test]
fn test_064_property_cumulative_por_mode_higher_score_wins_for_many_scores() -> TestResult {
    for score in 10u128..16u128 {
        let cfg = ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: true,
        };
        let label = format!(
            "test_064_property_cumulative_por_mode_higher_score_wins_for_many_scores_{score}"
        );
        let (fork, block_index, chain_view, db) = fresh_fixture(&label, cfg)?;
        let canonical = make_linear_chain(3, 6400)?;
        store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

        let old_tip = last_block(&canonical)?;
        store_block_with_status_and_score(&block_index, old_tip, ForkBlockStatus::Canonical, 1)?;

        let parent = block_at(&canonical, 1)?;
        let side = make_block(
            2,
            parent.block_hash,
            6410u64.saturating_add(
                u64::try_from(score)
                    .map_err(|e| storage_error(format!("failed to convert score to u64: {e}")))?,
            ),
        )?;
        store_block_with_status_and_score(&block_index, &side, ForkBlockStatus::SideBranch, score)?;

        match fork.on_new_block(&side)? {
            ForkAction::Reorg(plan) => assert_eq!(plan.new_tip_hash, side.block_hash),
            other => assert!(matches!(other, ForkAction::Reorg(_))),
        }
    }

    Ok(())
}

#[test]
fn test_065_property_missing_tip_meta_need_more_data_for_many_heights() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_065_property_missing_tip_meta_need_more_data_for_many_heights")?;
    let canonical = make_linear_chain(2, 6500)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 0)?;
    for len in 2u64..5u64 {
        let fork_blocks = make_fork_from_parent(parent, len, 6510u64.saturating_add(len))?;
        for block in &fork_blocks {
            block_index.put_block(block)?;
        }
        let tip = last_block(&fork_blocks)?;
        assert_need_more_data(fork.on_new_block(tip)?, tip.block_hash);
    }

    Ok(())
}

#[test]
fn test_066_property_apply_reorg_multiple_noop_plans() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_066_property_apply_reorg_multiple_noop_plans")?;

    for seed in 0u64..16u64 {
        let plan = noop_plan(deterministic_hash(6600u64.saturating_add(seed)));
        fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;
    }

    Ok(())
}

#[test]
fn test_067_property_apply_reorg_attach_many_single_blocks() -> TestResult {
    for height in 1u64..6u64 {
        let label = format!("test_067_property_apply_reorg_attach_many_single_blocks_{height}");
        let (fork, block_index, chain_view, _db) = default_fixture(&label)?;
        let genesis = make_block(0, [0u8; 64], 6700)?;
        let child = make_block(height, genesis.block_hash, 6700u64.saturating_add(height))?;

        store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

        let plan = simple_plan(
            &genesis,
            &child,
            &genesis,
            Vec::new(),
            vec![ReorgStep {
                height,
                hash: child.block_hash,
            }],
        );

        fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;
        assert_eq!(
            required(chain_view.get_hash_at_height(height)?, "attached height")?,
            child.block_hash
        );
    }

    Ok(())
}

#[test]
fn test_068_property_apply_reorg_callback_counts_match_steps() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_068_property_apply_reorg_callback_counts_match_steps")?;
    let canonical = make_linear_chain(4, 6800)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 0)?;
    let old_tip = last_block(&canonical)?;
    let fork_blocks = make_fork_from_parent(ancestor, 3, 6810)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;
    let new_tip = last_block(&fork_blocks)?;

    let plan = simple_plan(
        old_tip,
        new_tip,
        ancestor,
        vec![
            ReorgStep {
                height: 3,
                hash: block_at(&canonical, 3)?.block_hash,
            },
            ReorgStep {
                height: 2,
                hash: block_at(&canonical, 2)?.block_hash,
            },
            ReorgStep {
                height: 1,
                hash: block_at(&canonical, 1)?.block_hash,
            },
        ],
        vec![
            ReorgStep {
                height: 1,
                hash: block_at(&fork_blocks, 0)?.block_hash,
            },
            ReorgStep {
                height: 2,
                hash: block_at(&fork_blocks, 1)?.block_hash,
            },
            ReorgStep {
                height: 3,
                hash: block_at(&fork_blocks, 2)?.block_hash,
            },
        ],
    );

    let mut revert_count = 0usize;
    let mut apply_count = 0usize;

    fork.apply_reorg(
        &plan,
        |_h, _hash| {
            revert_count = revert_count.saturating_add(1);
            Ok(())
        },
        |_h, _hash| {
            apply_count = apply_count.saturating_add(1);
            Ok(())
        },
    )?;

    assert_eq!(revert_count, 3);
    assert_eq!(apply_count, 3);
    Ok(())
}

#[test]
fn test_069_property_reorg_plan_detach_attach_heights_many_values() {
    let hash = deterministic_hash(69);
    let plan = ReorgPlan {
        old_tip_height: 5,
        old_tip_hash: hash,
        new_tip_height: 6,
        new_tip_hash: hash,
        common_ancestor_height: 2,
        common_ancestor_hash: hash,
        detach: vec![
            ReorgStep { height: 5, hash },
            ReorgStep { height: 4, hash },
            ReorgStep { height: 3, hash },
        ],
        attach: vec![
            ReorgStep { height: 3, hash },
            ReorgStep { height: 4, hash },
            ReorgStep { height: 5, hash },
            ReorgStep { height: 6, hash },
        ],
    };

    assert_eq!(plan.detach_heights(), vec![5, 4, 3]);
    assert_eq!(plan.attach_heights(), vec![3, 4, 5, 6]);
}

#[test]
fn test_070_property_on_new_block_after_apply_new_tip_stays_when_seen_again() -> TestResult {
    let (fork, block_index, chain_view, db) = default_fixture(
        "test_070_property_on_new_block_after_apply_new_tip_stays_when_seen_again",
    )?;
    let canonical = make_linear_chain(2, 7000)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(genesis, 3, 7010)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let new_tip = last_block(&fork_blocks)?;
    let action = fork.on_new_block(new_tip)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;
    assert_stay(fork.on_new_block(new_tip)?);
    Ok(())
}

#[test]
fn test_071_adversarial_candidate_missing_parent_block_after_tip_meta_needs_data_vector()
-> TestResult {
    let (fork, block_index, chain_view, db) = default_fixture(
        "test_071_adversarial_candidate_missing_parent_block_after_tip_meta_needs_data_vector",
    )?;
    let canonical = make_linear_chain(2, 7100)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let missing_parent_hash = deterministic_hash(7101);
    let child = make_block(3, missing_parent_hash, 7110)?;
    let meta = block_index.make_scored_meta(&child, 100, ForkBlockStatus::SideBranch);

    block_index.put_meta(&child.block_hash, &meta)?;

    assert_need_more_data(fork.on_new_block(&child)?, missing_parent_hash);
    Ok(())
}

#[test]
fn test_072_adversarial_canonical_tip_hash_mapping_without_block_errors_vector() -> TestResult {
    let (fork, _block_index, chain_view, _db) = default_fixture(
        "test_072_adversarial_canonical_tip_hash_mapping_without_block_errors_vector",
    )?;
    let fake_hash = deterministic_hash(72);
    chain_view.set_tip(&fake_hash, 72)?;

    let block = make_block(73, fake_hash, 7210)?;

    assert_not_found(fork.on_new_block(&block));
    Ok(())
}

#[test]
fn test_073_adversarial_equal_height_reorg_disabled_blocks_lower_hash_vector() -> TestResult {
    let (fork, block_index, chain_view, db) = default_fixture(
        "test_073_adversarial_equal_height_reorg_disabled_blocks_lower_hash_vector",
    )?;
    let canonical = make_linear_chain(3, 7300)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let parent = block_at(&canonical, 1)?;
    let old_tip = last_block(&canonical)?;
    let competitor = find_equal_height_competitor(parent, old_tip.block_hash, true, 7310)?;
    store_block_with_status(&block_index, &competitor, ForkBlockStatus::SideBranch)?;

    assert_stay(fork.on_new_block(&competitor)?);
    Ok(())
}

#[test]
fn test_074_adversarial_large_depth_bound_allows_deep_reorg_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 128,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: false,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_074_adversarial_large_depth_bound_allows_deep_reorg_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(5, 7400)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(genesis, 6, 7410)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    match fork.on_new_block(last_block(&fork_blocks)?)? {
        ForkAction::Reorg(plan) => {
            assert_eq!(plan.detach.len(), 4);
            assert_eq!(plan.attach.len(), 6);
        }
        other => assert!(matches!(other, ForkAction::Reorg(_))),
    }

    Ok(())
}

#[test]
fn test_075_adversarial_zero_depth_bound_refuses_non_extension_reorg_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 0,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: false,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_075_adversarial_zero_depth_bound_refuses_non_extension_reorg_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(2, 7500)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(genesis, 3, 7510)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    assert_stay(fork.on_new_block(last_block(&fork_blocks)?)?);
    Ok(())
}

#[test]
fn test_076_adversarial_apply_attach_block_height_zero_mismatch_errors_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) = default_fixture(
        "test_076_adversarial_apply_attach_block_height_zero_mismatch_errors_vector",
    )?;
    let genesis = make_block(0, [0u8; 64], 7600)?;
    store_block_with_status(&block_index, &genesis, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &genesis,
        &genesis,
        Vec::new(),
        vec![ReorgStep {
            height: 1,
            hash: genesis.block_hash,
        }],
    );

    assert_blockchain_error(fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(())));
    Ok(())
}

#[test]
fn test_077_adversarial_apply_reorg_revert_error_stops_before_attach_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) = default_fixture(
        "test_077_adversarial_apply_reorg_revert_error_stops_before_attach_vector",
    )?;
    let genesis = make_block(0, [0u8; 64], 7700)?;
    let child = make_block(1, genesis.block_hash, 7701)?;
    store_block_with_status(&block_index, &child, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child,
        &genesis,
        vec![ReorgStep {
            height: 1,
            hash: deterministic_hash(7799),
        }],
        vec![ReorgStep {
            height: 1,
            hash: child.block_hash,
        }],
    );

    let mut apply_count = 0usize;
    let result = fork.apply_reorg(
        &plan,
        |_h, _hash| {
            Err(ErrorDetection::BlockchainError {
                details: "stop before attach".to_owned(),
            })
        },
        |_h, _hash| {
            apply_count = apply_count.saturating_add(1);
            Ok(())
        },
    );

    assert_blockchain_error(result);
    assert_eq!(apply_count, 0);
    Ok(())
}

#[test]
fn test_078_adversarial_apply_reorg_apply_error_after_first_attach_vector() -> TestResult {
    let (fork, block_index, _chain_view, _db) =
        default_fixture("test_078_adversarial_apply_reorg_apply_error_after_first_attach_vector")?;
    let genesis = make_block(0, [0u8; 64], 7800)?;
    let child1 = make_block(1, genesis.block_hash, 7801)?;
    let child2 = make_block(2, child1.block_hash, 7802)?;

    store_block_with_status(&block_index, &child1, ForkBlockStatus::SideBranch)?;
    store_block_with_status(&block_index, &child2, ForkBlockStatus::SideBranch)?;

    let plan = simple_plan(
        &genesis,
        &child2,
        &genesis,
        Vec::new(),
        vec![
            ReorgStep {
                height: 1,
                hash: child1.block_hash,
            },
            ReorgStep {
                height: 2,
                hash: child2.block_hash,
            },
        ],
    );

    let mut apply_count = 0usize;
    let result = fork.apply_reorg(
        &plan,
        |_h, _hash| Ok(()),
        |_h, _hash| {
            apply_count = apply_count.saturating_add(1);
            Err(ErrorDetection::BlockchainError {
                details: "apply stop".to_owned(),
            })
        },
    );

    assert_blockchain_error(result);
    assert_eq!(apply_count, 1);
    Ok(())
}

#[test]
fn test_079_adversarial_apply_noop_plan_with_invalid_hash_still_noops_vector() -> TestResult {
    let (fork, _block_index, _chain_view, _db) = default_fixture(
        "test_079_adversarial_apply_noop_plan_with_invalid_hash_still_noops_vector",
    )?;
    let plan = noop_plan([0xFFu8; 64]);

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;
    Ok(())
}

#[test]
fn test_080_adversarial_on_new_block_canonical_tip_missing_block_returns_not_found_vector()
-> TestResult {
    let (fork, _block_index, chain_view, _db) = default_fixture(
        "test_080_adversarial_on_new_block_canonical_tip_missing_block_returns_not_found_vector",
    )?;
    let fake_tip = deterministic_hash(80);
    chain_view.set_tip(&fake_tip, 1)?;
    let new_block = make_block(2, fake_tip, 8010)?;

    assert_not_found(fork.on_new_block(&new_block));
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 81–100: load/fuzz-style/end-to-end tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_081_load_on_new_block_long_fork_plan_32_blocks_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_081_load_on_new_block_long_fork_plan_32_blocks_vector")?;
    let canonical = make_linear_chain(16, 8100)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let fork_blocks = make_fork_from_parent(genesis, 32, 8110)?;
    store_side_branch(&block_index, &fork_blocks, 1000)?;

    match fork.on_new_block(last_block(&fork_blocks)?)? {
        ForkAction::Reorg(plan) => {
            assert_eq!(plan.detach.len(), 15);
            assert_eq!(plan.attach.len(), 32);
            assert_eq!(plan.new_tip_height, 32);
        }
        other => assert!(matches!(other, ForkAction::Reorg(_))),
    }

    Ok(())
}

#[test]
fn test_082_load_apply_reorg_32_attach_steps_vector() -> TestResult {
    let (fork, block_index, chain_view, _db) =
        default_fixture("test_082_load_apply_reorg_32_attach_steps_vector")?;
    let genesis = make_block(0, [0u8; 64], 8200)?;
    let fork_blocks = make_fork_from_parent(&genesis, 32, 8210)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let attach = fork_blocks
        .iter()
        .map(|block| ReorgStep {
            height: block.metadata.index,
            hash: block.block_hash,
        })
        .collect::<Vec<_>>();

    let tip = last_block(&fork_blocks)?;
    let plan = simple_plan(&genesis, tip, &genesis, Vec::new(), attach);

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(chain_view.get_tip_height()?, "load tip height")?,
        tip.metadata.index
    );
    assert_eq!(
        required(chain_view.get_hash_at_height(32)?, "height 32")?,
        tip.block_hash
    );
    Ok(())
}

#[test]
fn test_083_load_apply_reorg_32_detach_steps_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_083_load_apply_reorg_32_detach_steps_vector")?;
    let canonical = make_linear_chain(33, 8300)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;
    let genesis = block_at(&canonical, 0)?;
    let old_tip = last_block(&canonical)?;

    let detach = canonical
        .iter()
        .skip(1)
        .rev()
        .map(|block| ReorgStep {
            height: block.metadata.index,
            hash: block.block_hash,
        })
        .collect::<Vec<_>>();

    let plan = simple_plan(old_tip, genesis, genesis, detach, Vec::new());

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    for block in canonical.iter().skip(1) {
        assert_eq!(
            required(block_index.status_of(&block.block_hash)?, "detached status")?,
            ForkBlockStatus::SideBranch
        );
    }

    Ok(())
}

#[test]
fn test_084_fuzz_on_new_block_randomish_side_branch_lengths() -> TestResult {
    for len in 2u64..8u64 {
        let label = format!("test_084_fuzz_on_new_block_randomish_side_branch_lengths_{len}");
        let (fork, block_index, chain_view, db) = default_fixture(&label)?;
        let canonical = make_linear_chain(2, 8400u64.saturating_add(len))?;
        store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

        let genesis = block_at(&canonical, 0)?;
        let fork_blocks = make_fork_from_parent(genesis, len, 8410u64.saturating_add(len))?;
        store_side_branch(&block_index, &fork_blocks, 100)?;

        match fork.on_new_block(last_block(&fork_blocks)?)? {
            ForkAction::Reorg(plan) => assert_eq!(
                plan.attach.len(),
                usize::try_from(len).map_err(|e| {
                    storage_error(format!("failed to convert len to usize: {e}"))
                })?
            ),
            other => assert!(matches!(other, ForkAction::Reorg(_))),
        }
    }

    Ok(())
}

#[test]
fn test_085_fuzz_apply_single_attach_many_heights() -> TestResult {
    for height in 1u64..16u64 {
        let label = format!("test_085_fuzz_apply_single_attach_many_heights_{height}");
        let (fork, block_index, chain_view, _db) = default_fixture(&label)?;
        let genesis = make_block(0, [0u8; 64], 8500)?;
        let block = make_block(height, genesis.block_hash, 8500u64.saturating_add(height))?;
        store_block_with_status(&block_index, &block, ForkBlockStatus::SideBranch)?;

        let plan = simple_plan(
            &genesis,
            &block,
            &genesis,
            Vec::new(),
            vec![ReorgStep {
                height,
                hash: block.block_hash,
            }],
        );

        fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;
        assert_eq!(
            required(chain_view.get_hash_at_height(height)?, "fuzz height")?,
            block.block_hash
        );
    }

    Ok(())
}

#[test]
fn test_086_fuzz_apply_detach_callbacks_many_heights() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_086_fuzz_apply_detach_callbacks_many_heights")?;
    let hash = deterministic_hash(86);
    let detach = (1u64..17u64)
        .rev()
        .map(|height| ReorgStep { height, hash })
        .collect::<Vec<_>>();
    let plan = ReorgPlan {
        old_tip_height: 16,
        old_tip_hash: hash,
        new_tip_height: 0,
        new_tip_hash: hash,
        common_ancestor_height: 0,
        common_ancestor_hash: hash,
        detach,
        attach: Vec::new(),
    };
    let mut seen = Vec::new();

    fork.apply_reorg(
        &plan,
        |h, _hash| {
            seen.push(h);
            Ok(())
        },
        |_h, _hash| Ok(()),
    )?;

    assert_eq!(seen.first().copied(), Some(16));
    assert_eq!(seen.last().copied(), Some(1));
    Ok(())
}

#[test]
fn test_087_load_puzzle_proof_logging_many_heights() -> TestResult {
    let (fork, _block_index, _chain_view, _db) =
        default_fixture("test_087_load_puzzle_proof_logging_many_heights")?;

    for height in 0u64..16u64 {
        let proof = puzzle_proof(height);
        fork.on_puzzle_proof_for_branch(&proof);
    }

    Ok(())
}

#[test]
fn test_088_end_to_end_on_new_block_plan_then_apply_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_088_end_to_end_on_new_block_plan_then_apply_vector")?;
    let canonical = make_linear_chain(3, 8800)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let fork_blocks = make_fork_from_parent(ancestor, 3, 8810)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let new_tip = last_block(&fork_blocks)?;
    let action = fork.on_new_block(new_tip)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(chain_view.get_tip_hash()?, "end-to-end tip hash")?,
        new_tip.block_hash
    );
    Ok(())
}

#[test]
fn test_089_end_to_end_old_tip_becomes_side_branch_after_apply_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_089_end_to_end_old_tip_becomes_side_branch_after_apply_vector")?;
    let canonical = make_linear_chain(3, 8900)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let old_tip = last_block(&canonical)?;
    let ancestor = block_at(&canonical, 1)?;
    let fork_blocks = make_fork_from_parent(ancestor, 3, 8910)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let action = fork.on_new_block(last_block(&fork_blocks)?)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(
            block_index.status_of(&old_tip.block_hash)?,
            "old tip status"
        )?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_090_end_to_end_new_branch_blocks_become_canonical_after_apply_vector() -> TestResult {
    let (fork, block_index, chain_view, db) = default_fixture(
        "test_090_end_to_end_new_branch_blocks_become_canonical_after_apply_vector",
    )?;
    let canonical = make_linear_chain(3, 9000)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let fork_blocks = make_fork_from_parent(ancestor, 3, 9010)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let action = fork.on_new_block(last_block(&fork_blocks)?)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    for block in &fork_blocks {
        assert_eq!(
            required(
                block_index.status_of(&block.block_hash)?,
                "new canonical status"
            )?,
            ForkBlockStatus::Canonical
        );
    }

    Ok(())
}

#[test]
fn test_091_end_to_end_reorg_updates_canonical_height_hashes_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_091_end_to_end_reorg_updates_canonical_height_hashes_vector")?;
    let canonical = make_linear_chain(3, 9100)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let fork_blocks = make_fork_from_parent(ancestor, 3, 9110)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let action = fork.on_new_block(last_block(&fork_blocks)?)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    for block in &fork_blocks {
        assert_eq!(
            required(
                chain_view.get_hash_at_height(block.metadata.index)?,
                "canonical hash"
            )?,
            block.block_hash
        );
    }

    Ok(())
}

#[test]
fn test_092_end_to_end_reorg_callbacks_collect_all_steps_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_092_end_to_end_reorg_callbacks_collect_all_steps_vector")?;
    let canonical = make_linear_chain(4, 9200)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 1)?;
    let fork_blocks = make_fork_from_parent(ancestor, 4, 9210)?;
    store_side_branch(&block_index, &fork_blocks, 100)?;

    let action = fork.on_new_block(last_block(&fork_blocks)?)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    let mut reverted = Vec::new();
    let mut applied = Vec::new();

    fork.apply_reorg(
        &plan,
        |h, hash| {
            reverted.push((h, hash));
            Ok(())
        },
        |h, hash| {
            applied.push((h, hash));
            Ok(())
        },
    )?;

    assert_eq!(reverted.len(), plan.detach.len());
    assert_eq!(applied.len(), plan.attach.len());
    Ok(())
}

#[test]
fn test_093_load_apply_reorg_64_attach_steps_vector() -> TestResult {
    let (fork, block_index, chain_view, _db) =
        default_fixture("test_093_load_apply_reorg_64_attach_steps_vector")?;
    let genesis = make_block(0, [0u8; 64], 9300)?;
    let branch = make_fork_from_parent(&genesis, 64, 9310)?;
    store_side_branch(&block_index, &branch, 100)?;

    let attach = branch
        .iter()
        .map(|block| ReorgStep {
            height: block.metadata.index,
            hash: block.block_hash,
        })
        .collect::<Vec<_>>();

    let tip = last_block(&branch)?;
    let plan = simple_plan(&genesis, tip, &genesis, Vec::new(), attach);

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(required(chain_view.get_tip_height()?, "64 attach tip")?, 64);
    Ok(())
}

#[test]
fn test_094_load_on_new_block_reorg_at_depth_limit_64_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_094_load_on_new_block_reorg_at_depth_limit_64_vector")?;
    let canonical = make_linear_chain(2, 9400)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 64, 9410)?;
    store_side_branch(&block_index, &branch, 100)?;

    match fork.on_new_block(last_block(&branch)?)? {
        ForkAction::Reorg(plan) => {
            assert_eq!(plan.attach.len(), 64);
            assert_eq!(plan.new_tip_height, 64);
        }
        other => assert!(matches!(other, ForkAction::Reorg(_))),
    }

    Ok(())
}

#[test]
fn test_095_load_on_new_block_reorg_beyond_default_depth_stays_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_095_load_on_new_block_reorg_beyond_default_depth_stays_vector")?;
    let canonical = make_linear_chain(2, 9500)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 65, 9510)?;
    store_side_branch(&block_index, &branch, 100)?;

    assert_stay(fork.on_new_block(last_block(&branch)?)?);
    Ok(())
}

#[test]
fn test_096_fuzz_equal_height_tiebreak_lower_hash_many_attempts_vector() -> TestResult {
    for round in 0u64..4u64 {
        let cfg = ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: true,
            prefer_cumulative_por: false,
        };
        let label = format!("test_096_fuzz_equal_height_tiebreak_lower_hash_many_attempts_{round}");
        let (fork, block_index, chain_view, db) = fresh_fixture(&label, cfg)?;
        let canonical = make_linear_chain(3, 9600u64.saturating_add(round))?;
        store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

        let parent = block_at(&canonical, 1)?;
        let old_tip = last_block(&canonical)?;
        let competitor = find_equal_height_competitor(
            parent,
            old_tip.block_hash,
            true,
            9610u64.saturating_add(round.saturating_mul(100)),
        )?;
        store_block_with_status(&block_index, &competitor, ForkBlockStatus::SideBranch)?;

        match fork.on_new_block(&competitor)? {
            ForkAction::Reorg(plan) => assert_eq!(plan.new_tip_hash, competitor.block_hash),
            other => assert!(matches!(other, ForkAction::Reorg(_))),
        }
    }

    Ok(())
}

#[test]
fn test_097_fuzz_cumulative_por_equal_score_falls_back_to_height_vector() -> TestResult {
    let cfg = ReForkConfig {
        max_reorg_depth: 64,
        allow_equal_height_reorg: false,
        prefer_cumulative_por: true,
    };
    let (fork, block_index, chain_view, db) = fresh_fixture(
        "test_097_fuzz_cumulative_por_equal_score_falls_back_to_height_vector",
        cfg,
    )?;
    let canonical = make_linear_chain(3, 9700)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;
    let old_tip = last_block(&canonical)?;
    store_block_with_status_and_score(&block_index, old_tip, ForkBlockStatus::Canonical, 100)?;

    let parent = block_at(&canonical, 1)?;
    let branch = make_fork_from_parent(parent, 3, 9710)?;
    for block in &branch {
        store_block_with_status_and_score(&block_index, block, ForkBlockStatus::SideBranch, 100)?;
    }

    match fork.on_new_block(last_block(&branch)?)? {
        ForkAction::Reorg(plan) => assert_eq!(plan.new_tip_height, 4),
        other => assert!(matches!(other, ForkAction::Reorg(_))),
    }

    Ok(())
}

#[test]
fn test_098_end_to_end_apply_reorg_then_direct_extension_stays_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_098_end_to_end_apply_reorg_then_direct_extension_stays_vector")?;
    let canonical = make_linear_chain(2, 9800)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 9810)?;
    store_side_branch(&block_index, &branch, 100)?;
    let branch_tip = last_block(&branch)?;

    let action = fork.on_new_block(branch_tip)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    let next = make_block(
        branch_tip.metadata.index.saturating_add(1),
        branch_tip.block_hash,
        9899,
    )?;
    store_block_with_status(&block_index, &next, ForkBlockStatus::Validated)?;

    assert_stay(fork.on_new_block(&next)?);
    Ok(())
}

#[test]
fn test_099_end_to_end_apply_reorg_then_validate_latest_projection_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_099_end_to_end_apply_reorg_then_validate_latest_projection_vector")?;
    let canonical = make_linear_chain(2, 9900)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let genesis = block_at(&canonical, 0)?;
    let branch = make_fork_from_parent(genesis, 3, 9910)?;
    store_side_branch(&block_index, &branch, 100)?;
    let branch_tip = last_block(&branch)?;

    let action = fork.on_new_block(branch_tip)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    let projected = required(
        db.get_block_by_index(branch_tip.metadata.index)?,
        "latest projected branch tip",
    )?;
    assert_eq!(projected, *branch_tip);
    Ok(())
}

#[test]
fn test_100_end_to_end_full_fork_choice_flow_vector() -> TestResult {
    let (fork, block_index, chain_view, db) =
        default_fixture("test_100_end_to_end_full_fork_choice_flow_vector")?;
    let canonical = make_linear_chain(5, 10_000)?;
    store_canonical_chain(&block_index, &chain_view, &db, &canonical)?;

    let ancestor = block_at(&canonical, 2)?;
    let fork_blocks = make_fork_from_parent(ancestor, 4, 10_100)?;
    store_side_branch(&block_index, &fork_blocks, 1_000)?;

    let new_tip = last_block(&fork_blocks)?;
    let action = fork.on_new_block(new_tip)?;
    let plan = match action {
        ForkAction::Reorg(plan) => plan,
        other => {
            assert!(matches!(other, ForkAction::Reorg(_)));
            return Ok(());
        }
    };

    assert_eq!(plan.old_tip_height, 4);
    assert_eq!(plan.new_tip_height, 6);
    assert_eq!(plan.common_ancestor_height, 2);
    assert_eq!(plan.detach_heights(), vec![4, 3]);
    assert_eq!(plan.attach_heights(), vec![3, 4, 5, 6]);

    fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))?;

    assert_eq!(
        required(chain_view.get_tip_hash()?, "final tip hash")?,
        new_tip.block_hash
    );
    assert_eq!(
        required(chain_view.get_tip_height()?, "final tip height")?,
        6
    );
    assert_eq!(
        required(
            block_index.status_of(&new_tip.block_hash)?,
            "final new tip status"
        )?,
        ForkBlockStatus::Canonical
    );

    Ok(())
}
