use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::reorganization::reorg_001_block_index::ReorgBlockIndex;
use remzar::reorganization::reorg_002_chain_view::{BlockHash, ReorgChainView};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::storage::rocksdb_006_manager_ext::{CanonicalTipView, ForkBlockMeta, ForkBlockStatus};
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

fn fresh_views(
    label: &str,
) -> Result<(ReorgChainView, ReorgBlockIndex, Arc<RockDBManager>), ErrorDetection> {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "remzar_reorg_002_chain_view_{label}_{}_{}",
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
    let view = ReorgChainView::new(Arc::clone(&db));
    let block_index = ReorgBlockIndex::new(Arc::clone(&db));
    Ok((view, block_index, db))
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
    let batch_key = Some(format!("chain-view-batch-key-height-{height}-tag-{tag}"));
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

fn meta_for(block: &Block, status: ForkBlockStatus, score: u128) -> ForkBlockMeta {
    ForkBlockMeta {
        parent_hash: block.metadata.previous_hash,
        height: block.metadata.index,
        cumulative_score: score,
        status,
        received_at_unix_secs: block.metadata.timestamp,
    }
}

fn store_block_with_status(
    block_index: &ReorgBlockIndex,
    block: &Block,
    status: ForkBlockStatus,
) -> Result<(), ErrorDetection> {
    let meta = meta_for(block, status, u128::from(block.metadata.index));
    block_index.put_block_and_meta(block, &meta)
}

fn store_blocks(
    block_index: &ReorgBlockIndex,
    blocks: &[Block],
    status: ForkBlockStatus,
) -> Result<(), ErrorDetection> {
    for block in blocks {
        store_block_with_status(block_index, block, status)?;
    }
    Ok(())
}

fn map_blocks(view: &ReorgChainView, blocks: &[Block]) -> Result<(), ErrorDetection> {
    for block in blocks {
        view.set_hash_at_height(block.metadata.index, &block.block_hash)?;
    }
    Ok(())
}

fn store_and_map_blocks(
    view: &ReorgChainView,
    block_index: &ReorgBlockIndex,
    blocks: &[Block],
    status: ForkBlockStatus,
) -> Result<(), ErrorDetection> {
    store_blocks(block_index, blocks, status)?;
    map_blocks(view, blocks)
}

fn last_block(blocks: &[Block]) -> Result<&Block, ErrorDetection> {
    blocks.last().ok_or_else(|| ErrorDetection::NotFound {
        resource: "last block in test chain".to_owned(),
    })
}

fn block_at(blocks: &[Block], pos: usize) -> Result<&Block, ErrorDetection> {
    blocks.get(pos).ok_or_else(|| ErrorDetection::NotFound {
        resource: format!("block at test vector position {pos}"),
    })
}

fn hashes_from_blocks(blocks: &[Block]) -> Vec<BlockHash> {
    blocks.iter().map(|block| block.block_hash).collect()
}

fn steps_from_blocks(blocks: &[Block]) -> Vec<(u64, BlockHash)> {
    blocks
        .iter()
        .map(|block| (block.metadata.index, block.block_hash))
        .collect()
}

fn assert_tip(view: &ReorgChainView, hash: BlockHash, height: u64) -> TestResult {
    let tip = required(view.get_tip()?, "canonical tip")?;
    assert_eq!(tip.tip_hash, hash);
    assert_eq!(tip.tip_height, height);
    assert_eq!(required(view.get_tip_hash()?, "canonical tip hash")?, hash);
    assert_eq!(
        required(view.get_tip_height()?, "canonical tip height")?,
        height
    );
    Ok(())
}

fn assert_not_found<T>(result: Result<T, ErrorDetection>) -> TestResult {
    assert!(matches!(result, Err(ErrorDetection::NotFound { .. })));
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 1–20: core vector tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_01_new_keeps_same_db_arc_vector() -> TestResult {
    let (view, _block_index, db) = fresh_views("test_01_new_keeps_same_db_arc_vector")?;
    assert!(Arc::ptr_eq(view.db(), &db));
    Ok(())
}

#[test]
fn test_02_get_hash_at_height_missing_returns_none_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_02_get_hash_at_height_missing_returns_none_vector")?;
    assert!(view.get_hash_at_height(0)?.is_none());
    Ok(())
}

#[test]
fn test_03_has_height_false_when_missing_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_03_has_height_false_when_missing_vector")?;
    assert!(!view.has_height(0)?);
    Ok(())
}

#[test]
fn test_04_set_hash_at_height_zero_roundtrip_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_04_set_hash_at_height_zero_roundtrip_vector")?;
    let hash = deterministic_hash(4);

    view.set_hash_at_height(0, &hash)?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "height zero hash")?,
        hash
    );
    assert!(view.has_height(0)?);
    Ok(())
}

#[test]
fn test_05_set_hash_at_height_high_roundtrip_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_05_set_hash_at_height_high_roundtrip_vector")?;
    let hash = deterministic_hash(5);

    view.set_hash_at_height(1_000_000, &hash)?;

    assert_eq!(
        required(view.get_hash_at_height(1_000_000)?, "high height hash")?,
        hash
    );
    Ok(())
}

#[test]
fn test_06_set_hash_at_height_u64_max_roundtrip_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_06_set_hash_at_height_u64_max_roundtrip_vector")?;
    let hash = deterministic_hash(6);

    view.set_hash_at_height(u64::MAX, &hash)?;

    assert_eq!(
        required(view.get_hash_at_height(u64::MAX)?, "u64 max height hash")?,
        hash
    );
    Ok(())
}

#[test]
fn test_07_hash_mapping_overwrite_same_height_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_07_hash_mapping_overwrite_same_height_vector")?;
    let first = deterministic_hash(7);
    let second = deterministic_hash(8);

    view.set_hash_at_height(7, &first)?;
    view.set_hash_at_height(7, &second)?;

    assert_eq!(
        required(view.get_hash_at_height(7)?, "overwritten hash")?,
        second
    );
    Ok(())
}

#[test]
fn test_08_delete_height_range_single_height_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_08_delete_height_range_single_height_vector")?;
    let hash = deterministic_hash(8);

    view.set_hash_at_height(8, &hash)?;
    assert!(view.has_height(8)?);

    view.delete_height_range(8, 8)?;

    assert!(!view.has_height(8)?);
    Ok(())
}

#[test]
fn test_09_delete_height_range_inclusive_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_09_delete_height_range_inclusive_vector")?;

    for height in 0u64..6u64 {
        view.set_hash_at_height(height, &deterministic_hash(90u64.saturating_add(height)))?;
    }

    view.delete_height_range(2, 4)?;

    assert!(view.has_height(0)?);
    assert!(view.has_height(1)?);
    assert!(!view.has_height(2)?);
    assert!(!view.has_height(3)?);
    assert!(!view.has_height(4)?);
    assert!(view.has_height(5)?);
    Ok(())
}

#[test]
fn test_10_delete_height_range_noop_when_from_greater_than_to_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_10_delete_height_range_noop_when_from_greater_than_to_vector")?;
    let hash = deterministic_hash(10);

    view.set_hash_at_height(1, &hash)?;
    view.delete_height_range(5, 1)?;

    assert_eq!(required(view.get_hash_at_height(1)?, "kept hash")?, hash);
    Ok(())
}

#[test]
fn test_11_get_tip_missing_returns_none_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_11_get_tip_missing_returns_none_vector")?;

    assert!(view.get_tip()?.is_none());
    assert!(view.get_tip_hash()?.is_none());
    assert!(view.get_tip_height()?.is_none());
    Ok(())
}

#[test]
fn test_12_set_tip_roundtrip_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_12_set_tip_roundtrip_vector")?;
    let hash = deterministic_hash(12);

    view.set_tip(&hash, 12)?;

    assert_tip(&view, hash, 12)
}

#[test]
fn test_13_set_tip_overwrites_previous_tip_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_13_set_tip_overwrites_previous_tip_vector")?;
    let first = deterministic_hash(13);
    let second = deterministic_hash(14);

    view.set_tip(&first, 13)?;
    view.set_tip(&second, 14)?;

    assert_tip(&view, second, 14)
}

#[test]
fn test_14_set_tip_can_move_to_lower_height_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_14_set_tip_can_move_to_lower_height_vector")?;
    let high = deterministic_hash(140);
    let low = deterministic_hash(14);

    view.set_tip(&high, 140)?;
    view.set_tip(&low, 14)?;

    assert_tip(&view, low, 14)
}

#[test]
fn test_15_get_tip_with_legacy_fallback_prefers_explicit_tip_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_15_get_tip_with_legacy_fallback_prefers_explicit_tip_vector")?;
    let hash = deterministic_hash(15);

    view.set_tip(&hash, 15)?;

    let tip = required(
        view.get_tip_with_legacy_fallback()?,
        "explicit tip with fallback",
    )?;
    assert_eq!(tip.tip_hash, hash);
    assert_eq!(tip.tip_height, 15);
    Ok(())
}

#[test]
fn test_16_ensure_initialized_returns_existing_tip_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_16_ensure_initialized_returns_existing_tip_vector")?;
    let hash = deterministic_hash(16);

    view.set_tip(&hash, 16)?;

    let tip = required(view.ensure_initialized()?, "initialized tip")?;
    assert_eq!(tip.tip_hash, hash);
    assert_eq!(tip.tip_height, 16);
    Ok(())
}

#[test]
fn test_17_log_tip_summary_with_explicit_tip_succeeds_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_17_log_tip_summary_with_explicit_tip_succeeds_vector")?;
    let hash = deterministic_hash(17);

    view.set_tip(&hash, 17)?;
    view.log_tip_summary()?;

    Ok(())
}

#[test]
fn test_18_canonical_hashes_up_to_zero_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_18_canonical_hashes_up_to_zero_vector")?;
    let hash = deterministic_hash(18);

    view.set_hash_at_height(0, &hash)?;

    assert_eq!(view.canonical_hashes_up_to(0)?, vec![hash]);
    Ok(())
}

#[test]
fn test_19_canonical_steps_up_to_zero_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_19_canonical_steps_up_to_zero_vector")?;
    let hash = deterministic_hash(19);

    view.set_hash_at_height(0, &hash)?;

    assert_eq!(view.canonical_steps_up_to(0)?, vec![(0, hash)]);
    Ok(())
}

#[test]
fn test_20_canonical_steps_in_range_single_height_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_20_canonical_steps_in_range_single_height_vector")?;
    let hash = deterministic_hash(20);

    view.set_hash_at_height(20, &hash)?;

    assert_eq!(view.canonical_steps_in_range(20, 20)?, vec![(20, hash)]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 21–40: canonical path and block resolution
// ─────────────────────────────────────────────────────────────

#[test]
fn test_21_canonical_hashes_up_to_three_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_21_canonical_hashes_up_to_three_vector")?;
    let blocks = make_linear_chain(4, 2100)?;
    map_blocks(&view, &blocks)?;

    assert_eq!(view.canonical_hashes_up_to(3)?, hashes_from_blocks(&blocks));
    Ok(())
}

#[test]
fn test_22_canonical_steps_up_to_three_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_22_canonical_steps_up_to_three_vector")?;
    let blocks = make_linear_chain(4, 2200)?;
    map_blocks(&view, &blocks)?;

    assert_eq!(view.canonical_steps_up_to(3)?, steps_from_blocks(&blocks));
    Ok(())
}

#[test]
fn test_23_canonical_steps_in_range_middle_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_23_canonical_steps_in_range_middle_vector")?;
    let blocks = make_linear_chain(6, 2300)?;
    map_blocks(&view, &blocks)?;

    let expected = vec![
        (2, block_at(&blocks, 2)?.block_hash),
        (3, block_at(&blocks, 3)?.block_hash),
        (4, block_at(&blocks, 4)?.block_hash),
    ];

    assert_eq!(view.canonical_steps_in_range(2, 4)?, expected);
    Ok(())
}

#[test]
fn test_24_canonical_steps_in_range_from_greater_than_to_is_empty_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_24_canonical_steps_in_range_from_greater_than_to_is_empty_vector")?;

    assert!(view.canonical_steps_in_range(9, 2)?.is_empty());
    Ok(())
}

#[test]
fn test_25_canonical_hashes_up_to_missing_height_zero_errors_edge() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_25_canonical_hashes_up_to_missing_height_zero_errors_edge")?;

    assert_not_found(view.canonical_hashes_up_to(0))?;
    Ok(())
}

#[test]
fn test_26_canonical_hashes_up_to_gap_errors_edge() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_26_canonical_hashes_up_to_gap_errors_edge")?;
    view.set_hash_at_height(0, &deterministic_hash(2600))?;
    view.set_hash_at_height(2, &deterministic_hash(2602))?;

    assert_not_found(view.canonical_hashes_up_to(2))?;
    Ok(())
}

#[test]
fn test_27_canonical_steps_up_to_missing_tip_errors_edge() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_27_canonical_steps_up_to_missing_tip_errors_edge")?;
    view.set_hash_at_height(0, &deterministic_hash(2700))?;

    assert_not_found(view.canonical_steps_up_to(1))?;
    Ok(())
}

#[test]
fn test_28_canonical_steps_in_range_missing_start_errors_edge() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_28_canonical_steps_in_range_missing_start_errors_edge")?;
    view.set_hash_at_height(2, &deterministic_hash(2802))?;

    assert_not_found(view.canonical_steps_in_range(1, 2))?;
    Ok(())
}

#[test]
fn test_29_canonical_steps_in_range_missing_middle_errors_edge() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_29_canonical_steps_in_range_missing_middle_errors_edge")?;
    view.set_hash_at_height(1, &deterministic_hash(2901))?;
    view.set_hash_at_height(3, &deterministic_hash(2903))?;

    assert_not_found(view.canonical_steps_in_range(1, 3))?;
    Ok(())
}

#[test]
fn test_30_canonical_block_at_height_no_mapping_returns_none_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_30_canonical_block_at_height_no_mapping_returns_none_vector")?;

    assert!(view.canonical_block_at_height(0)?.is_none());
    Ok(())
}

#[test]
fn test_31_canonical_block_at_height_mapping_without_block_returns_none_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_31_canonical_block_at_height_mapping_without_block_returns_none_vector")?;
    let hash = deterministic_hash(31);

    view.set_hash_at_height(0, &hash)?;

    assert!(view.canonical_block_at_height(0)?.is_none());
    Ok(())
}

#[test]
fn test_32_canonical_block_at_height_returns_stored_block_vector() -> TestResult {
    let (view, block_index, _db) =
        fresh_views("test_32_canonical_block_at_height_returns_stored_block_vector")?;
    let block = make_block(0, [0u8; 64], 3200)?;

    store_block_with_status(&block_index, &block, ForkBlockStatus::Canonical)?;
    view.set_hash_at_height(0, &block.block_hash)?;

    assert_eq!(
        required(view.canonical_block_at_height(0)?, "canonical block")?,
        block
    );
    Ok(())
}

#[test]
fn test_33_canonical_block_at_height_reflects_mapping_overwrite_vector() -> TestResult {
    let (view, block_index, _db) =
        fresh_views("test_33_canonical_block_at_height_reflects_mapping_overwrite_vector")?;
    let first = make_block(0, [0u8; 64], 3300)?;
    let second = make_block(0, [0u8; 64], 3301)?;

    store_block_with_status(&block_index, &first, ForkBlockStatus::Canonical)?;
    store_block_with_status(&block_index, &second, ForkBlockStatus::Canonical)?;

    view.set_hash_at_height(0, &first.block_hash)?;
    assert_eq!(
        required(view.canonical_block_at_height(0)?, "first canonical block")?,
        first
    );

    view.set_hash_at_height(0, &second.block_hash)?;
    assert_eq!(
        required(view.canonical_block_at_height(0)?, "second canonical block")?,
        second
    );
    Ok(())
}

#[test]
fn test_34_delete_height_range_then_canonical_block_returns_none_edge() -> TestResult {
    let (view, block_index, _db) =
        fresh_views("test_34_delete_height_range_then_canonical_block_returns_none_edge")?;
    let block = make_block(0, [0u8; 64], 3400)?;

    store_block_with_status(&block_index, &block, ForkBlockStatus::Canonical)?;
    view.set_hash_at_height(0, &block.block_hash)?;
    view.delete_height_range(0, 0)?;

    assert!(view.canonical_block_at_height(0)?.is_none());
    Ok(())
}

#[test]
fn test_35_canonical_hashes_after_rewrite_use_latest_hash_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_35_canonical_hashes_after_rewrite_use_latest_hash_vector")?;
    let old_hash = deterministic_hash(3500);
    let new_hash = deterministic_hash(3501);

    view.set_hash_at_height(0, &old_hash)?;
    view.set_hash_at_height(0, &new_hash)?;

    assert_eq!(view.canonical_hashes_up_to(0)?, vec![new_hash]);
    Ok(())
}

#[test]
fn test_36_canonical_steps_after_rewrite_use_latest_hash_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_36_canonical_steps_after_rewrite_use_latest_hash_vector")?;
    let old_hash = deterministic_hash(3600);
    let new_hash = deterministic_hash(3601);

    view.set_hash_at_height(5, &old_hash)?;
    view.set_hash_at_height(5, &new_hash)?;

    assert_eq!(view.canonical_steps_in_range(5, 5)?, vec![(5, new_hash)]);
    Ok(())
}

#[test]
fn test_37_canonical_steps_can_span_high_heights_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_37_canonical_steps_can_span_high_heights_vector")?;
    let h1 = 1_000_000u64;
    let h2 = 1_000_001u64;
    let first = deterministic_hash(3701);
    let second = deterministic_hash(3702);

    view.set_hash_at_height(h1, &first)?;
    view.set_hash_at_height(h2, &second)?;

    assert_eq!(
        view.canonical_steps_in_range(h1, h2)?,
        vec![(h1, first), (h2, second)]
    );
    Ok(())
}

#[test]
fn test_38_canonical_steps_can_span_u64_max_minus_one_to_max_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_38_canonical_steps_can_span_u64_max_minus_one_to_max_vector")?;
    let h1 = u64::MAX.saturating_sub(1);
    let h2 = u64::MAX;
    let first = deterministic_hash(3801);
    let second = deterministic_hash(3802);

    view.set_hash_at_height(h1, &first)?;
    view.set_hash_at_height(h2, &second)?;

    assert_eq!(
        view.canonical_steps_in_range(h1, h2)?,
        vec![(h1, first), (h2, second)]
    );
    Ok(())
}

#[test]
fn test_39_delete_height_range_high_heights_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_39_delete_height_range_high_heights_vector")?;
    let h1 = 9_000_000u64;
    let h2 = 9_000_001u64;

    view.set_hash_at_height(h1, &deterministic_hash(3901))?;
    view.set_hash_at_height(h2, &deterministic_hash(3902))?;
    view.delete_height_range(h1, h2)?;

    assert!(!view.has_height(h1)?);
    assert!(!view.has_height(h2)?);
    Ok(())
}

#[test]
fn test_40_delete_height_range_u64_max_single_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_40_delete_height_range_u64_max_single_vector")?;
    let hash = deterministic_hash(40);

    view.set_hash_at_height(u64::MAX, &hash)?;
    view.delete_height_range(u64::MAX, u64::MAX)?;

    assert!(!view.has_height(u64::MAX)?);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 41–60: tip choice, summaries, initialization helpers
// ─────────────────────────────────────────────────────────────

#[test]
fn test_41_choose_better_tip_candidate_higher_height_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_41_choose_better_tip_candidate_higher_height_vector")?;
    let current = deterministic_hash(4100);
    let candidate = deterministic_hash(4101);

    let chosen = view.choose_better_tip(&current, 1, &candidate, 2, false)?;

    assert_eq!(chosen, candidate);
    Ok(())
}

#[test]
fn test_42_choose_better_tip_current_higher_height_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_42_choose_better_tip_current_higher_height_vector")?;
    let current = deterministic_hash(4200);
    let candidate = deterministic_hash(4201);

    let chosen = view.choose_better_tip(&current, 3, &candidate, 2, true)?;

    assert_eq!(chosen, current);
    Ok(())
}

#[test]
fn test_43_choose_better_tip_equal_height_no_tiebreak_keeps_current_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_43_choose_better_tip_equal_height_no_tiebreak_keeps_current_vector")?;
    let current = deterministic_hash(4300);
    let candidate = deterministic_hash(4301);

    let chosen = view.choose_better_tip(&current, 3, &candidate, 3, false)?;

    assert_eq!(chosen, current);
    Ok(())
}

#[test]
fn test_44_choose_better_tip_equal_height_tiebreak_candidate_lower_hash_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_44_choose_better_tip_equal_height_tiebreak_candidate_lower_hash_vector")?;
    let current = [9u8; 64];
    let candidate = [1u8; 64];

    let chosen = view.choose_better_tip(&current, 3, &candidate, 3, true)?;

    assert_eq!(chosen, candidate);
    Ok(())
}

#[test]
fn test_45_choose_better_tip_equal_height_tiebreak_candidate_higher_hash_keeps_current_vector()
-> TestResult {
    let (view, _block_index, _db) = fresh_views(
        "test_45_choose_better_tip_equal_height_tiebreak_candidate_higher_hash_keeps_current_vector",
    )?;
    let current = [1u8; 64];
    let candidate = [9u8; 64];

    let chosen = view.choose_better_tip(&current, 3, &candidate, 3, true)?;

    assert_eq!(chosen, current);
    Ok(())
}

#[test]
fn test_46_choose_better_tip_equal_hash_keeps_current_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_46_choose_better_tip_equal_hash_keeps_current_vector")?;
    let current = deterministic_hash(46);
    let candidate = current;

    let chosen = view.choose_better_tip(&current, 3, &candidate, 3, true)?;

    assert_eq!(chosen, current);
    Ok(())
}

#[test]
fn test_47_choose_better_tip_candidate_height_wins_over_hash_tiebreak_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_47_choose_better_tip_candidate_height_wins_over_hash_tiebreak_vector")?;
    let current = [1u8; 64];
    let candidate = [9u8; 64];

    let chosen = view.choose_better_tip(&current, 4, &candidate, 5, false)?;

    assert_eq!(chosen, candidate);
    Ok(())
}

#[test]
fn test_48_summarize_tip_missing_meta_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_48_summarize_tip_missing_meta_vector")?;
    let hash = deterministic_hash(48);

    let summary = view.summarize_tip(&hash)?;

    assert!(summary.contains("<missing-meta>"));
    assert!(summary.contains(&hex::encode(hash)));
    Ok(())
}

#[test]
fn test_49_summarize_tip_with_header_only_meta_vector() -> TestResult {
    let (view, block_index, _db) =
        fresh_views("test_49_summarize_tip_with_header_only_meta_vector")?;
    let block = make_block(0, [0u8; 64], 4900)?;
    let meta = meta_for(&block, ForkBlockStatus::HeaderOnly, 49);

    block_index.put_meta(&block.block_hash, &meta)?;

    let summary = view.summarize_tip(&block.block_hash)?;

    assert!(summary.contains("height=0"));
    assert!(summary.contains("HeaderOnly"));
    assert!(summary.contains("score=49"));
    assert!(summary.contains(&hex::encode(block.block_hash)));
    Ok(())
}

#[test]
fn test_50_summarize_tip_with_canonical_meta_vector() -> TestResult {
    let (view, block_index, _db) = fresh_views("test_50_summarize_tip_with_canonical_meta_vector")?;
    let block = make_block(0, [0u8; 64], 5000)?;
    let meta = meta_for(&block, ForkBlockStatus::Canonical, 5_000);

    block_index.put_meta(&block.block_hash, &meta)?;

    let summary = view.summarize_tip(&block.block_hash)?;

    assert!(summary.contains("Canonical"));
    assert!(summary.contains("score=5000"));
    assert!(summary.contains(&hex::encode(block.metadata.previous_hash)));
    Ok(())
}

#[test]
fn test_51_summarize_tip_with_side_branch_meta_vector() -> TestResult {
    let (view, block_index, _db) =
        fresh_views("test_51_summarize_tip_with_side_branch_meta_vector")?;
    let genesis = make_block(0, [0u8; 64], 5100)?;
    let child = make_block(1, genesis.block_hash, 5101)?;
    let meta = meta_for(&child, ForkBlockStatus::SideBranch, 51);

    block_index.put_meta(&child.block_hash, &meta)?;

    let summary = view.summarize_tip(&child.block_hash)?;

    assert!(summary.contains("height=1"));
    assert!(summary.contains("SideBranch"));
    assert!(summary.contains(&hex::encode(genesis.block_hash)));
    Ok(())
}

#[test]
fn test_52_get_tip_with_legacy_fallback_empty_db_returns_none_edge() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_52_get_tip_with_legacy_fallback_empty_db_returns_none_edge")?;

    assert!(view.get_tip_with_legacy_fallback()?.is_none());
    Ok(())
}

#[test]
fn test_53_backfill_from_legacy_projection_empty_db_returns_none_edge() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_53_backfill_from_legacy_projection_empty_db_returns_none_edge")?;

    assert!(view.backfill_from_legacy_projection()?.is_none());
    Ok(())
}

#[test]
fn test_54_ensure_initialized_empty_db_returns_none_edge() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_54_ensure_initialized_empty_db_returns_none_edge")?;

    assert!(view.ensure_initialized()?.is_none());
    Ok(())
}

#[test]
fn test_55_log_tip_summary_empty_db_succeeds_edge() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_55_log_tip_summary_empty_db_succeeds_edge")?;

    view.log_tip_summary()?;

    Ok(())
}

#[test]
fn test_56_canonical_tip_view_bytes_roundtrip_vector() -> TestResult {
    let hash = deterministic_hash(56);
    let view = CanonicalTipView {
        tip_hash: hash,
        tip_height: 56,
    };

    let decoded = CanonicalTipView::from_bytes(&view.to_bytes())?;

    assert_eq!(decoded, view);
    Ok(())
}

#[test]
fn test_57_canonical_tip_view_rejects_short_bytes_edge() -> TestResult {
    let bytes = vec![0u8; 71];

    assert!(CanonicalTipView::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_58_canonical_tip_view_rejects_long_bytes_edge() -> TestResult {
    let bytes = vec![0u8; 73];

    assert!(CanonicalTipView::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_59_canonical_tip_view_big_endian_height_vector() -> TestResult {
    let hash = deterministic_hash(59);
    let height = 0x0102_0304_0506_0708u64;
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(&hash);
    bytes.extend_from_slice(&height.to_be_bytes());

    let decoded = CanonicalTipView::from_bytes(&bytes)?;

    assert_eq!(decoded.tip_hash, hash);
    assert_eq!(decoded.tip_height, height);
    Ok(())
}

#[test]
fn test_60_set_tip_keeps_legacy_tip_height_in_sync_vector() -> TestResult {
    let (view, _block_index, db) =
        fresh_views("test_60_set_tip_keeps_legacy_tip_height_in_sync_vector")?;
    let hash = deterministic_hash(60);

    view.set_tip(&hash, 60)?;

    assert_eq!(db.get_tip_height()?, 60);
    assert_eq!(db.get_latest_block_index()?, 60);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 61–80: attach and switch helpers
// ─────────────────────────────────────────────────────────────

#[test]
fn test_61_apply_canonical_attach_empty_is_noop_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_61_apply_canonical_attach_empty_is_noop_vector")?;

    view.apply_canonical_attach(&[])?;

    assert!(view.get_tip()?.is_none());
    Ok(())
}

#[test]
fn test_62_apply_canonical_attach_single_step_sets_mapping_and_tip_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_62_apply_canonical_attach_single_step_sets_mapping_and_tip_vector")?;
    let hash = deterministic_hash(62);
    let steps = [(0u64, hash)];

    view.apply_canonical_attach(&steps)?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "attached hash")?,
        hash
    );
    assert_tip(&view, hash, 0)
}

#[test]
fn test_63_apply_canonical_attach_multiple_steps_sets_tip_to_last_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_63_apply_canonical_attach_multiple_steps_sets_tip_to_last_vector")?;
    let first = deterministic_hash(6300);
    let second = deterministic_hash(6301);
    let third = deterministic_hash(6302);
    let steps = [(0u64, first), (1u64, second), (2u64, third)];

    view.apply_canonical_attach(&steps)?;

    assert_eq!(view.canonical_steps_up_to(2)?, steps.to_vec());
    assert_tip(&view, third, 2)
}

#[test]
fn test_64_apply_canonical_attach_overwrites_existing_mapping_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_64_apply_canonical_attach_overwrites_existing_mapping_vector")?;
    let old_hash = deterministic_hash(6400);
    let new_hash = deterministic_hash(6401);

    view.set_hash_at_height(1, &old_hash)?;
    view.apply_canonical_attach(&[(1u64, new_hash)])?;

    assert_eq!(
        required(view.get_hash_at_height(1)?, "rewritten attach")?,
        new_hash
    );
    assert_tip(&view, new_hash, 1)
}

#[test]
fn test_65_apply_canonical_attach_nonzero_start_height_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_65_apply_canonical_attach_nonzero_start_height_vector")?;
    let hash = deterministic_hash(65);

    view.apply_canonical_attach(&[(65u64, hash)])?;

    assert_eq!(required(view.get_hash_at_height(65)?, "height 65")?, hash);
    assert_tip(&view, hash, 65)
}

#[test]
fn test_66_switch_canonical_range_attach_only_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_66_switch_canonical_range_attach_only_vector")?;
    let hash = deterministic_hash(66);

    view.switch_canonical_range(None, None, &[(0u64, hash)])?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "attached hash")?,
        hash
    );
    assert_tip(&view, hash, 0)
}

#[test]
fn test_67_switch_canonical_range_detach_only_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_67_switch_canonical_range_detach_only_vector")?;
    for height in 0u64..3u64 {
        view.set_hash_at_height(height, &deterministic_hash(6700u64.saturating_add(height)))?;
    }

    view.switch_canonical_range(Some(1), Some(2), &[])?;

    assert!(view.has_height(0)?);
    assert!(!view.has_height(1)?);
    assert!(!view.has_height(2)?);
    assert!(view.get_tip()?.is_none());
    Ok(())
}

#[test]
fn test_68_switch_canonical_range_detach_and_attach_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_68_switch_canonical_range_detach_and_attach_vector")?;
    let old_zero = deterministic_hash(6800);
    let old_one = deterministic_hash(6801);
    let new_one = deterministic_hash(6811);
    let new_two = deterministic_hash(6812);

    view.apply_canonical_attach(&[(0u64, old_zero), (1u64, old_one)])?;
    view.switch_canonical_range(Some(1), Some(1), &[(1u64, new_one), (2u64, new_two)])?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "kept zero")?,
        old_zero
    );
    assert_eq!(required(view.get_hash_at_height(1)?, "new one")?, new_one);
    assert_eq!(required(view.get_hash_at_height(2)?, "new two")?, new_two);
    assert_tip(&view, new_two, 2)
}

#[test]
fn test_69_switch_canonical_range_ignores_partial_detach_none_from_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_69_switch_canonical_range_ignores_partial_detach_none_from_vector")?;
    let old_hash = deterministic_hash(6900);
    let new_hash = deterministic_hash(6901);

    view.set_hash_at_height(0, &old_hash)?;
    view.switch_canonical_range(None, Some(0), &[(1u64, new_hash)])?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "old hash kept")?,
        old_hash
    );
    assert_eq!(required(view.get_hash_at_height(1)?, "new hash")?, new_hash);
    assert_tip(&view, new_hash, 1)
}

#[test]
fn test_70_switch_canonical_range_ignores_partial_detach_none_to_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_70_switch_canonical_range_ignores_partial_detach_none_to_vector")?;
    let old_hash = deterministic_hash(7000);
    let new_hash = deterministic_hash(7001);

    view.set_hash_at_height(0, &old_hash)?;
    view.switch_canonical_range(Some(0), None, &[(1u64, new_hash)])?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "old hash kept")?,
        old_hash
    );
    assert_eq!(required(view.get_hash_at_height(1)?, "new hash")?, new_hash);
    assert_tip(&view, new_hash, 1)
}

#[test]
fn test_71_switch_canonical_range_from_greater_than_to_keeps_old_and_attaches_vector() -> TestResult
{
    let (view, _block_index, _db) = fresh_views(
        "test_71_switch_canonical_range_from_greater_than_to_keeps_old_and_attaches_vector",
    )?;
    let old_hash = deterministic_hash(7100);
    let new_hash = deterministic_hash(7101);

    view.set_hash_at_height(0, &old_hash)?;
    view.switch_canonical_range(Some(5), Some(1), &[(1u64, new_hash)])?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "old hash kept")?,
        old_hash
    );
    assert_eq!(required(view.get_hash_at_height(1)?, "new hash")?, new_hash);
    assert_tip(&view, new_hash, 1)
}

#[test]
fn test_72_apply_attach_allows_unsorted_steps_and_tip_is_last_input_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_72_apply_attach_allows_unsorted_steps_and_tip_is_last_input_vector")?;
    let high = deterministic_hash(7202);
    let low = deterministic_hash(7201);

    view.apply_canonical_attach(&[(2u64, high), (1u64, low)])?;

    assert_eq!(required(view.get_hash_at_height(2)?, "height two")?, high);
    assert_eq!(required(view.get_hash_at_height(1)?, "height one")?, low);
    assert_tip(&view, low, 1)
}

#[test]
fn test_73_apply_attach_duplicate_height_last_write_wins_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_73_apply_attach_duplicate_height_last_write_wins_vector")?;
    let first = deterministic_hash(7301);
    let second = deterministic_hash(7302);

    view.apply_canonical_attach(&[(3u64, first), (3u64, second)])?;

    assert_eq!(
        required(view.get_hash_at_height(3)?, "duplicate height")?,
        second
    );
    assert_tip(&view, second, 3)
}

#[test]
fn test_74_switch_reorg_common_shape_preserves_pre_detach_prefix_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_74_switch_reorg_common_shape_preserves_pre_detach_prefix_vector")?;
    let zero = deterministic_hash(7400);
    let old_one = deterministic_hash(7401);
    let old_two = deterministic_hash(7402);
    let new_one = deterministic_hash(7411);
    let new_two = deterministic_hash(7412);
    let new_three = deterministic_hash(7413);

    view.apply_canonical_attach(&[(0u64, zero), (1u64, old_one), (2u64, old_two)])?;
    view.switch_canonical_range(
        Some(1),
        Some(2),
        &[(1u64, new_one), (2u64, new_two), (3u64, new_three)],
    )?;

    assert_eq!(required(view.get_hash_at_height(0)?, "prefix")?, zero);
    assert_eq!(required(view.get_hash_at_height(1)?, "new one")?, new_one);
    assert_eq!(required(view.get_hash_at_height(2)?, "new two")?, new_two);
    assert_eq!(
        required(view.get_hash_at_height(3)?, "new three")?,
        new_three
    );
    assert_tip(&view, new_three, 3)
}

#[test]
fn test_75_switch_detaches_tail_without_attach_leaves_tip_unchanged_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_75_switch_detaches_tail_without_attach_leaves_tip_unchanged_vector")?;
    let zero = deterministic_hash(7500);
    let one = deterministic_hash(7501);
    let two = deterministic_hash(7502);

    view.apply_canonical_attach(&[(0u64, zero), (1u64, one), (2u64, two)])?;
    view.switch_canonical_range(Some(1), Some(2), &[])?;

    assert_eq!(required(view.get_hash_at_height(0)?, "zero kept")?, zero);
    assert!(!view.has_height(1)?);
    assert!(!view.has_height(2)?);
    assert_tip(&view, two, 2)
}

#[test]
fn test_76_apply_attach_u64_max_height_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_76_apply_attach_u64_max_height_vector")?;
    let hash = deterministic_hash(7600);

    view.apply_canonical_attach(&[(u64::MAX, hash)])?;

    assert_eq!(
        required(view.get_hash_at_height(u64::MAX)?, "u64 max attach")?,
        hash
    );
    assert_tip(&view, hash, u64::MAX)
}

#[test]
fn test_77_switch_range_u64_max_single_height_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_77_switch_range_u64_max_single_height_vector")?;
    let old_hash = deterministic_hash(7700);
    let new_hash = deterministic_hash(7701);

    view.set_hash_at_height(u64::MAX, &old_hash)?;
    view.switch_canonical_range(Some(u64::MAX), Some(u64::MAX), &[(u64::MAX, new_hash)])?;

    assert_eq!(
        required(view.get_hash_at_height(u64::MAX)?, "u64 max switched")?,
        new_hash
    );
    assert_tip(&view, new_hash, u64::MAX)
}

#[test]
fn test_78_switch_attach_empty_after_noop_detach_does_not_set_tip_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_78_switch_attach_empty_after_noop_detach_does_not_set_tip_vector")?;

    view.switch_canonical_range(Some(9), Some(1), &[])?;

    assert!(view.get_tip()?.is_none());
    Ok(())
}

#[test]
fn test_79_apply_attach_then_canonical_hashes_up_to_full_chain_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_79_apply_attach_then_canonical_hashes_up_to_full_chain_vector")?;
    let blocks = make_linear_chain(5, 7900)?;
    let steps = steps_from_blocks(&blocks);

    view.apply_canonical_attach(&steps)?;

    assert_eq!(view.canonical_hashes_up_to(4)?, hashes_from_blocks(&blocks));
    Ok(())
}

#[test]
fn test_80_switch_after_attach_then_steps_up_to_full_chain_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_80_switch_after_attach_then_steps_up_to_full_chain_vector")?;
    let zero = deterministic_hash(8000);
    let old_one = deterministic_hash(8001);
    let new_one = deterministic_hash(8011);

    view.apply_canonical_attach(&[(0u64, zero), (1u64, old_one)])?;
    view.switch_canonical_range(Some(1), Some(1), &[(1u64, new_one)])?;

    assert_eq!(
        view.canonical_steps_up_to(1)?,
        vec![(0u64, zero), (1u64, new_one)]
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 81–100: property, fuzz-style, adversarial and load tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_81_property_roundtrip_32_distinct_height_mappings() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_81_property_roundtrip_32_distinct_height_mappings")?;

    for height in 0u64..32u64 {
        let hash = deterministic_hash(8_100u64.saturating_add(height));
        view.set_hash_at_height(height, &hash)?;
        assert_eq!(
            required(view.get_hash_at_height(height)?, "property height hash")?,
            hash
        );
    }

    Ok(())
}

#[test]
fn test_82_property_delete_even_sized_ranges_preserves_outside_entries() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_82_property_delete_even_sized_ranges_preserves_outside_entries")?;

    for height in 0u64..10u64 {
        view.set_hash_at_height(height, &deterministic_hash(8_200u64.saturating_add(height)))?;
    }

    view.delete_height_range(3, 6)?;

    for height in 0u64..10u64 {
        let exists = view.has_height(height)?;
        if (3..=6).contains(&height) {
            assert!(!exists);
        } else {
            assert!(exists);
        }
    }

    Ok(())
}

#[test]
fn test_83_property_apply_attach_for_16_steps_matches_steps_builder() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_83_property_apply_attach_for_16_steps_matches_steps_builder")?;
    let blocks = make_linear_chain(16, 8300)?;
    let steps = steps_from_blocks(&blocks);

    view.apply_canonical_attach(&steps)?;

    assert_eq!(view.canonical_steps_up_to(15)?, steps);
    Ok(())
}

#[test]
fn test_84_property_choose_better_tip_height_dominates_for_many_heights() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_84_property_choose_better_tip_height_dominates_for_many_heights")?;
    let current = deterministic_hash(8400);
    let candidate = deterministic_hash(8401);

    for height in 0u64..16u64 {
        let chosen = view.choose_better_tip(
            &current,
            height,
            &candidate,
            height.saturating_add(1),
            false,
        )?;
        assert_eq!(chosen, candidate);
    }

    Ok(())
}

#[test]
fn test_85_property_summarize_all_statuses() -> TestResult {
    let (view, block_index, _db) = fresh_views("test_85_property_summarize_all_statuses")?;
    let statuses = [
        ForkBlockStatus::HeaderOnly,
        ForkBlockStatus::BlockStored,
        ForkBlockStatus::Validated,
        ForkBlockStatus::Canonical,
        ForkBlockStatus::SideBranch,
        ForkBlockStatus::Orphan,
    ];

    let mut height = 0u64;
    let mut parent_hash = [0u8; 64];

    for status in statuses {
        let block = make_block(height, parent_hash, 8_500u64.saturating_add(height))?;
        let meta = meta_for(&block, status, u128::from(height).saturating_add(100));
        block_index.put_meta(&block.block_hash, &meta)?;

        let summary = view.summarize_tip(&block.block_hash)?;
        assert!(summary.contains(&format!("{status:?}")));
        assert!(summary.contains(&format!("height={height}")));

        parent_hash = block.block_hash;
        height = height.saturating_add(1);
    }

    Ok(())
}

#[test]
fn test_86_fuzz_rewrite_same_height_many_times_last_hash_wins() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_86_fuzz_rewrite_same_height_many_times_last_hash_wins")?;
    let mut last_hash = [0u8; 64];

    for seed in 0u64..64u64 {
        last_hash = deterministic_hash(8_600u64.saturating_add(seed));
        view.set_hash_at_height(3, &last_hash)?;
    }

    assert_eq!(
        required(view.get_hash_at_height(3)?, "last fuzz hash")?,
        last_hash
    );
    Ok(())
}

#[test]
fn test_87_fuzz_attach_rewrite_same_tip_many_times_last_tip_wins() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_87_fuzz_attach_rewrite_same_tip_many_times_last_tip_wins")?;
    let mut last_hash = [0u8; 64];

    for seed in 0u64..32u64 {
        last_hash = deterministic_hash(8_700u64.saturating_add(seed));
        view.apply_canonical_attach(&[(7u64, last_hash)])?;
    }

    assert_tip(&view, last_hash, 7)
}

#[test]
fn test_88_adversarial_switch_to_shorter_chain_view_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_88_adversarial_switch_to_shorter_chain_view_vector")?;
    let zero = deterministic_hash(8800);
    let one = deterministic_hash(8801);
    let two = deterministic_hash(8802);
    let replacement_one = deterministic_hash(8811);

    view.apply_canonical_attach(&[(0u64, zero), (1u64, one), (2u64, two)])?;
    view.switch_canonical_range(Some(1), Some(2), &[(1u64, replacement_one)])?;

    assert_eq!(
        view.canonical_steps_up_to(1)?,
        vec![(0u64, zero), (1u64, replacement_one)]
    );
    assert!(!view.has_height(2)?);
    assert_tip(&view, replacement_one, 1)
}

#[test]
fn test_89_adversarial_switch_to_longer_chain_view_vector() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_89_adversarial_switch_to_longer_chain_view_vector")?;
    let zero = deterministic_hash(8900);
    let old_one = deterministic_hash(8901);
    let new_one = deterministic_hash(8911);
    let new_two = deterministic_hash(8912);
    let new_three = deterministic_hash(8913);

    view.apply_canonical_attach(&[(0u64, zero), (1u64, old_one)])?;
    view.switch_canonical_range(
        Some(1),
        Some(1),
        &[(1u64, new_one), (2u64, new_two), (3u64, new_three)],
    )?;

    assert_eq!(
        view.canonical_steps_up_to(3)?,
        vec![
            (0u64, zero),
            (1u64, new_one),
            (2u64, new_two),
            (3u64, new_three)
        ]
    );
    assert_tip(&view, new_three, 3)
}

#[test]
fn test_90_adversarial_switch_detach_gap_then_attach_late_height_leaves_gap_vector() -> TestResult {
    let (view, _block_index, _db) = fresh_views(
        "test_90_adversarial_switch_detach_gap_then_attach_late_height_leaves_gap_vector",
    )?;
    let zero = deterministic_hash(9000);
    let one = deterministic_hash(9001);
    let two = deterministic_hash(9002);
    let four = deterministic_hash(9004);

    view.apply_canonical_attach(&[(0u64, zero), (1u64, one), (2u64, two)])?;
    view.switch_canonical_range(Some(1), Some(2), &[(4u64, four)])?;

    assert_eq!(required(view.get_hash_at_height(0)?, "zero")?, zero);
    assert!(!view.has_height(1)?);
    assert!(!view.has_height(2)?);
    assert_eq!(required(view.get_hash_at_height(4)?, "four")?, four);
    assert_not_found(view.canonical_steps_up_to(4))?;
    assert_tip(&view, four, 4)
}

#[test]
fn test_91_load_attach_64_steps_and_read_tip() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_91_load_attach_64_steps_and_read_tip")?;
    let blocks = make_linear_chain(64, 9100)?;
    let steps = steps_from_blocks(&blocks);
    let tip = last_block(&blocks)?;

    view.apply_canonical_attach(&steps)?;

    assert_tip(&view, tip.block_hash, tip.metadata.index)
}

#[test]
fn test_92_load_attach_64_steps_and_read_hashes() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_92_load_attach_64_steps_and_read_hashes")?;
    let blocks = make_linear_chain(64, 9200)?;
    let steps = steps_from_blocks(&blocks);

    view.apply_canonical_attach(&steps)?;

    assert_eq!(
        view.canonical_hashes_up_to(63)?,
        hashes_from_blocks(&blocks)
    );
    Ok(())
}

#[test]
fn test_93_load_store_blocks_map_and_resolve_all_canonical_blocks() -> TestResult {
    let (view, block_index, _db) =
        fresh_views("test_93_load_store_blocks_map_and_resolve_all_canonical_blocks")?;
    let blocks = make_linear_chain(32, 9300)?;

    store_and_map_blocks(&view, &block_index, &blocks, ForkBlockStatus::Canonical)?;

    for block in &blocks {
        let fetched = required(
            view.canonical_block_at_height(block.metadata.index)?,
            "canonical block in load test",
        )?;
        assert_eq!(fetched, *block);
    }

    Ok(())
}

#[test]
fn test_94_load_delete_tail_from_64_step_chain() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_94_load_delete_tail_from_64_step_chain")?;
    let blocks = make_linear_chain(64, 9400)?;
    view.apply_canonical_attach(&steps_from_blocks(&blocks))?;

    view.delete_height_range(32, 63)?;

    for height in 0u64..32u64 {
        assert!(view.has_height(height)?);
    }
    for height in 32u64..64u64 {
        assert!(!view.has_height(height)?);
    }

    Ok(())
}

#[test]
fn test_95_load_switch_tail_of_64_step_chain() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_95_load_switch_tail_of_64_step_chain")?;
    let blocks = make_linear_chain(64, 9500)?;
    view.apply_canonical_attach(&steps_from_blocks(&blocks))?;

    let replacement_32 = deterministic_hash(9532);
    let replacement_33 = deterministic_hash(9533);
    view.switch_canonical_range(
        Some(32),
        Some(63),
        &[(32u64, replacement_32), (33u64, replacement_33)],
    )?;

    assert_eq!(
        required(view.get_hash_at_height(31)?, "height 31 kept")?,
        block_at(&blocks, 31)?.block_hash
    );
    assert_eq!(
        required(view.get_hash_at_height(32)?, "replacement 32")?,
        replacement_32
    );
    assert_eq!(
        required(view.get_hash_at_height(33)?, "replacement 33")?,
        replacement_33
    );
    assert!(!view.has_height(34)?);
    assert_tip(&view, replacement_33, 33)
}

#[test]
fn test_96_load_repeated_tip_overwrites_128_times() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_96_load_repeated_tip_overwrites_128_times")?;
    let mut last_height = 0u64;
    let mut last_hash = [0u8; 64];

    for height in 0u64..128u64 {
        last_hash = deterministic_hash(9_600u64.saturating_add(height));
        last_height = height;
        view.set_tip(&last_hash, last_height)?;
    }

    assert_tip(&view, last_hash, last_height)
}

#[test]
fn test_97_load_repeated_full_attach_batches() -> TestResult {
    let (view, _block_index, _db) = fresh_views("test_97_load_repeated_full_attach_batches")?;

    for base in [9_700u64, 9_800u64, 9_900u64] {
        let blocks = make_linear_chain(8, base)?;
        view.apply_canonical_attach(&steps_from_blocks(&blocks))?;
        let tip = last_block(&blocks)?;
        assert_tip(&view, tip.block_hash, tip.metadata.index)?;
    }

    Ok(())
}

#[test]
fn test_98_edge_canonical_steps_up_to_after_tip_set_but_no_mappings_errors() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_98_edge_canonical_steps_up_to_after_tip_set_but_no_mappings_errors")?;
    let hash = deterministic_hash(98);

    view.set_tip(&hash, 10)?;

    assert_not_found(view.canonical_steps_up_to(10))?;
    Ok(())
}

#[test]
fn test_99_edge_ensure_initialized_does_not_overwrite_existing_tip() -> TestResult {
    let (view, _block_index, _db) =
        fresh_views("test_99_edge_ensure_initialized_does_not_overwrite_existing_tip")?;
    let hash = deterministic_hash(99);

    view.set_tip(&hash, 99)?;

    let initialized = required(view.ensure_initialized()?, "existing initialized tip")?;
    assert_eq!(initialized.tip_hash, hash);
    assert_eq!(initialized.tip_height, 99);
    assert_tip(&view, hash, 99)
}

#[test]
fn test_100_end_to_end_reorg_chain_view_flow() -> TestResult {
    let (view, block_index, _db) = fresh_views("test_100_end_to_end_reorg_chain_view_flow")?;
    let canonical = make_linear_chain(5, 10_000)?;
    store_and_map_blocks(&view, &block_index, &canonical, ForkBlockStatus::Canonical)?;
    let canonical_tip = last_block(&canonical)?;
    view.set_tip(&canonical_tip.block_hash, canonical_tip.metadata.index)?;

    let fork_parent = block_at(&canonical, 2)?;
    let fork_3 = make_block(3, fork_parent.block_hash, 10_100)?;
    let fork_4 = make_block(4, fork_3.block_hash, 10_101)?;
    let fork_5 = make_block(5, fork_4.block_hash, 10_102)?;

    store_block_with_status(&block_index, &fork_3, ForkBlockStatus::SideBranch)?;
    store_block_with_status(&block_index, &fork_4, ForkBlockStatus::SideBranch)?;
    store_block_with_status(&block_index, &fork_5, ForkBlockStatus::SideBranch)?;

    view.switch_canonical_range(
        Some(3),
        Some(4),
        &[
            (3u64, fork_3.block_hash),
            (4u64, fork_4.block_hash),
            (5u64, fork_5.block_hash),
        ],
    )?;

    assert_eq!(
        required(view.get_hash_at_height(0)?, "height zero")?,
        block_at(&canonical, 0)?.block_hash
    );
    assert_eq!(
        required(view.get_hash_at_height(1)?, "height one")?,
        block_at(&canonical, 1)?.block_hash
    );
    assert_eq!(
        required(view.get_hash_at_height(2)?, "height two")?,
        block_at(&canonical, 2)?.block_hash
    );
    assert_eq!(
        required(view.get_hash_at_height(3)?, "fork height three")?,
        fork_3.block_hash
    );
    assert_eq!(
        required(view.get_hash_at_height(4)?, "fork height four")?,
        fork_4.block_hash
    );
    assert_eq!(
        required(view.get_hash_at_height(5)?, "fork height five")?,
        fork_5.block_hash
    );
    assert_tip(&view, fork_5.block_hash, 5)?;

    let chosen = view.choose_better_tip(
        &canonical_tip.block_hash,
        canonical_tip.metadata.index,
        &fork_5.block_hash,
        fork_5.metadata.index,
        true,
    )?;
    assert_eq!(chosen, fork_5.block_hash);

    Ok(())
}
