use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::reorganization::reorg_001_block_index::BlockHash;
use remzar::reorganization::reorg_001_block_index::ReorgBlockIndex;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};
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

fn fresh_index(label: &str) -> Result<(ReorgBlockIndex, Arc<RockDBManager>), ErrorDetection> {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "remzar_reorg_001_block_index_{label}_{}_{}",
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
    let index = ReorgBlockIndex::new(Arc::clone(&db));
    Ok((index, db))
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
    let batch_key = Some(format!("batch-key-height-{height}-tag-{tag}"));
    Block::new(
        metadata,
        batch_key,
        GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        0,
    )
}

fn make_block_with_batch_key(
    height: u64,
    parent_hash: BlockHash,
    tag: u64,
    batch_key: Option<String>,
) -> Result<Block, ErrorDetection> {
    let metadata = make_metadata(height, parent_hash, tag);
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

fn store_block_with_score(
    index: &ReorgBlockIndex,
    block: &Block,
    status: ForkBlockStatus,
    score: u128,
) -> Result<ForkBlockMeta, ErrorDetection> {
    let meta = meta_for(block, status, score);
    index.put_block_and_meta(block, &meta)?;
    Ok(meta)
}

fn store_block(
    index: &ReorgBlockIndex,
    block: &Block,
    status: ForkBlockStatus,
) -> Result<ForkBlockMeta, ErrorDetection> {
    store_block_with_score(index, block, status, u128::from(block.metadata.index))
}

fn store_chain(
    index: &ReorgBlockIndex,
    blocks: &[Block],
    status: ForkBlockStatus,
) -> Result<(), ErrorDetection> {
    for block in blocks {
        let _meta = store_block(index, block, status)?;
    }
    Ok(())
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

fn all_statuses() -> [ForkBlockStatus; 6] {
    [
        ForkBlockStatus::HeaderOnly,
        ForkBlockStatus::BlockStored,
        ForkBlockStatus::Validated,
        ForkBlockStatus::Canonical,
        ForkBlockStatus::SideBranch,
        ForkBlockStatus::Orphan,
    ]
}

#[test]
fn test_01_new_keeps_same_db_arc() -> TestResult {
    let (index, db) = fresh_index("test_01_new_keeps_same_db_arc")?;
    assert!(Arc::ptr_eq(index.db(), &db));
    Ok(())
}

#[test]
fn test_02_put_block_get_block_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_02_put_block_get_block_roundtrip_vector")?;
    let block = make_block(0, [0u8; 64], 2)?;
    index.put_block(&block)?;

    let fetched = required(index.get_block(&block.block_hash)?, "stored block")?;
    assert_eq!(fetched, block);
    assert!(fetched.verify_block_hash()?);
    Ok(())
}

#[test]
fn test_03_put_block_bytes_canonicalizes_padded_storage_vector() -> TestResult {
    let (index, _db) = fresh_index("test_03_put_block_bytes_canonicalizes_padded_storage_vector")?;
    let block = make_block(0, [0u8; 64], 3)?;
    let canonical = block.serialize_for_storage()?;
    let mut padded = canonical.clone();
    padded.extend_from_slice(&[0u8; 32]);

    index.put_block_bytes(&block.block_hash, &padded)?;

    let fetched = required(
        index.get_block(&block.block_hash)?,
        "block from padded bytes",
    )?;
    let fetched_bytes = fetched.serialize_for_storage()?;
    assert_eq!(fetched, block);
    assert_eq!(fetched_bytes, canonical);
    Ok(())
}

#[test]
fn test_04_get_block_absent_hash_returns_none_vector() -> TestResult {
    let (index, _db) = fresh_index("test_04_get_block_absent_hash_returns_none_vector")?;
    let missing_hash = deterministic_hash(404);
    assert!(index.get_block(&missing_hash)?.is_none());
    Ok(())
}

#[test]
fn test_05_has_block_flips_after_put_vector() -> TestResult {
    let (index, _db) = fresh_index("test_05_has_block_flips_after_put_vector")?;
    let block = make_block(0, [0u8; 64], 5)?;
    assert!(!index.has_block(&block.block_hash));

    index.put_block(&block)?;

    assert!(index.has_block(&block.block_hash));
    Ok(())
}

#[test]
fn test_06_put_meta_get_meta_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_06_put_meta_get_meta_roundtrip_vector")?;
    let block = make_block(0, [0u8; 64], 6)?;
    let meta = meta_for(&block, ForkBlockStatus::HeaderOnly, 123);

    index.put_meta(&block.block_hash, &meta)?;

    let fetched = required(index.get_meta(&block.block_hash)?, "stored metadata")?;
    assert_eq!(fetched, meta);
    Ok(())
}

#[test]
fn test_07_has_meta_flips_after_put_vector() -> TestResult {
    let (index, _db) = fresh_index("test_07_has_meta_flips_after_put_vector")?;
    let block = make_block(0, [0u8; 64], 7)?;
    let meta = meta_for(&block, ForkBlockStatus::Validated, 7);

    assert!(!index.has_meta(&block.block_hash)?);
    index.put_meta(&block.block_hash, &meta)?;
    assert!(index.has_meta(&block.block_hash)?);
    Ok(())
}

#[test]
fn test_08_put_block_and_meta_stores_both_vector() -> TestResult {
    let (index, _db) = fresh_index("test_08_put_block_and_meta_stores_both_vector")?;
    let block = make_block(0, [0u8; 64], 8)?;
    let meta = meta_for(&block, ForkBlockStatus::BlockStored, 8);

    index.put_block_and_meta(&block, &meta)?;

    assert!(index.has_block(&block.block_hash));
    assert!(index.has_meta(&block.block_hash)?);
    assert_eq!(required(index.get_meta(&block.block_hash)?, "meta")?, meta);
    Ok(())
}

#[test]
fn test_09_ingest_validated_block_stores_batch_by_hash_vector() -> TestResult {
    let (index, _db) = fresh_index("test_09_ingest_validated_block_stores_batch_by_hash_vector")?;
    let block = make_block(0, [0u8; 64], 9)?;
    let meta = meta_for(&block, ForkBlockStatus::Validated, 9);
    let batch_bytes = b"batch-for-block-hash-vector";

    index.ingest_validated_block(&block, meta.clone(), Some(batch_bytes))?;

    assert_eq!(required(index.get_meta(&block.block_hash)?, "meta")?, meta);
    assert_eq!(
        required(
            index.db().get_batch_by_block_hash(&block.block_hash)?,
            "batch by block hash"
        )?,
        batch_bytes.to_vec()
    );
    Ok(())
}

#[test]
fn test_10_make_height_meta_uses_block_height_and_parent_vector() -> TestResult {
    let (index, _db) = fresh_index("test_10_make_height_meta_uses_block_height_and_parent_vector")?;
    let parent = make_block(0, [0u8; 64], 10)?;
    let block = make_block(1, parent.block_hash, 11)?;

    let meta = index.make_height_meta(&block, ForkBlockStatus::Validated);

    assert_eq!(meta.parent_hash, parent.block_hash);
    assert_eq!(meta.height, 1);
    assert_eq!(meta.cumulative_score, 1);
    assert_eq!(meta.status, ForkBlockStatus::Validated);
    assert!(meta.received_at_unix_secs > 0);
    Ok(())
}

#[test]
fn test_11_make_scored_meta_preserves_explicit_score_vector() -> TestResult {
    let (index, _db) = fresh_index("test_11_make_scored_meta_preserves_explicit_score_vector")?;
    let parent = make_block(0, [0u8; 64], 12)?;
    let block = make_block(1, parent.block_hash, 13)?;

    let meta = index.make_scored_meta(&block, 99_999, ForkBlockStatus::SideBranch);

    assert_eq!(meta.parent_hash, parent.block_hash);
    assert_eq!(meta.height, 1);
    assert_eq!(meta.cumulative_score, 99_999);
    assert_eq!(meta.status, ForkBlockStatus::SideBranch);
    assert!(meta.received_at_unix_secs > 0);
    Ok(())
}

#[test]
fn test_12_parent_height_status_helpers_vector() -> TestResult {
    let (index, _db) = fresh_index("test_12_parent_height_status_helpers_vector")?;
    let chain = make_linear_chain(2, 20)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let child = block_at(&chain, 1)?;
    let parent = block_at(&chain, 0)?;

    assert_eq!(
        required(index.parent_hash(&child.block_hash)?, "parent hash")?,
        parent.block_hash
    );
    assert_eq!(required(index.height_of(&child.block_hash)?, "height")?, 1);
    assert_eq!(
        required(index.status_of(&child.block_hash)?, "status")?,
        ForkBlockStatus::Validated
    );
    Ok(())
}

#[test]
fn test_13_mark_canonical_updates_status_vector() -> TestResult {
    let (index, _db) = fresh_index("test_13_mark_canonical_updates_status_vector")?;
    let block = make_block(0, [0u8; 64], 30)?;
    let _meta = store_block(&index, &block, ForkBlockStatus::Validated)?;

    index.mark_canonical(&block.block_hash)?;

    assert_eq!(
        required(index.status_of(&block.block_hash)?, "status")?,
        ForkBlockStatus::Canonical
    );
    Ok(())
}

#[test]
fn test_14_mark_side_branch_updates_status_vector() -> TestResult {
    let (index, _db) = fresh_index("test_14_mark_side_branch_updates_status_vector")?;
    let block = make_block(0, [0u8; 64], 31)?;
    let _meta = store_block(&index, &block, ForkBlockStatus::Validated)?;

    index.mark_side_branch(&block.block_hash)?;

    assert_eq!(
        required(index.status_of(&block.block_hash)?, "status")?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_15_mark_orphan_updates_status_vector() -> TestResult {
    let (index, _db) = fresh_index("test_15_mark_orphan_updates_status_vector")?;
    let block = make_block(0, [0u8; 64], 32)?;
    let _meta = store_block(&index, &block, ForkBlockStatus::Validated)?;

    index.mark_orphan(&block.block_hash)?;

    assert_eq!(
        required(index.status_of(&block.block_hash)?, "status")?,
        ForkBlockStatus::Orphan
    );
    Ok(())
}

#[test]
fn test_16_has_known_parent_false_for_missing_meta_edge() -> TestResult {
    let (index, _db) = fresh_index("test_16_has_known_parent_false_for_missing_meta_edge")?;
    let missing_hash = deterministic_hash(1600);
    assert!(!index.has_known_parent(&missing_hash)?);
    Ok(())
}

#[test]
fn test_17_has_known_parent_true_for_zero_root_parent_edge() -> TestResult {
    let (index, _db) = fresh_index("test_17_has_known_parent_true_for_zero_root_parent_edge")?;
    let genesis = make_block(0, [0u8; 64], 1700)?;
    let _meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;

    assert!(index.has_known_parent(&genesis.block_hash)?);
    Ok(())
}

#[test]
fn test_18_has_known_parent_false_for_unknown_nonzero_parent_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_18_has_known_parent_false_for_unknown_nonzero_parent_edge")?;
    let unknown_parent = deterministic_hash(1800);
    let child = make_block(1, unknown_parent, 1801)?;
    let _meta = store_block(&index, &child, ForkBlockStatus::Orphan)?;

    assert!(!index.has_known_parent(&child.block_hash)?);
    Ok(())
}

#[test]
fn test_19_get_parent_block_none_when_child_meta_missing_edge() -> TestResult {
    let (index, _db) = fresh_index("test_19_get_parent_block_none_when_child_meta_missing_edge")?;
    let missing_hash = deterministic_hash(1900);

    assert!(index.get_parent_block(&missing_hash)?.is_none());
    Ok(())
}

#[test]
fn test_20_get_parent_block_none_for_zero_parent_edge() -> TestResult {
    let (index, _db) = fresh_index("test_20_get_parent_block_none_for_zero_parent_edge")?;
    let genesis = make_block(0, [0u8; 64], 2000)?;
    let _meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;

    assert!(index.get_parent_block(&genesis.block_hash)?.is_none());
    Ok(())
}

#[test]
fn test_21_get_parent_block_returns_parent_edge() -> TestResult {
    let (index, _db) = fresh_index("test_21_get_parent_block_returns_parent_edge")?;
    let chain = make_linear_chain(2, 2100)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;

    let parent = block_at(&chain, 0)?;
    let child = block_at(&chain, 1)?;
    let fetched_parent = required(index.get_parent_block(&child.block_hash)?, "parent block")?;

    assert_eq!(fetched_parent, *parent);
    Ok(())
}

#[test]
fn test_22_get_parent_meta_returns_parent_meta_edge() -> TestResult {
    let (index, _db) = fresh_index("test_22_get_parent_meta_returns_parent_meta_edge")?;
    let chain = make_linear_chain(2, 2200)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;

    let parent = block_at(&chain, 0)?;
    let child = block_at(&chain, 1)?;
    let parent_meta = required(index.get_meta(&parent.block_hash)?, "parent meta")?;
    let fetched_parent_meta = required(index.get_parent_meta(&child.block_hash)?, "parent meta")?;

    assert_eq!(fetched_parent_meta, parent_meta);
    Ok(())
}

#[test]
fn test_23_build_path_from_tip_zero_depth_is_empty_edge() -> TestResult {
    let (index, _db) = fresh_index("test_23_build_path_from_tip_zero_depth_is_empty_edge")?;
    let chain = make_linear_chain(3, 2300)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    let path = index.build_path_from_tip(&tip.block_hash, 0)?;

    assert!(path.is_empty());
    Ok(())
}

#[test]
fn test_24_build_path_from_tip_walks_tip_to_root_edge() -> TestResult {
    let (index, _db) = fresh_index("test_24_build_path_from_tip_walks_tip_to_root_edge")?;
    let chain = make_linear_chain(4, 2400)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    let path = index.build_path_from_tip(&tip.block_hash, 10)?;

    assert_eq!(path.len(), 4);
    assert_eq!(required(path.first().copied(), "path first")?.0, 3);
    assert_eq!(
        required(path.first().copied(), "path first")?.1,
        tip.block_hash
    );
    assert_eq!(required(path.last().copied(), "path last")?.0, 0);
    assert_eq!(
        required(path.last().copied(), "path last")?.1,
        block_at(&chain, 0)?.block_hash
    );
    Ok(())
}

#[test]
fn test_25_first_missing_ancestor_reports_start_when_start_meta_missing_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_25_first_missing_ancestor_reports_start_when_start_meta_missing_edge")?;
    let missing_hash = deterministic_hash(2500);

    let missing = required(
        index.first_missing_ancestor(&missing_hash, 10)?,
        "missing start ancestor",
    )?;

    assert_eq!(missing, missing_hash);
    Ok(())
}

#[test]
fn test_26_first_missing_ancestor_reports_unknown_parent_edge() -> TestResult {
    let (index, _db) = fresh_index("test_26_first_missing_ancestor_reports_unknown_parent_edge")?;
    let unknown_parent = deterministic_hash(2600);
    let child = make_block(1, unknown_parent, 2601)?;
    let _meta = store_block(&index, &child, ForkBlockStatus::Orphan)?;

    let missing = required(
        index.first_missing_ancestor(&child.block_hash, 10)?,
        "missing parent ancestor",
    )?;

    assert_eq!(missing, unknown_parent);
    Ok(())
}

#[test]
fn test_27_first_missing_ancestor_none_for_complete_chain_edge() -> TestResult {
    let (index, _db) = fresh_index("test_27_first_missing_ancestor_none_for_complete_chain_edge")?;
    let chain = make_linear_chain(5, 2700)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    assert!(index.first_missing_ancestor(&tip.block_hash, 10)?.is_none());
    Ok(())
}

#[test]
fn test_28_validate_block_meta_consistency_success_edge() -> TestResult {
    let (index, _db) = fresh_index("test_28_validate_block_meta_consistency_success_edge")?;
    let chain = make_linear_chain(3, 2800)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;

    for block in &chain {
        index.validate_block_meta_consistency(&block.block_hash)?;
    }

    Ok(())
}

#[test]
fn test_29_validate_block_meta_consistency_missing_block_errors_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_29_validate_block_meta_consistency_missing_block_errors_edge")?;
    let missing_hash = deterministic_hash(2900);
    let meta = ForkBlockMeta {
        parent_hash: [0u8; 64],
        height: 0,
        cumulative_score: 0,
        status: ForkBlockStatus::HeaderOnly,
        received_at_unix_secs: timestamp_at(0),
    };
    index.put_meta(&missing_hash, &meta)?;

    let result = index.validate_block_meta_consistency(&missing_hash);

    assert!(matches!(result, Err(ErrorDetection::NotFound { .. })));
    Ok(())
}

#[test]
fn test_30_validate_block_meta_consistency_missing_meta_errors_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_30_validate_block_meta_consistency_missing_meta_errors_edge")?;
    let block = make_block(0, [0u8; 64], 3000)?;
    index.put_block(&block)?;

    let result = index.validate_block_meta_consistency(&block.block_hash);

    assert!(matches!(result, Err(ErrorDetection::NotFound { .. })));
    Ok(())
}

#[test]
fn test_31_validate_block_meta_consistency_hash_mismatch_errors_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_31_validate_block_meta_consistency_hash_mismatch_errors_edge")?;
    let block = make_block(0, [0u8; 64], 3100)?;
    let wrong_hash = deterministic_hash(3101);
    let bytes = block.serialize_for_storage()?;
    let meta = meta_for(&block, ForkBlockStatus::Validated, 0);

    index.put_block_bytes(&wrong_hash, &bytes)?;
    index.put_meta(&wrong_hash, &meta)?;

    let result = index.validate_block_meta_consistency(&wrong_hash);

    assert!(matches!(
        result,
        Err(ErrorDetection::BlockchainError { .. })
    ));
    Ok(())
}

#[test]
fn test_32_validate_block_meta_consistency_height_mismatch_errors_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_32_validate_block_meta_consistency_height_mismatch_errors_edge")?;
    let block = make_block(0, [0u8; 64], 3200)?;
    index.put_block(&block)?;

    let wrong_meta = ForkBlockMeta {
        parent_hash: block.metadata.previous_hash,
        height: 9,
        cumulative_score: 9,
        status: ForkBlockStatus::Validated,
        received_at_unix_secs: block.metadata.timestamp,
    };
    index.put_meta(&block.block_hash, &wrong_meta)?;

    let result = index.validate_block_meta_consistency(&block.block_hash);

    assert!(matches!(
        result,
        Err(ErrorDetection::BlockchainError { .. })
    ));
    Ok(())
}

#[test]
fn test_33_validate_block_meta_consistency_parent_mismatch_errors_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_33_validate_block_meta_consistency_parent_mismatch_errors_edge")?;
    let parent = make_block(0, [0u8; 64], 3300)?;
    let child = make_block(1, parent.block_hash, 3301)?;
    index.put_block(&child)?;

    let wrong_meta = ForkBlockMeta {
        parent_hash: deterministic_hash(3399),
        height: child.metadata.index,
        cumulative_score: 33,
        status: ForkBlockStatus::Validated,
        received_at_unix_secs: child.metadata.timestamp,
    };
    index.put_meta(&child.block_hash, &wrong_meta)?;

    let result = index.validate_block_meta_consistency(&child.block_hash);

    assert!(matches!(
        result,
        Err(ErrorDetection::BlockchainError { .. })
    ));
    Ok(())
}

#[test]
fn test_34_property_fork_block_status_byte_roundtrip_all_statuses() -> TestResult {
    for status in all_statuses() {
        assert_eq!(ForkBlockStatus::from_u8(status.as_u8())?, status);
    }

    assert!(ForkBlockStatus::from_u8(6).is_err());
    Ok(())
}

#[test]
fn test_35_property_fork_block_meta_binary_roundtrip_and_rejects_bad_bytes() -> TestResult {
    let parent_hash = deterministic_hash(3500);

    for status in all_statuses() {
        let meta = ForkBlockMeta {
            parent_hash,
            height: 35,
            cumulative_score: 35_000,
            status,
            received_at_unix_secs: timestamp_at(35),
        };

        let bytes = meta.to_bytes();
        assert_eq!(bytes.len(), 97);
        assert_eq!(ForkBlockMeta::from_bytes(&bytes)?, meta);

        let mut bad_status = bytes.clone();
        match bad_status.get_mut(88) {
            Some(slot) => *slot = 255,
            None => {
                return Err(storage_error(
                    "ForkBlockMeta status byte position missing in test".to_owned(),
                ));
            }
        }
        assert!(ForkBlockMeta::from_bytes(&bad_status).is_err());
    }

    assert!(ForkBlockMeta::from_bytes(&[]).is_err());
    Ok(())
}

#[test]
fn test_36_property_none_and_empty_batch_key_have_same_block_hash() -> TestResult {
    let parent_hash = deterministic_hash(3600);

    let none_key = make_block_with_batch_key(1, parent_hash, 3601, None)?;
    let empty_key = make_block_with_batch_key(1, parent_hash, 3601, Some(String::new()))?;

    assert_eq!(none_key.block_hash, empty_key.block_hash);
    assert!(none_key.verify_block_hash()?);
    assert!(empty_key.verify_block_hash()?);
    Ok(())
}

#[test]
fn test_37_property_paths_descend_strictly_by_height_for_many_lengths() -> TestResult {
    let (index, _db) =
        fresh_index("test_37_property_paths_descend_strictly_by_height_for_many_lengths")?;

    for len in 1u64..9u64 {
        let chain = make_linear_chain(len, 3700u64.saturating_add(len.saturating_mul(100)))?;
        store_chain(&index, &chain, ForkBlockStatus::Validated)?;
        let tip = last_block(&chain)?;
        let path = index.build_path_from_tip(&tip.block_hash, 32)?;

        let mut previous_height: Option<u64> = None;
        for (height, _hash) in &path {
            if let Some(prev) = previous_height {
                assert!(prev > *height);
                assert_eq!(prev.saturating_sub(1), *height);
            }
            previous_height = Some(*height);
        }

        assert_eq!(path.len(), chain.len());
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// FUZZ-STYLE AND ADVERSARIAL NETWORK SIM TESTS
// ─────────────────────────────────────────────────────────────

#[test]
fn test_38_fuzz_deterministic_many_branches_keep_consistent_paths() -> TestResult {
    let (index, _db) =
        fresh_index("test_38_fuzz_deterministic_many_branches_keep_consistent_paths")?;
    let genesis = make_block(0, [0u8; 64], 3800)?;
    let _genesis_meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;

    let mut parent_hash = genesis.block_hash;

    for branch_id in 1u64..33u64 {
        let height = branch_id;
        let tag = 3_800u64.saturating_add(branch_id.saturating_mul(17));
        let block = make_block(height, parent_hash, tag)?;
        let status = if branch_id == 1 {
            ForkBlockStatus::Validated
        } else {
            ForkBlockStatus::SideBranch
        };
        let _meta = store_block_with_score(
            &index,
            &block,
            status,
            u128::from(height).saturating_mul(100),
        )?;

        assert!(index.has_block(&block.block_hash));
        assert!(index.has_meta(&block.block_hash)?);
        assert!(
            index
                .first_missing_ancestor(&block.block_hash, 64)?
                .is_none()
        );
        index.validate_block_meta_consistency(&block.block_hash)?;

        let path = index.build_path_from_tip(&block.block_hash, 64)?;
        assert_eq!(
            required(path.first().copied(), "fuzz path tip")?.1,
            block.block_hash
        );

        parent_hash = block.block_hash;
    }

    Ok(())
}

#[test]
fn test_39_adversarial_network_sim_child_before_parent_then_parent_heals_orphan() -> TestResult {
    let (index, _db) = fresh_index(
        "test_39_adversarial_network_sim_child_before_parent_then_parent_heals_orphan",
    )?;
    let parent = make_block(0, [0u8; 64], 3900)?;
    let child = make_block(1, parent.block_hash, 3901)?;

    let _child_meta = store_block(&index, &child, ForkBlockStatus::Orphan)?;

    assert!(!index.has_known_parent(&child.block_hash)?);
    assert_eq!(
        required(
            index.first_missing_ancestor(&child.block_hash, 8)?,
            "missing parent"
        )?,
        parent.block_hash
    );

    let _parent_meta = store_block(&index, &parent, ForkBlockStatus::Canonical)?;

    assert!(index.has_known_parent(&child.block_hash)?);
    assert!(
        index
            .first_missing_ancestor(&child.block_hash, 8)?
            .is_none()
    );

    index.mark_side_branch(&child.block_hash)?;
    assert_eq!(
        required(index.status_of(&child.block_hash)?, "child status")?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_40_load_ingest_96_blocks_validate_paths_statuses_and_batches() -> TestResult {
    let (index, _db) =
        fresh_index("test_40_load_ingest_96_blocks_validate_paths_statuses_and_batches")?;
    let chain = make_linear_chain(96, 4000)?;

    for block in &chain {
        let meta = meta_for(
            block,
            ForkBlockStatus::Validated,
            u128::from(block.metadata.index).saturating_mul(10),
        );
        let batch_payload = block.metadata.index.to_be_bytes();
        index.ingest_validated_block(block, meta, Some(batch_payload.as_slice()))?;
    }

    let tip = last_block(&chain)?;
    let path = index.build_path_from_tip(&tip.block_hash, 128)?;
    assert_eq!(path.len(), chain.len());

    for block in &chain {
        assert!(index.has_block(&block.block_hash));
        assert!(index.has_meta(&block.block_hash)?);
        index.validate_block_meta_consistency(&block.block_hash)?;
        index.mark_side_branch(&block.block_hash)?;
        assert_eq!(
            required(index.status_of(&block.block_hash)?, "load status")?,
            ForkBlockStatus::SideBranch
        );

        let expected_batch = block.metadata.index.to_be_bytes().to_vec();
        let stored_batch = required(
            index.db().get_batch_by_block_hash(&block.block_hash)?,
            "load batch by hash",
        )?;
        assert_eq!(stored_batch, expected_batch);
    }

    let ancestor = block_at(&chain, 0)?;
    let found = required(
        index
            .db()
            .find_common_ancestor_hash(&tip.block_hash, &ancestor.block_hash, 128)?,
        "common ancestor in load test",
    )?;
    assert_eq!(found, ancestor.block_hash);

    Ok(())
}

#[test]
fn test_41_set_and_get_canonical_hash_at_height_vector() -> TestResult {
    let (index, _db) = fresh_index("test_41_set_and_get_canonical_hash_at_height_vector")?;
    let chain = make_linear_chain(3, 4100)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;

    for block in &chain {
        index
            .db()
            .set_canonical_hash_at_height(block.metadata.index, &block.block_hash)?;

        let found = required(
            index
                .db()
                .get_canonical_hash_at_height(block.metadata.index)?,
            "canonical hash at height",
        )?;
        assert_eq!(found, block.block_hash);
    }

    Ok(())
}

#[test]
fn test_42_get_canonical_hash_at_height_missing_returns_none_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_42_get_canonical_hash_at_height_missing_returns_none_vector")?;

    assert!(index.db().get_canonical_hash_at_height(42)?.is_none());
    Ok(())
}

#[test]
fn test_43_delete_canonical_hash_range_removes_inclusive_range_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_43_delete_canonical_hash_range_removes_inclusive_range_vector")?;
    let chain = make_linear_chain(6, 4300)?;
    store_chain(&index, &chain, ForkBlockStatus::Canonical)?;

    for block in &chain {
        index
            .db()
            .set_canonical_hash_at_height(block.metadata.index, &block.block_hash)?;
    }

    index.db().delete_canonical_hash_range(2, 4)?;

    assert!(index.db().get_canonical_hash_at_height(0)?.is_some());
    assert!(index.db().get_canonical_hash_at_height(1)?.is_some());
    assert!(index.db().get_canonical_hash_at_height(2)?.is_none());
    assert!(index.db().get_canonical_hash_at_height(3)?.is_none());
    assert!(index.db().get_canonical_hash_at_height(4)?.is_none());
    assert!(index.db().get_canonical_hash_at_height(5)?.is_some());
    Ok(())
}

#[test]
fn test_44_delete_canonical_hash_range_noops_when_start_after_end_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_44_delete_canonical_hash_range_noops_when_start_after_end_vector")?;
    let block = make_block(0, [0u8; 64], 4400)?;
    let _meta = store_block(&index, &block, ForkBlockStatus::Canonical)?;

    index
        .db()
        .set_canonical_hash_at_height(block.metadata.index, &block.block_hash)?;
    index.db().delete_canonical_hash_range(9, 3)?;

    let found = required(
        index
            .db()
            .get_canonical_hash_at_height(block.metadata.index)?,
        "canonical hash after noop delete",
    )?;
    assert_eq!(found, block.block_hash);
    Ok(())
}

#[test]
fn test_45_set_and_get_canonical_tip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_45_set_and_get_canonical_tip_vector")?;
    let chain = make_linear_chain(4, 4500)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    index
        .db()
        .set_canonical_tip(&tip.block_hash, tip.metadata.index)?;

    let view = required(index.db().get_canonical_tip()?, "canonical tip view")?;
    assert_eq!(view.tip_hash, tip.block_hash);
    assert_eq!(view.tip_height, tip.metadata.index);
    assert_eq!(
        required(index.db().get_canonical_tip_hash()?, "canonical tip hash")?,
        tip.block_hash
    );
    assert_eq!(
        required(
            index.db().get_canonical_tip_height()?,
            "canonical tip height"
        )?,
        tip.metadata.index
    );
    Ok(())
}

#[test]
fn test_46_get_canonical_tip_missing_returns_none_vector() -> TestResult {
    let (index, _db) = fresh_index("test_46_get_canonical_tip_missing_returns_none_vector")?;

    assert!(index.db().get_canonical_tip()?.is_none());
    assert!(index.db().get_canonical_tip_hash()?.is_none());
    assert!(index.db().get_canonical_tip_height()?.is_none());
    Ok(())
}

#[test]
fn test_47_promote_block_to_canonical_updates_status_height_mapping_and_tip_vector() -> TestResult {
    let (index, _db) = fresh_index(
        "test_47_promote_block_to_canonical_updates_status_height_mapping_and_tip_vector",
    )?;
    let chain = make_linear_chain(3, 4700)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    index
        .db()
        .promote_block_to_canonical(tip.metadata.index, &tip.block_hash)?;

    assert_eq!(
        required(index.status_of(&tip.block_hash)?, "promoted status")?,
        ForkBlockStatus::Canonical
    );
    assert_eq!(
        required(
            index
                .db()
                .get_canonical_hash_at_height(tip.metadata.index)?,
            "canonical hash"
        )?,
        tip.block_hash
    );
    assert_eq!(
        required(index.db().get_canonical_tip_hash()?, "tip hash")?,
        tip.block_hash
    );
    assert_eq!(
        required(index.db().get_canonical_tip_height()?, "tip height")?,
        tip.metadata.index
    );
    Ok(())
}

#[test]
fn test_48_store_batch_by_block_hash_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_48_store_batch_by_block_hash_roundtrip_vector")?;
    let block = make_block(0, [0u8; 64], 4800)?;
    let batch = b"manual-batch-by-block-hash";

    index
        .db()
        .store_batch_by_block_hash(&block.block_hash, batch)?;

    assert!(index.db().has_batch_by_block_hash(&block.block_hash)?);
    assert_eq!(
        required(
            index.db().get_batch_by_block_hash(&block.block_hash)?,
            "manual batch"
        )?,
        batch.to_vec()
    );
    Ok(())
}

#[test]
fn test_49_batch_by_block_hash_missing_returns_none_vector() -> TestResult {
    let (index, _db) = fresh_index("test_49_batch_by_block_hash_missing_returns_none_vector")?;
    let missing_hash = deterministic_hash(4900);

    assert!(!index.db().has_batch_by_block_hash(&missing_hash)?);
    assert!(index.db().get_batch_by_block_hash(&missing_hash)?.is_none());
    Ok(())
}

#[test]
fn test_50_ingest_validated_block_without_batch_does_not_create_batch_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_50_ingest_validated_block_without_batch_does_not_create_batch_vector")?;
    let block = make_block(0, [0u8; 64], 5000)?;
    let meta = meta_for(&block, ForkBlockStatus::Validated, 50);

    index.ingest_validated_block(&block, meta, None)?;

    assert!(index.has_block(&block.block_hash));
    assert!(index.has_meta(&block.block_hash)?);
    assert!(!index.db().has_batch_by_block_hash(&block.block_hash)?);
    Ok(())
}

#[test]
fn test_51_set_status_missing_meta_returns_not_found_edge() -> TestResult {
    let (index, _db) = fresh_index("test_51_set_status_missing_meta_returns_not_found_edge")?;
    let missing_hash = deterministic_hash(5100);

    let result = index.set_status(&missing_hash, ForkBlockStatus::Canonical);

    assert!(matches!(result, Err(ErrorDetection::NotFound { .. })));
    Ok(())
}

#[test]
fn test_52_promote_missing_meta_returns_not_found_edge() -> TestResult {
    let (index, _db) = fresh_index("test_52_promote_missing_meta_returns_not_found_edge")?;
    let missing_hash = deterministic_hash(5200);

    let result = index.db().promote_block_to_canonical(52, &missing_hash);

    assert!(matches!(result, Err(ErrorDetection::NotFound { .. })));
    Ok(())
}

#[test]
fn test_53_build_path_from_tip_missing_start_returns_empty_edge() -> TestResult {
    let (index, _db) = fresh_index("test_53_build_path_from_tip_missing_start_returns_empty_edge")?;
    let missing_hash = deterministic_hash(5300);

    let path = index.build_path_from_tip(&missing_hash, 10)?;

    assert!(path.is_empty());
    Ok(())
}

#[test]
fn test_54_hash_ancestry_path_missing_start_includes_start_only_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_54_hash_ancestry_path_missing_start_includes_start_only_edge")?;
    let missing_hash = deterministic_hash(5400);

    let path = index.db().build_hash_ancestry_path(&missing_hash, 10)?;

    assert_eq!(path.len(), 1);
    assert_eq!(
        required(path.first().copied(), "missing-start ancestry hash")?,
        missing_hash
    );
    Ok(())
}

#[test]
fn test_55_hash_ancestry_path_zero_depth_returns_empty_edge() -> TestResult {
    let (index, _db) = fresh_index("test_55_hash_ancestry_path_zero_depth_returns_empty_edge")?;
    let chain = make_linear_chain(2, 5500)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    let path = index.db().build_hash_ancestry_path(&tip.block_hash, 0)?;

    assert!(path.is_empty());
    Ok(())
}

#[test]
fn test_56_first_missing_ancestor_respects_max_depth_edge() -> TestResult {
    let (index, _db) = fresh_index("test_56_first_missing_ancestor_respects_max_depth_edge")?;
    let unknown_parent = deterministic_hash(5600);
    let child = make_block(1, unknown_parent, 5601)?;
    let _meta = store_block(&index, &child, ForkBlockStatus::Orphan)?;

    assert!(
        index
            .first_missing_ancestor(&child.block_hash, 0)?
            .is_none()
    );
    assert_eq!(
        required(
            index.first_missing_ancestor(&child.block_hash, 1)?,
            "missing parent within depth"
        )?,
        unknown_parent
    );
    Ok(())
}

#[test]
fn test_57_parent_meta_none_for_zero_parent_edge() -> TestResult {
    let (index, _db) = fresh_index("test_57_parent_meta_none_for_zero_parent_edge")?;
    let genesis = make_block(0, [0u8; 64], 5700)?;
    let _meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;

    assert!(index.get_parent_meta(&genesis.block_hash)?.is_none());
    Ok(())
}

#[test]
fn test_58_parent_hash_none_for_missing_meta_edge() -> TestResult {
    let (index, _db) = fresh_index("test_58_parent_hash_none_for_missing_meta_edge")?;
    let missing_hash = deterministic_hash(5800);

    assert!(index.parent_hash(&missing_hash)?.is_none());
    assert!(index.height_of(&missing_hash)?.is_none());
    assert!(index.status_of(&missing_hash)?.is_none());
    Ok(())
}

#[test]
fn test_59_put_meta_overwrites_existing_status_and_score_edge() -> TestResult {
    let (index, _db) = fresh_index("test_59_put_meta_overwrites_existing_status_and_score_edge")?;
    let block = make_block(0, [0u8; 64], 5900)?;
    let original = meta_for(&block, ForkBlockStatus::HeaderOnly, 1);
    let replacement = ForkBlockMeta {
        parent_hash: block.metadata.previous_hash,
        height: block.metadata.index,
        cumulative_score: 999,
        status: ForkBlockStatus::Validated,
        received_at_unix_secs: timestamp_at(59),
    };

    index.put_meta(&block.block_hash, &original)?;
    index.put_meta(&block.block_hash, &replacement)?;

    assert_eq!(
        required(index.get_meta(&block.block_hash)?, "replacement meta")?,
        replacement
    );
    Ok(())
}

#[test]
fn test_60_put_block_overwrites_same_hash_without_losing_meta_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_60_put_block_overwrites_same_hash_without_losing_meta_edge")?;
    let block = make_block(0, [0u8; 64], 6000)?;
    let meta = meta_for(&block, ForkBlockStatus::Validated, 60);

    index.put_block_and_meta(&block, &meta)?;
    index.put_block(&block)?;

    assert_eq!(
        required(index.get_block(&block.block_hash)?, "block")?,
        block
    );
    assert_eq!(required(index.get_meta(&block.block_hash)?, "meta")?, meta);
    Ok(())
}

#[test]
fn test_61_property_promote_each_height_updates_tip_monotonically() -> TestResult {
    let (index, _db) =
        fresh_index("test_61_property_promote_each_height_updates_tip_monotonically")?;
    let chain = make_linear_chain(8, 6100)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;

    for block in &chain {
        index
            .db()
            .promote_block_to_canonical(block.metadata.index, &block.block_hash)?;

        assert_eq!(
            required(index.db().get_canonical_tip_height()?, "tip height")?,
            block.metadata.index
        );
        assert_eq!(
            required(index.db().get_canonical_tip_hash()?, "tip hash")?,
            block.block_hash
        );
        assert_eq!(
            required(index.status_of(&block.block_hash)?, "status")?,
            ForkBlockStatus::Canonical
        );
    }

    Ok(())
}

#[test]
fn test_62_property_canonical_hash_mapping_is_rewritable_per_height() -> TestResult {
    let (index, _db) =
        fresh_index("test_62_property_canonical_hash_mapping_is_rewritable_per_height")?;
    let genesis = make_block(0, [0u8; 64], 6200)?;
    let branch_a = make_block(1, genesis.block_hash, 6201)?;
    let branch_b = make_block(1, genesis.block_hash, 6202)?;

    let _genesis_meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;
    let _a_meta = store_block(&index, &branch_a, ForkBlockStatus::Canonical)?;
    let _b_meta = store_block(&index, &branch_b, ForkBlockStatus::SideBranch)?;

    index
        .db()
        .set_canonical_hash_at_height(1, &branch_a.block_hash)?;
    assert_eq!(
        required(index.db().get_canonical_hash_at_height(1)?, "branch a map")?,
        branch_a.block_hash
    );

    index
        .db()
        .set_canonical_hash_at_height(1, &branch_b.block_hash)?;
    assert_eq!(
        required(index.db().get_canonical_hash_at_height(1)?, "branch b map")?,
        branch_b.block_hash
    );
    Ok(())
}

#[test]
fn test_63_property_batch_by_hash_overwrite_keeps_latest_bytes() -> TestResult {
    let (index, _db) = fresh_index("test_63_property_batch_by_hash_overwrite_keeps_latest_bytes")?;
    let block = make_block(0, [0u8; 64], 6300)?;

    index
        .db()
        .store_batch_by_block_hash(&block.block_hash, b"old-batch")?;
    index
        .db()
        .store_batch_by_block_hash(&block.block_hash, b"new-batch")?;

    assert_eq!(
        required(
            index.db().get_batch_by_block_hash(&block.block_hash)?,
            "latest batch"
        )?,
        b"new-batch".to_vec()
    );
    Ok(())
}

#[test]
fn test_64_property_make_height_meta_for_multiple_heights_scores_equal_heights() -> TestResult {
    let (index, _db) =
        fresh_index("test_64_property_make_height_meta_for_multiple_heights_scores_equal_heights")?;
    let chain = make_linear_chain(10, 6400)?;

    for block in &chain {
        let meta = index.make_height_meta(block, ForkBlockStatus::HeaderOnly);
        assert_eq!(meta.height, block.metadata.index);
        assert_eq!(meta.cumulative_score, u128::from(block.metadata.index));
        assert_eq!(meta.parent_hash, block.metadata.previous_hash);
    }

    Ok(())
}

#[test]
fn test_65_property_make_scored_meta_accepts_large_u128_scores() -> TestResult {
    let (index, _db) = fresh_index("test_65_property_make_scored_meta_accepts_large_u128_scores")?;
    let block = make_block(0, [0u8; 64], 6500)?;
    let score = u128::MAX.saturating_sub(65);

    let meta = index.make_scored_meta(&block, score, ForkBlockStatus::Validated);

    assert_eq!(meta.cumulative_score, score);
    assert_eq!(meta.height, block.metadata.index);
    assert_eq!(meta.status, ForkBlockStatus::Validated);
    Ok(())
}

#[test]
fn test_66_property_status_transitions_preserve_parent_height_and_score() -> TestResult {
    let (index, _db) =
        fresh_index("test_66_property_status_transitions_preserve_parent_height_and_score")?;
    let block = make_block(0, [0u8; 64], 6600)?;
    let meta = store_block_with_score(&index, &block, ForkBlockStatus::HeaderOnly, 66_000)?;

    for status in all_statuses() {
        index.set_status(&block.block_hash, status)?;
        let updated = required(index.get_meta(&block.block_hash)?, "updated meta")?;
        assert_eq!(updated.parent_hash, meta.parent_hash);
        assert_eq!(updated.height, meta.height);
        assert_eq!(updated.cumulative_score, meta.cumulative_score);
        assert_eq!(updated.status, status);
    }

    Ok(())
}

#[test]
fn test_67_property_meta_bytes_are_stable_across_multiple_roundtrips() -> TestResult {
    let parent = deterministic_hash(6700);
    let meta = ForkBlockMeta {
        parent_hash: parent,
        height: 67,
        cumulative_score: 67_000,
        status: ForkBlockStatus::SideBranch,
        received_at_unix_secs: timestamp_at(67),
    };

    let first = meta.to_bytes();
    let decoded = ForkBlockMeta::from_bytes(&first)?;
    let second = decoded.to_bytes();
    let decoded_again = ForkBlockMeta::from_bytes(&second)?;

    assert_eq!(first, second);
    assert_eq!(decoded_again, meta);
    Ok(())
}

#[test]
fn test_68_property_hash_ancestry_matches_block_index_path_hashes() -> TestResult {
    let (index, _db) =
        fresh_index("test_68_property_hash_ancestry_matches_block_index_path_hashes")?;
    let chain = make_linear_chain(7, 6800)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    let hash_path = index.db().build_hash_ancestry_path(&tip.block_hash, 20)?;
    let height_hash_path = index.build_path_from_tip(&tip.block_hash, 20)?;

    assert_eq!(hash_path.len(), height_hash_path.len());
    for (pos, hash) in hash_path.iter().enumerate() {
        let pair = required(height_hash_path.get(pos).copied(), "height/hash pair")?;
        assert_eq!(*hash, pair.1);
    }

    Ok(())
}

#[test]
fn test_69_fuzz_repeated_meta_serialization_for_varied_scores_and_statuses() -> TestResult {
    let statuses = all_statuses();
    let mut status_index = 0usize;

    for seed in 0u64..64u64 {
        let status = required(statuses.get(status_index).copied(), "status by fuzz index")?;

        let meta = ForkBlockMeta {
            parent_hash: deterministic_hash(6900u64.saturating_add(seed)),
            height: seed,
            cumulative_score: u128::from(seed).saturating_mul(1_000_003),
            status,
            received_at_unix_secs: timestamp_at(seed),
        };

        let bytes = meta.to_bytes();
        assert_eq!(ForkBlockMeta::from_bytes(&bytes)?, meta);

        status_index = if status_index == 5 {
            0
        } else {
            status_index.saturating_add(1)
        };
    }

    Ok(())
}

#[test]
fn test_70_fuzz_many_noncanonical_branch_blocks_have_known_genesis_parent() -> TestResult {
    let (index, _db) =
        fresh_index("test_70_fuzz_many_noncanonical_branch_blocks_have_known_genesis_parent")?;
    let genesis = make_block(0, [0u8; 64], 7000)?;
    let _genesis_meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;

    let mut use_side_branch = true;

    for branch in 0u64..48u64 {
        let tag = 7001u64.saturating_add(branch);
        let block = make_block(1, genesis.block_hash, tag)?;
        let status = if use_side_branch {
            ForkBlockStatus::SideBranch
        } else {
            ForkBlockStatus::Orphan
        };

        use_side_branch = !use_side_branch;

        let _meta = store_block(&index, &block, status)?;

        assert!(index.has_known_parent(&block.block_hash)?);
        assert!(
            index
                .first_missing_ancestor(&block.block_hash, 8)?
                .is_none()
        );
        index.validate_block_meta_consistency(&block.block_hash)?;
    }

    Ok(())
}

#[test]
fn test_71_fuzz_corrupt_meta_lengths_are_rejected() -> TestResult {
    for len in 0usize..120usize {
        if len == 97 {
            continue;
        }

        let data = vec![1u8; len];
        assert!(ForkBlockMeta::from_bytes(&data).is_err());
    }

    Ok(())
}

#[test]
fn test_72_fuzz_deterministic_rewrites_of_same_block_remain_idempotent() -> TestResult {
    let (index, _db) =
        fresh_index("test_72_fuzz_deterministic_rewrites_of_same_block_remain_idempotent")?;
    let block = make_block(0, [0u8; 64], 7200)?;
    let meta = meta_for(&block, ForkBlockStatus::Validated, 72);

    for _round in 0u64..20u64 {
        index.put_block_and_meta(&block, &meta)?;
        assert_eq!(
            required(index.get_block(&block.block_hash)?, "block")?,
            block
        );
        assert_eq!(required(index.get_meta(&block.block_hash)?, "meta")?, meta);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// EXTRA ADVERSARIAL NETWORK SIM TESTS: 73–77
// ─────────────────────────────────────────────────────────────

#[test]
fn test_73_adversarial_two_forks_find_genesis_common_ancestor() -> TestResult {
    let (index, _db) = fresh_index("test_73_adversarial_two_forks_find_genesis_common_ancestor")?;
    let genesis = make_block(0, [0u8; 64], 7300)?;
    let a1 = make_block(1, genesis.block_hash, 7301)?;
    let a2 = make_block(2, a1.block_hash, 7302)?;
    let b1 = make_block(1, genesis.block_hash, 7311)?;
    let b2 = make_block(2, b1.block_hash, 7312)?;

    let _genesis_meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;
    let _a1_meta = store_block(&index, &a1, ForkBlockStatus::Canonical)?;
    let _a2_meta = store_block(&index, &a2, ForkBlockStatus::Canonical)?;
    let _b1_meta = store_block(&index, &b1, ForkBlockStatus::SideBranch)?;
    let _b2_meta = store_block(&index, &b2, ForkBlockStatus::SideBranch)?;

    let ancestor = required(
        index
            .db()
            .find_common_ancestor_hash(&a2.block_hash, &b2.block_hash, 10)?,
        "fork common ancestor",
    )?;

    assert_eq!(ancestor, genesis.block_hash);
    Ok(())
}

#[test]
fn test_74_adversarial_deeper_fork_common_ancestor_is_branch_point() -> TestResult {
    let (index, _db) =
        fresh_index("test_74_adversarial_deeper_fork_common_ancestor_is_branch_point")?;
    let base = make_linear_chain(4, 7400)?;
    store_chain(&index, &base, ForkBlockStatus::Canonical)?;
    let branch_point = block_at(&base, 2)?;
    let canonical_tip = last_block(&base)?;
    let side1 = make_block(3, branch_point.block_hash, 7410)?;
    let side2 = make_block(4, side1.block_hash, 7411)?;

    let _side1_meta = store_block(&index, &side1, ForkBlockStatus::SideBranch)?;
    let _side2_meta = store_block(&index, &side2, ForkBlockStatus::SideBranch)?;

    let ancestor = required(
        index
            .db()
            .find_common_ancestor_hash(&canonical_tip.block_hash, &side2.block_hash, 10)?,
        "deeper branch common ancestor",
    )?;

    assert_eq!(ancestor, branch_point.block_hash);
    Ok(())
}

#[test]
fn test_75_adversarial_unrelated_roots_have_no_common_ancestor() -> TestResult {
    let (index, _db) = fresh_index("test_75_adversarial_unrelated_roots_have_no_common_ancestor")?;
    let root_a = make_block(0, [0u8; 64], 7500)?;
    let root_b = make_block(0, [0u8; 64], 7501)?;
    let a1 = make_block(1, root_a.block_hash, 7502)?;
    let b1 = make_block(1, root_b.block_hash, 7503)?;

    let _root_a_meta = store_block(&index, &root_a, ForkBlockStatus::Canonical)?;
    let _root_b_meta = store_block(&index, &root_b, ForkBlockStatus::SideBranch)?;
    let _a1_meta = store_block(&index, &a1, ForkBlockStatus::Canonical)?;
    let _b1_meta = store_block(&index, &b1, ForkBlockStatus::SideBranch)?;

    assert!(
        index
            .db()
            .find_common_ancestor_hash(&a1.block_hash, &b1.block_hash, 10)?
            .is_none()
    );
    Ok(())
}

#[test]
fn test_76_adversarial_competing_tips_same_height_different_scores() -> TestResult {
    let (index, _db) =
        fresh_index("test_76_adversarial_competing_tips_same_height_different_scores")?;
    let genesis = make_block(0, [0u8; 64], 7600)?;
    let low_score = make_block(1, genesis.block_hash, 7601)?;
    let high_score = make_block(1, genesis.block_hash, 7602)?;

    let _genesis_meta = store_block(&index, &genesis, ForkBlockStatus::Canonical)?;
    let _low_meta = store_block_with_score(&index, &low_score, ForkBlockStatus::SideBranch, 10)?;
    let _high_meta =
        store_block_with_score(&index, &high_score, ForkBlockStatus::Validated, 10_000)?;

    let low_meta = required(index.get_meta(&low_score.block_hash)?, "low score meta")?;
    let high_meta = required(index.get_meta(&high_score.block_hash)?, "high score meta")?;

    assert_eq!(low_meta.height, high_meta.height);
    assert!(high_meta.cumulative_score > low_meta.cumulative_score);

    index
        .db()
        .promote_block_to_canonical(high_score.metadata.index, &high_score.block_hash)?;
    index.mark_side_branch(&low_score.block_hash)?;

    assert_eq!(
        required(
            index.status_of(&high_score.block_hash)?,
            "high score status"
        )?,
        ForkBlockStatus::Canonical
    );
    assert_eq!(
        required(index.status_of(&low_score.block_hash)?, "low score status")?,
        ForkBlockStatus::SideBranch
    );
    Ok(())
}

#[test]
fn test_77_adversarial_log_tip_summary_handles_present_and_missing_meta() -> TestResult {
    let (index, _db) =
        fresh_index("test_77_adversarial_log_tip_summary_handles_present_and_missing_meta")?;
    let block = make_block(0, [0u8; 64], 7700)?;
    let _meta = store_block(&index, &block, ForkBlockStatus::Canonical)?;
    let missing_hash = deterministic_hash(7799);

    index.log_tip_summary(&block.block_hash)?;
    index.log_tip_summary(&missing_hash)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// EXTRA LOAD TESTS: 78–80
// ─────────────────────────────────────────────────────────────

#[test]
fn test_78_load_canonical_mapping_for_128_blocks_then_delete_tail() -> TestResult {
    let (index, _db) =
        fresh_index("test_78_load_canonical_mapping_for_128_blocks_then_delete_tail")?;
    let chain = make_linear_chain(128, 7800)?;
    store_chain(&index, &chain, ForkBlockStatus::Canonical)?;

    for block in &chain {
        index
            .db()
            .set_canonical_hash_at_height(block.metadata.index, &block.block_hash)?;
    }

    for block in &chain {
        assert_eq!(
            required(
                index
                    .db()
                    .get_canonical_hash_at_height(block.metadata.index)?,
                "canonical hash before tail delete"
            )?,
            block.block_hash
        );
    }

    index.db().delete_canonical_hash_range(64, 127)?;

    for block in &chain {
        let found = index
            .db()
            .get_canonical_hash_at_height(block.metadata.index)?;
        if block.metadata.index < 64 {
            assert_eq!(
                required(found, "canonical hash kept before tail")?,
                block.block_hash
            );
        } else {
            assert!(found.is_none());
        }
    }

    Ok(())
}

#[test]
fn test_79_load_batches_for_128_blocks_are_retrievable_by_hash() -> TestResult {
    let (index, _db) = fresh_index("test_79_load_batches_for_128_blocks_are_retrievable_by_hash")?;
    let chain = make_linear_chain(128, 7900)?;

    for block in &chain {
        let meta = meta_for(
            block,
            ForkBlockStatus::Validated,
            u128::from(block.metadata.index),
        );
        let batch = format!("load-batch-for-height-{}", block.metadata.index);
        index.ingest_validated_block(block, meta, Some(batch.as_bytes()))?;
    }

    for block in &chain {
        let expected = format!("load-batch-for-height-{}", block.metadata.index).into_bytes();
        let stored = required(
            index.db().get_batch_by_block_hash(&block.block_hash)?,
            "load batch by hash",
        )?;
        assert_eq!(stored, expected);
    }

    Ok(())
}

#[test]
fn test_80_load_promote_96_blocks_to_canonical_tip_and_validate_consistency() -> TestResult {
    let (index, _db) =
        fresh_index("test_80_load_promote_96_blocks_to_canonical_tip_and_validate_consistency")?;
    let chain = make_linear_chain(96, 8000)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;

    for block in &chain {
        index
            .db()
            .promote_block_to_canonical(block.metadata.index, &block.block_hash)?;
        index.validate_block_meta_consistency(&block.block_hash)?;
    }

    let tip = last_block(&chain)?;
    assert_eq!(
        required(index.db().get_canonical_tip_hash()?, "final load tip hash")?,
        tip.block_hash
    );
    assert_eq!(
        required(
            index.db().get_canonical_tip_height()?,
            "final load tip height"
        )?,
        tip.metadata.index
    );

    let path = index.build_path_from_tip(&tip.block_hash, 128)?;
    assert_eq!(path.len(), chain.len());

    for block in &chain {
        assert_eq!(
            required(index.status_of(&block.block_hash)?, "canonical status")?,
            ForkBlockStatus::Canonical
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// LAST EDGE / VECTOR COVERAGE TESTS: 81–100
// ─────────────────────────────────────────────────────────────

#[test]
fn test_81_put_block_bytes_empty_blob_is_rejected_edge() -> TestResult {
    let (index, _db) = fresh_index("test_81_put_block_bytes_empty_blob_is_rejected_edge")?;
    let bad_hash = deterministic_hash(8100);

    let result = index.put_block_bytes(&bad_hash, &[]);

    assert!(result.is_err());
    assert!(!index.has_block(&bad_hash));
    Ok(())
}

#[test]
fn test_82_put_block_bytes_corrupt_blob_is_rejected_edge() -> TestResult {
    let (index, _db) = fresh_index("test_82_put_block_bytes_corrupt_blob_is_rejected_edge")?;
    let bad_hash = deterministic_hash(8200);
    let corrupt_bytes = b"not-a-postcard-block";

    let result = index.put_block_bytes(&bad_hash, corrupt_bytes);

    assert!(result.is_err());
    assert!(!index.has_block(&bad_hash));
    Ok(())
}

#[test]
fn test_83_fork_block_meta_rejects_boundary_lengths_96_and_98_edge() -> TestResult {
    let meta = ForkBlockMeta {
        parent_hash: deterministic_hash(8300),
        height: 83,
        cumulative_score: 83_000,
        status: ForkBlockStatus::Validated,
        received_at_unix_secs: timestamp_at(83),
    };

    let bytes = meta.to_bytes();

    let mut short = bytes.clone();
    short.truncate(96);

    let mut long = bytes;
    long.push(0);

    assert!(ForkBlockMeta::from_bytes(&short).is_err());
    assert!(ForkBlockMeta::from_bytes(&long).is_err());
    Ok(())
}

#[test]
fn test_84_fork_block_meta_big_endian_binary_layout_vector() -> TestResult {
    let parent_hash = deterministic_hash(8400);
    let height = 0x0102_0304_0506_0708u64;
    let cumulative_score = 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128;
    let received_at_unix_secs = 0x1112_1314_1516_1718u64;

    let mut bytes = Vec::with_capacity(97);
    bytes.extend_from_slice(&parent_hash);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&cumulative_score.to_be_bytes());
    bytes.push(ForkBlockStatus::Canonical.as_u8());
    bytes.extend_from_slice(&received_at_unix_secs.to_be_bytes());

    let decoded = ForkBlockMeta::from_bytes(&bytes)?;

    assert_eq!(decoded.parent_hash, parent_hash);
    assert_eq!(decoded.height, height);
    assert_eq!(decoded.cumulative_score, cumulative_score);
    assert_eq!(decoded.status, ForkBlockStatus::Canonical);
    assert_eq!(decoded.received_at_unix_secs, received_at_unix_secs);
    Ok(())
}

#[test]
fn test_85_fork_block_status_exact_byte_vectors() -> TestResult {
    let vectors = [
        (0u8, ForkBlockStatus::HeaderOnly),
        (1u8, ForkBlockStatus::BlockStored),
        (2u8, ForkBlockStatus::Validated),
        (3u8, ForkBlockStatus::Canonical),
        (4u8, ForkBlockStatus::SideBranch),
        (5u8, ForkBlockStatus::Orphan),
    ];

    for (byte, status) in vectors {
        assert_eq!(ForkBlockStatus::from_u8(byte)?, status);
        assert_eq!(status.as_u8(), byte);
    }

    assert!(ForkBlockStatus::from_u8(255).is_err());
    Ok(())
}

#[test]
fn test_86_non_genesis_zero_parent_block_is_rejected_on_put_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_86_non_genesis_zero_parent_block_is_rejected_on_put_edge")?;

    let result = make_block(1, [0u8; 64], 8600);

    assert!(matches!(
        result,
        Err(ErrorDetection::ValidationError { .. })
    ));

    assert!(index.get_block(&[0u8; 64])?.is_none());

    Ok(())
}

#[test]
fn test_87_corrupt_raw_overwrite_is_rejected_and_existing_block_survives_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_87_corrupt_raw_overwrite_is_rejected_and_existing_block_survives_edge")?;
    let block = make_block(0, [0u8; 64], 8700)?;

    index.put_block(&block)?;
    assert_eq!(
        required(
            index.get_block(&block.block_hash)?,
            "stored block before corrupt overwrite"
        )?,
        block
    );

    let result = index.put_block_bytes(&block.block_hash, b"corrupt-overwrite");

    assert!(result.is_err());
    assert_eq!(
        required(
            index.get_block(&block.block_hash)?,
            "stored block after rejected overwrite"
        )?,
        block
    );
    Ok(())
}

#[test]
fn test_88_valid_block_can_be_stored_after_rejected_corrupt_raw_attempt_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_88_valid_block_can_be_stored_after_rejected_corrupt_raw_attempt_edge")?;
    let block = make_block(0, [0u8; 64], 8800)?;

    let result = index.put_block_bytes(&block.block_hash, b"corrupt-first-write");

    assert!(result.is_err());
    assert!(!index.has_block(&block.block_hash));

    index.put_block(&block)?;

    assert_eq!(
        required(index.get_block(&block.block_hash)?, "valid block")?,
        block
    );
    Ok(())
}

#[test]
fn test_89_meta_helpers_work_even_when_block_body_is_missing_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_89_meta_helpers_work_even_when_block_body_is_missing_edge")?;
    let hash = deterministic_hash(8900);
    let parent_hash = deterministic_hash(8901);
    let meta = ForkBlockMeta {
        parent_hash,
        height: 89,
        cumulative_score: 8_900,
        status: ForkBlockStatus::HeaderOnly,
        received_at_unix_secs: timestamp_at(89),
    };

    index.put_meta(&hash, &meta)?;

    assert_eq!(
        required(index.parent_hash(&hash)?, "parent hash")?,
        parent_hash
    );
    assert_eq!(required(index.height_of(&hash)?, "height")?, 89);
    assert_eq!(
        required(index.status_of(&hash)?, "status")?,
        ForkBlockStatus::HeaderOnly
    );
    assert!(index.get_block(&hash)?.is_none());
    Ok(())
}

#[test]
fn test_90_unknown_nonzero_parent_keeps_parent_hash_but_parent_reads_none_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_90_unknown_nonzero_parent_keeps_parent_hash_but_parent_reads_none_edge")?;
    let unknown_parent = deterministic_hash(9000);
    let child = make_block(1, unknown_parent, 9001)?;
    let _meta = store_block(&index, &child, ForkBlockStatus::Orphan)?;

    assert_eq!(
        required(index.parent_hash(&child.block_hash)?, "stored parent hash")?,
        unknown_parent
    );
    assert!(!index.has_known_parent(&child.block_hash)?);
    assert!(index.get_parent_block(&child.block_hash)?.is_none());
    assert!(index.get_parent_meta(&child.block_hash)?.is_none());
    Ok(())
}

#[test]
fn test_91_parent_meta_present_without_parent_block_is_known_parent_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_91_parent_meta_present_without_parent_block_is_known_parent_edge")?;
    let parent = make_block(0, [0u8; 64], 9100)?;
    let child = make_block(1, parent.block_hash, 9101)?;
    let parent_meta = meta_for(&parent, ForkBlockStatus::HeaderOnly, 91);
    let child_meta = meta_for(&child, ForkBlockStatus::Orphan, 92);

    index.put_meta(&parent.block_hash, &parent_meta)?;
    index.put_block_and_meta(&child, &child_meta)?;

    assert!(index.has_known_parent(&child.block_hash)?);
    assert!(index.get_parent_block(&child.block_hash)?.is_none());
    assert_eq!(
        required(index.get_parent_meta(&child.block_hash)?, "parent meta")?,
        parent_meta
    );
    Ok(())
}

#[test]
fn test_92_parent_block_present_without_parent_meta_is_not_known_parent_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_92_parent_block_present_without_parent_meta_is_not_known_parent_edge")?;
    let parent = make_block(0, [0u8; 64], 9200)?;
    let child = make_block(1, parent.block_hash, 9201)?;
    let child_meta = meta_for(&child, ForkBlockStatus::Orphan, 92);

    index.put_block(&parent)?;
    index.put_block_and_meta(&child, &child_meta)?;

    assert!(!index.has_known_parent(&child.block_hash)?);
    assert_eq!(
        required(index.get_parent_block(&child.block_hash)?, "parent block")?,
        parent
    );
    assert!(index.get_parent_meta(&child.block_hash)?.is_none());
    Ok(())
}

#[test]
fn test_93_build_path_from_tip_respects_max_depth_truncation_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_93_build_path_from_tip_respects_max_depth_truncation_edge")?;
    let chain = make_linear_chain(5, 9300)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    let path = index.build_path_from_tip(&tip.block_hash, 3)?;
    let expected_heights = [4u64, 3u64, 2u64];

    assert_eq!(path.len(), expected_heights.len());

    for (pair, expected_height) in path.iter().zip(expected_heights.iter()) {
        assert_eq!(pair.0, *expected_height);
    }

    assert_eq!(
        required(path.first().copied(), "truncated path tip")?.1,
        tip.block_hash
    );
    Ok(())
}

#[test]
fn test_94_build_path_from_tip_stops_when_parent_meta_is_missing_edge() -> TestResult {
    let (index, _db) =
        fresh_index("test_94_build_path_from_tip_stops_when_parent_meta_is_missing_edge")?;
    let parent = make_block(0, [0u8; 64], 9400)?;
    let child = make_block(1, parent.block_hash, 9401)?;

    index.put_block(&parent)?;
    let _child_meta = store_block(&index, &child, ForkBlockStatus::Orphan)?;

    let path = index.build_path_from_tip(&child.block_hash, 8)?;

    assert_eq!(path.len(), 1);
    assert_eq!(
        required(path.first().copied(), "single path entry")?.1,
        child.block_hash
    );
    Ok(())
}

#[test]
fn test_95_first_missing_ancestor_finds_deeper_gap_only_with_sufficient_depth_edge() -> TestResult {
    let (index, _db) = fresh_index(
        "test_95_first_missing_ancestor_finds_deeper_gap_only_with_sufficient_depth_edge",
    )?;
    let missing_root = deterministic_hash(9500);
    let child = make_block(1, missing_root, 9501)?;
    let grandchild = make_block(2, child.block_hash, 9502)?;

    let _child_meta = store_block(&index, &child, ForkBlockStatus::Orphan)?;
    let _grandchild_meta = store_block(&index, &grandchild, ForkBlockStatus::Orphan)?;

    assert!(
        index
            .first_missing_ancestor(&grandchild.block_hash, 1)?
            .is_none()
    );
    assert_eq!(
        required(
            index.first_missing_ancestor(&grandchild.block_hash, 2)?,
            "deeper missing root"
        )?,
        missing_root
    );
    Ok(())
}

#[test]
fn test_96_common_ancestor_of_same_tip_is_that_tip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_96_common_ancestor_of_same_tip_is_that_tip_vector")?;
    let chain = make_linear_chain(4, 9600)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let tip = last_block(&chain)?;

    let ancestor = required(
        index
            .db()
            .find_common_ancestor_hash(&tip.block_hash, &tip.block_hash, 16)?,
        "same-tip common ancestor",
    )?;

    assert_eq!(ancestor, tip.block_hash);
    Ok(())
}

#[test]
fn test_97_common_ancestor_of_parent_and_child_is_parent_vector() -> TestResult {
    let (index, _db) = fresh_index("test_97_common_ancestor_of_parent_and_child_is_parent_vector")?;
    let chain = make_linear_chain(3, 9700)?;
    store_chain(&index, &chain, ForkBlockStatus::Validated)?;
    let parent = block_at(&chain, 1)?;
    let child = block_at(&chain, 2)?;

    let ancestor = required(
        index
            .db()
            .find_common_ancestor_hash(&parent.block_hash, &child.block_hash, 16)?,
        "parent-child common ancestor",
    )?;

    assert_eq!(ancestor, parent.block_hash);
    Ok(())
}

#[test]
fn test_98_canonical_tip_can_be_overwritten_with_lower_height_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_98_canonical_tip_can_be_overwritten_with_lower_height_vector")?;
    let chain = make_linear_chain(4, 9800)?;
    store_chain(&index, &chain, ForkBlockStatus::Canonical)?;
    let low = block_at(&chain, 1)?;
    let high = block_at(&chain, 3)?;

    index
        .db()
        .set_canonical_tip(&high.block_hash, high.metadata.index)?;
    assert_eq!(
        required(index.db().get_canonical_tip_height()?, "high tip height")?,
        high.metadata.index
    );

    index
        .db()
        .set_canonical_tip(&low.block_hash, low.metadata.index)?;

    assert_eq!(
        required(index.db().get_canonical_tip_hash()?, "low tip hash")?,
        low.block_hash
    );
    assert_eq!(
        required(index.db().get_canonical_tip_height()?, "low tip height")?,
        low.metadata.index
    );
    Ok(())
}

#[test]
fn test_99_delete_canonical_hash_range_single_height_vector() -> TestResult {
    let (index, _db) = fresh_index("test_99_delete_canonical_hash_range_single_height_vector")?;
    let chain = make_linear_chain(3, 9900)?;
    store_chain(&index, &chain, ForkBlockStatus::Canonical)?;

    for block in &chain {
        index
            .db()
            .set_canonical_hash_at_height(block.metadata.index, &block.block_hash)?;
    }

    index.db().delete_canonical_hash_range(1, 1)?;

    assert!(index.db().get_canonical_hash_at_height(0)?.is_some());
    assert!(index.db().get_canonical_hash_at_height(1)?.is_none());
    assert!(index.db().get_canonical_hash_at_height(2)?.is_some());
    Ok(())
}

#[test]
fn test_100_ingest_validated_block_with_empty_batch_stores_empty_batch_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_100_ingest_validated_block_with_empty_batch_stores_empty_batch_vector")?;
    let block = make_block(0, [0u8; 64], 10_000)?;
    let meta = meta_for(&block, ForkBlockStatus::Validated, 100);

    index.ingest_validated_block(&block, meta, Some(&[]))?;

    assert!(index.db().has_batch_by_block_hash(&block.block_hash)?);
    assert_eq!(
        required(
            index.db().get_batch_by_block_hash(&block.block_hash)?,
            "empty batch by block hash"
        )?,
        Vec::<u8>::new()
    );
    Ok(())
}
