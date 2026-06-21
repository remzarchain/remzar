use remzar::reorganization::reorg_004_batch_index::{BlockHash, ReorgBatchIndex};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
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

fn fresh_index(label: &str) -> Result<(ReorgBatchIndex, Arc<RockDBManager>), ErrorDetection> {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "remzar_reorg_004_batch_index_{label}_{}_{}",
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
    let index = ReorgBatchIndex::new(Arc::clone(&db));
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

fn batch_bytes(height: u64, salt: u64) -> Vec<u8> {
    format!("batch-height-{height}-salt-{salt}").into_bytes()
}

fn set_canonical_hash(
    index: &ReorgBatchIndex,
    height: u64,
    hash: &BlockHash,
) -> Result<(), ErrorDetection> {
    index.db().set_canonical_hash_at_height(height, hash)
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

// ─────────────────────────────────────────────────────────────
// 1–20: core vector tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_001_new_keeps_same_db_arc_vector() -> TestResult {
    let (index, db) = fresh_index("test_001_new_keeps_same_db_arc_vector")?;
    assert!(Arc::ptr_eq(index.db(), &db));
    Ok(())
}

#[test]
fn test_002_get_batch_by_block_hash_missing_returns_none_vector() -> TestResult {
    let (index, _db) = fresh_index("test_002_get_batch_by_block_hash_missing_returns_none_vector")?;
    let hash = deterministic_hash(2);

    assert!(index.get_batch_by_block_hash(&hash)?.is_none());
    Ok(())
}

#[test]
fn test_003_has_batch_by_block_hash_false_when_missing_vector() -> TestResult {
    let (index, _db) = fresh_index("test_003_has_batch_by_block_hash_false_when_missing_vector")?;
    let hash = deterministic_hash(3);

    assert!(!index.has_batch_by_block_hash(&hash)?);
    Ok(())
}

#[test]
fn test_004_put_batch_by_block_hash_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_004_put_batch_by_block_hash_roundtrip_vector")?;
    let hash = deterministic_hash(4);
    let bytes = batch_bytes(4, 40);

    index.put_batch_by_block_hash(&hash, &bytes)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "batch by hash")?,
        bytes
    );
    Ok(())
}

#[test]
fn test_005_has_batch_by_block_hash_true_after_put_vector() -> TestResult {
    let (index, _db) = fresh_index("test_005_has_batch_by_block_hash_true_after_put_vector")?;
    let hash = deterministic_hash(5);
    let bytes = batch_bytes(5, 50);

    index.put_batch_by_block_hash(&hash, &bytes)?;

    assert!(index.has_batch_by_block_hash(&hash)?);
    Ok(())
}

#[test]
fn test_006_put_batch_by_block_hash_overwrites_existing_vector() -> TestResult {
    let (index, _db) = fresh_index("test_006_put_batch_by_block_hash_overwrites_existing_vector")?;
    let hash = deterministic_hash(6);
    let first = batch_bytes(6, 60);
    let second = batch_bytes(6, 61);

    index.put_batch_by_block_hash(&hash, &first)?;
    index.put_batch_by_block_hash(&hash, &second)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "overwritten batch")?,
        second
    );
    Ok(())
}

#[test]
fn test_007_put_empty_batch_by_block_hash_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_007_put_empty_batch_by_block_hash_roundtrip_vector")?;
    let hash = deterministic_hash(7);
    let empty = Vec::<u8>::new();

    index.put_batch_by_block_hash(&hash, &empty)?;

    assert!(index.has_batch_by_block_hash(&hash)?);
    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "empty batch")?,
        empty
    );
    Ok(())
}

#[test]
fn test_008_put_large_but_small_test_batch_by_hash_roundtrip_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_008_put_large_but_small_test_batch_by_hash_roundtrip_vector")?;
    let hash = deterministic_hash(8);
    let bytes = vec![8u8; 4096];

    index.put_batch_by_block_hash(&hash, &bytes)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "4096 byte batch")?,
        bytes
    );
    Ok(())
}

#[test]
fn test_009_get_canonical_batch_at_height_missing_returns_none_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_009_get_canonical_batch_at_height_missing_returns_none_vector")?;

    assert!(index.get_canonical_batch_at_height(9)?.is_none());
    Ok(())
}

#[test]
fn test_010_set_canonical_batch_at_height_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_010_set_canonical_batch_at_height_roundtrip_vector")?;
    let bytes = batch_bytes(10, 100);

    index.set_canonical_batch_at_height(10, &bytes)?;

    assert_eq!(
        required(index.get_canonical_batch_at_height(10)?, "canonical batch")?,
        bytes
    );
    Ok(())
}

#[test]
fn test_011_set_canonical_batch_at_height_overwrites_existing_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_011_set_canonical_batch_at_height_overwrites_existing_vector")?;
    let first = batch_bytes(11, 110);
    let second = batch_bytes(11, 111);

    index.set_canonical_batch_at_height(11, &first)?;
    index.set_canonical_batch_at_height(11, &second)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(11)?,
            "overwritten canonical batch"
        )?,
        second
    );
    Ok(())
}

#[test]
fn test_012_set_empty_canonical_batch_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_012_set_empty_canonical_batch_roundtrip_vector")?;
    let empty = Vec::<u8>::new();

    index.set_canonical_batch_at_height(12, &empty)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(12)?,
            "empty canonical batch"
        )?,
        empty
    );
    Ok(())
}

#[test]
fn test_013_set_canonical_batch_high_height_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_013_set_canonical_batch_high_height_roundtrip_vector")?;
    let height = 1_000_000u64;
    let bytes = batch_bytes(height, 13);

    index.set_canonical_batch_at_height(height, &bytes)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(height)?,
            "high height canonical batch"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_014_set_canonical_batch_u64_max_height_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_014_set_canonical_batch_u64_max_height_roundtrip_vector")?;
    let bytes = batch_bytes(u64::MAX, 14);

    index.set_canonical_batch_at_height(u64::MAX, &bytes)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(u64::MAX)?,
            "u64 max canonical batch"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_015_get_canonical_batch_with_fallback_empty_returns_none_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_015_get_canonical_batch_with_fallback_empty_returns_none_vector")?;

    assert!(index.get_canonical_batch_with_fallback(15)?.is_none());
    Ok(())
}

#[test]
fn test_016_fallback_uses_batch_by_hash_when_mapping_and_truth_exist_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_016_fallback_uses_batch_by_hash_when_mapping_and_truth_exist_vector")?;
    let hash = deterministic_hash(16);
    let bytes = batch_bytes(16, 160);

    set_canonical_hash(&index, 16, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;

    assert_eq!(
        required(
            index.get_canonical_batch_with_fallback(16)?,
            "fallback by hash"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_017_fallback_uses_canonical_projection_when_hash_truth_missing_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_017_fallback_uses_canonical_projection_when_hash_truth_missing_vector")?;
    let hash = deterministic_hash(17);
    let canonical = batch_bytes(17, 170);

    set_canonical_hash(&index, 17, &hash)?;
    index.set_canonical_batch_at_height(17, &canonical)?;

    assert_eq!(
        required(
            index.get_canonical_batch_with_fallback(17)?,
            "fallback canonical projection"
        )?,
        canonical
    );
    Ok(())
}

#[test]
fn test_018_fallback_prefers_hash_truth_over_canonical_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_018_fallback_prefers_hash_truth_over_canonical_projection_vector")?;
    let hash = deterministic_hash(18);
    let canonical = batch_bytes(18, 180);
    let truth = batch_bytes(18, 181);

    set_canonical_hash(&index, 18, &hash)?;
    index.set_canonical_batch_at_height(18, &canonical)?;
    index.put_batch_by_block_hash(&hash, &truth)?;

    assert_eq!(
        required(
            index.get_canonical_batch_with_fallback(18)?,
            "preferred hash truth"
        )?,
        truth
    );
    Ok(())
}

#[test]
fn test_019_ingest_canonical_batch_stores_truth_and_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_019_ingest_canonical_batch_stores_truth_and_projection_vector")?;
    let hash = deterministic_hash(19);
    let bytes = batch_bytes(19, 190);

    index.ingest_canonical_batch(&hash, 19, &bytes)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "truth batch")?,
        bytes
    );
    assert_eq!(
        required(
            index.get_canonical_batch_at_height(19)?,
            "canonical projection"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_020_ingest_side_branch_batch_only_stores_truth_vector() -> TestResult {
    let (index, _db) = fresh_index("test_020_ingest_side_branch_batch_only_stores_truth_vector")?;
    let hash = deterministic_hash(20);
    let bytes = batch_bytes(20, 200);

    index.ingest_side_branch_batch(&hash, &bytes)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "side truth batch")?,
        bytes
    );
    assert!(index.get_canonical_batch_at_height(20)?.is_none());
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 21–40: remap and validation vectors
// ─────────────────────────────────────────────────────────────

#[test]
fn test_021_remap_canonical_batch_to_height_roundtrip_vector() -> TestResult {
    let (index, _db) = fresh_index("test_021_remap_canonical_batch_to_height_roundtrip_vector")?;
    let hash = deterministic_hash(21);
    let bytes = batch_bytes(21, 210);

    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.remap_canonical_batch_to_height(21, &hash)?;

    assert_eq!(
        required(index.get_canonical_batch_at_height(21)?, "remapped batch")?,
        bytes
    );
    Ok(())
}

#[test]
fn test_022_remap_canonical_batch_to_height_missing_truth_errors_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_022_remap_canonical_batch_to_height_missing_truth_errors_vector")?;
    let hash = deterministic_hash(22);

    assert_not_found(index.remap_canonical_batch_to_height(22, &hash));
    Ok(())
}

#[test]
fn test_023_remap_canonical_batch_overwrites_existing_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_023_remap_canonical_batch_overwrites_existing_projection_vector")?;
    let hash = deterministic_hash(23);
    let old = batch_bytes(23, 230);
    let truth = batch_bytes(23, 231);

    index.set_canonical_batch_at_height(23, &old)?;
    index.put_batch_by_block_hash(&hash, &truth)?;
    index.remap_canonical_batch_to_height(23, &hash)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(23)?,
            "remapped overwrite"
        )?,
        truth
    );
    Ok(())
}

#[test]
fn test_024_remap_canonical_batches_for_attach_steps_multiple_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_024_remap_canonical_batches_for_attach_steps_multiple_vector")?;
    let h1 = deterministic_hash(241);
    let h2 = deterministic_hash(242);
    let b1 = batch_bytes(1, 241);
    let b2 = batch_bytes(2, 242);

    index.put_batch_by_block_hash(&h1, &b1)?;
    index.put_batch_by_block_hash(&h2, &b2)?;
    index.remap_canonical_batches_for_attach_steps(&[(1u64, h1), (2u64, h2)])?;

    assert_eq!(
        required(index.get_canonical_batch_at_height(1)?, "height 1")?,
        b1
    );
    assert_eq!(
        required(index.get_canonical_batch_at_height(2)?, "height 2")?,
        b2
    );
    Ok(())
}

#[test]
fn test_025_remap_canonical_batches_for_attach_steps_empty_is_noop_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_025_remap_canonical_batches_for_attach_steps_empty_is_noop_vector")?;

    index.remap_canonical_batches_for_attach_steps(&[])?;

    assert!(index.get_canonical_batch_at_height(0)?.is_none());
    Ok(())
}

#[test]
fn test_026_remap_attach_steps_returns_error_on_first_missing_truth_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_026_remap_attach_steps_returns_error_on_first_missing_truth_vector")?;
    let present_hash = deterministic_hash(261);
    let missing_hash = deterministic_hash(262);
    let present_batch = batch_bytes(1, 261);

    index.put_batch_by_block_hash(&present_hash, &present_batch)?;
    let result = index
        .remap_canonical_batches_for_attach_steps(&[(1u64, present_hash), (2u64, missing_hash)]);

    assert_not_found(result);
    assert_eq!(
        required(
            index.get_canonical_batch_at_height(1)?,
            "height 1 remapped before missing"
        )?,
        present_batch
    );
    assert!(index.get_canonical_batch_at_height(2)?.is_none());
    Ok(())
}

#[test]
fn test_027_best_effort_remap_missing_truth_skips_without_error_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_027_best_effort_remap_missing_truth_skips_without_error_vector")?;
    let missing_hash = deterministic_hash(27);

    index.remap_canonical_batches_best_effort(&[(27u64, missing_hash)])?;

    assert!(index.get_canonical_batch_at_height(27)?.is_none());
    Ok(())
}

#[test]
fn test_028_best_effort_remap_present_truth_writes_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_028_best_effort_remap_present_truth_writes_projection_vector")?;
    let hash = deterministic_hash(28);
    let bytes = batch_bytes(28, 280);

    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.remap_canonical_batches_best_effort(&[(28u64, hash)])?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(28)?,
            "best effort remap"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_029_best_effort_remap_mixed_present_and_missing_vector() -> TestResult {
    let (index, _db) = fresh_index("test_029_best_effort_remap_mixed_present_and_missing_vector")?;
    let present_hash = deterministic_hash(291);
    let missing_hash = deterministic_hash(292);
    let present_batch = batch_bytes(1, 291);

    index.put_batch_by_block_hash(&present_hash, &present_batch)?;
    index.remap_canonical_batches_best_effort(&[(1u64, present_hash), (2u64, missing_hash)])?;

    assert_eq!(
        required(index.get_canonical_batch_at_height(1)?, "present remap")?,
        present_batch
    );
    assert!(index.get_canonical_batch_at_height(2)?.is_none());
    Ok(())
}

#[test]
fn test_030_validate_canonical_batch_consistency_success_vector() -> TestResult {
    let (index, _db) = fresh_index("test_030_validate_canonical_batch_consistency_success_vector")?;
    let hash = deterministic_hash(30);
    let bytes = batch_bytes(30, 300);

    set_canonical_hash(&index, 30, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.set_canonical_batch_at_height(30, &bytes)?;

    index.validate_canonical_batch_consistency(30)?;
    Ok(())
}

#[test]
fn test_031_validate_consistency_missing_canonical_hash_errors_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_031_validate_consistency_missing_canonical_hash_errors_vector")?;

    assert_not_found(index.validate_canonical_batch_consistency(31));
    Ok(())
}

#[test]
fn test_032_validate_consistency_missing_batch_by_hash_errors_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_032_validate_consistency_missing_batch_by_hash_errors_vector")?;
    let hash = deterministic_hash(32);

    set_canonical_hash(&index, 32, &hash)?;

    assert_not_found(index.validate_canonical_batch_consistency(32));
    Ok(())
}

#[test]
fn test_033_validate_consistency_missing_canonical_projection_errors_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_033_validate_consistency_missing_canonical_projection_errors_vector")?;
    let hash = deterministic_hash(33);
    let bytes = batch_bytes(33, 330);

    set_canonical_hash(&index, 33, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;

    assert_not_found(index.validate_canonical_batch_consistency(33));
    Ok(())
}

#[test]
fn test_034_validate_consistency_mismatch_errors_vector() -> TestResult {
    let (index, _db) = fresh_index("test_034_validate_consistency_mismatch_errors_vector")?;
    let hash = deterministic_hash(34);
    let truth = batch_bytes(34, 340);
    let wrong = batch_bytes(34, 341);

    set_canonical_hash(&index, 34, &hash)?;
    index.put_batch_by_block_hash(&hash, &truth)?;
    index.set_canonical_batch_at_height(34, &wrong)?;

    assert_blockchain_error(index.validate_canonical_batch_consistency(34));
    Ok(())
}

#[test]
fn test_035_first_inconsistent_returns_none_for_valid_range_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_035_first_inconsistent_returns_none_for_valid_range_vector")?;

    for height in 0u64..3u64 {
        let hash = deterministic_hash(350u64.saturating_add(height));
        let bytes = batch_bytes(height, 350);
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, &bytes)?;
        index.set_canonical_batch_at_height(height, &bytes)?;
    }

    assert!(index.first_inconsistent_canonical_batch(0, 2)?.is_none());
    Ok(())
}

#[test]
fn test_036_first_inconsistent_from_greater_than_to_returns_none_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_036_first_inconsistent_from_greater_than_to_returns_none_vector")?;

    assert!(index.first_inconsistent_canonical_batch(9, 2)?.is_none());
    Ok(())
}

#[test]
fn test_037_first_inconsistent_missing_hash_returns_from_height_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_037_first_inconsistent_missing_hash_returns_from_height_vector")?;

    assert_eq!(index.first_inconsistent_canonical_batch(37, 37)?, Some(37));
    Ok(())
}

#[test]
fn test_038_first_inconsistent_detects_gap_after_valid_start_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_038_first_inconsistent_detects_gap_after_valid_start_vector")?;
    let hash = deterministic_hash(38);
    let bytes = batch_bytes(38, 380);

    set_canonical_hash(&index, 0, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.set_canonical_batch_at_height(0, &bytes)?;

    assert_eq!(index.first_inconsistent_canonical_batch(0, 1)?, Some(1));
    Ok(())
}

#[test]
fn test_039_first_inconsistent_detects_mismatch_at_second_height_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_039_first_inconsistent_detects_mismatch_at_second_height_vector")?;

    for height in 0u64..2u64 {
        let hash = deterministic_hash(390u64.saturating_add(height));
        let truth = batch_bytes(height, 390);
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, &truth)?;
        if height == 0 {
            index.set_canonical_batch_at_height(height, &truth)?;
        } else {
            index.set_canonical_batch_at_height(height, b"wrong")?;
        }
    }

    assert_eq!(index.first_inconsistent_canonical_batch(0, 1)?, Some(1));
    Ok(())
}

#[test]
fn test_040_log_canonical_batch_summary_empty_slot_succeeds_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_040_log_canonical_batch_summary_empty_slot_succeeds_vector")?;

    index.log_canonical_batch_summary(40)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 41–60: diagnostics, migration, repair helpers
// ─────────────────────────────────────────────────────────────

#[test]
fn test_041_log_summary_hash_without_batch_succeeds_vector() -> TestResult {
    let (index, _db) = fresh_index("test_041_log_summary_hash_without_batch_succeeds_vector")?;
    let hash = deterministic_hash(41);

    set_canonical_hash(&index, 41, &hash)?;
    index.log_canonical_batch_summary(41)?;

    Ok(())
}

#[test]
fn test_042_log_summary_batch_without_hash_succeeds_vector() -> TestResult {
    let (index, _db) = fresh_index("test_042_log_summary_batch_without_hash_succeeds_vector")?;
    let bytes = batch_bytes(42, 420);

    index.set_canonical_batch_at_height(42, &bytes)?;
    index.log_canonical_batch_summary(42)?;

    Ok(())
}

#[test]
fn test_043_log_summary_hash_and_batch_succeeds_vector() -> TestResult {
    let (index, _db) = fresh_index("test_043_log_summary_hash_and_batch_succeeds_vector")?;
    let hash = deterministic_hash(43);
    let bytes = batch_bytes(43, 430);

    set_canonical_hash(&index, 43, &hash)?;
    index.set_canonical_batch_at_height(43, &bytes)?;
    index.log_canonical_batch_summary(43)?;

    Ok(())
}

#[test]
fn test_044_backfill_batch_by_hash_from_canonical_range_empty_range_noop_vector() -> TestResult {
    let (index, _db) = fresh_index(
        "test_044_backfill_batch_by_hash_from_canonical_range_empty_range_noop_vector",
    )?;

    index.backfill_batch_by_hash_from_canonical_range(5, 1)?;

    Ok(())
}

#[test]
fn test_045_backfill_skips_missing_canonical_hash_vector() -> TestResult {
    let (index, _db) = fresh_index("test_045_backfill_skips_missing_canonical_hash_vector")?;
    let bytes = batch_bytes(45, 450);

    index.set_canonical_batch_at_height(45, &bytes)?;
    index.backfill_batch_by_hash_from_canonical_range(45, 45)?;

    assert!(index.get_canonical_batch_at_height(45)?.is_some());
    Ok(())
}

#[test]
fn test_046_backfill_creates_batch_by_hash_from_canonical_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_046_backfill_creates_batch_by_hash_from_canonical_projection_vector")?;
    let hash = deterministic_hash(46);
    let bytes = batch_bytes(46, 460);

    set_canonical_hash(&index, 46, &hash)?;
    index.set_canonical_batch_at_height(46, &bytes)?;
    index.backfill_batch_by_hash_from_canonical_range(46, 46)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "backfilled by hash")?,
        bytes
    );
    Ok(())
}

#[test]
fn test_047_backfill_does_not_overwrite_existing_batch_by_hash_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_047_backfill_does_not_overwrite_existing_batch_by_hash_vector")?;
    let hash = deterministic_hash(47);
    let existing = batch_bytes(47, 470);
    let canonical = batch_bytes(47, 471);

    set_canonical_hash(&index, 47, &hash)?;
    index.put_batch_by_block_hash(&hash, &existing)?;
    index.set_canonical_batch_at_height(47, &canonical)?;
    index.backfill_batch_by_hash_from_canonical_range(47, 47)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "preserved by hash")?,
        existing
    );
    Ok(())
}

#[test]
fn test_048_backfill_skips_missing_canonical_batch_vector() -> TestResult {
    let (index, _db) = fresh_index("test_048_backfill_skips_missing_canonical_batch_vector")?;
    let hash = deterministic_hash(48);

    set_canonical_hash(&index, 48, &hash)?;
    index.backfill_batch_by_hash_from_canonical_range(48, 48)?;

    assert!(index.get_batch_by_block_hash(&hash)?.is_none());
    Ok(())
}

#[test]
fn test_049_backfill_range_mixed_slots_vector() -> TestResult {
    let (index, _db) = fresh_index("test_049_backfill_range_mixed_slots_vector")?;
    let h0 = deterministic_hash(490);
    let h2 = deterministic_hash(492);
    let b0 = batch_bytes(0, 490);
    let b2 = batch_bytes(2, 492);

    set_canonical_hash(&index, 0, &h0)?;
    set_canonical_hash(&index, 2, &h2)?;
    index.set_canonical_batch_at_height(0, &b0)?;
    index.set_canonical_batch_at_height(2, &b2)?;
    index.backfill_batch_by_hash_from_canonical_range(0, 2)?;

    assert_eq!(required(index.get_batch_by_block_hash(&h0)?, "h0")?, b0);
    assert_eq!(required(index.get_batch_by_block_hash(&h2)?, "h2")?, b2);
    Ok(())
}

#[test]
fn test_050_rebuild_canonical_projection_empty_range_noop_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_050_rebuild_canonical_projection_empty_range_noop_vector")?;

    index.rebuild_canonical_projection_from_hash_range(5, 1)?;

    Ok(())
}

#[test]
fn test_051_rebuild_skips_missing_canonical_hash_vector() -> TestResult {
    let (index, _db) = fresh_index("test_051_rebuild_skips_missing_canonical_hash_vector")?;

    index.rebuild_canonical_projection_from_hash_range(51, 51)?;

    assert!(index.get_canonical_batch_at_height(51)?.is_none());
    Ok(())
}

#[test]
fn test_052_rebuild_creates_canonical_projection_from_batch_by_hash_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_052_rebuild_creates_canonical_projection_from_batch_by_hash_vector")?;
    let hash = deterministic_hash(52);
    let bytes = batch_bytes(52, 520);

    set_canonical_hash(&index, 52, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.rebuild_canonical_projection_from_hash_range(52, 52)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(52)?,
            "rebuilt canonical projection"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_053_rebuild_overwrites_existing_projection_from_batch_by_hash_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_053_rebuild_overwrites_existing_projection_from_batch_by_hash_vector")?;
    let hash = deterministic_hash(53);
    let old = batch_bytes(53, 530);
    let truth = batch_bytes(53, 531);

    set_canonical_hash(&index, 53, &hash)?;
    index.set_canonical_batch_at_height(53, &old)?;
    index.put_batch_by_block_hash(&hash, &truth)?;
    index.rebuild_canonical_projection_from_hash_range(53, 53)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(53)?,
            "rebuilt overwrite"
        )?,
        truth
    );
    Ok(())
}

#[test]
fn test_054_rebuild_skips_missing_batch_by_hash_vector() -> TestResult {
    let (index, _db) = fresh_index("test_054_rebuild_skips_missing_batch_by_hash_vector")?;
    let hash = deterministic_hash(54);

    set_canonical_hash(&index, 54, &hash)?;
    index.rebuild_canonical_projection_from_hash_range(54, 54)?;

    assert!(index.get_canonical_batch_at_height(54)?.is_none());
    Ok(())
}

#[test]
fn test_055_rebuild_range_mixed_slots_vector() -> TestResult {
    let (index, _db) = fresh_index("test_055_rebuild_range_mixed_slots_vector")?;
    let h0 = deterministic_hash(550);
    let h2 = deterministic_hash(552);
    let b0 = batch_bytes(0, 550);
    let b2 = batch_bytes(2, 552);

    set_canonical_hash(&index, 0, &h0)?;
    set_canonical_hash(&index, 2, &h2)?;
    index.put_batch_by_block_hash(&h0, &b0)?;
    index.put_batch_by_block_hash(&h2, &b2)?;
    index.rebuild_canonical_projection_from_hash_range(0, 2)?;

    assert_eq!(required(index.get_canonical_batch_at_height(0)?, "h0")?, b0);
    assert!(index.get_canonical_batch_at_height(1)?.is_none());
    assert_eq!(required(index.get_canonical_batch_at_height(2)?, "h2")?, b2);
    Ok(())
}

#[test]
fn test_056_fallback_after_rebuild_returns_rebuilt_bytes_vector() -> TestResult {
    let (index, _db) = fresh_index("test_056_fallback_after_rebuild_returns_rebuilt_bytes_vector")?;
    let hash = deterministic_hash(56);
    let bytes = batch_bytes(56, 560);

    set_canonical_hash(&index, 56, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.rebuild_canonical_projection_from_hash_range(56, 56)?;

    assert_eq!(
        required(
            index.get_canonical_batch_with_fallback(56)?,
            "fallback after rebuild"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_057_validate_after_rebuild_succeeds_vector() -> TestResult {
    let (index, _db) = fresh_index("test_057_validate_after_rebuild_succeeds_vector")?;
    let hash = deterministic_hash(57);
    let bytes = batch_bytes(57, 570);

    set_canonical_hash(&index, 57, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.rebuild_canonical_projection_from_hash_range(57, 57)?;

    index.validate_canonical_batch_consistency(57)?;
    Ok(())
}

#[test]
fn test_058_backfill_then_validate_succeeds_vector() -> TestResult {
    let (index, _db) = fresh_index("test_058_backfill_then_validate_succeeds_vector")?;
    let hash = deterministic_hash(58);
    let bytes = batch_bytes(58, 580);

    set_canonical_hash(&index, 58, &hash)?;
    index.set_canonical_batch_at_height(58, &bytes)?;
    index.backfill_batch_by_hash_from_canonical_range(58, 58)?;

    index.validate_canonical_batch_consistency(58)?;
    Ok(())
}

#[test]
fn test_059_same_hash_truth_and_projection_can_exist_at_different_heights_vector() -> TestResult {
    let (index, _db) = fresh_index(
        "test_059_same_hash_truth_and_projection_can_exist_at_different_heights_vector",
    )?;
    let hash = deterministic_hash(59);
    let bytes = batch_bytes(59, 590);

    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.set_canonical_batch_at_height(99, &bytes)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "truth")?,
        bytes
    );
    assert_eq!(
        required(index.get_canonical_batch_at_height(99)?, "projection")?,
        bytes
    );
    Ok(())
}

#[test]
fn test_060_same_batch_bytes_can_be_stored_for_multiple_hashes_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_060_same_batch_bytes_can_be_stored_for_multiple_hashes_vector")?;
    let h1 = deterministic_hash(601);
    let h2 = deterministic_hash(602);
    let bytes = batch_bytes(60, 600);

    index.put_batch_by_block_hash(&h1, &bytes)?;
    index.put_batch_by_block_hash(&h2, &bytes)?;

    assert_eq!(required(index.get_batch_by_block_hash(&h1)?, "h1")?, bytes);
    assert_eq!(required(index.get_batch_by_block_hash(&h2)?, "h2")?, bytes);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 61–80: property and adversarial tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_061_property_by_hash_roundtrip_many_entries() -> TestResult {
    let (index, _db) = fresh_index("test_061_property_by_hash_roundtrip_many_entries")?;

    for height in 0u64..32u64 {
        let hash = deterministic_hash(6_100u64.saturating_add(height));
        let bytes = batch_bytes(height, 610);
        index.put_batch_by_block_hash(&hash, &bytes)?;
        assert_eq!(
            required(index.get_batch_by_block_hash(&hash)?, "property by hash")?,
            bytes
        );
    }

    Ok(())
}

#[test]
fn test_062_property_canonical_projection_roundtrip_many_entries() -> TestResult {
    let (index, _db) =
        fresh_index("test_062_property_canonical_projection_roundtrip_many_entries")?;

    for height in 0u64..32u64 {
        let bytes = batch_bytes(height, 620);
        index.set_canonical_batch_at_height(height, &bytes)?;
        assert_eq!(
            required(
                index.get_canonical_batch_at_height(height)?,
                "property canonical batch"
            )?,
            bytes
        );
    }

    Ok(())
}

#[test]
fn test_063_property_ingest_canonical_many_entries() -> TestResult {
    let (index, _db) = fresh_index("test_063_property_ingest_canonical_many_entries")?;

    for height in 0u64..32u64 {
        let hash = deterministic_hash(6_300u64.saturating_add(height));
        let bytes = batch_bytes(height, 630);
        index.ingest_canonical_batch(&hash, height, &bytes)?;
        assert_eq!(
            required(index.get_batch_by_block_hash(&hash)?, "ingested truth")?,
            bytes
        );
        assert_eq!(
            required(
                index.get_canonical_batch_at_height(height)?,
                "ingested projection"
            )?,
            bytes
        );
    }

    Ok(())
}

#[test]
fn test_064_property_remap_attach_many_entries() -> TestResult {
    let (index, _db) = fresh_index("test_064_property_remap_attach_many_entries")?;
    let mut steps = Vec::new();

    for height in 0u64..32u64 {
        let hash = deterministic_hash(6_400u64.saturating_add(height));
        let bytes = batch_bytes(height, 640);
        index.put_batch_by_block_hash(&hash, &bytes)?;
        steps.push((height, hash));
    }

    index.remap_canonical_batches_for_attach_steps(&steps)?;

    for (height, hash) in steps {
        let expected = required(index.get_batch_by_block_hash(&hash)?, "truth after remap")?;
        assert_eq!(
            required(
                index.get_canonical_batch_at_height(height)?,
                "projection after remap"
            )?,
            expected
        );
    }

    Ok(())
}

#[test]
fn test_065_property_best_effort_many_mixed_entries() -> TestResult {
    let (index, _db) = fresh_index("test_065_property_best_effort_many_mixed_entries")?;
    let mut steps = Vec::new();
    let mut store_next = true;

    for height in 0u64..16u64 {
        let hash = deterministic_hash(6_500u64.saturating_add(height));
        if store_next {
            let bytes = batch_bytes(height, 650);
            index.put_batch_by_block_hash(&hash, &bytes)?;
        }
        store_next = !store_next;
        steps.push((height, hash));
    }

    index.remap_canonical_batches_best_effort(&steps)?;

    let mut should_exist = true;
    for (height, _hash) in steps {
        if should_exist {
            assert!(index.get_canonical_batch_at_height(height)?.is_some());
        } else {
            assert!(index.get_canonical_batch_at_height(height)?.is_none());
        }
        should_exist = !should_exist;
    }

    Ok(())
}

#[test]
fn test_066_property_validate_many_consistent_entries() -> TestResult {
    let (index, _db) = fresh_index("test_066_property_validate_many_consistent_entries")?;

    for height in 0u64..24u64 {
        let hash = deterministic_hash(6_600u64.saturating_add(height));
        let bytes = batch_bytes(height, 660);
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, &bytes)?;
        index.set_canonical_batch_at_height(height, &bytes)?;
        index.validate_canonical_batch_consistency(height)?;
    }

    Ok(())
}

#[test]
fn test_067_property_first_inconsistent_none_many_consistent_entries() -> TestResult {
    let (index, _db) =
        fresh_index("test_067_property_first_inconsistent_none_many_consistent_entries")?;

    for height in 0u64..24u64 {
        let hash = deterministic_hash(6_700u64.saturating_add(height));
        let bytes = batch_bytes(height, 670);
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, &bytes)?;
        index.set_canonical_batch_at_height(height, &bytes)?;
    }

    assert!(index.first_inconsistent_canonical_batch(0, 23)?.is_none());
    Ok(())
}

#[test]
fn test_068_property_fallback_many_prefers_hash_truth() -> TestResult {
    let (index, _db) = fresh_index("test_068_property_fallback_many_prefers_hash_truth")?;

    for height in 0u64..16u64 {
        let hash = deterministic_hash(6_800u64.saturating_add(height));
        let projection = batch_bytes(height, 680);
        let truth = batch_bytes(height, 681);
        set_canonical_hash(&index, height, &hash)?;
        index.set_canonical_batch_at_height(height, &projection)?;
        index.put_batch_by_block_hash(&hash, &truth)?;

        assert_eq!(
            required(
                index.get_canonical_batch_with_fallback(height)?,
                "fallback truth"
            )?,
            truth
        );
    }

    Ok(())
}

#[test]
fn test_069_property_by_hash_overwrite_many_times_last_wins() -> TestResult {
    let (index, _db) = fresh_index("test_069_property_by_hash_overwrite_many_times_last_wins")?;
    let hash = deterministic_hash(69);
    let mut last = Vec::new();

    for salt in 0u64..32u64 {
        last = batch_bytes(69, salt);
        index.put_batch_by_block_hash(&hash, &last)?;
    }

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "last truth")?,
        last
    );
    Ok(())
}

#[test]
fn test_070_property_canonical_overwrite_many_times_last_wins() -> TestResult {
    let (index, _db) = fresh_index("test_070_property_canonical_overwrite_many_times_last_wins")?;
    let mut last = Vec::new();

    for salt in 0u64..32u64 {
        last = batch_bytes(70, salt);
        index.set_canonical_batch_at_height(70, &last)?;
    }

    assert_eq!(
        required(index.get_canonical_batch_at_height(70)?, "last projection")?,
        last
    );
    Ok(())
}

#[test]
fn test_071_adversarial_fallback_protects_against_stale_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_071_adversarial_fallback_protects_against_stale_projection_vector")?;
    let hash = deterministic_hash(71);
    let stale = b"stale-canonical-projection".to_vec();
    let truth = b"truth-from-batch-by-hash".to_vec();

    set_canonical_hash(&index, 71, &hash)?;
    index.set_canonical_batch_at_height(71, &stale)?;
    index.put_batch_by_block_hash(&hash, &truth)?;

    assert_eq!(
        required(
            index.get_canonical_batch_with_fallback(71)?,
            "protected fallback"
        )?,
        truth
    );
    Ok(())
}

#[test]
fn test_072_adversarial_validate_catches_stale_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_072_adversarial_validate_catches_stale_projection_vector")?;
    let hash = deterministic_hash(72);

    set_canonical_hash(&index, 72, &hash)?;
    index.put_batch_by_block_hash(&hash, b"truth")?;
    index.set_canonical_batch_at_height(72, b"stale")?;

    assert_blockchain_error(index.validate_canonical_batch_consistency(72));
    Ok(())
}

#[test]
fn test_073_adversarial_remap_heals_stale_projection_vector() -> TestResult {
    let (index, _db) = fresh_index("test_073_adversarial_remap_heals_stale_projection_vector")?;
    let hash = deterministic_hash(73);
    let truth = b"truth-after-heal".to_vec();

    set_canonical_hash(&index, 73, &hash)?;
    index.set_canonical_batch_at_height(73, b"stale")?;
    index.put_batch_by_block_hash(&hash, &truth)?;
    index.remap_canonical_batch_to_height(73, &hash)?;

    index.validate_canonical_batch_consistency(73)?;
    assert_eq!(
        required(
            index.get_canonical_batch_at_height(73)?,
            "healed projection"
        )?,
        truth
    );
    Ok(())
}

#[test]
fn test_074_adversarial_best_effort_missing_truth_does_not_erase_existing_projection() -> TestResult
{
    let (index, _db) = fresh_index(
        "test_074_adversarial_best_effort_missing_truth_does_not_erase_existing_projection",
    )?;
    let missing_hash = deterministic_hash(74);
    let existing = b"existing-projection".to_vec();

    index.set_canonical_batch_at_height(74, &existing)?;
    index.remap_canonical_batches_best_effort(&[(74u64, missing_hash)])?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(74)?,
            "existing projection"
        )?,
        existing
    );
    Ok(())
}

#[test]
fn test_075_adversarial_strict_remap_missing_truth_does_not_erase_existing_projection() -> TestResult
{
    let (index, _db) = fresh_index(
        "test_075_adversarial_strict_remap_missing_truth_does_not_erase_existing_projection",
    )?;
    let missing_hash = deterministic_hash(75);
    let existing = b"existing-projection".to_vec();

    index.set_canonical_batch_at_height(75, &existing)?;
    assert_not_found(index.remap_canonical_batch_to_height(75, &missing_hash));

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(75)?,
            "existing projection"
        )?,
        existing
    );
    Ok(())
}

#[test]
fn test_076_adversarial_backfill_does_not_overwrite_existing_truth_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_076_adversarial_backfill_does_not_overwrite_existing_truth_vector")?;
    let hash = deterministic_hash(76);

    set_canonical_hash(&index, 76, &hash)?;
    index.put_batch_by_block_hash(&hash, b"truth-existing")?;
    index.set_canonical_batch_at_height(76, b"canonical-poison")?;
    index.backfill_batch_by_hash_from_canonical_range(76, 76)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "truth preserved")?,
        b"truth-existing".to_vec()
    );
    Ok(())
}

#[test]
fn test_077_adversarial_rebuild_overwrites_poisoned_projection_from_truth_vector() -> TestResult {
    let (index, _db) = fresh_index(
        "test_077_adversarial_rebuild_overwrites_poisoned_projection_from_truth_vector",
    )?;
    let hash = deterministic_hash(77);

    set_canonical_hash(&index, 77, &hash)?;
    index.put_batch_by_block_hash(&hash, b"truth-clean")?;
    index.set_canonical_batch_at_height(77, b"projection-poison")?;
    index.rebuild_canonical_projection_from_hash_range(77, 77)?;

    assert_eq!(
        required(index.get_canonical_batch_at_height(77)?, "clean projection")?,
        b"truth-clean".to_vec()
    );
    Ok(())
}

#[test]
fn test_078_adversarial_empty_batch_consistency_succeeds_vector() -> TestResult {
    let (index, _db) = fresh_index("test_078_adversarial_empty_batch_consistency_succeeds_vector")?;
    let hash = deterministic_hash(78);
    let empty = Vec::<u8>::new();

    set_canonical_hash(&index, 78, &hash)?;
    index.put_batch_by_block_hash(&hash, &empty)?;
    index.set_canonical_batch_at_height(78, &empty)?;

    index.validate_canonical_batch_consistency(78)?;
    Ok(())
}

#[test]
fn test_079_adversarial_duplicate_attach_steps_last_write_wins_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_079_adversarial_duplicate_attach_steps_last_write_wins_vector")?;
    let h1 = deterministic_hash(791);
    let h2 = deterministic_hash(792);

    index.put_batch_by_block_hash(&h1, b"first")?;
    index.put_batch_by_block_hash(&h2, b"second")?;
    index.remap_canonical_batches_for_attach_steps(&[(79u64, h1), (79u64, h2)])?;

    assert_eq!(
        required(index.get_canonical_batch_at_height(79)?, "duplicate attach")?,
        b"second".to_vec()
    );
    Ok(())
}

#[test]
fn test_080_adversarial_best_effort_duplicate_steps_missing_then_present_vector() -> TestResult {
    let (index, _db) = fresh_index(
        "test_080_adversarial_best_effort_duplicate_steps_missing_then_present_vector",
    )?;
    let missing = deterministic_hash(801);
    let present = deterministic_hash(802);

    index.put_batch_by_block_hash(&present, b"present")?;
    index.remap_canonical_batches_best_effort(&[(80u64, missing), (80u64, present)])?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(80)?,
            "present after missing"
        )?,
        b"present".to_vec()
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 81–100: edge, fuzz-style, and load tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_081_edge_u64_max_remap_succeeds_vector() -> TestResult {
    let (index, _db) = fresh_index("test_081_edge_u64_max_remap_succeeds_vector")?;
    let hash = deterministic_hash(81);
    let bytes = batch_bytes(u64::MAX, 81);

    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.remap_canonical_batch_to_height(u64::MAX, &hash)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(u64::MAX)?,
            "u64 max remap"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_082_edge_first_inconsistent_u64_max_valid_none_vector() -> TestResult {
    let (index, _db) = fresh_index("test_082_edge_first_inconsistent_u64_max_valid_none_vector")?;
    let hash = deterministic_hash(82);
    let bytes = batch_bytes(u64::MAX, 82);

    set_canonical_hash(&index, u64::MAX, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.set_canonical_batch_at_height(u64::MAX, &bytes)?;

    assert!(
        index
            .first_inconsistent_canonical_batch(u64::MAX, u64::MAX)?
            .is_none()
    );
    Ok(())
}

#[test]
fn test_083_edge_first_inconsistent_u64_max_missing_projection_vector() -> TestResult {
    let (index, _db) =
        fresh_index("test_083_edge_first_inconsistent_u64_max_missing_projection_vector")?;
    let hash = deterministic_hash(83);
    let bytes = batch_bytes(u64::MAX, 83);

    set_canonical_hash(&index, u64::MAX, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;

    assert_eq!(
        index.first_inconsistent_canonical_batch(u64::MAX, u64::MAX)?,
        Some(u64::MAX)
    );
    Ok(())
}

#[test]
fn test_084_edge_backfill_u64_max_vector() -> TestResult {
    let (index, _db) = fresh_index("test_084_edge_backfill_u64_max_vector")?;
    let hash = deterministic_hash(84);
    let bytes = batch_bytes(u64::MAX, 84);

    set_canonical_hash(&index, u64::MAX, &hash)?;
    index.set_canonical_batch_at_height(u64::MAX, &bytes)?;
    index.backfill_batch_by_hash_from_canonical_range(u64::MAX, u64::MAX)?;

    assert_eq!(
        required(index.get_batch_by_block_hash(&hash)?, "u64 max backfill")?,
        bytes
    );
    Ok(())
}

#[test]
fn test_085_edge_rebuild_u64_max_vector() -> TestResult {
    let (index, _db) = fresh_index("test_085_edge_rebuild_u64_max_vector")?;
    let hash = deterministic_hash(85);
    let bytes = batch_bytes(u64::MAX, 85);

    set_canonical_hash(&index, u64::MAX, &hash)?;
    index.put_batch_by_block_hash(&hash, &bytes)?;
    index.rebuild_canonical_projection_from_hash_range(u64::MAX, u64::MAX)?;

    assert_eq!(
        required(
            index.get_canonical_batch_at_height(u64::MAX)?,
            "u64 max rebuild"
        )?,
        bytes
    );
    Ok(())
}

#[test]
fn test_086_fuzz_variable_batch_lengths_by_hash_roundtrip() -> TestResult {
    let (index, _db) = fresh_index("test_086_fuzz_variable_batch_lengths_by_hash_roundtrip")?;

    for len in 0usize..64usize {
        let hash = deterministic_hash(
            8_600u64.saturating_add(
                u64::try_from(len)
                    .map_err(|e| storage_error(format!("failed to convert len to u64: {e}")))?,
            ),
        );
        let bytes = vec![3u8; len];
        index.put_batch_by_block_hash(&hash, &bytes)?;
        assert_eq!(
            required(index.get_batch_by_block_hash(&hash)?, "variable by hash")?,
            bytes
        );
    }

    Ok(())
}

#[test]
fn test_087_fuzz_variable_batch_lengths_canonical_roundtrip() -> TestResult {
    let (index, _db) = fresh_index("test_087_fuzz_variable_batch_lengths_canonical_roundtrip")?;

    for height in 0u64..64u64 {
        let len = usize::try_from(height)
            .map_err(|e| storage_error(format!("failed to convert height to usize: {e}")))?;
        let bytes = vec![7u8; len];
        index.set_canonical_batch_at_height(height, &bytes)?;
        assert_eq!(
            required(
                index.get_canonical_batch_at_height(height)?,
                "variable canonical"
            )?,
            bytes
        );
    }

    Ok(())
}

#[test]
fn test_088_fuzz_repeated_remap_same_height_last_truth_wins() -> TestResult {
    let (index, _db) = fresh_index("test_088_fuzz_repeated_remap_same_height_last_truth_wins")?;
    let mut last = Vec::new();

    for salt in 0u64..32u64 {
        let hash = deterministic_hash(8_800u64.saturating_add(salt));
        last = batch_bytes(88, salt);
        index.put_batch_by_block_hash(&hash, &last)?;
        index.remap_canonical_batch_to_height(88, &hash)?;
    }

    assert_eq!(
        required(index.get_canonical_batch_at_height(88)?, "last remap")?,
        last
    );
    Ok(())
}

#[test]
fn test_089_fuzz_backfill_alternating_missing_canonical_hashes() -> TestResult {
    let (index, _db) = fresh_index("test_089_fuzz_backfill_alternating_missing_canonical_hashes")?;
    let mut has_hash = true;

    for height in 0u64..16u64 {
        let bytes = batch_bytes(height, 890);
        index.set_canonical_batch_at_height(height, &bytes)?;
        if has_hash {
            let hash = deterministic_hash(8_900u64.saturating_add(height));
            set_canonical_hash(&index, height, &hash)?;
        }
        has_hash = !has_hash;
    }

    index.backfill_batch_by_hash_from_canonical_range(0, 15)?;

    let mut should_exist = true;
    for height in 0u64..16u64 {
        if should_exist {
            let hash = required(
                index.db().get_canonical_hash_at_height(height)?,
                "canonical hash",
            )?;
            assert!(index.has_batch_by_block_hash(&hash)?);
        }
        should_exist = !should_exist;
    }

    Ok(())
}

#[test]
fn test_090_fuzz_rebuild_alternating_missing_batch_truth() -> TestResult {
    let (index, _db) = fresh_index("test_090_fuzz_rebuild_alternating_missing_batch_truth")?;
    let mut store_truth = true;

    for height in 0u64..16u64 {
        let hash = deterministic_hash(9_000u64.saturating_add(height));
        set_canonical_hash(&index, height, &hash)?;
        if store_truth {
            let bytes = batch_bytes(height, 900);
            index.put_batch_by_block_hash(&hash, &bytes)?;
        }
        store_truth = !store_truth;
    }

    index.rebuild_canonical_projection_from_hash_range(0, 15)?;

    let mut should_exist = true;
    for height in 0u64..16u64 {
        if should_exist {
            assert!(index.get_canonical_batch_at_height(height)?.is_some());
        } else {
            assert!(index.get_canonical_batch_at_height(height)?.is_none());
        }
        should_exist = !should_exist;
    }

    Ok(())
}

#[test]
fn test_091_load_ingest_canonical_128_entries_validate_all() -> TestResult {
    let (index, _db) = fresh_index("test_091_load_ingest_canonical_128_entries_validate_all")?;

    for height in 0u64..128u64 {
        let hash = deterministic_hash(9_100u64.saturating_add(height));
        let bytes = batch_bytes(height, 910);
        set_canonical_hash(&index, height, &hash)?;
        index.ingest_canonical_batch(&hash, height, &bytes)?;
    }

    for height in 0u64..128u64 {
        index.validate_canonical_batch_consistency(height)?;
    }

    Ok(())
}

#[test]
fn test_092_load_remap_128_side_branch_batches() -> TestResult {
    let (index, _db) = fresh_index("test_092_load_remap_128_side_branch_batches")?;
    let mut steps = Vec::new();

    for height in 0u64..128u64 {
        let hash = deterministic_hash(9_200u64.saturating_add(height));
        let bytes = batch_bytes(height, 920);
        index.ingest_side_branch_batch(&hash, &bytes)?;
        steps.push((height, hash));
    }

    index.remap_canonical_batches_for_attach_steps(&steps)?;

    for (height, hash) in steps {
        let expected = required(index.get_batch_by_block_hash(&hash)?, "expected side batch")?;
        assert_eq!(
            required(
                index.get_canonical_batch_at_height(height)?,
                "remapped side batch"
            )?,
            expected
        );
    }

    Ok(())
}

#[test]
fn test_093_load_rebuild_128_entries() -> TestResult {
    let (index, _db) = fresh_index("test_093_load_rebuild_128_entries")?;

    for height in 0u64..128u64 {
        let hash = deterministic_hash(9_300u64.saturating_add(height));
        let bytes = batch_bytes(height, 930);
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, &bytes)?;
    }

    index.rebuild_canonical_projection_from_hash_range(0, 127)?;

    for height in 0u64..128u64 {
        assert!(index.get_canonical_batch_at_height(height)?.is_some());
    }

    Ok(())
}

#[test]
fn test_094_load_backfill_128_entries() -> TestResult {
    let (index, _db) = fresh_index("test_094_load_backfill_128_entries")?;

    for height in 0u64..128u64 {
        let hash = deterministic_hash(9_400u64.saturating_add(height));
        let bytes = batch_bytes(height, 940);
        set_canonical_hash(&index, height, &hash)?;
        index.set_canonical_batch_at_height(height, &bytes)?;
    }

    index.backfill_batch_by_hash_from_canonical_range(0, 127)?;

    for height in 0u64..128u64 {
        let hash = required(
            index.db().get_canonical_hash_at_height(height)?,
            "canonical hash",
        )?;
        assert!(index.has_batch_by_block_hash(&hash)?);
    }

    Ok(())
}

#[test]
fn test_095_load_first_inconsistent_finds_late_mismatch() -> TestResult {
    let (index, _db) = fresh_index("test_095_load_first_inconsistent_finds_late_mismatch")?;

    for height in 0u64..64u64 {
        let hash = deterministic_hash(9_500u64.saturating_add(height));
        let bytes = batch_bytes(height, 950);
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, &bytes)?;
        if height == 63 {
            index.set_canonical_batch_at_height(height, b"late-mismatch")?;
        } else {
            index.set_canonical_batch_at_height(height, &bytes)?;
        }
    }

    assert_eq!(index.first_inconsistent_canonical_batch(0, 63)?, Some(63));
    Ok(())
}

#[test]
fn test_096_load_best_effort_128_entries_half_missing() -> TestResult {
    let (index, _db) = fresh_index("test_096_load_best_effort_128_entries_half_missing")?;
    let mut steps = Vec::new();
    let mut store_truth = true;

    for height in 0u64..128u64 {
        let hash = deterministic_hash(9_600u64.saturating_add(height));
        if store_truth {
            let bytes = batch_bytes(height, 960);
            index.put_batch_by_block_hash(&hash, &bytes)?;
        }
        store_truth = !store_truth;
        steps.push((height, hash));
    }

    index.remap_canonical_batches_best_effort(&steps)?;

    let mut should_exist = true;
    for height in 0u64..128u64 {
        if should_exist {
            assert!(index.get_canonical_batch_at_height(height)?.is_some());
        } else {
            assert!(index.get_canonical_batch_at_height(height)?.is_none());
        }
        should_exist = !should_exist;
    }

    Ok(())
}

#[test]
fn test_097_load_canonical_fallback_128_entries_prefers_truth() -> TestResult {
    let (index, _db) = fresh_index("test_097_load_canonical_fallback_128_entries_prefers_truth")?;

    for height in 0u64..128u64 {
        let hash = deterministic_hash(9_700u64.saturating_add(height));
        let truth = batch_bytes(height, 971);
        set_canonical_hash(&index, height, &hash)?;
        index.set_canonical_batch_at_height(height, b"stale")?;
        index.put_batch_by_block_hash(&hash, &truth)?;
        assert_eq!(
            required(
                index.get_canonical_batch_with_fallback(height)?,
                "fallback truth load"
            )?,
            truth
        );
    }

    Ok(())
}

#[test]
fn test_098_load_rebuild_heals_64_poisoned_projections() -> TestResult {
    let (index, _db) = fresh_index("test_098_load_rebuild_heals_64_poisoned_projections")?;

    for height in 0u64..64u64 {
        let hash = deterministic_hash(9_800u64.saturating_add(height));
        let truth = batch_bytes(height, 980);
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, &truth)?;
        index.set_canonical_batch_at_height(height, b"poison")?;
    }

    index.rebuild_canonical_projection_from_hash_range(0, 63)?;

    for height in 0u64..64u64 {
        index.validate_canonical_batch_consistency(height)?;
    }

    Ok(())
}

#[test]
fn test_099_load_backfill_preserves_64_existing_truth_values() -> TestResult {
    let (index, _db) = fresh_index("test_099_load_backfill_preserves_64_existing_truth_values")?;

    for height in 0u64..64u64 {
        let hash = deterministic_hash(9_900u64.saturating_add(height));
        set_canonical_hash(&index, height, &hash)?;
        index.put_batch_by_block_hash(&hash, b"existing-truth")?;
        index.set_canonical_batch_at_height(height, b"canonical-other")?;
    }

    index.backfill_batch_by_hash_from_canonical_range(0, 63)?;

    for height in 0u64..64u64 {
        let hash = required(
            index.db().get_canonical_hash_at_height(height)?,
            "canonical hash",
        )?;
        assert_eq!(
            required(
                index.get_batch_by_block_hash(&hash)?,
                "preserved existing truth"
            )?,
            b"existing-truth".to_vec()
        );
    }

    Ok(())
}

#[test]
fn test_100_end_to_end_side_branch_reorg_batch_remap_flow() -> TestResult {
    let (index, _db) = fresh_index("test_100_end_to_end_side_branch_reorg_batch_remap_flow")?;

    let old_h0 = deterministic_hash(10_000);
    let old_h1 = deterministic_hash(10_001);
    let old_h2 = deterministic_hash(10_002);

    let new_h1 = deterministic_hash(10_101);
    let new_h2 = deterministic_hash(10_102);
    let new_h3 = deterministic_hash(10_103);

    let old_b0 = b"old-canonical-0".to_vec();
    let old_b1 = b"old-canonical-1".to_vec();
    let old_b2 = b"old-canonical-2".to_vec();

    index.ingest_canonical_batch(&old_h0, 0, &old_b0)?;
    index.ingest_canonical_batch(&old_h1, 1, &old_b1)?;
    index.ingest_canonical_batch(&old_h2, 2, &old_b2)?;

    set_canonical_hash(&index, 0, &old_h0)?;
    set_canonical_hash(&index, 1, &old_h1)?;
    set_canonical_hash(&index, 2, &old_h2)?;

    let new_b1 = b"new-side-1".to_vec();
    let new_b2 = b"new-side-2".to_vec();
    let new_b3 = b"new-side-3".to_vec();

    index.ingest_side_branch_batch(&new_h1, &new_b1)?;
    index.ingest_side_branch_batch(&new_h2, &new_b2)?;
    index.ingest_side_branch_batch(&new_h3, &new_b3)?;

    set_canonical_hash(&index, 1, &new_h1)?;
    set_canonical_hash(&index, 2, &new_h2)?;
    set_canonical_hash(&index, 3, &new_h3)?;

    index.remap_canonical_batches_for_attach_steps(&[
        (1u64, new_h1),
        (2u64, new_h2),
        (3u64, new_h3),
    ])?;

    assert_eq!(
        required(index.get_canonical_batch_at_height(0)?, "kept height 0")?,
        old_b0
    );
    assert_eq!(
        required(index.get_canonical_batch_at_height(1)?, "new height 1")?,
        new_b1
    );
    assert_eq!(
        required(index.get_canonical_batch_at_height(2)?, "new height 2")?,
        new_b2
    );
    assert_eq!(
        required(index.get_canonical_batch_at_height(3)?, "new height 3")?,
        new_b3
    );

    index.validate_canonical_batch_consistency(1)?;
    index.validate_canonical_batch_consistency(2)?;
    index.validate_canonical_batch_consistency(3)?;

    Ok(())
}
