#![allow(clippy::too_many_lines)]

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::storage::rocksdb_006_manager_ext::{CanonicalTipView, ForkBlockMeta, ForkBlockStatus};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), Box<dyn Error>>;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestDb {
    manager: Option<RockDBManager>,
    root: PathBuf,
}

impl TestDb {
    fn manager(&self) -> Result<&RockDBManager, Box<dyn Error>> {
        self.manager
            .as_ref()
            .ok_or_else(|| boxed_error("test database manager is not available"))
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        drop(self.manager.take());

        if let Err(_cleanup_error) = std::fs::remove_dir_all(&self.root) {
            // Best-effort cleanup only.
        }
    }
}

fn boxed_error(message: &str) -> Box<dyn Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        message.to_owned(),
    ))
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_rocksdb_006_manager_ext_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> Result<String, Box<dyn Error>> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn node_opts(root: &Path) -> Result<NodeOpts, Box<dyn Error>> {
    Ok(NodeOpts {
        identity_file: path_to_string(&root.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "error".to_owned(),
        data_dir: path_to_string(root)?,
        wallet_address: wallet(1),
        founder: false,
    })
}

fn new_blockchain_db(label: &str) -> Result<TestDb, Box<dyn Error>> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path)?;

    let manager = RockDBManager::new_blockchain(&opts, &blockchain_path_string)?;

    Ok(TestDb {
        manager: Some(manager),
        root,
    })
}

fn new_cli_db(label: &str) -> Result<TestDb, Box<dyn Error>> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let manager = RockDBManager::new(&opts)?;

    Ok(TestDb {
        manager: Some(manager),
        root,
    })
}

fn hash_from_u64(seed: u64) -> Hash {
    let mut out = [0u8; 64];

    for (offset, byte) in out.iter_mut().enumerate() {
        let off = u64::try_from(offset).unwrap_or(0);
        let value = seed
            .wrapping_mul(31)
            .wrapping_add(off)
            .rem_euclid(251)
            .saturating_add(1);

        *byte = u8::try_from(value).unwrap_or(1);
    }

    out
}

fn zero_hash() -> Hash {
    [0u8; 64]
}

fn test_metadata(index: u64, previous_hash: Hash) -> BlockMetadata {
    let timestamp = 1_800_000_000u64.saturating_add(index);
    let merkle_root = hash_from_u64(index.saturating_add(1_000));

    let mut guardian_signature = [0u8; GlobalConfiguration::GUARDIAN_SIG_LEN];
    if index > 0 {
        let sig_seed = u8::try_from(index.rem_euclid(251))
            .unwrap_or(1)
            .saturating_add(1);
        guardian_signature.fill(sig_seed);
    }

    BlockMetadata::new(
        index,
        timestamp,
        previous_hash,
        merkle_root,
        guardian_signature,
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    )
}

fn test_block(index: u64, previous_hash: Hash) -> Result<Block, ErrorDetection> {
    let miner = if index == 0 {
        String::new()
    } else {
        wallet(index.saturating_add(10))
    };

    let batch_key = if index == 0 {
        None
    } else {
        Some(format!("tx_batch_{index:010}"))
    };

    Block::new(test_metadata(index, previous_hash), batch_key, miner, index)
}

fn block_bytes(block: &Block) -> Result<Vec<u8>, ErrorDetection> {
    block.serialize_for_storage()
}

fn fork_meta(
    parent_hash: Hash,
    height: u64,
    cumulative_score: u128,
    status: ForkBlockStatus,
) -> ForkBlockMeta {
    ForkBlockMeta {
        parent_hash,
        height,
        cumulative_score,
        status,
        received_at_unix_secs: 1_900_000_000u64.saturating_add(height),
    }
}

fn assert_some_hash(value: Option<Hash>, expected: Hash) -> TestResult {
    let actual = value.ok_or_else(|| boxed_error("expected Some(Hash)"))?;
    assert_eq!(actual, expected);
    Ok(())
}

fn assert_some_bytes(value: Option<Vec<u8>>, expected: &[u8]) -> TestResult {
    let actual = value.ok_or_else(|| boxed_error("expected Some(Vec<u8>)"))?;
    assert_eq!(actual, expected);
    Ok(())
}

fn assert_some_meta(value: Option<ForkBlockMeta>, expected: &ForkBlockMeta) -> TestResult {
    let actual = value.ok_or_else(|| boxed_error("expected Some(ForkBlockMeta)"))?;
    assert_eq!(&actual, expected);
    Ok(())
}

fn assert_some_tip(value: Option<CanonicalTipView>, expected: &CanonicalTipView) -> TestResult {
    let actual = value.ok_or_else(|| boxed_error("expected Some(CanonicalTipView)"))?;
    assert_eq!(&actual, expected);
    Ok(())
}

fn get_vec_item<T: Clone>(items: &[T], index: usize) -> Result<T, Box<dyn Error>> {
    items
        .get(index)
        .cloned()
        .ok_or_else(|| boxed_error("test vector item missing"))
}

#[test]
fn test_001_status_header_only_round_trip() -> TestResult {
    assert_eq!(ForkBlockStatus::from_u8(0)?, ForkBlockStatus::HeaderOnly);
    assert_eq!(ForkBlockStatus::HeaderOnly.as_u8(), 0);
    Ok(())
}

#[test]
fn test_002_status_block_stored_round_trip() -> TestResult {
    assert_eq!(ForkBlockStatus::from_u8(1)?, ForkBlockStatus::BlockStored);
    assert_eq!(ForkBlockStatus::BlockStored.as_u8(), 1);
    Ok(())
}

#[test]
fn test_003_status_validated_round_trip() -> TestResult {
    assert_eq!(ForkBlockStatus::from_u8(2)?, ForkBlockStatus::Validated);
    assert_eq!(ForkBlockStatus::Validated.as_u8(), 2);
    Ok(())
}

#[test]
fn test_004_status_canonical_round_trip() -> TestResult {
    assert_eq!(ForkBlockStatus::from_u8(3)?, ForkBlockStatus::Canonical);
    assert_eq!(ForkBlockStatus::Canonical.as_u8(), 3);
    Ok(())
}

#[test]
fn test_005_status_side_branch_round_trip() -> TestResult {
    assert_eq!(ForkBlockStatus::from_u8(4)?, ForkBlockStatus::SideBranch);
    assert_eq!(ForkBlockStatus::SideBranch.as_u8(), 4);
    Ok(())
}

#[test]
fn test_006_status_orphan_round_trip() -> TestResult {
    assert_eq!(ForkBlockStatus::from_u8(5)?, ForkBlockStatus::Orphan);
    assert_eq!(ForkBlockStatus::Orphan.as_u8(), 5);
    Ok(())
}

#[test]
fn test_007_status_rejects_invalid_low_vector() -> TestResult {
    assert!(ForkBlockStatus::from_u8(6).is_err());
    Ok(())
}

#[test]
fn test_008_status_rejects_invalid_high_vector() -> TestResult {
    assert!(ForkBlockStatus::from_u8(u8::MAX).is_err());
    Ok(())
}

#[test]
fn test_009_status_copy_clone_and_eq_are_stable() -> TestResult {
    let status = ForkBlockStatus::Validated;
    let copied = status;
    let cloned = status.clone();

    assert_eq!(copied, status);
    assert_eq!(cloned, status);
    Ok(())
}

#[test]
fn test_010_status_all_known_values_are_unique() -> TestResult {
    let statuses = [
        ForkBlockStatus::HeaderOnly,
        ForkBlockStatus::BlockStored,
        ForkBlockStatus::Validated,
        ForkBlockStatus::Canonical,
        ForkBlockStatus::SideBranch,
        ForkBlockStatus::Orphan,
    ];

    let mut values: Vec<u8> = statuses.iter().map(|status| status.as_u8()).collect();
    values.sort();
    values.dedup();

    assert_eq!(values.len(), statuses.len());
    Ok(())
}

#[test]
fn test_011_fork_meta_serializes_to_exact_97_bytes() -> TestResult {
    let meta = fork_meta(hash_from_u64(1), 10, 99, ForkBlockStatus::BlockStored);

    assert_eq!(meta.to_bytes().len(), 97);
    Ok(())
}

#[test]
fn test_012_fork_meta_round_trip_header_only() -> TestResult {
    let meta = fork_meta(hash_from_u64(2), 0, 0, ForkBlockStatus::HeaderOnly);
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_013_fork_meta_round_trip_block_stored() -> TestResult {
    let meta = fork_meta(hash_from_u64(3), 1, 1, ForkBlockStatus::BlockStored);
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_014_fork_meta_round_trip_validated() -> TestResult {
    let meta = fork_meta(hash_from_u64(4), 2, 50, ForkBlockStatus::Validated);
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_015_fork_meta_round_trip_canonical() -> TestResult {
    let meta = fork_meta(hash_from_u64(5), 3, 100, ForkBlockStatus::Canonical);
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_016_fork_meta_round_trip_side_branch() -> TestResult {
    let meta = fork_meta(hash_from_u64(6), 4, 150, ForkBlockStatus::SideBranch);
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_017_fork_meta_round_trip_orphan() -> TestResult {
    let meta = fork_meta(hash_from_u64(7), 5, 200, ForkBlockStatus::Orphan);
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_018_fork_meta_round_trip_u64_max_height() -> TestResult {
    let meta = fork_meta(
        hash_from_u64(8),
        u64::MAX,
        123_456,
        ForkBlockStatus::Validated,
    );
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded.height, u64::MAX);
    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_019_fork_meta_round_trip_u128_max_score() -> TestResult {
    let meta = fork_meta(hash_from_u64(9), 9, u128::MAX, ForkBlockStatus::Validated);
    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded.cumulative_score, u128::MAX);
    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_020_fork_meta_round_trip_u64_max_received_time() -> TestResult {
    let mut meta = fork_meta(hash_from_u64(10), 10, 10, ForkBlockStatus::Validated);
    meta.received_at_unix_secs = u64::MAX;

    let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;

    assert_eq!(decoded.received_at_unix_secs, u64::MAX);
    assert_eq!(decoded, meta);
    Ok(())
}

#[test]
fn test_021_fork_meta_rejects_empty_bytes() -> TestResult {
    assert!(ForkBlockMeta::from_bytes(&[]).is_err());
    Ok(())
}

#[test]
fn test_022_fork_meta_rejects_short_bytes() -> TestResult {
    let bytes = vec![0u8; 96];

    assert!(ForkBlockMeta::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_023_fork_meta_rejects_long_bytes() -> TestResult {
    let bytes = vec![0u8; 98];

    assert!(ForkBlockMeta::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_024_fork_meta_rejects_invalid_status_byte() -> TestResult {
    let meta = fork_meta(hash_from_u64(11), 11, 11, ForkBlockStatus::Validated);
    let mut bytes = meta.to_bytes();

    if let Some(status_byte) = bytes.get_mut(88) {
        *status_byte = 99;
    }

    assert!(ForkBlockMeta::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_025_fork_meta_binary_layout_preserves_parent_hash_prefix() -> TestResult {
    let parent = hash_from_u64(12);
    let meta = fork_meta(parent, 12, 12, ForkBlockStatus::Validated);
    let bytes = meta.to_bytes();

    let prefix = bytes
        .get(0..64)
        .ok_or_else(|| boxed_error("missing fork meta parent hash prefix"))?;

    assert_eq!(prefix, parent);
    Ok(())
}

#[test]
fn test_026_canonical_tip_view_serializes_to_exact_72_bytes() -> TestResult {
    let view = CanonicalTipView {
        tip_hash: hash_from_u64(13),
        tip_height: 13,
    };

    assert_eq!(view.to_bytes().len(), 72);
    Ok(())
}

#[test]
fn test_027_canonical_tip_view_round_trip_zero_height() -> TestResult {
    let view = CanonicalTipView {
        tip_hash: hash_from_u64(14),
        tip_height: 0,
    };

    let decoded = CanonicalTipView::from_bytes(&view.to_bytes())?;

    assert_eq!(decoded, view);
    Ok(())
}

#[test]
fn test_028_canonical_tip_view_round_trip_height_one() -> TestResult {
    let view = CanonicalTipView {
        tip_hash: hash_from_u64(15),
        tip_height: 1,
    };

    let decoded = CanonicalTipView::from_bytes(&view.to_bytes())?;

    assert_eq!(decoded, view);
    Ok(())
}

#[test]
fn test_029_canonical_tip_view_round_trip_u64_max_height() -> TestResult {
    let view = CanonicalTipView {
        tip_hash: hash_from_u64(16),
        tip_height: u64::MAX,
    };

    let decoded = CanonicalTipView::from_bytes(&view.to_bytes())?;

    assert_eq!(decoded, view);
    Ok(())
}

#[test]
fn test_030_canonical_tip_view_rejects_empty_bytes() -> TestResult {
    assert!(CanonicalTipView::from_bytes(&[]).is_err());
    Ok(())
}

#[test]
fn test_031_canonical_tip_view_rejects_short_bytes() -> TestResult {
    let bytes = vec![0u8; 71];

    assert!(CanonicalTipView::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_032_canonical_tip_view_rejects_long_bytes() -> TestResult {
    let bytes = vec![0u8; 73];

    assert!(CanonicalTipView::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_033_canonical_tip_view_binary_layout_preserves_tip_hash_prefix() -> TestResult {
    let hash = hash_from_u64(17);
    let view = CanonicalTipView {
        tip_hash: hash,
        tip_height: 17,
    };

    let bytes = view.to_bytes();
    let prefix = bytes
        .get(0..64)
        .ok_or_else(|| boxed_error("missing canonical tip hash prefix"))?;

    assert_eq!(prefix, hash);
    Ok(())
}

#[test]
fn test_034_canonical_tip_view_binary_layout_preserves_height_suffix() -> TestResult {
    let view = CanonicalTipView {
        tip_hash: hash_from_u64(18),
        tip_height: 18,
    };

    let bytes = view.to_bytes();
    let suffix = bytes
        .get(64..72)
        .ok_or_else(|| boxed_error("missing canonical tip height suffix"))?;

    assert_eq!(suffix, 18u64.to_be_bytes());
    Ok(())
}

#[test]
fn test_035_canonical_tip_view_clone_and_eq_are_stable() -> TestResult {
    let view = CanonicalTipView {
        tip_hash: hash_from_u64(19),
        tip_height: 19,
    };
    let cloned = view.clone();

    assert_eq!(cloned, view);
    Ok(())
}

#[test]
fn test_036_store_and_get_block_meta_by_hash_round_trip() -> TestResult {
    let db = new_blockchain_db("meta_round_trip")?;
    let block_hash = hash_from_u64(20);
    let meta = fork_meta(hash_from_u64(21), 20, 200, ForkBlockStatus::Validated);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;

    assert_some_meta(db.manager()?.get_block_meta_by_hash(&block_hash)?, &meta)
}

#[test]
fn test_037_get_block_meta_by_hash_missing_returns_none() -> TestResult {
    let db = new_blockchain_db("meta_missing")?;

    assert!(
        db.manager()?
            .get_block_meta_by_hash(&hash_from_u64(22))?
            .is_none()
    );
    Ok(())
}

#[test]
fn test_038_has_block_meta_by_hash_false_when_missing() -> TestResult {
    let db = new_blockchain_db("meta_has_false")?;

    assert!(!db.manager()?.has_block_meta_by_hash(&hash_from_u64(23))?);
    Ok(())
}

#[test]
fn test_039_has_block_meta_by_hash_true_after_store() -> TestResult {
    let db = new_blockchain_db("meta_has_true")?;
    let block_hash = hash_from_u64(24);
    let meta = fork_meta(hash_from_u64(25), 24, 240, ForkBlockStatus::BlockStored);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;

    assert!(db.manager()?.has_block_meta_by_hash(&block_hash)?);
    Ok(())
}

#[test]
fn test_040_store_block_meta_overwrites_same_hash() -> TestResult {
    let db = new_blockchain_db("meta_overwrite")?;
    let block_hash = hash_from_u64(26);

    let first = fork_meta(hash_from_u64(27), 1, 1, ForkBlockStatus::BlockStored);
    let second = fork_meta(hash_from_u64(28), 2, 2, ForkBlockStatus::Validated);

    db.manager()?
        .store_block_meta_by_hash(&block_hash, &first)?;
    db.manager()?
        .store_block_meta_by_hash(&block_hash, &second)?;

    assert_some_meta(db.manager()?.get_block_meta_by_hash(&block_hash)?, &second)
}

#[test]
fn test_041_set_block_meta_status_updates_existing_record() -> TestResult {
    let db = new_blockchain_db("meta_status_update")?;
    let block_hash = hash_from_u64(29);
    let meta = fork_meta(hash_from_u64(30), 29, 290, ForkBlockStatus::BlockStored);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
    db.manager()?
        .set_block_meta_status(&block_hash, ForkBlockStatus::Canonical)?;

    let updated = db
        .manager()?
        .get_block_meta_by_hash(&block_hash)?
        .ok_or_else(|| boxed_error("missing updated block meta"))?;

    assert_eq!(updated.status, ForkBlockStatus::Canonical);
    assert_eq!(updated.height, meta.height);
    assert_eq!(updated.parent_hash, meta.parent_hash);
    Ok(())
}

#[test]
fn test_042_set_block_meta_status_errors_when_missing() -> TestResult {
    let db = new_blockchain_db("meta_status_missing")?;

    let result = db
        .manager()?
        .set_block_meta_status(&hash_from_u64(31), ForkBlockStatus::Canonical);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_043_store_block_meta_accepts_zero_parent_for_genesis_style_meta() -> TestResult {
    let db = new_blockchain_db("meta_zero_parent")?;
    let block_hash = hash_from_u64(32);
    let meta = fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;

    assert_some_meta(db.manager()?.get_block_meta_by_hash(&block_hash)?, &meta)
}

#[test]
fn test_044_store_block_meta_accepts_max_values() -> TestResult {
    let db = new_blockchain_db("meta_max_values")?;
    let block_hash = hash_from_u64(33);
    let mut meta = fork_meta(
        hash_from_u64(34),
        u64::MAX,
        u128::MAX,
        ForkBlockStatus::SideBranch,
    );
    meta.received_at_unix_secs = u64::MAX;

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;

    assert_some_meta(db.manager()?.get_block_meta_by_hash(&block_hash)?, &meta)
}

#[test]
fn test_045_store_block_meta_multiple_status_vectors() -> TestResult {
    let db = new_blockchain_db("meta_status_vectors")?;
    let statuses = [
        ForkBlockStatus::HeaderOnly,
        ForkBlockStatus::BlockStored,
        ForkBlockStatus::Validated,
        ForkBlockStatus::Canonical,
        ForkBlockStatus::SideBranch,
        ForkBlockStatus::Orphan,
    ];

    for (offset, status) in statuses.iter().enumerate() {
        let seed = u64::try_from(offset)?.saturating_add(40);
        let block_hash = hash_from_u64(seed);
        let meta = fork_meta(
            hash_from_u64(seed.saturating_add(1)),
            seed,
            seed.into(),
            *status,
        );

        db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
        assert_some_meta(db.manager()?.get_block_meta_by_hash(&block_hash)?, &meta)?;
    }

    Ok(())
}

#[test]
fn test_046_block_meta_persists_after_reopen() -> TestResult {
    let mut db = new_blockchain_db("meta_persist_reopen")?;
    let block_hash = hash_from_u64(50);
    let meta = fork_meta(hash_from_u64(51), 50, 500, ForkBlockStatus::Validated);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    assert_some_meta(reopened.get_block_meta_by_hash(&block_hash)?, &meta)?;

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_047_block_meta_cli_manager_errors_without_blockchain_handle() -> TestResult {
    let db = new_cli_db("meta_cli_error")?;
    let meta = fork_meta(hash_from_u64(52), 52, 520, ForkBlockStatus::Validated);

    let result = db
        .manager()?
        .store_block_meta_by_hash(&hash_from_u64(53), &meta);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_048_block_meta_get_cli_manager_errors_without_blockchain_handle() -> TestResult {
    let db = new_cli_db("meta_get_cli_error")?;

    let result = db.manager()?.get_block_meta_by_hash(&hash_from_u64(54));

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_049_block_meta_hashes_are_independent() -> TestResult {
    let db = new_blockchain_db("meta_hash_independent")?;

    let hash_a = hash_from_u64(55);
    let hash_b = hash_from_u64(56);
    let meta_a = fork_meta(hash_from_u64(57), 55, 550, ForkBlockStatus::BlockStored);
    let meta_b = fork_meta(hash_from_u64(58), 56, 560, ForkBlockStatus::SideBranch);

    db.manager()?.store_block_meta_by_hash(&hash_a, &meta_a)?;
    db.manager()?.store_block_meta_by_hash(&hash_b, &meta_b)?;

    assert_some_meta(db.manager()?.get_block_meta_by_hash(&hash_a)?, &meta_a)?;
    assert_some_meta(db.manager()?.get_block_meta_by_hash(&hash_b)?, &meta_b)?;
    Ok(())
}

#[test]
fn test_050_block_meta_status_update_does_not_mutate_score() -> TestResult {
    let db = new_blockchain_db("meta_status_score_stable")?;
    let block_hash = hash_from_u64(59);
    let meta = fork_meta(hash_from_u64(60), 59, u128::MAX, ForkBlockStatus::Validated);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
    db.manager()?
        .set_block_meta_status(&block_hash, ForkBlockStatus::Orphan)?;

    let updated = db
        .manager()?
        .get_block_meta_by_hash(&block_hash)?
        .ok_or_else(|| boxed_error("missing updated meta"))?;

    assert_eq!(updated.cumulative_score, u128::MAX);
    assert_eq!(updated.status, ForkBlockStatus::Orphan);
    Ok(())
}

#[test]
fn test_051_load_many_block_meta_records() -> TestResult {
    let db = new_blockchain_db("meta_load_many")?;

    for index in 0..128u64 {
        let block_hash = hash_from_u64(1_000u64.saturating_add(index));
        let parent_hash = hash_from_u64(2_000u64.saturating_add(index));
        let meta = fork_meta(
            parent_hash,
            index,
            u128::from(index).saturating_mul(10),
            ForkBlockStatus::Validated,
        );

        db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
        assert_some_meta(db.manager()?.get_block_meta_by_hash(&block_hash)?, &meta)?;
    }

    Ok(())
}

#[test]
fn test_052_property_block_meta_round_trip_deterministic_vectors() -> TestResult {
    for index in 0..64u64 {
        let status = ForkBlockStatus::from_u8(u8::try_from(index.rem_euclid(6))?)?;
        let meta = fork_meta(
            hash_from_u64(3_000u64.saturating_add(index)),
            index,
            u128::from(index).saturating_mul(999),
            status,
        );

        let decoded = ForkBlockMeta::from_bytes(&meta.to_bytes())?;
        assert_eq!(decoded, meta);
    }

    Ok(())
}

#[test]
fn test_053_store_batch_by_block_hash_round_trip() -> TestResult {
    let db = new_blockchain_db("batch_hash_round_trip")?;
    let block_hash = hash_from_u64(61);
    let batch = b"batch-by-hash";

    db.manager()?
        .store_batch_by_block_hash(&block_hash, batch)?;

    assert_some_bytes(db.manager()?.get_batch_by_block_hash(&block_hash)?, batch)
}

#[test]
fn test_054_get_batch_by_block_hash_missing_returns_none() -> TestResult {
    let db = new_blockchain_db("batch_hash_missing")?;

    assert!(
        db.manager()?
            .get_batch_by_block_hash(&hash_from_u64(62))?
            .is_none()
    );
    Ok(())
}

#[test]
fn test_055_has_batch_by_block_hash_false_when_missing() -> TestResult {
    let db = new_blockchain_db("batch_hash_has_false")?;

    assert!(!db.manager()?.has_batch_by_block_hash(&hash_from_u64(63))?);
    Ok(())
}

#[test]
fn test_056_has_batch_by_block_hash_true_after_store() -> TestResult {
    let db = new_blockchain_db("batch_hash_has_true")?;
    let block_hash = hash_from_u64(64);

    db.manager()?
        .store_batch_by_block_hash(&block_hash, b"batch")?;

    assert!(db.manager()?.has_batch_by_block_hash(&block_hash)?);
    Ok(())
}

#[test]
fn test_057_store_batch_by_block_hash_empty_bytes() -> TestResult {
    let db = new_blockchain_db("batch_hash_empty")?;
    let block_hash = hash_from_u64(65);

    db.manager()?.store_batch_by_block_hash(&block_hash, b"")?;

    assert_some_bytes(db.manager()?.get_batch_by_block_hash(&block_hash)?, b"")
}

#[test]
fn test_058_store_batch_by_block_hash_binary_bytes() -> TestResult {
    let db = new_blockchain_db("batch_hash_binary")?;
    let block_hash = hash_from_u64(66);
    let bytes = [0u8, 255, 1, 254, 2, 253];

    db.manager()?
        .store_batch_by_block_hash(&block_hash, &bytes)?;

    assert_some_bytes(db.manager()?.get_batch_by_block_hash(&block_hash)?, &bytes)
}

#[test]
fn test_059_store_batch_by_block_hash_overwrites_same_hash() -> TestResult {
    let db = new_blockchain_db("batch_hash_overwrite")?;
    let block_hash = hash_from_u64(67);

    db.manager()?
        .store_batch_by_block_hash(&block_hash, b"first")?;
    db.manager()?
        .store_batch_by_block_hash(&block_hash, b"second")?;

    assert_some_bytes(
        db.manager()?.get_batch_by_block_hash(&block_hash)?,
        b"second",
    )
}

#[test]
fn test_060_batch_by_block_hash_hashes_are_independent() -> TestResult {
    let db = new_blockchain_db("batch_hash_independent")?;

    let hash_a = hash_from_u64(68);
    let hash_b = hash_from_u64(69);

    db.manager()?.store_batch_by_block_hash(&hash_a, b"a")?;
    db.manager()?.store_batch_by_block_hash(&hash_b, b"b")?;

    assert_some_bytes(db.manager()?.get_batch_by_block_hash(&hash_a)?, b"a")?;
    assert_some_bytes(db.manager()?.get_batch_by_block_hash(&hash_b)?, b"b")?;
    Ok(())
}

#[test]
fn test_061_batch_by_block_hash_persists_after_reopen() -> TestResult {
    let mut db = new_blockchain_db("batch_hash_reopen")?;
    let block_hash = hash_from_u64(70);

    db.manager()?
        .store_batch_by_block_hash(&block_hash, b"persist-batch")?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    assert_some_bytes(
        reopened.get_batch_by_block_hash(&block_hash)?,
        b"persist-batch",
    )?;

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_062_batch_by_block_hash_cli_manager_errors_without_blockchain_handle() -> TestResult {
    let db = new_cli_db("batch_cli_error")?;

    let result = db
        .manager()?
        .store_batch_by_block_hash(&hash_from_u64(71), b"batch");

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_063_load_many_batches_by_block_hash() -> TestResult {
    let db = new_blockchain_db("batch_hash_load_many")?;

    for index in 0..128u64 {
        let block_hash = hash_from_u64(4_000u64.saturating_add(index));
        let bytes = format!("batch-hash-load-{index:04}").into_bytes();

        db.manager()?
            .store_batch_by_block_hash(&block_hash, &bytes)?;
        assert_some_bytes(db.manager()?.get_batch_by_block_hash(&block_hash)?, &bytes)?;
    }

    Ok(())
}

#[test]
fn test_064_property_batch_by_hash_last_write_wins() -> TestResult {
    let db = new_blockchain_db("batch_hash_last_write")?;
    let block_hash = hash_from_u64(72);

    for index in 0..50u64 {
        let bytes = index.to_be_bytes();

        db.manager()?
            .store_batch_by_block_hash(&block_hash, &bytes)?;
        assert_some_bytes(db.manager()?.get_batch_by_block_hash(&block_hash)?, &bytes)?;
    }

    Ok(())
}

#[test]
fn test_065_property_batch_by_hash_sparse_hashes_are_independent() -> TestResult {
    let db = new_blockchain_db("batch_hash_sparse")?;

    let seeds = [1u64, 10, 100, 1_000, 10_000, u64::from(u32::MAX)];
    for seed in seeds {
        let block_hash = hash_from_u64(seed);
        let bytes = seed.to_be_bytes();

        db.manager()?
            .store_batch_by_block_hash(&block_hash, &bytes)?;
        assert_some_bytes(db.manager()?.get_batch_by_block_hash(&block_hash)?, &bytes)?;
    }

    Ok(())
}

#[test]
fn test_066_set_and_get_canonical_hash_at_height_round_trip() -> TestResult {
    let db = new_blockchain_db("canonical_height_round_trip")?;
    let block_hash = hash_from_u64(73);

    db.manager()?.set_canonical_hash_at_height(7, &block_hash)?;

    assert_some_hash(db.manager()?.get_canonical_hash_at_height(7)?, block_hash)
}

#[test]
fn test_067_get_canonical_hash_missing_returns_none() -> TestResult {
    let db = new_blockchain_db("canonical_height_missing")?;

    assert!(db.manager()?.get_canonical_hash_at_height(7)?.is_none());
    Ok(())
}

#[test]
fn test_068_canonical_height_zero_round_trip() -> TestResult {
    let db = new_blockchain_db("canonical_height_zero")?;
    let block_hash = hash_from_u64(74);

    db.manager()?.set_canonical_hash_at_height(0, &block_hash)?;

    assert_some_hash(db.manager()?.get_canonical_hash_at_height(0)?, block_hash)
}

#[test]
fn test_069_canonical_height_u64_max_round_trip() -> TestResult {
    let db = new_blockchain_db("canonical_height_u64_max")?;
    let block_hash = hash_from_u64(75);

    db.manager()?
        .set_canonical_hash_at_height(u64::MAX, &block_hash)?;

    assert_some_hash(
        db.manager()?.get_canonical_hash_at_height(u64::MAX)?,
        block_hash,
    )
}

#[test]
fn test_070_canonical_height_overwrite_same_height() -> TestResult {
    let db = new_blockchain_db("canonical_height_overwrite")?;
    let first = hash_from_u64(76);
    let second = hash_from_u64(77);

    db.manager()?.set_canonical_hash_at_height(9, &first)?;
    db.manager()?.set_canonical_hash_at_height(9, &second)?;

    assert_some_hash(db.manager()?.get_canonical_hash_at_height(9)?, second)
}

#[test]
fn test_071_canonical_height_multiple_heights_independent() -> TestResult {
    let db = new_blockchain_db("canonical_height_independent")?;

    for height in 0..16u64 {
        let block_hash = hash_from_u64(5_000u64.saturating_add(height));
        db.manager()?
            .set_canonical_hash_at_height(height, &block_hash)?;
    }

    for height in 0..16u64 {
        let block_hash = hash_from_u64(5_000u64.saturating_add(height));
        assert_some_hash(
            db.manager()?.get_canonical_hash_at_height(height)?,
            block_hash,
        )?;
    }

    Ok(())
}

#[test]
fn test_072_delete_canonical_hash_range_removes_inclusive_range() -> TestResult {
    let db = new_blockchain_db("canonical_delete_range")?;

    for height in 0..10u64 {
        let block_hash = hash_from_u64(6_000u64.saturating_add(height));
        db.manager()?
            .set_canonical_hash_at_height(height, &block_hash)?;
    }

    db.manager()?.delete_canonical_hash_range(3, 6)?;

    assert!(db.manager()?.get_canonical_hash_at_height(2)?.is_some());
    assert!(db.manager()?.get_canonical_hash_at_height(3)?.is_none());
    assert!(db.manager()?.get_canonical_hash_at_height(6)?.is_none());
    assert!(db.manager()?.get_canonical_hash_at_height(7)?.is_some());
    Ok(())
}

#[test]
fn test_073_delete_canonical_hash_range_noop_when_from_greater_than_to() -> TestResult {
    let db = new_blockchain_db("canonical_delete_noop")?;
    let block_hash = hash_from_u64(78);

    db.manager()?.set_canonical_hash_at_height(5, &block_hash)?;
    db.manager()?.delete_canonical_hash_range(9, 5)?;

    assert_some_hash(db.manager()?.get_canonical_hash_at_height(5)?, block_hash)
}

#[test]
fn test_074_delete_canonical_hash_single_height() -> TestResult {
    let db = new_blockchain_db("canonical_delete_single")?;
    let block_hash = hash_from_u64(79);

    db.manager()?.set_canonical_hash_at_height(5, &block_hash)?;
    db.manager()?.delete_canonical_hash_range(5, 5)?;

    assert!(db.manager()?.get_canonical_hash_at_height(5)?.is_none());
    Ok(())
}

#[test]
fn test_075_canonical_height_invalid_stored_hash_length_errors() -> TestResult {
    let db = new_blockchain_db("canonical_invalid_len")?;

    db.manager()?.write(
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        &5u64.to_be_bytes(),
        b"bad-length",
    )?;

    assert!(db.manager()?.get_canonical_hash_at_height(5).is_err());
    Ok(())
}

#[test]
fn test_076_canonical_height_persists_after_reopen() -> TestResult {
    let mut db = new_blockchain_db("canonical_height_reopen")?;
    let block_hash = hash_from_u64(80);

    db.manager()?
        .set_canonical_hash_at_height(80, &block_hash)?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    assert_some_hash(reopened.get_canonical_hash_at_height(80)?, block_hash)?;

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_077_load_many_canonical_height_mappings() -> TestResult {
    let db = new_blockchain_db("canonical_height_load_many")?;

    for height in 0..128u64 {
        let block_hash = hash_from_u64(7_000u64.saturating_add(height));
        db.manager()?
            .set_canonical_hash_at_height(height, &block_hash)?;
    }

    for height in 0..128u64 {
        let block_hash = hash_from_u64(7_000u64.saturating_add(height));
        assert_some_hash(
            db.manager()?.get_canonical_hash_at_height(height)?,
            block_hash,
        )?;
    }

    Ok(())
}

#[test]
fn test_078_set_and_get_canonical_tip_round_trip() -> TestResult {
    let db = new_blockchain_db("tip_round_trip")?;
    let tip_hash = hash_from_u64(81);

    db.manager()?.set_canonical_tip(&tip_hash, 81)?;

    let expected = CanonicalTipView {
        tip_hash,
        tip_height: 81,
    };

    assert_some_tip(db.manager()?.get_canonical_tip()?, &expected)
}

#[test]
fn test_079_get_canonical_tip_missing_returns_none() -> TestResult {
    let db = new_blockchain_db("tip_missing")?;

    assert!(db.manager()?.get_canonical_tip()?.is_none());
    Ok(())
}

#[test]
fn test_080_get_canonical_tip_hash_returns_hash_only() -> TestResult {
    let db = new_blockchain_db("tip_hash_only")?;
    let tip_hash = hash_from_u64(82);

    db.manager()?.set_canonical_tip(&tip_hash, 82)?;

    assert_some_hash(db.manager()?.get_canonical_tip_hash()?, tip_hash)
}

#[test]
fn test_081_get_canonical_tip_height_returns_height_only() -> TestResult {
    let db = new_blockchain_db("tip_height_only")?;
    let tip_hash = hash_from_u64(83);

    db.manager()?.set_canonical_tip(&tip_hash, 83)?;

    let height = db
        .manager()?
        .get_canonical_tip_height()?
        .ok_or_else(|| boxed_error("missing canonical tip height"))?;

    assert_eq!(height, 83);
    Ok(())
}

#[test]
fn test_082_set_canonical_tip_updates_legacy_tip_metadata() -> TestResult {
    let db = new_blockchain_db("tip_updates_legacy")?;
    let tip_hash = hash_from_u64(84);

    db.manager()?.set_canonical_tip(&tip_hash, 84)?;

    assert_eq!(db.manager()?.get_tip_height()?, 84);
    assert_eq!(db.manager()?.get_latest_block_index()?, 84);
    Ok(())
}

#[test]
fn test_083_set_canonical_tip_overwrites_previous_tip() -> TestResult {
    let db = new_blockchain_db("tip_overwrite")?;
    let first = hash_from_u64(85);
    let second = hash_from_u64(86);

    db.manager()?.set_canonical_tip(&first, 85)?;
    db.manager()?.set_canonical_tip(&second, 86)?;

    let expected = CanonicalTipView {
        tip_hash: second,
        tip_height: 86,
    };

    assert_some_tip(db.manager()?.get_canonical_tip()?, &expected)
}

#[test]
fn test_084_canonical_tip_invalid_stored_length_errors() -> TestResult {
    let db = new_blockchain_db("tip_invalid_len")?;

    db.manager()?.write(
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
        b"canonical_tip_view",
        b"bad",
    )?;

    assert!(db.manager()?.get_canonical_tip().is_err());
    Ok(())
}

#[test]
fn test_085_canonical_tip_persists_after_reopen() -> TestResult {
    let mut db = new_blockchain_db("tip_reopen")?;
    let tip_hash = hash_from_u64(87);

    db.manager()?.set_canonical_tip(&tip_hash, 87)?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    let expected = CanonicalTipView {
        tip_hash,
        tip_height: 87,
    };

    assert_some_tip(reopened.get_canonical_tip()?, &expected)?;

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_086_set_canonical_tip_accepts_height_zero() -> TestResult {
    let db = new_blockchain_db("tip_height_zero")?;
    let tip_hash = hash_from_u64(88);

    db.manager()?.set_canonical_tip(&tip_hash, 0)?;

    let expected = CanonicalTipView {
        tip_hash,
        tip_height: 0,
    };

    assert_some_tip(db.manager()?.get_canonical_tip()?, &expected)
}

#[test]
fn test_087_ingest_fork_block_stores_block_meta_and_batch() -> TestResult {
    let db = new_blockchain_db("ingest_full")?;
    let block = test_block(0, zero_hash())?;
    let bytes = block_bytes(&block)?;
    let meta = fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Validated);
    let batch = b"genesis-batch";

    db.manager()?
        .ingest_fork_block(&block.block_hash, &bytes, &meta, Some(batch))?;

    assert!(db.manager()?.has_block_by_hash(&block.block_hash));
    assert_some_meta(
        db.manager()?.get_block_meta_by_hash(&block.block_hash)?,
        &meta,
    )?;
    assert_some_bytes(
        db.manager()?.get_batch_by_block_hash(&block.block_hash)?,
        batch,
    )?;
    Ok(())
}

#[test]
fn test_088_ingest_fork_block_without_batch_stores_block_and_meta_only() -> TestResult {
    let db = new_blockchain_db("ingest_without_batch")?;
    let block = test_block(0, zero_hash())?;
    let bytes = block_bytes(&block)?;
    let meta = fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Validated);

    db.manager()?
        .ingest_fork_block(&block.block_hash, &bytes, &meta, None)?;

    assert!(db.manager()?.has_block_by_hash(&block.block_hash));
    assert_some_meta(
        db.manager()?.get_block_meta_by_hash(&block.block_hash)?,
        &meta,
    )?;
    assert!(
        db.manager()?
            .get_batch_by_block_hash(&block.block_hash)?
            .is_none()
    );
    Ok(())
}

#[test]
fn test_089_ingest_fork_block_rejects_invalid_block_bytes() -> TestResult {
    let db = new_blockchain_db("ingest_bad_block")?;
    let block_hash = hash_from_u64(89);
    let meta = fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Validated);

    let result = db
        .manager()?
        .ingest_fork_block(&block_hash, b"not-a-block", &meta, None);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_090_promote_block_to_canonical_updates_status_mapping_and_tip() -> TestResult {
    let db = new_blockchain_db("promote_canonical")?;
    let block_hash = hash_from_u64(90);
    let meta = fork_meta(hash_from_u64(91), 90, 900, ForkBlockStatus::Validated);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
    db.manager()?.promote_block_to_canonical(90, &block_hash)?;

    let updated = db
        .manager()?
        .get_block_meta_by_hash(&block_hash)?
        .ok_or_else(|| boxed_error("missing promoted meta"))?;

    assert_eq!(updated.status, ForkBlockStatus::Canonical);
    assert_some_hash(db.manager()?.get_canonical_hash_at_height(90)?, block_hash)?;
    assert_some_hash(db.manager()?.get_canonical_tip_hash()?, block_hash)?;
    assert_eq!(db.manager()?.get_canonical_tip_height()?, Some(90));
    Ok(())
}

#[test]
fn test_091_promote_block_to_canonical_errors_when_meta_missing() -> TestResult {
    let db = new_blockchain_db("promote_missing_meta")?;

    let result = db
        .manager()?
        .promote_block_to_canonical(91, &hash_from_u64(91));

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_092_promote_block_to_canonical_persists_after_reopen() -> TestResult {
    let mut db = new_blockchain_db("promote_reopen")?;
    let block_hash = hash_from_u64(92);
    let meta = fork_meta(hash_from_u64(93), 92, 920, ForkBlockStatus::Validated);

    db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
    db.manager()?.promote_block_to_canonical(92, &block_hash)?;
    db.manager()?.flush_blockchain_db()?;

    let opts = node_opts(db.root())?;
    let blockchain_path = db.manager()?.directory.blockchain_path.clone();

    drop(db.manager.take());

    let reopened_path = path_to_string(&blockchain_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &reopened_path)?;

    assert_some_hash(reopened.get_canonical_hash_at_height(92)?, block_hash)?;
    assert_some_hash(reopened.get_canonical_tip_hash()?, block_hash)?;

    drop(reopened);
    std::fs::remove_dir_all(db.root())?;
    Ok(())
}

#[test]
fn test_093_ingest_and_promote_valid_block_flow() -> TestResult {
    let db = new_blockchain_db("ingest_promote_flow")?;
    let block = test_block(0, zero_hash())?;
    let bytes = block_bytes(&block)?;
    let meta = fork_meta(zero_hash(), 0, 1, ForkBlockStatus::Validated);

    db.manager()?
        .ingest_fork_block(&block.block_hash, &bytes, &meta, Some(b"batch"))?;
    db.manager()?
        .promote_block_to_canonical(0, &block.block_hash)?;

    assert_some_hash(
        db.manager()?.get_canonical_hash_at_height(0)?,
        block.block_hash,
    )?;
    assert_some_hash(db.manager()?.get_canonical_tip_hash()?, block.block_hash)?;
    Ok(())
}

#[test]
fn test_094_build_hash_ancestry_path_stops_at_zero_parent() -> TestResult {
    let db = new_blockchain_db("ancestry_zero_parent")?;
    let genesis = hash_from_u64(100);
    let child = hash_from_u64(101);

    let genesis_meta = fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical);
    let child_meta = fork_meta(genesis, 1, 1, ForkBlockStatus::Validated);

    db.manager()?
        .store_block_meta_by_hash(&genesis, &genesis_meta)?;
    db.manager()?
        .store_block_meta_by_hash(&child, &child_meta)?;

    let path = db.manager()?.build_hash_ancestry_path(&child, 10)?;

    assert_eq!(path.len(), 2);
    assert_eq!(get_vec_item(&path, 0)?, child);
    assert_eq!(get_vec_item(&path, 1)?, genesis);
    Ok(())
}

#[test]
fn test_095_build_hash_ancestry_path_stops_when_metadata_missing() -> TestResult {
    let db = new_blockchain_db("ancestry_missing_meta")?;
    let parent = hash_from_u64(102);
    let child = hash_from_u64(103);

    let child_meta = fork_meta(parent, 1, 1, ForkBlockStatus::Validated);
    db.manager()?
        .store_block_meta_by_hash(&child, &child_meta)?;

    let path = db.manager()?.build_hash_ancestry_path(&child, 10)?;

    assert_eq!(path.len(), 2);
    assert_eq!(get_vec_item(&path, 0)?, child);
    assert_eq!(get_vec_item(&path, 1)?, parent);
    Ok(())
}

#[test]
fn test_096_build_hash_ancestry_path_respects_max_depth() -> TestResult {
    let db = new_blockchain_db("ancestry_max_depth")?;
    let a = hash_from_u64(104);
    let b = hash_from_u64(105);
    let c = hash_from_u64(106);

    db.manager()?.store_block_meta_by_hash(
        &a,
        &fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical),
    )?;
    db.manager()?
        .store_block_meta_by_hash(&b, &fork_meta(a, 1, 1, ForkBlockStatus::Validated))?;
    db.manager()?
        .store_block_meta_by_hash(&c, &fork_meta(b, 2, 2, ForkBlockStatus::Validated))?;

    let path = db.manager()?.build_hash_ancestry_path(&c, 2)?;

    assert_eq!(path.len(), 2);
    assert_eq!(get_vec_item(&path, 0)?, c);
    assert_eq!(get_vec_item(&path, 1)?, b);
    Ok(())
}

#[test]
fn test_097_find_common_ancestor_hash_finds_shared_parent() -> TestResult {
    let db = new_blockchain_db("ancestor_shared_parent")?;
    let root = hash_from_u64(107);
    let left = hash_from_u64(108);
    let right = hash_from_u64(109);

    db.manager()?.store_block_meta_by_hash(
        &root,
        &fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical),
    )?;
    db.manager()?
        .store_block_meta_by_hash(&left, &fork_meta(root, 1, 10, ForkBlockStatus::SideBranch))?;
    db.manager()?
        .store_block_meta_by_hash(&right, &fork_meta(root, 1, 11, ForkBlockStatus::SideBranch))?;

    let ancestor = db
        .manager()?
        .find_common_ancestor_hash(&left, &right, 10)?
        .ok_or_else(|| boxed_error("missing common ancestor"))?;

    assert_eq!(ancestor, root);
    Ok(())
}

#[test]
fn test_098_find_common_ancestor_hash_returns_tip_when_same_tip() -> TestResult {
    let db = new_blockchain_db("ancestor_same_tip")?;
    let tip = hash_from_u64(110);

    db.manager()?.store_block_meta_by_hash(
        &tip,
        &fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical),
    )?;

    let ancestor = db
        .manager()?
        .find_common_ancestor_hash(&tip, &tip, 10)?
        .ok_or_else(|| boxed_error("missing self common ancestor"))?;

    assert_eq!(ancestor, tip);
    Ok(())
}

#[test]
fn test_099_find_common_ancestor_hash_returns_none_for_disjoint_paths() -> TestResult {
    let db = new_blockchain_db("ancestor_disjoint")?;
    let a_root = hash_from_u64(111);
    let b_root = hash_from_u64(112);
    let a_tip = hash_from_u64(113);
    let b_tip = hash_from_u64(114);

    db.manager()?.store_block_meta_by_hash(
        &a_root,
        &fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical),
    )?;
    db.manager()?.store_block_meta_by_hash(
        &b_root,
        &fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical),
    )?;
    db.manager()?.store_block_meta_by_hash(
        &a_tip,
        &fork_meta(a_root, 1, 1, ForkBlockStatus::SideBranch),
    )?;
    db.manager()?.store_block_meta_by_hash(
        &b_tip,
        &fork_meta(b_root, 1, 1, ForkBlockStatus::SideBranch),
    )?;

    assert!(
        db.manager()?
            .find_common_ancestor_hash(&a_tip, &b_tip, 10)?
            .is_none()
    );
    Ok(())
}

#[test]
fn test_100_adversarial_fork_graph_load_promote_and_common_ancestor_sweep() -> TestResult {
    let db = new_blockchain_db("adversarial_fork_graph")?;

    let genesis = hash_from_u64(10_000);
    db.manager()?.store_block_meta_by_hash(
        &genesis,
        &fork_meta(zero_hash(), 0, 0, ForkBlockStatus::Canonical),
    )?;
    db.manager()?.set_canonical_hash_at_height(0, &genesis)?;
    db.manager()?.set_canonical_tip(&genesis, 0)?;

    let mut canonical_parent = genesis;
    for height in 1..32u64 {
        let block_hash = hash_from_u64(10_000u64.saturating_add(height));
        let meta = fork_meta(
            canonical_parent,
            height,
            u128::from(height).saturating_mul(100),
            ForkBlockStatus::Validated,
        );

        db.manager()?.store_block_meta_by_hash(&block_hash, &meta)?;
        db.manager()?
            .promote_block_to_canonical(height, &block_hash)?;
        canonical_parent = block_hash;
    }

    let fork_point = db
        .manager()?
        .get_canonical_hash_at_height(16)?
        .ok_or_else(|| boxed_error("missing fork point"))?;

    let mut side_parent = fork_point;
    for height in 17..40u64 {
        let side_hash = hash_from_u64(20_000u64.saturating_add(height));
        let meta = fork_meta(
            side_parent,
            height,
            u128::from(height).saturating_mul(101),
            ForkBlockStatus::SideBranch,
        );

        db.manager()?.store_block_meta_by_hash(&side_hash, &meta)?;
        db.manager()?
            .store_batch_by_block_hash(&side_hash, &height.to_be_bytes())?;
        side_parent = side_hash;
    }

    let canonical_tip = db
        .manager()?
        .get_canonical_tip_hash()?
        .ok_or_else(|| boxed_error("missing canonical tip hash"))?;

    let ancestor = db
        .manager()?
        .find_common_ancestor_hash(&canonical_tip, &side_parent, 128)?
        .ok_or_else(|| boxed_error("missing adversarial common ancestor"))?;

    assert_eq!(ancestor, fork_point);
    assert_eq!(db.manager()?.get_canonical_tip_height()?, Some(31));
    assert!(db.manager()?.has_batch_by_block_hash(&side_parent)?);

    Ok(())
}
