use remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use remzar::storage::rocksdb_008_helper::force_full_compaction;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use rust_rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

type TestResult = Result<(), String>;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Result<Self, String> {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_rocksdb_008_sst_compaction_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            let _remove_result = fs::remove_dir_all(&root);
        }

        fs::create_dir_all(&root)
            .map_err(|err| format!("failed to create temp root '{}': {err}", root.display()))?;

        Ok(Self { root })
    }

    fn child(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _remove_result = fs::remove_dir_all(&self.root);
    }
}

fn debug_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn test_options() -> Options {
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options
}

fn expected_cf_names() -> Vec<&'static str> {
    vec![
        "default",
        GlobalConfiguration::META_DATA_COLUMN_NAME,
        GlobalConfiguration::GLOBAL_COLUMN_NAME,
        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME,
        GlobalConfiguration::STATE_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        GlobalConfiguration::REWARD_COLUMN_NAME,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        GlobalConfiguration::LOGS_COLUMN_NAME,
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::IDENTITY_COLUMN_NAME,
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
    ]
}

fn expected_cf_set() -> BTreeSet<String> {
    expected_cf_names().into_iter().map(str::to_owned).collect()
}

fn open_default_db(path: &Path) -> Result<DB, String> {
    DB::open(&test_options(), path).map_err(debug_err)
}

fn open_full_db(path: &Path) -> Result<DB, String> {
    DB::open_cf_descriptors(&test_options(), path, CFDescriptors::get_cf_descriptors())
        .map_err(debug_err)
}

fn open_extra_only_db(path: &Path) -> Result<DB, String> {
    let descriptors = vec![
        ColumnFamilyDescriptor::new("default", Options::default()),
        ColumnFamilyDescriptor::new("extra_cf", Options::default()),
    ];

    DB::open_cf_descriptors(&test_options(), path, descriptors).map_err(debug_err)
}

fn open_full_plus_extra_db(path: &Path) -> Result<DB, String> {
    let mut descriptors = CFDescriptors::get_cf_descriptors();

    descriptors.push(ColumnFamilyDescriptor::new("extra_cf", Options::default()));

    DB::open_cf_descriptors(&test_options(), path, descriptors).map_err(debug_err)
}

fn list_cf_set(path: &Path) -> Result<BTreeSet<String>, String> {
    DB::list_cf(&test_options(), path)
        .map(|names| names.into_iter().collect())
        .map_err(debug_err)
}

fn put_default(db: &DB, key: &[u8], value: &[u8]) -> TestResult {
    db.put(key, value).map_err(debug_err)
}

fn get_default(db: &DB, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
    db.get(key).map_err(debug_err)
}

fn put_cf(db: &DB, cf_name: &str, key: &[u8], value: &[u8]) -> TestResult {
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("missing column family: {cf_name}"))?;

    db.put_cf(cf, key, value).map_err(debug_err)
}

fn get_cf(db: &DB, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("missing column family: {cf_name}"))?;

    db.get_cf(cf, key).map_err(debug_err)
}

fn count_default_entries(db: &DB) -> usize {
    db.iterator(IteratorMode::Start)
        .filter_map(Result::ok)
        .count()
}

fn count_cf_entries(db: &DB, cf_name: &str) -> Result<usize, String> {
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("missing column family: {cf_name}"))?;

    Ok(db
        .iterator_cf(cf, IteratorMode::Start)
        .filter_map(Result::ok)
        .count())
}

fn deterministic_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| {
            let low = index.to_le_bytes()[0];
            seed.wrapping_add(low).rotate_left(1)
        })
        .collect()
}

#[test]
fn sst_compaction_001_default_only_empty_db_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_001")?;
    let db = open_default_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    Ok(())
}

#[test]
fn sst_compaction_002_full_schema_empty_db_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_002")?;
    let db = open_full_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    Ok(())
}

#[test]
fn sst_compaction_003_extra_only_db_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_003")?;
    let db = open_extra_only_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    Ok(())
}

#[test]
fn sst_compaction_004_full_plus_extra_db_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_004")?;
    let db = open_full_plus_extra_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    Ok(())
}

#[test]
fn sst_compaction_005_default_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_005")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_006_full_schema_default_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_006")?;
    let db = open_full_db(&temp.child("db"))?;

    put_default(&db, b"default-key", b"default-value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_default(&db, b"default-key")?,
        Some(b"default-value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_007_meta_data_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_007")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::META_DATA_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::META_DATA_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_008_global_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_008")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::GLOBAL_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::GLOBAL_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_009_account_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_009")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::ACCOUNT_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_010_network_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_010")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::NETWORK_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_011_sidechain_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_011")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::SIDECHAIN_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_012_state_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_012")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::STATE_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::STATE_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_013_transaction_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_013")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::TRANSACTION_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_014_transaction_batch_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_014")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(
            &db,
            GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
            b"key"
        )?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_015_reward_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_015")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::REWARD_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::REWARD_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_016_reward_batch_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_016")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::REWARD_BATCH_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_017_blockmint_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_017")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_018_logs_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_018")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(&db, GlobalConfiguration::LOGS_COLUMN_NAME, b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::LOGS_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_019_block_to_hash_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_019")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_020_tx_to_hash_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_020")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::TX_TO_HASH_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_021_identity_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_021")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::IDENTITY_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::IDENTITY_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_022_block_meta_by_hash_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_022")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(
            &db,
            GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
            b"key"
        )?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_023_batch_by_block_hash_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_023")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(
            &db,
            GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
            b"key"
        )?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_024_canonical_height_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_024")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(
            &db,
            GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
            b"key"
        )?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_025_canonical_chain_view_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_025")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
        b"key",
        b"value",
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(
            &db,
            GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
            b"key"
        )?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_026_all_expected_cfs_are_present_in_full_schema() -> TestResult {
    let temp = TempTree::new("sst_compaction_026")?;
    let path = temp.child("db");

    let db = open_full_db(&path)?;
    force_full_compaction(&db).map_err(debug_err)?;
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_cf_set());

    Ok(())
}

#[test]
fn sst_compaction_027_default_only_schema_remains_default_only() -> TestResult {
    let temp = TempTree::new("sst_compaction_027")?;
    let path = temp.child("db");

    let db = open_default_db(&path)?;
    force_full_compaction(&db).map_err(debug_err)?;
    drop(db);

    assert_eq!(
        list_cf_set(&path)?,
        ["default".to_owned()].into_iter().collect()
    );

    Ok(())
}

#[test]
fn sst_compaction_028_full_plus_extra_schema_preserves_extra_cf() -> TestResult {
    let temp = TempTree::new("sst_compaction_028")?;
    let path = temp.child("db");

    let db = open_full_plus_extra_db(&path)?;
    force_full_compaction(&db).map_err(debug_err)?;
    drop(db);

    let cfs = list_cf_set(&path)?;

    assert!(cfs.contains("extra_cf"));
    assert!(cfs.is_superset(&expected_cf_set()));

    Ok(())
}

#[test]
fn sst_compaction_029_extra_only_schema_preserves_extra_cf() -> TestResult {
    let temp = TempTree::new("sst_compaction_029")?;
    let path = temp.child("db");

    let db = open_extra_only_db(&path)?;
    force_full_compaction(&db).map_err(debug_err)?;
    drop(db);

    let cfs = list_cf_set(&path)?;

    assert!(cfs.contains("default"));
    assert!(cfs.contains("extra_cf"));
    assert_eq!(cfs.len(), 2);

    Ok(())
}

#[test]
fn sst_compaction_030_extra_cf_value_survives_even_though_not_in_canonical_list() -> TestResult {
    let temp = TempTree::new("sst_compaction_030")?;
    let db = open_full_plus_extra_db(&temp.child("db"))?;

    put_cf(&db, "extra_cf", b"extra-key", b"extra-value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, "extra_cf", b"extra-key")?,
        Some(b"extra-value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_031_empty_key_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_031")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"", b"")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"")?, Some(Vec::new()));

    Ok(())
}

#[test]
fn sst_compaction_032_binary_key_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_032")?;
    let db = open_full_db(&temp.child("db"))?;
    let key = [0_u8, 1, 255, 128, 64];
    let value = [255_u8, 0, 42, 11, 9];

    put_cf(&db, GlobalConfiguration::LOGS_COLUMN_NAME, &key, &value)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::LOGS_COLUMN_NAME, &key)?,
        Some(value.to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_033_large_default_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_033")?;
    let db = open_default_db(&temp.child("db"))?;
    let value = deterministic_bytes(64 * 1024, 33);

    put_default(&db, b"large", &value)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"large")?, Some(value));

    Ok(())
}

#[test]
fn sst_compaction_034_large_cf_value_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_034")?;
    let db = open_full_db(&temp.child("db"))?;
    let value = deterministic_bytes(64 * 1024, 34);

    put_cf(
        &db,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        b"large-tx",
        &value,
    )?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(
            &db,
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            b"large-tx"
        )?,
        Some(value)
    );

    Ok(())
}

#[test]
fn sst_compaction_035_multiple_default_entries_survive_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_035")?;
    let db = open_default_db(&temp.child("db"))?;

    for index in 0..100 {
        put_default(
            &db,
            format!("key-{index:03}").as_bytes(),
            format!("value-{index:03}").as_bytes(),
        )?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(count_default_entries(&db), 100);

    Ok(())
}

#[test]
fn sst_compaction_036_multiple_cf_entries_survive_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_036")?;
    let db = open_full_db(&temp.child("db"))?;

    for index in 0..100 {
        put_cf(
            &db,
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            format!("tx-key-{index:03}").as_bytes(),
            format!("tx-value-{index:03}").as_bytes(),
        )?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        count_cf_entries(&db, GlobalConfiguration::TRANSACTION_COLUMN_NAME)?,
        100
    );

    Ok(())
}

#[test]
fn sst_compaction_037_repeated_compaction_on_empty_default_db_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_037")?;
    let db = open_default_db(&temp.child("db"))?;

    for _ in 0..10 {
        force_full_compaction(&db).map_err(debug_err)?;
    }

    Ok(())
}

#[test]
fn sst_compaction_038_repeated_compaction_on_full_schema_db_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_038")?;
    let db = open_full_db(&temp.child("db"))?;

    for _ in 0..10 {
        force_full_compaction(&db).map_err(debug_err)?;
    }

    Ok(())
}

#[test]
fn sst_compaction_039_repeated_compaction_preserves_default_value() -> TestResult {
    let temp = TempTree::new("sst_compaction_039")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"value")?;

    for _ in 0..10 {
        force_full_compaction(&db).map_err(debug_err)?;
    }

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_040_repeated_compaction_preserves_full_schema_value() -> TestResult {
    let temp = TempTree::new("sst_compaction_040")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(
        &db,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        b"key",
        b"value",
    )?;

    for _ in 0..10 {
        force_full_compaction(&db).map_err(debug_err)?;
    }

    assert_eq!(
        get_cf(&db, GlobalConfiguration::REWARD_BATCH_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_041_compaction_after_overwrite_keeps_latest_default_value() -> TestResult {
    let temp = TempTree::new("sst_compaction_041")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"old")?;
    put_default(&db, b"key", b"new")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"new".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_042_compaction_after_overwrite_keeps_latest_cf_value() -> TestResult {
    let temp = TempTree::new("sst_compaction_042")?;
    let db = open_full_db(&temp.child("db"))?;

    put_cf(&db, GlobalConfiguration::STATE_COLUMN_NAME, b"key", b"old")?;
    put_cf(&db, GlobalConfiguration::STATE_COLUMN_NAME, b"key", b"new")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::STATE_COLUMN_NAME, b"key")?,
        Some(b"new".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_043_default_data_persists_after_reopen_following_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_043")?;
    let path = temp.child("db");

    {
        let db = open_default_db(&path)?;
        put_default(&db, b"key", b"value")?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    let reopened = open_default_db(&path)?;

    assert_eq!(get_default(&reopened, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_044_full_schema_data_persists_after_reopen_following_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_044")?;
    let path = temp.child("db");

    {
        let db = open_full_db(&path)?;
        put_cf(
            &db,
            GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
            b"key",
            b"value",
        )?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    let reopened = open_full_db(&path)?;

    assert_eq!(
        get_cf(
            &reopened,
            GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
            b"key"
        )?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_045_full_schema_all_cfs_accept_one_value_before_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_045")?;
    let db = open_full_db(&temp.child("db"))?;

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        put_cf(&db, cf_name, b"shared-key", cf_name.as_bytes())?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        assert_eq!(
            get_cf(&db, cf_name, b"shared-key")?,
            Some(cf_name.as_bytes().to_vec())
        );
    }

    Ok(())
}

#[test]
fn sst_compaction_046_full_schema_all_cfs_accept_binary_values_before_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_046")?;
    let db = open_full_db(&temp.child("db"))?;

    for (index, cf_name) in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
        .enumerate()
    {
        let value = deterministic_bytes(32, index.to_le_bytes()[0]);
        put_cf(&db, cf_name, b"binary-key", &value)?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    for (index, cf_name) in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
        .enumerate()
    {
        let value = deterministic_bytes(32, index.to_le_bytes()[0]);

        assert_eq!(get_cf(&db, cf_name, b"binary-key")?, Some(value));
    }

    Ok(())
}

#[test]
fn sst_compaction_047_full_schema_missing_unknown_cf_handle_is_none() -> TestResult {
    let temp = TempTree::new("sst_compaction_047")?;
    let db = open_full_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    assert!(db.cf_handle("unknown_cf").is_none());

    Ok(())
}

#[test]
fn sst_compaction_048_default_only_known_non_default_cf_handles_are_none() -> TestResult {
    let temp = TempTree::new("sst_compaction_048")?;
    let db = open_default_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    assert!(
        db.cf_handle(GlobalConfiguration::META_DATA_COLUMN_NAME)
            .is_none()
    );
    assert!(
        db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .is_none()
    );
    assert!(
        db.cf_handle(GlobalConfiguration::REWARD_BATCH_COLUMN_NAME)
            .is_none()
    );

    Ok(())
}

#[test]
fn sst_compaction_049_default_only_database_lists_default_cf_after_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_049")?;
    let path = temp.child("db");

    {
        let db = open_default_db(&path)?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    let cf_set = list_cf_set(&path)?;

    assert_eq!(
        cf_set,
        ["default".to_owned()].into_iter().collect::<BTreeSet<_>>()
    );

    Ok(())
}

#[test]
fn sst_compaction_050_full_schema_every_expected_cf_handle_exists() -> TestResult {
    let temp = TempTree::new("sst_compaction_050")?;
    let db = open_full_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    for cf_name in expected_cf_names() {
        assert!(
            db.cf_handle(cf_name).is_some(),
            "missing CF handle: {cf_name}"
        );
    }

    Ok(())
}

#[test]
fn sst_compaction_051_vector_expected_cf_list_length_matches_global_total_columns() -> TestResult {
    assert_eq!(
        expected_cf_names().len(),
        GlobalConfiguration::TOTAL_COLUMNS + 1
    );

    Ok(())
}

#[test]
fn sst_compaction_052_vector_expected_cf_list_has_no_duplicates() -> TestResult {
    let names = expected_cf_names();
    let unique = expected_cf_set();

    assert_eq!(names.len(), unique.len());

    Ok(())
}

#[test]
fn sst_compaction_053_vector_expected_cf_list_first_is_default() -> TestResult {
    assert_eq!(expected_cf_names().first().copied(), Some("default"));

    Ok(())
}

#[test]
fn sst_compaction_054_vector_expected_cf_list_last_is_canonical_chain_view() -> TestResult {
    assert_eq!(
        expected_cf_names().last().copied(),
        Some(GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME)
    );

    Ok(())
}

#[test]
fn sst_compaction_055_vector_expected_cf_names_are_non_empty() -> TestResult {
    for cf_name in expected_cf_names() {
        assert!(!cf_name.is_empty());
    }

    Ok(())
}

#[test]
fn sst_compaction_056_vector_expected_cf_names_are_safe_ascii_identifiers() -> TestResult {
    for cf_name in expected_cf_names() {
        assert!(
            cf_name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
            "unsafe CF name: {cf_name}"
        );
    }

    Ok(())
}

#[test]
fn sst_compaction_057_vector_expected_cf_names_have_no_path_separators() -> TestResult {
    for cf_name in expected_cf_names() {
        assert!(!cf_name.contains('/'));
        assert!(!cf_name.contains('\\'));
    }

    Ok(())
}

#[test]
fn sst_compaction_058_vector_expected_cf_set_contains_core_columns() -> TestResult {
    let names = expected_cf_set();

    for required in [
        "default",
        GlobalConfiguration::META_DATA_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        GlobalConfiguration::REWARD_COLUMN_NAME,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
    ] {
        assert!(names.contains(required), "missing required CF: {required}");
    }

    Ok(())
}

#[test]
fn sst_compaction_059_vector_expected_cf_set_excludes_unknown_columns() -> TestResult {
    let names = expected_cf_set();

    for unknown in ["", "unknown", "DEFAULT", "transaction_data "] {
        assert!(
            !names.contains(unknown),
            "unexpected CF in expected set: {unknown}"
        );
    }

    Ok(())
}

#[test]
fn sst_compaction_060_vector_cf_descriptors_match_expected_list() -> TestResult {
    let descriptor_names = CFDescriptors::get_cf_descriptors()
        .into_iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect::<Vec<_>>();

    let expected = expected_cf_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert_eq!(descriptor_names, expected);

    Ok(())
}

#[test]
fn sst_compaction_061_load_many_default_entries_then_compact() -> TestResult {
    let temp = TempTree::new("sst_compaction_061")?;
    let db = open_default_db(&temp.child("db"))?;

    for index in 0..1_000 {
        put_default(
            &db,
            format!("load-key-{index:04}").as_bytes(),
            format!("load-value-{index:04}").as_bytes(),
        )?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(count_default_entries(&db), 1_000);

    Ok(())
}

#[test]
fn sst_compaction_062_load_many_transaction_entries_then_compact() -> TestResult {
    let temp = TempTree::new("sst_compaction_062")?;
    let db = open_full_db(&temp.child("db"))?;

    for index in 0..1_000 {
        put_cf(
            &db,
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            format!("tx-key-{index:04}").as_bytes(),
            format!("tx-value-{index:04}").as_bytes(),
        )?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        count_cf_entries(&db, GlobalConfiguration::TRANSACTION_COLUMN_NAME)?,
        1_000
    );

    Ok(())
}

#[test]
fn sst_compaction_063_load_many_reward_entries_then_compact() -> TestResult {
    let temp = TempTree::new("sst_compaction_063")?;
    let db = open_full_db(&temp.child("db"))?;

    for index in 0..1_000 {
        put_cf(
            &db,
            GlobalConfiguration::REWARD_COLUMN_NAME,
            format!("reward-key-{index:04}").as_bytes(),
            format!("reward-value-{index:04}").as_bytes(),
        )?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        count_cf_entries(&db, GlobalConfiguration::REWARD_COLUMN_NAME)?,
        1_000
    );

    Ok(())
}

#[test]
fn sst_compaction_064_load_many_log_entries_then_compact() -> TestResult {
    let temp = TempTree::new("sst_compaction_064")?;
    let db = open_full_db(&temp.child("db"))?;

    for index in 0..1_000 {
        put_cf(
            &db,
            GlobalConfiguration::LOGS_COLUMN_NAME,
            format!("log-key-{index:04}").as_bytes(),
            format!("log-value-{index:04}").as_bytes(),
        )?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        count_cf_entries(&db, GlobalConfiguration::LOGS_COLUMN_NAME)?,
        1_000
    );

    Ok(())
}

#[test]
fn sst_compaction_065_load_repeated_compaction_with_interleaved_writes() -> TestResult {
    let temp = TempTree::new("sst_compaction_065")?;
    let db = open_default_db(&temp.child("db"))?;

    for round in 0..10 {
        put_default(
            &db,
            format!("round-key-{round}").as_bytes(),
            format!("round-value-{round}").as_bytes(),
        )?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    assert_eq!(count_default_entries(&db), 10);

    Ok(())
}

#[test]
fn sst_compaction_066_load_repeated_full_schema_compaction_with_interleaved_writes() -> TestResult {
    let temp = TempTree::new("sst_compaction_066")?;
    let db = open_full_db(&temp.child("db"))?;

    for round in 0..10 {
        put_cf(
            &db,
            GlobalConfiguration::STATE_COLUMN_NAME,
            format!("round-key-{round}").as_bytes(),
            format!("round-value-{round}").as_bytes(),
        )?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    assert_eq!(
        count_cf_entries(&db, GlobalConfiguration::STATE_COLUMN_NAME)?,
        10
    );

    Ok(())
}

#[test]
fn sst_compaction_067_parallel_isolated_default_dbs_compact_successfully() -> TestResult {
    let temp = TempTree::new("sst_compaction_067")?;
    let mut handles = Vec::new();

    for index in 0..12 {
        let path = temp.child(&format!("db_{index:02}"));

        handles.push(thread::spawn(move || -> Result<Vec<u8>, String> {
            let db = open_default_db(&path)?;
            let key = format!("key-{index:02}");
            let value = format!("value-{index:02}").into_bytes();

            put_default(&db, key.as_bytes(), &value)?;
            force_full_compaction(&db).map_err(debug_err)?;

            get_default(&db, key.as_bytes())?
                .ok_or_else(|| "missing value after compaction".to_owned())
        }));
    }

    for (index, handle) in handles.into_iter().enumerate() {
        let value = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel default compaction worker panicked".to_owned()),
        };

        assert_eq!(value, format!("value-{index:02}").into_bytes());
    }

    Ok(())
}

#[test]
fn sst_compaction_068_parallel_isolated_full_schema_dbs_compact_successfully() -> TestResult {
    let temp = TempTree::new("sst_compaction_068")?;
    let mut handles = Vec::new();

    for index in 0..12 {
        let path = temp.child(&format!("db_{index:02}"));

        handles.push(thread::spawn(move || -> Result<Vec<u8>, String> {
            let db = open_full_db(&path)?;
            let key = format!("key-{index:02}");
            let value = format!("value-{index:02}").into_bytes();

            put_cf(
                &db,
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                key.as_bytes(),
                &value,
            )?;
            force_full_compaction(&db).map_err(debug_err)?;

            get_cf(
                &db,
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                key.as_bytes(),
            )?
            .ok_or_else(|| "missing CF value after compaction".to_owned())
        }));
    }

    for (index, handle) in handles.into_iter().enumerate() {
        let value = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel full schema compaction worker panicked".to_owned()),
        };

        assert_eq!(value, format!("value-{index:02}").into_bytes());
    }

    Ok(())
}

#[test]
fn sst_compaction_069_parallel_isolated_extra_dbs_compact_successfully() -> TestResult {
    let temp = TempTree::new("sst_compaction_069")?;
    let mut handles = Vec::new();

    for index in 0..12 {
        let path = temp.child(&format!("db_{index:02}"));

        handles.push(thread::spawn(move || -> Result<Vec<u8>, String> {
            let db = open_full_plus_extra_db(&path)?;
            let key = format!("key-{index:02}");
            let value = format!("extra-value-{index:02}").into_bytes();

            put_cf(&db, "extra_cf", key.as_bytes(), &value)?;
            force_full_compaction(&db).map_err(debug_err)?;

            get_cf(&db, "extra_cf", key.as_bytes())?
                .ok_or_else(|| "missing extra CF value after compaction".to_owned())
        }));
    }

    for (index, handle) in handles.into_iter().enumerate() {
        let value = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel extra CF compaction worker panicked".to_owned()),
        };

        assert_eq!(value, format!("extra-value-{index:02}").into_bytes());
    }

    Ok(())
}

#[test]
fn sst_compaction_070_parallel_compaction_on_same_db_handle_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_070")?;
    let db = std::sync::Arc::new(open_full_db(&temp.child("db"))?);

    put_cf(
        &db,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        b"key",
        b"value",
    )?;

    let mut handles = Vec::new();

    for _ in 0..8 {
        let db_clone = std::sync::Arc::clone(&db);

        handles.push(thread::spawn(move || -> Result<(), String> {
            force_full_compaction(&db_clone).map_err(debug_err)
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("same DB compaction worker panicked".to_owned()),
        }
    }

    assert_eq!(
        get_cf(&db, GlobalConfiguration::TRANSACTION_COLUMN_NAME, b"key")?,
        Some(b"value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_071_compaction_with_spaces_in_path_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_071")?;
    let db = open_full_db(&temp.child("db with spaces"))?;

    put_default(&db, b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_072_compaction_with_unicode_path_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_072")?;
    let db = open_full_db(&temp.child("db_δ_测试"))?;

    put_default(&db, b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_073_compaction_with_dots_and_dashes_path_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_073")?;
    let db = open_full_db(&temp.child("db.with.dots-and-dashes"))?;

    put_default(&db, b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_074_compaction_with_nested_path_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_074")?;
    let path = temp.child("a").join("b").join("c").join("db");
    let db = open_full_db(&path)?;

    put_default(&db, b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_075_all_cfs_have_distinct_values_after_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_075")?;
    let db = open_full_db(&temp.child("db"))?;

    put_default(&db, b"shared", b"default")?;

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        put_cf(&db, cf_name, b"shared", cf_name.as_bytes())?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"shared")?, Some(b"default".to_vec()));

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        assert_eq!(
            get_cf(&db, cf_name, b"shared")?,
            Some(cf_name.as_bytes().to_vec())
        );
    }

    Ok(())
}

#[test]
fn sst_compaction_076_compaction_preserves_deleted_absence_default() -> TestResult {
    let temp = TempTree::new("sst_compaction_076")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"value")?;
    db.delete(b"key").map_err(debug_err)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, None);

    Ok(())
}

#[test]
fn sst_compaction_077_compaction_preserves_deleted_absence_cf() -> TestResult {
    let temp = TempTree::new("sst_compaction_077")?;
    let db = open_full_db(&temp.child("db"))?;
    let cf_name = GlobalConfiguration::NETWORK_COLUMN_NAME;
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("missing column family: {cf_name}"))?;

    put_cf(&db, cf_name, b"key", b"value")?;
    db.delete_cf(cf, b"key").map_err(debug_err)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_cf(&db, cf_name, b"key")?, None);

    Ok(())
}

#[test]
fn sst_compaction_078_compaction_after_many_overwrites_default_keeps_latest() -> TestResult {
    let temp = TempTree::new("sst_compaction_078")?;
    let db = open_default_db(&temp.child("db"))?;

    for index in 0..100 {
        put_default(&db, b"same-key", format!("value-{index:03}").as_bytes())?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"same-key")?, Some(b"value-099".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_079_compaction_after_many_overwrites_cf_keeps_latest() -> TestResult {
    let temp = TempTree::new("sst_compaction_079")?;
    let db = open_full_db(&temp.child("db"))?;
    let cf_name = GlobalConfiguration::ACCOUNT_COLUMN_NAME;

    for index in 0..100 {
        put_cf(
            &db,
            cf_name,
            b"same-key",
            format!("value-{index:03}").as_bytes(),
        )?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, cf_name, b"same-key")?,
        Some(b"value-099".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_080_compaction_result_can_be_reopened_with_same_schema() -> TestResult {
    let temp = TempTree::new("sst_compaction_080")?;
    let path = temp.child("db");

    {
        let db = open_full_db(&path)?;
        put_cf(
            &db,
            GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
            b"tip",
            b"hash",
        )?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    let reopened = open_full_db(&path)?;

    assert_eq!(
        get_cf(
            &reopened,
            GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
            b"tip"
        )?,
        Some(b"hash".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_081_compaction_keeps_default_entry_count_stable() -> TestResult {
    let temp = TempTree::new("sst_compaction_081")?;
    let db = open_default_db(&temp.child("db"))?;

    for index in 0..25 {
        put_default(
            &db,
            format!("key-{index:02}").as_bytes(),
            format!("value-{index:02}").as_bytes(),
        )?;
    }

    let before = count_default_entries(&db);
    force_full_compaction(&db).map_err(debug_err)?;
    let after = count_default_entries(&db);

    assert_eq!(before, 25);
    assert_eq!(after, before);

    Ok(())
}

#[test]
fn sst_compaction_082_compaction_keeps_cf_entry_count_stable() -> TestResult {
    let temp = TempTree::new("sst_compaction_082")?;
    let db = open_full_db(&temp.child("db"))?;
    let cf_name = GlobalConfiguration::SIDECHAIN_COLUMN_NAME;

    for index in 0..25 {
        put_cf(
            &db,
            cf_name,
            format!("key-{index:02}").as_bytes(),
            format!("value-{index:02}").as_bytes(),
        )?;
    }

    let before = count_cf_entries(&db, cf_name)?;
    force_full_compaction(&db).map_err(debug_err)?;
    let after = count_cf_entries(&db, cf_name)?;

    assert_eq!(before, 25);
    assert_eq!(after, before);

    Ok(())
}

#[test]
fn sst_compaction_083_compaction_on_default_db_ignores_missing_project_cfs() -> TestResult {
    let temp = TempTree::new("sst_compaction_083")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert!(
        db.cf_handle(GlobalConfiguration::META_DATA_COLUMN_NAME)
            .is_none()
    );
    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_084_compaction_on_extra_only_db_ignores_missing_project_cfs() -> TestResult {
    let temp = TempTree::new("sst_compaction_084")?;
    let db = open_extra_only_db(&temp.child("db"))?;

    put_cf(&db, "extra_cf", b"key", b"value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert!(
        db.cf_handle(GlobalConfiguration::META_DATA_COLUMN_NAME)
            .is_none()
    );
    assert_eq!(get_cf(&db, "extra_cf", b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_085_compaction_after_flush_default_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_085")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"value")?;
    db.flush().map_err(debug_err)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_086_compaction_after_flush_cf_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_086")?;
    let db = open_full_db(&temp.child("db"))?;
    let cf_name = GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME;
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("missing column family: {cf_name}"))?;

    put_cf(&db, cf_name, b"key", b"value")?;
    db.flush_cf(cf).map_err(debug_err)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_cf(&db, cf_name, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_087_compaction_after_flush_all_cfs_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_087")?;
    let db = open_full_db(&temp.child("db"))?;

    put_default(&db, b"default-key", b"default-value")?;

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        put_cf(&db, cf_name, b"key", cf_name.as_bytes())?;
        let cf = db
            .cf_handle(cf_name)
            .ok_or_else(|| format!("missing column family: {cf_name}"))?;
        db.flush_cf(cf).map_err(debug_err)?;
    }

    db.flush().map_err(debug_err)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_default(&db, b"default-key")?,
        Some(b"default-value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_088_compaction_with_only_default_data_in_full_schema_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_088")?;
    let db = open_full_db(&temp.child("db"))?;

    put_default(&db, b"only-default-key", b"only-default-value")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_default(&db, b"only-default-key")?,
        Some(b"only-default-value".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_089_compaction_with_only_one_non_default_cf_data_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_089")?;
    let db = open_full_db(&temp.child("db"))?;
    let cf_name = GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME;

    put_cf(&db, cf_name, b"block-hash", b"batch-bytes")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, cf_name, b"block-hash")?,
        Some(b"batch-bytes".to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_090_compaction_with_all_cfs_empty_succeeds() -> TestResult {
    let temp = TempTree::new("sst_compaction_090")?;
    let db = open_full_db(&temp.child("db"))?;

    force_full_compaction(&db).map_err(debug_err)?;

    for cf_name in expected_cf_names() {
        assert!(db.cf_handle(cf_name).is_some());
    }

    Ok(())
}

#[test]
fn sst_compaction_091_compaction_after_delete_and_reinsert_default_keeps_reinserted_value()
-> TestResult {
    let temp = TempTree::new("sst_compaction_091")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"old")?;
    db.delete(b"key").map_err(debug_err)?;
    put_default(&db, b"key", b"new")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"key")?, Some(b"new".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_092_compaction_after_delete_and_reinsert_cf_keeps_reinserted_value() -> TestResult
{
    let temp = TempTree::new("sst_compaction_092")?;
    let db = open_full_db(&temp.child("db"))?;
    let cf_name = GlobalConfiguration::NETWORK_COLUMN_NAME;
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("missing column family: {cf_name}"))?;

    put_cf(&db, cf_name, b"key", b"old")?;
    db.delete_cf(cf, b"key").map_err(debug_err)?;
    put_cf(&db, cf_name, b"key", b"new")?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_cf(&db, cf_name, b"key")?, Some(b"new".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_093_multiple_compactions_after_flush_preserve_value() -> TestResult {
    let temp = TempTree::new("sst_compaction_093")?;
    let db = open_default_db(&temp.child("db"))?;

    put_default(&db, b"key", b"value")?;
    db.flush().map_err(debug_err)?;

    for _ in 0..5 {
        force_full_compaction(&db).map_err(debug_err)?;
    }

    assert_eq!(get_default(&db, b"key")?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn sst_compaction_094_large_binary_keys_survive_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_094")?;
    let db = open_full_db(&temp.child("db"))?;
    let key = deterministic_bytes(4 * 1024, 94);
    let value = b"value";

    put_cf(&db, GlobalConfiguration::LOGS_COLUMN_NAME, &key, value)?;
    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(
        get_cf(&db, GlobalConfiguration::LOGS_COLUMN_NAME, &key)?,
        Some(value.to_vec())
    );

    Ok(())
}

#[test]
fn sst_compaction_095_empty_value_in_every_cf_survives_compaction() -> TestResult {
    let temp = TempTree::new("sst_compaction_095")?;
    let db = open_full_db(&temp.child("db"))?;

    put_default(&db, b"empty", b"")?;

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        put_cf(&db, cf_name, b"empty", b"")?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"empty")?, Some(Vec::new()));

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        assert_eq!(get_cf(&db, cf_name, b"empty")?, Some(Vec::new()));
    }

    Ok(())
}

#[test]
fn sst_compaction_096_same_key_across_all_cfs_does_not_cross_contaminate() -> TestResult {
    let temp = TempTree::new("sst_compaction_096")?;
    let db = open_full_db(&temp.child("db"))?;

    put_default(&db, b"same-key", b"default")?;

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        put_cf(&db, cf_name, b"same-key", cf_name.as_bytes())?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"same-key")?, Some(b"default".to_vec()));

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        assert_eq!(
            get_cf(&db, cf_name, b"same-key")?,
            Some(cf_name.as_bytes().to_vec())
        );
    }

    Ok(())
}

#[test]
fn sst_compaction_097_compaction_preserves_full_schema_after_reopen_list_cf() -> TestResult {
    let temp = TempTree::new("sst_compaction_097")?;
    let path = temp.child("db");

    {
        let db = open_full_db(&path)?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    assert_eq!(list_cf_set(&path)?, expected_cf_set());

    Ok(())
}

#[test]
fn sst_compaction_098_compaction_preserves_default_schema_after_reopen_list_cf() -> TestResult {
    let temp = TempTree::new("sst_compaction_098")?;
    let path = temp.child("db");

    {
        let db = open_default_db(&path)?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    assert_eq!(
        list_cf_set(&path)?,
        ["default".to_owned()].into_iter().collect()
    );

    Ok(())
}

#[test]
fn sst_compaction_099_compaction_on_full_plus_extra_preserves_schema_after_reopen_list_cf()
-> TestResult {
    let temp = TempTree::new("sst_compaction_099")?;
    let path = temp.child("db");

    {
        let db = open_full_plus_extra_db(&path)?;
        force_full_compaction(&db).map_err(debug_err)?;
    }

    let cfs = list_cf_set(&path)?;

    assert!(cfs.contains("extra_cf"));
    assert!(cfs.is_superset(&expected_cf_set()));

    Ok(())
}

#[test]
fn sst_compaction_100_final_vector_full_compaction_preserves_all_known_cf_values() -> TestResult {
    let temp = TempTree::new("sst_compaction_100")?;
    let db = open_full_db(&temp.child("db"))?;

    put_default(&db, b"final-key", b"default")?;

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        put_cf(&db, cf_name, b"final-key", cf_name.as_bytes())?;
    }

    force_full_compaction(&db).map_err(debug_err)?;

    assert_eq!(get_default(&db, b"final-key")?, Some(b"default".to_vec()));

    for cf_name in expected_cf_names()
        .into_iter()
        .filter(|name| *name != "default")
    {
        assert_eq!(
            get_cf(&db, cf_name, b"final-key")?,
            Some(cf_name.as_bytes().to_vec())
        );
    }

    Ok(())
}
