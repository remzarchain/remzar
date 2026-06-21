use remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use remzar::storage::rocksdb_004_config::RockSDBConfig;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use rust_rocksdb::{ColumnFamilyDescriptor, DB, Options};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
            "remzar_rocksdb_004_config_{test_name}_{}_{}",
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

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn expected_full_cf_names() -> Vec<String> {
    CFDescriptors::get_cf_descriptors()
        .into_iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect()
}

fn expected_full_cf_set() -> BTreeSet<String> {
    expected_full_cf_names().into_iter().collect()
}

fn list_cf_set(path: &Path) -> Result<BTreeSet<String>, String> {
    let config = RockSDBConfig::new();

    DB::list_cf(config.get_options(), path)
        .map(|names| names.into_iter().collect::<BTreeSet<_>>())
        .map_err(debug_err)
}

fn create_default_only_db(path: &Path) -> TestResult {
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), path).map_err(debug_err)?;
    drop(db);

    Ok(())
}

fn create_full_schema_db(path: &Path) -> TestResult {
    let config = RockSDBConfig::new();
    let descriptors = CFDescriptors::get_cf_descriptors();
    let db = DB::open_cf_descriptors(config.get_options(), path, descriptors).map_err(debug_err)?;
    drop(db);

    Ok(())
}

fn create_full_schema_with_extra_cf_db(path: &Path) -> TestResult {
    let config = RockSDBConfig::new();
    let mut descriptors = CFDescriptors::get_cf_descriptors();

    descriptors.push(ColumnFamilyDescriptor::new(
        "unexpected_extra_cf",
        Options::default(),
    ));

    let db = DB::open_cf_descriptors(config.get_options(), path, descriptors).map_err(debug_err)?;
    drop(db);

    Ok(())
}

fn database_error_details<T>(result: Result<T, ErrorDetection>) -> Result<String, String> {
    match result {
        Ok(_) => Err("expected database error but got Ok".to_owned()),
        Err(ErrorDetection::DatabaseError { details }) => Ok(details),
        Err(other) => Err(format!("unexpected error variant: {other:?}")),
    }
}

fn configuration_error_message<T>(result: Result<T, ErrorDetection>) -> Result<String, String> {
    match result {
        Ok(_) => Err("expected configuration error but got Ok".to_owned()),
        Err(ErrorDetection::ConfigurationError { message }) => Ok(message),
        Err(other) => Err(format!("unexpected error variant: {other:?}")),
    }
}

fn assert_arc_pair_matches(
    db: &Arc<DB>,
    batch: &remzar::storage::rocksdb_003_batches::RockBatch,
) -> TestResult {
    assert!(Arc::ptr_eq(db, &batch.db));

    Ok(())
}

fn deterministic_config_test_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| {
            let low = index.to_le_bytes()[0];
            seed.wrapping_add(low).rotate_left(1)
        })
        .collect()
}

#[test]
fn rocksdb_config_001_new_returns_reusable_config() -> TestResult {
    let config = RockSDBConfig::new();
    let _options = config.get_options();

    Ok(())
}

#[test]
fn rocksdb_config_002_default_returns_reusable_config() -> TestResult {
    let config = RockSDBConfig::default();
    let _options = config.get_options();

    Ok(())
}

#[test]
fn rocksdb_config_003_new_options_can_create_default_only_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_003")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();

    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    drop(db);

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn rocksdb_config_004_default_options_can_create_default_only_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_004")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::default();

    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    drop(db);

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn rocksdb_config_005_open_db_cli_creates_default_only_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_005")?;
    let path = temp.child("cli_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    assert_arc_pair_matches(&db, &batch)?;
    drop(batch);
    drop(db);

    let cf_set = list_cf_set(&path)?;

    assert_eq!(cf_set, ["default".to_owned()].into_iter().collect());

    Ok(())
}

#[test]
fn rocksdb_config_006_open_db_multi_cf_creates_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_006")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    assert_arc_pair_matches(&db, &batch)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_007_open_db_blockchain_creates_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_007")?;
    let path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;
    assert_arc_pair_matches(&db, &batch)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_008_open_db_accountmodel_creates_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_008")?;
    let path = temp.child("accountmodel_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_accountmodel(&path_string(&path))
        .map_err(debug_err)?;
    assert_arc_pair_matches(&db, &batch)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_009_open_db_registry_creates_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_009")?;
    let path = temp.child("registry_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;
    assert_arc_pair_matches(&db, &batch)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_010_open_db_multi_cf_reopens_existing_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_010")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    {
        let (db, batch) = config
            .open_db_multi_cf(&path_string(&path))
            .map_err(debug_err)?;
        drop(batch);
        drop(db);
    }

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_011_open_db_blockchain_reopens_existing_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_011")?;
    let path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    create_full_schema_db(&path)?;

    let (db, batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_012_open_db_accountmodel_reopens_existing_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_012")?;
    let path = temp.child("accountmodel_db");
    let config = RockSDBConfig::new();

    create_full_schema_db(&path)?;

    let (db, batch) = config
        .open_db_accountmodel(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_013_open_db_registry_reopens_existing_full_schema_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_013")?;
    let path = temp.child("registry_db");
    let config = RockSDBConfig::new();

    create_full_schema_db(&path)?;

    let (db, batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_014_open_db_multi_cf_rejects_existing_default_only_db_as_missing_cfs()
-> TestResult {
    let temp = TempTree::new("rocksdb_config_014")?;
    let path = temp.child("default_only_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let message = configuration_error_message(config.open_db_multi_cf(&path_string(&path)))?;

    assert!(message.contains("Missing column family"));
    assert!(message.contains(&path.display().to_string()));

    Ok(())
}

#[test]
fn rocksdb_config_015_open_db_blockchain_rejects_existing_default_only_db_as_missing_cfs()
-> TestResult {
    let temp = TempTree::new("rocksdb_config_015")?;
    let path = temp.child("default_only_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let message = configuration_error_message(config.open_db_blockchain(&path_string(&path)))?;

    assert!(message.contains("Missing column family"));
    assert!(message.contains(&path.display().to_string()));

    Ok(())
}

#[test]
fn rocksdb_config_016_open_db_registry_rejects_existing_default_only_db_as_missing_cfs()
-> TestResult {
    let temp = TempTree::new("rocksdb_config_016")?;
    let path = temp.child("default_only_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let message = configuration_error_message(config.open_db_registry(&path_string(&path)))?;

    assert!(message.contains("Missing column family"));
    assert!(message.contains(&path.display().to_string()));

    Ok(())
}

#[test]
fn rocksdb_config_017_open_db_multi_cf_rejects_unexpected_extra_column_family() -> TestResult {
    let temp = TempTree::new("rocksdb_config_017")?;
    let path = temp.child("extra_cf_db");
    let config = RockSDBConfig::new();

    create_full_schema_with_extra_cf_db(&path)?;

    let message = configuration_error_message(config.open_db_multi_cf(&path_string(&path)))?;

    assert!(message.contains("Unexpected column family"));
    assert!(message.contains("unexpected_extra_cf"));
    assert!(message.contains(&path.display().to_string()));

    Ok(())
}

#[test]
fn rocksdb_config_018_open_db_blockchain_rejects_unexpected_extra_column_family() -> TestResult {
    let temp = TempTree::new("rocksdb_config_018")?;
    let path = temp.child("extra_cf_db");
    let config = RockSDBConfig::new();

    create_full_schema_with_extra_cf_db(&path)?;

    let message = configuration_error_message(config.open_db_blockchain(&path_string(&path)))?;

    assert!(message.contains("Unexpected column family"));
    assert!(message.contains("unexpected_extra_cf"));

    Ok(())
}

#[test]
fn rocksdb_config_019_open_db_cli_error_mentions_path_when_parent_is_file() -> TestResult {
    let temp = TempTree::new("rocksdb_config_019")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let path = file_base.join("cli_db");
    let config = RockSDBConfig::new();
    let details = database_error_details(config.open_db_cli(&path_string(&path)))?;

    assert!(details.contains("RockSDBConfig CLI open failed"));
    assert!(details.contains(&path.display().to_string()));

    Ok(())
}

#[test]
fn rocksdb_config_020_open_db_multi_cf_error_mentions_path_when_parent_is_file() -> TestResult {
    let temp = TempTree::new("rocksdb_config_020")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let path = file_base.join("multi_cf_db");
    let config = RockSDBConfig::new();
    let details = database_error_details(config.open_db_multi_cf(&path_string(&path)))?;

    assert!(details.contains("RockSDBConfig multi-CF open failed"));
    assert!(details.contains(&path.display().to_string()));

    Ok(())
}

#[test]
fn rocksdb_config_021_open_db_cli_returned_batch_rejects_transaction_cf_operation() -> TestResult {
    let temp = TempTree::new("rocksdb_config_021")?;
    let path = temp.child("cli_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;

    let err = batch
        .store_temp_transaction(b"tx", b"value")
        .expect_err("CLI DB should not contain transaction_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(GlobalConfiguration::TRANSACTION_COLUMN_NAME));

    Ok(())
}

#[test]
fn rocksdb_config_022_open_db_multi_cf_returned_batch_can_store_temp_transaction() -> TestResult {
    let temp = TempTree::new("rocksdb_config_022")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_temp_transaction(b"tx-key", b"tx-value")?;

    let listed = batch.list_temp_transactions()?;
    let value = listed
        .iter()
        .find(|(key, _value)| key.as_slice() == b"tx-key")
        .map(|(_key, value)| value.as_slice());

    assert_eq!(value, Some(b"tx-value".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_023_open_db_blockchain_returned_batch_can_store_transaction_batch() -> TestResult
{
    let temp = TempTree::new("rocksdb_config_023")?;
    let path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_transaction_batch(23, b"batch-value")?;

    let listed = batch.list_unprocessed_batches()?;
    let value = listed
        .iter()
        .find(|(index, _value)| *index == 23)
        .map(|(_index, value)| value.as_slice());

    assert_eq!(value, Some(b"batch-value".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_024_open_db_registry_returned_batch_can_store_reward_batch() -> TestResult {
    let temp = TempTree::new("rocksdb_config_024")?;
    let path = temp.child("registry_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_reward_batch(24, b"reward-batch")?;

    let listed = batch.list_reward_batches()?;
    let value = listed
        .iter()
        .find(|(index, _value)| *index == 24)
        .map(|(_index, value)| value.as_slice());

    assert_eq!(value, Some(b"reward-batch".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_025_open_db_accountmodel_returned_batch_can_store_signature() -> TestResult {
    let temp = TempTree::new("rocksdb_config_025")?;
    let path = temp.child("accountmodel_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_accountmodel(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_batch_signature(b"signature-key", b"signature-value")?;

    assert_eq!(
        batch.load_batch_signature(b"signature-key")?,
        b"signature-value"
    );

    Ok(())
}

#[test]
fn rocksdb_config_026_get_write_options_all_boolean_combinations_construct() -> TestResult {
    let _a = RockSDBConfig::get_write_options(false, false);
    let _b = RockSDBConfig::get_write_options(true, false);
    let _c = RockSDBConfig::get_write_options(false, true);
    let _d = RockSDBConfig::get_write_options(true, true);

    Ok(())
}

#[test]
fn rocksdb_config_027_get_read_options_all_boolean_combinations_construct() -> TestResult {
    let _a = RockSDBConfig::get_read_options(false, false);
    let _b = RockSDBConfig::get_read_options(true, false);
    let _c = RockSDBConfig::get_read_options(false, true);
    let _d = RockSDBConfig::get_read_options(true, true);

    Ok(())
}

#[test]
fn rocksdb_config_028_write_options_can_be_used_for_default_db_put() -> TestResult {
    let temp = TempTree::new("rocksdb_config_028")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();

    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let write_options = RockSDBConfig::get_write_options(false, false);

    db.put_opt(b"key", b"value", &write_options)
        .map_err(debug_err)?;

    assert_eq!(db.get(b"key").map_err(debug_err)?, Some(b"value".to_vec()));

    Ok(())
}

#[test]
fn rocksdb_config_029_force_sync_write_options_reject_without_wal() -> TestResult {
    let temp = TempTree::new("rocksdb_config_029")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();

    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let write_options = RockSDBConfig::get_write_options(false, true);

    let err = db
        .put_opt(b"sync-key", b"sync-value", &write_options)
        .expect_err("sync write with WAL disabled must fail");

    let err_text = debug_err(err);

    assert!(err_text.contains("Sync writes has to enable WAL"));

    Ok(())
}

#[test]
fn rocksdb_config_030_batch_mode_write_options_reject_without_wal() -> TestResult {
    let temp = TempTree::new("rocksdb_config_030")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();

    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let write_options = RockSDBConfig::get_write_options(true, false);

    let err = db
        .put_opt(b"batch-key", b"batch-value", &write_options)
        .expect_err("batch-mode sync write with WAL disabled must fail");

    let err_text = debug_err(err);

    assert!(err_text.contains("Sync writes has to enable WAL"));

    Ok(())
}

#[test]
fn rocksdb_config_031_read_options_can_be_used_for_default_db_get() -> TestResult {
    let temp = TempTree::new("rocksdb_config_031")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();

    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    db.put(b"read-key", b"read-value").map_err(debug_err)?;

    let read_options = RockSDBConfig::get_read_options(true, false);
    let loaded = db.get_opt(b"read-key", &read_options).map_err(debug_err)?;

    assert_eq!(loaded, Some(b"read-value".to_vec()));

    Ok(())
}

#[test]
fn rocksdb_config_032_read_options_with_prefetch_can_be_used_for_default_db_get() -> TestResult {
    let temp = TempTree::new("rocksdb_config_032")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();

    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    db.put(b"prefetch-key", b"prefetch-value")
        .map_err(debug_err)?;

    let read_options = RockSDBConfig::get_read_options(true, true);
    let loaded = db
        .get_opt(b"prefetch-key", &read_options)
        .map_err(debug_err)?;

    assert_eq!(loaded, Some(b"prefetch-value".to_vec()));

    Ok(())
}

#[test]
fn rocksdb_config_033_open_db_multi_cf_with_spaces_in_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_033")?;
    let path = temp.child("node with spaces").join("multi cf db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_034_open_db_multi_cf_with_dots_and_dashes_in_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_034")?;
    let path = temp.child("node.with.dots-and-dashes").join("multi-cf.db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_035_open_db_cli_with_spaces_in_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_035")?;
    let path = temp.child("node with spaces").join("cli db");
    let config = RockSDBConfig::new();

    let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn rocksdb_config_036_load_repeated_multi_cf_creation_uses_full_schema() -> TestResult {
    let temp = TempTree::new("rocksdb_config_036")?;
    let config = RockSDBConfig::new();

    for index in 0..24 {
        let path = temp.child(&format!("multi_cf_node_{index:02}"));
        let (db, batch) = config
            .open_db_multi_cf(&path_string(&path))
            .map_err(debug_err)?;
        drop(batch);
        drop(db);

        assert_eq!(list_cf_set(&path)?, expected_full_cf_set());
    }

    Ok(())
}

#[test]
fn rocksdb_config_037_load_repeated_cli_creation_uses_default_schema() -> TestResult {
    let temp = TempTree::new("rocksdb_config_037")?;
    let config = RockSDBConfig::new();

    for index in 0..24 {
        let path = temp.child(&format!("cli_node_{index:02}"));
        let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
        drop(batch);
        drop(db);

        assert_eq!(
            list_cf_set(&path)?,
            ["default".to_owned()].into_iter().collect()
        );
    }

    Ok(())
}

#[test]
fn rocksdb_config_038_parallel_isolated_multi_cf_opens_create_full_schemas() -> TestResult {
    let temp = TempTree::new("rocksdb_config_038")?;
    let mut handles = Vec::new();

    for index in 0..12 {
        let path = temp.child(&format!("parallel_multi_cf_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<BTreeSet<String>, String> {
                let config = RockSDBConfig::new();
                let (db, batch) = config
                    .open_db_multi_cf(&path_string(&path))
                    .map_err(debug_err)?;
                drop(batch);
                drop(db);

                list_cf_set(&path)
            },
        ));
    }

    let expected = expected_full_cf_set();

    for handle in handles {
        let actual = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel multi-CF open worker panicked".to_owned()),
        };

        assert_eq!(actual, expected);
    }

    Ok(())
}

#[test]
fn rocksdb_config_039_parallel_isolated_cli_opens_create_default_schemas() -> TestResult {
    let temp = TempTree::new("rocksdb_config_039")?;
    let mut handles = Vec::new();

    for index in 0..12 {
        let path = temp.child(&format!("parallel_cli_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<BTreeSet<String>, String> {
                let config = RockSDBConfig::new();
                let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
                drop(batch);
                drop(db);

                list_cf_set(&path)
            },
        ));
    }

    let expected = ["default".to_owned()].into_iter().collect::<BTreeSet<_>>();

    for handle in handles {
        let actual = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel CLI open worker panicked".to_owned()),
        };

        assert_eq!(actual, expected);
    }

    Ok(())
}

#[test]
fn rocksdb_config_040_vector_full_schema_count_matches_global_total_columns_plus_default()
-> TestResult {
    let expected_names = expected_full_cf_names();

    assert_eq!(expected_names.len(), GlobalConfiguration::TOTAL_COLUMNS + 1);
    assert!(expected_names.contains(&"default".to_owned()));
    assert!(expected_names.contains(&GlobalConfiguration::META_DATA_COLUMN_NAME.to_owned()));
    assert!(expected_names.contains(&GlobalConfiguration::TRANSACTION_COLUMN_NAME.to_owned()));
    assert!(expected_names.contains(&GlobalConfiguration::REWARD_BATCH_COLUMN_NAME.to_owned()));
    assert!(
        expected_names.contains(&GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME.to_owned())
    );

    Ok(())
}

#[test]
fn rocksdb_config_041_expected_full_cf_names_are_unique() -> TestResult {
    let names = expected_full_cf_names();
    let unique = names.iter().cloned().collect::<BTreeSet<_>>();

    assert_eq!(names.len(), unique.len());

    Ok(())
}

#[test]
fn rocksdb_config_042_expected_full_cf_names_are_non_empty() -> TestResult {
    for name in expected_full_cf_names() {
        assert!(!name.is_empty());
    }

    Ok(())
}

#[test]
fn rocksdb_config_043_expected_full_cf_names_are_safe_ascii_identifiers() -> TestResult {
    for name in expected_full_cf_names() {
        assert!(
            name.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
            "unsafe CF name: {name}"
        );
    }

    Ok(())
}

#[test]
fn rocksdb_config_044_expected_full_cf_order_matches_cf_descriptors() -> TestResult {
    let descriptor_names = CFDescriptors::get_cf_descriptors()
        .into_iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect::<Vec<_>>();

    assert_eq!(expected_full_cf_names(), descriptor_names);

    Ok(())
}

#[test]
fn rocksdb_config_045_open_db_cli_reopens_existing_default_only_db() -> TestResult {
    let temp = TempTree::new("rocksdb_config_045")?;
    let path = temp.child("cli_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    assert_arc_pair_matches(&db, &batch)?;
    drop(batch);
    drop(db);

    assert_eq!(
        list_cf_set(&path)?,
        ["default".to_owned()].into_iter().collect()
    );

    Ok(())
}

#[test]
fn rocksdb_config_046_open_db_cli_twice_sequentially_keeps_default_schema() -> TestResult {
    let temp = TempTree::new("rocksdb_config_046")?;
    let path = temp.child("cli_db");
    let config = RockSDBConfig::new();

    let (first_db, first_batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    drop(first_batch);
    drop(first_db);

    let (second_db, second_batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    drop(second_batch);
    drop(second_db);

    assert_eq!(
        list_cf_set(&path)?,
        ["default".to_owned()].into_iter().collect()
    );

    Ok(())
}

#[test]
fn rocksdb_config_047_open_db_multi_cf_twice_sequentially_keeps_full_schema() -> TestResult {
    let temp = TempTree::new("rocksdb_config_047")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    let (first_db, first_batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(first_batch);
    drop(first_db);

    let (second_db, second_batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(second_batch);
    drop(second_db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_048_blockchain_wrapper_and_multi_cf_wrapper_create_same_schema() -> TestResult {
    let temp = TempTree::new("rocksdb_config_048")?;
    let multi_path = temp.child("multi_cf_db");
    let blockchain_path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    let (multi_db, multi_batch) = config
        .open_db_multi_cf(&path_string(&multi_path))
        .map_err(debug_err)?;
    drop(multi_batch);
    drop(multi_db);

    let (blockchain_db, blockchain_batch) = config
        .open_db_blockchain(&path_string(&blockchain_path))
        .map_err(debug_err)?;
    drop(blockchain_batch);
    drop(blockchain_db);

    assert_eq!(list_cf_set(&multi_path)?, list_cf_set(&blockchain_path)?);

    Ok(())
}

#[test]
fn rocksdb_config_049_accountmodel_wrapper_and_blockchain_wrapper_create_same_schema() -> TestResult
{
    let temp = TempTree::new("rocksdb_config_049")?;
    let accountmodel_path = temp.child("accountmodel_db");
    let blockchain_path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    let (accountmodel_db, accountmodel_batch) = config
        .open_db_accountmodel(&path_string(&accountmodel_path))
        .map_err(debug_err)?;
    drop(accountmodel_batch);
    drop(accountmodel_db);

    let (blockchain_db, blockchain_batch) = config
        .open_db_blockchain(&path_string(&blockchain_path))
        .map_err(debug_err)?;
    drop(blockchain_batch);
    drop(blockchain_db);

    assert_eq!(
        list_cf_set(&accountmodel_path)?,
        list_cf_set(&blockchain_path)?
    );

    Ok(())
}

#[test]
fn rocksdb_config_050_registry_wrapper_and_multi_cf_wrapper_create_same_schema() -> TestResult {
    let temp = TempTree::new("rocksdb_config_050")?;
    let registry_path = temp.child("registry_db");
    let multi_path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    let (registry_db, registry_batch) = config
        .open_db_registry(&path_string(&registry_path))
        .map_err(debug_err)?;
    drop(registry_batch);
    drop(registry_db);

    let (multi_db, multi_batch) = config
        .open_db_multi_cf(&path_string(&multi_path))
        .map_err(debug_err)?;
    drop(multi_batch);
    drop(multi_db);

    assert_eq!(list_cf_set(&registry_path)?, list_cf_set(&multi_path)?);

    Ok(())
}

#[test]
fn rocksdb_config_051_open_db_blockchain_returned_batch_can_store_log_entry() -> TestResult {
    let temp = TempTree::new("rocksdb_config_051")?;
    let path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_log_entry(b"log-key", b"log-value")?;

    let logs = batch.list_log_entries()?;
    let value = logs
        .iter()
        .find(|(key, _value)| key.as_slice() == b"log-key")
        .map(|(_key, value)| value.as_slice());

    assert_eq!(value, Some(b"log-value".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_052_open_db_registry_returned_batch_can_store_transaction() -> TestResult {
    let temp = TempTree::new("rocksdb_config_052")?;
    let path = temp.child("registry_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_transaction(b"tx-id", b"tx-bytes")?;

    let transactions = batch.list_temp_transactions()?;
    let value = transactions
        .iter()
        .find(|(key, _value)| key.as_slice() == b"tx-id")
        .map(|(_key, value)| value.as_slice());

    assert_eq!(value, Some(b"tx-bytes".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_053_open_db_accountmodel_returned_batch_can_execute_records() -> TestResult {
    let temp = TempTree::new("rocksdb_config_053")?;
    let path = temp.child("accountmodel_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_accountmodel(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_temp_transaction(b"exec-key", b"exec-value")?;
    batch.batch_execute_records()?;

    let meta = batch.load_batch_signature(b"exec-key")?;
    let text = String::from_utf8(meta).map_err(debug_err)?;

    assert!(text.contains("Applied record"));

    Ok(())
}

#[test]
fn rocksdb_config_054_cli_returned_batch_can_be_shared_until_arc_dropped() -> TestResult {
    let temp = TempTree::new("rocksdb_config_054")?;
    let path = temp.child("cli_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    let cloned = Arc::clone(&db);

    assert!(Arc::ptr_eq(&db, &batch.db));
    assert_eq!(Arc::strong_count(&db), 3);

    drop(cloned);
    assert_eq!(Arc::strong_count(&db), 2);

    Ok(())
}

#[test]
fn rocksdb_config_055_multi_cf_returned_batch_can_be_shared_until_arc_dropped() -> TestResult {
    let temp = TempTree::new("rocksdb_config_055")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    let cloned = Arc::clone(&db);

    assert!(Arc::ptr_eq(&db, &batch.db));
    assert_eq!(Arc::strong_count(&db), 3);

    drop(cloned);
    assert_eq!(Arc::strong_count(&db), 2);

    Ok(())
}

#[test]
fn rocksdb_config_056_multi_cf_rejects_plain_file_existing_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_056")?;
    let path = temp.child("plain_file");

    fs::write(&path, b"not a RocksDB directory").map_err(debug_err)?;

    let config = RockSDBConfig::new();
    let details = database_error_details(config.open_db_multi_cf(&path_string(&path)))?;

    assert!(details.contains(&path.display().to_string()) || !details.is_empty());

    Ok(())
}

#[test]
fn rocksdb_config_057_cli_rejects_plain_file_existing_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_057")?;
    let path = temp.child("plain_file");

    fs::write(&path, b"not a RocksDB directory").map_err(debug_err)?;

    let config = RockSDBConfig::new();
    let details = database_error_details(config.open_db_cli(&path_string(&path)))?;

    assert!(details.contains("RockSDBConfig CLI open failed"));
    assert!(details.contains(&path.display().to_string()));

    Ok(())
}

#[test]
fn rocksdb_config_058_multi_cf_rejects_existing_db_missing_first_non_default_cf() -> TestResult {
    let temp = TempTree::new("rocksdb_config_058")?;
    let path = temp.child("default_only_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let message = configuration_error_message(config.open_db_multi_cf(&path_string(&path)))?;

    assert!(message.contains("Missing column family"));
    assert!(message.contains(GlobalConfiguration::META_DATA_COLUMN_NAME));

    Ok(())
}

#[test]
fn rocksdb_config_059_registry_rejects_existing_db_missing_first_non_default_cf() -> TestResult {
    let temp = TempTree::new("rocksdb_config_059")?;
    let path = temp.child("default_only_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let message = configuration_error_message(config.open_db_registry(&path_string(&path)))?;

    assert!(message.contains("Missing column family"));
    assert!(message.contains(GlobalConfiguration::META_DATA_COLUMN_NAME));

    Ok(())
}

#[test]
fn rocksdb_config_060_blockchain_rejects_existing_db_missing_first_non_default_cf() -> TestResult {
    let temp = TempTree::new("rocksdb_config_060")?;
    let path = temp.child("default_only_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let message = configuration_error_message(config.open_db_blockchain(&path_string(&path)))?;

    assert!(message.contains("Missing column family"));
    assert!(message.contains(GlobalConfiguration::META_DATA_COLUMN_NAME));

    Ok(())
}

#[test]
fn rocksdb_config_061_open_db_multi_cf_persists_transaction_after_reopen() -> TestResult {
    let temp = TempTree::new("rocksdb_config_061")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    {
        let (_db, batch) = config
            .open_db_multi_cf(&path_string(&path))
            .map_err(debug_err)?;
        batch.store_temp_transaction(b"persist-key", b"persist-value")?;
    }

    let (_db, reopened_batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    let listed = reopened_batch.list_temp_transactions()?;

    let value = listed
        .iter()
        .find(|(key, _value)| key.as_slice() == b"persist-key")
        .map(|(_key, value)| value.as_slice());

    assert_eq!(value, Some(b"persist-value".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_062_open_db_blockchain_persists_batch_after_reopen() -> TestResult {
    let temp = TempTree::new("rocksdb_config_062")?;
    let path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    {
        let (_db, batch) = config
            .open_db_blockchain(&path_string(&path))
            .map_err(debug_err)?;
        batch.store_transaction_batch(62, b"persisted-batch")?;
    }

    let (_db, reopened_batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;
    let listed = reopened_batch.list_unprocessed_batches()?;

    let value = listed
        .iter()
        .find(|(index, _value)| *index == 62)
        .map(|(_index, value)| value.as_slice());

    assert_eq!(value, Some(b"persisted-batch".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_063_open_db_registry_persists_reward_batch_after_reopen() -> TestResult {
    let temp = TempTree::new("rocksdb_config_063")?;
    let path = temp.child("registry_db");
    let config = RockSDBConfig::new();

    {
        let (_db, batch) = config
            .open_db_registry(&path_string(&path))
            .map_err(debug_err)?;
        batch.store_reward_batch(63, b"persisted-reward")?;
    }

    let (_db, reopened_batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;
    let listed = reopened_batch.list_reward_batches()?;

    let value = listed
        .iter()
        .find(|(index, _value)| *index == 63)
        .map(|(_index, value)| value.as_slice());

    assert_eq!(value, Some(b"persisted-reward".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_064_open_db_accountmodel_persists_signature_after_reopen() -> TestResult {
    let temp = TempTree::new("rocksdb_config_064")?;
    let path = temp.child("accountmodel_db");
    let config = RockSDBConfig::new();

    {
        let (_db, batch) = config
            .open_db_accountmodel(&path_string(&path))
            .map_err(debug_err)?;
        batch.store_batch_signature(b"persist-signature", b"signature-value")?;
    }

    let (_db, reopened_batch) = config
        .open_db_accountmodel(&path_string(&path))
        .map_err(debug_err)?;

    assert_eq!(
        reopened_batch.load_batch_signature(b"persist-signature")?,
        b"signature-value"
    );

    Ok(())
}

#[test]
fn rocksdb_config_065_write_options_modes_match_wal_sync_constraints() -> TestResult {
    let temp = TempTree::new("rocksdb_config_065")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;

    let valid_options = RockSDBConfig::get_write_options(false, false);
    db.put_opt(b"key-ff", b"value-ff", &valid_options)
        .map_err(debug_err)?;

    assert_eq!(
        db.get(b"key-ff").map_err(debug_err)?,
        Some(b"value-ff".to_vec())
    );

    let invalid_cases = [
        (true, false, b"key-tf".as_slice(), b"value-tf".as_slice()),
        (false, true, b"key-ft".as_slice(), b"value-ft".as_slice()),
        (true, true, b"key-tt".as_slice(), b"value-tt".as_slice()),
    ];

    for (batch_mode, force_sync, key, value) in invalid_cases {
        let options = RockSDBConfig::get_write_options(batch_mode, force_sync);
        let err = db
            .put_opt(key, value, &options)
            .expect_err("sync write with WAL disabled must fail");

        let err_text = debug_err(err);

        assert!(err_text.contains("Sync writes has to enable WAL"));
    }

    Ok(())
}

#[test]
fn rocksdb_config_066_read_options_all_modes_can_read_distinct_keys() -> TestResult {
    let temp = TempTree::new("rocksdb_config_066")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;

    let cases = [
        (false, false, b"key-ff".as_slice(), b"value-ff".as_slice()),
        (true, false, b"key-tf".as_slice(), b"value-tf".as_slice()),
        (false, true, b"key-ft".as_slice(), b"value-ft".as_slice()),
        (true, true, b"key-tt".as_slice(), b"value-tt".as_slice()),
    ];

    for (verify_checksums, enable_prefetching, key, value) in cases {
        db.put(key, value).map_err(debug_err)?;
        let options = RockSDBConfig::get_read_options(verify_checksums, enable_prefetching);
        assert_eq!(
            db.get_opt(key, &options).map_err(debug_err)?,
            Some(value.to_vec())
        );
    }

    Ok(())
}

#[test]
fn rocksdb_config_067_read_options_return_none_for_missing_key() -> TestResult {
    let temp = TempTree::new("rocksdb_config_067")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;

    let options = RockSDBConfig::get_read_options(true, true);

    assert_eq!(
        db.get_opt(b"missing-key", &options).map_err(debug_err)?,
        None
    );

    Ok(())
}

#[test]
fn rocksdb_config_068_write_options_support_empty_key_and_value_without_sync() -> TestResult {
    let temp = TempTree::new("rocksdb_config_068")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let options = RockSDBConfig::get_write_options(false, false);

    db.put_opt(b"", b"", &options).map_err(debug_err)?;

    assert_eq!(db.get(b"").map_err(debug_err)?, Some(Vec::new()));

    Ok(())
}

#[test]
fn rocksdb_config_069_write_and_read_options_support_large_value_without_sync() -> TestResult {
    let temp = TempTree::new("rocksdb_config_069")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let value = deterministic_config_test_bytes(64 * 1024, 69);

    let write_options = RockSDBConfig::get_write_options(false, false);
    db.put_opt(b"large-key", &value, &write_options)
        .map_err(debug_err)?;

    let read_options = RockSDBConfig::get_read_options(true, true);
    assert_eq!(
        db.get_opt(b"large-key", &read_options).map_err(debug_err)?,
        Some(value)
    );

    Ok(())
}

#[test]
fn rocksdb_config_070_open_db_cli_with_nested_missing_parent_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_070")?;
    let path = temp.child("a").join("b").join("c").join("cli_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn rocksdb_config_071_open_db_multi_cf_with_nested_missing_parent_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_071")?;
    let path = temp.child("a").join("b").join("c").join("multi_cf_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_072_open_db_blockchain_with_unicode_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_072")?;
    let path = temp.child("node_δ_测试").join("blockchain_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_073_open_db_cli_with_unicode_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_073")?;
    let path = temp.child("node_δ_测试").join("cli_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(
        list_cf_set(&path)?,
        ["default".to_owned()].into_iter().collect()
    );

    Ok(())
}

#[test]
fn rocksdb_config_074_expected_full_cf_set_contains_all_core_storage_families() -> TestResult {
    let names = expected_full_cf_set();

    for required in [
        GlobalConfiguration::META_DATA_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        GlobalConfiguration::REWARD_COLUMN_NAME,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        GlobalConfiguration::LOGS_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
    ] {
        assert!(names.contains(required), "missing required CF: {required}");
    }

    Ok(())
}

#[test]
fn rocksdb_config_075_expected_full_cf_set_does_not_contain_unknown_names() -> TestResult {
    let names = expected_full_cf_set();

    for unknown in ["", "unknown_cf", "DEFAULT", "transaction_data "] {
        assert!(
            !names.contains(unknown),
            "unexpected unknown CF present: {unknown}"
        );
    }

    Ok(())
}

#[test]
fn rocksdb_config_076_load_repeated_wrapper_opens_use_full_schema() -> TestResult {
    let temp = TempTree::new("rocksdb_config_076")?;
    let config = RockSDBConfig::new();

    for index in 0..12 {
        let blockchain_path = temp.child(&format!("blockchain_{index:02}"));
        let accountmodel_path = temp.child(&format!("accountmodel_{index:02}"));
        let registry_path = temp.child(&format!("registry_{index:02}"));

        let (blockchain_db, blockchain_batch) = config
            .open_db_blockchain(&path_string(&blockchain_path))
            .map_err(debug_err)?;
        drop(blockchain_batch);
        drop(blockchain_db);

        let (accountmodel_db, accountmodel_batch) = config
            .open_db_accountmodel(&path_string(&accountmodel_path))
            .map_err(debug_err)?;
        drop(accountmodel_batch);
        drop(accountmodel_db);

        let (registry_db, registry_batch) = config
            .open_db_registry(&path_string(&registry_path))
            .map_err(debug_err)?;
        drop(registry_batch);
        drop(registry_db);

        assert_eq!(list_cf_set(&blockchain_path)?, expected_full_cf_set());
        assert_eq!(list_cf_set(&accountmodel_path)?, expected_full_cf_set());
        assert_eq!(list_cf_set(&registry_path)?, expected_full_cf_set());
    }

    Ok(())
}

#[test]
fn rocksdb_config_077_load_repeated_config_construction_can_open_default_dbs() -> TestResult {
    let temp = TempTree::new("rocksdb_config_077")?;

    for index in 0..24 {
        let path = temp.child(&format!("default_db_{index:02}"));
        let config = RockSDBConfig::new();
        let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
        drop(db);

        assert!(path.is_dir());
    }

    Ok(())
}

#[test]
fn rocksdb_config_078_parallel_isolated_registry_opens_create_full_schemas() -> TestResult {
    let temp = TempTree::new("rocksdb_config_078")?;
    let mut handles = Vec::new();

    for index in 0..12 {
        let path = temp.child(&format!("parallel_registry_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<BTreeSet<String>, String> {
                let config = RockSDBConfig::new();
                let (db, batch) = config
                    .open_db_registry(&path_string(&path))
                    .map_err(debug_err)?;
                drop(batch);
                drop(db);

                list_cf_set(&path)
            },
        ));
    }

    let expected = expected_full_cf_set();

    for handle in handles {
        let actual = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel registry open worker panicked".to_owned()),
        };

        assert_eq!(actual, expected);
    }

    Ok(())
}

#[test]
fn rocksdb_config_079_parallel_isolated_blockchain_batches_can_write_data() -> TestResult {
    let temp = TempTree::new("rocksdb_config_079")?;
    let mut handles = Vec::new();

    for index in 0..12_u64 {
        let path = temp.child(&format!("parallel_blockchain_write_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<Vec<(u64, Vec<u8>)>, String> {
                let config = RockSDBConfig::new();
                let (_db, batch) = config
                    .open_db_blockchain(&path_string(&path))
                    .map_err(debug_err)?;
                let value = format!("batch-value-{index:02}").into_bytes();

                batch.store_transaction_batch(index, &value)?;

                batch.list_unprocessed_batches()
            },
        ));
    }

    for (index, handle) in handles.into_iter().enumerate() {
        let listed = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel blockchain write worker panicked".to_owned()),
        };

        let value = listed
            .iter()
            .find(|(batch_index, _value)| *batch_index == index as u64)
            .map(|(_batch_index, value)| value.as_slice());

        assert_eq!(value, Some(format!("batch-value-{index:02}").as_bytes()));
    }

    Ok(())
}

#[test]
fn rocksdb_config_080_parallel_isolated_cli_batches_reject_cf_operations() -> TestResult {
    let temp = TempTree::new("rocksdb_config_080")?;
    let mut handles = Vec::new();

    for index in 0..12 {
        let path = temp.child(&format!("parallel_cli_reject_{index:02}"));

        handles.push(thread::spawn(move || -> Result<String, String> {
            let config = RockSDBConfig::new();
            let (_db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;

            batch
                .store_transaction_batch(1, b"value")
                .expect_err("CLI default-only DB must reject transaction_batch_data CF")
                .pipe(Ok)
        }));
    }

    for handle in handles {
        let err = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel CLI reject worker panicked".to_owned()),
        };

        assert!(err.contains("Column Family"));
        assert!(err.contains(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME));
    }

    Ok(())
}

#[test]
fn rocksdb_config_081_vector_full_cf_names_match_expected_first_and_last_entries() -> TestResult {
    let names = expected_full_cf_names();

    assert_eq!(names.first().map(String::as_str), Some("default"));
    assert_eq!(
        names.last().map(String::as_str),
        Some(GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME)
    );

    Ok(())
}

#[test]
fn rocksdb_config_082_vector_full_cf_names_have_no_whitespace() -> TestResult {
    for name in expected_full_cf_names() {
        assert!(
            !name.chars().any(char::is_whitespace),
            "column family name contains whitespace: {name:?}"
        );
    }

    Ok(())
}

#[test]
fn rocksdb_config_083_vector_full_cf_names_have_no_path_separators() -> TestResult {
    for name in expected_full_cf_names() {
        assert!(
            !name.contains('/'),
            "column family name contains slash: {name}"
        );
        assert!(
            !name.contains('\\'),
            "column family name contains backslash: {name}"
        );
    }

    Ok(())
}

#[test]
fn rocksdb_config_084_edge_open_multi_cf_after_direct_full_schema_creation() -> TestResult {
    let temp = TempTree::new("rocksdb_config_084")?;
    let path = temp.child("direct_full_schema_db");
    let config = RockSDBConfig::new();

    create_full_schema_db(&path)?;

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_085_edge_open_blockchain_after_multi_cf_created_same_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_085")?;
    let path = temp.child("shared_full_schema_db");
    let config = RockSDBConfig::new();

    let (multi_db, multi_batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(multi_batch);
    drop(multi_db);

    let (blockchain_db, blockchain_batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;
    drop(blockchain_batch);
    drop(blockchain_db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_086_edge_open_registry_after_blockchain_created_same_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_086")?;
    let path = temp.child("shared_registry_blockchain_db");
    let config = RockSDBConfig::new();

    let (blockchain_db, blockchain_batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;
    drop(blockchain_batch);
    drop(blockchain_db);

    let (registry_db, registry_batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;
    drop(registry_batch);
    drop(registry_db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_087_edge_open_accountmodel_after_registry_created_same_path() -> TestResult {
    let temp = TempTree::new("rocksdb_config_087")?;
    let path = temp.child("shared_accountmodel_registry_db");
    let config = RockSDBConfig::new();

    let (registry_db, registry_batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;
    drop(registry_batch);
    drop(registry_db);

    let (accountmodel_db, accountmodel_batch) = config
        .open_db_accountmodel(&path_string(&path))
        .map_err(debug_err)?;
    drop(accountmodel_batch);
    drop(accountmodel_db);

    assert_eq!(list_cf_set(&path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_088_edge_cli_db_persists_default_cf_key_after_reopen() -> TestResult {
    let temp = TempTree::new("rocksdb_config_088")?;
    let path = temp.child("cli_db");
    let config = RockSDBConfig::new();

    {
        let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
        let write_options = RockSDBConfig::get_write_options(false, false);

        db.put_opt(b"default-key", b"default-value", &write_options)
            .map_err(debug_err)?;

        drop(batch);
        drop(db);
    }

    let (db, batch) = config.open_db_cli(&path_string(&path)).map_err(debug_err)?;
    assert_eq!(
        db.get(b"default-key").map_err(debug_err)?,
        Some(b"default-value".to_vec())
    );

    drop(batch);
    drop(db);

    Ok(())
}

#[test]
fn rocksdb_config_089_edge_multi_cf_batch_supports_binary_transaction_key_and_value() -> TestResult
{
    let temp = TempTree::new("rocksdb_config_089")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    let key = [0_u8, 1, 2, 255, 128];
    let value = [255_u8, 0, 42, 7, 8, 9];

    batch.store_temp_transaction(&key, &value)?;

    let listed = batch.list_temp_transactions()?;
    let stored = listed
        .iter()
        .find(|(stored_key, _stored_value)| stored_key.as_slice() == key)
        .map(|(_stored_key, stored_value)| stored_value.as_slice());

    assert_eq!(stored, Some(value.as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_090_edge_blockchain_batch_supports_empty_log_value() -> TestResult {
    let temp = TempTree::new("rocksdb_config_090")?;
    let path = temp.child("blockchain_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_blockchain(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_log_entry(b"empty-log-value-key", b"")?;

    let logs = batch.list_log_entries()?;
    let stored = logs
        .iter()
        .find(|(key, _value)| key.as_slice() == b"empty-log-value-key")
        .map(|(_key, value)| value.as_slice());

    assert_eq!(stored, Some(b"".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_091_edge_registry_batch_supports_u64_max_reward_batch_index() -> TestResult {
    let temp = TempTree::new("rocksdb_config_091")?;
    let path = temp.child("registry_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_registry(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_reward_batch(u64::MAX, b"max-reward-batch")?;

    let listed = batch.list_reward_batches()?;
    let stored = listed
        .iter()
        .find(|(index, _value)| *index == u64::MAX)
        .map(|(_index, value)| value.as_slice());

    assert_eq!(stored, Some(b"max-reward-batch".as_slice()));

    Ok(())
}

#[test]
fn rocksdb_config_092_edge_accountmodel_batch_supports_empty_signature_value() -> TestResult {
    let temp = TempTree::new("rocksdb_config_092")?;
    let path = temp.child("accountmodel_db");
    let config = RockSDBConfig::new();

    let (_db, batch) = config
        .open_db_accountmodel(&path_string(&path))
        .map_err(debug_err)?;

    batch.store_batch_signature(b"empty-signature-value", b"")?;

    assert_eq!(batch.load_batch_signature(b"empty-signature-value")?, b"");

    Ok(())
}

#[test]
fn rocksdb_config_093_edge_sync_write_options_reject_empty_key_value_without_wal() -> TestResult {
    let temp = TempTree::new("rocksdb_config_093")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let write_options = RockSDBConfig::get_write_options(true, true);

    let err = db
        .put_opt(b"", b"", &write_options)
        .expect_err("sync write with WAL disabled must fail");

    let err_text = debug_err(err);

    assert!(err_text.contains("Sync writes has to enable WAL"));

    Ok(())
}

#[test]
fn rocksdb_config_094_edge_safe_write_options_support_binary_key_value() -> TestResult {
    let temp = TempTree::new("rocksdb_config_094")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let write_options = RockSDBConfig::get_write_options(false, false);
    let key = [0_u8, 255, 1, 2, 3];
    let value = [9_u8, 8, 7, 0, 255];

    db.put_opt(key, value, &write_options).map_err(debug_err)?;

    assert_eq!(db.get(key).map_err(debug_err)?, Some(value.to_vec()));

    Ok(())
}

#[test]
fn rocksdb_config_095_edge_read_options_without_checksums_read_existing_value() -> TestResult {
    let temp = TempTree::new("rocksdb_config_095")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;

    db.put(b"no-checksum-key", b"no-checksum-value")
        .map_err(debug_err)?;

    let read_options = RockSDBConfig::get_read_options(false, false);

    assert_eq!(
        db.get_opt(b"no-checksum-key", &read_options)
            .map_err(debug_err)?,
        Some(b"no-checksum-value".to_vec())
    );

    Ok(())
}

#[test]
fn rocksdb_config_096_edge_read_options_with_prefetch_read_missing_value_as_none() -> TestResult {
    let temp = TempTree::new("rocksdb_config_096")?;
    let path = temp.child("default_db");
    let config = RockSDBConfig::new();
    let db = DB::open(config.get_options(), &path).map_err(debug_err)?;
    let read_options = RockSDBConfig::get_read_options(false, true);

    assert_eq!(
        db.get_opt(b"definitely-missing-key", &read_options)
            .map_err(debug_err)?,
        None
    );

    Ok(())
}

#[test]
fn rocksdb_config_097_edge_existing_extra_cf_rejection_is_strict_even_with_all_expected_cfs()
-> TestResult {
    let temp = TempTree::new("rocksdb_config_097")?;
    let path = temp.child("full_plus_extra_db");
    let config = RockSDBConfig::new();

    create_full_schema_with_extra_cf_db(&path)?;

    let message = configuration_error_message(config.open_db_multi_cf(&path_string(&path)))?;

    assert!(message.contains("Unexpected column family"));
    assert!(message.contains("unexpected_extra_cf"));

    Ok(())
}

#[test]
fn rocksdb_config_098_edge_existing_default_only_db_remains_default_only_after_rejected_multi_open()
-> TestResult {
    let temp = TempTree::new("rocksdb_config_098")?;
    let path = temp.child("default_only_db");
    let config = RockSDBConfig::new();

    create_default_only_db(&path)?;

    let message = configuration_error_message(config.open_db_multi_cf(&path_string(&path)))?;
    assert!(message.contains("Missing column family"));

    assert_eq!(
        list_cf_set(&path)?,
        ["default".to_owned()].into_iter().collect()
    );

    Ok(())
}

#[test]
fn rocksdb_config_099_vector_open_all_wrappers_on_distinct_paths_produces_expected_schemas()
-> TestResult {
    let temp = TempTree::new("rocksdb_config_099")?;
    let config = RockSDBConfig::new();

    let cli_path = temp.child("cli_db");
    let multi_path = temp.child("multi_cf_db");
    let blockchain_path = temp.child("blockchain_db");
    let accountmodel_path = temp.child("accountmodel_db");
    let registry_path = temp.child("registry_db");

    let (cli_db, cli_batch) = config
        .open_db_cli(&path_string(&cli_path))
        .map_err(debug_err)?;
    drop(cli_batch);
    drop(cli_db);

    let (multi_db, multi_batch) = config
        .open_db_multi_cf(&path_string(&multi_path))
        .map_err(debug_err)?;
    drop(multi_batch);
    drop(multi_db);

    let (blockchain_db, blockchain_batch) = config
        .open_db_blockchain(&path_string(&blockchain_path))
        .map_err(debug_err)?;
    drop(blockchain_batch);
    drop(blockchain_db);

    let (accountmodel_db, accountmodel_batch) = config
        .open_db_accountmodel(&path_string(&accountmodel_path))
        .map_err(debug_err)?;
    drop(accountmodel_batch);
    drop(accountmodel_db);

    let (registry_db, registry_batch) = config
        .open_db_registry(&path_string(&registry_path))
        .map_err(debug_err)?;
    drop(registry_batch);
    drop(registry_db);

    assert_eq!(
        list_cf_set(&cli_path)?,
        ["default".to_owned()].into_iter().collect()
    );
    assert_eq!(list_cf_set(&multi_path)?, expected_full_cf_set());
    assert_eq!(list_cf_set(&blockchain_path)?, expected_full_cf_set());
    assert_eq!(list_cf_set(&accountmodel_path)?, expected_full_cf_set());
    assert_eq!(list_cf_set(&registry_path)?, expected_full_cf_set());

    Ok(())
}

#[test]
fn rocksdb_config_100_vector_multi_cf_schema_contains_every_descriptor_name_exactly_once()
-> TestResult {
    let temp = TempTree::new("rocksdb_config_100")?;
    let path = temp.child("multi_cf_db");
    let config = RockSDBConfig::new();

    let (db, batch) = config
        .open_db_multi_cf(&path_string(&path))
        .map_err(debug_err)?;
    drop(batch);
    drop(db);

    let actual = list_cf_set(&path)?;
    let expected = expected_full_cf_set();

    assert_eq!(actual.len(), GlobalConfiguration::TOTAL_COLUMNS + 1);
    assert_eq!(actual, expected);

    Ok(())
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}
