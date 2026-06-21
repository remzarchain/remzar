use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_002_schema::RockDbSchema;
use remzar::storage::rocksdb_003_batches::RockBatch;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use rust_rocksdb::WriteBatch;
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
            "remzar_rocksdb_003_batch_{test_name}_{}_{}",
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

fn open_full_batch(path: &Path) -> Result<RockBatch, String> {
    let db = RockBatch::open_db_blockchain(&path_string(path)).map_err(debug_err)?;

    Ok(RockBatch { db: Arc::new(db) })
}

fn deterministic_bytes_for_batch_tests(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| {
            let low = index.to_le_bytes()[0];
            seed.wrapping_add(low).rotate_left(1)
        })
        .collect()
}

fn open_cli_batch(path: &Path) -> Result<RockBatch, String> {
    let db = RockBatch::open_db_cli(&path_string(path)).map_err(debug_err)?;

    Ok(RockBatch { db: Arc::new(db) })
}

fn open_log_batch(directory: &DirectoryDB) -> Result<RockBatch, String> {
    let db = RockDbSchema::open_log_db(directory).map_err(debug_err)?;

    Ok(RockBatch { db: Arc::new(db) })
}

fn database_error_details<T>(result: Result<T, ErrorDetection>) -> Result<String, String> {
    match result {
        Ok(_) => Err("expected database error but got Ok".to_owned()),
        Err(ErrorDetection::DatabaseError { details }) => Ok(details),
        Err(other) => Err(format!("unexpected error variant: {other:?}")),
    }
}

fn expected_full_cf_names() -> Vec<&'static str> {
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

fn raw_put_cf(batch: &RockBatch, cf_name: &str, key: &[u8], value: &[u8]) -> TestResult {
    let cf_handle = batch
        .db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("Column Family {cf_name} not found"))?;

    let mut write_batch = WriteBatch::default();
    write_batch.put_cf(cf_handle, key, value);

    batch.db.write(&write_batch).map_err(debug_err)?;

    Ok(())
}

fn raw_get_cf(batch: &RockBatch, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let cf_handle = batch
        .db
        .cf_handle(cf_name)
        .ok_or_else(|| format!("Column Family {cf_name} not found"))?;

    batch
        .db
        .get_cf(cf_handle, key)
        .map(|maybe_value| maybe_value.map(|value| value.to_vec()))
        .map_err(debug_err)
}

fn sorted_kv(mut values: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
    values.sort_by(|left, right| left.0.cmp(&right.0));
    values
}

fn sorted_indexed(mut values: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    values.sort_by_key(|(index, _value)| *index);
    values
}

fn value_for_index(values: &[(u64, Vec<u8>)], expected_index: u64) -> Option<&[u8]> {
    values
        .iter()
        .find(|(index, _value)| *index == expected_index)
        .map(|(_index, value)| value.as_slice())
}

fn value_for_key<'a>(values: &'a [(Vec<u8>, Vec<u8>)], expected_key: &[u8]) -> Option<&'a [u8]> {
    values
        .iter()
        .find(|(key, _value)| key.as_slice() == expected_key)
        .map(|(_key, value)| value.as_slice())
}

#[test]
fn rock_batch_001_open_db_blockchain_creates_full_schema() -> TestResult {
    let temp = TempTree::new("rock_batch_001")?;
    let path = temp.child("blockchain_db");

    let batch = open_full_batch(&path)?;
    drop(batch);

    RockDbSchema::validate_column_families(&path, &expected_full_cf_names())?;

    Ok(())
}

#[test]
fn rock_batch_002_open_db_cli_creates_default_only_database() -> TestResult {
    let temp = TempTree::new("rock_batch_002")?;
    let path = temp.child("cli_db");

    let batch = open_cli_batch(&path)?;
    drop(batch);

    RockDbSchema::validate_column_families(&path, &["default"])?;

    let err = RockDbSchema::validate_column_families(
        &path,
        &[GlobalConfiguration::TRANSACTION_COLUMN_NAME],
    )
    .expect_err("CLI DB opened with DB::open should not have transaction_data CF");

    assert!(err.contains("Missing required column family"));

    Ok(())
}

#[test]
fn rock_batch_003_open_db_blockchain_error_mentions_path_when_parent_is_file() -> TestResult {
    let temp = TempTree::new("rock_batch_003")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let target = file_base.join("blockchain");
    let details = database_error_details(RockBatch::open_db_blockchain(&path_string(&target)))?;

    assert!(details.contains("RockBatch blockchain open failed"));
    assert!(details.contains(&target.display().to_string()));

    Ok(())
}

#[test]
fn rock_batch_004_open_db_cli_error_mentions_path_when_parent_is_file() -> TestResult {
    let temp = TempTree::new("rock_batch_004")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let target = file_base.join("cli");
    let details = database_error_details(RockBatch::open_db_cli(&path_string(&target)))?;

    assert!(details.contains("RockBatch CLI open failed"));
    assert!(details.contains(&target.display().to_string()));

    Ok(())
}

#[test]
fn rock_batch_005_list_unprocessed_batches_is_empty_on_new_full_db() -> TestResult {
    let temp = TempTree::new("rock_batch_005")?;
    let batch = open_full_batch(&temp.child("db"))?;

    assert!(batch.list_unprocessed_batches()?.is_empty());

    Ok(())
}

#[test]
fn rock_batch_006_store_transaction_batch_round_trips_single_batch() -> TestResult {
    let temp = TempTree::new("rock_batch_006")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction_batch(7, b"serialized batch seven")?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(
        value_for_index(&batches, 7),
        Some(b"serialized batch seven".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_007_transaction_batches_are_listed_by_big_endian_key_order() -> TestResult {
    let temp = TempTree::new("rock_batch_007")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction_batch(10, b"ten")?;
    batch.store_transaction_batch(2, b"two")?;
    batch.store_transaction_batch(1, b"one")?;

    let batches = batch.list_unprocessed_batches()?;
    let indexes = batches
        .iter()
        .map(|(index, _value)| *index)
        .collect::<Vec<_>>();

    assert_eq!(indexes, vec![1, 2, 10]);

    Ok(())
}

#[test]
fn rock_batch_008_store_transaction_batch_overwrites_same_index() -> TestResult {
    let temp = TempTree::new("rock_batch_008")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction_batch(42, b"old")?;
    batch.store_transaction_batch(42, b"new")?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(batches.len(), 1);
    assert_eq!(value_for_index(&batches, 42), Some(b"new".as_slice()));

    Ok(())
}

#[test]
fn rock_batch_009_list_unprocessed_batches_filters_keys_shorter_than_eight_bytes() -> TestResult {
    let temp = TempTree::new("rock_batch_009")?;
    let batch = open_full_batch(&temp.child("db"))?;

    raw_put_cf(
        &batch,
        RockDbSchema::transaction_batch_column_name(),
        b"short",
        b"bad",
    )?;
    batch.store_transaction_batch(1, b"good")?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(batches.len(), 1);
    assert_eq!(value_for_index(&batches, 1), Some(b"good".as_slice()));

    Ok(())
}

#[test]
fn rock_batch_010_list_unprocessed_batches_uses_first_eight_bytes_of_long_key() -> TestResult {
    let temp = TempTree::new("rock_batch_010")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let mut key = 99_u64.to_be_bytes().to_vec();
    key.extend_from_slice(b"extra suffix");

    raw_put_cf(
        &batch,
        RockDbSchema::transaction_batch_column_name(),
        &key,
        b"long-key-value",
    )?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(
        value_for_index(&batches, 99),
        Some(b"long-key-value".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_011_list_reward_batches_is_empty_on_new_full_db() -> TestResult {
    let temp = TempTree::new("rock_batch_011")?;
    let batch = open_full_batch(&temp.child("db"))?;

    assert!(batch.list_reward_batches()?.is_empty());

    Ok(())
}

#[test]
fn rock_batch_012_store_reward_batch_round_trips_single_batch() -> TestResult {
    let temp = TempTree::new("rock_batch_012")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward_batch(5, b"reward batch five")?;

    let batches = batch.list_reward_batches()?;

    assert_eq!(
        value_for_index(&batches, 5),
        Some(b"reward batch five".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_013_reward_batches_are_listed_by_big_endian_key_order() -> TestResult {
    let temp = TempTree::new("rock_batch_013")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward_batch(3, b"three")?;
    batch.store_reward_batch(1, b"one")?;
    batch.store_reward_batch(2, b"two")?;

    let batches = batch.list_reward_batches()?;
    let indexes = batches
        .iter()
        .map(|(index, _value)| *index)
        .collect::<Vec<_>>();

    assert_eq!(indexes, vec![1, 2, 3]);

    Ok(())
}

#[test]
fn rock_batch_014_store_reward_batch_overwrites_same_index() -> TestResult {
    let temp = TempTree::new("rock_batch_014")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward_batch(88, b"old reward")?;
    batch.store_reward_batch(88, b"new reward")?;

    let batches = batch.list_reward_batches()?;

    assert_eq!(batches.len(), 1);
    assert_eq!(
        value_for_index(&batches, 88),
        Some(b"new reward".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_015_list_reward_batches_filters_keys_shorter_than_eight_bytes() -> TestResult {
    let temp = TempTree::new("rock_batch_015")?;
    let batch = open_full_batch(&temp.child("db"))?;

    raw_put_cf(
        &batch,
        RockDbSchema::reward_batch_column_name(),
        b"short",
        b"bad reward",
    )?;
    batch.store_reward_batch(4, b"good reward")?;

    let batches = batch.list_reward_batches()?;

    assert_eq!(batches.len(), 1);
    assert_eq!(
        value_for_index(&batches, 4),
        Some(b"good reward".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_016_store_and_load_batch_signature_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_016")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_batch_signature(b"signing-key-1", b"signature-bytes")?;

    let loaded = batch.load_batch_signature(b"signing-key-1")?;

    assert_eq!(loaded, b"signature-bytes");

    Ok(())
}

#[test]
fn rock_batch_017_load_missing_batch_signature_returns_error() -> TestResult {
    let temp = TempTree::new("rock_batch_017")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let err = batch
        .load_batch_signature(b"missing-signature")
        .expect_err("missing signature should return an error");

    assert!(err.contains("No batch signature found"));

    Ok(())
}

#[test]
fn rock_batch_018_store_batch_signature_overwrites_same_key() -> TestResult {
    let temp = TempTree::new("rock_batch_018")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_batch_signature(b"same-key", b"old-signature")?;
    batch.store_batch_signature(b"same-key", b"new-signature")?;

    let loaded = batch.load_batch_signature(b"same-key")?;

    assert_eq!(loaded, b"new-signature");

    Ok(())
}

#[test]
fn rock_batch_019_store_batch_signature_supports_empty_key() -> TestResult {
    let temp = TempTree::new("rock_batch_019")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_batch_signature(b"", b"signature-for-empty-key")?;

    let loaded = batch.load_batch_signature(b"")?;

    assert_eq!(loaded, b"signature-for-empty-key");

    Ok(())
}

#[test]
fn rock_batch_020_list_temp_transactions_is_empty_on_new_full_db() -> TestResult {
    let temp = TempTree::new("rock_batch_020")?;
    let batch = open_full_batch(&temp.child("db"))?;

    assert!(batch.list_temp_transactions()?.is_empty());

    Ok(())
}

#[test]
fn rock_batch_021_store_temp_transaction_round_trips_in_transaction_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_021")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transaction(b"tx-key-1", b"tx-data-1")?;

    let transactions = sorted_kv(batch.list_temp_transactions()?);

    assert_eq!(transactions.len(), 1);
    assert_eq!(
        value_for_key(&transactions, b"tx-key-1"),
        Some(b"tx-data-1".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_022_store_temp_transactions_batch_round_trips_multiple_entries() -> TestResult {
    let temp = TempTree::new("rock_batch_022")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let transactions = vec![
        (b"tx-a".to_vec(), b"value-a".to_vec()),
        (b"tx-b".to_vec(), b"value-b".to_vec()),
        (b"tx-c".to_vec(), b"value-c".to_vec()),
    ];

    batch.store_temp_transactions(&transactions)?;

    let listed = sorted_kv(batch.list_temp_transactions()?);

    assert_eq!(listed.len(), 3);
    assert_eq!(value_for_key(&listed, b"tx-a"), Some(b"value-a".as_slice()));
    assert_eq!(value_for_key(&listed, b"tx-b"), Some(b"value-b".as_slice()));
    assert_eq!(value_for_key(&listed, b"tx-c"), Some(b"value-c".as_slice()));

    Ok(())
}

#[test]
fn rock_batch_023_store_temp_transactions_duplicate_key_keeps_last_value() -> TestResult {
    let temp = TempTree::new("rock_batch_023")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let transactions = vec![
        (b"same-tx".to_vec(), b"old".to_vec()),
        (b"same-tx".to_vec(), b"new".to_vec()),
    ];

    batch.store_temp_transactions(&transactions)?;

    let listed = batch.list_temp_transactions()?;

    assert_eq!(listed.len(), 1);
    assert_eq!(value_for_key(&listed, b"same-tx"), Some(b"new".as_slice()));

    Ok(())
}

#[test]
fn rock_batch_024_store_temp_transaction_supports_empty_value() -> TestResult {
    let temp = TempTree::new("rock_batch_024")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transaction(b"empty-value-tx", b"")?;

    let listed = batch.list_temp_transactions()?;

    assert_eq!(
        value_for_key(&listed, b"empty-value-tx"),
        Some(b"".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_025_batch_execute_records_succeeds_when_transaction_cf_is_empty() -> TestResult {
    let temp = TempTree::new("rock_batch_025")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.batch_execute_records()?;

    Ok(())
}

#[test]
fn rock_batch_026_batch_execute_records_writes_meta_for_valid_transaction() -> TestResult {
    let temp = TempTree::new("rock_batch_026")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let key = b"tx-exec-key";
    batch.store_temp_transaction(key, b"tx-exec-value")?;
    batch.batch_execute_records()?;

    let meta_value = batch.load_batch_signature(key)?;
    let meta_text = String::from_utf8(meta_value).map_err(debug_err)?;
    let expected_key_debug = format!("{key:?}");

    assert!(meta_text.contains("Applied record"));
    assert!(meta_text.contains(&expected_key_debug));

    Ok(())
}

#[test]
fn rock_batch_027_batch_execute_records_rejects_empty_transaction_key() -> TestResult {
    let temp = TempTree::new("rock_batch_027")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transaction(b"", b"non-empty-value")?;

    let err = batch
        .batch_execute_records()
        .expect_err("empty transaction key must be rejected");

    assert!(err.contains("Record invalid"));

    Ok(())
}

#[test]
fn rock_batch_028_batch_execute_records_rejects_empty_transaction_value() -> TestResult {
    let temp = TempTree::new("rock_batch_028")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transaction(b"non-empty-key", b"")?;

    let err = batch
        .batch_execute_records()
        .expect_err("empty transaction value must be rejected");

    assert!(err.contains("Record invalid"));

    Ok(())
}

#[test]
fn rock_batch_029_store_transaction_writes_transaction_column_family() -> TestResult {
    let temp = TempTree::new("rock_batch_029")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction(b"tx-id-1", b"tx-bytes-1")?;

    let stored = raw_get_cf(&batch, RockDbSchema::transaction_column_name(), b"tx-id-1")?
        .ok_or_else(|| "stored transaction missing".to_owned())?;

    assert_eq!(stored, b"tx-bytes-1");

    Ok(())
}

#[test]
fn rock_batch_030_store_transaction_overwrites_same_transaction_id() -> TestResult {
    let temp = TempTree::new("rock_batch_030")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction(b"tx-id", b"old-tx")?;
    batch.store_transaction(b"tx-id", b"new-tx")?;

    let stored = raw_get_cf(&batch, RockDbSchema::transaction_column_name(), b"tx-id")?
        .ok_or_else(|| "stored transaction missing".to_owned())?;

    assert_eq!(stored, b"new-tx");

    Ok(())
}

#[test]
fn rock_batch_031_store_reward_writes_reward_column_family() -> TestResult {
    let temp = TempTree::new("rock_batch_031")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward(b"reward-id-1", b"reward-bytes-1")?;

    let stored = raw_get_cf(&batch, RockDbSchema::reward_column_name(), b"reward-id-1")?
        .ok_or_else(|| "stored reward missing".to_owned())?;

    assert_eq!(stored, b"reward-bytes-1");

    Ok(())
}

#[test]
fn rock_batch_032_store_reward_overwrites_same_reward_id() -> TestResult {
    let temp = TempTree::new("rock_batch_032")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward(b"reward-id", b"old-reward")?;
    batch.store_reward(b"reward-id", b"new-reward")?;

    let stored = raw_get_cf(&batch, RockDbSchema::reward_column_name(), b"reward-id")?
        .ok_or_else(|| "stored reward missing".to_owned())?;

    assert_eq!(stored, b"new-reward");

    Ok(())
}

#[test]
fn rock_batch_033_store_log_entry_round_trips_on_full_db() -> TestResult {
    let temp = TempTree::new("rock_batch_033")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_log_entry(b"log-key-1", b"log-value-1")?;

    let logs = batch.list_log_entries()?;

    assert_eq!(
        value_for_key(&logs, b"log-key-1"),
        Some(b"log-value-1".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_034_list_log_entries_is_empty_on_new_full_db() -> TestResult {
    let temp = TempTree::new("rock_batch_034")?;
    let batch = open_full_batch(&temp.child("db"))?;

    assert!(batch.list_log_entries()?.is_empty());

    Ok(())
}

#[test]
fn rock_batch_035_store_log_entry_round_trips_on_log_schema_db() -> TestResult {
    let temp = TempTree::new("rock_batch_035")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    batch.store_log_entry(b"log-only-key", b"log-only-value")?;

    let logs = batch.list_log_entries()?;

    assert_eq!(
        value_for_key(&logs, b"log-only-key"),
        Some(b"log-only-value".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_036_log_schema_db_rejects_transaction_operations() -> TestResult {
    let temp = TempTree::new("rock_batch_036")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    let err = batch
        .store_temp_transaction(b"tx", b"value")
        .expect_err("log-only DB should not contain transaction_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::transaction_column_name()));

    Ok(())
}

#[test]
fn rock_batch_037_log_schema_db_rejects_reward_operations() -> TestResult {
    let temp = TempTree::new("rock_batch_037")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    let err = batch
        .store_reward_batch(1, b"reward")
        .expect_err("log-only DB should not contain reward_batch CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::reward_batch_column_name()));

    Ok(())
}

#[test]
fn rock_batch_038_cli_db_rejects_full_schema_batch_operations() -> TestResult {
    let temp = TempTree::new("rock_batch_038")?;
    let batch = open_cli_batch(&temp.child("cli_db"))?;

    let err = batch
        .store_transaction_batch(1, b"batch")
        .expect_err("CLI DB opened with default CF only should reject transaction_batch CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::transaction_batch_column_name()));

    Ok(())
}

#[test]
fn rock_batch_039_load_many_temp_transactions_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_039")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let transactions = (0..128_u64)
        .map(|index| {
            (
                format!("tx-key-{index:03}").into_bytes(),
                format!("tx-value-{index:03}").into_bytes(),
            )
        })
        .collect::<Vec<_>>();

    batch.store_temp_transactions(&transactions)?;

    let listed = sorted_kv(batch.list_temp_transactions()?);

    assert_eq!(listed.len(), transactions.len());

    for (key, value) in transactions {
        assert_eq!(value_for_key(&listed, &key), Some(value.as_slice()));
    }

    Ok(())
}

#[test]
fn rock_batch_040_adversarial_parallel_isolated_blockchain_batches() -> TestResult {
    let temp = TempTree::new("rock_batch_040")?;
    let mut handles = Vec::new();

    for index in 0..16_u64 {
        let path = temp.child(&format!("parallel_db_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<Vec<(u64, Vec<u8>)>, String> {
                let batch = open_full_batch(&path)?;
                let value = format!("parallel-batch-{index}").into_bytes();

                batch.store_transaction_batch(index, &value)?;

                let listed = sorted_indexed(batch.list_unprocessed_batches()?);

                Ok(listed)
            },
        ));
    }

    for (index, handle) in handles.into_iter().enumerate() {
        let listed = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel RockBatch worker panicked".to_owned()),
        };

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, index as u64);
        assert_eq!(listed[0].1, format!("parallel-batch-{index}").into_bytes());
    }

    Ok(())
}

#[test]
fn rock_batch_041_transaction_batch_persists_after_reopen() -> TestResult {
    let temp = TempTree::new("rock_batch_041")?;
    let path = temp.child("db");

    {
        let batch = open_full_batch(&path)?;
        batch.store_transaction_batch(11, b"persisted transaction batch")?;
    }

    let reopened = open_full_batch(&path)?;
    let batches = reopened.list_unprocessed_batches()?;

    assert_eq!(
        value_for_index(&batches, 11),
        Some(b"persisted transaction batch".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_042_reward_batch_persists_after_reopen() -> TestResult {
    let temp = TempTree::new("rock_batch_042")?;
    let path = temp.child("db");

    {
        let batch = open_full_batch(&path)?;
        batch.store_reward_batch(12, b"persisted reward batch")?;
    }

    let reopened = open_full_batch(&path)?;
    let batches = reopened.list_reward_batches()?;

    assert_eq!(
        value_for_index(&batches, 12),
        Some(b"persisted reward batch".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_043_batch_signature_persists_after_reopen() -> TestResult {
    let temp = TempTree::new("rock_batch_043")?;
    let path = temp.child("db");

    {
        let batch = open_full_batch(&path)?;
        batch.store_batch_signature(b"persist-signature-key", b"persisted-signature")?;
    }

    let reopened = open_full_batch(&path)?;
    let loaded = reopened.load_batch_signature(b"persist-signature-key")?;

    assert_eq!(loaded, b"persisted-signature");

    Ok(())
}

#[test]
fn rock_batch_044_temp_transaction_persists_after_reopen() -> TestResult {
    let temp = TempTree::new("rock_batch_044")?;
    let path = temp.child("db");

    {
        let batch = open_full_batch(&path)?;
        batch.store_temp_transaction(b"persist-tx-key", b"persist-tx-value")?;
    }

    let reopened = open_full_batch(&path)?;
    let transactions = reopened.list_temp_transactions()?;

    assert_eq!(
        value_for_key(&transactions, b"persist-tx-key"),
        Some(b"persist-tx-value".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_045_log_entry_persists_after_reopen() -> TestResult {
    let temp = TempTree::new("rock_batch_045")?;
    let path = temp.child("db");

    {
        let batch = open_full_batch(&path)?;
        batch.store_log_entry(b"persist-log-key", b"persist-log-value")?;
    }

    let reopened = open_full_batch(&path)?;
    let logs = reopened.list_log_entries()?;

    assert_eq!(
        value_for_key(&logs, b"persist-log-key"),
        Some(b"persist-log-value".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_046_single_transaction_persists_after_reopen() -> TestResult {
    let temp = TempTree::new("rock_batch_046")?;
    let path = temp.child("db");

    {
        let batch = open_full_batch(&path)?;
        batch.store_transaction(b"persist-single-tx", b"single-tx-bytes")?;
    }

    let reopened = open_full_batch(&path)?;
    let stored = raw_get_cf(
        &reopened,
        RockDbSchema::transaction_column_name(),
        b"persist-single-tx",
    )?
    .ok_or_else(|| "persisted transaction missing after reopen".to_owned())?;

    assert_eq!(stored, b"single-tx-bytes");

    Ok(())
}

#[test]
fn rock_batch_047_single_reward_persists_after_reopen() -> TestResult {
    let temp = TempTree::new("rock_batch_047")?;
    let path = temp.child("db");

    {
        let batch = open_full_batch(&path)?;
        batch.store_reward(b"persist-single-reward", b"single-reward-bytes")?;
    }

    let reopened = open_full_batch(&path)?;
    let stored = raw_get_cf(
        &reopened,
        RockDbSchema::reward_column_name(),
        b"persist-single-reward",
    )?
    .ok_or_else(|| "persisted reward missing after reopen".to_owned())?;

    assert_eq!(stored, b"single-reward-bytes");

    Ok(())
}

#[test]
fn rock_batch_048_transaction_batch_supports_zero_index() -> TestResult {
    let temp = TempTree::new("rock_batch_048")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction_batch(0, b"zero-index-batch")?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(
        value_for_index(&batches, 0),
        Some(b"zero-index-batch".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_049_transaction_batch_supports_u64_max_index() -> TestResult {
    let temp = TempTree::new("rock_batch_049")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction_batch(u64::MAX, b"max-index-batch")?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(
        value_for_index(&batches, u64::MAX),
        Some(b"max-index-batch".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_050_reward_batch_supports_zero_index() -> TestResult {
    let temp = TempTree::new("rock_batch_050")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward_batch(0, b"zero-index-reward")?;

    let batches = batch.list_reward_batches()?;

    assert_eq!(
        value_for_index(&batches, 0),
        Some(b"zero-index-reward".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_051_reward_batch_supports_u64_max_index() -> TestResult {
    let temp = TempTree::new("rock_batch_051")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward_batch(u64::MAX, b"max-index-reward")?;

    let batches = batch.list_reward_batches()?;

    assert_eq!(
        value_for_index(&batches, u64::MAX),
        Some(b"max-index-reward".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_052_empty_transaction_batch_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_052")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction_batch(52, b"")?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(value_for_index(&batches, 52), Some(b"".as_slice()));

    Ok(())
}

#[test]
fn rock_batch_053_empty_reward_batch_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_053")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward_batch(53, b"")?;

    let batches = batch.list_reward_batches()?;

    assert_eq!(value_for_index(&batches, 53), Some(b"".as_slice()));

    Ok(())
}

#[test]
fn rock_batch_054_empty_signature_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_054")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_batch_signature(b"empty-signature-value", b"")?;

    let loaded = batch.load_batch_signature(b"empty-signature-value")?;

    assert_eq!(loaded, b"");

    Ok(())
}

#[test]
fn rock_batch_055_empty_log_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_055")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_log_entry(b"empty-log-value", b"")?;

    let logs = batch.list_log_entries()?;

    assert_eq!(
        value_for_key(&logs, b"empty-log-value"),
        Some(b"".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_056_empty_log_key_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_056")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_log_entry(b"", b"log-value-for-empty-key")?;

    let logs = batch.list_log_entries()?;

    assert_eq!(
        value_for_key(&logs, b""),
        Some(b"log-value-for-empty-key".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_057_store_transaction_supports_empty_key() -> TestResult {
    let temp = TempTree::new("rock_batch_057")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction(b"", b"transaction-for-empty-key")?;

    let stored = raw_get_cf(&batch, RockDbSchema::transaction_column_name(), b"")?
        .ok_or_else(|| "transaction for empty key missing".to_owned())?;

    assert_eq!(stored, b"transaction-for-empty-key");

    Ok(())
}

#[test]
fn rock_batch_058_store_reward_supports_empty_key() -> TestResult {
    let temp = TempTree::new("rock_batch_058")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward(b"", b"reward-for-empty-key")?;

    let stored = raw_get_cf(&batch, RockDbSchema::reward_column_name(), b"")?
        .ok_or_else(|| "reward for empty key missing".to_owned())?;

    assert_eq!(stored, b"reward-for-empty-key");

    Ok(())
}

#[test]
fn rock_batch_059_large_transaction_batch_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_059")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let value = deterministic_bytes_for_batch_tests(64 * 1024, 59);

    batch.store_transaction_batch(59, &value)?;

    let batches = batch.list_unprocessed_batches()?;

    assert_eq!(value_for_index(&batches, 59), Some(value.as_slice()));

    Ok(())
}

#[test]
fn rock_batch_060_large_reward_batch_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_060")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let value = deterministic_bytes_for_batch_tests(64 * 1024, 60);

    batch.store_reward_batch(60, &value)?;

    let batches = batch.list_reward_batches()?;

    assert_eq!(value_for_index(&batches, 60), Some(value.as_slice()));

    Ok(())
}

#[test]
fn rock_batch_061_large_signature_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_061")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let value = deterministic_bytes_for_batch_tests(32 * 1024, 61);

    batch.store_batch_signature(b"large-signature-key", &value)?;

    let loaded = batch.load_batch_signature(b"large-signature-key")?;

    assert_eq!(loaded, value);

    Ok(())
}

#[test]
fn rock_batch_062_large_temp_transaction_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_062")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let value = deterministic_bytes_for_batch_tests(32 * 1024, 62);

    batch.store_temp_transaction(b"large-temp-tx", &value)?;

    let listed = batch.list_temp_transactions()?;

    assert_eq!(
        value_for_key(&listed, b"large-temp-tx"),
        Some(value.as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_063_large_log_value_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_063")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let value = deterministic_bytes_for_batch_tests(32 * 1024, 63);

    batch.store_log_entry(b"large-log-key", &value)?;

    let logs = batch.list_log_entries()?;

    assert_eq!(
        value_for_key(&logs, b"large-log-key"),
        Some(value.as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_064_store_temp_transactions_empty_slice_is_noop() -> TestResult {
    let temp = TempTree::new("rock_batch_064")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transactions(&[])?;

    assert!(batch.list_temp_transactions()?.is_empty());

    Ok(())
}

#[test]
fn rock_batch_065_batch_execute_records_applies_multiple_valid_transactions() -> TestResult {
    let temp = TempTree::new("rock_batch_065")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transactions(&[
        (b"exec-a".to_vec(), b"value-a".to_vec()),
        (b"exec-b".to_vec(), b"value-b".to_vec()),
        (b"exec-c".to_vec(), b"value-c".to_vec()),
    ])?;

    batch.batch_execute_records()?;

    for key in [
        b"exec-a".as_slice(),
        b"exec-b".as_slice(),
        b"exec-c".as_slice(),
    ] {
        let meta = batch.load_batch_signature(key)?;
        let text = String::from_utf8(meta).map_err(debug_err)?;

        assert!(text.contains("Applied record"));
    }

    Ok(())
}

#[test]
fn rock_batch_066_batch_execute_records_does_not_remove_transactions() -> TestResult {
    let temp = TempTree::new("rock_batch_066")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transaction(b"still-present", b"value")?;
    batch.batch_execute_records()?;

    let transactions = batch.list_temp_transactions()?;

    assert_eq!(
        value_for_key(&transactions, b"still-present"),
        Some(b"value".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_067_batch_execute_records_fails_if_any_record_has_empty_value() -> TestResult {
    let temp = TempTree::new("rock_batch_067")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transactions(&[
        (b"valid-key".to_vec(), b"valid-value".to_vec()),
        (b"bad-empty-value".to_vec(), Vec::new()),
    ])?;

    let err = batch
        .batch_execute_records()
        .expect_err("any empty transaction value must reject execution");

    assert!(err.contains("Record invalid"));

    Ok(())
}

#[test]
fn rock_batch_068_batch_execute_records_fails_if_any_record_has_empty_key() -> TestResult {
    let temp = TempTree::new("rock_batch_068")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transactions(&[
        (b"valid-key".to_vec(), b"valid-value".to_vec()),
        (Vec::new(), b"bad-empty-key".to_vec()),
    ])?;

    let err = batch
        .batch_execute_records()
        .expect_err("any empty transaction key must reject execution");

    assert!(err.contains("Record invalid"));

    Ok(())
}

#[test]
fn rock_batch_069_cli_db_rejects_signature_operations_due_missing_meta_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_069")?;
    let batch = open_cli_batch(&temp.child("cli_db"))?;

    let err = batch
        .store_batch_signature(b"key", b"signature")
        .expect_err("default-only CLI DB must not contain meta_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::meta_data_column_name()));

    Ok(())
}

#[test]
fn rock_batch_070_cli_db_rejects_log_operations_due_missing_logs_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_070")?;
    let batch = open_cli_batch(&temp.child("cli_db"))?;

    let err = batch
        .store_log_entry(b"log-key", b"log-value")
        .expect_err("default-only CLI DB must not contain logs_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::logs_column_name()));

    Ok(())
}

#[test]
fn rock_batch_071_log_schema_db_rejects_signature_operations_due_missing_meta_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_071")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    let err = batch
        .store_batch_signature(b"key", b"signature")
        .expect_err("log schema DB must not contain meta_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::meta_data_column_name()));

    Ok(())
}

#[test]
fn rock_batch_072_log_schema_db_rejects_list_temp_transactions_due_missing_transaction_cf()
-> TestResult {
    let temp = TempTree::new("rock_batch_072")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    let err = batch
        .list_temp_transactions()
        .expect_err("log schema DB must not contain transaction_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::transaction_column_name()));

    Ok(())
}

#[test]
fn rock_batch_073_log_schema_db_rejects_list_unprocessed_batches_due_missing_batch_cf() -> TestResult
{
    let temp = TempTree::new("rock_batch_073")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    let err = batch
        .list_unprocessed_batches()
        .expect_err("log schema DB must not contain transaction_batch_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::transaction_batch_column_name()));

    Ok(())
}

#[test]
fn rock_batch_074_log_schema_db_rejects_list_reward_batches_due_missing_reward_batch_cf()
-> TestResult {
    let temp = TempTree::new("rock_batch_074")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    let err = batch
        .list_reward_batches()
        .expect_err("log schema DB must not contain reward_batch_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::reward_batch_column_name()));

    Ok(())
}

#[test]
fn rock_batch_075_transaction_and_temp_transaction_share_transaction_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_075")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction(b"shared-tx-key", b"from-store-transaction")?;

    let listed = batch.list_temp_transactions()?;

    assert_eq!(
        value_for_key(&listed, b"shared-tx-key"),
        Some(b"from-store-transaction".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_076_temp_transaction_overwrites_store_transaction_same_key() -> TestResult {
    let temp = TempTree::new("rock_batch_076")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction(b"same-shared-key", b"from-store-transaction")?;
    batch.store_temp_transaction(b"same-shared-key", b"from-temp-transaction")?;

    let stored = raw_get_cf(
        &batch,
        RockDbSchema::transaction_column_name(),
        b"same-shared-key",
    )?
    .ok_or_else(|| "shared transaction key missing".to_owned())?;

    assert_eq!(stored, b"from-temp-transaction");

    Ok(())
}

#[test]
fn rock_batch_077_store_transaction_overwrites_temp_transaction_same_key() -> TestResult {
    let temp = TempTree::new("rock_batch_077")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transaction(b"same-shared-key", b"from-temp-transaction")?;
    batch.store_transaction(b"same-shared-key", b"from-store-transaction")?;

    let stored = raw_get_cf(
        &batch,
        RockDbSchema::transaction_column_name(),
        b"same-shared-key",
    )?
    .ok_or_else(|| "shared transaction key missing".to_owned())?;

    assert_eq!(stored, b"from-store-transaction");

    Ok(())
}

#[test]
fn rock_batch_078_store_log_entry_overwrites_same_key() -> TestResult {
    let temp = TempTree::new("rock_batch_078")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_log_entry(b"same-log-key", b"old-log")?;
    batch.store_log_entry(b"same-log-key", b"new-log")?;

    let logs = batch.list_log_entries()?;

    assert_eq!(
        value_for_key(&logs, b"same-log-key"),
        Some(b"new-log".as_slice())
    );

    Ok(())
}

#[test]
fn rock_batch_079_load_many_reward_batches_round_trips() -> TestResult {
    let temp = TempTree::new("rock_batch_079")?;
    let batch = open_full_batch(&temp.child("db"))?;

    for index in 0..128_u64 {
        let value = format!("reward-batch-{index:03}").into_bytes();
        batch.store_reward_batch(index, &value)?;
    }

    let listed = sorted_indexed(batch.list_reward_batches()?);

    assert_eq!(listed.len(), 128);

    for (index, value) in listed {
        assert_eq!(value, format!("reward-batch-{index:03}").into_bytes());
    }

    Ok(())
}

#[test]
fn rock_batch_080_adversarial_parallel_writes_to_same_blockchain_db() -> TestResult {
    let temp = TempTree::new("rock_batch_080")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let shared = Arc::new(batch);
    let mut handles = Vec::new();

    for index in 0..32_u64 {
        let worker_batch = Arc::clone(&shared);

        handles.push(thread::spawn(move || -> Result<(), String> {
            let key = format!("parallel-tx-{index:02}").into_bytes();
            let value = format!("parallel-value-{index:02}").into_bytes();

            worker_batch.store_temp_transaction(&key, &value)
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel writer panicked".to_owned()),
        }
    }

    let listed = shared.list_temp_transactions()?;

    for index in 0..32_u64 {
        let key = format!("parallel-tx-{index:02}").into_bytes();
        let value = format!("parallel-value-{index:02}").into_bytes();

        assert_eq!(value_for_key(&listed, &key), Some(value.as_slice()));
    }

    Ok(())
}

#[test]
fn rock_batch_081_vector_transaction_batches_round_trip_known_indexes_and_values() -> TestResult {
    let temp = TempTree::new("rock_batch_081")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let vectors = [
        (0_u64, b"batch-zero".as_slice()),
        (1_u64, b"batch-one".as_slice()),
        (255_u64, b"batch-255".as_slice()),
        (65_535_u64, b"batch-65535".as_slice()),
        (u32::MAX as u64, b"batch-u32-max".as_slice()),
    ];

    for (index, value) in vectors {
        batch.store_transaction_batch(index, value)?;
    }

    let listed = sorted_indexed(batch.list_unprocessed_batches()?);

    assert_eq!(listed.len(), vectors.len());

    for (index, value) in vectors {
        assert_eq!(value_for_index(&listed, index), Some(value));
    }

    Ok(())
}

#[test]
fn rock_batch_082_vector_reward_batches_round_trip_known_indexes_and_values() -> TestResult {
    let temp = TempTree::new("rock_batch_082")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let vectors = [
        (0_u64, b"reward-zero".as_slice()),
        (1_u64, b"reward-one".as_slice()),
        (255_u64, b"reward-255".as_slice()),
        (65_535_u64, b"reward-65535".as_slice()),
        (u32::MAX as u64, b"reward-u32-max".as_slice()),
    ];

    for (index, value) in vectors {
        batch.store_reward_batch(index, value)?;
    }

    let listed = sorted_indexed(batch.list_reward_batches()?);

    assert_eq!(listed.len(), vectors.len());

    for (index, value) in vectors {
        assert_eq!(value_for_index(&listed, index), Some(value));
    }

    Ok(())
}

#[test]
fn rock_batch_083_edge_signature_supports_binary_key_and_binary_value() -> TestResult {
    let temp = TempTree::new("rock_batch_083")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let key = [0_u8, 1, 2, 3, 255, 254, 128];
    let value = [255_u8, 0, 42, 99, 100, 101];

    batch.store_batch_signature(&key, &value)?;

    let loaded = batch.load_batch_signature(&key)?;

    assert_eq!(loaded, value);

    Ok(())
}

#[test]
fn rock_batch_084_edge_log_entry_supports_binary_key_and_binary_value() -> TestResult {
    let temp = TempTree::new("rock_batch_084")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let key = [0_u8, 255, 10, 13, 1];
    let value = [8_u8, 6, 7, 5, 3, 0, 9];

    batch.store_log_entry(&key, &value)?;

    let logs = batch.list_log_entries()?;

    assert_eq!(value_for_key(&logs, &key), Some(value.as_slice()));

    Ok(())
}

#[test]
fn rock_batch_085_edge_temp_transactions_support_binary_keys_and_values() -> TestResult {
    let temp = TempTree::new("rock_batch_085")?;
    let batch = open_full_batch(&temp.child("db"))?;

    let entries = vec![
        (vec![0_u8, 1, 2, 3], vec![4_u8, 5, 6]),
        (vec![255_u8, 254, 253], vec![252_u8, 251]),
        (vec![10_u8, 0, 10], vec![0_u8, 0, 1]),
    ];

    batch.store_temp_transactions(&entries)?;

    let listed = batch.list_temp_transactions()?;

    for (key, value) in entries {
        assert_eq!(value_for_key(&listed, &key), Some(value.as_slice()));
    }

    Ok(())
}

#[test]
fn rock_batch_086_edge_store_temp_transactions_allows_empty_key_and_empty_value() -> TestResult {
    let temp = TempTree::new("rock_batch_086")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_temp_transactions(&[(Vec::new(), Vec::new())])?;

    let listed = batch.list_temp_transactions()?;

    assert_eq!(listed.len(), 1);
    assert_eq!(value_for_key(&listed, b""), Some(b"".as_slice()));

    Ok(())
}

#[test]
fn rock_batch_087_edge_transaction_batch_long_keys_with_same_prefix_list_as_same_index()
-> TestResult {
    let temp = TempTree::new("rock_batch_087")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let mut first_key = 87_u64.to_be_bytes().to_vec();
    let mut second_key = 87_u64.to_be_bytes().to_vec();

    first_key.extend_from_slice(b"-first");
    second_key.extend_from_slice(b"-second");

    raw_put_cf(
        &batch,
        RockDbSchema::transaction_batch_column_name(),
        &first_key,
        b"first",
    )?;
    raw_put_cf(
        &batch,
        RockDbSchema::transaction_batch_column_name(),
        &second_key,
        b"second",
    )?;

    let listed = batch.list_unprocessed_batches()?;
    let same_index_count = listed.iter().filter(|(index, _value)| *index == 87).count();

    assert_eq!(same_index_count, 2);

    Ok(())
}

#[test]
fn rock_batch_088_edge_reward_batch_long_keys_with_same_prefix_list_as_same_index() -> TestResult {
    let temp = TempTree::new("rock_batch_088")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let mut first_key = 88_u64.to_be_bytes().to_vec();
    let mut second_key = 88_u64.to_be_bytes().to_vec();

    first_key.extend_from_slice(b"-first");
    second_key.extend_from_slice(b"-second");

    raw_put_cf(
        &batch,
        RockDbSchema::reward_batch_column_name(),
        &first_key,
        b"first-reward",
    )?;
    raw_put_cf(
        &batch,
        RockDbSchema::reward_batch_column_name(),
        &second_key,
        b"second-reward",
    )?;

    let listed = batch.list_reward_batches()?;
    let same_index_count = listed.iter().filter(|(index, _value)| *index == 88).count();

    assert_eq!(same_index_count, 2);

    Ok(())
}

#[test]
fn rock_batch_089_vector_batch_execute_records_writes_expected_debug_meta_for_binary_key()
-> TestResult {
    let temp = TempTree::new("rock_batch_089")?;
    let batch = open_full_batch(&temp.child("db"))?;
    let key = [0_u8, 255, 1, 2];

    batch.store_temp_transaction(&key, b"binary-key-transaction")?;
    batch.batch_execute_records()?;

    let meta = batch.load_batch_signature(&key)?;
    let text = String::from_utf8(meta).map_err(debug_err)?;

    assert!(text.contains("Applied record"));
    assert!(text.contains("255"));

    Ok(())
}

#[test]
fn rock_batch_090_edge_cli_db_rejects_list_log_entries_due_missing_logs_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_090")?;
    let batch = open_cli_batch(&temp.child("cli_db"))?;

    let err = batch
        .list_log_entries()
        .expect_err("default-only CLI DB must not contain logs_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::logs_column_name()));

    Ok(())
}

#[test]
fn rock_batch_091_edge_cli_db_rejects_list_reward_batches_due_missing_reward_batch_cf() -> TestResult
{
    let temp = TempTree::new("rock_batch_091")?;
    let batch = open_cli_batch(&temp.child("cli_db"))?;

    let err = batch
        .list_reward_batches()
        .expect_err("default-only CLI DB must not contain reward_batch_data CF");

    assert!(err.contains("Column Family"));
    assert!(err.contains(RockDbSchema::reward_batch_column_name()));

    Ok(())
}

#[test]
fn rock_batch_092_edge_cli_db_rejects_store_reward_due_missing_reward_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_092")?;
    let batch = open_cli_batch(&temp.child("cli_db"))?;

    let err = batch
        .store_reward(b"reward-id", b"reward-bytes")
        .expect_err("default-only CLI DB must not contain reward_data CF");

    assert!(err.contains("CF"));
    assert!(err.contains(RockDbSchema::reward_column_name()));

    Ok(())
}

#[test]
fn rock_batch_093_edge_cli_db_rejects_store_transaction_due_missing_transaction_cf() -> TestResult {
    let temp = TempTree::new("rock_batch_093")?;
    let batch = open_cli_batch(&temp.child("cli_db"))?;

    let err = batch
        .store_transaction(b"tx-id", b"tx-bytes")
        .expect_err("default-only CLI DB must not contain transaction_data CF");

    assert!(err.contains("CF"));
    assert!(err.contains(RockDbSchema::transaction_column_name()));

    Ok(())
}

#[test]
fn rock_batch_094_vector_log_schema_allows_multiple_ordered_log_entries() -> TestResult {
    let temp = TempTree::new("rock_batch_094")?;
    let directory = DirectoryDB::from_base_dir(&temp.child("node"))?;
    let batch = open_log_batch(&directory)?;

    batch.store_log_entry(b"log-c", b"value-c")?;
    batch.store_log_entry(b"log-a", b"value-a")?;
    batch.store_log_entry(b"log-b", b"value-b")?;

    let logs = sorted_kv(batch.list_log_entries()?);

    assert_eq!(logs.len(), 3);
    assert_eq!(logs[0], (b"log-a".to_vec(), b"value-a".to_vec()));
    assert_eq!(logs[1], (b"log-b".to_vec(), b"value-b".to_vec()));
    assert_eq!(logs[2], (b"log-c".to_vec(), b"value-c".to_vec()));

    Ok(())
}

#[test]
fn rock_batch_095_edge_batch_execute_records_overwrites_existing_meta_for_same_key() -> TestResult {
    let temp = TempTree::new("rock_batch_095")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_batch_signature(b"same-meta-key", b"old-meta-value")?;
    batch.store_temp_transaction(b"same-meta-key", b"transaction-value")?;
    batch.batch_execute_records()?;

    let meta = batch.load_batch_signature(b"same-meta-key")?;
    let text = String::from_utf8(meta).map_err(debug_err)?;

    assert!(text.contains("Applied record"));
    assert!(!text.contains("old-meta-value"));

    Ok(())
}

#[test]
fn rock_batch_096_vector_batch_execute_records_preserves_unrelated_signature_meta() -> TestResult {
    let temp = TempTree::new("rock_batch_096")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_batch_signature(b"unrelated-signature-key", b"signature-value")?;
    batch.store_temp_transaction(b"transaction-key", b"transaction-value")?;
    batch.batch_execute_records()?;

    let loaded = batch.load_batch_signature(b"unrelated-signature-key")?;

    assert_eq!(loaded, b"signature-value");

    Ok(())
}

#[test]
fn rock_batch_097_edge_store_transaction_empty_key_then_execute_fails() -> TestResult {
    let temp = TempTree::new("rock_batch_097")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction(b"", b"stored-through-transaction-writer")?;

    let err = batch
        .batch_execute_records()
        .expect_err("empty transaction key must fail batch execution");

    assert!(err.contains("Record invalid"));

    Ok(())
}

#[test]
fn rock_batch_098_edge_store_reward_supports_empty_value() -> TestResult {
    let temp = TempTree::new("rock_batch_098")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_reward(b"reward-empty-value", b"")?;

    let stored = raw_get_cf(
        &batch,
        RockDbSchema::reward_column_name(),
        b"reward-empty-value",
    )?
    .ok_or_else(|| "reward with empty value missing".to_owned())?;

    assert_eq!(stored, b"");

    Ok(())
}

#[test]
fn rock_batch_099_edge_open_db_blockchain_with_spaces_and_dots_in_path() -> TestResult {
    let temp = TempTree::new("rock_batch_099")?;
    let path = temp
        .child("node with spaces.and.dots")
        .join("blockchain db");

    let batch = open_full_batch(&path)?;
    drop(batch);

    RockDbSchema::validate_column_families(&path, &expected_full_cf_names())?;

    Ok(())
}

#[test]
fn rock_batch_100_vector_transaction_and_reward_batches_keep_separate_column_families() -> TestResult
{
    let temp = TempTree::new("rock_batch_100")?;
    let batch = open_full_batch(&temp.child("db"))?;

    batch.store_transaction_batch(100, b"transaction-batch-value")?;
    batch.store_reward_batch(100, b"reward-batch-value")?;

    let transaction_batches = batch.list_unprocessed_batches()?;
    let reward_batches = batch.list_reward_batches()?;

    assert_eq!(
        value_for_index(&transaction_batches, 100),
        Some(b"transaction-batch-value".as_slice())
    );
    assert_eq!(
        value_for_index(&reward_batches, 100),
        Some(b"reward-batch-value".as_slice())
    );

    Ok(())
}
