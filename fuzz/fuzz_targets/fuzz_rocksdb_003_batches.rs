#![no_main]

/*
    fuzz_rocksdb_003_batches.rs

    MEMORY-ONLY / NO-REAL-ROCKSDB fuzz target for:

        src/storage/rocksdb_003_batches.rs

    Important:
    - Does NOT use remzar = { path = ".." }
    - Does NOT use the real rust-rocksdb crate
    - Does NOT open a real RocksDB database
    - Does NOT create database directories
    - Uses:
          extern crate self as rust_rocksdb;
      so production lines like:
          use rust_rocksdb::{ColumnFamily, DB, IteratorMode, WriteBatch};
      resolve to the fake in-memory types below.

    This runs the real RockBatch methods against a fake in-memory DB.
*/

extern crate self as rust_rocksdb;

use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

/* ─────────────────────────────────────────────────────────────
   Fake rust_rocksdb API
   ───────────────────────────────────────────────────────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DBCompressionType {
    None,
    Snappy,
    Lz4,
    Zstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DBCompactionStyle {
    Level,
    Universal,
    Fifo,
}

#[derive(Debug, Clone, Default)]
pub struct UniversalCompactOptions {
    pub min_merge_width: i32,
    pub max_merge_width: i32,
    pub size_ratio: i32,
}

impl UniversalCompactOptions {
    pub fn set_min_merge_width(&mut self, v: i32) {
        self.min_merge_width = v;
    }

    pub fn set_max_merge_width(&mut self, v: i32) {
        self.max_merge_width = v;
    }

    pub fn set_size_ratio(&mut self, v: i32) {
        self.size_ratio = v;
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub create_if_missing: bool,
    pub create_missing_column_families: bool,
    pub write_buffer_size: usize,
    pub max_write_buffer_number: i32,
    pub min_write_buffer_number_to_merge: i32,
    pub target_file_size_base: u64,
    pub max_background_jobs: i32,
    pub max_open_files: i32,
    pub level_compaction_dynamic_level_bytes: bool,
    pub use_direct_io_for_flush_and_compaction: bool,
    pub use_direct_reads: bool,
    pub paranoid_checks: bool,
    pub compression_type: DBCompressionType,
    pub bottommost_compression_type: DBCompressionType,
    pub parallelism: i32,
    pub compaction_style: DBCompactionStyle,
    pub disable_auto_compactions: bool,
    pub keep_log_file_num: usize,
    pub max_log_file_size: usize,
    pub universal_min_merge_width: i32,
    pub universal_max_merge_width: i32,
    pub universal_size_ratio: i32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            create_if_missing: false,
            create_missing_column_families: false,
            write_buffer_size: 0,
            max_write_buffer_number: 0,
            min_write_buffer_number_to_merge: 0,
            target_file_size_base: 0,
            max_background_jobs: 0,
            max_open_files: 0,
            level_compaction_dynamic_level_bytes: false,
            use_direct_io_for_flush_and_compaction: false,
            use_direct_reads: false,
            paranoid_checks: false,
            compression_type: DBCompressionType::None,
            bottommost_compression_type: DBCompressionType::None,
            parallelism: 0,
            compaction_style: DBCompactionStyle::Level,
            disable_auto_compactions: false,
            keep_log_file_num: 0,
            max_log_file_size: 0,
            universal_min_merge_width: 0,
            universal_max_merge_width: 0,
            universal_size_ratio: 0,
        }
    }
}

impl Options {
    pub fn create_if_missing(&mut self, v: bool) {
        self.create_if_missing = v;
    }

    pub fn create_missing_column_families(&mut self, v: bool) {
        self.create_missing_column_families = v;
    }

    pub fn set_write_buffer_size(&mut self, v: usize) {
        self.write_buffer_size = v;
    }

    pub fn set_max_write_buffer_number(&mut self, v: i32) {
        self.max_write_buffer_number = v;
    }

    pub fn set_min_write_buffer_number_to_merge(&mut self, v: i32) {
        self.min_write_buffer_number_to_merge = v;
    }

    pub fn set_target_file_size_base(&mut self, v: u64) {
        self.target_file_size_base = v;
    }

    pub fn set_max_background_jobs(&mut self, v: i32) {
        self.max_background_jobs = v;
    }

    pub fn set_max_open_files(&mut self, v: i32) {
        self.max_open_files = v;
    }

    pub fn set_level_compaction_dynamic_level_bytes(&mut self, v: bool) {
        self.level_compaction_dynamic_level_bytes = v;
    }

    pub fn set_use_direct_io_for_flush_and_compaction(&mut self, v: bool) {
        self.use_direct_io_for_flush_and_compaction = v;
    }

    pub fn set_use_direct_reads(&mut self, v: bool) {
        self.use_direct_reads = v;
    }

    pub fn set_paranoid_checks(&mut self, v: bool) {
        self.paranoid_checks = v;
    }

    pub fn set_compression_type(&mut self, v: DBCompressionType) {
        self.compression_type = v;
    }

    pub fn set_bottommost_compression_type(&mut self, v: DBCompressionType) {
        self.bottommost_compression_type = v;
    }

    pub fn increase_parallelism(&mut self, v: i32) {
        self.parallelism = v;
    }

    pub fn set_compaction_style(&mut self, v: DBCompactionStyle) {
        self.compaction_style = v;
    }

    pub fn set_universal_compaction_options(&mut self, v: &UniversalCompactOptions) {
        self.universal_min_merge_width = v.min_merge_width;
        self.universal_max_merge_width = v.max_merge_width;
        self.universal_size_ratio = v.size_ratio;
    }

    pub fn set_disable_auto_compactions(&mut self, v: bool) {
        self.disable_auto_compactions = v;
    }

    pub fn set_keep_log_file_num(&mut self, v: usize) {
        self.keep_log_file_num = v;
    }

    pub fn set_max_log_file_size(&mut self, v: usize) {
        self.max_log_file_size = v;
    }
}

#[derive(Debug, Clone)]
pub struct ColumnFamilyDescriptor {
    name: String,
    options: Options,
}

impl ColumnFamilyDescriptor {
    pub fn new(name: impl Into<String>, options: Options) -> Self {
        Self {
            name: name.into(),
            options,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn options(&self) -> &Options {
        &self.options
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ColumnFamily {
    name: String,
}

impl ColumnFamily {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IteratorMode {
    Start,
}

#[derive(Debug, Clone)]
pub struct StubRockDbError {
    details: String,
}

impl StubRockDbError {
    fn new(details: impl Into<String>) -> Self {
        Self {
            details: details.into(),
        }
    }
}

impl std::fmt::Display for StubRockDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl std::error::Error for StubRockDbError {}

#[derive(Debug, Clone, Default)]
pub struct WriteBatch {
    ops: Vec<BatchOp>,
}

#[derive(Debug, Clone)]
struct BatchOp {
    cf_name: String,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl WriteBatch {
    pub fn put_cf<K, V>(&mut self, cf: &ColumnFamily, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.ops.push(BatchOp {
            cf_name: cf.name().to_string(),
            key: key.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
        });
    }
}

#[derive(Debug)]
pub struct DB {
    cfs: BTreeMap<String, ColumnFamily>,
    data: Mutex<BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl DB {
    fn new_with_cf_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut cfs = BTreeMap::<String, ColumnFamily>::new();
        let mut data = BTreeMap::<String, BTreeMap<Vec<u8>, Vec<u8>>>::new();

        for name in names {
            let name = name.into();

            cfs.entry(name.clone())
                .or_insert_with(|| ColumnFamily { name: name.clone() });

            data.entry(name).or_default();
        }

        cfs.entry("default".to_string())
            .or_insert_with(|| ColumnFamily {
                name: "default".to_string(),
            });

        data.entry("default".to_string()).or_default();

        Self {
            cfs,
            data: Mutex::new(data),
        }
    }

    pub fn open<P: AsRef<Path>>(_opts: &Options, _path: P) -> Result<Self, StubRockDbError> {
        Ok(Self::new_with_cf_names(["default"]))
    }

    pub fn open_cf_descriptors<P: AsRef<Path>>(
        _opts: &Options,
        _path: P,
        cf_descriptors: Vec<ColumnFamilyDescriptor>,
    ) -> Result<Self, StubRockDbError> {
        let names = cf_descriptors
            .into_iter()
            .map(|d| d.name().to_string())
            .collect::<Vec<_>>();

        Ok(Self::new_with_cf_names(names))
    }

    pub fn open_for_read_only<P: AsRef<Path>>(
        _opts: &Options,
        path: P,
        _error_if_log_file_exist: bool,
    ) -> Result<Self, StubRockDbError> {
        Err(StubRockDbError::new(format!(
            "read-only real RocksDB open disabled in fuzz target: {}",
            path.as_ref().display()
        )))
    }

    pub fn list_cf<P: AsRef<Path>>(
        _opts: &Options,
        path: P,
    ) -> Result<Vec<String>, StubRockDbError> {
        Err(StubRockDbError::new(format!(
            "real RocksDB list_cf disabled in fuzz target: {}",
            path.as_ref().display()
        )))
    }

    pub fn cf_handle(&self, name: &str) -> Option<&ColumnFamily> {
        self.cfs.get(name)
    }

    pub fn write(&self, batch: &WriteBatch) -> Result<(), StubRockDbError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| StubRockDbError::new("fake DB mutex poisoned"))?;

        for op in &batch.ops {
            if !self.cfs.contains_key(&op.cf_name) {
                return Err(StubRockDbError::new(format!(
                    "missing column family {}",
                    op.cf_name
                )));
            }

            data.entry(op.cf_name.clone())
                .or_default()
                .insert(op.key.clone(), op.value.clone());
        }

        Ok(())
    }

    pub fn get_cf<K>(&self, cf: &ColumnFamily, key: K) -> Result<Option<Vec<u8>>, StubRockDbError>
    where
        K: AsRef<[u8]>,
    {
        let data = self
            .data
            .lock()
            .map_err(|_| StubRockDbError::new("fake DB mutex poisoned"))?;

        Ok(data
            .get(cf.name())
            .and_then(|m| m.get(key.as_ref()).cloned()))
    }

    pub fn iterator_cf(&self, cf: &ColumnFamily, _mode: IteratorMode) -> DBIterator {
        let rows = self
            .data
            .lock()
            .ok()
            .and_then(|data| data.get(cf.name()).cloned())
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| Ok((k, v)))
            .collect::<Vec<_>>();

        DBIterator {
            inner: rows.into_iter(),
        }
    }
}

pub struct DBIterator {
    inner: std::vec::IntoIter<Result<(Vec<u8>, Vec<u8>), StubRockDbError>>,
}

impl Iterator for DBIterator {
    type Item = Result<(Vec<u8>, Vec<u8>), StubRockDbError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/* ─────────────────────────────────────────────────────────────
   Utility shims
   ───────────────────────────────────────────────────────────── */

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const META_DATA_COLUMN_NAME: &'static str = "meta_data";
            pub const GLOBAL_COLUMN_NAME: &'static str = "global_data";
            pub const ACCOUNT_COLUMN_NAME: &'static str = "account_data";
            pub const NETWORK_COLUMN_NAME: &'static str = "network_data";
            pub const SIDECHAIN_COLUMN_NAME: &'static str = "sidechain_data";
            pub const STATE_COLUMN_NAME: &'static str = "state_data";
            pub const TRANSACTION_COLUMN_NAME: &'static str = "transaction_data";
            pub const TRANSACTION_BATCH_COLUMN_NAME: &'static str = "transaction_batch_data";
            pub const REWARD_COLUMN_NAME: &'static str = "reward_data";
            pub const REWARD_BATCH_COLUMN_NAME: &'static str = "reward_batch_data";
            pub const BLOCKMINT_DATA_COLUMN_NAME: &'static str = "blockmint_data";
            pub const LOGS_COLUMN_NAME: &'static str = "logs_data";
            pub const BLOCK_TO_HASH_COLUMN_NAME: &'static str = "block_to_hash";
            pub const TX_TO_HASH_COLUMN_NAME: &'static str = "tx_to_hash";
            pub const IDENTITY_COLUMN_NAME: &'static str = "identity_data";
            pub const BLOCK_META_BY_HASH_COLUMN_NAME: &'static str = "block_meta_by_hash";
            pub const BATCH_BY_BLOCK_HASH_COLUMN_NAME: &'static str = "batch_by_block_hash";
            pub const CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME: &'static str =
                "canonical_height_to_hash";
            pub const CANONICAL_CHAIN_VIEW_COLUMN_NAME: &'static str = "canonical_chain_view";
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            DatabaseError {
                details: String,
            },
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::DatabaseError { details } => {
                        write!(f, "DatabaseError(details={details})")
                    }
                    Self::ValidationError { message, tx_id } => {
                        write!(f, "ValidationError(message={message}, tx_id={tx_id:?})")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod helper {
        pub type KVVecResult = Result<Vec<(Vec<u8>, Vec<u8>)>, String>;
    }
}

/* ─────────────────────────────────────────────────────────────
   Storage module shape expected by production files
   ───────────────────────────────────────────────────────────── */

mod storage {
    pub mod rocksdb_000_directory {
        use std::path::PathBuf;

        #[derive(Debug, Clone)]
        pub struct DirectoryDB {
            pub wallets_path: PathBuf,
            pub db_path: PathBuf,
            pub blockchain_path: PathBuf,
            pub registry_path: PathBuf,
            pub accountmodel_path: PathBuf,
            pub sidechain_path: PathBuf,
            pub log_path: PathBuf,
            pub audit_reports_path: PathBuf,
            pub peerlist_path: PathBuf,
        }
    }

    pub use crate::rocksdb_001_cf_descriptors;
    pub use crate::rocksdb_002_schema;
}

/* ─────────────────────────────────────────────────────────────
   Pull in real production files
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/storage/rocksdb_001_cf_descriptors.rs"]
pub mod rocksdb_001_cf_descriptors;

#[path = "../../src/storage/rocksdb_002_schema.rs"]
pub mod rocksdb_002_schema;

#[path = "../../src/storage/rocksdb_003_batches.rs"]
pub mod rocksdb_003_batches;

/* ─────────────────────────────────────────────────────────────
   Imports
   ───────────────────────────────────────────────────────────── */

use crate::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::rocksdb_002_schema::RockDbSchema;
use crate::rocksdb_003_batches::RockBatch;

/* ─────────────────────────────────────────────────────────────
   Main fuzz entry
   ───────────────────────────────────────────────────────────── */

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] % 10;
    let body = &data[1..];

    match mode {
        0 => fuzz_open_helpers(body),
        1 => fuzz_transaction_batch_roundtrip(body),
        2 => fuzz_reward_batch_roundtrip(body),
        3 => fuzz_signature_roundtrip(body),
        4 => fuzz_temp_transactions(body),
        5 => fuzz_logs_rewards_transactions(body),
        6 => fuzz_batch_execute_records(body),
        7 => fuzz_missing_cf_errors(body),
        8 => fuzz_malformed_index_keys_are_ignored(body),
        _ => fuzz_state_machine(body),
    }
});

/* ─────────────────────────────────────────────────────────────
   DB helpers
   ───────────────────────────────────────────────────────────── */

fn make_full_fake_db() -> DB {
    let opts = RockDbSchema::robust_db_options();
    let cfs = CFDescriptors::get_cf_descriptors();

    DB::open_cf_descriptors(&opts, "/memory/remzar/full", cfs)
        .expect("fake full DB should open")
}

fn make_default_only_fake_db() -> DB {
    let opts = RockDbSchema::robust_db_options();

    DB::open(&opts, "/memory/remzar/default-only")
        .expect("fake default-only DB should open")
}

fn make_batch_full() -> RockBatch {
    RockBatch {
        db: Arc::new(make_full_fake_db()),
    }
}

fn make_batch_default_only() -> RockBatch {
    RockBatch {
        db: Arc::new(make_default_only_fake_db()),
    }
}

/* ─────────────────────────────────────────────────────────────
   Fuzz cases
   ───────────────────────────────────────────────────────────── */

fn fuzz_open_helpers(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let path = make_fake_path(&mut r);

    let cli = RockBatch::open_db_cli(&path);
    assert!(cli.is_ok());

    let blockchain = RockBatch::open_db_blockchain(&path);
    assert!(blockchain.is_ok());

    let cli_db = cli.unwrap();
    assert!(cli_db.cf_handle("default").is_some());

    let blockchain_db = blockchain.unwrap();
    assert!(blockchain_db
        .cf_handle(RockDbSchema::transaction_column_name())
        .is_some());
    assert!(blockchain_db
        .cf_handle(RockDbSchema::transaction_batch_column_name())
        .is_some());
    assert!(blockchain_db
        .cf_handle(RockDbSchema::reward_batch_column_name())
        .is_some());
}

fn fuzz_transaction_batch_roundtrip(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let count = 1 + r.next_usize(16);
    let mut expected = BTreeMap::<u64, Vec<u8>>::new();

    for _ in 0..count {
        let index = r.next_u64();
        let value = make_bytes(&mut r, 256);

        assert!(rb.store_transaction_batch(index, &value).is_ok());
        expected.insert(index, value);
    }

    let listed = rb
        .list_unprocessed_batches()
        .expect("list_unprocessed_batches should work");

    let actual = listed.into_iter().collect::<BTreeMap<u64, Vec<u8>>>();

    for (k, v) in expected {
        assert_eq!(actual.get(&k), Some(&v));
    }
}

fn fuzz_reward_batch_roundtrip(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let count = 1 + r.next_usize(16);
    let mut expected = BTreeMap::<u64, Vec<u8>>::new();

    for _ in 0..count {
        let index = r.next_u64();
        let value = make_bytes(&mut r, 256);

        assert!(rb.store_reward_batch(index, &value).is_ok());
        expected.insert(index, value);
    }

    let listed = rb
        .list_reward_batches()
        .expect("list_reward_batches should work");

    let actual = listed.into_iter().collect::<BTreeMap<u64, Vec<u8>>>();

    for (k, v) in expected {
        assert_eq!(actual.get(&k), Some(&v));
    }
}

fn fuzz_signature_roundtrip(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let key = make_nonempty_bytes(&mut r, 128);
    let signature = make_bytes(&mut r, 512);

    assert!(rb.store_batch_signature(&key, &signature).is_ok());

    let loaded = rb
        .load_batch_signature(&key)
        .expect("stored signature should load");

    assert_eq!(loaded, signature);

    let missing_key = make_different_key(&key);
    assert!(rb.load_batch_signature(&missing_key).is_err());
}

fn fuzz_temp_transactions(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let count = 1 + r.next_usize(16);
    let mut expected = BTreeMap::<Vec<u8>, Vec<u8>>::new();

    for _ in 0..count {
        let key = make_bytes(&mut r, 96);
        let val = make_bytes(&mut r, 256);

        assert!(rb.store_temp_transaction(&key, &val).is_ok());
        expected.insert(key, val);
    }

    let batch_count = r.next_usize(16);
    let mut batch_items = Vec::<(Vec<u8>, Vec<u8>)>::with_capacity(batch_count);

    for _ in 0..batch_count {
        let key = make_bytes(&mut r, 96);
        let val = make_bytes(&mut r, 256);

        expected.insert(key.clone(), val.clone());
        batch_items.push((key, val));
    }

    assert!(rb.store_temp_transactions(&batch_items).is_ok());

    let listed = rb
        .list_temp_transactions()
        .expect("list_temp_transactions should work");

    let actual = listed.into_iter().collect::<BTreeMap<Vec<u8>, Vec<u8>>>();

    for (k, v) in expected {
        assert_eq!(actual.get(&k), Some(&v));
    }
}

fn fuzz_logs_rewards_transactions(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let log_key = make_bytes(&mut r, 96);
    let log_val = make_bytes(&mut r, 256);

    assert!(rb.store_log_entry(&log_key, &log_val).is_ok());

    let logs = rb.list_log_entries().expect("list logs should work");
    assert!(logs.iter().any(|(k, v)| k == &log_key && v == &log_val));

    let reward_key = make_bytes(&mut r, 96);
    let reward_val = make_bytes(&mut r, 256);

    assert!(rb.store_reward(&reward_key, &reward_val).is_ok());

    let reward_cf = rb
        .db
        .cf_handle(RockDbSchema::reward_column_name())
        .expect("reward CF should exist");

    assert_eq!(
        rb.db.get_cf(reward_cf, &reward_key).unwrap(),
        Some(reward_val)
    );

    let tx_key = make_bytes(&mut r, 96);
    let tx_val = make_bytes(&mut r, 256);

    assert!(rb.store_transaction(&tx_key, &tx_val).is_ok());

    let tx_cf = rb
        .db
        .cf_handle(RockDbSchema::transaction_column_name())
        .expect("transaction CF should exist");

    assert_eq!(rb.db.get_cf(tx_cf, &tx_key).unwrap(), Some(tx_val));
}

fn fuzz_batch_execute_records(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let valid_count = r.next_usize(16);

    for _ in 0..valid_count {
        let key = make_nonempty_bytes(&mut r, 96);
        let value = make_nonempty_bytes(&mut r, 256);

        assert!(rb.store_temp_transaction(&key, &value).is_ok());
    }

    let insert_invalid = r.next_bool();

    if insert_invalid {
        let key = if r.next_bool() {
            Vec::new()
        } else {
            make_nonempty_bytes(&mut r, 96)
        };

        let value = if r.next_bool() {
            Vec::new()
        } else {
            make_nonempty_bytes(&mut r, 256)
        };

        assert!(rb.store_temp_transaction(&key, &value).is_ok());

        if key.is_empty() || value.is_empty() {
            assert!(rb.batch_execute_records().is_err());
            return;
        }
    }

    assert!(rb.batch_execute_records().is_ok());

    let txs = rb
        .list_temp_transactions()
        .expect("temp tx list should still work");

    let meta_cf = rb
        .db
        .cf_handle(RockDbSchema::meta_data_column_name())
        .expect("meta CF should exist");

    for (key, value) in txs {
        if !key.is_empty() && !value.is_empty() {
            let stored = rb.db.get_cf(meta_cf, &key).unwrap();
            assert!(stored.is_some());
        }
    }
}

fn fuzz_missing_cf_errors(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_default_only();

    let key = make_bytes(&mut r, 64);
    let val = make_bytes(&mut r, 128);

    assert!(rb.store_transaction_batch(r.next_u64(), &val).is_err());
    assert!(rb.list_unprocessed_batches().is_err());

    assert!(rb.store_batch_signature(&key, &val).is_err());
    assert!(rb.load_batch_signature(&key).is_err());

    assert!(rb.batch_execute_records().is_err());

    assert!(rb.store_temp_transaction(&key, &val).is_err());
    assert!(rb.list_temp_transactions().is_err());
    assert!(rb.store_temp_transactions(&[(key.clone(), val.clone())]).is_err());

    assert!(rb.store_log_entry(&key, &val).is_err());
    assert!(rb.list_log_entries().is_err());

    assert!(rb.store_reward_batch(r.next_u64(), &val).is_err());
    assert!(rb.list_reward_batches().is_err());

    assert!(rb.store_reward(&key, &val).is_err());
    assert!(rb.store_transaction(&key, &val).is_err());
}

fn fuzz_malformed_index_keys_are_ignored(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let tx_batch_cf = rb
        .db
        .cf_handle(RockDbSchema::transaction_batch_column_name())
        .expect("transaction_batch CF should exist");

    let reward_batch_cf = rb
        .db
        .cf_handle(RockDbSchema::reward_batch_column_name())
        .expect("reward_batch CF should exist");

    let malformed_count = 1 + r.next_usize(16);

    let mut wb = WriteBatch::default();

    for _ in 0..malformed_count {
        let short_key_len = r.next_usize(8);
        let short_key = make_exact_bytes(&mut r, short_key_len);
        let value = make_bytes(&mut r, 128);

        wb.put_cf(tx_batch_cf, &short_key, &value);
        wb.put_cf(reward_batch_cf, &short_key, &value);
    }

    rb.db.write(&wb).expect("fake DB write should succeed");

    let tx_batches = rb
        .list_unprocessed_batches()
        .expect("listing tx batches should succeed");

    let reward_batches = rb
        .list_reward_batches()
        .expect("listing reward batches should succeed");

    assert!(tx_batches.is_empty());
    assert!(reward_batches.is_empty());

    let good_index = r.next_u64();
    let good_value = make_bytes(&mut r, 128);

    assert!(rb
        .store_transaction_batch(good_index, &good_value)
        .is_ok());

    let tx_batches = rb.list_unprocessed_batches().unwrap();
    assert!(tx_batches
        .iter()
        .any(|(idx, v)| *idx == good_index && v == &good_value));
}

fn fuzz_state_machine(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let rb = make_batch_full();

    let steps = 1 + r.next_usize(64);

    for _ in 0..steps {
        match r.next_u8() % 9 {
            0 => {
                let value = make_bytes(&mut r, 128);
                let _ = rb.store_transaction_batch(r.next_u64(), &value);
            }
            1 => {
                let value = make_bytes(&mut r, 128);
                let _ = rb.store_reward_batch(r.next_u64(), &value);
            }
            2 => {
                let key = make_bytes(&mut r, 64);
                let val = make_bytes(&mut r, 128);
                let _ = rb.store_batch_signature(&key, &val);
                let _ = rb.load_batch_signature(&key);
            }
            3 => {
                let key = make_bytes(&mut r, 64);
                let val = make_bytes(&mut r, 128);
                let _ = rb.store_temp_transaction(&key, &val);
            }
            4 => {
                let txs = make_kv_vec(&mut r, 8, 64, 128);
                let _ = rb.store_temp_transactions(&txs);
            }
            5 => {
                let key = make_bytes(&mut r, 64);
                let val = make_bytes(&mut r, 128);
                let _ = rb.store_log_entry(&key, &val);
            }
            6 => {
                let key = make_bytes(&mut r, 64);
                let val = make_bytes(&mut r, 128);
                let _ = rb.store_reward(&key, &val);
                let _ = rb.store_transaction(&key, &val);
            }
            7 => {
                let _ = rb.list_unprocessed_batches();
                let _ = rb.list_reward_batches();
                let _ = rb.list_temp_transactions();
                let _ = rb.list_log_entries();
            }
            _ => {
                let _ = rb.batch_execute_records();
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Input helpers
   ───────────────────────────────────────────────────────────── */

fn make_bytes(r: &mut FuzzBytes<'_>, max_len: usize) -> Vec<u8> {
    let len = r.next_usize(max_len.saturating_add(1));
    make_exact_bytes(r, len)
}

fn make_nonempty_bytes(r: &mut FuzzBytes<'_>, max_len: usize) -> Vec<u8> {
    let len = 1 + r.next_usize(max_len.max(1));
    make_exact_bytes(r, len)
}

fn make_exact_bytes(r: &mut FuzzBytes<'_>, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for _ in 0..len {
        out.push(r.next_u8());
    }

    out
}

fn make_different_key(key: &[u8]) -> Vec<u8> {
    let mut out = key.to_vec();

    if out.is_empty() {
        out.push(1);
    } else {
        out[0] ^= 0xA5;
    }

    out
}

fn make_kv_vec(
    r: &mut FuzzBytes<'_>,
    max_count: usize,
    max_key_len: usize,
    max_val_len: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let count = r.next_usize(max_count.saturating_add(1));
    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        out.push((make_bytes(r, max_key_len), make_bytes(r, max_val_len)));
    }

    out
}

fn make_fake_path(r: &mut FuzzBytes<'_>) -> String {
    let mut s = String::from("/memory/remzar-fuzz-batches");

    let parts = 1 + r.next_usize(4);

    for i in 0..parts {
        s.push('/');
        s.push('p');
        s.push_str(&i.to_string());
        s.push('_');

        let len = 1 + r.next_usize(16);

        for _ in 0..len {
            let b = r.next_u8();

            let c = match b % 37 {
                0..=9 => char::from(b'0' + (b % 10)),
                10..=35 => char::from(b'a' + ((b - 10) % 26)),
                _ => '_',
            };

            s.push(c);
        }
    }

    s
}

/* ─────────────────────────────────────────────────────────────
   Deterministic byte reader
   ───────────────────────────────────────────────────────────── */

struct FuzzBytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FuzzBytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }

        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];

        for b in &mut out {
            *b = self.next_u8();
        }

        u64::from_le_bytes(out)
    }

    fn next_usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }

        (self.next_u64() as usize) % max_exclusive
    }
}