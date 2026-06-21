#![no_main]

extern crate self as rust_rocksdb;

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone)]
pub struct DB;

#[derive(Debug, Clone)]
pub struct StubRockDbError {
    details: String,
}

impl StubRockDbError {
    fn disabled(op: &str, path: &Path) -> Self {
        Self {
            details: format!(
                "real RocksDB operation disabled in fuzz target: op={op} path={}",
                path.display()
            ),
        }
    }
}

impl std::fmt::Display for StubRockDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl std::error::Error for StubRockDbError {}

impl DB {
    pub fn open_cf_descriptors<P: AsRef<Path>>(
        _opts: &Options,
        path: P,
        _cf_descriptors: Vec<ColumnFamilyDescriptor>,
    ) -> Result<Self, StubRockDbError> {
        Err(StubRockDbError::disabled(
            "open_cf_descriptors",
            path.as_ref(),
        ))
    }

    pub fn open_for_read_only<P: AsRef<Path>>(
        _opts: &Options,
        path: P,
        _error_if_log_file_exist: bool,
    ) -> Result<Self, StubRockDbError> {
        Err(StubRockDbError::disabled(
            "open_for_read_only",
            path.as_ref(),
        ))
    }

    pub fn list_cf<P: AsRef<Path>>(
        _opts: &Options,
        path: P,
    ) -> Result<Vec<String>, StubRockDbError> {
        Err(StubRockDbError::disabled("list_cf", path.as_ref()))
    }
}

/* ─────────────────────────────────────────────────────────────
   Minimal utility shims needed by rocksdb_001 + rocksdb_002.
   ───────────────────────────────────────────────────────────── */

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const META_DATA_COLUMN_NAME: &'static str = "meta_data";
            pub const GLOBAL_COLUMN_NAME: &'static str = "global_metadata";
            pub const ACCOUNT_COLUMN_NAME: &'static str = "wallet_accounts";
            pub const NETWORK_COLUMN_NAME: &'static str = "network_data";
            pub const SIDECHAIN_COLUMN_NAME: &'static str = "sidechain_data";
            pub const STATE_COLUMN_NAME: &'static str = "state_data";
            pub const TRANSACTION_COLUMN_NAME: &'static str = "transaction_data";
            pub const TRANSACTION_BATCH_COLUMN_NAME: &'static str = "transaction_batch_data";
            pub const REWARD_COLUMN_NAME: &'static str = "reward_data";
            pub const REWARD_BATCH_COLUMN_NAME: &'static str = "reward_batch_data";
            pub const BLOCKMINT_DATA_COLUMN_NAME: &'static str = "blockmint_data";
            pub const LOGS_COLUMN_NAME: &'static str = "logs_data";
            pub const BLOCK_TO_HASH_COLUMN_NAME: &'static str = "blockhash_data";
            pub const TX_TO_HASH_COLUMN_NAME: &'static str = "txhash_data";
            pub const IDENTITY_COLUMN_NAME: &'static str = "node_identity_data";
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
}

/* ─────────────────────────────────────────────────────────────
   Storage shim for DirectoryDB.

   Only a path container. No filesystem calls.
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

        impl DirectoryDB {
            pub fn new_for_fuzz(base: PathBuf) -> Self {
                Self {
                    wallets_path: base.join("wallets"),
                    db_path: base.join("cli_db"),
                    blockchain_path: base.join("blockchain_db"),
                    registry_path: base.join("registry_db"),
                    accountmodel_path: base.join("accountmodel_db"),
                    sidechain_path: base.join("sidechain_db"),
                    log_path: base.join("log_db"),
                    audit_reports_path: base.join("audit_reports"),
                    peerlist_path: base.join("peerlist"),
                }
            }
        }
    }

    pub use crate::rocksdb_001_cf_descriptors;
}

/* ─────────────────────────────────────────────────────────────
   Pull in the real production files.
   Do NOT use include!().
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/storage/rocksdb_001_cf_descriptors.rs"]
pub mod rocksdb_001_cf_descriptors;

#[path = "../../src/storage/rocksdb_002_schema.rs"]
pub mod rocksdb_002_schema;

/* ─────────────────────────────────────────────────────────────
   Imports
   ───────────────────────────────────────────────────────────── */

use crate::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::rocksdb_002_schema::RockDbSchema;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;

/* ─────────────────────────────────────────────────────────────
   Main fuzz entry
   ───────────────────────────────────────────────────────────── */

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] % 9;
    let body = &data[1..];

    match mode {
        0 => fuzz_schema_column_name_getters(body),
        1 => fuzz_cf_descriptors_have_required_schema_names(body),
        2 => fuzz_cf_descriptor_clone_preserves_name(body),
        3 => fuzz_options_construction(body),
        4 => fuzz_snapshot_options_construction(body),
        5 => fuzz_fake_directory_shape(body),
        6 => fuzz_descriptor_name_invariants(body),
        7 => fuzz_disabled_db_calls_return_errors(body),
        _ => fuzz_mixed_sequence(body),
    }
});

/* ─────────────────────────────────────────────────────────────
   Fuzz cases
   ───────────────────────────────────────────────────────────── */

fn fuzz_schema_column_name_getters(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let names = schema_column_names();

    assert!(!names.is_empty());
    assert_unique_nonempty_ascii_names(&names);

    assert_eq!(
        RockDbSchema::meta_data_column_name(),
        GlobalConfiguration::META_DATA_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::global_column_name(),
        GlobalConfiguration::GLOBAL_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::account_column_name(),
        GlobalConfiguration::ACCOUNT_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::network_column_name(),
        GlobalConfiguration::NETWORK_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::sidechain_column_name(),
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::state_column_name(),
        GlobalConfiguration::STATE_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::transaction_column_name(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::transaction_batch_column_name(),
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::reward_column_name(),
        GlobalConfiguration::REWARD_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::reward_batch_column_name(),
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::blockmint_data_column_name(),
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::logs_column_name(),
        GlobalConfiguration::LOGS_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::block_to_hash_column_name(),
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::tx_to_hash_column_name(),
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::block_meta_by_hash_column_name(),
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::batch_by_block_hash_column_name(),
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::canonical_height_to_hash_column_name(),
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
    );
    assert_eq!(
        RockDbSchema::canonical_chain_view_column_name(),
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME
    );

    let idx = r.next_usize(names.len());
    assert_valid_cf_name(names[idx]);
}

fn fuzz_cf_descriptors_have_required_schema_names(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let descriptors = CFDescriptors::get_cf_descriptors();
    let descriptor_names = cf_descriptor_names(&descriptors);

    assert!(!descriptor_names.is_empty());
    assert!(descriptor_names.iter().any(|n| n == "default"));
    assert_unique_string_names(&descriptor_names);

    for name in &descriptor_names {
        assert_valid_cf_name(name);
    }

    for required_name in required_cf_names() {
        assert!(
            descriptor_names.iter().any(|name| name == required_name),
            "missing required CF descriptor: {required_name}"
        );
    }

    let idx = r.next_usize(descriptor_names.len());
    assert_valid_cf_name(&descriptor_names[idx]);
}

fn fuzz_cf_descriptor_clone_preserves_name(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let descriptors = CFDescriptors::get_cf_descriptors();
    assert!(!descriptors.is_empty());

    for descriptor in &descriptors {
        let cloned = CFDescriptors::clone_column_family_descriptor(descriptor);

        assert_eq!(cloned.name(), descriptor.name());
        assert_valid_cf_name(cloned.name());
    }

    let idx = r.next_usize(descriptors.len());
    let selected = &descriptors[idx];

    let c1 = CFDescriptors::clone_column_family_descriptor(selected);
    let c2 = CFDescriptors::clone_column_family_descriptor(&c1);

    assert_eq!(selected.name(), c1.name());
    assert_eq!(c1.name(), c2.name());
}

fn fuzz_options_construction(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let opts = RockDbSchema::robust_db_options();

    assert!(opts.create_if_missing);
    assert!(opts.create_missing_column_families);
    assert!(opts.paranoid_checks);
    assert!(opts.use_direct_reads);
    assert!(opts.use_direct_io_for_flush_and_compaction);

    let rounds = 1 + r.next_usize(16);

    for _ in 0..rounds {
        let opts = RockDbSchema::robust_db_options();

        assert!(opts.create_if_missing);
        assert!(opts.create_missing_column_families);
        assert!(opts.paranoid_checks);
        assert!(opts.use_direct_reads);
        assert!(opts.use_direct_io_for_flush_and_compaction);
        assert!(opts.level_compaction_dynamic_level_bytes);
        assert!(!opts.disable_auto_compactions);
        assert_eq!(opts.compression_type, DBCompressionType::Lz4);
        assert_eq!(opts.bottommost_compression_type, DBCompressionType::Zstd);
        assert_eq!(opts.max_background_jobs, RockDbSchema::robust_db_options().max_background_jobs);
        assert_eq!(opts.max_open_files, RockDbSchema::robust_db_options().max_open_files);
    }
}

fn fuzz_snapshot_options_construction(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let rounds = 1 + r.next_usize(16);

    for _ in 0..rounds {
        let opts = match r.next_u8() % 3 {
            0 => RockDbSchema::snapshot_audit_data(),
            1 => RockDbSchema::snapshot_blockmint_data(),
            _ => RockDbSchema::snapshot_accountmodel_data(),
        };

        let robust = RockDbSchema::robust_db_options();

        assert!(opts.create_if_missing);
        assert!(opts.create_missing_column_families);
        assert!(opts.paranoid_checks);
        assert_eq!(opts.max_background_jobs, robust.max_background_jobs);
    }
}

fn fuzz_fake_directory_shape(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let base = make_safe_fake_base_path(&mut r);
    let dir = DirectoryDB::new_for_fuzz(base.clone());

    assert!(dir.db_path.starts_with(&base));
    assert!(dir.blockchain_path.starts_with(&base));
    assert!(dir.registry_path.starts_with(&base));
    assert!(dir.accountmodel_path.starts_with(&base));
    assert!(dir.sidechain_path.starts_with(&base));
    assert!(dir.log_path.starts_with(&base));
    assert!(dir.wallets_path.starts_with(&base));
    assert!(dir.audit_reports_path.starts_with(&base));
    assert!(dir.peerlist_path.starts_with(&base));

    assert_ne!(dir.db_path, dir.blockchain_path);
    assert_ne!(dir.db_path, dir.registry_path);
    assert_ne!(dir.blockchain_path, dir.log_path);
}

fn fuzz_descriptor_name_invariants(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let schema_names = schema_column_names();
    let descriptor_names = cf_descriptor_names(&CFDescriptors::get_cf_descriptors());

    for s in &schema_names {
        assert_valid_cf_name(s);
    }

    for d in &descriptor_names {
        assert_valid_cf_name(d);
    }

    for s in &schema_names {
        assert!(
            descriptor_names.iter().any(|d| d == s),
            "schema getter name is missing from CFDescriptors: {s}"
        );
    }

    let a = schema_names[r.next_usize(schema_names.len())];
    let b = descriptor_names[r.next_usize(descriptor_names.len())].as_str();

    if a == b {
        assert_eq!(a.as_bytes(), b.as_bytes());
    } else {
        assert_ne!(a, b);
    }
}

fn fuzz_disabled_db_calls_return_errors(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let base = make_safe_fake_base_path(&mut r);
    let dir = DirectoryDB::new_for_fuzz(base);

    match r.next_u8() % 7 {
        0 => {
            assert!(RockDbSchema::open_cli_db(&dir).is_err());
        }
        1 => {
            assert!(RockDbSchema::open_blockchain_db(&dir).is_err());
        }
        2 => {
            assert!(RockDbSchema::open_state_db(&dir).is_err());
        }
        3 => {
            assert!(RockDbSchema::open_registry_db(&dir).is_err());
        }
        4 => {
            assert!(RockDbSchema::open_log_db(&dir).is_err());
        }
        5 => {
            assert!(RockDbSchema::validate_db_integrity(Path::new(
                "/tmp/remzar-fuzz-no-db"
            ))
            .is_err());
        }
        _ => {
            let expected = required_cf_names();
            assert!(RockDbSchema::validate_column_families(
                Path::new("/tmp/remzar-fuzz-no-db"),
                &expected
            )
            .is_err());
        }
    }
}

fn fuzz_mixed_sequence(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let steps = 1 + r.next_usize(32);

    for _ in 0..steps {
        match r.next_u8() % 8 {
            0 => fuzz_schema_column_name_getters(r.remaining_window(128)),
            1 => fuzz_cf_descriptors_have_required_schema_names(r.remaining_window(128)),
            2 => fuzz_cf_descriptor_clone_preserves_name(r.remaining_window(128)),
            3 => fuzz_options_construction(r.remaining_window(128)),
            4 => fuzz_snapshot_options_construction(r.remaining_window(128)),
            5 => fuzz_fake_directory_shape(r.remaining_window(128)),
            6 => fuzz_descriptor_name_invariants(r.remaining_window(128)),
            _ => fuzz_disabled_db_calls_return_errors(r.remaining_window(128)),
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Schema helpers
   ───────────────────────────────────────────────────────────── */

fn schema_column_names() -> Vec<&'static str> {
    vec![
        RockDbSchema::meta_data_column_name(),
        RockDbSchema::global_column_name(),
        RockDbSchema::account_column_name(),
        RockDbSchema::network_column_name(),
        RockDbSchema::sidechain_column_name(),
        RockDbSchema::state_column_name(),
        RockDbSchema::transaction_column_name(),
        RockDbSchema::transaction_batch_column_name(),
        RockDbSchema::reward_column_name(),
        RockDbSchema::reward_batch_column_name(),
        RockDbSchema::blockmint_data_column_name(),
        RockDbSchema::logs_column_name(),
        RockDbSchema::block_to_hash_column_name(),
        RockDbSchema::tx_to_hash_column_name(),
        RockDbSchema::block_meta_by_hash_column_name(),
        RockDbSchema::batch_by_block_hash_column_name(),
        RockDbSchema::canonical_height_to_hash_column_name(),
        RockDbSchema::canonical_chain_view_column_name(),
    ]
}

fn required_cf_names() -> Vec<&'static str> {
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

fn cf_descriptor_names(descriptors: &[ColumnFamilyDescriptor]) -> Vec<String> {
    descriptors.iter().map(|d| d.name().to_string()).collect()
}

fn assert_unique_nonempty_ascii_names(names: &[&str]) {
    let mut seen = BTreeSet::<&str>::new();

    for name in names {
        assert_valid_cf_name(name);
        assert!(seen.insert(*name), "duplicate schema name: {name}");
    }
}

fn assert_unique_string_names(names: &[String]) {
    let mut seen = BTreeSet::<&str>::new();

    for name in names {
        assert_valid_cf_name(name);
        assert!(
            seen.insert(name.as_str()),
            "duplicate CF descriptor name: {name}"
        );
    }
}

fn assert_valid_cf_name(name: &str) {
    assert!(!name.is_empty(), "CF name must not be empty");
    assert!(
        name.is_ascii(),
        "CF name must be ASCII for stable RocksDB schema portability: {name:?}"
    );
    assert!(
        !name.bytes().any(|b| b == 0),
        "CF name must not contain NUL byte"
    );
    assert!(
        !name.chars().any(char::is_whitespace),
        "CF name must not contain whitespace: {name:?}"
    );
    assert!(
        name == "default"
            || name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "CF name should be lowercase snake_case or default: {name:?}"
    );
}

/* ─────────────────────────────────────────────────────────────
   Path helpers
   ───────────────────────────────────────────────────────────── */

fn make_safe_fake_base_path(r: &mut FuzzBytes<'_>) -> PathBuf {
    let mut p = PathBuf::from("/tmp/remzar-fuzz-schema-no-open");

    let components = 1 + r.next_usize(4);

    for i in 0..components {
        p.push(make_safe_path_component(r, i));
    }

    p
}

fn make_safe_path_component(r: &mut FuzzBytes<'_>, idx: usize) -> String {
    let len = 1 + r.next_usize(24);
    let mut s = String::with_capacity(len + 8);

    s.push('c');
    s.push_str(&idx.to_string());
    s.push('_');

    for _ in 0..len {
        let b = r.next_u8();

        let c = match b % 37 {
            0..=9 => char::from(b'0' + (b % 10)),
            10..=35 => char::from(b'a' + ((b - 10) % 26)),
            _ => '_',
        };

        s.push(c);
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

    fn remaining_window(&mut self, max_len: usize) -> &'a [u8] {
        if self.data.is_empty() || max_len == 0 {
            return &[];
        }

        let start = self.pos % self.data.len();
        let available = self.data.len().saturating_sub(start);
        let len = available.min(max_len);

        self.pos = self.pos.wrapping_add(len.max(1));

        &self.data[start..start + len]
    }
}