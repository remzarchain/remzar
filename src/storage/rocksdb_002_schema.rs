use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use rust_rocksdb::{ColumnFamilyDescriptor, DB, DBCompressionType, Options};
use std::path::Path;

/// Defines all production RocksDB schemas for REMZAR.
pub struct RockDbSchema;

/// Memory-bounded RocksDB defaults.
const ROCKSDB_WRITE_BUFFER_BYTES: usize = 32 * 1024 * 1024;
const ROCKSDB_MAX_WRITE_BUFFERS: i32 = 4;
const ROCKSDB_MIN_WRITE_BUFFERS_TO_MERGE: i32 = 1;
const ROCKSDB_TARGET_FILE_SIZE_BASE: u64 = 64 * 1024 * 1024;
const ROCKSDB_MAX_BACKGROUND_JOBS: i32 = 4;
const ROCKSDB_MAX_OPEN_FILES: i32 = 512;
const ROCKSDB_MAX_PARALLELISM: usize = 4;
const ROCKSDB_PARALLELISM_FALLBACK: i32 = 4;

impl RockDbSchema {
    // Helper: always get robust options matching cf_descriptors.rs
    pub fn robust_db_options() -> Options {
        let mut opts = Options::default();

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Memory-bounded memtable/SST/thread config.
        opts.set_write_buffer_size(ROCKSDB_WRITE_BUFFER_BYTES);
        opts.set_max_write_buffer_number(ROCKSDB_MAX_WRITE_BUFFERS);
        opts.set_min_write_buffer_number_to_merge(ROCKSDB_MIN_WRITE_BUFFERS_TO_MERGE);
        opts.set_target_file_size_base(ROCKSDB_TARGET_FILE_SIZE_BASE);
        opts.set_max_background_jobs(ROCKSDB_MAX_BACKGROUND_JOBS);
        opts.set_max_open_files(ROCKSDB_MAX_OPEN_FILES);

        // Keep compaction behavior ON.
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_disable_auto_compactions(false);

        // Keep direct I/O behavior.
        opts.set_use_direct_io_for_flush_and_compaction(true);
        opts.set_use_direct_reads(true);

        // Keep safety checks.
        opts.set_paranoid_checks(true);

        // Production compression policy:
        // - LZ4 for active/hot data.
        // - Zstd for bottommost/cold data.
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(DBCompressionType::Zstd);

        // Bound RocksDB thread parallelism.
        //
        // Using all CPUs can increase memory pressure during flush/compaction.
        let parallelism = i32::try_from(num_cpus::get().min(ROCKSDB_MAX_PARALLELISM))
            .unwrap_or(ROCKSDB_PARALLELISM_FALLBACK);
        opts.increase_parallelism(parallelism);

        opts
    }

    // 1) CLI Database (single default CF)
    pub fn open_cli_db(directory: &DirectoryDB) -> Result<DB, ErrorDetection> {
        let opts = Self::robust_db_options();
        let db_path = &directory.db_path;
        let cf_descriptors = CFDescriptors::get_cf_descriptors();

        DB::open_cf_descriptors(&opts, db_path, cf_descriptors)
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to open CLI RocksDB at {}: {}", db_path.display(), e),
            })
            .inspect(|_| {
                println!(
                    "✅ Successfully opened CLI RocksDB at {}",
                    db_path.display()
                )
            })
    }

    // 2) Blockchain Database (full schema)
    pub fn open_blockchain_db(directory: &DirectoryDB) -> Result<DB, ErrorDetection> {
        let opts = Self::robust_db_options();
        let db_path = &directory.blockchain_path;
        let cf_descriptors = CFDescriptors::get_cf_descriptors();

        DB::open_cf_descriptors(&opts, db_path, cf_descriptors)
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!(
                    "Failed to open Blockchain RocksDB at {}: {}",
                    db_path.display(),
                    e
                ),
            })
            .inspect(|_| {
                println!(
                    "✅ Successfully opened Blockchain RocksDB at {}",
                    db_path.display()
                )
            })
    }

    // 3) AccountModelTree Database (full schema)
    pub fn open_state_db(directory: &DirectoryDB) -> Result<DB, ErrorDetection> {
        let opts = Self::robust_db_options();
        let db_path = &directory.blockchain_path;
        let cf_descriptors = CFDescriptors::get_cf_descriptors();

        DB::open_cf_descriptors(&opts, db_path, cf_descriptors)
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!(
                    "Failed to open AccountModelTree RocksDB at {}: {}",
                    db_path.display(),
                    e
                ),
            })
            .inspect(|_| {
                println!(
                    "✅ Successfully opened AccountModelTree RocksDB at {}",
                    db_path.display()
                )
            })
    }

    // 4) Registry/Reward Database (full schema)
    pub fn open_registry_db(directory: &DirectoryDB) -> Result<DB, ErrorDetection> {
        let opts = Self::robust_db_options();
        let db_path = &directory.registry_path;
        let cf_descriptors = CFDescriptors::get_cf_descriptors();

        DB::open_cf_descriptors(&opts, db_path, cf_descriptors)
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!(
                    "Failed to open Registry RocksDB at {}: {}",
                    db_path.display(),
                    e
                ),
            })
            .inspect(|_| {
                println!(
                    "✅ Successfully opened Registry RocksDB at {}",
                    db_path.display()
                )
            })
    }

    // 5) Log Database (can be default+logs_data only)
    pub fn open_log_db(directory: &DirectoryDB) -> Result<DB, ErrorDetection> {
        let mut opts = Self::robust_db_options();

        opts.set_keep_log_file_num(100);
        opts.set_max_log_file_size(1024 * 1024);

        let db_path = &directory.log_path;
        let logs_cf_name = Self::logs_column_name();

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new("default", Options::default()),
            ColumnFamilyDescriptor::new(logs_cf_name, Options::default()),
        ];

        DB::open_cf_descriptors(&opts, db_path, cf_descriptors)
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to open Log RocksDB at {}: {}", db_path.display(), e),
            })
            .inspect(|_| {
                println!(
                    "✅ Successfully opened Log RocksDB at {}",
                    db_path.display()
                )
            })
    }

    // Helpers for snapshot/migration/validation.
    //
    // Keep these aligned with robust_db_options().
    // Do not override max_background_jobs back to 16, because that defeats the
    // memory-bounded profile during snapshot/migration paths.
    pub fn snapshot_audit_data() -> Options {
        Self::robust_db_options()
    }

    pub fn snapshot_blockmint_data() -> Options {
        Self::robust_db_options()
    }

    pub fn snapshot_accountmodel_data() -> Options {
        Self::robust_db_options()
    }

    // Column family name getters
    #[inline]
    pub fn meta_data_column_name() -> &'static str {
        GlobalConfiguration::META_DATA_COLUMN_NAME
    }

    #[inline]
    pub fn global_column_name() -> &'static str {
        GlobalConfiguration::GLOBAL_COLUMN_NAME
    }

    #[inline]
    pub fn account_column_name() -> &'static str {
        GlobalConfiguration::ACCOUNT_COLUMN_NAME
    }

    #[inline]
    pub fn network_column_name() -> &'static str {
        GlobalConfiguration::NETWORK_COLUMN_NAME
    }

    #[inline]
    pub fn sidechain_column_name() -> &'static str {
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME
    }

    #[inline]
    pub fn state_column_name() -> &'static str {
        GlobalConfiguration::STATE_COLUMN_NAME
    }

    #[inline]
    pub fn transaction_column_name() -> &'static str {
        GlobalConfiguration::TRANSACTION_COLUMN_NAME
    }

    #[inline]
    pub fn transaction_batch_column_name() -> &'static str {
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
    }

    #[inline]
    pub fn reward_column_name() -> &'static str {
        GlobalConfiguration::REWARD_COLUMN_NAME
    }

    #[inline]
    pub fn reward_batch_column_name() -> &'static str {
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME
    }

    #[inline]
    pub fn blockmint_data_column_name() -> &'static str {
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
    }

    #[inline]
    pub fn logs_column_name() -> &'static str {
        GlobalConfiguration::LOGS_COLUMN_NAME
    }

    #[inline]
    pub fn block_to_hash_column_name() -> &'static str {
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
    }

    #[inline]
    pub fn tx_to_hash_column_name() -> &'static str {
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME
    }

    #[inline]
    pub fn block_meta_by_hash_column_name() -> &'static str {
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME
    }

    #[inline]
    pub fn batch_by_block_hash_column_name() -> &'static str {
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME
    }

    #[inline]
    pub fn canonical_height_to_hash_column_name() -> &'static str {
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
    }

    #[inline]
    pub fn canonical_chain_view_column_name() -> &'static str {
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME
    }

    // Validation utilities
    pub fn validate_db_integrity(db_path: &Path) -> Result<(), String> {
        let opts = Self::robust_db_options();

        match DB::open_for_read_only(&opts, db_path, false) {
            Ok(_) => {
                println!(
                    "✅ RocksDB at '{}' is valid and not corrupted.",
                    db_path.display()
                );
                Ok(())
            }
            Err(e) => Err(format!(
                "❌ RocksDB at '{}' might be missing or corrupted: {}",
                db_path.display(),
                e
            )),
        }
    }

    pub fn validate_column_families(db_path: &Path, expected_cfs: &[&str]) -> Result<(), String> {
        let opts = Self::robust_db_options();

        match DB::list_cf(&opts, db_path) {
            Ok(existing_cfs) => {
                for &cf in expected_cfs {
                    if !existing_cfs.iter().any(|x| x == cf) {
                        return Err(format!(
                            "❌ Missing required column family '{}'. Found: {:?}",
                            cf, existing_cfs
                        ));
                    }
                }

                println!(
                    "✅ All required column families exist in '{}'",
                    db_path.display()
                );

                Ok(())
            }
            Err(e) => Err(format!("❌ Failed to list column families: {}", e)),
        }
    }
}
