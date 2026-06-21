use crate::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::storage::rocksdb_003_batches::RockBatch;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use rust_rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompressionType, LogLevel, Options,
    ReadOptions, WriteOptions,
};
use std::sync::Arc;

/// RocksDB memory profile.
const ROCKSDB_BLOCK_CACHE_BYTES: usize = 128 * 1024 * 1024;
const ROCKSDB_WRITE_BUFFER_BYTES: usize = 32 * 1024 * 1024;
const ROCKSDB_MAX_WRITE_BUFFERS: i32 = 4;
const ROCKSDB_MIN_WRITE_BUFFERS_TO_MERGE: i32 = 1;
const ROCKSDB_TARGET_FILE_SIZE_BASE: u64 = 64 * 1024 * 1024;
const ROCKSDB_MAX_BACKGROUND_JOBS: i32 = 4;
const ROCKSDB_MAX_PARALLELISM: usize = 4;
const ROCKSDB_MAX_OPEN_FILES: i32 = 512;

pub struct RockSDBConfig {
    options: Options,
}

impl RockSDBConfig {
    /// Creates a memory-bounded production RocksDB configuration.
    pub fn new() -> Self {
        let mut opts = Options::default();
        let mut block_opts = BlockBasedOptions::default();

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_log_level(LogLevel::Fatal);

        // Bound parallelism.
        let parallelism = i32::try_from(num_cpus::get().min(ROCKSDB_MAX_PARALLELISM)).unwrap_or(4);
        opts.increase_parallelism(parallelism);

        // Keep direct I/O behavior.
        opts.set_use_direct_io_for_flush_and_compaction(true);
        opts.set_use_direct_reads(true);
        opts.set_allow_mmap_reads(false);
        opts.set_allow_mmap_writes(false);
        opts.set_allow_concurrent_memtable_write(true);

        // Memory-bounded write-buffer and compaction profile.
        opts.set_max_write_buffer_number(ROCKSDB_MAX_WRITE_BUFFERS);
        opts.set_write_buffer_size(ROCKSDB_WRITE_BUFFER_BYTES);
        opts.set_min_write_buffer_number_to_merge(ROCKSDB_MIN_WRITE_BUFFERS_TO_MERGE);
        opts.set_target_file_size_base(ROCKSDB_TARGET_FILE_SIZE_BASE);
        opts.set_max_background_jobs(ROCKSDB_MAX_BACKGROUND_JOBS);
        opts.set_max_open_files(ROCKSDB_MAX_OPEN_FILES);

        // Keep dynamic level sizing and automatic compaction ON.
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.set_disable_auto_compactions(false);

        // Production compression policy.
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_bottommost_compression_type(DBCompressionType::Zstd);

        opts.set_paranoid_checks(true);

        // Bounded block cache.
        let cache = Cache::new_lru_cache(ROCKSDB_BLOCK_CACHE_BYTES);
        block_opts.set_block_cache(&cache);
        opts.set_block_based_table_factory(&block_opts);

        Self { options: opts }
    }

    /// Public getter for RocksDB options.
    pub fn get_options(&self) -> &Options {
        &self.options
    }

    // =========================================================================
    //                OPEN DATABASES — FULLY ALIGNED AND FUTURE-PROOF
    // =========================================================================

    /// Open a CLI DB (default CF only). Returns `(Arc<DB>, RockBatch)`.
    pub fn open_db_cli(&self, path: &str) -> Result<(Arc<DB>, RockBatch), ErrorDetection> {
        let db = Arc::new(DB::open(self.get_options(), path).map_err(|e| {
            ErrorDetection::DatabaseError {
                details: format!("RockSDBConfig CLI open failed at {}: {}", path, e),
            }
        })?);

        Ok((Arc::clone(&db), RockBatch { db }))
    }

    /// Open any multi-column-family DB.
    pub fn open_db_multi_cf(&self, path: &str) -> Result<(Arc<DB>, RockBatch), ErrorDetection> {
        let cf_descriptors = CFDescriptors::get_cf_descriptors();

        // If DB exists, validate the CF set before opening.
        if std::path::Path::new(path).exists() {
            Self::validate_column_families(self.get_options(), path, &cf_descriptors)?;
        }

        let db = Arc::new(
            DB::open_cf_descriptors(self.get_options(), path, cf_descriptors).map_err(|e| {
                ErrorDetection::DatabaseError {
                    details: format!("RockSDBConfig multi-CF open failed at {}: {}", path, e),
                }
            })?,
        );

        Ok((Arc::clone(&db), RockBatch { db }))
    }

    /// Open blockchain DB.
    pub fn open_db_blockchain(&self, path: &str) -> Result<(Arc<DB>, RockBatch), ErrorDetection> {
        self.open_db_multi_cf(path)
    }

    /// Open account model DB.
    ///
    /// Unified design: account model uses the main blockchain DB.
    pub fn open_db_accountmodel(&self, path: &str) -> Result<(Arc<DB>, RockBatch), ErrorDetection> {
        self.open_db_blockchain(path)
    }

    /// Open registry DB.
    pub fn open_db_registry(&self, path: &str) -> Result<(Arc<DB>, RockBatch), ErrorDetection> {
        self.open_db_multi_cf(path)
    }

    // =========================================================================
    //                   COLUMN FAMILY VALIDATION
    // =========================================================================

    /// Checks for exact CFs on disk.
    fn validate_column_families(
        options: &Options,
        path: &str,
        expected: &[ColumnFamilyDescriptor],
    ) -> Result<(), ErrorDetection> {
        let existing_cfs =
            DB::list_cf(options, path).map_err(|err| ErrorDetection::DatabaseError {
                details: err.to_string(),
            })?;

        let expected_cfs: Vec<String> = expected.iter().map(|cf| cf.name().to_string()).collect();

        for cf in &expected_cfs {
            if !existing_cfs.contains(cf) {
                return Err(ErrorDetection::ConfigurationError {
                    message: format!("❌ Missing column family: {} in RocksDB at {}", cf, path),
                });
            }
        }

        for cf in &existing_cfs {
            if !expected_cfs.contains(cf) {
                return Err(ErrorDetection::ConfigurationError {
                    message: format!(
                        "❌ Unexpected column family: {} found in RocksDB at {}",
                        cf, path
                    ),
                });
            }
        }

        Ok(())
    }

    // =========================================================================
    //                       WRITE/READ OPTIONS
    // =========================================================================

    pub fn get_write_options(batch_mode: bool, force_sync: bool) -> WriteOptions {
        let mut write_opt = WriteOptions::default();

        // Existing project behavior preserved.
        write_opt.disable_wal(true);

        if batch_mode || force_sync {
            write_opt.set_sync(true);
        }

        write_opt
    }

    pub fn get_read_options(verify_checksums: bool, enable_prefetching: bool) -> ReadOptions {
        let mut read_opt = ReadOptions::default();

        read_opt.set_verify_checksums(verify_checksums);

        if enable_prefetching {
            let readahead_size =
                usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX);
            read_opt.set_readahead_size(readahead_size);
        }

        read_opt
    }
}

impl Default for RockSDBConfig {
    fn default() -> Self {
        Self::new()
    }
}
