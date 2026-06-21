//! rocksdb_005_manager.rs

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::network::p2p_006_reqresp::Hash;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::storage::rocksdb_003_batches::RockBatch;
use crate::storage::rocksdb_004_config::RockSDBConfig;
use crate::storage::rocksdb_008_helper::force_full_compaction;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::KVResultIter;
use crate::utility::helper::STATE_KEY;
use crate::utility::helper::open_cf_with_retries;
use crate::utility::logging_data::JsonLogger;
use rust_rocksdb::{DB, IteratorMode, Options, WriteBatch, WriteOptions};
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, PartialEq, Clone)]
pub enum Mode {
    CLI,
    Blockchain,
    AccountModel,
    Sidechain,
    Log,
}

const MAX_BLOCKS_BETWEEN_REQUEST: u64 = 100_000;

const MAX_ITERATE_COLUMN_ITEMS: usize = 100_000;

const MAX_LAST_BLOCKS_FETCH: usize = 4_096;

/// **RocksDB High-Level Manager**
#[derive(Debug)]
pub struct RockDBManager {
    pub directory: DirectoryDB,
    pub mode: Mode,
    blockchain_handle: Option<Arc<DB>>,
}

impl Clone for RockDBManager {
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            mode: self.mode.clone(),
            blockchain_handle: self.blockchain_handle.clone(),
        }
    }
}

impl RockDBManager {
    // ─────────────────────────────────────────────────────────────────
    // RocksDB startup/open guardrails
    // ─────────────────────────────────────────────────────────────────

    #[inline]
    fn validate_db_directory(path: &Path, role: &str) -> Result<(), ErrorDetection> {
        let metadata = fs::symlink_metadata(path).map_err(|e| ErrorDetection::DatabaseError {
            details: format!(
                "{role} RocksDB directory '{}' is not accessible: {e}",
                path.display()
            ),
        })?;

        if metadata.file_type().is_symlink() {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "{role} RocksDB directory '{}' is a symlink; refusing to use it",
                    path.display()
                ),
            });
        }

        if !metadata.is_dir() {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "{role} RocksDB path '{}' exists but is not a directory",
                    path.display()
                ),
            });
        }

        Ok(())
    }

    #[inline]
    fn path_as_utf8<'a>(path: &'a Path, role: &str) -> Result<&'a str, ErrorDetection> {
        path.to_str().ok_or_else(|| ErrorDetection::DatabaseError {
            details: format!("{role} RocksDB path is not valid UTF-8: {}", path.display()),
        })
    }

    #[inline]
    fn looks_like_lock_contention(message: &str) -> bool {
        let lower = message.to_ascii_lowercase();

        lower.contains("lock file")
            || lower.contains("failed to lock")
            || lower.contains("io error: lock")
            || lower.contains("lock held")
            || lower.contains("lock hold")
            || lower.contains("resource temporarily unavailable")
            || lower.contains("temporarily unavailable")
            || lower.contains("already in use")
            || lower.contains("another process")
            || lower.contains("database is locked")
    }

    fn rocksdb_open_error(path: &Path, operation: &str, error: &impl Display) -> ErrorDetection {
        let error_message = error.to_string();
        let lock_guidance = if Self::looks_like_lock_contention(&error_message) {
            " This usually means another live process owns the RocksDB lock; \
             do not delete the LOCK file manually. Stop the other writer or use read-only mode."
        } else {
            ""
        };

        ErrorDetection::DatabaseError {
            details: format!(
                "{operation} failed at '{}': {error_message}.{lock_guidance}",
                path.display()
            ),
        }
    }

    fn open_rw_db_at_path(path: &Path, role: &str) -> Result<Arc<DB>, ErrorDetection> {
        Self::validate_db_directory(path, role)?;

        let db_path_str = Self::path_as_utf8(path, role)?;
        let config = RockSDBConfig::new();
        let opts = config.get_options();

        let operation = format!("Failed to open {role} RocksDB");
        let raw = open_cf_with_retries(opts, db_path_str)
            .map_err(|e| Self::rocksdb_open_error(path, &operation, &e))?;

        Ok(Arc::new(raw))
    }

    #[inline]
    fn accountmodel_write_column_allowed(column: &str) -> bool {
        column == GlobalConfiguration::STATE_COLUMN_NAME
            || column == GlobalConfiguration::ACCOUNT_COLUMN_NAME
    }

    // ─────────────────────────────────────────────────────────────────
    // 1) Initialize CLI Manager
    // ─────────────────────────────────────────────────────────────────
    pub fn new(opts: &NodeOpts) -> Result<Self, ErrorDetection> {
        let directory =
            DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to initialize directories: {}", e),
            })?;

        directory
            .setup_database(&directory.db_path)
            .map_err(|e| ErrorDetection::StorageError { message: e })?;

        Self::validate_db_directory(&directory.db_path, "CLI")?;

        println!("✅ RocksDB initialized successfully with directory setup (CLI mode)");
        Ok(RockDBManager {
            directory,
            mode: Mode::CLI,
            blockchain_handle: None,
        })
    }

    // ─────────────────────────────────────────────────────────────────
    // 1B) Initialize Blockchain Manager
    // ─────────────────────────────────────────────────────────────────
    pub fn new_blockchain(node_opts: &NodeOpts, db_path: &str) -> Result<Self, ErrorDetection> {
        // 1) Directory setup
        let mut directory =
            DirectoryDB::from_node_opts(node_opts).map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to initialize directories: {}", e),
            })?;
        let path_obj = Path::new(db_path);
        if path_obj.is_absolute() && db_path.ends_with(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
        {
            directory.blockchain_path = PathBuf::from(db_path);
            directory
                .create_blockchain_directory()
                .map_err(|e| ErrorDetection::StorageError { message: e })?;
        } else {
            directory
                .setup_database(&directory.blockchain_path)
                .map_err(|e| ErrorDetection::StorageError { message: e })?;
        }

        println!(
            "✅ RocksDB initialized successfully with directory setup (Blockchain mode) at {}",
            directory.blockchain_path.display()
        );

        let db_arc = Self::open_rw_db_at_path(&directory.blockchain_path, "Blockchain")?;

        Ok(RockDBManager {
            directory,
            mode: Mode::Blockchain,
            blockchain_handle: Some(db_arc),
        })
    }

    // ─────────────────────────────────────────────────────────────────
    // 1C) Initialize AccountModelTree Manager
    // ─────────────────────────────────────────────────────────────────
    /// Initialize an AccountModelTree RocksDB manager.
    pub fn new_accountmodel(opts: &NodeOpts, db_path: &str) -> Result<Self, ErrorDetection> {
        // 1) Build fresh dirs config:
        let mut directory =
            DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to initialize directories: {}", e),
            })?;

        // 2) If user passed an absolute path ending in our BLOCKCHAIN_DATABASE_DIR, use it;
        //    otherwise bootstrap the standard one under correct dir.
        let path_obj = Path::new(db_path);
        if path_obj.is_absolute() && db_path.ends_with(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
        {
            directory.blockchain_path = PathBuf::from(db_path);
            directory
                .create_blockchain_directory()
                .map_err(|e| ErrorDetection::StorageError { message: e })?;
        } else {
            directory
                .setup_database(&directory.blockchain_path)
                .map_err(|e| ErrorDetection::StorageError { message: e })?;
        }

        // 3) Open once and keep a shared Arc<DB>. The old code left this as None,
        // which allowed open_db_accountmodel() to reopen the RocksDB handle on
        // repeated state/account operations.
        let db_arc = Self::open_rw_db_at_path(&directory.blockchain_path, "AccountModelTree")?;

        println!(
            "✅ RocksDB initialized successfully for AccountModelTree at {}",
            directory.blockchain_path.display()
        );
        Ok(Self {
            directory,
            mode: Mode::AccountModel,
            blockchain_handle: Some(db_arc),
        })
    }

    /// Build an AccountModel manager that reuses an already-open Blockchain DB
    /// handle. Prefer this when the node already owns the blockchain RocksDB in
    /// the same process; it avoids a second writer open attempt against the same
    /// RocksDB path.
    pub fn from_blockchain_for_accountmodel(blockchain: &Self) -> Result<Self, ErrorDetection> {
        let handle = blockchain.blockchain_handle.clone().ok_or_else(|| {
            ErrorDetection::DatabaseError {
                details: "Cannot build AccountModel manager: source Blockchain DB handle is not initialized"
                    .into(),
            }
        })?;

        Ok(Self {
            directory: blockchain.directory.clone(),
            mode: Mode::AccountModel,
            blockchain_handle: Some(handle),
        })
    }

    /// Open the blockchain RocksDB in true read-only mode (no LOCK file).
    pub fn from_existing_readonly<P: AsRef<Path>>(
        opts: &NodeOpts,
        db_path: P,
    ) -> Result<Self, ErrorDetection> {
        let mut directory =
            DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to init directories: {}", e),
            })?;

        // Safely assign the path
        let path_ref = db_path.as_ref();
        if !path_ref.exists() {
            return Err(ErrorDetection::DatabaseError {
                details: format!("Blockchain DB path does not exist: {}", path_ref.display()),
            });
        }
        directory.blockchain_path = path_ref.to_path_buf();
        Self::validate_db_directory(&directory.blockchain_path, "Read-only Blockchain")?;

        // 2) Open read-only with exactly the same CF descriptors you use elsewhere
        let mut rocksdb_opts = Options::default();
        rocksdb_opts.create_if_missing(false);
        rocksdb_opts.create_missing_column_families(false);

        let cfs = CFDescriptors::get_cf_descriptors();
        let raw_db = DB::open_cf_descriptors_read_only(
            &rocksdb_opts,
            &directory.blockchain_path,
            cfs,
            /* error_if_log_file_exist = */ false,
        )
        .map_err(|e| {
            Self::rocksdb_open_error(
                &directory.blockchain_path,
                "Failed to open blockchain DB read-only",
                &e,
            )
        })?;

        // 3) Wrap in Arc and return a manager in Blockchain mode
        Ok(RockDBManager {
            directory,
            mode: Mode::Blockchain,
            blockchain_handle: Some(Arc::new(raw_db)),
        })
    }

    // ─────────────────────────────────────────────────────────────────
    // 1F) Initialize Log Manager
    // ─────────────────────────────────────────────────────────────────

    /// Initialize a RocksDBManager pointed at a Log directory.
    pub fn new_log(opts: &NodeOpts, db_path: &str) -> Result<Self, ErrorDetection> {
        // 1) Build the base DirectoryDB
        let mut directory =
            DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to init directories: {}", e),
            })?;

        // 2) Set up the folder (absolute vs default "./007.log_db")
        let path_obj = Path::new(db_path);
        if path_obj.is_absolute() && db_path.ends_with(GlobalConfiguration::LOG_DATABASE_DIR) {
            directory.log_path = PathBuf::from(db_path);
            directory
                .create_log_directory()
                .map_err(|e| ErrorDetection::StorageError { message: e })?;
        } else {
            directory
                .setup_database(&directory.log_path)
                .map_err(|e| ErrorDetection::StorageError { message: e })?;
        }

        // 3) Validate the directory only. RocksDB owns the actual file lock.
        Self::validate_db_directory(&directory.log_path, "Log")?;

        println!(
            "✅ RocksDB initialized for Logs at {}",
            directory.log_path.display()
        );

        Ok(RockDBManager {
            directory,
            mode: Mode::Log,
            blockchain_handle: None,
        })
    }

    // ─────────────────────────────────────────────────────────────────
    // 2) Opening the DB in each Mode (with retry logic)
    // ─────────────────────────────────────────────────────────────────

    pub fn open_db_cli(&self) -> Result<DB, ErrorDetection> {
        let db_path = &self.directory.db_path;
        Self::validate_db_directory(db_path, "CLI")?;

        // Safely convert to &str for RocksDB
        let db_path_str = Self::path_as_utf8(db_path, "CLI")?;

        let config = RockSDBConfig::new();
        let opts = config.get_options();

        open_cf_with_retries(opts, db_path_str)
            .map_err(|e| Self::rocksdb_open_error(db_path, "Failed to open CLI RocksDB", &e))
    }

    pub fn open_db_blockchain(&self) -> Result<Arc<DB>, ErrorDetection> {
        self.blockchain_handle
            .clone()
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: "Blockchain DB handle not initialized; call new_blockchain() or from_blockchain_for_accountmodel() first".into(),
            })
    }

    // ─────────────────────────────────────────────────────────────────
    // 2B) Opening the DB for AccountModel
    // ─────────────────────────────────────────────────────────────────
    pub fn open_db_accountmodel(&self) -> Result<Arc<DB>, ErrorDetection> {
        self.blockchain_handle
            .clone()
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: "AccountModel DB handle not initialized; call new_accountmodel() or from_blockchain_for_accountmodel() first"
                    .into(),
            })
    }

    // ─────────────────────────────────────────────────────────────────
    // 2C) Opening the DB for Logs
    // ─────────────────────────────────────────────────────────────────
    pub fn open_db_log(&self) -> Result<DB, ErrorDetection> {
        use rust_rocksdb::ColumnFamilyDescriptor;

        let db_path = &self.directory.log_path;
        Self::validate_db_directory(db_path, "Log")?;

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_keep_log_file_num(100);
        opts.set_max_log_file_size(1024 * 1024);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new("default", Options::default()),
            ColumnFamilyDescriptor::new(GlobalConfiguration::LOGS_COLUMN_NAME, Options::default()),
        ];

        DB::open_cf_descriptors(&opts, db_path, cf_descriptors)
            .map_err(|e| Self::rocksdb_open_error(db_path, "Failed to open Log RocksDB", &e))
    }

    // ─────────────────────────────────────────────────────────────────
    // Write Options Helpers
    // ─────────────────────────────────────────────────────────────────
    pub fn sync_write_options() -> WriteOptions {
        let mut opts = WriteOptions::default();
        opts.set_sync(true);
        opts
    }

    pub fn non_sync_write_options() -> WriteOptions {
        let mut opts = WriteOptions::default();
        opts.disable_wal(true);
        opts.set_sync(false);
        opts
    }

    // ─────────────────────────────────────────────────────────────────
    // 3) GLOBAL METADATA (CLI or Blockchain)
    // ─────────────────────────────────────────────────────────────────
    pub fn store_metadata(&self, key: &str, value: &[u8]) -> Result<(), ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::CLI => Arc::new(self.open_db_cli()?),
            Mode::Blockchain => self.open_db_blockchain()?,
            Mode::AccountModel | Mode::Sidechain | Mode::Log => {
                return Err(ErrorDetection::StorageError {
                    message: "Metadata storage is only supported in CLI or Blockchain modes."
                        .into(),
                });
            }
        };

        let cf_handle = db
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_handle, key.as_bytes(), value);
        db.write_opt(&batch, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store metadata: {}", e),
            })?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // 3B) tip-height metadata helpers
    // ─────────────────────────────────────────────────────────────────
    pub fn set_latest_block_index(&self, height: u64) -> Result<(), ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::Blockchain => self.open_db_blockchain()?,
            Mode::CLI => Arc::new(self.open_db_cli()?),
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "set_latest_block_index() only valid in CLI or Blockchain modes"
                        .into(),
                });
            }
        };

        let cf = db
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;

        let buf = height.to_be_bytes();

        db.put_cf_opt(cf, b"latest_block_index", buf, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store latest_block_index metadata: {e}"),
            })?;

        db.put_cf_opt(cf, b"tip_height", buf, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store tip_height metadata: {e}"),
            })
    }

    // ─────────────────────────────────────────────────────────────────
    // 4) READING A BLOCK (Blockchain)
    // ─────────────────────────────────────────────────────────────────

    /// Step 1: iterate raw bytes, exactly as before
    pub fn get_latest_block_by_iter(&self) -> Result<Option<Vec<u8>>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;
        let mut it = db.iterator_cf(cf, IteratorMode::End);
        if let Some(item) = it.next() {
            let (key, data) = item.map_err(|e| ErrorDetection::StorageError {
                message: format!("Error retrieving latest block by iter: {}", e),
            })?;
            if key.starts_with(b"block_") {
                return Ok(Some(data.to_vec()));
            }
        }
        Ok(None)
    }

    /// Step 2: deserialize those bytes into Block struct
    pub fn get_latest_block(&self) -> Result<Option<Block>, ErrorDetection> {
        if let Some(raw) = self.get_latest_block_by_iter()? {
            let block = crate::blockchain::block_002_blocks::Block::deserialize_from_storage(&raw)?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Step 3: pull out exactly the header hash for chaining (64 bytes).
    pub fn get_latest_block_hash(&self) -> Result<Hash, ErrorDetection> {
        let block = self
            .get_latest_block()?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: "latest block".into(),
            })?;
        Ok(block.block_hash)
    }

    // ─────────────────────────────────────────────────────────────────
    // 5) BATCH PROCESS (for CLI or Blockchain DB)
    // ─────────────────────────────────────────────────────────────────
    pub fn batch_process_all(&self) -> Result<(), ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::CLI => {
                let raw = self.open_db_cli()?;
                Arc::new(raw)
            }
            Mode::Blockchain => self.open_db_blockchain()?,
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "batch_process_all() is only supported in CLI or Blockchain modes."
                        .to_string(),
                });
            }
        };

        let batch_processor = RockBatch { db };

        batch_processor
            .batch_execute_records()
            .map_err(|e| ErrorDetection::BlockchainError { details: e })?;
        batch_processor
            .store_batch_signature(b"placeholder_key", b"placeholder_sig")
            .map_err(|e| ErrorDetection::BlockchainError { details: e })?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // 6) MAX BLOCK STORAGE
    // ─────────────────────────────────────────────────────────────────
    pub fn store_latest_block(
        &self,
        block_data: &[u8],
        block_index: u64,
    ) -> Result<(), ErrorDetection> {
        self.batch_process_all()?;

        // Keep the size guard (important). Refuse impossible platform/config combinations.
        let max_block_size =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).map_err(|_| {
                ErrorDetection::StorageError {
                    message: format!(
                        "Configured maximum block size does not fit usize: {}",
                        GlobalConfiguration::MAX_BLOCK_SIZE
                    ),
                }
            })?;

        if block_data.is_empty() {
            return Err(ErrorDetection::StorageError {
                message: "❌ Refusing to store an empty block payload".to_string(),
            });
        }

        if block_data.len() > max_block_size {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "❌ Block too large: maximum {} bytes allowed, got {}",
                    GlobalConfiguration::MAX_BLOCK_SIZE,
                    block_data.len()
                ),
            });
        }

        let db = self.open_db_blockchain()?;
        let cf_handle = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;

        let mut final_batch = WriteBatch::default();
        let key = format!("block_{:010}", block_index);

        // Store canonical bytes exactly as produced by serializer
        final_batch.put_cf(cf_handle, key.as_bytes(), block_data);

        db.write_opt(&final_batch, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("❌ Failed to store latest block data: {}", e),
            })?;

        db.flush_cf(cf_handle)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!(
                    "❌ Failed to flush {} column: {}",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
                    e
                ),
            })?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // 7) STATE DATA (Account Model in Mode::AccountModel)
    // ─────────────────────────────────────────────────────────────────

    /// Serialize & persist the entire AccountModelTree under STATE_COLUMN_NAME/STATE_KEY.
    pub fn store_state(&self, state_tree: &AccountModelTree) -> Result<(), ErrorDetection> {
        let db = self.open_db_accountmodel()?;
        let cf = db
            .cf_handle(GlobalConfiguration::STATE_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::STATE_COLUMN_NAME),
            })?;

        let data = state_tree
            .serialize_state()
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("State serialization failed: {}", e),
            })?;

        db.put_cf_opt(cf, STATE_KEY, &data, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store state data: {}", e),
            })?;

        Ok(())
    }

    /// Load (or initialize) the AccountModelTree from STATE_COLUMN_NAME/STATE_KEY.
    pub fn load_state(&self) -> Result<AccountModelTree, ErrorDetection> {
        let db = self.open_db_accountmodel()?;
        let cf = db
            .cf_handle(GlobalConfiguration::STATE_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::STATE_COLUMN_NAME),
            })?;

        match db
            .get_pinned_cf(cf, STATE_KEY)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to retrieve state data: {}", e),
            })? {
            Some(pinned) => AccountModelTree::deserialize_state(pinned.as_ref(), self.clone())
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!("State deserialization failed: {}", e),
                }),
            None => Ok(AccountModelTree::with_manager(self.clone())),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // 8) READ, ITERATE (Generic)
    // ─────────────────────────────────────────────────────────────────
    pub fn read(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::CLI => Arc::new(self.open_db_cli()?),
            Mode::Blockchain => self.open_db_blockchain()?,
            Mode::AccountModel => self.open_db_accountmodel()?,
            Mode::Log => Arc::new(self.open_db_log()?),
            Mode::Sidechain => {
                return Err(ErrorDetection::StorageError {
                    message: "read() is only supported in CLI, Blockchain or AccountModel modes."
                        .into(),
                });
            }
        };

        let cf_handle = db
            .cf_handle(column)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column '{}' not found", column),
            })?;

        let result =
            db.get_pinned_cf(cf_handle, key)
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!("Error reading from RocksDB: {e}"),
                })?;

        Ok(result.map(|slice| slice.to_vec()))
    }

    pub fn iterate_column(&self, column: &str) -> Result<KVResultIter, ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::CLI => Arc::new(self.open_db_cli()?),
            Mode::Blockchain => self.open_db_blockchain()?,
            Mode::AccountModel => self.open_db_accountmodel()?,
            Mode::Log => Arc::new(self.open_db_log()?),
            Mode::Sidechain => {
                return Err(ErrorDetection::StorageError {
                    message: "iterate_column() is only supported in CLI, Blockchain or AccountModel modes."
                        .into(),
                });
            }
        };

        let cf_handle = db
            .cf_handle(column)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column family '{}' not found!", column),
            })?;

        let mut items = Vec::new();
        for item in db.iterator_cf(cf_handle, IteratorMode::Start) {
            if items.len() >= MAX_ITERATE_COLUMN_ITEMS {
                return Err(ErrorDetection::StorageError {
                    message: format!(
                        "Refusing to materialize more than {} items from column '{}' in memory; use a paged/ranged API",
                        MAX_ITERATE_COLUMN_ITEMS, column
                    ),
                });
            }

            let (k, v) = item.map_err(|e| ErrorDetection::StorageError {
                message: format!("Error iterating column '{column}': {e}"),
            })?;
            items.push((k.into_vec(), v.into_vec()));
        }

        Ok(Box::new(
            items
                .into_iter()
                .map(Ok::<(Vec<u8>, Vec<u8>), ErrorDetection>),
        ))
    }

    // ─────────────────────────────────────────────────────────────────
    // 9) TRANSACTION BATCH -> ACCOUNT MODEL
    // ─────────────────────────────────────────────────────────────────
    pub fn apply_transaction_batch(&self, batch: &TransactionBatch) -> Result<(), ErrorDetection> {
        let mut state_tree = self.load_state()?;
        state_tree.apply_batch(batch)?;
        self.store_state(&state_tree)
    }

    /// Example convenience for overwriting balances in an `AccountModelTree`.
    pub fn set_account_balance(&self, account: &str, balance: u64) -> Result<(), ErrorDetection> {
        // 1) Keep the state snapshot correct
        let mut state_tree = self.load_state()?;
        state_tree.set_balance(account, balance);
        self.store_state(&state_tree)?;

        // 2) Mirror to ACCOUNT CF so `check_balance()` can read it
        state_tree
            .flush_addresses(std::iter::once(account.to_string()))
            .map_err(|e| ErrorDetection::StorageError { message: e })?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // 10) WALLET ACCOUNTS, NETWORK, BLOCKS, …
    // ─────────────────────────────────────────────────────────────────
    pub fn store_wallet_balance(
        &self,
        wallet_address: &str,
        balance: &[u8],
    ) -> Result<(), ErrorDetection> {
        match self.mode {
            Mode::CLI | Mode::Blockchain => {}
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "Wallet balances are only stored in CLI or Blockchain modes."
                        .to_string(),
                });
            }
        }

        self.batch_process_all()?;

        let db: Arc<DB> = match self.mode {
            Mode::CLI => Arc::new(self.open_db_cli()?),
            Mode::Blockchain => self.open_db_blockchain()?,
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "Wallet balances are only stored in CLI or Blockchain modes."
                        .to_string(),
                });
            }
        };

        let cf_handle = db
            .cf_handle(GlobalConfiguration::ACCOUNT_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::ACCOUNT_COLUMN_NAME),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_handle, wallet_address.as_bytes(), balance);

        db.write_opt(&batch, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store wallet balance: {}", e),
            })?;
        Ok(())
    }

    pub fn register_peer(&self, peer_id: &str, peer_data: &[u8]) -> Result<(), ErrorDetection> {
        match self.mode {
            Mode::CLI | Mode::Blockchain => {}
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "Cannot register peer outside CLI or Blockchain modes.".to_string(),
                });
            }
        }
        self.write(
            GlobalConfiguration::NETWORK_COLUMN_NAME,
            peer_id.as_bytes(),
            peer_data,
        )
    }

    pub fn remove_peer(&self, peer_id: &str) -> Result<(), ErrorDetection> {
        match self.mode {
            Mode::CLI | Mode::Blockchain => {}
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "Cannot remove peer outside CLI or Blockchain modes.".to_string(),
                });
            }
        }
        self.delete(GlobalConfiguration::NETWORK_COLUMN_NAME, peer_id.as_bytes())
    }

    pub fn delete_block(&self, block_key: &[u8]) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf_handle = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;
        db.delete_cf(cf_handle, block_key)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to delete block: {}", e),
            })?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // 11.A) GENERIC CRUD – write
    // ─────────────────────────────────────────────────────────────────
    pub fn write(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::CLI => {
                self.batch_process_all()?;
                Arc::new(self.open_db_cli()?)
            }
            Mode::Blockchain => {
                self.batch_process_all()?;
                self.open_db_blockchain()?
            }
            Mode::AccountModel => {
                if !Self::accountmodel_write_column_allowed(column) {
                    return Err(ErrorDetection::StorageError {
                        message: format!(
                            "AccountModel write is only allowed for '{}' or '{}' columns, got '{}'",
                            GlobalConfiguration::STATE_COLUMN_NAME,
                            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                            column
                        ),
                    });
                }
                self.open_db_accountmodel()?
            }
            Mode::Sidechain | Mode::Log => {
                return Err(ErrorDetection::StorageError {
                    message: "Generic write is only allowed in CLI, Blockchain, or AccountModel state/account modes."
                        .to_string(),
                });
            }
        };

        let cf_handle = db
            .cf_handle(column)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column '{}' not found", column),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_handle, key, value);

        // Use WAL + sync here because this generic write path is used by
        // blockchain/state helpers where the caller is writing durable state.
        db.write_opt(&batch, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to write to RocksDB: {}", e),
            })?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // 12) GENERIC CRUD – delete
    // ─────────────────────────────────────────────────────────────────
    pub fn delete(&self, column: &str, key: &[u8]) -> Result<(), ErrorDetection> {
        match self.mode {
            Mode::CLI | Mode::Blockchain => {}
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "Generic delete is only allowed in CLI or Blockchain modes."
                        .to_string(),
                });
            }
        }

        self.batch_process_all()?;

        let db: Arc<DB> = match self.mode {
            Mode::CLI => Arc::new(self.open_db_cli()?),
            Mode::Blockchain => self.open_db_blockchain()?,
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "Generic delete is only allowed in CLI or Blockchain modes."
                        .to_string(),
                });
            }
        };

        let cf_handle = db
            .cf_handle(column)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column '{}' not found", column),
            })?;

        db.delete_cf(cf_handle, key)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to delete key: {}", e),
            })?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // 13) P2P SYSTEM (block and transaction hash indexing)
    // ─────────────────────────────────────────────────────────────────

    #[inline]
    fn log_block_index_error_gracefully(&self, event: &str, message: &str) {
        if let Ok(logger) = JsonLogger::new(&self.directory) {
            drop(logger.log_error_event("p2p_system", event, message));
        }
    }

    /// Index a block’s bytes under its 64-byte hash for O(1) lookups.
    pub fn index_block_by_hash(
        &self,
        hash: &Hash,
        block_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        // Canonicalize bytes before indexing under hash (consensus-safe storage)
        let canonical_block_bytes: Vec<u8> = {
            let block = Block::deserialize_from_storage(block_bytes)?;
            block.serialize_for_storage()?
        };

        let db = self.open_db_blockchain()?;

        let cf = db
            .cf_handle(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| {
                let message = format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
                );
                self.log_block_index_error_gracefully("BlockIndexColumnFamilyMissing", &message);
                ErrorDetection::DatabaseError { details: message }
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(cf, hash, &canonical_block_bytes);

        let write_res = db.write_opt(&batch, &Self::sync_write_options());
        match write_res {
            Ok(_) => Ok(()),
            Err(e) => {
                let message = format!("Failed to write block hash index: {}", e);
                self.log_block_index_error_gracefully("BlockIndexWriteFailed", &message);
                Err(ErrorDetection::StorageError { message })
            }
        }
    }

    /// Retrieve a block by its 64-byte hash from the hash index.
    pub fn get_block_by_hash(&self, hash: &Hash) -> Option<Block> {
        let db = match self.open_db_blockchain() {
            Ok(db) => db,
            Err(e) => {
                let message = format!("Failed to open blockchain DB for hash {:?}: {:?}", hash, e);
                self.log_block_index_error_gracefully("BlockIndexOpenDbFailed", &message);
                return None;
            }
        };

        let cf = match db.cf_handle(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME) {
            Some(cf) => cf,
            None => {
                let message = format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
                );
                self.log_block_index_error_gracefully("BlockIndexColumnFamilyMissing", &message);
                return None;
            }
        };

        let pinned = match db.get_pinned_cf(cf, hash) {
            Ok(Some(pin)) => pin,
            Ok(None) => {
                return None;
            }
            Err(e) => {
                let message = format!("Failed to fetch block by hash {:?}: {:?}", hash, e);
                self.log_block_index_error_gracefully("BlockIndexFetchByHashFailed", &message);
                return None;
            }
        };

        let bytes: &[u8] = pinned.as_ref();
        let block = Block::deserialize_from_storage(bytes);
        match block {
            Ok(b) => Some(b),
            Err(e) => {
                let message = format!(
                    "Failed to deserialize block fetched by hash {:?}: {:?}",
                    hash, e
                );
                self.log_block_index_error_gracefully(
                    "BlockIndexDeserializeByHashFailed",
                    &message,
                );
                None
            }
        }
    }

    /// Retrieve the block hash (64 bytes) for a block at a specific index.
    pub fn get_block_hash_by_index(&self, index: u64) -> Result<Hash, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| {
                let message = format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                );
                self.log_block_index_error_gracefully("BlockIndexColumnFamilyMissing", &message);
                ErrorDetection::DatabaseError { details: message }
            })?;

        let key = format!("block_{:010}", index);

        let bytes = db
            .get_pinned_cf(cf, key.as_bytes())
            .map_err(|e| {
                let message = format!("Failed to fetch block {index}: {e}");
                self.log_block_index_error_gracefully("BlockIndexFetchByIndexFailed", &message);
                ErrorDetection::StorageError { message }
            })?
            .ok_or_else(|| {
                let resource = format!("block_{:010}", index);
                let message = format!("{} not found", resource);
                self.log_block_index_error_gracefully("BlockIndexBlockNotFound", &message);
                ErrorDetection::NotFound { resource }
            })?;

        let block = crate::blockchain::block_002_blocks::Block::deserialize_from_storage(&bytes)?;

        Ok(block.block_hash)
    }

    /// Fetch and deserialize a block by its integer index (e.g. block_0000000001).
    pub fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| {
                let message = format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                );
                self.log_block_index_error_gracefully("BlockIndexColumnFamilyMissing", &message);
                ErrorDetection::DatabaseError { details: message }
            })?;

        let key = format!("block_{:010}", index);

        let bytes = db.get_pinned_cf(cf, key.as_bytes()).map_err(|e| {
            let message = format!("Failed to fetch block {index}: {e}");
            self.log_block_index_error_gracefully("BlockIndexFetchByIndexFailed", &message);
            ErrorDetection::StorageError { message }
        })?;

        if let Some(data) = bytes {
            let block = crate::blockchain::block_002_blocks::Block::deserialize_from_storage(
                data.as_ref(),
            )?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    pub fn get_block_bytes_by_index(&self, index: u64) -> Result<Option<Vec<u8>>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| {
                let message = format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                );
                self.log_block_index_error_gracefully("BlockIndexColumnFamilyMissing", &message);
                ErrorDetection::DatabaseError { details: message }
            })?;

        let key = format!("block_{:010}", index);

        let bytes = db.get_pinned_cf(cf, key.as_bytes()).map_err(|e| {
            let message = format!("Failed to fetch block bytes for index {index}: {e}");
            self.log_block_index_error_gracefully("BlockIndexFetchBytesByIndexFailed", &message);
            ErrorDetection::StorageError { message }
        })?;

        Ok(bytes.map(|b| b.to_vec()))
    }

    /// Return `true` if the hash→block mapping exists.
    pub fn has_block_by_hash(&self, hash: &Hash) -> bool {
        let db = match self.open_db_blockchain() {
            Ok(db) => db,
            Err(e) => {
                let message = format!("Failed to open blockchain DB for hash {:?}: {:?}", hash, e);
                self.log_block_index_error_gracefully("BlockIndexOpenDbFailed", &message);
                return false;
            }
        };

        let cf = match db.cf_handle(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME) {
            Some(cf) => cf,
            None => {
                let message = format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
                );
                self.log_block_index_error_gracefully("BlockIndexColumnFamilyMissing", &message);
                return false;
            }
        };

        match db.get_pinned_cf(cf, hash) {
            Ok(opt) => opt.is_some(),
            Err(e) => {
                let message = format!("Failed to check block hash {:?}: {:?}", hash, e);
                self.log_block_index_error_gracefully("BlockIndexHashExistsCheckFailed", &message);
                false
            }
        }
    }

    /// Fetches batch bytes using the canonical `"tx_batch_{:010}"` key.
    pub fn get_batch_bytes_by_index(&self, index: u64) -> Result<Option<Vec<u8>>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
            .ok_or_else(|| {
                let message = "transaction_batch_data CF not found".to_string();
                self.log_block_index_error_gracefully(
                    "TransactionBatchColumnFamilyMissing",
                    &message,
                );
                ErrorDetection::DatabaseError { details: message }
            })?;

        let key = format!("tx_batch_{:010}", index);

        let bytes = db.get_pinned_cf(cf, key.as_bytes()).map_err(|e| {
            let message = format!("Failed to fetch tx_batch bytes for index {index}: {e}");
            self.log_block_index_error_gracefully(
                "TransactionBatchFetchBytesByIndexFailed",
                &message,
            );
            ErrorDetection::StorageError { message }
        })?;

        Ok(bytes.map(|b| b.to_vec()))
    }

    // ─────────────────────────────────────────────────────────────────
    // 14) LIST COLUMN FAMILIES
    // ─────────────────────────────────────────────────────────────────
    pub fn list_column_families(&self) -> Result<Vec<String>, ErrorDetection> {
        let db_path = match self.mode {
            Mode::CLI => &self.directory.db_path,
            Mode::Blockchain | Mode::AccountModel => &self.directory.blockchain_path,
            Mode::Log => &self.directory.log_path,
            Mode::Sidechain => {
                return Err(ErrorDetection::StorageError {
                    message:
                        "Listing column families only supported in CLI, Blockchain, or AccountModel modes."
                            .to_string(),
                })
            }
        };

        let db_path_str = db_path
            .to_str()
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: "Database path contains invalid UTF-8 and cannot be converted to &str"
                    .to_string(),
            })?;

        let opts = Options::default();
        match DB::list_cf(&opts, db_path_str) {
            Ok(cfs) => Ok(cfs),
            Err(e) => Err(ErrorDetection::DatabaseError {
                details: format!(
                    "❌ Error listing column families for '{}': {}",
                    db_path.display(),
                    e
                ),
            }),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // 15) GETTER SECTION
    // ─────────────────────────────────────────────────────────────────
    pub fn get_peer_info(&self, peer_id: &str) -> Result<Option<Vec<u8>>, ErrorDetection> {
        match self.mode {
            Mode::CLI | Mode::Blockchain => {
                self.read(GlobalConfiguration::NETWORK_COLUMN_NAME, peer_id.as_bytes())
            }
            _ => Err(ErrorDetection::StorageError {
                message: "Peers are only stored in CLI or Blockchain modes.".to_string(),
            }),
        }
    }

    pub fn get_wallet_balance(
        &self,
        wallet_address: &str,
    ) -> Result<Option<Vec<u8>>, ErrorDetection> {
        match self.mode {
            Mode::CLI | Mode::Blockchain => self.read(
                GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                wallet_address.as_bytes(),
            ),
            _ => Err(ErrorDetection::StorageError {
                message: "Wallet balances are only stored in CLI or Blockchain modes.".to_string(),
            }),
        }
    }

    /// Generic metadata read helper (GLOBAL CF).
    pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::CLI => Arc::new(self.open_db_cli()?),
            Mode::Blockchain => self.open_db_blockchain()?,
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "Metadata is only available in CLI or Blockchain modes.".to_string(),
                });
            }
        };

        let cf_handle = db
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;

        let result = db.get_pinned_cf(cf_handle, key.as_bytes()).map_err(|e| {
            ErrorDetection::StorageError {
                message: format!("Error reading metadata: {}", e),
            }
        })?;

        Ok(result.map(|slice| slice.to_vec()))
    }

    pub fn get_account_balance(&self, account: &str) -> Result<u64, ErrorDetection> {
        let state_tree = self.load_state()?;
        Ok(state_tree.get_balance(account))
    }

    // ─────────────────────────────────────────────────────────────────
    // 16) Explicit Flush (CLI, Blockchain, AccountModel)
    // ─────────────────────────────────────────────────────────────────

    /// Private helper: flush every column family.
    fn flush_all_cfs(db: &DB) -> Result<(), ErrorDetection> {
        for desc in CFDescriptors::get_cf_descriptors() {
            let name = desc.name();
            if let Some(handle) = db.cf_handle(name) {
                db.flush_cf(handle)
                    .map_err(|e| ErrorDetection::DatabaseError {
                        details: format!("Flush of column family '{}' failed: {}", name, e),
                    })?;
            }
        }
        Ok(())
    }

    /// Flush the **CLI** database (all CFs).
    pub fn flush_cli_db(&self) -> Result<(), ErrorDetection> {
        let db = self.open_db_cli()?;
        Self::flush_all_cfs(&db)?;
        Ok(())
    }

    /// Flush the **Blockchain** database.
    pub fn flush_blockchain_db(&self) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        Self::flush_all_cfs(&db)?;
        Ok(())
    }

    /// Flush the **AccountModelTree** database (state_data CF).
    pub fn flush_state_db(&self) -> Result<(), ErrorDetection> {
        let db = self.open_db_accountmodel()?;
        Self::flush_all_cfs(&db)?;
        Ok(())
    }

    /// Optional maintenance: compact the **CLI** database.
    pub fn compact_cli_db(&self) -> Result<(), ErrorDetection> {
        let db = self.open_db_cli()?;
        force_full_compaction(&db).map_err(|e| ErrorDetection::DatabaseError {
            details: format!("Manual compaction (CLI DB) failed: {e}"),
        })
    }

    /// Optional maintenance: compact the **Blockchain** database.
    pub fn compact_blockchain_db(&self) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        force_full_compaction(&db).map_err(|e| ErrorDetection::DatabaseError {
            details: format!("Manual compaction (Blockchain DB) failed: {e}"),
        })
    }

    /// Optional maintenance: compact the **AccountModelTree** database.
    pub fn compact_state_db(&self) -> Result<(), ErrorDetection> {
        let db = self.open_db_accountmodel()?;
        force_full_compaction(&db).map_err(|e| ErrorDetection::DatabaseError {
            details: format!("Manual compaction (State DB) failed: {e}"),
        })
    }

    // ─────────────────────────────────────────────────────────────────
    // 17) CONSOLE HELPERS
    // ─────────────────────────────────────────────────────────────────

    /// List all block keys (e.g. "block_0000000001") in ascending order.
    pub fn list_block_indices(&self) -> Result<Vec<String>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column '{}' not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;
        let mut out = Vec::new();
        for entry in db.iterator_cf(cf, IteratorMode::Start) {
            if out.len() >= MAX_ITERATE_COLUMN_ITEMS {
                return Err(ErrorDetection::StorageError {
                    message: format!(
                        "Refusing to list more than {} block indices in memory; use ranged block lookups",
                        MAX_ITERATE_COLUMN_ITEMS
                    ),
                });
            }

            let (key, _) = entry.map_err(|e| ErrorDetection::StorageError {
                message: format!("Error iterating blocks: {}", e),
            })?;
            out.push(String::from_utf8_lossy(&key).to_string());
        }
        Ok(out)
    }

    /// Fetch up to `count` of the *most recent* blocks.
    pub fn get_last_blocks(&self, count: usize) -> Result<Vec<Block>, ErrorDetection> {
        if count > MAX_LAST_BLOCKS_FETCH {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "Refusing to fetch {} recent blocks into memory; cap is {}",
                    count, MAX_LAST_BLOCKS_FETCH
                ),
            });
        }

        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column '{}' not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;
        let mut blocks = Vec::new();
        let mut iter = db.iterator_cf(cf, IteratorMode::End);
        for _ in 0..count {
            if let Some(Ok((_, bytes))) = iter.next() {
                blocks.push(Block::deserialize_from_storage(&bytes)?);
            } else {
                break;
            }
        }
        Ok(blocks)
    }

    // ─────────────────────────────────────────────────────────────────
    // 18) FETCHES BATCH BYTE / FETCHES BATCH KEY
    // ─────────────────────────────────────────────────────────────────

    /// Fetches batch bytes using `"tx_batch_{:010}"` format (canonical for audit/export).
    pub fn get_tx_batch_bytes_by_index(
        &self,
        block_index: u64,
    ) -> Result<Option<Vec<u8>>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF not found",
                    GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
                ),
            })?;
        let key = format!("tx_batch_{:010}", block_index);
        let bytes =
            db.get_pinned_cf(cf, key.as_bytes())
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!(
                        "Failed to fetch tx_batch bytes for block index {block_index}: {e}"
                    ),
                })?;
        Ok(bytes.map(|b| b.to_vec()))
    }

    // ─────────────────────────────────────────────────────────────────
    // 19) TIP LOOK UP - Big-endian
    // ─────────────────────────────────────────────────────────────────

    /// Fast O(1) tip lookup that falls back to the legacy iterator scan.
    pub fn get_tip_height(&self) -> Result<u64, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let db_ref = db.as_ref();

        let cf = db_ref
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF missing", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;

        if let Some(bytes) =
            db_ref
                .get_pinned_cf(cf, b"tip_height")
                .map_err(|e| ErrorDetection::DatabaseError {
                    details: format!("Failed to read tip_height: {e}"),
                })?
            && bytes.len() == 8
        {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            return Ok(u64::from_be_bytes(arr));
        }

        self.get_latest_block_index()
    }

    pub fn set_tip_height(&self, height: u64) -> Result<(), ErrorDetection> {
        let db: Arc<DB> = match self.mode {
            Mode::Blockchain => self.open_db_blockchain()?,
            Mode::CLI => Arc::new(self.open_db_cli()?),
            _ => {
                return Err(ErrorDetection::StorageError {
                    message: "set_tip_height() only valid in CLI or Blockchain modes".into(),
                });
            }
        };

        let cf = db
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;

        let mut buf = [0u8; 8];
        buf.copy_from_slice(&height.to_be_bytes());

        db.put_cf_opt(cf, b"tip_height", buf, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store tip height metadata: {e}"),
            })
    }

    // ─────────────────────────────────────────────────────────────────
    // 19) GET AND STORE
    // ─────────────────────────────────────────────────────────────────

    /// Read the latest block index (defaults to 0 if missing/malformed).
    pub fn get_latest_block_index(&self) -> Result<u64, ErrorDetection> {
        let db = self.open_db_blockchain()?;

        let cf_handle = db
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF not found", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;

        let opt_bytes = db
            .get_pinned_cf(cf_handle, b"latest_block_index")
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to read latest_block_index: {e}"),
            })?;

        if let Some(bytes) = opt_bytes
            && bytes.len() == 8
        {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes.as_ref());
            return Ok(u64::from_be_bytes(arr));
        }

        Ok(0)
    }

    /// Open the blockchain DB in **read-only**
    pub fn open_db_blockchain_readonly(&self) -> Result<DB, ErrorDetection> {
        let cfs = CFDescriptors::get_cf_descriptors();

        let mut opts = Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);

        let db_path = Path::new(&self.directory.blockchain_path);

        DB::open_cf_descriptors_read_only(
            &opts, db_path, cfs, /* error_if_log_file_exist = */ false,
        )
        .map_err(|e| Self::rocksdb_open_error(db_path, "Failed to open read-only RocksDB", &e))
    }

    /// Store a raw batch’s bytes under its numeric batch index
    /// using the canonical key `tx_batch_{:010}`.
    pub fn store_batch_bytes(
        &self,
        batch_index: u64,
        batch_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;

        let cf_handle = db
            .cf_handle(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF not found",
                    GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
                ),
            })?;

        let key = format!("tx_batch_{:010}", batch_index);

        let mut wb = WriteBatch::default();
        wb.put_cf(cf_handle, key.as_bytes(), batch_bytes);

        if let Err(e) = db.write_opt(&wb, &Self::sync_write_options()) {
            return Err(ErrorDetection::StorageError {
                message: format!("❌ Failed to store batch bytes: {}", e),
            });
        }

        if let Err(e) = db.flush_cf(cf_handle) {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "❌ Failed to flush {} column: {}",
                    GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                    e
                ),
            });
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // Address/UTXO index height metadata (GLOBAL CF)
    // ─────────────────────────────────────────────────────────────────

    pub fn get_addr_index_height(&self) -> Result<u64, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF missing", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;
        if let Some(bytes) = db.get_pinned_cf(cf, b"addr_index_height").map_err(|e| {
            ErrorDetection::DatabaseError {
                details: format!("Failed to read addr_index_height: {e}"),
            }
        })? && bytes.len() == 8
        {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            return Ok(u64::from_be_bytes(arr));
        }
        Ok(0)
    }

    pub fn set_addr_index_height(&self, height: u64) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::GLOBAL_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF missing", GlobalConfiguration::GLOBAL_COLUMN_NAME),
            })?;
        let buf = height.to_be_bytes();
        db.put_cf_opt(cf, b"addr_index_height", buf, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store addr_index_height: {e}"),
            })
    }

    //---------------------------------------------------------------
    // 20) REMOVALS
    //---------------------------------------------------------------

    fn delete_block_by_index(&self, idx: u64) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;
        let key = format!("block_{:010}", idx);
        db.delete_cf(cf, key.as_bytes())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to delete block bytes at index {idx}: {e}"),
            })
    }

    fn delete_block_hash_mapping(&self, hash: &Hash) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF not found",
                    GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
                ),
            })?;
        db.delete_cf(cf, hash)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to delete block hash mapping: {e}"),
            })
    }

    pub fn remove_block_by_index(&self, idx: u64) -> Result<(), ErrorDetection> {
        let block = self
            .get_block_by_index(idx)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!("block_{:010}", idx),
            })?;

        self.delete_block_by_index(idx)?;

        if self.get_batch_bytes_by_index(idx)?.is_some() {
            let db = self.open_db_blockchain()?;
            let cf = db
                .cf_handle(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
                .ok_or_else(|| ErrorDetection::DatabaseError {
                    details: format!(
                        "{} CF not found",
                        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
                    ),
                })?;
            let key = format!("tx_batch_{:010}", idx);
            db.delete_cf(cf, key.as_bytes())
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!("Failed to delete tx_batch at index {idx}: {e}"),
                })?;
        }

        self.delete_block_hash_mapping(&block.block_hash)?;

        Ok(())
    }

    fn get_header_by_hash(&self, hash: &Hash) -> Option<(u64, Hash)> {
        self.get_block_by_hash(hash)
            .map(|b| (b.metadata.index, b.metadata.previous_hash))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  BlockStore trait + implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal trait used by fork/sync logic to query blocks from storage.
pub trait BlockStore {
    /// Walk back from `hash` until a locally-stored block is found, returning that hash.
    fn find_common_ancestor(&self, hash: Hash) -> Option<Hash>;

    /// Return every block strictly between `ancestor` and `tip`,
    /// inclusive of `tip`, exclusive of `ancestor`.
    fn get_blocks_between(&self, ancestor: Hash, tip: Hash) -> Result<Vec<Block>, String>;
}

// ─────────────────────────────────────────────────────────────────────────────
//  BlockStore implementation
// ─────────────────────────────────────────────────────────────────────────────
impl BlockStore for RockDBManager {
    fn find_common_ancestor(&self, mut hash: Hash) -> Option<Hash> {
        const MAX_BACKTRACK: usize = 100_000;
        let mut last_height: Option<u64> = None;

        for _ in 0..=MAX_BACKTRACK {
            if self.has_block_by_hash(&hash) {
                return Some(hash);
            }

            match self.get_header_by_hash(&hash) {
                Some((height, prev_hash)) => {
                    if let Some(prev_h) = last_height
                        && height >= prev_h
                    {
                        return None;
                    }
                    last_height = Some(height);
                    hash = prev_hash;
                    continue;
                }
                None => {
                    return None;
                }
            }
        }

        None
    }

    fn get_blocks_between(&self, ancestor: Hash, tip: Hash) -> Result<Vec<Block>, String> {
        let ancestor_block = self
            .get_block_by_hash(&ancestor)
            .ok_or_else(|| format!("Ancestor block not found: {}", hex::encode(ancestor)))?;

        let tip_block = self
            .get_block_by_hash(&tip)
            .ok_or_else(|| format!("Tip block not found: {}", hex::encode(tip)))?;

        let ancestor_idx = ancestor_block.metadata.index;
        let tip_idx = tip_block.metadata.index;

        if tip_idx <= ancestor_idx {
            return Err(format!(
                "Tip height {} must be greater than ancestor height {}",
                tip_idx, ancestor_idx
            ));
        }

        let diff = tip_idx.checked_sub(ancestor_idx).ok_or_else(|| {
            format!(
                "Tip height {} must not be lower than ancestor height {}",
                tip_idx, ancestor_idx
            )
        })?;

        if diff > MAX_BLOCKS_BETWEEN_REQUEST {
            return Err(format!(
                "Requested block range is too large: {} blocks exceeds limit {}",
                diff, MAX_BLOCKS_BETWEEN_REQUEST
            ));
        }

        let capacity = usize::try_from(diff)
            .map_err(|_| format!("Block range does not fit usize capacity: {diff}"))?;
        let mut blocks: Vec<Block> = Vec::with_capacity(capacity);

        let start_idx = ancestor_idx
            .checked_add(1)
            .ok_or_else(|| "Ancestor index overflow when computing start range".to_string())?;

        for idx in start_idx..=tip_idx {
            let block = self
                .get_block_by_index(idx)
                .map_err(|e| format!("DB error at index {idx}: {e:?}"))?
                .ok_or_else(|| format!("Missing block at index {idx}"))?;

            if let Some(prev) = blocks.last() {
                if block.metadata.previous_hash != prev.block_hash {
                    return Err(format!(
                        "Hash linkage broken at index {idx}: \
                            prev hash {:x?} ≠ current.prev_hash {:x?}",
                        prev.block_hash, block.metadata.previous_hash
                    ));
                }
            } else if block.metadata.previous_hash != ancestor {
                return Err(format!(
                    "First block after ancestor (index {}) has wrong previous_hash",
                    idx
                ));
            }

            blocks.push(block);
        }

        Ok(blocks)
    }
}
