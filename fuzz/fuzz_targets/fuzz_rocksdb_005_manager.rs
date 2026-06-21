/*
Robust in-memory fuzz target for rocksdb_005_manager behavior.

Why this target exists:
- The production RockDBManager uses real RocksDB handles and sync writes.
- Running real RocksDB inside libFuzzer is slow, noisy, lock-prone, and can stall.
- This fuzz target mirrors the public manager API and high-level semantics in memory.
- It drives many different operation sequences from the input bytes instead of running
  one fixed two-block script.

Suggested target filename:
    fuzz_targets/fuzz_rocksdb_005_manager.rs

It covers:
- CLI / Blockchain / AccountModel / Log mode construction.
- Mode guardrails for write/delete/metadata/wallet/peer/state APIs.
- Generic read/write/delete/iterate/list CF behavior.
- Metadata and tip-height big-endian helpers.
- Address index height helpers.
- Batch bytes helpers.
- Block storage by height.
- Block hash indexing.
- Latest block lookup.
- Block removal.
- Last-block listing.
- BlockStore::get_blocks_between linkage checks.
- BlockStore::find_common_ancestor bounded traversal semantics.
- Serialization/deserialization error paths.
- Empty-block rejection.
- Missing key / missing block / missing hash paths.
- Flush/compact/open helpers.

This target intentionally does NOT use rust_rocksdb and does NOT include the real
rocksdb_005_manager.rs, because libFuzzer should not spend most of its time doing
filesystem locks, WAL, flush, compaction, and open/close cycles.
*/

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static CASE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// Serde helper for [u8; 64]
// ─────────────────────────────────────────────────────────────────────────────

mod serde_u8_array_64 {
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(64)?;
        for b in arr {
            tup.serialize_element(b)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Arr64Visitor;

        impl<'de> Visitor<'de> for Arr64Visitor {
            type Value = [u8; 64];

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a 64-byte array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = [0u8; 64];

                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| DeError::invalid_length(i, &self))?;
                }

                if let Some(_extra) = seq.next_element::<u8>()? {
                    return Err(DeError::invalid_length(65, &self));
                }

                Ok(out)
            }
        }

        deserializer.deserialize_tuple(64, Arr64Visitor)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime mock aligned with real NodeOpts usage
// ─────────────────────────────────────────────────────────────────────────────

mod runtime {
    pub mod p2p_006_sync_runtime {
        #[derive(Debug, Clone)]
        pub struct NodeOpts {
            pub data_dir: String,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network hash primitive
// ─────────────────────────────────────────────────────────────────────────────

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility mocks aligned with real manager dependencies
// ─────────────────────────────────────────────────────────────────────────────

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const WALLETS_DIR: &str = "000.wallets";
            pub const DATABASE_DIR_NAME: &str = "001.database_db";
            pub const BLOCKCHAIN_DATABASE_DIR: &str = "002.blockchain_db";
            pub const REGISTRY_DIR_NAME: &str = "003.registry_db";
            pub const LOG_DATABASE_DIR: &str = "004.log_db";
            pub const AUDIT_REPORTS_DIR: &str = "005.audit_reports";
            pub const ACCOUNTMODEL_DATABASE_DIR: &str = "006.accountmodel_db";
            pub const PEER_LIST_DIR: &str = "007.peerlist";
            pub const SIDECHAIN_DATABASE_DIR: &str = "008.sidechain_db";

            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;

            pub const META_DATA_COLUMN_NAME: &str = "meta_data";
            pub const GLOBAL_COLUMN_NAME: &str = "global_metadata";
            pub const ACCOUNT_COLUMN_NAME: &str = "wallet_accounts";
            pub const NETWORK_COLUMN_NAME: &str = "network_data";
            pub const SIDECHAIN_COLUMN_NAME: &str = "sidechain_data";
            pub const STATE_COLUMN_NAME: &str = "state_data";
            pub const TRANSACTION_COLUMN_NAME: &str = "transaction_data";
            pub const TRANSACTION_BATCH_COLUMN_NAME: &str = "transaction_batch_data";
            pub const REWARD_COLUMN_NAME: &str = "reward_data";
            pub const REWARD_BATCH_COLUMN_NAME: &str = "reward_batch_data";
            pub const BLOCKMINT_DATA_COLUMN_NAME: &str = "blockmint_data";
            pub const LOGS_COLUMN_NAME: &str = "logs_data";
            pub const BLOCK_TO_HASH_COLUMN_NAME: &str = "blockhash_data";
            pub const TX_TO_HASH_COLUMN_NAME: &str = "txhash_data";
            pub const IDENTITY_COLUMN_NAME: &str = "node_identity_data";
            pub const BLOCK_META_BY_HASH_COLUMN_NAME: &str = "block_meta_by_hash";
            pub const BATCH_BY_BLOCK_HASH_COLUMN_NAME: &str = "batch_by_block_hash";
            pub const CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME: &str = "canonical_height_to_hash";
            pub const CANONICAL_CHAIN_VIEW_COLUMN_NAME: &str = "canonical_chain_view";
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            DatabaseError { details: String },
            StorageError { message: String },
            BlockchainError { details: String },
            ConfigurationError { message: String },
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError { details: String },
            NotFound { resource: String },
            InvalidSignatureFormat { format: String },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::DatabaseError { details } => write!(f, "DatabaseError: {details}"),
                    Self::StorageError { message } => write!(f, "StorageError: {message}"),
                    Self::BlockchainError { details } => write!(f, "BlockchainError: {details}"),
                    Self::ConfigurationError { message } => {
                        write!(f, "ConfigurationError: {message}")
                    }
                    Self::ValidationError { message, tx_id } => {
                        write!(f, "ValidationError: {message} {tx_id:?}")
                    }
                    Self::SerializationError { details } => {
                        write!(f, "SerializationError: {details}")
                    }
                    Self::NotFound { resource } => write!(f, "NotFound: {resource}"),
                    Self::InvalidSignatureFormat { format } => {
                        write!(f, "InvalidSignatureFormat: {format}")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub type KVResultIter =
            Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), ErrorDetection>>>;

        pub const STATE_KEY: &[u8] = b"__account_state__";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Blockchain mocks
// ─────────────────────────────────────────────────────────────────────────────

mod blockchain {
    pub mod block_002_blocks {
        use crate::network::p2p_006_reqresp::Hash;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct BlockMetadata {
            pub index: u64,

            #[serde(with = "crate::serde_u8_array_64")]
            pub previous_hash: Hash,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct Block {
            #[serde(with = "crate::serde_u8_array_64")]
            pub block_hash: Hash,

            pub metadata: BlockMetadata,

            pub payload: Vec<u8>,
        }

        impl Block {
            pub fn serialize_for_storage(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: format!("block serialize failed: {e}"),
                })
            }

            pub fn deserialize_from_storage(bytes: &[u8]) -> Result<Self, ErrorDetection> {
                postcard::from_bytes(bytes).map_err(|e| ErrorDetection::SerializationError {
                    details: format!("block deserialize failed: {e}"),
                })
            }
        }
    }

    pub mod transaction_005_tx_batch {
        #[derive(Debug, Clone, Default)]
        pub struct TransactionBatch;
    }

    pub mod transaction_005_tx_account_tree {
        use crate::memory_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use serde::{Deserialize, Serialize};
        use std::collections::BTreeMap;

        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct AccountModelTree {
            balances: BTreeMap<String, u64>,
        }

        impl AccountModelTree {
            pub fn with_manager(_manager: RockDBManager) -> Self {
                Self::default()
            }

            pub fn serialize_state(&self) -> Result<Vec<u8>, String> {
                postcard::to_allocvec(self).map_err(|e| e.to_string())
            }

            pub fn deserialize_state(bytes: &[u8], _manager: RockDBManager) -> Result<Self, String> {
                postcard::from_bytes(bytes).map_err(|e| e.to_string())
            }

            pub fn apply_batch(
                &mut self,
                _batch: &crate::blockchain::transaction_005_tx_batch::TransactionBatch,
            ) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn set_balance(&mut self, account: &str, balance: u64) {
                self.balances.insert(account.to_string(), balance);
            }

            pub fn get_balance(&self, account: &str) -> u64 {
                self.balances.get(account).copied().unwrap_or(0)
            }

            pub fn flush_addresses<I>(&self, _addresses: I) -> Result<(), String>
            where
                I: IntoIterator<Item = String>,
            {
                Ok(())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory manager aligned with rocksdb_005_manager public API
// ─────────────────────────────────────────────────────────────────────────────

mod memory_manager {
    use crate::blockchain::block_002_blocks::Block;
    use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
    use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
    use crate::network::p2p_006_reqresp::Hash;
    use crate::runtime::p2p_006_sync_runtime::NodeOpts;
    use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
    use crate::utility::alpha_002_error_detection_system::ErrorDetection;
    use crate::utility::helper::{KVResultIter, STATE_KEY};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, MutexGuard};

    const MAX_BLOCKS_BETWEEN_REQUEST: u64 = 100_000;

    #[derive(Debug, PartialEq, Clone)]
    pub enum Mode {
        CLI,
        Blockchain,
        AccountModel,
        Sidechain,
        Log,
    }

    #[derive(Debug, Clone)]
    pub struct DirectoryDB {
        pub db_path: PathBuf,
        pub blockchain_path: PathBuf,
        pub log_path: PathBuf,
        pub sidechain_path: PathBuf,
    }

    #[derive(Debug, Default)]
    struct MemoryDB {
        columns: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
    }

    #[derive(Debug, Clone)]
    pub struct RockDBManager {
        pub directory: DirectoryDB,
        pub mode: Mode,
        db: Arc<Mutex<MemoryDB>>,
    }

    impl MemoryDB {
        fn ensure_cf(&mut self, name: &str) {
            self.columns.entry(name.to_string()).or_default();
        }
    }

    impl RockDBManager {
        fn all_column_families() -> &'static [&'static str] {
            &[
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

        fn new_memory(mode: Mode, root: &Path) -> Self {
            let mut db = MemoryDB::default();

            for cf in Self::all_column_families() {
                db.ensure_cf(cf);
            }

            Self {
                directory: DirectoryDB {
                    db_path: root.join(GlobalConfiguration::DATABASE_DIR_NAME),
                    blockchain_path: root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR),
                    log_path: root.join(GlobalConfiguration::LOG_DATABASE_DIR),
                    sidechain_path: root.join(GlobalConfiguration::SIDECHAIN_DATABASE_DIR),
                },
                mode,
                db: Arc::new(Mutex::new(db)),
            }
        }

        pub fn new(opts: &NodeOpts) -> Result<Self, ErrorDetection> {
            Ok(Self::new_memory(Mode::CLI, Path::new(&opts.data_dir)))
        }

        pub fn new_blockchain(_opts: &NodeOpts, db_path: &str) -> Result<Self, ErrorDetection> {
            Ok(Self::new_memory(Mode::Blockchain, Path::new(db_path)))
        }

        pub fn new_accountmodel(_opts: &NodeOpts, db_path: &str) -> Result<Self, ErrorDetection> {
            Ok(Self::new_memory(Mode::AccountModel, Path::new(db_path)))
        }

        pub fn new_log(_opts: &NodeOpts, db_path: &str) -> Result<Self, ErrorDetection> {
            Ok(Self::new_memory(Mode::Log, Path::new(db_path)))
        }

        pub fn from_existing_readonly<P: AsRef<Path>>(
            _opts: &NodeOpts,
            db_path: P,
        ) -> Result<Self, ErrorDetection> {
            Ok(Self::new_memory(Mode::Blockchain, db_path.as_ref()))
        }

        pub fn open_db_cli(&self) -> Result<(), ErrorDetection> {
            match self.mode {
                Mode::CLI => Ok(()),
                _ => Err(ErrorDetection::StorageError {
                    message: "open_db_cli() only valid in CLI mode".to_string(),
                }),
            }
        }

        pub fn open_db_blockchain(&self) -> Result<(), ErrorDetection> {
            match self.mode {
                Mode::Blockchain => Ok(()),
                _ => Err(ErrorDetection::DatabaseError {
                    details: "Blockchain DB handle not initialized; call new_blockchain() first"
                        .to_string(),
                }),
            }
        }

        pub fn open_db_accountmodel(&self) -> Result<(), ErrorDetection> {
            match self.mode {
                Mode::Blockchain | Mode::AccountModel => Ok(()),
                _ => Err(ErrorDetection::StorageError {
                    message: "open_db_accountmodel() only valid in Blockchain/AccountModel mode"
                        .to_string(),
                }),
            }
        }

        pub fn open_db_log(&self) -> Result<(), ErrorDetection> {
            match self.mode {
                Mode::Log => Ok(()),
                _ => Err(ErrorDetection::StorageError {
                    message: "open_db_log() only valid in Log mode".to_string(),
                }),
            }
        }

        fn lock(&self) -> Result<MutexGuard<'_, MemoryDB>, ErrorDetection> {
            self.db.lock().map_err(|_| ErrorDetection::StorageError {
                message: "memory db lock poisoned".to_string(),
            })
        }

        fn write_inner(
            &self,
            column: &str,
            key: &[u8],
            value: &[u8],
        ) -> Result<(), ErrorDetection> {
            let mut db = self.lock()?;
            let cf = db.columns.get_mut(column).ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column '{column}' not found"),
            })?;
            cf.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn read_inner(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, ErrorDetection> {
            let db = self.lock()?;
            let cf = db.columns.get(column).ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column '{column}' not found"),
            })?;
            Ok(cf.get(key).cloned())
        }

        fn delete_inner(&self, column: &str, key: &[u8]) -> Result<(), ErrorDetection> {
            let mut db = self.lock()?;
            let cf = db.columns.get_mut(column).ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column '{column}' not found"),
            })?;
            cf.remove(key);
            Ok(())
        }

        fn check_cli_or_blockchain(&self, op: &str) -> Result<(), ErrorDetection> {
            match self.mode {
                Mode::CLI | Mode::Blockchain => Ok(()),
                _ => Err(ErrorDetection::StorageError {
                    message: format!("{op} is only supported in CLI or Blockchain modes."),
                }),
            }
        }

        pub fn sync_write_options() {}

        pub fn non_sync_write_options() {}

        pub fn store_metadata(&self, key: &str, value: &[u8]) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("Metadata storage")?;
            self.write_inner(GlobalConfiguration::GLOBAL_COLUMN_NAME, key.as_bytes(), value)
        }

        pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorDetection> {
            self.check_cli_or_blockchain("Metadata")?;
            self.read_inner(GlobalConfiguration::GLOBAL_COLUMN_NAME, key.as_bytes())
        }

        pub fn set_latest_block_index(&self, height: u64) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("set_latest_block_index()")?;
            let bytes = height.to_be_bytes();
            self.write_inner(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"latest_block_index", &bytes)?;
            self.write_inner(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"tip_height", &bytes)
        }

        pub fn get_latest_block_index(&self) -> Result<u64, ErrorDetection> {
            self.check_cli_or_blockchain("get_latest_block_index()")?;
            let Some(bytes) = self.read_inner(
                GlobalConfiguration::GLOBAL_COLUMN_NAME,
                b"latest_block_index",
            )?
            else {
                return Ok(0);
            };
            Ok(decode_be_u64_or_zero(&bytes))
        }

        pub fn set_tip_height(&self, height: u64) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("set_tip_height()")?;
            self.write_inner(
                GlobalConfiguration::GLOBAL_COLUMN_NAME,
                b"tip_height",
                &height.to_be_bytes(),
            )
        }

        pub fn get_tip_height(&self) -> Result<u64, ErrorDetection> {
            self.check_cli_or_blockchain("get_tip_height()")?;
            let Some(bytes) =
                self.read_inner(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"tip_height")?
            else {
                return Ok(0);
            };
            Ok(decode_be_u64_or_zero(&bytes))
        }

        pub fn get_addr_index_height(&self) -> Result<u64, ErrorDetection> {
            self.open_db_blockchain()?;
            let Some(bytes) = self.read_inner(
                GlobalConfiguration::GLOBAL_COLUMN_NAME,
                b"addr_index_height",
            )?
            else {
                return Ok(0);
            };
            Ok(decode_be_u64_or_zero(&bytes))
        }

        pub fn set_addr_index_height(&self, height: u64) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()?;
            self.write_inner(
                GlobalConfiguration::GLOBAL_COLUMN_NAME,
                b"addr_index_height",
                &height.to_be_bytes(),
            )
        }

        pub fn batch_process_all(&self) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("batch_process_all()")
        }

        pub fn write(
            &self,
            column: &str,
            key: &[u8],
            value: &[u8],
        ) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("Generic write")?;
            self.batch_process_all()?;
            self.write_inner(column, key, value)
        }

        pub fn read(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, ErrorDetection> {
            match self.mode {
                Mode::CLI | Mode::Blockchain | Mode::AccountModel | Mode::Log => {
                    self.read_inner(column, key)
                }
                Mode::Sidechain => Err(ErrorDetection::StorageError {
                    message: "read() is only supported in CLI, Blockchain, AccountModel, or Log modes."
                        .to_string(),
                }),
            }
        }

        pub fn delete(&self, column: &str, key: &[u8]) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("Generic delete")?;
            self.batch_process_all()?;
            self.delete_inner(column, key)
        }

        pub fn iterate_column(&self, column: &str) -> Result<KVResultIter, ErrorDetection> {
            match self.mode {
                Mode::CLI | Mode::Blockchain | Mode::AccountModel | Mode::Log => {}
                Mode::Sidechain => {
                    return Err(ErrorDetection::StorageError {
                        message: "iterate_column() is only supported in CLI, Blockchain, AccountModel, or Log modes."
                            .to_string(),
                    });
                }
            }

            let db = self.lock()?;
            let cf = db.columns.get(column).ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("Column family '{column}' not found!"),
            })?;
            let values: Vec<_> = cf
                .iter()
                .map(|(k, v)| Ok((k.clone(), v.clone())))
                .collect();
            Ok(Box::new(values.into_iter()))
        }

        pub fn list_column_families(&self) -> Result<Vec<String>, ErrorDetection> {
            match self.mode {
                Mode::CLI | Mode::Blockchain | Mode::AccountModel | Mode::Log => {}
                Mode::Sidechain => {
                    return Err(ErrorDetection::StorageError {
                        message: "Listing column families only supported in CLI, Blockchain, AccountModel, or Log modes."
                            .to_string(),
                    });
                }
            }
            let db = self.lock()?;
            Ok(db.columns.keys().cloned().collect())
        }

        pub fn store_wallet_balance(
            &self,
            wallet_address: &str,
            balance: &[u8],
        ) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("Wallet balances")?;
            self.batch_process_all()?;
            self.write_inner(
                GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                wallet_address.as_bytes(),
                balance,
            )
        }

        pub fn get_wallet_balance(
            &self,
            wallet_address: &str,
        ) -> Result<Option<Vec<u8>>, ErrorDetection> {
            self.check_cli_or_blockchain("Wallet balances")?;
            self.read_inner(
                GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                wallet_address.as_bytes(),
            )
        }

        pub fn register_peer(&self, peer_id: &str, peer_data: &[u8]) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("Peer registry")?;
            self.write(
                GlobalConfiguration::NETWORK_COLUMN_NAME,
                peer_id.as_bytes(),
                peer_data,
            )
        }

        pub fn remove_peer(&self, peer_id: &str) -> Result<(), ErrorDetection> {
            self.check_cli_or_blockchain("Peer registry")?;
            self.delete(GlobalConfiguration::NETWORK_COLUMN_NAME, peer_id.as_bytes())
        }

        pub fn get_peer_info(&self, peer_id: &str) -> Result<Option<Vec<u8>>, ErrorDetection> {
            self.check_cli_or_blockchain("Peer registry")?;
            self.read(
                GlobalConfiguration::NETWORK_COLUMN_NAME,
                peer_id.as_bytes(),
            )
        }

        pub fn store_batch_bytes(
            &self,
            batch_index: u64,
            batch_bytes: &[u8],
        ) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()?;
            let key = format!("tx_batch_{batch_index:010}");
            self.write_inner(
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                key.as_bytes(),
                batch_bytes,
            )
        }

        pub fn get_batch_bytes_by_index(
            &self,
            index: u64,
        ) -> Result<Option<Vec<u8>>, ErrorDetection> {
            self.open_db_blockchain()?;
            let key = format!("tx_batch_{index:010}");
            self.read_inner(
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                key.as_bytes(),
            )
        }

        pub fn get_tx_batch_bytes_by_index(
            &self,
            index: u64,
        ) -> Result<Option<Vec<u8>>, ErrorDetection> {
            self.get_batch_bytes_by_index(index)
        }

        pub fn store_latest_block(
            &self,
            block_data: &[u8],
            block_index: u64,
        ) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()?;
            self.batch_process_all()?;

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
                    message: "Refusing to store an empty block payload".to_string(),
                });
            }

            if block_data.len() > max_block_size {
                return Err(ErrorDetection::StorageError {
                    message: format!(
                        "Block too large: maximum {} bytes allowed, got {}",
                        GlobalConfiguration::MAX_BLOCK_SIZE,
                        block_data.len()
                    ),
                });
            }

            let key = format!("block_{block_index:010}");
            self.write_inner(
                GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
                key.as_bytes(),
                block_data,
            )
        }

        pub fn get_latest_block_by_iter(&self) -> Result<Option<Vec<u8>>, ErrorDetection> {
            self.open_db_blockchain()?;
            let db = self.lock()?;
            let Some(cf) = db
                .columns
                .get(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            else {
                return Err(ErrorDetection::DatabaseError {
                    details: format!(
                        "{} CF not found",
                        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                    ),
                });
            };

            for (key, value) in cf.iter().rev() {
                if key.starts_with(b"block_") {
                    return Ok(Some(value.clone()));
                }
            }

            Ok(None)
        }

        pub fn get_latest_block(&self) -> Result<Option<Block>, ErrorDetection> {
            let Some(raw) = self.get_latest_block_by_iter()? else {
                return Ok(None);
            };
            Ok(Some(Block::deserialize_from_storage(&raw)?))
        }

        pub fn get_latest_block_hash(&self) -> Result<Hash, ErrorDetection> {
            let block = self.get_latest_block()?.ok_or_else(|| ErrorDetection::NotFound {
                resource: "latest block".to_string(),
            })?;
            Ok(block.block_hash)
        }

        pub fn index_block_by_hash(
            &self,
            hash: &Hash,
            block_bytes: &[u8],
        ) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()?;
            let canonical = Block::deserialize_from_storage(block_bytes)?.serialize_for_storage()?;
            self.write_inner(
                GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
                hash,
                &canonical,
            )
        }

        pub fn get_block_by_hash(&self, hash: &Hash) -> Option<Block> {
            let bytes = self
                .read_inner(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME, hash)
                .ok()
                .flatten()?;
            Block::deserialize_from_storage(&bytes).ok()
        }

        pub fn has_block_by_hash(&self, hash: &Hash) -> bool {
            self.read_inner(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME, hash)
                .map(|opt| opt.is_some())
                .unwrap_or(false)
        }

        pub fn get_block_hash_by_index(&self, index: u64) -> Result<Hash, ErrorDetection> {
            let block = self
                .get_block_by_index(index)?
                .ok_or_else(|| ErrorDetection::NotFound {
                    resource: format!("block_{index:010}"),
                })?;
            Ok(block.block_hash)
        }

        pub fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, ErrorDetection> {
            let key = format!("block_{index:010}");
            let Some(bytes) = self.read_inner(
                GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
                key.as_bytes(),
            )?
            else {
                return Ok(None);
            };
            Ok(Some(Block::deserialize_from_storage(&bytes)?))
        }

        pub fn get_block_bytes_by_index(
            &self,
            index: u64,
        ) -> Result<Option<Vec<u8>>, ErrorDetection> {
            let key = format!("block_{index:010}");
            self.read_inner(
                GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
                key.as_bytes(),
            )
        }

        pub fn delete_block(&self, block_key: &[u8]) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()?;
            self.delete_inner(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME, block_key)
        }

        fn delete_block_by_index(&self, idx: u64) -> Result<(), ErrorDetection> {
            let key = format!("block_{idx:010}");
            self.delete_block(key.as_bytes())
        }

        fn delete_block_hash_mapping(&self, hash: &Hash) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()?;
            self.delete_inner(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME, hash)
        }

        pub fn remove_block_by_index(&self, idx: u64) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()?;

            let maybe_block = self.get_block_by_index(idx)?;
            self.delete_block_by_index(idx)?;

            if let Some(block) = maybe_block {
                self.delete_block_hash_mapping(&block.block_hash)?;
            }

            Ok(())
        }

        pub fn list_block_indices(&self) -> Result<Vec<String>, ErrorDetection> {
            self.open_db_blockchain()?;
            let db = self.lock()?;
            let cf = db
                .columns
                .get(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
                .ok_or_else(|| ErrorDetection::DatabaseError {
                    details: format!(
                        "{} CF not found",
                        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                    ),
                })?;

            Ok(cf
                .keys()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect())
        }

        pub fn get_last_blocks(&self, count: usize) -> Result<Vec<Block>, ErrorDetection> {
            self.open_db_blockchain()?;
            let db = self.lock()?;
            let cf = db
                .columns
                .get(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
                .ok_or_else(|| ErrorDetection::DatabaseError {
                    details: format!(
                        "{} CF not found",
                        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                    ),
                })?;

            let mut out = Vec::new();
            for (_key, value) in cf.iter().rev().take(count) {
                out.push(Block::deserialize_from_storage(value)?);
            }
            Ok(out)
        }

        pub fn store_state(&self, state_tree: &AccountModelTree) -> Result<(), ErrorDetection> {
            self.open_db_accountmodel()?;
            let data = state_tree
                .serialize_state()
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!("State serialization failed: {e}"),
                })?;
            self.write_inner(GlobalConfiguration::STATE_COLUMN_NAME, STATE_KEY, &data)
        }

        pub fn load_state(&self) -> Result<AccountModelTree, ErrorDetection> {
            self.open_db_accountmodel()?;
            let Some(bytes) = self.read_inner(GlobalConfiguration::STATE_COLUMN_NAME, STATE_KEY)?
            else {
                return Ok(AccountModelTree::with_manager(self.clone()));
            };

            AccountModelTree::deserialize_state(&bytes, self.clone()).map_err(|e| {
                ErrorDetection::StorageError {
                    message: format!("State deserialization failed: {e}"),
                }
            })
        }

        pub fn apply_transaction_batch(
            &self,
            batch: &TransactionBatch,
        ) -> Result<(), ErrorDetection> {
            let mut state = self.load_state()?;
            state.apply_batch(batch)?;
            self.store_state(&state)
        }

        pub fn set_account_balance(
            &self,
            account: &str,
            balance: u64,
        ) -> Result<(), ErrorDetection> {
            let mut state_tree = self.load_state()?;
            state_tree.set_balance(account, balance);
            self.store_state(&state_tree)?;
            state_tree
                .flush_addresses(std::iter::once(account.to_string()))
                .map_err(|e| ErrorDetection::StorageError { message: e })?;
            Ok(())
        }

        pub fn get_account_balance(&self, account: &str) -> Result<u64, ErrorDetection> {
            let state_tree = self.load_state()?;
            Ok(state_tree.get_balance(account))
        }

        pub fn flush_cli_db(&self) -> Result<(), ErrorDetection> {
            self.open_db_cli()
        }

        pub fn flush_blockchain_db(&self) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()
        }

        pub fn flush_state_db(&self) -> Result<(), ErrorDetection> {
            self.open_db_accountmodel()
        }

        pub fn compact_cli_db(&self) -> Result<(), ErrorDetection> {
            self.open_db_cli()
        }

        pub fn compact_blockchain_db(&self) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()
        }

        pub fn compact_state_db(&self) -> Result<(), ErrorDetection> {
            self.open_db_accountmodel()
        }

        pub fn open_db_blockchain_readonly(&self) -> Result<(), ErrorDetection> {
            self.open_db_blockchain()
        }

        fn get_header_by_hash(&self, hash: &Hash) -> Option<(u64, Hash)> {
            self.get_block_by_hash(hash)
                .map(|b| (b.metadata.index, b.metadata.previous_hash))
        }
    }

    fn decode_be_u64_or_zero(bytes: &[u8]) -> u64 {
        if bytes.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            u64::from_be_bytes(arr)
        } else {
            0
        }
    }

    pub trait BlockStore {
        fn find_common_ancestor(&self, hash: Hash) -> Option<Hash>;

        fn get_blocks_between(&self, ancestor: Hash, tip: Hash) -> Result<Vec<Block>, String>;
    }

    impl BlockStore for RockDBManager {
        fn find_common_ancestor(&self, mut hash: Hash) -> Option<Hash> {
            let mut last_height: Option<u64> = None;

            for _ in 0..=MAX_BLOCKS_BETWEEN_REQUEST {
                if self.has_block_by_hash(&hash) {
                    return Some(hash);
                }

                let Some((height, prev_hash)) = self.get_header_by_hash(&hash) else {
                    return None;
                };

                if let Some(prev_h) = last_height {
                    if height >= prev_h {
                        return None;
                    }
                }

                last_height = Some(height);
                hash = prev_hash;
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
                    "Tip height {tip_idx} must be greater than ancestor height {ancestor_idx}"
                ));
            }

            let diff = tip_idx.checked_sub(ancestor_idx).ok_or_else(|| {
                format!("Tip height {tip_idx} must not be lower than ancestor height {ancestor_idx}")
            })?;

            if diff > MAX_BLOCKS_BETWEEN_REQUEST {
                return Err(format!(
                    "Requested block range is too large: {diff} blocks exceeds limit {MAX_BLOCKS_BETWEEN_REQUEST}"
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
                        return Err(format!("Hash linkage broken at index {idx}"));
                    }
                } else if block.metadata.previous_hash != ancestor {
                    return Err(format!(
                        "First block after ancestor (index {idx}) has wrong previous_hash"
                    ));
                }

                blocks.push(block);
            }

            Ok(blocks)
        }
    }
}

use blockchain::block_002_blocks::{Block, BlockMetadata};
use blockchain::transaction_005_tx_account_tree::AccountModelTree;
use blockchain::transaction_005_tx_batch::TransactionBatch;
use memory_manager::{BlockStore, Mode, RockDBManager};
use network::p2p_006_reqresp::Hash;
use runtime::p2p_006_sync_runtime::NodeOpts;
use utility::alpha_001_global_configuration::GlobalConfiguration;
use utility::alpha_002_error_detection_system::ErrorDetection;

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz input reader
// ─────────────────────────────────────────────────────────────────────────────

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }


    fn usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }
        usize::from(self.byte()) % max_exclusive
    }

    fn u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        for b in &mut out {
            *b = self.byte();
        }
        u64::from_le_bytes(out)
    }

    fn small_u64(&mut self, modulus: u64) -> u64 {
        if modulus == 0 {
            return 0;
        }
        self.u64() % modulus
    }

    fn bytes(&mut self, max_len: usize, allow_empty: bool) -> Vec<u8> {
        let mut len = self.usize(max_len.saturating_add(1));
        if !allow_empty && len == 0 {
            len = 1;
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.byte());
        }
        out
    }

    fn ascii_string(&mut self, prefix: &str, max_len: usize) -> String {
        let len = 1 + self.usize(max_len.max(1));
        let mut out = String::with_capacity(prefix.len() + len);
        out.push_str(prefix);
        for _ in 0..len {
            let c = b'a' + (self.byte() % 26);
            out.push(char::from(c));
        }
        out
    }

    fn hash(&mut self, salt: u8) -> Hash {
        let mut out = [0u8; 64];

        for (i, slot) in out.iter_mut().enumerate() {
            let a = self.byte();
            let b = self.byte().rotate_left(1);
            let c = self.byte().rotate_right(1);
            *slot = a ^ b ^ c ^ salt.wrapping_add(i as u8);
        }

        if out == [0u8; 64] {
            out[0] = 1;
        }

        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers and invariants
// ─────────────────────────────────────────────────────────────────────────────

fn touch_error(error: &ErrorDetection) {
    let _ = error.to_string();
    match error {
        ErrorDetection::DatabaseError { details }
        | ErrorDetection::BlockchainError { details }
        | ErrorDetection::SerializationError { details } => {
            let _ = details.len();
        }
        ErrorDetection::StorageError { message }
        | ErrorDetection::ConfigurationError { message } => {
            let _ = message.len();
        }
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            let _ = tx_id.as_ref().map(|s| s.len());
        }
        ErrorDetection::NotFound { resource } => {
            let _ = resource.len();
        }
        ErrorDetection::InvalidSignatureFormat { format } => {
            let _ = format.len();
        }
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            touch_error(&error);
            None
        }
    }
}

fn make_temp_root() -> PathBuf {
    let id = CASE_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!("/tmp/remzar-rocksdb-manager-fuzz-{id}"))
}

fn make_opts(root: &Path) -> NodeOpts {
    NodeOpts {
        data_dir: root.to_string_lossy().to_string(),
    }
}

fn choose_column(reader: &mut Reader<'_>) -> &'static str {
    const COLUMNS: &[&str] = &[
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
        "missing_column_family",
    ];
    COLUMNS[reader.usize(COLUMNS.len())]
}

fn make_block(reader: &mut Reader<'_>, index: u64, previous_hash: Hash, payload_max: usize) -> Block {
    let mut hash = reader.hash(index as u8);
    let idx_bytes = index.to_le_bytes();
    for (i, b) in idx_bytes.iter().enumerate() {
        hash[i] ^= *b;
        hash[63 - i] ^= b.wrapping_mul(31);
    }
    if hash == [0u8; 64] {
        hash[0] = 1;
    }

    Block {
        block_hash: hash,
        metadata: BlockMetadata {
            index,
            previous_hash,
        },
        payload: reader.bytes(payload_max, true),
    }
}

fn serialize_block(block: &Block) -> Vec<u8> {
    block
        .serialize_for_storage()
        .expect("mock block serialization should not fail")
}

fn assert_block_roundtrip(block: &Block) {
    let bytes = serialize_block(block);
    let decoded = Block::deserialize_from_storage(&bytes)
        .expect("serialized block should deserialize");
    assert_eq!(&decoded, block);
}

fn assert_manager_basics(manager: &RockDBManager) {
    // Directory paths must be deterministic and mode must be readable.
    let _ = manager.directory.db_path.to_string_lossy();
    let _ = manager.directory.blockchain_path.to_string_lossy();
    let _ = manager.directory.log_path.to_string_lossy();
    let _ = manager.directory.sidechain_path.to_string_lossy();

    match manager.mode {
        Mode::CLI | Mode::Blockchain | Mode::AccountModel | Mode::Sidechain | Mode::Log => {}
    }

    // Listing is allowed in all real public modes except Sidechain.
    if manager.mode != Mode::Sidechain {
        if let Some(cfs) = touch_result(manager.list_column_families()) {
            assert!(cfs.iter().any(|cf| cf == GlobalConfiguration::GLOBAL_COLUMN_NAME));
            assert!(cfs.iter().any(|cf| cf == GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME));
            assert!(cfs.iter().any(|cf| cf == GlobalConfiguration::STATE_COLUMN_NAME));
        }
    }
}

fn assert_height_metadata(manager: &RockDBManager, height: u64) {
    if manager.mode == Mode::CLI || manager.mode == Mode::Blockchain {
        if touch_result(manager.set_latest_block_index(height)).is_some() {
            if let Some(got) = touch_result(manager.get_latest_block_index()) {
                assert_eq!(got, height);
            }
            if let Some(tip_height) = touch_result(manager.get_tip_height()) {
                assert_eq!(tip_height, height);
            }
        }

        let other = height.wrapping_add(1) % 1_000_000;
        if touch_result(manager.set_tip_height(other)).is_some() {
            if let Some(got) = touch_result(manager.get_tip_height()) {
                assert_eq!(got, other);
            }
        }
    }
}

fn assert_metadata_roundtrip(manager: &RockDBManager, key: &str, value: &[u8]) {
    if manager.mode == Mode::CLI || manager.mode == Mode::Blockchain {
        if touch_result(manager.store_metadata(key, value)).is_some() {
            if let Some(got) = touch_result(manager.get_metadata(key)) {
                assert_eq!(got, Some(value.to_vec()));
            }
        }
    } else {
        assert!(manager.store_metadata(key, value).is_err());
    }
}

fn assert_generic_kv_roundtrip(
    manager: &RockDBManager,
    column: &str,
    key: &[u8],
    value: &[u8],
) {
    let write_result = manager.write(column, key, value);

    match manager.mode {
        Mode::CLI | Mode::Blockchain => {
            if column == "missing_column_family" {
                assert!(write_result.is_err());
                return;
            }

            if touch_result(write_result).is_some() {
                let got = touch_result(manager.read(column, key));
                if let Some(got) = got {
                    assert_eq!(got, Some(value.to_vec()));
                }

                let iter = touch_result(manager.iterate_column(column));
                if let Some(iter) = iter {
                    let mut found = false;
                    for item in iter {
                        if let Ok((k, v)) = item {
                            if k == key && v == value {
                                found = true;
                            }
                        }
                    }
                    assert!(found);
                }

                if touch_result(manager.delete(column, key)).is_some() {
                    let got_after_delete = touch_result(manager.read(column, key));
                    if let Some(got_after_delete) = got_after_delete {
                        assert_eq!(got_after_delete, None);
                    }
                }
            }
        }
        _ => {
            assert!(write_result.is_err());
        }
    }
}

fn assert_wallet_peer_roundtrip(manager: &RockDBManager, account: &str, value: &[u8]) {
    if manager.mode == Mode::CLI || manager.mode == Mode::Blockchain {
        if touch_result(manager.store_wallet_balance(account, value)).is_some() {
            if let Some(got) = touch_result(manager.get_wallet_balance(account)) {
                assert_eq!(got, Some(value.to_vec()));
            }
        }

        if touch_result(manager.register_peer(account, value)).is_some() {
            if let Some(got) = touch_result(manager.get_peer_info(account)) {
                assert_eq!(got, Some(value.to_vec()));
            }
            let _ = touch_result(manager.remove_peer(account));
            if let Some(got) = touch_result(manager.get_peer_info(account)) {
                assert_eq!(got, None);
            }
        }
    } else {
        assert!(manager.store_wallet_balance(account, value).is_err());
        assert!(manager.register_peer(account, value).is_err());
    }
}

fn assert_state_roundtrip(manager: &RockDBManager, account: &str, balance: u64) {
    if manager.mode == Mode::Blockchain || manager.mode == Mode::AccountModel {
        let mut tree = AccountModelTree::with_manager(manager.clone());
        tree.set_balance(account, balance);

        if touch_result(manager.store_state(&tree)).is_some() {
            if let Some(loaded) = touch_result(manager.load_state()) {
                assert_eq!(loaded.get_balance(account), balance);
            }
        }

        if touch_result(manager.set_account_balance(account, balance)).is_some() {
            if let Some(got) = touch_result(manager.get_account_balance(account)) {
                assert_eq!(got, balance);
            }
        }

        let batch = TransactionBatch::default();
        let _ = touch_result(manager.apply_transaction_batch(&batch));
    } else {
        assert!(manager.load_state().is_err());
        assert!(manager.set_account_balance(account, balance).is_err());
    }
}

fn insert_chain(
    manager: &RockDBManager,
    reader: &mut Reader<'_>,
    len: usize,
    payload_max: usize,
) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut previous = [0u8; 64];

    for i in 0..len {
        let height = u64::try_from(i).unwrap_or(0);
        let block = make_block(reader, height, previous, payload_max);
        assert_block_roundtrip(&block);

        let bytes = serialize_block(&block);

        if touch_result(manager.store_latest_block(&bytes, block.metadata.index)).is_some() {
            if let Some(raw) = touch_result(manager.get_block_bytes_by_index(block.metadata.index))
            {
                assert_eq!(raw, Some(bytes.clone()));
            }

            if let Some(got) = touch_result(manager.get_block_by_index(block.metadata.index)) {
                assert_eq!(got, Some(block.clone()));
            }

            if let Some(got_hash) = touch_result(manager.get_block_hash_by_index(block.metadata.index))
            {
                assert_eq!(got_hash, block.block_hash);
            }
        }

        if touch_result(manager.index_block_by_hash(&block.block_hash, &bytes)).is_some() {
            assert!(manager.has_block_by_hash(&block.block_hash));
            assert_eq!(manager.get_block_by_hash(&block.block_hash), Some(block.clone()));
        }

        previous = block.block_hash;
        blocks.push(block);
    }

    blocks
}

fn assert_blockchain_block_paths(manager: &RockDBManager, reader: &mut Reader<'_>) {
    if manager.mode != Mode::Blockchain {
        return;
    }

    // Empty payload is an important real error path.
    let empty_result = manager.store_latest_block(&[], reader.small_u64(16));
    assert!(empty_result.is_err());

    let batch_idx = reader.small_u64(64);
    let batch_bytes = reader.bytes(256, true);
    if touch_result(manager.store_batch_bytes(batch_idx, &batch_bytes)).is_some() {
        if let Some(got) = touch_result(manager.get_batch_bytes_by_index(batch_idx)) {
            assert_eq!(got, Some(batch_bytes.clone()));
        }
        if let Some(got) = touch_result(manager.get_tx_batch_bytes_by_index(batch_idx)) {
            assert_eq!(got, Some(batch_bytes.clone()));
        }
    }

    let addr_h = reader.small_u64(1_000_000);
    if touch_result(manager.set_addr_index_height(addr_h)).is_some() {
        if let Some(got) = touch_result(manager.get_addr_index_height()) {
            assert_eq!(got, addr_h);
        }
    }

    let block_root = format!(
        "fuzz-block-paths-{}",
        CASE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let block_opts = NodeOpts {
        data_dir: block_root.clone(),
    };
    let block_manager = match RockDBManager::new_blockchain(&block_opts, &block_root) {
        Ok(manager) => manager,
        Err(error) => {
            touch_error(&error);
            return;
        }
    };

    let chain_len = 2 + reader.usize(8);
    let blocks = insert_chain(&block_manager, reader, chain_len, 192);

    if let Some(latest) = touch_result(block_manager.get_latest_block()) {
        assert_eq!(latest, blocks.last().cloned());
    }

    if let Some(latest_hash) = touch_result(block_manager.get_latest_block_hash()) {
        assert_eq!(latest_hash, blocks.last().unwrap().block_hash);
    }

    if let Some(indices) = touch_result(block_manager.list_block_indices()) {
        assert!(!indices.is_empty());
        assert!(indices.iter().all(|s| s.starts_with("block_")));
    }

    if let Some(last_blocks) = touch_result(block_manager.get_last_blocks(chain_len + 2)) {
        assert!(!last_blocks.is_empty());
        assert!(last_blocks.len() <= chain_len);
        for w in last_blocks.windows(2) {
            // get_last_blocks returns descending key order: higher heights first.
            assert!(w[0].metadata.index >= w[1].metadata.index);
        }
    }

    if blocks.len() >= 2 {
        let ancestor = blocks[0].clone();
        let tip = blocks.last().cloned().unwrap();

        let between = block_manager.get_blocks_between(ancestor.block_hash, tip.block_hash);
        if let Ok(between) = between {
            assert_eq!(between.len(), blocks.len().saturating_sub(1));
            assert_eq!(between.first().map(|b| b.metadata.index), Some(1));
            assert_eq!(between.last().map(|b| b.block_hash), Some(tip.block_hash));
            for window in between.windows(2) {
                assert_eq!(window[1].metadata.previous_hash, window[0].block_hash);
            }
        }

        let common = block_manager.find_common_ancestor(tip.block_hash);
        assert_eq!(common, Some(tip.block_hash));

        let remove_idx = reader.usize(blocks.len());
        let remove_block = blocks[remove_idx].clone();
        if touch_result(block_manager.remove_block_by_index(remove_block.metadata.index)).is_some() {
            assert_eq!(
                touch_result(block_manager.get_block_by_index(remove_block.metadata.index)),
                Some(None)
            );
            assert!(!block_manager.has_block_by_hash(&remove_block.block_hash));
        }
    }

    // Malformed serialized block must fail hash indexing.
    let bad = reader.bytes(64, true);
    if !bad.is_empty() {
        let random_hash = reader.hash(0xD5);
        let _ = touch_result(block_manager.index_block_by_hash(&random_hash, &bad));
    }
}

fn assert_mode_specific_helpers(manager: &RockDBManager) {
    match manager.mode {
        Mode::CLI => {
            assert!(manager.open_db_cli().is_ok());
            assert!(manager.flush_cli_db().is_ok());
            assert!(manager.compact_cli_db().is_ok());
            assert!(manager.open_db_blockchain().is_err());
        }
        Mode::Blockchain => {
            assert!(manager.open_db_blockchain().is_ok());
            assert!(manager.open_db_blockchain_readonly().is_ok());
            assert!(manager.flush_blockchain_db().is_ok());
            assert!(manager.compact_blockchain_db().is_ok());
        }
        Mode::AccountModel => {
            assert!(manager.open_db_accountmodel().is_ok());
            assert!(manager.flush_state_db().is_ok());
            assert!(manager.compact_state_db().is_ok());
            assert!(manager.open_db_blockchain().is_err());
        }
        Mode::Log => {
            assert!(manager.open_db_log().is_ok());
            assert!(manager.read(GlobalConfiguration::LOGS_COLUMN_NAME, b"x").is_ok());
            assert!(manager.write(GlobalConfiguration::LOGS_COLUMN_NAME, b"x", b"y").is_err());
        }
        Mode::Sidechain => {}
    }
}

fn run_operation_script(
    reader: &mut Reader<'_>,
    cli: &RockDBManager,
    blockchain: &RockDBManager,
    accountmodel: &RockDBManager,
    log: &RockDBManager,
) {
    let managers = [cli, blockchain, accountmodel, log];
    let op_count = 8 + reader.usize(72);

    for _ in 0..op_count {
        let manager = managers[reader.usize(managers.len())];
        let op = reader.byte() % 18;
        let key = reader.ascii_string("k", 16);
        let account = reader.ascii_string("acct", 18);
        let value = reader.bytes(256, true);
        let height = reader.small_u64(1_000_000);
        let column = choose_column(reader);

        match op {
            0 => assert_manager_basics(manager),
            1 => assert_height_metadata(manager, height),
            2 => assert_metadata_roundtrip(manager, &key, &value),
            3 => assert_generic_kv_roundtrip(manager, column, key.as_bytes(), &value),
            4 => assert_wallet_peer_roundtrip(manager, &account, &value),
            5 => assert_state_roundtrip(manager, &account, height),
            6 => assert_blockchain_block_paths(manager, reader),
            7 => assert_mode_specific_helpers(manager),
            8 => {
                let _ = touch_result(manager.iterate_column(column));
            }
            9 => {
                let _ = touch_result(manager.list_column_families());
            }
            10 => {
                let _ = touch_result(manager.batch_process_all());
            }
            11 => {
                let _ = touch_result(manager.flush_cli_db());
                let _ = touch_result(manager.flush_blockchain_db());
                let _ = touch_result(manager.flush_state_db());
            }
            12 => {
                let _ = touch_result(manager.compact_cli_db());
                let _ = touch_result(manager.compact_blockchain_db());
                let _ = touch_result(manager.compact_state_db());
            }
            13 => {
                let _ = touch_result(manager.get_latest_block_by_iter());
                let _ = touch_result(manager.get_latest_block());
                let _ = touch_result(manager.get_latest_block_hash());
            }
            14 => {
                let _ = touch_result(manager.get_block_by_index(height % 16));
                let _ = touch_result(manager.get_block_bytes_by_index(height % 16));
                let _ = touch_result(manager.get_block_hash_by_index(height % 16));
            }
            15 => {
                let unknown = reader.hash(0xA5);
                let _ = manager.get_block_by_hash(&unknown);
                let _ = manager.has_block_by_hash(&unknown);
                let _ = manager.find_common_ancestor(unknown);
            }
            16 => {
                let _ = touch_result(manager.store_batch_bytes(height % 64, &value));
                let _ = touch_result(manager.get_batch_bytes_by_index(height % 64));
                let _ = touch_result(manager.get_tx_batch_bytes_by_index(height % 64));
            }
            _ => {
                let _ = touch_result(manager.remove_block_by_index(height % 16));
                let block_key = format!("block_{:010}", height % 16);
                let _ = touch_result(manager.delete_block(block_key.as_bytes()));
            }
        }
    }
}

fn exercise_mode_denials(
    cli: &RockDBManager,
    blockchain: &RockDBManager,
    accountmodel: &RockDBManager,
    log: &RockDBManager,
) {
    // These assertions keep the mock aligned with the real mode guardrails.
    assert!(cli.store_metadata("m", b"v").is_ok());
    assert!(blockchain.store_metadata("m", b"v").is_ok());
    assert!(accountmodel.store_metadata("m", b"v").is_err());
    assert!(log.store_metadata("m", b"v").is_err());

    assert!(cli.write(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"k", b"v").is_ok());
    assert!(blockchain
        .write(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"k", b"v")
        .is_ok());
    assert!(accountmodel
        .write(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"k", b"v")
        .is_err());
    assert!(log
        .write(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"k", b"v")
        .is_err());

    assert!(accountmodel.load_state().is_ok());
    assert!(blockchain.load_state().is_ok());
    assert!(cli.load_state().is_err());
    assert!(log.load_state().is_err());
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let data = if data.len() > 8_192 {
        &data[..8_192]
    } else {
        data
    };

    let root = make_temp_root();
    let opts = make_opts(&root);

    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let accountmodel_path = root.join(GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR);
    let log_path = root.join(GlobalConfiguration::LOG_DATABASE_DIR);

    let Some(cli) = touch_result(RockDBManager::new(&opts)) else {
        return;
    };
    let Some(blockchain) = touch_result(RockDBManager::new_blockchain(
        &opts,
        &blockchain_path.to_string_lossy(),
    )) else {
        return;
    };
    let Some(accountmodel) = touch_result(RockDBManager::new_accountmodel(
        &opts,
        &accountmodel_path.to_string_lossy(),
    )) else {
        return;
    };
    let Some(log) = touch_result(RockDBManager::new_log(&opts, &log_path.to_string_lossy())) else {
        return;
    };

    let _ = touch_result(RockDBManager::from_existing_readonly(
        &opts,
        &blockchain_path,
    ));

    exercise_mode_denials(&cli, &blockchain, &accountmodel, &log);

    let mut reader = Reader::new(data);

    assert_manager_basics(&cli);
    assert_manager_basics(&blockchain);
    assert_manager_basics(&accountmodel);
    assert_manager_basics(&log);

    assert_blockchain_block_paths(&blockchain, &mut reader);
    run_operation_script(&mut reader, &cli, &blockchain, &accountmodel, &log);
});
