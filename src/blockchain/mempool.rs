//! Mempool Module

use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::alpha_003_detection_system::DetectionSystem;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::time_policy::TimePolicy;

use postcard::to_allocvec;
use rust_rocksdb::{IteratorMode, WriteBatch};
use std::collections::HashSet;
use std::sync::Arc;

/// Production-ready mempool manager.
pub struct MemPool {
    db_manager: Arc<RockDBManager>,
    detection: Arc<DetectionSystem>,
}

impl MemPool {
    /// Creates a new mempool instance.
    pub fn new(db_manager: Arc<RockDBManager>, detection: Arc<DetectionSystem>) -> Self {
        Self {
            db_manager,
            detection,
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Wiring-only safety helpers (no crypto changes)
    // ────────────────────────────────────────────────────────────────────

    /// Key used to persist mempool byte usage (prevents O(N) scan per insert).
    const MEMPOOL_BYTES_KEY: &'static [u8] = b"__mempool_bytes_used_v1";

    /// Tightest tx-count cap (protocol cap + DoS cap).
    #[inline]
    fn max_batch_txs() -> usize {
        let protocol =
            usize::try_from(GlobalConfiguration::MAX_TXS_PER_BLOCK).unwrap_or(usize::MAX);
        let dos = GlobalConfiguration::MAX_BATCH_ITEMS;
        protocol.min(dos)
    }

    /// Compute the maximum number of bytes the mempool is allowed to contribute to a block.
    #[inline]
    fn batch_budget_bytes() -> usize {
        usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
            .unwrap_or(usize::MAX)
            .saturating_sub(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE)
    }

    /// Canonical byte representation for TxKind used for:
    /// - mempool sizing/budget checks
    /// - mempool hashing/deduplication
    /// - mempool storage bytes
    #[inline]
    fn canonical_txkind_bytes(kind: &TxKind) -> Result<Vec<u8>, ErrorDetection> {
        to_allocvec(kind).map_err(|e| ErrorDetection::SerializationError {
            details: format!("TxKind serialize failed: {e}"),
        })
    }

    /// Runtime-only mempool admission validation.
    fn validate_txkind_for_mempool(kind: &TxKind) -> Result<(), ErrorDetection> {
        // First run the enum-level validation that already exists in the project.
        kind.validate()?;

        // Then run variant-specific runtime timestamp hygiene for variants that
        // expose it. Other variants keep their structural validation from kind.validate().
        match kind {
            TxKind::Transfer(tx) => tx.validate_for_mempool(),
            TxKind::RegisterNode(tx) => tx.validate_for_mempool(),
            TxKind::Reward(tx) => tx.validate_for_runtime(),
            _ => Ok(()),
        }
    }

    /// Read persisted mempool bytes-used counter. If missing/corrupt, returns None.
    fn read_mempool_bytes_used(
        db: &rust_rocksdb::DB,
        cf_tx: &rust_rocksdb::ColumnFamily,
    ) -> Result<Option<u64>, ErrorDetection> {
        match db.get_pinned_cf(cf_tx, Self::MEMPOOL_BYTES_KEY) {
            Ok(Some(v)) => {
                let used: u64 =
                    postcard::from_bytes(&v).map_err(|e| ErrorDetection::SerializationError {
                        details: format!("Failed to decode mempool bytes counter: {}", e),
                    })?;
                Ok(Some(used))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ErrorDetection::StorageError {
                message: format!("Failed to read mempool bytes counter: {}", e),
            }),
        }
    }

    /// Recompute current mempool bytes by scanning CF (used as a fallback).
    fn recompute_mempool_bytes_used(
        db: &rust_rocksdb::DB,
        cf_tx: &rust_rocksdb::ColumnFamily,
    ) -> Result<u64, ErrorDetection> {
        let mut total: u64 = 0;
        for item in db.iterator_cf(cf_tx, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed iterating mempool for size recompute: {}", e),
            })?;
            // Skip our internal counter key.
            if k.as_ref() == Self::MEMPOOL_BYTES_KEY {
                continue;
            }
            total = total.checked_add(v.len() as u64).ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: "Overflow while recomputing mempool byte usage".into(),
                    tx_id: None,
                }
            })?;
        }
        Ok(total)
    }

    /// Defensive bound for untrusted mempool entry bytes before attempting deserialize.
    #[inline]
    fn check_entry_size_bound(len: usize) -> Result<(), ErrorDetection> {
        if len > GlobalConfiguration::MAX_ITEM_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Mempool entry too large: {} bytes > MAX_ITEM_BYTES {}",
                    len,
                    GlobalConfiguration::MAX_ITEM_BYTES
                ),
                tx_id: None,
            });
        }
        Ok(())
    }

    // ────────────────────────────────────────────────────────────────────
    // Add Transactions / TxKind to the Mempool
    // ────────────────────────────────────────────────────────────────────

    pub fn add_transaction(&self, tx: &Transaction) -> Result<(), ErrorDetection> {
        let kind = TxKind::Transfer(tx.clone());
        self.add_tx_kind(&kind)
    }

    /// Add an arbitrary `TxKind` into the mempool.
    pub fn add_tx_kind(&self, kind: &TxKind) -> Result<(), ErrorDetection> {
        Self::validate_txkind_for_mempool(kind)?;

        // Serialize TxKind using the CANONICAL encoding (must match BlockMint signature slices).
        let serialized = Self::canonical_txkind_bytes(kind)?;
        let new_size_u64: u64 = serialized.len() as u64;

        // Defensive: single item must not exceed MAX_ITEM_BYTES.
        Self::check_entry_size_bound(serialized.len())?;

        // Critical consensus safety: reject transactions that can NEVER fit in any block.
        let budget = Self::batch_budget_bytes();
        if serialized.len() > budget {
            let tx_id_opt = if let TxKind::Transfer(tx) = kind {
                Some(tx.id()?)
            } else {
                None
            };

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Transaction too large to ever fit: tx {} bytes > batch budget {} bytes (MAX_BLOCK_SIZE {} - BLOCK_OVERHEAD_RESERVE {})",
                    serialized.len(),
                    budget,
                    GlobalConfiguration::MAX_BLOCK_SIZE,
                    GlobalConfiguration::BLOCK_OVERHEAD_RESERVE
                ),
                tx_id: tx_id_opt,
            });
        }

        // Compute current buffer usage (persisted counter w/ graceful fallback).
        let db = self.db_manager.open_db_blockchain()?;
        let cf_tx = db
            .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF missing",
                    GlobalConfiguration::TRANSACTION_COLUMN_NAME
                ),
            })?;

        let current_buffer = match Self::read_mempool_bytes_used(&db, cf_tx)? {
            Some(v) => v,
            None => {
                // Grace fallback: recompute once if counter missing.
                Self::recompute_mempool_bytes_used(&db, cf_tx)?
            }
        };

        // Reject if adding this tx would exceed the configured mempool limit.
        let new_total = current_buffer.checked_add(new_size_u64).ok_or_else(|| {
            ErrorDetection::ValidationError {
                message: "Overflow while computing mempool capacity".into(),
                tx_id: None,
            }
        })?;
        if new_total > GlobalConfiguration::TRANSACTION_BUFFER_LIMIT {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Mempool full: current {} bytes + new {} bytes > {} bytes",
                    current_buffer,
                    new_size_u64,
                    GlobalConfiguration::TRANSACTION_BUFFER_LIMIT
                ),
                tx_id: None,
            });
        }

        // Existing replay-attack check — ONLY for balance-changing transfers.
        if let TxKind::Transfer(tx) = kind {
            let tx_id = tx.id()?;
            let existing_pairs = self.collect_existing_id_sig_pairs()?;
            self.detection.detect_replay(
                existing_pairs
                    .into_iter()
                    .chain(std::iter::once((tx_id, Vec::new()))),
            )?;
        }

        // Runtime storage key and column handles.
        let timestamp_key = Self::generate_unique_key()?;
        let cf_hash = db
            .cf_handle(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF missing", GlobalConfiguration::TX_TO_HASH_COLUMN_NAME),
            })?;

        // Canonical mempool hash = hash(canonical TxKind bytes).
        let hash: Hash = RemzarHash::compute_bytes_hash(&serialized);

        // Reject if this exact tx hash already exists.
        if db
            .get_pinned_cf(cf_hash, hash.as_slice())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to check existing tx hash: {}", e),
            })?
            .is_some()
        {
            let tx_id_opt = if let TxKind::Transfer(tx) = kind {
                Some(tx.id()?)
            } else {
                None
            };

            return Err(ErrorDetection::ValidationError {
                message: "Duplicate transaction (hash already in mempool)".into(),
                tx_id: tx_id_opt,
            });
        }

        // Batch write: store canonical TxKind bytes in both CFs + update bytes counter.
        let mut batch = WriteBatch::default();
        batch.put_cf(cf_tx, timestamp_key.as_bytes(), &serialized);
        batch.put_cf(cf_hash, hash, &serialized);

        // Update mempool bytes counter (stored in TRANSACTION CF).
        let counter_bytes =
            to_allocvec(&new_total).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to encode mempool bytes counter: {}", e),
            })?;
        batch.put_cf(cf_tx, Self::MEMPOOL_BYTES_KEY, &counter_bytes);

        db.write_opt(&batch, &RockDBManager::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed adding tx to mempool: {}", e),
            })
    }

    // ────────────────────────────────────────────────────────────────────
    // Helper: Collect existing (tx_id, signature) pairs from the mempool
    // ────────────────────────────────────────────────────────────────────
    fn collect_existing_id_sig_pairs(&self) -> Result<Vec<(String, Vec<u8>)>, ErrorDetection> {
        let db = self.db_manager.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF missing",
                    GlobalConfiguration::TRANSACTION_COLUMN_NAME
                ),
            })?;

        db.iterator_cf(cf, IteratorMode::Start)
            .filter_map(|item| item.ok())
            .filter_map(|(k, v)| {
                // Skip internal counter key.
                if k.as_ref() == Self::MEMPOOL_BYTES_KEY {
                    return None;
                }
                Some((k, v))
            })
            .filter_map(|(_k, v)| {
                // Defensive: refuse to deserialize unbounded entries.
                if Self::check_entry_size_bound(v.len()).is_err() {
                    return None;
                }
                TxKind::deserialize(&v).ok()
            })
            .filter_map(|kind| {
                if let TxKind::Transfer(tx) = kind {
                    Some(tx)
                } else {
                    None
                }
            })
            .map(|t| Ok((t.id()?, Vec::new()))) // We are only checking tx_id here.
            .collect()
    }

    // ────────────────────────────────────────────────────────────────────
    // Get Batchable Transactions (as TxKind)
    // ────────────────────────────────────────────────────────────────────
    /// Pull out as many pending txs as will fit in a block, returning their mempool-keys too.
    pub fn fetch_transactions_for_block(&self) -> Result<Vec<(Vec<u8>, TxKind)>, ErrorDetection> {
        let db = self.db_manager.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF missing",
                    GlobalConfiguration::TRANSACTION_COLUMN_NAME
                ),
            })?;

        let mut entries = Vec::new();
        let mut total_size = 0usize;
        let max_count = Self::max_batch_txs();

        let budget = Self::batch_budget_bytes();

        for item in db.iterator_cf(cf, IteratorMode::Start) {
            let (key, value) = item.map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed iterating mempool transactions: {}", e),
            })?;

            // Skip internal counter key.
            if key.as_ref() == Self::MEMPOOL_BYTES_KEY {
                continue;
            }

            // Defensive: bound entry size before deserialize (untrusted DB contents).
            Self::check_entry_size_bound(value.len())?;

            if let Ok(kind) = TxKind::deserialize(&value) {
                // Runtime freshness is rechecked when selecting from mempool so old
                // or manually-inserted poisoned DB entries do not get batched.
                if Self::validate_txkind_for_mempool(&kind).is_err() {
                    continue;
                }

                // Canonical size must be measured using the same encoding used by BlockMint signatures.
                // This makes mempool selection deterministic and future-proof even if older DB entries
                // used a different encoding historically.
                let canonical_bytes = match Self::canonical_txkind_bytes(&kind) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let size = canonical_bytes.len();

                // If a single item exceeds the budget, it cannot fit in ANY block.
                // We do not include it; it should have been rejected on admission
                // (add_tx_kind guard), but this is defensive for old DB contents.
                if size > budget {
                    continue;
                }

                if total_size.saturating_add(size) > budget {
                    // Too large to include in this batch; skip it but keep scanning.
                    continue;
                }
                if entries.len() >= max_count {
                    break;
                }

                total_size = total_size.saturating_add(size);
                entries.push((key.to_vec(), kind));
            }
        }

        Ok(entries)
    }

    // ────────────────────────────────────────────────────────────────────
    // Remove Transactions After Block Inclusion
    // ────────────────────────────────────────────────────────────────────
    pub fn remove_transactions(&self, tx_keys: &[Vec<u8>]) -> Result<(), ErrorDetection> {
        let db = self.db_manager.open_db_blockchain()?;

        let cf_tx = db
            .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF missing",
                    GlobalConfiguration::TRANSACTION_COLUMN_NAME
                ),
            })?;

        let cf_hash = db
            .cf_handle(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF missing", GlobalConfiguration::TX_TO_HASH_COLUMN_NAME),
            })?;

        // Read current counter (grace fallback to recompute).
        let current_buffer = match Self::read_mempool_bytes_used(&db, cf_tx)? {
            Some(v) => v,
            None => Self::recompute_mempool_bytes_used(&db, cf_tx)?,
        };
        let mut new_buffer = current_buffer;

        let mut batch = WriteBatch::default();

        // Delete both the timestamp-keyed entry and its hash-index entry.
        for key in tx_keys {
            if key.as_slice() == Self::MEMPOOL_BYTES_KEY {
                continue;
            }

            if let Ok(Some(val)) = db.get_pinned_cf(cf_tx, key) {
                // Update bytes counter (subtract stored len, checked).
                new_buffer = new_buffer.saturating_sub(val.len() as u64);

                // Delete hash index by re-hashing the stored bytes.
                let h = RemzarHash::compute_bytes_hash(&val);
                batch.delete_cf(cf_hash, h);
            }

            batch.delete_cf(cf_tx, key);
        }

        // Update counter key.
        let counter_bytes =
            to_allocvec(&new_buffer).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to encode mempool bytes counter: {}", e),
            })?;
        batch.put_cf(cf_tx, Self::MEMPOOL_BYTES_KEY, &counter_bytes);

        db.write_opt(&batch, &RockDBManager::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to remove transactions from mempool: {}", e),
            })
    }

    /// Remove any mempool transactions that were included in the given batch.
    pub fn remove_transactions_in_batch(
        &self,
        batch: &crate::blockchain::transaction_005_tx_batch::TransactionBatch,
    ) -> Result<(), ErrorDetection> {
        // Build a set of hashes for all TxKinds in the batch using CANONICAL bytes.
        let mut wanted: HashSet<Hash> = HashSet::new();
        for k in &batch.transactions {
            let bytes = Self::canonical_txkind_bytes(k)?;
            let h: Hash = RemzarHash::compute_bytes_hash(&bytes);
            wanted.insert(h);
        }
        if wanted.is_empty() {
            return Ok(());
        }

        // Open DB and column families.
        let db = self.db_manager.open_db_blockchain()?;
        let cf_tx = db
            .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF missing",
                    GlobalConfiguration::TRANSACTION_COLUMN_NAME
                ),
            })?;
        let cf_hash = db
            .cf_handle(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF missing", GlobalConfiguration::TX_TO_HASH_COLUMN_NAME),
            })?;

        // Read current counter (grace fallback to recompute).
        let current_buffer = match Self::read_mempool_bytes_used(&db, cf_tx)? {
            Some(v) => v,
            None => Self::recompute_mempool_bytes_used(&db, cf_tx)?,
        };
        let mut new_buffer = current_buffer;

        // Scan timestamp-keyed mempool entries, delete any whose hash is in `wanted`.
        let mut wb = WriteBatch::default();
        for item in db.iterator_cf(cf_tx, IteratorMode::Start) {
            let (key, val) = item.map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed iterating mempool for prune: {}", e),
            })?;

            // Skip counter key.
            if key.as_ref() == Self::MEMPOOL_BYTES_KEY {
                continue;
            }

            // `val` is stored mempool bytes; hash it directly (must match admission/indexing).
            let h = RemzarHash::compute_bytes_hash(&val);
            if wanted.contains(&h) {
                new_buffer = new_buffer.saturating_sub(val.len() as u64);
                wb.delete_cf(cf_tx, &key);
                wb.delete_cf(cf_hash, h);
            }
        }

        // Update counter key.
        let counter_bytes =
            to_allocvec(&new_buffer).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to encode mempool bytes counter: {}", e),
            })?;
        wb.put_cf(cf_tx, Self::MEMPOOL_BYTES_KEY, &counter_bytes);

        db.write_opt(&wb, &RockDBManager::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed pruning mempool after batch: {}", e),
            })
    }

    // ────────────────────────────────────────────────────────────────────
    // Get Transaction by Hash
    // ────────────────────────────────────────────────────────────────────
    pub fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, ErrorDetection> {
        let db = self.db_manager.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("{} CF missing", GlobalConfiguration::TX_TO_HASH_COLUMN_NAME),
            })?;

        match db.get_pinned_cf(cf, hash) {
            Ok(Some(data)) => {
                // Defensive bound for untrusted data.
                Self::check_entry_size_bound(data.len())?;

                match TxKind::deserialize(&data) {
                    Ok(TxKind::Transfer(tx)) => Ok(Some(tx)),
                    Ok(_) => Ok(None),
                    Err(e) => Err(ErrorDetection::SerializationError {
                        details: format!("Deserialize TxKind failed: {}", e),
                    }),
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ErrorDetection::StorageError {
                message: format!("Error accessing transaction by hash: {}", e),
            }),
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Count Pending Transactions
    // ────────────────────────────────────────────────────────────────────
    pub fn mempool_size(&self) -> Result<usize, ErrorDetection> {
        let db = self.db_manager.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "{} CF missing",
                    GlobalConfiguration::TRANSACTION_COLUMN_NAME
                ),
            })?;

        // Exclude our internal counter key.
        let count = db
            .iterator_cf(cf, IteratorMode::Start)
            .filter_map(|it| it.ok())
            .filter(|(k, _v)| k.as_ref() != Self::MEMPOOL_BYTES_KEY)
            .count();
        Ok(count)
    }

    // ────────────────────────────────────────────────────────────────────
    // Utilities
    // ────────────────────────────────────────────────────────────────────
    fn generate_unique_key() -> Result<String, ErrorDetection> {
        use rand::RngExt as _;

        // Runtime-only storage key. This is not consensus data.
        // We use TimePolicy instead of direct chrono::Utc so wall-clock use is centralized.
        let now_millis = TimePolicy::now_unix_millis_runtime()?;
        let now_microsish =
            now_millis
                .checked_mul(1_000)
                .ok_or_else(|| ErrorDetection::TimestampError {
                    message: "Failed to generate mempool key timestamp".into(),
                    details: "milliseconds-to-microseconds multiplication overflowed".into(),
                    source: None,
                })?;

        let rand_suffix: u32 = rand::rng().random();

        Ok(format!("tx_{}_{}", now_microsish, rand_suffix))
    }
}
