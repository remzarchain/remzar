use crate::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::storage::rocksdb_002_schema::RockDbSchema;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::KVVecResult;
use rayon::prelude::*;
use rust_rocksdb::{ColumnFamily, DB, IteratorMode, WriteBatch};
use std::result::Result;
use std::sync::Arc;

pub struct RockBatch {
    /// Shared reference to the **DB** (CLI or Blockchain).
    pub db: Arc<DB>,
}

impl RockBatch {
    // ─────────────────────────────────────────────────────────────────
    // (A) OPENING DATABASES (aligned with RockDbSchema)
    // ─────────────────────────────────────────────────────────────────

    /// Opens the **CLI DB** using the robust schema options.
    pub fn open_db_cli(path: &str) -> Result<DB, ErrorDetection> {
        let opts = RockDbSchema::robust_db_options();
        // CLI DB uses only the default CF
        DB::open(&opts, path).map_err(|e| ErrorDetection::DatabaseError {
            details: format!("RockBatch CLI open failed at {}: {}", path, e),
        })
    }

    /// Opens the **Blockchain DB** with all column families and robust options.
    pub fn open_db_blockchain(path: &str) -> Result<DB, ErrorDetection> {
        let opts = RockDbSchema::robust_db_options();
        let cf_descriptors = CFDescriptors::get_cf_descriptors();
        DB::open_cf_descriptors(&opts, path, cf_descriptors).map_err(|e| {
            ErrorDetection::DatabaseError {
                details: format!("RockBatch blockchain open failed at {}: {}", path, e),
            }
        })
    }

    // ─────────────────────────────────────────────────────────────────
    // (B) TRANSACTION BATCH OPERATIONS
    // ─────────────────────────────────────────────────────────────────
    pub fn store_transaction_batch(
        &self,
        batch_index: u64,
        serialized_batch: &[u8],
    ) -> Result<(), String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::transaction_batch_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::transaction_batch_column_name()
                )
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_handle, batch_index.to_be_bytes(), serialized_batch);

        self.db
            .write(&batch)
            .map_err(|e| format!("Failed to commit transaction batch: {}", e))?;
        Ok(())
    }

    /// **Lists all transaction batches** in the `transaction_batch` column family.
    pub fn list_unprocessed_batches(&self) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::transaction_batch_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::transaction_batch_column_name()
                )
            })?;

        let iter = self.db.iterator_cf(cf_handle, IteratorMode::Start);
        let data: Vec<(u64, Vec<u8>)> = iter
            .filter_map(|kv| kv.ok())
            .filter_map(|(k, v)| {
                if k.len() < 8 {
                    return None;
                }
                let mut idx_bytes = [0u8; 8];
                let prefix = k.get(..8)?;
                idx_bytes.copy_from_slice(prefix);
                let index = u64::from_be_bytes(idx_bytes);
                Some((index, v.to_vec()))
            })
            .collect();
        Ok(data)
    }

    // ─────────────────────────────────────────────────────────────────
    // (C) SIGNATURE AND META DATA OPERATIONS
    // ─────────────────────────────────────────────────────────────────
    pub fn store_batch_signature(
        &self,
        signing_data_key: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::meta_data_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::meta_data_column_name()
                )
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_handle, signing_data_key, signature);

        self.db
            .write(&batch)
            .map_err(|e| format!("Failed to store batch signature: {}", e))?;
        Ok(())
    }

    pub fn load_batch_signature(&self, signing_data_key: &[u8]) -> Result<Vec<u8>, String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::meta_data_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::meta_data_column_name()
                )
            })?;

        let stored_signature = self
            .db
            .get_cf(cf_handle, signing_data_key)
            .map_err(|e| format!("Error retrieving batch signature: {}", e))?
            .ok_or_else(|| "No batch signature found".to_string())?;
        Ok(stored_signature)
    }

    // ─────────────────────────────────────────────────────────────────
    // (E) TRANSACTION & META RECORD EXECUTION
    // ─────────────────────────────────────────────────────────────────
    pub fn batch_execute_records(&self) -> Result<(), String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::transaction_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::transaction_column_name()
                )
            })?;

        let records = self.load_all_kv(cf_handle);
        records.par_iter().try_for_each(|(key, value)| {
            if key.is_empty() || value.is_empty() {
                Err("Record invalid: key or value is empty".to_string())
            } else {
                Ok(())
            }
        })?;

        let meta_cf = self
            .db
            .cf_handle(RockDbSchema::meta_data_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::meta_data_column_name()
                )
            })?;

        let mut batch = WriteBatch::default();
        for (key, _) in &records {
            let info = format!("Applied record: {:?}", key);
            batch.put_cf(meta_cf, key, info.as_bytes());
        }
        self.db
            .write(&batch)
            .map_err(|e| format!("Batch execution failed: {}", e))?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // (F) TEMPORARY TRANSACTION STORAGE
    // ─────────────────────────────────────────────────────────────────
    pub fn store_temp_transaction(&self, tx_key: &[u8], tx_data: &[u8]) -> Result<(), String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::transaction_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::transaction_column_name()
                )
            })?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf_handle, tx_key, tx_data);
        self.db
            .write(&batch)
            .map_err(|e| format!("Failed to store temp transaction: {}", e))?;
        Ok(())
    }

    pub fn list_temp_transactions(&self) -> KVVecResult {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::transaction_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::transaction_column_name()
                )
            })?;
        Ok(self.load_all_kv(cf_handle))
    }

    pub fn store_temp_transactions(
        &self,
        transactions: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::transaction_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::transaction_column_name()
                )
            })?;
        let mut batch = WriteBatch::default();
        for (tx_key, tx_data) in transactions {
            batch.put_cf(cf_handle, tx_key, tx_data);
        }
        self.db
            .write(&batch)
            .map_err(|e| format!("Failed to store transactions: {}", e))?;
        Ok(())
    }

    // ───────────────────────────────────────────────────────
    // (G) LOG COLUMN OPERATIONS
    // ───────────────────────────────────────────────────────
    /// **Stores a log entry** in the `logs_data` column family.
    pub fn store_log_entry(&self, log_key: &[u8], log_value: &[u8]) -> Result<(), String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::logs_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::logs_column_name()
                )
            })?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf_handle, log_key, log_value);
        self.db
            .write(&batch)
            .map_err(|e| format!("Failed to write log entry: {}", e))?;
        Ok(())
    }

    /// **Lists all log entries** in the `logs_data` column family.
    pub fn list_log_entries(&self) -> KVVecResult {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::logs_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::logs_column_name()
                )
            })?;
        Ok(self.load_all_kv(cf_handle))
    }

    // ─────────────────────────────────────────────────────────────────
    // (H) REWARD BATCH OPERATIONS
    // ─────────────────────────────────────────────────────────────────
    /// **Stores a reward batch** in the `reward_batch` column family.
    pub fn store_reward_batch(
        &self,
        batch_index: u64,
        serialized_reward_batch: &[u8],
    ) -> Result<(), String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::reward_batch_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::reward_batch_column_name()
                )
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(
            cf_handle,
            batch_index.to_be_bytes(),
            serialized_reward_batch,
        );

        self.db
            .write(&batch)
            .map_err(|e| format!("Failed to commit reward batch: {}", e))?;
        Ok(())
    }

    /// **Lists all reward batches** in the `reward_batch` column family.
    pub fn list_reward_batches(&self) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let cf_handle = self
            .db
            .cf_handle(RockDbSchema::reward_batch_column_name())
            .ok_or_else(|| {
                format!(
                    "Column Family {} not found",
                    RockDbSchema::reward_batch_column_name()
                )
            })?;
        let iter = self.db.iterator_cf(cf_handle, IteratorMode::Start);
        let data: Vec<(u64, Vec<u8>)> = iter
            .filter_map(|kv| kv.ok())
            .filter_map(|(k, v)| {
                if k.len() < 8 {
                    return None;
                }
                let mut idx_bytes = [0u8; 8];
                let prefix = k.get(..8)?;
                idx_bytes.copy_from_slice(prefix);
                let index = u64::from_be_bytes(idx_bytes);
                Some((index, v.to_vec()))
            })
            .collect();
        Ok(data)
    }

    // ─────────────────────────────────────────────────────────────────
    // (I) SINGLE TRANSACTION & REWARD WRITERS
    // ─────────────────────────────────────────────────────────────────

    /// Persist one RewardTx into the `reward_data` CF
    pub fn store_reward(&self, rew_id: &[u8], rew_bytes: &[u8]) -> Result<(), String> {
        let cf = self
            .db
            .cf_handle(RockDbSchema::reward_column_name())
            .ok_or_else(|| format!("CF {} not found", RockDbSchema::reward_column_name()))?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf, rew_id, rew_bytes);
        self.db.write(&batch).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persist one Transaction into the `transaction_data` CF
    pub fn store_transaction(&self, tx_id: &[u8], tx_bytes: &[u8]) -> Result<(), String> {
        let cf = self
            .db
            .cf_handle(RockDbSchema::transaction_column_name())
            .ok_or_else(|| format!("CF {} not found", RockDbSchema::transaction_column_name()))?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf, tx_id, tx_bytes);
        self.db.write(&batch).map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // PRIVATE / HELPER METHODS
    // ─────────────────────────────────────────────────────────────────
    /// Loads all key/value pairs from a given column family.
    fn load_all_kv(&self, cf: &ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let data: Vec<(Vec<u8>, Vec<u8>)> = iter
            .filter_map(|kv| kv.ok())
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        data
    }
}
