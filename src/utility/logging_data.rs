// src/utility/logging.rs

use crate::storage::{rocksdb_000_directory::DirectoryDB, rocksdb_002_schema::RockDbSchema};
use crate::utility::time_policy::TimePolicy;
use chrono::{DateTime, SecondsFormat};
use rust_rocksdb::DB;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static LOG_KEY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A logger that writes structured JSON logs to a RocksDB column family.
pub struct JsonLogger {
    db: Arc<DB>,
    cf_name: &'static str,
}

impl JsonLogger {
    pub fn new(directory_db: &DirectoryDB) -> Result<Self, String> {
        let db = RockDbSchema::open_log_db(directory_db)
            .map_err(|e| format!("Failed to open log DB: {:?}", e))?;
        Ok(JsonLogger {
            db: Arc::new(db),
            cf_name: RockDbSchema::logs_column_name(),
        })
    }

    /// Runtime/off-chain UNIX milliseconds for logging.
    #[inline]
    fn runtime_unix_millis() -> Result<u64, String> {
        TimePolicy::now_unix_millis_runtime()
            .map_err(|e| format!("Failed to derive runtime log timestamp: {e:?}"))
    }

    /// Runtime/off-chain UTC timestamp for JSON log fields.
    #[inline]
    fn runtime_rfc3339_millis() -> Result<String, String> {
        let now_ms = Self::runtime_unix_millis()?;
        let now_i64 = i64::try_from(now_ms)
            .map_err(|_| format!("Runtime log timestamp does not fit i64: {now_ms}"))?;

        DateTime::from_timestamp_millis(now_i64)
            .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Millis, true))
            .ok_or_else(|| format!("Failed to format runtime log timestamp: {now_ms}"))
    }

    /// Build a unique, lexicographically sortable RocksDB key for a log entry.
    #[inline]
    fn log_key() -> Result<String, String> {
        let now_ms = Self::runtime_unix_millis()?;
        let seq = LOG_KEY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(format!("{now_ms:020}_{seq:016}"))
    }

    pub fn log(&self, log_entry: &Value) -> Result<(), String> {
        let log_bytes = serde_json::to_vec(log_entry)
            .map_err(|e| format!("Failed to serialize log entry: {:?}", e))?;

        let log_key = Self::log_key()?;

        let cf = self
            .db
            .cf_handle(self.cf_name)
            .ok_or("Failed to get logs column family handle")?;

        self.db
            .put_cf(cf, log_key.as_bytes(), &log_bytes)
            .map_err(|e| format!("Failed to write log entry: {:?}", e))?;
        Ok(())
    }

    /// Write a standard error event with full context (example).
    pub fn log_block_validation_failed(
        &self,
        block_number: u64,
        tx_hash: &str,
        expected_signature: &str,
        found_signature: &str,
        validator: &str,
        chain_id: &str,
    ) -> Result<(), String> {
        let current_thread = std::thread::current();
        let thread_name = current_thread.name().map_or("main", |s| s);
        let timestamp = Self::runtime_rfc3339_millis()?;

        let log_entry = json!({
            "timestamp": timestamp,
            "level": "ERROR",
            "system": "consensus_engine",
            "event": "BlockValidationFailed",
            "message": format!("Block {} failed validation due to invalid signature.", block_number),
            "block_number": block_number,
            "tx_hash": tx_hash,
            "node_id": "peer-7d92",
            "peer_ip": "192.0.2.5",
            "file": "consensus.rs",
            "line": 142,
            "thread": thread_name,
            "details": {
                "expected_signature": expected_signature,
                "found_signature": found_signature,
                "validator": validator,
                "chain_id": chain_id
            },
            "context": {
                "session": "s-202505201650",
                "user_id": "remzar",
                "rpc_call": "/block/validate"
            }
        });
        self.log(&log_entry)
    }

    /// Log any error with a custom event name.
    pub fn log_error_event(&self, system: &str, event: &str, message: &str) -> Result<(), String> {
        // keep the Thread object alive in a variable
        let current_thread = std::thread::current();
        let thread_name = current_thread.name().unwrap_or("main");
        let timestamp = Self::runtime_rfc3339_millis()?;

        let entry = json!({
            "timestamp": timestamp,
            "level":     "ERROR",
            "system":    system,
            "event":     event,
            "message":   message,
            "thread":    thread_name,
        });

        self.log(&entry)
    }

    pub fn db(&self) -> &Arc<DB> {
        &self.db
    }

    /// This allows RocksDB to safely delete WAL files up to this point.
    pub fn flush(&self) -> Result<(), String> {
        self.db
            .flush()
            .map_err(|e| format!("Failed to flush RocksDB logs: {}", e))
    }

    pub fn flush_logs_cf(&self) -> Result<(), String> {
        let cf = self
            .db
            .cf_handle(self.cf_name)
            .ok_or("Logs column family not found")?;
        self.db
            .flush_cf(cf)
            .map_err(|e| format!("Failed to flush log CF: {}", e))
    }
}
