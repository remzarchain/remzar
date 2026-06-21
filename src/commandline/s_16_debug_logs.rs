//! src/commandline/s_16_debug_logs.rs

use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_002_schema::RockDbSchema;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;
use colored::Colorize;
use rust_rocksdb::IteratorMode;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Section 16: Debug Log Information.
pub struct S16DebugLogs;

impl S16DebugLogs {
    pub fn new() -> Self {
        Self
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // 16) Debug Log Information (exports latest ~1MB to JSON) — hardened (NO new deps)
    // ──────────────────────────────────────────────────────────────────────────────
    pub fn debug_logs(
        &self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        // ─────────────── Lightweight CLI/DoS guards ───────────────
        const MAX_YN_INPUT_LEN: usize = 16;
        const MAX_PROMPT_ATTEMPTS: usize = 5;

        // Export budget.
        const MAX_TOTAL_EXPORT_BYTES: usize = 1_048_576;

        // If a single log value is huge, don’t allocate/pretty-print it in memory.
        const MAX_SINGLE_ENTRY_BYTES: usize = 256 * 1024;

        // Only attempt JSON parsing/pretty-print if the decoded string is reasonably small.
        const MAX_JSON_PARSE_CHARS: usize = 64 * 1024;
        // ───────────────────────────────────────────────────────────

        // Read a line with a hard cap (prevents paste/pipe DoS)
        fn read_line_capped(prompt: &str, cap: usize) -> Result<String, ErrorDetection> {
            use std::io::{self, Write};

            print!("{prompt}");
            io::stdout().flush().map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to flush stdout: {}", e),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;

            let mut s = String::new();
            io::stdin()
                .read_line(&mut s)
                .map_err(|e| ErrorDetection::IoError {
                    message: format!("Failed to read input: {}", e),
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                })?;

            if s.len() > cap {
                return Err(ErrorDetection::ValidationError {
                    message: format!("Input too long (max {} chars)", cap),
                    tx_id: None,
                });
            }

            Ok(s.trim().to_string())
        }

        // Prompt user (guarded attempts)
        let mut attempts = 0usize;
        loop {
            attempts = attempts.saturating_add(1);
            if attempts > MAX_PROMPT_ATTEMPTS {
                println!(
                    "{}",
                    "❌ Too many invalid attempts. Returning to the menu.".red()
                );
                return Ok(());
            }

            let ans = match read_line_capped(
                "🪵 Do you want to check your error logs? (yes/no): ",
                MAX_YN_INPUT_LEN,
            ) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("❌ {}", e).red());
                    json_logger
                        .log_error_event("log", "PromptInputTooLong", "Prompt input too long")
                        .ok();
                    continue;
                }
            };

            match ans.to_ascii_lowercase().as_str() {
                "yes" | "y" => break,
                "no" | "n" => {
                    println!("{}", "❌ Returning to the menu.".red());
                    return Ok(());
                }
                _ => println!(
                    "{}",
                    "❌ Invalid response. Please type 'yes' or 'no'.".red()
                ),
            }
        }

        // Export latest ~1 MB of logs (hardened decoding/parsing)
        let db = json_logger.db();
        let cf = db
            .cf_handle(RockDbSchema::logs_column_name())
            .ok_or_else(|| {
                let msg = "logs_data column family not found".to_string();
                json_logger.log_error_event("log", "CfMissing", &msg).ok();
                ErrorDetection::StorageError { message: msg }
            })?;

        // Store JSON Values directly (safer than building huge Strings)
        let mut out_values: Vec<serde_json::Value> = Vec::new();
        let mut total_size = 0usize;

        for item in db.iterator_cf(cf, IteratorMode::End) {
            let (_k, val) = match item {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("⚠️ Failed to read log entry: {}", e);
                    continue;
                }
            };

            let sz = val.len();

            // Hard per-entry guard: skip absurdly large blobs
            if sz > MAX_SINGLE_ENTRY_BYTES {
                if total_size >= MAX_TOTAL_EXPORT_BYTES && !out_values.is_empty() {
                    break;
                }
                out_values.push(serde_json::json!({
                    "skipped": "entry_too_large",
                    "bytes": sz,
                    "note": "Log entry exceeded per-entry cap; omitted from export for safety."
                }));
                continue;
            }

            // Stop when we exceed the total budget (same behavior as before)
            if total_size.saturating_add(sz) > MAX_TOTAL_EXPORT_BYTES && !out_values.is_empty() {
                break;
            }

            // Strict UTF-8: no lossy. If not UTF-8, hex wrap it (NO new deps; you already have `hex`).
            let value_json: serde_json::Value = match std::str::from_utf8(&val) {
                Ok(s) => {
                    if s.len() <= MAX_JSON_PARSE_CHARS {
                        // Parse compact JSON, pretty-print happens at file serialization step
                        match serde_json::from_str::<serde_json::Value>(s) {
                            Ok(v) => v,
                            Err(_) => serde_json::json!({ "malformed": s }),
                        }
                    } else {
                        serde_json::json!({
                            "raw": s,
                            "note": "Entry too large to JSON-parse/pretty-print; stored as raw string."
                        })
                    }
                }
                Err(_) => {
                    // Non-UTF8 bytes: encode as hex (deterministic, strict)
                    let hx = hex::encode(&val);
                    serde_json::json!({
                        "non_utf8_hex": hx,
                        "bytes": sz
                    })
                }
            };

            out_values.push(value_json);
            total_size = total_size.saturating_add(sz);
        }

        out_values.reverse(); // oldest → newest

        if out_values.is_empty() {
            println!("{}", "ℹ️ No logs available to export.".yellow());
            return Ok(());
        }

        // Ensure output directory exists via DirectoryDB
        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| {
            let msg = format!("Failed to initialize directories: {}", e);
            json_logger
                .log_error_event("log", "DirectoryDBInitFailed", &msg)
                .ok();
            ErrorDetection::StorageError { message: msg }
        })?;

        directory.create_log_directory().map_err(|e| {
            let msg = format!("Failed to create log directory: {}", e);
            json_logger
                .log_error_event("log", "CreateDirFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: None,
                source: None,
            }
        })?;

        let out_path = directory.log_path.join("remzar_error_log.json");

        // Atomic write: tmp -> rename (prevents partial/corrupt files on crash)
        let mut tmp_path: PathBuf = out_path.clone();
        tmp_path.set_extension("json.tmp");

        if let Err(_e) = fs::remove_file(&tmp_path) {
            // (file may not exist, permissions, etc.)
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                let msg = format!("Failed to create temp log file: {}", e);
                json_logger
                    .log_error_event("log", "CreateTempFileFailed", &msg)
                    .ok();
                ErrorDetection::IoError {
                    message: msg,
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                }
            })?;

        // Pretty JSON array (bounded by ~1MB + markers; avoids per-entry pretty work)
        let pretty = serde_json::to_string_pretty(&out_values).map_err(|e| {
            let msg = format!("Failed to serialize logs to JSON: {}", e);
            json_logger
                .log_error_event("log", "SerializeJsonFailed", &msg)
                .ok();
            ErrorDetection::SerializationError { details: msg }
        })?;

        file.write_all(pretty.as_bytes()).map_err(|e| {
            let msg = format!("Failed to write temp log file: {}", e);
            json_logger
                .log_error_event("log", "WriteTempFileFailed", &msg)
                .ok();
            ErrorDetection::IoError {
                message: msg,
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        file.flush().map_err(|e| {
            json_logger
                .log_error_event(
                    "log",
                    "FlushTempFileFailed",
                    "Failed to flush temp log file",
                )
                .ok();

            ErrorDetection::IoError {
                message: "Failed to flush temp log file".to_string(),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        fs::rename(&tmp_path, &out_path).map_err(|e| {
            json_logger
                .log_error_event(
                    "log",
                    "FinalizeRenameFailed",
                    "Failed to finalize log file (rename temp -> final)",
                )
                .ok();

            ErrorDetection::IoError {
                message: "Failed to finalize log file (rename temp -> final)".to_string(),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        println!(
            "{}",
            format!("✅ Exported latest logs (~1 MB) to {}", out_path.display()).green()
        );

        Ok(())
    }
}

impl Default for S16DebugLogs {
    fn default() -> Self {
        Self::new()
    }
}
