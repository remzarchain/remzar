use chrono::DateTime;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_002_schema::RockDbSchema;
use remzar::utility::logging_data::JsonLogger;
use rust_rocksdb::IteratorMode;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

type TestResult = Result<(), String>;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_base_dir(label: &str) -> PathBuf {
    let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_logging_test_{}_{}_{}",
        label,
        std::process::id(),
        n
    ))
}

fn fresh_directory(label: &str) -> Result<DirectoryDB, String> {
    let base = next_base_dir(label);
    let directory = DirectoryDB::from_base_dir(&base)?;
    std::fs::create_dir_all(&directory.log_path).map_err(|e| e.to_string())?;
    Ok(directory)
}

fn fresh_logger(label: &str) -> Result<(DirectoryDB, JsonLogger), String> {
    let directory = fresh_directory(label)?;
    let logger = JsonLogger::new(&directory)?;
    Ok((directory, logger))
}

fn read_log_key_values(logger: &JsonLogger) -> Result<Vec<(String, Value)>, String> {
    let cf = logger
        .db()
        .cf_handle(RockDbSchema::logs_column_name())
        .ok_or_else(|| "logs column family was missing".to_string())?;

    let mut out = Vec::new();

    for item in logger.db().iterator_cf(cf, IteratorMode::Start) {
        let (key, value) = item.map_err(|e| e.to_string())?;
        let key = String::from_utf8(key.to_vec()).map_err(|e| e.to_string())?;
        let value = serde_json::from_slice::<Value>(&value).map_err(|e| e.to_string())?;
        out.push((key, value));
    }

    Ok(out)
}

fn read_log_values(logger: &JsonLogger) -> Result<Vec<Value>, String> {
    Ok(read_log_key_values(logger)?
        .into_iter()
        .map(|(_, value)| value)
        .collect())
}

fn log_and_flush(logger: &JsonLogger, entry: &Value) -> TestResult {
    logger.log(entry)?;
    logger.flush_logs_cf()?;
    Ok(())
}

fn only_log_value(logger: &JsonLogger) -> Result<Value, String> {
    let values = read_log_values(logger)?;
    assert_eq!(values.len(), 1);
    values
        .into_iter()
        .next()
        .ok_or_else(|| "missing only log value".to_string())
}

fn assert_rfc3339_millis_timestamp(value: &Value) -> TestResult {
    let ts = value
        .get("timestamp")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing timestamp string".to_string())?;

    assert!(ts.ends_with('Z'));
    assert!(ts.contains('.'));
    DateTime::parse_from_rfc3339(ts).map_err(|e| e.to_string())?;
    Ok(())
}

fn create_file_at(path: &Path) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, b"not a directory").map_err(|e| e.to_string())
}

fn parse_log_key_for_test(key: &str) -> Result<(u128, u128), String> {
    let (millis, seq) = key
        .split_once('_')
        .ok_or_else(|| format!("log key missing sequence separator: {key}"))?;

    if millis.len() != 20 {
        return Err(format!(
            "log key millis component should be 20 digits, got {} in {key}",
            millis.len()
        ));
    }

    if seq.len() != 16 {
        return Err(format!(
            "log key sequence component should be 16 digits, got {} in {key}",
            seq.len()
        ));
    }

    if !millis.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "log key millis component is not decimal digits: {key}"
        ));
    }

    if !seq.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "log key sequence component is not decimal digits: {key}"
        ));
    }

    let millis = millis.parse::<u128>().map_err(|e| e.to_string())?;
    let seq = seq.parse::<u128>().map_err(|e| e.to_string())?;

    Ok((millis, seq))
}

#[test]
fn logging_001_new_opens_log_db_and_logs_cf_exists() -> TestResult {
    let (_directory, logger) = fresh_logger("new_opens")?;

    assert!(
        logger
            .db()
            .cf_handle(RockDbSchema::logs_column_name())
            .is_some()
    );
    Ok(())
}

#[test]
fn logging_002_log_writes_simple_json_object() -> TestResult {
    let (_directory, logger) = fresh_logger("simple_object")?;
    let entry = json!({"level": "INFO", "event": "SimpleObject"});

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_003_log_writes_valid_json_bytes_to_logs_cf() -> TestResult {
    let (_directory, logger) = fresh_logger("valid_json_bytes")?;
    let entry = json!({"message": "valid json"});

    log_and_flush(&logger, &entry)?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["message"], "valid json");
    Ok(())
}

#[test]
fn logging_004_log_preserves_nested_object_fields() -> TestResult {
    let (_directory, logger) = fresh_logger("nested_object")?;
    let entry = json!({
        "level": "WARN",
        "details": {
            "height": 99,
            "validator": "rvalidator",
            "accepted": false
        }
    });

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["details"]["height"], 99);
    assert_eq!(stored["details"]["validator"], "rvalidator");
    assert_eq!(stored["details"]["accepted"], false);
    Ok(())
}

#[test]
fn logging_005_log_preserves_array_values() -> TestResult {
    let (_directory, logger) = fresh_logger("array_values")?;
    let entry = json!({"peers": ["peer-a", "peer-b", "peer-c"]});

    log_and_flush(&logger, &entry)?;

    assert_eq!(
        only_log_value(&logger)?["peers"].as_array().map(Vec::len),
        Some(3)
    );
    Ok(())
}

#[test]
fn logging_006_log_preserves_number_bool_and_null_values() -> TestResult {
    let (_directory, logger) = fresh_logger("scalar_values")?;
    let entry = json!({
        "height": 123456789_u64,
        "ok": true,
        "optional": null
    });

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["height"], 123456789_u64);
    assert_eq!(stored["ok"], true);
    assert!(stored["optional"].is_null());
    Ok(())
}

#[test]
fn logging_007_log_preserves_unicode_strings() -> TestResult {
    let (_directory, logger) = fresh_logger("unicode")?;
    let entry = json!({
        "message": "Remzar 鎖 данные ブロック",
        "event": "UnicodeEvent"
    });

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_008_log_preserves_large_string_payload() -> TestResult {
    let (_directory, logger) = fresh_logger("large_string")?;
    let entry = json!({
        "event": "LargePayload",
        "blob": "x".repeat(32_768)
    });

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["blob"].as_str().map(str::len), Some(32_768));
    Ok(())
}

#[test]
fn logging_009_log_key_is_padded_millis_plus_sequence_string() -> TestResult {
    let (_directory, logger) = fresh_logger("key_shape")?;
    let entry = json!({"event": "KeyShape"});

    log_and_flush(&logger, &entry)?;

    let key_values = read_log_key_values(&logger)?;
    assert_eq!(key_values.len(), 1);

    let key = &key_values[0].0;
    assert_eq!(key.len(), 37);
    assert_eq!(key.as_bytes()[20], b'_');

    let (millis, _seq) = parse_log_key_for_test(key)?;
    assert!(millis > 0);

    Ok(())
}

#[test]
fn logging_010_multiple_logs_create_multiple_entries_with_sleep_spacing() -> TestResult {
    let (_directory, logger) = fresh_logger("multiple_logs")?;

    for index in 0_u64..3_u64 {
        logger.log(&json!({"index": index}))?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 3);
    Ok(())
}

#[test]
fn logging_011_flush_succeeds_on_empty_log_database() -> TestResult {
    let (_directory, logger) = fresh_logger("flush_empty")?;

    logger.flush()?;
    Ok(())
}

#[test]
fn logging_012_flush_logs_cf_succeeds_on_empty_log_database() -> TestResult {
    let (_directory, logger) = fresh_logger("flush_cf_empty")?;

    logger.flush_logs_cf()?;
    Ok(())
}

#[test]
fn logging_013_flush_and_flush_logs_cf_succeed_after_write() -> TestResult {
    let (_directory, logger) = fresh_logger("flush_after_write")?;

    logger.log(&json!({"event": "FlushAfterWrite"}))?;
    logger.flush()?;
    logger.flush_logs_cf()?;

    assert_eq!(read_log_values(&logger)?.len(), 1);
    Ok(())
}

#[test]
fn logging_014_log_error_event_writes_standard_error_shape() -> TestResult {
    let (_directory, logger) = fresh_logger("error_event_shape")?;

    logger.log_error_event("sync", "PeerDropped", "peer timed out")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["level"], "ERROR");
    assert_eq!(stored["system"], "sync");
    assert_eq!(stored["event"], "PeerDropped");
    assert_eq!(stored["message"], "peer timed out");
    assert!(stored.get("thread").and_then(Value::as_str).is_some());
    assert_rfc3339_millis_timestamp(&stored)?;
    Ok(())
}

#[test]
fn logging_015_log_error_event_accepts_empty_strings_as_payload_data() -> TestResult {
    let (_directory, logger) = fresh_logger("empty_strings")?;

    logger.log_error_event("", "", "")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["level"], "ERROR");
    assert_eq!(stored["system"], "");
    assert_eq!(stored["event"], "");
    assert_eq!(stored["message"], "");
    Ok(())
}

#[test]
fn logging_016_log_error_event_preserves_unicode_payloads() -> TestResult {
    let (_directory, logger) = fresh_logger("unicode_error_event")?;

    logger.log_error_event("система", "Événement鎖", "message ブロック")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["system"], "система");
    assert_eq!(stored["event"], "Événement鎖");
    assert_eq!(stored["message"], "message ブロック");
    Ok(())
}

#[test]
fn logging_017_log_block_validation_failed_writes_expected_top_level_fields() -> TestResult {
    let (_directory, logger) = fresh_logger("block_validation_top")?;

    logger.log_block_validation_failed(
        42,
        "tx-hash-42",
        "expected-sig",
        "found-sig",
        "validator-r",
        "mainnet",
    )?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["level"], "ERROR");
    assert_eq!(stored["system"], "consensus_engine");
    assert_eq!(stored["event"], "BlockValidationFailed");
    assert_eq!(stored["block_number"], 42);
    assert_eq!(stored["tx_hash"], "tx-hash-42");
    assert_eq!(stored["node_id"], "peer-7d92");
    assert_eq!(stored["peer_ip"], "192.0.2.5");
    assert_eq!(stored["file"], "consensus.rs");
    assert_eq!(stored["line"], 142);
    assert_rfc3339_millis_timestamp(&stored)?;
    Ok(())
}

#[test]
fn logging_018_log_block_validation_failed_preserves_details_object() -> TestResult {
    let (_directory, logger) = fresh_logger("block_validation_details")?;

    logger.log_block_validation_failed(
        7,
        "tx-7",
        "expected-signature-value",
        "found-signature-value",
        "validator-address",
        "remzar-chain",
    )?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(
        stored["details"]["expected_signature"],
        "expected-signature-value"
    );
    assert_eq!(
        stored["details"]["found_signature"],
        "found-signature-value"
    );
    assert_eq!(stored["details"]["validator"], "validator-address");
    assert_eq!(stored["details"]["chain_id"], "remzar-chain");
    Ok(())
}

#[test]
fn logging_019_log_block_validation_failed_context_is_stable_vector() -> TestResult {
    let (_directory, logger) = fresh_logger("block_validation_context")?;

    logger.log_block_validation_failed(1, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["context"]["session"], "s-202505201650");
    assert_eq!(stored["context"]["user_id"], "remzar");
    assert_eq!(stored["context"]["rpc_call"], "/block/validate");
    Ok(())
}

#[test]
fn logging_020_log_block_validation_failed_message_includes_block_number() -> TestResult {
    let (_directory, logger) = fresh_logger("block_validation_message")?;

    logger.log_block_validation_failed(999, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    let message = stored["message"]
        .as_str()
        .ok_or_else(|| "message was not a string".to_string())?;

    assert!(message.contains("Block 999 failed validation"));
    assert!(message.contains("invalid signature"));
    Ok(())
}

#[test]
fn logging_021_db_accessor_returns_same_arc_instance() -> TestResult {
    let (_directory, logger) = fresh_logger("db_accessor")?;

    let first = logger.db().clone();
    let second = logger.db().clone();

    assert!(Arc::ptr_eq(&first, &second));
    assert!(first.cf_handle(RockDbSchema::logs_column_name()).is_some());
    Ok(())
}

#[test]
fn logging_022_reopen_logger_reads_existing_log_entry() -> TestResult {
    let directory = fresh_directory("reopen")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "BeforeReopen"}))?;
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    let values = read_log_values(&reopened)?;

    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["event"], "BeforeReopen");
    Ok(())
}

#[test]
fn logging_023_log_accepts_empty_json_object() -> TestResult {
    let (_directory, logger) = fresh_logger("empty_object")?;
    let entry = json!({});

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_024_log_accepts_json_string_value() -> TestResult {
    let (_directory, logger) = fresh_logger("string_value")?;
    let entry = json!("plain string log value");

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_025_log_accepts_json_array_value() -> TestResult {
    let (_directory, logger) = fresh_logger("array_value")?;
    let entry = json!(["a", "b", 3, true]);

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_026_log_accepts_json_null_value() -> TestResult {
    let (_directory, logger) = fresh_logger("null_value")?;
    let entry = Value::Null;

    log_and_flush(&logger, &entry)?;

    assert!(only_log_value(&logger)?.is_null());
    Ok(())
}

#[test]
fn logging_027_repeated_flush_calls_are_idempotent() -> TestResult {
    let (_directory, logger) = fresh_logger("repeated_flush")?;

    logger.log(&json!({"event": "RepeatedFlush"}))?;

    for _ in 0..10 {
        logger.flush()?;
        logger.flush_logs_cf()?;
    }

    assert_eq!(read_log_values(&logger)?.len(), 1);
    Ok(())
}

#[test]
fn logging_028_log_keys_are_unique_for_spaced_writes() -> TestResult {
    let (_directory, logger) = fresh_logger("unique_keys")?;

    for index in 0_u64..5_u64 {
        logger.log(&json!({"index": index}))?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let key_values = read_log_key_values(&logger)?;
    let keys = key_values
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(key_values.len(), 5);
    assert_eq!(keys.len(), 5);
    Ok(())
}

#[test]
fn logging_029_iterator_keys_are_sorted_lexicographically_by_rocksdb() -> TestResult {
    let (_directory, logger) = fresh_logger("sorted_keys")?;

    for index in 0_u64..5_u64 {
        logger.log(&json!({"index": index}))?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let keys = read_log_key_values(&logger)?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();

    let mut sorted = keys.clone();
    sorted.sort();

    assert_eq!(keys, sorted);
    Ok(())
}

#[test]
fn logging_030_log_does_not_mutate_original_json_value() -> TestResult {
    let (_directory, logger) = fresh_logger("no_mutation")?;
    let entry = json!({
        "event": "NoMutation",
        "details": {"a": 1, "b": [2, 3]}
    });
    let before = entry.clone();

    log_and_flush(&logger, &entry)?;

    assert_eq!(entry, before);
    assert_eq!(only_log_value(&logger)?, before);
    Ok(())
}

#[test]
fn logging_031_log_error_event_records_named_thread_when_called_inside_named_thread() -> TestResult
{
    let directory = fresh_directory("named_thread")?;

    let handle = std::thread::Builder::new()
        .name("remzar-logger-test-worker".to_string())
        .spawn(move || -> Result<Value, String> {
            let logger = JsonLogger::new(&directory)?;
            logger.log_error_event("thread-system", "ThreadEvent", "thread message")?;
            logger.flush_logs_cf()?;
            only_log_value(&logger)
        })
        .map_err(|e| e.to_string())?;

    let stored = handle
        .join()
        .map_err(|_| "named logging thread panicked".to_string())??;

    assert_eq!(stored["thread"], "remzar-logger-test-worker");
    Ok(())
}

#[test]
fn logging_032_main_thread_fallback_name_is_main_or_current_name() -> TestResult {
    let (_directory, logger) = fresh_logger("main_thread")?;

    logger.log_error_event("main-thread", "ThreadName", "check")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    let thread_name = stored["thread"]
        .as_str()
        .ok_or_else(|| "thread was not a string".to_string())?;

    assert!(!thread_name.is_empty());
    Ok(())
}

#[test]
fn logging_033_json_logger_new_fails_when_log_path_is_regular_file() -> TestResult {
    let base = next_base_dir("log_path_file");
    let directory = DirectoryDB::from_base_dir(&base)?;
    create_file_at(&directory.log_path)?;

    let result = JsonLogger::new(&directory);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn logging_034_log_error_event_large_message_is_preserved() -> TestResult {
    let (_directory, logger) = fresh_logger("large_error_message")?;
    let message = "m".repeat(64_000);

    logger.log_error_event("system", "LargeMessage", &message)?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["message"].as_str().map(str::len), Some(64_000));
    Ok(())
}

#[test]
fn logging_035_log_block_validation_failed_accepts_empty_detail_strings() -> TestResult {
    let (_directory, logger) = fresh_logger("empty_block_details")?;

    logger.log_block_validation_failed(0, "", "", "", "", "")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["block_number"], 0);
    assert_eq!(stored["tx_hash"], "");
    assert_eq!(stored["details"]["expected_signature"], "");
    assert_eq!(stored["details"]["found_signature"], "");
    assert_eq!(stored["details"]["validator"], "");
    assert_eq!(stored["details"]["chain_id"], "");
    Ok(())
}

#[test]
fn logging_036_log_block_validation_failed_accepts_u64_max_block_number() -> TestResult {
    let (_directory, logger) = fresh_logger("u64_max_block")?;

    logger.log_block_validation_failed(
        u64::MAX,
        "tx",
        "expected",
        "found",
        "validator",
        "chain",
    )?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["block_number"], u64::MAX);
    assert!(
        stored["message"]
            .as_str()
            .is_some_and(|message| message.contains(&u64::MAX.to_string()))
    );
    Ok(())
}

#[test]
fn logging_037_load_write_25_error_events_and_read_them_back() -> TestResult {
    let (_directory, logger) = fresh_logger("load_25_errors")?;

    for index in 0_u64..25_u64 {
        logger.log_error_event(
            "load",
            &format!("Event{index}"),
            &format!("message-{index}"),
        )?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 25);
    assert!(values.iter().all(|value| value["level"] == "ERROR"));
    Ok(())
}

#[test]
fn logging_038_load_write_50_direct_json_events_and_read_them_back() -> TestResult {
    let (_directory, logger) = fresh_logger("load_50_direct")?;

    for index in 0_u64..50_u64 {
        logger.log(&json!({
            "event": "DirectLoad",
            "index": index,
            "even": index % 2 == 0
        }))?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 50);
    assert_eq!(
        values.first().and_then(|v| v.get("event")),
        Some(&Value::from("DirectLoad"))
    );
    Ok(())
}

#[test]
fn logging_039_load_reopen_after_many_logs_preserves_count() -> TestResult {
    let directory = fresh_directory("reopen_many")?;

    {
        let logger = JsonLogger::new(&directory)?;
        for index in 0_u64..10_u64 {
            logger.log(&json!({"index": index}))?;
            std::thread::sleep(Duration::from_millis(1));
        }
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    let values = read_log_values(&reopened)?;

    assert_eq!(values.len(), 10);
    Ok(())
}

#[test]
fn logging_040_load_mixed_logging_methods_produce_valid_json_entries() -> TestResult {
    let (_directory, logger) = fresh_logger("mixed_methods")?;

    logger.log(&json!({"event": "Direct"}))?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log_error_event("mixed", "ErrorEvent", "mixed message")?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log_block_validation_failed(5, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;

    assert_eq!(values.len(), 3);
    assert!(values.iter().any(|v| v["event"] == "Direct"));
    assert!(values.iter().any(|v| v["event"] == "ErrorEvent"));
    assert!(values.iter().any(|v| v["event"] == "BlockValidationFailed"));
    Ok(())
}

#[test]
fn logging_041_new_creates_or_uses_log_path_directory() -> TestResult {
    let directory = fresh_directory("new_log_path_exists")?;
    assert!(directory.log_path.exists());
    assert!(directory.log_path.is_dir());

    let _logger = JsonLogger::new(&directory)?;

    assert!(directory.log_path.exists());
    assert!(directory.log_path.is_dir());
    Ok(())
}

#[test]
fn logging_042_log_path_contains_rocksdb_files_after_write_and_flush() -> TestResult {
    let (directory, logger) = fresh_logger("rocksdb_files")?;

    logger.log(&json!({"event": "RocksDbFiles"}))?;
    logger.flush()?;

    let entries = std::fs::read_dir(&directory.log_path)
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    assert!(!entries.is_empty());
    Ok(())
}

#[test]
fn logging_043_reopen_after_flush_preserves_exact_direct_json_payload() -> TestResult {
    let directory = fresh_directory("reopen_exact_payload")?;
    let entry = json!({
        "event": "ExactPayload",
        "nested": {"a": 1, "b": ["x", "y"]},
        "flag": true
    });

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&entry)?;
        logger.flush()?;
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    assert_eq!(only_log_value(&reopened)?, entry);
    Ok(())
}

#[test]
fn logging_044_log_preserves_escaped_control_characters_in_strings() -> TestResult {
    let (_directory, logger) = fresh_logger("escaped_control_chars")?;
    let entry = json!({
        "event": "Escapes",
        "message": "line1\nline2\tTabbed\rCarriage"
    });

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_045_log_preserves_quotes_and_backslashes() -> TestResult {
    let (_directory, logger) = fresh_logger("quotes_backslashes")?;
    let entry = json!({
        "event": "Quotes",
        "path": "C:\\remzar\\logs\\file.json",
        "message": "validator said \"invalid\""
    });

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_046_log_preserves_deeply_nested_json_object() -> TestResult {
    let (_directory, logger) = fresh_logger("deep_nested")?;
    let entry = json!({
        "a": {
            "b": {
                "c": {
                    "d": {
                        "e": {
                            "height": 42
                        }
                    }
                }
            }
        }
    });

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["a"]["b"]["c"]["d"]["e"]["height"], 42);
    Ok(())
}

#[test]
fn logging_047_log_preserves_large_numeric_vectors() -> TestResult {
    let (_directory, logger) = fresh_logger("large_numbers")?;
    let entry = json!({
        "zero": 0_u64,
        "one": 1_u64,
        "max_u64": u64::MAX,
        "negative": -1_i64
    });

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["zero"], 0);
    assert_eq!(stored["one"], 1);
    assert_eq!(stored["max_u64"], u64::MAX);
    assert_eq!(stored["negative"], -1);
    Ok(())
}

#[test]
fn logging_048_log_error_event_timestamp_is_recent_rfc3339_millis() -> TestResult {
    let (_directory, logger) = fresh_logger("recent_timestamp")?;

    logger.log_error_event("clock", "RecentTimestamp", "timestamp check")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_rfc3339_millis_timestamp(&stored)?;

    let ts = stored["timestamp"]
        .as_str()
        .ok_or_else(|| "timestamp was not string".to_string())?;
    let parsed = DateTime::parse_from_rfc3339(ts).map_err(|e| e.to_string())?;

    let now = chrono::Utc::now();
    let delta = now
        .signed_duration_since(parsed.with_timezone(&chrono::Utc))
        .num_seconds()
        .abs();

    assert!(delta < 30);
    Ok(())
}

#[test]
fn logging_049_log_block_validation_failed_timestamp_is_recent_rfc3339_millis() -> TestResult {
    let (_directory, logger) = fresh_logger("recent_block_timestamp")?;

    logger.log_block_validation_failed(1, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_rfc3339_millis_timestamp(&stored)?;
    Ok(())
}

#[test]
fn logging_050_log_error_event_top_level_has_expected_key_set() -> TestResult {
    let (_directory, logger) = fresh_logger("error_key_set")?;

    logger.log_error_event("sys", "Event", "message")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    let object = stored
        .as_object()
        .ok_or_else(|| "stored log was not object".to_string())?;
    let keys = object
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let expected = ["event", "level", "message", "system", "thread", "timestamp"]
        .into_iter()
        .map(str::to_string)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(keys, expected);
    Ok(())
}

#[test]
fn logging_051_block_validation_failed_contains_details_and_context_objects() -> TestResult {
    let (_directory, logger) = fresh_logger("details_context_objects")?;

    logger.log_block_validation_failed(2, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert!(stored["details"].is_object());
    assert!(stored["context"].is_object());
    Ok(())
}

#[test]
fn logging_052_block_validation_failed_top_level_key_presence_vector() -> TestResult {
    let (_directory, logger) = fresh_logger("block_key_presence")?;

    logger.log_block_validation_failed(3, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    for key in [
        "timestamp",
        "level",
        "system",
        "event",
        "message",
        "block_number",
        "tx_hash",
        "node_id",
        "peer_ip",
        "file",
        "line",
        "thread",
        "details",
        "context",
    ] {
        assert!(stored.get(key).is_some(), "missing key {key}");
    }

    Ok(())
}

#[test]
fn logging_053_block_validation_failed_preserves_unicode_detail_strings() -> TestResult {
    let (_directory, logger) = fresh_logger("unicode_details")?;

    logger.log_block_validation_failed(
        4,
        "tx-鎖",
        "expected-данные",
        "found-ブロック",
        "validator-鎖",
        "chain-данные",
    )?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["tx_hash"], "tx-鎖");
    assert_eq!(stored["details"]["expected_signature"], "expected-данные");
    assert_eq!(stored["details"]["found_signature"], "found-ブロック");
    assert_eq!(stored["details"]["validator"], "validator-鎖");
    assert_eq!(stored["details"]["chain_id"], "chain-данные");
    Ok(())
}

#[test]
fn logging_054_block_validation_failed_preserves_large_signature_strings() -> TestResult {
    let (_directory, logger) = fresh_logger("large_signature_strings")?;
    let expected = "a".repeat(16_384);
    let found = "b".repeat(16_384);

    logger.log_block_validation_failed(5, "tx", &expected, &found, "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(
        stored["details"]["expected_signature"]
            .as_str()
            .map(str::len),
        Some(16_384)
    );
    assert_eq!(
        stored["details"]["found_signature"].as_str().map(str::len),
        Some(16_384)
    );
    Ok(())
}

#[test]
fn logging_055_direct_log_after_error_event_preserves_both_entries() -> TestResult {
    let (_directory, logger) = fresh_logger("direct_after_error")?;

    logger.log_error_event("sys", "ErrorFirst", "message")?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log(&json!({"event": "DirectSecond"}))?;
    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 2);
    assert!(values.iter().any(|v| v["event"] == "ErrorFirst"));
    assert!(values.iter().any(|v| v["event"] == "DirectSecond"));
    Ok(())
}

#[test]
fn logging_056_error_event_after_direct_log_preserves_both_entries() -> TestResult {
    let (_directory, logger) = fresh_logger("error_after_direct")?;

    logger.log(&json!({"event": "DirectFirst"}))?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log_error_event("sys", "ErrorSecond", "message")?;
    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 2);
    assert!(values.iter().any(|v| v["event"] == "DirectFirst"));
    assert!(values.iter().any(|v| v["event"] == "ErrorSecond"));
    Ok(())
}

#[test]
fn logging_057_reopen_after_error_event_preserves_standard_shape() -> TestResult {
    let directory = fresh_directory("reopen_error_shape")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log_error_event("reopen", "ErrorShape", "message")?;
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    let stored = only_log_value(&reopened)?;

    assert_eq!(stored["level"], "ERROR");
    assert_eq!(stored["system"], "reopen");
    assert_eq!(stored["event"], "ErrorShape");
    assert_eq!(stored["message"], "message");
    assert_rfc3339_millis_timestamp(&stored)?;
    Ok(())
}

#[test]
fn logging_058_reopen_after_block_validation_failed_preserves_nested_details() -> TestResult {
    let directory = fresh_directory("reopen_block_validation")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log_block_validation_failed(
            8,
            "tx8",
            "expected8",
            "found8",
            "validator8",
            "chain8",
        )?;
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    let stored = only_log_value(&reopened)?;

    assert_eq!(stored["event"], "BlockValidationFailed");
    assert_eq!(stored["details"]["expected_signature"], "expected8");
    assert_eq!(stored["details"]["found_signature"], "found8");
    assert_eq!(stored["details"]["validator"], "validator8");
    assert_eq!(stored["details"]["chain_id"], "chain8");
    Ok(())
}

#[test]
fn logging_059_log_key_millis_and_sequence_parse_as_positive_numbers() -> TestResult {
    let (_directory, logger) = fresh_logger("key_parse_i128")?;

    logger.log(&json!({"event": "ParseKey"}))?;
    logger.flush_logs_cf()?;

    let key_values = read_log_key_values(&logger)?;
    let (millis, _seq) = parse_log_key_for_test(&key_values[0].0)?;

    assert!(millis > 0);
    Ok(())
}

#[test]
fn logging_060_spaced_log_keys_are_strictly_increasing() -> TestResult {
    let (_directory, logger) = fresh_logger("increasing_keys")?;

    for index in 0_u64..5_u64 {
        logger.log(&json!({"index": index}))?;
        std::thread::sleep(Duration::from_millis(2));
    }

    logger.flush_logs_cf()?;

    let keys = read_log_key_values(&logger)?
        .into_iter()
        .map(|(key, _)| parse_log_key_for_test(&key))
        .collect::<Result<Vec<_>, _>>()?;

    for pair in keys.windows(2) {
        assert!(
            pair[0] < pair[1],
            "log key tuple should increase: {:?} !< {:?}",
            pair[0],
            pair[1]
        );
    }

    Ok(())
}

#[test]
fn logging_061_read_back_values_match_spaced_write_order_by_key() -> TestResult {
    let (_directory, logger) = fresh_logger("order_by_key")?;

    for index in 0_u64..5_u64 {
        logger.log(&json!({"index": index}))?;
        std::thread::sleep(Duration::from_millis(2));
    }

    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    let indexes = values
        .iter()
        .map(|value| {
            value["index"]
                .as_u64()
                .ok_or_else(|| "missing index".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(indexes, vec![0, 1, 2, 3, 4]);
    Ok(())
}

#[test]
fn logging_062_flush_logs_cf_after_reopen_succeeds() -> TestResult {
    let directory = fresh_directory("flush_cf_after_reopen")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "BeforeReopenFlush"}))?;
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    reopened.flush_logs_cf()?;

    assert_eq!(read_log_values(&reopened)?.len(), 1);
    Ok(())
}

#[test]
fn logging_063_flush_after_reopen_succeeds() -> TestResult {
    let directory = fresh_directory("flush_after_reopen")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "BeforeReopenFlushAll"}))?;
        logger.flush()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    reopened.flush()?;

    assert_eq!(read_log_values(&reopened)?.len(), 1);
    Ok(())
}

#[test]
fn logging_064_direct_log_with_all_json_scalar_types_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("all_scalar_types")?;
    let entry = json!({
        "string": "value",
        "integer": 123_i64,
        "float": 1.25_f64,
        "bool_true": true,
        "bool_false": false,
        "null_value": null
    });

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_065_log_array_of_objects_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("array_objects")?;
    let entry = json!([
        {"event": "a", "height": 1},
        {"event": "b", "height": 2},
        {"event": "c", "height": 3}
    ]);

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored.as_array().map(Vec::len), Some(3));
    assert_eq!(stored[1]["event"], "b");
    Ok(())
}

#[test]
fn logging_066_log_error_event_message_with_newlines_and_tabs_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("error_message_controls")?;
    let message = "line1\nline2\tline3";

    logger.log_error_event("sys", "ControlMessage", message)?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["message"], message);
    Ok(())
}

#[test]
fn logging_067_log_error_event_system_and_event_with_spaces_roundtrip() -> TestResult {
    let (_directory, logger) = fresh_logger("system_event_spaces")?;

    logger.log_error_event("consensus engine", "Peer Timeout Event", "message")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["system"], "consensus engine");
    assert_eq!(stored["event"], "Peer Timeout Event");
    Ok(())
}

#[test]
fn logging_068_block_validation_failed_static_fields_are_stable_vector() -> TestResult {
    let (_directory, logger) = fresh_logger("static_fields")?;

    logger.log_block_validation_failed(10, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["node_id"], "peer-7d92");
    assert_eq!(stored["peer_ip"], "192.0.2.5");
    assert_eq!(stored["file"], "consensus.rs");
    assert_eq!(stored["line"], 142);
    Ok(())
}

#[test]
fn logging_069_block_validation_failed_thread_field_is_nonempty_string() -> TestResult {
    let (_directory, logger) = fresh_logger("block_thread_field")?;

    logger.log_block_validation_failed(11, "tx", "expected", "found", "validator", "chain")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    let thread = stored["thread"]
        .as_str()
        .ok_or_else(|| "thread field was not string".to_string())?;

    assert!(!thread.is_empty());
    Ok(())
}

#[test]
fn logging_070_named_thread_block_validation_failed_records_thread_name() -> TestResult {
    let directory = fresh_directory("named_thread_block")?;

    let handle = std::thread::Builder::new()
        .name("remzar-block-validator-test".to_string())
        .spawn(move || -> Result<Value, String> {
            let logger = JsonLogger::new(&directory)?;
            logger.log_block_validation_failed(
                12,
                "tx",
                "expected",
                "found",
                "validator",
                "chain",
            )?;
            logger.flush_logs_cf()?;
            only_log_value(&logger)
        })
        .map_err(|e| e.to_string())?;

    let stored = handle
        .join()
        .map_err(|_| "named block validation thread panicked".to_string())??;

    assert_eq!(stored["thread"], "remzar-block-validator-test");
    Ok(())
}

#[test]
fn logging_071_open_log_db_directly_has_logs_column_family() -> TestResult {
    let directory = fresh_directory("open_log_db_direct")?;

    let db =
        RockDbSchema::open_log_db(&directory).map_err(|e| format!("open_log_db failed: {e:?}"))?;

    assert!(db.cf_handle(RockDbSchema::logs_column_name()).is_some());
    Ok(())
}

#[test]
fn logging_072_validate_column_families_accepts_opened_log_db_schema_after_drop() -> TestResult {
    let directory = fresh_directory("validate_log_cf")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "ValidateCf"}))?;
        logger.flush_logs_cf()?;
    }

    RockDbSchema::validate_column_families(
        &directory.log_path,
        &["default", RockDbSchema::logs_column_name()],
    )?;

    Ok(())
}

#[test]
fn logging_073_validate_db_integrity_accepts_created_log_db_after_drop() -> TestResult {
    let directory = fresh_directory("validate_integrity")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "ValidateIntegrity"}))?;
        logger.flush()?;
    }

    RockDbSchema::validate_db_integrity(&directory.log_path)?;
    Ok(())
}

#[test]
fn logging_074_validate_column_families_rejects_missing_cf_name() -> TestResult {
    let directory = fresh_directory("validate_missing_cf")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "MissingCf"}))?;
        logger.flush_logs_cf()?;
    }

    let result = RockDbSchema::validate_column_families(
        &directory.log_path,
        &["default", "definitely_missing_cf"],
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn logging_075_validate_db_integrity_rejects_missing_database_path() -> TestResult {
    let directory = DirectoryDB::from_base_dir(&next_base_dir("missing_db_integrity"))?;

    let result = RockDbSchema::validate_db_integrity(&directory.log_path);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn logging_076_load_write_75_spaced_direct_events_unique_count() -> TestResult {
    let (_directory, logger) = fresh_logger("load_75_spaced")?;

    for index in 0_u64..75_u64 {
        logger.log(&json!({"event": "Load75", "index": index}))?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let key_values = read_log_key_values(&logger)?;
    let keys = key_values
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(key_values.len(), 75);
    assert_eq!(keys.len(), 75);
    Ok(())
}

#[test]
fn logging_077_load_reopen_30_error_events_preserves_all_events() -> TestResult {
    let directory = fresh_directory("load_reopen_30_errors")?;

    {
        let logger = JsonLogger::new(&directory)?;
        for index in 0_u64..30_u64 {
            logger.log_error_event("load-reopen", &format!("Error{index}"), "message")?;
            std::thread::sleep(Duration::from_millis(1));
        }
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    let values = read_log_values(&reopened)?;

    assert_eq!(values.len(), 30);
    assert!(values.iter().all(|v| v["system"] == "load-reopen"));
    Ok(())
}

#[test]
fn logging_078_load_mixed_large_and_small_payloads_roundtrip() -> TestResult {
    let (_directory, logger) = fresh_logger("mixed_large_small")?;

    logger.log(&json!({"event": "small"}))?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log(&json!({"event": "large", "blob": "x".repeat(128_000)}))?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log_error_event("mixed", "SmallError", "small message")?;
    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 3);
    assert!(values.iter().any(|v| v["event"] == "small"));
    assert!(values.iter().any(|v| v["event"] == "large"));
    assert!(values.iter().any(|v| v["event"] == "SmallError"));
    Ok(())
}

#[test]
fn logging_079_load_repeated_reopen_does_not_duplicate_entries() -> TestResult {
    let directory = fresh_directory("repeated_reopen_no_duplicate")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "OnlyOnce"}))?;
        logger.flush_logs_cf()?;
    }

    for _ in 0..5 {
        let reopened = JsonLogger::new(&directory)?;
        assert_eq!(read_log_values(&reopened)?.len(), 1);
    }

    Ok(())
}

#[test]
fn logging_080_load_repeated_flushes_after_many_writes_keep_count_stable() -> TestResult {
    let (_directory, logger) = fresh_logger("flush_count_stable")?;

    for index in 0_u64..20_u64 {
        logger.log(&json!({"index": index}))?;
        std::thread::sleep(Duration::from_millis(1));
    }

    for _ in 0..20 {
        logger.flush()?;
        logger.flush_logs_cf()?;
        assert_eq!(read_log_values(&logger)?.len(), 20);
    }

    Ok(())
}

#[test]
fn logging_081_direct_log_boolean_true_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("bool_true")?;
    let entry = Value::Bool(true);

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, Value::Bool(true));
    Ok(())
}

#[test]
fn logging_082_direct_log_boolean_false_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("bool_false")?;
    let entry = Value::Bool(false);

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, Value::Bool(false));
    Ok(())
}

#[test]
fn logging_083_direct_log_number_zero_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("number_zero")?;
    let entry = json!(0);

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, json!(0));
    Ok(())
}

#[test]
fn logging_084_direct_log_negative_number_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("negative_number")?;
    let entry = json!(-12345);

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, json!(-12345));
    Ok(())
}

#[test]
fn logging_085_direct_log_floating_number_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("floating_number")?;
    let entry = json!(123.456);

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, json!(123.456));
    Ok(())
}

#[test]
fn logging_086_direct_log_empty_array_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("empty_array")?;
    let entry = json!([]);

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert!(stored.is_array());
    assert_eq!(stored.as_array().map(Vec::len), Some(0));
    Ok(())
}

#[test]
fn logging_087_direct_log_nested_empty_objects_and_arrays_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("nested_empty")?;
    let entry = json!({
        "empty_object": {},
        "empty_array": [],
        "nested": {
            "items": [
                {},
                [],
                {"inner": []}
            ]
        }
    });

    log_and_flush(&logger, &entry)?;

    assert_eq!(only_log_value(&logger)?, entry);
    Ok(())
}

#[test]
fn logging_088_error_event_with_quote_backslash_and_newline_payloads_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("error_special_chars")?;
    let system = "consensus\\engine";
    let event = "Quote\"Event";
    let message = "line-one\nline-two\\tail\"quote";

    logger.log_error_event(system, event, message)?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["system"], system);
    assert_eq!(stored["event"], event);
    assert_eq!(stored["message"], message);
    Ok(())
}

#[test]
fn logging_089_block_validation_failed_with_quote_backslash_payloads_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("block_special_chars")?;

    logger.log_block_validation_failed(
        89,
        "tx\\hash\"quoted",
        "expected\\signature\"quoted",
        "found\\signature\"quoted",
        "validator\\wallet\"quoted",
        "chain\\id\"quoted",
    )?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["tx_hash"], "tx\\hash\"quoted");
    assert_eq!(
        stored["details"]["expected_signature"],
        "expected\\signature\"quoted"
    );
    assert_eq!(
        stored["details"]["found_signature"],
        "found\\signature\"quoted"
    );
    assert_eq!(stored["details"]["validator"], "validator\\wallet\"quoted");
    assert_eq!(stored["details"]["chain_id"], "chain\\id\"quoted");
    Ok(())
}

#[test]
fn logging_090_reopen_after_direct_null_log_preserves_null_entry() -> TestResult {
    let directory = fresh_directory("reopen_null")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&Value::Null)?;
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    assert!(only_log_value(&reopened)?.is_null());
    Ok(())
}

#[test]
fn logging_091_reopen_after_direct_array_log_preserves_array_entry() -> TestResult {
    let directory = fresh_directory("reopen_array")?;
    let entry = json!([1, 2, 3, {"event": "array"}]);

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&entry)?;
        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    assert_eq!(only_log_value(&reopened)?, entry);
    Ok(())
}

#[test]
fn logging_092_log_error_event_repeated_same_payload_creates_distinct_entries_when_spaced()
-> TestResult {
    let (_directory, logger) = fresh_logger("same_error_payload_spaced")?;

    for _ in 0..5 {
        logger.log_error_event("same-system", "SameEvent", "same message")?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 5);
    assert!(values.iter().all(|v| v["event"] == "SameEvent"));
    Ok(())
}

#[test]
fn logging_093_direct_repeated_same_payload_creates_distinct_entries_when_spaced() -> TestResult {
    let (_directory, logger) = fresh_logger("same_direct_payload_spaced")?;
    let entry = json!({"event": "SameDirect", "value": 1});

    for _ in 0..5 {
        logger.log(&entry)?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 5);
    assert!(values.iter().all(|v| *v == entry));
    Ok(())
}

#[test]
fn logging_094_block_validation_failed_repeated_same_payload_creates_distinct_entries_when_spaced()
-> TestResult {
    let (_directory, logger) = fresh_logger("same_block_payload_spaced")?;

    for _ in 0..5 {
        logger.log_block_validation_failed(94, "tx", "expected", "found", "validator", "chain")?;
        std::thread::sleep(Duration::from_millis(1));
    }

    logger.flush_logs_cf()?;

    let values = read_log_values(&logger)?;
    assert_eq!(values.len(), 5);
    assert!(values.iter().all(|v| v["event"] == "BlockValidationFailed"));
    Ok(())
}

#[test]
fn logging_095_log_error_event_with_very_large_system_and_event_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("large_system_event")?;
    let system = "s".repeat(16_384);
    let event = "e".repeat(16_384);

    logger.log_error_event(&system, &event, "large fields")?;
    logger.flush_logs_cf()?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored["system"].as_str().map(str::len), Some(16_384));
    assert_eq!(stored["event"].as_str().map(str::len), Some(16_384));
    assert_eq!(stored["message"], "large fields");
    Ok(())
}

#[test]
fn logging_096_direct_log_large_array_roundtrips() -> TestResult {
    let (_directory, logger) = fresh_logger("large_array")?;
    let entry = Value::Array((0_u64..1_000_u64).map(Value::from).collect::<Vec<_>>());

    log_and_flush(&logger, &entry)?;

    let stored = only_log_value(&logger)?;
    assert_eq!(stored.as_array().map(Vec::len), Some(1_000));
    assert_eq!(stored[0], 0);
    assert_eq!(stored[999], 999);
    Ok(())
}

#[test]
fn logging_097_read_log_key_values_returns_valid_json_for_mixed_scalar_entries() -> TestResult {
    let (_directory, logger) = fresh_logger("mixed_scalars")?;

    logger.log(&Value::Null)?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log(&Value::Bool(true))?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log(&json!(123))?;
    std::thread::sleep(Duration::from_millis(1));
    logger.log(&json!("text"))?;
    logger.flush_logs_cf()?;

    let key_values = read_log_key_values(&logger)?;

    assert_eq!(key_values.len(), 4);
    assert!(
        key_values
            .iter()
            .all(|(key, _)| parse_log_key_for_test(key).is_ok())
    );
    assert!(key_values.iter().any(|(_, value)| value.is_null()));
    assert!(key_values.iter().any(|(_, value)| value == true));
    assert!(key_values.iter().any(|(_, value)| value == 123));
    assert!(key_values.iter().any(|(_, value)| value == "text"));
    Ok(())
}

#[test]
fn logging_098_validate_column_families_accepts_only_logs_cf_requirement_after_drop() -> TestResult
{
    let directory = fresh_directory("validate_only_logs_cf")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "OnlyLogsCf"}))?;
        logger.flush_logs_cf()?;
    }

    RockDbSchema::validate_column_families(
        &directory.log_path,
        &[RockDbSchema::logs_column_name()],
    )?;

    Ok(())
}

#[test]
fn logging_099_load_reopen_many_mixed_scalar_entries_preserves_count() -> TestResult {
    let directory = fresh_directory("reopen_many_scalars")?;

    {
        let logger = JsonLogger::new(&directory)?;

        for index in 0_u64..20_u64 {
            let entry = match index % 4 {
                0 => Value::Null,
                1 => Value::Bool(index % 2 == 0),
                2 => json!(index),
                _ => json!(format!("text-{index}")),
            };

            logger.log(&entry)?;
            std::thread::sleep(Duration::from_millis(1));
        }

        logger.flush_logs_cf()?;
    }

    let reopened = JsonLogger::new(&directory)?;
    assert_eq!(read_log_values(&reopened)?.len(), 20);
    Ok(())
}

#[test]
fn logging_100_load_repeated_reopen_and_flush_after_mixed_methods_preserves_entries() -> TestResult
{
    let directory = fresh_directory("final_reopen_flush_mixed")?;

    {
        let logger = JsonLogger::new(&directory)?;
        logger.log(&json!({"event": "DirectFinal"}))?;
        std::thread::sleep(Duration::from_millis(1));
        logger.log_error_event("final", "ErrorFinal", "message")?;
        std::thread::sleep(Duration::from_millis(1));
        logger.log_block_validation_failed(100, "tx", "expected", "found", "validator", "chain")?;
        logger.flush_logs_cf()?;
    }

    for _ in 0..5 {
        let reopened = JsonLogger::new(&directory)?;
        reopened.flush()?;
        reopened.flush_logs_cf()?;

        let values = read_log_values(&reopened)?;
        assert_eq!(values.len(), 3);
        assert!(values.iter().any(|v| v["event"] == "DirectFinal"));
        assert!(values.iter().any(|v| v["event"] == "ErrorFinal"));
        assert!(values.iter().any(|v| v["event"] == "BlockValidationFailed"));
    }

    Ok(())
}
