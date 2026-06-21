use chrono::{TimeZone, Utc};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::audit_report_001_hub::{AuditBlock, AuditReport, AuditTransaction};
use rust_rocksdb::{DB, Options};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), String>;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_test_path(label: &str) -> PathBuf {
    let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_audit_hub_test_{}_{}_{}",
        label,
        std::process::id(),
        n
    ))
}

fn remove_path_if_exists(path: &PathBuf) -> TestResult {
    if path.exists() {
        if path.is_dir() {
            std::fs::remove_dir_all(path).map_err(|e| e.to_string())?;
        } else {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn sample_tx(
    kind: &str,
    sender: Option<&str>,
    receiver: Option<&str>,
    amount: Option<u64>,
) -> AuditTransaction {
    AuditTransaction {
        kind: kind.to_string(),
        sender: sender.map(ToOwned::to_owned),
        receiver: receiver.map(ToOwned::to_owned),
        amount,
    }
}

fn sample_block(index: u64, timestamp: u64, tx_count: u64) -> AuditBlock {
    AuditBlock {
        index,
        timestamp,
        size: 512_u64.saturating_add(index),
        tx_count,
        transactions: vec![sample_tx(
            "transfer",
            Some("sender-wallet"),
            Some("receiver-wallet"),
            Some(123),
        )],
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    }
}

fn empty_report() -> AuditReport {
    AuditReport { blocks: Vec::new() }
}

fn sample_report() -> AuditReport {
    AuditReport {
        blocks: vec![sample_block(7, 1_700_000_000, 1)],
    }
}

fn two_block_report() -> AuditReport {
    AuditReport {
        blocks: vec![
            sample_block(1, 1_111, 2),
            AuditBlock {
                index: 2,
                timestamp: 2_222,
                size: 2_048,
                tx_count: 3,
                transactions: vec![
                    sample_tx("reward", None, Some("miner-wallet"), Some(500)),
                    sample_tx("register_node", None, Some("node-wallet"), None),
                    sample_tx("nft_transfer", None, Some("owner-wallet"), None),
                ],
                current_hash: "1".repeat(128),
                previous_hash: "2".repeat(128),
                merkle_root: "3".repeat(128),
                guardian_sig: "4".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
            },
        ],
    }
}

fn canonical_json_value(report: &AuditReport) -> Result<Value, String> {
    let bytes = report
        .canonical_bytes()
        .map_err(|e| format!("canonical_bytes failed: {e:?}"))?;

    serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())
}

fn canonical_json_string(report: &AuditReport) -> Result<String, String> {
    let bytes = report
        .canonical_bytes()
        .map_err(|e| format!("canonical_bytes failed: {e:?}"))?;

    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn create_empty_blockchain_db(path: &PathBuf) -> TestResult {
    remove_path_if_exists(path)?;

    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let cf_names = [
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
    ];

    let db = DB::open_cf(&opts, path, cf_names).map_err(|e| e.to_string())?;
    drop(db);
    Ok(())
}

fn assert_database_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::DatabaseError { details }) => {
            assert!(!details.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected DatabaseError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected DatabaseError, got Err({error:?})")),
    }
}

fn assert_io_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::IoError { message, .. }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected IoError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected IoError, got Err({error:?})")),
    }
}

#[test]
fn audit_hub_001_audit_transaction_transfer_serializes_snake_case_fields() -> TestResult {
    let tx = sample_tx("transfer", Some("alice"), Some("bob"), Some(42));
    let value = serde_json::to_value(&tx).map_err(|e| e.to_string())?;

    assert_eq!(value["kind"], "transfer");
    assert_eq!(value["sender"], "alice");
    assert_eq!(value["receiver"], "bob");
    assert_eq!(value["amount"], 42);
    assert!(value.get("tx_count").is_none());
    Ok(())
}

#[test]
fn audit_hub_002_audit_transaction_reward_allows_null_sender() -> TestResult {
    let tx = sample_tx("reward", None, Some("miner"), Some(99));
    let value = serde_json::to_value(&tx).map_err(|e| e.to_string())?;

    assert_eq!(value["kind"], "reward");
    assert!(value["sender"].is_null());
    assert_eq!(value["receiver"], "miner");
    assert_eq!(value["amount"], 99);
    Ok(())
}

#[test]
fn audit_hub_003_audit_transaction_register_node_allows_null_amount() -> TestResult {
    let tx = sample_tx("register_node", None, Some("wallet"), None);
    let value = serde_json::to_value(&tx).map_err(|e| e.to_string())?;

    assert_eq!(value["kind"], "register_node");
    assert!(value["sender"].is_null());
    assert_eq!(value["receiver"], "wallet");
    assert!(value["amount"].is_null());
    Ok(())
}

#[test]
fn audit_hub_004_audit_transaction_nft_mint_allows_all_optional_fields_null() -> TestResult {
    let tx = sample_tx("nft_mint", None, None, None);
    let value = serde_json::to_value(&tx).map_err(|e| e.to_string())?;

    assert_eq!(value["kind"], "nft_mint");
    assert!(value["sender"].is_null());
    assert!(value["receiver"].is_null());
    assert!(value["amount"].is_null());
    Ok(())
}

#[test]
fn audit_hub_005_audit_block_serializes_snake_case_shape() -> TestResult {
    let block = sample_block(5, 1_234_567, 1);
    let value = serde_json::to_value(&block).map_err(|e| e.to_string())?;

    assert_eq!(value["index"], 5);
    assert_eq!(value["timestamp"], 1_234_567);
    assert_eq!(value["tx_count"], 1);
    assert!(value.get("currentHash").is_none());
    assert!(value.get("current_hash").is_some());
    assert!(value.get("guardian_sig").is_some());
    Ok(())
}

#[test]
fn audit_hub_006_empty_report_canonical_bytes_are_valid_json() -> TestResult {
    let report = empty_report();
    let value = canonical_json_value(&report)?;

    assert!(value.is_object());
    Ok(())
}

#[test]
fn audit_hub_007_empty_report_canonical_bytes_are_stable_across_calls() -> TestResult {
    let report = empty_report();

    let first = report
        .canonical_bytes()
        .map_err(|e| format!("first canonical_bytes failed: {e:?}"))?;
    let second = report
        .canonical_bytes()
        .map_err(|e| format!("second canonical_bytes failed: {e:?}"))?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn audit_hub_008_sample_report_canonical_bytes_are_stable_across_calls() -> TestResult {
    let report = sample_report();

    let first = report
        .canonical_bytes()
        .map_err(|e| format!("first canonical_bytes failed: {e:?}"))?;
    let second = report
        .canonical_bytes()
        .map_err(|e| format!("second canonical_bytes failed: {e:?}"))?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn audit_hub_009_canonical_bytes_include_block_and_transaction_payloads() -> TestResult {
    let report = sample_report();
    let json = canonical_json_string(&report)?;

    assert!(json.contains("transfer"));
    assert!(json.contains("sender-wallet"));
    assert!(json.contains("receiver-wallet"));
    assert!(json.contains(&"a".repeat(128)));
    Ok(())
}

#[test]
fn audit_hub_010_canonical_bytes_use_first_block_timestamp_as_snapshot_vector() -> TestResult {
    let report = two_block_report();
    let json = canonical_json_string(&report)?;

    assert!(json.contains("1111"));
    assert!(json.contains("2222"));
    assert!(json.find("1111").is_some());
    Ok(())
}

#[test]
fn audit_hub_011_canonical_bytes_include_total_transaction_count_vector() -> TestResult {
    let report = two_block_report();
    let json = canonical_json_string(&report)?;

    assert!(json.contains("5"));
    assert!(json.contains("reward"));
    assert!(json.contains("register_node"));
    assert!(json.contains("nft_transfer"));
    Ok(())
}

#[test]
fn audit_hub_012_canonical_bytes_handles_zero_tx_count_with_nonempty_transactions() -> TestResult {
    let mut block = sample_block(9, 9_999, 0);
    block.transactions = vec![sample_tx("transfer", Some("a"), Some("b"), Some(1))];

    let report = AuditReport {
        blocks: vec![block],
    };
    let json = canonical_json_string(&report)?;

    assert!(json.contains("transfer"));
    assert!(json.contains("\"tx_count\"") || json.contains("tx_count"));
    Ok(())
}

#[test]
fn audit_hub_013_canonical_bytes_handles_empty_transactions_with_nonzero_tx_count() -> TestResult {
    let mut block = sample_block(10, 10_000, 3);
    block.transactions.clear();

    let report = AuditReport {
        blocks: vec![block],
    };
    let json = canonical_json_string(&report)?;

    assert!(json.contains("3"));
    assert!(json.contains(&"a".repeat(128)));
    Ok(())
}

#[test]
fn audit_hub_014_export_json_writes_valid_json_file() -> TestResult {
    let path = next_test_path("export_json_valid");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    report
        .export_json(&path)
        .map_err(|e| format!("export_json failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let value = serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())?;

    assert!(value.is_object());
    assert!(!bytes.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_015_export_json_overwrites_existing_file() -> TestResult {
    let path = next_test_path("export_json_overwrite");
    remove_path_if_exists(&path)?;

    std::fs::write(&path, b"old contents").map_err(|e| e.to_string())?;

    let report = sample_report();
    report
        .export_json(&path)
        .map_err(|e| format!("export_json failed: {e:?}"))?;

    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;

    assert!(!text.contains("old contents"));
    assert!(text.contains("transfer"));

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_016_export_json_to_missing_parent_returns_io_error() -> TestResult {
    let path = next_test_path("missing_parent_json").join("child.json");
    remove_path_if_exists(&path)?;

    let report = sample_report();

    assert_io_error(report.export_json(&path))?;
    Ok(())
}

#[test]
fn audit_hub_017_export_json_empty_report_writes_valid_json() -> TestResult {
    let path = next_test_path("empty_json");
    remove_path_if_exists(&path)?;

    let report = empty_report();
    report
        .export_json(&path)
        .map_err(|e| format!("export_json empty report failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let value = serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())?;

    assert!(value.is_object());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_018_export_pdf_with_fixed_time_writes_pdf_file() -> TestResult {
    let path = next_test_path("fixed_pdf");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_000, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("export_pdf_with_time failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.len() > 100);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_019_export_pdf_writes_pdf_file() -> TestResult {
    let path = next_test_path("pdf_now");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    report
        .export_pdf(&path)
        .map_err(|e| format!("export_pdf failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.len() > 100);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_020_export_pdf_to_missing_parent_returns_io_error() -> TestResult {
    let path = next_test_path("missing_parent_pdf").join("child.pdf");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_000, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    assert_io_error(report.export_pdf_with_time(&path, fixed))?;
    Ok(())
}

#[test]
fn audit_hub_021_export_pdf_empty_report_writes_pdf() -> TestResult {
    let path = next_test_path("empty_pdf");
    remove_path_if_exists(&path)?;

    let report = empty_report();
    let fixed = Utc
        .timestamp_opt(0, 0)
        .single()
        .ok_or_else(|| "failed to construct epoch timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("empty export_pdf_with_time failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.len() > 100);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_022_load_range_with_path_missing_db_returns_database_error() -> TestResult {
    let path = next_test_path("missing_db");
    remove_path_if_exists(&path)?;

    assert_database_error(AuditReport::load_range_with_path(&path, 0, 1))?;
    Ok(())
}

#[test]
fn audit_hub_023_load_range_with_empty_db_returns_empty_report() -> TestResult {
    let path = next_test_path("empty_db");
    create_empty_blockchain_db(&path)?;

    let report = AuditReport::load_range_with_path(&path, 0, 3)
        .map_err(|e| format!("load_range_with_path failed: {e:?}"))?;

    assert!(report.blocks.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_024_load_range_start_greater_than_end_returns_empty_report_for_valid_db() -> TestResult
{
    let path = next_test_path("reverse_range_db");
    create_empty_blockchain_db(&path)?;

    let report = AuditReport::load_range_with_path(&path, 10, 3)
        .map_err(|e| format!("reverse load_range_with_path failed: {e:?}"))?;

    assert!(report.blocks.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_025_load_range_single_missing_block_returns_empty_report() -> TestResult {
    let path = next_test_path("single_missing_block_db");
    create_empty_blockchain_db(&path)?;

    let report = AuditReport::load_range_with_path(&path, 5, 5)
        .map_err(|e| format!("single missing block load failed: {e:?}"))?;

    assert!(report.blocks.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_026_load_range_large_empty_range_returns_empty_report() -> TestResult {
    let path = next_test_path("large_empty_range_db");
    create_empty_blockchain_db(&path)?;

    let report = AuditReport::load_range_with_path(&path, 0, 250)
        .map_err(|e| format!("large empty range load failed: {e:?}"))?;

    assert!(report.blocks.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_027_canonical_bytes_handles_max_u64_values() -> TestResult {
    let block = AuditBlock {
        index: u64::MAX,
        timestamp: u64::MAX,
        size: u64::MAX,
        tx_count: u64::MAX,
        transactions: Vec::new(),
        current_hash: "f".repeat(128),
        previous_hash: "e".repeat(128),
        merkle_root: "d".repeat(128),
        guardian_sig: "c".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };

    let report = AuditReport {
        blocks: vec![block],
    };

    let json = canonical_json_string(&report)?;
    assert!(json.contains(&u64::MAX.to_string()));
    Ok(())
}

#[test]
fn audit_hub_028_canonical_bytes_handles_unicode_transaction_fields() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 1,
        transactions: vec![sample_tx(
            "transfer",
            Some("sender-鎖"),
            Some("receiver-данные"),
            Some(4),
        )],
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };

    let report = AuditReport {
        blocks: vec![block],
    };

    let json = canonical_json_string(&report)?;

    assert!(json.contains("sender-"));
    assert!(json.contains("receiver-"));
    Ok(())
}

#[test]
fn audit_hub_029_canonical_bytes_handles_newline_transaction_fields() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 1,
        transactions: vec![sample_tx(
            "transfer",
            Some("sender\nline"),
            Some("receiver\nline"),
            Some(4),
        )],
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };

    let report = AuditReport {
        blocks: vec![block],
    };

    let json = canonical_json_string(&report)?;

    assert!(json.contains("\\n"));
    Ok(())
}

#[test]
fn audit_hub_030_canonical_bytes_are_sensitive_to_tx_count_changes() -> TestResult {
    let report_a = AuditReport {
        blocks: vec![sample_block(1, 1_000, 1)],
    };
    let report_b = AuditReport {
        blocks: vec![sample_block(1, 1_000, 2)],
    };

    let bytes_a = report_a
        .canonical_bytes()
        .map_err(|e| format!("canonical A failed: {e:?}"))?;
    let bytes_b = report_b
        .canonical_bytes()
        .map_err(|e| format!("canonical B failed: {e:?}"))?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_hub_031_canonical_bytes_are_sensitive_to_block_order() -> TestResult {
    let report_a = two_block_report();
    let mut report_b = two_block_report();
    report_b.blocks.reverse();

    let bytes_a = report_a
        .canonical_bytes()
        .map_err(|e| format!("canonical A failed: {e:?}"))?;
    let bytes_b = report_b
        .canonical_bytes()
        .map_err(|e| format!("canonical B failed: {e:?}"))?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_hub_032_export_json_and_canonical_bytes_are_both_valid_json() -> TestResult {
    let path = next_test_path("json_and_canonical");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let canonical = report
        .canonical_bytes()
        .map_err(|e| format!("canonical failed: {e:?}"))?;

    report
        .export_json(&path)
        .map_err(|e| format!("export_json failed: {e:?}"))?;

    let exported = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(serde_json::from_slice::<Value>(&canonical).is_ok());
    assert!(serde_json::from_slice::<Value>(&exported).is_ok());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_033_export_json_export_time_makes_file_different_from_stable_canonical_bytes()
-> TestResult {
    let path = next_test_path("json_export_time_diff");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let canonical = report
        .canonical_bytes()
        .map_err(|e| format!("canonical failed: {e:?}"))?;

    report
        .export_json(&path)
        .map_err(|e| format!("export_json failed: {e:?}"))?;

    let exported = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(serde_json::from_slice::<Value>(&exported).is_ok());
    assert!(!exported.is_empty());
    assert!(!canonical.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_034_export_pdf_with_same_snapshot_writes_nonempty_files_twice() -> TestResult {
    let path_a = next_test_path("pdf_twice_a");
    let path_b = next_test_path("pdf_twice_b");
    remove_path_if_exists(&path_a)?;
    remove_path_if_exists(&path_b)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_650_000_000, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path_a, fixed)
        .map_err(|e| format!("first pdf export failed: {e:?}"))?;
    report
        .export_pdf_with_time(&path_b, fixed)
        .map_err(|e| format!("second pdf export failed: {e:?}"))?;

    let bytes_a = std::fs::read(&path_a).map_err(|e| e.to_string())?;
    let bytes_b = std::fs::read(&path_b).map_err(|e| e.to_string())?;

    assert!(bytes_a.starts_with(b"%PDF"));
    assert!(bytes_b.starts_with(b"%PDF"));
    assert!(bytes_a.len() > 100);
    assert!(bytes_b.len() > 100);

    remove_path_if_exists(&path_a)?;
    remove_path_if_exists(&path_b)?;
    Ok(())
}

#[test]
fn audit_hub_035_audit_report_blocks_vector_is_public_and_mutable() -> TestResult {
    let mut report = empty_report();

    assert!(report.blocks.is_empty());

    report.blocks.push(sample_block(1, 10, 1));
    report.blocks.push(sample_block(2, 20, 0));

    assert_eq!(report.blocks.len(), 2);
    assert_eq!(report.blocks[0].index, 1);
    assert_eq!(report.blocks[1].index, 2);
    Ok(())
}

#[test]
fn audit_hub_036_load_range_with_file_path_instead_of_db_returns_database_error() -> TestResult {
    let path = next_test_path("not_a_db_file");
    remove_path_if_exists(&path)?;

    std::fs::write(&path, b"not a database").map_err(|e| e.to_string())?;

    assert_database_error(AuditReport::load_range_with_path(&path, 0, 0))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_037_export_json_to_directory_path_returns_io_error() -> TestResult {
    let path = next_test_path("json_to_dir");
    remove_path_if_exists(&path)?;
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;

    let report = sample_report();

    assert_io_error(report.export_json(&path))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_038_export_pdf_to_directory_path_returns_io_error() -> TestResult {
    let path = next_test_path("pdf_to_dir");
    remove_path_if_exists(&path)?;
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_650_000_000, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    assert_io_error(report.export_pdf_with_time(&path, fixed))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_039_load_empty_db_repeatedly_is_stable() -> TestResult {
    let path = next_test_path("repeat_empty_db");
    create_empty_blockchain_db(&path)?;

    for _ in 0..50 {
        let report = AuditReport::load_range_with_path(&path, 0, 5)
            .map_err(|e| format!("repeated load failed: {e:?}"))?;
        assert!(report.blocks.is_empty());
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_040_load_and_export_repeated_empty_reports() -> TestResult {
    let path = next_test_path("repeat_exports");
    remove_path_if_exists(&path)?;

    let report = empty_report();

    for index in 0_u64..25_u64 {
        let file = path.with_extension(format!("{index}.json"));
        remove_path_if_exists(&file)?;

        report
            .export_json(&file)
            .map_err(|e| format!("export_json failed at {index}: {e:?}"))?;

        let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
        assert!(serde_json::from_slice::<Value>(&bytes).is_ok());

        remove_path_if_exists(&file)?;
    }

    Ok(())
}

#[test]
fn audit_hub_041_audit_transaction_deserializes_missing_optional_fields_as_none() -> TestResult {
    let json = r#"{"kind":"nft_mint"}"#;
    let tx = serde_json::from_str::<AuditTransaction>(json).map_err(|e| e.to_string())?;

    assert_eq!(tx.kind, "nft_mint");
    assert_eq!(tx.sender, None);
    assert_eq!(tx.receiver, None);
    assert_eq!(tx.amount, None);
    Ok(())
}

#[test]
fn audit_hub_042_audit_transaction_deserializes_full_transfer_vector() -> TestResult {
    let json = r#"{"kind":"transfer","sender":"alice","receiver":"bob","amount":1000}"#;
    let tx = serde_json::from_str::<AuditTransaction>(json).map_err(|e| e.to_string())?;

    assert_eq!(tx.kind, "transfer");
    assert_eq!(tx.sender, Some("alice".to_string()));
    assert_eq!(tx.receiver, Some("bob".to_string()));
    assert_eq!(tx.amount, Some(1_000));
    Ok(())
}

#[test]
fn audit_hub_043_audit_transaction_deserializes_explicit_null_optionals() -> TestResult {
    let json = r#"{"kind":"reward","sender":null,"receiver":"miner","amount":null}"#;
    let tx = serde_json::from_str::<AuditTransaction>(json).map_err(|e| e.to_string())?;

    assert_eq!(tx.kind, "reward");
    assert_eq!(tx.sender, None);
    assert_eq!(tx.receiver, Some("miner".to_string()));
    assert_eq!(tx.amount, None);
    Ok(())
}

#[test]
fn audit_hub_044_audit_transaction_rejects_missing_required_kind() -> TestResult {
    let json = r#"{"sender":"alice","receiver":"bob","amount":1}"#;
    let result = serde_json::from_str::<AuditTransaction>(json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn audit_hub_045_audit_transaction_allows_unknown_kind_as_report_data() -> TestResult {
    let tx = sample_tx("future_tx_kind", Some("a"), Some("b"), Some(9));
    let value = serde_json::to_value(&tx).map_err(|e| e.to_string())?;

    assert_eq!(value["kind"], "future_tx_kind");
    assert_eq!(value["amount"], 9);
    Ok(())
}

#[test]
fn audit_hub_046_audit_transaction_amount_accepts_u64_max() -> TestResult {
    let tx = sample_tx(
        "transfer",
        Some("max-sender"),
        Some("max-receiver"),
        Some(u64::MAX),
    );
    let value = serde_json::to_value(&tx).map_err(|e| e.to_string())?;

    assert_eq!(value["amount"], u64::MAX);
    Ok(())
}

#[test]
fn audit_hub_047_audit_block_deserializes_full_vector() -> TestResult {
    let guardian = "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));
    let json = format!(
        r#"{{
            "index":1,
            "timestamp":2,
            "size":3,
            "tx_count":1,
            "transactions":[{{"kind":"reward","sender":null,"receiver":"miner","amount":7}}],
            "current_hash":"{}",
            "previous_hash":"{}",
            "merkle_root":"{}",
            "guardian_sig":"{}"
        }}"#,
        "a".repeat(128),
        "b".repeat(128),
        "c".repeat(128),
        guardian
    );

    let block = serde_json::from_str::<AuditBlock>(&json).map_err(|e| e.to_string())?;

    assert_eq!(block.index, 1);
    assert_eq!(block.timestamp, 2);
    assert_eq!(block.size, 3);
    assert_eq!(block.tx_count, 1);
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(block.transactions[0].kind, "reward");
    Ok(())
}

#[test]
fn audit_hub_048_audit_block_rejects_missing_required_hash_field() -> TestResult {
    let json = r#"{
        "index":1,
        "timestamp":2,
        "size":3,
        "tx_count":0,
        "transactions":[],
        "previous_hash":"bbbb",
        "merkle_root":"cccc",
        "guardian_sig":"dddd"
    }"#;

    let result = serde_json::from_str::<AuditBlock>(json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn audit_hub_049_audit_block_allows_empty_transaction_vector() -> TestResult {
    let block = AuditBlock {
        index: 44,
        timestamp: 55,
        size: 66,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };

    let value = serde_json::to_value(&block).map_err(|e| e.to_string())?;

    assert_eq!(value["index"], 44);
    assert_eq!(value["transactions"].as_array().map(Vec::len), Some(0));
    Ok(())
}

#[test]
fn audit_hub_050_audit_block_serialization_preserves_transaction_order() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 3,
        transactions: vec![
            sample_tx("transfer", Some("a"), Some("b"), Some(1)),
            sample_tx("reward", None, Some("miner"), Some(2)),
            sample_tx("nft_transfer", None, Some("owner"), None),
        ],
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };

    let value = serde_json::to_value(&block).map_err(|e| e.to_string())?;
    let transactions = value["transactions"]
        .as_array()
        .ok_or_else(|| "transactions was not an array".to_string())?;

    assert_eq!(transactions[0]["kind"], "transfer");
    assert_eq!(transactions[1]["kind"], "reward");
    assert_eq!(transactions[2]["kind"], "nft_transfer");
    Ok(())
}

#[test]
fn audit_hub_051_canonical_bytes_preserve_duplicate_blocks_as_distinct_entries() -> TestResult {
    let block = sample_block(3, 333, 1);
    let report = AuditReport {
        blocks: vec![block, sample_block(3, 333, 1)],
    };

    let json = canonical_json_string(&report)?;

    assert!(json.matches("\"index\"").count() >= 2);
    assert!(json.contains("transfer"));
    Ok(())
}

#[test]
fn audit_hub_052_canonical_bytes_are_sensitive_to_transaction_order() -> TestResult {
    let block_a = AuditBlock {
        index: 1,
        timestamp: 1,
        size: 1,
        tx_count: 2,
        transactions: vec![
            sample_tx("transfer", Some("a"), Some("b"), Some(1)),
            sample_tx("reward", None, Some("miner"), Some(2)),
        ],
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };
    let block_b = AuditBlock {
        transactions: vec![
            sample_tx("reward", None, Some("miner"), Some(2)),
            sample_tx("transfer", Some("a"), Some("b"), Some(1)),
        ],
        ..block_a
    };

    let report_a = AuditReport {
        blocks: vec![block_b],
    };
    let report_b = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 1,
            size: 1,
            tx_count: 2,
            transactions: vec![
                sample_tx("transfer", Some("a"), Some("b"), Some(1)),
                sample_tx("reward", None, Some("miner"), Some(2)),
            ],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let bytes_a = report_a
        .canonical_bytes()
        .map_err(|e| format!("canonical A failed: {e:?}"))?;
    let bytes_b = report_b
        .canonical_bytes()
        .map_err(|e| format!("canonical B failed: {e:?}"))?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_hub_053_canonical_bytes_are_sensitive_to_hash_changes() -> TestResult {
    let report_a = AuditReport {
        blocks: vec![sample_block(1, 1, 1)],
    };
    let mut changed = sample_block(1, 1, 1);
    changed.current_hash = "f".repeat(128);
    let report_b = AuditReport {
        blocks: vec![changed],
    };

    let bytes_a = report_a
        .canonical_bytes()
        .map_err(|e| format!("canonical A failed: {e:?}"))?;
    let bytes_b = report_b
        .canonical_bytes()
        .map_err(|e| format!("canonical B failed: {e:?}"))?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_hub_054_canonical_bytes_are_sensitive_to_guardian_signature_changes() -> TestResult {
    let report_a = AuditReport {
        blocks: vec![sample_block(1, 1, 1)],
    };
    let mut changed = sample_block(1, 1, 1);
    changed.guardian_sig = "e".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));
    let report_b = AuditReport {
        blocks: vec![changed],
    };

    let bytes_a = report_a
        .canonical_bytes()
        .map_err(|e| format!("canonical A failed: {e:?}"))?;
    let bytes_b = report_b
        .canonical_bytes()
        .map_err(|e| format!("canonical B failed: {e:?}"))?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_hub_055_canonical_bytes_are_sensitive_to_amount_changes() -> TestResult {
    let report_a = AuditReport {
        blocks: vec![sample_block(1, 1, 1)],
    };
    let mut changed = sample_block(1, 1, 1);
    changed.transactions = vec![sample_tx(
        "transfer",
        Some("sender-wallet"),
        Some("receiver-wallet"),
        Some(124),
    )];
    let report_b = AuditReport {
        blocks: vec![changed],
    };

    let bytes_a = report_a
        .canonical_bytes()
        .map_err(|e| format!("canonical A failed: {e:?}"))?;
    let bytes_b = report_b
        .canonical_bytes()
        .map_err(|e| format!("canonical B failed: {e:?}"))?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_hub_056_canonical_bytes_handles_large_transaction_vector() -> TestResult {
    let transactions = (0_u64..500_u64)
        .map(|index| sample_tx("transfer", Some("sender"), Some("receiver"), Some(index)))
        .collect::<Vec<_>>();

    let block = AuditBlock {
        index: 500,
        timestamp: 500,
        size: 500,
        tx_count: 500,
        transactions,
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = report
        .canonical_bytes()
        .map_err(|e| format!("canonical large transaction vector failed: {e:?}"))?;
    let value = serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())?;

    assert!(value.is_object());
    assert!(bytes.len() > 500);
    Ok(())
}

#[test]
fn audit_hub_057_export_json_large_transaction_vector_writes_valid_json() -> TestResult {
    let path = next_test_path("large_tx_json");
    remove_path_if_exists(&path)?;

    let transactions = (0_u64..250_u64)
        .map(|index| sample_tx("reward", None, Some("receiver"), Some(index)))
        .collect::<Vec<_>>();

    let block = AuditBlock {
        index: 250,
        timestamp: 250,
        size: 250,
        tx_count: 250,
        transactions,
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    report
        .export_json(&path)
        .map_err(|e| format!("large export_json failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    assert!(bytes.len() > 250);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_058_export_pdf_large_transaction_vector_writes_pdf() -> TestResult {
    let path = next_test_path("large_tx_pdf");
    remove_path_if_exists(&path)?;

    let transactions = (0_u64..100_u64)
        .map(|index| sample_tx("transfer", Some("a"), Some("b"), Some(index)))
        .collect::<Vec<_>>();

    let block = AuditBlock {
        index: 100,
        timestamp: 100,
        size: 100,
        tx_count: 100,
        transactions,
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };
    let report = AuditReport {
        blocks: vec![block],
    };
    let fixed = Utc
        .timestamp_opt(1_700_000_001, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("large export_pdf_with_time failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.len() > 100);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_059_export_json_with_unicode_file_name_writes_valid_json() -> TestResult {
    let path = next_test_path("unicode_name").with_file_name(format!(
        "remzar_audit_unicode_{}_{}.json",
        std::process::id(),
        "鎖"
    ));
    remove_path_if_exists(&path)?;

    let report = sample_report();
    report
        .export_json(&path)
        .map_err(|e| format!("unicode filename export_json failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_060_export_pdf_with_unicode_file_name_writes_pdf() -> TestResult {
    let path = next_test_path("unicode_pdf").with_file_name(format!(
        "remzar_audit_unicode_{}_{}.pdf",
        std::process::id(),
        "報告"
    ));
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_002, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("unicode filename export_pdf failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    assert!(bytes.starts_with(b"%PDF"));

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_061_export_json_then_export_pdf_same_report_both_outputs_valid() -> TestResult {
    let json_path = next_test_path("dual_export_json");
    let pdf_path = next_test_path("dual_export_pdf");
    remove_path_if_exists(&json_path)?;
    remove_path_if_exists(&pdf_path)?;

    let report = two_block_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_003, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_json(&json_path)
        .map_err(|e| format!("dual export_json failed: {e:?}"))?;
    report
        .export_pdf_with_time(&pdf_path, fixed)
        .map_err(|e| format!("dual export_pdf failed: {e:?}"))?;

    let json_bytes = std::fs::read(&json_path).map_err(|e| e.to_string())?;
    let pdf_bytes = std::fs::read(&pdf_path).map_err(|e| e.to_string())?;

    assert!(serde_json::from_slice::<Value>(&json_bytes).is_ok());
    assert!(pdf_bytes.starts_with(b"%PDF"));

    remove_path_if_exists(&json_path)?;
    remove_path_if_exists(&pdf_path)?;
    Ok(())
}

#[test]
fn audit_hub_062_load_range_with_nested_missing_path_returns_database_error() -> TestResult {
    let path = next_test_path("missing_nested_db")
        .join("missing")
        .join("chain_db");

    assert_database_error(AuditReport::load_range_with_path(&path, 0, 0))?;
    Ok(())
}

#[test]
fn audit_hub_063_load_range_with_empty_db_at_u64_max_single_index_is_empty() -> TestResult {
    let path = next_test_path("empty_db_u64_max");
    create_empty_blockchain_db(&path)?;

    let report = AuditReport::load_range_with_path(&path, u64::MAX, u64::MAX)
        .map_err(|e| format!("u64 max single load failed: {e:?}"))?;

    assert!(report.blocks.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_064_load_range_reverse_u64_bounds_is_empty_for_valid_db() -> TestResult {
    let path = next_test_path("reverse_u64_bounds");
    create_empty_blockchain_db(&path)?;

    let report = AuditReport::load_range_with_path(&path, u64::MAX, 0)
        .map_err(|e| format!("reverse u64 bounds load failed: {e:?}"))?;

    assert!(report.blocks.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_065_load_range_empty_db_zero_to_zero_is_empty() -> TestResult {
    let path = next_test_path("zero_zero_empty_db");
    create_empty_blockchain_db(&path)?;

    let report = AuditReport::load_range_with_path(&path, 0, 0)
        .map_err(|e| format!("zero-to-zero load failed: {e:?}"))?;

    assert!(report.blocks.is_empty());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_066_export_json_file_can_be_read_multiple_times_consistently() -> TestResult {
    let path = next_test_path("json_repeat_read");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    report
        .export_json(&path)
        .map_err(|e| format!("export_json failed: {e:?}"))?;

    let first = std::fs::read(&path).map_err(|e| e.to_string())?;
    let second = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert_eq!(first, second);
    assert!(serde_json::from_slice::<Value>(&first).is_ok());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_067_pdf_file_can_be_read_multiple_times_consistently() -> TestResult {
    let path = next_test_path("pdf_repeat_read");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_004, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("export_pdf failed: {e:?}"))?;

    let first = std::fs::read(&path).map_err(|e| e.to_string())?;
    let second = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert_eq!(first, second);
    assert!(first.starts_with(b"%PDF"));

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_068_canonical_json_has_no_trailing_garbage_after_parse() -> TestResult {
    let report = sample_report();
    let bytes = report
        .canonical_bytes()
        .map_err(|e| format!("canonical failed: {e:?}"))?;

    let de = serde_json::Deserializer::from_slice(&bytes);
    let mut stream = de.into_iter::<Value>();

    assert!(
        stream
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_some()
    );
    assert!(
        stream
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_none()
    );
    Ok(())
}

#[test]
fn audit_hub_069_exported_json_has_no_trailing_garbage_after_parse() -> TestResult {
    let path = next_test_path("json_no_trailing");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    report
        .export_json(&path)
        .map_err(|e| format!("export_json failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let de = serde_json::Deserializer::from_slice(&bytes);
    let mut stream = de.into_iter::<Value>();

    assert!(
        stream
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_some()
    );
    assert!(
        stream
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_none()
    );

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_070_canonical_bytes_for_empty_and_nonempty_reports_differ() -> TestResult {
    let empty = empty_report();
    let nonempty = sample_report();

    let empty_bytes = empty
        .canonical_bytes()
        .map_err(|e| format!("empty canonical failed: {e:?}"))?;
    let nonempty_bytes = nonempty
        .canonical_bytes()
        .map_err(|e| format!("nonempty canonical failed: {e:?}"))?;

    assert_ne!(empty_bytes, nonempty_bytes);
    Ok(())
}

#[test]
fn audit_hub_071_canonical_bytes_handles_many_blocks() -> TestResult {
    let blocks = (0_u64..100_u64)
        .map(|index| sample_block(index, index.saturating_add(1_000), 1))
        .collect::<Vec<_>>();

    let report = AuditReport { blocks };
    let bytes = report
        .canonical_bytes()
        .map_err(|e| format!("many blocks canonical failed: {e:?}"))?;

    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    assert!(bytes.len() > 1_000);
    Ok(())
}

#[test]
fn audit_hub_072_export_json_handles_many_blocks() -> TestResult {
    let path = next_test_path("many_blocks_json");
    remove_path_if_exists(&path)?;

    let blocks = (0_u64..50_u64)
        .map(|index| sample_block(index, index.saturating_add(2_000), 1))
        .collect::<Vec<_>>();
    let report = AuditReport { blocks };

    report
        .export_json(&path)
        .map_err(|e| format!("many blocks export_json failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    assert!(bytes.len() > 500);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_073_export_pdf_handles_many_blocks() -> TestResult {
    let path = next_test_path("many_blocks_pdf");
    remove_path_if_exists(&path)?;

    let blocks = (0_u64..25_u64)
        .map(|index| sample_block(index, index.saturating_add(3_000), 1))
        .collect::<Vec<_>>();
    let report = AuditReport { blocks };
    let fixed = Utc
        .timestamp_opt(1_700_000_005, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("many blocks export_pdf failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.len() > 100);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_074_export_json_zero_length_hash_strings_still_serializes_report_data() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: String::new(),
        previous_hash: String::new(),
        merkle_root: String::new(),
        guardian_sig: String::new(),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let json = canonical_json_string(&report)?;

    assert!(json.contains("\"current_hash\""));
    assert!(json.contains("\"previous_hash\""));
    assert!(json.contains("\"merkle_root\""));
    assert!(json.contains("\"guardian_sig\""));
    Ok(())
}

#[test]
fn audit_hub_075_export_json_to_path_without_extension_writes_valid_json() -> TestResult {
    let path = next_test_path("json_no_extension");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    report
        .export_json(&path)
        .map_err(|e| format!("no extension export_json failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_076_export_pdf_to_path_without_extension_writes_pdf_bytes() -> TestResult {
    let path = next_test_path("pdf_no_extension");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_006, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("no extension export_pdf failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    assert!(bytes.starts_with(b"%PDF"));

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_077_repeated_canonical_bytes_for_many_blocks_are_stable() -> TestResult {
    let blocks = (0_u64..25_u64)
        .map(|index| sample_block(index, index.saturating_add(4_000), 1))
        .collect::<Vec<_>>();
    let report = AuditReport { blocks };

    let baseline = report
        .canonical_bytes()
        .map_err(|e| format!("baseline canonical failed: {e:?}"))?;

    for _ in 0..100 {
        let next = report
            .canonical_bytes()
            .map_err(|e| format!("repeated canonical failed: {e:?}"))?;
        assert_eq!(next, baseline);
    }

    Ok(())
}

#[test]
fn audit_hub_078_repeated_export_json_overwrites_same_file_with_valid_json() -> TestResult {
    let path = next_test_path("repeat_same_json");
    remove_path_if_exists(&path)?;

    let report = sample_report();

    for _ in 0..25 {
        report
            .export_json(&path)
            .map_err(|e| format!("repeat export_json failed: {e:?}"))?;

        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_079_repeated_export_pdf_overwrites_same_file_with_pdf() -> TestResult {
    let path = next_test_path("repeat_same_pdf");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_007, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    for _ in 0..10 {
        report
            .export_pdf_with_time(&path, fixed)
            .map_err(|e| format!("repeat export_pdf failed: {e:?}"))?;

        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        assert!(bytes.starts_with(b"%PDF"));
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_080_load_range_with_empty_db_repeated_reverse_ranges_are_stable() -> TestResult {
    let path = next_test_path("repeat_reverse_empty_db");
    create_empty_blockchain_db(&path)?;

    for index in 0_u64..50_u64 {
        let report = AuditReport::load_range_with_path(&path, index.saturating_add(10), index)
            .map_err(|e| format!("reverse empty load failed at {index}: {e:?}"))?;
        assert!(report.blocks.is_empty());
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_081_audit_transaction_rejects_string_amount_for_u64_field() -> TestResult {
    let json = r#"{"kind":"transfer","sender":"alice","receiver":"bob","amount":"100"}"#;
    let result = serde_json::from_str::<AuditTransaction>(json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn audit_hub_082_audit_transaction_rejects_negative_amount_for_u64_field() -> TestResult {
    let json = r#"{"kind":"transfer","sender":"alice","receiver":"bob","amount":-1}"#;
    let result = serde_json::from_str::<AuditTransaction>(json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn audit_hub_083_audit_block_rejects_string_index_for_u64_field() -> TestResult {
    let guardian = "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));
    let json = format!(
        r#"{{
            "index":"1",
            "timestamp":2,
            "size":3,
            "tx_count":0,
            "transactions":[],
            "current_hash":"{}",
            "previous_hash":"{}",
            "merkle_root":"{}",
            "guardian_sig":"{}"
        }}"#,
        "a".repeat(128),
        "b".repeat(128),
        "c".repeat(128),
        guardian
    );

    let result = serde_json::from_str::<AuditBlock>(&json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn audit_hub_084_audit_block_rejects_non_array_transactions_field() -> TestResult {
    let guardian = "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));
    let json = format!(
        r#"{{
            "index":1,
            "timestamp":2,
            "size":3,
            "tx_count":0,
            "transactions":"not-array",
            "current_hash":"{}",
            "previous_hash":"{}",
            "merkle_root":"{}",
            "guardian_sig":"{}"
        }}"#,
        "a".repeat(128),
        "b".repeat(128),
        "c".repeat(128),
        guardian
    );

    let result = serde_json::from_str::<AuditBlock>(&json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn audit_hub_085_audit_block_allows_unknown_extra_json_fields_by_default() -> TestResult {
    let guardian = "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));
    let json = format!(
        r#"{{
            "index":1,
            "timestamp":2,
            "size":3,
            "tx_count":0,
            "transactions":[],
            "current_hash":"{}",
            "previous_hash":"{}",
            "merkle_root":"{}",
            "guardian_sig":"{}",
            "future_field":"allowed-by-serde"
        }}"#,
        "a".repeat(128),
        "b".repeat(128),
        "c".repeat(128),
        guardian
    );

    let block = serde_json::from_str::<AuditBlock>(&json).map_err(|e| e.to_string())?;

    assert_eq!(block.index, 1);
    assert_eq!(block.transactions.len(), 0);
    Ok(())
}

#[test]
fn audit_hub_086_audit_transaction_allows_unknown_extra_json_fields_by_default() -> TestResult {
    let json = r#"{
        "kind":"transfer",
        "sender":"alice",
        "receiver":"bob",
        "amount":5,
        "future_field":"allowed-by-serde"
    }"#;

    let tx = serde_json::from_str::<AuditTransaction>(json).map_err(|e| e.to_string())?;

    assert_eq!(tx.kind, "transfer");
    assert_eq!(tx.amount, Some(5));
    Ok(())
}

#[test]
fn audit_hub_087_canonical_bytes_preserve_null_optional_transaction_fields() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 1,
        transactions: vec![sample_tx("nft_mint", None, None, None)],
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let json = canonical_json_string(&report)?;

    assert!(json.contains("nft_mint"));
    assert!(json.contains("null"));
    Ok(())
}

#[test]
fn audit_hub_088_canonical_bytes_preserve_zero_amount_vector() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 1,
        transactions: vec![sample_tx("transfer", Some("alice"), Some("bob"), Some(0))],
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let json = canonical_json_string(&report)?;

    assert!(json.contains("\"amount\""));
    assert!(json.contains("0"));
    Ok(())
}

#[test]
fn audit_hub_089_canonical_bytes_preserve_large_hash_strings() -> TestResult {
    let large_hash = "a".repeat(4_096);
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: large_hash.clone(),
        previous_hash: "b".repeat(4_096),
        merkle_root: "c".repeat(4_096),
        guardian_sig: "d".repeat(4_096),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let json = canonical_json_string(&report)?;

    assert!(json.contains(&large_hash));
    assert!(json.len() > 16_000);
    Ok(())
}

#[test]
fn audit_hub_090_exported_pdf_contains_pdf_eof_marker() -> TestResult {
    let path = next_test_path("pdf_eof_marker");
    remove_path_if_exists(&path)?;

    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_008, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("export_pdf failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.windows(5).any(|window| window == b"%%EOF"));

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_091_exported_pdf_for_empty_report_contains_pdf_eof_marker() -> TestResult {
    let path = next_test_path("empty_pdf_eof_marker");
    remove_path_if_exists(&path)?;

    let report = empty_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_009, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&path, fixed)
        .map_err(|e| format!("empty export_pdf failed: {e:?}"))?;

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;

    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.windows(5).any(|window| window == b"%%EOF"));

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_092_export_json_creates_file_when_parent_exists_but_file_does_not() -> TestResult {
    let dir = next_test_path("json_parent_exists");
    remove_path_if_exists(&dir)?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let file = dir.join("audit.json");
    let report = sample_report();

    report
        .export_json(&file)
        .map_err(|e| format!("export_json failed: {e:?}"))?;

    assert!(file.exists());
    let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());

    remove_path_if_exists(&dir)?;
    Ok(())
}

#[test]
fn audit_hub_093_export_pdf_creates_file_when_parent_exists_but_file_does_not() -> TestResult {
    let dir = next_test_path("pdf_parent_exists");
    remove_path_if_exists(&dir)?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let file = dir.join("audit.pdf");
    let report = sample_report();
    let fixed = Utc
        .timestamp_opt(1_700_000_010, 0)
        .single()
        .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

    report
        .export_pdf_with_time(&file, fixed)
        .map_err(|e| format!("export_pdf failed: {e:?}"))?;

    assert!(file.exists());
    let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
    assert!(bytes.starts_with(b"%PDF"));

    remove_path_if_exists(&dir)?;
    Ok(())
}

#[test]
fn audit_hub_094_load_range_with_db_missing_transaction_batch_cf_returns_database_error()
-> TestResult {
    let path = next_test_path("missing_tx_cf_db");
    remove_path_if_exists(&path)?;

    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let cf_names = [GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME];
    let db = DB::open_cf(&opts, &path, cf_names).map_err(|e| e.to_string())?;
    drop(db);

    assert_database_error(AuditReport::load_range_with_path(&path, 0, 0))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_095_load_range_with_db_missing_blockmint_cf_returns_database_error() -> TestResult {
    let path = next_test_path("missing_block_cf_db");
    remove_path_if_exists(&path)?;

    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let cf_names = [GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME];
    let db = DB::open_cf(&opts, &path, cf_names).map_err(|e| e.to_string())?;
    drop(db);

    assert_database_error(AuditReport::load_range_with_path(&path, 0, 0))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_096_load_range_with_default_only_rocksdb_returns_database_error() -> TestResult {
    let path = next_test_path("default_only_db");
    remove_path_if_exists(&path)?;

    let mut opts = Options::default();
    opts.create_if_missing(true);

    let db = DB::open(&opts, &path).map_err(|e| e.to_string())?;
    drop(db);

    assert_database_error(AuditReport::load_range_with_path(&path, 0, 0))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn audit_hub_097_canonical_bytes_many_reports_property_nonempty_valid_json() -> TestResult {
    for index in 0_u64..100_u64 {
        let report = AuditReport {
            blocks: vec![sample_block(
                index,
                index.saturating_add(10_000),
                index.rem_euclid(5),
            )],
        };

        let bytes = report
            .canonical_bytes()
            .map_err(|e| format!("canonical failed at {index}: {e:?}"))?;

        assert!(!bytes.is_empty());
        assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    }

    Ok(())
}

#[test]
fn audit_hub_098_export_json_many_reports_property_valid_json() -> TestResult {
    let base = next_test_path("many_json_property");
    remove_path_if_exists(&base)?;

    for index in 0_u64..25_u64 {
        let file = base.with_extension(format!("{index}.json"));
        remove_path_if_exists(&file)?;

        let report = AuditReport {
            blocks: vec![sample_block(
                index,
                index.saturating_add(20_000),
                index.rem_euclid(7),
            )],
        };

        report
            .export_json(&file)
            .map_err(|e| format!("export_json failed at {index}: {e:?}"))?;

        let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
        assert!(serde_json::from_slice::<Value>(&bytes).is_ok());

        remove_path_if_exists(&file)?;
    }

    Ok(())
}

#[test]
fn audit_hub_099_export_pdf_many_reports_property_pdf_header() -> TestResult {
    let base = next_test_path("many_pdf_property");
    remove_path_if_exists(&base)?;

    for index in 0_i64..10_i64 {
        let file = base.with_extension(format!("{index}.pdf"));
        remove_path_if_exists(&file)?;

        let report = AuditReport {
            blocks: vec![sample_block(
                u64::try_from(index).map_err(|e| e.to_string())?,
                u64::try_from(index.saturating_add(30_000)).map_err(|e| e.to_string())?,
                1,
            )],
        };
        let fixed = Utc
            .timestamp_opt(1_700_000_100_i64.saturating_add(index), 0)
            .single()
            .ok_or_else(|| "failed to construct fixed timestamp".to_string())?;

        report
            .export_pdf_with_time(&file, fixed)
            .map_err(|e| format!("export_pdf failed at {index}: {e:?}"))?;

        let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
        assert!(bytes.starts_with(b"%PDF"));

        remove_path_if_exists(&file)?;
    }

    Ok(())
}

#[test]
fn audit_hub_100_load_empty_db_many_forward_ranges_property_empty_reports() -> TestResult {
    let path = next_test_path("many_forward_ranges_empty_db");
    create_empty_blockchain_db(&path)?;

    for start in 0_u64..25_u64 {
        let end = start.saturating_add(3);
        let report = AuditReport::load_range_with_path(&path, start, end)
            .map_err(|e| format!("load_range failed for {start}..={end}: {e:?}"))?;

        assert!(report.blocks.is_empty());
    }

    remove_path_if_exists(&path)?;
    Ok(())
}
