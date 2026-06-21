use chrono::{TimeZone, Utc};
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::commandline::s_17_debug_audit_report::S17DebugAuditReport;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::{Mode, RockDBManager};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::audit_report_001_hub::{AuditBlock, AuditReport, AuditTransaction};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(case_name: &str) -> TestResult<Self> {
        let mut path = std::env::temp_dir();
        path.push(format!("remzar_s17_{case_name}_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self.path.exists() {
            match fs::remove_dir_all(&self.path) {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

fn boxed_error(message: &str) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message.to_owned()))
}

fn string_error(message: String) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message))
}

fn path_to_string(path: &Path) -> TestResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn node_opts(root: &Path) -> TestResult<NodeOpts> {
    Ok(NodeOpts {
        identity_file: path_to_string(&root.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "off".to_owned(),
        data_dir: path_to_string(root)?,
        wallet_address: String::new(),
        founder: false,
    })
}

fn wallet_with_pair(pair: &str) -> String {
    let mut wallet = String::from("r");
    for _ in 0..64 {
        wallet.push_str(pair);
    }
    wallet
}

fn sample_tx(kind: &str, amount: Option<u64>) -> AuditTransaction {
    AuditTransaction {
        kind: kind.to_owned(),
        sender: Some("sender-wallet".to_owned()),
        receiver: Some("receiver-wallet".to_owned()),
        amount,
    }
}

fn sample_block(index: u64, timestamp: u64, tx_count: u64) -> AuditBlock {
    AuditBlock {
        index,
        timestamp,
        size: 512u64.saturating_add(index),
        tx_count,
        transactions: Vec::new(),
        current_hash: "aa".repeat(64),
        previous_hash: "bb".repeat(64),
        merkle_root: "cc".repeat(64),
        guardian_sig: "dd".repeat(128),
    }
}

fn sample_block_with_transaction(index: u64, timestamp: u64, tx: AuditTransaction) -> AuditBlock {
    let mut block = sample_block(index, timestamp, 1);
    block.transactions.push(tx);
    block
}

fn report_empty() -> AuditReport {
    AuditReport { blocks: Vec::new() }
}

fn report_one() -> AuditReport {
    AuditReport {
        blocks: vec![sample_block(0, 1_700_000_000, 0)],
    }
}

fn report_two() -> AuditReport {
    AuditReport {
        blocks: vec![
            sample_block(0, 1_700_000_000, 2),
            sample_block(1, 1_700_000_012, 3),
        ],
    }
}

fn canonical_json(report: &AuditReport) -> TestResult<Value> {
    let bytes = report.canonical_bytes()?;
    let value = serde_json::from_slice::<Value>(&bytes)?;
    Ok(value)
}

fn export_json_value(report: &AuditReport, root: &Path, file_name: &str) -> TestResult<Value> {
    let path = root.join(file_name);
    report.export_json(&path)?;
    let bytes = fs::read(path)?;
    let value = serde_json::from_slice::<Value>(&bytes)?;
    Ok(value)
}

fn create_empty_blockchain_path(case_name: &str) -> TestResult<(TempRoot, NodeOpts, PathBuf)> {
    let temp = TempRoot::new(case_name)?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    let path = directory.blockchain_path.clone();
    let manager = RockDBManager::new_blockchain(&opts, &path.to_string_lossy())?;
    assert_eq!(manager.mode, Mode::Blockchain);
    drop(manager);
    Ok((temp, opts, path))
}

fn create_genesis_block_bytes(founder: &str) -> TestResult<Vec<u8>> {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar audit test genesis",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        founder,
    )?;
    let metadata = BlockMetadata::from_genesis(genesis)?;
    let block = Block::new(metadata, None, founder.to_owned(), 0)?;
    Ok(block.serialize_for_storage()?)
}

fn create_blockchain_with_block_zero(case_name: &str) -> TestResult<(TempRoot, NodeOpts, PathBuf)> {
    let temp = TempRoot::new(case_name)?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    let path = directory.blockchain_path.clone();

    let manager = RockDBManager::new_blockchain(&opts, &path.to_string_lossy())?;
    let founder = wallet_with_pair("11");
    let bytes = create_genesis_block_bytes(&founder)?;
    manager.store_latest_block(&bytes, 0)?;
    drop(manager);

    Ok((temp, opts, path))
}

fn create_blockchain_with_invalid_block_zero(case_name: &str) -> TestResult<(TempRoot, PathBuf)> {
    let temp = TempRoot::new(case_name)?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    let path = directory.blockchain_path.clone();

    let manager = RockDBManager::new_blockchain(&opts, &path.to_string_lossy())?;
    manager.write(
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        b"block_0000000000",
        b"not-a-valid-block",
    )?;
    drop(manager);

    Ok((temp, path))
}

fn fixed_time() -> TestResult<chrono::DateTime<Utc>> {
    Utc.timestamp_opt(1_700_000_000, 0)
        .single()
        .ok_or_else(|| boxed_error("invalid fixed timestamp"))
}

#[test]
fn s17_01_new_constructs_wrapper() -> TestResult {
    let _section = S17DebugAuditReport::new();
    Ok(())
}

#[test]
fn s17_02_default_constructs_wrapper() -> TestResult {
    let _section = S17DebugAuditReport;
    let _default_section = S17DebugAuditReport::default();
    Ok(())
}

#[test]
fn s17_03_multiple_new_instances_are_independent_zero_sized_wrappers() -> TestResult {
    let _first = S17DebugAuditReport::new();
    let _second = S17DebugAuditReport::new();
    Ok(())
}

#[test]
fn s17_04_empty_report_canonical_json_has_meta_and_blocks() -> TestResult {
    let value = canonical_json(&report_empty())?;
    assert!(value.get("meta").is_some());
    assert!(value.get("blocks").is_some());
    Ok(())
}

#[test]
fn s17_05_empty_report_block_span_is_zero() -> TestResult {
    let value = canonical_json(&report_empty())?;
    assert_eq!(value["meta"]["block_span"], 0);
    Ok(())
}

#[test]
fn s17_06_empty_report_total_tx_is_zero() -> TestResult {
    let value = canonical_json(&report_empty())?;
    assert_eq!(value["meta"]["total_tx"], 0);
    Ok(())
}

#[test]
fn s17_07_empty_report_report_time_is_zero() -> TestResult {
    let value = canonical_json(&report_empty())?;
    assert_eq!(value["meta"]["report_time"], 0);
    Ok(())
}

#[test]
fn s17_08_empty_report_export_time_is_zero_for_canonical_bytes() -> TestResult {
    let value = canonical_json(&report_empty())?;
    assert_eq!(value["meta"]["export_time"], 0);
    Ok(())
}

#[test]
fn s17_09_single_block_report_has_block_span_one() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["meta"]["block_span"], 1);
    Ok(())
}

#[test]
fn s17_10_two_block_report_sums_total_tx() -> TestResult {
    let value = canonical_json(&report_two())?;
    assert_eq!(value["meta"]["total_tx"], 5);
    Ok(())
}

#[test]
fn s17_11_canonical_report_time_uses_first_block_timestamp() -> TestResult {
    let value = canonical_json(&report_two())?;
    assert_eq!(value["meta"]["report_time"], 1_700_000_000);
    Ok(())
}

#[test]
fn s17_12_canonical_export_time_uses_first_block_timestamp() -> TestResult {
    let value = canonical_json(&report_two())?;
    assert_eq!(value["meta"]["export_time"], 1_700_000_000);
    Ok(())
}

#[test]
fn s17_13_canonical_json_preserves_block_index() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["blocks"][0]["index"], 0);
    Ok(())
}

#[test]
fn s17_14_canonical_json_preserves_block_timestamp() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["blocks"][0]["timestamp"], 1_700_000_000);
    Ok(())
}

#[test]
fn s17_15_canonical_json_preserves_block_size() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["blocks"][0]["size"], 512);
    Ok(())
}

#[test]
fn s17_16_canonical_json_preserves_current_hash() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["blocks"][0]["current_hash"], "aa".repeat(64));
    Ok(())
}

#[test]
fn s17_17_canonical_json_preserves_previous_hash() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["blocks"][0]["previous_hash"], "bb".repeat(64));
    Ok(())
}

#[test]
fn s17_18_canonical_json_preserves_merkle_root() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["blocks"][0]["merkle_root"], "cc".repeat(64));
    Ok(())
}

#[test]
fn s17_19_canonical_json_preserves_guardian_signature() -> TestResult {
    let value = canonical_json(&report_one())?;
    assert_eq!(value["blocks"][0]["guardian_sig"], "dd".repeat(128));
    Ok(())
}

#[test]
fn s17_20_canonical_json_preserves_transfer_transaction() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block_with_transaction(
            7,
            1_700_000_111,
            sample_tx("transfer", Some(42)),
        )],
    };

    let value = canonical_json(&report)?;
    assert_eq!(value["blocks"][0]["transactions"][0]["kind"], "transfer");
    assert_eq!(value["blocks"][0]["transactions"][0]["amount"], 42);
    Ok(())
}

#[test]
fn s17_21_canonical_json_preserves_null_amount() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block_with_transaction(
            8,
            1_700_000_112,
            sample_tx("register_node", None),
        )],
    };

    let value = canonical_json(&report)?;
    assert!(value["blocks"][0]["transactions"][0]["amount"].is_null());
    Ok(())
}

#[test]
fn s17_22_canonical_json_is_pretty_printed() -> TestResult {
    let bytes = report_one().canonical_bytes()?;
    let text = String::from_utf8(bytes)?;
    assert!(text.contains('\n'));
    assert!(text.contains("    \"meta\""));
    Ok(())
}

#[test]
fn s17_23_canonical_bytes_are_stable_for_identical_reports() -> TestResult {
    let first = report_two().canonical_bytes()?;
    let second = report_two().canonical_bytes()?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn s17_24_canonical_bytes_change_when_block_hash_changes() -> TestResult {
    let first = report_one().canonical_bytes()?;
    let mut block = sample_block(0, 1_700_000_000, 0);
    block.current_hash = "ee".repeat(64);
    let second = AuditReport {
        blocks: vec![block],
    }
    .canonical_bytes()?;
    assert_ne!(first, second);
    Ok(())
}

#[test]
fn s17_25_canonical_bytes_handle_u64_max_timestamp_by_clamping_to_i64_max() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(0, u64::MAX, 0)],
    };

    let value = canonical_json(&report)?;
    assert_eq!(value["meta"]["report_time"], i64::MAX);
    Ok(())
}

#[test]
fn s17_26_export_json_creates_file() -> TestResult {
    let temp = TempRoot::new("26_export_json_creates_file")?;
    let path = temp.path().join("audit.json");
    report_one().export_json(&path)?;
    assert!(path.is_file());
    Ok(())
}

#[test]
fn s17_27_export_json_file_is_valid_json() -> TestResult {
    let temp = TempRoot::new("27_export_json_valid")?;
    let value = export_json_value(&report_one(), temp.path(), "audit.json")?;
    assert!(value.get("meta").is_some());
    assert!(value.get("blocks").is_some());
    Ok(())
}

#[test]
fn s17_28_export_json_writes_runtime_export_time() -> TestResult {
    let temp = TempRoot::new("28_export_time")?;
    let value = export_json_value(&report_one(), temp.path(), "audit.json")?;
    let export_time = value["meta"]["export_time"]
        .as_i64()
        .ok_or_else(|| boxed_error("export_time was not i64"))?;
    assert!(export_time > 0);
    Ok(())
}

#[test]
fn s17_29_export_json_preserves_snapshot_report_time() -> TestResult {
    let temp = TempRoot::new("29_report_time")?;
    let value = export_json_value(&report_one(), temp.path(), "audit.json")?;
    assert_eq!(value["meta"]["report_time"], 1_700_000_000);
    Ok(())
}

#[test]
fn s17_30_export_json_overwrites_existing_file() -> TestResult {
    let temp = TempRoot::new("30_overwrite_json")?;
    let path = temp.path().join("audit.json");
    fs::write(&path, b"old")?;
    report_one().export_json(&path)?;
    let text = fs::read_to_string(path)?;
    assert!(text.contains("\"blocks\""));
    assert!(!text.contains("old"));
    Ok(())
}

#[test]
fn s17_31_export_json_to_missing_parent_fails() -> TestResult {
    let temp = TempRoot::new("31_missing_parent_json")?;
    let path = temp.path().join("missing").join("audit.json");
    let result = report_one().export_json(&path);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn s17_32_export_json_to_directory_path_fails() -> TestResult {
    let temp = TempRoot::new("32_json_to_directory")?;
    let result = report_one().export_json(temp.path());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn s17_33_export_json_handles_empty_report() -> TestResult {
    let temp = TempRoot::new("33_empty_json")?;
    let value = export_json_value(&report_empty(), temp.path(), "empty.json")?;
    assert_eq!(value["meta"]["block_span"], 0);
    assert_eq!(value["blocks"].as_array().map_or(usize::MAX, Vec::len), 0);
    Ok(())
}

#[test]
fn s17_34_export_json_handles_unicode_transaction_fields() -> TestResult {
    let tx = AuditTransaction {
        kind: "memo".to_owned(),
        sender: Some("送信者".to_owned()),
        receiver: Some("受信者".to_owned()),
        amount: None,
    };
    let report = AuditReport {
        blocks: vec![sample_block_with_transaction(1, 1_700_000_010, tx)],
    };

    let temp = TempRoot::new("34_unicode_json")?;
    let value = export_json_value(&report, temp.path(), "unicode.json")?;
    assert_eq!(value["blocks"][0]["transactions"][0]["sender"], "送信者");
    Ok(())
}

#[test]
fn s17_35_export_json_sums_large_tx_counts() -> TestResult {
    let report = AuditReport {
        blocks: vec![
            sample_block(0, 1_700_000_000, 1_000_000),
            sample_block(1, 1_700_000_001, 2_000_000),
        ],
    };
    let temp = TempRoot::new("35_large_tx_counts")?;
    let value = export_json_value(&report, temp.path(), "audit.json")?;
    assert_eq!(value["meta"]["total_tx"], 3_000_000);
    Ok(())
}

#[test]
fn s17_36_export_pdf_creates_nonempty_file_for_empty_report() -> TestResult {
    let temp = TempRoot::new("36_empty_pdf")?;
    let path = temp.path().join("audit.pdf");
    report_empty().export_pdf(&path)?;
    assert!(path.is_file());
    assert!(fs::metadata(path)?.len() > 0);
    Ok(())
}

#[test]
fn s17_37_export_pdf_creates_nonempty_file_for_single_block() -> TestResult {
    let temp = TempRoot::new("37_one_pdf")?;
    let path = temp.path().join("audit.pdf");
    report_one().export_pdf(&path)?;
    assert!(fs::metadata(path)?.len() > 0);
    Ok(())
}

#[test]
fn s17_38_export_pdf_output_starts_with_pdf_header() -> TestResult {
    let temp = TempRoot::new("38_pdf_header")?;
    let path = temp.path().join("audit.pdf");
    report_one().export_pdf(&path)?;
    let bytes = fs::read(path)?;
    assert!(bytes.starts_with(b"%PDF"));
    Ok(())
}

#[test]
fn s17_39_export_pdf_with_time_creates_file() -> TestResult {
    let temp = TempRoot::new("39_pdf_with_time")?;
    let path = temp.path().join("audit.pdf");
    report_one().export_pdf_with_time(&path, fixed_time()?)?;
    assert!(path.is_file());
    Ok(())
}

#[test]
fn s17_40_export_pdf_to_missing_parent_fails() -> TestResult {
    let temp = TempRoot::new("40_missing_parent_pdf")?;
    let path = temp.path().join("missing").join("audit.pdf");
    let result = report_one().export_pdf(&path);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn s17_41_export_pdf_to_directory_path_fails() -> TestResult {
    let temp = TempRoot::new("41_pdf_to_directory")?;
    let result = report_one().export_pdf(temp.path());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn s17_42_export_pdf_handles_many_blocks() -> TestResult {
    let temp = TempRoot::new("42_many_blocks_pdf")?;
    let blocks: Vec<AuditBlock> = (0u64..40u64)
        .map(|idx| sample_block(idx, 1_700_000_000u64.saturating_add(idx), idx % 3))
        .collect();
    let report = AuditReport { blocks };
    let path = temp.path().join("audit.pdf");
    report.export_pdf(&path)?;
    assert!(fs::metadata(path)?.len() > 0);
    Ok(())
}

#[test]
fn s17_43_export_pdf_handles_very_long_ascii_hash_fields() -> TestResult {
    let temp = TempRoot::new("43_long_hash_pdf")?;
    let mut block = sample_block(0, 1_700_000_000, 0);
    block.current_hash = "a".repeat(4096);
    block.previous_hash = "b".repeat(4096);
    block.merkle_root = "c".repeat(4096);
    block.guardian_sig = "d".repeat(8192);
    let report = AuditReport {
        blocks: vec![block],
    };
    let path = temp.path().join("audit.pdf");
    report.export_pdf(&path)?;
    assert!(fs::metadata(path)?.len() > 0);
    Ok(())
}

#[test]
fn s17_44_export_pdf_handles_invalid_signature_hex_for_fingerprint_line() -> TestResult {
    let temp = TempRoot::new("44_bad_sig_hex_pdf")?;
    let mut block = sample_block(0, 1_700_000_000, 0);
    block.guardian_sig = "not-hex-signature".to_owned();
    let report = AuditReport {
        blocks: vec![block],
    };
    let path = temp.path().join("audit.pdf");
    report.export_pdf(&path)?;
    assert!(fs::metadata(path)?.len() > 0);
    Ok(())
}

#[test]
fn s17_45_export_pdf_handles_empty_hash_strings() -> TestResult {
    let temp = TempRoot::new("45_empty_hash_pdf")?;
    let block = AuditBlock {
        index: 0,
        timestamp: 1_700_000_000,
        size: 0,
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
    let path = temp.path().join("audit.pdf");
    report.export_pdf(&path)?;
    assert!(fs::metadata(path)?.len() > 0);
    Ok(())
}

#[test]
fn s17_46_canonical_bytes_can_be_blake3_hashed() -> TestResult {
    let bytes = report_two().canonical_bytes()?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    assert_eq!(hash.len(), 64);
    Ok(())
}

#[test]
fn s17_47_pdf_bytes_can_be_blake3_hashed() -> TestResult {
    let temp = TempRoot::new("47_pdf_hash")?;
    let path = temp.path().join("audit.pdf");
    report_one().export_pdf_with_time(&path, fixed_time()?)?;
    let bytes = fs::read(path)?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    assert_eq!(hash.len(), 64);
    Ok(())
}

#[test]
fn s17_48_canonical_empty_report_is_smaller_than_pdf_empty_report() -> TestResult {
    let temp = TempRoot::new("48_json_pdf_size")?;
    let pdf_path = temp.path().join("audit.pdf");
    report_empty().export_pdf(&pdf_path)?;
    let canonical_len = report_empty().canonical_bytes()?.len();
    let pdf_len = usize::try_from(fs::metadata(pdf_path)?.len())
        .map_err(|_| boxed_error("pdf length does not fit usize"))?;
    assert!(pdf_len > canonical_len);
    Ok(())
}

#[test]
fn s17_49_load_range_missing_db_path_fails() -> TestResult {
    let temp = TempRoot::new("49_missing_db")?;
    let missing = temp.path().join("missing-db");
    let result = AuditReport::load_range_with_path(&missing, 0, 0);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn s17_50_load_range_file_path_fails() -> TestResult {
    let temp = TempRoot::new("50_file_db_path")?;
    let file_path = temp.path().join("not-db");
    fs::write(&file_path, b"not a rocksdb")?;
    let result = AuditReport::load_range_with_path(&file_path, 0, 0);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn s17_51_load_range_empty_blockchain_db_returns_empty_report() -> TestResult {
    let (_temp, _opts, path) = create_empty_blockchain_path("51_empty_db")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_52_load_range_empty_db_large_range_returns_empty_report() -> TestResult {
    let (_temp, _opts, path) = create_empty_blockchain_path("52_empty_large_range")?;
    let report = AuditReport::load_range_with_path(&path, 0, 250)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_53_load_range_start_greater_than_end_returns_empty_report() -> TestResult {
    let (_temp, _opts, path) = create_empty_blockchain_path("53_start_gt_end")?;
    let report = AuditReport::load_range_with_path(&path, 10, 1)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_54_load_range_single_genesis_block_returns_one_block() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("54_one_block")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    assert_eq!(report.blocks.len(), 1);
    Ok(())
}

#[test]
fn s17_55_load_range_nonmatching_height_returns_empty() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("55_missing_height")?;
    let report = AuditReport::load_range_with_path(&path, 1, 1)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_56_load_range_spanning_existing_and_missing_blocks_returns_existing_only() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("56_span")?;
    let report = AuditReport::load_range_with_path(&path, 0, 5)?;
    assert_eq!(report.blocks.len(), 1);
    Ok(())
}

#[test]
fn s17_57_loaded_genesis_block_has_index_zero() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("57_loaded_index")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let first = report
        .blocks
        .first()
        .ok_or_else(|| boxed_error("missing audit block"))?;
    assert_eq!(first.index, 0);
    Ok(())
}

#[test]
fn s17_58_loaded_genesis_block_has_zero_tx_count_without_batch() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("58_loaded_tx_count")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let first = report
        .blocks
        .first()
        .ok_or_else(|| boxed_error("missing audit block"))?;
    assert_eq!(first.tx_count, 0);
    Ok(())
}

#[test]
fn s17_59_loaded_genesis_block_has_no_transactions_without_batch() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("59_loaded_txs")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let first = report
        .blocks
        .first()
        .ok_or_else(|| boxed_error("missing audit block"))?;
    assert!(first.transactions.is_empty());
    Ok(())
}

#[test]
fn s17_60_loaded_genesis_hash_hex_is_128_chars() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("60_hash_len")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let first = report
        .blocks
        .first()
        .ok_or_else(|| boxed_error("missing audit block"))?;
    assert_eq!(first.current_hash.len(), 128);
    Ok(())
}

#[test]
fn s17_61_loaded_previous_hash_hex_is_128_chars() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("61_prev_len")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let first = report
        .blocks
        .first()
        .ok_or_else(|| boxed_error("missing audit block"))?;
    assert_eq!(first.previous_hash.len(), 128);
    Ok(())
}

#[test]
fn s17_62_loaded_merkle_root_hex_is_128_chars() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("62_merkle_len")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let first = report
        .blocks
        .first()
        .ok_or_else(|| boxed_error("missing audit block"))?;
    assert_eq!(first.merkle_root.len(), 128);
    Ok(())
}

#[test]
fn s17_63_loaded_guardian_sig_is_hex_string() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("63_sig_hex")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let first = report
        .blocks
        .first()
        .ok_or_else(|| boxed_error("missing audit block"))?;
    assert!(first.guardian_sig.chars().all(|c| c.is_ascii_hexdigit()));
    Ok(())
}

#[test]
fn s17_64_loaded_report_can_export_json() -> TestResult {
    let (temp, _opts, path) = create_blockchain_with_block_zero("64_loaded_export_json")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let out = temp.path().join("loaded.json");
    report.export_json(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_65_loaded_report_can_export_pdf() -> TestResult {
    let (temp, _opts, path) = create_blockchain_with_block_zero("65_loaded_export_pdf")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let out = temp.path().join("loaded.pdf");
    report.export_pdf(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_66_loaded_report_canonical_bytes_are_valid_json() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("66_loaded_canonical")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let value = canonical_json(&report)?;
    assert_eq!(value["meta"]["block_span"], 1);
    Ok(())
}

#[test]
fn s17_67_load_range_skips_invalid_block_bytes() -> TestResult {
    let (_temp, path) = create_blockchain_with_invalid_block_zero("67_invalid_block")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_68_load_range_invalid_block_then_missing_range_is_empty() -> TestResult {
    let (_temp, path) = create_blockchain_with_invalid_block_zero("68_invalid_missing_range")?;
    let report = AuditReport::load_range_with_path(&path, 0, 3)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_69_empty_db_report_can_export_json() -> TestResult {
    let (temp, _opts, path) = create_empty_blockchain_path("69_empty_db_export_json")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let out = temp.path().join("empty_loaded.json");
    report.export_json(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_70_empty_db_report_can_export_pdf() -> TestResult {
    let (temp, _opts, path) = create_empty_blockchain_path("70_empty_db_export_pdf")?;
    let report = AuditReport::load_range_with_path(&path, 0, 0)?;
    let out = temp.path().join("empty_loaded.pdf");
    report.export_pdf(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_71_vector_canonical_json_block_spans() -> TestResult {
    for count in [0usize, 1, 2, 5, 10] {
        let blocks: Vec<AuditBlock> = (0..count)
            .map(|idx| sample_block(u64::try_from(idx).unwrap_or(0), 1_700_000_000, 0))
            .collect();
        let report = AuditReport { blocks };
        let value = canonical_json(&report)?;
        assert_eq!(value["meta"]["block_span"], u64::try_from(count)?);
    }
    Ok(())
}

#[test]
fn s17_72_vector_total_tx_sums() -> TestResult {
    for counts in [vec![0u64], vec![1, 2, 3], vec![10, 20, 30, 40]] {
        let expected: u64 = counts.iter().copied().sum();
        let blocks: Vec<AuditBlock> = counts
            .iter()
            .enumerate()
            .map(|(idx, tx_count)| {
                sample_block(u64::try_from(idx).unwrap_or(0), 1_700_000_000, *tx_count)
            })
            .collect();
        let report = AuditReport { blocks };
        let value = canonical_json(&report)?;
        assert_eq!(value["meta"]["total_tx"], expected);
    }
    Ok(())
}

#[test]
fn s17_73_vector_export_json_many_reports() -> TestResult {
    let temp = TempRoot::new("73_vector_json")?;

    for idx in 0u64..8u64 {
        let report = AuditReport {
            blocks: vec![sample_block(idx, 1_700_000_000u64.saturating_add(idx), idx)],
        };
        let file_name = format!("audit-{idx}.json");
        let value = export_json_value(&report, temp.path(), &file_name)?;
        assert_eq!(value["meta"]["block_span"], 1);
    }

    Ok(())
}

#[test]
fn s17_74_vector_export_pdf_many_reports() -> TestResult {
    let temp = TempRoot::new("74_vector_pdf")?;

    for idx in 0u64..5u64 {
        let report = AuditReport {
            blocks: vec![sample_block(idx, 1_700_000_000u64.saturating_add(idx), idx)],
        };
        let path = temp.path().join(format!("audit-{idx}.pdf"));
        report.export_pdf_with_time(&path, fixed_time()?)?;
        assert!(fs::metadata(path)?.len() > 0);
    }

    Ok(())
}

#[test]
fn s17_75_vector_load_ranges_on_empty_db() -> TestResult {
    let (_temp, _opts, path) = create_empty_blockchain_path("75_vector_empty_ranges")?;

    for (start, end) in [(0u64, 0u64), (0, 10), (10, 20), (250, 500), (5, 4)] {
        let report = AuditReport::load_range_with_path(&path, start, end)?;
        assert!(report.blocks.is_empty());
    }

    Ok(())
}

#[test]
fn s17_76_vector_load_ranges_on_one_block_db() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("76_vector_one_block_ranges")?;

    for (start, end, expected) in [(0u64, 0u64, 1usize), (0, 10, 1), (1, 10, 0), (10, 1, 0)] {
        let report = AuditReport::load_range_with_path(&path, start, end)?;
        assert_eq!(report.blocks.len(), expected);
    }

    Ok(())
}

#[test]
fn s17_77_load_range_max_span_style_range_on_empty_db_returns_empty() -> TestResult {
    let (_temp, _opts, path) = create_empty_blockchain_path("77_max_span_empty")?;
    let report = AuditReport::load_range_with_path(&path, 100, 350)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_78_load_range_over_ui_max_span_still_safe_in_noninteractive_engine() -> TestResult {
    let (_temp, _opts, path) = create_empty_blockchain_path("78_over_ui_span")?;
    let report = AuditReport::load_range_with_path(&path, 0, 300)?;
    assert!(report.blocks.is_empty());
    Ok(())
}

#[test]
fn s17_79_export_json_nested_existing_directory_succeeds() -> TestResult {
    let temp = TempRoot::new("79_nested_json")?;
    let nested = temp.path().join("a").join("b").join("c");
    fs::create_dir_all(&nested)?;
    let out = nested.join("audit.json");
    report_one().export_json(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_80_export_pdf_nested_existing_directory_succeeds() -> TestResult {
    let temp = TempRoot::new("80_nested_pdf")?;
    let nested = temp.path().join("a").join("b").join("c");
    fs::create_dir_all(&nested)?;
    let out = nested.join("audit.pdf");
    report_one().export_pdf(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_81_export_json_preserves_block_order() -> TestResult {
    let report = AuditReport {
        blocks: vec![
            sample_block(3, 1_700_000_003, 0),
            sample_block(1, 1_700_000_001, 0),
            sample_block(2, 1_700_000_002, 0),
        ],
    };
    let value = canonical_json(&report)?;
    assert_eq!(value["blocks"][0]["index"], 3);
    assert_eq!(value["blocks"][1]["index"], 1);
    assert_eq!(value["blocks"][2]["index"], 2);
    Ok(())
}

#[test]
fn s17_82_canonical_json_uses_first_block_timestamp_even_if_unsorted() -> TestResult {
    let report = AuditReport {
        blocks: vec![
            sample_block(9, 1_700_000_900, 0),
            sample_block(1, 1_700_000_001, 0),
        ],
    };
    let value = canonical_json(&report)?;
    assert_eq!(value["meta"]["report_time"], 1_700_000_900);
    Ok(())
}

#[test]
fn s17_83_export_json_handles_zero_size_block() -> TestResult {
    let temp = TempRoot::new("83_zero_size")?;
    let mut block = sample_block(0, 1_700_000_000, 0);
    block.size = 0;
    let report = AuditReport {
        blocks: vec![block],
    };
    let value = export_json_value(&report, temp.path(), "audit.json")?;
    assert_eq!(value["blocks"][0]["size"], 0);
    Ok(())
}

#[test]
fn s17_84_export_json_handles_u64_max_size_block() -> TestResult {
    let temp = TempRoot::new("84_max_size")?;
    let mut block = sample_block(0, 1_700_000_000, 0);
    block.size = u64::MAX;
    let report = AuditReport {
        blocks: vec![block],
    };
    let value = export_json_value(&report, temp.path(), "audit.json")?;
    assert_eq!(value["blocks"][0]["size"], Value::from(u64::MAX));
    Ok(())
}

#[test]
fn s17_85_export_json_handles_u64_max_tx_count() -> TestResult {
    let temp = TempRoot::new("85_max_tx_count")?;
    let block = sample_block(0, 1_700_000_000, u64::MAX);
    let report = AuditReport {
        blocks: vec![block],
    };
    let value = export_json_value(&report, temp.path(), "audit.json")?;
    assert_eq!(value["meta"]["total_tx"], Value::from(u64::MAX));
    Ok(())
}

#[test]
fn s17_86_canonical_bytes_saturating_total_tx_can_panic_on_overflow_is_not_triggered_by_safe_vector()
-> TestResult {
    let report = AuditReport {
        blocks: vec![
            sample_block(0, 1_700_000_000, 1),
            sample_block(1, 1_700_000_001, 2),
            sample_block(2, 1_700_000_002, 3),
        ],
    };
    let value = canonical_json(&report)?;
    assert_eq!(value["meta"]["total_tx"], 6);
    Ok(())
}

#[test]
fn s17_87_pdf_export_with_many_transactions_in_block_succeeds() -> TestResult {
    let temp = TempRoot::new("87_many_txs_pdf")?;
    let mut block = sample_block(0, 1_700_000_000, 100);
    block.transactions = (0u64..100u64)
        .map(|amount| sample_tx("transfer", Some(amount)))
        .collect();
    let report = AuditReport {
        blocks: vec![block],
    };
    let out = temp.path().join("many-txs.pdf");
    report.export_pdf(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_88_json_export_with_many_transactions_preserves_array_len() -> TestResult {
    let temp = TempRoot::new("88_many_txs_json")?;
    let mut block = sample_block(0, 1_700_000_000, 25);
    block.transactions = (0u64..25u64)
        .map(|amount| sample_tx("transfer", Some(amount)))
        .collect();
    let report = AuditReport {
        blocks: vec![block],
    };
    let value = export_json_value(&report, temp.path(), "many-txs.json")?;
    assert_eq!(
        value["blocks"][0]["transactions"]
            .as_array()
            .map_or(usize::MAX, Vec::len),
        25
    );
    Ok(())
}

#[test]
fn s17_89_pdf_export_zero_timestamp_block_succeeds() -> TestResult {
    let temp = TempRoot::new("89_zero_ts_pdf")?;
    let report = AuditReport {
        blocks: vec![sample_block(0, 0, 0)],
    };
    let out = temp.path().join("zero-ts.pdf");
    report.export_pdf(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_90_json_export_zero_timestamp_block_sets_report_time_zero() -> TestResult {
    let temp = TempRoot::new("90_zero_ts_json")?;
    let report = AuditReport {
        blocks: vec![sample_block(0, 0, 0)],
    };
    let value = export_json_value(&report, temp.path(), "zero-ts.json")?;
    assert_eq!(value["meta"]["report_time"], 0);
    Ok(())
}

#[test]
fn s17_91_loaded_empty_db_canonical_hash_is_stable() -> TestResult {
    let (_temp, _opts, path) = create_empty_blockchain_path("91_empty_db_hash_stable")?;
    let first = AuditReport::load_range_with_path(&path, 0, 0)?.canonical_bytes()?;
    let second = AuditReport::load_range_with_path(&path, 0, 0)?.canonical_bytes()?;
    assert_eq!(blake3::hash(&first), blake3::hash(&second));
    Ok(())
}

#[test]
fn s17_92_loaded_one_block_canonical_hash_is_stable() -> TestResult {
    let (_temp, _opts, path) = create_blockchain_with_block_zero("92_one_block_hash_stable")?;
    let first = AuditReport::load_range_with_path(&path, 0, 0)?.canonical_bytes()?;
    let second = AuditReport::load_range_with_path(&path, 0, 0)?.canonical_bytes()?;
    assert_eq!(blake3::hash(&first), blake3::hash(&second));
    Ok(())
}

#[test]
fn s17_93_repeated_json_export_overwrites_and_remains_valid() -> TestResult {
    let temp = TempRoot::new("93_repeat_json")?;
    let out = temp.path().join("audit.json");

    for _ in 0..5 {
        report_two().export_json(&out)?;
        let value = serde_json::from_slice::<Value>(&fs::read(&out)?)?;
        assert_eq!(value["meta"]["block_span"], 2);
    }

    Ok(())
}

#[test]
fn s17_94_repeated_pdf_export_overwrites_and_remains_pdf() -> TestResult {
    let temp = TempRoot::new("94_repeat_pdf")?;
    let out = temp.path().join("audit.pdf");

    for _ in 0..3 {
        report_two().export_pdf_with_time(&out, fixed_time()?)?;
        let bytes = fs::read(&out)?;
        assert!(bytes.starts_with(b"%PDF"));
    }

    Ok(())
}

#[test]
fn s17_95_load_test_canonical_json_for_200_blocks() -> TestResult {
    let blocks: Vec<AuditBlock> = (0u64..200u64)
        .map(|idx| sample_block(idx, 1_700_000_000u64.saturating_add(idx), idx % 5))
        .collect();
    let report = AuditReport { blocks };
    let value = canonical_json(&report)?;
    assert_eq!(value["meta"]["block_span"], 200);
    Ok(())
}

#[test]
fn s17_96_load_test_export_json_for_200_blocks() -> TestResult {
    let temp = TempRoot::new("96_200_blocks_json")?;
    let blocks: Vec<AuditBlock> = (0u64..200u64)
        .map(|idx| sample_block(idx, 1_700_000_000u64.saturating_add(idx), idx % 5))
        .collect();
    let report = AuditReport { blocks };
    let value = export_json_value(&report, temp.path(), "audit.json")?;
    assert_eq!(value["meta"]["block_span"], 200);
    Ok(())
}

#[test]
fn s17_97_load_test_export_pdf_for_120_blocks() -> TestResult {
    let temp = TempRoot::new("97_120_blocks_pdf")?;
    let blocks: Vec<AuditBlock> = (0u64..120u64)
        .map(|idx| sample_block(idx, 1_700_000_000u64.saturating_add(idx), idx % 5))
        .collect();
    let report = AuditReport { blocks };
    let out = temp.path().join("audit.pdf");
    report.export_pdf_with_time(&out, fixed_time()?)?;
    assert!(fs::metadata(out)?.len() > 0);
    Ok(())
}

#[test]
fn s17_98_adversarial_non_hex_hash_strings_still_export_json() -> TestResult {
    let temp = TempRoot::new("98_non_hex_json")?;
    let block = AuditBlock {
        index: 0,
        timestamp: 1_700_000_000,
        size: 1,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: "not_hex_current".to_owned(),
        previous_hash: "not_hex_previous".to_owned(),
        merkle_root: "not_hex_merkle".to_owned(),
        guardian_sig: "not_hex_sig".to_owned(),
    };
    let report = AuditReport {
        blocks: vec![block],
    };
    let value = export_json_value(&report, temp.path(), "audit.json")?;
    assert_eq!(value["blocks"][0]["current_hash"], "not_hex_current");
    Ok(())
}

#[test]
fn s17_99_adversarial_non_hex_hash_strings_still_export_pdf() -> TestResult {
    let temp = TempRoot::new("99_non_hex_pdf")?;
    let block = AuditBlock {
        index: 0,
        timestamp: 1_700_000_000,
        size: 1,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: "not_hex_current".to_owned(),
        previous_hash: "not_hex_previous".to_owned(),
        merkle_root: "not_hex_merkle".to_owned(),
        guardian_sig: "not_hex_sig".to_owned(),
    };
    let report = AuditReport {
        blocks: vec![block],
    };
    let out = temp.path().join("audit.pdf");
    report.export_pdf(&out)?;
    assert!(out.is_file());
    Ok(())
}

#[test]
fn s17_100_full_noninteractive_audit_pipeline_smoke_test() -> TestResult {
    let (temp, _opts, db_path) = create_blockchain_with_block_zero("100_pipeline")?;
    let report = AuditReport::load_range_with_path(&db_path, 0, 250)?;
    assert_eq!(report.blocks.len(), 1);

    let canonical = report.canonical_bytes()?;
    assert!(!canonical.is_empty());

    let json_path = temp.path().join("audit_report.json");
    report.export_json(&json_path)?;
    assert!(json_path.is_file());

    let pdf_path = temp.path().join("audit_report.pdf");
    report.export_pdf_with_time(&pdf_path, fixed_time()?)?;
    assert!(pdf_path.is_file());
    assert!(fs::read(pdf_path)?.starts_with(b"%PDF"));

    Ok(())
}
