// tests/proptests_audit_report_001_hub.rs

use proptest::prelude::*;
use proptest::string::string_regex;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::utility::audit_report_001_hub::{AuditBlock, AuditReport, AuditTransaction};

use chrono::{TimeZone, Utc};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
struct TxSpec {
    kind: String,
    sender: Option<String>,
    receiver: Option<String>,
    amount: Option<u64>,
}

#[derive(Debug, Clone)]
struct BlockSpec {
    index: u64,
    timestamp: u64,
    size: u64,
    tx_count: u64,
    transactions: Vec<TxSpec>,
    current_hash: String,
    previous_hash: String,
    merkle_root: String,
    guardian_sig: String,
}

fn temp_dir(label: &str) -> Result<PathBuf, String> {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e:?}"))?
        .as_nanos();

    let safe_label = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();

    let path = std::env::temp_dir().join(format!(
        "remzar_audit_report_hub_prop_tests_{}_{}_{}_{}",
        std::process::id(),
        nanos,
        counter,
        safe_label
    ));

    if path.exists() {
        fs::remove_dir_all(&path)
            .map_err(|e| format!("failed to remove stale temp dir {}: {e}", path.display()))?;
    }

    fs::create_dir_all(&path)
        .map_err(|e| format!("failed to create temp dir {}: {e}", path.display()))?;

    Ok(path)
}

fn assert_pdf(bytes: &[u8]) -> Result<(), TestCaseError> {
    prop_assert!(bytes.len() > 4);
    prop_assert_eq!(&bytes[..4], b"%PDF");
    Ok(())
}

fn hex_128() -> BoxedStrategy<String> {
    string_regex("[0-9a-f]{128}")
        .expect("valid 128 lowercase hex regex")
        .boxed()
}

fn hex_var_0_512() -> BoxedStrategy<String> {
    string_regex("[0-9a-f]{0,512}")
        .expect("valid variable hex regex")
        .boxed()
}

fn safe_ascii_0_32() -> BoxedStrategy<String> {
    string_regex("[A-Za-z0-9_.:\\-]{0,32}")
        .expect("valid safe ascii regex")
        .boxed()
}

fn safe_dir_leaf() -> BoxedStrategy<String> {
    string_regex("[A-Za-z0-9_-]{1,32}")
        .expect("valid safe dir leaf regex")
        .boxed()
}

fn tx_kind_name() -> BoxedStrategy<String> {
    prop_oneof![
        Just("transfer".to_string()),
        Just("reward".to_string()),
        Just("register_node".to_string()),
        Just("nft_mint".to_string()),
        Just("nft_transfer".to_string()),
        Just("unknown_test_kind".to_string()),
    ]
    .boxed()
}

fn opt_text() -> BoxedStrategy<Option<String>> {
    prop_oneof![Just(None), safe_ascii_0_32().prop_map(Some),].boxed()
}

fn opt_amount() -> BoxedStrategy<Option<u64>> {
    prop_oneof![Just(None), (0u64..1_000_000_000u64).prop_map(Some),].boxed()
}

fn tx_spec_strategy() -> BoxedStrategy<TxSpec> {
    (tx_kind_name(), opt_text(), opt_text(), opt_amount())
        .prop_map(|(kind, sender, receiver, amount)| TxSpec {
            kind,
            sender,
            receiver,
            amount,
        })
        .boxed()
}

fn block_spec_strategy() -> BoxedStrategy<BlockSpec> {
    (
        0u64..100_000u64,
        0u64..4_102_444_800u64,
        0u64..10_000_000u64,
        0u64..100_000u64,
        proptest::collection::vec(tx_spec_strategy(), 0..8),
        hex_128(),
        hex_128(),
        hex_128(),
        hex_var_0_512(),
    )
        .prop_map(
            |(
                index,
                timestamp,
                size,
                tx_count,
                transactions,
                current_hash,
                previous_hash,
                merkle_root,
                guardian_sig,
            )| BlockSpec {
                index,
                timestamp,
                size,
                tx_count,
                transactions,
                current_hash,
                previous_hash,
                merkle_root,
                guardian_sig,
            },
        )
        .boxed()
}

fn block_specs_small() -> BoxedStrategy<Vec<BlockSpec>> {
    proptest::collection::vec(block_spec_strategy(), 0..8).boxed()
}

fn tx_from_spec(spec: TxSpec) -> AuditTransaction {
    AuditTransaction {
        kind: spec.kind,
        sender: spec.sender,
        receiver: spec.receiver,
        amount: spec.amount,
    }
}

fn block_from_spec(spec: BlockSpec) -> AuditBlock {
    AuditBlock {
        index: spec.index,
        timestamp: spec.timestamp,
        size: spec.size,
        tx_count: spec.tx_count,
        transactions: spec.transactions.into_iter().map(tx_from_spec).collect(),
        current_hash: spec.current_hash,
        previous_hash: spec.previous_hash,
        merkle_root: spec.merkle_root,
        guardian_sig: spec.guardian_sig,
    }
}

fn report_from_specs(specs: Vec<BlockSpec>) -> AuditReport {
    AuditReport {
        blocks: specs.into_iter().map(block_from_spec).collect(),
    }
}

fn parse_canonical_json(report: &AuditReport) -> Result<Value, TestCaseError> {
    let bytes = report
        .canonical_bytes()
        .map_err(|e| TestCaseError::fail(format!("canonical_bytes failed: {e:?}")))?;

    serde_json::from_slice(&bytes)
        .map_err(|e| TestCaseError::fail(format!("canonical JSON decode failed: {e}")))
}

fn total_tx_from_specs(specs: &[BlockSpec]) -> u64 {
    specs.iter().map(|b| b.tx_count).sum()
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn audit_hub_prop_001_empty_report_canonical_json_has_zero_meta(_case in any::<u8>()) {
        let report = AuditReport { blocks: Vec::new() };
        let value = parse_canonical_json(&report)?;

        prop_assert_eq!(value["meta"]["block_span"].as_u64(), Some(0));
        prop_assert_eq!(value["meta"]["total_tx"].as_u64(), Some(0));
        prop_assert_eq!(value["meta"]["report_time"].as_i64(), Some(0));
        prop_assert_eq!(value["meta"]["export_time"].as_i64(), Some(0));
        prop_assert_eq!(value["blocks"].as_array().map(|a| a.len()), Some(0));
    }

    // 02/25
    #[test]
    fn audit_hub_prop_002_canonical_bytes_are_deterministic_for_same_report(
        specs in block_specs_small()
    ) {
        let report = report_from_specs(specs);

        let first = report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("first canonical_bytes failed: {e:?}")))?;
        let second = report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("second canonical_bytes failed: {e:?}")))?;

        prop_assert_eq!(&first, &second);
    }

    // 03/25
    #[test]
    fn audit_hub_prop_003_canonical_bytes_change_when_block_hash_changes(
        mut spec in block_spec_strategy(),
        replacement_hash in hex_128(),
    ) {
        prop_assume!(spec.current_hash != replacement_hash);

        let original_report = report_from_specs(vec![spec.clone()]);
        let original_bytes = original_report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("original canonical_bytes failed: {e:?}")))?;

        spec.current_hash = replacement_hash;

        let changed_report = report_from_specs(vec![spec]);
        let changed_bytes = changed_report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("changed canonical_bytes failed: {e:?}")))?;

        prop_assert_ne!(&original_bytes, &changed_bytes);
    }

    // 04/25
    #[test]
    fn audit_hub_prop_004_meta_block_span_matches_number_of_blocks(
        specs in block_specs_small()
    ) {
        let expected_len = specs.len() as u64;
        let report = report_from_specs(specs);
        let value = parse_canonical_json(&report)?;

        prop_assert_eq!(value["meta"]["block_span"].as_u64(), Some(expected_len));
        prop_assert_eq!(
            value["blocks"].as_array().map(|a| a.len() as u64),
            Some(expected_len)
        );
    }

    // 05/25
    #[test]
    fn audit_hub_prop_005_meta_total_tx_is_sum_of_block_tx_count(
        specs in block_specs_small()
    ) {
        let expected_total = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);
        let value = parse_canonical_json(&report)?;

        prop_assert_eq!(value["meta"]["total_tx"].as_u64(), Some(expected_total));
    }

    // 06/25
    #[test]
    fn audit_hub_prop_006_canonical_report_time_and_export_time_use_first_block_timestamp(
        specs in proptest::collection::vec(block_spec_strategy(), 1..8)
    ) {
        let expected_ts = specs[0].timestamp as i64;
        let report = report_from_specs(specs);
        let value = parse_canonical_json(&report)?;

        prop_assert_eq!(value["meta"]["report_time"].as_i64(), Some(expected_ts));
        prop_assert_eq!(value["meta"]["export_time"].as_i64(), Some(expected_ts));
    }

    // 07/25
    #[test]
    fn audit_hub_prop_007_block_order_is_preserved_in_canonical_json(
        specs in proptest::collection::vec(block_spec_strategy(), 1..8)
    ) {
        let expected_indexes = specs.iter().map(|b| b.index).collect::<Vec<_>>();
        let report = report_from_specs(specs);
        let value = parse_canonical_json(&report)?;

        let blocks = value["blocks"]
            .as_array()
            .ok_or_else(|| TestCaseError::fail("blocks must be JSON array"))?;

        let actual_indexes = blocks
            .iter()
            .map(|b| b["index"].as_u64().unwrap_or(u64::MAX))
            .collect::<Vec<_>>();

        prop_assert_eq!(&actual_indexes, &expected_indexes);
    }

    // 08/25
    #[test]
    fn audit_hub_prop_008_transactions_are_serialized_under_their_blocks(
        mut spec in block_spec_strategy(),
        txs in proptest::collection::vec(tx_spec_strategy(), 1..8),
    ) {
        spec.transactions = txs.clone();
        spec.tx_count = txs.len() as u64;

        let report = report_from_specs(vec![spec]);
        let value = parse_canonical_json(&report)?;

        let transactions = value["blocks"][0]["transactions"]
            .as_array()
            .ok_or_else(|| TestCaseError::fail("transactions must be JSON array"))?;

        prop_assert_eq!(transactions.len(), txs.len());

        for (json_tx, expected_tx) in transactions.iter().zip(txs.iter()) {
            prop_assert_eq!(
                json_tx["kind"].as_str(),
                Some(expected_tx.kind.as_str())
            );
        }
    }

    // 09/25
    #[test]
    fn audit_hub_prop_009_json_uses_expected_snake_case_block_keys(
        spec in block_spec_strategy()
    ) {
        let report = report_from_specs(vec![spec]);
        let value = parse_canonical_json(&report)?;

        let block = value["blocks"][0]
            .as_object()
            .ok_or_else(|| TestCaseError::fail("block must be JSON object"))?;

        for key in [
            "index",
            "timestamp",
            "size",
            "tx_count",
            "transactions",
            "current_hash",
            "previous_hash",
            "merkle_root",
            "guardian_sig",
        ] {
            prop_assert!(block.contains_key(key), "missing expected key {key}");
        }

        prop_assert!(!block.contains_key("txCount"));
        prop_assert!(!block.contains_key("currentHash"));
        prop_assert!(!block.contains_key("previousHash"));
        prop_assert!(!block.contains_key("merkleRoot"));
        prop_assert!(!block.contains_key("guardianSig"));
    }

    // 10/25
    #[test]
    fn audit_hub_prop_010_hash_string_fields_are_preserved_exactly(
        spec in block_spec_strategy()
    ) {
        let expected_current = spec.current_hash.clone();
        let expected_previous = spec.previous_hash.clone();
        let expected_merkle = spec.merkle_root.clone();
        let expected_sig = spec.guardian_sig.clone();

        let report = report_from_specs(vec![spec]);
        let value = parse_canonical_json(&report)?;

        prop_assert_eq!(value["blocks"][0]["current_hash"].as_str(), Some(expected_current.as_str()));
        prop_assert_eq!(value["blocks"][0]["previous_hash"].as_str(), Some(expected_previous.as_str()));
        prop_assert_eq!(value["blocks"][0]["merkle_root"].as_str(), Some(expected_merkle.as_str()));
        prop_assert_eq!(value["blocks"][0]["guardian_sig"].as_str(), Some(expected_sig.as_str()));
    }

    // 11/25
    #[test]
    fn audit_hub_prop_011_transaction_optional_fields_roundtrip_through_json(
        kind in tx_kind_name(),
        sender in opt_text(),
        receiver in opt_text(),
        amount in opt_amount(),
    ) {
        let tx = TxSpec {
            kind: kind.clone(),
            sender: sender.clone(),
            receiver: receiver.clone(),
            amount,
        };

        let mut spec = BlockSpec {
            index: 1,
            timestamp: 123,
            size: 456,
            tx_count: 1,
            transactions: vec![tx],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        spec.tx_count = spec.transactions.len() as u64;

        let report = report_from_specs(vec![spec]);
        let value = parse_canonical_json(&report)?;
        let json_tx = &value["blocks"][0]["transactions"][0];

        prop_assert_eq!(json_tx["kind"].as_str(), Some(kind.as_str()));

        match sender {
            Some(s) => prop_assert_eq!(json_tx["sender"].as_str(), Some(s.as_str())),
            None => prop_assert!(json_tx["sender"].is_null()),
        }

        match receiver {
            Some(r) => prop_assert_eq!(json_tx["receiver"].as_str(), Some(r.as_str())),
            None => prop_assert!(json_tx["receiver"].is_null()),
        }

        match amount {
            Some(a) => prop_assert_eq!(json_tx["amount"].as_u64(), Some(a)),
            None => prop_assert!(json_tx["amount"].is_null()),
        }
    }

    // 12/25
    #[test]
    fn audit_hub_prop_012_canonical_json_is_pretty_printed_with_four_space_indent(
        specs in block_specs_small()
    ) {
        let report = report_from_specs(specs);
        let bytes = report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("canonical_bytes failed: {e:?}")))?;

        let text = String::from_utf8(bytes)
            .map_err(|e| TestCaseError::fail(format!("canonical JSON is not UTF-8: {e}")))?;

        prop_assert_eq!(text.chars().next(), Some('{'));
        prop_assert!(text.contains('\n'));
        prop_assert!(
            text.contains("\n    \"meta\"") || text.contains("\n    \"blocks\""),
            "canonical JSON should use 4-space pretty indentation"
        );
    }

    // 13/25
    #[test]
    fn audit_hub_prop_013_canonical_bytes_are_valid_json_for_generated_reports(
        specs in block_specs_small()
    ) {
        let report = report_from_specs(specs);
        let bytes = report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("canonical_bytes failed: {e:?}")))?;

        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| TestCaseError::fail(format!("canonical bytes decode failed: {e}")))?;

        prop_assert!(value.get("meta").is_some());
        prop_assert!(value.get("blocks").is_some());
    }

    // 14/25
    #[test]
    fn audit_hub_prop_014_export_json_creates_valid_json_file(
        specs in block_specs_small(),
        leaf in safe_dir_leaf(),
    ) {
        let root = temp_dir("export-json")
            .map_err(TestCaseError::fail)?;
        let path = root.join(format!("{leaf}.json"));

        let expected_total = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        report
            .export_json(&path)
            .map_err(|e| TestCaseError::fail(format!("export_json failed: {e:?}")))?;

        prop_assert!(path.exists());

        let bytes = fs::read(&path)
            .map_err(|e| TestCaseError::fail(format!("read exported json failed: {e}")))?;

        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| TestCaseError::fail(format!("exported JSON decode failed: {e}")))?;

        prop_assert_eq!(value["meta"]["total_tx"].as_u64(), Some(expected_total));
        prop_assert!(value["blocks"].is_array());
    }

    // 15/25
    #[test]
    fn audit_hub_prop_015_export_json_overwrites_existing_file(
        specs in block_specs_small(),
        stale in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let root = temp_dir("export-json-overwrite")
            .map_err(TestCaseError::fail)?;
        let path = root.join("audit.json");

        fs::write(&path, stale)
            .map_err(|e| TestCaseError::fail(format!("write stale file failed: {e}")))?;

        let report = report_from_specs(specs);

        report
            .export_json(&path)
            .map_err(|e| TestCaseError::fail(format!("export_json failed: {e:?}")))?;

        let bytes = fs::read(&path)
            .map_err(|e| TestCaseError::fail(format!("read overwritten json failed: {e}")))?;

        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| TestCaseError::fail(format!("overwritten JSON decode failed: {e}")))?;

        prop_assert!(value.get("meta").is_some());
        prop_assert!(value.get("blocks").is_some());
    }

    // 16/25
    #[test]
    fn audit_hub_prop_016_export_json_rejects_directory_path(
        specs in block_specs_small(),
    ) {
        let root = temp_dir("export-json-dir-path")
            .map_err(TestCaseError::fail)?;
        let report = report_from_specs(specs);

        prop_assert!(
            report.export_json(&root).is_err(),
            "export_json must reject a directory path as the output file"
        );
    }

    // 17/25
    #[test]
    fn audit_hub_prop_017_export_pdf_with_time_creates_pdf_file(
        specs in block_specs_small(),
        leaf in safe_dir_leaf(),
    ) {
        let root = temp_dir("export-pdf")
            .map_err(TestCaseError::fail)?;
        let path = root.join(format!("{leaf}.pdf"));

        let report = report_from_specs(specs);
        let snapshot_ts = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .ok_or_else(|| TestCaseError::fail("failed to build snapshot timestamp"))?;

        report
            .export_pdf_with_time(&path, snapshot_ts)
            .map_err(|e| TestCaseError::fail(format!("export_pdf_with_time failed: {e:?}")))?;

        prop_assert!(path.exists());

        let bytes = fs::read(&path)
            .map_err(|e| TestCaseError::fail(format!("read exported pdf failed: {e}")))?;
        assert_pdf(&bytes)?;
    }

    // 18/25
    #[test]
    fn audit_hub_prop_018_export_pdf_with_time_overwrites_existing_file(
        specs in block_specs_small(),
        stale in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let root = temp_dir("export-pdf-overwrite")
            .map_err(TestCaseError::fail)?;
        let path = root.join("audit.pdf");

        fs::write(&path, stale)
            .map_err(|e| TestCaseError::fail(format!("write stale pdf failed: {e}")))?;

        let report = report_from_specs(specs);
        let snapshot_ts = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .ok_or_else(|| TestCaseError::fail("failed to build snapshot timestamp"))?;

        report
            .export_pdf_with_time(&path, snapshot_ts)
            .map_err(|e| TestCaseError::fail(format!("export_pdf_with_time failed: {e:?}")))?;

        let bytes = fs::read(&path)
            .map_err(|e| TestCaseError::fail(format!("read overwritten pdf failed: {e}")))?;

        assert_pdf(&bytes)?;
    }

    // 19/25
    #[test]
    fn audit_hub_prop_019_export_pdf_with_time_rejects_directory_path(
        specs in block_specs_small(),
    ) {
        let root = temp_dir("export-pdf-dir-path")
            .map_err(TestCaseError::fail)?;
        let report = report_from_specs(specs);
        let snapshot_ts = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .ok_or_else(|| TestCaseError::fail("failed to build snapshot timestamp"))?;

        prop_assert!(
            report.export_pdf_with_time(&root, snapshot_ts).is_err(),
            "export_pdf_with_time must reject a directory path as the output file"
        );
    }

    // 20/25
    #[test]
    fn audit_hub_prop_020_export_pdf_default_creates_pdf_file(
        specs in block_specs_small(),
        leaf in safe_dir_leaf(),
    ) {
        let root = temp_dir("export-pdf-default")
            .map_err(TestCaseError::fail)?;
        let path = root.join(format!("{leaf}.pdf"));

        let report = report_from_specs(specs);

        report
            .export_pdf(&path)
            .map_err(|e| TestCaseError::fail(format!("export_pdf failed: {e:?}")))?;

        let bytes = fs::read(&path)
            .map_err(|e| TestCaseError::fail(format!("read exported pdf failed: {e}")))?;

        assert_pdf(&bytes)?;
    }

    // 21/25
    #[test]
    fn audit_hub_prop_021_canonical_data_hash_is_stable_for_same_report(
        specs in block_specs_small()
    ) {
        let report = report_from_specs(specs);

        let first = report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("first canonical_bytes failed: {e:?}")))?;
        let second = report
            .canonical_bytes()
            .map_err(|e| TestCaseError::fail(format!("second canonical_bytes failed: {e:?}")))?;

        let first_hash = blake3::hash(&first).to_hex().to_string();
        let second_hash = blake3::hash(&second).to_hex().to_string();

        prop_assert_eq!(&first_hash, &second_hash);
        prop_assert_eq!(first_hash.len(), 64);
    }

    // 22/25
    #[test]
    fn audit_hub_prop_022_load_range_with_path_rejects_missing_database_path(
        leaf in safe_dir_leaf(),
        start in 0u64..10u64,
        len in 0u64..10u64,
    ) {
        let root = temp_dir("missing-db-root")
            .map_err(TestCaseError::fail)?;
        let missing_path = root.join(leaf);
        let end = start.saturating_add(len);

        prop_assert!(
            AuditReport::load_range_with_path(&missing_path, start, end).is_err(),
            "missing RocksDB path must return an error"
        );
    }

    // 23/25
    #[test]
    fn audit_hub_prop_023_load_range_with_path_rejects_regular_file_path(
        contents in proptest::collection::vec(any::<u8>(), 1..256),
        start in 0u64..10u64,
        len in 0u64..10u64,
    ) {
        let root = temp_dir("file-db-root")
            .map_err(TestCaseError::fail)?;
        let file_path = root.join("not_a_rocksdb");
        fs::write(&file_path, contents)
            .map_err(|e| TestCaseError::fail(format!("write fake db file failed: {e}")))?;

        let end = start.saturating_add(len);

        prop_assert!(
            AuditReport::load_range_with_path(&file_path, start, end).is_err(),
            "regular file path must not open as blockchain RocksDB"
        );
    }

    // 24/25
    #[test]
    fn audit_hub_prop_024_first_timestamp_above_i64_max_is_capped_to_i64_max(
        high_timestamp in (i64::MAX as u64)..u64::MAX,
    ) {
        let spec = BlockSpec {
            index: 1,
            timestamp: high_timestamp,
            size: 1,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let report = report_from_specs(vec![spec]);
        let value = parse_canonical_json(&report)?;

        prop_assert_eq!(value["meta"]["report_time"].as_i64(), Some(i64::MAX));
        prop_assert_eq!(value["meta"]["export_time"].as_i64(), Some(i64::MAX));
    }

    // 25/25
    #[test]
    fn audit_hub_prop_025_full_report_json_and_pdf_exports_can_be_created_together(
        specs in block_specs_small(),
        json_leaf in safe_dir_leaf(),
        pdf_leaf in safe_dir_leaf(),
    ) {
        let root = temp_dir("json-and-pdf-export")
            .map_err(TestCaseError::fail)?;

        let json_path = root.join(format!("{json_leaf}.json"));
        let pdf_path = root.join(format!("{pdf_leaf}.pdf"));

        let expected_total = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        report
            .export_json(&json_path)
            .map_err(|e| TestCaseError::fail(format!("export_json failed: {e:?}")))?;

        let snapshot_ts = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .ok_or_else(|| TestCaseError::fail("failed to build snapshot timestamp"))?;

        report
            .export_pdf_with_time(&pdf_path, snapshot_ts)
            .map_err(|e| TestCaseError::fail(format!("export_pdf_with_time failed: {e:?}")))?;

        prop_assert!(json_path.exists());
        prop_assert!(pdf_path.exists());

        let json_bytes = fs::read(&json_path)
            .map_err(|e| TestCaseError::fail(format!("read json failed: {e}")))?;
        let pdf_bytes = fs::read(&pdf_path)
            .map_err(|e| TestCaseError::fail(format!("read pdf failed: {e}")))?;

        let value: Value = serde_json::from_slice(&json_bytes)
            .map_err(|e| TestCaseError::fail(format!("exported JSON decode failed: {e}")))?;

        prop_assert_eq!(value["meta"]["total_tx"].as_u64(), Some(expected_total));
        assert_pdf(&pdf_bytes)?;
    }
}
