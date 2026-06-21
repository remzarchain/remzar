use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::audit_report_001_hub::{AuditBlock, AuditReport, AuditTransaction};
use remzar::utility::audit_report_003_json::build_json;
use serde_json::Value;

type TestResult = Result<(), String>;

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
        size: 1_024_u64.saturating_add(index),
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

fn json_bytes(report: &AuditReport, total_tx: u64, export_time: i64) -> Result<Vec<u8>, String> {
    build_json(report, total_tx, export_time).map_err(|e| e.to_string())
}

fn json_value(report: &AuditReport, total_tx: u64, export_time: i64) -> Result<Value, String> {
    let bytes = json_bytes(report, total_tx, export_time)?;
    serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())
}

fn json_text(report: &AuditReport, total_tx: u64, export_time: i64) -> Result<String, String> {
    let bytes = json_bytes(report, total_tx, export_time)?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn meta<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    value
        .get("meta")
        .and_then(|m| m.get(key))
        .ok_or_else(|| format!("missing meta.{key}"))
}

fn blocks(value: &Value) -> Result<&Vec<Value>, String> {
    value
        .get("blocks")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing blocks array".to_string())
}

#[test]
fn audit_json_001_empty_report_builds_valid_json_object() -> TestResult {
    let value = json_value(&empty_report(), 0, 123)?;

    assert!(value.is_object());
    assert!(value.get("meta").is_some());
    assert!(value.get("blocks").is_some());
    Ok(())
}

#[test]
fn audit_json_002_empty_report_has_zero_meta_vectors() -> TestResult {
    let value = json_value(&empty_report(), 0, 999)?;

    assert_eq!(meta(&value, "chain_id")?, GlobalConfiguration::COIN_NAME);
    assert_eq!(
        meta(&value, "guardian_id")?,
        GlobalConfiguration::GENESIS_VALIDATOR
    );
    assert_eq!(meta(&value, "report_time")?, 0);
    assert_eq!(meta(&value, "export_time")?, 999);
    assert_eq!(meta(&value, "block_span")?, 0);
    assert_eq!(meta(&value, "total_tx")?, 0);
    assert!(blocks(&value)?.is_empty());
    Ok(())
}

#[test]
fn audit_json_003_sample_report_meta_uses_first_block_timestamp() -> TestResult {
    let value = json_value(&sample_report(), 1, 1_700_000_100)?;

    assert_eq!(meta(&value, "report_time")?, 1_700_000_000_i64);
    assert_eq!(meta(&value, "export_time")?, 1_700_000_100_i64);
    assert_eq!(meta(&value, "block_span")?, 1);
    assert_eq!(meta(&value, "total_tx")?, 1);
    Ok(())
}

#[test]
fn audit_json_004_two_block_report_meta_uses_first_not_last_timestamp() -> TestResult {
    let value = json_value(&two_block_report(), 5, 44)?;

    assert_eq!(meta(&value, "report_time")?, 1_111_i64);
    assert_eq!(meta(&value, "export_time")?, 44_i64);
    assert_eq!(meta(&value, "block_span")?, 2);
    assert_eq!(meta(&value, "total_tx")?, 5);
    Ok(())
}

#[test]
fn audit_json_005_chain_id_matches_global_coin_name() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;

    assert_eq!(meta(&value, "chain_id")?, GlobalConfiguration::COIN_NAME);
    Ok(())
}

#[test]
fn audit_json_006_guardian_id_matches_global_genesis_validator() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;

    assert_eq!(
        meta(&value, "guardian_id")?,
        GlobalConfiguration::GENESIS_VALIDATOR
    );
    Ok(())
}

#[test]
fn audit_json_007_export_time_preserves_negative_i64_vector() -> TestResult {
    let value = json_value(&sample_report(), 1, -123)?;

    assert_eq!(meta(&value, "export_time")?, -123);
    Ok(())
}

#[test]
fn audit_json_008_export_time_preserves_i64_max_vector() -> TestResult {
    let value = json_value(&sample_report(), 1, i64::MAX)?;

    assert_eq!(meta(&value, "export_time")?, i64::MAX);
    Ok(())
}

#[test]
fn audit_json_009_export_time_preserves_i64_min_vector() -> TestResult {
    let value = json_value(&sample_report(), 1, i64::MIN)?;

    assert_eq!(meta(&value, "export_time")?, i64::MIN);
    Ok(())
}

#[test]
fn audit_json_010_u64_max_timestamp_saturates_report_time_to_i64_max() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(1, u64::MAX, 1)],
    };
    let value = json_value(&report, 1, 0)?;

    assert_eq!(meta(&value, "report_time")?, i64::MAX);
    Ok(())
}

#[test]
fn audit_json_011_i64_max_timestamp_roundtrips_as_report_time() -> TestResult {
    let timestamp = u64::try_from(i64::MAX).map_err(|e| e.to_string())?;
    let report = AuditReport {
        blocks: vec![sample_block(1, timestamp, 1)],
    };
    let value = json_value(&report, 1, 0)?;

    assert_eq!(meta(&value, "report_time")?, i64::MAX);
    Ok(())
}

#[test]
fn audit_json_012_total_tx_preserves_u64_max_vector() -> TestResult {
    let value = json_value(&sample_report(), u64::MAX, 0)?;

    assert_eq!(meta(&value, "total_tx")?, u64::MAX);
    Ok(())
}

#[test]
fn audit_json_013_block_span_counts_blocks_not_tx_count() -> TestResult {
    let mut report = two_block_report();

    if let Some(first) = report.blocks.first_mut() {
        first.tx_count = u64::MAX;
    }

    let value = json_value(&report, 123, 0)?;

    assert_eq!(meta(&value, "block_span")?, 2);
    assert_eq!(meta(&value, "total_tx")?, 123);
    Ok(())
}

#[test]
fn audit_json_014_output_is_pretty_printed_with_newlines() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    assert!(text.contains('\n'));
    assert!(text.starts_with("{\n"));
    assert!(text.ends_with('}'));
    assert!(!text.ends_with("}\n"));
    Ok(())
}

#[test]
fn audit_json_015_output_uses_four_space_indent_vector() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    assert!(text.contains("\n    \"meta\""));
    assert!(text.contains("\n    \"blocks\""));
    assert!(text.contains("\n        \"chain_id\""));
    Ok(())
}

#[test]
fn audit_json_016_output_has_no_trailing_garbage_after_single_json_value() -> TestResult {
    let bytes = json_bytes(&sample_report(), 1, 0)?;
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
fn audit_json_017_same_input_same_export_time_is_deterministic() -> TestResult {
    let report = sample_report();

    let first = json_bytes(&report, 1, 777)?;
    let second = json_bytes(&report, 1, 777)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn audit_json_018_different_export_time_changes_bytes() -> TestResult {
    let report = sample_report();

    let first = json_bytes(&report, 1, 777)?;
    let second = json_bytes(&report, 1, 778)?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn audit_json_019_different_total_tx_changes_bytes() -> TestResult {
    let report = sample_report();

    let first = json_bytes(&report, 1, 777)?;
    let second = json_bytes(&report, 2, 777)?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn audit_json_020_different_block_order_changes_bytes() -> TestResult {
    let report_a = two_block_report();
    let mut report_b = two_block_report();
    report_b.blocks.reverse();

    let first = json_bytes(&report_a, 5, 777)?;
    let second = json_bytes(&report_b, 5, 777)?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn audit_json_021_blocks_array_preserves_block_order() -> TestResult {
    let value = json_value(&two_block_report(), 5, 0)?;
    let blocks = blocks(&value)?;

    assert_eq!(
        blocks.first().and_then(|b| b.get("index")),
        Some(&Value::from(1))
    );
    assert_eq!(
        blocks.get(1).and_then(|b| b.get("index")),
        Some(&Value::from(2))
    );
    Ok(())
}

#[test]
fn audit_json_022_block_fields_serialize_snake_case_vectors() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;

    assert!(first_block.get("current_hash").is_some());
    assert!(first_block.get("previous_hash").is_some());
    assert!(first_block.get("merkle_root").is_some());
    assert!(first_block.get("guardian_sig").is_some());
    assert!(first_block.get("currentHash").is_none());
    Ok(())
}

#[test]
fn audit_json_023_transaction_fields_serialize_null_optionals() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx("nft_mint", None, None, None)],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let value = json_value(&report, 1, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;
    let transactions = first_block
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing transactions".to_string())?;
    let tx = transactions
        .first()
        .ok_or_else(|| "missing first transaction".to_string())?;

    assert_eq!(tx.get("kind"), Some(&Value::from("nft_mint")));
    assert!(tx.get("sender").is_some_and(Value::is_null));
    assert!(tx.get("receiver").is_some_and(Value::is_null));
    assert!(tx.get("amount").is_some_and(Value::is_null));
    Ok(())
}

#[test]
fn audit_json_024_transaction_order_is_preserved() -> TestResult {
    let value = json_value(&two_block_report(), 5, 0)?;
    let second_block = blocks(&value)?
        .get(1)
        .ok_or_else(|| "missing second block".to_string())?;
    let transactions = second_block
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing transactions".to_string())?;

    assert_eq!(
        transactions.first().and_then(|tx| tx.get("kind")),
        Some(&Value::from("reward"))
    );
    assert_eq!(
        transactions.get(1).and_then(|tx| tx.get("kind")),
        Some(&Value::from("register_node"))
    );
    assert_eq!(
        transactions.get(2).and_then(|tx| tx.get("kind")),
        Some(&Value::from("nft_transfer"))
    );
    Ok(())
}

#[test]
fn audit_json_025_empty_transactions_with_nonzero_tx_count_serializes_both() -> TestResult {
    let mut block = sample_block(1, 2, 9);
    block.transactions.clear();
    let report = AuditReport {
        blocks: vec![block],
    };

    let value = json_value(&report, 9, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;

    assert_eq!(first_block.get("tx_count"), Some(&Value::from(9)));
    assert_eq!(
        first_block
            .get("transactions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[test]
fn audit_json_026_zero_tx_count_with_nonempty_transactions_serializes_both() -> TestResult {
    let block = sample_block(1, 2, 0);
    let report = AuditReport {
        blocks: vec![block],
    };

    let value = json_value(&report, 0, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;

    assert_eq!(first_block.get("tx_count"), Some(&Value::from(0)));
    assert_eq!(
        first_block
            .get("transactions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn audit_json_027_unicode_transaction_fields_are_valid_json() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
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
        }],
    };

    let text = json_text(&report, 1, 0)?;

    assert!(text.contains("sender-"));
    assert!(text.contains("receiver-"));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_028_newline_transaction_fields_are_escaped() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
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
        }],
    };

    let text = json_text(&report, 1, 0)?;

    assert!(text.contains("\\n"));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_029_zero_length_hash_strings_are_serialized() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: String::new(),
            previous_hash: String::new(),
            merkle_root: String::new(),
            guardian_sig: String::new(),
        }],
    };

    let value = json_value(&report, 0, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;

    assert_eq!(first_block.get("current_hash"), Some(&Value::from("")));
    assert_eq!(first_block.get("previous_hash"), Some(&Value::from("")));
    assert_eq!(first_block.get("merkle_root"), Some(&Value::from("")));
    assert_eq!(first_block.get("guardian_sig"), Some(&Value::from("")));
    Ok(())
}

#[test]
fn audit_json_030_large_hash_strings_are_serialized() -> TestResult {
    let large_hash = "a".repeat(4_096);
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: large_hash.clone(),
            previous_hash: "b".repeat(4_096),
            merkle_root: "c".repeat(4_096),
            guardian_sig: "d".repeat(4_096),
        }],
    };

    let text = json_text(&report, 0, 0)?;

    assert!(text.contains(&large_hash));
    assert!(text.len() > 16_000);
    Ok(())
}

#[test]
fn audit_json_031_max_u64_block_fields_are_serialized() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: u64::MAX,
            timestamp: u64::MAX,
            size: u64::MAX,
            tx_count: u64::MAX,
            transactions: Vec::new(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let text = json_text(&report, u64::MAX, i64::MAX)?;

    assert!(text.contains(&u64::MAX.to_string()));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_032_many_blocks_are_serialized_with_correct_span() -> TestResult {
    let audit_blocks = (0_u64..100_u64)
        .map(|index| sample_block(index, index.saturating_add(10_000), 1))
        .collect::<Vec<_>>();
    let report = AuditReport {
        blocks: audit_blocks,
    };

    let value = json_value(&report, 100, 0)?;

    assert_eq!(meta(&value, "block_span")?, 100);
    assert_eq!(blocks(&value)?.len(), 100);
    Ok(())
}

#[test]
fn audit_json_033_large_transaction_vector_serializes() -> TestResult {
    let transactions = (0_u64..500_u64)
        .map(|index| sample_tx("transfer", Some("sender"), Some("receiver"), Some(index)))
        .collect::<Vec<_>>();

    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 500,
            transactions,
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let value = json_value(&report, 500, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;

    assert_eq!(
        first_block
            .get("transactions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(500)
    );
    Ok(())
}

#[test]
fn audit_json_034_duplicate_blocks_are_preserved() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(1, 2, 1), sample_block(1, 2, 1)],
    };

    let value = json_value(&report, 2, 0)?;

    assert_eq!(blocks(&value)?.len(), 2);
    assert_eq!(meta(&value, "block_span")?, 2);
    Ok(())
}

#[test]
fn audit_json_035_root_has_only_meta_and_blocks_keys() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;
    let object = value
        .as_object()
        .ok_or_else(|| "root was not object".to_string())?;

    assert_eq!(object.len(), 2);
    assert!(object.contains_key("meta"));
    assert!(object.contains_key("blocks"));
    Ok(())
}

#[test]
fn audit_json_036_meta_has_exact_expected_keys() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;
    let meta_object = value
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| "meta was not object".to_string())?;

    let keys = meta_object
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "block_span",
        "chain_id",
        "export_time",
        "guardian_id",
        "report_time",
        "total_tx",
    ]
    .iter()
    .map(|key| (*key).to_string())
    .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(keys, expected);
    Ok(())
}

#[test]
fn audit_json_037_property_many_reports_are_valid_json() -> TestResult {
    for index in 0_u64..100_u64 {
        let report = AuditReport {
            blocks: vec![sample_block(
                index,
                index.saturating_add(1_000),
                index.rem_euclid(9),
            )],
        };

        let bytes = json_bytes(
            &report,
            index.rem_euclid(9),
            i64::try_from(index).map_err(|e| e.to_string())?,
        )?;

        assert!(!bytes.is_empty());
        assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    }

    Ok(())
}

#[test]
fn audit_json_038_repeated_many_block_serialization_is_stable() -> TestResult {
    let blocks = (0_u64..50_u64)
        .map(|index| sample_block(index, index.saturating_add(2_000), 1))
        .collect::<Vec<_>>();
    let report = AuditReport { blocks };
    let baseline = json_bytes(&report, 50, 9)?;

    for _ in 0..100 {
        let next = json_bytes(&report, 50, 9)?;
        assert_eq!(next, baseline);
    }

    Ok(())
}

#[test]
fn audit_json_039_load_large_report_serialization_is_valid() -> TestResult {
    let blocks = (0_u64..1_000_u64)
        .map(|index| sample_block(index, index.saturating_add(3_000), 1))
        .collect::<Vec<_>>();
    let report = AuditReport { blocks };

    let bytes = json_bytes(&report, 1_000, 123)?;

    assert!(bytes.len() > 1_000);
    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    Ok(())
}

#[test]
fn audit_json_040_load_repeated_small_reports_are_valid_and_nonempty() -> TestResult {
    for index in 0_i64..250_i64 {
        let block_index = u64::try_from(index).map_err(|e| e.to_string())?;
        let report = AuditReport {
            blocks: vec![sample_block(
                block_index,
                block_index.saturating_add(4_000),
                1,
            )],
        };

        let bytes = json_bytes(&report, 1, index)?;

        assert!(!bytes.is_empty());
        assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    }

    Ok(())
}

#[test]
fn audit_json_041_root_field_order_is_meta_then_blocks() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    let meta_pos = text
        .find("\"meta\"")
        .ok_or_else(|| "missing meta field".to_string())?;
    let blocks_pos = text
        .find("\"blocks\"")
        .ok_or_else(|| "missing blocks field".to_string())?;

    assert!(meta_pos < blocks_pos);
    Ok(())
}

#[test]
fn audit_json_042_meta_field_order_is_stable_vector() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    let chain_pos = text
        .find("\"chain_id\"")
        .ok_or_else(|| "missing chain_id".to_string())?;
    let guardian_pos = text
        .find("\"guardian_id\"")
        .ok_or_else(|| "missing guardian_id".to_string())?;
    let report_pos = text
        .find("\"report_time\"")
        .ok_or_else(|| "missing report_time".to_string())?;
    let export_pos = text
        .find("\"export_time\"")
        .ok_or_else(|| "missing export_time".to_string())?;
    let span_pos = text
        .find("\"block_span\"")
        .ok_or_else(|| "missing block_span".to_string())?;
    let tx_pos = text
        .find("\"total_tx\"")
        .ok_or_else(|| "missing total_tx".to_string())?;

    assert!(chain_pos < guardian_pos);
    assert!(guardian_pos < report_pos);
    assert!(report_pos < export_pos);
    assert!(export_pos < span_pos);
    assert!(span_pos < tx_pos);
    Ok(())
}

#[test]
fn audit_json_043_empty_report_blocks_array_is_empty_vector() -> TestResult {
    let value = json_value(&empty_report(), 0, 0)?;

    assert_eq!(blocks(&value)?.len(), 0);
    assert_eq!(meta(&value, "block_span")?, 0);
    Ok(())
}

#[test]
fn audit_json_044_empty_report_allows_nonzero_total_tx_vector() -> TestResult {
    let value = json_value(&empty_report(), 99, 123)?;

    assert_eq!(meta(&value, "block_span")?, 0);
    assert_eq!(meta(&value, "total_tx")?, 99);
    assert_eq!(meta(&value, "report_time")?, 0);
    Ok(())
}

#[test]
fn audit_json_045_total_tx_is_caller_supplied_not_computed_from_blocks() -> TestResult {
    let report = two_block_report();
    let value = json_value(&report, 123_456, 0)?;

    assert_eq!(meta(&value, "total_tx")?, 123_456);
    assert_eq!(meta(&value, "block_span")?, 2);
    Ok(())
}

#[test]
fn audit_json_046_first_block_timestamp_controls_report_time_even_if_later_block_is_smaller()
-> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(1, 9_999, 1), sample_block(2, 1, 1)],
    };

    let value = json_value(&report, 2, 0)?;

    assert_eq!(meta(&value, "report_time")?, 9_999);
    Ok(())
}

#[test]
fn audit_json_047_first_block_timestamp_saturates_even_when_second_is_small() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(1, u64::MAX, 1), sample_block(2, 1, 1)],
    };

    let value = json_value(&report, 2, 0)?;

    assert_eq!(meta(&value, "report_time")?, i64::MAX);
    Ok(())
}

#[test]
fn audit_json_048_second_block_u64_max_timestamp_does_not_affect_report_time() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(1, 123, 1), sample_block(2, u64::MAX, 1)],
    };

    let value = json_value(&report, 2, 0)?;

    assert_eq!(meta(&value, "report_time")?, 123);
    Ok(())
}

#[test]
fn audit_json_049_export_time_zero_vector_is_preserved() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;

    assert_eq!(meta(&value, "export_time")?, 0);
    Ok(())
}

#[test]
fn audit_json_050_export_time_minus_one_vector_is_preserved() -> TestResult {
    let value = json_value(&sample_report(), 1, -1)?;

    assert_eq!(meta(&value, "export_time")?, -1);
    Ok(())
}

#[test]
fn audit_json_051_block_with_zero_values_serializes_exactly() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 0,
            timestamp: 0,
            size: 0,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: String::new(),
            previous_hash: String::new(),
            merkle_root: String::new(),
            guardian_sig: String::new(),
        }],
    };

    let value = json_value(&report, 0, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;

    assert_eq!(first_block.get("index"), Some(&Value::from(0)));
    assert_eq!(first_block.get("timestamp"), Some(&Value::from(0)));
    assert_eq!(first_block.get("size"), Some(&Value::from(0)));
    assert_eq!(first_block.get("tx_count"), Some(&Value::from(0)));
    Ok(())
}

#[test]
fn audit_json_052_block_size_change_changes_json_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.size = 100;
    block_b.size = 200;

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_053_block_index_change_changes_json_bytes() -> TestResult {
    let report_a = AuditReport {
        blocks: vec![sample_block(1, 2, 1)],
    };
    let report_b = AuditReport {
        blocks: vec![sample_block(2, 2, 1)],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_054_block_timestamp_change_changes_json_bytes() -> TestResult {
    let report_a = AuditReport {
        blocks: vec![sample_block(1, 2, 1)],
    };
    let report_b = AuditReport {
        blocks: vec![sample_block(1, 3, 1)],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_055_current_hash_change_changes_json_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.current_hash = "a".repeat(128);
    block_b.current_hash = "f".repeat(128);

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_056_previous_hash_change_changes_json_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.previous_hash = "b".repeat(128);
    block_b.previous_hash = "e".repeat(128);

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_057_merkle_root_change_changes_json_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.merkle_root = "c".repeat(128);
    block_b.merkle_root = "9".repeat(128);

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_058_guardian_signature_change_changes_json_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.guardian_sig = "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));
    block_b.guardian_sig = "a".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_059_transaction_amount_change_changes_json_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.transactions = vec![sample_tx("transfer", Some("a"), Some("b"), Some(1))];
    block_b.transactions = vec![sample_tx("transfer", Some("a"), Some("b"), Some(2))];

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_060_transaction_kind_change_changes_json_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.transactions = vec![sample_tx("transfer", Some("a"), Some("b"), Some(1))];
    block_b.transactions = vec![sample_tx("reward", None, Some("b"), Some(1))];

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    assert_ne!(json_bytes(&report_a, 1, 0)?, json_bytes(&report_b, 1, 0)?);
    Ok(())
}

#[test]
fn audit_json_061_unknown_transaction_kind_is_preserved_as_data() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx("future_kind", None, None, None)],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let text = json_text(&report, 1, 0)?;

    assert!(text.contains("future_kind"));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_062_empty_string_transaction_fields_are_preserved() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx("", Some(""), Some(""), Some(0))],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let value = json_value(&report, 1, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;
    let tx = first_block
        .get("transactions")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| "missing first transaction".to_string())?;

    assert_eq!(tx.get("kind"), Some(&Value::from("")));
    assert_eq!(tx.get("sender"), Some(&Value::from("")));
    assert_eq!(tx.get("receiver"), Some(&Value::from("")));
    assert_eq!(tx.get("amount"), Some(&Value::from(0)));
    Ok(())
}

#[test]
fn audit_json_063_tab_and_carriage_return_transaction_fields_are_escaped() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx(
                "transfer",
                Some("sender\tfield"),
                Some("receiver\rfield"),
                Some(4),
            )],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let text = json_text(&report, 1, 0)?;

    assert!(text.contains("\\t"));
    assert!(text.contains("\\r"));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_064_quote_and_backslash_transaction_fields_are_escaped() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx(
                "transfer",
                Some("sender\"quoted"),
                Some("receiver\\path"),
                Some(4),
            )],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let text = json_text(&report, 1, 0)?;

    assert!(text.contains("\\\""));
    assert!(text.contains("\\\\"));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_065_large_unicode_hash_like_fields_are_valid_json() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: "鎖".repeat(256),
            previous_hash: "данные".repeat(128),
            merkle_root: "ブロック".repeat(128),
            guardian_sig: "sig-鎖".repeat(128),
        }],
    };

    let text = json_text(&report, 0, 0)?;

    assert!(serde_json::from_str::<Value>(&text).is_ok());
    assert!(text.contains("sig-"));
    Ok(())
}

#[test]
fn audit_json_066_pretty_json_has_expected_opening_lines() -> TestResult {
    let text = json_text(&empty_report(), 0, 0)?;
    let lines = text.lines().take(4).collect::<Vec<_>>();

    assert_eq!(lines.first().copied(), Some("{"));
    assert_eq!(lines.get(1).copied(), Some("    \"meta\": {"));
    assert!(
        lines
            .get(2)
            .is_some_and(|line| line.contains("\"chain_id\""))
    );
    Ok(())
}

#[test]
fn audit_json_067_pretty_json_empty_blocks_has_same_line_empty_array() -> TestResult {
    let text = json_text(&empty_report(), 0, 0)?;

    assert!(text.contains("\"blocks\": []"));
    Ok(())
}

#[test]
fn audit_json_068_pretty_json_nonempty_blocks_opens_array_on_field_line() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    assert!(text.contains("\"blocks\": ["));
    Ok(())
}

#[test]
fn audit_json_069_json_bytes_are_utf8() -> TestResult {
    let bytes = json_bytes(&sample_report(), 1, 0)?;
    let text = String::from_utf8(bytes).map_err(|e| e.to_string())?;

    assert!(text.starts_with('{'));
    assert!(text.ends_with('}'));
    Ok(())
}

#[test]
fn audit_json_070_json_output_has_no_bom() -> TestResult {
    let bytes = json_bytes(&sample_report(), 1, 0)?;

    assert!(!bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
    Ok(())
}

#[test]
fn audit_json_071_json_output_contains_no_nul_bytes() -> TestResult {
    let bytes = json_bytes(&sample_report(), 1, 0)?;

    assert!(!bytes.contains(&0));
    Ok(())
}

#[test]
fn audit_json_072_repeated_empty_report_serialization_is_stable() -> TestResult {
    let report = empty_report();
    let baseline = json_bytes(&report, 0, 0)?;

    for _ in 0..250 {
        let next = json_bytes(&report, 0, 0)?;
        assert_eq!(next, baseline);
    }

    Ok(())
}

#[test]
fn audit_json_073_many_empty_blocks_are_serialized() -> TestResult {
    let audit_blocks = (0_u64..100_u64)
        .map(|index| AuditBlock {
            index,
            timestamp: index,
            size: 0,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: String::new(),
            previous_hash: String::new(),
            merkle_root: String::new(),
            guardian_sig: String::new(),
        })
        .collect::<Vec<_>>();

    let report = AuditReport {
        blocks: audit_blocks,
    };
    let value = json_value(&report, 0, 0)?;

    assert_eq!(blocks(&value)?.len(), 100);
    assert_eq!(meta(&value, "block_span")?, 100);
    Ok(())
}

#[test]
fn audit_json_074_many_blocks_with_reversed_indexes_preserve_given_order() -> TestResult {
    let audit_blocks = (0_u64..50_u64)
        .rev()
        .map(|index| sample_block(index, index.saturating_add(10), 1))
        .collect::<Vec<_>>();

    let report = AuditReport {
        blocks: audit_blocks,
    };
    let value = json_value(&report, 50, 0)?;
    let block_values = blocks(&value)?;

    assert_eq!(
        block_values.first().and_then(|b| b.get("index")),
        Some(&Value::from(49))
    );
    assert_eq!(
        block_values.get(49).and_then(|b| b.get("index")),
        Some(&Value::from(0))
    );
    Ok(())
}

#[test]
fn audit_json_075_property_total_tx_vectors_are_preserved() -> TestResult {
    for total_tx in [0_u64, 1, 2, 10, 99, 1_000_000, u64::MAX] {
        let value = json_value(&sample_report(), total_tx, 0)?;

        assert_eq!(meta(&value, "total_tx")?, total_tx);
    }

    Ok(())
}

#[test]
fn audit_json_076_property_export_time_vectors_are_preserved() -> TestResult {
    for export_time in [i64::MIN, -1, 0, 1, 999, i64::MAX] {
        let value = json_value(&sample_report(), 1, export_time)?;

        assert_eq!(meta(&value, "export_time")?, export_time);
    }

    Ok(())
}

#[test]
fn audit_json_077_property_first_timestamp_vectors_are_preserved_or_saturated() -> TestResult {
    let cases = [
        (0_u64, 0_i64),
        (1_u64, 1_i64),
        (1_700_000_000_u64, 1_700_000_000_i64),
        (
            u64::try_from(i64::MAX).map_err(|e| e.to_string())?,
            i64::MAX,
        ),
        (u64::MAX, i64::MAX),
    ];

    for (timestamp, expected) in cases {
        let report = AuditReport {
            blocks: vec![sample_block(1, timestamp, 1)],
        };
        let value = json_value(&report, 1, 0)?;

        assert_eq!(meta(&value, "report_time")?, expected);
    }

    Ok(())
}

#[test]
fn audit_json_078_load_serializes_many_reports_with_unicode_payloads() -> TestResult {
    for index in 0_u64..100_u64 {
        let report = AuditReport {
            blocks: vec![AuditBlock {
                index,
                timestamp: index.saturating_add(100),
                size: index.saturating_add(200),
                tx_count: 1,
                transactions: vec![sample_tx(
                    "transfer",
                    Some("sender-鎖"),
                    Some("receiver-данные"),
                    Some(index),
                )],
                current_hash: "鎖".repeat(16),
                previous_hash: "данные".repeat(16),
                merkle_root: "ブロック".repeat(16),
                guardian_sig: "sig".repeat(16),
            }],
        };

        let bytes = json_bytes(&report, 1, i64::try_from(index).map_err(|e| e.to_string())?)?;
        assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    }

    Ok(())
}

#[test]
fn audit_json_079_load_large_block_and_transaction_report_is_valid_json() -> TestResult {
    let audit_blocks = (0_u64..100_u64)
        .map(|block_index| AuditBlock {
            index: block_index,
            timestamp: block_index.saturating_add(1_000),
            size: block_index.saturating_add(2_000),
            tx_count: 25,
            transactions: (0_u64..25_u64)
                .map(|tx_index| {
                    sample_tx(
                        "transfer",
                        Some("sender"),
                        Some("receiver"),
                        Some(block_index.saturating_mul(25).saturating_add(tx_index)),
                    )
                })
                .collect::<Vec<_>>(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        })
        .collect::<Vec<_>>();

    let report = AuditReport {
        blocks: audit_blocks,
    };
    let bytes = json_bytes(&report, 2_500, 123)?;

    assert!(bytes.len() > 10_000);
    assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
    Ok(())
}

#[test]
fn audit_json_080_load_repeated_large_report_serialization_is_stable() -> TestResult {
    let audit_blocks = (0_u64..200_u64)
        .map(|index| sample_block(index, index.saturating_add(5_000), 1))
        .collect::<Vec<_>>();
    let report = AuditReport {
        blocks: audit_blocks,
    };
    let baseline = json_bytes(&report, 200, 456)?;

    for _ in 0..50 {
        let next = json_bytes(&report, 200, 456)?;
        assert_eq!(next, baseline);
    }

    Ok(())
}

#[test]
fn audit_json_081_block_field_order_is_stable_vector() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    let index_pos = text
        .find("\"index\"")
        .ok_or_else(|| "missing index field".to_string())?;
    let timestamp_pos = text
        .find("\"timestamp\"")
        .ok_or_else(|| "missing timestamp field".to_string())?;
    let size_pos = text
        .find("\"size\"")
        .ok_or_else(|| "missing size field".to_string())?;
    let tx_count_pos = text
        .find("\"tx_count\"")
        .ok_or_else(|| "missing tx_count field".to_string())?;
    let transactions_pos = text
        .find("\"transactions\"")
        .ok_or_else(|| "missing transactions field".to_string())?;
    let current_pos = text
        .find("\"current_hash\"")
        .ok_or_else(|| "missing current_hash field".to_string())?;
    let previous_pos = text
        .find("\"previous_hash\"")
        .ok_or_else(|| "missing previous_hash field".to_string())?;
    let merkle_pos = text
        .find("\"merkle_root\"")
        .ok_or_else(|| "missing merkle_root field".to_string())?;
    let sig_pos = text
        .find("\"guardian_sig\"")
        .ok_or_else(|| "missing guardian_sig field".to_string())?;

    assert!(index_pos < timestamp_pos);
    assert!(timestamp_pos < size_pos);
    assert!(size_pos < tx_count_pos);
    assert!(tx_count_pos < transactions_pos);
    assert!(transactions_pos < current_pos);
    assert!(current_pos < previous_pos);
    assert!(previous_pos < merkle_pos);
    assert!(merkle_pos < sig_pos);
    Ok(())
}

#[test]
fn audit_json_082_transaction_field_order_is_stable_vector() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    let kind_pos = text
        .find("\"kind\"")
        .ok_or_else(|| "missing kind field".to_string())?;
    let sender_pos = text
        .find("\"sender\"")
        .ok_or_else(|| "missing sender field".to_string())?;
    let receiver_pos = text
        .find("\"receiver\"")
        .ok_or_else(|| "missing receiver field".to_string())?;
    let amount_pos = text
        .find("\"amount\"")
        .ok_or_else(|| "missing amount field".to_string())?;

    assert!(kind_pos < sender_pos);
    assert!(sender_pos < receiver_pos);
    assert!(receiver_pos < amount_pos);
    Ok(())
}

#[test]
fn audit_json_083_camel_case_field_names_are_absent() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    assert!(!text.contains("chainId"));
    assert!(!text.contains("guardianId"));
    assert!(!text.contains("reportTime"));
    assert!(!text.contains("exportTime"));
    assert!(!text.contains("blockSpan"));
    assert!(!text.contains("totalTx"));
    assert!(!text.contains("currentHash"));
    assert!(!text.contains("previousHash"));
    assert!(!text.contains("merkleRoot"));
    assert!(!text.contains("guardianSig"));
    Ok(())
}

#[test]
fn audit_json_084_meta_fields_appear_exactly_once() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    for field in [
        "\"chain_id\"",
        "\"guardian_id\"",
        "\"report_time\"",
        "\"export_time\"",
        "\"block_span\"",
        "\"total_tx\"",
    ] {
        assert_eq!(
            text.matches(field).count(),
            1,
            "field {field} count mismatch"
        );
    }

    Ok(())
}

#[test]
fn audit_json_085_root_blocks_field_appears_exactly_once() -> TestResult {
    let text = json_text(&two_block_report(), 5, 0)?;

    assert_eq!(text.matches("\"blocks\"").count(), 1);
    Ok(())
}

#[test]
fn audit_json_086_json_output_uses_spaces_not_tabs_for_formatting() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    assert!(!text.lines().any(|line| line.starts_with('\t')));
    assert!(text.contains("\n    \"meta\""));
    Ok(())
}

#[test]
fn audit_json_087_json_output_uses_lf_not_crlf() -> TestResult {
    let text = json_text(&sample_report(), 1, 0)?;

    assert!(text.contains('\n'));
    assert!(!text.contains("\r\n"));
    assert!(!text.contains('\r'));
    Ok(())
}

#[test]
fn audit_json_088_html_like_transaction_text_is_preserved_as_json_string_data() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx(
                "transfer<script>",
                Some("<sender>&\"quoted\""),
                Some("</receiver>"),
                Some(4),
            )],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let text = json_text(&report, 1, 0)?;

    assert!(text.contains("<script>"));
    assert!(text.contains("<sender>"));
    assert!(text.contains("</receiver>"));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_089_backspace_and_formfeed_transaction_fields_are_escaped() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx(
                "transfer",
                Some("sender\u{0008}field"),
                Some("receiver\u{000C}field"),
                Some(4),
            )],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let text = json_text(&report, 1, 0)?;

    assert!(text.contains("\\b"));
    assert!(text.contains("\\f"));
    assert!(serde_json::from_str::<Value>(&text).is_ok());
    Ok(())
}

#[test]
fn audit_json_090_duplicate_transactions_are_preserved() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 2,
            transactions: vec![
                sample_tx("transfer", Some("alice"), Some("bob"), Some(1)),
                sample_tx("transfer", Some("alice"), Some("bob"), Some(1)),
            ],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        }],
    };

    let value = json_value(&report, 2, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;
    let transactions = first_block
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing transactions".to_string())?;

    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions.first(), transactions.get(1));
    Ok(())
}

#[test]
fn audit_json_091_total_tx_zero_with_nonzero_block_tx_counts_is_preserved() -> TestResult {
    let report = two_block_report();
    let value = json_value(&report, 0, 0)?;

    assert_eq!(meta(&value, "total_tx")?, 0);
    assert_eq!(meta(&value, "block_span")?, 2);
    Ok(())
}

#[test]
fn audit_json_092_total_tx_u64_max_with_empty_report_is_preserved() -> TestResult {
    let value = json_value(&empty_report(), u64::MAX, 0)?;

    assert_eq!(meta(&value, "total_tx")?, u64::MAX);
    assert_eq!(meta(&value, "block_span")?, 0);
    assert_eq!(blocks(&value)?.len(), 0);
    Ok(())
}

#[test]
fn audit_json_093_guardian_id_length_matches_global_validator_length() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;
    let guardian = meta(&value, "guardian_id")?
        .as_str()
        .ok_or_else(|| "guardian_id was not a string".to_string())?;

    assert_eq!(guardian, GlobalConfiguration::GENESIS_VALIDATOR);
    assert_eq!(guardian.len(), GlobalConfiguration::GENESIS_VALIDATOR.len());
    Ok(())
}

#[test]
fn audit_json_094_chain_id_is_lowercase_ascii_vector() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;
    let chain_id = meta(&value, "chain_id")?
        .as_str()
        .ok_or_else(|| "chain_id was not a string".to_string())?;

    assert_eq!(chain_id, GlobalConfiguration::COIN_NAME);
    assert!(chain_id.is_ascii());
    assert_eq!(chain_id, chain_id.to_ascii_lowercase());
    Ok(())
}

#[test]
fn audit_json_095_all_block_hash_fields_keep_exact_string_lengths() -> TestResult {
    let value = json_value(&sample_report(), 1, 0)?;
    let first_block = blocks(&value)?
        .first()
        .ok_or_else(|| "missing first block".to_string())?;

    for field in ["current_hash", "previous_hash", "merkle_root"] {
        let s = first_block
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing block field {field}"))?;
        assert_eq!(s.len(), 128);
    }

    let sig = first_block
        .get("guardian_sig")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing guardian_sig".to_string())?;
    assert_eq!(
        sig.len(),
        GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)
    );
    Ok(())
}

#[test]
fn audit_json_096_many_blocks_with_u64_max_values_are_valid_json() -> TestResult {
    let audit_blocks = (0_u64..25_u64)
        .map(|index| AuditBlock {
            index,
            timestamp: u64::MAX,
            size: u64::MAX,
            tx_count: u64::MAX,
            transactions: Vec::new(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
        })
        .collect::<Vec<_>>();

    let report = AuditReport {
        blocks: audit_blocks,
    };
    let value = json_value(&report, u64::MAX, i64::MAX)?;

    assert_eq!(blocks(&value)?.len(), 25);
    assert_eq!(meta(&value, "report_time")?, i64::MAX);
    assert_eq!(meta(&value, "total_tx")?, u64::MAX);
    Ok(())
}

#[test]
fn audit_json_097_property_empty_and_nonempty_reports_have_different_bytes() -> TestResult {
    for index in 0_u64..50_u64 {
        let empty = empty_report();
        let nonempty = AuditReport {
            blocks: vec![sample_block(index, index.saturating_add(1), 1)],
        };

        assert_ne!(
            json_bytes(&empty, 0, i64::try_from(index).map_err(|e| e.to_string())?)?,
            json_bytes(
                &nonempty,
                1,
                i64::try_from(index).map_err(|e| e.to_string())?
            )?
        );
    }

    Ok(())
}

#[test]
fn audit_json_098_property_block_order_changes_bytes_for_many_reports() -> TestResult {
    for index in 0_u64..25_u64 {
        let report_a = AuditReport {
            blocks: vec![
                sample_block(index, index.saturating_add(10), 1),
                sample_block(index.saturating_add(1), index.saturating_add(20), 1),
            ],
        };

        let report_b = AuditReport {
            blocks: vec![
                sample_block(index.saturating_add(1), index.saturating_add(20), 1),
                sample_block(index, index.saturating_add(10), 1),
            ],
        };

        assert_ne!(json_bytes(&report_a, 2, 0)?, json_bytes(&report_b, 2, 0)?);
    }

    Ok(())
}

#[test]
fn audit_json_099_load_large_strings_are_valid_json_and_stable() -> TestResult {
    let report = AuditReport {
        blocks: vec![AuditBlock {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![sample_tx(
                &"kind".repeat(1_000),
                Some(&"sender".repeat(1_000)),
                Some(&"receiver".repeat(1_000)),
                Some(1),
            )],
            current_hash: "a".repeat(50_000),
            previous_hash: "b".repeat(50_000),
            merkle_root: "c".repeat(50_000),
            guardian_sig: "d".repeat(50_000),
        }],
    };

    let first = json_bytes(&report, 1, 0)?;
    let second = json_bytes(&report, 1, 0)?;

    assert_eq!(first, second);
    assert!(first.len() > 200_000);
    assert!(serde_json::from_slice::<Value>(&first).is_ok());
    Ok(())
}

#[test]
fn audit_json_100_load_repeated_edge_report_serialization_is_stable_and_valid() -> TestResult {
    let report = AuditReport {
        blocks: vec![
            AuditBlock {
                index: 0,
                timestamp: 0,
                size: 0,
                tx_count: 0,
                transactions: Vec::new(),
                current_hash: String::new(),
                previous_hash: String::new(),
                merkle_root: String::new(),
                guardian_sig: String::new(),
            },
            AuditBlock {
                index: u64::MAX,
                timestamp: u64::MAX,
                size: u64::MAX,
                tx_count: u64::MAX,
                transactions: vec![sample_tx(
                    "future_kind",
                    Some("sender-鎖\nline"),
                    Some("receiver-данные\tfield"),
                    Some(u64::MAX),
                )],
                current_hash: "鎖".repeat(64),
                previous_hash: "b".repeat(128),
                merkle_root: "c".repeat(128),
                guardian_sig: "not-hex-but-json-data".to_string(),
            },
        ],
    };

    let baseline = json_bytes(&report, u64::MAX, i64::MIN)?;

    for _ in 0..50 {
        let next = json_bytes(&report, u64::MAX, i64::MIN)?;
        assert_eq!(next, baseline);
        assert!(serde_json::from_slice::<Value>(&next).is_ok());
    }

    Ok(())
}
