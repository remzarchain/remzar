// tests/proptests_audit_report_003_json.rs

use proptest::prelude::*;
use proptest::string::string_regex;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::audit_report_001_hub::{AuditBlock, AuditReport, AuditTransaction};
use remzar::utility::audit_report_003_json::build_json;

use serde_json::Value;

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

fn unicode_text_0_128() -> BoxedStrategy<String> {
    proptest::collection::vec(
        prop_oneof![
            Just('a'),
            Just('Z'),
            Just('0'),
            Just(' '),
            Just('-'),
            Just('_'),
            Just('é'),
            Just('鎖'),
            Just('中'),
            Just('🙂'),
            Just('🚀'),
        ],
        0..128,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>())
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

fn block_specs_nonempty() -> BoxedStrategy<Vec<BlockSpec>> {
    proptest::collection::vec(block_spec_strategy(), 1..8).boxed()
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

fn json_bytes(
    report: &AuditReport,
    total_tx: u64,
    export_time: i64,
) -> Result<Vec<u8>, TestCaseError> {
    build_json(report, total_tx, export_time)
        .map_err(|e| TestCaseError::fail(format!("build_json failed: {e:?}")))
}

fn json_value(
    report: &AuditReport,
    total_tx: u64,
    export_time: i64,
) -> Result<Value, TestCaseError> {
    let bytes = json_bytes(report, total_tx, export_time)?;

    serde_json::from_slice(&bytes)
        .map_err(|e| TestCaseError::fail(format!("JSON decode failed: {e}")))
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
    fn audit_json_prop_001_empty_report_has_zero_meta(_case in any::<u8>()) {
        let report = AuditReport { blocks: Vec::new() };
        let value = json_value(&report, 0, 0)?;

        prop_assert_eq!(value.get("meta").and_then(|m| m.get("block_span")).and_then(Value::as_u64), Some(0));
        prop_assert_eq!(value.get("meta").and_then(|m| m.get("total_tx")).and_then(Value::as_u64), Some(0));
        prop_assert_eq!(value.get("meta").and_then(|m| m.get("report_time")).and_then(Value::as_i64), Some(0));
        prop_assert_eq!(value.get("meta").and_then(|m| m.get("export_time")).and_then(Value::as_i64), Some(0));
        prop_assert_eq!(value.get("blocks").and_then(Value::as_array).map(Vec::len), Some(0));
    }

    // 02/25
    #[test]
    fn audit_json_prop_002_generated_reports_always_build_valid_root_json(
        specs in block_specs_small(),
        total_tx in 0u64..1_000_000u64,
        export_time in -2_000_000_000i64..2_000_000_000i64,
    ) {
        let report = report_from_specs(specs);
        let value = json_value(&report, total_tx, export_time)?;

        prop_assert!(value.get("meta").is_some());
        prop_assert!(value.get("blocks").is_some());
        prop_assert!(value.get("blocks").and_then(Value::as_array).is_some());
    }

    // 03/25
    #[test]
    fn audit_json_prop_003_block_span_matches_report_block_count(
        specs in block_specs_small()
    ) {
        let expected_span = specs.len() as u64;
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);
        let value = json_value(&report, total_tx, 123)?;

        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("block_span")).and_then(Value::as_u64),
            Some(expected_span)
        );
        prop_assert_eq!(
            value.get("blocks").and_then(Value::as_array).map(|a| a.len() as u64),
            Some(expected_span)
        );
    }

    // 04/25
    #[test]
    fn audit_json_prop_004_total_tx_argument_is_preserved_exactly(
        specs in block_specs_small(),
        total_tx in 0u64..u64::MAX,
    ) {
        let report = report_from_specs(specs);
        let value = json_value(&report, total_tx, 123)?;

        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("total_tx")).and_then(Value::as_u64),
            Some(total_tx)
        );
    }

    // 05/25
    #[test]
    fn audit_json_prop_005_report_time_uses_first_block_timestamp(
        specs in block_specs_nonempty()
    ) {
        let expected_report_time = specs[0].timestamp as i64;
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);
        let value = json_value(&report, total_tx, 456)?;

        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("report_time")).and_then(Value::as_i64),
            Some(expected_report_time)
        );
    }

    // 06/25
    #[test]
    fn audit_json_prop_006_empty_report_uses_zero_report_time(
        export_time in -2_000_000_000i64..2_000_000_000i64,
        total_tx in 0u64..1_000_000u64,
    ) {
        let report = AuditReport { blocks: Vec::new() };
        let value = json_value(&report, total_tx, export_time)?;

        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("report_time")).and_then(Value::as_i64),
            Some(0)
        );
    }

    // 07/25
    #[test]
    fn audit_json_prop_007_first_timestamp_above_i64_max_is_capped_to_i64_max(
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
        let value = json_value(&report, 0, 999)?;

        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("report_time")).and_then(Value::as_i64),
            Some(i64::MAX)
        );
    }

    // 08/25
    #[test]
    fn audit_json_prop_008_export_time_argument_is_preserved_exactly(
        specs in block_specs_small(),
        export_time in any::<i64>(),
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);
        let value = json_value(&report, total_tx, export_time)?;

        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("export_time")).and_then(Value::as_i64),
            Some(export_time)
        );
    }

    // 09/25
    #[test]
    fn audit_json_prop_009_chain_id_and_guardian_id_match_global_configuration(
        specs in block_specs_small()
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);
        let value = json_value(&report, total_tx, 123)?;

        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("chain_id")).and_then(Value::as_str),
            Some(GlobalConfiguration::COIN_NAME)
        );
        prop_assert_eq!(
            value.get("meta").and_then(|m| m.get("guardian_id")).and_then(Value::as_str),
            Some(GlobalConfiguration::GENESIS_VALIDATOR)
        );
    }

    // 10/25
    #[test]
    fn audit_json_prop_010_block_order_is_preserved(
        specs in block_specs_nonempty()
    ) {
        let expected_indexes = specs.iter().map(|b| b.index).collect::<Vec<_>>();
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);
        let value = json_value(&report, total_tx, 123)?;

        let blocks = value
            .get("blocks")
            .and_then(Value::as_array)
            .ok_or_else(|| TestCaseError::fail("blocks should be an array"))?;

        let actual_indexes = blocks
            .iter()
            .map(|b| b.get("index").and_then(Value::as_u64).unwrap_or(u64::MAX))
            .collect::<Vec<_>>();

        prop_assert_eq!(&actual_indexes, &expected_indexes);
    }

    // 11/25
    #[test]
    fn audit_json_prop_011_block_numeric_fields_are_preserved(
        spec in block_spec_strategy()
    ) {
        let expected_index = spec.index;
        let expected_timestamp = spec.timestamp;
        let expected_size = spec.size;
        let expected_tx_count = spec.tx_count;

        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, expected_tx_count, 123)?;
        let block = &value["blocks"][0];

        prop_assert_eq!(block.get("index").and_then(Value::as_u64), Some(expected_index));
        prop_assert_eq!(block.get("timestamp").and_then(Value::as_u64), Some(expected_timestamp));
        prop_assert_eq!(block.get("size").and_then(Value::as_u64), Some(expected_size));
        prop_assert_eq!(block.get("tx_count").and_then(Value::as_u64), Some(expected_tx_count));
    }

    // 12/25
    #[test]
    fn audit_json_prop_012_block_string_fields_are_preserved_exactly(
        spec in block_spec_strategy()
    ) {
        let expected_current = spec.current_hash.clone();
        let expected_previous = spec.previous_hash.clone();
        let expected_merkle = spec.merkle_root.clone();
        let expected_sig = spec.guardian_sig.clone();

        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, 0, 123)?;
        let block = &value["blocks"][0];

        prop_assert_eq!(block.get("current_hash").and_then(Value::as_str), Some(expected_current.as_str()));
        prop_assert_eq!(block.get("previous_hash").and_then(Value::as_str), Some(expected_previous.as_str()));
        prop_assert_eq!(block.get("merkle_root").and_then(Value::as_str), Some(expected_merkle.as_str()));
        prop_assert_eq!(block.get("guardian_sig").and_then(Value::as_str), Some(expected_sig.as_str()));
    }

    // 13/25
    #[test]
    fn audit_json_prop_013_transaction_array_length_is_preserved(
        mut spec in block_spec_strategy(),
        txs in proptest::collection::vec(tx_spec_strategy(), 0..16),
    ) {
        let expected_len = txs.len();
        spec.transactions = txs;
        spec.tx_count = expected_len as u64;

        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, expected_len as u64, 123)?;

        let transactions = value
            .get("blocks")
            .and_then(Value::as_array)
            .and_then(|blocks| blocks.first())
            .and_then(|block| block.get("transactions"))
            .and_then(Value::as_array)
            .ok_or_else(|| TestCaseError::fail("transactions should be an array"))?;

        prop_assert_eq!(transactions.len(), expected_len);
    }

    // 14/25
    #[test]
    fn audit_json_prop_014_transaction_kind_order_is_preserved(
        mut spec in block_spec_strategy(),
        txs in proptest::collection::vec(tx_spec_strategy(), 1..16),
    ) {
        let expected_kinds = txs.iter().map(|tx| tx.kind.clone()).collect::<Vec<_>>();

        spec.transactions = txs;
        spec.tx_count = expected_kinds.len() as u64;

        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, expected_kinds.len() as u64, 123)?;

        let transactions = value
            .get("blocks")
            .and_then(Value::as_array)
            .and_then(|blocks| blocks.first())
            .and_then(|block| block.get("transactions"))
            .and_then(Value::as_array)
            .ok_or_else(|| TestCaseError::fail("transactions should be an array"))?;

        let actual_kinds = transactions
            .iter()
            .map(|tx| {
                tx.get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("<missing>")
                    .to_string()
            })
            .collect::<Vec<_>>();

        prop_assert_eq!(&actual_kinds, &expected_kinds);
    }

    // 15/25
    #[test]
    fn audit_json_prop_015_transaction_optional_sender_receiver_roundtrip(
        kind in tx_kind_name(),
        sender in opt_text(),
        receiver in opt_text(),
    ) {
        let tx = TxSpec {
            kind,
            sender: sender.clone(),
            receiver: receiver.clone(),
            amount: None,
        };

        let spec = BlockSpec {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![tx],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, 1, 123)?;
        let json_tx = &value["blocks"][0]["transactions"][0];

        match sender {
            Some(s) => prop_assert_eq!(json_tx.get("sender").and_then(Value::as_str), Some(s.as_str())),
            None => prop_assert!(json_tx.get("sender").is_some_and(Value::is_null)),
        }

        match receiver {
            Some(r) => prop_assert_eq!(json_tx.get("receiver").and_then(Value::as_str), Some(r.as_str())),
            None => prop_assert!(json_tx.get("receiver").is_some_and(Value::is_null)),
        }
    }

    // 16/25
    #[test]
    fn audit_json_prop_016_transaction_optional_amount_roundtrip(
        kind in tx_kind_name(),
        amount in opt_amount(),
    ) {
        let tx = TxSpec {
            kind,
            sender: None,
            receiver: None,
            amount,
        };

        let spec = BlockSpec {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![tx],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, 1, 123)?;
        let json_tx = &value["blocks"][0]["transactions"][0];

        match amount {
            Some(a) => prop_assert_eq!(json_tx.get("amount").and_then(Value::as_u64), Some(a)),
            None => prop_assert!(json_tx.get("amount").is_some_and(Value::is_null)),
        }
    }

    // 17/25
    #[test]
    fn audit_json_prop_017_canonical_json_is_pretty_printed_with_four_space_indent(
        specs in block_specs_small()
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);
        let bytes = json_bytes(&report, total_tx, 123)?;

        let text = String::from_utf8(bytes)
            .map_err(|e| TestCaseError::fail(format!("canonical JSON should be UTF-8: {e}")))?;

        prop_assert_eq!(text.chars().next(), Some('{'));
        prop_assert!(text.contains('\n'));
        prop_assert!(
            text.contains("\n    \"meta\"") || text.contains("\n    \"blocks\""),
            "canonical JSON should contain 4-space indentation"
        );
    }

    // 18/25
    #[test]
    fn audit_json_prop_018_same_report_same_total_and_export_time_are_deterministic(
        specs in block_specs_small(),
        export_time in -2_000_000_000i64..2_000_000_000i64,
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let first = json_bytes(&report, total_tx, export_time)?;
        let second = json_bytes(&report, total_tx, export_time)?;

        prop_assert_eq!(&first, &second);
    }

    // 19/25
    #[test]
    fn audit_json_prop_019_changing_export_time_changes_canonical_bytes(
        specs in block_specs_small(),
        first_export_time in -2_000_000_000i64..2_000_000_000i64,
        second_export_time in -2_000_000_000i64..2_000_000_000i64,
    ) {
        prop_assume!(first_export_time != second_export_time);

        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let first = json_bytes(&report, total_tx, first_export_time)?;
        let second = json_bytes(&report, total_tx, second_export_time)?;

        prop_assert_ne!(&first, &second);
    }

    // 20/25
    #[test]
    fn audit_json_prop_020_changing_total_tx_changes_canonical_bytes(
        specs in block_specs_small(),
        first_total in 0u64..1_000_000u64,
        second_total in 0u64..1_000_000u64,
    ) {
        prop_assume!(first_total != second_total);

        let report = report_from_specs(specs);

        let first = json_bytes(&report, first_total, 123)?;
        let second = json_bytes(&report, second_total, 123)?;

        prop_assert_ne!(&first, &second);
    }

    // 21/25
    #[test]
    fn audit_json_prop_021_changing_block_hash_changes_canonical_bytes(
        mut spec in block_spec_strategy(),
        replacement_hash in hex_128(),
    ) {
        prop_assume!(spec.current_hash != replacement_hash);

        let report_a = report_from_specs(vec![spec.clone()]);
        let first = json_bytes(&report_a, spec.tx_count, 123)?;

        spec.current_hash = replacement_hash;

        let report_b = report_from_specs(vec![spec.clone()]);
        let second = json_bytes(&report_b, spec.tx_count, 123)?;

        prop_assert_ne!(&first, &second);
    }

    // 22/25
    #[test]
    fn audit_json_prop_022_changing_transaction_amount_changes_canonical_bytes(
        first_amount in 0u64..1_000_000u64,
        second_amount in 0u64..1_000_000u64,
    ) {
        prop_assume!(first_amount != second_amount);

        let tx_a = TxSpec {
            kind: "transfer".to_string(),
            sender: Some("sender".to_string()),
            receiver: Some("receiver".to_string()),
            amount: Some(first_amount),
        };

        let tx_b = TxSpec {
            amount: Some(second_amount),
            ..tx_a.clone()
        };

        let base = BlockSpec {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![tx_a],
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let changed = BlockSpec {
            transactions: vec![tx_b],
            ..base.clone()
        };

        let report_a = report_from_specs(vec![base]);
        let report_b = report_from_specs(vec![changed]);

        let first = json_bytes(&report_a, 1, 123)?;
        let second = json_bytes(&report_b, 1, 123)?;

        prop_assert_ne!(&first, &second);
    }

    // 23/25
    #[test]
    fn audit_json_prop_023_unicode_strings_serialize_without_panic_and_decode_back(
        current in unicode_text_0_128(),
        previous in unicode_text_0_128(),
        merkle in unicode_text_0_128(),
        sig in unicode_text_0_128(),
        sender in unicode_text_0_128(),
        receiver in unicode_text_0_128(),
    ) {
        let tx = TxSpec {
            kind: "unicode_test".to_string(),
            sender: Some(sender.clone()),
            receiver: Some(receiver.clone()),
            amount: Some(42),
        };

        let spec = BlockSpec {
            index: 1,
            timestamp: 2,
            size: 3,
            tx_count: 1,
            transactions: vec![tx],
            current_hash: current.clone(),
            previous_hash: previous.clone(),
            merkle_root: merkle.clone(),
            guardian_sig: sig.clone(),
        };

        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, 1, 123)?;
        let block = &value["blocks"][0];
        let json_tx = &block["transactions"][0];

        prop_assert_eq!(block.get("current_hash").and_then(Value::as_str), Some(current.as_str()));
        prop_assert_eq!(block.get("previous_hash").and_then(Value::as_str), Some(previous.as_str()));
        prop_assert_eq!(block.get("merkle_root").and_then(Value::as_str), Some(merkle.as_str()));
        prop_assert_eq!(block.get("guardian_sig").and_then(Value::as_str), Some(sig.as_str()));
        prop_assert_eq!(json_tx.get("sender").and_then(Value::as_str), Some(sender.as_str()));
        prop_assert_eq!(json_tx.get("receiver").and_then(Value::as_str), Some(receiver.as_str()));
    }

    // 24/25
    #[test]
    fn audit_json_prop_024_json_uses_snake_case_keys_not_camel_case(
        spec in block_spec_strategy()
    ) {
        let report = report_from_specs(vec![spec]);
        let value = json_value(&report, 0, 123)?;
        let block = value
            .get("blocks")
            .and_then(Value::as_array)
            .and_then(|blocks| blocks.first())
            .and_then(Value::as_object)
            .ok_or_else(|| TestCaseError::fail("first block should be an object"))?;

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
            prop_assert!(block.contains_key(key), "missing expected snake_case key");
        }

        prop_assert!(!block.contains_key("txCount"));
        prop_assert!(!block.contains_key("currentHash"));
        prop_assert!(!block.contains_key("previousHash"));
        prop_assert!(!block.contains_key("merkleRoot"));
        prop_assert!(!block.contains_key("guardianSig"));
    }

    // 25/25
    #[test]
    fn audit_json_prop_025_blake3_digest_of_canonical_bytes_is_stable_and_64_hex_chars(
        specs in block_specs_small(),
        export_time in -2_000_000_000i64..2_000_000_000i64,
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let first_bytes = json_bytes(&report, total_tx, export_time)?;
        let second_bytes = json_bytes(&report, total_tx, export_time)?;

        let first_hash = blake3::hash(&first_bytes).to_hex().to_string();
        let second_hash = blake3::hash(&second_bytes).to_hex().to_string();

        prop_assert_eq!(&first_hash, &second_hash);
        prop_assert_eq!(first_hash.len(), 64);
        prop_assert!(first_hash.as_bytes().iter().all(|b| b.is_ascii_hexdigit()));
    }
}
