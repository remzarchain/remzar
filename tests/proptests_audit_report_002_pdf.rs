// tests/proptests_audit_report_002_pdf.rs

use proptest::prelude::*;
use proptest::string::string_regex;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::utility::audit_report_001_hub::{AuditBlock, AuditReport, AuditTransaction};
use remzar::utility::audit_report_002_pdf::build_pdf;

use chrono::{TimeZone, Utc};

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

fn fixed_time(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .expect("fixed timestamp should be valid")
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

fn hex_64() -> BoxedStrategy<String> {
    string_regex("[0-9a-f]{64}")
        .expect("valid 64 lowercase hex regex")
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

fn safe_ascii_1_64() -> BoxedStrategy<String> {
    string_regex("[A-Za-z0-9_.:\\-]{1,64}")
        .expect("valid safe ascii regex")
        .boxed()
}

fn unicode_text_0_160() -> BoxedStrategy<String> {
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
        0..160,
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
        proptest::collection::vec(tx_spec_strategy(), 0..6),
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

fn block_specs_many() -> BoxedStrategy<Vec<BlockSpec>> {
    proptest::collection::vec(block_spec_strategy(), 20..80).boxed()
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

fn build_test_pdf(
    report: &AuditReport,
    generated_ts: i64,
    export_ts: i64,
    maybe_fps: Option<(&str, &str)>,
    total_tx: u64,
) -> Result<Vec<u8>, TestCaseError> {
    build_pdf(
        report,
        &fixed_time(generated_ts),
        &fixed_time(export_ts),
        maybe_fps,
        total_tx,
    )
    .map_err(|e| TestCaseError::fail(format!("build_pdf failed: {e:?}")))
}

fn total_tx_from_specs(specs: &[BlockSpec]) -> u64 {
    specs.iter().map(|b| b.tx_count).sum()
}

fn one_block_with_sig(sig: String) -> AuditReport {
    report_from_specs(vec![BlockSpec {
        index: 1,
        timestamp: 123,
        size: 456,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: sig,
    }])
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn audit_pdf_prop_001_empty_report_builds_valid_pdf(_case in any::<u8>()) {
        let report = AuditReport { blocks: Vec::new() };

        let pdf = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, 0)?;

        assert_pdf(&pdf)?;
        prop_assert!(pdf.len() > 100);
    }

    // 02/25
    #[test]
    fn audit_pdf_prop_002_same_report_same_times_same_fps_is_deterministic(
        specs in block_specs_small()
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let first = build_test_pdf(
            &report,
            1_700_000_000,
            1_700_000_001,
            Some(("aabbcc", "ddeeff")),
            total_tx,
        )?;
        let second = build_test_pdf(
            &report,
            1_700_000_000,
            1_700_000_001,
            Some(("aabbcc", "ddeeff")),
            total_tx,
        )?;

        prop_assert_eq!(&first, &second);
        assert_pdf(&first)?;
    }

    // 03/25
    #[test]
    fn audit_pdf_prop_003_generated_timestamp_changes_pdf_bytes(
        specs in block_specs_small()
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let first = build_test_pdf(&report, 1_700_000_000, 1_700_000_010, None, total_tx)?;
        let second = build_test_pdf(&report, 1_700_000_001, 1_700_000_010, None, total_tx)?;

        prop_assert_ne!(&first, &second);
        assert_pdf(&first)?;
        assert_pdf(&second)?;
    }

    // 04/25
    #[test]
    fn audit_pdf_prop_004_export_timestamp_changes_pdf_bytes(
        specs in block_specs_small()
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let first = build_test_pdf(&report, 1_700_000_000, 1_700_000_010, None, total_tx)?;
        let second = build_test_pdf(&report, 1_700_000_000, 1_700_000_011, None, total_tx)?;

        prop_assert_ne!(&first, &second);
        assert_pdf(&first)?;
        assert_pdf(&second)?;
    }

    // 05/25
    #[test]
    fn audit_pdf_prop_005_total_tx_argument_affects_pdf_bytes(
        specs in block_specs_small(),
        first_total in 0u64..1_000_000u64,
        second_total in 0u64..1_000_000u64,
    ) {
        prop_assume!(first_total != second_total);

        let report = report_from_specs(specs);

        let first = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, first_total)?;
        let second = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, second_total)?;

        prop_assert_ne!(&first, &second);
        assert_pdf(&first)?;
        assert_pdf(&second)?;
    }

    // 06/25
    #[test]
    fn audit_pdf_prop_006_fingerprint_none_is_deterministic(
        specs in block_specs_small()
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let first = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, total_tx)?;
        let second = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, total_tx)?;

        prop_assert_eq!(&first, &second);
        assert_pdf(&first)?;
    }

    // 07/25
    #[test]
    fn audit_pdf_prop_007_fingerprint_some_changes_pdf_from_none(
        specs in block_specs_small(),
        data_fp in safe_ascii_1_64(),
        pdf_fp in safe_ascii_1_64(),
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let without_fps = build_test_pdf(
            &report,
            1_700_000_000,
            1_700_000_001,
            None,
            total_tx,
        )?;

        let with_fps = build_test_pdf(
            &report,
            1_700_000_000,
            1_700_000_001,
            Some((data_fp.as_str(), pdf_fp.as_str())),
            total_tx,
        )?;

        prop_assert_ne!(&without_fps, &with_fps);
        assert_pdf(&without_fps)?;
        assert_pdf(&with_fps)?;
    }

    // 08/25
    #[test]
    fn audit_pdf_prop_008_block_count_affects_pdf_bytes(
        specs in block_specs_small()
    ) {
        let report_a = report_from_specs(specs.clone());

        let mut extended = specs;
        extended.push(BlockSpec {
            index: 999_999,
            timestamp: 999_999,
            size: 999,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        });

        let report_b = report_from_specs(extended);

        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, 0)?;
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, 0)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 09/25
    #[test]
    fn audit_pdf_prop_009_single_block_core_fields_affect_pdf_bytes(
        mut spec in block_spec_strategy(),
        replacement_hash in hex_128(),
    ) {
        prop_assume!(spec.current_hash != replacement_hash);

        let total_tx = spec.tx_count;

        let report_a = report_from_specs(vec![spec.clone()]);
        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, total_tx)?;

        spec.current_hash = replacement_hash;

        let report_b = report_from_specs(vec![spec]);
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, total_tx)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 10/25
    #[test]
    fn audit_pdf_prop_010_report_range_duration_inputs_affect_pdf_bytes(
        start_ts in 0u64..1_000_000u64,
        first_delta in 0u64..1_000_000u64,
        second_delta in 0u64..1_000_000u64,
    ) {
        prop_assume!(first_delta != second_delta);

        let first_end_ts = start_ts.saturating_add(first_delta);
        let second_end_ts = start_ts.saturating_add(second_delta);

        let first_a = BlockSpec {
            index: 1,
            timestamp: start_ts,
            size: 100,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let first_b = first_a.clone();

        let second_a = BlockSpec {
            index: 2,
            timestamp: first_end_ts,
            size: 200,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: "e".repeat(128),
            previous_hash: "f".repeat(128),
            merkle_root: "0".repeat(128),
            guardian_sig: "1".repeat(128),
        };

        let second_b = BlockSpec {
            timestamp: second_end_ts,
            ..second_a.clone()
        };

        let report_a = report_from_specs(vec![first_a, second_a]);
        let report_b = report_from_specs(vec![first_b, second_b]);

        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, 0)?;
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, 0)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 11/25
    #[test]
    fn audit_pdf_prop_011_descending_timestamps_still_build_valid_pdf(
        start_ts in 1u64..1_000_000u64,
        backwards in 1u64..1_000_000u64,
    ) {
        let end_ts = start_ts.saturating_sub(backwards);

        let first = BlockSpec {
            index: 1,
            timestamp: start_ts,
            size: 100,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let second = BlockSpec {
            index: 2,
            timestamp: end_ts,
            size: 200,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: "e".repeat(128),
            previous_hash: "f".repeat(128),
            merkle_root: "0".repeat(128),
            guardian_sig: "1".repeat(128),
        };

        let report = report_from_specs(vec![first, second]);
        let pdf = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, 0)?;

        assert_pdf(&pdf)?;
    }

    // 12/25
    #[test]
    fn audit_pdf_prop_012_average_size_inputs_affect_pdf_bytes(
        a in 0u64..1_000_000u64,
        b in 0u64..1_000_000u64,
        c in 0u64..1_000_000u64,
        replacement_c in 0u64..1_000_000u64,
    ) {
        prop_assume!(c != replacement_c);

        let base_specs = vec![
            BlockSpec {
                index: 1,
                timestamp: 100,
                size: a,
                tx_count: 0,
                transactions: Vec::new(),
                current_hash: "a".repeat(128),
                previous_hash: "b".repeat(128),
                merkle_root: "c".repeat(128),
                guardian_sig: "d".repeat(128),
            },
            BlockSpec {
                index: 2,
                timestamp: 200,
                size: b,
                tx_count: 0,
                transactions: Vec::new(),
                current_hash: "e".repeat(128),
                previous_hash: "f".repeat(128),
                merkle_root: "0".repeat(128),
                guardian_sig: "1".repeat(128),
            },
            BlockSpec {
                index: 3,
                timestamp: 300,
                size: c,
                tx_count: 0,
                transactions: Vec::new(),
                current_hash: "2".repeat(128),
                previous_hash: "3".repeat(128),
                merkle_root: "4".repeat(128),
                guardian_sig: "5".repeat(128),
            },
        ];

        let mut changed_specs = base_specs.clone();
        changed_specs[2].size = replacement_c;

        let report_a = report_from_specs(base_specs);
        let report_b = report_from_specs(changed_specs);

        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, 0)?;
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, 0)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 13/25
    #[test]
    fn audit_pdf_prop_013_long_guardian_signature_middle_affects_pdf_via_fingerprint(
        mid_a in hex_64(),
        mid_b in hex_64(),
    ) {
        prop_assume!(mid_a != mid_b);

        let sig_a = format!("{}{}{}", "a".repeat(32), mid_a, "b".repeat(32));
        let sig_b = format!("{}{}{}", "a".repeat(32), mid_b, "b".repeat(32));

        let report_a = one_block_with_sig(sig_a);
        let report_b = one_block_with_sig(sig_b);

        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, 0)?;
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, 0)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 14/25
    #[test]
    fn audit_pdf_prop_014_valid_guardian_signature_variants_build_valid_pdfs(
        sig in string_regex("[0-9a-f]{2,512}").expect("valid hex regex"),
    ) {
        let even_sig = if sig.len() % 2 == 0 {
            sig
        } else {
            format!("{}0", sig)
        };

        let report = one_block_with_sig(even_sig);
        let pdf = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, 0)?;

        assert_pdf(&pdf)?;
    }

    // 15/25
    #[test]
    fn audit_pdf_prop_015_invalid_guardian_signature_hex_still_builds_valid_pdf(
        bad_char in prop_oneof![Just('g'), Just('z'), Just('Z'), Just('_'), Just('-')],
    ) {
        let bad_sig = format!("{}{}{}", "a".repeat(32), bad_char, "b".repeat(32));

        let report = one_block_with_sig(bad_sig);
        let pdf = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, 0)?;

        assert_pdf(&pdf)?;
    }

    // 16/25
    #[test]
    fn audit_pdf_prop_016_unicode_guardian_signature_never_panics(
        unicode_sig in unicode_text_0_160()
    ) {
        let report = one_block_with_sig(unicode_sig);

        let result = std::panic::catch_unwind(|| {
            build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, 0)
        });

        prop_assert!(result.is_ok(), "unicode guardian signature must not panic");

        let pdf = result
            .expect("panic checked above")
            .map_err(|e| TestCaseError::fail(format!("build_test_pdf failed: {e:?}")))?;

        assert_pdf(&pdf)?;
    }

    // 17/25
    #[test]
    fn audit_pdf_prop_017_unicode_hash_like_fields_never_panic(
        current in unicode_text_0_160(),
        previous in unicode_text_0_160(),
        merkle in unicode_text_0_160(),
    ) {
        let spec = BlockSpec {
            index: 1,
            timestamp: 123,
            size: 456,
            tx_count: 0,
            transactions: Vec::new(),
            current_hash: current,
            previous_hash: previous,
            merkle_root: merkle,
            guardian_sig: "ab".repeat(64),
        };

        let report = report_from_specs(vec![spec]);

        let result = std::panic::catch_unwind(|| {
            build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, 0)
        });

        prop_assert!(result.is_ok(), "unicode block display fields must not panic");

        let pdf = result
            .expect("panic checked above")
            .map_err(|e| TestCaseError::fail(format!("build_test_pdf failed: {e:?}")))?;

        assert_pdf(&pdf)?;
    }

    // 18/25
    #[test]
    fn audit_pdf_prop_018_many_blocks_paginate_and_still_build_valid_pdf(
        specs in block_specs_many()
    ) {
        let total_tx = total_tx_from_specs(&specs);
        let report = report_from_specs(specs);

        let pdf = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, total_tx)?;

        assert_pdf(&pdf)?;
        prop_assert!(pdf.len() > 1_000);
    }

    // 19/25
    #[test]
    fn audit_pdf_prop_019_block_order_affects_pdf_output(
        first in block_spec_strategy(),
        second in block_spec_strategy(),
    ) {
        prop_assume!(first.index != second.index || first.timestamp != second.timestamp);

        let report_a = report_from_specs(vec![first.clone(), second.clone()]);
        let report_b = report_from_specs(vec![second, first]);

        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, 0)?;
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, 0)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 20/25
    #[test]
    fn audit_pdf_prop_020_changing_block_size_changes_pdf_output(
        mut spec in block_spec_strategy(),
        new_size in 0u64..10_000_000u64,
    ) {
        prop_assume!(spec.size != new_size);

        let report_a = report_from_specs(vec![spec.clone()]);
        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, spec.tx_count)?;

        spec.size = new_size;

        let report_b = report_from_specs(vec![spec.clone()]);
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, spec.tx_count)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 21/25
    #[test]
    fn audit_pdf_prop_021_changing_hash_field_changes_pdf_output(
        mut spec in block_spec_strategy(),
        replacement_hash in hex_128(),
    ) {
        prop_assume!(spec.current_hash != replacement_hash);

        let report_a = report_from_specs(vec![spec.clone()]);
        let pdf_a = build_test_pdf(&report_a, 1_700_000_000, 1_700_000_001, None, spec.tx_count)?;

        spec.current_hash = replacement_hash;

        let report_b = report_from_specs(vec![spec.clone()]);
        let pdf_b = build_test_pdf(&report_b, 1_700_000_000, 1_700_000_001, None, spec.tx_count)?;

        prop_assert_ne!(&pdf_a, &pdf_b);
        assert_pdf(&pdf_a)?;
        assert_pdf(&pdf_b)?;
    }

    // 22/25
    #[test]
    fn audit_pdf_prop_022_zero_and_maxish_numeric_values_build_valid_pdf(
        index in prop_oneof![Just(0u64), Just(u64::MAX)],
        timestamp in prop_oneof![Just(0u64), Just(u64::MAX)],
        size in prop_oneof![Just(0u64), Just(1_000_000u64)],
        tx_count in prop_oneof![Just(0u64), Just(1_000_000u64)],
    ) {
        let spec = BlockSpec {
            index,
            timestamp,
            size,
            tx_count,
            transactions: Vec::new(),
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let report = report_from_specs(vec![spec]);
        let pdf = build_test_pdf(&report, 0, 1, None, tx_count)?;

        assert_pdf(&pdf)?;
    }

    // 23/25
    #[test]
    fn audit_pdf_prop_023_transaction_list_does_not_break_pdf_generation(
        txs in proptest::collection::vec(tx_spec_strategy(), 0..32)
    ) {
        let spec = BlockSpec {
            index: 1,
            timestamp: 123,
            size: 456,
            tx_count: txs.len() as u64,
            transactions: txs,
            current_hash: "a".repeat(128),
            previous_hash: "b".repeat(128),
            merkle_root: "c".repeat(128),
            guardian_sig: "d".repeat(128),
        };

        let report = report_from_specs(vec![spec]);
        let pdf = build_test_pdf(&report, 1_700_000_000, 1_700_000_001, None, 0)?;

        assert_pdf(&pdf)?;
    }

    // 24/25
    #[test]
    fn audit_pdf_prop_024_fingerprint_values_with_long_text_are_wrapped_safely(
        data_fp in safe_ascii_1_64(),
        pdf_fp in safe_ascii_1_64(),
        repeat_count in 2usize..20usize,
    ) {
        let long_data_fp = data_fp.repeat(repeat_count);
        let long_pdf_fp = pdf_fp.repeat(repeat_count);

        let report = AuditReport { blocks: Vec::new() };

        let pdf = build_test_pdf(
            &report,
            1_700_000_000,
            1_700_000_001,
            Some((long_data_fp.as_str(), long_pdf_fp.as_str())),
            0,
        )?;

        assert_pdf(&pdf)?;
    }

    // 25/25
    #[test]
    fn audit_pdf_prop_025_arbitrary_bounded_report_never_panics(
        specs in block_specs_small(),
        generated_ts in 0i64..2_000_000_000i64,
        export_ts in 0i64..2_000_000_000i64,
        total_tx in 0u64..1_000_000u64,
    ) {
        let report = report_from_specs(specs);

        let result = std::panic::catch_unwind(|| {
            build_test_pdf(&report, generated_ts, export_ts, None, total_tx)
        });

        prop_assert!(result.is_ok(), "bounded audit PDF generation must not panic");

        let pdf = result
            .expect("panic checked above")
            .map_err(|e| TestCaseError::fail(format!("build_test_pdf failed: {e:?}")))?;

        assert_pdf(&pdf)?;
    }
}
