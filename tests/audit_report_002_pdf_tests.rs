use chrono::{TimeZone, Utc};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::audit_report_001_hub::{AuditBlock, AuditReport, AuditTransaction};
use remzar::utility::audit_report_002_pdf::build_pdf;

type TestResult = Result<(), String>;

fn fixed_ts(seconds: i64) -> Result<chrono::DateTime<Utc>, String> {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .ok_or_else(|| format!("failed to construct timestamp {seconds}"))
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
        blocks: vec![sample_block(1, 1_700_000_000, 1)],
    }
}

fn multi_block_report(block_count: u64) -> AuditReport {
    let blocks = (0_u64..block_count)
        .map(|index| sample_block(index, 1_700_000_000_u64.saturating_add(index), 1))
        .collect::<Vec<_>>();

    AuditReport { blocks }
}

fn build_test_pdf(report: &AuditReport) -> Result<Vec<u8>, String> {
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    build_pdf(report, &generated, &exported, None, 0).map_err(|e| e.to_string())
}

fn build_test_pdf_with_fps(report: &AuditReport) -> Result<Vec<u8>, String> {
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    build_pdf(
        report,
        &generated,
        &exported,
        Some((
            "data-fingerprint-abcdefghijklmnopqrstuvwxyz0123456789",
            "pdf-fingerprint-abcdefghijklmnopqrstuvwxyz0123456789",
        )),
        777,
    )
    .map_err(|e| e.to_string())
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn assert_pdf_shape(bytes: &[u8]) {
    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes_contain(bytes, b"%%EOF"));
    assert!(bytes_contain(bytes, b"/Pages"));
    assert!(bytes_contain(bytes, b"/Type /Page"));
    assert!(bytes_contain(bytes, b"/Courier"));
}

#[test]
fn audit_pdf_001_empty_report_builds_valid_pdf() -> TestResult {
    let report = empty_report();
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 100);
    Ok(())
}

#[test]
fn audit_pdf_002_sample_report_builds_valid_pdf() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 100);
    Ok(())
}

#[test]
fn audit_pdf_003_pdf_starts_with_pdf_header_vector() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes.starts_with(b"%PDF"));
    Ok(())
}

#[test]
fn audit_pdf_004_pdf_contains_eof_marker_vector() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"%%EOF"));
    Ok(())
}

#[test]
fn audit_pdf_005_pdf_contains_courier_font_resource() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"/Courier"));
    assert!(bytes_contain(&bytes, b"/F1"));
    Ok(())
}

#[test]
fn audit_pdf_006_empty_report_contains_pages_tree_and_one_page() -> TestResult {
    let report = empty_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"/Type /Pages"));
    assert!(bytes_contain(&bytes, b"/Type /Page"));
    assert!(count_occurrences(&bytes, b"/Type /Page") >= 1);
    Ok(())
}

#[test]
fn audit_pdf_007_sample_report_contains_stream_objects() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"stream"));
    assert!(bytes_contain(&bytes, b"endstream"));
    Ok(())
}

#[test]
fn audit_pdf_008_same_input_is_deterministic() -> TestResult {
    let report = sample_report();

    let first = build_test_pdf(&report)?;
    let second = build_test_pdf(&report)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn audit_pdf_009_different_export_time_changes_pdf_bytes() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let export_a = fixed_ts(1_700_000_100)?;
    let export_b = fixed_ts(1_700_000_101)?;

    let bytes_a = build_pdf(&report, &generated, &export_a, None, 1).map_err(|e| e.to_string())?;
    let bytes_b = build_pdf(&report, &generated, &export_b, None, 1).map_err(|e| e.to_string())?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_010_different_generated_time_changes_pdf_bytes() -> TestResult {
    let report = sample_report();
    let generated_a = fixed_ts(1_700_000_000)?;
    let generated_b = fixed_ts(1_700_000_001)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes_a =
        build_pdf(&report, &generated_a, &exported, None, 1).map_err(|e| e.to_string())?;
    let bytes_b =
        build_pdf(&report, &generated_b, &exported, None, 1).map_err(|e| e.to_string())?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_011_total_transaction_count_changes_pdf_bytes() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes_a = build_pdf(&report, &generated, &exported, None, 1).map_err(|e| e.to_string())?;
    let bytes_b = build_pdf(&report, &generated, &exported, None, 2).map_err(|e| e.to_string())?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_012_optional_fingerprints_change_pdf_bytes() -> TestResult {
    let report = sample_report();

    let without = build_test_pdf(&report)?;
    let with = build_test_pdf_with_fps(&report)?;

    assert_ne!(without, with);
    assert_pdf_shape(&with);
    Ok(())
}

#[test]
fn audit_pdf_013_optional_fingerprints_are_deterministic() -> TestResult {
    let report = sample_report();

    let first = build_test_pdf_with_fps(&report)?;
    let second = build_test_pdf_with_fps(&report)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn audit_pdf_014_zero_total_tx_is_allowed() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes = build_pdf(&report, &generated, &exported, None, 0).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_015_u64_max_total_tx_is_allowed() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes =
        build_pdf(&report, &generated, &exported, None, u64::MAX).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_016_report_with_zero_blocks_has_valid_summary() -> TestResult {
    let report = empty_report();
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 100);
    Ok(())
}

#[test]
fn audit_pdf_017_report_with_single_block_has_valid_pdf() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_018_report_with_multiple_blocks_has_valid_pdf() -> TestResult {
    let report = multi_block_report(5);
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > build_test_pdf(&empty_report())?.len());
    Ok(())
}

#[test]
fn audit_pdf_019_large_report_forces_pagination_and_valid_pdf() -> TestResult {
    let report = multi_block_report(80);
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(count_occurrences(&bytes, b"/Type /Page") > 1);
    Ok(())
}

#[test]
fn audit_pdf_020_many_blocks_pdf_is_deterministic() -> TestResult {
    let report = multi_block_report(40);

    let first = build_test_pdf(&report)?;
    let second = build_test_pdf(&report)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn audit_pdf_021_empty_hash_strings_do_not_panic() -> TestResult {
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

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_022_short_signature_hex_does_not_panic() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.guardian_sig = "abcd".to_string();
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_023_invalid_signature_hex_uses_safe_fallback_and_valid_pdf() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.guardian_sig = "not-valid-hex".to_string();
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_024_odd_length_signature_hex_uses_safe_fallback_and_valid_pdf() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.guardian_sig = "abc".to_string();
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_025_long_signature_hex_is_previewed_without_exploding_size() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.guardian_sig = "d".repeat(100_000);
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() < 50_000);
    Ok(())
}

#[test]
fn audit_pdf_026_long_current_hash_wraps_without_panic() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.current_hash = "a".repeat(4_096);
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 1_000);
    Ok(())
}

#[test]
fn audit_pdf_027_long_previous_hash_wraps_without_panic() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.previous_hash = "b".repeat(4_096);
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 1_000);
    Ok(())
}

#[test]
fn audit_pdf_028_long_merkle_root_wraps_without_panic() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.merkle_root = "c".repeat(4_096);
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 1_000);
    Ok(())
}

#[test]
fn audit_pdf_029_unicode_hash_like_fields_do_not_panic() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: "鎖".repeat(200),
        previous_hash: "данные".repeat(100),
        merkle_root: "ブロック".repeat(100),
        guardian_sig: "nothex鎖".to_string(),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_030_unicode_exactly_around_wrap_boundary_does_not_panic() -> TestResult {
    let block = AuditBlock {
        index: 1,
        timestamp: 2,
        size: 3,
        tx_count: 0,
        transactions: Vec::new(),
        current_hash: "鎖".repeat(80),
        previous_hash: "鎖".repeat(81),
        merkle_root: "鎖".repeat(159),
        guardian_sig: "badhex鎖".to_string(),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_031_max_u64_block_fields_are_allowed() -> TestResult {
    let block = AuditBlock {
        index: u64::MAX,
        timestamp: u64::MAX,
        size: u64::MAX,
        tx_count: u64::MAX,
        transactions: Vec::new(),
        current_hash: "a".repeat(128),
        previous_hash: "b".repeat(128),
        merkle_root: "c".repeat(128),
        guardian_sig: "d".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)),
    };
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_032_out_of_order_blocks_are_allowed_and_deterministic() -> TestResult {
    let report = AuditReport {
        blocks: vec![
            sample_block(10, 2_000, 1),
            sample_block(2, 1_000, 1),
            sample_block(7, 1_500, 1),
        ],
    };

    let first = build_test_pdf(&report)?;
    let second = build_test_pdf(&report)?;

    assert_eq!(first, second);
    assert_pdf_shape(&first);
    Ok(())
}

#[test]
fn audit_pdf_033_zero_size_block_is_allowed_in_report_pdf() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.size = 0;
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_034_block_with_mismatched_tx_count_and_transactions_is_allowed() -> TestResult {
    let mut block = sample_block(1, 2, 99);
    block.transactions.clear();
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_035_large_fingerprints_wrap_without_panic() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;
    let data_fp = "data".repeat(1_000);
    let pdf_fp = "pdf".repeat(1_000);

    let bytes = build_pdf(&report, &generated, &exported, Some((&data_fp, &pdf_fp)), 1)
        .map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 1_000);
    Ok(())
}

#[test]
fn audit_pdf_036_empty_fingerprints_are_allowed() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes =
        build_pdf(&report, &generated, &exported, Some(("", "")), 1).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_037_pdf_size_grows_when_blocks_are_added() -> TestResult {
    let empty = build_test_pdf(&empty_report())?;
    let one = build_test_pdf(&multi_block_report(1))?;
    let ten = build_test_pdf(&multi_block_report(10))?;

    assert!(one.len() > empty.len());
    assert!(ten.len() > one.len());
    Ok(())
}

#[test]
fn audit_pdf_038_load_many_small_reports_property_valid_pdf() -> TestResult {
    for count in 0_u64..20_u64 {
        let report = multi_block_report(count);
        let bytes = build_test_pdf(&report)?;

        assert_pdf_shape(&bytes);
    }

    Ok(())
}

#[test]
fn audit_pdf_039_repeated_pdf_generation_for_large_report_is_stable() -> TestResult {
    let report = multi_block_report(25);
    let baseline = build_test_pdf(&report)?;

    for _ in 0..50 {
        let next = build_test_pdf(&report)?;
        assert_eq!(next, baseline);
    }

    Ok(())
}

#[test]
fn audit_pdf_040_build_pdf_load_test_many_blocks_valid_shape() -> TestResult {
    let report = multi_block_report(120);
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(count_occurrences(&bytes, b"/Type /Page") > 1);
    assert!(bytes.len() > 5_000);
    Ok(())
}

#[test]
fn audit_pdf_041_pdf_contains_catalog_and_page_tree_objects() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"/Type /Catalog"));
    assert!(bytes_contain(&bytes, b"/Type /Pages"));
    assert!(bytes_contain(&bytes, b"/Kids"));
    assert!(bytes_contain(&bytes, b"/Count"));
    Ok(())
}

#[test]
fn audit_pdf_042_pdf_contains_media_box_for_a4_page_vector() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"/MediaBox"));
    assert!(bytes_contain(&bytes, b"595"));
    assert!(bytes_contain(&bytes, b"842"));
    Ok(())
}

#[test]
fn audit_pdf_043_pdf_contains_content_stream_for_each_page() -> TestResult {
    let report = multi_block_report(80);
    let bytes = build_test_pdf(&report)?;

    let page_count = count_occurrences(&bytes, b"/Type /Page");
    let stream_count = count_occurrences(&bytes, b"stream");

    assert!(page_count > 1);
    assert!(stream_count >= page_count);
    Ok(())
}

#[test]
fn audit_pdf_044_pdf_contains_xref_and_trailer_sections() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"xref"));
    assert!(bytes_contain(&bytes, b"trailer"));
    assert!(bytes_contain(&bytes, b"startxref"));
    Ok(())
}

#[test]
fn audit_pdf_045_pdf_contains_root_reference_in_trailer() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(bytes_contain(&bytes, b"/Root"));
    assert!(bytes_contain(&bytes, b"1 0 R"));
    Ok(())
}

#[test]
fn audit_pdf_046_pdf_generation_is_stable_with_empty_report_and_fingerprints() -> TestResult {
    let report = empty_report();

    let first = build_test_pdf_with_fps(&report)?;
    let second = build_test_pdf_with_fps(&report)?;

    assert_eq!(first, second);
    assert_pdf_shape(&first);
    Ok(())
}

#[test]
fn audit_pdf_047_fingerprint_presence_increases_empty_report_pdf_size() -> TestResult {
    let report = empty_report();

    let without = build_test_pdf(&report)?;
    let with = build_test_pdf_with_fps(&report)?;

    assert!(with.len() > without.len());
    Ok(())
}

#[test]
fn audit_pdf_048_different_data_fingerprint_changes_pdf_bytes() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes_a = build_pdf(
        &report,
        &generated,
        &exported,
        Some(("data-fp-a", "pdf-fp")),
        1,
    )
    .map_err(|e| e.to_string())?;

    let bytes_b = build_pdf(
        &report,
        &generated,
        &exported,
        Some(("data-fp-b", "pdf-fp")),
        1,
    )
    .map_err(|e| e.to_string())?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_049_different_pdf_fingerprint_changes_pdf_bytes() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes_a = build_pdf(
        &report,
        &generated,
        &exported,
        Some(("data-fp", "pdf-fp-a")),
        1,
    )
    .map_err(|e| e.to_string())?;

    let bytes_b = build_pdf(
        &report,
        &generated,
        &exported,
        Some(("data-fp", "pdf-fp-b")),
        1,
    )
    .map_err(|e| e.to_string())?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_050_negative_unix_timestamps_are_allowed() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(-1)?;
    let exported = fixed_ts(-2)?;

    let bytes = build_pdf(&report, &generated, &exported, None, 1).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_051_far_future_unix_timestamps_are_allowed() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(4_102_444_800)?;
    let exported = fixed_ts(4_102_444_900)?;

    let bytes = build_pdf(&report, &generated, &exported, None, 1).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_052_same_generated_and_export_time_is_allowed() -> TestResult {
    let report = sample_report();
    let ts = fixed_ts(1_700_000_000)?;

    let bytes = build_pdf(&report, &ts, &ts, None, 1).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_053_export_time_before_generated_time_is_allowed() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_100)?;
    let exported = fixed_ts(1_700_000_000)?;

    let bytes = build_pdf(&report, &generated, &exported, None, 1).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_054_reversed_block_timestamps_are_allowed() -> TestResult {
    let report = AuditReport {
        blocks: vec![
            sample_block(1, 3_000, 1),
            sample_block(2, 2_000, 1),
            sample_block(3, 1_000, 1),
        ],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_055_duplicate_block_indexes_are_allowed() -> TestResult {
    let report = AuditReport {
        blocks: vec![
            sample_block(9, 1_000, 1),
            sample_block(9, 2_000, 1),
            sample_block(9, 3_000, 1),
        ],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_056_block_with_empty_transaction_vector_and_nonzero_total_tx_is_allowed() -> TestResult
{
    let mut block = sample_block(1, 2, 0);
    block.transactions.clear();

    let report = AuditReport {
        blocks: vec![block],
    };
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes = build_pdf(&report, &generated, &exported, None, 999).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_057_transaction_payload_changes_do_not_change_pdf_when_total_tx_is_same() -> TestResult
{
    let mut block_a = sample_block(1, 2, 1);
    block_a.transactions = vec![sample_tx("transfer", Some("a"), Some("b"), Some(1))];

    let mut block_b = sample_block(1, 2, 1);
    block_b.transactions = vec![
        sample_tx("reward", None, Some("miner"), Some(999)),
        sample_tx("nft_transfer", None, Some("owner"), None),
    ];

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes_a =
        build_pdf(&report_a, &generated, &exported, None, 1).map_err(|e| e.to_string())?;
    let bytes_b =
        build_pdf(&report_b, &generated, &exported, None, 1).map_err(|e| e.to_string())?;

    assert_eq!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_058_tx_count_field_changes_do_not_change_pdf_when_total_tx_is_same() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 999);

    block_a.transactions.clear();
    block_b.transactions.clear();

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_eq!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_059_block_size_change_changes_pdf_bytes() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    let mut block_b = sample_block(1, 2, 1);
    block_a.size = 1_000;
    block_b.size = 2_000;

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_060_block_index_change_changes_pdf_bytes() -> TestResult {
    let block_a = sample_block(1, 2, 1);
    let block_b = sample_block(2, 2, 1);

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_061_block_timestamp_change_changes_pdf_bytes() -> TestResult {
    let block_a = sample_block(1, 2, 1);
    let block_b = sample_block(1, 3, 1);

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_062_current_hash_change_changes_pdf_bytes() -> TestResult {
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

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_063_previous_hash_change_changes_pdf_bytes() -> TestResult {
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

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_064_merkle_root_change_changes_pdf_bytes() -> TestResult {
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

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_065_guardian_signature_change_changes_pdf_bytes() -> TestResult {
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

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_ne!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_066_one_page_report_has_fewer_page_objects_than_large_report() -> TestResult {
    let small = build_test_pdf(&sample_report())?;
    let large = build_test_pdf(&multi_block_report(120))?;

    assert!(count_occurrences(&large, b"/Type /Page") > count_occurrences(&small, b"/Type /Page"));
    Ok(())
}

#[test]
fn audit_pdf_067_many_pages_still_have_single_pages_tree() -> TestResult {
    let report = multi_block_report(150);
    let bytes = build_test_pdf(&report)?;

    assert!(count_occurrences(&bytes, b"/Type /Pages") >= 1);
    assert!(count_occurrences(&bytes, b"/Type /Page") > 1);
    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_068_report_with_boundary_58_blocks_builds_valid_pdf() -> TestResult {
    let report = multi_block_report(58);
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_069_report_with_boundary_59_blocks_builds_valid_pdf() -> TestResult {
    let report = multi_block_report(59);
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_070_report_with_boundary_60_blocks_builds_valid_pdf() -> TestResult {
    let report = multi_block_report(60);
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_071_long_ascii_fingerprints_do_not_break_pagination() -> TestResult {
    let report = multi_block_report(60);
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;
    let data_fp = "a".repeat(10_000);
    let pdf_fp = "b".repeat(10_000);

    let bytes = build_pdf(
        &report,
        &generated,
        &exported,
        Some((&data_fp, &pdf_fp)),
        123,
    )
    .map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    assert!(count_occurrences(&bytes, b"/Type /Page") > 1);
    Ok(())
}

#[test]
fn audit_pdf_072_unicode_fingerprints_do_not_panic() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;
    let data_fp = "鎖".repeat(250);
    let pdf_fp = "данные".repeat(250);

    let bytes = build_pdf(
        &report,
        &generated,
        &exported,
        Some((&data_fp, &pdf_fp)),
        123,
    )
    .map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_073_multiple_invalid_signature_hex_blocks_build_valid_pdf() -> TestResult {
    let blocks = (0_u64..25_u64)
        .map(|index| {
            let mut block = sample_block(index, index.saturating_add(10), 0);
            block.guardian_sig = format!("invalid-hex-{index}-鎖");
            block
        })
        .collect::<Vec<_>>();

    let report = AuditReport { blocks };
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_074_multiple_empty_field_blocks_build_valid_pdf() -> TestResult {
    let blocks = (0_u64..25_u64)
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

    let report = AuditReport { blocks };
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_075_report_with_very_large_hash_fields_remains_valid_pdf() -> TestResult {
    let blocks = (0_u64..5_u64)
        .map(|index| {
            let mut block = sample_block(index, index.saturating_add(1), 0);
            block.current_hash = "a".repeat(8_192);
            block.previous_hash = "b".repeat(8_192);
            block.merkle_root = "c".repeat(8_192);
            block.guardian_sig = "d".repeat(8_192);
            block
        })
        .collect::<Vec<_>>();

    let report = AuditReport { blocks };
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() > 10_000);
    Ok(())
}

#[test]
fn audit_pdf_076_pdf_contains_expected_number_of_eof_markers() -> TestResult {
    let report = multi_block_report(20);
    let bytes = build_test_pdf(&report)?;

    assert_eq!(count_occurrences(&bytes, b"%%EOF"), 1);
    Ok(())
}

#[test]
fn audit_pdf_077_pdf_contains_at_least_one_obj_and_endobj_pair() -> TestResult {
    let report = sample_report();
    let bytes = build_test_pdf(&report)?;

    assert!(count_occurrences(&bytes, b" obj") > 0);
    assert!(count_occurrences(&bytes, b"endobj") > 0);
    Ok(())
}

#[test]
fn audit_pdf_078_every_generated_pdf_has_more_endobj_than_zero() -> TestResult {
    for count in 0_u64..15_u64 {
        let report = multi_block_report(count);
        let bytes = build_test_pdf(&report)?;

        assert!(count_occurrences(&bytes, b"endobj") > 0);
        assert_pdf_shape(&bytes);
    }

    Ok(())
}

#[test]
fn audit_pdf_079_load_repeated_large_fingerprint_generation_is_stable() -> TestResult {
    let report = multi_block_report(10);
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;
    let data_fp = "data-fp".repeat(500);
    let pdf_fp = "pdf-fp".repeat(500);

    let baseline = build_pdf(
        &report,
        &generated,
        &exported,
        Some((&data_fp, &pdf_fp)),
        123,
    )
    .map_err(|e| e.to_string())?;

    for _ in 0..25 {
        let next = build_pdf(
            &report,
            &generated,
            &exported,
            Some((&data_fp, &pdf_fp)),
            123,
        )
        .map_err(|e| e.to_string())?;

        assert_eq!(next, baseline);
    }

    Ok(())
}

#[test]
fn audit_pdf_080_load_many_signature_lengths_build_valid_pdf() -> TestResult {
    for len in [0_usize, 1, 2, 3, 4, 63, 64, 65, 128, 1_024, 8_192] {
        let mut block = sample_block(u64::try_from(len).map_err(|e| e.to_string())?, 2, 0);
        block.guardian_sig = "a".repeat(len);

        let report = AuditReport {
            blocks: vec![block],
        };
        let bytes = build_test_pdf(&report)?;

        assert_pdf_shape(&bytes);
    }

    Ok(())
}

#[test]
fn audit_pdf_081_empty_report_with_u64_max_total_tx_builds_valid_pdf() -> TestResult {
    let report = empty_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes =
        build_pdf(&report, &generated, &exported, None, u64::MAX).map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_082_empty_report_with_empty_fingerprints_is_deterministic() -> TestResult {
    let report = empty_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let first =
        build_pdf(&report, &generated, &exported, Some(("", "")), 0).map_err(|e| e.to_string())?;
    let second =
        build_pdf(&report, &generated, &exported, Some(("", "")), 0).map_err(|e| e.to_string())?;

    assert_eq!(first, second);
    assert_pdf_shape(&first);
    Ok(())
}

#[test]
fn audit_pdf_083_some_empty_fingerprints_differs_from_none_fingerprints() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let without = build_pdf(&report, &generated, &exported, None, 1).map_err(|e| e.to_string())?;
    let with_empty =
        build_pdf(&report, &generated, &exported, Some(("", "")), 1).map_err(|e| e.to_string())?;

    assert_ne!(without, with_empty);
    assert_pdf_shape(&with_empty);
    Ok(())
}

#[test]
fn audit_pdf_084_data_fingerprint_empty_pdf_fingerprint_nonempty_builds_valid_pdf() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes = build_pdf(&report, &generated, &exported, Some(("", "pdf-only")), 1)
        .map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_085_data_fingerprint_nonempty_pdf_fingerprint_empty_builds_valid_pdf() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;

    let bytes = build_pdf(&report, &generated, &exported, Some(("data-only", "")), 1)
        .map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_086_report_with_timestamp_span_from_u64_max_to_zero_is_valid() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(1, u64::MAX, 1), sample_block(2, 0, 1)],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_087_report_with_zero_to_u64_max_timestamp_span_is_valid() -> TestResult {
    let report = AuditReport {
        blocks: vec![sample_block(1, 0, 1), sample_block(2, u64::MAX, 1)],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_088_large_but_safe_block_sizes_build_valid_average_summary() -> TestResult {
    let safe_large_size = u64::MAX / 4;
    let blocks = (0_u64..4_u64)
        .map(|index| {
            let mut block = sample_block(index, index.saturating_add(1), 0);
            block.size = safe_large_size;
            block
        })
        .collect::<Vec<_>>();

    let report = AuditReport { blocks };
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_089_many_zero_size_blocks_build_valid_pdf() -> TestResult {
    let blocks = (0_u64..50_u64)
        .map(|index| {
            let mut block = sample_block(index, index.saturating_add(10), 0);
            block.size = 0;
            block
        })
        .collect::<Vec<_>>();

    let report = AuditReport { blocks };
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(count_occurrences(&bytes, b"/Type /Page") >= 1);
    Ok(())
}

#[test]
fn audit_pdf_090_transaction_vector_size_is_ignored_by_pdf_detail_output() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    block_a.transactions = Vec::new();

    let mut block_b = sample_block(1, 2, 1);
    block_b.transactions = (0_u64..1_000_u64)
        .map(|index| sample_tx("transfer", Some("sender"), Some("receiver"), Some(index)))
        .collect::<Vec<_>>();

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_eq!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_091_unicode_transaction_payload_is_ignored_by_pdf_detail_output() -> TestResult {
    let mut block_a = sample_block(1, 2, 1);
    block_a.transactions = vec![sample_tx("transfer", Some("ascii"), Some("ascii"), Some(1))];

    let mut block_b = sample_block(1, 2, 1);
    block_b.transactions = vec![sample_tx(
        "transfer",
        Some("sender-鎖-данные"),
        Some("receiver-ブロック"),
        Some(1),
    )];

    let report_a = AuditReport {
        blocks: vec![block_a],
    };
    let report_b = AuditReport {
        blocks: vec![block_b],
    };

    let bytes_a = build_test_pdf(&report_a)?;
    let bytes_b = build_test_pdf(&report_b)?;

    assert_eq!(bytes_a, bytes_b);
    Ok(())
}

#[test]
fn audit_pdf_092_uppercase_signature_hex_builds_valid_pdf() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.guardian_sig = "A".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2));
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_093_mixed_case_signature_hex_builds_valid_pdf() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.guardian_sig = "aB".repeat(GlobalConfiguration::GUARDIAN_SIG_LEN);
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_094_guardian_sig_preview_keeps_huge_signature_pdf_bounded() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    block.guardian_sig = "b".repeat(1_000_000);
    let report = AuditReport {
        blocks: vec![block],
    };

    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(bytes.len() < 60_000);
    Ok(())
}

#[test]
fn audit_pdf_095_huge_current_hash_increases_pdf_more_than_huge_signature() -> TestResult {
    let mut hash_block = sample_block(1, 2, 0);
    hash_block.current_hash = "a".repeat(50_000);

    let mut sig_block = sample_block(1, 2, 0);
    sig_block.guardian_sig = "b".repeat(50_000);

    let hash_pdf = build_test_pdf(&AuditReport {
        blocks: vec![hash_block],
    })?;
    let sig_pdf = build_test_pdf(&AuditReport {
        blocks: vec![sig_block],
    })?;

    assert!(hash_pdf.len() > sig_pdf.len());
    assert_pdf_shape(&hash_pdf);
    assert_pdf_shape(&sig_pdf);
    Ok(())
}

#[test]
fn audit_pdf_096_pagination_with_long_hash_fields_has_multiple_pages() -> TestResult {
    let blocks = (0_u64..8_u64)
        .map(|index| {
            let mut block = sample_block(index, index.saturating_add(1), 0);
            block.current_hash = "a".repeat(10_000);
            block.previous_hash = "b".repeat(10_000);
            block.merkle_root = "c".repeat(10_000);
            block
        })
        .collect::<Vec<_>>();

    let report = AuditReport { blocks };
    let bytes = build_test_pdf(&report)?;

    assert_pdf_shape(&bytes);
    assert!(count_occurrences(&bytes, b"/Type /Page") > 1);
    Ok(())
}

#[test]
fn audit_pdf_097_pagination_with_long_fingerprints_has_multiple_pages() -> TestResult {
    let report = sample_report();
    let generated = fixed_ts(1_700_000_000)?;
    let exported = fixed_ts(1_700_000_100)?;
    let data_fp = "data-fingerprint-".repeat(2_000);
    let pdf_fp = "pdf-fingerprint-".repeat(2_000);

    let bytes = build_pdf(&report, &generated, &exported, Some((&data_fp, &pdf_fp)), 1)
        .map_err(|e| e.to_string())?;

    assert_pdf_shape(&bytes);
    assert!(count_occurrences(&bytes, b"/Type /Page") > 1);
    Ok(())
}

#[test]
fn audit_pdf_098_many_tiny_reports_have_stable_pdf_headers_and_eof() -> TestResult {
    for index in 0_u64..50_u64 {
        let report = AuditReport {
            blocks: vec![sample_block(
                index,
                index.saturating_add(100),
                index.rem_euclid(3),
            )],
        };
        let bytes = build_test_pdf(&report)?;

        assert!(bytes.starts_with(b"%PDF"));
        assert!(bytes_contain(&bytes, b"%%EOF"));
    }

    Ok(())
}

#[test]
fn audit_pdf_099_report_with_exact_signature_hex_length_vector_builds_valid_pdf() -> TestResult {
    let mut block = sample_block(1, 2, 0);
    let expected_hex_len = GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2);
    block.guardian_sig = "d".repeat(expected_hex_len);

    let report = AuditReport {
        blocks: vec![block],
    };
    let bytes = build_test_pdf(&report)?;

    assert_eq!(
        expected_hex_len,
        GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_mul(2)
    );
    assert_pdf_shape(&bytes);
    Ok(())
}

#[test]
fn audit_pdf_100_load_build_pdf_repeatedly_with_edge_blocks_valid_shape() -> TestResult {
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
                size: u64::MAX / 2,
                tx_count: u64::MAX,
                transactions: vec![sample_tx("future_kind", None, None, Some(u64::MAX))],
                current_hash: "鎖".repeat(128),
                previous_hash: "b".repeat(128),
                merkle_root: "c".repeat(128),
                guardian_sig: "not-hex".to_string(),
            },
        ],
    };

    let baseline = build_test_pdf(&report)?;
    assert_pdf_shape(&baseline);

    for _ in 0..25 {
        let next = build_test_pdf(&report)?;
        assert_eq!(next, baseline);
        assert_pdf_shape(&next);
    }

    Ok(())
}
