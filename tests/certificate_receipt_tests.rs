use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::certificate_receipt::CertificateReceipt;
use remzar::utility::helper::REMZAR_WALLET_LEN;
use serde_json::Value;

type TestResult = Result<(), String>;

fn valid_wallet() -> String {
    format!("r{}", "a".repeat(128))
}

fn other_valid_wallet() -> String {
    format!("r{}", "b".repeat(128))
}

fn valid_receipt() -> CertificateReceipt {
    CertificateReceipt {
        nft_id_hex: "a".repeat(128),
        owner_wallet: valid_wallet(),
        file_name: "certificate.png".to_string(),
        file_size_bytes: 1_234,
        content_hash_hex: "b".repeat(128),
        title: "Certificate Title".to_string(),
        description: "Certificate Description".to_string(),
        created_at_utc: "2026-04-26T00:00:00Z".to_string(),
        edition: Some("1 of 1".to_string()),
        kind: "nft_certificate".to_string(),
        schema: "remzar.certificate.v1".to_string(),
    }
}

fn assert_validation_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected ValidationError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected ValidationError, got Err({error:?})")),
    }
}

#[test]
fn certificate_receipt_001_valid_receipt_passes_validation() -> TestResult {
    let receipt = valid_receipt();

    receipt
        .validate()
        .map_err(|e| format!("valid receipt failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_002_valid_receipt_without_edition_passes_validation() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = None;

    receipt
        .validate()
        .map_err(|e| format!("receipt without edition failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_003_valid_receipt_with_blank_edition_passes_validation() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = Some("   ".to_string());

    receipt
        .validate()
        .map_err(|e| format!("blank optional edition failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_004_validate_trims_boundary_whitespace_on_text_fields() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.title = "  Certificate Title  ".to_string();
    receipt.description = "\nCertificate Description\t".to_string();
    receipt.created_at_utc = "  2026-04-26T00:00:00Z  ".to_string();
    receipt.kind = "\tnft_certificate\n".to_string();
    receipt.schema = "  remzar.certificate.v1  ".to_string();
    receipt.edition = Some("  1 of 10  ".to_string());

    receipt
        .validate()
        .map_err(|e| format!("trimmed text fields failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_005_nft_id_hex_accepts_uppercase_hex() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = "A".repeat(128);

    receipt
        .validate()
        .map_err(|e| format!("uppercase nft_id_hex failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_006_content_hash_hex_accepts_uppercase_hex() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = "F".repeat(128);

    receipt
        .validate()
        .map_err(|e| format!("uppercase content_hash_hex failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_007_hex_fields_accept_boundary_whitespace() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = format!("  {}  ", "a".repeat(128));
    receipt.content_hash_hex = format!("\n{}\t", "b".repeat(128));

    receipt
        .validate()
        .map_err(|e| format!("trimmed hex fields failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_008_owner_wallet_accepts_boundary_whitespace() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!(" \n{}\t ", valid_wallet());

    receipt
        .validate()
        .map_err(|e| format!("trimmed wallet failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_009_file_name_accepts_boundary_whitespace() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "  certificate.png  ".to_string();

    receipt
        .validate()
        .map_err(|e| format!("trimmed file_name failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_010_serializes_expected_snake_case_fields() -> TestResult {
    let receipt = valid_receipt();
    let value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    for field in [
        "nft_id_hex",
        "owner_wallet",
        "file_name",
        "file_size_bytes",
        "content_hash_hex",
        "title",
        "description",
        "created_at_utc",
        "edition",
        "kind",
        "schema",
    ] {
        assert!(
            value.get(field).is_some(),
            "missing serialized field {field}"
        );
    }

    assert!(value.get("nftIdHex").is_none());
    assert!(value.get("ownerWallet").is_none());
    Ok(())
}

#[test]
fn certificate_receipt_011_serde_json_roundtrip_preserves_fields() -> TestResult {
    let receipt = valid_receipt();
    let json = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
    let decoded = serde_json::from_str::<CertificateReceipt>(&json).map_err(|e| e.to_string())?;

    assert_eq!(decoded.nft_id_hex, receipt.nft_id_hex);
    assert_eq!(decoded.owner_wallet, receipt.owner_wallet);
    assert_eq!(decoded.file_name, receipt.file_name);
    assert_eq!(decoded.file_size_bytes, receipt.file_size_bytes);
    assert_eq!(decoded.content_hash_hex, receipt.content_hash_hex);
    assert_eq!(decoded.title, receipt.title);
    assert_eq!(decoded.description, receipt.description);
    assert_eq!(decoded.created_at_utc, receipt.created_at_utc);
    assert_eq!(decoded.edition, receipt.edition);
    assert_eq!(decoded.kind, receipt.kind);
    assert_eq!(decoded.schema, receipt.schema);

    decoded
        .validate()
        .map_err(|e| format!("decoded receipt failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_012_clone_preserves_all_public_fields() -> TestResult {
    let receipt = valid_receipt();
    let cloned = receipt.clone();

    assert_eq!(cloned.nft_id_hex, receipt.nft_id_hex);
    assert_eq!(cloned.owner_wallet, receipt.owner_wallet);
    assert_eq!(cloned.file_name, receipt.file_name);
    assert_eq!(cloned.file_size_bytes, receipt.file_size_bytes);
    assert_eq!(cloned.content_hash_hex, receipt.content_hash_hex);
    assert_eq!(cloned.title, receipt.title);
    assert_eq!(cloned.description, receipt.description);
    assert_eq!(cloned.created_at_utc, receipt.created_at_utc);
    assert_eq!(cloned.edition, receipt.edition);
    assert_eq!(cloned.kind, receipt.kind);
    assert_eq!(cloned.schema, receipt.schema);
    Ok(())
}

#[test]
fn certificate_receipt_013_debug_contains_struct_name_and_public_fields() -> TestResult {
    let receipt = valid_receipt();
    let rendered = format!("{receipt:?}");

    assert!(rendered.contains("CertificateReceipt"));
    assert!(rendered.contains("nft_id_hex"));
    assert!(rendered.contains("owner_wallet"));
    assert!(rendered.contains("file_name"));
    assert!(rendered.contains("content_hash_hex"));
    Ok(())
}

#[test]
fn certificate_receipt_014_nft_id_hex_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_015_nft_id_hex_short_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = "a".repeat(127);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_016_nft_id_hex_long_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = "a".repeat(129);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_017_nft_id_hex_non_hex_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = format!("{}g", "a".repeat(127));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_018_content_hash_hex_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_019_content_hash_hex_short_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = "b".repeat(127);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_020_content_hash_hex_long_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = "b".repeat(129);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_021_content_hash_hex_non_hex_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = format!("{}z", "b".repeat(127));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_022_owner_wallet_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_023_owner_wallet_short_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("r{}", "a".repeat(127));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_024_owner_wallet_long_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("r{}", "a".repeat(129));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_025_owner_wallet_wrong_prefix_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("x{}", "a".repeat(128));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_026_owner_wallet_uppercase_prefix_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("R{}", "a".repeat(128));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_027_owner_wallet_uppercase_body_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("r{}", "A".repeat(128));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_028_owner_wallet_non_hex_body_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("r{}g", "a".repeat(127));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_029_file_name_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_030_file_name_over_255_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "a".repeat(256);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_031_file_name_exactly_255_bytes_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "a".repeat(255);

    receipt
        .validate()
        .map_err(|e| format!("255-byte file_name failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_032_file_name_forward_slash_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "nested/file.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_033_file_name_backslash_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "nested\\file.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_034_file_name_dotdot_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "../file.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_035_file_name_embedded_dotdot_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "safe..name.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_036_file_name_newline_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "bad\nname.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_037_title_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.title.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_038_title_over_2048_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.title = "a".repeat(2_049);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_039_title_exactly_2048_bytes_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.title = "a".repeat(2_048);

    receipt
        .validate()
        .map_err(|e| format!("2048-byte title failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_040_file_size_bytes_zero_is_allowed_by_current_local_receipt_guard()
-> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_size_bytes = 0;

    receipt
        .validate()
        .map_err(|e| format!("zero file_size_bytes failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_041_description_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.description.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_042_description_whitespace_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.description = " \n\t ".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_043_description_exactly_2048_bytes_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.description = "d".repeat(2_048);

    receipt
        .validate()
        .map_err(|e| format!("2048-byte description failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_044_description_over_2048_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.description = "d".repeat(2_049);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_045_created_at_utc_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.created_at_utc.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_046_created_at_utc_whitespace_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.created_at_utc = " \r\n\t ".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_047_created_at_utc_exactly_2048_bytes_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.created_at_utc = "2".repeat(2_048);

    receipt
        .validate()
        .map_err(|e| format!("2048-byte created_at_utc failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_048_created_at_utc_over_2048_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.created_at_utc = "2".repeat(2_049);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_049_kind_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.kind.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_050_kind_whitespace_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.kind = " \t\n ".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_051_kind_over_2048_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.kind = "k".repeat(2_049);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_052_kind_exactly_2048_bytes_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.kind = "k".repeat(2_048);

    receipt
        .validate()
        .map_err(|e| format!("2048-byte kind failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_053_schema_empty_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.schema.clear();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_054_schema_whitespace_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.schema = " \n\t ".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_055_schema_over_2048_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.schema = "s".repeat(2_049);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_056_schema_exactly_2048_bytes_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.schema = "s".repeat(2_048);

    receipt
        .validate()
        .map_err(|e| format!("2048-byte schema failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_057_edition_empty_string_is_allowed() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = Some(String::new());

    receipt
        .validate()
        .map_err(|e| format!("empty optional edition failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_058_edition_whitespace_only_large_is_allowed_after_trim() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = Some(" ".repeat(3_000));

    receipt
        .validate()
        .map_err(|e| format!("large whitespace-only edition failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_059_edition_exactly_2048_bytes_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = Some("e".repeat(2_048));

    receipt
        .validate()
        .map_err(|e| format!("2048-byte edition failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_060_edition_over_2048_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = Some("e".repeat(2_049));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_061_file_name_single_dot_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = ".".to_string();

    receipt
        .validate()
        .map_err(|e| format!("single-dot file_name failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_062_file_name_hidden_dot_file_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = ".certificate".to_string();

    receipt
        .validate()
        .map_err(|e| format!("hidden file_name failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_063_file_name_exact_dotdot_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "..".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_064_file_name_mid_string_dotdot_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "safe..unsafe.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_065_file_name_tab_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "bad\tname.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_066_file_name_nul_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "bad\0name.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_067_file_name_unicode_within_limit_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "証明書_鎖.png".to_string();

    receipt
        .validate()
        .map_err(|e| format!("unicode file_name failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_068_file_name_unicode_over_255_bytes_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "鎖".repeat(86);

    assert!(receipt.file_name.len() > 255);
    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_069_owner_wallet_with_internal_space_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("r{} {}", "a".repeat(63), "b".repeat(64));

    assert_eq!(receipt.owner_wallet.len(), REMZAR_WALLET_LEN);
    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_070_owner_wallet_with_unicode_character_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = format!("r{}鎖{}", "a".repeat(63), "b".repeat(64));

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_071_nft_id_hex_mixed_case_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = "AaBbCcDdEeFf0123456789"
        .repeat(5)
        .chars()
        .chain("AaBbCcDdEeFf012345".chars())
        .collect::<String>();

    assert_eq!(receipt.nft_id_hex.len(), 128);

    receipt
        .validate()
        .map_err(|e| format!("mixed-case nft_id_hex failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_072_content_hash_hex_mixed_case_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = "FfEeDdCcBbAa9876543210"
        .repeat(5)
        .chars()
        .chain("FfEeDdCcBbAa987654".chars())
        .collect::<String>();

    assert_eq!(receipt.content_hash_hex.len(), 128);

    receipt
        .validate()
        .map_err(|e| format!("mixed-case content_hash_hex failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_073_nft_id_hex_internal_space_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = format!("{} {}", "a".repeat(63), "b".repeat(64));

    assert_eq!(receipt.nft_id_hex.len(), 128);
    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_074_content_hash_hex_internal_tab_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = format!("{}\t{}", "a".repeat(63), "b".repeat(64));

    assert_eq!(receipt.content_hash_hex.len(), 128);
    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_075_serde_deserialize_missing_optional_edition_sets_none() -> TestResult {
    let receipt = valid_receipt();
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    value
        .as_object_mut()
        .ok_or_else(|| "receipt JSON was not object".to_string())?
        .remove("edition");

    let decoded = serde_json::from_value::<CertificateReceipt>(value).map_err(|e| e.to_string())?;

    assert_eq!(decoded.edition, None);
    decoded
        .validate()
        .map_err(|e| format!("decoded missing-edition receipt failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_076_serde_deserialize_missing_required_title_rejected() -> TestResult {
    let receipt = valid_receipt();
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    value
        .as_object_mut()
        .ok_or_else(|| "receipt JSON was not object".to_string())?
        .remove("title");

    let decoded = serde_json::from_value::<CertificateReceipt>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn certificate_receipt_077_serde_deserialize_wrong_file_size_type_rejected() -> TestResult {
    let receipt = valid_receipt();
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    value["file_size_bytes"] = Value::from("not-a-number");

    let decoded = serde_json::from_value::<CertificateReceipt>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn certificate_receipt_078_serde_deserialize_negative_file_size_rejected() -> TestResult {
    let receipt = valid_receipt();
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    value["file_size_bytes"] = Value::from(-1);

    let decoded = serde_json::from_value::<CertificateReceipt>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn certificate_receipt_079_load_many_valid_receipts_with_unique_ids_validate() -> TestResult {
    for index in 0_u8..100_u8 {
        let mut receipt = valid_receipt();
        receipt.nft_id_hex = format!("{index:02x}{}", "a".repeat(126));
        receipt.content_hash_hex = format!("{index:02x}{}", "b".repeat(126));
        receipt.file_name = format!("certificate_{index}.png");
        receipt.title = format!("Certificate {index}");
        receipt.edition = Some(format!("Edition {index}"));

        receipt
            .validate()
            .map_err(|e| format!("valid load receipt failed at {index}: {e:?}"))?;
    }

    Ok(())
}

#[test]
fn certificate_receipt_080_load_many_invalid_wallets_reject() -> TestResult {
    for index in 0_u8..50_u8 {
        let mut receipt = valid_receipt();
        receipt.owner_wallet = format!("x{index:02x}{}", "a".repeat(126));

        assert_eq!(receipt.owner_wallet.len(), REMZAR_WALLET_LEN);
        assert_validation_error(receipt.validate())?;
    }

    Ok(())
}

#[test]
fn certificate_receipt_081_title_whitespace_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.title = " \n\t ".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_082_title_unicode_within_byte_limit_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.title = "鎖".repeat(682);

    assert_eq!(receipt.title.len(), 2_046);

    receipt
        .validate()
        .map_err(|e| format!("unicode title within limit failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_083_title_unicode_over_byte_limit_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.title = "鎖".repeat(683);

    assert!(receipt.title.len() > 2_048);
    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_084_description_unicode_within_byte_limit_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.description = "説明".repeat(341);

    assert_eq!(receipt.description.len(), 2_046);

    receipt
        .validate()
        .map_err(|e| format!("unicode description within limit failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_085_description_unicode_over_byte_limit_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.description = "説明".repeat(342);

    assert!(receipt.description.len() > 2_048);
    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_086_edition_unicode_within_byte_limit_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = Some("版".repeat(682));

    assert_eq!(receipt.edition.as_ref().map(String::len), Some(2_046));

    receipt
        .validate()
        .map_err(|e| format!("unicode edition within limit failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_087_edition_unicode_over_byte_limit_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.edition = Some("版".repeat(683));

    assert!(receipt.edition.as_ref().is_some_and(|s| s.len() > 2_048));
    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_088_file_name_carriage_return_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "bad\rname.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_089_file_name_with_safe_spaces_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "certificate final copy.png".to_string();

    receipt
        .validate()
        .map_err(|e| format!("file_name with safe spaces failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_090_file_name_with_double_dot_inside_word_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_name = "certificate..final.png".to_string();

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_091_nft_id_hex_all_zero_vector_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = "0".repeat(128);

    receipt
        .validate()
        .map_err(|e| format!("all-zero nft_id_hex failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_092_content_hash_hex_all_f_vector_accepted() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = "f".repeat(128);

    receipt
        .validate()
        .map_err(|e| format!("all-f content_hash_hex failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_093_nft_id_hex_over_max_hex_guard_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = "a".repeat(513);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_094_content_hash_hex_over_max_hex_guard_rejected() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.content_hash_hex = "b".repeat(513);

    assert_validation_error(receipt.validate())?;
    Ok(())
}

#[test]
fn certificate_receipt_095_file_size_bytes_usize_max_is_allowed_by_current_guard() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.file_size_bytes = usize::MAX;

    receipt
        .validate()
        .map_err(|e| format!("usize::MAX file_size_bytes failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_096_serde_deserialize_null_edition_sets_none() -> TestResult {
    let receipt = valid_receipt();
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    value["edition"] = Value::Null;

    let decoded = serde_json::from_value::<CertificateReceipt>(value).map_err(|e| e.to_string())?;

    assert_eq!(decoded.edition, None);
    decoded
        .validate()
        .map_err(|e| format!("decoded null-edition receipt failed validation: {e:?}"))?;

    Ok(())
}

#[test]
fn certificate_receipt_097_serde_deserialize_null_required_string_rejected() -> TestResult {
    let receipt = valid_receipt();
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    value["schema"] = Value::Null;

    let decoded = serde_json::from_value::<CertificateReceipt>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn certificate_receipt_098_serde_deserialize_unknown_extra_fields_ignored() -> TestResult {
    let receipt = valid_receipt();
    let mut value = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;

    value["future_field"] = Value::from("ignored");

    let decoded = serde_json::from_value::<CertificateReceipt>(value).map_err(|e| e.to_string())?;

    decoded
        .validate()
        .map_err(|e| format!("decoded receipt with extra field failed validation: {e:?}"))?;
    assert_eq!(decoded.nft_id_hex, receipt.nft_id_hex);
    Ok(())
}

#[test]
fn certificate_receipt_099_load_many_valid_receipts_with_optional_edition_none_validate()
-> TestResult {
    for index in 0_u8..100_u8 {
        let mut receipt = valid_receipt();
        receipt.nft_id_hex = format!("{index:02x}{}", "1".repeat(126));
        receipt.content_hash_hex = format!("{index:02x}{}", "2".repeat(126));
        receipt.owner_wallet = other_valid_wallet();
        receipt.file_name = format!("receipt_{index}.json");
        receipt.title = format!("Title {index}");
        receipt.description = format!("Description {index}");
        receipt.edition = None;

        receipt
            .validate()
            .map_err(|e| format!("valid no-edition receipt failed at {index}: {e:?}"))?;
    }

    Ok(())
}

#[test]
fn certificate_receipt_100_load_repeated_edge_receipt_validation_is_stable() -> TestResult {
    let mut receipt = valid_receipt();
    receipt.nft_id_hex = "F".repeat(128);
    receipt.content_hash_hex = "0".repeat(128);
    receipt.file_name = ".certificate".to_string();
    receipt.file_size_bytes = usize::MAX;
    receipt.title = "鎖".repeat(682);
    receipt.description = "d".repeat(2_048);
    receipt.created_at_utc = "2026-04-26T00:00:00Z".to_string();
    receipt.edition = Some(" ".repeat(4_096));
    receipt.kind = "k".repeat(2_048);
    receipt.schema = "s".repeat(2_048);

    for _ in 0..100 {
        receipt
            .validate()
            .map_err(|e| format!("repeated edge receipt validation failed: {e:?}"))?;
    }

    Ok(())
}
