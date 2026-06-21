// tests/digital_id_receipt_tests.rs

use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::digital_id_receipt::{
    DIGITAL_PASSPORT_KIND, DIGITAL_PASSPORT_SCHEMA, DigitalPassport, DigitalPassportFields,
};
use remzar::utility::helper::REMZAR_WALLET_LEN;

use fips204::ml_dsa_65;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = Result<(), String>;

const TEST_PASSPHRASE: &str = "remzar-digital-id-test-passphrase-2026!";

static TEST_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static OTHER_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);
static DIGITAL_ID_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn run_serial<F>(f: F) -> TestResult
where
    F: FnOnce() -> TestResult,
{
    let lock = DIGITAL_ID_TEST_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    f()
}

fn test_wallet() -> &'static MLDSA65Wallet {
    TEST_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(TEST_PASSPHRASE).expect("test wallet generation should succeed")
    })
}

fn other_wallet() -> &'static MLDSA65Wallet {
    OTHER_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(TEST_PASSPHRASE).expect("second test wallet generation should succeed")
    })
}

fn passport_id_hex(id: u64) -> String {
    format!("{id:0128x}")
}

fn assert_lower_hex_len(value: &str, expected_len: usize) {
    assert_eq!(value.len(), expected_len);
    assert!(value.as_bytes().iter().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(value, value.to_ascii_lowercase());
}

fn assert_png(bytes: &[u8]) {
    assert!(bytes.len() > 8);
    assert_eq!(
        &bytes[..8],
        &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n']
    );
}

fn assert_pdf(bytes: &[u8]) {
    assert!(bytes.len() > 4);
    assert_eq!(&bytes[..4], b"%PDF");
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

fn assert_cryptographic_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::CryptographicError { message }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected CryptographicError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected CryptographicError, got Err({error:?})")),
    }
}

fn assert_any_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Ok(_) => Err("expected Err(_), got Ok(_)".to_string()),
        Err(_) => Ok(()),
    }
}

fn ok<T>(result: Result<T, ErrorDetection>, context: &str) -> Result<T, String> {
    result.map_err(|e| format!("{context}: {e:?}"))
}

fn valid_fields() -> Result<DigitalPassportFields, ErrorDetection> {
    DigitalPassportFields::from_raw(
        "Alice Remzar".to_string(),
        "1985-04-22".to_string(),
        "F".to_string(),
        "170cm".to_string(),
        "Canadian".to_string(),
        "Canada".to_string(),
        "123 Blockchain Street".to_string(),
        "Developer".to_string(),
    )
}

fn minimal_name_fields() -> Result<DigitalPassportFields, ErrorDetection> {
    DigitalPassportFields::from_raw(
        "Alice".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
    )
}

fn all_fields_vector() -> Result<DigitalPassportFields, ErrorDetection> {
    DigitalPassportFields::from_raw(
        "Vector Name".to_string(),
        "1888-44-55".to_string(),
        "Self-declared".to_string(),
        "6ft".to_string(),
        "Remzarian".to_string(),
        "Remzarland".to_string(),
        "A".repeat(512),
        "Engineer".to_string(),
    )
}

fn signed_passport(id: u64) -> Result<DigitalPassport, ErrorDetection> {
    let wallet = test_wallet();

    DigitalPassport::new_signed(
        passport_id_hex(id),
        wallet.address.clone(),
        wallet,
        TEST_PASSPHRASE.to_string(),
        TEST_PASSPHRASE.to_string(),
        valid_fields()?,
    )
}

fn signed_passport_with_fields(
    id: u64,
    fields: DigitalPassportFields,
) -> Result<DigitalPassport, ErrorDetection> {
    let wallet = test_wallet();

    DigitalPassport::new_signed(
        passport_id_hex(id),
        wallet.address.clone(),
        wallet,
        TEST_PASSPHRASE.to_string(),
        TEST_PASSPHRASE.to_string(),
        fields,
    )
}

fn temp_dir(label: &str) -> Result<PathBuf, String> {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e:?}"))?
        .as_nanos();

    let path = std::env::temp_dir().join(format!(
        "remzar_digital_id_receipt_tests_{}_{}_{}_{}",
        std::process::id(),
        nanos,
        counter,
        label
    ));

    if path.exists() {
        fs::remove_dir_all(&path)
            .map_err(|e| format!("failed to remove stale temp dir {}: {e}", path.display()))?;
    }

    fs::create_dir_all(&path)
        .map_err(|e| format!("failed to create temp dir {}: {e}", path.display()))?;

    Ok(path)
}

#[test]
fn digital_id_001_fields_from_raw_trims_and_converts_blanks_to_none() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "  Alice  ".to_string(),
                "  ".to_string(),
                "\t".to_string(),
                "".to_string(),
                "  Canadian ".to_string(),
                "".to_string(),
                " 123 Main ".to_string(),
                " Developer ".to_string(),
            ),
            "from_raw should succeed",
        )?;

        assert_eq!(fields.name.as_deref(), Some("Alice"));
        assert_eq!(fields.birth, None);
        assert_eq!(fields.sex, None);
        assert_eq!(fields.height, None);
        assert_eq!(fields.nationality.as_deref(), Some("Canadian"));
        assert_eq!(fields.country, None);
        assert_eq!(fields.address.as_deref(), Some("123 Main"));
        assert_eq!(fields.job.as_deref(), Some("Developer"));
        Ok(())
    })
}

#[test]
fn digital_id_002_fields_from_raw_rejects_all_blank_identity_fields() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            " ".to_string(),
            "\t".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_003_fields_from_raw_accepts_name_only_minimum_identity() -> TestResult {
    run_serial(|| {
        let fields = ok(minimal_name_fields(), "minimal fields should succeed")?;

        assert_eq!(fields.name.as_deref(), Some("Alice"));
        assert_eq!(fields.birth, None);
        assert_eq!(fields.sex, None);
        assert_eq!(fields.height, None);
        assert_eq!(fields.nationality, None);
        assert_eq!(fields.country, None);
        assert_eq!(fields.address, None);
        assert_eq!(fields.job, None);
        Ok(())
    })
}

#[test]
fn digital_id_004_fields_from_raw_allows_self_declared_birth_text() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "".to_string(),
                "1888-44-55".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
            ),
            "birth-only fields should succeed",
        )?;

        assert_eq!(fields.birth.as_deref(), Some("1888-44-55"));
        Ok(())
    })
}

#[test]
fn digital_id_005_fields_from_raw_rejects_name_over_128_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "A".repeat(129),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_006_fields_from_raw_rejects_short_field_over_128_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "".to_string(),
            "S".repeat(129),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_007_fields_from_raw_accepts_address_at_512_bytes() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "A".repeat(512),
                "".to_string(),
            ),
            "512-byte address should succeed",
        )?;

        assert_eq!(fields.address.as_ref().map(String::len), Some(512));
        Ok(())
    })
}

#[test]
fn digital_id_008_fields_from_raw_rejects_address_over_512_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "A".repeat(513),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_009_fields_from_raw_rejects_control_characters() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "Alice\nMallory".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_010_validate_passphrase_confirmation_accepts_matching_values() -> TestResult {
    run_serial(|| {
        ok(
            DigitalPassport::validate_passphrase_confirmation("abc123!", "abc123!"),
            "matching passphrases should validate",
        )?;
        Ok(())
    })
}

#[test]
fn digital_id_011_validate_passphrase_confirmation_rejects_empty_passphrase() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassport::validate_passphrase_confirmation(
            "", "abc123!",
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_012_validate_passphrase_confirmation_rejects_empty_confirmation() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassport::validate_passphrase_confirmation(
            "abc123!", "",
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_013_validate_passphrase_confirmation_rejects_mismatch() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassport::validate_passphrase_confirmation(
            "abc123!", "abc123!!",
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_014_validate_passphrase_confirmation_rejects_absurdly_long_input() -> TestResult {
    run_serial(|| {
        let too_long = "x".repeat(16 * 1024 + 1);

        assert_validation_error(DigitalPassport::validate_passphrase_confirmation(
            &too_long, &too_long,
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_015_new_signed_creates_valid_passport() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(15), "new_signed should succeed")?;

        ok(passport.validate(), "passport should validate")?;
        assert_eq!(passport.kind, DIGITAL_PASSPORT_KIND);
        assert_eq!(passport.schema, DIGITAL_PASSPORT_SCHEMA);
        assert_eq!(passport.wallet_address, test_wallet().address);
        assert_eq!(passport.wallet_address.len(), REMZAR_WALLET_LEN);
        assert_lower_hex_len(&passport.passport_id_hex, 128);
        assert_lower_hex_len(&passport.digital_fingerprint_hex, 128);
        assert_lower_hex_len(&passport.wallet_public_key_hex, ml_dsa_65::PK_LEN * 2);
        assert_lower_hex_len(&passport.wallet_signature_hex, ml_dsa_65::SIG_LEN * 2);
        Ok(())
    })
}

#[test]
fn digital_id_016_new_signed_lowercases_uppercase_passport_id_hex() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();
        let uppercase_passport_id = "A".repeat(128);

        let passport = ok(
            DigitalPassport::new_signed(
                uppercase_passport_id,
                wallet.address.clone(),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                ok(valid_fields(), "valid fields")?,
            ),
            "new_signed should accept uppercase passport id by canonicalizing",
        )?;

        assert_eq!(passport.passport_id_hex, "a".repeat(128));
        ok(
            passport.validate(),
            "canonicalized passport should validate",
        )?;
        Ok(())
    })
}

#[test]
fn digital_id_017_new_signed_rejects_short_passport_id_hex() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        assert_validation_error(DigitalPassport::new_signed(
            "a".repeat(127),
            wallet.address.clone(),
            wallet,
            TEST_PASSPHRASE.to_string(),
            TEST_PASSPHRASE.to_string(),
            ok(valid_fields(), "valid fields")?,
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_018_new_signed_rejects_non_hex_passport_id() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        assert_validation_error(DigitalPassport::new_signed(
            "g".repeat(128),
            wallet.address.clone(),
            wallet,
            TEST_PASSPHRASE.to_string(),
            TEST_PASSPHRASE.to_string(),
            ok(valid_fields(), "valid fields")?,
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_019_new_signed_rejects_wallet_address_mismatch() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();
        let other = other_wallet();

        assert_validation_error(DigitalPassport::new_signed(
            passport_id_hex(19),
            other.address.clone(),
            wallet,
            TEST_PASSPHRASE.to_string(),
            TEST_PASSPHRASE.to_string(),
            ok(valid_fields(), "valid fields")?,
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_020_validate_rejects_bad_kind() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(20), "passport should build")?;
        passport.kind = "WrongKind".to_string();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_021_validate_rejects_bad_schema() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(21), "passport should build")?;
        passport.schema = "wrong-schema".to_string();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_022_validate_rejects_bad_passport_id_length_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(22), "passport should build")?;
        passport.passport_id_hex = "a".repeat(127);

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_023_validate_rejects_bad_wallet_length() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(23), "passport should build")?;
        passport.wallet_address = "r".to_string();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_024_validate_rejects_non_hex_public_key() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(24), "passport should build")?;
        passport.wallet_public_key_hex = "g".repeat(ml_dsa_65::PK_LEN * 2);

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_025_validate_rejects_wrong_public_key_length() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(25), "passport should build")?;
        passport.wallet_public_key_hex = "a".repeat((ml_dsa_65::PK_LEN * 2).saturating_sub(2));

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_026_validate_rejects_bad_fingerprint_length() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(26), "passport should build")?;
        passport.digital_fingerprint_hex = "a".repeat(127);

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_027_validate_rejects_bad_signature_length() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(27), "passport should build")?;
        passport.wallet_signature_hex = "0".repeat((ml_dsa_65::SIG_LEN * 2).saturating_sub(2));

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_028_validate_rejects_invalid_created_at_datetime() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(28), "passport should build")?;
        passport.created_at_utc = "not-a-date".to_string();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_029_validate_detects_fingerprint_tampering() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(29), "passport should build")?;
        passport.digital_fingerprint_hex = "0".repeat(128);

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_030_validate_detects_identity_field_tampering() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(30), "passport should build")?;
        passport.fields.name = Some("Mallory".to_string());

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_031_validate_detects_signature_tampering() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(31), "passport should build")?;
        passport.wallet_signature_hex = "0".repeat(ml_dsa_65::SIG_LEN * 2);

        assert_cryptographic_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_032_verify_wallet_signature_returns_true_for_valid_passport() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(32), "passport should build")?;

        let verified = ok(
            passport.verify_wallet_signature(),
            "signature verification should run",
        )?;

        assert!(verified);
        Ok(())
    })
}

#[test]
fn digital_id_033_verify_wallet_signature_returns_false_for_wrong_valid_length_signature()
-> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(33), "passport should build")?;
        passport.wallet_signature_hex = "0".repeat(ml_dsa_65::SIG_LEN * 2);

        let verified = ok(
            passport.verify_wallet_signature(),
            "signature verification should run",
        )?;

        assert!(!verified);
        Ok(())
    })
}

#[test]
fn digital_id_034_content_bytes_for_nft_returns_valid_json_proof_payload() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(34), "passport should build")?;

        let bytes = ok(
            passport.content_bytes_for_nft(),
            "content_bytes_for_nft should succeed",
        )?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("proof payload should be valid JSON: {e}"))?;

        assert_eq!(value["kind"], DIGITAL_PASSPORT_KIND);
        assert_eq!(value["schema"], DIGITAL_PASSPORT_SCHEMA);
        assert_eq!(value["passport_id_hex"], passport.passport_id_hex);
        assert_eq!(value["wallet_address"], passport.wallet_address);
        assert!(value.get("fields").is_some());
        Ok(())
    })
}

#[test]
fn digital_id_035_content_bytes_for_nft_excludes_signature_and_fingerprint_fields() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(35), "passport should build")?;

        let bytes = ok(
            passport.content_bytes_for_nft(),
            "content_bytes_for_nft should succeed",
        )?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("proof payload should be valid JSON: {e}"))?;

        assert!(value.get("wallet_signature_hex").is_none());
        assert!(value.get("digital_fingerprint_hex").is_none());
        Ok(())
    })
}

#[test]
fn digital_id_036_nft_title_is_redacted_constant() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(36), "passport should build")?;

        assert_eq!(passport.nft_title(), "Digital I.D. Passport");
        Ok(())
    })
}

#[test]
fn digital_id_037_nft_description_redacted_contains_public_proof_data_not_private_fields()
-> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(37), "passport should build")?;
        let description = passport.nft_description_redacted();

        assert!(description.contains(DIGITAL_PASSPORT_KIND));
        assert!(description.contains(DIGITAL_PASSPORT_SCHEMA));
        assert!(description.contains(&passport.digital_fingerprint_hex));
        assert!(description.contains(&passport.wallet_address));
        assert!(description.contains(&passport.created_at_utc));

        assert!(!description.contains("Alice Remzar"));
        assert!(!description.contains("1985-04-22"));
        assert!(!description.contains("123 Blockchain Street"));
        assert!(!description.contains("Developer"));
        assert!(!description.contains(&passport.wallet_signature_hex));
        assert!(!description.contains(&passport.wallet_public_key_hex));
        Ok(())
    })
}

#[test]
fn digital_id_038_to_pretty_json_bytes_contains_receipt_and_no_passphrase() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(38), "passport should build")?;

        let bytes = ok(
            passport.to_pretty_json_bytes(),
            "to_pretty_json_bytes should succeed",
        )?;
        let text = String::from_utf8(bytes).map_err(|e| format!("json should be utf8: {e}"))?;

        assert!(text.contains("Alice Remzar"));
        assert!(text.contains(&passport.wallet_address));
        assert!(text.contains(&passport.digital_fingerprint_hex));
        assert!(text.contains(&passport.wallet_signature_hex));
        assert!(!text.contains(TEST_PASSPHRASE));
        Ok(())
    })
}

#[test]
fn digital_id_039_to_pretty_json_bytes_roundtrips_to_valid_passport() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(39), "passport should build")?;

        let bytes = ok(
            passport.to_pretty_json_bytes(),
            "to_pretty_json_bytes should succeed",
        )?;
        let decoded: DigitalPassport = serde_json::from_slice(&bytes)
            .map_err(|e| format!("DigitalPassport JSON roundtrip failed: {e}"))?;

        assert_eq!(decoded, passport);
        ok(decoded.validate(), "decoded passport should validate")?;
        Ok(())
    })
}

#[test]
fn digital_id_040_build_qr_png_bytes_returns_png_image() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(40), "passport should build")?;

        let bytes = ok(
            passport.build_qr_png_bytes(),
            "build_qr_png_bytes should succeed",
        )?;

        assert_png(&bytes);
        assert!(bytes.len() < 2 * 1024 * 1024);
        Ok(())
    })
}

#[test]
fn digital_id_041_build_pdf_bytes_returns_pdf_document() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(41), "passport should build")?;

        let bytes = ok(passport.build_pdf_bytes(), "build_pdf_bytes should succeed")?;

        assert_pdf(&bytes);
        assert!(bytes.len() < 10 * 1024 * 1024);
        Ok(())
    })
}

#[test]
fn digital_id_042_write_json_file_creates_json_file() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(42), "passport should build")?;
        let dir = temp_dir("json")?;

        let path = ok(
            passport.write_json_file(&dir),
            "write_json_file should succeed",
        )?;

        assert!(path.exists());
        assert_eq!(path.parent(), Some(dir.as_path()));
        assert_eq!(path.extension().and_then(|s| s.to_str()), Some("json"));

        let decoded: DigitalPassport = serde_json::from_slice(
            &fs::read(&path).map_err(|e| format!("failed to read json file: {e}"))?,
        )
        .map_err(|e| format!("failed to decode json receipt: {e}"))?;

        assert_eq!(decoded.passport_id_hex, passport.passport_id_hex);
        ok(decoded.validate(), "decoded json receipt should validate")?;
        Ok(())
    })
}

#[test]
fn digital_id_043_write_pdf_file_creates_pdf_file() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(43), "passport should build")?;
        let dir = temp_dir("pdf")?;

        let path = ok(
            passport.write_pdf_file(&dir),
            "write_pdf_file should succeed",
        )?;

        assert!(path.exists());
        assert_eq!(path.parent(), Some(dir.as_path()));
        assert_eq!(path.extension().and_then(|s| s.to_str()), Some("pdf"));

        let bytes = fs::read(&path).map_err(|e| format!("failed to read pdf file: {e}"))?;
        assert_pdf(&bytes);
        Ok(())
    })
}

#[test]
fn digital_id_044_write_qr_png_file_creates_png_file() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(44), "passport should build")?;
        let dir = temp_dir("qr")?;

        let path = ok(
            passport.write_qr_png_file(&dir),
            "write_qr_png_file should succeed",
        )?;

        assert!(path.exists());
        assert_eq!(path.parent(), Some(dir.as_path()));
        assert_eq!(path.extension().and_then(|s| s.to_str()), Some("png"));

        let bytes = fs::read(&path).map_err(|e| format!("failed to read qr png file: {e}"))?;
        assert_png(&bytes);
        Ok(())
    })
}

#[test]
fn digital_id_045_write_receipt_files_creates_json_pdf_and_qr_outputs() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(45), "passport should build")?;
        let json_dir = temp_dir("receipt-json")?;
        let pdf_qr_dir = temp_dir("receipt-pdf-qr")?;

        let files = ok(
            passport.write_receipt_files(&json_dir, &pdf_qr_dir),
            "write_receipt_files should succeed",
        )?;

        assert!(files.json_path.exists());
        assert!(files.pdf_path.exists());
        assert!(files.qr_png_path.exists());

        assert_eq!(files.json_path.parent(), Some(json_dir.as_path()));
        assert_eq!(files.pdf_path.parent(), Some(pdf_qr_dir.as_path()));
        assert_eq!(files.qr_png_path.parent(), Some(pdf_qr_dir.as_path()));

        assert_eq!(
            files.json_path.extension().and_then(|s| s.to_str()),
            Some("json")
        );
        assert_eq!(
            files.pdf_path.extension().and_then(|s| s.to_str()),
            Some("pdf")
        );
        assert_eq!(
            files.qr_png_path.extension().and_then(|s| s.to_str()),
            Some("png")
        );

        assert_pdf(&fs::read(&files.pdf_path).map_err(|e| format!("read pdf failed: {e}"))?);
        assert_png(&fs::read(&files.qr_png_path).map_err(|e| format!("read png failed: {e}"))?);
        Ok(())
    })
}

#[test]
fn digital_id_046_deserialized_receipt_from_pretty_json_validates() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(46), "passport should build")?;
        let bytes = ok(passport.to_pretty_json_bytes(), "json should build")?;

        let decoded: DigitalPassport = serde_json::from_slice(&bytes)
            .map_err(|e| format!("failed to decode DigitalPassport JSON: {e}"))?;

        ok(decoded.validate(), "decoded passport should validate")?;
        assert_eq!(decoded.wallet_address, passport.wallet_address);
        assert_eq!(
            decoded.digital_fingerprint_hex,
            passport.digital_fingerprint_hex
        );
        assert_eq!(decoded.wallet_signature_hex, passport.wallet_signature_hex);
        Ok(())
    })
}

#[test]
fn digital_id_047_new_signed_accepts_uppercase_expected_wallet_address_boundary_input() -> TestResult
{
    run_serial(|| {
        let wallet = test_wallet();
        let uppercase_expected_wallet = wallet.address.to_ascii_uppercase();

        let passport = ok(
            DigitalPassport::new_signed(
                passport_id_hex(47),
                uppercase_expected_wallet,
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                ok(valid_fields(), "valid fields")?,
            ),
            "new_signed should canonicalize uppercase expected wallet input",
        )?;

        assert_eq!(passport.wallet_address, wallet.address);
        assert_eq!(
            passport.wallet_address,
            passport.wallet_address.to_ascii_lowercase()
        );
        ok(passport.validate(), "passport should validate")?;
        Ok(())
    })
}

#[test]
fn digital_id_048_validate_detects_wallet_public_key_binding_tampering() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(48), "passport should build")?;
        passport.wallet_address = other_wallet().address.clone();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_049_validate_detects_valid_datetime_created_at_tampering_by_fingerprint_mismatch()
-> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(49), "passport should build")?;
        passport.created_at_utc = "2025-01-01T00:00:00.000Z".to_string();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_050_all_identity_fields_vector_signs_validates_and_preserves_values() -> TestResult {
    run_serial(|| {
        let fields = ok(all_fields_vector(), "all fields vector should validate")?;
        let passport = ok(
            signed_passport_with_fields(50, fields.clone()),
            "passport with all fields should build",
        )?;

        ok(
            passport.validate(),
            "passport with all fields should validate",
        )?;

        assert_eq!(passport.fields, fields);
        assert_eq!(passport.fields.name.as_deref(), Some("Vector Name"));
        assert_eq!(passport.fields.birth.as_deref(), Some("1888-44-55"));
        assert_eq!(passport.fields.address.as_ref().map(String::len), Some(512));
        assert_lower_hex_len(&passport.digital_fingerprint_hex, 128);
        assert_lower_hex_len(&passport.wallet_signature_hex, ml_dsa_65::SIG_LEN * 2);
        Ok(())
    })
}

#[test]
fn digital_id_051_fields_from_raw_accepts_name_at_128_bytes() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "N".repeat(128),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
            ),
            "128-byte name should succeed",
        )?;

        assert_eq!(fields.name.as_ref().map(String::len), Some(128));
        Ok(())
    })
}

#[test]
fn digital_id_052_fields_from_raw_accepts_each_short_field_at_128_bytes() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "".to_string(),
                "B".repeat(128),
                "S".repeat(128),
                "H".repeat(128),
                "N".repeat(128),
                "C".repeat(128),
                "".to_string(),
                "J".repeat(128),
            ),
            "128-byte short fields should succeed",
        )?;

        assert_eq!(fields.birth.as_ref().map(String::len), Some(128));
        assert_eq!(fields.sex.as_ref().map(String::len), Some(128));
        assert_eq!(fields.height.as_ref().map(String::len), Some(128));
        assert_eq!(fields.nationality.as_ref().map(String::len), Some(128));
        assert_eq!(fields.country.as_ref().map(String::len), Some(128));
        assert_eq!(fields.job.as_ref().map(String::len), Some(128));
        Ok(())
    })
}

#[test]
fn digital_id_053_fields_from_raw_rejects_birth_over_128_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "B".repeat(129),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_054_fields_from_raw_rejects_height_over_128_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "H".repeat(129),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_055_fields_from_raw_rejects_nationality_over_128_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "N".repeat(129),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_056_fields_from_raw_rejects_country_over_128_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "C".repeat(129),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_057_fields_from_raw_rejects_job_over_128_bytes() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "J".repeat(129),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_058_fields_from_raw_rejects_birth_control_characters() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "1985\n04\n22".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_059_fields_from_raw_rejects_address_control_characters() -> TestResult {
    run_serial(|| {
        assert_validation_error(DigitalPassportFields::from_raw(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "123 Main\nStreet".to_string(),
            "".to_string(),
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_060_fields_from_raw_accepts_unicode_text_within_byte_limits() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "Alice 鎖".to_string(),
                "unknown".to_string(),
                "自".to_string(),
                "170cm".to_string(),
                "日本".to_string(),
                "Canada".to_string(),
                "Rue Blockchain".to_string(),
                "開発者".to_string(),
            ),
            "unicode fields within limits should succeed",
        )?;

        assert_eq!(fields.name.as_deref(), Some("Alice 鎖"));
        assert_eq!(fields.birth.as_deref(), Some("unknown"));
        assert_eq!(fields.job.as_deref(), Some("開発者"));
        Ok(())
    })
}

#[test]
fn digital_id_061_new_signed_accepts_zero_passport_id_vector() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        let passport = ok(
            DigitalPassport::new_signed(
                "0".repeat(128),
                wallet.address.clone(),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                ok(valid_fields(), "valid fields")?,
            ),
            "zero passport id should build",
        )?;

        assert_eq!(passport.passport_id_hex, "0".repeat(128));
        ok(passport.validate(), "zero id passport should validate")?;
        Ok(())
    })
}

#[test]
fn digital_id_062_new_signed_accepts_all_f_passport_id_vector() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        let passport = ok(
            DigitalPassport::new_signed(
                "f".repeat(128),
                wallet.address.clone(),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                ok(valid_fields(), "valid fields")?,
            ),
            "all-f passport id should build",
        )?;

        assert_eq!(passport.passport_id_hex, "f".repeat(128));
        ok(passport.validate(), "all-f id passport should validate")?;
        Ok(())
    })
}

#[test]
fn digital_id_063_new_signed_trims_passport_id_hex_boundary_input() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        let passport = ok(
            DigitalPassport::new_signed(
                format!("  {}  ", passport_id_hex(63)),
                wallet.address.clone(),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                ok(valid_fields(), "valid fields")?,
            ),
            "trimmed passport id should build",
        )?;

        assert_eq!(passport.passport_id_hex, passport_id_hex(63));
        ok(
            passport.validate(),
            "trimmed passport id passport should validate",
        )?;
        Ok(())
    })
}

#[test]
fn digital_id_064_new_signed_accepts_expected_wallet_with_surrounding_whitespace() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        let passport = ok(
            DigitalPassport::new_signed(
                passport_id_hex(64),
                format!("  {}  ", wallet.address),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                ok(valid_fields(), "valid fields")?,
            ),
            "expected wallet with whitespace should build",
        )?;

        assert_eq!(passport.wallet_address, wallet.address);
        ok(passport.validate(), "passport should validate")?;
        Ok(())
    })
}

#[test]
fn digital_id_065_new_signed_rejects_wrong_passphrase() -> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        assert_cryptographic_error(DigitalPassport::new_signed(
            passport_id_hex(65),
            wallet.address.clone(),
            wallet,
            "wrong-passphrase".to_string(),
            "wrong-passphrase".to_string(),
            ok(valid_fields(), "valid fields")?,
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_066_new_signed_rejects_mismatched_passphrase_confirmation_before_signing()
-> TestResult {
    run_serial(|| {
        let wallet = test_wallet();

        assert_validation_error(DigitalPassport::new_signed(
            passport_id_hex(66),
            wallet.address.clone(),
            wallet,
            TEST_PASSPHRASE.to_string(),
            "different-confirmation".to_string(),
            ok(valid_fields(), "valid fields")?,
        ))?;
        Ok(())
    })
}

#[test]
fn digital_id_067_validate_rejects_uppercase_wallet_address_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(67), "passport should build")?;
        passport.wallet_address = passport.wallet_address.to_ascii_uppercase();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_068_validate_rejects_wallet_with_non_hex_body_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(68), "passport should build")?;
        passport.wallet_address = format!("r{}", "g".repeat(128));

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_069_validate_rejects_uppercase_passport_id_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(69), "passport should build")?;
        passport.passport_id_hex = "A".repeat(128);

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_070_validate_rejects_uppercase_fingerprint_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(70), "passport should build")?;
        passport.digital_fingerprint_hex = passport.digital_fingerprint_hex.to_ascii_uppercase();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_071_validate_rejects_uppercase_signature_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(71), "passport should build")?;
        passport.wallet_signature_hex = passport.wallet_signature_hex.to_ascii_uppercase();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_072_validate_rejects_uppercase_public_key_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(72), "passport should build")?;
        passport.wallet_public_key_hex = passport.wallet_public_key_hex.to_ascii_uppercase();

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_073_validate_rejects_non_hex_signature_after_mutation() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(73), "passport should build")?;
        passport.wallet_signature_hex = "g".repeat(ml_dsa_65::SIG_LEN * 2);

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_074_validate_rejects_public_key_from_different_wallet() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(74), "passport should build")?;
        passport.wallet_public_key_hex = hex::encode(other_wallet().public);

        assert_validation_error(passport.validate())?;
        Ok(())
    })
}

#[test]
fn digital_id_075_verify_wallet_signature_rejects_non_hex_signature() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(75), "passport should build")?;
        passport.wallet_signature_hex = "z".repeat(ml_dsa_65::SIG_LEN * 2);

        assert_validation_error(passport.verify_wallet_signature())?;
        Ok(())
    })
}

#[test]
fn digital_id_076_verify_wallet_signature_rejects_short_signature_bytes() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(76), "passport should build")?;
        passport.wallet_signature_hex = "0".repeat((ml_dsa_65::SIG_LEN * 2).saturating_sub(2));

        assert_validation_error(passport.verify_wallet_signature())?;
        Ok(())
    })
}

#[test]
fn digital_id_077_verify_wallet_signature_rejects_bad_public_key_hex() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(77), "passport should build")?;
        passport.wallet_public_key_hex = "z".repeat(ml_dsa_65::PK_LEN * 2);

        assert_validation_error(passport.verify_wallet_signature())?;
        Ok(())
    })
}

#[test]
fn digital_id_078_verify_wallet_signature_rejects_short_public_key_hex() -> TestResult {
    run_serial(|| {
        let mut passport = ok(signed_passport(78), "passport should build")?;
        passport.wallet_public_key_hex = "0".repeat((ml_dsa_65::PK_LEN * 2).saturating_sub(2));

        assert_validation_error(passport.verify_wallet_signature())?;
        Ok(())
    })
}

#[test]
fn digital_id_079_verify_wallet_signature_returns_false_after_valid_created_at_change() -> TestResult
{
    run_serial(|| {
        let mut passport = ok(signed_passport(79), "passport should build")?;
        passport.created_at_utc = "2025-01-01T00:00:00.000Z".to_string();

        let verified = ok(
            passport.verify_wallet_signature(),
            "verify_wallet_signature should run",
        )?;

        assert!(!verified);
        Ok(())
    })
}

#[test]
fn digital_id_080_content_bytes_for_nft_are_deterministic_for_same_passport_instance() -> TestResult
{
    run_serial(|| {
        let passport = ok(signed_passport(80), "passport should build")?;

        let first = ok(
            passport.content_bytes_for_nft(),
            "first content bytes should build",
        )?;
        let second = ok(
            passport.content_bytes_for_nft(),
            "second content bytes should build",
        )?;

        assert_eq!(first, second);
        Ok(())
    })
}

#[test]
fn digital_id_081_content_bytes_for_nft_change_when_passport_id_changes() -> TestResult {
    run_serial(|| {
        let first = ok(signed_passport(81), "first passport should build")?;
        let second = ok(signed_passport(82), "second passport should build")?;

        let first_bytes = ok(first.content_bytes_for_nft(), "first content bytes")?;
        let second_bytes = ok(second.content_bytes_for_nft(), "second content bytes")?;

        assert_ne!(first.passport_id_hex, second.passport_id_hex);
        assert_ne!(first_bytes, second_bytes);
        Ok(())
    })
}

#[test]
fn digital_id_082_content_bytes_for_nft_change_when_fields_change() -> TestResult {
    run_serial(|| {
        let first = ok(signed_passport(82), "first passport should build")?;
        let second_fields = ok(
            DigitalPassportFields::from_raw(
                "Bob".to_string(),
                "1990-01-01".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
            ),
            "second fields should build",
        )?;
        let second = ok(
            signed_passport_with_fields(83, second_fields),
            "second passport should build",
        )?;

        let first_bytes = ok(first.content_bytes_for_nft(), "first content bytes")?;
        let second_bytes = ok(second.content_bytes_for_nft(), "second content bytes")?;

        assert_ne!(first_bytes, second_bytes);
        Ok(())
    })
}

#[test]
fn digital_id_083_nft_description_redacted_has_no_identity_field_values_for_max_vector()
-> TestResult {
    run_serial(|| {
        let fields = ok(all_fields_vector(), "all fields vector should build")?;
        let passport = ok(
            signed_passport_with_fields(83, fields.clone()),
            "passport should build",
        )?;
        let description = passport.nft_description_redacted();

        assert!(!description.contains(fields.name.as_deref().unwrap_or("")));
        assert!(!description.contains(fields.birth.as_deref().unwrap_or("")));
        assert!(!description.contains(fields.sex.as_deref().unwrap_or("")));
        assert!(!description.contains(fields.height.as_deref().unwrap_or("")));
        assert!(!description.contains(fields.nationality.as_deref().unwrap_or("")));
        assert!(!description.contains(fields.country.as_deref().unwrap_or("")));
        assert!(!description.contains(fields.address.as_deref().unwrap_or("")));
        assert!(!description.contains(fields.job.as_deref().unwrap_or("")));
        Ok(())
    })
}

#[test]
fn digital_id_084_to_pretty_json_bytes_is_pretty_and_contains_expected_top_level_keys() -> TestResult
{
    run_serial(|| {
        let passport = ok(signed_passport(84), "passport should build")?;

        let bytes = ok(passport.to_pretty_json_bytes(), "json should build")?;
        let text = String::from_utf8(bytes).map_err(|e| format!("json should be utf8: {e}"))?;

        assert!(text.contains('\n'));
        assert!(text.contains("\"kind\""));
        assert!(text.contains("\"schema\""));
        assert!(text.contains("\"passport_id_hex\""));
        assert!(text.contains("\"wallet_address\""));
        assert!(text.contains("\"wallet_public_key_hex\""));
        assert!(text.contains("\"fields\""));
        assert!(text.contains("\"created_at_utc\""));
        assert!(text.contains("\"digital_fingerprint_hex\""));
        assert!(text.contains("\"wallet_signature_hex\""));
        Ok(())
    })
}

#[test]
fn digital_id_085_deserialize_rejects_missing_required_fields() -> TestResult {
    run_serial(|| {
        let decoded = serde_json::from_str::<DigitalPassport>("{}");

        assert!(decoded.is_err());
        Ok(())
    })
}

#[test]
fn digital_id_086_deserialize_rejects_wrong_json_types() -> TestResult {
    run_serial(|| {
        let decoded = serde_json::from_str::<DigitalPassport>(
            r#"{
                "kind": 123,
                "schema": "digital-id-v1",
                "passport_id_hex": "0",
                "wallet_address": "0",
                "wallet_public_key_hex": "0",
                "fields": {},
                "created_at_utc": "2025-01-01T00:00:00.000Z",
                "digital_fingerprint_hex": "0",
                "wallet_signature_hex": "0"
            }"#,
        );

        assert!(decoded.is_err());
        Ok(())
    })
}

#[test]
fn digital_id_087_deserialize_ignores_unknown_json_fields_but_validation_still_passes() -> TestResult
{
    run_serial(|| {
        let passport = ok(signed_passport(87), "passport should build")?;
        let mut value: serde_json::Value =
            serde_json::from_slice(&ok(passport.to_pretty_json_bytes(), "json should build")?)
                .map_err(|e| format!("json should decode to value: {e}"))?;

        value["unknown_extra_field"] = serde_json::json!("ignored");

        let decoded: DigitalPassport =
            serde_json::from_value(value).map_err(|e| format!("deserialize failed: {e}"))?;

        assert_eq!(decoded, passport);
        ok(decoded.validate(), "decoded passport should validate")?;
        Ok(())
    })
}

#[test]
fn digital_id_088_build_qr_png_bytes_is_deterministic_for_same_passport() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(88), "passport should build")?;

        let first = ok(passport.build_qr_png_bytes(), "first qr should build")?;
        let second = ok(passport.build_qr_png_bytes(), "second qr should build")?;

        assert_eq!(first, second);
        assert_png(&first);
        Ok(())
    })
}

#[test]
fn digital_id_089_build_pdf_bytes_is_deterministic_for_same_passport() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(89), "passport should build")?;

        let first = ok(passport.build_pdf_bytes(), "first pdf should build")?;
        let second = ok(passport.build_pdf_bytes(), "second pdf should build")?;

        assert_eq!(first, second);
        assert_pdf(&first);
        Ok(())
    })
}

#[test]
fn digital_id_090_build_pdf_bytes_handles_unicode_fields_by_safe_rendering() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "Alice 鎖".to_string(),
                "unknown".to_string(),
                "自".to_string(),
                "170cm".to_string(),
                "日本".to_string(),
                "Canada".to_string(),
                "Rue Blockchain".to_string(),
                "開発者".to_string(),
            ),
            "unicode fields should build",
        )?;
        let passport = ok(
            signed_passport_with_fields(90, fields),
            "unicode passport should build",
        )?;

        let pdf = ok(passport.build_pdf_bytes(), "pdf should build")?;

        assert_pdf(&pdf);
        Ok(())
    })
}

#[test]
fn digital_id_091_write_json_file_overwrites_existing_receipt_atomically() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(91), "passport should build")?;
        let dir = temp_dir("overwrite-json")?;

        let first_path = ok(passport.write_json_file(&dir), "first write should succeed")?;
        fs::write(&first_path, b"stale-json")
            .map_err(|e| format!("failed to write stale json: {e}"))?;

        let second_path = ok(
            passport.write_json_file(&dir),
            "second write should succeed",
        )?;

        assert_eq!(first_path, second_path);

        let text = fs::read_to_string(&second_path)
            .map_err(|e| format!("failed to read overwritten json: {e}"))?;
        assert!(text.contains(&passport.passport_id_hex));
        assert!(!text.contains("stale-json"));
        Ok(())
    })
}

#[test]
fn digital_id_092_write_pdf_file_overwrites_existing_receipt_atomically() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(92), "passport should build")?;
        let dir = temp_dir("overwrite-pdf")?;

        let first_path = ok(passport.write_pdf_file(&dir), "first write should succeed")?;
        fs::write(&first_path, b"stale-pdf")
            .map_err(|e| format!("failed to write stale pdf: {e}"))?;

        let second_path = ok(passport.write_pdf_file(&dir), "second write should succeed")?;

        assert_eq!(first_path, second_path);

        let bytes = fs::read(&second_path).map_err(|e| format!("failed to read pdf: {e}"))?;
        assert_pdf(&bytes);
        assert_ne!(bytes, b"stale-pdf");
        Ok(())
    })
}

#[test]
fn digital_id_093_write_qr_png_file_overwrites_existing_receipt_atomically() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(93), "passport should build")?;
        let dir = temp_dir("overwrite-qr")?;

        let first_path = ok(
            passport.write_qr_png_file(&dir),
            "first write should succeed",
        )?;
        fs::write(&first_path, b"stale-png")
            .map_err(|e| format!("failed to write stale png: {e}"))?;

        let second_path = ok(
            passport.write_qr_png_file(&dir),
            "second write should succeed",
        )?;

        assert_eq!(first_path, second_path);

        let bytes = fs::read(&second_path).map_err(|e| format!("failed to read png: {e}"))?;
        assert_png(&bytes);
        assert_ne!(bytes, b"stale-png");
        Ok(())
    })
}

#[test]
fn digital_id_094_write_json_file_rejects_output_path_that_is_existing_file() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(94), "passport should build")?;
        let dir = temp_dir("json-dir-is-file")?;
        let file_path = dir.join("not-a-directory");
        fs::write(&file_path, b"I am a file")
            .map_err(|e| format!("failed to create file path: {e}"))?;

        assert_any_error(passport.write_json_file(&file_path))?;
        Ok(())
    })
}

#[test]
fn digital_id_095_write_pdf_file_rejects_output_path_that_is_existing_file() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(95), "passport should build")?;
        let dir = temp_dir("pdf-dir-is-file")?;
        let file_path = dir.join("not-a-directory");
        fs::write(&file_path, b"I am a file")
            .map_err(|e| format!("failed to create file path: {e}"))?;

        assert_any_error(passport.write_pdf_file(&file_path))?;
        Ok(())
    })
}

#[test]
fn digital_id_096_write_qr_png_file_rejects_output_path_that_is_existing_file() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(96), "passport should build")?;
        let dir = temp_dir("qr-dir-is-file")?;
        let file_path = dir.join("not-a-directory");
        fs::write(&file_path, b"I am a file")
            .map_err(|e| format!("failed to create file path: {e}"))?;

        assert_any_error(passport.write_qr_png_file(&file_path))?;
        Ok(())
    })
}

#[test]
fn digital_id_097_write_receipt_files_does_not_create_outputs_when_passport_invalid() -> TestResult
{
    run_serial(|| {
        let mut passport = ok(signed_passport(97), "passport should build")?;
        passport.kind = "InvalidKind".to_string();

        let json_dir = temp_dir("invalid-receipt-json")?;
        let pdf_dir = temp_dir("invalid-receipt-pdf")?;

        assert_validation_error(passport.write_receipt_files(&json_dir, &pdf_dir))?;

        let json_entries = fs::read_dir(&json_dir)
            .map_err(|e| format!("failed to read json dir: {e}"))?
            .count();
        let pdf_entries = fs::read_dir(&pdf_dir)
            .map_err(|e| format!("failed to read pdf dir: {e}"))?
            .count();

        assert_eq!(json_entries, 0);
        assert_eq!(pdf_entries, 0);
        Ok(())
    })
}

#[test]
fn digital_id_098_all_written_receipt_file_names_include_passport_id() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(98), "passport should build")?;
        let json_dir = temp_dir("file-name-json")?;
        let pdf_dir = temp_dir("file-name-pdf")?;

        let files = ok(
            passport.write_receipt_files(&json_dir, &pdf_dir),
            "receipt files should write",
        )?;

        let json_name = files
            .json_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "json file name should be utf8".to_string())?;
        let pdf_name = files
            .pdf_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "pdf file name should be utf8".to_string())?;
        let qr_name = files
            .qr_png_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "qr file name should be utf8".to_string())?;

        assert!(json_name.contains(&passport.passport_id_hex));
        assert!(pdf_name.contains(&passport.passport_id_hex));
        assert!(qr_name.contains(&passport.passport_id_hex));

        assert!(json_name.starts_with("digital_id_"));
        assert!(pdf_name.starts_with("digital_id_"));
        assert!(qr_name.starts_with("digital_id_"));

        assert!(json_name.ends_with(".json"));
        assert!(pdf_name.ends_with(".pdf"));
        assert!(qr_name.ends_with("_qr.png"));
        Ok(())
    })
}

#[test]
fn digital_id_099_created_at_from_new_signed_is_utc_rfc3339_with_z_suffix() -> TestResult {
    run_serial(|| {
        let passport = ok(signed_passport(99), "passport should build")?;

        assert!(passport.created_at_utc.ends_with('Z'));
        chrono::DateTime::parse_from_rfc3339(&passport.created_at_utc)
            .map_err(|e| format!("created_at_utc should parse as RFC3339: {e}"))?;
        Ok(())
    })
}

#[test]
fn digital_id_100_maximum_boundary_fields_sign_json_pdf_qr_and_receipt_files() -> TestResult {
    run_serial(|| {
        let fields = ok(
            DigitalPassportFields::from_raw(
                "N".repeat(128),
                "B".repeat(128),
                "S".repeat(128),
                "H".repeat(128),
                "T".repeat(128),
                "C".repeat(128),
                "A".repeat(512),
                "J".repeat(128),
            ),
            "maximum boundary fields should build",
        )?;

        let passport = ok(
            signed_passport_with_fields(100, fields),
            "maximum boundary passport should build",
        )?;

        ok(
            passport.validate(),
            "maximum boundary passport should validate",
        )?;

        let json = ok(passport.to_pretty_json_bytes(), "json should build")?;
        let pdf = ok(passport.build_pdf_bytes(), "pdf should build")?;
        let qr = ok(passport.build_qr_png_bytes(), "qr should build")?;

        assert!(json.len() < 64 * 1024);
        assert!(pdf.len() < 10 * 1024 * 1024);
        assert!(qr.len() < 2 * 1024 * 1024);

        assert_pdf(&pdf);
        assert_png(&qr);

        let json_dir = temp_dir("max-boundary-json")?;
        let pdf_dir = temp_dir("max-boundary-pdf")?;

        let files = ok(
            passport.write_receipt_files(&json_dir, &pdf_dir),
            "maximum boundary receipt files should write",
        )?;

        assert!(files.json_path.exists());
        assert!(files.pdf_path.exists());
        assert!(files.qr_png_path.exists());
        Ok(())
    })
}
