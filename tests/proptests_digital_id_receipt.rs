// tests/proptests_digital_id_receipt.rs

use proptest::prelude::*;
use proptest::string::string_regex;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::utility::digital_id_receipt::{
    DIGITAL_PASSPORT_KIND, DIGITAL_PASSPORT_SCHEMA, DigitalPassport, DigitalPassportFields,
};
use remzar::utility::helper::REMZAR_WALLET_LEN;

use fips204::ml_dsa_65;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_PASSPHRASE: &str = "remzar-digital-id-proptest-passphrase-2026!";

static TEST_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static OTHER_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);
static DIGITAL_ID_PROPTEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn digital_id_proptest_guard() -> MutexGuard<'static, ()> {
    DIGITAL_ID_PROPTEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_wallet() -> &'static MLDSA65Wallet {
    TEST_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(TEST_PASSPHRASE).expect("test wallet generation should succeed")
    })
}

fn other_wallet() -> &'static MLDSA65Wallet {
    OTHER_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(TEST_PASSPHRASE).expect("other wallet generation should succeed")
    })
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
        "remzar_digital_id_prop_tests_{}_{}_{}_{}",
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

fn assert_png(bytes: &[u8]) -> Result<(), TestCaseError> {
    prop_assert!(bytes.len() > 8);
    prop_assert_eq!(
        &bytes[..8],
        &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n']
    );
    Ok(())
}

fn assert_pdf(bytes: &[u8]) -> Result<(), TestCaseError> {
    prop_assert!(bytes.len() > 4);
    prop_assert_eq!(&bytes[..4], b"%PDF");
    Ok(())
}

fn lower_hex_128() -> BoxedStrategy<String> {
    string_regex("[0-9a-f]{128}")
        .expect("valid lowercase hex regex")
        .boxed()
}

fn mixed_hex_128() -> BoxedStrategy<String> {
    string_regex("[0-9a-fA-F]{128}")
        .expect("valid mixed hex regex")
        .boxed()
}

fn safe_text_64() -> BoxedStrategy<String> {
    string_regex("[A-Za-z0-9][A-Za-z0-9 .,_'()\\-]{0,63}")
        .expect("valid nonblank safe text regex")
        .boxed()
}

fn optional_safe_text_64() -> BoxedStrategy<String> {
    prop_oneof![Just("".to_string()), Just(" ".to_string()), safe_text_64(),].boxed()
}

fn safe_dir_leaf() -> BoxedStrategy<String> {
    string_regex("[A-Za-z0-9_-]{1,32}")
        .expect("valid safe dir leaf regex")
        .boxed()
}

fn safe_passphrase() -> BoxedStrategy<String> {
    string_regex("[A-Za-z0-9!@#_$%^&*+=.\\-]{1,128}")
        .expect("valid passphrase regex")
        .boxed()
}

fn make_fields(
    name: String,
    birth: String,
    sex: String,
    height: String,
    nationality: String,
    country: String,
    address: String,
    job: String,
) -> Result<DigitalPassportFields, TestCaseError> {
    DigitalPassportFields::from_raw(name, birth, sex, height, nationality, country, address, job)
        .map_err(|e| TestCaseError::fail(format!("DigitalPassportFields::from_raw failed: {e:?}")))
}

fn name_only_fields(name: String) -> Result<DigitalPassportFields, TestCaseError> {
    make_fields(
        name,
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
        "".to_string(),
    )
}

fn sign_passport(
    passport_id_hex: String,
    expected_wallet_address: String,
    fields: DigitalPassportFields,
) -> Result<DigitalPassport, TestCaseError> {
    let wallet = test_wallet();

    DigitalPassport::new_signed(
        passport_id_hex,
        expected_wallet_address,
        wallet,
        TEST_PASSPHRASE.to_string(),
        TEST_PASSPHRASE.to_string(),
        fields,
    )
    .map_err(|e| TestCaseError::fail(format!("DigitalPassport::new_signed failed: {e:?}")))
}

fn assert_valid_passport_shape(passport: &DigitalPassport) -> Result<(), TestCaseError> {
    prop_assert_eq!(&passport.kind, DIGITAL_PASSPORT_KIND);
    prop_assert_eq!(&passport.schema, DIGITAL_PASSPORT_SCHEMA);
    prop_assert_eq!(passport.passport_id_hex.len(), 128);
    prop_assert_eq!(passport.wallet_address.len(), REMZAR_WALLET_LEN);
    prop_assert_eq!(passport.wallet_public_key_hex.len(), ml_dsa_65::PK_LEN * 2);
    prop_assert_eq!(passport.digital_fingerprint_hex.len(), 128);
    prop_assert_eq!(passport.wallet_signature_hex.len(), ml_dsa_65::SIG_LEN * 2);
    prop_assert_eq!(
        &passport.passport_id_hex,
        &passport.passport_id_hex.to_ascii_lowercase()
    );
    prop_assert_eq!(
        &passport.digital_fingerprint_hex,
        &passport.digital_fingerprint_hex.to_ascii_lowercase()
    );
    prop_assert_eq!(
        &passport.wallet_signature_hex,
        &passport.wallet_signature_hex.to_ascii_lowercase()
    );
    Ok(())
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn digital_id_prop_001_from_raw_trims_identity_fields_and_turns_blanks_to_none(
        name in safe_text_64(),
        nationality in safe_text_64(),
        address in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let expected_name = name.trim().to_string();
        let expected_nationality = nationality.trim().to_string();
        let expected_address = address.trim().to_string();

        let fields = make_fields(
            format!("  {name}  "),
            "   ".to_string(),
            "\t".to_string(),
            "".to_string(),
            format!("  {nationality}  "),
            "".to_string(),
            format!("  {address}  "),
            " ".to_string(),
        )?;

        prop_assert_eq!(fields.name.as_deref(), Some(expected_name.as_str()));
        prop_assert_eq!(fields.birth, None);
        prop_assert_eq!(fields.sex, None);
        prop_assert_eq!(fields.height, None);
        prop_assert_eq!(
            fields.nationality.as_deref(),
            Some(expected_nationality.as_str())
        );
        prop_assert_eq!(fields.country, None);
        prop_assert_eq!(fields.address.as_deref(), Some(expected_address.as_str()));
        prop_assert_eq!(fields.job, None);
    }

    // 02/25
    #[test]
    fn digital_id_prop_002_generated_safe_identity_fields_are_accepted(
        name in safe_text_64(),
        birth in optional_safe_text_64(),
        sex in optional_safe_text_64(),
        height in optional_safe_text_64(),
        nationality in optional_safe_text_64(),
        country in optional_safe_text_64(),
        address in optional_safe_text_64(),
        job in optional_safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let expected_name = name.trim().to_string();

        let fields = make_fields(
            name,
            birth,
            sex,
            height,
            nationality,
            country,
            address,
            job,
        )?;

        prop_assert_eq!(fields.name.as_deref(), Some(expected_name.as_str()));
    }

    // 03/25
    #[test]
    fn digital_id_prop_003_all_blank_identity_fields_are_rejected(
        blanks in proptest::collection::vec(
            prop_oneof![
                Just("".to_string()),
                Just(" ".to_string()),
                Just("\t".to_string())
            ],
            8
        )
    ) {
        let _guard = digital_id_proptest_guard();
        prop_assert_eq!(blanks.len(), 8);

        prop_assert!(
            DigitalPassportFields::from_raw(
                blanks[0].clone(),
                blanks[1].clone(),
                blanks[2].clone(),
                blanks[3].clone(),
                blanks[4].clone(),
                blanks[5].clone(),
                blanks[6].clone(),
                blanks[7].clone(),
            ).is_err(),
            "all blank identity fields must be rejected"
        );
    }

    // 04/25
    #[test]
    fn digital_id_prop_004_name_over_128_bytes_is_rejected(
        extra in 1usize..128usize,
    ) {
        let _guard = digital_id_proptest_guard();
        let too_long_name = "N".repeat(128 + extra);

        prop_assert!(
            DigitalPassportFields::from_raw(
                too_long_name,
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
            ).is_err(),
            "name over 128 bytes must be rejected"
        );
    }

    // 05/25
    #[test]
    fn digital_id_prop_005_short_fields_over_128_bytes_are_rejected(
        field_index in 0usize..6usize,
        extra in 1usize..128usize,
    ) {
        let _guard = digital_id_proptest_guard();
        let too_long = "S".repeat(128 + extra);

        let mut birth = "".to_string();
        let mut sex = "".to_string();
        let mut height = "".to_string();
        let mut nationality = "".to_string();
        let mut country = "".to_string();
        let mut job = "".to_string();

        match field_index {
            0 => birth = too_long,
            1 => sex = too_long,
            2 => height = too_long,
            3 => nationality = too_long,
            4 => country = too_long,
            _ => job = too_long,
        }

        prop_assert!(
            DigitalPassportFields::from_raw(
                "Valid Name".to_string(),
                birth,
                sex,
                height,
                nationality,
                country,
                "".to_string(),
                job,
            ).is_err(),
            "short identity field over 128 bytes must be rejected"
        );
    }

    // 06/25
    #[test]
    fn digital_id_prop_006_address_accepts_up_to_512_and_rejects_over_512(
        good_len in 1usize..=512usize,
        bad_extra in 1usize..64usize,
    ) {
        let _guard = digital_id_proptest_guard();
        let good_address = "A".repeat(good_len);
        let bad_address = "B".repeat(512 + bad_extra);

        prop_assert!(
            DigitalPassportFields::from_raw(
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                good_address,
                "".to_string(),
            ).is_ok(),
            "address up to 512 bytes must be accepted"
        );

        prop_assert!(
            DigitalPassportFields::from_raw(
                "Valid Name".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                bad_address,
                "".to_string(),
            ).is_err(),
            "address over 512 bytes must be rejected"
        );
    }

    // 07/25
    #[test]
    fn digital_id_prop_007_control_characters_are_rejected_in_identity_text(
        field_index in 0usize..8usize,
        control in prop_oneof![Just('\n'), Just('\r'), Just('\t'), Just('\0')],
    ) {
        let _guard = digital_id_proptest_guard();
        let value = format!("abc{control}xyz");

        let mut name = "Valid Name".to_string();
        let mut birth = "".to_string();
        let mut sex = "".to_string();
        let mut height = "".to_string();
        let mut nationality = "".to_string();
        let mut country = "".to_string();
        let mut address = "".to_string();
        let mut job = "".to_string();

        match field_index {
            0 => name = value,
            1 => birth = value,
            2 => sex = value,
            3 => height = value,
            4 => nationality = value,
            5 => country = value,
            6 => address = value,
            _ => job = value,
        }

        prop_assert!(
            DigitalPassportFields::from_raw(
                name,
                birth,
                sex,
                height,
                nationality,
                country,
                address,
                job,
            ).is_err(),
            "control characters in identity text must be rejected"
        );
    }

    // 08/25
    #[test]
    fn digital_id_prop_008_passphrase_confirmation_accepts_matching_nonempty_inputs(
        passphrase in safe_passphrase()
    ) {
        let _guard = digital_id_proptest_guard();
        prop_assert!(
            DigitalPassport::validate_passphrase_confirmation(&passphrase, &passphrase).is_ok(),
            "matching nonempty passphrase and confirmation must validate"
        );
    }

    // 09/25
    #[test]
    fn digital_id_prop_009_passphrase_confirmation_rejects_mismatches(
        first in safe_passphrase(),
        second in safe_passphrase(),
    ) {
        let _guard = digital_id_proptest_guard();
        prop_assume!(first != second);

        prop_assert!(
            DigitalPassport::validate_passphrase_confirmation(&first, &second).is_err(),
            "mismatched passphrase confirmation must be rejected"
        );
    }

    // 10/25
    #[test]
    fn digital_id_prop_010_passphrase_confirmation_rejects_empty_or_too_long_values(
        extra in 1usize..128usize,
    ) {
        let _guard = digital_id_proptest_guard();
        let too_long = "x".repeat(16 * 1024 + extra);

        prop_assert!(DigitalPassport::validate_passphrase_confirmation("", "abc").is_err());
        prop_assert!(DigitalPassport::validate_passphrase_confirmation("abc", "").is_err());
        prop_assert!(
            DigitalPassport::validate_passphrase_confirmation(&too_long, &too_long).is_err(),
            "passphrase over max length must be rejected"
        );
    }

    // 11/25
    #[test]
    fn digital_id_prop_011_new_signed_accepts_generated_lowercase_passport_ids(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id.clone(), wallet.address.clone(), fields)?;

        prop_assert_eq!(&passport.passport_id_hex, &passport_id);
        prop_assert_eq!(&passport.wallet_address, &wallet.address);
        assert_valid_passport_shape(&passport)?;
        prop_assert!(passport.validate().is_ok());
    }

    // 12/25
    #[test]
    fn digital_id_prop_012_new_signed_canonicalizes_mixed_case_passport_id_and_wallet_input(
        passport_id in mixed_hex_128(),
        uppercase_wallet in any::<bool>(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let wallet_input = if uppercase_wallet {
            wallet.address.to_ascii_uppercase()
        } else {
            wallet.address.clone()
        };

        let passport = sign_passport(
            format!("  {passport_id}  "),
            format!("  {wallet_input}  "),
            fields,
        )?;

        prop_assert_eq!(&passport.passport_id_hex, &passport_id.to_ascii_lowercase());
        prop_assert_eq!(&passport.wallet_address, &wallet.address);
        prop_assert!(passport.validate().is_ok());
    }

    // 13/25
    #[test]
    fn digital_id_prop_013_new_signed_rejects_wrong_passport_id_lengths(
        len in 0usize..260usize,
        fill in "[0-9a-f]{1,260}",
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        prop_assume!(len != 128);

        let id = fill.chars().cycle().take(len).collect::<String>();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        prop_assert!(
            DigitalPassport::new_signed(
                id,
                wallet.address.clone(),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                fields,
            ).is_err(),
            "passport_id_hex with wrong length must be rejected"
        );
    }

    // 14/25
    #[test]
    fn digital_id_prop_014_new_signed_rejects_non_hex_passport_id_characters(
        mut passport_id in lower_hex_128(),
        index in 0usize..128usize,
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        passport_id.replace_range(index..index + 1, "g");

        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        prop_assert!(
            DigitalPassport::new_signed(
                passport_id,
                wallet.address.clone(),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                fields,
            ).is_err(),
            "passport_id_hex with non-hex character must be rejected"
        );
    }

    // 15/25
    #[test]
    fn digital_id_prop_015_new_signed_rejects_wallet_address_mismatch(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();
        let other = other_wallet();

        prop_assume!(wallet.address != other.address);

        prop_assert!(
            DigitalPassport::new_signed(
                passport_id,
                other.address.clone(),
                wallet,
                TEST_PASSPHRASE.to_string(),
                TEST_PASSPHRASE.to_string(),
                fields,
            ).is_err(),
            "expected wallet address must match loaded wallet address"
        );
    }

    // 16/25
    #[test]
    fn digital_id_prop_016_valid_signed_passport_verifies_wallet_signature(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        prop_assert!(passport.validate().is_ok());
        prop_assert!(
            passport.verify_wallet_signature()
                .map_err(|e| TestCaseError::fail(format!("verify_wallet_signature errored: {e:?}")))?,
            "valid signed passport must verify"
        );
    }

    // 17/25
    #[test]
    fn digital_id_prop_017_content_bytes_for_nft_are_valid_proof_json_and_exclude_receipt_signature(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        let bytes = passport.content_bytes_for_nft()
            .map_err(|e| TestCaseError::fail(format!("content_bytes_for_nft failed: {e:?}")))?;

        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| TestCaseError::fail(format!("proof payload JSON decode failed: {e}")))?;

        prop_assert_eq!(value.get("kind").and_then(Value::as_str), Some(DIGITAL_PASSPORT_KIND));
        prop_assert_eq!(value.get("schema").and_then(Value::as_str), Some(DIGITAL_PASSPORT_SCHEMA));
        prop_assert_eq!(
            value.get("passport_id_hex").and_then(Value::as_str),
            Some(passport.passport_id_hex.as_str())
        );
        prop_assert_eq!(
            value.get("wallet_address").and_then(Value::as_str),
            Some(passport.wallet_address.as_str())
        );
        prop_assert!(value.get("fields").is_some());
        prop_assert!(value.get("wallet_signature_hex").is_none());
        prop_assert!(value.get("digital_fingerprint_hex").is_none());
    }

    // 18/25
    #[test]
    fn digital_id_prop_018_nft_description_redacts_private_identity_fields(
        tag in "[A-Za-z0-9]{1,32}",
        passport_id in lower_hex_128(),
    ) {
        let _guard = digital_id_proptest_guard();
        let private_name = format!("PrivateName{tag}");
        let private_birth = format!("PrivateBirth{tag}");
        let private_sex = format!("PrivateSex{tag}");
        let private_height = format!("PrivateHeight{tag}");
        let private_nat = format!("PrivateNationality{tag}");
        let private_country = format!("PrivateCountry{tag}");
        let private_address = format!("PrivateAddress{tag}");
        let private_job = format!("PrivateJob{tag}");

        let fields = make_fields(
            private_name.clone(),
            private_birth.clone(),
            private_sex.clone(),
            private_height.clone(),
            private_nat.clone(),
            private_country.clone(),
            private_address.clone(),
            private_job.clone(),
        )?;

        let wallet = test_wallet();
        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        let description = passport.nft_description_redacted();

        prop_assert!(description.contains(DIGITAL_PASSPORT_KIND));
        prop_assert!(description.contains(DIGITAL_PASSPORT_SCHEMA));
        prop_assert!(description.contains(&passport.digital_fingerprint_hex));
        prop_assert!(description.contains(&passport.wallet_address));

        prop_assert!(!description.contains(&private_name));
        prop_assert!(!description.contains(&private_birth));
        prop_assert!(!description.contains(&private_sex));
        prop_assert!(!description.contains(&private_height));
        prop_assert!(!description.contains(&private_nat));
        prop_assert!(!description.contains(&private_country));
        prop_assert!(!description.contains(&private_address));
        prop_assert!(!description.contains(&private_job));
        prop_assert!(!description.contains(&passport.wallet_signature_hex));
        prop_assert!(!description.contains(&passport.wallet_public_key_hex));
    }

    // 19/25
    #[test]
    fn digital_id_prop_019_pretty_json_roundtrips_to_valid_passport_and_excludes_passphrase(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        let json_bytes = passport.to_pretty_json_bytes()
            .map_err(|e| TestCaseError::fail(format!("to_pretty_json_bytes failed: {e:?}")))?;
        let json_text = String::from_utf8(json_bytes.clone())
            .map_err(|e| TestCaseError::fail(format!("JSON was not UTF-8: {e}")))?;

        prop_assert!(json_text.contains('\n'));
        prop_assert!(!json_text.contains(TEST_PASSPHRASE));

        let decoded: DigitalPassport = serde_json::from_slice(&json_bytes)
            .map_err(|e| TestCaseError::fail(format!("DigitalPassport JSON decode failed: {e}")))?;

        prop_assert_eq!(&decoded, &passport);
        prop_assert!(decoded.validate().is_ok());
    }

    // 20/25
    #[test]
    fn digital_id_prop_020_identity_field_tampering_invalidates_passport(
        passport_id in lower_hex_128(),
        original_name in safe_text_64(),
        replacement_name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        prop_assume!(original_name != replacement_name);

        let fields = name_only_fields(original_name)?;
        let wallet = test_wallet();

        let mut passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        passport.fields.name = Some(replacement_name);

        prop_assert!(
            passport.validate().is_err(),
            "changing signed identity fields must invalidate fingerprint/signature"
        );
    }

    // 21/25
    #[test]
    fn digital_id_prop_021_public_key_or_wallet_binding_tampering_invalidates_passport(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
        tamper_wallet in any::<bool>(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();
        let other = other_wallet();

        prop_assume!(wallet.address != other.address);

        let mut passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        if tamper_wallet {
            passport.wallet_address = other.address.clone();
        } else {
            passport.wallet_public_key_hex = hex::encode(other.public);
        }

        prop_assert!(
            passport.validate().is_err(),
            "wallet/public-key binding tampering must invalidate passport"
        );
    }

    // 22/25
    #[test]
    fn digital_id_prop_022_qr_png_generation_is_deterministic_for_same_passport_instance(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        let first = passport.build_qr_png_bytes()
            .map_err(|e| TestCaseError::fail(format!("first QR build failed: {e:?}")))?;
        let second = passport.build_qr_png_bytes()
            .map_err(|e| TestCaseError::fail(format!("second QR build failed: {e:?}")))?;

        prop_assert_eq!(&first, &second);
        assert_png(&first)?;
        prop_assert!(first.len() < 2 * 1024 * 1024);
    }

    // 23/25
    #[test]
    fn digital_id_prop_023_pdf_generation_returns_stable_pdf_for_same_passport_instance(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        let first = passport.build_pdf_bytes()
            .map_err(|e| TestCaseError::fail(format!("first PDF build failed: {e:?}")))?;
        let second = passport.build_pdf_bytes()
            .map_err(|e| TestCaseError::fail(format!("second PDF build failed: {e:?}")))?;

        prop_assert_eq!(&first, &second);
        assert_pdf(&first)?;
        prop_assert!(first.len() < 10 * 1024 * 1024);
    }

    // 24/25
    #[test]
    fn digital_id_prop_024_write_receipt_files_creates_json_pdf_and_qr_outputs(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
        audit_leaf in safe_dir_leaf(),
        pdf_leaf in safe_dir_leaf(),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        let root = temp_dir("prop-write-receipts")
            .map_err(TestCaseError::fail)?;
        let audit_dir = root.join(audit_leaf);
        let pdf_dir = root.join(pdf_leaf);

        let files = passport.write_receipt_files(&audit_dir, &pdf_dir)
            .map_err(|e| TestCaseError::fail(format!("write_receipt_files failed: {e:?}")))?;

        prop_assert!(files.json_path.exists());
        prop_assert!(files.pdf_path.exists());
        prop_assert!(files.qr_png_path.exists());

        prop_assert_eq!(files.json_path.parent(), Some(audit_dir.as_path()));
        prop_assert_eq!(files.pdf_path.parent(), Some(pdf_dir.as_path()));
        prop_assert_eq!(files.qr_png_path.parent(), Some(pdf_dir.as_path()));

        let json_bytes = fs::read(&files.json_path)
            .map_err(|e| TestCaseError::fail(format!("read json failed: {e}")))?;
        let pdf_bytes = fs::read(&files.pdf_path)
            .map_err(|e| TestCaseError::fail(format!("read pdf failed: {e}")))?;
        let qr_bytes = fs::read(&files.qr_png_path)
            .map_err(|e| TestCaseError::fail(format!("read qr failed: {e}")))?;

        let decoded: DigitalPassport = serde_json::from_slice(&json_bytes)
            .map_err(|e| TestCaseError::fail(format!("decode written json failed: {e}")))?;

        prop_assert_eq!(&decoded, &passport);
        assert_pdf(&pdf_bytes)?;
        assert_png(&qr_bytes)?;
    }

    // 25/25
    #[test]
    fn digital_id_prop_025_output_path_that_is_existing_file_is_rejected(
        passport_id in lower_hex_128(),
        name in safe_text_64(),
        file_contents in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let _guard = digital_id_proptest_guard();
        let fields = name_only_fields(name)?;
        let wallet = test_wallet();

        let passport = sign_passport(passport_id, wallet.address.clone(), fields)?;

        let root = temp_dir("prop-output-path-file")
            .map_err(TestCaseError::fail)?;
        let output_file = root.join("not-a-directory");

        fs::write(&output_file, file_contents)
            .map_err(|e| TestCaseError::fail(format!("write output collision file failed: {e}")))?;

        prop_assert!(
            passport.write_json_file(&output_file).is_err(),
            "existing file used as output directory must be rejected"
        );
    }
}
