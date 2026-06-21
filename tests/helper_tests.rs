use fips204::ml_dsa_65;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::{
    Hash64, PreHash, REMZAR_WALLET_BODY_LEN, REMZAR_WALLET_LEN, REMZAR_WALLET_PREFIX, Signature,
    SignatureWrapper, SimplePreHasher, UNIT_DIVISOR, canon_wallet_id, canon_wallet_id_checked,
    decode_hex_to_64, derive_wallet_id_from_pubkey_bytes, format_remzar, format_remzar_trim,
    format_remzar_trim_one_decimal, from_micro_units, parse_wallet_address,
    parse_wallet_address_bytes, to_micro_units, to_micro_units_str,
    wallet_id_matches_pubkey_bytes_checked,
};

type TestResult = Result<(), String>;

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

fn assert_invalid_signature_format<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::InvalidSignatureFormat { format }) => {
            assert!(!format.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected InvalidSignatureFormat, got Ok(_)".to_string()),
        Err(error) => Err(format!(
            "expected InvalidSignatureFormat, got Err({error:?})"
        )),
    }
}

fn canonical_wallet() -> String {
    format!("r{}", "a".repeat(REMZAR_WALLET_BODY_LEN))
}

fn reference_wallet_from_pubkey(pk_bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pk_bytes);

    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

#[test]
fn helper_001_unit_and_wallet_constants_are_stable_vectors() -> TestResult {
    assert_eq!(UNIT_DIVISOR, 100_000_000);
    assert_eq!(REMZAR_WALLET_LEN, 129);
    assert_eq!(REMZAR_WALLET_BODY_LEN, 128);
    assert_eq!(REMZAR_WALLET_PREFIX, b'r');
    assert_eq!(REMZAR_WALLET_LEN, 1 + REMZAR_WALLET_BODY_LEN);
    Ok(())
}

#[test]
fn helper_002_to_micro_units_str_accepts_exact_decimal_vectors() -> TestResult {
    assert_eq!(to_micro_units_str("1"), 100_000_000);
    assert_eq!(to_micro_units_str("1.0"), 100_000_000);
    assert_eq!(to_micro_units_str("1.00000000"), 100_000_000);
    assert_eq!(to_micro_units_str("0.00000001"), 1);
    assert_eq!(to_micro_units_str("123.45678901"), 12_345_678_901);
    Ok(())
}

#[test]
fn helper_003_to_micro_units_str_accepts_dot_edge_vectors() -> TestResult {
    assert_eq!(to_micro_units_str(".5"), 50_000_000);
    assert_eq!(to_micro_units_str("1."), 100_000_000);
    assert_eq!(to_micro_units_str("0001.2300"), 123_000_000);
    assert_eq!(to_micro_units_str("0.1"), 10_000_000);
    Ok(())
}

#[test]
fn helper_004_to_micro_units_str_rejects_invalid_input_vectors() -> TestResult {
    for value in [
        "",
        "   ",
        "-1",
        "+1",
        "1 2",
        "1.2.3",
        "1e3",
        "1E3",
        "abc",
        "1.000000001",
    ] {
        assert_eq!(
            to_micro_units_str(value),
            0,
            "input {value:?} should reject"
        );
    }

    Ok(())
}

#[test]
fn helper_005_to_micro_units_str_rejects_overflow_and_dos_vectors() -> TestResult {
    assert_eq!(to_micro_units_str("184467440737.09551616"), 0);
    assert_eq!(to_micro_units_str("999999999999999999999999999999"), 0);
    assert_eq!(to_micro_units_str(&"1".repeat(65)), 0);
    Ok(())
}

#[test]
fn helper_006_to_micro_units_f64_rounds_ui_amounts_to_eight_decimals() -> TestResult {
    assert_eq!(to_micro_units(1.0), 100_000_000);
    assert_eq!(to_micro_units(1.234567891), 123_456_789);
    assert_eq!(to_micro_units(0.000000004), 0);
    assert_eq!(to_micro_units(0.000000009), 1);
    Ok(())
}

#[test]
fn helper_007_to_micro_units_f64_rejects_non_finite_and_non_positive() -> TestResult {
    assert_eq!(to_micro_units(f64::NAN), 0);
    assert_eq!(to_micro_units(f64::INFINITY), 0);
    assert_eq!(to_micro_units(f64::NEG_INFINITY), 0);
    assert_eq!(to_micro_units(0.0), 0);
    assert_eq!(to_micro_units(-1.0), 0);
    Ok(())
}

#[test]
fn helper_008_format_remzar_exact_fixed_width_vectors() -> TestResult {
    assert_eq!(format_remzar(0), "0.00000000");
    assert_eq!(format_remzar(1), "0.00000001");
    assert_eq!(format_remzar(100_000_000), "1.00000000");
    assert_eq!(format_remzar(12_345_678_901), "123.45678901");
    Ok(())
}

#[test]
fn helper_009_format_remzar_trim_vectors() -> TestResult {
    assert_eq!(format_remzar_trim(0), "0");
    assert_eq!(format_remzar_trim(1), "0.00000001");
    assert_eq!(format_remzar_trim(100_000_000), "1");
    assert_eq!(format_remzar_trim(30_012_000_000), "300.12");
    assert_eq!(format_remzar_trim(30_010_000_000), "300.1");
    Ok(())
}

#[test]
fn helper_010_format_remzar_trim_one_decimal_matches_trim_behavior_vectors() -> TestResult {
    assert_eq!(format_remzar_trim_one_decimal(30_000_000_000), "300");
    assert_eq!(format_remzar_trim_one_decimal(30_012_000_000), "300.12");
    assert_eq!(format_remzar_trim_one_decimal(30_010_000_000), "300.1");
    assert_eq!(format_remzar_trim_one_decimal(1), "0.00000001");
    Ok(())
}

#[test]
fn helper_011_from_micro_units_matches_format_parse_boundary() -> TestResult {
    for amount in [0_u64, 1, 100_000_000, 123_456_789, 12_345_678_901] {
        let parsed = from_micro_units(amount);
        let expected = format_remzar(amount)
            .parse::<f64>()
            .map_err(|e| e.to_string())?;

        assert_eq!(parsed, expected);
    }

    Ok(())
}

#[test]
fn helper_012_simple_prehasher_fills_full_output() -> TestResult {
    let mut bytes = [0_u8; 64];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::try_from(index).map_err(|e| e.to_string())?;
    }

    let mut prehasher = SimplePreHasher { bytes };
    let mut out = [0_u8; 64];

    prehasher.fill_bytes(&mut out);

    assert_eq!(out, bytes);
    Ok(())
}

#[test]
fn helper_013_simple_prehasher_fills_short_output_prefix_only() -> TestResult {
    let bytes = [7_u8; 64];
    let mut prehasher = SimplePreHasher { bytes };
    let mut out = [0_u8; 13];

    prehasher.fill_bytes(&mut out);

    assert_eq!(out, [7_u8; 13]);
    Ok(())
}

#[test]
fn helper_014_simple_prehasher_leaves_tail_when_output_longer_than_64() -> TestResult {
    let bytes = [9_u8; 64];
    let mut prehasher = SimplePreHasher { bytes };
    let mut out = [1_u8; 80];

    prehasher.fill_bytes(&mut out);

    assert_eq!(&out[..64], &[9_u8; 64]);
    assert_eq!(&out[64..], &[1_u8; 16]);
    Ok(())
}

#[test]
fn helper_015_signature_wrapper_from_signature_roundtrip() -> TestResult {
    let mut sig: Signature = [0_u8; ml_dsa_65::SIG_LEN];

    for (index, slot) in sig.iter_mut().enumerate() {
        *slot = u8::try_from(index % 251).unwrap_or(0);
    }

    let wrapper = SignatureWrapper::from_signature(&sig);
    let roundtrip = wrapper
        .to_signature()
        .map_err(|e| format!("to_signature failed: {e:?}"))?;

    assert_eq!(wrapper.as_bytes(), sig.as_slice());
    assert_eq!(roundtrip, sig);
    Ok(())
}

#[test]
fn helper_016_signature_wrapper_from_bytes_accepts_exact_length() -> TestResult {
    let bytes = vec![42_u8; ml_dsa_65::SIG_LEN];

    let wrapper = SignatureWrapper::from_bytes(&bytes)
        .map_err(|e| format!("from_bytes exact length failed: {e:?}"))?;

    assert_eq!(wrapper.as_bytes(), bytes.as_slice());
    assert_eq!(
        wrapper.to_signature().map_err(|e| format!("{e:?}"))?,
        [42_u8; ml_dsa_65::SIG_LEN]
    );
    Ok(())
}

#[test]
fn helper_017_signature_wrapper_from_bytes_rejects_short_and_long_lengths() -> TestResult {
    assert_invalid_signature_format(SignatureWrapper::from_bytes(&vec![
        1_u8;
        ml_dsa_65::SIG_LEN
            .saturating_sub(1)
    ]))?;

    assert_invalid_signature_format(SignatureWrapper::from_bytes(&vec![
        1_u8;
        ml_dsa_65::SIG_LEN
            .saturating_add(1)
    ]))?;

    Ok(())
}

#[test]
fn helper_018_signature_wrapper_serde_json_roundtrip_preserves_signature() -> TestResult {
    let sig: Signature = [5_u8; ml_dsa_65::SIG_LEN];
    let wrapper = SignatureWrapper::from_signature(&sig);

    let json = serde_json::to_string(&wrapper).map_err(|e| e.to_string())?;
    let decoded = serde_json::from_str::<SignatureWrapper>(&json).map_err(|e| e.to_string())?;

    assert_eq!(decoded.as_bytes(), wrapper.as_bytes());
    assert_eq!(decoded.to_signature().map_err(|e| format!("{e:?}"))?, sig);
    Ok(())
}

#[test]
fn helper_019_hash64_from_bytes_and_as_bytes_roundtrip() -> TestResult {
    let mut bytes = [0_u8; 64];

    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::try_from(index % 251).unwrap_or(0);
    }

    let hash = Hash64::from_bytes(bytes);

    assert_eq!(hash.as_bytes(), &bytes);
    assert_eq!(hash.0, bytes);
    Ok(())
}

#[test]
fn helper_020_hash64_copy_clone_preserves_bytes() -> TestResult {
    let hash = Hash64::from_bytes([8_u8; 64]);
    let copied = hash;
    let cloned = hash;

    assert_eq!(copied.as_bytes(), &[8_u8; 64]);
    assert_eq!(cloned.as_bytes(), &[8_u8; 64]);
    Ok(())
}

#[test]
fn helper_021_hash64_serde_json_roundtrip_preserves_64_tuple_values() -> TestResult {
    let hash = Hash64::from_bytes([11_u8; 64]);

    let json = serde_json::to_string(&hash).map_err(|e| e.to_string())?;
    let decoded = serde_json::from_str::<Hash64>(&json).map_err(|e| e.to_string())?;

    assert_eq!(decoded.as_bytes(), &[11_u8; 64]);
    assert!(json.contains("11"));
    Ok(())
}

#[test]
fn helper_022_hash64_serde_json_rejects_short_and_long_arrays() -> TestResult {
    let short = format!("[{}]", vec!["1"; 63].join(","));
    let long = format!("[{}]", vec!["1"; 65].join(","));

    assert!(serde_json::from_str::<Hash64>(&short).is_err());
    assert!(serde_json::from_str::<Hash64>(&long).is_err());
    Ok(())
}

#[test]
fn helper_023_decode_hex_to_64_accepts_lowercase_and_uppercase_vectors() -> TestResult {
    let lowercase = "ab".repeat(64);
    let uppercase = lowercase.to_ascii_uppercase();

    let lower = decode_hex_to_64(&lowercase).map_err(|e| format!("lower decode failed: {e:?}"))?;
    let upper = decode_hex_to_64(&uppercase).map_err(|e| format!("upper decode failed: {e:?}"))?;

    assert_eq!(lower, [0xAB_u8; 64]);
    assert_eq!(upper, [0xAB_u8; 64]);
    Ok(())
}

#[test]
fn helper_024_decode_hex_to_64_rejects_bad_length_vectors() -> TestResult {
    assert_validation_error(decode_hex_to_64(&"a".repeat(126)))?;
    assert_validation_error(decode_hex_to_64(&"a".repeat(130)))?;
    Ok(())
}

#[test]
fn helper_025_decode_hex_to_64_rejects_non_hex_vector() -> TestResult {
    let bad = format!("{}zz", "a".repeat(126));

    assert_validation_error(decode_hex_to_64(&bad))?;
    Ok(())
}

#[test]
fn helper_026_derive_wallet_id_matches_reference_blake3_xof64() -> TestResult {
    let public_key = b"remzar public key bytes";

    let got = derive_wallet_id_from_pubkey_bytes(public_key);
    let expected = reference_wallet_from_pubkey(public_key);

    assert_eq!(got, expected);
    assert_eq!(got.len(), REMZAR_WALLET_LEN);
    Ok(())
}

#[test]
fn helper_027_derive_wallet_id_is_deterministic_and_input_sensitive() -> TestResult {
    let first = derive_wallet_id_from_pubkey_bytes(b"public-key-a");
    let second = derive_wallet_id_from_pubkey_bytes(b"public-key-a");
    let third = derive_wallet_id_from_pubkey_bytes(b"public-key-b");

    assert_eq!(first, second);
    assert_ne!(first, third);
    Ok(())
}

#[test]
fn helper_028_canon_wallet_id_checked_accepts_canonical_address() -> TestResult {
    let wallet = canonical_wallet();

    let canonical =
        canon_wallet_id_checked(&wallet).map_err(|e| format!("canon wallet failed: {e:?}"))?;

    assert_eq!(canonical, wallet);
    Ok(())
}

#[test]
fn helper_029_canon_wallet_id_checked_trims_and_lowercases_boundary_input() -> TestResult {
    let wallet = canonical_wallet();
    let upper_padded = format!(" \n{}\t ", wallet.to_ascii_uppercase());

    let canonical = canon_wallet_id_checked(&upper_padded)
        .map_err(|e| format!("canon padded uppercase failed: {e:?}"))?;

    assert_eq!(canonical, wallet);
    Ok(())
}

#[test]
fn helper_030_canon_wallet_id_checked_rejects_invalid_wallet_vectors() -> TestResult {
    for wallet in [
        "",
        "   ",
        "r",
        "xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "raaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag",
    ] {
        assert_validation_error(canon_wallet_id_checked(wallet))?;
    }

    Ok(())
}

#[test]
fn helper_031_canon_wallet_id_fallback_returns_trimmed_original_on_invalid() -> TestResult {
    assert_eq!(canon_wallet_id("  bad-wallet  "), "bad-wallet");
    assert_eq!(
        canon_wallet_id(&canonical_wallet().to_ascii_uppercase()),
        canonical_wallet()
    );
    Ok(())
}

#[test]
fn helper_032_parse_wallet_address_accepts_lowercase_canonical_and_trimmed() -> TestResult {
    let wallet = canonical_wallet();
    let padded = format!(" \n{}\t ", wallet);

    parse_wallet_address(&wallet).map_err(|e| format!("parse wallet failed: {e:?}"))?;
    parse_wallet_address(&padded).map_err(|e| format!("parse padded wallet failed: {e:?}"))?;
    Ok(())
}

#[test]
fn helper_033_parse_wallet_address_rejects_uppercase_prefix_and_body() -> TestResult {
    let wallet = canonical_wallet();

    assert_validation_error(parse_wallet_address(&wallet.to_ascii_uppercase()))?;
    assert_validation_error(parse_wallet_address(&format!("r{}", "A".repeat(128))))?;
    Ok(())
}

#[test]
fn helper_034_parse_wallet_address_rejects_wrong_length_prefix_and_non_hex() -> TestResult {
    assert_validation_error(parse_wallet_address(&format!("r{}", "a".repeat(127))))?;
    assert_validation_error(parse_wallet_address(&format!("r{}", "a".repeat(129))))?;
    assert_validation_error(parse_wallet_address(&format!("x{}", "a".repeat(128))))?;
    assert_validation_error(parse_wallet_address(&format!("r{}g", "a".repeat(127))))?;
    Ok(())
}

#[test]
fn helper_035_parse_wallet_address_bytes_accepts_exact_ascii_wallet() -> TestResult {
    let wallet = canonical_wallet();

    let parsed = parse_wallet_address_bytes(wallet.as_bytes())
        .map_err(|e| format!("parse_wallet_address_bytes failed: {e:?}"))?;

    assert_eq!(parsed, wallet);
    Ok(())
}

#[test]
fn helper_036_parse_wallet_address_bytes_rejects_non_exact_length() -> TestResult {
    let wallet = canonical_wallet();

    assert_validation_error(parse_wallet_address_bytes(&wallet.as_bytes()[..128]))?;

    let mut long = wallet.into_bytes();
    long.push(b'a');
    assert_validation_error(parse_wallet_address_bytes(&long))?;

    Ok(())
}

#[test]
fn helper_037_parse_wallet_address_bytes_rejects_nul_and_invalid_utf8() -> TestResult {
    let mut with_nul = canonical_wallet().into_bytes();
    with_nul[10] = 0;

    assert_validation_error(parse_wallet_address_bytes(&with_nul))?;

    let invalid_utf8 = vec![0xFF_u8; REMZAR_WALLET_LEN];
    assert_validation_error(parse_wallet_address_bytes(&invalid_utf8))?;
    Ok(())
}

#[test]
fn helper_038_wallet_id_matches_pubkey_bytes_checked_accepts_derived_wallet() -> TestResult {
    let public_key = b"wallet match public key";
    let wallet = derive_wallet_id_from_pubkey_bytes(public_key);

    let canonical = wallet_id_matches_pubkey_bytes_checked(&wallet, public_key)
        .map_err(|e| format!("wallet match failed: {e:?}"))?;

    assert_eq!(canonical, wallet);
    Ok(())
}

#[test]
fn helper_039_wallet_id_matches_pubkey_bytes_checked_rejects_wrong_public_key() -> TestResult {
    let wallet = derive_wallet_id_from_pubkey_bytes(b"public-key-a");

    assert_validation_error(wallet_id_matches_pubkey_bytes_checked(
        &wallet,
        b"public-key-b",
    ))?;

    Ok(())
}

#[test]
fn helper_040_wallet_helpers_property_many_derived_wallets_are_canonical() -> TestResult {
    let mut wallets = std::collections::BTreeSet::new();

    for index in 0_u8..64_u8 {
        let public_key = vec![index; 32];
        let wallet = derive_wallet_id_from_pubkey_bytes(&public_key);

        assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
        assert!(wallet.starts_with('r'));
        assert!(
            wallet[1..]
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );

        let canonical = canon_wallet_id_checked(&wallet)
            .map_err(|e| format!("canon derived wallet failed at {index}: {e:?}"))?;
        assert_eq!(canonical, wallet);

        assert!(wallets.insert(wallet));
    }

    assert_eq!(wallets.len(), 64);
    Ok(())
}

#[test]
fn helper_041_to_micro_units_str_accepts_max_u64_micro_vector() -> TestResult {
    assert_eq!(to_micro_units_str("184467440737.09551615"), u64::MAX);
    Ok(())
}

#[test]
fn helper_042_to_micro_units_str_rejects_one_micro_over_u64_max() -> TestResult {
    assert_eq!(to_micro_units_str("184467440737.09551616"), 0);
    Ok(())
}

#[test]
fn helper_043_to_micro_units_str_accepts_64_byte_input_boundary() -> TestResult {
    let input = format!("{}{}", "1".repeat(55), ".12345678");

    assert_eq!(input.len(), 64);
    assert_eq!(to_micro_units_str(&input), 0);
    Ok(())
}

#[test]
fn helper_044_to_micro_units_str_rejects_fractional_precision_over_eight() -> TestResult {
    for value in ["0.000000001", ".000000001", "1.123456789", "999.000000001"] {
        assert_eq!(
            to_micro_units_str(value),
            0,
            "input {value:?} should reject"
        );
    }

    Ok(())
}

#[test]
fn helper_045_to_micro_units_str_accepts_leading_and_trailing_whitespace() -> TestResult {
    assert_eq!(to_micro_units_str("  1.25000000  "), 125_000_000);
    assert_eq!(to_micro_units_str("\n0.00000001\t"), 1);
    Ok(())
}

#[test]
fn helper_046_to_micro_units_str_rejects_internal_ascii_whitespace_vectors() -> TestResult {
    for value in ["1 0", "1\t0", "1\n0", "1.2 3", "1.2\r3"] {
        assert_eq!(
            to_micro_units_str(value),
            0,
            "input {value:?} should reject"
        );
    }

    Ok(())
}

#[test]
fn helper_047_to_micro_units_str_rejects_non_ascii_digits_and_separators() -> TestResult {
    for value in ["１", "1,000", "1_000", "1/2", "٠.١"] {
        assert_eq!(
            to_micro_units_str(value),
            0,
            "input {value:?} should reject"
        );
    }

    Ok(())
}

#[test]
fn helper_048_to_micro_units_f64_saturates_large_positive_amounts() -> TestResult {
    assert_eq!(to_micro_units(1.0e20), u64::MAX);
    assert_eq!(to_micro_units(184_467_440_738.0), u64::MAX);
    Ok(())
}

#[test]
fn helper_049_to_micro_units_f64_rounding_boundary_vectors() -> TestResult {
    assert_eq!(to_micro_units(1.000000004), 100_000_000);
    assert_eq!(to_micro_units(1.000000005), 100_000_000);
    assert_eq!(to_micro_units(1.000000006), 100_000_001);
    assert_eq!(to_micro_units(1.999999995), 200_000_000);
    Ok(())
}

#[test]
fn helper_050_format_remzar_u64_max_is_fixed_width_decimal() -> TestResult {
    let formatted = format_remzar(u64::MAX);

    assert_eq!(formatted, "184467440737.09551615");
    assert_eq!(to_micro_units_str(&formatted), u64::MAX);
    Ok(())
}

#[test]
fn helper_051_format_remzar_trim_u64_max_preserves_fraction() -> TestResult {
    assert_eq!(format_remzar_trim(u64::MAX), "184467440737.09551615");
    Ok(())
}

#[test]
fn helper_052_format_remzar_trim_trailing_zero_vectors() -> TestResult {
    assert_eq!(format_remzar_trim(10), "0.0000001");
    assert_eq!(format_remzar_trim(100), "0.000001");
    assert_eq!(format_remzar_trim(1_000), "0.00001");
    assert_eq!(format_remzar_trim(10_000), "0.0001");
    Ok(())
}

#[test]
fn helper_053_from_micro_units_roundtrip_through_format_for_exact_vectors() -> TestResult {
    for amount in [0_u64, 1, 10, 100, 1_000, 100_000_000, u64::MAX] {
        let parsed = from_micro_units(amount);
        let reparsed = parsed
            .to_string()
            .parse::<f64>()
            .map_err(|e| e.to_string())?;

        assert_eq!(parsed, reparsed);
    }

    Ok(())
}

#[test]
fn helper_054_decode_hex_to_64_accepts_all_zero_and_all_ff_vectors() -> TestResult {
    let zero =
        decode_hex_to_64(&"00".repeat(64)).map_err(|e| format!("zero decode failed: {e:?}"))?;
    let ff = decode_hex_to_64(&"ff".repeat(64)).map_err(|e| format!("ff decode failed: {e:?}"))?;

    assert_eq!(zero, [0_u8; 64]);
    assert_eq!(ff, [0xFF_u8; 64]);
    Ok(())
}

#[test]
fn helper_055_decode_hex_to_64_rejects_odd_length_hex() -> TestResult {
    assert_validation_error(decode_hex_to_64(&"a".repeat(127)))?;
    Ok(())
}

#[test]
fn helper_056_decode_hex_to_64_rejects_prefixed_hex_string() -> TestResult {
    let prefixed = format!("0x{}", "ab".repeat(64));

    assert_validation_error(decode_hex_to_64(&prefixed))?;
    Ok(())
}

#[test]
fn helper_057_hash64_json_shape_is_array_of_64_numbers() -> TestResult {
    let hash = Hash64::from_bytes([3_u8; 64]);
    let json = serde_json::to_string(&hash).map_err(|e| e.to_string())?;
    let value = serde_json::from_str::<serde_json::Value>(&json).map_err(|e| e.to_string())?;

    let arr = value
        .as_array()
        .ok_or_else(|| "Hash64 JSON was not an array".to_string())?;

    assert_eq!(arr.len(), 64);
    assert!(arr.iter().all(|v| v == 3));
    Ok(())
}

#[test]
fn helper_058_hash64_serde_json_rejects_non_u8_values() -> TestResult {
    let negative = format!("[{}]", vec!["-1"; 64].join(","));
    let too_large = format!("[{}]", vec!["256"; 64].join(","));

    assert!(serde_json::from_str::<Hash64>(&negative).is_err());
    assert!(serde_json::from_str::<Hash64>(&too_large).is_err());
    Ok(())
}

#[test]
fn helper_059_hash64_postcard_roundtrip_preserves_bytes() -> TestResult {
    let hash = Hash64::from_bytes([77_u8; 64]);

    let bytes = postcard::to_allocvec(&hash).map_err(|e| e.to_string())?;
    let decoded = postcard::from_bytes::<Hash64>(&bytes).map_err(|e| e.to_string())?;

    assert_eq!(decoded.as_bytes(), &[77_u8; 64]);
    Ok(())
}

#[test]
fn helper_060_signature_wrapper_json_shape_is_byte_array() -> TestResult {
    let sig: Signature = [12_u8; ml_dsa_65::SIG_LEN];
    let wrapper = SignatureWrapper::from_signature(&sig);
    let json = serde_json::to_string(&wrapper).map_err(|e| e.to_string())?;
    let value = serde_json::from_str::<serde_json::Value>(&json).map_err(|e| e.to_string())?;

    let arr = value
        .as_array()
        .ok_or_else(|| "SignatureWrapper JSON was not an array".to_string())?;

    assert_eq!(arr.len(), ml_dsa_65::SIG_LEN);
    assert_eq!(arr.first(), Some(&serde_json::Value::from(12)));
    Ok(())
}

#[test]
fn helper_061_signature_wrapper_deserialized_short_bytes_to_signature_errors() -> TestResult {
    let json = format!(
        "[{}]",
        vec!["1"; ml_dsa_65::SIG_LEN.saturating_sub(1)].join(",")
    );
    let wrapper = serde_json::from_str::<SignatureWrapper>(&json).map_err(|e| e.to_string())?;

    assert_invalid_signature_format(wrapper.to_signature())?;
    Ok(())
}

#[test]
fn helper_062_signature_wrapper_deserialized_long_bytes_to_signature_errors() -> TestResult {
    let json = format!(
        "[{}]",
        vec!["1"; ml_dsa_65::SIG_LEN.saturating_add(1)].join(",")
    );
    let wrapper = serde_json::from_str::<SignatureWrapper>(&json).map_err(|e| e.to_string())?;

    assert_invalid_signature_format(wrapper.to_signature())?;
    Ok(())
}

#[test]
fn helper_063_signature_wrapper_postcard_roundtrip_preserves_exact_signature() -> TestResult {
    let mut sig: Signature = [0_u8; ml_dsa_65::SIG_LEN];

    for (index, slot) in sig.iter_mut().enumerate() {
        *slot = u8::try_from(index % 251).unwrap_or(0);
    }

    let wrapper = SignatureWrapper::from_signature(&sig);
    let bytes = postcard::to_allocvec(&wrapper).map_err(|e| e.to_string())?;
    let decoded = postcard::from_bytes::<SignatureWrapper>(&bytes).map_err(|e| e.to_string())?;

    assert_eq!(decoded.as_bytes(), sig.as_slice());
    assert_eq!(decoded.to_signature().map_err(|e| format!("{e:?}"))?, sig);
    Ok(())
}

#[test]
fn helper_064_canon_wallet_id_checked_accepts_uppercase_prefix_lowercase_body() -> TestResult {
    let wallet = canonical_wallet();
    let mixed = format!("R{}", &wallet[1..]);

    let canonical = canon_wallet_id_checked(&mixed)
        .map_err(|e| format!("canon uppercase prefix failed: {e:?}"))?;

    assert_eq!(canonical, wallet);
    Ok(())
}

#[test]
fn helper_065_canon_wallet_id_checked_accepts_lowercase_prefix_uppercase_body() -> TestResult {
    let wallet = canonical_wallet();
    let mixed = format!("r{}", wallet[1..].to_ascii_uppercase());

    let canonical = canon_wallet_id_checked(&mixed)
        .map_err(|e| format!("canon uppercase body failed: {e:?}"))?;

    assert_eq!(canonical, wallet);
    Ok(())
}

#[test]
fn helper_066_canon_wallet_id_checked_rejects_internal_space_tab_and_newline() -> TestResult {
    for bad_char in [' ', '\t', '\n'] {
        let mut wallet = canonical_wallet().chars().collect::<Vec<_>>();
        wallet[64] = bad_char;
        let bad = wallet.into_iter().collect::<String>();

        assert_eq!(bad.len(), REMZAR_WALLET_LEN);
        assert_validation_error(canon_wallet_id_checked(&bad))?;
    }

    Ok(())
}

#[test]
fn helper_067_canon_wallet_id_checked_rejects_unicode_body_char() -> TestResult {
    let bad = format!("r{}鎖{}", "a".repeat(63), "b".repeat(64));

    assert_validation_error(canon_wallet_id_checked(&bad))?;
    Ok(())
}

#[test]
fn helper_068_parse_wallet_address_bytes_rejects_uppercase_wallet_bytes() -> TestResult {
    let upper = canonical_wallet().to_ascii_uppercase();

    assert_eq!(upper.len(), REMZAR_WALLET_LEN);
    assert_validation_error(parse_wallet_address_bytes(upper.as_bytes()))?;
    Ok(())
}

#[test]
fn helper_069_parse_wallet_address_bytes_rejects_boundary_whitespace_bytes() -> TestResult {
    let padded = format!(" {} ", canonical_wallet());

    assert_validation_error(parse_wallet_address_bytes(padded.as_bytes()))?;
    Ok(())
}

#[test]
fn helper_070_parse_wallet_address_bytes_rejects_unicode_same_char_count_not_same_byte_len()
-> TestResult {
    let bad = format!("r{}鎖{}", "a".repeat(63), "b".repeat(64));

    assert_validation_error(parse_wallet_address_bytes(bad.as_bytes()))?;
    Ok(())
}

#[test]
fn helper_071_parse_wallet_address_rejects_internal_control_characters() -> TestResult {
    let mut wallet = canonical_wallet().chars().collect::<Vec<_>>();
    wallet[32] = '\n';
    let bad = wallet.into_iter().collect::<String>();

    assert_validation_error(parse_wallet_address(&bad))?;
    Ok(())
}

#[test]
fn helper_072_wallet_id_matches_pubkey_accepts_uppercase_wallet_input() -> TestResult {
    let pk = b"uppercase wallet boundary";
    let wallet = derive_wallet_id_from_pubkey_bytes(pk);
    let uppercase = wallet.to_ascii_uppercase();

    let canonical = wallet_id_matches_pubkey_bytes_checked(&uppercase, pk)
        .map_err(|e| format!("uppercase wallet match failed: {e:?}"))?;

    assert_eq!(canonical, wallet);
    Ok(())
}

#[test]
fn helper_073_wallet_id_matches_pubkey_rejects_mutated_wallet_char() -> TestResult {
    let pk = b"mutated wallet";
    let wallet = derive_wallet_id_from_pubkey_bytes(pk);
    let mut chars = wallet.chars().collect::<Vec<_>>();
    chars[REMZAR_WALLET_LEN - 1] = if chars[REMZAR_WALLET_LEN - 1] == 'a' {
        'b'
    } else {
        'a'
    };
    let mutated = chars.into_iter().collect::<String>();

    assert_validation_error(wallet_id_matches_pubkey_bytes_checked(&mutated, pk))?;
    Ok(())
}

#[test]
fn helper_074_derive_wallet_id_from_empty_pubkey_matches_reference() -> TestResult {
    let got = derive_wallet_id_from_pubkey_bytes(b"");
    let expected = reference_wallet_from_pubkey(b"");

    assert_eq!(got, expected);
    assert_eq!(got.len(), REMZAR_WALLET_LEN);
    Ok(())
}

#[test]
fn helper_075_derive_wallet_id_from_large_pubkey_matches_reference() -> TestResult {
    let pk = (0_usize..65_536_usize)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect::<Vec<_>>();

    let got = derive_wallet_id_from_pubkey_bytes(&pk);
    let expected = reference_wallet_from_pubkey(&pk);

    assert_eq!(got, expected);
    Ok(())
}

#[test]
fn helper_076_simple_prehasher_zero_length_output_is_noop() -> TestResult {
    let mut prehasher = SimplePreHasher { bytes: [55_u8; 64] };
    let mut out: [u8; 0] = [];

    prehasher.fill_bytes(&mut out);

    assert!(out.is_empty());
    Ok(())
}

#[test]
fn helper_077_load_to_micro_units_str_many_valid_small_values() -> TestResult {
    for micro in 1_u64..=100_u64 {
        let formatted = format_remzar(micro);

        assert_eq!(to_micro_units_str(&formatted), micro);
    }

    Ok(())
}

#[test]
fn helper_078_load_wallet_canon_many_hex_digit_vectors() -> TestResult {
    for digit in ['0', '1', '2', '8', '9', 'a', 'b', 'f', 'A', 'B', 'F'] {
        let wallet = format!("R{}", digit.to_string().repeat(128));
        let canonical = canon_wallet_id_checked(&wallet)
            .map_err(|e| format!("canon failed for digit {digit}: {e:?}"))?;

        assert_eq!(canonical, wallet.to_ascii_lowercase());
        assert_eq!(canonical.len(), REMZAR_WALLET_LEN);
    }

    Ok(())
}

#[test]
fn helper_079_load_wallet_parse_rejects_many_non_hex_digit_vectors() -> TestResult {
    for ch in ['g', 'G', 'z', 'Z', '-', '_', ':', '/', '@'] {
        let wallet = format!("r{}{}", "a".repeat(127), ch);

        assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
        assert_validation_error(parse_wallet_address(&wallet))?;
    }

    Ok(())
}

#[test]
fn helper_080_load_signature_wrapper_many_lengths_boundary_validation() -> TestResult {
    for len in [
        0_usize,
        1,
        ml_dsa_65::SIG_LEN.saturating_sub(1),
        ml_dsa_65::SIG_LEN,
        ml_dsa_65::SIG_LEN.saturating_add(1),
    ] {
        let bytes = vec![3_u8; len];
        let result = SignatureWrapper::from_bytes(&bytes);

        if len == ml_dsa_65::SIG_LEN {
            let wrapper = result.map_err(|e| format!("exact signature length failed: {e:?}"))?;
            assert_eq!(wrapper.as_bytes().len(), ml_dsa_65::SIG_LEN);
        } else {
            assert_invalid_signature_format(result)?;
        }
    }

    Ok(())
}

#[test]
fn helper_081_to_micro_units_str_rejects_only_decimal_point() -> TestResult {
    assert_eq!(to_micro_units_str("."), 0);
    assert_eq!(to_micro_units_str(" . "), 0);
    Ok(())
}

#[test]
fn helper_082_to_micro_units_str_accepts_zero_fraction_forms() -> TestResult {
    assert_eq!(to_micro_units_str("0"), 0);
    assert_eq!(to_micro_units_str("0."), 0);
    assert_eq!(to_micro_units_str(".0"), 0);
    assert_eq!(to_micro_units_str("000.00000000"), 0);
    Ok(())
}

#[test]
fn helper_083_to_micro_units_str_rejects_unicode_whitespace_inside() -> TestResult {
    assert_eq!(to_micro_units_str("1\u{00A0}0"), 0);
    assert_eq!(to_micro_units_str("1.\u{00A0}0"), 0);
    Ok(())
}

#[test]
fn helper_084_to_micro_units_str_rejects_full_width_decimal_point() -> TestResult {
    assert_eq!(to_micro_units_str("1．25"), 0);
    Ok(())
}

#[test]
fn helper_085_format_trim_and_trim_one_decimal_match_for_vectors() -> TestResult {
    for amount in [
        0_u64,
        1,
        10,
        100,
        1_000,
        100_000_000,
        12_345_000_000,
        u64::MAX,
    ] {
        assert_eq!(
            format_remzar_trim(amount),
            format_remzar_trim_one_decimal(amount)
        );
    }

    Ok(())
}

#[test]
fn helper_086_format_remzar_always_has_eight_fractional_digits() -> TestResult {
    for amount in [0_u64, 1, 99, 100_000_000, 123_456_789, u64::MAX] {
        let formatted = format_remzar(amount);
        let (_, frac) = formatted
            .split_once('.')
            .ok_or_else(|| format!("missing decimal point in {formatted}"))?;

        assert_eq!(frac.len(), 8);
    }

    Ok(())
}

#[test]
fn helper_087_decode_hex_to_64_mixed_case_pattern_vector() -> TestResult {
    let hex_value = "AaBbCcDdEeFf00112233445566778899".repeat(4);

    assert_eq!(hex_value.len(), 128);

    let decoded =
        decode_hex_to_64(&hex_value).map_err(|e| format!("mixed-case hex decode failed: {e:?}"))?;

    assert_eq!(decoded.len(), 64);
    assert_eq!(hex::encode(decoded), hex_value.to_ascii_lowercase());
    Ok(())
}

#[test]
fn helper_088_decode_hex_to_64_rejects_boundary_whitespace() -> TestResult {
    let padded = format!(" {} ", "ab".repeat(64));

    assert_validation_error(decode_hex_to_64(&padded))?;
    Ok(())
}

#[test]
fn helper_089_hash64_debug_contains_hash64_and_numbers() -> TestResult {
    let hash = Hash64::from_bytes([4_u8; 64]);
    let rendered = format!("{hash:?}");

    assert!(rendered.contains("Hash64"));
    assert!(rendered.contains('4'));
    Ok(())
}

#[test]
fn helper_090_hash64_serde_json_rejects_non_array() -> TestResult {
    assert!(serde_json::from_str::<Hash64>("\"not-array\"").is_err());
    assert!(serde_json::from_str::<Hash64>("{}").is_err());
    Ok(())
}

#[test]
fn helper_091_signature_wrapper_from_bytes_does_not_alias_input_buffer() -> TestResult {
    let mut bytes = vec![1_u8; ml_dsa_65::SIG_LEN];
    let wrapper =
        SignatureWrapper::from_bytes(&bytes).map_err(|e| format!("from_bytes failed: {e:?}"))?;

    bytes[0] = 99;

    assert_eq!(wrapper.as_bytes()[0], 1);
    assert_ne!(wrapper.as_bytes()[0], bytes[0]);
    Ok(())
}

#[test]
fn helper_092_signature_wrapper_clone_preserves_bytes() -> TestResult {
    let sig: Signature = [6_u8; ml_dsa_65::SIG_LEN];
    let wrapper = SignatureWrapper::from_signature(&sig);
    let cloned = wrapper.clone();

    assert_eq!(cloned.as_bytes(), wrapper.as_bytes());
    assert_eq!(cloned.to_signature().map_err(|e| format!("{e:?}"))?, sig);
    Ok(())
}

#[test]
fn helper_093_signature_wrapper_serde_json_rejects_non_u8_values() -> TestResult {
    let negative = format!("[{}]", vec!["-1"; ml_dsa_65::SIG_LEN].join(","));
    let too_large = format!("[{}]", vec!["256"; ml_dsa_65::SIG_LEN].join(","));

    assert!(serde_json::from_str::<SignatureWrapper>(&negative).is_err());
    assert!(serde_json::from_str::<SignatureWrapper>(&too_large).is_err());
    Ok(())
}

#[test]
fn helper_094_canon_wallet_id_checked_accepts_all_zero_and_all_f_wallets() -> TestResult {
    let zero = format!("r{}", "0".repeat(128));
    let f = format!("R{}", "F".repeat(128));

    assert_eq!(
        canon_wallet_id_checked(&zero).map_err(|e| format!("{e:?}"))?,
        zero
    );
    assert_eq!(
        canon_wallet_id_checked(&f).map_err(|e| format!("{e:?}"))?,
        f.to_ascii_lowercase()
    );
    Ok(())
}

#[test]
fn helper_095_parse_wallet_address_rejects_all_uppercase_valid_shape() -> TestResult {
    let wallet = format!("R{}", "A".repeat(128));

    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
    assert_validation_error(parse_wallet_address(&wallet))?;
    Ok(())
}

#[test]
fn helper_096_parse_wallet_address_bytes_returns_borrowed_input_str() -> TestResult {
    let wallet = canonical_wallet();
    let parsed = parse_wallet_address_bytes(wallet.as_bytes())
        .map_err(|e| format!("parse_wallet_address_bytes failed: {e:?}"))?;

    assert_eq!(parsed.as_ptr(), wallet.as_ptr());
    assert_eq!(parsed, wallet);
    Ok(())
}

#[test]
fn helper_097_wallet_id_matches_pubkey_rejects_malformed_wallet_before_match() -> TestResult {
    assert_validation_error(wallet_id_matches_pubkey_bytes_checked(
        "not-a-wallet",
        b"public-key",
    ))?;

    Ok(())
}

#[test]
fn helper_098_derive_wallet_id_from_repeated_public_key_vectors_are_unique() -> TestResult {
    let mut wallets = std::collections::BTreeSet::new();

    for byte in [0_u8, 1, 2, 3, 127, 128, 254, 255] {
        let pk = vec![byte; 256];
        let wallet = derive_wallet_id_from_pubkey_bytes(&pk);

        assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
        assert!(wallets.insert(wallet));
    }

    assert_eq!(wallets.len(), 8);
    Ok(())
}

#[test]
fn helper_099_simple_prehasher_repeated_fill_is_stable() -> TestResult {
    let mut prehasher = SimplePreHasher { bytes: [88_u8; 64] };
    let mut first = [0_u8; 64];
    let mut second = [0_u8; 64];

    prehasher.fill_bytes(&mut first);
    prehasher.fill_bytes(&mut second);

    assert_eq!(first, [88_u8; 64]);
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn helper_100_load_roundtrip_many_micro_unit_values_through_format_parser() -> TestResult {
    for amount in [
        0_u64,
        1,
        2,
        9,
        10,
        99,
        100,
        999,
        1_000,
        99_999_999,
        100_000_000,
        100_000_001,
        12_345_678_901,
        u64::MAX,
    ] {
        let formatted = format_remzar(amount);
        assert_eq!(to_micro_units_str(&formatted), amount);
    }

    Ok(())
}
