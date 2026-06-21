use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

type TestResult = Result<(), String>;

fn debug_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn encrypt_bytes(plain: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    Cryption::encrypt_private_key_bytes(plain, passphrase).map_err(debug_err)
}

fn decrypt_bytes(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    Cryption::decrypt_private_key_bytes(encrypted, passphrase).map_err(debug_err)
}

fn encrypt_string(plain: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    Cryption::encrypt_private_key(plain, passphrase).map_err(debug_err)
}

fn decrypt_string(encrypted: &[u8], passphrase: &str) -> Result<String, String> {
    Cryption::decrypt_private_key(encrypted, passphrase).map_err(debug_err)
}

fn blake3_xof64(data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);

    let mut out = [0_u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn deterministic_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let low = i.to_le_bytes()[0];
            seed.wrapping_add(low).rotate_left(1)
        })
        .collect()
}

fn flip_byte(data: &mut [u8], position: usize) -> TestResult {
    let byte = data
        .get_mut(position)
        .ok_or_else(|| format!("byte position {position} out of bounds"))?;
    *byte ^= 1;
    Ok(())
}

fn salt_range() -> core::ops::Range<usize> {
    0..Cryption::SALT_BYTES
}

fn nonce_range() -> core::ops::Range<usize> {
    Cryption::SALT_BYTES..Cryption::SALT_BYTES + Cryption::NONCE_BYTES
}

fn ciphertext_range(len: usize) -> core::ops::Range<usize> {
    Cryption::SALT_BYTES + Cryption::NONCE_BYTES..len
}

#[test]
fn cryption_001_constants_match_expected_crypto_layout() -> TestResult {
    assert_eq!(Cryption::ML_DSA_65_SECRET_BYTES, 4_032);
    assert_eq!(Cryption::ML_DSA_65_SECRET_HEX_CHARS, 8_064);
    assert_eq!(Cryption::AES256_KEY_BYTES, 32);
    assert_eq!(Cryption::SALT_BYTES, 16);
    assert_eq!(Cryption::NONCE_BYTES, 12);
    assert_eq!(Cryption::GCM_TAG_BYTES, 16);

    Ok(())
}

#[test]
fn cryption_002_minimum_encrypted_blob_constants_are_exact() -> TestResult {
    assert_eq!(
        Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES,
        Cryption::SALT_BYTES
            + Cryption::NONCE_BYTES
            + Cryption::GCM_TAG_BYTES
            + Cryption::ML_DSA_65_SECRET_BYTES
    );
    assert_eq!(
        Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_HEX,
        Cryption::SALT_BYTES
            + Cryption::NONCE_BYTES
            + Cryption::GCM_TAG_BYTES
            + Cryption::ML_DSA_65_SECRET_HEX_CHARS
    );

    Ok(())
}

#[test]
fn cryption_003_configuration_sizes_match_cryption_layout() -> TestResult {
    assert_eq!(GlobalConfiguration::SALT_SIZE, Cryption::SALT_BYTES);
    assert_eq!(GlobalConfiguration::NONCE_SIZE, Cryption::NONCE_BYTES);

    const {
        assert!(GlobalConfiguration::MAX_PRIVATE_KEY_BYTES >= Cryption::ML_DSA_65_SECRET_BYTES);
        assert!(
            GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES
                >= Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES
        );
    }

    Ok(())
}

#[test]
fn cryption_004_core_hash_empty_matches_blake3_xof64_vector() -> TestResult {
    assert_eq!(Cryption::compute_core_hash(b""), blake3_xof64(b""));
    Ok(())
}

#[test]
fn cryption_005_core_hash_known_message_matches_blake3_xof64_vector() -> TestResult {
    let data = b"remzar-cryption-core-hash-vector";

    assert_eq!(Cryption::compute_core_hash(data), blake3_xof64(data));

    Ok(())
}

#[test]
fn cryption_006_core_hash_is_deterministic() -> TestResult {
    let data = b"same input same xof output";

    assert_eq!(
        Cryption::compute_core_hash(data),
        Cryption::compute_core_hash(data)
    );

    Ok(())
}

#[test]
fn cryption_007_core_hash_is_input_sensitive() -> TestResult {
    assert_ne!(
        Cryption::compute_core_hash(b"message-a"),
        Cryption::compute_core_hash(b"message-b")
    );

    Ok(())
}

#[test]
fn cryption_008_core_hash_output_is_sixty_four_bytes() -> TestResult {
    let hash = Cryption::compute_core_hash(b"length-check");

    assert_eq!(hash.len(), 64);

    Ok(())
}

#[test]
fn cryption_009_encrypt_decrypt_small_bytes_roundtrip() -> TestResult {
    let plaintext = b"small secret bytes";
    let passphrase = "correct horse battery staple";
    let encrypted = encrypt_bytes(plaintext, passphrase)?;
    let decrypted = decrypt_bytes(&encrypted, passphrase)?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_010_encrypted_blob_layout_has_salt_nonce_and_ciphertext_tag() -> TestResult {
    let plaintext = b"layout-check";
    let encrypted = encrypt_bytes(plaintext, "layout-passphrase")?;

    assert_eq!(
        encrypted.len(),
        Cryption::SALT_BYTES + Cryption::NONCE_BYTES + plaintext.len() + Cryption::GCM_TAG_BYTES
    );
    assert_eq!(
        encrypted.get(salt_range()).map(<[u8]>::len),
        Some(Cryption::SALT_BYTES)
    );
    assert_eq!(
        encrypted.get(nonce_range()).map(<[u8]>::len),
        Some(Cryption::NONCE_BYTES)
    );
    assert_eq!(
        encrypted
            .get(ciphertext_range(encrypted.len()))
            .map(<[u8]>::len),
        Some(plaintext.len() + Cryption::GCM_TAG_BYTES)
    );

    Ok(())
}

#[test]
fn cryption_011_encrypting_same_bytes_twice_produces_different_blob() -> TestResult {
    let plaintext = b"same plaintext randomized salt nonce";
    let passphrase = "same-passphrase";

    let first = encrypt_bytes(plaintext, passphrase)?;
    let second = encrypt_bytes(plaintext, passphrase)?;

    assert_ne!(first, second);
    assert_eq!(decrypt_bytes(&first, passphrase)?, plaintext);
    assert_eq!(decrypt_bytes(&second, passphrase)?, plaintext);

    Ok(())
}

#[test]
fn cryption_012_wrong_passphrase_rejects_decryption() -> TestResult {
    let encrypted = encrypt_bytes(b"secret", "right-passphrase")?;

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "wrong-passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_013_empty_passphrase_rejects_encrypt_bytes() -> TestResult {
    assert!(Cryption::encrypt_private_key_bytes(b"secret", "").is_err());
    Ok(())
}

#[test]
fn cryption_014_whitespace_only_passphrase_rejects_encrypt_bytes() -> TestResult {
    assert!(Cryption::encrypt_private_key_bytes(b"secret", "    \t\n").is_err());
    Ok(())
}

#[test]
fn cryption_015_empty_private_key_bytes_rejected() -> TestResult {
    assert!(Cryption::encrypt_private_key_bytes(&[], "valid-passphrase").is_err());
    Ok(())
}

#[test]
fn cryption_016_too_large_private_key_bytes_rejected() -> TestResult {
    let too_large = vec![7_u8; GlobalConfiguration::MAX_PRIVATE_KEY_BYTES.saturating_add(1)];

    assert!(Cryption::encrypt_private_key_bytes(&too_large, "valid-passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_017_decrypt_rejects_empty_blob() -> TestResult {
    assert!(Cryption::decrypt_private_key_bytes(&[], "valid-passphrase").is_err());
    Ok(())
}

#[test]
fn cryption_018_decrypt_rejects_blob_shorter_than_minimum_layout() -> TestResult {
    let min_len = Cryption::SALT_BYTES + Cryption::NONCE_BYTES + Cryption::GCM_TAG_BYTES;
    let short_blob = vec![0_u8; min_len.saturating_sub(1)];

    assert!(Cryption::decrypt_private_key_bytes(&short_blob, "valid-passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_019_decrypt_rejects_blob_larger_than_configured_cap() -> TestResult {
    let oversized = vec![0_u8; GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES.saturating_add(1)];

    assert!(Cryption::decrypt_private_key_bytes(&oversized, "valid-passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_020_tampered_salt_rejects_decryption() -> TestResult {
    let mut encrypted = encrypt_bytes(b"tamper salt", "passphrase")?;

    flip_byte(&mut encrypted, 0)?;

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_021_tampered_nonce_rejects_decryption() -> TestResult {
    let mut encrypted = encrypt_bytes(b"tamper nonce", "passphrase")?;
    let position = Cryption::SALT_BYTES;

    flip_byte(&mut encrypted, position)?;

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_022_tampered_ciphertext_rejects_decryption() -> TestResult {
    let mut encrypted = encrypt_bytes(b"tamper ciphertext", "passphrase")?;
    let position = Cryption::SALT_BYTES + Cryption::NONCE_BYTES;

    flip_byte(&mut encrypted, position)?;

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_023_tampered_tag_rejects_decryption() -> TestResult {
    let mut encrypted = encrypt_bytes(b"tamper tag", "passphrase")?;
    let last = encrypted
        .len()
        .checked_sub(1)
        .ok_or_else(|| "encrypted blob unexpectedly empty".to_string())?;

    flip_byte(&mut encrypted, last)?;

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_024_truncated_valid_blob_rejects_decryption() -> TestResult {
    let mut encrypted = encrypt_bytes(b"truncate me", "passphrase")?;

    encrypted.truncate(encrypted.len().saturating_sub(1));

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_025_extra_trailing_byte_rejects_decryption() -> TestResult {
    let mut encrypted = encrypt_bytes(b"append byte", "passphrase")?;

    encrypted.push(0);

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_026_legacy_string_roundtrip_ascii() -> TestResult {
    let plaintext = "legacy-private-key-string";
    let passphrase = "legacy-passphrase";
    let encrypted = encrypt_string(plaintext, passphrase)?;
    let decrypted = decrypt_string(&encrypted, passphrase)?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_027_legacy_string_roundtrip_unicode() -> TestResult {
    let plaintext = "remzar-秘密-key-🔐";
    let passphrase = "unicode-passphrase";
    let encrypted = encrypt_string(plaintext, passphrase)?;
    let decrypted = decrypt_string(&encrypted, passphrase)?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_028_legacy_string_rejects_empty_private_key() -> TestResult {
    assert!(Cryption::encrypt_private_key("", "valid-passphrase").is_err());
    Ok(())
}

#[test]
fn cryption_029_legacy_string_rejects_whitespace_private_key() -> TestResult {
    assert!(Cryption::encrypt_private_key("   \t\n", "valid-passphrase").is_err());
    Ok(())
}

#[test]
fn cryption_030_legacy_decrypt_rejects_non_utf8_plaintext() -> TestResult {
    let non_utf8 = [0xFF_u8, 0xFE, 0xFD, 0x00];
    let encrypted = encrypt_bytes(&non_utf8, "passphrase")?;

    assert!(Cryption::decrypt_private_key(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_031_raw_ml_dsa_secret_sized_payload_roundtrips() -> TestResult {
    let payload = deterministic_bytes(Cryption::ML_DSA_65_SECRET_BYTES, 0x65);
    let encrypted = encrypt_bytes(&payload, "ml-dsa-raw-passphrase")?;
    let decrypted = decrypt_bytes(&encrypted, "ml-dsa-raw-passphrase")?;

    assert_eq!(decrypted, payload);
    assert_eq!(
        encrypted.len(),
        Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES
    );

    Ok(())
}

#[test]
fn cryption_032_hex_ml_dsa_secret_sized_string_roundtrips() -> TestResult {
    let raw = deterministic_bytes(Cryption::ML_DSA_65_SECRET_BYTES, 0x42);
    let hex_plaintext = hex::encode(raw);
    let encrypted = encrypt_string(&hex_plaintext, "ml-dsa-hex-passphrase")?;
    let decrypted = decrypt_string(&encrypted, "ml-dsa-hex-passphrase")?;

    assert_eq!(decrypted, hex_plaintext);
    assert_eq!(
        encrypted.len(),
        Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_HEX
    );

    Ok(())
}

#[test]
fn cryption_033_real_generated_ml_dsa_secret_bytes_roundtrip() -> TestResult {
    let kp = MlDsa65Keypair::generate().map_err(debug_err)?;
    let secret = kp.secret_bytes_slice();
    let encrypted = encrypt_bytes(secret, "real-key-passphrase")?;
    let decrypted = decrypt_bytes(&encrypted, "real-key-passphrase")?;

    assert_eq!(decrypted.as_slice(), secret);

    Ok(())
}

#[test]
fn cryption_034_real_generated_ml_dsa_secret_hex_string_roundtrip() -> TestResult {
    let kp = MlDsa65Keypair::generate().map_err(debug_err)?;
    let secret_hex = hex::encode(kp.secret_bytes_slice());
    let encrypted = encrypt_string(&secret_hex, "real-key-hex-passphrase")?;
    let decrypted = decrypt_string(&encrypted, "real-key-hex-passphrase")?;

    assert_eq!(decrypted, secret_hex);

    Ok(())
}

#[test]
fn cryption_035_property_roundtrip_various_byte_lengths() -> TestResult {
    let lengths = [1_usize, 2, 3, 7, 16, 31, 64, 127, 256, 513];

    for len in lengths {
        let payload = deterministic_bytes(len, len.to_le_bytes()[0]);
        let passphrase = format!("property-passphrase-{len}");
        let encrypted = encrypt_bytes(&payload, &passphrase)?;
        let decrypted = decrypt_bytes(&encrypted, &passphrase)?;

        assert_eq!(decrypted, payload, "roundtrip mismatch at len {len}");
    }

    Ok(())
}

#[test]
fn cryption_036_property_wrong_passphrase_rejects_various_lengths() -> TestResult {
    let lengths = [1_usize, 8, 32, 128, 512];

    for len in lengths {
        let payload = deterministic_bytes(len, len.to_le_bytes()[0].wrapping_add(9));
        let encrypted = encrypt_bytes(&payload, "right-passphrase")?;

        assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, "wrong-passphrase").is_err(),
            "wrong passphrase decrypted payload length {len}"
        );
    }

    Ok(())
}

#[test]
fn cryption_037_property_sampled_blob_byte_flips_reject_decryption() -> TestResult {
    let payload = deterministic_bytes(256, 0xA5);
    let encrypted = encrypt_bytes(&payload, "tamper-sampling-passphrase")?;
    let step = encrypted.len().div_euclid(8).max(1);

    let mut position = 0_usize;
    while position < encrypted.len() {
        let mut changed = encrypted.clone();
        flip_byte(&mut changed, position)?;

        assert!(
            Cryption::decrypt_private_key_bytes(&changed, "tamper-sampling-passphrase").is_err(),
            "tampered blob byte {position} decrypted unexpectedly"
        );

        position = position.saturating_add(step);
    }

    Ok(())
}

#[test]
fn cryption_038_core_hash_property_known_vectors_are_stable() -> TestResult {
    let vectors: [&[u8]; 5] = [
        b"".as_slice(),
        b"a".as_slice(),
        b"abc".as_slice(),
        b"remzar".as_slice(),
        b"post-quantum-blockchain".as_slice(),
    ];

    for data in vectors {
        assert_eq!(Cryption::compute_core_hash(data), blake3_xof64(data));
    }

    Ok(())
}

#[test]
fn cryption_039_load_test_encrypt_decrypt_five_small_payloads() -> TestResult {
    for round in 0..5_usize {
        let payload = deterministic_bytes(round.saturating_add(1), round.to_le_bytes()[0]);
        let passphrase = format!("load-passphrase-{round}");
        let encrypted = encrypt_bytes(&payload, &passphrase)?;
        let decrypted = decrypt_bytes(&encrypted, &passphrase)?;

        assert_eq!(decrypted, payload);
    }

    Ok(())
}

#[test]
fn cryption_040_load_test_encrypt_decrypt_five_ml_dsa_sized_payloads() -> TestResult {
    for round in 0..5_usize {
        let payload = deterministic_bytes(
            Cryption::ML_DSA_65_SECRET_BYTES,
            round.to_le_bytes()[0].wrapping_add(1),
        );
        let passphrase = format!("ml-dsa-load-passphrase-{round}");
        let encrypted = encrypt_bytes(&payload, &passphrase)?;
        let decrypted = decrypt_bytes(&encrypted, &passphrase)?;

        assert_eq!(decrypted, payload);
    }

    Ok(())
}

#[test]
fn cryption_041_encrypt_bytes_with_single_byte_plaintext_roundtrips() -> TestResult {
    let plaintext = [0xA5_u8];
    let encrypted = encrypt_bytes(&plaintext, "single-byte-passphrase")?;
    let decrypted = decrypt_bytes(&encrypted, "single-byte-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_042_encrypt_bytes_with_all_zero_plaintext_roundtrips() -> TestResult {
    let plaintext = vec![0_u8; 64];
    let encrypted = encrypt_bytes(&plaintext, "zero-plaintext-passphrase")?;
    let decrypted = decrypt_bytes(&encrypted, "zero-plaintext-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_043_encrypt_bytes_with_all_max_plaintext_roundtrips() -> TestResult {
    let plaintext = vec![u8::MAX; 64];
    let encrypted = encrypt_bytes(&plaintext, "max-plaintext-passphrase")?;
    let decrypted = decrypt_bytes(&encrypted, "max-plaintext-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_044_encrypt_bytes_with_alternating_plaintext_roundtrips() -> TestResult {
    let mut plaintext = vec![0_u8; 128];

    for (index, byte) in plaintext.iter_mut().enumerate() {
        *byte = if index % 2 == 0 { 0xAA } else { 0x55 };
    }

    let encrypted = encrypt_bytes(&plaintext, "alternating-passphrase")?;
    let decrypted = decrypt_bytes(&encrypted, "alternating-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_045_non_ascii_passphrase_roundtrips_bytes() -> TestResult {
    let plaintext = b"secret protected by unicode passphrase";
    let passphrase = "秘密-passphrase-🔐";
    let encrypted = encrypt_bytes(plaintext, passphrase)?;
    let decrypted = decrypt_bytes(&encrypted, passphrase)?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_046_passphrase_with_surrounding_spaces_is_not_trimmed_for_key_derivation() -> TestResult
{
    let plaintext = b"space sensitive passphrase";
    let encrypted = encrypt_bytes(plaintext, " passphrase ")?;

    assert_eq!(decrypt_bytes(&encrypted, " passphrase ")?, plaintext);
    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_047_passphrase_case_change_rejects_decryption() -> TestResult {
    let encrypted = encrypt_bytes(b"case-sensitive", "CaseSensitivePassphrase")?;

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "casesensitivepassphrase").is_err());

    Ok(())
}

#[test]
fn cryption_048_passphrase_too_large_rejects_encrypt_bytes() -> TestResult {
    let huge_passphrase = "x".repeat(Cryption::MAX_PASSPHRASE_BYTES_ABSOLUTE.saturating_add(1));

    assert!(Cryption::encrypt_private_key_bytes(b"secret", &huge_passphrase).is_err());

    Ok(())
}

#[test]
fn cryption_049_passphrase_too_large_rejects_decrypt_bytes_before_accepting_blob() -> TestResult {
    let encrypted = encrypt_bytes(b"secret", "normal-passphrase")?;
    let huge_passphrase = "x".repeat(Cryption::MAX_PASSPHRASE_BYTES_ABSOLUTE.saturating_add(1));

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, &huge_passphrase).is_err());

    Ok(())
}

#[test]
fn cryption_050_legacy_string_passphrase_too_large_rejects_encrypt() -> TestResult {
    let huge_passphrase = "x".repeat(Cryption::MAX_PASSPHRASE_BYTES_ABSOLUTE.saturating_add(1));

    assert!(Cryption::encrypt_private_key("secret-string", &huge_passphrase).is_err());

    Ok(())
}

#[test]
fn cryption_051_legacy_string_passphrase_too_large_rejects_decrypt() -> TestResult {
    let encrypted = encrypt_string("secret-string", "normal-passphrase")?;
    let huge_passphrase = "x".repeat(Cryption::MAX_PASSPHRASE_BYTES_ABSOLUTE.saturating_add(1));

    assert!(Cryption::decrypt_private_key(&encrypted, &huge_passphrase).is_err());

    Ok(())
}

#[test]
fn cryption_052_legacy_string_wrong_passphrase_rejects_decrypt() -> TestResult {
    let encrypted = encrypt_string("legacy secret", "right-passphrase")?;

    assert!(Cryption::decrypt_private_key(&encrypted, "wrong-passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_053_legacy_string_tampered_blob_rejects_decrypt() -> TestResult {
    let mut encrypted = encrypt_string("legacy tamper secret", "passphrase")?;

    flip_byte(&mut encrypted, Cryption::SALT_BYTES + Cryption::NONCE_BYTES)?;

    assert!(Cryption::decrypt_private_key(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_054_legacy_string_extra_trailing_byte_rejects_decrypt() -> TestResult {
    let mut encrypted = encrypt_string("legacy append secret", "passphrase")?;

    encrypted.push(0);

    assert!(Cryption::decrypt_private_key(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_055_legacy_string_truncated_blob_rejects_decrypt() -> TestResult {
    let mut encrypted = encrypt_string("legacy truncate secret", "passphrase")?;

    encrypted.truncate(encrypted.len().saturating_sub(1));

    assert!(Cryption::decrypt_private_key(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_056_encrypted_blob_salt_region_is_not_all_zero() -> TestResult {
    let encrypted = encrypt_bytes(b"salt region check", "passphrase")?;
    let salt = encrypted
        .get(salt_range())
        .ok_or_else(|| "missing salt region".to_string())?;

    assert!(salt.iter().any(|byte| *byte != 0));

    Ok(())
}

#[test]
fn cryption_057_encrypted_blob_nonce_region_is_not_all_zero() -> TestResult {
    let encrypted = encrypt_bytes(b"nonce region check", "passphrase")?;
    let nonce = encrypted
        .get(nonce_range())
        .ok_or_else(|| "missing nonce region".to_string())?;

    assert!(nonce.iter().any(|byte| *byte != 0));

    Ok(())
}

#[test]
fn cryption_058_same_plaintext_twice_uses_different_salt_or_nonce() -> TestResult {
    let plaintext = b"randomized envelope regions";
    let passphrase = "randomized-passphrase";

    let first = encrypt_bytes(plaintext, passphrase)?;
    let second = encrypt_bytes(plaintext, passphrase)?;

    let first_salt = first
        .get(salt_range())
        .ok_or_else(|| "missing first salt".to_string())?;
    let second_salt = second
        .get(salt_range())
        .ok_or_else(|| "missing second salt".to_string())?;
    let first_nonce = first
        .get(nonce_range())
        .ok_or_else(|| "missing first nonce".to_string())?;
    let second_nonce = second
        .get(nonce_range())
        .ok_or_else(|| "missing second nonce".to_string())?;

    assert!(first_salt != second_salt || first_nonce != second_nonce);

    Ok(())
}

#[test]
fn cryption_059_ciphertext_region_length_includes_gcm_tag() -> TestResult {
    let plaintext = deterministic_bytes(99, 0x33);
    let encrypted = encrypt_bytes(&plaintext, "ciphertext-length-passphrase")?;
    let ciphertext = encrypted
        .get(ciphertext_range(encrypted.len()))
        .ok_or_else(|| "missing ciphertext region".to_string())?;

    assert_eq!(ciphertext.len(), plaintext.len() + Cryption::GCM_TAG_BYTES);

    Ok(())
}

#[test]
fn cryption_060_exact_minimum_layout_zero_blob_rejects_decrypt() -> TestResult {
    let min_len = Cryption::SALT_BYTES + Cryption::NONCE_BYTES + Cryption::GCM_TAG_BYTES;
    let blob = vec![0_u8; min_len];

    assert!(Cryption::decrypt_private_key_bytes(&blob, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_061_valid_blob_with_removed_salt_byte_rejects_decrypt() -> TestResult {
    let encrypted = encrypt_bytes(b"remove salt byte", "passphrase")?;
    let shifted = encrypted
        .get(1..)
        .ok_or_else(|| "missing shifted encrypted blob".to_string())?;

    assert!(Cryption::decrypt_private_key_bytes(shifted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_062_valid_blob_with_leading_zero_byte_rejects_decrypt() -> TestResult {
    let encrypted = encrypt_bytes(b"leading zero byte", "passphrase")?;
    let mut prefixed = Vec::with_capacity(encrypted.len().saturating_add(1));

    prefixed.push(0);
    prefixed.extend_from_slice(&encrypted);

    assert!(Cryption::decrypt_private_key_bytes(&prefixed, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_063_valid_blob_with_nonce_region_zeroed_rejects_decrypt() -> TestResult {
    let mut encrypted = encrypt_bytes(b"zero nonce region", "passphrase")?;
    let nonce = encrypted
        .get_mut(nonce_range())
        .ok_or_else(|| "missing nonce region".to_string())?;

    nonce.fill(0);

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_064_valid_blob_with_salt_region_zeroed_rejects_decrypt() -> TestResult {
    let mut encrypted = encrypt_bytes(b"zero salt region", "passphrase")?;
    let salt = encrypted
        .get_mut(salt_range())
        .ok_or_else(|| "missing salt region".to_string())?;

    salt.fill(0);

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_065_valid_blob_with_tag_region_zeroed_rejects_decrypt() -> TestResult {
    let mut encrypted = encrypt_bytes(b"zero tag region", "passphrase")?;
    let tag_start = encrypted.len().saturating_sub(Cryption::GCM_TAG_BYTES);
    let tag = encrypted
        .get_mut(tag_start..)
        .ok_or_else(|| "missing tag region".to_string())?;

    tag.fill(0);

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_066_string_with_newlines_tabs_and_spaces_roundtrips() -> TestResult {
    let plaintext = "line one\nline two\twith tab and spaces   ";
    let encrypted = encrypt_string(plaintext, "multiline-passphrase")?;
    let decrypted = decrypt_string(&encrypted, "multiline-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_067_string_with_embedded_nul_roundtrips() -> TestResult {
    let plaintext = "prefix\0middle\0suffix";
    let encrypted = encrypt_string(plaintext, "nul-string-passphrase")?;
    let decrypted = decrypt_string(&encrypted, "nul-string-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_068_bytes_with_embedded_nuls_roundtrip() -> TestResult {
    let plaintext = [0_u8, 0, 1, 0, 2, 3, 0, 255, 0];
    let encrypted = encrypt_bytes(&plaintext, "nul-bytes-passphrase")?;
    let decrypted = decrypt_bytes(&encrypted, "nul-bytes-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_069_core_hash_one_mebibyte_vector_matches_blake3_xof64() -> TestResult {
    let data = vec![0x5C_u8; 1024 * 1024];

    assert_eq!(Cryption::compute_core_hash(&data), blake3_xof64(&data));

    Ok(())
}

#[test]
fn cryption_070_core_hash_changes_when_one_byte_changes() -> TestResult {
    let original = deterministic_bytes(256, 0x11);
    let mut changed = original.clone();

    flip_byte(&mut changed, 128)?;

    assert_ne!(
        Cryption::compute_core_hash(&original),
        Cryption::compute_core_hash(&changed)
    );

    Ok(())
}

#[test]
fn cryption_071_core_hash_distinguishes_prefix_extension() -> TestResult {
    assert_ne!(
        Cryption::compute_core_hash(b"abc"),
        Cryption::compute_core_hash(b"abcd")
    );

    Ok(())
}

#[test]
fn cryption_072_core_hash_distinguishes_empty_from_zero_byte() -> TestResult {
    assert_ne!(
        Cryption::compute_core_hash(b""),
        Cryption::compute_core_hash(&[0_u8])
    );

    Ok(())
}

#[test]
fn cryption_073_property_core_hash_vectors_for_lengths_zero_through_thirty_two() -> TestResult {
    for len in 0..=32_usize {
        let data = deterministic_bytes(len, len.to_le_bytes()[0]);
        assert_eq!(
            Cryption::compute_core_hash(&data),
            blake3_xof64(&data),
            "hash mismatch at len {len}"
        );
    }

    Ok(())
}

#[test]
fn cryption_074_property_encrypt_decrypt_power_of_two_lengths() -> TestResult {
    for len in [1_usize, 2, 4, 8, 16, 32, 64, 128] {
        let payload = deterministic_bytes(len, len.to_le_bytes()[0].wrapping_add(1));
        let passphrase = format!("power-two-passphrase-{len}");
        let encrypted = encrypt_bytes(&payload, &passphrase)?;
        let decrypted = decrypt_bytes(&encrypted, &passphrase)?;

        assert_eq!(decrypted, payload);
    }

    Ok(())
}

#[test]
fn cryption_075_property_encrypted_length_matches_plaintext_plus_envelope() -> TestResult {
    for len in [1_usize, 3, 16, 65, 129] {
        let payload = deterministic_bytes(len, len.to_le_bytes()[0].wrapping_add(2));
        let passphrase = format!("length-envelope-passphrase-{len}");
        let encrypted = encrypt_bytes(&payload, &passphrase)?;

        assert_eq!(
            encrypted.len(),
            Cryption::SALT_BYTES + Cryption::NONCE_BYTES + Cryption::GCM_TAG_BYTES + len
        );
    }

    Ok(())
}

#[test]
fn cryption_076_property_legacy_strings_roundtrip_various_inputs() -> TestResult {
    let cases = [
        "a",
        "abc",
        "with spaces",
        "with\nnewline",
        "unicode-🔐",
        "0123456789abcdef",
    ];

    for case in cases {
        let encrypted = encrypt_string(case, "legacy-property-passphrase")?;
        let decrypted = decrypt_string(&encrypted, "legacy-property-passphrase")?;

        assert_eq!(decrypted, case);
    }

    Ok(())
}

#[test]
fn cryption_077_property_wrong_passphrase_rejects_legacy_strings() -> TestResult {
    let cases = ["a", "abc", "unicode-🔐"];

    for case in cases {
        let encrypted = encrypt_string(case, "right-legacy-passphrase")?;

        assert!(
            Cryption::decrypt_private_key(&encrypted, "wrong-legacy-passphrase").is_err(),
            "wrong passphrase decrypted legacy case {case:?}"
        );
    }

    Ok(())
}

#[test]
fn cryption_078_load_light_encrypt_decrypt_ten_medium_payloads() -> TestResult {
    for round in 0..10_usize {
        let payload = deterministic_bytes(512, round.to_le_bytes()[0]);
        let passphrase = format!("medium-load-passphrase-{round}");
        let encrypted = encrypt_bytes(&payload, &passphrase)?;
        let decrypted = decrypt_bytes(&encrypted, &passphrase)?;

        assert_eq!(decrypted, payload);
    }

    Ok(())
}

#[test]
fn cryption_079_load_light_hash_one_hundred_vectors() -> TestResult {
    for round in 0..100_usize {
        let payload = deterministic_bytes(round, round.to_le_bytes()[0]);
        assert_eq!(
            Cryption::compute_core_hash(&payload),
            blake3_xof64(&payload)
        );
    }

    Ok(())
}

#[test]
fn cryption_080_real_ml_dsa_secret_wrong_passphrase_rejects() -> TestResult {
    let kp = MlDsa65Keypair::generate().map_err(debug_err)?;
    let encrypted = encrypt_bytes(kp.secret_bytes_slice(), "correct-real-secret-passphrase")?;

    assert!(
        Cryption::decrypt_private_key_bytes(&encrypted, "wrong-real-secret-passphrase").is_err()
    );

    Ok(())
}

#[test]
fn cryption_081_legacy_string_with_leading_and_trailing_spaces_roundtrips_exactly() -> TestResult {
    let plaintext = "   secret with surrounding spaces   ";
    let encrypted = encrypt_string(plaintext, "space-preserving-passphrase")?;
    let decrypted = decrypt_string(&encrypted, "space-preserving-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_082_legacy_string_with_only_newline_tab_space_is_rejected() -> TestResult {
    assert!(Cryption::encrypt_private_key("\n\t   ", "valid-passphrase").is_err());
    Ok(())
}

#[test]
fn cryption_083_legacy_string_too_large_rejected() -> TestResult {
    let too_large = "x".repeat(GlobalConfiguration::MAX_PRIVATE_KEY_BYTES.saturating_add(1));

    assert!(Cryption::encrypt_private_key(&too_large, "valid-passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_084_legacy_string_at_ml_dsa_secret_hex_length_roundtrips() -> TestResult {
    let plaintext = "a".repeat(Cryption::ML_DSA_65_SECRET_HEX_CHARS);
    let encrypted = encrypt_string(&plaintext, "exact-hex-length-passphrase")?;
    let decrypted = decrypt_string(&encrypted, "exact-hex-length-passphrase")?;

    assert_eq!(decrypted, plaintext);
    assert_eq!(
        encrypted.len(),
        Cryption::SALT_BYTES
            + Cryption::NONCE_BYTES
            + Cryption::GCM_TAG_BYTES
            + Cryption::ML_DSA_65_SECRET_HEX_CHARS
    );

    Ok(())
}

#[test]
fn cryption_085_raw_bytes_at_ml_dsa_secret_length_have_expected_blob_length() -> TestResult {
    let plaintext = deterministic_bytes(Cryption::ML_DSA_65_SECRET_BYTES, 0x21);
    let encrypted = encrypt_bytes(&plaintext, "exact-raw-secret-length-passphrase")?;

    assert_eq!(
        encrypted.len(),
        Cryption::SALT_BYTES
            + Cryption::NONCE_BYTES
            + Cryption::GCM_TAG_BYTES
            + Cryption::ML_DSA_65_SECRET_BYTES
    );

    Ok(())
}

#[test]
fn cryption_086_decrypt_rejects_salt_only_blob() -> TestResult {
    let blob = vec![0_u8; Cryption::SALT_BYTES];

    assert!(Cryption::decrypt_private_key_bytes(&blob, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_087_decrypt_rejects_salt_plus_nonce_only_blob() -> TestResult {
    let blob = vec![0_u8; Cryption::SALT_BYTES + Cryption::NONCE_BYTES];

    assert!(Cryption::decrypt_private_key_bytes(&blob, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_088_decrypt_rejects_salt_nonce_and_short_tag_blob() -> TestResult {
    let blob = vec![
        0_u8;
        Cryption::SALT_BYTES
            + Cryption::NONCE_BYTES
            + Cryption::GCM_TAG_BYTES.saturating_sub(1)
    ];

    assert!(Cryption::decrypt_private_key_bytes(&blob, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_089_decrypt_rejects_exact_min_layout_with_nonzero_bytes() -> TestResult {
    let blob =
        vec![0xAB_u8; Cryption::SALT_BYTES + Cryption::NONCE_BYTES + Cryption::GCM_TAG_BYTES];

    assert!(Cryption::decrypt_private_key_bytes(&blob, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_090_valid_blob_with_ciphertext_region_reversed_rejects_decryption() -> TestResult {
    let mut encrypted = encrypt_bytes(b"reverse ciphertext region", "passphrase")?;
    let range = ciphertext_range(encrypted.len());
    let ciphertext = encrypted
        .get_mut(range)
        .ok_or_else(|| "missing ciphertext region".to_string())?;

    ciphertext.reverse();

    assert!(Cryption::decrypt_private_key_bytes(&encrypted, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_091_valid_blob_with_salt_and_nonce_swapped_rejects_decryption() -> TestResult {
    let encrypted = encrypt_bytes(b"swap salt nonce", "passphrase")?;
    let salt = encrypted
        .get(salt_range())
        .ok_or_else(|| "missing salt".to_string())?;
    let nonce = encrypted
        .get(nonce_range())
        .ok_or_else(|| "missing nonce".to_string())?;
    let ciphertext = encrypted
        .get(ciphertext_range(encrypted.len()))
        .ok_or_else(|| "missing ciphertext".to_string())?;

    let mut swapped = Vec::with_capacity(encrypted.len());
    swapped.extend_from_slice(nonce);
    swapped.extend_from_slice(salt);
    swapped.extend_from_slice(ciphertext);

    assert_eq!(swapped.len(), encrypted.len());
    assert!(Cryption::decrypt_private_key_bytes(&swapped, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_092_valid_blob_duplicate_full_frame_rejects_decryption() -> TestResult {
    let encrypted = encrypt_bytes(b"duplicate full encrypted frame", "passphrase")?;
    let mut duplicated = Vec::with_capacity(encrypted.len().saturating_mul(2));

    duplicated.extend_from_slice(&encrypted);
    duplicated.extend_from_slice(&encrypted);

    assert!(Cryption::decrypt_private_key_bytes(&duplicated, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_093_valid_blob_byte_by_byte_reassembly_decrypts() -> TestResult {
    let plaintext = b"byte by byte network reassembly";
    let encrypted = encrypt_bytes(plaintext, "reassembly-passphrase")?;
    let mut reassembled = Vec::with_capacity(encrypted.len());

    for byte in encrypted.iter().copied() {
        reassembled.push(byte);
    }

    let decrypted = decrypt_bytes(&reassembled, "reassembly-passphrase")?;

    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn cryption_094_valid_blob_fragment_swap_rejects_decryption() -> TestResult {
    let encrypted = encrypt_bytes(b"fragment swap encrypted frame", "passphrase")?;

    let first = encrypted
        .get(..Cryption::SALT_BYTES)
        .ok_or_else(|| "missing first fragment".to_string())?;
    let second = encrypted
        .get(Cryption::SALT_BYTES..Cryption::SALT_BYTES + Cryption::NONCE_BYTES)
        .ok_or_else(|| "missing second fragment".to_string())?;
    let third = encrypted
        .get(Cryption::SALT_BYTES + Cryption::NONCE_BYTES..)
        .ok_or_else(|| "missing third fragment".to_string())?;

    let mut swapped = Vec::with_capacity(encrypted.len());
    swapped.extend_from_slice(second);
    swapped.extend_from_slice(first);
    swapped.extend_from_slice(third);

    assert_eq!(swapped.len(), encrypted.len());
    assert!(Cryption::decrypt_private_key_bytes(&swapped, "passphrase").is_err());

    Ok(())
}

#[test]
fn cryption_095_core_hash_of_all_zero_block_matches_blake3_xof64() -> TestResult {
    let data = vec![0_u8; 4096];

    assert_eq!(Cryption::compute_core_hash(&data), blake3_xof64(&data));

    Ok(())
}

#[test]
fn cryption_096_core_hash_of_all_max_block_matches_blake3_xof64() -> TestResult {
    let data = vec![u8::MAX; 4096];

    assert_eq!(Cryption::compute_core_hash(&data), blake3_xof64(&data));

    Ok(())
}

#[test]
fn cryption_097_core_hash_of_deterministic_ml_dsa_sized_payload_matches_blake3_xof64() -> TestResult
{
    let data = deterministic_bytes(Cryption::ML_DSA_65_SECRET_BYTES, 0x77);

    assert_eq!(Cryption::compute_core_hash(&data), blake3_xof64(&data));

    Ok(())
}

#[test]
fn cryption_098_property_every_sampled_truncation_of_valid_blob_rejects() -> TestResult {
    let encrypted = encrypt_bytes(b"sample truncation rejection", "passphrase")?;
    let step = encrypted.len().div_euclid(8).max(1);
    let mut len = 0_usize;

    while len < encrypted.len() {
        let truncated = encrypted
            .get(..len)
            .ok_or_else(|| format!("missing truncation length {len}"))?;

        assert!(
            Cryption::decrypt_private_key_bytes(truncated, "passphrase").is_err(),
            "truncation length {len} decrypted unexpectedly"
        );

        len = len.saturating_add(step);
    }

    Ok(())
}

#[test]
fn cryption_099_property_sampled_wrong_passphrases_reject_same_blob() -> TestResult {
    let encrypted = encrypt_bytes(b"wrong passphrase matrix", "correct-passphrase")?;
    let wrong_passphrases = [
        "correct-passphrase ",
        " correct-passphrase",
        "Correct-passphrase",
        "correct_passphrase",
        "correct-passphrase!",
        "wrong",
    ];

    for passphrase in wrong_passphrases {
        assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, passphrase).is_err(),
            "wrong passphrase {passphrase:?} decrypted unexpectedly"
        );
    }

    Ok(())
}

#[test]
fn cryption_100_load_light_real_ml_dsa_secret_encrypt_decrypt_three_keypairs() -> TestResult {
    for round in 0..3_usize {
        let kp = MlDsa65Keypair::generate().map_err(debug_err)?;
        let passphrase = format!("final-real-key-load-passphrase-{round}");
        let encrypted = encrypt_bytes(kp.secret_bytes_slice(), &passphrase)?;
        let decrypted = decrypt_bytes(&encrypted, &passphrase)?;

        assert_eq!(decrypted.as_slice(), kp.secret_bytes_slice());
    }

    Ok(())
}
