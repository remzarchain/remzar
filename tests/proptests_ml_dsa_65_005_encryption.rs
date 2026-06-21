use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;

const PASSPHRASE_RE: &str = "[A-Za-z0-9_!@#%+=.,:-]{1,32}";
const UTF8_SECRET_RE: &str = "[A-Za-z0-9_!@#%+=.,:/-]{1,128}";

fn minimum_encrypted_blob_len() -> usize {
    Cryption::SALT_BYTES + Cryption::NONCE_BYTES + Cryption::GCM_TAG_BYTES
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_encrypt_decrypt_private_key_bytes_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
    ) {
        let encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed for non-empty bounded plaintext and passphrase");

        let expected_len = Cryption::SALT_BYTES
            + Cryption::NONCE_BYTES
            + plaintext.len()
            + Cryption::GCM_TAG_BYTES;

        prop_assert_eq!(
            encrypted.len(),
            expected_len,
            "encrypted blob must be salt || nonce || ciphertext_with_gcm_tag"
        );

        let decrypted = Cryption::decrypt_private_key_bytes(&encrypted, &passphrase)
            .expect("decryption should succeed with the correct passphrase");

        prop_assert_eq!(
            decrypted,
            plaintext,
            "decrypt(encrypt(plaintext)) must equal original plaintext bytes"
        );
    }

    // 02/25
    #[test]
    fn test_002_decrypt_private_key_bytes_rejects_wrong_passphrase(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        left_tail in "[A-Za-z0-9_!@#%+=.,:-]{0,16}",
        right_tail in "[A-Za-z0-9_!@#%+=.,:-]{0,16}",
    ) {
        let passphrase = format!("A{left_tail}");
        let wrong_passphrase = format!("B{right_tail}");

        let encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &wrong_passphrase).is_err(),
            "decryption must reject the wrong passphrase"
        );
    }

    // 03/25
    #[test]
    fn test_003_decrypt_private_key_bytes_rejects_tampered_encrypted_blob(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
        byte_index_seed in any::<usize>(),
        delta in 1u8..=255u8,
    ) {
        let mut encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        prop_assume!(!encrypted.is_empty());

        let byte_index = byte_index_seed % encrypted.len();
        encrypted[byte_index] = encrypted[byte_index].wrapping_add(delta);

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &passphrase).is_err(),
            "decryption must reject a tampered encrypted blob at byte index {byte_index}"
        );
    }

    // 04/25
    #[test]
    fn test_004_decrypt_private_key_bytes_rejects_truncated_encrypted_blob(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
        keep_seed in any::<usize>(),
    ) {
        let encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        prop_assume!(!encrypted.is_empty());

        let keep_len = keep_seed % encrypted.len();
        let truncated = &encrypted[..keep_len];

        prop_assert!(
            Cryption::decrypt_private_key_bytes(truncated, &passphrase).is_err(),
            "decryption must reject truncated encrypted blob of length {keep_len}"
        );
    }

    // 05/25
    #[test]
    fn test_005_encrypt_private_key_bytes_rejects_empty_plaintext(
        passphrase in PASSPHRASE_RE,
    ) {
        let empty: Vec<u8> = Vec::new();

        prop_assert!(
            Cryption::encrypt_private_key_bytes(&empty, &passphrase).is_err(),
            "encryption must reject empty private key bytes"
        );
    }

    // 06/25
    #[test]
    fn test_006_encrypt_private_key_string_roundtrip_preserves_utf8_secret(
        private_key in UTF8_SECRET_RE,
        passphrase in PASSPHRASE_RE,
    ) {
        let encrypted = Cryption::encrypt_private_key(&private_key, &passphrase)
            .expect("string encryption should succeed for non-empty bounded UTF-8 secret");

        let decrypted = Cryption::decrypt_private_key(&encrypted, &passphrase)
            .expect("string decryption should succeed with correct passphrase");

        prop_assert_eq!(
            decrypted,
            private_key,
            "string decrypt(encrypt(secret)) must equal original UTF-8 secret"
        );
    }

    // 07/25
    #[test]
    fn test_007_compute_core_hash_is_64_bytes_deterministic_and_input_sensitive(
        tail in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut input_a = Vec::with_capacity(tail.len() + 1);
        input_a.push(0u8);
        input_a.extend_from_slice(&tail);

        let mut input_b = Vec::with_capacity(tail.len() + 1);
        input_b.push(1u8);
        input_b.extend_from_slice(&tail);

        let hash_a1 = Cryption::compute_core_hash(&input_a);
        let hash_a2 = Cryption::compute_core_hash(&input_a);
        let hash_b = Cryption::compute_core_hash(&input_b);

        prop_assert_eq!(
            hash_a1.len(),
            64,
            "core hash output must be exactly 64 bytes"
        );

        prop_assert_eq!(
            hash_a1,
            hash_a2,
            "core hash must be deterministic for the same input"
        );

        prop_assert_ne!(
            hash_a1,
            hash_b,
            "core hash should change when the input changes"
        );
    }

    // 08/25
    #[test]
    fn test_008_encrypted_blob_layout_has_fixed_salt_nonce_and_gcm_tag_sections(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
    ) {
        let encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        let salt_end = Cryption::SALT_BYTES;
        let nonce_end = Cryption::SALT_BYTES + Cryption::NONCE_BYTES;

        prop_assert_eq!(
            encrypted[..salt_end].len(),
            Cryption::SALT_BYTES,
            "encrypted blob must start with fixed-size salt"
        );

        prop_assert_eq!(
            encrypted[salt_end..nonce_end].len(),
            Cryption::NONCE_BYTES,
            "encrypted blob must contain fixed-size nonce after salt"
        );

        prop_assert_eq!(
            encrypted[nonce_end..].len(),
            plaintext.len() + Cryption::GCM_TAG_BYTES,
            "ciphertext section must include plaintext-length ciphertext plus GCM tag"
        );
    }

    // 09/25
    #[test]
    fn test_009_encrypting_same_plaintext_twice_uses_fresh_salt_or_nonce(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
    ) {
        let encrypted_a = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("first encryption should succeed");

        let encrypted_b = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("second encryption should succeed");

        prop_assert_ne!(
            &encrypted_a,
            &encrypted_b,
            "encrypting the same plaintext twice with the same passphrase should use fresh randomness"
        );

        let decrypted_a = Cryption::decrypt_private_key_bytes(&encrypted_a, &passphrase)
            .expect("first blob should decrypt");

        let decrypted_b = Cryption::decrypt_private_key_bytes(&encrypted_b, &passphrase)
            .expect("second blob should decrypt");

        prop_assert_eq!(
            decrypted_a.as_slice(),
            plaintext.as_slice(),
            "first randomized blob must decrypt to original plaintext"
        );

        prop_assert_eq!(
            decrypted_b.as_slice(),
            plaintext.as_slice(),
            "second randomized blob must decrypt to original plaintext"
        );
    }

    // 10/25
    #[test]
    fn test_010_tampering_salt_section_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
        salt_index in 0usize..Cryption::SALT_BYTES,
        delta in 1u8..=255u8,
    ) {
        let mut encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        encrypted[salt_index] = encrypted[salt_index].wrapping_add(delta);

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &passphrase).is_err(),
            "decryption must reject salt tampering at index {salt_index}"
        );
    }

    // 11/25
    #[test]
    fn test_011_tampering_nonce_section_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
        nonce_index in 0usize..Cryption::NONCE_BYTES,
        delta in 1u8..=255u8,
    ) {
        let mut encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        let absolute_index = Cryption::SALT_BYTES + nonce_index;
        encrypted[absolute_index] = encrypted[absolute_index].wrapping_add(delta);

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &passphrase).is_err(),
            "decryption must reject nonce tampering at index {nonce_index}"
        );
    }

    // 12/25
    #[test]
    fn test_012_tampering_ciphertext_body_section_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
        body_index_seed in any::<usize>(),
        delta in 1u8..=255u8,
    ) {
        let mut encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        let body_start = Cryption::SALT_BYTES + Cryption::NONCE_BYTES;
        let body_len = plaintext.len();
        let body_index = body_index_seed % body_len;
        let absolute_index = body_start + body_index;

        encrypted[absolute_index] = encrypted[absolute_index].wrapping_add(delta);

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &passphrase).is_err(),
            "decryption must reject ciphertext-body tampering"
        );
    }

    // 13/25
    #[test]
    fn test_013_tampering_gcm_tag_section_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
        tag_index in 0usize..Cryption::GCM_TAG_BYTES,
        delta in 1u8..=255u8,
    ) {
        let mut encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        let tag_start = encrypted.len() - Cryption::GCM_TAG_BYTES;
        let absolute_index = tag_start + tag_index;

        encrypted[absolute_index] = encrypted[absolute_index].wrapping_add(delta);

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &passphrase).is_err(),
            "decryption must reject GCM tag tampering"
        );
    }

    // 14/25
    #[test]
    fn test_014_decrypt_private_key_bytes_rejects_every_blob_shorter_than_minimum(
        len in 0usize..44usize,
        fill in any::<u8>(),
        passphrase in PASSPHRASE_RE,
    ) {
        prop_assume!(len < minimum_encrypted_blob_len());

        let encrypted = vec![fill; len];

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &passphrase).is_err(),
            "decrypt must reject encrypted blob shorter than salt + nonce + GCM tag"
        );
    }

    // 15/25
    #[test]
    fn test_015_decrypt_private_key_rejects_non_utf8_plaintext_from_valid_byte_encryption(
        tail in proptest::collection::vec(any::<u8>(), 0..32),
        passphrase in PASSPHRASE_RE,
    ) {
        let mut non_utf8_plaintext = Vec::with_capacity(tail.len() + 1);
        non_utf8_plaintext.push(0xFF);
        non_utf8_plaintext.extend_from_slice(&tail);

        let encrypted = Cryption::encrypt_private_key_bytes(&non_utf8_plaintext, &passphrase)
            .expect("byte encryption should accept arbitrary non-empty bytes");

        prop_assert!(
            Cryption::decrypt_private_key(&encrypted, &passphrase).is_err(),
            "legacy string decrypt must reject valid decrypted bytes that are not UTF-8"
        );
    }

    // 16/25
    #[test]
    fn test_016_encrypt_private_key_rejects_blank_or_whitespace_string_secret(
        spaces in "[ \\t\\r\\n]{0,32}",
        passphrase in PASSPHRASE_RE,
    ) {
        prop_assert!(
            Cryption::encrypt_private_key(&spaces, &passphrase).is_err(),
            "legacy string encryption must reject blank or whitespace-only private key strings"
        );
    }

    // 17/25
    #[test]
    fn test_017_encrypt_private_key_bytes_rejects_blank_or_whitespace_passphrase(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        spaces in "[ \\t\\r\\n]{0,32}",
    ) {
        prop_assert!(
            Cryption::encrypt_private_key_bytes(&plaintext, &spaces).is_err(),
            "byte encryption must reject blank or whitespace-only passphrases"
        );
    }

    // 18/25
    #[test]
    fn test_018_decrypt_private_key_bytes_rejects_blank_or_whitespace_passphrase(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
        spaces in "[ \\t\\r\\n]{0,32}",
    ) {
        let encrypted = Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
            .expect("encryption should succeed");

        prop_assert!(
            Cryption::decrypt_private_key_bytes(&encrypted, &spaces).is_err(),
            "byte decryption must reject blank or whitespace-only passphrases"
        );
    }

    // 19/25
    #[test]
    fn test_019_string_api_ciphertext_can_be_decrypted_by_byte_api(
        private_key in UTF8_SECRET_RE,
        passphrase in PASSPHRASE_RE,
    ) {
        let encrypted = Cryption::encrypt_private_key(&private_key, &passphrase)
            .expect("string encryption should succeed");

        let decrypted_bytes = Cryption::decrypt_private_key_bytes(&encrypted, &passphrase)
            .expect("byte decrypt should understand string API encrypted blob");

        prop_assert_eq!(
            decrypted_bytes,
            private_key.as_bytes(),
            "string API encryption must produce the same byte-envelope format used by byte decrypt"
        );
    }

    // 20/25
    #[test]
    fn test_020_byte_api_ciphertext_with_utf8_plaintext_can_be_decrypted_by_string_api(
        private_key in UTF8_SECRET_RE,
        passphrase in PASSPHRASE_RE,
    ) {
        let encrypted = Cryption::encrypt_private_key_bytes(private_key.as_bytes(), &passphrase)
            .expect("byte encryption should succeed for UTF-8 secret bytes");

        let decrypted_string = Cryption::decrypt_private_key(&encrypted, &passphrase)
            .expect("string decrypt should accept byte API blob when plaintext is valid UTF-8");

        prop_assert_eq!(
            decrypted_string,
            private_key,
            "byte API encrypted UTF-8 plaintext must be compatible with legacy string decrypt"
        );
    }

    // 21/25
    #[test]
    fn test_021_constants_have_expected_cryption_envelope_sizes(_case in any::<u8>()) {
        prop_assert_eq!(
            Cryption::AES256_KEY_BYTES,
            32,
            "AES-256 key size must remain 32 bytes"
        );

        prop_assert_eq!(
            Cryption::SALT_BYTES,
            16,
            "salt size must remain 16 bytes"
        );

        prop_assert_eq!(
            Cryption::NONCE_BYTES,
            12,
            "AES-GCM nonce size must remain 12 bytes"
        );

        prop_assert_eq!(
            Cryption::GCM_TAG_BYTES,
            16,
            "AES-GCM tag size must remain 16 bytes"
        );

        prop_assert_eq!(
            Cryption::ML_DSA_65_SECRET_HEX_CHARS,
            Cryption::ML_DSA_65_SECRET_BYTES * 2,
            "hex ML-DSA secret length must stay exactly 2 chars per byte"
        );
    }

    // 22/25
    #[test]
    fn test_022_minimum_ml_dsa_secret_blob_constants_match_envelope_math(_case in any::<u8>()) {
        prop_assert_eq!(
            Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES,
            Cryption::SALT_BYTES
                + Cryption::NONCE_BYTES
                + Cryption::GCM_TAG_BYTES
                + Cryption::ML_DSA_65_SECRET_BYTES,
            "raw ML-DSA secret encrypted minimum must equal salt + nonce + tag + secret bytes"
        );

        prop_assert_eq!(
            Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_HEX,
            Cryption::SALT_BYTES
                + Cryption::NONCE_BYTES
                + Cryption::GCM_TAG_BYTES
                + Cryption::ML_DSA_65_SECRET_HEX_CHARS,
            "hex ML-DSA secret encrypted minimum must equal salt + nonce + tag + hex chars"
        );
    }

    // 23/25
    #[test]
    fn test_023_compute_core_hash_matches_independent_blake3_xof64(
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&data);

        let mut expected = [0u8; 64];
        hasher.finalize_xof().fill(&mut expected);

        let actual = Cryption::compute_core_hash(&data);

        prop_assert_eq!(
            actual,
            expected,
            "compute_core_hash must equal independent BLAKE3-XOF(64) computation"
        );
    }

    // 24/25
    #[test]
    fn test_024_decrypt_private_key_bytes_never_panics_for_arbitrary_external_blob(
        encrypted_blob in proptest::collection::vec(any::<u8>(), 0..256),
        passphrase in PASSPHRASE_RE,
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Cryption::decrypt_private_key_bytes(&encrypted_blob, &passphrase)
        }));

        prop_assert!(
            result.is_ok(),
            "byte decrypt must never panic for arbitrary external encrypted blob bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_encrypt_and_decrypt_bytes_never_panic_for_bounded_valid_inputs(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        passphrase in PASSPHRASE_RE,
    ) {
        let encrypt_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Cryption::encrypt_private_key_bytes(&plaintext, &passphrase)
        }));

        prop_assert!(
            encrypt_result.is_ok(),
            "byte encryption must never panic for bounded valid plaintext and passphrase"
        );

        let encrypted = encrypt_result
            .expect("panic was already checked")
            .expect("bounded valid encryption should succeed");

        let decrypt_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Cryption::decrypt_private_key_bytes(&encrypted, &passphrase)
        }));

        prop_assert!(
            decrypt_result.is_ok(),
            "byte decryption must never panic for a blob produced by byte encryption"
        );

        prop_assert_eq!(
            decrypt_result
                .expect("panic was already checked")
                .expect("decryption of produced blob should succeed"),
            plaintext,
            "panic-safe encrypt/decrypt path must still preserve plaintext"
        );
    }
}
