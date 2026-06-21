use fips204::ml_dsa_65;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::utility::helper::{
    derive_wallet_id_from_pubkey_bytes, wallet_id_matches_pubkey_bytes_checked,
};

use std::sync::{Mutex, OnceLock};

type TestResult = Result<(), String>;

static WALLET_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn run_serial<F>(f: F) -> TestResult
where
    F: FnOnce() -> TestResult,
{
    let lock = WALLET_TEST_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    f()
}

fn debug_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn new_wallet(passphrase: &str) -> Result<MLDSA65Wallet, String> {
    MLDSA65Wallet::new(passphrase).map_err(debug_err)
}

fn assert_wallet_address_shape(address: &str) -> TestResult {
    assert_eq!(address.len(), 129);
    assert!(address.starts_with('r'));

    let body = address
        .get(1..)
        .ok_or_else(|| "missing wallet address body".to_string())?;

    assert_eq!(body.len(), 128);
    assert!(body.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(body.bytes().all(|byte| !byte.is_ascii_uppercase()));

    Ok(())
}

fn sign_wallet(
    wallet: &MLDSA65Wallet,
    passphrase: &str,
    message: &[u8],
) -> Result<Vec<u8>, String> {
    wallet.sign(passphrase, message).map_err(debug_err)
}

fn secret_hex(wallet: &MLDSA65Wallet, passphrase: &str) -> Result<String, String> {
    wallet.secret_key_hex(passphrase).map_err(debug_err)
}

fn flip_byte(data: &mut [u8], position: usize) -> TestResult {
    let byte = data
        .get_mut(position)
        .ok_or_else(|| format!("byte position {position} out of bounds"))?;
    *byte ^= 1;
    Ok(())
}

fn deterministic_message(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| {
            let low = index.to_le_bytes()[0];
            seed.wrapping_add(low.rotate_left(1))
        })
        .collect()
}

fn assert_address_from_secret_rejects_without_unwinding(secret: &[u8]) -> TestResult {
    let old_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(|_| {
        // Silence expected dependency panic from malformed ML-DSA secret bytes.
    }));

    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MLDSA65Wallet::address_from_secret_bytes(secret)
    }));

    std::panic::set_hook(old_hook);

    let result =
        caught.map_err(|_| "address_from_secret_bytes allowed a panic to escape".to_string())?;

    assert!(
        result.is_err(),
        "malformed secret unexpectedly derived a wallet address"
    );

    Ok(())
}

#[test]
fn wallet_001_new_wallet_has_expected_field_lengths() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-field-length-passphrase")?;

        assert_eq!(wallet.public.len(), ml_dsa_65::PK_LEN);
        assert_eq!(wallet.address.len(), 129);
        assert!(!wallet.encrypted_secret.is_empty());

        Ok(())
    })
}

#[test]
fn wallet_002_new_wallet_address_has_canonical_shape() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-address-shape-passphrase")?;

        assert_wallet_address_shape(&wallet.address)?;

        Ok(())
    })
}

#[test]
fn wallet_003_new_wallet_validates_self() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-self-validation-passphrase")?;

        wallet.validate_self().map_err(debug_err)?;

        Ok(())
    })
}

#[test]
fn wallet_004_generated_address_matches_helper_derivation() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-helper-derivation-passphrase")?;
        let expected = derive_wallet_id_from_pubkey_bytes(&wallet.public);

        assert_eq!(wallet.address, expected);

        Ok(())
    })
}

#[test]
fn wallet_005_generated_address_matches_public_key_binding_helper() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-binding-helper-passphrase")?;
        let canonical = wallet_id_matches_pubkey_bytes_checked(&wallet.address, &wallet.public)
            .map_err(debug_err)?;

        assert_eq!(canonical, wallet.address);

        Ok(())
    })
}

#[test]
fn wallet_006_public_generate_address_matches_wallet_address() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-public-generate-address-passphrase")?;
        let generated = MLDSA65Wallet::generate_address(&wallet.public).map_err(debug_err)?;

        assert_eq!(generated, wallet.address);

        Ok(())
    })
}

#[test]
fn wallet_007_validate_address_format_accepts_generated_address() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-format-valid-passphrase")?;

        MLDSA65Wallet::validate_address_format(&wallet.address).map_err(debug_err)?;

        Ok(())
    })
}

#[test]
fn wallet_008_validate_address_format_rejects_empty_address() -> TestResult {
    run_serial(|| {
        assert!(MLDSA65Wallet::validate_address_format("").is_err());
        Ok(())
    })
}

#[test]
fn wallet_009_validate_address_format_rejects_short_address() -> TestResult {
    run_serial(|| {
        let short = format!("r{}", "a".repeat(127));

        assert!(MLDSA65Wallet::validate_address_format(&short).is_err());

        Ok(())
    })
}

#[test]
fn wallet_010_validate_address_format_rejects_long_address() -> TestResult {
    run_serial(|| {
        let long = format!("r{}", "a".repeat(129));

        assert!(MLDSA65Wallet::validate_address_format(&long).is_err());

        Ok(())
    })
}

#[test]
fn wallet_011_validate_address_format_rejects_wrong_prefix() -> TestResult {
    run_serial(|| {
        let invalid = format!("p{}", "a".repeat(128));

        assert!(MLDSA65Wallet::validate_address_format(&invalid).is_err());

        Ok(())
    })
}

#[test]
fn wallet_012_validate_address_format_rejects_non_hex_body() -> TestResult {
    run_serial(|| {
        let invalid = format!("r{}z", "a".repeat(127));

        assert!(MLDSA65Wallet::validate_address_format(&invalid).is_err());

        Ok(())
    })
}

#[test]
fn wallet_013_validate_address_format_accepts_uppercase_address_input() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-uppercase-format-passphrase")?;
        let uppercase = wallet.address.to_ascii_uppercase();

        MLDSA65Wallet::validate_address_format(&uppercase).map_err(debug_err)?;

        Ok(())
    })
}

#[test]
fn wallet_014_from_parts_reconstructs_wallet_with_same_public_address_and_secret_blob() -> TestResult
{
    run_serial(|| {
        let wallet = new_wallet("wallet-from-parts-passphrase")?;
        let loaded = MLDSA65Wallet::from_parts(wallet.public, wallet.encrypted_secret.clone())
            .map_err(debug_err)?;

        assert_eq!(loaded.public, wallet.public);
        assert_eq!(loaded.address, wallet.address);
        assert_eq!(loaded.encrypted_secret, wallet.encrypted_secret);
        loaded.validate_self().map_err(debug_err)?;

        Ok(())
    })
}

#[test]
fn wallet_015_from_parts_rejects_too_small_encrypted_secret() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-from-parts-small-secret-passphrase")?;
        let too_small = vec![0_u8; 31];

        assert!(MLDSA65Wallet::from_parts(wallet.public, too_small).is_err());

        Ok(())
    })
}

#[test]
fn wallet_016_from_parts_rejects_too_large_encrypted_secret() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-from-parts-large-secret-passphrase")?;
        let too_large = vec![0_u8; 64 * 1024 + 1];

        assert!(MLDSA65Wallet::from_parts(wallet.public, too_large).is_err());

        Ok(())
    })
}

#[test]
fn wallet_017_public_key_hex_has_expected_length_and_content() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-public-hex-passphrase")?;
        let public_hex = wallet.public_key_hex();

        assert_eq!(public_hex.len(), ml_dsa_65::PK_LEN * 2);
        assert_eq!(public_hex, hex::encode(wallet.public));
        assert!(public_hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(public_hex.bytes().all(|byte| !byte.is_ascii_uppercase()));

        Ok(())
    })
}

#[test]
fn wallet_018_secret_key_hex_has_expected_length() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-secret-hex-passphrase")?;
        let secret = secret_hex(&wallet, "wallet-secret-hex-passphrase")?;

        assert_eq!(secret.len(), ml_dsa_65::SK_LEN * 2);
        assert!(secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(secret.bytes().all(|byte| !byte.is_ascii_uppercase()));

        Ok(())
    })
}

#[test]
fn wallet_019_secret_key_hex_wrong_passphrase_rejected() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-secret-export-right-passphrase")?;

        assert!(
            wallet
                .secret_key_hex("wallet-secret-export-wrong-passphrase")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_020_address_from_secret_bytes_matches_wallet_address() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-address-from-secret-passphrase")?;
        let secret = secret_hex(&wallet, "wallet-address-from-secret-passphrase")?;
        let secret_bytes = hex::decode(secret).map_err(debug_err)?;
        let recovered =
            MLDSA65Wallet::address_from_secret_bytes(&secret_bytes).map_err(debug_err)?;

        assert_eq!(recovered, wallet.address);

        Ok(())
    })
}

#[test]
fn wallet_021_address_from_secret_bytes_rejects_empty_secret() -> TestResult {
    run_serial(|| {
        assert!(MLDSA65Wallet::address_from_secret_bytes(&[]).is_err());
        Ok(())
    })
}

#[test]
fn wallet_022_address_from_secret_bytes_rejects_short_secret() -> TestResult {
    run_serial(|| {
        let short_secret = vec![0_u8; ml_dsa_65::SK_LEN.saturating_sub(1)];

        assert!(MLDSA65Wallet::address_from_secret_bytes(&short_secret).is_err());

        Ok(())
    })
}

#[test]
fn wallet_023_address_from_secret_bytes_rejects_long_secret() -> TestResult {
    run_serial(|| {
        let long_secret = vec![0_u8; ml_dsa_65::SK_LEN.saturating_add(1)];

        assert!(MLDSA65Wallet::address_from_secret_bytes(&long_secret).is_err());

        Ok(())
    })
}

#[test]
fn wallet_024_sign_returns_exact_ml_dsa_signature_length() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-sign-length-passphrase")?;
        let signature = sign_wallet(&wallet, "wallet-sign-length-passphrase", b"message")?;

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);

        Ok(())
    })
}

#[test]
fn wallet_025_sign_and_verify_small_message_succeeds() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-sign-verify-passphrase")?;
        let message = b"wallet signed message";
        let signature = sign_wallet(&wallet, "wallet-sign-verify-passphrase", message)?;

        assert!(wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_026_sign_and_verify_empty_message_succeeds() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-empty-message-passphrase")?;
        let message = b"";
        let signature = sign_wallet(&wallet, "wallet-empty-message-passphrase", message)?;

        assert!(wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_027_sign_with_wrong_passphrase_rejected() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-right-sign-passphrase")?;

        assert!(
            wallet
                .sign("wallet-wrong-sign-passphrase", b"message")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_028_verify_rejects_changed_message() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-changed-message-passphrase")?;
        let signature = sign_wallet(&wallet, "wallet-changed-message-passphrase", b"original")?;

        assert!(!wallet.verify(b"changed", &signature));

        Ok(())
    })
}

#[test]
fn wallet_029_verify_rejects_wrong_wallet_public_key() -> TestResult {
    run_serial(|| {
        let signer = new_wallet("wallet-signer-passphrase")?;
        let verifier = new_wallet("wallet-verifier-passphrase")?;
        let signature = sign_wallet(&signer, "wallet-signer-passphrase", b"message")?;

        assert!(signer.verify(b"message", &signature));
        assert!(!verifier.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_030_verify_rejects_empty_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-empty-signature-passphrase")?;

        assert!(!wallet.verify(b"message", &[]));

        Ok(())
    })
}

#[test]
fn wallet_031_verify_rejects_short_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-short-signature-passphrase")?;
        let mut signature = sign_wallet(&wallet, "wallet-short-signature-passphrase", b"message")?;

        signature.truncate(signature.len().saturating_sub(1));

        assert!(!wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_032_verify_rejects_long_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-long-signature-passphrase")?;
        let mut signature = sign_wallet(&wallet, "wallet-long-signature-passphrase", b"message")?;

        signature.push(0);

        assert!(!wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_033_verify_rejects_tampered_signature_first_byte() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-tampered-signature-passphrase")?;
        let mut signature =
            sign_wallet(&wallet, "wallet-tampered-signature-passphrase", b"message")?;

        flip_byte(&mut signature, 0)?;

        assert!(!wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_034_verify_rejects_tampered_signature_last_byte() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-tampered-last-signature-passphrase")?;
        let mut signature = sign_wallet(
            &wallet,
            "wallet-tampered-last-signature-passphrase",
            b"message",
        )?;
        let last = signature
            .len()
            .checked_sub(1)
            .ok_or_else(|| "signature unexpectedly empty".to_string())?;

        flip_byte(&mut signature, last)?;

        assert!(!wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_035_validate_self_rejects_tampered_address() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-tampered-address-passphrase")?;

        wallet.address = format!("r{}", "a".repeat(128));

        assert!(wallet.validate_self().is_err());

        Ok(())
    })
}

#[test]
fn wallet_036_validate_self_rejects_wrong_address_prefix() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-wrong-prefix-passphrase")?;

        wallet.address.replace_range(0..1, "p");

        assert!(wallet.validate_self().is_err());

        Ok(())
    })
}

#[test]
fn wallet_037_validate_self_rejects_too_small_encrypted_secret() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-small-encrypted-secret-passphrase")?;

        wallet.encrypted_secret = vec![0_u8; 31];

        assert!(wallet.validate_self().is_err());

        Ok(())
    })
}

#[test]
fn wallet_038_validate_self_rejects_too_large_encrypted_secret() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-large-encrypted-secret-passphrase")?;

        wallet.encrypted_secret = vec![0_u8; 64 * 1024 + 1];

        assert!(wallet.validate_self().is_err());

        Ok(())
    })
}

#[test]
fn wallet_039_sign_rejects_tampered_encrypted_secret() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-tampered-secret-passphrase")?;

        flip_byte(&mut wallet.encrypted_secret, 0)?;

        assert!(
            wallet
                .sign("wallet-tampered-secret-passphrase", b"message")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_040_verify_still_uses_public_key_even_if_encrypted_secret_is_tampered() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-public-only-verify-passphrase")?;
        let signature = sign_wallet(&wallet, "wallet-public-only-verify-passphrase", b"message")?;
        let mut tampered_wallet = wallet.clone();

        flip_byte(&mut tampered_wallet.encrypted_secret, 0)?;

        assert!(tampered_wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_041_clone_preserves_public_address_and_encrypted_secret() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-clone-passphrase")?;
        let cloned = wallet.clone();

        assert_eq!(cloned.public, wallet.public);
        assert_eq!(cloned.address, wallet.address);
        assert_eq!(cloned.encrypted_secret, wallet.encrypted_secret);

        Ok(())
    })
}

#[test]
fn wallet_042_clone_can_verify_original_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-clone-verify-passphrase")?;
        let cloned = wallet.clone();
        let message = b"clone verification message";
        let signature = sign_wallet(&wallet, "wallet-clone-verify-passphrase", message)?;

        assert!(cloned.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_043_clone_can_sign_and_original_can_verify() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-clone-sign-passphrase")?;
        let cloned = wallet.clone();
        let message = b"clone signing message";
        let signature = sign_wallet(&cloned, "wallet-clone-sign-passphrase", message)?;

        assert!(wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_044_debug_output_contains_wallet_struct_name() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-debug-passphrase")?;
        let debug_output = format!("{wallet:?}");

        assert!(debug_output.contains("MLDSA65Wallet"));
        assert!(debug_output.contains("public"));
        assert!(debug_output.contains("address"));
        assert!(debug_output.contains("encrypted_secret"));

        Ok(())
    })
}

#[test]
fn wallet_045_two_new_wallets_have_distinct_addresses() -> TestResult {
    run_serial(|| {
        let first = new_wallet("wallet-distinct-one-passphrase")?;
        let second = new_wallet("wallet-distinct-two-passphrase")?;

        assert_ne!(first.address, second.address);
        assert_ne!(first.public, second.public);

        Ok(())
    })
}

#[test]
fn wallet_046_new_wallets_with_same_passphrase_still_have_distinct_addresses() -> TestResult {
    run_serial(|| {
        let first = new_wallet("same-passphrase-distinct-wallets")?;
        let second = new_wallet("same-passphrase-distinct-wallets")?;

        assert_ne!(first.address, second.address);
        assert_ne!(first.public, second.public);

        Ok(())
    })
}

#[test]
fn wallet_047_encrypted_secret_length_matches_raw_ml_dsa_secret_envelope() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-encrypted-secret-length-passphrase")?;
        let expected_len = 16_usize + 12_usize + 16_usize + ml_dsa_65::SK_LEN;

        assert_eq!(wallet.encrypted_secret.len(), expected_len);

        Ok(())
    })
}

#[test]
fn wallet_048_encrypted_secret_is_not_plain_secret_hex() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-encrypted-not-plain-passphrase")?;
        let secret = secret_hex(&wallet, "wallet-encrypted-not-plain-passphrase")?;
        let secret_bytes = hex::decode(secret).map_err(debug_err)?;

        assert_ne!(wallet.encrypted_secret.as_slice(), secret_bytes.as_slice());

        Ok(())
    })
}

#[test]
fn wallet_049_secret_key_hex_roundtrips_to_address_from_secret_bytes() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-secret-address-roundtrip-passphrase")?;
        let secret = secret_hex(&wallet, "wallet-secret-address-roundtrip-passphrase")?;
        let secret_bytes = hex::decode(secret).map_err(debug_err)?;
        let recovered =
            MLDSA65Wallet::address_from_secret_bytes(&secret_bytes).map_err(debug_err)?;

        assert_eq!(recovered, wallet.address);

        Ok(())
    })
}

#[test]
fn wallet_050_secret_key_hex_is_stable_for_same_wallet_and_passphrase() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-secret-stable-passphrase")?;
        let first = secret_hex(&wallet, "wallet-secret-stable-passphrase")?;
        let second = secret_hex(&wallet, "wallet-secret-stable-passphrase")?;

        assert_eq!(first, second);

        Ok(())
    })
}

#[test]
fn wallet_051_signing_same_message_twice_produces_verifiable_signatures() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-repeat-sign-passphrase")?;
        let message = b"repeat sign message";

        let first = sign_wallet(&wallet, "wallet-repeat-sign-passphrase", message)?;
        let second = sign_wallet(&wallet, "wallet-repeat-sign-passphrase", message)?;

        assert_eq!(first.len(), ml_dsa_65::SIG_LEN);
        assert_eq!(second.len(), ml_dsa_65::SIG_LEN);
        assert!(wallet.verify(message, &first));
        assert!(wallet.verify(message, &second));

        Ok(())
    })
}

#[test]
fn wallet_052_signature_for_empty_message_rejects_zero_byte_message() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-empty-vs-zero-passphrase")?;
        let signature = sign_wallet(&wallet, "wallet-empty-vs-zero-passphrase", b"")?;

        assert!(wallet.verify(b"", &signature));
        assert!(!wallet.verify(&[0_u8], &signature));

        Ok(())
    })
}

#[test]
fn wallet_053_signature_for_zero_byte_message_rejects_empty_message() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-zero-vs-empty-passphrase")?;
        let zero = [0_u8];
        let signature = sign_wallet(&wallet, "wallet-zero-vs-empty-passphrase", &zero)?;

        assert!(wallet.verify(&zero, &signature));
        assert!(!wallet.verify(b"", &signature));

        Ok(())
    })
}

#[test]
fn wallet_054_sign_and_verify_unicode_message_bytes() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-unicode-message-passphrase")?;
        let message = "remzar wallet message 🔐 秘密".as_bytes();
        let signature = sign_wallet(&wallet, "wallet-unicode-message-passphrase", message)?;

        assert!(wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_055_sign_and_verify_binary_message_with_nul_bytes() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-binary-message-passphrase")?;
        let message = [0_u8, 1, 2, 0, 3, 255, 0, 4];
        let signature = sign_wallet(&wallet, "wallet-binary-message-passphrase", &message)?;

        assert!(wallet.verify(&message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_056_sign_and_verify_one_kib_message() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-one-kib-message-passphrase")?;
        let message = vec![0x5A_u8; 1024];
        let signature = sign_wallet(&wallet, "wallet-one-kib-message-passphrase", &message)?;

        assert!(wallet.verify(&message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_057_verify_rejects_reversed_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-reversed-signature-passphrase")?;
        let message = b"reverse signature message";
        let mut signature = sign_wallet(&wallet, "wallet-reversed-signature-passphrase", message)?;

        signature.reverse();

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        assert!(!wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_058_verify_rejects_rotated_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-rotated-signature-passphrase")?;
        let message = b"rotate signature message";
        let mut signature = sign_wallet(&wallet, "wallet-rotated-signature-passphrase", message)?;

        signature.rotate_left(1);

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        assert!(!wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_059_verify_rejects_all_zero_exact_length_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-zero-signature-passphrase")?;
        let signature = vec![0_u8; ml_dsa_65::SIG_LEN];

        assert!(!wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_060_verify_rejects_all_max_exact_length_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-max-signature-passphrase")?;
        let signature = vec![u8::MAX; ml_dsa_65::SIG_LEN];

        assert!(!wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_061_verify_rejects_alternating_exact_length_signature() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-alternating-signature-passphrase")?;
        let mut signature = vec![0_u8; ml_dsa_65::SIG_LEN];

        for (index, byte) in signature.iter_mut().enumerate() {
            *byte = if index % 2 == 0 { 0xAA } else { 0x55 };
        }

        assert!(!wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_062_from_parts_with_other_public_but_same_secret_blob_validates_structurally()
-> TestResult {
    run_serial(|| {
        let secret_owner = new_wallet("wallet-secret-owner-passphrase")?;
        let public_owner = new_wallet("wallet-public-owner-passphrase")?;

        let loaded =
            MLDSA65Wallet::from_parts(public_owner.public, secret_owner.encrypted_secret.clone())
                .map_err(debug_err)?;

        assert_eq!(loaded.public, public_owner.public);
        assert_eq!(loaded.address, public_owner.address);
        loaded.validate_self().map_err(debug_err)?;

        Ok(())
    })
}

#[test]
fn wallet_063_from_parts_with_other_public_rejects_signing_due_to_secret_public_mismatch()
-> TestResult {
    run_serial(|| {
        let secret_owner = new_wallet("wallet-secret-owner-sign-passphrase")?;
        let public_owner = new_wallet("wallet-public-owner-sign-passphrase")?;

        let loaded =
            MLDSA65Wallet::from_parts(public_owner.public, secret_owner.encrypted_secret.clone())
                .map_err(debug_err)?;

        assert!(
            loaded
                .sign("wallet-secret-owner-sign-passphrase", b"message")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_064_validate_self_rejects_public_address_mismatch_using_valid_other_public() -> TestResult
{
    run_serial(|| {
        let mut wallet = new_wallet("wallet-public-mismatch-passphrase")?;
        let other = new_wallet("wallet-other-public-passphrase")?;

        wallet.public = other.public;

        assert!(wallet.validate_self().is_err());

        Ok(())
    })
}

#[test]
fn wallet_065_verify_rejects_public_address_mismatch_using_valid_other_public() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-verify-public-mismatch-passphrase")?;
        let signature = sign_wallet(
            &wallet,
            "wallet-verify-public-mismatch-passphrase",
            b"message",
        )?;
        let other = new_wallet("wallet-verify-other-public-passphrase")?;
        let mut tampered = wallet.clone();

        tampered.public = other.public;

        assert!(!tampered.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_066_validate_self_accepts_uppercase_stored_address_for_same_public() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-uppercase-stored-address-passphrase")?;

        wallet.address = wallet.address.to_ascii_uppercase();

        wallet.validate_self().map_err(debug_err)?;

        Ok(())
    })
}

#[test]
fn wallet_067_verify_accepts_uppercase_stored_address_for_same_public() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-uppercase-verify-passphrase")?;
        let signature = sign_wallet(&wallet, "wallet-uppercase-verify-passphrase", b"message")?;
        let mut uppercase_wallet = wallet.clone();

        uppercase_wallet.address = uppercase_wallet.address.to_ascii_uppercase();

        assert!(uppercase_wallet.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_068_sign_rejects_uppercase_stored_address_even_for_same_public() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-uppercase-sign-passphrase")?;

        wallet.address = wallet.address.to_ascii_uppercase();

        assert!(
            wallet
                .sign("wallet-uppercase-sign-passphrase", b"message")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_069_validate_address_format_rejects_internal_whitespace() -> TestResult {
    run_serial(|| {
        let invalid = format!("r{} {}", "a".repeat(64), "b".repeat(63));

        assert!(MLDSA65Wallet::validate_address_format(&invalid).is_err());

        Ok(())
    })
}

#[test]
fn wallet_070_validate_address_format_rejects_trailing_whitespace_due_length_check() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-trailing-space-address-passphrase")?;
        let invalid = format!("{} ", wallet.address);

        assert!(MLDSA65Wallet::validate_address_format(&invalid).is_err());

        Ok(())
    })
}

#[test]
fn wallet_071_public_key_hex_matches_generate_address_input() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-public-hex-address-passphrase")?;
        let public_hex = wallet.public_key_hex();
        let public_bytes = hex::decode(public_hex).map_err(debug_err)?;
        let public_array: [u8; ml_dsa_65::PK_LEN] = public_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "public hex did not decode to ML-DSA-65 public key length".to_string())?;
        let generated = MLDSA65Wallet::generate_address(&public_array).map_err(debug_err)?;

        assert_eq!(generated, wallet.address);

        Ok(())
    })
}

#[test]
fn wallet_072_secret_key_hex_decodes_to_ml_dsa_secret_length() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-secret-hex-decode-passphrase")?;
        let secret = secret_hex(&wallet, "wallet-secret-hex-decode-passphrase")?;
        let secret_bytes = hex::decode(secret).map_err(debug_err)?;

        assert_eq!(secret_bytes.len(), ml_dsa_65::SK_LEN);

        Ok(())
    })
}

#[test]
fn wallet_073_property_sign_verify_various_message_lengths() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-various-message-lengths-passphrase")?;

        for len in [0_usize, 1, 2, 7, 16, 31, 64, 127, 256] {
            let message = deterministic_message(len, len.to_le_bytes()[0]);
            let signature = sign_wallet(
                &wallet,
                "wallet-various-message-lengths-passphrase",
                &message,
            )?;

            assert!(
                wallet.verify(&message, &signature),
                "message length {len} did not verify"
            );
        }

        Ok(())
    })
}

#[test]
fn wallet_074_property_each_message_byte_change_rejects() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-message-byte-change-passphrase")?;
        let message = deterministic_message(32, 0xA5);
        let signature = sign_wallet(&wallet, "wallet-message-byte-change-passphrase", &message)?;

        for position in [0_usize, 1, 7, 15, 31] {
            let mut changed = message.clone();
            flip_byte(&mut changed, position)?;
            assert!(
                !wallet.verify(&changed, &signature),
                "changed message byte {position} verified unexpectedly"
            );
        }

        Ok(())
    })
}

#[test]
fn wallet_075_property_sampled_signature_byte_flips_reject() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-sampled-signature-flips-passphrase")?;
        let message = b"sampled signature flip message";
        let signature = sign_wallet(
            &wallet,
            "wallet-sampled-signature-flips-passphrase",
            message,
        )?;

        let positions = [
            0_usize,
            1,
            64,
            ml_dsa_65::SIG_LEN.div_euclid(2),
            ml_dsa_65::SIG_LEN.saturating_sub(2),
            ml_dsa_65::SIG_LEN.saturating_sub(1),
        ];

        for position in positions {
            let mut changed = signature.clone();
            flip_byte(&mut changed, position)?;
            assert!(
                !wallet.verify(message, &changed),
                "changed signature byte {position} verified unexpectedly"
            );
        }

        Ok(())
    })
}

#[test]
fn wallet_076_load_test_sign_verify_ten_messages_same_wallet() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-load-ten-messages-passphrase")?;

        for round in 0..10_usize {
            let message = deterministic_message(round + 1, round.to_le_bytes()[0]);
            let signature = sign_wallet(&wallet, "wallet-load-ten-messages-passphrase", &message)?;

            assert!(wallet.verify(&message, &signature));
        }

        Ok(())
    })
}

#[test]
fn wallet_077_load_test_five_wallets_sign_and_verify() -> TestResult {
    run_serial(|| {
        for round in 0..5_usize {
            let passphrase = format!("wallet-load-five-wallets-passphrase-{round}");
            let wallet = new_wallet(&passphrase)?;
            let message = deterministic_message(32, round.to_le_bytes()[0]);
            let signature = sign_wallet(&wallet, &passphrase, &message)?;

            assert!(wallet.verify(&message, &signature));
        }

        Ok(())
    })
}

#[test]
fn wallet_078_sign_rejects_message_above_absolute_bound() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-too-large-message-sign-passphrase")?;
        let message = vec![0_u8; 16 * 1024 * 1024 + 1];

        assert!(
            wallet
                .sign("wallet-too-large-message-sign-passphrase", &message)
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_079_verify_rejects_message_above_absolute_bound() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-too-large-message-verify-passphrase")?;
        let signature = sign_wallet(
            &wallet,
            "wallet-too-large-message-verify-passphrase",
            b"small",
        )?;
        let message = vec![0_u8; 16 * 1024 * 1024 + 1];

        assert!(!wallet.verify(&message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_080_verify_rejects_signature_after_drop_first_byte_and_pad_end() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-drop-first-pad-end-passphrase")?;
        let message = b"drop first pad end";
        let signature = sign_wallet(&wallet, "wallet-drop-first-pad-end-passphrase", message)?;
        let shifted = signature
            .get(1..)
            .ok_or_else(|| "missing shifted signature".to_string())?;

        let mut modified = Vec::with_capacity(signature.len());
        modified.extend_from_slice(shifted);
        modified.push(0);

        assert_eq!(modified.len(), ml_dsa_65::SIG_LEN);
        assert!(!wallet.verify(message, &modified));

        Ok(())
    })
}

#[test]
fn wallet_081_verify_rejects_signature_after_leading_zero_and_drop_last_byte() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-leading-zero-drop-last-passphrase")?;
        let message = b"leading zero drop last";
        let signature = sign_wallet(&wallet, "wallet-leading-zero-drop-last-passphrase", message)?;
        let without_last = signature
            .get(..signature.len().saturating_sub(1))
            .ok_or_else(|| "missing shortened signature".to_string())?;

        let mut modified = Vec::with_capacity(signature.len());
        modified.push(0);
        modified.extend_from_slice(without_last);

        assert_eq!(modified.len(), ml_dsa_65::SIG_LEN);
        assert!(!wallet.verify(message, &modified));

        Ok(())
    })
}

#[test]
fn wallet_082_verify_rejects_signature_with_first_sixty_four_bytes_zeroed() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-zero-head-signature-passphrase")?;
        let message = b"zero head signature";
        let mut signature = sign_wallet(&wallet, "wallet-zero-head-signature-passphrase", message)?;

        let head = signature
            .get_mut(..64)
            .ok_or_else(|| "missing signature head".to_string())?;
        head.fill(0);

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        assert!(!wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_083_verify_rejects_signature_with_last_sixty_four_bytes_zeroed() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-zero-tail-signature-passphrase")?;
        let message = b"zero tail signature";
        let mut signature = sign_wallet(&wallet, "wallet-zero-tail-signature-passphrase", message)?;
        let start = signature.len().saturating_sub(64);

        let tail = signature
            .get_mut(start..)
            .ok_or_else(|| "missing signature tail".to_string())?;
        tail.fill(0);

        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        assert!(!wallet.verify(message, &signature));

        Ok(())
    })
}

#[test]
fn wallet_084_verify_rejects_signature_duplicate_full_frame_by_length() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-duplicate-signature-frame-passphrase")?;
        let message = b"duplicate signature frame";
        let signature = sign_wallet(
            &wallet,
            "wallet-duplicate-signature-frame-passphrase",
            message,
        )?;
        let mut duplicated = Vec::with_capacity(signature.len().saturating_mul(2));

        duplicated.extend_from_slice(&signature);
        duplicated.extend_from_slice(&signature);

        assert!(!wallet.verify(message, &duplicated));

        Ok(())
    })
}

#[test]
fn wallet_085_signature_byte_by_byte_reassembly_verifies() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-byte-reassembly-passphrase")?;
        let message = b"byte by byte signature reassembly";
        let signature = sign_wallet(&wallet, "wallet-byte-reassembly-passphrase", message)?;
        let mut reassembled = Vec::with_capacity(signature.len());

        for byte in signature.iter().copied() {
            reassembled.push(byte);
        }

        assert!(wallet.verify(message, &reassembled));

        Ok(())
    })
}

#[test]
fn wallet_086_from_parts_with_random_structural_secret_blob_validates_but_cannot_sign() -> TestResult
{
    run_serial(|| {
        let wallet = new_wallet("wallet-random-blob-owner-passphrase")?;
        let random_blob = vec![0xAB_u8; 64];

        let loaded = MLDSA65Wallet::from_parts(wallet.public, random_blob).map_err(debug_err)?;

        loaded.validate_self().map_err(debug_err)?;
        assert!(
            loaded
                .sign("wallet-random-blob-owner-passphrase", b"message")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_087_secret_key_hex_rejects_tampered_encrypted_secret() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-secret-export-tamper-passphrase")?;

        flip_byte(&mut wallet.encrypted_secret, 0)?;

        assert!(
            wallet
                .secret_key_hex("wallet-secret-export-tamper-passphrase")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_088_secret_key_hex_rejects_valid_other_wallet_secret_blob() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-secret-export-owner-passphrase")?;
        let other = new_wallet("wallet-secret-export-other-passphrase")?;

        wallet.encrypted_secret = other.encrypted_secret.clone();

        assert!(
            wallet
                .secret_key_hex("wallet-secret-export-other-passphrase")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_089_sign_rejects_valid_other_wallet_secret_blob() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-sign-owner-passphrase")?;
        let other = new_wallet("wallet-sign-other-passphrase")?;

        wallet.encrypted_secret = other.encrypted_secret.clone();

        assert!(
            wallet
                .sign("wallet-sign-other-passphrase", b"message")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_090_verify_rejects_wrong_address_even_when_public_key_matches_signature_key() -> TestResult
{
    run_serial(|| {
        let wallet = new_wallet("wallet-wrong-address-verify-passphrase")?;
        let signature = sign_wallet(
            &wallet,
            "wallet-wrong-address-verify-passphrase",
            b"message",
        )?;
        let mut tampered = wallet.clone();

        tampered.address = format!("r{}", "0".repeat(128));

        assert!(!tampered.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_091_verify_rejects_shortened_address_even_when_public_key_matches() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-short-address-verify-passphrase")?;
        let signature = sign_wallet(
            &wallet,
            "wallet-short-address-verify-passphrase",
            b"message",
        )?;
        let mut tampered = wallet.clone();

        tampered.address.truncate(128);

        assert!(!tampered.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_092_verify_rejects_non_hex_address_even_when_public_key_matches() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-nonhex-address-verify-passphrase")?;
        let signature = sign_wallet(
            &wallet,
            "wallet-nonhex-address-verify-passphrase",
            b"message",
        )?;
        let mut tampered = wallet.clone();

        tampered.address = format!("r{}z", "a".repeat(127));

        assert!(!tampered.verify(b"message", &signature));

        Ok(())
    })
}

#[test]
fn wallet_093_sign_rejects_wrong_address_even_with_correct_passphrase_and_secret() -> TestResult {
    run_serial(|| {
        let mut wallet = new_wallet("wallet-wrong-address-sign-passphrase")?;

        wallet.address = format!("r{}", "0".repeat(128));

        assert!(
            wallet
                .sign("wallet-wrong-address-sign-passphrase", b"message")
                .is_err()
        );

        Ok(())
    })
}

#[test]
fn wallet_094_address_from_secret_bytes_matches_after_from_parts_reload() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-reload-address-secret-passphrase")?;
        let loaded = MLDSA65Wallet::from_parts(wallet.public, wallet.encrypted_secret.clone())
            .map_err(debug_err)?;
        let secret = secret_hex(&loaded, "wallet-reload-address-secret-passphrase")?;
        let secret_bytes = hex::decode(secret).map_err(debug_err)?;
        let recovered =
            MLDSA65Wallet::address_from_secret_bytes(&secret_bytes).map_err(debug_err)?;

        assert_eq!(recovered, loaded.address);
        assert_eq!(recovered, wallet.address);

        Ok(())
    })
}

#[test]
fn wallet_095_property_generate_address_is_stable_for_same_public_key() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-stable-address-generation-passphrase")?;

        let first = MLDSA65Wallet::generate_address(&wallet.public).map_err(debug_err)?;
        let second = MLDSA65Wallet::generate_address(&wallet.public).map_err(debug_err)?;

        assert_eq!(first, second);
        assert_eq!(first, wallet.address);

        Ok(())
    })
}

#[test]
fn wallet_096_property_addresses_are_distinct_across_small_wallet_set() -> TestResult {
    run_serial(|| {
        let mut addresses = Vec::with_capacity(5);

        for round in 0..5_usize {
            let passphrase = format!("wallet-distinct-set-passphrase-{round}");
            let wallet = new_wallet(&passphrase)?;

            assert!(
                !addresses.iter().any(|seen| seen == &wallet.address),
                "duplicate wallet address at round {round}"
            );

            addresses.push(wallet.address);
        }

        Ok(())
    })
}

#[test]
fn wallet_097_property_public_keys_are_distinct_across_small_wallet_set() -> TestResult {
    run_serial(|| {
        let mut public_keys: Vec<[u8; ml_dsa_65::PK_LEN]> = Vec::with_capacity(5);

        for round in 0..5_usize {
            let passphrase = format!("wallet-distinct-public-set-passphrase-{round}");
            let wallet = new_wallet(&passphrase)?;

            assert!(
                !public_keys.iter().any(|seen| seen == &wallet.public),
                "duplicate wallet public key at round {round}"
            );

            public_keys.push(wallet.public);
        }

        Ok(())
    })
}

#[test]
fn wallet_098_load_light_three_wallets_export_secret_and_recover_address() -> TestResult {
    run_serial(|| {
        for round in 0..3_usize {
            let passphrase = format!("wallet-load-export-recover-passphrase-{round}");
            let wallet = new_wallet(&passphrase)?;
            let secret = secret_hex(&wallet, &passphrase)?;
            let secret_bytes = hex::decode(secret).map_err(debug_err)?;
            let recovered =
                MLDSA65Wallet::address_from_secret_bytes(&secret_bytes).map_err(debug_err)?;

            assert_eq!(recovered, wallet.address);
        }

        Ok(())
    })
}

#[test]
fn wallet_099_load_light_three_wallets_sign_verify_binary_messages() -> TestResult {
    run_serial(|| {
        for round in 0..3_usize {
            let passphrase = format!("wallet-load-binary-message-passphrase-{round}");
            let wallet = new_wallet(&passphrase)?;
            let message = deterministic_message(64, round.to_le_bytes()[0].wrapping_add(9));
            let signature = sign_wallet(&wallet, &passphrase, &message)?;

            assert!(wallet.verify(&message, &signature));
        }

        Ok(())
    })
}

#[test]
fn wallet_100_load_light_one_wallet_signs_twenty_small_messages() -> TestResult {
    run_serial(|| {
        let passphrase = "wallet-final-load-one-wallet-passphrase";
        let wallet = new_wallet(passphrase)?;

        for round in 0..20_usize {
            let message = deterministic_message(round.saturating_add(1), round.to_le_bytes()[0]);
            let signature = sign_wallet(&wallet, passphrase, &message)?;

            assert!(
                wallet.verify(&message, &signature),
                "signature did not verify at round {round}"
            );
        }

        Ok(())
    })
}

#[test]
fn wallet_101_address_from_secret_bytes_rejects_all_zero_exact_length_secret_without_panic()
-> TestResult {
    run_serial(|| {
        let secret = vec![0_u8; ml_dsa_65::SK_LEN];

        assert_address_from_secret_rejects_without_unwinding(&secret)
    })
}

#[test]
fn wallet_102_address_from_secret_bytes_rejects_all_ff_exact_length_secret_without_panic()
-> TestResult {
    run_serial(|| {
        let secret = vec![u8::MAX; ml_dsa_65::SK_LEN];

        assert_address_from_secret_rejects_without_unwinding(&secret)
    })
}

#[test]
fn wallet_103_address_from_secret_bytes_rejects_alternating_exact_length_secret_without_panic()
-> TestResult {
    run_serial(|| {
        let mut secret = vec![0_u8; ml_dsa_65::SK_LEN];

        for (index, byte) in secret.iter_mut().enumerate() {
            *byte = if index % 2 == 0 { 0xAA } else { 0x55 };
        }

        assert_address_from_secret_rejects_without_unwinding(&secret)
    })
}

#[test]
fn wallet_104_address_from_secret_bytes_rejects_incrementing_exact_length_secret_without_panic()
-> TestResult {
    run_serial(|| {
        let secret: Vec<u8> = (0..ml_dsa_65::SK_LEN)
            .map(|index| index.to_le_bytes()[0])
            .collect();

        assert_address_from_secret_rejects_without_unwinding(&secret)
    })
}

#[test]
fn wallet_105_address_from_secret_bytes_rejects_mutated_valid_secret_without_panic() -> TestResult {
    run_serial(|| {
        let wallet = new_wallet("wallet-mutated-valid-secret-guard-passphrase")?;
        let secret = secret_hex(&wallet, "wallet-mutated-valid-secret-guard-passphrase")?;
        let mut secret_bytes = hex::decode(secret).map_err(debug_err)?;

        flip_byte(&mut secret_bytes, 0)?;
        flip_byte(&mut secret_bytes, ml_dsa_65::SK_LEN / 2)?;
        flip_byte(&mut secret_bytes, ml_dsa_65::SK_LEN.saturating_sub(1))?;

        assert_address_from_secret_rejects_without_unwinding(&secret_bytes)
    })
}
