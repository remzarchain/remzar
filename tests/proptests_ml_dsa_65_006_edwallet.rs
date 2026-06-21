use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use std::sync::{Mutex, MutexGuard, OnceLock};

const PRIMARY_PASSPHRASE: &str = "remzar-wallet-proptest-primary-passphrase-2026!";
const SECONDARY_PASSPHRASE: &str = "remzar-wallet-proptest-secondary-passphrase-2026!";
const WRONG_PASSPHRASE: &str = "remzar-wallet-proptest-wrong-passphrase-2026!";

static WALLET_CRYPTO_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static PRIMARY_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static SECONDARY_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();

fn wallet_crypto_guard() -> MutexGuard<'static, ()> {
    WALLET_CRYPTO_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn primary_wallet() -> &'static MLDSA65Wallet {
    PRIMARY_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(PRIMARY_PASSPHRASE)
            .expect("primary ML-DSA-65 wallet generation should succeed")
    })
}

fn secondary_wallet() -> &'static MLDSA65Wallet {
    SECONDARY_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(SECONDARY_PASSPHRASE)
            .expect("secondary ML-DSA-65 wallet generation should succeed")
    })
}

proptest! {
    #![proptest_config(Config {
        // Keep these real ML-DSA wallet property checks fast. Each case may
        // decrypt, parse, sign, or verify through the hardened ML-DSA path.
        cases: 1,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_wallet_new_generates_valid_address_and_valid_invariants(_case in any::<u8>()) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        prop_assert!(
            wallet.validate_self().is_ok(),
            "new wallet must satisfy wallet invariants"
        );

        prop_assert!(
            MLDSA65Wallet::validate_address_format(&wallet.address).is_ok(),
            "generated wallet address must have valid canonical format"
        );

        prop_assert_eq!(
            wallet.address.len(),
            129,
            "wallet address must be 'r' plus 128 lowercase hex chars"
        );

        prop_assert!(
            wallet.address.starts_with('r'),
            "wallet address must start with 'r'"
        );

        prop_assert_eq!(
            wallet.public.len(),
            ml_dsa_65::PK_LEN,
            "wallet public key must have ML-DSA-65 public-key length"
        );

        prop_assert!(
            !wallet.encrypted_secret.is_empty(),
            "wallet encrypted secret must not be empty"
        );
    }

    // 02/25
    #[test]
    fn test_002_wallet_sign_then_verify_accepts_valid_signature(
        message in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let signature = wallet
            .sign(PRIMARY_PASSPHRASE, &message)
            .expect("wallet signing should succeed with correct passphrase");

        prop_assert_eq!(
            signature.len(),
            ml_dsa_65::SIG_LEN,
            "wallet signature must have exact ML-DSA-65 signature length"
        );

        prop_assert!(
            wallet.verify(&message, &signature),
            "wallet must verify its own valid signature over the same message"
        );
    }

    // 03/25
    #[test]
    fn test_003_wallet_verify_rejects_tampered_signature_byte(
        message in proptest::collection::vec(any::<u8>(), 0..512),
        sig_index in 0usize..ml_dsa_65::SIG_LEN,
        delta in 1u8..=255u8,
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let mut signature = wallet
            .sign(PRIMARY_PASSPHRASE, &message)
            .expect("wallet signing should succeed");

        signature[sig_index] = signature[sig_index].wrapping_add(delta);

        prop_assert!(
            !wallet.verify(&message, &signature),
            "wallet verification must reject tampered signature byte at index {sig_index}"
        );
    }

    // 04/25
    #[test]
    fn test_004_wallet_verify_rejects_tampered_message(
        tail in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let mut original_message = Vec::with_capacity(tail.len() + 1);
        original_message.push(0u8);
        original_message.extend_from_slice(&tail);

        let mut tampered_message = Vec::with_capacity(tail.len() + 1);
        tampered_message.push(1u8);
        tampered_message.extend_from_slice(&tail);

        let signature = wallet
            .sign(PRIMARY_PASSPHRASE, &original_message)
            .expect("wallet signing should succeed");

        prop_assert!(
            !wallet.verify(&tampered_message, &signature),
            "wallet verification must reject signature when message changes"
        );
    }

    // 05/25
    #[test]
    fn test_005_wallet_sign_rejects_wrong_passphrase(
        message in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        prop_assert!(
            wallet.sign(WRONG_PASSPHRASE, &message).is_err(),
            "wallet signing must reject the wrong passphrase"
        );
    }

    // 06/25
    #[test]
    fn test_006_wallet_secret_key_hex_roundtrip_recovers_same_address(_case in any::<u8>()) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let secret_hex = wallet
            .secret_key_hex(PRIMARY_PASSPHRASE)
            .expect("secret export should succeed with correct passphrase");

        prop_assert_eq!(
            secret_hex.len(),
            ml_dsa_65::SK_LEN * 2,
            "secret key hex must encode exactly the ML-DSA-65 secret key bytes"
        );

        let secret_bytes = hex::decode(&secret_hex)
            .expect("exported secret hex should decode");

        prop_assert_eq!(
            secret_bytes.len(),
            ml_dsa_65::SK_LEN,
            "decoded secret bytes must have ML-DSA-65 secret-key length"
        );

        let recovered_address = MLDSA65Wallet::address_from_secret_bytes(&secret_bytes)
            .expect("address recovery from exported secret bytes should succeed");

        prop_assert_eq!(
            recovered_address.as_str(),
            wallet.address.as_str(),
            "address recovered from secret bytes must match wallet address"
        );
    }

    // 07/25
    #[test]
    fn test_007_wallet_from_parts_preserves_address_and_can_sign(
        message in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let restored = MLDSA65Wallet::from_parts(
            wallet.public,
            wallet.encrypted_secret.clone(),
        )
        .expect("wallet restoration from public bytes and encrypted secret should succeed");

        prop_assert_eq!(
            &restored.address,
            &wallet.address,
            "wallet restored from parts must derive the same address"
        );

        prop_assert!(
            restored.validate_self().is_ok(),
            "restored wallet must satisfy wallet invariants"
        );

        let signature = restored
            .sign(PRIMARY_PASSPHRASE, &message)
            .expect("restored wallet should sign with correct passphrase");

        prop_assert!(
            restored.verify(&message, &signature),
            "restored wallet must verify its own signature"
        );
    }

    // 08/25
    #[test]
    fn test_008_wallet_verify_rejects_wrong_signature_lengths(
        message in proptest::collection::vec(any::<u8>(), 0..512),
        bad_len in 0usize..6000usize,
        fill in any::<u8>(),
    ) {
        let _guard = wallet_crypto_guard();
        prop_assume!(bad_len != ml_dsa_65::SIG_LEN);

        let wallet = primary_wallet();
        let bad_signature = vec![fill; bad_len];

        prop_assert!(
            !wallet.verify(&message, &bad_signature),
            "wallet verification must reject signature length {bad_len}"
        );
    }

    // 09/25
    #[test]
    fn test_009_wallet_validate_address_format_rejects_short_canonical_like_addresses(
        tail in "[0-9a-f]{0,127}",
    ) {
        let candidate = format!("r{tail}");

        prop_assert!(
            MLDSA65Wallet::validate_address_format(&candidate).is_err(),
            "wallet address validator must reject too-short canonical-like addresses"
        );
    }

    // 10/25
    #[test]
    fn test_010_wallet_public_key_hex_has_exact_length_and_matches_public_bytes(_case in any::<u8>()) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let public_hex = wallet.public_key_hex();
        let expected_public_hex = hex::encode(wallet.public);

        prop_assert_eq!(
            public_hex.len(),
            ml_dsa_65::PK_LEN * 2,
            "public key hex must encode exactly the ML-DSA-65 public key bytes"
        );

        prop_assert_eq!(
            public_hex.as_str(),
            expected_public_hex.as_str(),
            "public_key_hex must be lowercase hex of wallet.public"
        );

        let decoded = hex::decode(&public_hex)
            .expect("public key hex should decode");

        prop_assert_eq!(
            decoded.as_slice(),
            wallet.public.as_slice(),
            "decoded public hex must recover exact public key bytes"
        );
    }

    // 11/25
    #[test]
    fn test_011_wallet_generate_address_from_public_matches_wallet_address(_case in any::<u8>()) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let derived = MLDSA65Wallet::generate_address(&wallet.public)
            .expect("address generation from wallet public key should succeed");

        prop_assert_eq!(
            derived.as_str(),
            wallet.address.as_str(),
            "address generated from wallet public bytes must match stored wallet address"
        );

        prop_assert!(
            MLDSA65Wallet::validate_address_format(&derived).is_ok(),
            "derived address must have valid canonical format"
        );
    }

    // 12/25
    #[test]
    fn test_012_wallet_validate_address_format_accepts_generated_addresses(_case in any::<u8>()) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        prop_assert!(
            MLDSA65Wallet::validate_address_format(&wallet.address).is_ok(),
            "validator must accept addresses generated by the wallet implementation"
        );

        prop_assert!(
            wallet.address.chars().skip(1).all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "wallet address body must be lowercase hexadecimal"
        );
    }

    // 13/25
    #[test]
    fn test_013_wallet_validate_address_format_rejects_wrong_prefix(
        body in "[0-9a-f]{128}",
        wrong_prefix in "[A-QS-Za-qs-z0-9]",
    ) {
        prop_assume!(wrong_prefix != "r");

        let candidate = format!("{wrong_prefix}{body}");

        prop_assert!(
            MLDSA65Wallet::validate_address_format(&candidate).is_err(),
            "wallet address validator must reject addresses that do not start with canonical 'r'"
        );
    }

    // 14/25
    #[test]
    fn test_014_wallet_validate_address_format_rejects_non_hex_body_character(
        prefix_body in "[0-9a-f]{0,127}",
        suffix_body in "[0-9a-f]{0,127}",
        bad_char in "[g-zG-Z!@#%+=.,:/-]",
    ) {
        let mut body = String::with_capacity(128);
        body.push_str(&prefix_body);
        body.push_str(&bad_char);
        body.push_str(&suffix_body);

        while body.len() < 128 {
            body.push('0');
        }

        body.truncate(128);

        let candidate = format!("r{body}");

        prop_assert!(
            MLDSA65Wallet::validate_address_format(&candidate).is_err(),
            "wallet address validator must reject non-hex characters in the address body"
        );
    }

    // 15/25
    #[test]
    fn test_015_wallet_validate_address_format_rejects_too_long_addresses(
        body in "[0-9a-f]{129,160}",
    ) {
        let candidate = format!("r{body}");

        prop_assert!(
            MLDSA65Wallet::validate_address_format(&candidate).is_err(),
            "wallet address validator must reject addresses longer than 129 characters"
        );
    }

    // 16/25
    #[test]
    fn test_016_wallet_address_from_secret_bytes_rejects_wrong_secret_lengths(
        len in 0usize..5000usize,
        fill in any::<u8>(),
    ) {
        prop_assume!(len != ml_dsa_65::SK_LEN);

        let secret = vec![fill; len];

        prop_assert!(
            MLDSA65Wallet::address_from_secret_bytes(&secret).is_err(),
            "address recovery must reject secret length {len}"
        );
    }

    // 17/25
    #[test]
    fn test_017_wallet_secret_key_hex_rejects_wrong_passphrase(_case in any::<u8>()) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        prop_assert!(
            wallet.secret_key_hex(WRONG_PASSPHRASE).is_err(),
            "secret key export must reject the wrong passphrase"
        );
    }

    // 18/25
    #[test]
    fn test_018_wallet_from_parts_rejects_too_small_encrypted_secret(
        len in 0usize..32usize,
        fill in any::<u8>(),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();
        let encrypted_secret = vec![fill; len];

        prop_assert!(
            MLDSA65Wallet::from_parts(wallet.public, encrypted_secret).is_err(),
            "from_parts must reject encrypted secret shorter than wallet minimum"
        );
    }

    // 19/25
    #[test]
    fn test_019_wallet_from_parts_rejects_too_large_encrypted_secret(fill in any::<u8>()) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();
        let encrypted_secret = vec![fill; 64 * 1024 + 1];

        prop_assert!(
            MLDSA65Wallet::from_parts(wallet.public, encrypted_secret).is_err(),
            "from_parts must reject encrypted secret above wallet maximum"
        );
    }

    // 20/25
    #[test]
    fn test_020_wallet_with_tampered_encrypted_secret_cannot_sign(
        message in proptest::collection::vec(any::<u8>(), 0..512),
        byte_index_seed in any::<usize>(),
        delta in 1u8..=255u8,
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();
        let mut tampered_secret = wallet.encrypted_secret.clone();
        prop_assume!(!tampered_secret.is_empty());

        let byte_index = byte_index_seed % tampered_secret.len();
        tampered_secret[byte_index] = tampered_secret[byte_index].wrapping_add(delta);

        let restored = MLDSA65Wallet::from_parts(wallet.public, tampered_secret);

        if let Ok(restored_wallet) = restored {
            prop_assert!(
                restored_wallet.sign(PRIMARY_PASSPHRASE, &message).is_err(),
                "wallet restored with tampered encrypted secret must not sign"
            );
        }
    }

    // 21/25
    #[test]
    fn test_021_wallet_verify_rejects_signature_from_different_wallet(
        message in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let signer_wallet = primary_wallet();
        let verifier_wallet = secondary_wallet();

        prop_assert_ne!(
            signer_wallet.address.as_str(),
            verifier_wallet.address.as_str(),
            "test wallets must be distinct"
        );

        let signature = signer_wallet
            .sign(PRIMARY_PASSPHRASE, &message)
            .expect("signer wallet signing should succeed");

        prop_assert!(
            !verifier_wallet.verify(&message, &signature),
            "wallet verification must reject signatures produced by a different wallet"
        );
    }

    // 22/25
    #[test]
    fn test_022_wallet_signing_same_message_twice_produces_verifiable_exact_length_signatures(
        message in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let signature_a = wallet
            .sign(PRIMARY_PASSPHRASE, &message)
            .expect("first wallet signing should succeed");

        let signature_b = wallet
            .sign(PRIMARY_PASSPHRASE, &message)
            .expect("second wallet signing should succeed");

        prop_assert_eq!(
            signature_a.len(),
            ml_dsa_65::SIG_LEN,
            "first wallet signature must have exact ML-DSA-65 length"
        );

        prop_assert_eq!(
            signature_b.len(),
            ml_dsa_65::SIG_LEN,
            "second wallet signature must have exact ML-DSA-65 length"
        );

        prop_assert!(
            wallet.verify(&message, &signature_a),
            "first signature over same message must verify"
        );

        prop_assert!(
            wallet.verify(&message, &signature_b),
            "second signature over same message must verify"
        );
    }

    // 23/25
    #[test]
    fn test_023_wallet_empty_message_signature_rejects_non_empty_message(
        tail in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();
        let empty_message: Vec<u8> = Vec::new();

        let mut non_empty_message = Vec::with_capacity(tail.len() + 1);
        non_empty_message.push(1u8);
        non_empty_message.extend_from_slice(&tail);

        let signature = wallet
            .sign(PRIMARY_PASSPHRASE, &empty_message)
            .expect("wallet signing of empty message should succeed");

        prop_assert!(
            wallet.verify(&empty_message, &signature),
            "empty-message signature must verify for the empty message"
        );

        prop_assert!(
            !wallet.verify(&non_empty_message, &signature),
            "empty-message signature must not verify for a non-empty message"
        );
    }

    // 24/25
    #[test]
    fn test_024_wallet_sign_never_panics_for_bounded_messages_and_valid_passphrase(
        message in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wallet.sign(PRIMARY_PASSPHRASE, &message)
        }));

        prop_assert!(
            result.is_ok(),
            "wallet sign must never panic for bounded messages and valid passphrase"
        );

        prop_assert!(
            result.expect("panic was already checked").is_ok(),
            "wallet sign should succeed for bounded messages and valid passphrase"
        );
    }

    // 25/25
    #[test]
    fn test_025_wallet_verify_never_panics_for_arbitrary_external_signature_bytes(
        message in proptest::collection::vec(any::<u8>(), 0..512),
        signature_bytes in proptest::collection::vec(any::<u8>(), 0..6000),
    ) {
        let _guard = wallet_crypto_guard();
        let wallet = primary_wallet();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wallet.verify(&message, &signature_bytes)
        }));

        prop_assert!(
            result.is_ok(),
            "wallet verify must never panic for arbitrary external signature bytes"
        );
    }
}
