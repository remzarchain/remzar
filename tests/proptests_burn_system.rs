use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;
use fips204::traits::SerDes;
use remzar::utility::burn_system::{BurnWalletMLDSA65, MLDSABurnWallet};
use std::sync::{Mutex, MutexGuard, OnceLock};

use remzar::utility::helper::{
    REMZAR_WALLET_BODY_LEN, REMZAR_WALLET_LEN, canon_wallet_id_checked,
    derive_wallet_id_from_pubkey_bytes, parse_wallet_address,
};

static BASE_BURN_WALLET: OnceLock<MLDSABurnWallet> = OnceLock::new();
static BURN_PROPTEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn burn_proptest_guard() -> MutexGuard<'static, ()> {
    BURN_PROPTEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cached_burn_wallet() -> MLDSABurnWallet {
    BASE_BURN_WALLET
        .get_or_init(|| {
            BurnWalletMLDSA65::generate_and_destroy_secret()
                .expect("test burn wallet generation should succeed")
        })
        .clone()
}

fn public_bytes_strategy() -> impl Strategy<Value = [u8; ml_dsa_65::PK_LEN]> {
    proptest::collection::vec(any::<u8>(), ml_dsa_65::PK_LEN).prop_map(|bytes| {
        let mut out = [0u8; ml_dsa_65::PK_LEN];
        out.copy_from_slice(&bytes);
        out
    })
}

fn is_lowercase_remzar_hex_address(address: &str) -> bool {
    let bytes = address.as_bytes();

    bytes.len() == REMZAR_WALLET_LEN
        && bytes.first() == Some(&b'r')
        && bytes[1..]
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn flip_wallet_body_hex_char(address: &str, body_index: usize) -> String {
    let mut bytes = address.as_bytes().to_vec();
    let index = 1 + (body_index % REMZAR_WALLET_BODY_LEN);

    bytes[index] = if bytes[index] == b'0' { b'1' } else { b'0' };

    String::from_utf8(bytes).expect("wallet address should remain valid UTF-8")
}

fn replace_wallet_body_with_non_hex(address: &str, body_index: usize, replacement: u8) -> String {
    let mut bytes = address.as_bytes().to_vec();
    let index = 1 + (body_index % REMZAR_WALLET_BODY_LEN);

    bytes[index] = replacement;

    String::from_utf8(bytes).expect("test replacement should remain valid UTF-8")
}

fn wrap_with_ascii_whitespace(value: &str, left_count: usize, right_count: usize) -> String {
    let left = " \t\r\n"
        .chars()
        .cycle()
        .take(left_count)
        .collect::<String>();

    let right = "\n\r\t "
        .chars()
        .cycle()
        .take(right_count)
        .collect::<String>();

    format!("{left}{value}{right}")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 001/25
    #[test]
    fn address_derivation_matches_independent_blake3_xof_64_spec(
        _case in any::<u8>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&burn.public);

        let mut commitment = [0u8; 64];
        hasher.finalize_xof().fill(&mut commitment);

        let expected = format!("r{}", hex::encode(commitment));
        let actual = BurnWalletMLDSA65::address_from_public_key_bytes(&burn.public);

        prop_assert_eq!(
            actual,
            expected,
            "burn address must be r + lowercase hex(BLAKE3-XOF-64(public_key_bytes))"
        );
    }

    // 002/25
    #[test]
    fn address_derivation_is_total_and_canonical_for_any_1952_byte_input(
        public_bytes in public_bytes_strategy(),
    ) {
        let _guard = burn_proptest_guard();

        let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public_bytes);

        prop_assert_eq!(
            address.len(),
            REMZAR_WALLET_LEN,
            "address derivation must always emit exactly 129 ASCII bytes"
        );

        prop_assert!(
            is_lowercase_remzar_hex_address(&address),
            "derived address must always be canonical r + 128 lowercase hex chars"
        );

        prop_assert!(
            parse_wallet_address(&address).is_ok(),
            "derived address must pass strict wallet parser"
        );
    }

    // 003/25
    #[test]
    fn address_derivation_matches_shared_wallet_helper_source_of_truth(
        _case in any::<u16>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        let expected = derive_wallet_id_from_pubkey_bytes(burn.public.as_slice());
        let actual = BurnWalletMLDSA65::address_from_public_key_bytes(&burn.public);

        prop_assert_eq!(
            actual,
            expected,
            "burn address derivation must stay aligned with global wallet-id helper"
        );
    }

    // 004/25
    #[test]
    fn validate_remzar_address_format_accepts_generated_canonical_burn_address(
        _case in any::<u8>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&burn.address).is_ok(),
            "generated burn address must pass format-only validation"
        );

        prop_assert!(
            canon_wallet_id_checked(&burn.address).is_ok(),
            "generated burn address must also pass canonical helper validation"
        );
    }

    // 005/25
    #[test]
    fn validate_remzar_address_format_accepts_uppercase_boundary_input_and_outer_whitespace(
        left_count in 0usize..4usize,
        right_count in 0usize..4usize,
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();
        let uppercase = burn.address.to_ascii_uppercase();
        let wrapped = wrap_with_ascii_whitespace(&uppercase, left_count, right_count);

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&wrapped).is_ok(),
            "format validation should accept trimmed uppercase boundary input"
        );

        let canonical = canon_wallet_id_checked(&wrapped)
            .expect("uppercase wrapped address should canonicalize");

        prop_assert_eq!(
            canonical,
            burn.address,
            "uppercase/whitespace boundary input must canonicalize back to the burn address"
        );
    }

    // 006/25
    #[test]
    fn validate_remzar_address_format_rejects_short_and_overlong_addresses(
        tail in "[0-9a-f]{128}",
        extra in "[0-9a-f]{1,8}",
        left_count in 0usize..4usize,
        right_count in 0usize..4usize,
    ) {
        let _guard = burn_proptest_guard();

        let short = format!("r{}", &tail[..127]);
        let long = format!("r{tail}{extra}");

        let short_wrapped = wrap_with_ascii_whitespace(&short, left_count, right_count);
        let long_wrapped = wrap_with_ascii_whitespace(&long, left_count, right_count);

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&short_wrapped).is_err(),
            "format validation must reject addresses shorter than r + 128 hex chars"
        );

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&long_wrapped).is_err(),
            "format validation must reject addresses longer than r + 128 hex chars"
        );
    }

    // 007/25
    #[test]
    fn validate_remzar_address_format_rejects_wrong_prefix_even_with_valid_hex_body(
        prefix in "[A-QS-Z0-9]{1}",
        tail in "[0-9a-f]{128}",
    ) {
        let _guard = burn_proptest_guard();

        let candidate = format!("{prefix}{tail}");

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&candidate).is_err(),
            "format validation must reject anything other than r/R prefix"
        );
    }

    // 008/25
    #[test]
    fn validate_remzar_address_format_rejects_non_hex_body_bytes(
        tail in "[0-9a-f]{128}",
        body_index in 0usize..REMZAR_WALLET_BODY_LEN,
        bad_char in "[G-Zg-z]{1}",
    ) {
        let _guard = burn_proptest_guard();

        let candidate = format!("r{tail}");
        let bad = replace_wallet_body_with_non_hex(
            &candidate,
            body_index,
            bad_char.as_bytes()[0],
        );

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&bad).is_err(),
            "format validation must reject non-hex body characters"
        );
    }

    // 009/25
    #[test]
    fn validate_remzar_address_format_rejects_unicode_length_spoofing(
        before_count in 0usize..=127usize,
    ) {
        let _guard = burn_proptest_guard();

        let after_count = 127usize - before_count;

        let spoof = format!(
            "r{}é{}",
            "a".repeat(before_count),
            "b".repeat(after_count),
        );

        prop_assert_eq!(
            spoof.chars().count(),
            REMZAR_WALLET_LEN,
            "test input intentionally has 129 chars"
        );

        prop_assert!(
            spoof.len() > REMZAR_WALLET_LEN,
            "test input intentionally exceeds 129 bytes because é is multibyte"
        );

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&spoof).is_err(),
            "format validation must reject Unicode byte-length spoofing"
        );
    }

    // 010/25
    #[test]
    fn validate_address_matches_public_bytes_accepts_exact_generated_binding(
        _case in any::<u8>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        prop_assert!(
            BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &burn.address,
                &burn.public,
            ).is_ok(),
            "strong validation must accept generated address/public binding"
        );
    }

    // 011/25
    #[test]
    fn validate_address_matches_public_bytes_accepts_canonicalizable_matching_address(
        left_count in 0usize..4usize,
        right_count in 0usize..4usize,
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        let uppercase = burn.address.to_ascii_uppercase();
        let wrapped = wrap_with_ascii_whitespace(&uppercase, left_count, right_count);

        prop_assert!(
            BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &wrapped,
                &burn.public,
            ).is_ok(),
            "strong validation should canonicalize boundary address before binding check"
        );
    }

    // 012/25
    #[test]
    fn format_only_validation_can_pass_while_strong_public_binding_fails(
        body_index in 0usize..REMZAR_WALLET_BODY_LEN,
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();
        let tampered = flip_wallet_body_hex_char(&burn.address, body_index);

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&tampered).is_ok(),
            "tampered address should still have valid address syntax"
        );

        prop_assert!(
            BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &tampered,
                &burn.public,
            ).is_err(),
            "strong validation must reject valid-shape address with wrong public-key commitment"
        );
    }

    // 013/25
    #[test]
    fn validate_address_matches_public_bytes_rejects_mutated_public_key_for_original_address(
        public_index in 0usize..ml_dsa_65::PK_LEN,
        delta in 1u8..=u8::MAX,
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();
        let mut mutated_public = burn.public;

        mutated_public[public_index] ^= delta;

        prop_assert!(
            BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &burn.address,
                &mutated_public,
            ).is_err(),
            "strong validation must reject original address when public bytes are changed"
        );
    }

    // 014/25
    #[test]
    fn validate_address_matches_public_bytes_rejects_malformed_address_even_with_valid_public_key(
        body_index in 0usize..REMZAR_WALLET_BODY_LEN,
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();
        let malformed = replace_wallet_body_with_non_hex(&burn.address, body_index, b'g');

        prop_assert!(
            BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &malformed,
                &burn.public,
            ).is_err(),
            "strong validation must fail closed on malformed address strings"
        );
    }

    // 015/25
    #[test]
    fn validate_address_matches_public_bytes_rejects_invalid_public_key_even_if_address_was_derived_from_it(
        raw_public in public_bytes_strategy(),
    ) {
        let _guard = burn_proptest_guard();

        let address = BurnWalletMLDSA65::address_from_public_key_bytes(&raw_public);

        let public_parses = ml_dsa_65::PublicKey::try_from_bytes(raw_public).is_ok();
        let binding_result = BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &address,
            &raw_public,
        );

        if public_parses {
            prop_assert!(
                binding_result.is_ok(),
                "if arbitrary public bytes parse as ML-DSA-65 public key, matching derived address should validate"
            );
        } else {
            prop_assert!(
                binding_result.is_err(),
                "strong validation must reject non-parseable ML-DSA-65 public bytes even when address commitment matches raw bytes"
            );
        }
    }

    // 016/25
    #[test]
    fn from_public_bytes_reconstructs_exact_public_only_burn_wallet(
        _case in any::<u8>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        let reconstructed = BurnWalletMLDSA65::from_public_bytes(&burn.public)
            .expect("valid generated public key should reconstruct burn wallet");

        prop_assert_eq!(
            reconstructed.public,
            burn.public,
            "from_public_bytes must preserve the exact public key bytes"
        );

        prop_assert_eq!(
            reconstructed.address,
            burn.address,
            "from_public_bytes must derive the same burn address from stored public bytes"
        );
    }

    // 017/25
    #[test]
    fn from_public_bytes_output_passes_format_and_strong_binding_validation(
        _case in any::<u16>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        let reconstructed = BurnWalletMLDSA65::from_public_bytes(&burn.public)
            .expect("valid generated public key should reconstruct burn wallet");

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(
                &reconstructed.address,
            ).is_ok(),
            "reconstructed burn wallet address must pass format validation"
        );

        prop_assert!(
            BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &reconstructed.address,
                &reconstructed.public,
            ).is_ok(),
            "reconstructed burn wallet must be self-bound"
        );
    }

    // 018/25
    #[test]
    fn from_public_bytes_fails_closed_for_arbitrary_public_bytes_that_do_not_parse(
        raw_public in public_bytes_strategy(),
    ) {
        let _guard = burn_proptest_guard();

        let public_parses = ml_dsa_65::PublicKey::try_from_bytes(raw_public).is_ok();
        let result = BurnWalletMLDSA65::from_public_bytes(&raw_public);

        if public_parses {
            let burn = result.expect("parseable ML-DSA-65 public bytes should build a burn wallet");

            prop_assert_eq!(
                burn.public,
                raw_public,
                "from_public_bytes must preserve parseable public bytes"
            );

            prop_assert!(
                BurnWalletMLDSA65::validate_address_matches_public_bytes(
                    &burn.address,
                    &burn.public,
                ).is_ok(),
                "burn wallet built from parseable public bytes must be self-bound"
            );
        } else {
            prop_assert!(
                result.is_err(),
                "from_public_bytes must reject non-parseable ML-DSA-65 public bytes"
            );
        }
    }

    // 019/25
    #[test]
    fn from_public_bytes_with_mutated_public_never_reconstructs_original_burn_identity(
        public_index in 0usize..ml_dsa_65::PK_LEN,
        delta in 1u8..=u8::MAX,
    ) {
        let _guard = burn_proptest_guard();

        let original = cached_burn_wallet();
        let mut mutated_public = original.public;

        mutated_public[public_index] ^= delta;

        match BurnWalletMLDSA65::from_public_bytes(&mutated_public) {
            Ok(mutated_burn) => {
                prop_assert!(
                    mutated_burn.public != original.public,
                    "mutated public wallet must not preserve original public bytes"
                );

                prop_assert!(
                    mutated_burn.address != original.address,
                    "mutated public wallet must not preserve original burn address"
                );
            }
            Err(_) => {
                prop_assert!(
                    BurnWalletMLDSA65::validate_address_matches_public_bytes(
                        &original.address,
                        &mutated_public,
                    ).is_err(),
                    "if mutated public cannot build a wallet, it also must not validate against original address"
                );
            }
        }
    }

    // 020/25
    #[test]
    fn generate_and_destroy_secret_returns_public_only_wallet_with_valid_self_binding(
        _case in any::<u8>(),
    ) {
        let _guard = burn_proptest_guard();

        let generated = BurnWalletMLDSA65::generate_and_destroy_secret()
            .expect("burn wallet generation should succeed");

        prop_assert!(
            is_lowercase_remzar_hex_address(&generated.address),
            "generated burn wallet must expose a canonical address"
        );

        prop_assert!(
            ml_dsa_65::PublicKey::try_from_bytes(generated.public).is_ok(),
            "generated burn wallet must expose parseable ML-DSA-65 public bytes"
        );

        prop_assert!(
            BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &generated.address,
                &generated.public,
            ).is_ok(),
            "generated burn wallet must validate against its public bytes"
        );
    }

    // 021/25
    #[test]
    fn generate_and_destroy_secret_produces_distinct_burn_wallets_across_calls(
        _case in any::<u8>(),
    ) {
        let _guard = burn_proptest_guard();

        let first = BurnWalletMLDSA65::generate_and_destroy_secret()
            .expect("first burn wallet generation should succeed");

        let second = BurnWalletMLDSA65::generate_and_destroy_secret()
            .expect("second burn wallet generation should succeed");

        prop_assert!(
            first.public != second.public,
            "two independent burn wallet generations must not reuse the same public key"
        );

        prop_assert!(
            first.address != second.address,
            "two independent burn wallet generations must not reuse the same address"
        );
    }

    // 022/25
    #[test]
    fn is_burn_address_accepts_only_exact_stored_address(
        _case in any::<u16>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        prop_assert!(
            BurnWalletMLDSA65::is_burn_address(&burn.address, &burn),
            "exact stored burn address must be recognized"
        );

        let reconstructed = BurnWalletMLDSA65::from_public_bytes(&burn.public)
            .expect("valid generated public key should reconstruct burn wallet");

        prop_assert!(
            BurnWalletMLDSA65::is_burn_address(&reconstructed.address, &burn),
            "same address reconstructed from public bytes must be recognized"
        );
    }

    // 023/25
    #[test]
    fn is_burn_address_does_not_canonicalize_uppercase_or_whitespace_variants(
        left_count in 0usize..4usize,
        right_count in 0usize..4usize,
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();

        let uppercase = burn.address.to_ascii_uppercase();
        let wrapped = wrap_with_ascii_whitespace(&uppercase, left_count, right_count);

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&wrapped).is_ok(),
            "variant should be valid at boundary-format layer"
        );

        prop_assert!(
            !BurnWalletMLDSA65::is_burn_address(&wrapped, &burn),
            "is_burn_address must remain an exact equality check, not a canonicalizing parser"
        );
    }

    // 024/25
    #[test]
    fn is_burn_address_rejects_valid_shape_one_hex_character_tampering(
        body_index in 0usize..REMZAR_WALLET_BODY_LEN,
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();
        let tampered = flip_wallet_body_hex_char(&burn.address, body_index);

        prop_assert!(
            BurnWalletMLDSA65::validate_remzar_address_format(&tampered).is_ok(),
            "tampered address should still be syntactically valid"
        );

        prop_assert!(
            !BurnWalletMLDSA65::is_burn_address(&tampered, &burn),
            "is_burn_address must reject any one-character address tampering"
        );
    }

    // 025/25
    #[test]
    fn mldsa_burn_wallet_clone_and_debug_are_public_safe_and_stable(
        _case in any::<u8>(),
    ) {
        let _guard = burn_proptest_guard();

        let burn = cached_burn_wallet();
        let cloned = burn.clone();

        prop_assert_eq!(
            &cloned.public,
            &burn.public,
            "Clone must preserve public key bytes exactly"
        );

        prop_assert_eq!(
            &cloned.address,
            &burn.address,
            "Clone must preserve burn address exactly"
        );

        let debug = format!("{burn:?}");
        let public_prefix_hex = hex::encode(&burn.public[..16]);

        prop_assert!(
            debug.contains("MLDSABurnWallet"),
            "Debug output should identify the burn wallet type"
        );

        prop_assert!(
            debug.contains("[PUBLIC_KEY_PRESENT]"),
            "Debug output should redact raw public bytes behind a marker"
        );

        prop_assert!(
            debug.contains(burn.address.as_str()),
            "Debug output should include the public burn address"
        );

        prop_assert!(
            !debug.contains(&public_prefix_hex),
            "Debug output must not dump raw public key bytes"
        );

        prop_assert!(
            !debug.to_ascii_lowercase().contains("secret"),
            "public-only burn wallet debug output must not suggest secret material is present"
        );
    }
}
