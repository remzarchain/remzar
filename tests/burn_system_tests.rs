use fips204::ml_dsa_65;
use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::burn_system::{BurnWalletMLDSA65, MLDSABurnWallet};
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    wallet_id_matches_pubkey_bytes_checked,
};
use std::sync::{Mutex, OnceLock};

type TestResult = Result<(), String>;

fn burn_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn run_serial<F>(f: F) -> TestResult
where
    F: FnOnce() -> TestResult,
{
    let _guard = burn_test_lock()
        .lock()
        .map_err(|_| "burn test serialization lock poisoned".to_string())?;

    f()
}

fn generated_public_bytes() -> Result<[u8; ml_dsa_65::PK_LEN], String> {
    let keypair =
        MlDsa65Keypair::generate().map_err(|e| format!("keypair generate failed: {e:?}"))?;
    Ok(keypair.public_key_bytes())
}

fn generated_burn_wallet() -> Result<MLDSABurnWallet, String> {
    let public = generated_public_bytes()?;
    BurnWalletMLDSA65::from_public_bytes(&public)
        .map_err(|e| format!("from_public_bytes failed: {e:?}"))
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

fn mutate_last_hex_char(address: &str) -> Result<String, String> {
    let mut chars = address.chars().collect::<Vec<_>>();
    let last = chars
        .last_mut()
        .ok_or_else(|| "address unexpectedly empty".to_string())?;

    *last = if *last == 'a' { 'b' } else { 'a' };

    Ok(chars.into_iter().collect())
}

fn assert_canonical_address_shape(address: &str) {
    assert_eq!(address.len(), REMZAR_WALLET_LEN);
    assert!(address.starts_with('r'));
    assert!(
        address.as_bytes()[1..]
            .iter()
            .all(|b| { matches!(b, b'0'..=b'9' | b'a'..=b'f') })
    );
}

#[test]
fn burn_wallet_001_wallet_length_constant_matches_burn_address_rule() -> TestResult {
    run_serial(|| {
        assert_eq!(REMZAR_WALLET_LEN, 129);
        assert_eq!(REMZAR_WALLET_LEN, 1 + 128);
        Ok(())
    })
}

#[test]
fn burn_wallet_002_address_from_public_key_has_canonical_shape() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

        assert_canonical_address_shape(&address);
        Ok(())
    })
}

#[test]
fn burn_wallet_003_address_from_public_key_matches_helper_derivation() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;

        let burn_address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);
        let helper_address = derive_wallet_id_from_pubkey_bytes(public.as_slice());

        assert_eq!(burn_address, helper_address);
        Ok(())
    })
}

#[test]
fn burn_wallet_004_address_derivation_is_deterministic_for_same_public_key() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;

        let first = BurnWalletMLDSA65::address_from_public_key_bytes(&public);
        let second = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

        assert_eq!(first, second);
        Ok(())
    })
}

#[test]
fn burn_wallet_005_different_public_keys_produce_different_addresses_vector() -> TestResult {
    run_serial(|| {
        let first_public = generated_public_bytes()?;
        let second_public = generated_public_bytes()?;

        let first = BurnWalletMLDSA65::address_from_public_key_bytes(&first_public);
        let second = BurnWalletMLDSA65::address_from_public_key_bytes(&second_public);

        assert_ne!(first_public, second_public);
        assert_ne!(first, second);
        Ok(())
    })
}

#[test]
fn burn_wallet_006_from_public_bytes_returns_public_and_derived_address() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let burn = BurnWalletMLDSA65::from_public_bytes(&public)
            .map_err(|e| format!("from_public_bytes failed: {e:?}"))?;

        assert_eq!(burn.public, public);
        assert_eq!(
            burn.address,
            BurnWalletMLDSA65::address_from_public_key_bytes(&public)
        );
        assert_canonical_address_shape(&burn.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_007_from_public_bytes_address_matches_helper_binding() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let burn = BurnWalletMLDSA65::from_public_bytes(&public)
            .map_err(|e| format!("from_public_bytes failed: {e:?}"))?;

        let canonical =
            wallet_id_matches_pubkey_bytes_checked(&burn.address, burn.public.as_slice())
                .map_err(|e| format!("helper binding check failed: {e:?}"))?;

        assert_eq!(canonical, burn.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_008_generate_and_destroy_secret_returns_valid_public_only_wallet() -> TestResult {
    run_serial(|| {
        let burn = BurnWalletMLDSA65::generate_and_destroy_secret()
            .map_err(|e| format!("generate_and_destroy_secret failed: {e:?}"))?;

        assert_canonical_address_shape(&burn.address);
        assert_eq!(
            burn.address,
            BurnWalletMLDSA65::address_from_public_key_bytes(&burn.public)
        );
        Ok(())
    })
}

#[test]
fn burn_wallet_009_generate_and_destroy_secret_wallet_validates_against_public_key() -> TestResult {
    run_serial(|| {
        let burn = BurnWalletMLDSA65::generate_and_destroy_secret()
            .map_err(|e| format!("generate_and_destroy_secret failed: {e:?}"))?;

        BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
            .map_err(|e| format!("validate generated burn wallet failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_010_generated_wallets_are_unique_vector() -> TestResult {
    run_serial(|| {
        let first = BurnWalletMLDSA65::generate_and_destroy_secret()
            .map_err(|e| format!("first burn generation failed: {e:?}"))?;
        let second = BurnWalletMLDSA65::generate_and_destroy_secret()
            .map_err(|e| format!("second burn generation failed: {e:?}"))?;

        assert_ne!(first.public, second.public);
        assert_ne!(first.address, second.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_011_validate_remzar_address_format_accepts_canonical_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        BurnWalletMLDSA65::validate_remzar_address_format(&burn.address)
            .map_err(|e| format!("validate address format failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_012_validate_remzar_address_format_accepts_trimmed_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let padded = format!(" \n\t{} \t\n", burn.address);

        BurnWalletMLDSA65::validate_remzar_address_format(&padded)
            .map_err(|e| format!("validate trimmed address failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_013_validate_remzar_address_format_accepts_uppercase_prefix_and_body() -> TestResult
{
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let uppercase = burn.address.to_ascii_uppercase();

        BurnWalletMLDSA65::validate_remzar_address_format(&uppercase)
            .map_err(|e| format!("validate uppercase address failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_014_validate_remzar_address_format_rejects_empty_address() -> TestResult {
    run_serial(|| {
        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(""))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_015_validate_remzar_address_format_rejects_whitespace_address() -> TestResult {
    run_serial(|| {
        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(" \n\t "))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_016_validate_remzar_address_format_rejects_short_address() -> TestResult {
    run_serial(|| {
        let short = format!("r{}", "a".repeat(127));

        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&short))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_017_validate_remzar_address_format_rejects_long_address() -> TestResult {
    run_serial(|| {
        let long = format!("r{}", "a".repeat(129));

        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&long))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_018_validate_remzar_address_format_rejects_wrong_prefix() -> TestResult {
    run_serial(|| {
        let wrong_prefix = format!("x{}", "a".repeat(128));

        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(
            &wrong_prefix,
        ))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_019_validate_remzar_address_format_rejects_non_hex_body() -> TestResult {
    run_serial(|| {
        let bad = format!("r{}g", "a".repeat(127));

        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_020_validate_remzar_address_format_rejects_internal_space() -> TestResult {
    run_serial(|| {
        let bad = format!("r{} {}", "a".repeat(63), "b".repeat(64));

        assert_eq!(bad.len(), REMZAR_WALLET_LEN);
        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_021_validate_address_matches_public_bytes_accepts_canonical_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
            .map_err(|e| format!("validate canonical binding failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_022_validate_address_matches_public_bytes_accepts_trimmed_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let padded = format!(" \n{} \t", burn.address);

        BurnWalletMLDSA65::validate_address_matches_public_bytes(&padded, &burn.public)
            .map_err(|e| format!("validate trimmed binding failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_023_validate_address_matches_public_bytes_accepts_uppercase_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let uppercase = burn.address.to_ascii_uppercase();

        BurnWalletMLDSA65::validate_address_matches_public_bytes(&uppercase, &burn.public)
            .map_err(|e| format!("validate uppercase binding failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_024_validate_address_matches_public_bytes_rejects_mutated_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mutated = mutate_last_hex_char(&burn.address)?;

        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &mutated,
            &burn.public,
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_025_validate_address_matches_public_bytes_rejects_wrong_public_key() -> TestResult {
    run_serial(|| {
        let first = generated_burn_wallet()?;
        let second = generated_burn_wallet()?;

        assert_ne!(first.public, second.public);
        assert_ne!(first.address, second.address);

        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &first.address,
            &second.public,
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_026_validate_address_matches_public_bytes_rejects_format_invalid_address()
-> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let bad = "not-a-wallet";

        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            bad, &public,
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_027_is_burn_address_true_for_exact_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        assert!(BurnWalletMLDSA65::is_burn_address(&burn.address, &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_028_is_burn_address_false_for_uppercase_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let uppercase = burn.address.to_ascii_uppercase();

        assert!(!BurnWalletMLDSA65::is_burn_address(&uppercase, &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_029_is_burn_address_false_for_trimmed_input_with_spaces() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let padded = format!(" {} ", burn.address);

        assert!(!BurnWalletMLDSA65::is_burn_address(&padded, &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_030_is_burn_address_false_for_different_valid_burn_wallet() -> TestResult {
    run_serial(|| {
        let first = generated_burn_wallet()?;
        let second = generated_burn_wallet()?;

        assert!(!BurnWalletMLDSA65::is_burn_address(&first.address, &second));
        Ok(())
    })
}

#[test]
fn burn_wallet_031_debug_redacts_public_key_bytes_and_shows_placeholder() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let rendered = format!("{burn:?}");
        let public_hex = hex::encode(burn.public);

        assert!(rendered.contains("MLDSABurnWallet"));
        assert!(rendered.contains("[PUBLIC_KEY_PRESENT]"));
        assert!(rendered.contains(&burn.address));
        assert!(!rendered.contains(&public_hex));
        Ok(())
    })
}

#[test]
fn burn_wallet_032_clone_preserves_public_and_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let cloned = burn.clone();

        assert_eq!(cloned.public, burn.public);
        assert_eq!(cloned.address, burn.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_033_address_body_is_exactly_128_lowercase_hex_chars() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let body = burn
            .address
            .get(1..)
            .ok_or_else(|| "missing address body".to_string())?;

        assert_eq!(body.len(), 128);
        assert!(body.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        Ok(())
    })
}

#[test]
fn burn_wallet_034_address_from_public_key_is_accepted_by_canon_wallet_helper() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

        let canonical =
            canon_wallet_id_checked(&address).map_err(|e| format!("canon helper failed: {e:?}"))?;

        assert_eq!(canonical, address);
        Ok(())
    })
}

#[test]
fn burn_wallet_035_uppercase_address_canonicalizes_to_burn_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let uppercase = burn.address.to_ascii_uppercase();

        let canonical = canon_wallet_id_checked(&uppercase)
            .map_err(|e| format!("canon uppercase failed: {e:?}"))?;

        assert_eq!(canonical, burn.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_036_helper_wallet_match_returns_canonical_burn_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        let canonical =
            wallet_id_matches_pubkey_bytes_checked(&burn.address, burn.public.as_slice())
                .map_err(|e| format!("wallet helper match failed: {e:?}"))?;

        assert_eq!(canonical, burn.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_037_helper_wallet_match_rejects_mutated_burn_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mutated = mutate_last_hex_char(&burn.address)?;

        assert_validation_error(wallet_id_matches_pubkey_bytes_checked(
            &mutated,
            burn.public.as_slice(),
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_038_address_generation_property_many_public_keys_are_valid_and_unique() -> TestResult
{
    run_serial(|| {
        let mut addresses = std::collections::BTreeSet::new();

        for _ in 0..16 {
            let public = generated_public_bytes()?;
            let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

            assert_canonical_address_shape(&address);
            assert!(addresses.insert(address));
        }

        assert_eq!(addresses.len(), 16);
        Ok(())
    })
}

#[test]
fn burn_wallet_039_from_public_bytes_property_many_outputs_validate() -> TestResult {
    run_serial(|| {
        for _ in 0..10 {
            let public = generated_public_bytes()?;
            let burn = BurnWalletMLDSA65::from_public_bytes(&public)
                .map_err(|e| format!("from_public_bytes property failed: {e:?}"))?;

            assert_eq!(burn.public, public);
            BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
                .map_err(|e| format!("property validate binding failed: {e:?}"))?;
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_040_generate_and_destroy_secret_property_many_outputs_validate() -> TestResult {
    run_serial(|| {
        let mut addresses = std::collections::BTreeSet::new();

        for _ in 0..8 {
            let burn = BurnWalletMLDSA65::generate_and_destroy_secret()
                .map_err(|e| format!("generate property failed: {e:?}"))?;

            assert_canonical_address_shape(&burn.address);
            BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
                .map_err(|e| format!("validate generated property failed: {e:?}"))?;
            assert!(addresses.insert(burn.address));
        }

        assert_eq!(addresses.len(), 8);
        Ok(())
    })
}

#[test]
fn burn_wallet_041_address_from_zero_public_bytes_is_canonical_shape() -> TestResult {
    run_serial(|| {
        let public = [0_u8; ml_dsa_65::PK_LEN];
        let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

        assert_canonical_address_shape(&address);
        assert_eq!(
            address,
            derive_wallet_id_from_pubkey_bytes(public.as_slice())
        );
        Ok(())
    })
}

#[test]
fn burn_wallet_042_address_from_max_public_bytes_is_canonical_shape() -> TestResult {
    run_serial(|| {
        let public = [0xFF_u8; ml_dsa_65::PK_LEN];
        let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

        assert_canonical_address_shape(&address);
        assert_eq!(
            address,
            derive_wallet_id_from_pubkey_bytes(public.as_slice())
        );
        Ok(())
    })
}

#[test]
fn burn_wallet_043_address_from_pattern_public_bytes_is_deterministic() -> TestResult {
    run_serial(|| {
        let mut public = [0_u8; ml_dsa_65::PK_LEN];

        for (index, slot) in public.iter_mut().enumerate() {
            *slot = u8::try_from(index % 251).unwrap_or(0);
        }

        let first = BurnWalletMLDSA65::address_from_public_key_bytes(&public);
        let second = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

        assert_eq!(first, second);
        assert_canonical_address_shape(&first);
        Ok(())
    })
}

#[test]
fn burn_wallet_044_address_from_public_key_changes_when_first_byte_changes() -> TestResult {
    run_serial(|| {
        let first = [0_u8; ml_dsa_65::PK_LEN];
        let mut second = [0_u8; ml_dsa_65::PK_LEN];

        second[0] = 1;

        let first_addr = BurnWalletMLDSA65::address_from_public_key_bytes(&first);
        let second_addr = BurnWalletMLDSA65::address_from_public_key_bytes(&second);

        assert_ne!(first, second);
        assert_ne!(first_addr, second_addr);
        Ok(())
    })
}

#[test]
fn burn_wallet_045_address_from_public_key_changes_when_last_byte_changes() -> TestResult {
    run_serial(|| {
        let first = [0_u8; ml_dsa_65::PK_LEN];
        let mut second = [0_u8; ml_dsa_65::PK_LEN];

        let last_index = ml_dsa_65::PK_LEN.saturating_sub(1);
        second[last_index] = 1;

        let first_addr = BurnWalletMLDSA65::address_from_public_key_bytes(&first);
        let second_addr = BurnWalletMLDSA65::address_from_public_key_bytes(&second);

        assert_ne!(first_addr, second_addr);
        Ok(())
    })
}

#[test]
fn burn_wallet_046_address_from_public_key_changes_when_middle_byte_changes() -> TestResult {
    run_serial(|| {
        let first = [0_u8; ml_dsa_65::PK_LEN];
        let mut second = [0_u8; ml_dsa_65::PK_LEN];

        second[ml_dsa_65::PK_LEN / 2] = 1;

        let first_addr = BurnWalletMLDSA65::address_from_public_key_bytes(&first);
        let second_addr = BurnWalletMLDSA65::address_from_public_key_bytes(&second);

        assert_ne!(first_addr, second_addr);
        Ok(())
    })
}

#[test]
fn burn_wallet_047_validate_format_accepts_uppercase_body_with_lowercase_prefix() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mixed = format!(
            "r{}",
            burn.address
                .get(1..)
                .ok_or_else(|| "missing address body".to_string())?
                .to_ascii_uppercase()
        );

        BurnWalletMLDSA65::validate_remzar_address_format(&mixed)
            .map_err(|e| format!("validate uppercase body failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_048_validate_format_accepts_uppercase_prefix_with_lowercase_body() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mixed = format!(
            "R{}",
            burn.address
                .get(1..)
                .ok_or_else(|| "missing address body".to_string())?
        );

        BurnWalletMLDSA65::validate_remzar_address_format(&mixed)
            .map_err(|e| format!("validate uppercase prefix failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_049_validate_format_rejects_body_with_newline() -> TestResult {
    run_serial(|| {
        let bad = format!("r{}{}", "a".repeat(63), "\n".repeat(65));

        assert_eq!(bad.len(), REMZAR_WALLET_LEN);
        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_050_validate_format_rejects_body_with_tab() -> TestResult {
    run_serial(|| {
        let bad = format!("r{}{}{}", "a".repeat(64), "\t", "b".repeat(63));

        assert_eq!(bad.len(), REMZAR_WALLET_LEN);
        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_051_validate_format_rejects_body_with_nul() -> TestResult {
    run_serial(|| {
        let bad = format!("r{}{}{}", "a".repeat(64), "\0", "b".repeat(63));

        assert_eq!(bad.len(), REMZAR_WALLET_LEN);
        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_052_validate_format_rejects_unicode_body_character() -> TestResult {
    run_serial(|| {
        let bad = format!("r{}鎖{}", "a".repeat(63), "b".repeat(64));

        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_053_validate_format_rejects_missing_prefix_with_128_hex_chars() -> TestResult {
    run_serial(|| {
        let bad = "a".repeat(128);

        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_054_validate_format_rejects_prefix_only_with_128_non_hex_chars() -> TestResult {
    run_serial(|| {
        let bad = format!("r{}", "z".repeat(128));

        assert_eq!(bad.len(), REMZAR_WALLET_LEN);
        assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_055_validate_binding_rejects_address_with_valid_shape_but_wrong_hash() -> TestResult
{
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let wrong = format!("r{}", "0".repeat(128));

        assert_canonical_address_shape(&wrong);
        assert_ne!(wrong, burn.address);

        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &wrong,
            &burn.public,
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_056_validate_binding_accepts_helper_derived_address() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let helper_address = derive_wallet_id_from_pubkey_bytes(public.as_slice());

        BurnWalletMLDSA65::validate_address_matches_public_bytes(&helper_address, &public)
            .map_err(|e| format!("binding validation failed for helper-derived address: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_057_validate_binding_accepts_canonicalized_uppercase_helper_address() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let helper_address = derive_wallet_id_from_pubkey_bytes(public.as_slice());
        let uppercase = helper_address.to_ascii_uppercase();

        BurnWalletMLDSA65::validate_address_matches_public_bytes(&uppercase, &public).map_err(
            |e| format!("binding validation failed for uppercase helper address: {e:?}"),
        )?;

        Ok(())
    })
}

#[test]
fn burn_wallet_058_from_public_bytes_roundtrip_through_address_validator() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;
        let burn = BurnWalletMLDSA65::from_public_bytes(&public)
            .map_err(|e| format!("from_public_bytes failed: {e:?}"))?;

        BurnWalletMLDSA65::validate_remzar_address_format(&burn.address)
            .map_err(|e| format!("format validation failed: {e:?}"))?;
        BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
            .map_err(|e| format!("binding validation failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_059_from_public_bytes_repeated_same_public_bytes_same_output() -> TestResult {
    run_serial(|| {
        let public = generated_public_bytes()?;

        let first = BurnWalletMLDSA65::from_public_bytes(&public)
            .map_err(|e| format!("first from_public_bytes failed: {e:?}"))?;
        let second = BurnWalletMLDSA65::from_public_bytes(&public)
            .map_err(|e| format!("second from_public_bytes failed: {e:?}"))?;

        assert_eq!(first.public, second.public);
        assert_eq!(first.address, second.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_060_generated_public_bytes_can_rebuild_same_burn_wallet() -> TestResult {
    run_serial(|| {
        let generated = BurnWalletMLDSA65::generate_and_destroy_secret()
            .map_err(|e| format!("generate_and_destroy_secret failed: {e:?}"))?;
        let rebuilt = BurnWalletMLDSA65::from_public_bytes(&generated.public)
            .map_err(|e| format!("from_public_bytes rebuild failed: {e:?}"))?;

        assert_eq!(rebuilt.public, generated.public);
        assert_eq!(rebuilt.address, generated.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_061_is_burn_address_false_for_mutated_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mutated = mutate_last_hex_char(&burn.address)?;

        assert!(!BurnWalletMLDSA65::is_burn_address(&mutated, &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_062_is_burn_address_false_for_empty_string() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        assert!(!BurnWalletMLDSA65::is_burn_address("", &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_063_is_burn_address_false_for_whitespace_string() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        assert!(!BurnWalletMLDSA65::is_burn_address("   ", &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_064_is_burn_address_false_for_canonical_other_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let other = format!("r{}", "0".repeat(128));

        assert!(!BurnWalletMLDSA65::is_burn_address(&other, &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_065_debug_output_is_stable_for_clone() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let cloned = burn.clone();

        assert_eq!(format!("{burn:?}"), format!("{cloned:?}"));
        Ok(())
    })
}

#[test]
fn burn_wallet_066_debug_output_does_not_include_raw_public_prefix_hex() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let rendered = format!("{burn:?}");
        let public_hex = hex::encode(burn.public);
        let public_prefix = public_hex
            .get(..32)
            .ok_or_else(|| "missing public hex prefix".to_string())?;

        assert!(!rendered.contains(public_prefix));
        assert!(rendered.contains("[PUBLIC_KEY_PRESENT]"));
        Ok(())
    })
}

#[test]
fn burn_wallet_067_clone_debug_redaction_still_applies() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let cloned = burn.clone();
        let rendered = format!("{cloned:?}");

        assert!(rendered.contains("[PUBLIC_KEY_PRESENT]"));
        assert!(rendered.contains(&cloned.address));
        assert!(!rendered.contains(&hex::encode(cloned.public)));
        Ok(())
    })
}

#[test]
fn burn_wallet_068_public_key_length_matches_mldsa_constant() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        assert_eq!(burn.public.len(), ml_dsa_65::PK_LEN);
        assert_eq!(ml_dsa_65::PK_LEN, MlDsa65Keypair::PUBLIC_LEN);
        Ok(())
    })
}

#[test]
fn burn_wallet_069_address_length_matches_helper_constant_for_generated_wallets() -> TestResult {
    run_serial(|| {
        for _ in 0..8 {
            let burn = generated_burn_wallet()?;

            assert_eq!(burn.address.len(), REMZAR_WALLET_LEN);
            assert_canonical_address_shape(&burn.address);
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_070_canon_wallet_helper_accepts_generated_address_with_boundary_whitespace()
-> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let padded = format!("\n\t{} \r\n", burn.address);

        let canonical =
            canon_wallet_id_checked(&padded).map_err(|e| format!("canon padded failed: {e:?}"))?;

        assert_eq!(canonical, burn.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_071_canon_wallet_helper_rejects_generated_address_with_internal_whitespace()
-> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mut chars = burn.address.chars().collect::<Vec<_>>();

        chars[64] = ' ';
        let bad = chars.into_iter().collect::<String>();

        assert_validation_error(canon_wallet_id_checked(&bad))?;
        Ok(())
    })
}

#[test]
fn burn_wallet_072_address_from_public_key_property_artificial_vectors_are_canonical() -> TestResult
{
    run_serial(|| {
        for seed in 0_u8..16_u8 {
            let mut public = [0_u8; ml_dsa_65::PK_LEN];

            for (index, slot) in public.iter_mut().enumerate() {
                let idx = u8::try_from(index % 251).unwrap_or(0);
                *slot = seed.wrapping_add(idx);
            }

            let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);
            assert_canonical_address_shape(&address);
            assert_eq!(
                address,
                derive_wallet_id_from_pubkey_bytes(public.as_slice())
            );
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_073_address_from_public_key_property_artificial_vectors_are_unique() -> TestResult {
    run_serial(|| {
        let mut addresses = std::collections::BTreeSet::new();

        for seed in 0_u8..16_u8 {
            let public = [seed; ml_dsa_65::PK_LEN];
            let address = BurnWalletMLDSA65::address_from_public_key_bytes(&public);

            assert!(addresses.insert(address));
        }

        assert_eq!(addresses.len(), 16);
        Ok(())
    })
}

#[test]
fn burn_wallet_074_validate_format_property_hex_digit_variants_are_accepted() -> TestResult {
    run_serial(|| {
        for digit in ['0', '1', '9', 'a', 'b', 'f', 'A', 'B', 'F'] {
            let address = format!("r{}", digit.to_string().repeat(128));

            BurnWalletMLDSA65::validate_remzar_address_format(&address)
                .map_err(|e| format!("hex digit {digit} should validate: {e:?}"))?;
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_075_validate_format_property_non_hex_digit_variants_are_rejected() -> TestResult {
    run_serial(|| {
        for ch in ['g', 'G', 'z', 'Z', '-', '_', ':', '/', '@'] {
            let address = format!("r{}{}", "a".repeat(127), ch);

            assert_eq!(address.len(), REMZAR_WALLET_LEN);
            assert_validation_error(BurnWalletMLDSA65::validate_remzar_address_format(&address))?;
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_076_validate_binding_rejects_each_single_char_mutation_sample() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        for index in [1_usize, 2, 64, 128] {
            let mut chars = burn.address.chars().collect::<Vec<_>>();
            let current = chars
                .get(index)
                .copied()
                .ok_or_else(|| format!("missing char at {index}"))?;
            chars[index] = if current == 'a' { 'b' } else { 'a' };

            let mutated = chars.into_iter().collect::<String>();

            assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
                &mutated,
                &burn.public,
            ))?;
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_077_generate_and_destroy_secret_load_test_32_unique_addresses() -> TestResult {
    run_serial(|| {
        let mut addresses = std::collections::BTreeSet::new();

        for _ in 0..32 {
            let burn = BurnWalletMLDSA65::generate_and_destroy_secret()
                .map_err(|e| format!("generate load test failed: {e:?}"))?;

            assert_canonical_address_shape(&burn.address);
            assert!(addresses.insert(burn.address));
        }

        assert_eq!(addresses.len(), 32);
        Ok(())
    })
}

#[test]
fn burn_wallet_078_from_public_bytes_load_test_32_generated_keys() -> TestResult {
    run_serial(|| {
        for _ in 0..32 {
            let public = generated_public_bytes()?;
            let burn = BurnWalletMLDSA65::from_public_bytes(&public)
                .map_err(|e| format!("from_public_bytes load test failed: {e:?}"))?;

            assert_eq!(burn.public, public);
            assert_eq!(
                burn.address,
                BurnWalletMLDSA65::address_from_public_key_bytes(&public)
            );
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_079_validate_binding_load_test_many_generated_wallets() -> TestResult {
    run_serial(|| {
        for _ in 0..24 {
            let burn = generated_burn_wallet()?;

            BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
                .map_err(|e| format!("binding load validate failed: {e:?}"))?;
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_080_debug_load_test_never_leaks_public_hex() -> TestResult {
    run_serial(|| {
        for _ in 0..16 {
            let burn = generated_burn_wallet()?;
            let rendered = format!("{burn:?}");
            let public_hex = hex::encode(burn.public);

            assert!(rendered.contains("[PUBLIC_KEY_PRESENT]"));
            assert!(rendered.contains(&burn.address));
            assert!(!rendered.contains(&public_hex));
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_081_address_has_no_ascii_whitespace_or_control_chars() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        assert!(!burn.address.chars().any(char::is_whitespace));
        assert!(!burn.address.chars().any(char::is_control));
        assert_canonical_address_shape(&burn.address);
        Ok(())
    })
}

#[test]
fn burn_wallet_082_address_body_contains_only_ascii_hex_not_unicode() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let body = burn
            .address
            .get(1..)
            .ok_or_else(|| "missing address body".to_string())?;

        assert!(body.is_ascii());
        assert!(body.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        Ok(())
    })
}

#[test]
fn burn_wallet_083_validate_format_accepts_all_zero_address_shape() -> TestResult {
    run_serial(|| {
        let address = format!("r{}", "0".repeat(128));

        BurnWalletMLDSA65::validate_remzar_address_format(&address)
            .map_err(|e| format!("all-zero shaped address failed format validation: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_084_validate_format_accepts_all_f_address_shape() -> TestResult {
    run_serial(|| {
        let address = format!("r{}", "f".repeat(128));

        BurnWalletMLDSA65::validate_remzar_address_format(&address)
            .map_err(|e| format!("all-f shaped address failed format validation: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_085_validate_format_accepts_mixed_case_hex_shape() -> TestResult {
    run_serial(|| {
        let mixed_body = "AaBbCcDdEeFf0123456789"
            .repeat(5)
            .chars()
            .chain("AaBbCcDdEeFf012345".chars())
            .collect::<String>();
        let address = format!("R{mixed_body}");

        assert_eq!(mixed_body.len(), 128);
        assert_eq!(address.len(), REMZAR_WALLET_LEN);

        BurnWalletMLDSA65::validate_remzar_address_format(&address)
            .map_err(|e| format!("mixed-case hex address failed format validation: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_086_canon_helper_lowercases_mixed_case_hex_shape() -> TestResult {
    run_serial(|| {
        let mixed_body = "AaBbCcDdEeFf0123456789"
            .repeat(5)
            .chars()
            .chain("AaBbCcDdEeFf012345".chars())
            .collect::<String>();
        let address = format!("R{mixed_body}");

        assert_eq!(mixed_body.len(), 128);
        assert_eq!(address.len(), REMZAR_WALLET_LEN);

        let canonical = canon_wallet_id_checked(&address)
            .map_err(|e| format!("canon mixed-case failed: {e:?}"))?;

        assert_eq!(canonical, address.to_ascii_lowercase());
        assert_canonical_address_shape(&canonical);
        Ok(())
    })
}

#[test]
fn burn_wallet_087_validate_binding_rejects_wrong_prefix_even_with_correct_body() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let body = burn
            .address
            .get(1..)
            .ok_or_else(|| "missing address body".to_string())?;
        let wrong_prefix = format!("x{body}");

        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &wrong_prefix,
            &burn.public,
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_088_validate_binding_accepts_lowercase_after_roundtrip_canonicalization()
-> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let uppercase = burn.address.to_ascii_uppercase();
        let canonical = canon_wallet_id_checked(&uppercase)
            .map_err(|e| format!("canon uppercase failed: {e:?}"))?;

        assert_eq!(canonical, burn.address);
        BurnWalletMLDSA65::validate_address_matches_public_bytes(&canonical, &burn.public)
            .map_err(|e| format!("validate canonicalized binding failed: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_089_validate_binding_rejects_all_zero_valid_shape_for_generated_public() -> TestResult
{
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let zero_address = format!("r{}", "0".repeat(128));

        assert_ne!(zero_address, burn.address);
        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &zero_address,
            &burn.public,
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_090_validate_binding_rejects_all_f_valid_shape_for_generated_public() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let f_address = format!("r{}", "f".repeat(128));

        assert_ne!(f_address, burn.address);
        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &f_address,
            &burn.public,
        ))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_091_is_burn_address_is_exact_string_match_only() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let canonicalized_upper = canon_wallet_id_checked(&burn.address.to_ascii_uppercase())
            .map_err(|e| format!("canon uppercase failed: {e:?}"))?;

        assert!(BurnWalletMLDSA65::is_burn_address(&burn.address, &burn));
        assert!(BurnWalletMLDSA65::is_burn_address(
            &canonicalized_upper,
            &burn
        ));
        assert!(!BurnWalletMLDSA65::is_burn_address(
            &burn.address.to_ascii_uppercase(),
            &burn
        ));
        Ok(())
    })
}

#[test]
fn burn_wallet_092_clone_mutated_address_does_not_affect_original() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mut cloned = burn.clone();

        cloned.address = mutate_last_hex_char(&cloned.address)?;

        assert_ne!(cloned.address, burn.address);
        assert!(BurnWalletMLDSA65::is_burn_address(&burn.address, &burn));
        assert!(!BurnWalletMLDSA65::is_burn_address(&cloned.address, &burn));
        Ok(())
    })
}

#[test]
fn burn_wallet_093_clone_mutated_public_no_longer_matches_original_address() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let mut cloned = burn.clone();

        cloned.public[0] ^= 0x01;

        assert_validation_error(BurnWalletMLDSA65::validate_address_matches_public_bytes(
            &burn.address,
            &cloned.public,
        ))?;

        BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
            .map_err(|e| format!("original binding failed after clone mutation: {e:?}"))?;

        Ok(())
    })
}

#[test]
fn burn_wallet_094_debug_output_contains_address_once_and_no_secret_words() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let rendered = format!("{burn:?}");

        assert_eq!(rendered.matches(&burn.address).count(), 1);
        assert!(!rendered.to_ascii_lowercase().contains("secret"));
        assert!(!rendered.to_ascii_lowercase().contains("private"));
        Ok(())
    })
}

#[test]
fn burn_wallet_095_debug_output_is_short_and_operationally_safe() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;
        let rendered = format!("{burn:?}");

        assert!(rendered.len() < 256);
        assert!(rendered.contains("public"));
        assert!(rendered.contains("address"));
        assert!(rendered.contains("[PUBLIC_KEY_PRESENT]"));
        Ok(())
    })
}

#[test]
fn burn_wallet_096_rebuilt_wallet_debug_matches_generated_wallet_debug() -> TestResult {
    run_serial(|| {
        let generated = BurnWalletMLDSA65::generate_and_destroy_secret()
            .map_err(|e| format!("generate_and_destroy_secret failed: {e:?}"))?;
        let rebuilt = BurnWalletMLDSA65::from_public_bytes(&generated.public)
            .map_err(|e| format!("from_public_bytes rebuild failed: {e:?}"))?;

        assert_eq!(format!("{generated:?}"), format!("{rebuilt:?}"));
        Ok(())
    })
}

#[test]
fn burn_wallet_097_repeated_validate_format_on_same_address_is_stable() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        for _ in 0..100 {
            BurnWalletMLDSA65::validate_remzar_address_format(&burn.address)
                .map_err(|e| format!("repeated format validation failed: {e:?}"))?;
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_098_repeated_validate_binding_on_same_wallet_is_stable() -> TestResult {
    run_serial(|| {
        let burn = generated_burn_wallet()?;

        for _ in 0..100 {
            BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
                .map_err(|e| format!("repeated binding validation failed: {e:?}"))?;
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_099_load_rebuild_many_generated_wallets_from_public_bytes() -> TestResult {
    run_serial(|| {
        for _ in 0..40 {
            let generated = BurnWalletMLDSA65::generate_and_destroy_secret()
                .map_err(|e| format!("generate load rebuild failed: {e:?}"))?;
            let rebuilt = BurnWalletMLDSA65::from_public_bytes(&generated.public)
                .map_err(|e| format!("rebuild load failed: {e:?}"))?;

            assert_eq!(rebuilt.public, generated.public);
            assert_eq!(rebuilt.address, generated.address);
            assert_canonical_address_shape(&rebuilt.address);
        }

        Ok(())
    })
}

#[test]
fn burn_wallet_100_load_generated_addresses_are_valid_unique_and_helper_canonical() -> TestResult {
    run_serial(|| {
        let mut addresses = std::collections::BTreeSet::new();

        for _ in 0..40 {
            let burn = BurnWalletMLDSA65::generate_and_destroy_secret()
                .map_err(|e| format!("generate load unique failed: {e:?}"))?;
            let canonical = canon_wallet_id_checked(&burn.address)
                .map_err(|e| format!("canon failed: {e:?}"))?;

            assert_eq!(canonical, burn.address);
            assert_canonical_address_shape(&burn.address);
            assert!(addresses.insert(burn.address));
        }

        assert_eq!(addresses.len(), 40);
        Ok(())
    })
}
