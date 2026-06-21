//! tests/generate_mldsa65_burn_wallet_tests.rs

#![cfg(test)]

use fips204::ml_dsa_65;
use remzar::utility::burn_system::BurnWalletMLDSA65;
use remzar::utility::helper::REMZAR_WALLET_LEN;

#[test]
fn generate_one_mldsa65_burn_wallet_and_print() {
    // Generate burn wallet (secret exists only transiently; never returned).
    let burn = BurnWalletMLDSA65::generate_and_destroy_secret()
        .expect("burn wallet generation must succeed");

    // Format-only validation: canonical "r" + 128 lowercase hex (129 chars).
    BurnWalletMLDSA65::validate_remzar_address_format(&burn.address)
        .expect("burn address format must be canonical");

    // Strong correctness check: address must match pubkey commitment under Remzar rule.
    BurnWalletMLDSA65::validate_address_matches_public_bytes(&burn.address, &burn.public)
        .expect("burn address must match ML-DSA-65 public key bytes");

    // Defensive invariants.
    assert_eq!(burn.address.len(), REMZAR_WALLET_LEN);
    assert_eq!(burn.public.len(), ml_dsa_65::PK_LEN);

    println!("\n=== Remzar ML-DSA-65 BURN WALLET (PUBLIC ONLY) ===");
    println!("BURN_ADDRESS = {}", burn.address);
    println!(
        "BURN_PUBLIC_BYTES ({} bytes) = {}",
        burn.public.len(),
        hex::encode(burn.public)
    );
    println!("================================================\n");
}
