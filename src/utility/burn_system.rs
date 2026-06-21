//! ML-DSA-65 Burn Wallet (ML-DSA-authentic address + best-effort secret destruction)

use crate::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    wallet_id_matches_pubkey_bytes_checked,
};
use fips204::ml_dsa_65;
use fips204::traits::SerDes;
use zeroize::{Zeroize, Zeroizing};

/// Public-only burn wallet material safe to embed in genesis/config.
#[derive(Clone)]
pub struct MLDSABurnWallet {
    /// ML-DSA-65 public key bytes (public)
    pub public: [u8; ml_dsa_65::PK_LEN],
    /// Remzar address: "r" + 128 lowercase hex characters (129 chars total)
    pub address: String,
}

// Prevent accidental verbose logging in case someone does `{:?}` on this type.
// Public key isn't secret, but this reduces risk of operational mistakes.
impl core::fmt::Debug for MLDSABurnWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MLDSABurnWallet")
            .field("public", &"[PUBLIC_KEY_PRESENT]")
            .field("address", &self.address)
            .finish()
    }
}

/// Burn wallet utilities.
///
/// IMPORTANT:
/// - There is intentionally NO method here to sign.
/// - There is intentionally NO method here to retrieve secrets.
/// - Generation is best done ONCE (offline), then you store only {public,address}.
pub struct BurnWalletMLDSA65;

impl BurnWalletMLDSA65 {
    // ─────────────────────────────────────────────────────────────────────────
    // Address computation (must match canonical wallet rule)
    // ─────────────────────────────────────────────────────────────────────────

    /// Compute the canonical Remzar address from ML-DSA-65 public key bytes.
    /// Format: "r" + 128 lowercase hex characters from BLAKE3-XOF-64(pubkey_bytes).
    #[inline]
    pub fn address_from_public_key_bytes(public_key_bytes: &[u8; ml_dsa_65::PK_LEN]) -> String {
        derive_wallet_id_from_pubkey_bytes(public_key_bytes.as_slice())
    }

    /// Validate string format only (not public-key binding).
    pub fn validate_remzar_address_format(address: &str) -> Result<(), ErrorDetection> {
        // Canonicalize + validate per helper.rs:
        // - trims
        // - accepts 'r' or 'R'
        // - requires REMZAR_WALLET_LEN (129)
        // - requires 128 lowercase hex after 'r'
        let _ = canon_wallet_id_checked(address)?;

        // Defensive: ensure it canonicalizes to the expected length.
        // (canon_wallet_id_checked already enforces length; this is just belt-and-suspenders.)
        if address.trim().len() != REMZAR_WALLET_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid address length (expected {}): {}",
                    REMZAR_WALLET_LEN,
                    address.trim().len()
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Strong check: confirms address matches the given ML-DSA-65 public key bytes under rule.
    pub fn validate_address_matches_public_bytes(
        address: &str,
        public_key_bytes: &[u8; ml_dsa_65::PK_LEN],
    ) -> Result<(), ErrorDetection> {
        // Defensive: ensure the public key bytes parse as a valid ML-DSA-65 public key.
        let _ = ml_dsa_65::PublicKey::try_from_bytes(*public_key_bytes).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Invalid ML-DSA-65 public key bytes: {e}"),
                tx_id: None,
            }
        })?;

        // Single source-of-truth check:
        // - canonicalize address
        // - derive expected id from pubkey bytes
        // - ensure they match
        let _canon = wallet_id_matches_pubkey_bytes_checked(address, public_key_bytes.as_slice())?;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Robust “generate and destroy” burn wallet creation
    // ─────────────────────────────────────────────────────────────────────────

    /// Generates a brand-new ML-DSA-65 burn wallet and destroys secret material immediately.
    ///
    /// This returns ONLY public key bytes + address.
    ///
    /// Defensive measures:
    /// - secret bytes are copied into a Zeroizing wrapper and wiped
    /// - we explicitly drop the keypair ASAP so its Drop runs (wiping internal secret_bytes)
    ///
    /// Operational advice:
    /// - Run this ONCE offline (or at install-time), record {public,address} into genesis config,
    ///   and never call it again in production.
    pub fn generate_and_destroy_secret() -> Result<MLDSABurnWallet, ErrorDetection> {
        // Generate using your secure RNG path.
        let keypair = MlDsa65Keypair::generate()?;

        // Derive public + address while keypair still exists.
        let verifying_key = keypair.get_verifying_key()?;
        let public_bytes: [u8; ml_dsa_65::PK_LEN] = verifying_key.into_bytes();
        let address = Self::address_from_public_key_bytes(&public_bytes);

        // Defense-in-depth:
        // Create a temporary copy of secret bytes and wipe it deterministically.
        // (This doesn't replace wiping the internal secret; it reduces exposure further.)
        let mut secret_copy: Zeroizing<[u8; ml_dsa_65::SK_LEN]> =
            Zeroizing::new(keypair.to_bytes());
        secret_copy.zeroize(); // explicit wipe (also wiped again on drop)

        // Now force-drop keypair ASAP so its Drop wipes internal secret_bytes immediately.
        drop(keypair);

        // Validate our own output defensively (format + binding).
        Self::validate_address_matches_public_bytes(&address, &public_bytes)?;

        Ok(MLDSABurnWallet {
            public: public_bytes,
            address,
        })
    }

    /// Build a burn wallet from stored ML-DSA-65 public key bytes (1952 bytes).
    ///
    /// Use this in production after you’ve generated burn wallet OFFLINE.
    /// This avoids ever generating secrets in production.
    pub fn from_public_bytes(
        public_bytes: &[u8; ml_dsa_65::PK_LEN],
    ) -> Result<MLDSABurnWallet, ErrorDetection> {
        // Defensive: ensure the public key bytes parse.
        let _ = ml_dsa_65::PublicKey::try_from_bytes(*public_bytes).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Invalid ML-DSA-65 public key bytes for burn wallet: {e}"),
                tx_id: None,
            }
        })?;

        let address = Self::address_from_public_key_bytes(public_bytes);
        Self::validate_address_matches_public_bytes(&address, public_bytes)?;

        Ok(MLDSABurnWallet {
            public: *public_bytes,
            address,
        })
    }

    /// Helper: check whether an address equals this burn wallet.
    #[inline]
    pub fn is_burn_address(addr: &str, burn: &MLDSABurnWallet) -> bool {
        addr == burn.address
    }
}
