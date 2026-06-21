//! # MLDSA65Wallet (Remzar Chain Wallet System)
//!
//! - Generates, encrypts, and manages wallets for the Remzar blockchain.
//! - **Wallet address format is now 64-byte consistent**:
//!     - `"r" + 128 lowercase hexadecimal characters`
//!     - derived from `BLAKE3-XOF(64)( ML-DSA-65 public_key_bytes )` (64-byte digest → 128 hex chars)
//!
//! ML-DSA-65 facts (FIPS 204 / `fips204` crate):
//! - secret key bytes: `ml_dsa_65::SK_LEN` (4032 bytes)
//! - public key bytes: `ml_dsa_65::PK_LEN` (1952 bytes)
//! - signature bytes:  `ml_dsa_65::SIG_LEN` (3309 bytes)
//!
//! Storage pattern:
//! - ENCRYPT/STORAGE: encrypt **raw secret bytes** (4032) via Cryption (AES-GCM + Argon2id).
//! - ADDRESS: 64-byte commitment (`r` + 128 hex) from BLAKE3-XOF(64) over pubkey bytes.
//! - PUBLIC KEY: stored as bytes (`[u8; PK_LEN]`) for verification/reconstruction.

use crate::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

// Single source of truth for wallet formatting/derivation/validation
use crate::utility::helper::{
    canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    wallet_id_matches_pubkey_bytes_checked,
};

// Single source of truth for 64-byte BLAKE3-XOF hashing primitives (no local Hasher usage)
use crate::utility::hash_system_remzarhash::RemzarHash;

use fips204::ml_dsa_65;
// - PublicKey try_from_bytes works (SerDes).
// - PrivateKey signing is short-lived and only reached through the hardened
//   MlDsa65Keypair wrapper.
// - PublicKey verify works (Verifier).
use fips204::traits::{SerDes, Signer, Verifier};

use std::panic::{AssertUnwindSafe, catch_unwind};
use tracing::{error, warn};
use zeroize::{Zeroize, Zeroizing};

/// Consensus signing context for ML-DSA.
const CONSENSUS_CTX: &[u8] = b"";
const MAX_ENCRYPTED_SECRET_BYTES_ABSOLUTE: usize = 64 * 1024;
const MIN_ENCRYPTED_SECRET_BYTES_ABSOLUTE: usize = 32;
const MAX_WALLET_ADDRESS_LEN: usize = 129;
const MAX_SIGNATURE_BYTES_ABSOLUTE: usize = ml_dsa_65::SIG_LEN;
const MAX_MESSAGE_BYTES_ABSOLUTE: usize = 16 * 1024 * 1024;

#[inline]
fn maybe_fault(op: &'static str) -> Result<(), ErrorDetection> {
    if std::env::var_os(format!("REMZAR_FAIL_{}", op)).is_some() {
        return Err(ErrorDetection::CryptographicError {
            message: format!("Fault injection triggered at operation: {op}"),
        });
    }

    Ok(())
}

/// Internal helper: compute the canonical Remzar wallet address from raw public key bytes.
#[inline]
fn compute_address_from_public_key_bytes(public_key_bytes: &[u8; ml_dsa_65::PK_LEN]) -> String {
    derive_wallet_id_from_pubkey_bytes(public_key_bytes)
}

/// Fast format-only validator: canonicalizes + validates `"r" + 128 lowercase hex`.
#[inline]
fn validate_address_format_only(address: &str) -> Result<(), ErrorDetection> {
    if address.len() != MAX_WALLET_ADDRESS_LEN {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Wallet address length mismatch: expected {} chars, got {}",
                MAX_WALLET_ADDRESS_LEN,
                address.len()
            ),
            tx_id: None,
        });
    }

    let canonical = canon_wallet_id_checked(address)?;
    if canonical.len() != MAX_WALLET_ADDRESS_LEN {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Canonical wallet address length mismatch: expected {} chars, got {}",
                MAX_WALLET_ADDRESS_LEN,
                canonical.len()
            ),
            tx_id: None,
        });
    }

    Ok(())
}

/// Full validator: checks format AND that it matches the given ML-DSA-65 public key bytes.
fn validate_wallet_address(
    address: &str,
    public_key_bytes: &[u8; ml_dsa_65::PK_LEN],
) -> Result<(), ErrorDetection> {
    validate_address_format_only(address)?;

    // Defensive: ensure pubkey bytes parse as ML-DSA-65 without letting a
    // dependency panic escape wallet loading/validation.
    let public_parse = catch_unwind(AssertUnwindSafe(|| {
        ml_dsa_65::PublicKey::try_from_bytes(*public_key_bytes)
    }));

    match public_parse {
        Ok(Ok(_pk)) => {}
        Ok(Err(e)) => {
            return Err(ErrorDetection::ValidationError {
                message: format!("Invalid ML-DSA-65 public key bytes: {e}"),
                tx_id: None,
            });
        }
        Err(_) => {
            return Err(ErrorDetection::CryptographicError {
                message: "ML-DSA-65 public key parsing panicked during wallet validation"
                    .to_string(),
            });
        }
    }

    // Canonical + binding validation (single source of truth).
    wallet_id_matches_pubkey_bytes_checked(address, public_key_bytes)?;
    Ok(())
}

/// Generates a wallet address from the ML-DSA-65 public key bytes.
///
/// Produces `"r"` + 128 lowercase hex chars (BLAKE3-XOF(64) digest).
fn generate_address(public_key_bytes: &[u8; ml_dsa_65::PK_LEN]) -> Result<String, ErrorDetection> {
    // Derive using helper.rs (no drift).
    let address = compute_address_from_public_key_bytes(public_key_bytes);

    // Validate our own output defensively (format + binding).
    validate_wallet_address(&address, public_key_bytes)?;
    Ok(address)
}

/// ML-DSA-65 Wallet: Key Generator & Cryptographic Tool
#[derive(Clone, Debug)]
pub struct MLDSA65Wallet {
    /// ML-DSA-65 public key bytes (1952 bytes)
    pub public: [u8; ml_dsa_65::PK_LEN],
    /// Wallet address ("r" + 128 lowercase hex)
    pub address: String,
    /// AES-GCM encrypted ML-DSA-65 secret key bytes (4032 bytes plaintext, encrypted)
    pub encrypted_secret: Vec<u8>,
}

impl MLDSA65Wallet {
    // ─────────────────────────────────────────────────────────────────
    // Internal validation / invariants
    // ─────────────────────────────────────────────────────────────────

    #[inline]
    fn validate_encrypted_secret_bounds(encrypted_secret: &[u8]) -> Result<(), ErrorDetection> {
        if encrypted_secret.len() < MIN_ENCRYPTED_SECRET_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Encrypted secret too small: {} bytes < minimum {}",
                    encrypted_secret.len(),
                    MIN_ENCRYPTED_SECRET_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        if encrypted_secret.len() > MAX_ENCRYPTED_SECRET_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Encrypted secret too large: {} bytes > maximum {}",
                    encrypted_secret.len(),
                    MAX_ENCRYPTED_SECRET_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_message_bounds(message: &[u8]) -> Result<(), ErrorDetection> {
        if message.len() > MAX_MESSAGE_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Message too large: {} bytes exceeds maximum {}",
                    message.len(),
                    MAX_MESSAGE_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_signature_len(signature_bytes: &[u8]) -> bool {
        if signature_bytes.len() > MAX_SIGNATURE_BYTES_ABSOLUTE {
            return false;
        }
        signature_bytes.len() == ml_dsa_65::SIG_LEN
    }

    #[inline]
    fn validate_invariants(&self) -> Result<(), ErrorDetection> {
        maybe_fault("WALLET_VALIDATE_PRE")?;

        validate_wallet_address(&self.address, &self.public)?;
        Self::validate_encrypted_secret_bounds(&self.encrypted_secret)?;

        maybe_fault("WALLET_VALIDATE_POST")?;
        Ok(())
    }

    #[inline]
    fn validate_signing_secret_for_wallet(
        &self,
        secret_bytes: &[u8],
    ) -> Result<MlDsa65Keypair, ErrorDetection> {
        if secret_bytes.len() != ml_dsa_65::SK_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "ML-DSA-65 secret key must be {} bytes, got {}",
                    ml_dsa_65::SK_LEN,
                    secret_bytes.len()
                ),
                tx_id: None,
            });
        }

        let mut sk_arr: [u8; ml_dsa_65::SK_LEN] =
            secret_bytes
                .try_into()
                .map_err(|_| ErrorDetection::ValidationError {
                    message: format!(
                        "Failed to convert secret bytes to [u8; {}]",
                        ml_dsa_65::SK_LEN
                    ),
                    tx_id: None,
                })?;

        // IMPORTANT:
        // Do not decode private material through raw fips204 here. Route decrypted
        // private material through the hardened wrapper so wallet signing inherits
        // timeout/fail-fast validation from MlDsa65Keypair.
        let keypair = match MlDsa65Keypair::from_secret(sk_arr) {
            Ok(keypair) => {
                sk_arr.zeroize();
                keypair
            }
            Err(error) => {
                sk_arr.zeroize();
                return Err(error);
            }
        };

        keypair.validate_self()?;

        if keypair.public_bytes_slice() != self.public.as_slice() {
            return Err(ErrorDetection::ValidationError {
                message: "Decrypted secret key does not match this wallet's stored public key."
                    .to_string(),
                tx_id: None,
            });
        }

        let pk_bytes = keypair.public_key_bytes();
        let expected_addr = compute_address_from_public_key_bytes(&pk_bytes);
        if expected_addr != self.address {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Decrypted key does not match wallet address. expected={} got={}",
                    expected_addr, self.address
                ),
                tx_id: None,
            });
        }

        Ok(keypair)
    }

    // ─────────────────────────────────────────────────────────────────
    // Constructors / loaders
    // ─────────────────────────────────────────────────────────────────

    /// Creates a new wallet:
    /// 1) Generates an ML-DSA-65 keypair.
    /// 2) Derives address = "r" + hex(BLAKE3-XOF(64)(pubkey_bytes)).
    /// 3) Encrypts secret key raw bytes using Cryption.
    pub fn new(passphrase: &str) -> Result<Self, ErrorDetection> {
        maybe_fault("WALLET_NEW_PRE")?;

        // 1) Generate keypair
        let keypair = MlDsa65Keypair::generate()?;

        // 2) Public bytes + address
        let public_bytes: [u8; ml_dsa_65::PK_LEN] = keypair.public_key_bytes();
        let address = Self::generate_address(&public_bytes)?;

        // 3) Encrypt secret raw bytes (4032)
        let mut secret_bytes = keypair.to_bytes(); // [u8; 4032]
        let encrypted_secret = Cryption::encrypt_private_key_bytes(&secret_bytes, passphrase)?;

        // 4) Zeroize plaintext secret
        secret_bytes.zeroize();

        let wallet = Self {
            public: public_bytes,
            address,
            encrypted_secret,
        };

        wallet.validate_invariants()?;
        maybe_fault("WALLET_NEW_POST")?;
        Ok(wallet)
    }

    /// Build a wallet struct from known public bytes + encrypted secret bytes.
    /// (Useful later add a “load wallet file” path.)
    pub fn from_parts(
        public: [u8; ml_dsa_65::PK_LEN],
        encrypted_secret: Vec<u8>,
    ) -> Result<Self, ErrorDetection> {
        maybe_fault("WALLET_FROM_PARTS_PRE")?;

        Self::validate_encrypted_secret_bounds(&encrypted_secret)?;
        let address = Self::generate_address(&public)?;

        let wallet = Self {
            public,
            address,
            encrypted_secret,
        };

        wallet.validate_invariants()?;
        maybe_fault("WALLET_FROM_PARTS_POST")?;
        Ok(wallet)
    }

    /// Validates that this wallet's `address` matches its `public` bytes and
    /// that the encrypted secret looks structurally sane.
    pub fn validate_self(&self) -> Result<(), ErrorDetection> {
        self.validate_invariants()
    }

    /// Generate address from ML-DSA-65 public bytes (BLAKE3-XOF(64) digest).
    #[inline]
    pub fn generate_address(
        public_key_bytes: &[u8; ml_dsa_65::PK_LEN],
    ) -> Result<String, ErrorDetection> {
        generate_address(public_key_bytes)
    }

    /// Validate address format only ("r" + 128 lowercase hex).
    #[inline]
    pub fn validate_address_format(address: &str) -> Result<(), ErrorDetection> {
        validate_address_format_only(address)
    }

    /// Hash message using canonical RemzarHash BLAKE3-XOF(64) (64 bytes).
    #[inline]
    fn hash_message(message: &[u8]) -> [u8; 64] {
        RemzarHash::compute_bytes_hash(message)
    }

    // ─────────────────────────────────────────────────────────────────
    // Signing / verification
    // ─────────────────────────────────────────────────────────────────

    /// Signs a message:
    /// - Decrypts secret bytes using Cryption.
    /// - Hashes message (BLAKE3-XOF(64)).
    /// - Signs the 64-byte hash with ML-DSA-65.
    /// - Returns raw signature bytes (3309 bytes).
    pub fn sign(&self, passphrase: &str, message: &[u8]) -> Result<Vec<u8>, ErrorDetection> {
        maybe_fault("WALLET_SIGN_PRE")?;
        self.validate_invariants()?;
        Self::validate_message_bounds(message)?;

        // Decrypt secret bytes (Zeroizing buffer)
        let secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Cryption::decrypt_private_key_bytes(
            &self.encrypted_secret,
            passphrase,
        )?);

        let keypair = self.validate_signing_secret_for_wallet(secret_bytes.as_slice())?;
        let sk = keypair.get_signing_key()?;

        // Sign BLAKE3-XOF(64)(message). The signing key was created via the
        // hardened wrapper above; this catch_unwind only prevents a dependency
        // panic from taking down the live node.
        let hashed = Self::hash_message(message);
        let sig: [u8; ml_dsa_65::SIG_LEN] =
            match catch_unwind(AssertUnwindSafe(|| sk.try_sign(&hashed, CONSENSUS_CTX))) {
                Ok(Ok(sig)) => sig,
                Ok(Err(e)) => {
                    error!("Wallet signing failed: {e}");
                    return Err(ErrorDetection::CryptographicError {
                        message: format!("Signing failed: {e}"),
                    });
                }
                Err(_) => {
                    error!("Wallet signing panicked");
                    return Err(ErrorDetection::CryptographicError {
                        message: "Wallet signing failed safely after signer panic".to_string(),
                    });
                }
            };

        let out = sig.to_vec();
        if out.len() != ml_dsa_65::SIG_LEN {
            error!(
                "Wallet signing produced invalid signature length: expected {}, got {}",
                ml_dsa_65::SIG_LEN,
                out.len()
            );
            return Err(ErrorDetection::CryptographicError {
                message: format!(
                    "Signing produced invalid signature length: expected {}, got {}",
                    ml_dsa_65::SIG_LEN,
                    out.len()
                ),
            });
        }

        maybe_fault("WALLET_SIGN_POST")?;
        Ok(out)
    }

    /// Verifies a raw ML-DSA-65 signature against a message using this wallet's public key.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> bool {
        if self.validate_invariants().is_err() {
            warn!("Wallet verify rejected: wallet invariants failed");
            return false;
        }

        if Self::validate_message_bounds(message).is_err() {
            warn!("Wallet verify rejected: message exceeds wallet maximum");
            return false;
        }

        if !Self::validate_signature_len(signature_bytes) {
            return false;
        }

        let sig_arr: &[u8; ml_dsa_65::SIG_LEN] = match signature_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };

        let pk = match catch_unwind(AssertUnwindSafe(|| {
            ml_dsa_65::PublicKey::try_from_bytes(self.public)
        })) {
            Ok(Ok(pk)) => pk,
            Ok(Err(_)) | Err(_) => return false,
        };

        let hashed = Self::hash_message(message);
        catch_unwind(AssertUnwindSafe(|| {
            pk.verify(&hashed, sig_arr, CONSENSUS_CTX)
        }))
        .unwrap_or(false)
    }

    // ─────────────────────────────────────────────────────────────────
    // DISPLAY / EXPORT HELPERS
    // ─────────────────────────────────────────────────────────────────

    /// Returns the public key as lowercase hex (human-readable).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public)
    }

    /// Decrypts secret bytes and returns lowercase hex (human-readable).
    pub fn secret_key_hex(&self, passphrase: &str) -> Result<String, ErrorDetection> {
        maybe_fault("WALLET_SECRET_EXPORT_PRE")?;
        self.validate_invariants()?;

        let sk: Zeroizing<Vec<u8>> = Zeroizing::new(Cryption::decrypt_private_key_bytes(
            &self.encrypted_secret,
            passphrase,
        )?);

        if sk.len() != ml_dsa_65::SK_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "ML-DSA-65 secret key must be {} bytes, got {}",
                    ml_dsa_65::SK_LEN,
                    sk.len()
                ),
                tx_id: None,
            });
        }

        // Validate that the decrypted secret belongs to this wallet before export.
        let _ = self.validate_signing_secret_for_wallet(sk.as_slice())?;

        let s = hex::encode(sk.as_slice());
        maybe_fault("WALLET_SECRET_EXPORT_POST")?;
        Ok(s)
    }

    /// Recover a Remzar wallet address (“r…” string) from raw ML-DSA-65 secret key bytes.
    pub fn address_from_secret_bytes(secret: &[u8]) -> Result<String, ErrorDetection> {
        maybe_fault("WALLET_ADDRESS_FROM_SECRET_PRE")?;

        if secret.len() != ml_dsa_65::SK_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "ML-DSA-65 secret key must be {} bytes, got {} bytes",
                    ml_dsa_65::SK_LEN,
                    secret.len()
                ),
                tx_id: None,
            });
        }

        let mut sk_arr: [u8; ml_dsa_65::SK_LEN] =
            secret
                .try_into()
                .map_err(|_| ErrorDetection::ValidationError {
                    message: format!(
                        "ML-DSA-65 secret key must be {} bytes (conversion failed)",
                        ml_dsa_65::SK_LEN
                    ),
                    tx_id: None,
                })?;

        // Route secret material through the hardened wrapper. This prevents a
        // malformed imported wallet secret from hitting raw fips204 private-key
        // parsing directly.
        let keypair = match MlDsa65Keypair::from_secret(sk_arr) {
            Ok(keypair) => {
                sk_arr.zeroize();
                keypair
            }
            Err(error) => {
                sk_arr.zeroize();
                warn!(
                    target: "wallet",
                    "Rejected invalid ML-DSA-65 secret key bytes while deriving wallet address: {}",
                    error
                );
                return Err(error);
            }
        };

        keypair.validate_self()?;

        let pk_bytes = keypair.public_key_bytes();
        let addr = compute_address_from_public_key_bytes(&pk_bytes);

        let canonical = canon_wallet_id_checked(&addr)?;

        if canonical != addr {
            return Err(ErrorDetection::ValidationError {
                message: "Derived wallet address is not canonical".to_string(),
                tx_id: None,
            });
        }

        maybe_fault("WALLET_ADDRESS_FROM_SECRET_POST")?;

        Ok(addr)
    }
}
