use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngExt;
use tracing::{error, warn};
use zeroize::Zeroize;

type EncryptedBlobParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// **Cryption: A Cryptographic Utility Module**
pub struct Cryption;

impl Cryption {
    pub const ML_DSA_65_SECRET_BYTES: usize = 4032;
    pub const ML_DSA_65_SECRET_HEX_CHARS: usize = Self::ML_DSA_65_SECRET_BYTES * 2;
    pub const AES256_KEY_BYTES: usize = 32;
    pub const SALT_BYTES: usize = 16;
    pub const NONCE_BYTES: usize = 12;
    pub const GCM_TAG_BYTES: usize = 16;

    /// Minimal encrypted blob size for a hex-encoded ML-DSA secret:
    /// salt (16) + nonce (12) + tag (16) + plaintext (8064) = 8108 bytes.
    pub const MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_HEX: usize = Self::SALT_BYTES
        + Self::NONCE_BYTES
        + Self::GCM_TAG_BYTES
        + Self::ML_DSA_65_SECRET_HEX_CHARS;

    /// Minimal encrypted blob size for raw ML-DSA secret bytes:
    /// salt (16) + nonce (12) + tag (16) + plaintext (4032) = 4076 bytes.
    pub const MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES: usize =
        Self::SALT_BYTES + Self::NONCE_BYTES + Self::GCM_TAG_BYTES + Self::ML_DSA_65_SECRET_BYTES;

    /// Absolute hard caps independent of config.
    pub const MAX_PASSPHRASE_BYTES_ABSOLUTE: usize = 16 * 1024;
    pub const MAX_PLAINTEXT_BYTES_ABSOLUTE: usize = 1024 * 1024; // 1 MiB
    pub const MAX_ENCRYPTED_BLOB_BYTES_ABSOLUTE: usize = 16 * 1024 * 1024; // 16 MiB

    // ─────────────────────────────────────────────────────────────────────────────
    // FAULT INJECTION
    // ─────────────────────────────────────────────────────────────────────────────

    #[inline]
    fn maybe_fault(op: &'static str) -> Result<(), ErrorDetection> {
        if std::env::var_os(format!("REMZAR_FAIL_{}", op)).is_some() {
            return Err(ErrorDetection::EncryptionError {
                message: format!("Fault injection triggered at operation: {op}"),
            });
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // VALIDATION
    // ─────────────────────────────────────────────────────────────────────────────

    #[inline]
    fn validate_configuration() -> Result<(), ErrorDetection> {
        if GlobalConfiguration::SALT_SIZE != Self::SALT_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid configuration: SALT_SIZE must be {}, got {}",
                    Self::SALT_BYTES,
                    GlobalConfiguration::SALT_SIZE
                ),
                tx_id: None,
            });
        }

        if GlobalConfiguration::NONCE_SIZE != Self::NONCE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid configuration: NONCE_SIZE must be {}, got {}",
                    Self::NONCE_BYTES,
                    GlobalConfiguration::NONCE_SIZE
                ),
                tx_id: None,
            });
        }

        if GlobalConfiguration::MAX_PRIVATE_KEY_BYTES == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Invalid configuration: MAX_PRIVATE_KEY_BYTES must be > 0".to_string(),
                tx_id: None,
            });
        }

        if GlobalConfiguration::MAX_PRIVATE_KEY_BYTES > Self::MAX_PLAINTEXT_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid configuration: MAX_PRIVATE_KEY_BYTES={} exceeds absolute cap {}",
                    GlobalConfiguration::MAX_PRIVATE_KEY_BYTES,
                    Self::MAX_PLAINTEXT_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        if GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES
            < Self::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "MAX_ENCRYPTED_BLOB_BYTES={} is too small for ML-DSA-65 secret encryption minimum ({}). Increase MAX_ENCRYPTED_BLOB_BYTES.",
                    GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES,
                    Self::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES
                ),
                tx_id: None,
            });
        }

        if GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES > Self::MAX_ENCRYPTED_BLOB_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid configuration: MAX_ENCRYPTED_BLOB_BYTES={} exceeds absolute cap {}",
                    GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES,
                    Self::MAX_ENCRYPTED_BLOB_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_passphrase(passphrase: &str) -> Result<(), ErrorDetection> {
        if passphrase.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Passphrase cannot be empty.".to_string(),
                tx_id: None,
            });
        }

        // Prevent absurdly large passphrases (cost/log/memory).
        if passphrase.len() > Self::MAX_PASSPHRASE_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: "Passphrase is too large.".to_string(),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Validates plaintext *byte* payload (recommended path).
    #[inline]
    fn validate_private_key_bytes_input(private_key: &[u8]) -> Result<(), ErrorDetection> {
        if private_key.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private key bytes cannot be empty.".to_string(),
                tx_id: None,
            });
        }

        // Roadmap sanity: ensure config can actually support ML-DSA-65 secrets.
        if GlobalConfiguration::MAX_PRIVATE_KEY_BYTES < Self::ML_DSA_65_SECRET_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "MAX_PRIVATE_KEY_BYTES={} is too small for ML-DSA-65 secret bytes ({}). Increase MAX_PRIVATE_KEY_BYTES.",
                    GlobalConfiguration::MAX_PRIVATE_KEY_BYTES,
                    Self::ML_DSA_65_SECRET_BYTES
                ),
                tx_id: None,
            });
        }

        if private_key.len() > GlobalConfiguration::MAX_PRIVATE_KEY_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private key bytes are too large (>{} bytes).",
                    GlobalConfiguration::MAX_PRIVATE_KEY_BYTES
                ),
                tx_id: None,
            });
        }

        if private_key.len() > Self::MAX_PLAINTEXT_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private key bytes exceed absolute cap (>{} bytes).",
                    Self::MAX_PLAINTEXT_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Validates plaintext *string* payload (legacy path, kept intact).
    #[inline]
    fn validate_private_key_string_input(private_key: &str) -> Result<(), ErrorDetection> {
        if private_key.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private key cannot be empty.".to_string(),
                tx_id: None,
            });
        }

        // Ensure config can support hex ML-DSA secret strings.
        if GlobalConfiguration::MAX_PRIVATE_KEY_BYTES < Self::ML_DSA_65_SECRET_HEX_CHARS {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "MAX_PRIVATE_KEY_BYTES={} is too small for hex-encoded ML-DSA-65 secret ({} chars). Increase MAX_PRIVATE_KEY_BYTES.",
                    GlobalConfiguration::MAX_PRIVATE_KEY_BYTES,
                    Self::ML_DSA_65_SECRET_HEX_CHARS
                ),
                tx_id: None,
            });
        }

        if private_key.len() > GlobalConfiguration::MAX_PRIVATE_KEY_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private key is too large (>{} bytes).",
                    GlobalConfiguration::MAX_PRIVATE_KEY_BYTES
                ),
                tx_id: None,
            });
        }

        if private_key.len() > Self::MAX_PLAINTEXT_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private key string exceeds absolute cap (>{} bytes).",
                    Self::MAX_PLAINTEXT_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_encrypted_blob(encrypted_data: &[u8]) -> Result<(), ErrorDetection> {
        let min_len =
            GlobalConfiguration::SALT_SIZE + GlobalConfiguration::NONCE_SIZE + Self::GCM_TAG_BYTES;

        // Must be at least: salt + nonce + GCM tag (16 bytes).
        if encrypted_data.len() < min_len {
            return Err(ErrorDetection::ValidationError {
                message: "Encrypted data is too short".to_string(),
                tx_id: None,
            });
        }

        if encrypted_data.len() > GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Encrypted data is too large (>{} bytes).",
                    GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES
                ),
                tx_id: None,
            });
        }

        if encrypted_data.len() > Self::MAX_ENCRYPTED_BLOB_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Encrypted data exceeds absolute cap (>{} bytes).",
                    Self::MAX_ENCRYPTED_BLOB_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        let rest_len = encrypted_data
            .len()
            .checked_sub(GlobalConfiguration::SALT_SIZE)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Encrypted data layout is malformed".to_string(),
                tx_id: None,
            })?;

        if rest_len < GlobalConfiguration::NONCE_SIZE + Self::GCM_TAG_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: "Encrypted data layout is malformed".to_string(),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn split_encrypted_blob(
        encrypted_data: &[u8],
    ) -> Result<EncryptedBlobParts<'_>, ErrorDetection> {
        Self::validate_encrypted_blob(encrypted_data)?;

        let (salt, rest) = encrypted_data.split_at(GlobalConfiguration::SALT_SIZE);
        let (nonce_bytes, ciphertext) = rest.split_at(GlobalConfiguration::NONCE_SIZE);

        if ciphertext.len() < Self::GCM_TAG_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: "Ciphertext is too short to contain a GCM tag".to_string(),
                tx_id: None,
            });
        }

        Ok((salt, nonce_bytes, ciphertext))
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // BLAKE3 HASH (64-BYTE OUTPUT VIA XOF)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Canonical 64-byte hash output using BLAKE3 XOF.
    #[inline]
    fn blake3_hash64(data: &[u8]) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);
        out
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ARGON2 KEY DERIVATION
    // ─────────────────────────────────────────────────────────────────────────────

    /// Derive an AES-256 key (32 bytes) from passphrase + salt using Argon2id.
    fn derive_key_from_passphrase(
        passphrase: &str,
        salt: &[u8],
    ) -> Result<[u8; 32], ErrorDetection> {
        Self::maybe_fault("CRYPTION_DERIVE_KEY_PRE")?;
        Self::validate_configuration()?;
        Self::validate_passphrase(passphrase)?;

        if salt.len() != GlobalConfiguration::SALT_SIZE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Salt length mismatch: expected {}, got {}",
                    GlobalConfiguration::SALT_SIZE,
                    salt.len()
                ),
                tx_id: None,
            });
        }

        let params = Params::new(
            GlobalConfiguration::ARGON2_MEMORY_KIB,
            GlobalConfiguration::ARGON2_TIME_COST,
            GlobalConfiguration::ARGON2_LANES,
            None,
        )
        .map_err(|e| ErrorDetection::EncryptionError {
            message: format!("Invalid Argon2 parameters: {:?}", e),
        })?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; Self::AES256_KEY_BYTES];
        let result = argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key);

        match result {
            Ok(()) => {
                Self::maybe_fault("CRYPTION_DERIVE_KEY_POST")?;
                Ok(key)
            }
            Err(_) => {
                key.zeroize();
                Err(ErrorDetection::EncryptionError {
                    message: "Key derivation failed (Argon2id)".to_string(),
                })
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ENCRYPT (RECOMMENDED): RAW BYTES
    // ─────────────────────────────────────────────────────────────────────────────

    /// Encrypt arbitrary sensitive bytes using AES-GCM with a user passphrase.
    pub fn encrypt_private_key_bytes(
        private_key_bytes: &[u8],
        passphrase: &str,
    ) -> Result<Vec<u8>, ErrorDetection> {
        Self::maybe_fault("CRYPTION_ENCRYPT_BYTES_PRE")?;
        Self::validate_configuration()?;
        Self::validate_private_key_bytes_input(private_key_bytes)?;
        Self::validate_passphrase(passphrase)?;

        let mut rng = rand::rng();

        // Salt
        let mut salt = [0u8; Self::SALT_BYTES];
        rng.fill(&mut salt);

        // Derive key (AES-256 => 32 bytes)
        let mut key = match Self::derive_key_from_passphrase(passphrase, &salt) {
            Ok(k) => k,
            Err(e) => {
                salt.zeroize();
                return Err(e);
            }
        };

        // Cipher
        let cipher = match Aes256Gcm::new_from_slice(&key) {
            Ok(c) => c,
            Err(e) => {
                key.zeroize();
                salt.zeroize();
                return Err(ErrorDetection::EncryptionError {
                    message: format!("AES-GCM creation failed: {:?}", e),
                });
            }
        };

        // Nonce
        let mut nonce_bytes = [0u8; Self::NONCE_BYTES];
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt
        let ciphertext = match cipher.encrypt(&nonce, private_key_bytes) {
            Ok(c) => c,
            Err(e) => {
                key.zeroize();
                nonce_bytes.zeroize();
                salt.zeroize();
                return Err(ErrorDetection::EncryptionError {
                    message: format!("Encryption failed: {:?}", e),
                });
            }
        };

        // Assemble output
        let capacity = salt
            .len()
            .checked_add(Self::NONCE_BYTES)
            .and_then(|v| v.checked_add(ciphertext.len()))
            .ok_or_else(|| ErrorDetection::EncryptionError {
                message: "Encrypted blob capacity overflow".to_string(),
            })?;

        let mut encrypted_data = Vec::with_capacity(capacity);
        encrypted_data.extend_from_slice(&salt);
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext);

        key.zeroize();
        nonce_bytes.zeroize();
        salt.zeroize();

        Self::validate_encrypted_blob(&encrypted_data)?;
        Self::maybe_fault("CRYPTION_ENCRYPT_BYTES_POST")?;
        Ok(encrypted_data)
    }

    /// Decrypt bytes encrypted via `encrypt_private_key_bytes`.
    pub fn decrypt_private_key_bytes(
        encrypted_data: &[u8],
        passphrase: &str,
    ) -> Result<Vec<u8>, ErrorDetection> {
        Self::maybe_fault("CRYPTION_DECRYPT_BYTES_PRE")?;
        Self::validate_configuration()?;
        Self::validate_passphrase(passphrase)?;

        let (salt, nonce_bytes, ciphertext) = Self::split_encrypted_blob(encrypted_data)?;

        let mut nonce_arr = [0u8; Self::NONCE_BYTES];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = Nonce::from(nonce_arr);

        let mut key = match Self::derive_key_from_passphrase(passphrase, salt) {
            Ok(k) => k,
            Err(e) => {
                nonce_arr.zeroize();
                return Err(e);
            }
        };

        let cipher = match Aes256Gcm::new_from_slice(&key) {
            Ok(c) => c,
            Err(e) => {
                key.zeroize();
                nonce_arr.zeroize();
                return Err(ErrorDetection::EncryptionError {
                    message: format!("AES-GCM creation failed: {:?}", e),
                });
            }
        };

        let mut plaintext = match cipher.decrypt(&nonce, ciphertext) {
            Ok(p) => p,
            Err(e) => {
                key.zeroize();
                nonce_arr.zeroize();
                return Err(ErrorDetection::DecryptionError {
                    message: format!("Decryption failed: {:?}", e),
                });
            }
        };

        // Cap plaintext size.
        if plaintext.len() > GlobalConfiguration::MAX_PRIVATE_KEY_BYTES {
            plaintext.zeroize();
            key.zeroize();
            nonce_arr.zeroize();
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Decrypted plaintext too large (>{} bytes).",
                    GlobalConfiguration::MAX_PRIVATE_KEY_BYTES
                ),
                tx_id: None,
            });
        }

        if plaintext.len() > Self::MAX_PLAINTEXT_BYTES_ABSOLUTE {
            plaintext.zeroize();
            key.zeroize();
            nonce_arr.zeroize();
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Decrypted plaintext exceeds absolute cap (>{} bytes).",
                    Self::MAX_PLAINTEXT_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        if plaintext.is_empty() {
            plaintext.zeroize();
            key.zeroize();
            nonce_arr.zeroize();
            return Err(ErrorDetection::ValidationError {
                message: "Decrypted plaintext is empty".to_string(),
                tx_id: None,
            });
        }

        key.zeroize();
        nonce_arr.zeroize();

        Self::maybe_fault("CRYPTION_DECRYPT_BYTES_POST")?;
        Ok(plaintext)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ENCRYPT / DECRYPT
    // ─────────────────────────────────────────────────────────────────────────────

    /// Encrypts sensitive data provided as a string.
    pub fn encrypt_private_key(
        private_key: &str,
        passphrase: &str,
    ) -> Result<Vec<u8>, ErrorDetection> {
        Self::maybe_fault("CRYPTION_ENCRYPT_STRING_PRE")?;
        Self::validate_private_key_string_input(private_key)?;
        Self::validate_passphrase(passphrase)?;

        // Copy into a zeroizable buffer we control (does not zeroize caller's string).
        let mut buf = private_key.as_bytes().to_vec();
        let result = Self::encrypt_private_key_bytes(&buf, passphrase);

        buf.zeroize();

        if result.is_err() {
            warn!("Cryption::encrypt_private_key failed");
        }

        Self::maybe_fault("CRYPTION_ENCRYPT_STRING_POST")?;
        result
    }

    /// Decrypts into a UTF-8 string.
    pub fn decrypt_private_key(
        encrypted_data: &[u8],
        passphrase: &str,
    ) -> Result<String, ErrorDetection> {
        Self::maybe_fault("CRYPTION_DECRYPT_STRING_PRE")?;

        let mut plaintext = Self::decrypt_private_key_bytes(encrypted_data, passphrase)?;

        // Convert decrypted bytes into UTF-8 string, then zeroize plaintext bytes.
        let s = match std::str::from_utf8(&plaintext) {
            Ok(st) => st.to_owned(),
            Err(e) => {
                plaintext.zeroize();
                error!("Cryption::decrypt_private_key invalid UTF-8: {:?}", e);
                return Err(ErrorDetection::ValidationError {
                    message: format!("Invalid UTF-8 data: {:?}", e),
                    tx_id: None,
                });
            }
        };

        plaintext.zeroize();
        Self::maybe_fault("CRYPTION_DECRYPT_STRING_POST")?;
        Ok(s)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // BLAKE3 CORE HASH (64-BYTE OUTPUT)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Compute the canonical 64-byte core hash for Remzar (BLAKE3-XOF(64)).
    pub fn compute_core_hash(data: &[u8]) -> [u8; 64] {
        Self::blake3_hash64(data)
    }
}
