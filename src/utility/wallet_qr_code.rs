//! src/utility/wallet_qr_code.rs

use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{canon_wallet_id_checked, wallet_id_matches_pubkey_bytes_checked};

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use image::{DynamicImage, ImageFormat, Luma};
use qrcode::{EcLevel, QrCode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Cursor, ErrorKind};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Result object returned after a wallet QR code is generated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QRWalletReceipt {
    /// Canonical wallet address: "r" + 128 lowercase hex chars.
    pub wallet_address: String,

    /// The PNG file written locally.
    pub qr_png_path: PathBuf,

    /// The exact QR payload byte length.
    ///
    /// This should always be 129 for Remzar wallet addresses.
    pub qr_payload_bytes_len: usize,
}

/// Wallet QR generator / verifier.
pub struct QRWallet;

impl QRWallet {
    /// Folder name under the node data directory.
    pub const WALLET_QR_DIR_NAME: &'static str = "qr_code_wallet";

    /// Remzar wallet address:
    /// - 1 byte prefix: "r"
    /// - 128 lowercase hex chars
    pub const WALLET_ADDRESS_LEN: usize = 129;

    /// Defensive wallet-file cap.
    ///
    /// Current encrypted wallet files should be far below this, but the cap
    /// prevents accidental/hostile huge reads.
    pub const MAX_WALLET_FILE_BYTES: u64 = 64 * 1024;

    /// Defensive QR payload cap.
    ///
    /// The real payload is only the wallet address, so this is intentionally tiny.
    pub const MAX_QR_PAYLOAD_BYTES: usize = 256;

    /// Defensive generated PNG cap.
    pub const MAX_QR_PNG_BYTES: usize = 2 * 1024 * 1024;

    /// Passphrase defensive cap.
    ///
    /// This matches the style used by your Digital I.D. receipt code.
    pub const MAX_PASSPHRASE_BYTES: usize = 16 * 1024;

    /// Default QR output size.
    pub const QR_MIN_WIDTH: u32 = 512;
    pub const QR_MIN_HEIGHT: u32 = 512;

    /// Main public API:
    ///
    /// Verifies local ownership of `wallet_address` using `passphrase`, then
    /// writes a PNG QR code whose scan result is ONLY the canonical wallet address.
    pub fn generate_for_owned_wallet(
        opts: &NodeOpts,
        wallet_address: &str,
        passphrase: &str,
    ) -> Result<QRWalletReceipt, ErrorDetection> {
        Self::validate_passphrase(passphrase)?;

        let wallet = Self::load_owned_wallet(opts, wallet_address, passphrase)?;
        Self::write_qr_png_for_verified_wallet(opts, &wallet)
    }

    /// Load and verify that the caller owns the requested wallet address.
    ///
    /// Ownership proof is local passphrase authentication against the wallet file.
    pub fn load_owned_wallet(
        opts: &NodeOpts,
        wallet_address: &str,
        passphrase: &str,
    ) -> Result<MLDSA65Wallet, ErrorDetection> {
        Self::validate_passphrase(passphrase)?;

        let wallet_address = Self::canonical_wallet(wallet_address)?;

        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to initialize directories for wallet QR: {e}"),
            code: None,
            source: None,
        })?;

        directory
            .create_wallets_directory()
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to create/check wallets directory for wallet QR: {e}"),
                code: None,
                source: None,
            })?;

        Self::reject_symlink_dir(&directory.wallets_path, "wallets directory")?;

        let wallet_file = directory
            .wallets_path
            .join(format!("{wallet_address}.wallet"));
        Self::validate_wallet_file_path(&wallet_file)?;

        let encrypted_secret = fs::read(&wallet_file).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to read wallet file for wallet QR at {}: {e}",
                wallet_file.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            Cryption::decrypt_private_key_bytes(&encrypted_secret, passphrase).map_err(|e| {
                ErrorDetection::CryptographicError {
                    message: format!("Wallet QR passphrase verification failed: {e}"),
                }
            })?,
        );

        if secret_bytes.len() != ml_dsa_65::SK_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR decrypted secret has invalid length: expected {}, got {}",
                    ml_dsa_65::SK_LEN,
                    secret_bytes.len()
                ),
                tx_id: None,
            });
        }

        let secret_arr: [u8; ml_dsa_65::SK_LEN] =
            secret_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ErrorDetection::ValidationError {
                    message: format!(
                        "Failed to convert wallet QR secret bytes to [u8; {}]",
                        ml_dsa_65::SK_LEN
                    ),
                    tx_id: None,
                })?;

        let sk = ml_dsa_65::PrivateKey::try_from_bytes(secret_arr).map_err(|e| {
            ErrorDetection::CryptographicError {
                message: format!("Wallet QR secret is not a valid ML-DSA-65 key: {e}"),
            }
        })?;

        let pk = sk.get_public_key();
        let public_bytes = pk.into_bytes();

        let wallet = MLDSA65Wallet::from_parts(public_bytes, encrypted_secret).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Failed to reconstruct wallet for QR authentication: {e}"),
                tx_id: None,
            }
        })?;

        wallet
            .validate_self()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("Wallet QR self-validation failed: {e}"),
                tx_id: None,
            })?;

        let loaded_wallet_address = Self::canonical_wallet(&wallet.address)?;

        if loaded_wallet_address != wallet_address {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR address mismatch: entered {} but loaded wallet is {}",
                    wallet_address, loaded_wallet_address
                ),
                tx_id: None,
            });
        }

        wallet_id_matches_pubkey_bytes_checked(&wallet_address, &wallet.public).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Wallet QR address does not match wallet public key: {e}"),
                tx_id: None,
            }
        })?;

        Ok(wallet)
    }

    /// Write a wallet QR PNG for an already-verified wallet.
    pub fn write_qr_png_for_verified_wallet(
        opts: &NodeOpts,
        wallet: &MLDSA65Wallet,
    ) -> Result<QRWalletReceipt, ErrorDetection> {
        wallet
            .validate_self()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("Wallet QR verified wallet failed self-validation: {e}"),
                tx_id: None,
            })?;

        let wallet_address = Self::canonical_wallet(&wallet.address)?;
        wallet_id_matches_pubkey_bytes_checked(&wallet_address, &wallet.public).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Wallet QR verified wallet/public-key binding failed: {e}"),
                tx_id: None,
            }
        })?;

        let qr_payload = Self::qr_payload(&wallet_address)?;
        let qr_bytes = Self::build_qr_png_bytes_from_payload(&qr_payload)?;

        let qr_dir = Self::wallet_qr_output_dir(opts)?;
        let qr_path = qr_dir.join(Self::wallet_qr_file_name(&wallet_address)?);

        Self::atomic_write_qr_png(&qr_path, &qr_bytes)?;

        Ok(QRWalletReceipt {
            wallet_address,
            qr_png_path: qr_path,
            qr_payload_bytes_len: qr_payload.len(),
        })
    }

    /// Build QR PNG bytes from a wallet address.
    pub fn build_qr_png_bytes(wallet_address: &str) -> Result<Vec<u8>, ErrorDetection> {
        let wallet_address = Self::canonical_wallet(wallet_address)?;
        let qr_payload = Self::qr_payload(&wallet_address)?;
        Self::build_qr_png_bytes_from_payload(&qr_payload)
    }

    /// Return the exact QR scan payload.
    pub fn qr_payload(wallet_address: &str) -> Result<String, ErrorDetection> {
        let wallet_address = Self::canonical_wallet(wallet_address)?;

        if wallet_address.len() != Self::WALLET_ADDRESS_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR payload length mismatch: expected {} bytes, got {}",
                    Self::WALLET_ADDRESS_LEN,
                    wallet_address.len()
                ),
                tx_id: None,
            });
        }

        if wallet_address.len() > Self::MAX_QR_PAYLOAD_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR payload too large: {} bytes > {} bytes",
                    wallet_address.len(),
                    Self::MAX_QR_PAYLOAD_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(wallet_address)
    }

    /// Returns the exact output directory:
    pub fn wallet_qr_output_dir(opts: &NodeOpts) -> Result<PathBuf, ErrorDetection> {
        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to initialize directories for wallet QR output: {e}"),
            code: None,
            source: None,
        })?;

        let base_dir = directory
            .wallets_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(&opts.data_dir));

        Self::reject_symlink_dir(&base_dir, "wallet QR base data directory")?;

        let qr_dir = base_dir.join(Self::WALLET_QR_DIR_NAME);

        if qr_dir.exists() {
            Self::reject_symlink_dir(&qr_dir, "wallet QR directory")?;
        }

        fs::create_dir_all(&qr_dir).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to create wallet QR directory {}: {e}",
                qr_dir.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        Self::reject_symlink_dir(&qr_dir, "wallet QR directory")?;

        Ok(qr_dir)
    }

    fn canonical_wallet(wallet_address: &str) -> Result<String, ErrorDetection> {
        let wallet_address = wallet_address.trim();

        if wallet_address.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet QR address cannot be empty".into(),
                tx_id: None,
            });
        }

        if wallet_address.len() > Self::WALLET_ADDRESS_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR address too long: expected {} chars, got {}",
                    Self::WALLET_ADDRESS_LEN,
                    wallet_address.len()
                ),
                tx_id: None,
            });
        }

        let canonical = canon_wallet_id_checked(wallet_address).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Wallet QR address is invalid or incomplete: {e}"),
                tx_id: None,
            }
        })?;

        if canonical.len() != Self::WALLET_ADDRESS_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Canonical wallet QR address length mismatch: expected {} chars, got {}",
                    Self::WALLET_ADDRESS_LEN,
                    canonical.len()
                ),
                tx_id: None,
            });
        }

        Ok(canonical)
    }

    fn validate_passphrase(passphrase: &str) -> Result<(), ErrorDetection> {
        if passphrase.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet QR passphrase cannot be empty".into(),
                tx_id: None,
            });
        }

        if passphrase.len() > Self::MAX_PASSPHRASE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR passphrase too long: max {} bytes",
                    Self::MAX_PASSPHRASE_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn validate_wallet_file_path(wallet_file: &Path) -> Result<(), ErrorDetection> {
        if let Ok(meta) = fs::symlink_metadata(wallet_file)
            && meta.file_type().is_symlink()
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Refusing to read symlinked wallet file for QR: {}",
                    wallet_file.display()
                ),
                tx_id: None,
            });
        }

        let meta = fs::metadata(wallet_file).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to stat wallet file for QR at {}: {e}",
                wallet_file.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !meta.is_file() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR path is not a regular wallet file: {}",
                    wallet_file.display()
                ),
                tx_id: None,
            });
        }

        if meta.len() == 0 {
            return Err(ErrorDetection::ValidationError {
                message: format!("Wallet QR wallet file is empty: {}", wallet_file.display()),
                tx_id: None,
            });
        }

        if meta.len() > Self::MAX_WALLET_FILE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR wallet file too large: {} bytes > {} bytes",
                    meta.len(),
                    Self::MAX_WALLET_FILE_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn build_qr_png_bytes_from_payload(payload: &str) -> Result<Vec<u8>, ErrorDetection> {
        if payload.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet QR payload cannot be empty".into(),
                tx_id: None,
            });
        }

        if payload.len() > Self::MAX_QR_PAYLOAD_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR payload too large: {} bytes > {} bytes",
                    payload.len(),
                    Self::MAX_QR_PAYLOAD_BYTES
                ),
                tx_id: None,
            });
        }

        let qr =
            QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M).map_err(|e| {
                ErrorDetection::SerializationError {
                    details: format!("build wallet QR code: {e}"),
                }
            })?;

        let qr_image = qr
            .render::<Luma<u8>>()
            .quiet_zone(true)
            .min_dimensions(Self::QR_MIN_WIDTH, Self::QR_MIN_HEIGHT)
            .build();

        let mut cursor = Cursor::new(Vec::new());

        DynamicImage::ImageLuma8(qr_image)
            .write_to(&mut cursor, ImageFormat::Png)
            .map_err(|e| ErrorDetection::SerializationError {
                details: format!("encode wallet QR PNG: {e}"),
            })?;

        let bytes = cursor.into_inner();

        if bytes.len() > Self::MAX_QR_PNG_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR PNG too large: {} bytes > {} bytes",
                    bytes.len(),
                    Self::MAX_QR_PNG_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(bytes)
    }

    fn wallet_qr_file_name(wallet_address: &str) -> Result<String, ErrorDetection> {
        let wallet_address = Self::canonical_wallet(wallet_address)?;

        if !wallet_address
            .chars()
            .all(|c| c == 'r' || c.is_ascii_hexdigit())
        {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet QR filename rejected invalid wallet characters".into(),
                tx_id: None,
            });
        }

        Ok(format!("wallet_{}_qr.png", wallet_address))
    }

    fn atomic_write_qr_png(path: &Path, bytes: &[u8]) -> Result<(), ErrorDetection> {
        if bytes.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet QR PNG bytes cannot be empty".into(),
                tx_id: None,
            });
        }

        if bytes.len() > Self::MAX_QR_PNG_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet QR PNG too large: {} bytes > {} bytes",
                    bytes.len(),
                    Self::MAX_QR_PNG_BYTES
                ),
                tx_id: None,
            });
        }

        if let Some(parent) = path.parent() {
            Self::reject_symlink_dir(parent, "wallet QR output parent directory")?;
        } else {
            return Err(ErrorDetection::ValidationError {
                message: format!("Wallet QR output path has no parent: {}", path.display()),
                tx_id: None,
            });
        }

        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Refusing to overwrite symlinked wallet QR file: {}",
                        path.display()
                    ),
                    tx_id: None,
                });
            }

            if meta.is_dir() {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Wallet QR output path is a directory, not a file: {}",
                        path.display()
                    ),
                    tx_id: None,
                });
            }
        }

        let tmp_path = path.with_extension("png.tmp");

        if let Ok(meta) = fs::symlink_metadata(&tmp_path) {
            if meta.file_type().is_symlink() {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Refusing to use symlinked wallet QR temp file: {}",
                        tmp_path.display()
                    ),
                    tx_id: None,
                });
            }

            if meta.is_dir() {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Wallet QR temp path is a directory, not a file: {}",
                        tmp_path.display()
                    ),
                    tx_id: None,
                });
            }
        }

        if let Err(e) = fs::remove_file(&tmp_path)
            && e.kind() != ErrorKind::NotFound
        {
            return Err(ErrorDetection::IoError {
                message: format!(
                    "Failed to remove stale wallet QR temp file {}: {e}",
                    tmp_path.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            });
        }

        fs::write(&tmp_path, bytes).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to write wallet QR temp file {}: {e}",
                tmp_path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o644)).map_err(|e| {
                ErrorDetection::IoError {
                    message: format!(
                        "Failed to set wallet QR file permissions on {}: {e}",
                        tmp_path.display()
                    ),
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                }
            })?;
        }

        // Replace existing non-symlink regular file.
        if path.exists() {
            fs::remove_file(path).map_err(|e| ErrorDetection::IoError {
                message: format!(
                    "Failed to replace existing wallet QR file {}: {e}",
                    path.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;
        }

        fs::rename(&tmp_path, path).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to finalize wallet QR file (rename {} -> {}): {e}",
                tmp_path.display(),
                path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        Ok(())
    }

    fn reject_symlink_dir(path: &Path, label: &str) -> Result<(), ErrorDetection> {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(ErrorDetection::ValidationError {
                    message: format!("Refusing to use symlinked {label}: {}", path.display()),
                    tx_id: None,
                });
            }

            if !meta.is_dir() {
                return Err(ErrorDetection::ValidationError {
                    message: format!("Expected {label} to be a directory: {}", path.display()),
                    tx_id: None,
                });
            }
        }

        Ok(())
    }
}
