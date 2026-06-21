//! src/privacy/privacy_001_private_receive_wallet.rs

use crate::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::time_policy::TimePolicy;

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Public API facade for private receive wallet creation.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrivateRW;

/// Version marker for this private receive feature.
pub const PRIVATE_RECEIVE_VERSION: u16 = 1;

pub const PRIVATE_RECEIVE_INVOICE_PREFIX: &str = "remzar-private-receive";

/// Subdirectory inside the existing wallets directory for private receive metadata.
pub const PRIVATE_RECEIVE_METADATA_DIR: &str = "private_receive";

/// File extension for encrypted wallet files.
pub const WALLET_FILE_EXT: &str = "wallet";

/// File extension for local private receive metadata records.
pub const PRIVATE_RECEIVE_RECORD_EXT: &str = "prw.json";

/// Hard guard for invoice size.
pub const MAX_PRIVATE_RECEIVE_INVOICE_LEN: usize = 512;

/// Request for creating a one-time private receive wallet.
#[derive(Debug, Clone)]
pub struct PrivateReceiveCreateRequest<'a> {
    /// The user's main Remzar wallet that owns/controls this private receive address locally.
    pub owner_wallet: &'a str,

    /// Passphrase used to encrypt the one-time receive wallet.
    pub passphrase: &'a str,

    /// If true, this module checks that `<owner_wallet>.wallet` exists.
    pub require_owner_wallet_file: bool,
}

/// Same as `PrivateReceiveCreateRequest`, but owns the passphrase so this module can zeroize it.
#[derive(Debug)]
pub struct PrivateReceiveCreateOwnedRequest {
    pub owner_wallet: String,
    pub passphrase: String,
    pub require_owner_wallet_file: bool,
}

/// Receipt returned after creating a private receive wallet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateReceiveWalletReceipt {
    pub version: u16,

    /// Main wallet that locally owns this private receive address.
    pub owner_wallet: String,

    /// Fresh one-time Remzar wallet address.
    pub one_time_wallet: String,

    /// Shareable invoice.
    pub invoice: String,

    /// When this one-time wallet was created.
    pub created_unix_secs: u64,

    /// Where the encrypted one-time wallet secret was saved.
    pub wallet_file_path: String,

    /// Where local metadata was saved.
    pub metadata_file_path: String,
}

/// Disk record saved locally for future wallet index/scanning code.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateReceiveWalletRecord {
    pub version: u16,
    pub kind: String,
    pub owner_wallet: String,
    pub one_time_wallet: String,
    pub invoice: String,
    pub created_unix_secs: u64,
    pub wallet_file_name: String,
}

impl PrivateRW {
    // ─────────────────────────────────────────────────────────────────────
    // Public constructors
    // ─────────────────────────────────────────────────────────────────────

    pub fn new() -> Self {
        Self
    }

    /// Create a one-time private receive wallet using a borrowed passphrase.
    pub fn create_receive_wallet(
        &self,
        opts: &NodeOpts,
        request: PrivateReceiveCreateRequest<'_>,
    ) -> Result<PrivateReceiveWalletReceipt, ErrorDetection> {
        Self::maybe_fault("PRIVATE_RW_CREATE_PRE")?;

        let owner_wallet = Self::canonical_owner_wallet(request.owner_wallet)?;
        Self::validate_passphrase(request.passphrase)?;

        let directory = Self::load_directory(opts)?;
        Self::ensure_wallets_dir(&directory)?;

        if request.require_owner_wallet_file {
            Self::ensure_owner_wallet_file_exists(&directory.wallets_path, &owner_wallet)?;
        }

        let created_unix_secs = TimePolicy::now_unix_secs_runtime()?;

        let one_time_wallet = MLDSA65Wallet::new(request.passphrase).map_err(|e| {
            ErrorDetection::InitializationError {
                message: format!("Failed to generate private receive wallet: {e}"),
            }
        })?;

        one_time_wallet
            .validate_self()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("Generated private receive wallet failed validation: {e}"),
                tx_id: None,
            })?;

        let one_time_address = canon_wallet_id_checked(&one_time_wallet.address)?;

        if one_time_address == owner_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive one-time wallet unexpectedly equals owner wallet".into(),
                tx_id: None,
            });
        }

        let invoice = Self::make_invoice(&one_time_address)?;

        let wallet_file = Self::wallet_file_path(&directory.wallets_path, &one_time_address);
        let metadata_dir = Self::metadata_dir_path(&directory.wallets_path);
        let metadata_file = Self::metadata_file_path(&directory.wallets_path, &one_time_address);

        fs::create_dir_all(&metadata_dir).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to create private receive metadata directory '{}': {e}",
                metadata_dir.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if wallet_file.exists() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Refusing to overwrite existing private receive wallet file: {}",
                    wallet_file.display()
                ),
                tx_id: None,
            });
        }

        if metadata_file.exists() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Refusing to overwrite existing private receive metadata file: {}",
                    metadata_file.display()
                ),
                tx_id: None,
            });
        }

        let record = PrivateReceiveWalletRecord {
            version: PRIVATE_RECEIVE_VERSION,
            kind: "remzar_private_receive_wallet".to_string(),
            owner_wallet: owner_wallet.clone(),
            one_time_wallet: one_time_address.clone(),
            invoice: invoice.clone(),
            created_unix_secs,
            wallet_file_name: Self::wallet_file_name(&one_time_address),
        };

        let record_bytes =
            serde_json::to_vec_pretty(&record).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to serialize private receive wallet record: {e}"),
            })?;

        // 1) Write encrypted wallet file first.
        Self::atomic_write_new_private_file(&wallet_file, &one_time_wallet.encrypted_secret)?;

        // 2) Write metadata record. If this fails, clean up wallet file.
        if let Err(e) = Self::atomic_write_new_private_file(&metadata_file, &record_bytes) {
            drop(fs::remove_file(&wallet_file));
            return Err(e);
        }

        let receipt = PrivateReceiveWalletReceipt {
            version: PRIVATE_RECEIVE_VERSION,
            owner_wallet,
            one_time_wallet: one_time_address,
            invoice,
            created_unix_secs,
            wallet_file_path: wallet_file.display().to_string(),
            metadata_file_path: metadata_file.display().to_string(),
        };

        Self::validate_receipt(&receipt)?;

        Self::maybe_fault("PRIVATE_RW_CREATE_POST")?;
        Ok(receipt)
    }

    /// Create a one-time private receive wallet and zeroize the owned passphrase.
    pub fn create_receive_wallet_owned(
        &self,
        opts: &NodeOpts,
        mut request: PrivateReceiveCreateOwnedRequest,
    ) -> Result<PrivateReceiveWalletReceipt, ErrorDetection> {
        let result = self.create_receive_wallet(
            opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &request.owner_wallet,
                passphrase: &request.passphrase,
                require_owner_wallet_file: request.require_owner_wallet_file,
            },
        );

        request.passphrase.zeroize();
        result
    }

    // ─────────────────────────────────────────────────────────────────────
    // Invoice helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Build a private receive invoice from a one-time wallet address.
    pub fn make_invoice(one_time_wallet: &str) -> Result<String, ErrorDetection> {
        let one_time_wallet = canon_wallet_id_checked(one_time_wallet)?;
        let invoice = format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, one_time_wallet
        );

        if invoice.len() > MAX_PRIVATE_RECEIVE_INVOICE_LEN {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice exceeds maximum allowed length".into(),
                tx_id: None,
            });
        }

        Ok(invoice)
    }

    /// Parse a private receive invoice and return the one-time Remzar wallet address.
    pub fn parse_invoice_or_address(input: &str) -> Result<String, ErrorDetection> {
        let s = input.trim();

        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice/address cannot be empty".into(),
                tx_id: None,
            });
        }

        if s.len() > MAX_PRIVATE_RECEIVE_INVOICE_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private receive invoice/address too long: {} > {}",
                    s.len(),
                    MAX_PRIVATE_RECEIVE_INVOICE_LEN
                ),
                tx_id: None,
            });
        }

        let invoice_prefix = format!("{}:", PRIVATE_RECEIVE_INVOICE_PREFIX);

        if let Some(rest) = s.strip_prefix(&invoice_prefix) {
            let (version_part, wallet_part) =
                rest.split_once(':').ok_or_else(|| ErrorDetection::ValidationError {
                    message:
                        "Invalid private receive invoice. Expected remzar-private-receive:v1:<wallet>"
                            .into(),
                    tx_id: None,
                })?;

            let expected_version = format!("v{}", PRIVATE_RECEIVE_VERSION);

            if version_part != expected_version {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Unsupported private receive invoice version '{}'; expected '{}'",
                        version_part, expected_version
                    ),
                    tx_id: None,
                });
            }

            if wallet_part.is_empty() {
                return Err(ErrorDetection::ValidationError {
                    message: "Private receive invoice wallet address is empty".into(),
                    tx_id: None,
                });
            }

            if wallet_part.contains(':') {
                return Err(ErrorDetection::ValidationError {
                    message: "Invalid private receive invoice: too many ':' separators".into(),
                    tx_id: None,
                });
            }

            return canon_wallet_id_checked(wallet_part).map_err(|e| {
                ErrorDetection::ValidationError {
                    message: format!("Invalid private receive invoice wallet address: {e}"),
                    tx_id: None,
                }
            });
        }

        // Any other colon-containing payload is neither a valid invoice nor a raw wallet.
        // Raw Remzar wallet addresses do not contain ':'.
        if s.contains(':') {
            return Err(ErrorDetection::ValidationError {
                message:
                    "Invalid private receive invoice/address. Expected remzar-private-receive:v1:<wallet> or raw wallet address"
                        .into(),
                tx_id: None,
            });
        }

        // Convenience path: raw one-time wallet address.
        canon_wallet_id_checked(s).map_err(|e| ErrorDetection::ValidationError {
            message: format!("Invalid private receive wallet address: {e}"),
            tx_id: None,
        })
    }

    /// Return true if input looks like a Remzar private receive invoice.
    pub fn is_private_receive_invoice(input: &str) -> bool {
        let s = input.trim();
        s.starts_with(&format!(
            "{}:v{}:",
            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
        ))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Load / validate local records
    // ─────────────────────────────────────────────────────────────────────

    /// Load a private receive metadata record by one-time wallet address.
    pub fn load_record_by_one_time_wallet(
        opts: &NodeOpts,
        one_time_wallet: &str,
    ) -> Result<PrivateReceiveWalletRecord, ErrorDetection> {
        let one_time_wallet = canon_wallet_id_checked(one_time_wallet)?;
        let directory = Self::load_directory(opts)?;
        let metadata_file = Self::metadata_file_path(&directory.wallets_path, &one_time_wallet);

        let bytes = fs::read(&metadata_file).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to read private receive metadata '{}': {e}",
                metadata_file.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let record: PrivateReceiveWalletRecord =
            serde_json::from_slice(&bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!(
                    "Failed to decode private receive metadata '{}': {e}",
                    metadata_file.display()
                ),
            })?;

        Self::validate_record(&record)?;
        Ok(record)
    }

    pub fn validate_receipt(receipt: &PrivateReceiveWalletReceipt) -> Result<(), ErrorDetection> {
        if receipt.version != PRIVATE_RECEIVE_VERSION {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private receive receipt version mismatch: expected {}, got {}",
                    PRIVATE_RECEIVE_VERSION, receipt.version
                ),
                tx_id: None,
            });
        }

        let owner = canon_wallet_id_checked(&receipt.owner_wallet)?;
        let one_time = canon_wallet_id_checked(&receipt.one_time_wallet)?;

        if owner == one_time {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive owner wallet and one-time wallet cannot be the same"
                    .into(),
                tx_id: None,
            });
        }

        let parsed = Self::parse_invoice_or_address(&receipt.invoice)?;
        if parsed != one_time {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive receipt invoice does not match one-time wallet".into(),
                tx_id: None,
            });
        }

        if receipt.created_unix_secs == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive receipt has invalid created_unix_secs=0".into(),
                tx_id: None,
            });
        }

        if receipt.wallet_file_path.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive receipt wallet_file_path is empty".into(),
                tx_id: None,
            });
        }

        if receipt.metadata_file_path.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive receipt metadata_file_path is empty".into(),
                tx_id: None,
            });
        }

        Ok(())
    }

    pub fn validate_record(record: &PrivateReceiveWalletRecord) -> Result<(), ErrorDetection> {
        if record.version != PRIVATE_RECEIVE_VERSION {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private receive record version mismatch: expected {}, got {}",
                    PRIVATE_RECEIVE_VERSION, record.version
                ),
                tx_id: None,
            });
        }

        if record.kind != "remzar_private_receive_wallet" {
            return Err(ErrorDetection::ValidationError {
                message: format!("Invalid private receive record kind '{}'", record.kind),
                tx_id: None,
            });
        }

        let owner = canon_wallet_id_checked(&record.owner_wallet)?;
        let one_time = canon_wallet_id_checked(&record.one_time_wallet)?;

        if owner == one_time {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive record owner and one-time wallet cannot be the same"
                    .into(),
                tx_id: None,
            });
        }

        let parsed = Self::parse_invoice_or_address(&record.invoice)?;
        if parsed != one_time {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive record invoice does not match one-time wallet".into(),
                tx_id: None,
            });
        }

        if record.created_unix_secs == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive record has invalid created_unix_secs=0".into(),
                tx_id: None,
            });
        }

        if record.wallet_file_name != Self::wallet_file_name(&one_time) {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive record wallet_file_name does not match one-time wallet"
                    .into(),
                tx_id: None,
            });
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Path helpers
    // ─────────────────────────────────────────────────────────────────────

    pub fn wallet_file_name(wallet: &str) -> String {
        format!("{wallet}.{WALLET_FILE_EXT}")
    }

    pub fn wallet_file_path(wallets_path: &Path, wallet: &str) -> PathBuf {
        wallets_path.join(Self::wallet_file_name(wallet))
    }

    pub fn metadata_dir_path(wallets_path: &Path) -> PathBuf {
        wallets_path.join(PRIVATE_RECEIVE_METADATA_DIR)
    }

    pub fn metadata_file_path(wallets_path: &Path, one_time_wallet: &str) -> PathBuf {
        Self::metadata_dir_path(wallets_path)
            .join(format!("{one_time_wallet}.{PRIVATE_RECEIVE_RECORD_EXT}"))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal guards
    // ─────────────────────────────────────────────────────────────────────

    #[inline]
    fn maybe_fault(op: &'static str) -> Result<(), ErrorDetection> {
        if std::env::var_os(format!("REMZAR_FAIL_{op}")).is_some() {
            return Err(ErrorDetection::CryptographicError {
                message: format!("Fault injection triggered at operation: {op}"),
            });
        }

        Ok(())
    }

    fn canonical_owner_wallet(owner_wallet: &str) -> Result<String, ErrorDetection> {
        canon_wallet_id_checked(owner_wallet).map_err(|e| ErrorDetection::ValidationError {
            message: format!("Invalid owner wallet for private receive wallet: {e}"),
            tx_id: None,
        })
    }

    fn validate_passphrase(passphrase: &str) -> Result<(), ErrorDetection> {
        if passphrase.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive wallet passphrase cannot be empty".into(),
                tx_id: None,
            });
        }

        // Keep this conservative. Cryption has its own hard caps too.
        if passphrase.len() > 16 * 1024 {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive wallet passphrase is too large".into(),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn load_directory(opts: &NodeOpts) -> Result<DirectoryDB, ErrorDetection> {
        DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to initialize Remzar directories: {e}"),
            code: None,
            source: None,
        })
    }

    fn ensure_wallets_dir(directory: &DirectoryDB) -> Result<(), ErrorDetection> {
        directory
            .create_wallets_directory()
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to create/check wallets directory: {e}"),
                code: None,
                source: None,
            })
    }

    fn ensure_owner_wallet_file_exists(
        wallets_path: &Path,
        owner_wallet: &str,
    ) -> Result<(), ErrorDetection> {
        let owner_wallet = canon_wallet_id_checked(owner_wallet)?;
        let owner_file = Self::wallet_file_path(wallets_path, &owner_wallet);

        if !owner_file.exists() {
            return Err(ErrorDetection::NotFound {
                resource: format!(
                    "Owner wallet file not found for private receive generation: {}",
                    owner_file.display()
                ),
            });
        }

        Ok(())
    }

    /// Atomic write helper:
    fn atomic_write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), ErrorDetection> {
        if path.exists() {
            return Err(ErrorDetection::ValidationError {
                message: format!("Refusing to overwrite existing file: {}", path.display()),
                tx_id: None,
            });
        }

        let parent = path.parent().ok_or_else(|| ErrorDetection::StorageError {
            message: format!("Path has no parent directory: {}", path.display()),
        })?;

        fs::create_dir_all(parent).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to create parent directory '{}': {e}",
                parent.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let tmp_path = path.with_extension(format!(
            "{}.tmp",
            path.extension().and_then(|e| e.to_str()).unwrap_or("tmp")
        ));

        if let Err(e) = fs::remove_file(&tmp_path)
            && e.kind() != ErrorKind::NotFound
        {
            return Err(ErrorDetection::IoError {
                message: format!(
                    "Failed to remove stale temp file '{}': {e}",
                    tmp_path.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            });
        }

        fs::write(&tmp_path, bytes).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to write temp file '{}': {e}", tmp_path.display()),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        #[cfg(unix)]
        Self::set_private_file_permissions_best_effort(&tmp_path)?;

        #[cfg(not(unix))]
        Self::set_private_file_permissions_best_effort(&tmp_path);

        fs::rename(&tmp_path, path).map_err(|e| {
            drop(fs::remove_file(&tmp_path));
            ErrorDetection::IoError {
                message: format!(
                    "Failed to atomically move temp file '{}' to '{}': {e}",
                    tmp_path.display(),
                    path.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })?;

        Ok(())
    }

    #[cfg(unix)]
    fn set_private_file_permissions_best_effort(path: &Path) -> Result<(), ErrorDetection> {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            ErrorDetection::IoError {
                message: format!(
                    "Failed to set private wallet index permissions to 0600 for '{}': {e}",
                    path.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }
        })
    }

    #[cfg(not(unix))]
    fn set_private_file_permissions_best_effort(_path: &Path) {}
}
