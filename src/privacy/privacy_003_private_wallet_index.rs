//! src/privacy/privacy_003_private_wallet_index.rs

use crate::privacy::privacy_001_private_receive_wallet::{
    PRIVATE_RECEIVE_METADATA_DIR, PRIVATE_RECEIVE_RECORD_EXT, PRIVATE_RECEIVE_VERSION, PrivateRW,
    PrivateReceiveWalletReceipt, PrivateReceiveWalletRecord,
};
use crate::privacy::privacy_002_private_receive_invoice::{
    MAX_PRIVATE_RECEIVE_CONTEXT_LEN, MAX_PRIVATE_RECEIVE_LABEL_LEN, PrivateRI,
};
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::time_policy::TimePolicy;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone, Copy)]
pub struct PrivateWI;

/// Human-readable JSON kind marker.
pub const PRIVATE_WALLET_INDEX_KIND: &str = "remzar_private_wallet_index";

/// Index file name.
pub const PRIVATE_WALLET_INDEX_FILE_NAME: &str = "private_wallet_index_v1.json";

/// Backup file name used during atomic-ish replacement on Windows.
pub const PRIVATE_WALLET_INDEX_BACKUP_FILE_NAME: &str = "private_wallet_index_v1.json.bak";

/// Temporary file name used for writes.
pub const PRIVATE_WALLET_INDEX_TMP_FILE_NAME: &str = "private_wallet_index_v1.json.tmp";

/// Hard cap to prevent local index bloat or accidental huge imports.
pub const MAX_PRIVATE_INDEX_OWNERS: usize = 100_000;

/// Hard cap per owner wallet.
pub const MAX_PRIVATE_INDEX_ENTRIES_PER_OWNER: usize = 100_000;

/// Hard cap total entries.
pub const MAX_PRIVATE_INDEX_TOTAL_ENTRIES: usize = 1_000_000;

/// Hard cap for JSON file size before parsing.
pub const MAX_PRIVATE_INDEX_JSON_BYTES: usize = 128 * 1024 * 1024;

/// One local index entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateWalletIndexEntry {
    pub version: u16,

    /// Main wallet that owns/controls this one-time private receive wallet locally.
    pub owner_wallet: String,

    /// One-time receive wallet address.
    pub one_time_wallet: String,

    /// Canonical invoice:
    pub invoice: String,

    /// Expected encrypted one-time wallet file name:
    pub wallet_file_name: String,

    /// When the one-time wallet was created.
    pub created_unix_secs: u64,

    /// When it was added to this local index.
    pub indexed_unix_secs: u64,

    /// Optional local label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Optional local context/note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Disk JSON shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateWalletIndexFile {
    pub kind: String,
    pub version: u16,
    pub created_unix_secs: u64,
    pub updated_unix_secs: u64,

    #[serde(default)]
    pub entries_by_owner: BTreeMap<String, Vec<PrivateWalletIndexEntry>>,
}

/// Request for adding an index entry.
#[derive(Debug, Clone)]
pub struct PrivateWalletIndexAddRequest<'a> {
    pub owner_wallet: &'a str,
    pub one_time_wallet: &'a str,

    /// Optional invoice. If omitted, it is generated from `one_time_wallet`.
    pub invoice: Option<&'a str>,

    /// Optional wallet file name. If omitted, it is generated from `one_time_wallet`.
    pub wallet_file_name: Option<&'a str>,

    /// Optional creation time. If omitted, current runtime time is used.
    pub created_unix_secs: Option<u64>,

    pub label: Option<&'a str>,
    pub context: Option<&'a str>,

    /// If true, require that `<wallets_path>/<one_time_wallet>.wallet` exists.
    pub require_one_time_wallet_file: bool,
}

/// Owned version for CLI/UI workflows.
#[derive(Debug, Clone)]
pub struct PrivateWalletIndexAddOwnedRequest {
    pub owner_wallet: String,
    pub one_time_wallet: String,
    pub invoice: Option<String>,
    pub wallet_file_name: Option<String>,
    pub created_unix_secs: Option<u64>,
    pub label: Option<String>,
    pub context: Option<String>,
    pub require_one_time_wallet_file: bool,
}

/// Result for owner lookup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateWalletOwnerLookup {
    pub owner_wallet: String,
    pub entry: PrivateWalletIndexEntry,
}

impl PrivateWI {
    // ─────────────────────────────────────────────────────────────────────
    // Constructors
    // ─────────────────────────────────────────────────────────────────────

    pub fn new() -> Self {
        Self
    }

    // ─────────────────────────────────────────────────────────────────────
    // Add / import
    // ─────────────────────────────────────────────────────────────────────

    /// Add an index entry from the receipt returned by `PrivateRW::create_receive_wallet`.
    pub fn add_from_receipt(
        &self,
        opts: &NodeOpts,
        receipt: &PrivateReceiveWalletReceipt,
        label: Option<&str>,
        context: Option<&str>,
        require_one_time_wallet_file: bool,
    ) -> Result<PrivateWalletIndexEntry, ErrorDetection> {
        PrivateRW::validate_receipt(receipt)?;

        self.add_entry(
            opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &receipt.owner_wallet,
                one_time_wallet: &receipt.one_time_wallet,
                invoice: Some(&receipt.invoice),
                wallet_file_name: None,
                created_unix_secs: Some(receipt.created_unix_secs),
                label,
                context,
                require_one_time_wallet_file,
            },
        )
    }

    /// Add an index entry from a local `.prw.json` record written by `PrivateRW`.
    pub fn add_from_record(
        &self,
        opts: &NodeOpts,
        record: &PrivateReceiveWalletRecord,
        label: Option<&str>,
        context: Option<&str>,
        require_one_time_wallet_file: bool,
    ) -> Result<PrivateWalletIndexEntry, ErrorDetection> {
        PrivateRW::validate_record(record)?;

        self.add_entry(
            opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &record.owner_wallet,
                one_time_wallet: &record.one_time_wallet,
                invoice: Some(&record.invoice),
                wallet_file_name: Some(&record.wallet_file_name),
                created_unix_secs: Some(record.created_unix_secs),
                label,
                context,
                require_one_time_wallet_file,
            },
        )
    }

    /// Add or update one local index entry.
    pub fn add_entry(
        &self,
        opts: &NodeOpts,
        request: PrivateWalletIndexAddRequest<'_>,
    ) -> Result<PrivateWalletIndexEntry, ErrorDetection> {
        Self::maybe_fault("PRIVATE_WI_ADD_PRE")?;

        let directory = Self::load_directory(opts)?;
        Self::ensure_wallets_dir(&directory)?;
        Self::ensure_private_receive_dir(&directory.wallets_path)?;

        // Capture this bool BEFORE request is moved into build_entry().
        let require_one_time_wallet_file = request.require_one_time_wallet_file;

        let entry = Self::build_entry(&directory.wallets_path, request)?;
        Self::validate_entry(&entry)?;

        if require_one_time_wallet_file {
            Self::ensure_one_time_wallet_file_exists(&directory.wallets_path, &entry)?;
        }

        let mut index = self.load_or_new(opts)?;
        Self::insert_or_replace_entry(&mut index, entry.clone())?;

        index.updated_unix_secs = TimePolicy::now_unix_secs_runtime()?;
        Self::validate_index_file(&index)?;

        self.save_index(opts, &index)?;

        Self::maybe_fault("PRIVATE_WI_ADD_POST")?;
        Ok(entry)
    }

    /// Add entry using owned request values.
    pub fn add_entry_owned(
        &self,
        opts: &NodeOpts,
        request: PrivateWalletIndexAddOwnedRequest,
    ) -> Result<PrivateWalletIndexEntry, ErrorDetection> {
        self.add_entry(
            opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &request.owner_wallet,
                one_time_wallet: &request.one_time_wallet,
                invoice: request.invoice.as_deref(),
                wallet_file_name: request.wallet_file_name.as_deref(),
                created_unix_secs: request.created_unix_secs,
                label: request.label.as_deref(),
                context: request.context.as_deref(),
                require_one_time_wallet_file: request.require_one_time_wallet_file,
            },
        )
    }

    /// Rebuild the index from all `.prw.json` metadata records written by `PrivateRW`.
    pub fn rebuild_from_private_receive_records(
        &self,
        opts: &NodeOpts,
        require_one_time_wallet_file: bool,
    ) -> Result<PrivateWalletIndexFile, ErrorDetection> {
        Self::maybe_fault("PRIVATE_WI_REBUILD_PRE")?;

        let directory = Self::load_directory(opts)?;
        Self::ensure_wallets_dir(&directory)?;
        let metadata_dir = PrivateRW::metadata_dir_path(&directory.wallets_path);
        Self::ensure_private_receive_dir(&directory.wallets_path)?;

        let mut index = Self::new_empty_index()?;

        if metadata_dir.exists() {
            for item in fs::read_dir(&metadata_dir).map_err(|e| ErrorDetection::IoError {
                message: format!(
                    "Failed to read private receive metadata directory '{}': {e}",
                    metadata_dir.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })? {
                let item = item.map_err(|e| ErrorDetection::IoError {
                    message: format!("Failed to read private receive metadata entry: {e}"),
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                })?;

                let path = item.path();

                if !Self::is_private_receive_record_path(&path) {
                    continue;
                }

                Self::ensure_path_not_symlink(&path)?;

                let bytes = fs::read(&path).map_err(|e| ErrorDetection::IoError {
                    message: format!(
                        "Failed to read private receive record '{}': {e}",
                        path.display()
                    ),
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                })?;

                if bytes.len() > 1024 * 1024 {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Private receive record too large: {} bytes at {}",
                            bytes.len(),
                            path.display()
                        ),
                        tx_id: None,
                    });
                }

                let record: PrivateReceiveWalletRecord =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        ErrorDetection::SerializationError {
                            details: format!(
                                "Failed to decode private receive record '{}': {e}",
                                path.display()
                            ),
                        }
                    })?;

                PrivateRW::validate_record(&record)?;

                let entry = Self::build_entry(
                    &directory.wallets_path,
                    PrivateWalletIndexAddRequest {
                        owner_wallet: &record.owner_wallet,
                        one_time_wallet: &record.one_time_wallet,
                        invoice: Some(&record.invoice),
                        wallet_file_name: Some(&record.wallet_file_name),
                        created_unix_secs: Some(record.created_unix_secs),
                        label: None,
                        context: Some("rebuilt_from_private_receive_record"),
                        require_one_time_wallet_file,
                    },
                )?;

                if require_one_time_wallet_file {
                    Self::ensure_one_time_wallet_file_exists(&directory.wallets_path, &entry)?;
                }

                Self::insert_or_replace_entry(&mut index, entry)?;
            }
        }

        index.updated_unix_secs = TimePolicy::now_unix_secs_runtime()?;
        Self::validate_index_file(&index)?;
        self.save_index(opts, &index)?;

        Self::maybe_fault("PRIVATE_WI_REBUILD_POST")?;
        Ok(index)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Load / save
    // ─────────────────────────────────────────────────────────────────────

    /// Load the existing index.
    pub fn load_index(&self, opts: &NodeOpts) -> Result<PrivateWalletIndexFile, ErrorDetection> {
        let directory = Self::load_directory(opts)?;
        let index_path = Self::index_file_path(&directory.wallets_path);

        if !index_path.exists() {
            return Err(ErrorDetection::NotFound {
                resource: format!("Private wallet index not found: {}", index_path.display()),
            });
        }

        Self::ensure_path_not_symlink(&index_path)?;

        let metadata = fs::metadata(&index_path).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to read private wallet index metadata '{}': {e}",
                index_path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let len = usize::try_from(metadata.len()).map_err(|_| ErrorDetection::ValidationError {
            message: format!(
                "Private wallet index file too large to fit usize: {}",
                metadata.len()
            ),
            tx_id: None,
        })?;

        if len > MAX_PRIVATE_INDEX_JSON_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index JSON too large: {} > {} bytes",
                    len, MAX_PRIVATE_INDEX_JSON_BYTES
                ),
                tx_id: None,
            });
        }

        let bytes = fs::read(&index_path).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to read private wallet index '{}': {e}",
                index_path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        let mut index: PrivateWalletIndexFile =
            serde_json::from_slice(&bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!(
                    "Failed to decode private wallet index '{}': {e}",
                    index_path.display()
                ),
            })?;

        Self::canonicalize_index_in_place(&mut index)?;
        Self::validate_index_file(&index)?;
        Ok(index)
    }

    /// Load existing index, or create an empty in-memory index if no file exists.
    pub fn load_or_new(&self, opts: &NodeOpts) -> Result<PrivateWalletIndexFile, ErrorDetection> {
        match self.load_index(opts) {
            Ok(index) => Ok(index),
            Err(ErrorDetection::NotFound { .. }) => Self::new_empty_index(),
            Err(e) => Err(e),
        }
    }

    /// Save the index file to disk.
    pub fn save_index(
        &self,
        opts: &NodeOpts,
        index: &PrivateWalletIndexFile,
    ) -> Result<(), ErrorDetection> {
        let directory = Self::load_directory(opts)?;
        Self::ensure_wallets_dir(&directory)?;
        Self::ensure_private_receive_dir(&directory.wallets_path)?;

        let mut index = index.clone();
        Self::canonicalize_index_in_place(&mut index)?;
        Self::validate_index_file(&index)?;

        let bytes =
            serde_json::to_vec_pretty(&index).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to serialize private wallet index: {e}"),
            })?;

        if bytes.len() > MAX_PRIVATE_INDEX_JSON_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index JSON too large to save: {} > {} bytes",
                    bytes.len(),
                    MAX_PRIVATE_INDEX_JSON_BYTES
                ),
                tx_id: None,
            });
        }

        let index_path = Self::index_file_path(&directory.wallets_path);
        Self::atomic_replace_private_file(&index_path, &bytes)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Query
    // ─────────────────────────────────────────────────────────────────────

    /// List all one-time entries for an owner wallet.
    pub fn list_for_owner(
        &self,
        opts: &NodeOpts,
        owner_wallet: &str,
    ) -> Result<Vec<PrivateWalletIndexEntry>, ErrorDetection> {
        let owner_wallet = Self::canonical_wallet(owner_wallet)?;
        let index = self.load_or_new(opts)?;

        let mut out = index
            .entries_by_owner
            .get(&owner_wallet)
            .cloned()
            .unwrap_or_default();

        out.sort_by(Self::entry_sort_cmp);
        Ok(out)
    }

    /// List every indexed one-time wallet.
    pub fn list_all_entries(
        &self,
        opts: &NodeOpts,
    ) -> Result<Vec<PrivateWalletIndexEntry>, ErrorDetection> {
        let index = self.load_or_new(opts)?;
        Ok(Self::flatten_entries(&index))
    }

    /// Count entries owned by a wallet.
    pub fn count_for_owner(
        &self,
        opts: &NodeOpts,
        owner_wallet: &str,
    ) -> Result<usize, ErrorDetection> {
        Ok(self.list_for_owner(opts, owner_wallet)?.len())
    }

    /// Return true if the one-time wallet is indexed.
    pub fn contains_one_time_wallet(
        &self,
        opts: &NodeOpts,
        one_time_wallet: &str,
    ) -> Result<bool, ErrorDetection> {
        Ok(self.lookup_owner(opts, one_time_wallet)?.is_some())
    }

    /// Find the owner wallet for a one-time wallet.
    pub fn lookup_owner(
        &self,
        opts: &NodeOpts,
        one_time_wallet: &str,
    ) -> Result<Option<String>, ErrorDetection> {
        let one_time_wallet = Self::canonical_wallet(one_time_wallet)?;
        let index = self.load_or_new(opts)?;

        for (owner, entries) in &index.entries_by_owner {
            for entry in entries {
                if entry.one_time_wallet == one_time_wallet {
                    return Ok(Some(owner.clone()));
                }
            }
        }

        Ok(None)
    }

    /// Find the full index entry for a one-time wallet.
    pub fn lookup_entry(
        &self,
        opts: &NodeOpts,
        one_time_wallet: &str,
    ) -> Result<Option<PrivateWalletOwnerLookup>, ErrorDetection> {
        let one_time_wallet = Self::canonical_wallet(one_time_wallet)?;
        let index = self.load_or_new(opts)?;

        for (owner, entries) in &index.entries_by_owner {
            for entry in entries {
                if entry.one_time_wallet == one_time_wallet {
                    return Ok(Some(PrivateWalletOwnerLookup {
                        owner_wallet: owner.clone(),
                        entry: entry.clone(),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Remove a one-time wallet from the index.
    pub fn remove_one_time_wallet(
        &self,
        opts: &NodeOpts,
        one_time_wallet: &str,
    ) -> Result<Option<PrivateWalletIndexEntry>, ErrorDetection> {
        Self::maybe_fault("PRIVATE_WI_REMOVE_PRE")?;

        let one_time_wallet = Self::canonical_wallet(one_time_wallet)?;
        let mut index = self.load_or_new(opts)?;

        let mut removed: Option<PrivateWalletIndexEntry> = None;
        let owners: Vec<String> = index.entries_by_owner.keys().cloned().collect();

        for owner in owners {
            if let Some(entries) = index.entries_by_owner.get_mut(&owner)
                && let Some(pos) = entries
                    .iter()
                    .position(|entry| entry.one_time_wallet == one_time_wallet)
            {
                removed = Some(entries.remove(pos));
            }

            if index
                .entries_by_owner
                .get(&owner)
                .map(|v| v.is_empty())
                .unwrap_or(false)
            {
                index.entries_by_owner.remove(&owner);
            }

            if removed.is_some() {
                break;
            }
        }

        if removed.is_some() {
            index.updated_unix_secs = TimePolicy::now_unix_secs_runtime()?;
            Self::validate_index_file(&index)?;
            self.save_index(opts, &index)?;
        }

        Self::maybe_fault("PRIVATE_WI_REMOVE_POST")?;
        Ok(removed)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Path helpers
    // ─────────────────────────────────────────────────────────────────────

    pub fn index_file_path(wallets_path: &Path) -> PathBuf {
        PrivateRW::metadata_dir_path(wallets_path).join(PRIVATE_WALLET_INDEX_FILE_NAME)
    }

    pub fn index_tmp_file_path(wallets_path: &Path) -> PathBuf {
        PrivateRW::metadata_dir_path(wallets_path).join(PRIVATE_WALLET_INDEX_TMP_FILE_NAME)
    }

    pub fn index_backup_file_path(wallets_path: &Path) -> PathBuf {
        PrivateRW::metadata_dir_path(wallets_path).join(PRIVATE_WALLET_INDEX_BACKUP_FILE_NAME)
    }

    /// Resolve the index path from `NodeOpts`.
    pub fn index_path_from_opts(opts: &NodeOpts) -> Result<PathBuf, ErrorDetection> {
        let directory = Self::load_directory(opts)?;
        Ok(Self::index_file_path(&directory.wallets_path))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Validation
    // ─────────────────────────────────────────────────────────────────────

    pub fn validate_entry(entry: &PrivateWalletIndexEntry) -> Result<(), ErrorDetection> {
        if entry.version != PRIVATE_RECEIVE_VERSION {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index entry version mismatch: expected {}, got {}",
                    PRIVATE_RECEIVE_VERSION, entry.version
                ),
                tx_id: None,
            });
        }

        let owner = Self::canonical_wallet(&entry.owner_wallet)?;
        let one_time = Self::canonical_wallet(&entry.one_time_wallet)?;

        if owner == one_time {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index entry owner and one-time wallet cannot be the same"
                    .into(),
                tx_id: None,
            });
        }

        let parsed = PrivateRI::parse_invoice_or_address(&entry.invoice)?;
        if parsed.one_time_wallet != one_time {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index entry invoice does not match one-time wallet".into(),
                tx_id: None,
            });
        }

        if parsed.canonical_invoice != entry.invoice {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index entry invoice is not canonical".into(),
                tx_id: None,
            });
        }

        let expected_wallet_file_name = PrivateRW::wallet_file_name(&one_time);
        if entry.wallet_file_name != expected_wallet_file_name {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index entry wallet_file_name mismatch: expected '{}', got '{}'",
                    expected_wallet_file_name, entry.wallet_file_name
                ),
                tx_id: None,
            });
        }

        if entry.created_unix_secs == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index entry created_unix_secs cannot be zero".into(),
                tx_id: None,
            });
        }

        if entry.indexed_unix_secs == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index entry indexed_unix_secs cannot be zero".into(),
                tx_id: None,
            });
        }

        if let Some(label) = entry.label.as_deref() {
            Self::validate_optional_label(label)?;
        }

        if let Some(context) = entry.context.as_deref() {
            Self::validate_optional_context(context)?;
        }

        Ok(())
    }

    pub fn validate_index_file(index: &PrivateWalletIndexFile) -> Result<(), ErrorDetection> {
        if index.kind != PRIVATE_WALLET_INDEX_KIND {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid private wallet index kind '{}'; expected '{}'",
                    index.kind, PRIVATE_WALLET_INDEX_KIND
                ),
                tx_id: None,
            });
        }

        if index.version != PRIVATE_RECEIVE_VERSION {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index version mismatch: expected {}, got {}",
                    PRIVATE_RECEIVE_VERSION, index.version
                ),
                tx_id: None,
            });
        }

        if index.created_unix_secs == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index created_unix_secs cannot be zero".into(),
                tx_id: None,
            });
        }

        if index.updated_unix_secs == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index updated_unix_secs cannot be zero".into(),
                tx_id: None,
            });
        }

        if index.entries_by_owner.len() > MAX_PRIVATE_INDEX_OWNERS {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index owner count too large: {} > {}",
                    index.entries_by_owner.len(),
                    MAX_PRIVATE_INDEX_OWNERS
                ),
                tx_id: None,
            });
        }

        let mut total_entries = 0usize;
        let mut seen_one_time_wallets: BTreeSet<String> = BTreeSet::new();

        for (owner_key, entries) in &index.entries_by_owner {
            let canonical_owner = Self::canonical_wallet(owner_key)?;

            if owner_key != &canonical_owner {
                return Err(ErrorDetection::ValidationError {
                    message: "Private wallet index owner key is not canonical".into(),
                    tx_id: None,
                });
            }

            if entries.len() > MAX_PRIVATE_INDEX_ENTRIES_PER_OWNER {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Private wallet index entries for owner {} too large: {} > {}",
                        owner_key,
                        entries.len(),
                        MAX_PRIVATE_INDEX_ENTRIES_PER_OWNER
                    ),
                    tx_id: None,
                });
            }

            total_entries = total_entries.checked_add(entries.len()).ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: "Overflow while counting private wallet index entries".into(),
                    tx_id: None,
                }
            })?;

            if total_entries > MAX_PRIVATE_INDEX_TOTAL_ENTRIES {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Private wallet index total entries too large: {} > {}",
                        total_entries, MAX_PRIVATE_INDEX_TOTAL_ENTRIES
                    ),
                    tx_id: None,
                });
            }

            for entry in entries {
                Self::validate_entry(entry)?;

                if entry.owner_wallet != canonical_owner {
                    return Err(ErrorDetection::ValidationError {
                        message:
                            "Private wallet index entry owner_wallet does not match owner map key"
                                .into(),
                        tx_id: None,
                    });
                }

                if !seen_one_time_wallets.insert(entry.one_time_wallet.clone()) {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Duplicate one-time wallet in private wallet index: {}",
                            entry.one_time_wallet
                        ),
                        tx_id: None,
                    });
                }
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal helpers
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

    fn ensure_private_receive_dir(wallets_path: &Path) -> Result<(), ErrorDetection> {
        let dir = wallets_path.join(PRIVATE_RECEIVE_METADATA_DIR);

        if dir.exists() {
            Self::ensure_path_not_symlink(&dir)?;
        }

        fs::create_dir_all(&dir).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to create private receive index directory '{}': {e}",
                dir.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })
    }

    fn ensure_path_not_symlink(path: &Path) -> Result<(), ErrorDetection> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ErrorDetection::StorageError {
                        message: format!(
                            "Refusing to use symlinked private wallet index path '{}'",
                            path.display()
                        ),
                    });
                }

                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ErrorDetection::IoError {
                message: format!("Failed to inspect path '{}': {e}", path.display()),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }),
        }
    }

    fn ensure_one_time_wallet_file_exists(
        wallets_path: &Path,
        entry: &PrivateWalletIndexEntry,
    ) -> Result<(), ErrorDetection> {
        let wallet_file = PrivateRW::wallet_file_path(wallets_path, &entry.one_time_wallet);

        Self::ensure_path_not_symlink(&wallet_file)?;

        if !wallet_file.exists() {
            return Err(ErrorDetection::NotFound {
                resource: format!(
                    "One-time private receive wallet file not found: {}",
                    wallet_file.display()
                ),
            });
        }

        Ok(())
    }

    fn canonical_wallet(wallet: &str) -> Result<String, ErrorDetection> {
        canon_wallet_id_checked(wallet).map_err(|e| ErrorDetection::ValidationError {
            message: format!("Invalid Remzar wallet address for private wallet index: {e}"),
            tx_id: None,
        })
    }

    fn validate_optional_label(label: &str) -> Result<String, ErrorDetection> {
        let label = label.trim();

        if label.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index label cannot be empty when provided".into(),
                tx_id: None,
            });
        }

        if label.len() > MAX_PRIVATE_RECEIVE_LABEL_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index label too long: {} > {}",
                    label.len(),
                    MAX_PRIVATE_RECEIVE_LABEL_LEN
                ),
                tx_id: None,
            });
        }

        if label.bytes().any(|b| b.is_ascii_control()) {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index label contains control characters".into(),
                tx_id: None,
            });
        }

        Ok(label.to_string())
    }

    fn validate_optional_context(context: &str) -> Result<String, ErrorDetection> {
        let context = context.trim();

        if context.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index context cannot be empty when provided".into(),
                tx_id: None,
            });
        }

        if context.len() > MAX_PRIVATE_RECEIVE_CONTEXT_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private wallet index context too long: {} > {}",
                    context.len(),
                    MAX_PRIVATE_RECEIVE_CONTEXT_LEN
                ),
                tx_id: None,
            });
        }

        if context.bytes().any(|b| b.is_ascii_control()) {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index context contains control characters".into(),
                tx_id: None,
            });
        }

        Ok(context.to_string())
    }

    fn build_entry(
        wallets_path: &Path,
        request: PrivateWalletIndexAddRequest<'_>,
    ) -> Result<PrivateWalletIndexEntry, ErrorDetection> {
        let owner_wallet = Self::canonical_wallet(request.owner_wallet)?;
        let one_time_wallet = Self::canonical_wallet(request.one_time_wallet)?;

        if owner_wallet == one_time_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "Private wallet index owner and one-time wallet cannot be the same".into(),
                tx_id: None,
            });
        }

        let invoice = match request.invoice {
            Some(invoice_input) => {
                let parsed = PrivateRI::parse_invoice_or_address(invoice_input)?;

                if parsed.one_time_wallet != one_time_wallet {
                    return Err(ErrorDetection::ValidationError {
                        message:
                            "Private wallet index request invoice does not match one-time wallet"
                                .into(),
                        tx_id: None,
                    });
                }

                parsed.canonical_invoice
            }
            None => PrivateRI::parse_invoice_or_address(&one_time_wallet)?.canonical_invoice,
        };

        let wallet_file_name = match request.wallet_file_name {
            Some(file_name) => {
                let expected = PrivateRW::wallet_file_name(&one_time_wallet);
                if file_name != expected {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Private wallet index request wallet_file_name mismatch: expected '{}', got '{}'",
                            expected, file_name
                        ),
                        tx_id: None,
                    });
                }
                file_name.to_string()
            }
            None => PrivateRW::wallet_file_name(&one_time_wallet),
        };

        let created_unix_secs = match request.created_unix_secs {
            Some(v) if v > 0 => v,
            Some(_) => {
                return Err(ErrorDetection::ValidationError {
                    message: "Private wallet index request created_unix_secs cannot be zero".into(),
                    tx_id: None,
                });
            }
            None => TimePolicy::now_unix_secs_runtime()?,
        };

        let indexed_unix_secs = TimePolicy::now_unix_secs_runtime()?;

        let label = match request.label {
            Some(v) => Some(Self::validate_optional_label(v)?),
            None => None,
        };

        let context = match request.context {
            Some(v) => Some(Self::validate_optional_context(v)?),
            None => None,
        };

        let entry = PrivateWalletIndexEntry {
            version: PRIVATE_RECEIVE_VERSION,
            owner_wallet,
            one_time_wallet,
            invoice,
            wallet_file_name,
            created_unix_secs,
            indexed_unix_secs,
            label,
            context,
        };

        // Defensive path consistency check: generated wallet filename must resolve under wallets_path.
        let expected_wallet_file =
            PrivateRW::wallet_file_path(wallets_path, &entry.one_time_wallet);
        let expected_file_name = expected_wallet_file
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Failed to compute private receive wallet file name".into(),
                tx_id: None,
            })?;

        if expected_file_name != entry.wallet_file_name {
            return Err(ErrorDetection::ValidationError {
                message: "Computed private receive wallet file name mismatch".into(),
                tx_id: None,
            });
        }

        Self::validate_entry(&entry)?;
        Ok(entry)
    }

    fn new_empty_index() -> Result<PrivateWalletIndexFile, ErrorDetection> {
        let now = TimePolicy::now_unix_secs_runtime()?;

        let index = PrivateWalletIndexFile {
            kind: PRIVATE_WALLET_INDEX_KIND.to_string(),
            version: PRIVATE_RECEIVE_VERSION,
            created_unix_secs: now,
            updated_unix_secs: now,
            entries_by_owner: BTreeMap::new(),
        };

        Self::validate_index_file(&index)?;
        Ok(index)
    }

    fn insert_or_replace_entry(
        index: &mut PrivateWalletIndexFile,
        entry: PrivateWalletIndexEntry,
    ) -> Result<(), ErrorDetection> {
        Self::validate_entry(&entry)?;

        let existing_owner = Self::find_owner_in_index(index, &entry.one_time_wallet)?;

        if let Some(owner) = existing_owner
            && owner.as_str() != entry.owner_wallet.as_str()
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "One-time wallet {} is already indexed under a different owner",
                    entry.one_time_wallet
                ),
                tx_id: None,
            });
        }

        let owner_entries = index
            .entries_by_owner
            .entry(entry.owner_wallet.clone())
            .or_default();

        owner_entries.retain(|existing| existing.one_time_wallet != entry.one_time_wallet);
        owner_entries.push(entry);
        owner_entries.sort_by(Self::entry_sort_cmp);

        Self::canonicalize_index_in_place(index)?;
        Self::validate_index_file(index)?;
        Ok(())
    }

    fn find_owner_in_index(
        index: &PrivateWalletIndexFile,
        one_time_wallet: &str,
    ) -> Result<Option<String>, ErrorDetection> {
        let one_time_wallet = Self::canonical_wallet(one_time_wallet)?;

        for (owner, entries) in &index.entries_by_owner {
            for entry in entries {
                if entry.one_time_wallet == one_time_wallet {
                    return Ok(Some(owner.clone()));
                }
            }
        }

        Ok(None)
    }

    fn canonicalize_index_in_place(
        index: &mut PrivateWalletIndexFile,
    ) -> Result<(), ErrorDetection> {
        let mut rebuilt: BTreeMap<String, Vec<PrivateWalletIndexEntry>> = BTreeMap::new();

        let old = std::mem::take(&mut index.entries_by_owner);

        for (_owner_key, mut entries) in old {
            for mut entry in entries.drain(..) {
                entry.owner_wallet = Self::canonical_wallet(&entry.owner_wallet)?;
                entry.one_time_wallet = Self::canonical_wallet(&entry.one_time_wallet)?;
                entry.invoice =
                    PrivateRI::parse_invoice_or_address(&entry.invoice)?.canonical_invoice;
                entry.wallet_file_name = PrivateRW::wallet_file_name(&entry.one_time_wallet);

                if let Some(label) = entry.label.as_deref() {
                    entry.label = Some(Self::validate_optional_label(label)?);
                }

                if let Some(context) = entry.context.as_deref() {
                    entry.context = Some(Self::validate_optional_context(context)?);
                }

                Self::validate_entry(&entry)?;
                rebuilt
                    .entry(entry.owner_wallet.clone())
                    .or_default()
                    .push(entry);
            }
        }

        for entries in rebuilt.values_mut() {
            entries.sort_by(Self::entry_sort_cmp);
            entries.dedup_by(|a, b| a.one_time_wallet == b.one_time_wallet);
        }

        index.entries_by_owner = rebuilt;
        Ok(())
    }

    fn flatten_entries(index: &PrivateWalletIndexFile) -> Vec<PrivateWalletIndexEntry> {
        let mut out = Vec::new();

        for entries in index.entries_by_owner.values() {
            out.extend(entries.iter().cloned());
        }

        out.sort_by(Self::entry_sort_cmp);
        out
    }

    fn entry_sort_cmp(
        a: &PrivateWalletIndexEntry,
        b: &PrivateWalletIndexEntry,
    ) -> std::cmp::Ordering {
        a.created_unix_secs
            .cmp(&b.created_unix_secs)
            .then_with(|| a.owner_wallet.cmp(&b.owner_wallet))
            .then_with(|| a.one_time_wallet.cmp(&b.one_time_wallet))
    }

    fn is_private_receive_record_path(path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
            return false;
        };

        name.ends_with(&format!(".{PRIVATE_RECEIVE_RECORD_EXT}"))
    }

    /// Atomic-ish private file replacement.
    fn atomic_replace_private_file(path: &Path, bytes: &[u8]) -> Result<(), ErrorDetection> {
        let parent = path.parent().ok_or_else(|| ErrorDetection::StorageError {
            message: format!(
                "Private wallet index path has no parent: {}",
                path.display()
            ),
        })?;

        fs::create_dir_all(parent).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to create private wallet index parent directory '{}': {e}",
                parent.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        Self::ensure_path_not_symlink(parent)?;
        Self::ensure_path_not_symlink(path)?;

        let tmp_path = parent.join(PRIVATE_WALLET_INDEX_TMP_FILE_NAME);
        let backup_path = parent.join(PRIVATE_WALLET_INDEX_BACKUP_FILE_NAME);

        Self::remove_file_if_exists(&tmp_path)?;
        Self::remove_file_if_exists(&backup_path)?;

        fs::write(&tmp_path, bytes).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to write private wallet index temp file '{}': {e}",
                tmp_path.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        #[cfg(unix)]
        Self::set_private_file_permissions_best_effort(&tmp_path)?;

        #[cfg(not(unix))]
        Self::set_private_file_permissions_best_effort(&tmp_path);

        let had_existing = path.exists();

        if had_existing {
            fs::rename(path, &backup_path).map_err(|e| {
                if let Err(_cleanup_err) = fs::remove_file(&tmp_path) {
                    // Best-effort cleanup only. Preserve and return the original rename error below.
                }

                ErrorDetection::IoError {
                    message: format!(
                        "Failed to move existing private wallet index '{}' to backup '{}': {e}",
                        path.display(),
                        backup_path.display()
                    ),
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                }
            })?;
        }

        if let Err(e) = fs::rename(&tmp_path, path) {
            if let Err(_cleanup_err) = fs::remove_file(&tmp_path) {
                // Best-effort cleanup only. Preserve and return the original rename error below.
            }

            if had_existing
                && backup_path.exists()
                && let Err(_restore_err) = fs::rename(&backup_path, path)
            {
                // Best-effort rollback only. Preserve and return the original rename error below.
            }

            return Err(ErrorDetection::IoError {
                message: format!(
                    "Failed to move private wallet index temp file '{}' to '{}': {e}",
                    tmp_path.display(),
                    path.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            });
        }

        if had_existing {
            Self::remove_file_if_exists(&backup_path)?;
        }

        Ok(())
    }

    fn remove_file_if_exists(path: &Path) -> Result<(), ErrorDetection> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ErrorDetection::IoError {
                message: format!("Failed to remove file '{}': {e}", path.display()),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            }),
        }
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

impl PrivateWalletIndexEntry {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        PrivateWI::validate_entry(self)
    }

    pub fn short_one_time_wallet(&self) -> Result<String, ErrorDetection> {
        PrivateRI::short_wallet(&self.one_time_wallet)
    }
}

impl PrivateWalletIndexFile {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        PrivateWI::validate_index_file(self)
    }

    pub fn total_entries(&self) -> usize {
        self.entries_by_owner.values().map(Vec::len).sum()
    }

    pub fn owner_count(&self) -> usize {
        self.entries_by_owner.len()
    }
}
