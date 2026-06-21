use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const DB_LOCK_FILE_NAME: &str = ".remzar_db.lock";
const DB_OWNER_FILE_NAME: &str = "OWNER";
const MAX_NODE_ID_BYTES: usize = 256;

/// Holds the process-level DB ownership lock for as long as this value lives.
pub struct DbGuard {
    _lock: File,
    pub db_dir: PathBuf,
    pub owner_path: PathBuf,
    pub lock_path: PathBuf,
}

pub fn enforce_db_ownership(db_dir: &Path, node_id: &str) -> Result<DbGuard, ErrorDetection> {
    validate_node_id(node_id)?;

    // Ensure dir exists before validation/canonicalization.
    fs::create_dir_all(db_dir).map_err(|e| ErrorDetection::StorageError {
        message: format!("Failed to create DB dir {}: {}", db_dir.display(), e),
    })?;

    // Refuse symlink DB roots before canonicalizing. Canonicalization resolves
    // symlinks, so the symlink check must happen on the caller-provided path.
    let meta = fs::symlink_metadata(db_dir).map_err(|e| ErrorDetection::StorageError {
        message: format!("Failed to stat DB dir {}: {}", db_dir.display(), e),
    })?;

    if meta.file_type().is_symlink() {
        return Err(ErrorDetection::StorageError {
            message: format!(
                "Refusing DB dir symlink for ownership guard: {}",
                db_dir.display()
            ),
        });
    }

    if !meta.is_dir() {
        return Err(ErrorDetection::StorageError {
            message: format!("DB path is not a directory: {}", db_dir.display()),
        });
    }

    // Canonicalize so different spellings of the same path map to one lock.
    let canonical_db_dir = fs::canonicalize(db_dir).map_err(|e| ErrorDetection::StorageError {
        message: format!("Failed to canonicalize DB dir {}: {}", db_dir.display(), e),
    })?;

    let lock_path = canonical_db_dir.join(DB_LOCK_FILE_NAME);
    reject_symlink_if_present(&lock_path, "DB lockfile")?;

    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| ErrorDetection::DatabaseError {
            details: format!("Failed to open lockfile {}: {}", lock_path.display(), e),
        })?;

    lock.try_lock().map_err(|e| ErrorDetection::DatabaseError {
        details: format!(
            "Blockchain DB is already in use (ownership lock held): {} ({})",
            canonical_db_dir.display(),
            e
        ),
    })?;

    // Owner binding is checked only after the process lock is held.
    let owner_path = canonical_db_dir.join(DB_OWNER_FILE_NAME);
    reject_symlink_if_present(&owner_path, "DB OWNER file")?;

    match fs::read_to_string(&owner_path) {
        Ok(owner) => {
            let owner_trim = owner.trim();
            validate_node_id(owner_trim)?;

            if owner_trim != node_id {
                return Err(ErrorDetection::DatabaseError {
                    details: format!(
                        "DB ownership mismatch. DB owner='{}', this node='{}' (dir={})",
                        owner_trim,
                        node_id,
                        canonical_db_dir.display()
                    ),
                });
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            write_owner_file_atomic(&owner_path, node_id)?;
        }
        Err(err) => {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "Failed reading OWNER file {}: {}",
                    owner_path.display(),
                    err
                ),
            });
        }
    }

    Ok(DbGuard {
        _lock: lock,
        db_dir: canonical_db_dir,
        owner_path,
        lock_path,
    })
}

fn validate_node_id(node_id: &str) -> Result<(), ErrorDetection> {
    let trimmed = node_id.trim();

    if trimmed.is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: "DB owner node_id must be non-empty".into(),
            tx_id: None,
        });
    }

    if trimmed != node_id {
        return Err(ErrorDetection::ValidationError {
            message: "DB owner node_id must not contain leading/trailing whitespace".into(),
            tx_id: None,
        });
    }

    if node_id.len() > MAX_NODE_ID_BYTES {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "DB owner node_id is too long: {} > {} bytes",
                node_id.len(),
                MAX_NODE_ID_BYTES
            ),
            tx_id: None,
        });
    }

    if node_id.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(ErrorDetection::ValidationError {
            message: "DB owner node_id contains ASCII control bytes".into(),
            tx_id: None,
        });
    }

    if node_id.contains('/') || node_id.contains('\\') {
        return Err(ErrorDetection::ValidationError {
            message: "DB owner node_id must not contain path separators".into(),
            tx_id: None,
        });
    }

    Ok(())
}

fn reject_symlink_if_present(path: &Path, label: &str) -> Result<(), ErrorDetection> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(ErrorDetection::StorageError {
            message: format!("Refusing symlink {}: {}", label, path.display()),
        }),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ErrorDetection::StorageError {
            message: format!("Failed to stat {} {}: {}", label, path.display(), err),
        }),
    }
}

fn write_owner_file_atomic(owner_path: &Path, node_id: &str) -> Result<(), ErrorDetection> {
    let parent = owner_path
        .parent()
        .ok_or_else(|| ErrorDetection::StorageError {
            message: format!("OWNER path has no parent: {}", owner_path.display()),
        })?;

    let tmp = parent.join(format!(
        ".OWNER.tmp.{}.{}",
        std::process::id(),
        monotonic_tmp_suffix()
    ));

    // Remove a stale same-process temp file if one exists.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(ErrorDetection::StorageError {
                message: format!("Failed removing stale OWNER tmp {}: {}", tmp.display(), err),
            });
        }
    }

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| ErrorDetection::StorageError {
            message: format!("Failed creating OWNER tmp {}: {}", tmp.display(), e),
        })?;

    file.write_all(node_id.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|e| ErrorDetection::StorageError {
            message: format!("Failed writing OWNER tmp {}: {}", tmp.display(), e),
        })?;

    drop(file);

    fs::rename(&tmp, owner_path).map_err(|e| ErrorDetection::StorageError {
        message: format!(
            "Failed atomically installing OWNER file {} from {}: {}",
            owner_path.display(),
            tmp.display(),
            e
        ),
    })?;

    Ok(())
}

fn monotonic_tmp_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
