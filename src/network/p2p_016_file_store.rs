// src/network/p2p_016_file_store.rs

use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::utility::send_file::{FileChunkMessage, IncomingFile};

use chrono::Utc;
use hex;
use once_cell::sync::Lazy;
use serde_json;
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

/// In-memory assembly state for incoming files, keyed by file_id (BLAKE3 digest).
static INCOMING_FILES: Lazy<Mutex<HashMap<[u8; 32], IncomingFile>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/* ───────────── paranoia knobs ───────────── */

/// Max number of simultaneously tracked incoming files.
/// Prevents memory DoS by spamming new file_ids.
const MAX_INCOMING_FILES: usize = 64;

/// Max total_chunks accepted for any single file (defensive).
/// If the sender tries to claim billions of chunks, we fail-fast.
const MAX_TOTAL_CHUNKS: u32 = 50_000;

/// Max filename length we'll allow when storing.
const MAX_FILENAME_BYTES: usize = 128;

/// Cap JSON line size we append (best-effort logging safety).
const MAX_JSONL_LINE_BYTES: usize = 7_500;

/// Cap per-log-file growth (best-effort rotation) to avoid disk-fill.
const MAX_LOG_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Cap reconstructed file size (best-effort).
/// This should be >= maximum allowed file size in send_file module.
const MAX_RECONSTRUCTED_FILE_BYTES: u64 = 128 * 1024 * 1024;

/* ───────────── path helpers ───────────── */

/// Base directory for incoming files:
///   <opts.data_dir>/receiver.file
fn receiver_base_dir(opts: &NodeOpts) -> PathBuf {
    let mut dir = PathBuf::from(&opts.data_dir);
    dir.push("receiver.file");
    dir
}

/// Base directory for outgoing file logs:
///   <opts.data_dir>/sender.file
fn sender_base_dir(opts: &NodeOpts) -> PathBuf {
    let mut dir = PathBuf::from(&opts.data_dir);
    dir.push("sender.file");
    dir
}

/// Refuse symlink path to avoid log/file clobbering via symlink tricks.
fn refuse_symlink(path: &Path) -> io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to write to symlink path: {}", path.display()),
        ));
    }
    Ok(())
}

/// Ensure path is within base_dir after normalization.
/// (We still rely on `IncomingFile::suggested_output_path`, but this is the belt.)
fn ensure_within_base(base: &Path, candidate: &Path) -> bool {
    // If candidate is absolute, reject.
    if candidate.is_absolute() {
        return false;
    }

    // Reject any ParentDir components to prevent traversal.
    for c in candidate.components() {
        if matches!(c, Component::ParentDir) {
            return false;
        }
    }

    // Join and check it starts with base (best-effort; symlinks are handled separately).
    let joined = base.join(candidate);
    joined.starts_with(base)
}

/// Very conservative filename sanitizer.
fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(MAX_FILENAME_BYTES));
    for b in name.as_bytes().iter().copied() {
        if out.len() >= MAX_FILENAME_BYTES {
            break;
        }
        let ch = b as char;
        let ok = ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_';
        out.push(if ok { ch } else { '_' });
    }
    if out.is_empty() {
        "file".to_string()
    } else {
        out
    }
}

/// Rotate a log file if it is too large.
/// Renames `<file>.jsonl` → `<file>.jsonl.1` (overwriting previous `.1`).
fn rotate_if_too_large(file_path: &Path) -> io::Result<()> {
    if let Ok(meta) = fs::metadata(file_path)
        && meta.len() >= MAX_LOG_FILE_BYTES
    {
        let rotated = file_path.with_extension("jsonl.1");
        _ = fs::remove_file(&rotated);
        fs::rename(file_path, &rotated)?;
    }
    Ok(())
}

/// Append a single JSONL line safely (no pretty JSON, capped line length).
fn append_jsonl_record(dir: &Path, file_path: &Path, record: &serde_json::Value) -> io::Result<()> {
    refuse_symlink(dir)?;
    fs::create_dir_all(dir)?;
    refuse_symlink(file_path)?;
    _ = rotate_if_too_large(file_path);

    let line = serde_json::to_string(record).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("json serialization failed: {e}"),
        )
    })?;

    if line.len() > MAX_JSONL_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "jsonl line too large: {} bytes (max {})",
                line.len(),
                MAX_JSONL_LINE_BYTES
            ),
        ));
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

/* ───────────── outgoing logging ───────────── */

/// Arguments for `save_outgoing_file` to avoid too-many-arguments lint.
pub struct SaveOutgoingFileArgs<'a> {
    pub file_id: [u8; 32],
    pub from_wallet: &'a str,
    pub to_wallet: &'a str,
    pub filename: &'a str,
    pub file_size_bytes: u64,
    pub content_hash_hex: &'a str,
    pub original_path: &'a str,
}

/// Best-effort: append an outgoing file-transfer JSON line to:
///   <data_dir>/sender.file/sent_files.jsonl
pub fn save_outgoing_file(opts: &NodeOpts, args: SaveOutgoingFileArgs<'_>) {
    let SaveOutgoingFileArgs {
        file_id,
        from_wallet,
        to_wallet,
        filename,
        file_size_bytes,
        content_hash_hex,
        original_path,
    } = args;

    // Fail-fast on obviously invalid sizes (prevents silly overflows later).
    if file_size_bytes > MAX_RECONSTRUCTED_FILE_BYTES {
        return;
    }

    let dir = sender_base_dir(opts);
    let file_path = dir.join("sent_files.jsonl");

    let record = serde_json::json!({
        "direction": "outgoing",
        "file_id": hex::encode(file_id),
        "from_wallet": from_wallet,
        "to_wallet": to_wallet,
        "filename": sanitize_filename(filename),
        "file_size_bytes": file_size_bytes,
        "content_hash_hex": content_hash_hex,
        "original_path": original_path,
        "timestamp_ms": Utc::now().timestamp_millis(),
    });

    drop(append_jsonl_record(&dir, &file_path, &record));
}

/* ───────────── incoming finalize ───────────── */

/// Internal helper: write a fully-verified incoming file to disk and
fn finalize_incoming_file(opts: &NodeOpts, incoming: IncomingFile) {
    let file_id = incoming.file_id;
    let base_dir = receiver_base_dir(opts);

    if refuse_symlink(&base_dir).is_err() {
        return;
    }
    if fs::create_dir_all(&base_dir).is_err() {
        return;
    }

    // Capture metadata we still need *after* consuming `incoming`.
    let from_wallet = incoming.from_wallet.clone();
    let to_wallet = incoming.to_wallet.clone();
    let filename_raw = incoming.filename.clone();
    let filename = sanitize_filename(&filename_raw);
    let file_size_bytes = incoming.file_size_bytes;
    let content_hash_hex = incoming.content_hash_hex.clone();

    // Fail-fast on insane sizes.
    if file_size_bytes > MAX_RECONSTRUCTED_FILE_BYTES {
        return;
    }

    // Suggested output path (we still validate below).
    let suggested = incoming.suggested_output_path(&base_dir);

    // Belt: ensure suggested path is within base and not absolute/traversal.
    // Also force sanitized filename if the suggested path embeds the raw filename.
    let encoded_id = hex::encode(file_id);
    let id_prefix = encoded_id.get(..12).unwrap_or(&encoded_id);
    let safe_rel = PathBuf::from(format!("{id_prefix}_{filename}"));

    let out_path = if suggested.starts_with(&base_dir) {
        // If suggested is under base_dir, keep it.
        // Convert to an owned PathBuf so match arms unify.
        let rel: PathBuf = match suggested.strip_prefix(&base_dir) {
            Ok(r) => r.to_path_buf(),
            Err(_) => safe_rel.clone(),
        };

        if ensure_within_base(&base_dir, &rel) {
            base_dir.join(&rel)
        } else {
            base_dir.join(&safe_rel)
        }
    } else {
        // Not under base_dir: use safe fallback.
        base_dir.join(&safe_rel)
    };

    if refuse_symlink(&out_path).is_err() {
        return;
    }

    // Reconstruct and verify bytes using existing logic (BLAKE3 + size).
    let bytes = match incoming.into_verified_bytes() {
        Ok(b) => b,
        Err(_) => {
            return;
        }
    };

    // Defensive re-check.
    if (bytes.len() as u64) != file_size_bytes {
        return;
    }

    if fs::write(&out_path, &bytes).is_err() {
        return;
    }

    println!(
        "{} [FILE][IN] stored file from={} to={} bytes={} path={}",
        Utc::now().to_rfc3339(),
        from_wallet,
        to_wallet,
        file_size_bytes,
        out_path.display()
    );

    // Append JSON index entry for received files.
    let index_path = base_dir.join("received_files.jsonl");

    let record = serde_json::json!({
        "direction": "incoming",
        "file_id": hex::encode(file_id),
        "from_wallet": from_wallet,
        "to_wallet": to_wallet,
        "filename": filename,
        "file_size_bytes": file_size_bytes,
        "content_hash_hex": content_hash_hex,
        "stored_at": out_path.display().to_string(),
        "timestamp_ms": Utc::now().timestamp_millis(),
    });

    drop(append_jsonl_record(&base_dir, &index_path, &record));
}

/* ───────────── incoming entry point ───────────── */

pub fn handle_incoming_file_chunk(chunk: FileChunkMessage, local_wallet: &str, opts: &NodeOpts) {
    // Only process files intended for this node.
    if local_wallet.is_empty() || !chunk.to_wallet.eq_ignore_ascii_case(local_wallet) {
        return;
    }

    // Fail-fast: prevent silly / hostile metadata.
    if chunk.total_chunks == 0 || chunk.total_chunks > MAX_TOTAL_CHUNKS {
        return;
    }

    if chunk.chunk_index >= chunk.total_chunks {
        return;
    }

    if chunk.file_size_bytes > MAX_RECONSTRUCTED_FILE_BYTES {
        return;
    }

    if chunk.filename.len() > 8 * MAX_FILENAME_BYTES {
        // Hard cap on wire filename size (even before sanitization).
        return;
    }

    let file_id = chunk.file_id;

    let mut guard = match INCOMING_FILES.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Capacity guard: refuse new file_ids if we're already tracking too many.
    if !guard.contains_key(&file_id) && guard.len() >= MAX_INCOMING_FILES {
        return;
    }

    // If first time we see this file_id, seed an IncomingFile from the chunk.
    let entry = guard
        .entry(file_id)
        .or_insert_with(|| IncomingFile::from_first_chunk(&chunk));

    // Apply the new chunk; IncomingFile enforces file_id / size / hash consistency.
    if entry.apply_chunk(chunk).is_err() {
        return;
    }

    // Not complete yet → nothing more to do this time.
    if !entry.is_complete() {
        return;
    }

    // Take ownership of the finished file and drop it from the map before heavy IO.
    let complete = match guard.remove(&file_id) {
        Some(f) => f,
        None => {
            return;
        }
    };
    drop(guard); // release mutex before writing to disk

    finalize_incoming_file(opts, complete);
}
