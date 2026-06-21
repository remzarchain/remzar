// src/network/p2p_015_chat_store.rs

use crate::network::p2p_014_chat::ChatMessage;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;

use fips204::ml_dsa_65;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Defensive cap for JSONL line size.
const MAX_CHAT_JSONL_LINE_BYTES: usize = 4096;

/// Defensive cap for on-disk chat logs (per file).
const MAX_CHAT_LOG_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Path base: <opts.data_dir>/json.chat
fn chat_log_path(opts: &NodeOpts) -> PathBuf {
    let mut base = PathBuf::from(&opts.data_dir);
    base.push("json.chat");
    base
}

/// Ensure we are not about to write to a symlink path.
/// This blocks trivial "symlink to /etc/passwd" style log clobbering.
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

/// Rotate the file if it exceeds `MAX_CHAT_LOG_FILE_BYTES`.
/// Simple and robust: rename to `.1` (overwriting prior `.1` if present).
fn rotate_if_too_large(file_path: &Path) -> io::Result<()> {
    if let Ok(meta) = fs::metadata(file_path)
        && meta.len() >= MAX_CHAT_LOG_FILE_BYTES
    {
        let rotated = file_path.with_extension("jsonl.1");

        // Best-effort cleanup of old rotated file.
        _ = fs::remove_file(&rotated);

        fs::rename(file_path, &rotated)?;
    }
    Ok(())
}

/// Serialize `ChatMessage` to a single-line JSON string, with size caps and no panic.
/// Returns a line WITHOUT trailing newline.
fn encode_chat_jsonl_line(chat: &ChatMessage) -> io::Result<String> {
    if chat.json.len() > crate::network::p2p_014_chat::MAX_CHAT_JSON_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("chat.json too large for logging: {} bytes", chat.json.len()),
        ));
    }
    if chat.signature.len() != ml_dsa_65::SIG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "chat.signature invalid length for logging: {} bytes (expected {})",
                chat.signature.len(),
                ml_dsa_65::SIG_LEN
            ),
        ));
    }

    let line = serde_json::to_string(chat).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialize ChatMessage as JSON: {e}"),
        )
    })?;

    // Hard cap on a single JSONL line (defensive).
    if line.len() > MAX_CHAT_JSONL_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "chat JSONL line too large: {} bytes (max {})",
                line.len(),
                MAX_CHAT_JSONL_LINE_BYTES
            ),
        ));
    }

    Ok(line)
}

/// Internal helper: append a JSONL line to the given file, with paranoia wiring.
fn append_jsonl_line(dir: &Path, file_path: &Path, line: &str) -> io::Result<()> {
    // Ensure directory exists and is not a symlink
    refuse_symlink(dir)?;
    fs::create_dir_all(dir)?;

    // Refuse symlink file target
    refuse_symlink(file_path)?;

    // Rotate if the log is growing too large
    rotate_if_too_large(file_path)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)?;

    // Write line + newline (atomic-ish per write call; still safe for JSONL).
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

/// Append one incoming ChatMessage as JSON to a .jsonl file.
pub fn save_incoming_chat(opts: &NodeOpts, chat: &ChatMessage) -> Result<(), std::io::Error> {
    let dir = chat_log_path(opts);
    let file_path = dir.join("received_chat.jsonl");

    let line = encode_chat_jsonl_line(chat)?;
    append_jsonl_line(&dir, &file_path, &line)
}

/// Append one OUTGOING ChatMessage as JSON to a .jsonl file.
pub fn save_outgoing_chat(opts: &NodeOpts, chat: &ChatMessage) -> Result<(), std::io::Error> {
    let dir = chat_log_path(opts);
    let file_path = dir.join("sent_chat.jsonl");

    let line = encode_chat_jsonl_line(chat)?;
    append_jsonl_line(&dir, &file_path, &line)
}
