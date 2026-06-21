use std::fs;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};

/// Maximum allowed file size for off-chain sharing (5 MiB).
pub const MAX_P2P_FILE_BYTES: usize = 5 * 1024 * 1024;

/// Chunk size for file transfer (32 KiB).
pub const FILE_CHUNK_SIZE: usize = 32 * 1024;

/// Maximum number of chunks allowed for a single file, derived from
#[allow(clippy::cast_possible_truncation)]
pub const MAX_TOTAL_CHUNKS: u32 = (MAX_P2P_FILE_BYTES.div_ceil(FILE_CHUNK_SIZE)) as u32;

/* ─────────────────────────────────────────────────────────────
   Paranoia bounds (cheap, non-crypto)
───────────────────────────────────────────────────────────── */

/// `file_id` is the raw 32-byte BLAKE3 digest of the full file.
const FILE_ID_BYTES: usize = 32;

/// Hex length for a 32-byte BLAKE3 digest.
const CONTENT_HASH_HEX_LEN: usize = FILE_ID_BYTES * 2;

/// Cap filenames to prevent log/path abuse; we keep only file_name anyway.
const MAX_FILENAME_LEN: usize = 255;

/// Allow some slack for clock skew; reject absurd future timestamps.
const MAX_FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Clone)]
struct CanonicalChunkMeta {
    from_wallet: String,
    to_wallet: String,
    filename: String,
    content_hash_hex: String,
}

#[inline(always)]
fn canonicalize_wallet_str(label: &'static str, s: &str) -> Result<String, ErrorDetection> {
    let trimmed = s.trim();

    if trimmed.is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: format!("{} wallet is empty", label),
            tx_id: None,
        });
    }

    if trimmed.len() != REMZAR_WALLET_LEN {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "{} wallet has invalid length: {} chars (expected {})",
                label,
                trimmed.len(),
                REMZAR_WALLET_LEN
            ),
            tx_id: None,
        });
    }

    canon_wallet_id_checked(trimmed)
}

#[inline(always)]
fn canonicalize_content_hash_hex(input: &str) -> Result<String, ErrorDetection> {
    let s = input.trim().to_ascii_lowercase();

    if s.len() != CONTENT_HASH_HEX_LEN {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "content_hash_hex has invalid length: {} chars (expected {})",
                s.len(),
                CONTENT_HASH_HEX_LEN
            ),
            tx_id: None,
        });
    }

    if !s
        .as_bytes()
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ErrorDetection::ValidationError {
            message: "content_hash_hex contains non-hex characters".into(),
            tx_id: None,
        });
    }

    Ok(s)
}

#[inline(always)]
fn validate_file_identity_consistency(
    file_id: &[u8; FILE_ID_BYTES],
    content_hash_hex: &str,
) -> Result<(), ErrorDetection> {
    let canonical_hash = canonicalize_content_hash_hex(content_hash_hex)?;
    let encoded_file_id = hex::encode(file_id);

    if encoded_file_id != canonical_hash {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "file identity mismatch: file_id hex {} != content_hash_hex {}",
                encoded_file_id, canonical_hash
            ),
            tx_id: None,
        });
    }

    Ok(())
}

/// Keep only a safe filename component (no directories).
#[inline(always)]
fn sanitize_filename(input: &str) -> Result<String, ErrorDetection> {
    let trimmed = input.trim();

    let name = Path::new(trimmed)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unnamed_file");

    if name.is_empty() {
        return Ok("unnamed_file".to_string());
    }

    if name.len() > MAX_FILENAME_LEN {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "filename too long: {} bytes (max {})",
                name.len(),
                MAX_FILENAME_LEN
            ),
            tx_id: None,
        });
    }

    // Reject control chars and NUL to keep logs/fs safe.
    if name.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(ErrorDetection::ValidationError {
            message: "filename contains invalid control characters".into(),
            tx_id: None,
        });
    }

    Ok(name.to_string())
}

#[inline(always)]
fn validate_timestamp_ms(ts: u64) -> Result<(), ErrorDetection> {
    let now = Utc::now().timestamp_millis();
    let ts_i = i64::try_from(ts).unwrap_or(i64::MAX);

    if ts_i > now.saturating_add(MAX_FUTURE_SKEW_MS) {
        return Err(ErrorDetection::ValidationError {
            message: format!("timestamp_ms too far in the future: {}", ts),
            tx_id: None,
        });
    }

    Ok(())
}

#[inline(always)]
fn expected_total_chunks(file_size_bytes: u64) -> Result<u32, ErrorDetection> {
    if file_size_bytes == 0 {
        return Err(ErrorDetection::ValidationError {
            message: "file_size_bytes cannot be zero".into(),
            tx_id: None,
        });
    }

    let size_usize =
        usize::try_from(file_size_bytes).map_err(|_| ErrorDetection::ValidationError {
            message: format!(
                "declared file_size_bytes {} cannot be represented as usize",
                file_size_bytes
            ),
            tx_id: None,
        })?;

    if size_usize > MAX_P2P_FILE_BYTES {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "declared file_size_bytes {} exceeds MAX_P2P_FILE_BYTES {}",
                file_size_bytes, MAX_P2P_FILE_BYTES
            ),
            tx_id: None,
        });
    }

    let chunks_usize = size_usize.div_ceil(FILE_CHUNK_SIZE);
    let chunks = u32::try_from(chunks_usize).map_err(|_| ErrorDetection::ValidationError {
        message: format!(
            "computed total_chunks {} cannot be represented as u32",
            chunks_usize
        ),
        tx_id: None,
    })?;

    if chunks == 0 || chunks > MAX_TOTAL_CHUNKS {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "computed total_chunks {} out of bounds (MAX_TOTAL_CHUNKS={})",
                chunks, MAX_TOTAL_CHUNKS
            ),
            tx_id: None,
        });
    }

    Ok(chunks)
}

#[inline(always)]
fn validate_chunk_len_for_index(
    file_size_bytes: u64,
    total_chunks: u32,
    chunk_index: u32,
    chunk_len: usize,
) -> Result<(), ErrorDetection> {
    if chunk_len == 0 {
        return Err(ErrorDetection::ValidationError {
            message: format!("received empty chunk at index {}", chunk_index),
            tx_id: None,
        });
    }

    if chunk_len > FILE_CHUNK_SIZE {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "chunk {} has size {} which exceeds FILE_CHUNK_SIZE {}",
                chunk_index, chunk_len, FILE_CHUNK_SIZE
            ),
            tx_id: None,
        });
    }

    if total_chunks == 0 {
        return Err(ErrorDetection::ValidationError {
            message: "total_chunks cannot be zero".into(),
            tx_id: None,
        });
    }

    if chunk_index >= total_chunks {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "chunk_index {} out of range (total_chunks={})",
                chunk_index, total_chunks
            ),
            tx_id: None,
        });
    }

    let size_usize =
        usize::try_from(file_size_bytes).map_err(|_| ErrorDetection::ValidationError {
            message: format!(
                "file_size_bytes {} cannot be represented as usize",
                file_size_bytes
            ),
            tx_id: None,
        })?;

    let rem = size_usize % FILE_CHUNK_SIZE;
    let last_len = if rem == 0 { FILE_CHUNK_SIZE } else { rem };

    let is_last = chunk_index
        .checked_add(1)
        .is_some_and(|next| next == total_chunks);

    if is_last {
        if chunk_len != last_len {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "last chunk size mismatch at idx {}: got {}, expected {}",
                    chunk_index, chunk_len, last_len
                ),
                tx_id: None,
            });
        }
    } else if chunk_len != FILE_CHUNK_SIZE {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "non-last chunk size mismatch at idx {}: got {}, expected {}",
                chunk_index, chunk_len, FILE_CHUNK_SIZE
            ),
            tx_id: None,
        });
    }

    Ok(())
}

#[inline(always)]
fn validate_chunk_message_metadata(
    chunk: &FileChunkMessage,
) -> Result<CanonicalChunkMeta, ErrorDetection> {
    let from_wallet = canonicalize_wallet_str("from", &chunk.from_wallet)?;
    let to_wallet = canonicalize_wallet_str("to", &chunk.to_wallet)?;

    if from_wallet == to_wallet {
        return Err(ErrorDetection::ValidationError {
            message: "from_wallet and to_wallet cannot be the same".into(),
            tx_id: None,
        });
    }

    let filename = sanitize_filename(&chunk.filename)?;
    let content_hash_hex = canonicalize_content_hash_hex(&chunk.content_hash_hex)?;

    validate_file_identity_consistency(&chunk.file_id, &content_hash_hex)?;
    validate_timestamp_ms(chunk.timestamp_ms)?;

    let expected_chunks = expected_total_chunks(chunk.file_size_bytes)?;
    if chunk.total_chunks != expected_chunks {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "chunk total_chunks {} inconsistent with file_size_bytes {} (expected {})",
                chunk.total_chunks, chunk.file_size_bytes, expected_chunks
            ),
            tx_id: None,
        });
    }

    validate_chunk_len_for_index(
        chunk.file_size_bytes,
        chunk.total_chunks,
        chunk.chunk_index,
        chunk.chunk_bytes.len(),
    )?;

    Ok(CanonicalChunkMeta {
        from_wallet,
        to_wallet,
        filename,
        content_hash_hex,
    })
}

/// Message used for p2p file transfer.
/// This is what will eventually be carried by `NetCmd::SendFileChunk(...)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkMessage {
    /// Stable id for the whole file (BLAKE3 digest of the full file).
    /// Intentionally 32-byte: BLAKE3 digest size is 32 bytes.
    pub file_id: [u8; 32],

    /// Wallet that originated the transfer.
    pub from_wallet: String,

    /// Wallet that should receive the file.
    pub to_wallet: String,

    /// Zero-based chunk index.
    pub chunk_index: u32,

    /// Total number of chunks for this file.
    pub total_chunks: u32,

    /// Optional human filename (kept for convenience).
    pub filename: String,

    /// Total file size in bytes (same on every chunk).
    pub file_size_bytes: u64,

    /// BLAKE3 hex digest of the full file (same on every chunk).
    pub content_hash_hex: String,

    /// Actual payload for this chunk.
    pub chunk_bytes: Vec<u8>,

    /// Wall-clock timestamp for when the sender created this chunk.
    pub timestamp_ms: u64,
}

impl FileChunkMessage {
    /// Strict standalone validation for an incoming chunk message.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        let _ = validate_chunk_message_metadata(self)?;
        Ok(())
    }
}

/// Sender-side representation of a file to be sent off-chain.
#[derive(Debug, Clone)]
pub struct SendFile {
    pub file_id: [u8; 32],
    pub from_wallet: String,
    pub to_wallet: String,
    pub filename: String,
    pub file_size_bytes: u64,
    pub content_hash_hex: String,
    pub total_chunks: u32,
    pub created_at_ms: u64,
    bytes: Vec<u8>,
}

impl SendFile {
    /// Load a file from disk, enforce size bounds, compute BLAKE3 hash
    /// and prepare metadata for chunking.
    pub fn from_path<P: AsRef<Path>>(
        from_wallet: String,
        to_wallet: String,
        path: P,
    ) -> Result<Self, ErrorDetection> {
        let from_wallet = canonicalize_wallet_str("from", &from_wallet)?;
        let to_wallet = canonicalize_wallet_str("to", &to_wallet)?;

        if from_wallet == to_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "from_wallet and to_wallet cannot be the same".into(),
                tx_id: None,
            });
        }

        let path_ref = path.as_ref();

        let metadata = fs::metadata(path_ref).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to stat file {}: {e}", path_ref.display()),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !metadata.is_file() {
            return Err(ErrorDetection::ValidationError {
                message: format!("Path is not a regular file: {}", path_ref.display()),
                tx_id: None,
            });
        }

        let file_len =
            usize::try_from(metadata.len()).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "File {} is too large to represent on this platform",
                    path_ref.display()
                ),
                tx_id: None,
            })?;

        if file_len == 0 {
            return Err(ErrorDetection::ValidationError {
                message: format!("File {} is empty", path_ref.display()),
                tx_id: None,
            });
        }

        if file_len > MAX_P2P_FILE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "File {} is too large for off-chain transfer: {} bytes (max {} bytes)",
                    path_ref.display(),
                    file_len,
                    MAX_P2P_FILE_BYTES
                ),
                tx_id: None,
            });
        }

        let bytes = fs::read(path_ref).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to read file {}: {e}", path_ref.display()),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if bytes.len() != file_len {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "File size changed while reading {}: metadata={} bytes, read={} bytes",
                    path_ref.display(),
                    file_len,
                    bytes.len()
                ),
                tx_id: None,
            });
        }

        let mut hasher = Hasher::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();

        let mut file_id = [0u8; 32];
        file_id.copy_from_slice(digest.as_bytes());

        let content_hash_hex = hex::encode(digest.as_bytes());
        validate_file_identity_consistency(&file_id, &content_hash_hex)?;

        let file_size_bytes =
            u64::try_from(bytes.len()).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "File {} size cannot be represented as u64",
                    path_ref.display()
                ),
                tx_id: None,
            })?;

        let raw_filename = path_ref
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed_file");
        let filename = sanitize_filename(raw_filename)?;

        let total_chunks = expected_total_chunks(file_size_bytes)?;

        let created_at_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);

        Ok(Self {
            file_id,
            from_wallet,
            to_wallet,
            filename,
            file_size_bytes,
            content_hash_hex,
            total_chunks,
            created_at_ms,
            bytes,
        })
    }

    /// Return an iterator over `FileChunkMessage` values ready to be sent
    /// via `NetCmd::SendFileChunk`.
    pub fn iter_chunks(&self) -> impl Iterator<Item = FileChunkMessage> + '_ {
        let total_chunks = self.total_chunks;
        let file_id = self.file_id;
        let from_wallet = self.from_wallet.clone();
        let to_wallet = self.to_wallet.clone();
        let filename = self.filename.clone();
        let file_size_bytes = self.file_size_bytes;
        let content_hash_hex = self.content_hash_hex.clone();

        self.bytes
            .chunks(FILE_CHUNK_SIZE)
            .enumerate()
            .map(move |(idx, chunk)| {
                let chunk_index = match u32::try_from(idx) {
                    Ok(v) => v,
                    Err(_) => {
                        debug_assert!(
                            false,
                            "iter_chunks: chunk index exceeds u32::MAX (invalid chunk enumeration)"
                        );
                        u32::MAX
                    }
                };

                let timestamp_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);

                FileChunkMessage {
                    file_id,
                    from_wallet: from_wallet.clone(),
                    to_wallet: to_wallet.clone(),
                    chunk_index,
                    total_chunks,
                    filename: filename.clone(),
                    file_size_bytes,
                    content_hash_hex: content_hash_hex.clone(),
                    chunk_bytes: chunk.to_vec(),
                    timestamp_ms,
                }
            })
    }
}

/// Receiver-side state for reconstructing a file from chunks.
#[derive(Debug)]
pub struct IncomingFile {
    pub file_id: [u8; 32],
    pub from_wallet: String,
    pub to_wallet: String,
    pub filename: String,
    pub file_size_bytes: u64,
    pub content_hash_hex: String,
    pub total_chunks: u32,
    received_chunks: Vec<Option<Vec<u8>>>,
    received_count: u32,
    received_total_bytes: u64,
}

impl IncomingFile {
    /// Strict constructor that validates the first chunk metadata.
    pub fn from_first_chunk_checked(chunk: &FileChunkMessage) -> Result<Self, ErrorDetection> {
        let meta = validate_chunk_message_metadata(chunk)?;
        let total_chunks = expected_total_chunks(chunk.file_size_bytes)?;

        let total_chunks_usize =
            usize::try_from(total_chunks).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "total_chunks {} cannot be represented as usize",
                    total_chunks
                ),
                tx_id: None,
            })?;

        let mut received_chunks = Vec::with_capacity(total_chunks_usize);
        received_chunks.resize_with(total_chunks_usize, || None);

        Ok(Self {
            file_id: chunk.file_id,
            from_wallet: meta.from_wallet,
            to_wallet: meta.to_wallet,
            filename: meta.filename,
            file_size_bytes: chunk.file_size_bytes,
            content_hash_hex: meta.content_hash_hex,
            total_chunks,
            received_chunks,
            received_count: 0,
            received_total_bytes: 0,
        })
    }

    /// Backward-compatible constructor.
    /// Prefer `from_first_chunk_checked()` in new call sites.
    pub fn from_first_chunk(chunk: &FileChunkMessage) -> Self {
        match Self::from_first_chunk_checked(chunk) {
            Ok(v) => v,
            Err(_) => {
                let safe_total_chunks = chunk.total_chunks.min(MAX_TOTAL_CHUNKS);
                let safe_total_chunks_usize = usize::try_from(safe_total_chunks).unwrap_or(0);

                let mut received_chunks = Vec::with_capacity(safe_total_chunks_usize);
                received_chunks.resize_with(safe_total_chunks_usize, || None);

                let filename =
                    sanitize_filename(&chunk.filename).unwrap_or_else(|_| "unnamed_file".into());
                let content_hash_hex = canonicalize_content_hash_hex(&chunk.content_hash_hex)
                    .unwrap_or_else(|_| String::new());

                IncomingFile {
                    file_id: chunk.file_id,
                    from_wallet: chunk.from_wallet.trim().to_string(),
                    to_wallet: chunk.to_wallet.trim().to_string(),
                    filename,
                    file_size_bytes: chunk.file_size_bytes,
                    content_hash_hex,
                    total_chunks: safe_total_chunks,
                    received_chunks,
                    received_count: 0,
                    received_total_bytes: 0,
                }
            }
        }
    }

    #[inline]
    fn validate_state_metadata(&self) -> Result<(), ErrorDetection> {
        let _ = canonicalize_wallet_str("from", &self.from_wallet)?;
        let _ = canonicalize_wallet_str("to", &self.to_wallet)?;

        if self.from_wallet == self.to_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: from_wallet and to_wallet cannot be the same".into(),
                tx_id: None,
            });
        }

        let _ = sanitize_filename(&self.filename)?;
        validate_file_identity_consistency(&self.file_id, &self.content_hash_hex)?;

        if self.file_size_bytes == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: file_size_bytes cannot be zero".into(),
                tx_id: None,
            });
        }

        let file_size_usize =
            usize::try_from(self.file_size_bytes).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: file_size_bytes {} cannot be represented as usize",
                    self.file_size_bytes
                ),
                tx_id: None,
            })?;

        if file_size_usize > MAX_P2P_FILE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: declared file_size_bytes {} exceeds MAX_P2P_FILE_BYTES {}",
                    self.file_size_bytes, MAX_P2P_FILE_BYTES
                ),
                tx_id: None,
            });
        }

        if self.total_chunks == 0 || self.total_chunks > MAX_TOTAL_CHUNKS {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: invalid total_chunks {} (MAX_TOTAL_CHUNKS={})",
                    self.total_chunks, MAX_TOTAL_CHUNKS
                ),
                tx_id: None,
            });
        }

        let expected_chunks = expected_total_chunks(self.file_size_bytes)?;
        if expected_chunks != self.total_chunks {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: total_chunks {} inconsistent with file_size_bytes {} (expected {})",
                    self.total_chunks, self.file_size_bytes, expected_chunks
                ),
                tx_id: None,
            });
        }

        let slots_len =
            usize::try_from(self.total_chunks).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: total_chunks {} cannot be represented as usize",
                    self.total_chunks
                ),
                tx_id: None,
            })?;

        if self.received_chunks.len() != slots_len {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: received_chunks len {} != total_chunks {}",
                    self.received_chunks.len(),
                    self.total_chunks
                ),
                tx_id: None,
            });
        }

        if self.received_count > self.total_chunks {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: received_count {} exceeds total_chunks {}",
                    self.received_count, self.total_chunks
                ),
                tx_id: None,
            });
        }

        if self.received_total_bytes > self.file_size_bytes {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: received_total_bytes {} exceeds file_size_bytes {}",
                    self.received_total_bytes, self.file_size_bytes
                ),
                tx_id: None,
            });
        }

        if self.received_total_bytes > MAX_P2P_FILE_BYTES as u64 {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: received_total_bytes {} exceeds MAX_P2P_FILE_BYTES {}",
                    self.received_total_bytes, MAX_P2P_FILE_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn apply_chunk(&mut self, chunk: FileChunkMessage) -> Result<(), ErrorDetection> {
        self.validate_state_metadata()?;

        let meta = validate_chunk_message_metadata(&chunk)?;

        if chunk.file_id != self.file_id {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: file_id mismatch on chunk".into(),
                tx_id: None,
            });
        }

        if meta.from_wallet != self.from_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: from_wallet mismatch on chunk".into(),
                tx_id: None,
            });
        }

        if meta.to_wallet != self.to_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: to_wallet mismatch on chunk".into(),
                tx_id: None,
            });
        }

        if meta.filename != self.filename {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: filename mismatch on chunk".into(),
                tx_id: None,
            });
        }

        if chunk.total_chunks != self.total_chunks {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: total_chunks mismatch on chunk".into(),
                tx_id: None,
            });
        }

        if chunk.file_size_bytes != self.file_size_bytes {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: file_size_bytes mismatch on chunk".into(),
                tx_id: None,
            });
        }

        if meta.content_hash_hex != self.content_hash_hex {
            return Err(ErrorDetection::ValidationError {
                message: "IncomingFile: content_hash_hex mismatch on chunk".into(),
                tx_id: None,
            });
        }

        let idx =
            usize::try_from(chunk.chunk_index).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: chunk_index {} cannot be represented as usize",
                    chunk.chunk_index
                ),
                tx_id: None,
            })?;

        if idx >= self.received_chunks.len() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: chunk_index {} out of range (total_chunks={})",
                    idx, self.total_chunks
                ),
                tx_id: None,
            });
        }

        if let Some(existing) = self.received_chunks.get(idx).and_then(|slot| slot.as_ref()) {
            if existing == &chunk.chunk_bytes {
                return Ok(());
            }

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: conflicting duplicate payload for chunk {}",
                    chunk.chunk_index
                ),
                tx_id: None,
            });
        }

        let chunk_len_u64 = u64::try_from(chunk.chunk_bytes.len()).map_err(|_| {
            ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: chunk {} length cannot be represented as u64",
                    chunk.chunk_index
                ),
                tx_id: None,
            }
        })?;

        let new_total = self
            .received_total_bytes
            .checked_add(chunk_len_u64)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "IncomingFile: received_total_bytes overflow".into(),
                tx_id: None,
            })?;

        if new_total > self.file_size_bytes {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: cumulative chunk payload {} exceeds declared file_size_bytes {}",
                    new_total, self.file_size_bytes
                ),
                tx_id: None,
            });
        }

        if new_total > MAX_P2P_FILE_BYTES as u64 {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: cumulative chunk payload {} bytes would exceed MAX_P2P_FILE_BYTES {}",
                    new_total, MAX_P2P_FILE_BYTES
                ),
                tx_id: None,
            });
        }

        let received_chunks_len = self.received_chunks.len();
        *self
            .received_chunks
            .get_mut(idx)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: chunk index {} out of bounds (len {})",
                    idx, received_chunks_len
                ),
                tx_id: None,
            })? = Some(chunk.chunk_bytes);

        self.received_count =
            self.received_count
                .checked_add(1)
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: "IncomingFile: received_count overflow".into(),
                    tx_id: None,
                })?;

        self.received_total_bytes = new_total;

        Ok(())
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.received_count == self.total_chunks
    }

    #[allow(clippy::too_many_lines)]
    pub fn into_verified_bytes(self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate_state_metadata()?;

        let actual_present = self
            .received_chunks
            .iter()
            .filter(|slot| slot.is_some())
            .count();
        let actual_present_u32 =
            u32::try_from(actual_present).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: actual present chunk count {} cannot be represented as u32",
                    actual_present
                ),
                tx_id: None,
            })?;

        if actual_present_u32 != self.received_count {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: internal chunk accounting mismatch (received_count={}, actual_present={})",
                    self.received_count, actual_present_u32
                ),
                tx_id: None,
            });
        }

        if self.received_count != self.total_chunks {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: incomplete (have {}, need {})",
                    self.received_count, self.total_chunks
                ),
                tx_id: None,
            });
        }

        let file_size_usize =
            usize::try_from(self.file_size_bytes).map_err(|_| ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: file_size_bytes {} cannot fit into usize on this platform",
                    self.file_size_bytes
                ),
                tx_id: None,
            })?;

        let mut all_bytes = Vec::with_capacity(file_size_usize);

        for (i, maybe_chunk) in self.received_chunks.into_iter().enumerate() {
            let chunk = maybe_chunk.ok_or_else(|| ErrorDetection::ValidationError {
                message: format!("IncomingFile: missing chunk {}", i),
                tx_id: None,
            })?;

            let reconstructed_size = all_bytes.len().checked_add(chunk.len()).ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: format!(
                        "IncomingFile: reconstructed size would overflow at chunk {}",
                        i
                    ),
                    tx_id: None,
                }
            })?;

            if reconstructed_size > MAX_P2P_FILE_BYTES {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "IncomingFile: reconstructed size would exceed MAX_P2P_FILE_BYTES {} at chunk {}",
                        MAX_P2P_FILE_BYTES, i
                    ),
                    tx_id: None,
                });
            }

            all_bytes.extend_from_slice(&chunk);
        }

        if all_bytes.len() != file_size_usize {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: reconstructed size {} != expected {}",
                    all_bytes.len(),
                    file_size_usize
                ),
                tx_id: None,
            });
        }

        let mut hasher = Hasher::new();
        hasher.update(&all_bytes);
        let digest = hasher.finalize();
        let hash_hex = hex::encode(digest.as_bytes());

        if hash_hex != self.content_hash_hex {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: BLAKE3 mismatch (got {}, expected {})",
                    hash_hex, self.content_hash_hex
                ),
                tx_id: None,
            });
        }

        let file_id_hex = hex::encode(self.file_id);
        if file_id_hex != hash_hex {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "IncomingFile: reconstructed digest {} does not match file_id {}",
                    hash_hex, file_id_hex
                ),
                tx_id: None,
            });
        }

        Ok(all_bytes)
    }

    #[must_use]
    pub fn suggested_output_path(&self, base_dir: &Path) -> PathBuf {
        let mut p = base_dir.to_path_buf();
        let encoded_id = hex::encode(self.file_id);
        let id_prefix = encoded_id.get(..16).unwrap_or(&encoded_id);
        let safe_name = sanitize_filename(&self.filename).unwrap_or_else(|_| "unnamed_file".into());
        let name = format!("{}_{}", id_prefix, safe_name);
        p.push(name);
        p
    }
}
