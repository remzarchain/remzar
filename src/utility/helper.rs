// src/utility/helper.rs

use crate::consensus::por_000_ephemeral_registration::RegistryData;
use crate::runtime::p2p_001_sync_builders::P2pSync;
use crate::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use blake3;
use fips204::ml_dsa_65;
use hex;
use once_cell::sync::Lazy;
use rust_rocksdb::Error as RocksDbError;
use rust_rocksdb::{DB, Options};
use serde::{Deserialize, Serialize};
use serde_bytes;
use std::path::PathBuf;
use std::time::Duration;
use std::{env, thread};

pub type KVResultIter = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), ErrorDetection>>>;
pub type KVVecResult = Result<Vec<(Vec<u8>, Vec<u8>)>, String>;

/// A single 64-byte sibling hash in the Merkle proof (canonical consensus hash).
pub type InclusionProof = Hash64;

pub const STATE_KEY: &[u8] = b"__account_state__";

// Global wallet registry with a 'static lifetime.
// In production, populate this registry via node registration.
pub static WALLET_REGISTRY: Lazy<RegistryData> = Lazy::new(RegistryData::new);

/// Smallest unit divisor: 1 Remzar = 100,000,000 Remzar units.
pub const UNIT_DIVISOR: u64 = 100_000_000;

/// Convert a floating-point Remzar amount to micro-units (1 Remzar = 100_000_000).
/// - This function is therefore **UI-only** and intentionally **ROUNDS to 8 decimals**.
/// - Consensus / mempool / tx construction must use `to_micro_units_str()` on the original user string.
///
/// Returns:
/// - `0` for non-finite, <= 0, or values that round to 0 at 8 decimals.
/// - `u64::MAX` if the value is positive finite but would overflow u64 when scaled.
///
/// This function is hardened against:
/// - NaN/Inf
/// - negative / zero
/// - overflow
/// - float->string weirdness (scientific notation never used here)
#[inline]
pub fn to_micro_units(amount: f64) -> u64 {
    if !amount.is_finite() || amount <= 0.0 {
        return 0;
    }

    // Round to 8 decimals for UI display behavior (NOT for tx construction).
    // This creates a canonical fixed-point decimal string.
    let s = format!("{amount:.8}");

    // Fast path: parse fixed-point string deterministically.
    let micro = to_micro_units_str(&s);
    if micro != 0 {
        return micro;
    }

    // If micro == 0 here, there are only two realistic possibilities:
    // 1) It rounded to exactly 0.00000000 (tiny positive) => return 0 (caller can reject).
    // 2) It overflowed the u64 range when scaled by 1e8 => saturate to u64::MAX.
    //
    // Determine overflow by examining the whole-part of the rounded 8-decimal string.
    // u64::MAX = 18446744073709551615 micro
    // max whole part at 8 decimals = 184467440737
    let s_trim = s.trim();
    let (whole_str, _frac_str) = match s_trim.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s_trim, ""),
    };
    let whole_str = if whole_str.is_empty() { "0" } else { whole_str };

    // Should never happen for format!("{amount:.8}"), but keep it defensive.
    if !whole_str.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }

    // Any whole part longer than 12 digits must overflow u64 when scaled by 1e8.
    if whole_str.len() > 12 {
        return u64::MAX;
    }

    // If exactly 12 digits, compare to the max whole part.
    if whole_str.len() == 12 && whole_str > "184467440737" {
        return u64::MAX;
    }

    // Otherwise it was tiny and rounded down to 0.00000000.
    0
}

/// Parse a human-readable Remzar amount into micro-units (1 Remzar = 100_000_000).
#[inline]
pub fn to_micro_units_str(s: &str) -> u64 {
    const SCALE: u64 = 100_000_000;
    const MAX_INPUT_LEN: usize = 64;

    let s = s.trim();
    if s.is_empty() || s.len() > MAX_INPUT_LEN {
        return 0;
    }

    if s.starts_with('-') || s.starts_with('+') {
        return 0;
    }
    if s.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
        return 0;
    }
    if s.contains('e') || s.contains('E') {
        return 0;
    }

    let (whole_part, frac_part) = match s.split_once('.') {
        Some((w, f)) => {
            if f.contains('.') {
                return 0;
            }
            (w, f)
        }
        None => (s, ""),
    };

    if whole_part.is_empty() && frac_part.is_empty() {
        return 0;
    }

    let whole_str = if whole_part.is_empty() {
        "0"
    } else {
        whole_part
    };
    if !whole_str.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }

    if !frac_part.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    if frac_part.len() > 8 {
        return 0;
    }

    let whole: u64 = match whole_str.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // Parse fractional digits and right-pad to 8 decimals.
    let mut frac: u64 = 0;
    for &b in frac_part.as_bytes() {
        // Avoid `b - b'0'` (arithmetic_side_effects); use checked_sub instead.
        let digit = match b.checked_sub(b'0') {
            Some(d) => u64::from(d),
            None => return 0,
        };

        frac = match frac.checked_mul(10).and_then(|v| v.checked_add(digit)) {
            Some(v) => v,
            None => return 0,
        };
    }

    for _ in frac_part.len()..8 {
        frac = match frac.checked_mul(10) {
            Some(v) => v,
            None => return 0,
        };
    }

    let whole_scaled = match whole.checked_mul(SCALE) {
        Some(v) => v,
        None => return 0,
    };

    whole_scaled.checked_add(frac).unwrap_or_default()
}

#[inline]
pub fn from_micro_units(amount: u64) -> f64 {
    let s = format_remzar(amount);

    s.parse::<f64>().unwrap_or(0.0)
}

/// Format micro-units as a human-readable decimal string: "<whole>.<8 digits>".
#[inline]
pub fn format_remzar(amount: u64) -> String {
    const UNIT_DIVISOR_U64: u64 = 100_000_000;

    // Integer split into whole + fractional micro-units.
    let whole = amount.div_euclid(UNIT_DIVISOR_U64);

    let frac = amount.rem_euclid(UNIT_DIVISOR_U64);

    // Represent exactly as "<whole>.<8 digits>".
    format!("{whole}.{frac:08}")
}

/// Format micro-units as a human-readable decimal string and trim trailing zeros:
/// - "300.00000000" -> "300"
/// - "300.12000000" -> "300.12"
/// - "300.10000000" -> "300.1"
/// - "0.00000001"   -> "0.00000001"
#[inline]
pub fn format_remzar_trim_one_decimal(amount: u64) -> String {
    let s = format_remzar(amount);
    match s.split_once('.') {
        Some((whole, frac)) => {
            let frac_trimmed = frac.trim_end_matches('0');
            if frac_trimmed.is_empty() {
                whole.to_string()
            } else {
                format!("{whole}.{frac_trimmed}")
            }
        }
        None => s,
    }
}

/// Format micro-units as a human-readable decimal string and trim trailing zeros:
/// - "100.00000000" -> "100"
/// - "100.12000000" -> "100.12"
/// - "0.00000001"   -> "0.00000001"
#[inline]
pub fn format_remzar_trim(amount: u64) -> String {
    let s = format_remzar(amount);
    match s.split_once('.') {
        Some((whole, frac)) => {
            let frac_trimmed = frac.trim_end_matches('0');
            if frac_trimmed.is_empty() {
                whole.to_string()
            } else {
                format!("{whole}.{frac_trimmed}")
            }
        }
        None => s,
    }
}

/// Minimal prehash trait kept for legacy compatibility within Remzar code.
pub trait PreHash {
    fn fill_bytes(&mut self, out: &mut [u8]);
}

/// ML-DSA-65 raw signature bytes (3309 bytes).
pub type Signature = [u8; ml_dsa_65::SIG_LEN];

/// **PreHash helper (legacy-compatible)**
/// Allows pre-hashed data to be provided via `fill_bytes`.
pub struct SimplePreHasher {
    pub bytes: [u8; 64],
}

impl PreHash for SimplePreHasher {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        let len = out.len().min(64);

        if let (Some(dst), Some(src)) = (out.get_mut(..len), self.bytes.get(..len)) {
            dst.copy_from_slice(src);
        }
    }
}

/// **ML-DSA Signature Wrapper for Serialization**
/// Uses `serde_bytes` for compact storage.
///
/// Marking with `#[serde(transparent)]` removes extra overhead in serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureWrapper {
    #[serde(with = "serde_bytes")]
    signature_bytes: Vec<u8>,
}

impl SignatureWrapper {
    /// Create a wrapper from a given ML-DSA raw signature.
    pub fn from_signature(sig: &Signature) -> Self {
        Self {
            signature_bytes: sig.to_vec(),
        }
    }

    /// Create a wrapper from raw bytes (validates length).
    pub fn from_bytes(sig_bytes: &[u8]) -> Result<Self, ErrorDetection> {
        if sig_bytes.len() != ml_dsa_65::SIG_LEN {
            return Err(ErrorDetection::InvalidSignatureFormat {
                format: format!(
                    "Invalid ML-DSA-65 signature length: expected {}, got {}",
                    ml_dsa_65::SIG_LEN,
                    sig_bytes.len()
                ),
            });
        }
        Ok(Self {
            signature_bytes: sig_bytes.to_vec(),
        })
    }

    /// Convert the wrapper back into an ML-DSA signature byte array.
    pub fn to_signature(&self) -> Result<Signature, ErrorDetection> {
        if self.signature_bytes.len() != ml_dsa_65::SIG_LEN {
            return Err(ErrorDetection::InvalidSignatureFormat {
                format: format!(
                    "Invalid ML-DSA-65 signature length: expected {}, got {}",
                    ml_dsa_65::SIG_LEN,
                    self.signature_bytes.len()
                ),
            });
        }

        let mut out = [0u8; ml_dsa_65::SIG_LEN];
        out.copy_from_slice(&self.signature_bytes);
        Ok(out)
    }

    /// Borrow raw bytes (useful for verify paths without copying).
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }
}

pub mod serde_u8_array_64 {
    use core::fmt;
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(64)?;
        for b in arr.iter() {
            tup.serialize_element(b)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Arr64Visitor;

        impl<'de> Visitor<'de> for Arr64Visitor {
            type Value = [u8; 64];

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a 64-byte array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| DeError::invalid_length(i, &self))?;
                }
                // If there are extra elements, treat as invalid (strict).
                if let Some(_extra) = seq.next_element::<u8>()? {
                    return Err(DeError::invalid_length(65, &self));
                }
                Ok(out)
            }
        }

        deserializer.deserialize_tuple(64, Arr64Visitor)
    }
}

/// **Hash64** is a newtype wrapper around a `[u8; 64]` array.
/// Uses the serde adapter above for toolchains lacking `[T; 64]` impls.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash64(#[serde(with = "serde_u8_array_64")] pub [u8; 64]);

impl Hash64 {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Hash64(bytes)
    }

    /// Returns the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// **Helper to decode a hex string into a 64-byte array.**
pub fn decode_hex_to_64(hex_str: &str) -> Result<[u8; 64], ErrorDetection> {
    let bytes = hex::decode(hex_str).map_err(|e| ErrorDetection::ValidationError {
        message: format!("Invalid hex in configuration: {:?}", e),
        tx_id: None,
    })?;

    if bytes.len() != 64 {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Expected a 64-byte value in configuration (128 hex chars), got {} bytes",
                bytes.len()
            ),
            tx_id: None,
        });
    }

    let array: [u8; 64] =
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ErrorDetection::ValidationError {
                message: "Expected a 64-byte value in configuration".to_string(),
                tx_id: None,
            })?;

    Ok(array)
}

/* ───────────────────────── helpers ───────────────────────── */

pub const REMZAR_WALLET_LEN: usize = 129;
pub const REMZAR_WALLET_BODY_LEN: usize = 128;
pub const REMZAR_WALLET_PREFIX: u8 = b'r';

#[inline]
pub fn derive_wallet_id_from_pubkey_bytes(pk_bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pk_bytes);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    // hex::encode outputs lowercase
    format!("r{}", hex::encode(out))
}

#[inline]
pub fn wallet_id_matches_pubkey_bytes_checked(
    wallet_id: &str,
    pk_bytes: &[u8],
) -> Result<String, ErrorDetection> {
    let canon = canon_wallet_id_checked(wallet_id)?;
    let derived = derive_wallet_id_from_pubkey_bytes(pk_bytes);

    if canon != derived {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address does not match derived public key commitment".into(),
            tx_id: None,
        });
    }

    Ok(canon)
}

/// Canonicalize & validate a Remzar wallet address:
#[inline]
pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
    let s = id.trim();

    if s.len() != REMZAR_WALLET_LEN {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address is invalid or incomplete".into(),
            tx_id: None,
        });
    }

    // Lowercase once: makes 'r' -> 'r' and normalizes hex.
    let lower = s.to_ascii_lowercase();
    let b = lower.as_bytes();

    if b.first() != Some(&REMZAR_WALLET_PREFIX) {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address is invalid or incomplete".into(),
            tx_id: None,
        });
    }

    // Enforce 128 lowercase hex chars after the leading 'r'
    if !b
        .get(1..)
        .is_some_and(|body| body.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address is invalid or incomplete".into(),
            tx_id: None,
        });
    }

    Ok(lower)
}

/// Remzar wallet address must be canonical:
#[must_use]
pub fn canon_wallet_id(id: &str) -> String {
    canon_wallet_id_checked(id).unwrap_or_else(|_| id.trim().to_string())
}

/// Validates a Remzar wallet address:
pub fn parse_wallet_address(address: &str) -> Result<(), ErrorDetection> {
    // Align behavior with other helpers: trim here too
    let address = address.trim();

    if address.len() != REMZAR_WALLET_LEN {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address is invalid or incomplete".into(),
            tx_id: None,
        });
    }
    if !address.starts_with('r') {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address is invalid or incomplete".into(),
            tx_id: None,
        });
    }

    // Enforce 128 lowercase hex chars after the leading 'r'
    let body = address
        .get(1..)
        .ok_or_else(|| ErrorDetection::ValidationError {
            message: "Wallet address is invalid or incomplete".into(),
            tx_id: None,
        })?;

    if body.len() != REMZAR_WALLET_BODY_LEN
        || !body.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address is invalid or incomplete".into(),
            tx_id: None,
        });
    }

    Ok(())
}

/// Parse a wallet address from bytes (STRICT, no legacy tolerance):
#[inline]
pub fn parse_wallet_address_bytes(bytes: &[u8]) -> Result<&str, ErrorDetection> {
    // Must be exactly 129 bytes (r + 128 hex)
    if bytes.len() != REMZAR_WALLET_LEN {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address bytes are invalid".into(),
            tx_id: None,
        });
    }

    // No NULs allowed anywhere (no legacy padding)
    if bytes.contains(&0) {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address bytes are invalid".into(),
            tx_id: None,
        });
    }

    // MUST be strict UTF-8 (no lossy)
    let s = std::str::from_utf8(bytes).map_err(|_| ErrorDetection::ValidationError {
        message: "Wallet address bytes are invalid".into(),
        tx_id: None,
    })?;

    // Reuse strict format validation (expects canonical r + 128 lowercase hex)
    parse_wallet_address(s)?;

    Ok(s)
}

/// Resolve the blockchain DB directory:
pub fn get_blockchain_db_dir() -> PathBuf {
    match env::var("BLOCKCHAIN_DATABASE_DIR") {
        Ok(s) if !s.trim().is_empty() => PathBuf::from(s),
        _ => PathBuf::from(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR),
    }
}

/* ───────────────────────── retry helpers ───────────────────────── */

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum RocksDbOpenFailureKind {
    LockContention,
    CorruptionOrMissingFiles,
    Other,
}

#[inline]
fn classify_rocksdb_open_error(e: &RocksDbError) -> RocksDbOpenFailureKind {
    let msg = e.to_string();
    let lower = msg.to_ascii_lowercase();

    let mentions_manifest_or_table_file = lower.contains("manifest")
        || lower.contains(".sst")
        || lower.contains(".ldb")
        || lower.contains("/current")
        || lower.contains("\\current");

    let corruption_or_missing_files = lower.contains("corruption")
        || lower.contains("checksum mismatch")
        || lower.contains("not an sstable")
        || lower.contains("bad table magic number")
        || lower.contains("manifest")
        || lower.contains("missing sst")
        || lower.contains("sst file")
        || (mentions_manifest_or_table_file
            && (lower.contains("no such file or directory")
                || lower.contains("file not found")
                || lower.contains("cannot find the file")
                || lower.contains("could not find")
                || lower.contains("not found")));

    if corruption_or_missing_files {
        return RocksDbOpenFailureKind::CorruptionOrMissingFiles;
    }

    // Only match phrases that RocksDB/OS commonly use for true lock contention.
    // Do not match arbitrary "lock" because paths, project names, or DB names may contain it.
    let lock_contention = lower.contains("lock file")
        || lower.contains("failed to lock")
        || lower.contains("io error: lock")
        || lower.contains("lock held")
        || lower.contains("lock hold")
        || lower.contains("resource temporarily unavailable")
        || lower.contains("temporarily unavailable")
        || lower.contains("already in use")
        || lower.contains("another process")
        || lower.contains("database is locked");

    if lock_contention {
        return RocksDbOpenFailureKind::LockContention;
    }

    RocksDbOpenFailureKind::Other
}

#[inline]
fn rocksdb_open_failure_label(kind: RocksDbOpenFailureKind) -> &'static str {
    match kind {
        RocksDbOpenFailureKind::LockContention => "lock contention",
        RocksDbOpenFailureKind::CorruptionOrMissingFiles => "corruption or missing RocksDB files",
        RocksDbOpenFailureKind::Other => "open failure",
    }
}

/// Retry-wrapper around `DB::open_cf_descriptors`.
pub fn open_cf_with_retries(opts: &Options, path: &str) -> Result<DB, ErrorDetection> {
    if path.trim().is_empty() {
        return Err(ErrorDetection::DatabaseError {
            details: "Failed to open RocksDB: empty database path".to_string(),
        });
    }

    let mut last_err: Option<(RocksDbOpenFailureKind, RocksDbError)> = None;

    for attempt in 1..=GlobalConfiguration::MAX_ATTEMPTS {
        let cfs = CFDescriptors::get_cf_descriptors();

        match DB::open_cf_descriptors(opts, path, cfs) {
            Ok(db) => return Ok(db),
            Err(e) => {
                let kind = classify_rocksdb_open_error(&e);

                match kind {
                    RocksDbOpenFailureKind::LockContention
                        if attempt < GlobalConfiguration::MAX_ATTEMPTS =>
                    {
                        tracing::warn!(
                            "RocksDB lock contention on '{}' (attempt {}/{}) — retrying in {}s: {}",
                            path,
                            attempt,
                            GlobalConfiguration::MAX_ATTEMPTS,
                            GlobalConfiguration::RETRY_DELAY_SECS,
                            e
                        );

                        last_err = Some((kind, e));
                        thread::sleep(Duration::from_secs(GlobalConfiguration::RETRY_DELAY_SECS));
                        continue;
                    }

                    RocksDbOpenFailureKind::CorruptionOrMissingFiles => {
                        tracing::error!(
                            "RocksDB corruption/missing-file error at '{}'; refusing retry loop: {}",
                            path,
                            e
                        );

                        return Err(ErrorDetection::DatabaseError {
                            details: format!(
                                "RocksDB corruption or missing files detected at '{}'. \
                                 This is not a LOCK issue, and retrying will not fix it. \
                                 Do not delete the LOCK file manually. \
                                 Restore from backup, resync/rebuild the local chain DB, or run an explicit RocksDB repair workflow only after copying the full DB directory. \
                                 Details: {}",
                                path, e
                            ),
                        });
                    }

                    _ => {
                        last_err = Some((kind, e));
                        break;
                    }
                }
            }
        }
    }

    Err(ErrorDetection::DatabaseError {
        details: {
            let (label, err_str) = last_err
                .as_ref()
                .map(|(kind, e)| (rocksdb_open_failure_label(*kind), e.to_string()))
                .unwrap_or(("unknown", "no error captured".to_string()));

            format!(
                "Failed to open RocksDB at '{}' after {} attempts ({label}): {}",
                path,
                GlobalConfiguration::MAX_ATTEMPTS,
                err_str
            )
        },
    })
}

pub fn flush_all_cfs(db: &DB) -> Result<(), ErrorDetection> {
    for desc in CFDescriptors::get_cf_descriptors() {
        let name = desc.name();
        if let Some(cf_handle) = db.cf_handle(name) {
            db.flush_cf(cf_handle)
                .map_err(|e| ErrorDetection::DatabaseError {
                    details: format!("Flush failed for CF '{}': {}", name, e),
                })?;
        }
    }
    Ok(())
}

pub fn blocks_match(
    local: &crate::blockchain::block_002_blocks::Block,
    genesis: &crate::blockchain::genesis_001_block::GenesisBlock,
) -> bool {
    local.block_hash == genesis.genesis_hash
        && local.metadata.merkle_root == genesis.merkle_root
        && local.metadata.previous_hash == genesis.prev_hash
        && local.metadata.timestamp == genesis.timestamp
}

#[inline]
pub fn ready_to_mine(sync: &P2pSync, peer_count: usize) -> bool {
    peer_count > 0 && sync.has_synced()
}

/// UI-only helper: shorten long ASCII strings as "head...tail".
/// Safe for hex (ASCII). Does NOT affect consensus/stored values.
#[inline]
pub fn ellipsize_middle_ascii(s: &str, head: usize, tail: usize) -> String {
    if head == 0 || tail == 0 {
        return s.to_string();
    }

    let bytes = s.as_bytes();

    // If it would not actually shorten, return original.
    if bytes.len() <= head.saturating_add(tail).saturating_add(3) {
        return s.to_string();
    }

    let start_tail = bytes.len().saturating_sub(tail);

    // Use .get(..) / .get(..) so we never panic (clippy::indexing_slicing forbidden).
    let head_str = bytes
        .get(..head)
        .and_then(|b| core::str::from_utf8(b).ok())
        .unwrap_or(s);

    let tail_str = bytes
        .get(start_tail..)
        .and_then(|b| core::str::from_utf8(b).ok())
        .unwrap_or(s);

    format!("{head_str}...{tail_str}")
}

/* ─────────────────────────────────────────────────────────────
Consensus quorum helpers
───────────────────────────────────────────────────────────── */

#[inline]
#[must_use]
pub fn quorum_threshold(n: usize) -> usize {
    match n {
        0 | 1 => 1,
        2..=9 => 2,
        _ => n.div_ceil(5),
    }
}

#[inline]
pub fn quorum_threshold_checked(n: usize) -> Result<usize, ErrorDetection> {
    match n {
        0 | 1 => Ok(1),
        2..=9 => Ok(2),
        _ => Ok(n.div_ceil(5)),
    }
}

#[inline]
#[must_use]
pub fn has_quorum(have: usize, canon_n: usize) -> bool {
    have >= quorum_threshold(canon_n)
}
