// src/blockchain/transaction_002_tx_register.rs

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
use crate::utility::time_policy::TimePolicy;

use postcard::{take_from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RegisterNodeTx {
    /// Canonical wallet: ASCII "r" + 128 lowercase hex characters.
    #[serde(with = "serde_big_array::BigArray")]
    pub wallet_address: [u8; WALLET_LEN],
    /// Self-reported transaction creation timestamp, seconds since UNIX epoch.
    pub timestamp: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Strict guards & canonicalization
// ─────────────────────────────────────────────────────────────────────────────

const WALLET_LEN: usize = REMZAR_WALLET_LEN;

/// Canonicalize from &str using the single source of truth:
fn canon_wallet_from_str(s: &str) -> Result<[u8; WALLET_LEN], ErrorDetection> {
    let canon = canon_wallet_id_checked(s)?;
    let b = canon.as_bytes();

    if b.len() != WALLET_LEN {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Invalid wallet length (expected {}): {}",
                WALLET_LEN,
                b.len()
            ),
            tx_id: None,
        });
    }

    let mut out = [0u8; WALLET_LEN];
    out.copy_from_slice(b);
    Ok(out)
}

/// Canonicalize from raw bytes:
fn canon_wallet_from_bytes(b: &[u8]) -> Result<[u8; WALLET_LEN], ErrorDetection> {
    let end = b
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last_non_zero_index| {
            last_non_zero_index.saturating_add(1)
        });

    let trimmed = b
        .get(..end)
        .ok_or_else(|| ErrorDetection::ValidationError {
            message: "Wallet address bytes could not be trimmed safely".into(),
            tx_id: None,
        })?;

    if trimmed.is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address bytes are empty".into(),
            tx_id: None,
        });
    }

    if trimmed.contains(&0) {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address bytes contain embedded NUL".into(),
            tx_id: None,
        });
    }

    let s = std::str::from_utf8(trimmed).map_err(|_| ErrorDetection::ValidationError {
        message: "Wallet address bytes are invalid UTF-8".into(),
        tx_id: None,
    })?;

    canon_wallet_from_str(s)
}

/// Replay-safe timestamp validation.
fn validate_timestamp_structural(label: &'static str, ts: u64) -> Result<(), ErrorDetection> {
    TimePolicy::validate_unix_secs_structural(label, ts)
}

/// Runtime-only timestamp validation.
fn validate_timestamp_for_mempool_at(
    label: &'static str,
    ts: u64,
    now_unix: u64,
) -> Result<(), ErrorDetection> {
    TimePolicy::validate_runtime_future_skew_secs_default(label, ts, now_unix)
}

impl RegisterNodeTx {
    /// Construct from a string wallet.
    pub fn new(wallet_address: String) -> Result<Self, ErrorDetection> {
        let wallet_canon = canon_wallet_from_str(&wallet_address)?;
        let timestamp = TimePolicy::now_unix_secs_runtime()?;

        let tx = Self {
            wallet_address: wallet_canon,
            timestamp,
        };

        tx.validate_for_mempool()?;
        Ok(tx)
    }

    /// Optional helper: build from bytes.
    pub fn new_from_bytes(wallet_bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let wallet_canon = canon_wallet_from_bytes(wallet_bytes)?;
        let timestamp = TimePolicy::now_unix_secs_runtime()?;

        let tx = Self {
            wallet_address: wallet_canon,
            timestamp,
        };

        tx.validate_for_mempool()?;
        Ok(tx)
    }

    /// Postcard serialization.
    pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
        // Serialization should not silently emit malformed transactions.
        self.validate_structural()?;

        to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
            details: format!("RegisterNodeTx serialize failed: {}", e),
        })
    }

    /// Postcard deserialization with strict replay-safe validation:
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let (mut tx, remaining): (Self, &[u8]) =
            take_from_bytes(bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!("RegisterNodeTx deserialize failed: {}", e),
            })?;

        if !remaining.is_empty() {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "RegisterNodeTx deserialize failed: trailing bytes after payload: {} bytes",
                    remaining.len()
                ),
            });
        }

        tx.wallet_address = canon_wallet_from_bytes(&tx.wallet_address)?;
        tx.validate_structural()?;

        Ok(tx)
    }

    /// Runtime/mempool deserialization.
    pub fn deserialize_for_mempool(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let tx = Self::deserialize(bytes)?;
        tx.validate_for_mempool()?;
        Ok(tx)
    }

    /// Replay-safe invariant validation on an existing instance.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        self.validate_structural()
    }

    /// Replay-safe structural validation.
    pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
        let canon = canon_wallet_from_bytes(&self.wallet_address)?;

        if canon != self.wallet_address {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet address is not in canonical form ('r' + lowercase hex)".into(),
                tx_id: None,
            });
        }

        validate_timestamp_structural("RegisterNodeTx.timestamp", self.timestamp)
    }

    /// Runtime-only validation for mempool / gossip admission.
    pub fn validate_for_mempool(&self) -> Result<(), ErrorDetection> {
        let now = TimePolicy::now_unix_secs_runtime()?;
        self.validate_for_mempool_at(now)
    }

    /// Runtime-only validation with caller-supplied `now`.
    pub fn validate_for_mempool_at(&self, now_unix: u64) -> Result<(), ErrorDetection> {
        self.validate_structural()?;
        validate_timestamp_for_mempool_at("RegisterNodeTx.timestamp", self.timestamp, now_unix)
    }

    /// Borrow the canonical "r"+128hex as &str.
    pub fn wallet_str(&self) -> Result<&str, ErrorDetection> {
        let s = std::str::from_utf8(&self.wallet_address).map_err(|_| {
            ErrorDetection::ValidationError {
                message: "Wallet address is not valid UTF-8".into(),
                tx_id: None,
            }
        })?;

        // Keep this accessor defensive. It returns a borrowed string only if the
        // stored bytes are already canonical.
        let canon = canon_wallet_id_checked(s).map_err(|e| ErrorDetection::ValidationError {
            message: format!("RegisterNodeTx wallet_str invalid wallet: {e}"),
            tx_id: None,
        })?;

        if canon != s {
            return Err(ErrorDetection::ValidationError {
                message: "RegisterNodeTx wallet_str wallet is not canonical".into(),
                tx_id: None,
            });
        }

        Ok(s)
    }
}
