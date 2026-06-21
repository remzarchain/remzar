// src/blockchain/transaction_001_tx.rs

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, from_micro_units, parse_wallet_address_bytes,
    to_micro_units_str,
};
use crate::utility::time_policy::TimePolicy;

use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

/// **Transaction**
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Transaction {
    #[serde(with = "serde_big_array::BigArray")]
    pub sender: [u8; REMZAR_WALLET_LEN],
    #[serde(with = "serde_big_array::BigArray")]
    pub receiver: [u8; REMZAR_WALLET_LEN],
    pub amount: u64,
    pub timestamp: u64,
}

impl Transaction {
    // ─────────────────────────────────────────────────────────────
    // Constructors
    // ─────────────────────────────────────────────────────────────

    /// Creates a new transaction given micro-units.
    pub fn new(sender: String, receiver: String, amount: u64) -> Result<Self, ErrorDetection> {
        // Validate + canonicalize through helper.rs
        let (sender_canon, receiver_canon) = Self::basic_checks(&sender, &receiver, amount)?;

        let sender_arr = Self::str_to_arr(&sender_canon)?;
        let receiver_arr = Self::str_to_arr(&receiver_canon)?;
        let timestamp = Self::now_ts()?;

        let tx = Self {
            sender: sender_arr,
            receiver: receiver_arr,
            amount,
            timestamp,
        };

        // New locally-created txs should satisfy mempool/runtime freshness too.
        tx.validate_for_mempool()?;
        Ok(tx)
    }

    /// Creates a new transaction from **human-readable REMZAR** (f64).
    pub fn new_from_remzar(
        sender: String,
        receiver: String,
        amount_remzar: f64,
    ) -> Result<Self, ErrorDetection> {
        // Handle NaN and infinities explicitly so tests get stable error contracts.
        if amount_remzar.is_nan() {
            return Err(validation_err(
                "Transaction amount must be greater than zero.",
            ));
        }
        if amount_remzar.is_infinite() {
            return Err(validation_err("Transaction amount too large (overflow)."));
        }

        if amount_remzar <= 0.0 {
            return Err(validation_err(
                "Transaction amount must be greater than zero.",
            ));
        }

        // Deterministic conversion: fixed 8 decimals -> parse as fixed-point string.
        let s = format!("{amount_remzar:.8}");

        // Overflow pre-check (same logic you already had)
        let s_trim = s.trim();
        let (whole_str, frac_str) = match s_trim.split_once('.') {
            Some((w, f)) => (w, f),
            None => (s_trim, ""),
        };
        let whole_str = if whole_str.is_empty() { "0" } else { whole_str };

        if !whole_str.as_bytes().iter().all(|b| b.is_ascii_digit())
            || !frac_str.as_bytes().iter().all(|b| b.is_ascii_digit())
            || frac_str.len() > 8
        {
            return Err(validation_err("Transaction amount invalid."));
        }

        if whole_str.len() > 12 {
            return Err(validation_err("Transaction amount too large (overflow)."));
        }

        if whole_str.len() == 12 {
            let max_whole: &[u8] = b"184467440737".as_slice();
            let whole_bytes = whole_str.as_bytes();

            if whole_bytes > max_whole {
                return Err(validation_err("Transaction amount too large (overflow)."));
            }

            if whole_bytes == max_whole {
                let frac_nonzero = frac_str.as_bytes().iter().any(|&b| b != b'0');
                if frac_nonzero {
                    return Err(validation_err("Transaction amount too large (overflow)."));
                }
            }
        }

        let amount_micro = to_micro_units_str(&s);

        if amount_micro == 0 {
            return Err(validation_err(
                "Transaction amount must be greater than zero.",
            ));
        }

        Self::new(sender, receiver, amount_micro)
    }

    // Backwards-compat alias (if other code still calls new_from_aos)
    pub fn new_from_aos(
        sender: String,
        receiver: String,
        amount_aos: f64,
    ) -> Result<Self, ErrorDetection> {
        Self::new_from_remzar(sender, receiver, amount_aos)
    }

    // ─────────────────────────────────────────────────────────────
    // Convenience getters
    // ─────────────────────────────────────────────────────────────

    /// Returns the amount in human-readable REMZAR.
    pub fn amount_as_remzar(&self) -> f64 {
        from_micro_units(self.amount)
    }

    // Backwards-compat alias
    pub fn amount_as_aos(&self) -> f64 {
        self.amount_as_remzar()
    }

    // ─────────────────────────────────────────────────────────────
    // Validation helpers
    // ─────────────────────────────────────────────────────────────

    /// Replay-safe validation used by builders, block validation, and deserialization.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        self.validate_structural()
    }

    /// Replay-safe structural validation.
    pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
        Self::basic_checks_arr(&self.sender, &self.receiver, self.amount)?;
        Self::validate_timestamp_structural(self.timestamp)
    }

    /// Runtime-only validation for mempool / gossip admission.
    pub fn validate_for_mempool(&self) -> Result<(), ErrorDetection> {
        let now = TimePolicy::now_unix_secs_runtime()?;
        self.validate_for_mempool_at(now)
    }

    /// Runtime-only validation with caller-supplied `now`.
    pub fn validate_for_mempool_at(&self, now_unix: u64) -> Result<(), ErrorDetection> {
        self.validate_structural()?;
        TimePolicy::validate_runtime_future_skew_secs_default(
            "Transaction.timestamp",
            self.timestamp,
            now_unix,
        )
    }

    // ─────────────────────────────────────────────────────────────
    // (De)serialization
    // ─────────────────────────────────────────────────────────────

    pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
        // Never emit malformed transactions.
        self.validate_structural()?;

        to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Failed to serialize transaction: {e}"),
        })
    }

    /// Replay-safe deserialization.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let tx: Self = from_bytes(bytes).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Failed to deserialize transaction: {e}"),
        })?;

        // Reject malformed/non-canonical txs from the wire.
        tx.validate_structural()?;

        let canonical = to_allocvec(&tx).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Failed to reserialize transaction after decode: {e}"),
        })?;

        if canonical != bytes {
            return Err(ErrorDetection::SerializationError {
                details:
                    "Failed to deserialize transaction: non-canonical or trailing bytes rejected"
                        .to_string(),
            });
        }

        Ok(tx)
    }

    /// Runtime/mempool deserialization.
    pub fn deserialize_for_mempool(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let tx = Self::deserialize(bytes)?;
        tx.validate_for_mempool()?;
        Ok(tx)
    }

    // ─────────────────────────────────────────────────────────────
    // Internal utilities
    // ─────────────────────────────────────────────────────────────

    /// Validates and canonicalizes sender/receiver through helper.rs.
    fn basic_checks(
        sender: &str,
        receiver: &str,
        amount: u64,
    ) -> Result<(String, String), ErrorDetection> {
        let sender_trim = sender.trim();
        let receiver_trim = receiver.trim();

        if sender_trim.is_empty() || receiver_trim.is_empty() {
            return Err(validation_err(
                "Sender and receiver addresses cannot be empty.",
            ));
        }

        if sender_trim.len() != REMZAR_WALLET_LEN || receiver_trim.len() != REMZAR_WALLET_LEN {
            return Err(validation_err(format!(
                "Invalid address length: sender({}) receiver({}) expected({})",
                sender_trim.len(),
                receiver_trim.len(),
                REMZAR_WALLET_LEN
            )));
        }

        // Canonicalize + validate using helper.rs (single source of truth)
        let sender_canon = canon_wallet_id_checked(sender_trim)?;
        let receiver_canon = canon_wallet_id_checked(receiver_trim)?;

        if sender_canon == receiver_canon {
            return Err(validation_err("Sender and receiver cannot be the same."));
        }

        if amount == 0 {
            return Err(validation_err(
                "Transaction amount must be greater than zero.",
            ));
        }

        Ok((sender_canon, receiver_canon))
    }

    fn basic_checks_arr(
        sender: &[u8; REMZAR_WALLET_LEN],
        receiver: &[u8; REMZAR_WALLET_LEN],
        amount: u64,
    ) -> Result<(), ErrorDetection> {
        // Enforce canonical wallet encoding via helper.rs strict bytes parser.
        let s_sender = parse_wallet_address_bytes(sender)?;
        let s_receiver = parse_wallet_address_bytes(receiver)?;

        if s_sender == s_receiver {
            return Err(validation_err("Sender and receiver cannot be the same."));
        }
        if amount == 0 {
            return Err(validation_err(
                "Transaction amount must be greater than zero.",
            ));
        }
        Ok(())
    }

    pub fn id(&self) -> Result<String, ErrorDetection> {
        let bytes = self.serialize()?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    #[inline]
    fn str_to_arr(s: &str) -> Result<[u8; REMZAR_WALLET_LEN], ErrorDetection> {
        // At this point, `s` should already be canonical from helper.rs.
        if s.len() != REMZAR_WALLET_LEN {
            return Err(validation_err(format!(
                "Address must be exactly {} bytes in length. Found {} bytes.",
                REMZAR_WALLET_LEN,
                s.len()
            )));
        }

        let mut arr = [0u8; REMZAR_WALLET_LEN];
        arr.copy_from_slice(s.as_bytes());
        Ok(arr)
    }

    #[inline]
    fn now_ts() -> Result<u64, ErrorDetection> {
        TimePolicy::now_unix_secs_runtime()
    }

    #[inline]
    fn validate_timestamp_structural(ts: u64) -> Result<(), ErrorDetection> {
        TimePolicy::validate_unix_secs_structural("Transaction.timestamp", ts)
    }
}

#[inline]
fn validation_err(message: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: message.into(),
        tx_id: None,
    }
}
