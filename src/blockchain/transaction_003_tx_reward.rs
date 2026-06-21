// src/blockchain/transaction_003_tx_reward.rs

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, parse_wallet_address_bytes,
};
use crate::utility::time_policy::TimePolicy;

use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

/// RewardTx
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RewardTx {
    /// Exactly 129 ASCII bytes: 'r' + 128 hex.
    #[serde(with = "serde_big_array::BigArray")]
    pub receiver: [u8; REMZAR_WALLET_LEN],

    /// Reward amount in micro-ZAR / micro-REMZAR.
    pub amount: u64,

    /// Block height associated with this reward.
    pub block_height: u64,

    /// Creation / block-associated time, Unix seconds.
    pub timestamp: u64,
}

impl RewardTx {
    /// Backward-compatible constructor.
    pub fn new(receiver: String, amount: u64, block_height: u64) -> Result<Self, ErrorDetection> {
        let timestamp = Self::now_unix_secs()?;
        Self::new_with_timestamp(receiver, amount, block_height, timestamp)
    }

    /// Constructor with explicit timestamp.
    pub fn new_with_timestamp(
        receiver: String,
        amount: u64,
        block_height: u64,
        timestamp: u64,
    ) -> Result<Self, ErrorDetection> {
        // Receiver format: canonical Remzar wallet id.
        let receiver_canon =
            canon_wallet_id_checked(&receiver).map_err(|_| ErrorDetection::ValidationError {
                message: format!("Invalid receiver address format: {}", receiver),
                tx_id: None,
            })?;

        Self::validate_amount(amount)?;
        Self::validate_block_height(block_height)?;
        Self::validate_timestamp_structural(timestamp)?;

        let mut receiver_arr = [0u8; REMZAR_WALLET_LEN];
        receiver_arr.copy_from_slice(receiver_canon.as_bytes());

        let tx = Self {
            receiver: receiver_arr,
            amount,
            block_height,
            timestamp,
        };

        tx.validate()?;
        Ok(tx)
    }

    pub fn amount_as_remzar(&self) -> f64 {
        crate::utility::helper::from_micro_units(self.amount)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
        // Never emit malformed reward transactions.
        self.validate()?;

        to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Failed to serialize reward transaction: {}", e),
        })
    }

    /// Replay-safe deserialization.
    pub fn deserialize(data: &[u8]) -> Result<Self, ErrorDetection> {
        let tx: Self = from_bytes(data).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Failed to deserialize reward transaction: {}", e),
        })?;

        tx.validate()?;

        let canonical = to_allocvec(&tx).map_err(|e| ErrorDetection::SerializationError {
            details: format!(
                "Failed to reserialize reward transaction after decode: {}",
                e
            ),
        })?;

        if canonical != data {
            return Err(ErrorDetection::SerializationError {
                details:
                    "Failed to deserialize reward transaction: non-canonical or trailing bytes rejected"
                        .to_string(),
            });
        }

        Ok(tx)
    }

    /// Defensive replay-safe validation for reward txs.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        Self::validate_amount(self.amount)?;
        Self::validate_block_height(self.block_height)?;
        Self::validate_receiver_canonical(&self.receiver)?;
        Self::validate_timestamp_structural(self.timestamp)?;
        Ok(())
    }

    /// Runtime-only validation for freshly created rewards or operator tooling.
    pub fn validate_for_runtime(&self) -> Result<(), ErrorDetection> {
        let now = Self::now_unix_secs()?;
        self.validate_for_runtime_at(now)
    }

    /// Runtime-only validation with caller-provided `now`.
    pub fn validate_for_runtime_at(&self, now_unix: u64) -> Result<(), ErrorDetection> {
        self.validate()?;
        TimePolicy::validate_runtime_future_skew_secs_default(
            "RewardTx.timestamp",
            self.timestamp,
            now_unix,
        )
    }

    /// Optional deterministic block-time relationship check.
    pub fn validate_against_block_timestamp(
        &self,
        block_timestamp: u64,
        allowed_delta_secs: u64,
    ) -> Result<(), ErrorDetection> {
        self.validate()?;
        TimePolicy::validate_tx_timestamp_within_block_window(
            "RewardTx.timestamp",
            self.timestamp,
            block_timestamp,
            allowed_delta_secs,
        )
    }

    #[inline]
    fn now_unix_secs() -> Result<u64, ErrorDetection> {
        TimePolicy::now_unix_secs_runtime()
    }

    #[inline]
    fn validate_amount(amount: u64) -> Result<(), ErrorDetection> {
        if amount == 0 {
            return Err(validation_err("Reward amount must be greater than zero."));
        }

        if amount > GlobalConfiguration::MAX_BLOCK_REWARD {
            return Err(validation_err(format!(
                "Reward amount {} exceeds allowed maximum {}.",
                amount,
                GlobalConfiguration::MAX_BLOCK_REWARD
            )));
        }

        Ok(())
    }

    #[inline]
    fn validate_block_height(block_height: u64) -> Result<(), ErrorDetection> {
        if block_height == 0 {
            return Err(validation_err("Block height cannot be zero."));
        }
        Ok(())
    }

    fn validate_receiver_canonical(
        receiver: &[u8; REMZAR_WALLET_LEN],
    ) -> Result<(), ErrorDetection> {
        // Address must be valid UTF-8 "r" + 128 hex, exactly 129 bytes.
        let addr = parse_wallet_address_bytes(receiver)?;

        if addr.len() != REMZAR_WALLET_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!("Invalid receiver address format: {}", addr),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_timestamp_structural(timestamp: u64) -> Result<(), ErrorDetection> {
        TimePolicy::validate_unix_secs_structural("RewardTx.timestamp", timestamp)
    }
}

#[inline]
fn validation_err(message: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: message.into(),
        tx_id: None,
    }
}
