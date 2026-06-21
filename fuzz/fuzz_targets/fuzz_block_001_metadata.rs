#![no_main]

use fips204::ml_dsa_65;
use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
            pub const MAX_METADATA_DECOMPRESSED_BYTES: usize = 8 * 1024;
            pub const MIN_BLOCK_SIZE: u64 = 64;
            pub const MIN_TIMESTAMP_SECS: u64 = 946_684_800;
            pub const MAX_FUTURE_DRIFT_SECS: u64 = 3600 * 24 * 365 * 10;
            pub const MAX_FUTURE_SKEW_SECS: u64 = Self::MAX_FUTURE_DRIFT_SECS;
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
            TimestampError {
                message: String,
                details: String,
                source: Option<String>,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, .. } => write!(f, "{message}"),
                    Self::SerializationError { details } => write!(f, "{details}"),
                    Self::TimestampError { message, details, .. } => {
                        write!(f, "{message}: {details}")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use serde::de::{Error as DeError, SeqAccess, Visitor};
        use serde::ser::SerializeTuple;
        use serde::{Deserializer, Serializer};
        use std::fmt;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        pub mod serde_u8_array_64 {
            use super::*;

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

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

                        if let Some(_extra) = seq.next_element::<u8>()? {
                            return Err(DeError::invalid_length(65, &self));
                        }

                        Ok(out)
                    }
                }

                deserializer.deserialize_tuple(64, Arr64Visitor)
            }
        }

        #[inline]
        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

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
    }

    pub mod time_policy {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::time::{SystemTime, UNIX_EPOCH};

        /// 2000-01-01T00:00:00Z.
        pub const UNIX_2000_SECS: u64 = 946_684_800;

        /// 9999-12-31T23:59:59Z.
        pub const UNIX_9999_SECS: u64 = 253_402_300_799;

        pub const UNIX_2000_MILLIS: u64 = UNIX_2000_SECS * 1_000;
        pub const UNIX_9999_MILLIS: u64 = UNIX_9999_SECS * 1_000;
        pub const MAX_SLOT_GATE_DRIFT_SECS: u64 = 24 * 60 * 60;
        pub const MAX_BLOCK_INTERVAL_SECS: u64 = 24 * 60 * 60;

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct ChainTimePolicyConfig {
            pub genesis_time_unix: u64,
            pub block_interval_secs: u64,
            pub slot_gate_drift_secs: u64,
        }

        impl ChainTimePolicyConfig {
            #[must_use]
            pub fn new(
                genesis_time_unix: u64,
                block_interval_secs: u64,
                slot_gate_drift_secs: u64,
            ) -> Self {
                Self {
                    genesis_time_unix,
                    block_interval_secs,
                    slot_gate_drift_secs,
                }
            }

            #[must_use]
            pub fn from_genesis_and_globals(genesis_time_unix: u64) -> Self {
                Self::new(
                    genesis_time_unix,
                    GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
                    GlobalConfiguration::SLOT_GATE_DRIFT_SECS,
                )
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                TimePolicy::validate_unix_secs_structural("genesis_time_unix", self.genesis_time_unix)?;

                if self.block_interval_secs == 0 {
                    return Err(TimePolicy::validation_err(
                        "ChainTimePolicyConfig invalid: block_interval_secs must be >= 1",
                    ));
                }

                if self.block_interval_secs > MAX_BLOCK_INTERVAL_SECS {
                    return Err(TimePolicy::validation_err(format!(
                        "ChainTimePolicyConfig invalid: block_interval_secs={} exceeds max {}",
                        self.block_interval_secs, MAX_BLOCK_INTERVAL_SECS
                    )));
                }

                if self.slot_gate_drift_secs > MAX_SLOT_GATE_DRIFT_SECS {
                    return Err(TimePolicy::validation_err(format!(
                        "ChainTimePolicyConfig invalid: slot_gate_drift_secs={} exceeds max {}",
                        self.slot_gate_drift_secs, MAX_SLOT_GATE_DRIFT_SECS
                    )));
                }

                Ok(())
            }

            pub fn slot_start_unix_checked(&self, slot: u64) -> Result<u64, ErrorDetection> {
                self.validate()?;
                let offset = slot.checked_mul(self.block_interval_secs).ok_or_else(|| {
                    TimePolicy::validation_err(format!(
                        "slot_start_unix overflow while multiplying slot={} by block_interval_secs={}",
                        slot, self.block_interval_secs
                    ))
                })?;
                let start = self.genesis_time_unix.checked_add(offset).ok_or_else(|| {
                    TimePolicy::validation_err(format!(
                        "slot_start_unix overflow while adding genesis={} offset={}",
                        self.genesis_time_unix, offset
                    ))
                })?;
                TimePolicy::validate_unix_secs_structural("slot_start_unix", start)?;
                Ok(start)
            }

            #[must_use]
            pub fn slot_start_unix_saturating(&self, slot: u64) -> u64 {
                self.genesis_time_unix
                    .saturating_add(slot.saturating_mul(self.block_interval_secs.max(1)))
            }

            pub fn slot_for_timestamp_checked(&self, ts_unix: u64) -> Result<u64, ErrorDetection> {
                self.validate()?;
                TimePolicy::validate_unix_secs_structural("timestamp", ts_unix)?;

                if ts_unix < self.genesis_time_unix.saturating_sub(self.slot_gate_drift_secs) {
                    return Err(TimePolicy::validation_err(format!(
                        "timestamp before genesis window: ts={} genesis={} drift={}s",
                        ts_unix, self.genesis_time_unix, self.slot_gate_drift_secs
                    )));
                }

                Ok(ts_unix
                    .saturating_sub(self.genesis_time_unix)
                    .div_euclid(self.block_interval_secs))
            }

            pub fn secs_into_slot_checked(
                &self,
                slot: u64,
                ts_unix: u64,
            ) -> Result<u64, ErrorDetection> {
                self.validate()?;
                TimePolicy::validate_unix_secs_structural("timestamp", ts_unix)?;
                let slot_start = self.slot_start_unix_checked(slot)?;
                Ok(ts_unix.saturating_sub(slot_start))
            }
        }

        pub struct TimePolicy;

        impl TimePolicy {
            #[inline]
            pub fn now_unix_secs_runtime() -> Result<u64, ErrorDetection> {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| ErrorDetection::TimestampError {
                        message: "Timestamp error".into(),
                        details: e.to_string(),
                        source: None,
                    })?
                    .as_secs();

                Self::validate_unix_secs_structural("runtime_now_unix_secs", now)?;
                Ok(now)
            }

            #[inline]
            pub fn now_unix_millis_runtime() -> Result<u64, ErrorDetection> {
                let millis = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| ErrorDetection::TimestampError {
                        message: "Timestamp error".into(),
                        details: e.to_string(),
                        source: None,
                    })?
                    .as_millis();

                let now = u64::try_from(millis).map_err(|_| ErrorDetection::TimestampError {
                    message: "Timestamp error".into(),
                    details: "runtime UNIX milliseconds overflowed u64".into(),
                    source: None,
                })?;

                Self::validate_unix_millis_structural("runtime_now_unix_millis", now)?;
                Ok(now)
            }

            pub fn validate_unix_secs_structural(
                label: &'static str,
                ts: u64,
            ) -> Result<(), ErrorDetection> {
                if ts < UNIX_2000_SECS {
                    return Err(Self::validation_err(format!(
                        "{label}: timestamp below UNIX_2000_SECS: {ts}"
                    )));
                }

                if ts > UNIX_9999_SECS {
                    return Err(Self::validation_err(format!(
                        "{label}: timestamp above UNIX_9999_SECS: {ts}"
                    )));
                }

                Ok(())
            }

            pub fn validate_unix_millis_structural(
                label: &'static str,
                ts_ms: u64,
            ) -> Result<(), ErrorDetection> {
                if ts_ms < UNIX_2000_MILLIS {
                    return Err(Self::validation_err(format!(
                        "{label}: timestamp_ms below UNIX_2000_MILLIS: {ts_ms}"
                    )));
                }

                if ts_ms > UNIX_9999_MILLIS {
                    return Err(Self::validation_err(format!(
                        "{label}: timestamp_ms above UNIX_9999_MILLIS: {ts_ms}"
                    )));
                }

                Ok(())
            }

            pub fn validate_runtime_future_skew_secs(
                label: &'static str,
                ts: u64,
                now_unix: u64,
                max_future_skew_secs: u64,
            ) -> Result<(), ErrorDetection> {
                Self::validate_unix_secs_structural(label, ts)?;
                Self::validate_unix_secs_structural("now_unix", now_unix)?;

                let max_allowed = now_unix.checked_add(max_future_skew_secs).ok_or_else(|| {
                    Self::validation_err(format!(
                        "{label}: overflow computing future skew: now={now_unix} max_future_skew_secs={max_future_skew_secs}"
                    ))
                })?;

                Self::validate_unix_secs_structural("runtime_future_skew_max_allowed", max_allowed)?;

                if ts > max_allowed {
                    return Err(Self::validation_err(format!(
                        "{label}: timestamp too far in future: ts={ts} now={now_unix} max_future_skew_secs={max_future_skew_secs}"
                    )));
                }

                Ok(())
            }

            pub fn validate_runtime_future_skew_secs_default(
                label: &'static str,
                ts: u64,
                now_unix: u64,
            ) -> Result<(), ErrorDetection> {
                Self::validate_runtime_future_skew_secs(
                    label,
                    ts,
                    now_unix,
                    GlobalConfiguration::MAX_FUTURE_SKEW_SECS,
                )
            }

            pub fn validate_block_timestamp_against_parent(
                block_ts: u64,
                parent_ts: u64,
                min_delta_secs: u64,
            ) -> Result<(), ErrorDetection> {
                Self::validate_unix_secs_structural("block.timestamp", block_ts)?;
                Self::validate_unix_secs_structural("parent_block.timestamp", parent_ts)?;

                let min_allowed = parent_ts.checked_add(min_delta_secs).ok_or_else(|| {
                    Self::validation_err(format!(
                        "block.timestamp parent delta overflow: parent_ts={parent_ts} min_delta_secs={min_delta_secs}"
                    ))
                })?;

                Self::validate_unix_secs_structural("block.min_allowed_timestamp", min_allowed)?;

                if block_ts < min_allowed {
                    return Err(Self::validation_err(format!(
                        "block.timestamp too early: block_ts={block_ts} parent_ts={parent_ts} min_delta_secs={min_delta_secs}"
                    )));
                }

                Ok(())
            }

            pub fn validate_block_timestamp_for_declared_slot(
                cfg: ChainTimePolicyConfig,
                declared_slot: u64,
                block_ts: u64,
            ) -> Result<(), ErrorDetection> {
                cfg.validate()?;
                Self::validate_unix_secs_structural("block.timestamp", block_ts)?;

                let slot_start = cfg.slot_start_unix_checked(declared_slot)?;
                let drift = cfg.slot_gate_drift_secs;
                let earliest = slot_start.saturating_sub(drift);
                let latest = slot_start
                    .checked_add(cfg.block_interval_secs)
                    .and_then(|v| v.checked_add(drift))
                    .ok_or_else(|| {
                        Self::validation_err(format!(
                            "declared slot window overflow: slot={} slot_start={} block_interval={} drift={}",
                            declared_slot, slot_start, cfg.block_interval_secs, drift
                        ))
                    })?;

                Self::validate_unix_secs_structural("declared_slot.latest", latest)?;

                if block_ts < earliest || block_ts > latest {
                    return Err(Self::validation_err(format!(
                        "block.timestamp outside declared slot window: slot={declared_slot} ts={block_ts} earliest={earliest} latest={latest} drift={drift}"
                    )));
                }

                Ok(())
            }

            pub fn derive_slot_from_block_timestamp(
                cfg: ChainTimePolicyConfig,
                block_ts: u64,
            ) -> Result<(u64, u64), ErrorDetection> {
                cfg.validate()?;
                Self::validate_unix_secs_structural("block.timestamp", block_ts)?;
                let slot = cfg.slot_for_timestamp_checked(block_ts)?;
                let secs_into_slot = cfg.secs_into_slot_checked(slot, block_ts)?;
                Ok((slot, secs_into_slot))
            }

            pub fn canonical_event_timestamp_from_block(
                label: &'static str,
                containing_block_ts: u64,
            ) -> Result<u64, ErrorDetection> {
                Self::validate_unix_secs_structural(label, containing_block_ts)?;
                Ok(containing_block_ts)
            }

            pub fn validate_tx_timestamp_within_block_window(
                label: &'static str,
                tx_ts: u64,
                block_ts: u64,
                allowed_delta_secs: u64,
            ) -> Result<(), ErrorDetection> {
                Self::validate_unix_secs_structural(label, tx_ts)?;
                Self::validate_unix_secs_structural("block.timestamp", block_ts)?;

                let earliest = block_ts.saturating_sub(allowed_delta_secs);
                let latest = block_ts
                    .checked_add(allowed_delta_secs)
                    .ok_or_else(|| {
                        Self::validation_err(format!(
                            "{label}: overflow computing tx/block timestamp window: block_ts={block_ts} allowed_delta_secs={allowed_delta_secs}"
                        ))
                    })?;

                Self::validate_unix_secs_structural("tx_block_window.latest", latest)?;

                if tx_ts < earliest || tx_ts > latest {
                    return Err(Self::validation_err(format!(
                        "{label}: tx timestamp outside containing block window: tx_ts={tx_ts} block_ts={block_ts} allowed_delta_secs={allowed_delta_secs}"
                    )));
                }

                Ok(())
            }

            pub fn validate_offchain_timestamp_ms(
                label: &'static str,
                ts_ms: u64,
                now_ms: u64,
                max_future_skew_ms: u64,
                max_past_age_ms: Option<u64>,
            ) -> Result<(), ErrorDetection> {
                Self::validate_unix_millis_structural(label, ts_ms)?;
                Self::validate_unix_millis_structural("now_ms", now_ms)?;

                let max_allowed = now_ms.checked_add(max_future_skew_ms).ok_or_else(|| {
                    Self::validation_err(format!(
                        "{label}: overflow computing future skew ms: now_ms={now_ms} max_future_skew_ms={max_future_skew_ms}"
                    ))
                })?;

                Self::validate_unix_millis_structural("offchain_future_skew_max_allowed", max_allowed)?;

                if ts_ms > max_allowed {
                    return Err(Self::validation_err(format!(
                        "{label}: timestamp_ms too far in future: ts_ms={ts_ms} now_ms={now_ms} max_future_skew_ms={max_future_skew_ms}"
                    )));
                }

                if let Some(max_past) = max_past_age_ms {
                    let min_allowed = now_ms.saturating_sub(max_past);
                    if ts_ms < min_allowed {
                        return Err(Self::validation_err(format!(
                            "{label}: timestamp_ms too old: ts_ms={ts_ms} now_ms={now_ms} max_past_age_ms={max_past}"
                        )));
                    }
                }

                Ok(())
            }

            #[inline]
            pub(crate) fn validation_err(message: impl Into<String>) -> ErrorDetection {
                ErrorDetection::ValidationError {
                    message: message.into(),
                    tx_id: None,
                }
            }
        }
    }

    pub mod hash_system_remzarhash {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use blake3::Hasher;
        use postcard::to_allocvec;
        use serde::Serialize;

        pub struct RemzarHash;

        impl RemzarHash {
            const MAX_SERIALIZED_BYTES: usize = 4 * 1024 * 1024;

            #[inline]
            fn ensure_size_limit(len: usize, context: &'static str) -> Result<(), ErrorDetection> {
                if len > Self::MAX_SERIALIZED_BYTES {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "{context} serialized size {len} exceeds MAX_SERIALIZED_BYTES {}",
                            Self::MAX_SERIALIZED_BYTES
                        ),
                        tx_id: None,
                    });
                }

                Ok(())
            }

            #[inline]
            pub fn compute_bytes_hash(bytes: &[u8]) -> [u8; 64] {
                let mut h = Hasher::new();
                h.update(bytes);

                let mut out = [0u8; 64];
                h.finalize_xof().fill(&mut out);
                out
            }

            #[inline]
            pub fn compute_bytes_hash_hex(bytes: &[u8]) -> String {
                hex::encode(Self::compute_bytes_hash(bytes))
            }

            pub fn compute_data_hash<T: Serialize + ?Sized>(
                data: &T,
            ) -> Result<String, ErrorDetection> {
                let bytes = to_allocvec(data).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })?;

                Self::ensure_size_limit(bytes.len(), "compute_data_hash")?;
                Ok(Self::compute_bytes_hash_hex(&bytes))
            }

            pub fn compute_merkle_root<T: Serialize + Send + Sync>(
                transactions: &[T],
            ) -> Result<String, ErrorDetection> {
                let mut h = Hasher::new();

                if transactions.is_empty() {
                    h.update(b"EMPTY_MERKLE_ROOT");
                } else {
                    for tx in transactions {
                        let bytes =
                            to_allocvec(tx).map_err(|e| ErrorDetection::SerializationError {
                                details: e.to_string(),
                            })?;

                        Self::ensure_size_limit(bytes.len(), "compute_merkle_root(tx)")?;
                        h.update(&bytes);
                    }
                }

                let mut out = [0u8; 64];
                h.finalize_xof().fill(&mut out);
                Ok(hex::encode(out))
            }

            pub fn compute_dummy_hash() -> String {
                Self::compute_bytes_hash_hex(b"remzar_empty_block_mint")
            }
        }
    }
}

mod consensus {
    pub mod por_002_puzzle_engine {
        #[derive(Debug, Default)]
        pub struct PorPuzzleEngine;
    }

    pub mod por_004_puzzle_proof {
        use crate::consensus::por_002_puzzle_engine::PorPuzzleEngine;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct PorPuzzleProof {
            pub height: u64,
            pub validator: String,
            pub prev_block_hash: [u8; 64],
            pub output: u128,
        }

        impl PorPuzzleProof {
            pub fn verify_with_engine_checked(
                &self,
                _engine: &PorPuzzleEngine,
            ) -> Result<bool, ErrorDetection> {
                Ok(self.output != 0)
            }
        }
    }
}

#[path = "../../src/blockchain/block_003_puzzleproof.rs"]
mod real_block_003_puzzleproof;

mod blockchain {
    pub mod genesis_001_block {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use crate::utility::time_policy::TimePolicy;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct GenesisBlock {
            pub genesis_hash: [u8; 64],
            pub merkle_root: [u8; 64],
            pub prev_hash: [u8; 64],
            pub timestamp: u64,
            pub data: String,
            pub founder_wallet: Option<String>,
        }

        impl GenesisBlock {
            pub fn validate(&self) -> Result<(), ErrorDetection> {
                TimePolicy::validate_unix_secs_structural("GenesisBlock.timestamp", self.timestamp)?;

                if self.prev_hash != [0u8; 64] {
                    return Err(ErrorDetection::ValidationError {
                        message: "GenesisBlock.prev_hash must be all zeros".into(),
                        tx_id: None,
                    });
                }

                if self.genesis_hash == [0u8; 64] {
                    return Err(ErrorDetection::ValidationError {
                        message: "GenesisBlock.genesis_hash must not be all zeros".into(),
                        tx_id: None,
                    });
                }

                if self.merkle_root == [0u8; 64] {
                    return Err(ErrorDetection::ValidationError {
                        message: "GenesisBlock.merkle_root must not be all zeros".into(),
                        tx_id: None,
                    });
                }

                if self.data.len() > GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "GenesisBlock.data too large: {} bytes exceeds {}",
                            self.data.len(),
                            GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES
                        ),
                        tx_id: None,
                    });
                }

                if let Some(founder_wallet) = self.founder_wallet.as_deref() {
                    let _ = canon_wallet_id_checked(founder_wallet)?;
                }

                Ok(())
            }
        }
    }

    pub mod block_003_puzzleproof {
        pub use crate::real_block_003_puzzleproof::*;
    }
}

#[path = "../../src/blockchain/block_001_metadata.rs"]
mod block_001_metadata;

use blockchain::block_003_puzzleproof::BlockPuzzleProof;
use blockchain::genesis_001_block::GenesisBlock;
use block_001_metadata::BlockMetadata;
use consensus::por_002_puzzle_engine::PorPuzzleEngine;
use utility::alpha_001_global_configuration::GlobalConfiguration;
use utility::alpha_002_error_detection_system::ErrorDetection;
use utility::time_policy::{ChainTimePolicyConfig, TimePolicy};

fn touch_error(error: &ErrorDetection) {
    match error {
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            let _ = tx_id.as_ref().map(|s| s.len());
        }
        ErrorDetection::SerializationError { details } => {
            let _ = details.len();
        }
        ErrorDetection::TimestampError {
            message,
            details,
            source,
        } => {
            let _ = message.len();
            let _ = details.len();
            let _ = source.as_ref().map(|s| s.len());
        }
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            touch_error(&error);
            None
        }
    }
}

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for i in 0..8 {
        out[i] = byte_at(data, offset + i, i as u8);
    }

    u64::from_le_bytes(out)
}

fn read_u128(data: &[u8], offset: usize) -> u128 {
    let mut out = [0u8; 16];

    for i in 0..16 {
        out[i] = byte_at(data, offset + i, i as u8);
    }

    u128::from_le_bytes(out)
}

fn fuzz_hash(data: &[u8], salt: usize) -> [u8; 64] {
    let mut out = [0u8; 64];

    if data.is_empty() {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(salt as u8).wrapping_add(1);
        }
        return out;
    }

    for i in 0..64 {
        let a = data[(i + salt) % data.len()];
        let b = data[(i.wrapping_mul(7).wrapping_add(salt)) % data.len()];
        out[i] = a ^ b ^ (i as u8).wrapping_add(salt as u8);
    }

    out
}

fn non_sentinel_hash(data: &[u8], salt: usize) -> [u8; 64] {
    let mut h = fuzz_hash(data, salt);

    if h == [0u8; 64] {
        h[0] = 1;
    }

    if h == [0xFFu8; 64] {
        h[0] = 0x7F;
    }

    h
}

fn different_nonzero_hash(data: &[u8], salt: usize, other: &[u8; 64]) -> [u8; 64] {
    let mut h = non_sentinel_hash(data, salt);

    if &h == other {
        h[0] ^= 0xA5;
        if h == [0u8; 64] {
            h[0] = 1;
        }
    }

    h
}

fn fuzz_signature(data: &[u8], salt: usize) -> [u8; ml_dsa_65::SIG_LEN] {
    let mut out = [0u8; ml_dsa_65::SIG_LEN];

    if data.is_empty() {
        out[0] = 1;
        return out;
    }

    for i in 0..out.len() {
        let a = data[(i + salt) % data.len()];
        let b = data[(i.wrapping_mul(13).wrapping_add(salt)) % data.len()];
        out[i] = a ^ b ^ (salt as u8);
    }

    if out == [0u8; ml_dsa_65::SIG_LEN] {
        out[0] = 1;
    }

    out
}

fn canonical_wallet(data: &[u8], salt: usize) -> String {
    let h = non_sentinel_hash(data, salt);
    format!("r{}", hex::encode(h))
}

fn bounded_height(data: &[u8], offset: usize) -> u64 {
    (read_u64(data, offset) % 10_000_000) + 1
}

fn valid_timestamp(data: &[u8], offset: usize) -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS + (read_u64(data, offset) % 2_000_000)
}

fn valid_size(data: &[u8], offset: usize) -> u64 {
    GlobalConfiguration::MIN_BLOCK_SIZE + (read_u64(data, offset) % 7_500)
}

fn is_lower_hex_128(s: &str) -> bool {
    s.len() == 128 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn mutate_valid_hex_128(s: &str, data: &[u8]) -> String {
    let mut bytes = s.as_bytes().to_vec();

    if !bytes.is_empty() {
        let idx = byte_at(data, 91, 0) as usize % bytes.len();
        bytes[idx] = match bytes[idx] {
            b'0' => b'1',
            b'1' => b'2',
            b'a' => b'b',
            b'f' => b'e',
            _ => b'0',
        };
    }

    String::from_utf8(bytes).unwrap_or_else(|_| "0".repeat(128))
}

fn mutate_bytes(buf: &mut [u8], data: &[u8], salt: usize) {
    if buf.is_empty() {
        return;
    }

    if data.is_empty() {
        buf[salt % buf.len()] ^= 0xA5;
        return;
    }

    let stride = ((data[0] as usize) % 31) + 1;

    for (i, byte) in data.iter().enumerate() {
        let idx = i
            .wrapping_mul(stride)
            .wrapping_add(salt)
            .wrapping_rem(buf.len());

        buf[idx] ^= *byte;
    }
}

fn mutate_length(mut buf: Vec<u8>, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        if !buf.is_empty() {
            buf.pop();
        }
        return buf;
    }

    match data[0] % 7 {
        0 => buf.clear(),
        1 => {
            let new_len = byte_at(data, 1, 0) as usize % buf.len().saturating_add(1);
            buf.truncate(new_len);
        }
        2 => buf.push(byte_at(data, 2, 0)),
        3 => buf.extend_from_slice(data),
        4 => {
            if !buf.is_empty() {
                let idx = byte_at(data, 3, 0) as usize % buf.len();
                buf.remove(idx);
            }
        }
        5 => {
            let remove = ((byte_at(data, 4, 0) as usize) % 32) + 1;
            let new_len = buf.len().saturating_sub(remove);
            buf.truncate(new_len);
        }
        _ => {}
    }

    buf
}

fn make_transactions(data: &[u8]) -> Vec<Vec<u8>> {
    let count = byte_at(data, 17, 0) as usize % 8;
    let mut cursor = 18usize;
    let mut txs = Vec::with_capacity(count);

    for tx_index in 0..count {
        let len = byte_at(data, cursor, tx_index as u8) as usize % 64;
        cursor = cursor.wrapping_add(1);

        let mut tx = Vec::with_capacity(len);
        for j in 0..len {
            tx.push(byte_at(data, cursor + j, j as u8) ^ tx_index as u8);
        }

        cursor = cursor.wrapping_add(len);
        txs.push(tx);
    }

    txs
}

fn make_valid_proof(
    height: u64,
    prev_block_hash: [u8; 64],
    data: &[u8],
    salt: usize,
) -> Option<BlockPuzzleProof> {
    let output = read_u128(data, salt).max(1);
    let validator = canonical_wallet(data, salt.wrapping_add(33));

    touch_result(BlockPuzzleProof::new(
        height,
        validator,
        prev_block_hash,
        output,
    ))
}

fn make_direct_proof(data: &[u8], salt: usize) -> BlockPuzzleProof {
    let mode = byte_at(data, salt, 0) % 6;

    let height = match mode {
        0 => 10_000_001,
        _ => read_u64(data, salt) % 10_000_001,
    };

    let validator = match mode {
        1 => String::new(),
        2 => "rzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".into(),
        3 => "x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111".into(),
        _ => canonical_wallet(data, salt.wrapping_add(44)),
    };

    let prev_block_hash = match mode {
        4 => [0u8; 64],
        5 => [0xFFu8; 64],
        _ => non_sentinel_hash(data, salt.wrapping_add(55)),
    };

    let output = if mode == 0 {
        0
    } else {
        read_u128(data, salt.wrapping_add(66))
    };

    BlockPuzzleProof {
        height,
        validator,
        prev_block_hash,
        output,
    }
}

fn exercise_proof(proof: BlockPuzzleProof, data: &[u8]) {
    let _ = format!("{:?}", &proof);

    let _ = touch_result(proof.validate_structural());

    if let Some(commitment) = touch_result(proof.commitment_bytes()) {
        assert_eq!(commitment.len(), 64);
    }

    if let Some(hex_commitment) = touch_result(proof.commitment_hex()) {
        assert!(is_lower_hex_128(&hex_commitment));
    }

    let gossip = proof.to_gossip();
    let _ = touch_result(BlockPuzzleProof::from_gossip(&gossip)).map(|roundtrip| {
        let _ = touch_result(roundtrip.validate_structural());
        let _ = touch_result(roundtrip.commitment_bytes());
    });

    let engine = PorPuzzleEngine::default();
    let _ = proof.verify_with_engine(&engine);
    let _ = touch_result(proof.verify_with_engine_checked(&engine));

    let mut mutated = proof.clone();
    mutated.output ^= read_u128(data, 123).max(1);
    let _ = touch_result(mutated.validate_structural());
    let _ = touch_result(mutated.commitment_bytes());
}

fn make_valid_metadata(data: &[u8], with_proof: bool) -> BlockMetadata {
    let index = bounded_height(data, 0);
    let timestamp = valid_timestamp(data, 8);
    let previous_hash = non_sentinel_hash(data, 21);
    let merkle_root = different_nonzero_hash(data, 37, &previous_hash);
    let guardian_signature = fuzz_signature(data, 53);
    let size = valid_size(data, 69);

    let puzzle_proof = if with_proof {
        make_valid_proof(index, previous_hash, data, 85)
    } else {
        None
    };

    BlockMetadata::new(
        index,
        timestamp,
        previous_hash,
        merkle_root,
        guardian_signature,
        puzzle_proof,
        size,
    )
}

fn make_genesis(data: &[u8]) -> GenesisBlock {
    let prev_hash = [0u8; 64];
    let merkle_root = non_sentinel_hash(data, 700);
    let genesis_hash = different_nonzero_hash(data, 701, &merkle_root);

    GenesisBlock {
        genesis_hash,
        merkle_root,
        prev_hash,
        timestamp: valid_timestamp(data, 702),
        data: "remzar fuzz genesis".to_string(),
        founder_wallet: Some(canonical_wallet(data, 703)),
    }
}

fn exercise_metadata(mut meta: BlockMetadata, data: &[u8]) {
    let _ = format!("{:?}", &meta);

    let _ = touch_result(meta.validate_structural());
    let _ = touch_result(meta.validate_size());

    let now = valid_timestamp(data, 201).saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS);
    let _ = touch_result(meta.validate_against_now(now));

    let previous_timestamp = read_u64(data, 209);
    let _ = touch_result(meta.validate_timestamp(previous_timestamp));

    let close_previous = meta
        .timestamp
        .saturating_sub(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS);
    let _ = touch_result(meta.validate_timestamp(close_previous));

    if let Some(proof) = meta.puzzle_proof().cloned() {
        exercise_proof(proof, data);
    }

    if let Some(commitment) = touch_result(meta.puzzle_commitment_bytes()) {
        assert_eq!(commitment.len(), 64);
    }

    if let Some(commitment_hex) = touch_result(meta.puzzle_commitment_hex()) {
        assert!(is_lower_hex_128(&commitment_hex));
    }

    if let Some(hash) = touch_result(meta.compute_hash()) {
        assert!(is_lower_hex_128(&hash));

        if let Some(ok) = touch_result(meta.verify_hash(&hash)) {
            assert!(ok, "BlockMetadata must verify against its own computed hash");
        }

        let mutated_hash = mutate_valid_hex_128(&hash, data);
        let _ = touch_result(meta.verify_hash(&mutated_hash));

        let short_hash = &hash[..64];
        let _ = touch_result(meta.verify_hash(short_hash));

        let long_hash = format!("{hash}00");
        let _ = touch_result(meta.verify_hash(&long_hash));
    }

    let fuzz_expected = String::from_utf8_lossy(data).to_string();
    let _ = touch_result(meta.verify_hash(&fuzz_expected));

    if let Some(encoded) = touch_result(meta.to_bytes()) {
        assert!(encoded.len() <= GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES);

        if let Some(decoded) = touch_result(BlockMetadata::from_bytes(&encoded)) {
            assert_eq!(decoded, meta);

            if let Some(reencoded) = touch_result(decoded.to_bytes()) {
                assert_eq!(reencoded, encoded);
            }
        }

        let mut mutated = encoded.clone();
        mutate_bytes(&mut mutated, data, 313);
        let _ = touch_result(BlockMetadata::from_bytes(&mutated));

        let resized = mutate_length(encoded.clone(), data);
        let _ = touch_result(BlockMetadata::from_bytes(&resized));

        let mut trailing_zero = encoded.clone();
        trailing_zero.push(0);
        let _ = touch_result(BlockMetadata::from_bytes(&trailing_zero));

        let mut trailing_nonzero = encoded;
        trailing_nonzero.push(byte_at(data, 333, 1).max(1));
        let _ = touch_result(BlockMetadata::from_bytes(&trailing_nonzero));
    }

    let empty_transactions: Vec<Vec<u8>> = Vec::new();
    let _ = touch_result(meta.set_merkle_root(&empty_transactions));

    let txs = make_transactions(data);
    let _ = touch_result(meta.set_merkle_root(&txs));

    meta.set_guardian_signature(fuzz_signature(data, 401));

    let replacement_proof = make_valid_proof(meta.index, meta.previous_hash, data, 409);
    meta.set_puzzle_proof(replacement_proof);
    let _ = touch_result(meta.validate_structural());

    meta.set_puzzle_proof(None);
    let _ = touch_result(meta.puzzle_commitment_bytes());
}

fn exercise_invalid_shapes(data: &[u8]) {
    let valid = make_valid_metadata(data, true);

    let mut too_high_index = valid.clone();
    too_high_index.index = 10_000_001;
    exercise_metadata(too_high_index, data);

    let mut too_small_size = valid.clone();
    too_small_size.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1);
    exercise_metadata(too_small_size, data);

    let mut too_large_size = valid.clone();
    too_large_size.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);
    exercise_metadata(too_large_size, data);

    let mut old_timestamp = valid.clone();
    old_timestamp.timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1);
    exercise_metadata(old_timestamp, data);

    let mut zero_prev = valid.clone();
    zero_prev.previous_hash = [0u8; 64];
    exercise_metadata(zero_prev, data);

    let mut zero_merkle = valid.clone();
    zero_merkle.merkle_root = [0u8; 64];
    exercise_metadata(zero_merkle, data);

    let mut zero_sig = valid.clone();
    zero_sig.guardian_signature = [0u8; ml_dsa_65::SIG_LEN];
    exercise_metadata(zero_sig, data);

    let mut equal_hashes = valid.clone();
    equal_hashes.merkle_root = equal_hashes.previous_hash;
    exercise_metadata(equal_hashes, data);

    let mut genesis_with_proof = valid.clone();
    genesis_with_proof.index = 0;
    genesis_with_proof.guardian_signature = [0u8; ml_dsa_65::SIG_LEN];
    genesis_with_proof.puzzle_proof = make_valid_proof(0, genesis_with_proof.previous_hash, data, 501);
    exercise_metadata(genesis_with_proof, data);

    let mut proof_height_mismatch = valid.clone();
    if let Some(mut proof) = proof_height_mismatch.puzzle_proof.clone() {
        proof.height = proof_height_mismatch.index.saturating_add(1);
        proof_height_mismatch.puzzle_proof = Some(proof);
    }
    exercise_metadata(proof_height_mismatch, data);

    let mut proof_prev_mismatch = valid.clone();
    if let Some(mut proof) = proof_prev_mismatch.puzzle_proof.clone() {
        proof.prev_block_hash = different_nonzero_hash(data, 601, &proof_prev_mismatch.previous_hash);
        proof_prev_mismatch.puzzle_proof = Some(proof);
    }
    exercise_metadata(proof_prev_mismatch, data);

    let mut direct_bad_proof_meta = valid;
    direct_bad_proof_meta.puzzle_proof = Some(make_direct_proof(data, 777));
    exercise_metadata(direct_bad_proof_meta, data);
}

fn exercise_time_policy(data: &[u8]) {
    let base = GlobalConfiguration::MIN_TIMESTAMP_SECS;
    let block_interval = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
    let slot_gate_drift = GlobalConfiguration::SLOT_GATE_DRIFT_SECS;

    let genesis_ts = base.saturating_add(read_u64(data, 1200) % 1_000_000);
    let slot = read_u64(data, 1208) % 100_000;
    let cfg = ChainTimePolicyConfig::new(genesis_ts, block_interval, slot_gate_drift);

    let _ = touch_result(cfg.validate());

    if let Some(slot_start) = touch_result(cfg.slot_start_unix_checked(slot)) {
        let block_ts = slot_start.saturating_add(read_u64(data, 1216) % block_interval);

        let _ = touch_result(TimePolicy::validate_unix_secs_structural(
            "fuzz.metadata.block_ts",
            block_ts,
        ));

        let _ = touch_result(TimePolicy::canonical_event_timestamp_from_block(
            "fuzz.metadata.canonical_event_ts",
            block_ts,
        ));

        let _ = touch_result(cfg.slot_for_timestamp_checked(block_ts));
        let _ = touch_result(cfg.secs_into_slot_checked(slot, block_ts));
        let _ = touch_result(TimePolicy::derive_slot_from_block_timestamp(cfg, block_ts));
        let _ = touch_result(TimePolicy::validate_block_timestamp_for_declared_slot(
            cfg, slot, block_ts,
        ));

        let parent_ts = block_ts.saturating_sub(block_interval);
        let _ = touch_result(TimePolicy::validate_block_timestamp_against_parent(
            block_ts,
            parent_ts,
            block_interval,
        ));

        let now = block_ts.saturating_add(read_u64(data, 1224) % 100_000);
        let _ = touch_result(TimePolicy::validate_runtime_future_skew_secs(
            "fuzz.metadata.block_ts",
            block_ts,
            now,
            GlobalConfiguration::MAX_FUTURE_DRIFT_SECS,
        ));

        let tx_ts = block_ts.saturating_add(read_u64(data, 1232) % block_interval);
        let _ = touch_result(TimePolicy::validate_tx_timestamp_within_block_window(
            "fuzz.metadata.tx_ts",
            tx_ts,
            block_ts,
            block_interval,
        ));
    }

    let _ = touch_result(TimePolicy::now_unix_secs_runtime());
    let _ = touch_result(TimePolicy::now_unix_millis_runtime());
}

fuzz_target!(|data: &[u8]| {
    exercise_time_policy(data);

    // 1. Raw untrusted metadata bytes through the real canonical decoder.
    if let Some(meta) = touch_result(BlockMetadata::from_bytes(data)) {
        exercise_metadata(meta, data);
    }

    // 2. Raw postcard decode without structural validation, then run real methods.
    if let Ok(meta) = postcard::from_bytes::<BlockMetadata>(data) {
        exercise_metadata(meta, data);
    }

    // 3. Explicit over-cap payload must reject cleanly.
    let over_cap = vec![0xA5; GlobalConfiguration::MAX_METADATA_DECOMPRESSED_BYTES + 1];
    let _ = touch_result(BlockMetadata::from_bytes(&over_cap));

    // 4. Valid non-genesis metadata without puzzle proof.
    let valid_without_proof = make_valid_metadata(data, false);
    exercise_metadata(valid_without_proof, data);

    // 5. Valid non-genesis metadata with structurally aligned puzzle proof.
    let valid_with_proof = make_valid_metadata(data, true);
    exercise_metadata(valid_with_proof, data);

    // 6. Genesis conversion path.
    let genesis = make_genesis(data);
    if let Some(meta) = touch_result(BlockMetadata::from_genesis(genesis)) {
        assert_eq!(meta.index, 0);
        assert!(meta.puzzle_proof.is_none());
        exercise_metadata(meta, data);
    }

    // 7. Invalid genesis: zero merkle root must reject cleanly.
    let mut bad_genesis = make_genesis(data);
    bad_genesis.merkle_root = [0u8; 64];
    let _ = touch_result(BlockMetadata::from_genesis(bad_genesis));

    // 8. Boundary and malformed object shapes.
    exercise_invalid_shapes(data);

    // 9. Standalone real BlockPuzzleProof structural and commitment fuzzing.
    let direct_proof = make_direct_proof(data, 900);
    exercise_proof(direct_proof, data);

    let prev = non_sentinel_hash(data, 950);
    if let Some(valid_proof) = make_valid_proof(bounded_height(data, 960), prev, data, 970) {
        exercise_proof(valid_proof, data);
    }
});