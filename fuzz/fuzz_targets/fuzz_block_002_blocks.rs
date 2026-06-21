#![no_main]

use fips204::ml_dsa_65;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
            pub const MIN_BLOCK_SIZE: u64 = 64;

            pub const MAX_METADATA_DECOMPRESSED_BYTES: usize = 8 * 1024;
            pub const MIN_TIMESTAMP_SECS: u64 = 946_684_800;
            pub const MAX_FUTURE_DRIFT_SECS: u64 = 3600 * 24 * 365 * 10;
            pub const MAX_FUTURE_SKEW_SECS: u64 = Self::MAX_FUTURE_DRIFT_SECS;
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;

            pub const GUARDIAN_SIG_LEN: usize = fips204::ml_dsa_65::SIG_LEN;

            pub const DOMAIN_SEPARATION_ON: bool = false;
            pub const DOMAIN_TAG: &'static [u8] = b"remzar_guardian_domain";

            pub const MAX_BATCH_ITEMS: usize = 64;
            pub const MAX_ITEM_BYTES: usize = 4096;
            pub const MAX_TOTAL_BATCH_BYTES: usize =
                Self::MAX_BATCH_ITEMS * Self::MAX_ITEM_BYTES;
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
            CryptographicError {
                message: String,
            },
            MerkleProofGenerationError {
                reason: String,
            },
            SignatureVerificationFailed {
                message: String,
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
                    Self::CryptographicError { message } => write!(f, "{message}"),
                    Self::MerkleProofGenerationError { reason } => write!(f, "{reason}"),
                    Self::SignatureVerificationFailed { message } => write!(f, "{message}"),
                    Self::TimestampError { message, details, .. } => write!(f, "{message}: {details}"),
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
                    message: format!(
                        "Wallet address length mismatch: expected {}, got {}",
                        REMZAR_WALLET_LEN,
                        s.len()
                    ),
                    tx_id: None,
                });
            }

            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address must start with r".into(),
                    tx_id: None,
                });
            }

            if !b
                .get(1..)
                .is_some_and(|body| body.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
            {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address body must be 128 lowercase hex chars".into(),
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

#[path = "../../src/cryptography/ml_dsa_65_004_guardian_signature.rs"]
mod real_guardian_signature;

mod cryptography {
    pub mod ml_dsa_65_002_merkleproof {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub fn compute_merkle_root(
            hashes: &[[u8; 64]],
        ) -> Result<([u8; 64], Vec<Vec<[u8; 64]>>), ErrorDetection> {
            if hashes.len() > GlobalConfiguration::MAX_BATCH_ITEMS {
                return Err(ErrorDetection::MerkleProofGenerationError {
                    reason: format!(
                        "hash count {} exceeds MAX_BATCH_ITEMS {}",
                        hashes.len(),
                        GlobalConfiguration::MAX_BATCH_ITEMS
                    ),
                });
            }

            let mut current = if hashes.is_empty() {
                vec![crate::utility::hash_system_remzarhash::RemzarHash::compute_bytes_hash(
                    b"EMPTY_GUARDIAN_BATCH",
                )]
            } else {
                hashes.to_vec()
            };

            let mut levels = vec![current.clone()];

            while current.len() > 1 {
                let mut next = Vec::with_capacity((current.len() + 1) / 2);

                for pair in current.chunks(2) {
                    let left = pair[0];
                    let right = if pair.len() == 2 { pair[1] } else { pair[0] };

                    let mut buf = Vec::with_capacity(128);
                    buf.extend_from_slice(&left);
                    buf.extend_from_slice(&right);

                    next.push(
                        crate::utility::hash_system_remzarhash::RemzarHash::compute_bytes_hash(
                            &buf,
                        ),
                    );
                }

                current = next;
                levels.push(current.clone());
            }

            Ok((current[0], levels))
        }
    }

    pub mod ml_dsa_65_004_guardian_signature {
        pub use crate::real_guardian_signature::*;
    }
}

#[path = "../../src/blockchain/block_003_puzzleproof.rs"]
mod real_block_003_puzzleproof;

#[path = "../../src/blockchain/block_001_metadata.rs"]
mod real_block_001_metadata;

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
                TimePolicy::validate_unix_secs_structural("genesis.timestamp", self.timestamp)?;

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

    pub mod block_001_metadata {
        pub use crate::real_block_001_metadata::*;
    }
}

#[path = "../../src/blockchain/block_002_blocks.rs"]
mod block_002_blocks;

use blockchain::block_001_metadata::BlockMetadata;
use blockchain::block_003_puzzleproof::BlockPuzzleProof;
use block_002_blocks::Block;
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
        ErrorDetection::CryptographicError { message } => {
            let _ = message.len();
        }
        ErrorDetection::MerkleProofGenerationError { reason } => {
            let _ = reason.len();
        }
        ErrorDetection::SignatureVerificationFailed { message } => {
            let _ = message.len();
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

fn keypair() -> Option<&'static (ml_dsa_65::PublicKey, ml_dsa_65::PrivateKey)> {
    static KEYS: OnceLock<Option<(ml_dsa_65::PublicKey, ml_dsa_65::PrivateKey)>> = OnceLock::new();

    KEYS.get_or_init(|| ml_dsa_65::try_keygen().ok()).as_ref()
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

fn maybe_uppercase_wallet(wallet: String, data: &[u8]) -> String {
    if byte_at(data, 701, 0) & 1 == 0 {
        wallet
    } else {
        wallet.to_ascii_uppercase().replacen('R', "r", 1)
    }
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

fn bounded_reward(data: &[u8], offset: usize) -> u64 {
    read_u64(data, offset) % 10_000_000_000
}

fn fuzz_batch_key(data: &[u8], salt: usize) -> Option<String> {
    match byte_at(data, salt, 0) % 5 {
        0 => None,
        1 => Some(String::new()),
        2 => Some(hex::encode(non_sentinel_hash(data, salt + 1))),
        3 => {
            let len = byte_at(data, salt + 2, 0) as usize % 256;
            let mut s = String::with_capacity(len);
            for i in 0..len {
                let ch = b'a'.wrapping_add(byte_at(data, salt + 3 + i, i as u8) % 26);
                s.push(char::from(ch));
            }
            Some(s)
        }
        _ => Some("remzar_batch_key".to_string()),
    }
}

fn overlong_batch_key(data: &[u8]) -> String {
    let fill = char::from(b'a'.wrapping_add(byte_at(data, 777, 0) % 26));
    std::iter::repeat(fill).take(4097).collect()
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

fn make_genesis_metadata(data: &[u8]) -> BlockMetadata {
    BlockMetadata::new(
        0,
        valid_timestamp(data, 501),
        [0u8; 64],
        non_sentinel_hash(data, 502),
        [0u8; ml_dsa_65::SIG_LEN],
        None,
        valid_size(data, 503),
    )
}

fn is_lower_hex_128(s: &str) -> bool {
    s.len() == 128 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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

fn exercise_block(mut block: Block, data: &[u8]) {
    let _ = format!("{:?}", &block);

    let _ = block.miner_wallet().len();

    let hash_hex = block.hash_hex();
    assert!(is_lower_hex_128(&hash_hex));

    if let Some(computed) = touch_result(block.compute_block_hash()) {
        assert!(is_lower_hex_128(&computed));
    }

    let _ = touch_result(block.verify_block_hash());
    let _ = touch_result(block.validate(None));

    let prev_ts = block
        .metadata
        .timestamp
        .saturating_sub(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS);
    let _ = touch_result(block.validate(Some(prev_ts)));

    if let Some(unpadded_len) = touch_result(block.encoded_len_unpadded()) {
        assert!(
            unpadded_len <= usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX)
        );
    }

    let padded_len = block.encoded_len_padded();
    let _ = padded_len;

    if let Some(storage) = touch_result(block.serialize_for_storage()) {
        assert!(
            storage.len() <= usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX)
        );

        if let Some(decoded) = touch_result(Block::deserialize_from_storage(&storage)) {
            let _ = touch_result(decoded.validate(None));
            let _ = touch_result(decoded.verify_block_hash());
        }

        if let Some((decoded, actual, stored)) = touch_result(Block::deserialize_with_sizes(&storage))
        {
            assert!(actual > 0);
            assert!(actual <= stored);
            assert_eq!(stored, storage.len());
            let _ = touch_result(decoded.validate(None));
        }

        let mut mutated = storage.clone();
        mutate_bytes(&mut mutated, data, 101);
        let _ = touch_result(Block::deserialize_from_storage(&mutated));
        let _ = touch_result(Block::deserialize_with_sizes(&mutated));

        let resized = mutate_length(storage.clone(), data);
        let _ = touch_result(Block::deserialize_from_storage(&resized));
        let _ = touch_result(Block::deserialize_with_sizes(&resized));

        let mut padded_zero = storage.clone();
        padded_zero.extend(std::iter::repeat(0u8).take(byte_at(data, 111, 0) as usize % 64));
        let _ = touch_result(Block::deserialize_from_storage(&padded_zero));
        let _ = touch_result(Block::deserialize_with_sizes(&padded_zero));

        let mut padded_nonzero = storage;
        padded_nonzero.push(byte_at(data, 112, 1).max(1));
        let _ = touch_result(Block::deserialize_from_storage(&padded_nonzero));
        let _ = touch_result(Block::deserialize_with_sizes(&padded_nonzero));
    }

    let mut bad_hash = block.clone();
    bad_hash.block_hash[0] ^= 0xA5;
    let _ = touch_result(bad_hash.verify_block_hash());
    let _ = touch_result(bad_hash.validate(None));

    if let Some((vk, sk)) = keypair() {
        let _ = touch_result(block.sign_block(sk));

        let _ = touch_result(block.verify_block_signature(vk));
        let _ = touch_result(block.verify_block_hash());
        let _ = touch_result(block.validate(None));

        let mut tampered_after_sign = block.clone();
        tampered_after_sign.reward ^= 1;
        let _ = touch_result(tampered_after_sign.verify_block_hash());
        let _ = touch_result(tampered_after_sign.validate(None));

        let mut tampered_sig = block.clone();
        tampered_sig.metadata.guardian_signature[0] ^= 0x5A;
        let _ = touch_result(tampered_sig.verify_block_signature(vk));
        let _ = touch_result(tampered_sig.verify_block_hash());
    }
}

fn exercise_constructors(data: &[u8]) {
    let metadata = make_valid_metadata(data, true);
    let miner = maybe_uppercase_wallet(canonical_wallet(data, 200), data);
    let reward = bounded_reward(data, 208);
    let batch_key = fuzz_batch_key(data, 216);

    if let Some(block) = touch_result(Block::new(
        metadata.clone(),
        batch_key.clone(),
        miner.clone(),
        reward,
    )) {
        exercise_block(block, data);
    }

    if let Some(block_none) = touch_result(Block::new(
        metadata.clone(),
        None,
        miner.clone(),
        reward,
    )) {
        if let Some(block_empty) = touch_result(Block::new(
            metadata.clone(),
            Some(String::new()),
            miner.clone(),
            reward,
        )) {
            assert_eq!(
                block_none.compute_block_hash().ok(),
                block_empty.compute_block_hash().ok(),
                "None and Some(empty) batch_key must hash identically"
            );
        }

        exercise_block(block_none, data);
    }

    let _ = touch_result(Block::new(
        metadata.clone(),
        Some(overlong_batch_key(data)),
        miner.clone(),
        reward,
    ));

    let _ = touch_result(Block::new(
        metadata.clone(),
        batch_key.clone(),
        String::new(),
        reward,
    ));

    let _ = touch_result(Block::new(
        metadata.clone(),
        batch_key.clone(),
        "not_a_wallet".to_string(),
        reward,
    ));

    let mut zero_hash_metadata = metadata.clone();
    zero_hash_metadata.previous_hash = [0u8; 64];
    let _ = touch_result(Block::new(
        zero_hash_metadata,
        batch_key.clone(),
        miner.clone(),
        reward,
    ))
    .map(|block| exercise_block(block, data));

    let genesis_metadata = make_genesis_metadata(data);
    if let Some(genesis_block) = touch_result(Block::new(
        genesis_metadata,
        None,
        String::new(),
        0,
    )) {
        exercise_block(genesis_block, data);
    }

    let mut bad_genesis_metadata = make_genesis_metadata(data);
    bad_genesis_metadata.puzzle_proof =
        make_valid_proof(0, bad_genesis_metadata.previous_hash, data, 333);
    let _ = touch_result(Block::new(
        bad_genesis_metadata,
        None,
        String::new(),
        0,
    ))
    .map(|block| exercise_block(block, data));
}

fn exercise_raw_deserialize(data: &[u8]) {
    let _ = touch_result(Block::deserialize_from_storage(data));
    let _ = touch_result(Block::deserialize_with_sizes(data));

    if let Ok(block) = postcard::from_bytes::<Block>(data) {
        exercise_block(block, data);
    }

    let over_cap = vec![
        0xAB;
        usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
            .unwrap_or(0)
            .saturating_add(1)
    ];
    let _ = touch_result(Block::deserialize_from_storage(&over_cap));
    let _ = touch_result(Block::deserialize_with_sizes(&over_cap));

    let tiny_len = byte_at(data, 900, 0) as usize % GlobalConfiguration::MIN_BLOCK_SIZE as usize;
    let tiny = vec![byte_at(data, 901, 0xCD); tiny_len];
    let _ = touch_result(Block::deserialize_from_storage(&tiny));
    let _ = touch_result(Block::deserialize_with_sizes(&tiny));
}

fn exercise_invalid_shapes(data: &[u8]) {
    let metadata = make_valid_metadata(data, true);
    let miner = canonical_wallet(data, 1000);
    let reward = bounded_reward(data, 1008);

    if let Some(mut block) = touch_result(Block::new(metadata.clone(), None, miner.clone(), reward)) {
        block.miner.clear();
        let _ = touch_result(block.validate(None));

        block.miner = "r".repeat(130);
        let _ = touch_result(block.validate(None));

        block.miner = canonical_wallet(data, 1016);
        block.batch_key = Some(overlong_batch_key(data));
        let _ = touch_result(block.validate(None));

        block.batch_key = None;
        block.block_hash = [0u8; 64];
        let _ = touch_result(block.validate(None));
        let _ = touch_result(block.verify_block_hash());

        block.block_hash = non_sentinel_hash(data, 1024);
        block.metadata.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);
        let _ = touch_result(block.validate(None));
        let _ = touch_result(block.serialize_for_storage());

        block.metadata.size = GlobalConfiguration::MIN_BLOCK_SIZE.saturating_sub(1);
        let _ = touch_result(block.validate(None));
    }
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
            "fuzz.block_ts",
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
        let _ = touch_result(TimePolicy::validate_runtime_future_skew_secs_default(
            "fuzz.block_ts",
            block_ts,
            now,
        ));
    }

    let _ = touch_result(TimePolicy::now_unix_secs_runtime());
    let _ = touch_result(TimePolicy::now_unix_millis_runtime());
}

fuzz_target!(|data: &[u8]| {
    exercise_time_policy(data);
    exercise_constructors(data);
    exercise_raw_deserialize(data);
    exercise_invalid_shapes(data);
});
