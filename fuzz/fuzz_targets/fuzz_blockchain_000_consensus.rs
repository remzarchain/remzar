#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_BATCH_ITEMS: usize = 64;
            pub const MAX_ITEM_BYTES: usize = 4096;

            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const PUZZLE_CREATION_INTERVAL_SECS: u64 = 1;

            pub const ACTIVATION_WARMUP_SECS: u64 = 30;
            pub const REWARD_DELAY_BLOCKS: usize = 1;
            pub const QUARANTINE_BLOCKS: u64 = 4;
            pub const EPOCH_SLOTS: u64 = 60;

            pub const FAILOVER_BUILD_SLACK_SECS: u64 = 3;
            pub const FAILOVER_LEADER_GRACE_SECS: u64 = 3;
            pub const FAILOVER_SLACK_SECS: u64 =
                Self::FAILOVER_BUILD_SLACK_SECS + Self::FAILOVER_LEADER_GRACE_SECS;
            pub const FAILOVER_WINDOW_SECS: u64 =
                Self::PUZZLE_CREATION_INTERVAL_SECS + Self::FAILOVER_SLACK_SECS;

            pub const SLOT_GOSSIP_BUFFER_SECS: u64 = 6;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
            pub const MAX_FUTURE_SKEW_SECS: u64 = 15 * 60;
            pub const MAX_VALIDATORS: usize = 4096;
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
            StorageError {
                message: String,
            },
            DatabaseError {
                details: String,
            },
            NotFound {
                resource: String,
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
                    Self::StorageError { message } => write!(f, "{message}"),
                    Self::DatabaseError { details } => write!(f, "{details}"),
                    Self::NotFound { resource } => write!(f, "{resource} not found"),
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
                    message: format!(
                        "wallet length mismatch: expected {}, got {}",
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
                    message: "wallet must start with r".into(),
                    tx_id: None,
                });
            }

            if !b
                .get(1..)
                .is_some_and(|body| body.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
            {
                return Err(ErrorDetection::ValidationError {
                    message: "wallet body must be 128 lowercase hex chars".into(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }
    }

    pub mod hash_system_remzarhash {
        use blake3::Hasher;

        pub struct RemzarHash;

        impl RemzarHash {
            #[inline]
            pub fn compute_bytes_hash(bytes: &[u8]) -> [u8; 64] {
                let mut h = Hasher::new();
                h.update(bytes);

                let mut out = [0u8; 64];
                h.finalize_xof().fill(&mut out);
                out
            }
        }
    }

    pub mod time_policy {

        use chrono::Utc;

        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        /// Hard lower-bound sanity check for UNIX seconds.
        /// 2000-01-01T00:00:00Z
        pub const UNIX_2000_SECS: u64 = 946_684_800;

        /// Hard lower-bound sanity check for UNIX milliseconds.
        /// 2000-01-01T00:00:00Z in ms.
        pub const UNIX_2000_MILLIS: u64 = UNIX_2000_SECS * 1_000;

        /// Deterministic upper bound for UNIX seconds.
        /// 9999-12-31T23:59:59Z
        ///
        /// Why not `u64::MAX`?
        /// - prevents absurd timestamps from producing absurd slots
        /// - prevents silent math surprises in long-range slot derivation
        /// - remains deterministic and does NOT depend on local wall clock
        pub const UNIX_9999_SECS: u64 = 253_402_300_799;

        /// Deterministic upper bound for UNIX milliseconds.
        pub const UNIX_9999_MILLIS: u64 = UNIX_9999_SECS * 1_000;

        /// Hard defensive cap for slot drift.
        ///
        /// This is not a network latency setting. It only prevents accidental config
        /// values like millions of seconds from making timestamp gates meaningless.
        pub const MAX_SLOT_GATE_DRIFT_SECS: u64 = 24 * 60 * 60; // 24 hours

        /// Hard defensive cap for block interval.
        ///
        /// Remzar currently uses small block intervals. This cap is intentionally broad
        /// enough for future tuning while still rejecting pathological config.
        pub const MAX_BLOCK_INTERVAL_SECS: u64 = 24 * 60 * 60; // 24 hours

        /// Minimal deterministic chain-time config.
        ///
        /// Prefer constructing this from existing `TimeManager` values:
        /// - `tm.cfg().genesis_time_unix`
        /// - `tm.block_interval_secs()`
        /// - `tm.slot_gate_drift_secs()`
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct ChainTimePolicyConfig {
            /// UNIX timestamp when slot 0 starts.
            pub genesis_time_unix: u64,

            /// Nominal slot/block interval in seconds.
            pub block_interval_secs: u64,

            /// Deterministic drift tolerance around slot boundaries.
            /// This is NOT local-wall-clock tolerance.
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

            /// Validate config deterministically.
            ///
            /// This must be called before using config in consensus gates.
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

            /// Deterministic UNIX start time of a slot.
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

            /// Saturating convenience helper for non-validation display/logging only.
            ///
            /// Prefer `slot_start_unix_checked` in validation paths.
            #[must_use]
            pub fn slot_start_unix_saturating(&self, slot: u64) -> u64 {
                self.genesis_time_unix
                    .saturating_add(slot.saturating_mul(self.block_interval_secs.max(1)))
            }

            /// Derive slot from timestamp.
            pub fn slot_for_timestamp_checked(&self, ts_unix: u64) -> Result<u64, ErrorDetection> {
                self.validate()?;
                TimePolicy::validate_unix_secs_structural("timestamp", ts_unix)?;

                if ts_unix
                    < self
                        .genesis_time_unix
                        .saturating_sub(self.slot_gate_drift_secs)
                {
                    return Err(TimePolicy::validation_err(format!(
                        "timestamp before genesis window: ts={} genesis={} drift={}s",
                        ts_unix, self.genesis_time_unix, self.slot_gate_drift_secs
                    )));
                }

                let elapsed = ts_unix.saturating_sub(self.genesis_time_unix);
                Ok(elapsed.div_euclid(self.block_interval_secs))
            }

            /// Seconds into a slot from a timestamp.
            pub fn secs_into_slot_checked(&self, slot: u64, ts_unix: u64) -> Result<u64, ErrorDetection> {
                self.validate()?;
                TimePolicy::validate_unix_secs_structural("timestamp", ts_unix)?;

                let slot_start = self.slot_start_unix_checked(slot)?;
                Ok(ts_unix.saturating_sub(slot_start))
            }
        }

        /// Timestamp policy namespace.
        ///
        /// This is intentionally a zero-sized type: use `TimePolicy::method(...)`.
        pub struct TimePolicy;

        impl TimePolicy {
            // ─────────────────────────────────────────────────────────────
            // Runtime wall-clock entry points
            // ─────────────────────────────────────────────────────────────

            /// Runtime wall-clock UNIX seconds.
            ///
            /// Allowed for:
            /// - local scheduling
            /// - mempool freshness checks
            /// - local block production candidate timestamps
            ///
            /// Forbidden for:
            /// - canonical chain replay
            /// - validator-state rebuild from blocks
            #[inline]
            pub fn now_unix_secs_runtime() -> Result<u64, ErrorDetection> {
                let now =
                    u64::try_from(Utc::now().timestamp()).map_err(|_| ErrorDetection::TimestampError {
                        message: "Timestamp error".into(),
                        details: "chrono::Utc::now().timestamp() returned a negative value".into(),
                        source: None,
                    })?;

                Self::validate_unix_secs_structural("runtime_now_unix_secs", now)?;
                Ok(now)
            }

            /// Runtime wall-clock UNIX milliseconds.
            /// Use only for runtime/off-chain features.
            #[inline]
            pub fn now_unix_millis_runtime() -> Result<u64, ErrorDetection> {
                let now = u64::try_from(Utc::now().timestamp_millis()).map_err(|_| {
                    ErrorDetection::TimestampError {
                        message: "Timestamp error".into(),
                        details: "chrono::Utc::now().timestamp_millis() returned a negative value".into(),
                        source: None,
                    }
                })?;

                Self::validate_unix_millis_structural("runtime_now_unix_millis", now)?;
                Ok(now)
            }

            // ─────────────────────────────────────────────────────────────
            // Structural checks: deterministic, replay-safe
            // ─────────────────────────────────────────────────────────────

            /// Replay-safe UNIX seconds check.
            ///
            /// This does NOT compare to local wall clock.
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

            /// Replay-safe UNIX milliseconds check.
            ///
            /// This does NOT compare to local wall clock.
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

            // ─────────────────────────────────────────────────────────────
            // Runtime / mempool wall-clock checks
            // ─────────────────────────────────────────────────────────────

            /// Runtime-only future-skew check for seconds timestamps.
            ///
            /// Use this at mempool admission, inbound gossip prefiltering, or local UX.
            /// Do NOT use this while replaying already-accepted canonical blocks.
            pub fn validate_runtime_future_skew_secs(
                label: &'static str,
                ts: u64,
                now_unix: u64,
                max_future_skew_secs: u64,
            ) -> Result<(), ErrorDetection> {
                Self::validate_unix_secs_structural(label, ts)?;
                Self::validate_unix_secs_structural("now_unix", now_unix)?;

                let max_allowed = now_unix
                    .checked_add(max_future_skew_secs)
                    .ok_or_else(|| {
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

            /// Runtime-only future-skew check using the project global skew.
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

            /// Runtime/off-chain timestamp hygiene for millisecond timestamps.
            ///
            /// Use this for chat, file transfer, UI, etc. Not consensus.
            pub fn validate_offchain_timestamp_ms(
                label: &'static str,
                ts_ms: u64,
                now_ms: u64,
                max_future_skew_ms: u64,
                max_past_age_ms: Option<u64>,
            ) -> Result<(), ErrorDetection> {
                Self::validate_unix_millis_structural(label, ts_ms)?;
                Self::validate_unix_millis_structural("now_ms", now_ms)?;

                let max_allowed = now_ms
                    .checked_add(max_future_skew_ms)
                    .ok_or_else(|| {
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

            // ─────────────────────────────────────────────────────────────
            // Consensus / replay checks: deterministic only
            // ─────────────────────────────────────────────────────────────

            /// Validate a canonical block timestamp against the previous canonical block.
            ///
            /// This is replay-safe because it compares chain data to chain data.
            /// It does NOT use local `now`.
            ///
            /// `min_delta_secs` preserve current rule:
            /// - strict 30s spacing: use `GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS`
            /// - monotonic only: use `0`
            pub fn validate_block_timestamp_against_parent(
                block_ts: u64,
                parent_ts: u64,
                min_delta_secs: u64,
            ) -> Result<(), ErrorDetection> {
                Self::validate_unix_secs_structural("block.timestamp", block_ts)?;
                Self::validate_unix_secs_structural("parent_block.timestamp", parent_ts)?;

                let min_allowed = parent_ts
                    .checked_add(min_delta_secs)
                    .ok_or_else(|| {
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

            /// Validate a block timestamp against a declared slot.
            ///
            /// Use this only if the block/proof actually carries the slot being claimed.
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

            /// Derive canonical slot and seconds-into-slot from block timestamp.
            ///
            /// This is replay-safe: all nodes compute the same answer from genesis config
            /// and the block timestamp.
            pub fn derive_slot_from_block_timestamp(
                cfg: ChainTimePolicyConfig,
                block_ts: u64,
            ) -> Result<(u64, u64), ErrorDetection> {
                cfg.validate()?;
                Self::validate_unix_secs_structural("block.timestamp", block_ts)?;

                let slot = cfg.slot_for_timestamp_checked(block_ts)?;
                let into = cfg.secs_into_slot_checked(slot, block_ts)?;
                Ok((slot, into))
            }

            /// Canonical event timestamp for on-chain lifecycle events.
            ///
            /// Recommended use:
            /// - validator join/renew timestamp = containing block timestamp
            /// - not the self-reported tx timestamp
            pub fn canonical_event_timestamp_from_block(
                label: &'static str,
                containing_block_ts: u64,
            ) -> Result<u64, ErrorDetection> {
                Self::validate_unix_secs_structural(label, containing_block_ts)?;
                Ok(containing_block_ts)
            }

            /// Optional deterministic check for a transaction timestamp inside a block.
            ///
            /// This is NOT needed for validator lifecycle if you use the containing block
            /// timestamp as the canonical event time. Use this only as a soft/structural
            /// transaction sanity check.
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

            #[inline]
            fn validation_err(msg: impl Into<String>) -> ErrorDetection {
                ErrorDetection::ValidationError {
                    message: msg.into(),
                    tx_id: None,
                }
            }
        }
    }
}

mod blockchain {
    pub mod block_001_metadata {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct BlockMetadata {
            pub index: u64,
        }
    }

    pub mod block_002_blocks {
        use crate::blockchain::block_001_metadata::BlockMetadata;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct Block {
            pub metadata: BlockMetadata,
        }

        impl Block {
            pub fn with_index(index: u64) -> Self {
                Self {
                    metadata: BlockMetadata { index },
                }
            }
        }
    }

    pub mod transaction_002_tx_register {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct RegisterNodeTx {
            wallet: String,
            pub timestamp: u64,
        }

        impl RegisterNodeTx {
            pub fn new(wallet_address: String) -> Result<Self, ErrorDetection> {
                let wallet = canon_wallet_id_checked(&wallet_address)?;
                Ok(Self {
                    wallet,
                    timestamp: 946_684_800,
                })
            }

            pub fn wallet_str(&self) -> Result<&str, ErrorDetection> {
                Ok(&self.wallet)
            }
        }
    }

    pub mod validatorstate {
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::collections::BTreeMap;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct ValidatorMeta {
            pub join_height: u64,
            pub join_timestamp: u64,
            pub exit_height: Option<u64>,
        }

        #[derive(Debug, Clone)]
        pub struct ValidatorState {
            inner: BTreeMap<String, ValidatorMeta>,
            _db_manager: RockDBManager,
        }

        impl ValidatorState {
            pub fn load_or_new(db_manager: RockDBManager) -> Result<Self, ErrorDetection> {
                Ok(Self {
                    inner: BTreeMap::new(),
                    _db_manager: db_manager,
                })
            }

            pub fn seed_genesis_founder(
                &mut self,
                founder_wallet: &str,
                join_timestamp: u64,
            ) -> Result<(), ErrorDetection> {
                let wallet = canon_wallet_id_checked(founder_wallet)?;
                self.inner.insert(
                    wallet,
                    ValidatorMeta {
                        join_height: 0,
                        join_timestamp,
                        exit_height: None,
                    },
                );
                Ok(())
            }

            pub fn apply_register_tx(
                &mut self,
                block_height: u64,
                tx: &RegisterNodeTx,
            ) -> Result<(), ErrorDetection> {
                let wallet = canon_wallet_id_checked(tx.wallet_str()?)?;
                self.inner.entry(wallet).or_insert(ValidatorMeta {
                    join_height: block_height,
                    join_timestamp: tx.timestamp,
                    exit_height: None,
                });
                Ok(())
            }

            pub fn is_canonically_known(&self, wallet: &str) -> Result<bool, ErrorDetection> {
                let wallet = canon_wallet_id_checked(wallet)?;
                Ok(self.inner.contains_key(&wallet))
            }

            pub fn meta_for(&self, wallet: &str) -> Option<&ValidatorMeta> {
                let wallet = canon_wallet_id_checked(wallet).ok()?;
                self.inner.get(&wallet)
            }

            pub fn reward_eligible_at(&self, wallet: &str, _height: u64) -> bool {
                canon_wallet_id_checked(wallet)
                    .ok()
                    .is_some_and(|w| self.inner.contains_key(&w))
            }

            pub fn proposable_at(&self, height: u64, activation_delay_blocks: u64) -> Vec<String> {
                let mut out = Vec::new();

                for (wallet, meta) in &self.inner {
                    if meta.exit_height.is_some() {
                        continue;
                    }

                    if meta.join_height == 0
                        || height >= meta.join_height.saturating_add(activation_delay_blocks)
                    {
                        out.push(wallet.clone());
                    }
                }

                out.sort();
                out
            }
        }
    }
}

mod storage {
    pub mod rocksdb_005_manager {
        use crate::blockchain::block_002_blocks::Block;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone)]
        pub struct RockDBManager {
            inner: Arc<Mutex<MockDb>>,
        }

        #[derive(Debug, Clone, Default)]
        struct MockDb {
            tip_height: u64,
            blocks_by_hash: BTreeMap<[u8; 64], Block>,
        }

        impl RockDBManager {
            pub fn new_for_fuzz(tip_height: u64, known_parent_hash: [u8; 64]) -> Self {
                let mut blocks_by_hash = BTreeMap::new();
                blocks_by_hash.insert(known_parent_hash, Block::with_index(tip_height));

                Self {
                    inner: Arc::new(Mutex::new(MockDb {
                        tip_height,
                        blocks_by_hash,
                    })),
                }
            }

            pub fn add_known_block_hash(&self, hash: [u8; 64], index: u64) {
                if let Ok(mut db) = self.inner.lock() {
                    db.blocks_by_hash.insert(hash, Block::with_index(index));
                    db.tip_height = db.tip_height.max(index);
                }
            }

            pub fn get_tip_height(&self) -> Result<u64, ErrorDetection> {
                self.inner
                    .lock()
                    .map(|db| db.tip_height)
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "mock db mutex poisoned".into(),
                    })
            }

            pub fn get_block_by_hash(&self, hash: &[u8; 64]) -> Option<Block> {
                self.inner
                    .lock()
                    .ok()
                    .and_then(|db| db.blocks_by_hash.get(hash).cloned())
            }
        }
    }
}

mod consensus {
    pub mod por_000_ephemeral_registration {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::collections::BTreeSet;

        #[derive(Debug, Default, Clone)]
        pub struct EphemeralRegistry {
            wallets: BTreeSet<String>,
        }

        pub type RegistryData = EphemeralRegistry;

        impl EphemeralRegistry {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn clear(&mut self) {
                self.wallets.clear();
            }

            pub fn sorted_wallets(&self) -> Vec<String> {
                self.wallets.iter().cloned().collect()
            }

            pub fn is_registered(&self, addr: &str) -> bool {
                canon_wallet_id_checked(addr)
                    .ok()
                    .is_some_and(|can| self.wallets.contains(&can))
            }

            pub fn register_wallet_strict(
                &mut self,
                wallet_addr: &str,
                _join_height: u64,
            ) -> Result<String, ErrorDetection> {
                let can = canon_wallet_id_checked(wallet_addr)?;
                self.wallets.insert(can.clone());
                Ok(can)
            }
        }
    }

    pub mod por_001_consensus_config {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::time::Duration;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum PorPuzzleKind {
            FibonacciDelayDev,
            FactorizationDelayDev,
        }

        #[derive(Clone, Debug)]
        pub struct PorConsensusConfig {
            pub target_block_time: Duration,
            pub puzzle_kind: PorPuzzleKind,
            pub max_local_puzzle_ms: u64,
        }

        impl PorConsensusConfig {
            pub fn from_globals() -> Self {
                let secs = GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS
                    .max(1)
                    .min(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1));

                Self {
                    target_block_time: Duration::from_secs(secs),
                    puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
                    max_local_puzzle_ms: secs.saturating_mul(1000),
                }
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                if self.target_block_time.is_zero() || self.max_local_puzzle_ms == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid PoR config".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }
        }

        impl Default for PorConsensusConfig {
            fn default() -> Self {
                Self::from_globals()
            }
        }
    }

    pub mod por_002_puzzle_engine {
        use crate::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::hash_system_remzarhash::RemzarHash;
        use crate::utility::helper::canon_wallet_id_checked;

        #[derive(Clone, Debug)]
        pub struct PorPuzzleHeader {
            pub height: u64,
            pub validator: String,
            pub prev_block_hash: [u8; 64],
            pub kind: PorPuzzleKind,
            pub param: u32,
        }

        #[derive(Clone, Debug)]
        pub struct PorPuzzleSolution {
            pub header: PorPuzzleHeader,
            pub output: u128,
            pub solved_in_ms: u64,
        }

        #[derive(Clone, Debug)]
        pub struct PorPuzzleEngine {
            cfg: PorConsensusConfig,
        }

        impl PorPuzzleEngine {
            pub fn new(cfg: PorConsensusConfig) -> Self {
                Self { cfg }
            }

            pub fn from_globals() -> Self {
                Self {
                    cfg: PorConsensusConfig::from_globals(),
                }
            }

            pub fn config(&self) -> &PorConsensusConfig {
                &self.cfg
            }

            pub fn derive_puzzle(
                &self,
                height: u64,
                validator_wallet: &str,
                prev_block_hash: [u8; 64],
            ) -> PorPuzzleHeader {
                let validator = canon_wallet_id_checked(validator_wallet)
                    .unwrap_or_else(|_| "por:<invalid-wallet>".to_string());

                let mut preimage = Vec::with_capacity(64 + 8 + validator.len());
                preimage.extend_from_slice(&prev_block_hash);
                preimage.extend_from_slice(&height.to_be_bytes());
                preimage.extend_from_slice(validator.as_bytes());

                let digest = RemzarHash::compute_bytes_hash(&preimage);
                let param = 26u32.saturating_add(u32::from(digest[0] & 7));

                PorPuzzleHeader {
                    height,
                    validator,
                    prev_block_hash,
                    kind: self.cfg.puzzle_kind,
                    param,
                }
            }

            fn expected_output(header: &PorPuzzleHeader) -> u128 {
                let mut preimage = Vec::with_capacity(64 + 8 + header.validator.len() + 4);
                preimage.extend_from_slice(&header.prev_block_hash);
                preimage.extend_from_slice(&header.height.to_be_bytes());
                preimage.extend_from_slice(header.validator.as_bytes());
                preimage.extend_from_slice(&header.param.to_be_bytes());

                let h = RemzarHash::compute_bytes_hash(&preimage);

                let mut lo = [0u8; 16];
                lo.copy_from_slice(&h[..16]);

                u128::from_be_bytes(lo).max(1)
            }

            pub fn solve_locally_checked(
                &self,
                header: &PorPuzzleHeader,
            ) -> Result<PorPuzzleSolution, ErrorDetection> {
                Ok(PorPuzzleSolution {
                    header: header.clone(),
                    output: Self::expected_output(header),
                    solved_in_ms: 1,
                })
            }

            pub fn verify_checked(
                &self,
                solution: &PorPuzzleSolution,
                expected_height: u64,
                expected_validator: &str,
                expected_prev_block_hash: [u8; 64],
            ) -> Result<(), ErrorDetection> {
                let expected_header =
                    self.derive_puzzle(expected_height, expected_validator, expected_prev_block_hash);

                if solution.header.height != expected_header.height
                    || solution.header.validator != expected_header.validator
                    || solution.header.prev_block_hash != expected_header.prev_block_hash
                    || solution.header.param != expected_header.param
                {
                    return Err(ErrorDetection::ValidationError {
                        message: "puzzle header mismatch".into(),
                        tx_id: None,
                    });
                }

                let expected = Self::expected_output(&expected_header);
                if solution.output != expected {
                    return Err(ErrorDetection::ValidationError {
                        message: "puzzle output mismatch".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }

            pub fn verify(
                &self,
                solution: &PorPuzzleSolution,
                expected_height: u64,
                expected_validator: &str,
                expected_prev_block_hash: [u8; 64],
            ) -> bool {
                self.verify_checked(
                    solution,
                    expected_height,
                    expected_validator,
                    expected_prev_block_hash,
                )
                .is_ok()
            }
        }
    }

    pub mod por_003_puzzle_pool {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::collections::BTreeMap;

        #[derive(Default, Debug, Clone)]
        pub struct PorPuzzlePool {
            winners: BTreeMap<u64, BTreeMap<String, u128>>,
        }

        impl PorPuzzlePool {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn record_success_checked(
                &mut self,
                height: u64,
                wallet: &str,
                output: u128,
            ) -> Result<(), ErrorDetection> {
                if height == 0 || output == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid puzzle pool success".into(),
                        tx_id: None,
                    });
                }

                let wallet = canon_wallet_id_checked(wallet)?;
                self.winners.entry(height).or_default().insert(wallet, output);
                Ok(())
            }

            pub fn record_success(&mut self, height: u64, wallet: &str, output: u128) {
                let _ = self.record_success_checked(height, wallet, output);
            }

            pub fn gc_below(&mut self, height: u64) {
                self.winners.retain(|h, _| *h >= height);
            }
        }
    }

    pub mod por_004_puzzle_proof {
        use crate::consensus::por_002_puzzle_engine::{
            PorPuzzleEngine, PorPuzzleHeader, PorPuzzleSolution,
        };
        use crate::consensus::por_003_puzzle_pool::PorPuzzlePool;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct PorPuzzleProof {
            pub height: u64,
            pub validator: String,
            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub prev_block_hash: [u8; 64],
            pub output: u128,
        }

        impl PorPuzzleProof {
            pub fn from_solution(sol: &PorPuzzleSolution) -> Self {
                let PorPuzzleHeader {
                    height,
                    validator,
                    prev_block_hash,
                    ..
                } = &sol.header;

                Self {
                    height: *height,
                    validator: validator.clone(),
                    prev_block_hash: *prev_block_hash,
                    output: sol.output,
                }
            }

            pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
                let can = canon_wallet_id_checked(&self.validator)?;
                if can != self.validator {
                    return Err(ErrorDetection::ValidationError {
                        message: "validator is not canonical".into(),
                        tx_id: None,
                    });
                }

                if self.height == 0 || self.height > 10_000_000 {
                    return Err(ErrorDetection::ValidationError {
                        message: "height out of bounds".into(),
                        tx_id: None,
                    });
                }

                if self.prev_block_hash == [0u8; 64] || self.prev_block_hash == [0xFFu8; 64] {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid sentinel parent hash".into(),
                        tx_id: None,
                    });
                }

                if self.output == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "output cannot be zero".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }

            pub fn verify_with_engine_checked(
                &self,
                engine: &PorPuzzleEngine,
            ) -> Result<bool, ErrorDetection> {
                self.validate_structural()?;

                let validator = canon_wallet_id_checked(&self.validator)?;
                let header = engine.derive_puzzle(self.height, &validator, self.prev_block_hash);

                let sol = PorPuzzleSolution {
                    header,
                    output: self.output,
                    solved_in_ms: 0,
                };

                Ok(engine.verify(&sol, self.height, &validator, self.prev_block_hash))
            }

            pub fn verify_with_engine(&self, engine: &PorPuzzleEngine) -> bool {
                self.verify_with_engine_checked(engine).unwrap_or(false)
            }

            pub fn verify_and_record_checked(
                &self,
                engine: &PorPuzzleEngine,
                pool: &mut PorPuzzlePool,
            ) -> Result<bool, ErrorDetection> {
                if !self.verify_with_engine_checked(engine)? {
                    return Ok(false);
                }

                pool.record_success_checked(self.height, &self.validator, self.output)?;
                Ok(true)
            }
        }
    }

    pub mod por_005_time_management {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use std::time::Duration;

        #[derive(Clone, Debug)]
        pub struct TimeConfig {
            pub genesis_time_unix: u64,
            pub block_interval_secs: u64,
            pub puzzle_interval_secs: u64,
            pub quarantine_blocks: u64,
            pub failover_window_secs: u64,
        }

        impl TimeConfig {
            pub fn from_genesis_ts(genesis_time_unix: u64) -> Self {
                Self {
                    genesis_time_unix: genesis_time_unix.max(1),
                    block_interval_secs: GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1),
                    puzzle_interval_secs: GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS.max(1),
                    quarantine_blocks: GlobalConfiguration::QUARANTINE_BLOCKS,
                    failover_window_secs: GlobalConfiguration::FAILOVER_WINDOW_SECS.max(1),
                }
            }

            pub fn proposer_delay_blocks(&self) -> u64 {
                self.quarantine_blocks.max(1)
            }
        }

        #[derive(Clone, Debug)]
        pub struct TimeManager {
            cfg: TimeConfig,
        }

        impl TimeManager {
            pub fn new(cfg: TimeConfig) -> Self {
                Self { cfg }
            }

            pub fn cfg(&self) -> &TimeConfig {
                &self.cfg
            }

            pub fn proposer_delay_blocks(&self) -> u64 {
                self.cfg.proposer_delay_blocks()
            }

            pub fn failover_window_secs(&self) -> u64 {
                self.cfg.failover_window_secs.max(1)
            }

            pub fn puzzle_interval_secs(&self) -> u64 {
                self.cfg.puzzle_interval_secs.max(1)
            }

            pub fn block_interval(&self) -> Duration {
                Duration::from_secs(self.cfg.block_interval_secs.max(1))
            }

            pub fn height_start_unix(&self, height: u64) -> u64 {
                self.cfg
                    .genesis_time_unix
                    .saturating_add(height.saturating_mul(self.cfg.block_interval_secs.max(1)))
            }

            pub fn now_unix() -> u64 {
                946_684_800 + 300
            }
        }
    }

    pub mod por_006_committee_eligibility {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::collections::BTreeSet;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum IneligibilityReason {
            NotLive,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct CommitteeEligibilityDecision {
            pub wallet: String,
            pub eligible: bool,
            pub reasons: Vec<IneligibilityReason>,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct CommitteeEligibilityConfig {
            pub max_tip_lag_blocks: u64,
            pub min_peers_connected: usize,
            pub min_connected_wallet_peers: usize,
            pub require_non_isolated: bool,
            pub require_synced: bool,
        }

        impl Default for CommitteeEligibilityConfig {
            fn default() -> Self {
                Self {
                    max_tip_lag_blocks: 2,
                    min_peers_connected: 0,
                    min_connected_wallet_peers: 0,
                    require_non_isolated: false,
                    require_synced: false,
                }
            }
        }

        impl CommitteeEligibilityConfig {
            pub fn from_globals() -> Self {
                Self::default()
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                if self.min_connected_wallet_peers > self.min_peers_connected {
                    return Err(ErrorDetection::ValidationError {
                        message: "connected-wallet peers exceeds peers".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct CommitteeEligibility {
            live_wallets: BTreeSet<String>,
            _config: CommitteeEligibilityConfig,
        }

        impl CommitteeEligibility {
            pub fn new(config: CommitteeEligibilityConfig) -> Self {
                Self {
                    live_wallets: BTreeSet::new(),
                    _config: config,
                }
            }

            pub fn replace_live_wallets<I>(&mut self, wallets: I) -> Result<(), ErrorDetection>
            where
                I: IntoIterator<Item = String>,
            {
                self.live_wallets.clear();

                for wallet in wallets {
                    self.live_wallets.insert(canon_wallet_id_checked(&wallet)?);
                }

                Ok(())
            }

            pub fn decide_wallet(&self, wallet: &str) -> CommitteeEligibilityDecision {
                match canon_wallet_id_checked(wallet) {
                    Ok(can) if self.live_wallets.contains(&can) => CommitteeEligibilityDecision {
                        wallet: can,
                        eligible: true,
                        reasons: Vec::new(),
                    },
                    Ok(can) => CommitteeEligibilityDecision {
                        wallet: can,
                        eligible: false,
                        reasons: vec![IneligibilityReason::NotLive],
                    },
                    Err(_) => CommitteeEligibilityDecision {
                        wallet: wallet.to_string(),
                        eligible: false,
                        reasons: vec![IneligibilityReason::NotLive],
                    },
                }
            }
        }
    }

    pub mod por_007_leader_schedule {
        use crate::blockchain::validatorstate::ValidatorState;
        use crate::consensus::por_005_time_management::TimeManager;
        use crate::consensus::por_006_committee_eligibility::CommitteeEligibility;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::hash_system_remzarhash::RemzarHash;
        use crate::utility::helper::canon_wallet_id_checked;

        #[derive(Debug, Clone)]
        pub struct CommitteeSnapshot {
            pub height: u64,
            pub parent_hash: [u8; 64],
            pub activation_delay_blocks: u64,
            pub validators: Vec<String>,
            pub committee_hash: [u8; 64],
        }

        impl CommitteeSnapshot {
            pub fn contains_wallet(&self, wallet: &str) -> bool {
                self.validators
                    .iter()
                    .any(|v| v.eq_ignore_ascii_case(wallet))
            }
        }

        #[derive(Debug, Clone)]
        pub struct LeaderDecision {
            pub height: u64,
            pub round: u64,
            pub parent_hash: [u8; 64],
            pub committee_hash: [u8; 64],
            pub leader: String,
            pub leader_index_in_snapshot: usize,
            pub committee_len: usize,
        }

        #[derive(Debug, Clone)]
        pub struct LeaderTrace {
            pub snapshot: CommitteeSnapshot,
            pub decision: LeaderDecision,
            pub observed_time_unix: u64,
            pub height_start_unix: u64,
            pub round_start_unix: u64,
            pub elapsed_secs: u64,
            pub in_round_secs: u64,
            pub failover_window_secs: u64,
        }

        #[derive(Debug, Clone)]
        pub struct MintAuthorization {
            pub local_wallet: String,
            pub trace: LeaderTrace,
        }

        #[derive(Debug, Clone)]
        pub struct LeaderSchedule {
            local_wallet: String,
        }

        impl LeaderSchedule {
            pub fn new(local_wallet: String) -> Result<Self, ErrorDetection> {
                Ok(Self {
                    local_wallet: canon_wallet_id_checked(&local_wallet)?,
                })
            }

            pub fn committee_snapshot(
                validator_state: &ValidatorState,
                _committee_eligibility: &CommitteeEligibility,
                tm: &TimeManager,
                parent_hash: [u8; 64],
                height: u64,
            ) -> Result<CommitteeSnapshot, ErrorDetection> {
                if height == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "committee snapshot for height zero".into(),
                        tx_id: None,
                    });
                }

                let validators = validator_state.proposable_at(height, tm.proposer_delay_blocks());
                if validators.is_empty() {
                    return Err(ErrorDetection::ValidationError {
                        message: "empty canonical committee".into(),
                        tx_id: None,
                    });
                }

                let committee_hash =
                    Self::compute_committee_hash(parent_hash, height, tm.proposer_delay_blocks(), &validators);

                Ok(CommitteeSnapshot {
                    height,
                    parent_hash,
                    activation_delay_blocks: tm.proposer_delay_blocks(),
                    validators,
                    committee_hash,
                })
            }

            fn compute_committee_hash(
                parent_hash: [u8; 64],
                height: u64,
                activation_delay_blocks: u64,
                validators: &[String],
            ) -> [u8; 64] {
                let mut preimage = Vec::new();
                preimage.extend_from_slice(b"fuzz:committee");
                preimage.extend_from_slice(&parent_hash);
                preimage.extend_from_slice(&height.to_be_bytes());
                preimage.extend_from_slice(&activation_delay_blocks.to_be_bytes());

                for validator in validators {
                    preimage.extend_from_slice(validator.as_bytes());
                    preimage.push(0);
                }

                RemzarHash::compute_bytes_hash(&preimage)
            }

            pub fn assert_local_can_mint_now(
                &self,
                validator_state: &ValidatorState,
                committee_eligibility: &CommitteeEligibility,
                tm: &TimeManager,
                parent_hash: [u8; 64],
                height: u64,
                now: u64,
            ) -> Result<MintAuthorization, ErrorDetection> {
                let snapshot = Self::committee_snapshot(
                    validator_state,
                    committee_eligibility,
                    tm,
                    parent_hash,
                    height,
                )?;

                if !snapshot.contains_wallet(&self.local_wallet) {
                    return Err(ErrorDetection::ValidationError {
                        message: "local wallet not in committee".into(),
                        tx_id: None,
                    });
                }

                let round = 0;
                let leader = snapshot
                    .validators
                    .first()
                    .cloned()
                    .ok_or_else(|| ErrorDetection::ValidationError {
                        message: "empty committee".into(),
                        tx_id: None,
                    })?;

                if leader != self.local_wallet {
                    return Err(ErrorDetection::ValidationError {
                        message: "local wallet is not leader".into(),
                        tx_id: None,
                    });
                }

                let decision = LeaderDecision {
                    height,
                    round,
                    parent_hash,
                    committee_hash: snapshot.committee_hash,
                    leader,
                    leader_index_in_snapshot: 0,
                    committee_len: snapshot.validators.len(),
                };

                let trace = LeaderTrace {
                    snapshot,
                    decision,
                    observed_time_unix: now,
                    height_start_unix: tm.height_start_unix(height),
                    round_start_unix: tm.height_start_unix(height),
                    elapsed_secs: now.saturating_sub(tm.height_start_unix(height)),
                    in_round_secs: 0,
                    failover_window_secs: tm.failover_window_secs(),
                };

                Ok(MintAuthorization {
                    local_wallet: self.local_wallet.clone(),
                    trace,
                })
            }
        }
    }
}

mod real_blockchain_000_consensus {

    use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
    use crate::blockchain::validatorstate::ValidatorState;
    use crate::consensus::por_000_ephemeral_registration::RegistryData;
    use crate::consensus::por_001_consensus_config::PorConsensusConfig;
    use crate::consensus::por_002_puzzle_engine::PorPuzzleEngine;
    use crate::consensus::por_002_puzzle_engine::PorPuzzleSolution;
    use crate::consensus::por_003_puzzle_pool::PorPuzzlePool;
    use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
    use crate::consensus::por_005_time_management::TimeManager;
    use crate::consensus::por_006_committee_eligibility::CommitteeEligibility;
    use crate::consensus::por_006_committee_eligibility::CommitteeEligibilityConfig;
    use crate::consensus::por_007_leader_schedule::LeaderSchedule;
    use crate::storage::rocksdb_005_manager::RockDBManager;
    use crate::utility::alpha_002_error_detection_system::ErrorDetection;
    use crate::utility::helper::canon_wallet_id_checked;
    use crate::utility::time_policy::TimePolicy;

    use chrono::DateTime;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tracing::debug;

    /// Maximum number of unknown-parent puzzle proofs retained globally.
    ///
    /// LIVENESS RULE:
    /// Unknown-parent proofs are orphan/side-branch hints. They must never be able
    /// to grow without bound or prevent local canonical-tip production.
    const MAX_BUFFERED_UNKNOWN_PARENT_PROOFS: usize = 256;

    /// Maximum number of unknown-parent puzzle proofs retained for one parent hash.
    ///
    /// This bounds per-parent memory usage and prevents one missing parent from
    /// becoming an unbounded in-memory queue.
    const MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT: usize = 32;

    /// Maximum future distance, measured from the local proposal height, for
    /// unknown-parent proofs retained in memory.
    ///
    /// Proofs too far ahead of the local tip are treated as gossip noise. They can
    /// be re-gossiped later if their parent branch becomes real.
    const MAX_UNKNOWN_PARENT_FUTURE_HEIGHT_DISTANCE: u64 = 8;

    /// Consensus engine for puzzle flow + local proposer authorization.
    pub struct BlockchainConsensus {
        db_manager: Arc<RockDBManager>,

        /// Snapshot of the runtime registry injected by orchestration.
        ///
        /// IMPORTANT:
        /// - retained for deterministic `RegisterNodeTx` collection
        /// - retained for refreshing the local live-wallet/runtime view
        /// - MUST NOT be treated as canonical validator membership
        wallet_registry: RegistryData,

        /// Shared runtime/local mint-readiness policy.
        ///
        /// IMPORTANT:
        /// - local producer policy only
        /// - MUST NOT be used as canonical committee truth
        committee_eligibility: CommitteeEligibility,

        /// Canonical on-chain validator registry (membership only).
        validator_state: ValidatorState,

        /// Time manager (slot clock + derived intervals).
        tm: Arc<TimeManager>,

        local_wallet: String,

        /// POR puzzle engine (local delay + deterministic proof verification).
        por_engine: PorPuzzleEngine,

        /// In-memory pool of puzzle winners (RAM-only, keyed by block height).
        ///
        /// IMPORTANT:
        /// - Local solutions are recorded here by `run_local_puzzle_for_block`
        /// - Remote solutions are recorded here by `on_puzzle_proof(..)` only when
        ///   the referenced parent block is already known locally
        /// - This pool is NOT used to select the canonical leader
        puzzle_pool: PorPuzzlePool,

        /// Remote proofs that are cryptographically valid but whose parent block is
        /// not yet known locally.
        ///
        /// IMPORTANT:
        /// - keyed by `prev_block_hash`
        /// - these proofs MUST NOT enter the active puzzle pool until the parent
        ///   block exists locally
        /// - sync / hydration code should call
        ///   `replay_buffered_puzzle_proofs_for_parent(..)` after the parent arrives
        ///
        /// LIVENESS RULE:
        /// - this is an orphan/side-branch buffer only
        /// - it MUST NEVER globally freeze local canonical-tip minting
        /// - it is bounded and garbage-collected defensively
        pending_proofs_by_prev_hash: HashMap<[u8; 64], Vec<PorPuzzleProof>>,

        /// Stash the most recent POR puzzle proof so the caller can gossip it.
        ///
        /// IMPORTANT:
        /// - this proof is bound to `(height, validator, prev_block_hash)`
        /// - it may be staged before this node becomes the active round leader
        /// - final canonical leader authorization still happens immediately before
        ///   block assembly in `assert_can_build_block`
        pending_puzzle_proof: Option<PorPuzzleProof>,

        /// Runtime/orchestration catch-up gate.
        ///
        /// IMPORTANT:
        /// - local proposal safety only
        /// - when active, this node must not stage or build new local blocks
        /// - consensus truth for remote blocks is unaffected
        runtime_rejoin_catchup_gate_active: bool,
        runtime_rejoin_catchup_reason: Option<String>,

        /// Runtime signal that branch hydration / recovery is still active.
        ///
        /// IMPORTANT:
        /// - local proposal safety only
        /// - while true, this node must not stage or build local blocks
        runtime_branch_hydration_active: bool,

        /// Optional runtime-observed canonical tip context that proposal attempts
        /// must still match.
        ///
        /// IMPORTANT:
        /// - local proposal safety only
        /// - when populated, local proposal attempts must target exactly this
        ///   `(tip_height, tip_hash)` context
        runtime_canonical_tip_height: Option<u64>,
        runtime_canonical_tip_hash: Option<[u8; 64]>,

        /// Most recent canonical tip height for which `ValidatorState` was rebuilt.
        ///
        /// IMPORTANT:
        /// - local proposal safety only
        /// - detached-branch validator state must not survive rejoin / reorg windows
        validator_state_rebuilt_at_tip: Option<u64>,

        /// Canonical leader scheduler.
        leader_schedule: LeaderSchedule,
    }

    impl BlockchainConsensus {
        #[must_use = "BlockchainConsensus::new returns a consensus engine that should be retained by the block builder"]
        pub fn new(
            db_manager: Arc<RockDBManager>,
            local_wallet: String,
            tm: Arc<TimeManager>,
        ) -> Result<Self, ErrorDetection> {
            let tip = db_manager.get_tip_height()?;

            // Canonicalize local wallet once so all comparisons are CANONICAL ONLY.
            let local_wallet = canon_wallet_id_checked(&local_wallet)?;

            // Consensus config from globals ONLY.
            let por_cfg = PorConsensusConfig::from_globals();
            por_cfg.validate()?;
            let por_engine = PorPuzzleEngine::new(por_cfg);

            let cfg = por_engine.config();
            println!();
            println!();
            println!(
                "{} [POR][CONFIG] tip={} puzzle_kind={:?} target_block_time={}s max_local_puzzle_ms={} mode=MANDATORY_ON",
                Self::runtime_log_timestamp(),
                tip,
                cfg.puzzle_kind,
                cfg.target_block_time.as_secs(),
                cfg.max_local_puzzle_ms
            );

            // Canonical on-chain validator state, backed by RocksDB.
            let validator_state = ValidatorState::load_or_new((*db_manager).clone())?;
            let leader_schedule = LeaderSchedule::new(local_wallet.clone())?;

            let committee_cfg = CommitteeEligibilityConfig::from_globals();
            committee_cfg.validate()?;

            Ok(Self {
                db_manager,
                wallet_registry: RegistryData::new(),
                committee_eligibility: CommitteeEligibility::new(committee_cfg),
                validator_state,
                tm,
                local_wallet,
                por_engine,
                puzzle_pool: PorPuzzlePool::new(),
                pending_proofs_by_prev_hash: HashMap::new(),
                pending_puzzle_proof: None,
                runtime_rejoin_catchup_gate_active: false,
                runtime_rejoin_catchup_reason: None,
                runtime_branch_hydration_active: false,
                runtime_canonical_tip_height: None,
                runtime_canonical_tip_hash: None,
                validator_state_rebuilt_at_tip: Some(tip),
                leader_schedule,
            })
        }
    

        pub fn local_wallet(&self) -> &String {
            &self.local_wallet
        }

        /// Immutable access to the canonical validator registry.
        pub fn validator_state(&self) -> &ValidatorState {
            &self.validator_state
        }

        /// Mutable access so the orchestration loop can apply committed blocks and
        /// rebuild the on-chain validator snapshot.
        pub fn validator_state_mut(&mut self) -> &mut ValidatorState {
            &mut self.validator_state
        }

        /// Immutable access to runtime/local mint-readiness policy.
        pub fn committee_eligibility(&self) -> &CommitteeEligibility {
            &self.committee_eligibility
        }

        /// Mutable access so orchestration can refresh live-wallet and runtime
        /// health signals used for local mint suppression.
        pub fn committee_eligibility_mut(&mut self) -> &mut CommitteeEligibility {
            &mut self.committee_eligibility
        }

        /// Replace the runtime/local mint-readiness object entirely.
        pub fn set_committee_eligibility(&mut self, ce: CommitteeEligibility) {
            self.committee_eligibility = ce;
        }

        /// Refresh the runtime registry snapshot (called by orchestration each tick).
        ///
        /// IMPORTANT:
        /// - retained for runtime registration collection
        /// - refreshes the local live-wallet view used by runtime mint-readiness
        /// - MUST NOT alter canonical committee membership
        pub fn set_registry(&mut self, reg: RegistryData) {
            let live_wallets = reg.sorted_wallets();
            self.wallet_registry = reg;

            if let Err(e) = self
                .committee_eligibility
                .replace_live_wallets(live_wallets)
            {
                println!(
                    "{} [COMMITTEE][LIVE][ERROR] failed to refresh runtime live-wallet view: {:?}",
                    Self::runtime_log_timestamp(),
                    e
                );
            }
        }

        /// Peek at the most recent POR puzzle proof, if any.
        pub fn pending_puzzle_proof(&self) -> Option<&PorPuzzleProof> {
            self.pending_puzzle_proof.as_ref()
        }

        /// Take and clear the most recent POR puzzle proof (for gossip).
        pub fn take_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> {
            self.pending_puzzle_proof.take()
        }

        /// Clear any staged local puzzle proof without using it for block assembly.
        pub fn clear_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> {
            self.pending_puzzle_proof.take()
        }

        /// Mark whether orchestration is still holding this node in catch-up mode.
        ///
        /// IMPORTANT:
        /// - local proposal safety only
        /// - while active, local staging/building must fail closed
        pub fn set_runtime_rejoin_catchup_gate(&mut self, active: bool, reason: Option<String>) {
            self.runtime_rejoin_catchup_gate_active = active;
            self.runtime_rejoin_catchup_reason = if active { reason } else { None };

            if active {
                let catchup_reason = self
                    .runtime_rejoin_catchup_reason
                    .clone()
                    .unwrap_or_else(|| "runtime catch-up gate active".to_string());

                self.clear_staged_local_puzzle_proof_with_reason(&catchup_reason);
            }
        }

        pub fn runtime_rejoin_catchup_gate_active(&self) -> bool {
            self.runtime_rejoin_catchup_gate_active
        }

        /// Mark whether branch hydration / recovery is still active locally.
        ///
        /// IMPORTANT:
        /// - local proposal safety only
        /// - while true, local staging/building must fail closed
        pub fn set_runtime_branch_hydration_active(&mut self, active: bool) {
            self.runtime_branch_hydration_active = active;

            if active {
                self.clear_staged_local_puzzle_proof_with_reason("runtime branch hydration active");
            }
        }

        pub fn runtime_branch_hydration_active(&self) -> bool {
            self.runtime_branch_hydration_active
        }

        /// Publish the runtime-observed canonical tip context that any local
        /// proposal attempt must still match.
        pub fn set_runtime_canonical_tip_context(&mut self, tip_height: u64, tip_hash: [u8; 64]) {
            self.runtime_canonical_tip_height = Some(tip_height);
            self.runtime_canonical_tip_hash = Some(tip_hash);
        }

        pub fn clear_runtime_canonical_tip_context(&mut self) {
            self.runtime_canonical_tip_height = None;
            self.runtime_canonical_tip_hash = None;
        }

        /// Record that `ValidatorState` has been rebuilt from canonical chain data
        /// through `tip_height`.
        pub fn note_validator_state_rebuilt_to_tip(&mut self, tip_height: u64) {
            self.validator_state_rebuilt_at_tip = Some(tip_height);
        }

        pub fn validator_state_rebuilt_at_tip(&self) -> Option<u64> {
            self.validator_state_rebuilt_at_tip
        }

        /// Reset all local proposal-safety state after a successful catch-up / reorg rebuild.
        pub fn reset_runtime_proposal_safety_state(
            &mut self,
            canonical_tip_height: u64,
            canonical_tip_hash: [u8; 64],
        ) {
            self.runtime_rejoin_catchup_gate_active = false;
            self.runtime_rejoin_catchup_reason = None;
            self.runtime_branch_hydration_active = false;
            self.runtime_canonical_tip_height = Some(canonical_tip_height);
            self.runtime_canonical_tip_hash = Some(canonical_tip_hash);
            self.validator_state_rebuilt_at_tip = Some(canonical_tip_height);

            let _ = self.clear_buffered_unknown_parent_puzzle_proofs_for_liveness(
                "runtime proposal safety state reset after catch-up / reorg rebuild",
            );
        }

        #[inline]
        fn has_known_parent_hash(&self, parent_hash: &[u8; 64]) -> bool {
            self.db_manager.get_block_by_hash(parent_hash).is_some()
        }

        #[inline]
        fn same_proof_identity(a: &PorPuzzleProof, b: &PorPuzzleProof) -> bool {
            a.height == b.height
                && a.prev_block_hash == b.prev_block_hash
                && a.output == b.output
                && a.validator.eq_ignore_ascii_case(&b.validator)
        }

        fn total_buffered_puzzle_proofs(&self) -> usize {
            self.pending_proofs_by_prev_hash
                .values()
                .map(std::vec::Vec::len)
                .sum()
        }

        pub fn pending_buffered_puzzle_proof_total(&self) -> usize {
            self.total_buffered_puzzle_proofs()
        }

        pub fn pending_buffered_puzzle_proof_count_for_parent(&self, parent_hash: [u8; 64]) -> usize {
            self.pending_proofs_by_prev_hash
                .get(&parent_hash)
                .map(std::vec::Vec::len)
                .unwrap_or(0)
        }

        /// Operator/emergency liveness valve.
        ///
        /// This intentionally clears only the orphan unknown-parent proof buffer.
        /// It does not touch canonical chain state, validator state, the active
        /// puzzle pool, or any staged local proof.
        pub fn clear_buffered_unknown_parent_puzzle_proofs_for_liveness(
            &mut self,
            reason: &str,
        ) -> usize {
            let removed = self.total_buffered_puzzle_proofs();

            if removed > 0 {
                println!();
                println!(
                    "{} [POR][PUZZLE][GC][CLEAR_ALL] removed {} buffered unknown-parent proof(s) reason={}",
                    Self::runtime_log_timestamp(),
                    removed,
                    reason,
                );
            }

            self.pending_proofs_by_prev_hash.clear();
            removed
        }

        fn replay_buffered_puzzle_proofs_with_known_parents(&mut self) -> usize {
            let known_parent_hashes: Vec<[u8; 64]> = self
                .pending_proofs_by_prev_hash
                .keys()
                .copied()
                .filter(|parent_hash| self.has_known_parent_hash(parent_hash))
                .collect();

            let mut admitted = 0usize;

            for parent_hash in known_parent_hashes {
                admitted =
                    admitted.saturating_add(self.replay_buffered_puzzle_proofs_for_parent(parent_hash));
            }

            admitted
        }

        fn drop_one_buffered_puzzle_proof_for_liveness(&mut self, reason: &'static str) -> bool {
            let Some(parent_hash) = self
                .pending_proofs_by_prev_hash
                .iter()
                .max_by_key(|(_, proofs)| proofs.len())
                .map(|(parent_hash, _)| *parent_hash)
            else {
                return false;
            };

            let removed = {
                let Some(proofs) = self.pending_proofs_by_prev_hash.get_mut(&parent_hash) else {
                    return false;
                };

                proofs.pop()
            };

            let should_remove_bucket = self
                .pending_proofs_by_prev_hash
                .get(&parent_hash)
                .map(|proofs| proofs.is_empty())
                .unwrap_or(false);

            if should_remove_bucket {
                self.pending_proofs_by_prev_hash.remove(&parent_hash);
            }

            if let Some(proof) = removed {
                println!();
                println!(
                    "{} [POR][PUZZLE][GC][DROP_ONE] reason={} height={} validator={} prev_hash={} output={} remaining_buffered={}",
                    Self::runtime_log_timestamp(),
                    reason,
                    proof.height,
                    proof.validator,
                    hex::encode(proof.prev_block_hash),
                    proof.output,
                    self.total_buffered_puzzle_proofs(),
                );
                return true;
            }

            false
        }

        /// Defensive liveness GC for unknown-parent proofs.
        ///
        /// Critical rule: unknown-parent proofs are treated as orphan/side-branch
        /// hints. They may be replayed if their parent arrives, but they must never
        /// stop this node from building on its known canonical tip.
        fn gc_buffered_puzzle_proofs_for_local_proposal(
            &mut self,
            height: u64,
            prev_hash: [u8; 64],
            phase: &'static str,
        ) {
            let before = self.total_buffered_puzzle_proofs();

            let replayed = self.replay_buffered_puzzle_proofs_with_known_parents();

            let max_future_height = height.saturating_add(MAX_UNKNOWN_PARENT_FUTURE_HEIGHT_DISTANCE);

            self.pending_proofs_by_prev_hash.retain(|parent_hash, proofs| {
                proofs.retain(|proof| {
                    let malformed = proof.height == 0 || proof.prev_block_hash == [0u8; 64];
                    let current_tip_parent = proof.prev_block_hash == prev_hash;
                    let stale_for_local_tip = proof.height <= height;
                    let too_far_future = proof.height > max_future_height;

                    let keep = !(malformed || current_tip_parent || stale_for_local_tip || too_far_future);

                    if !keep {
                        println!();
                        println!(
                            "{} [POR][PUZZLE][GC][ORPHAN] phase={} drop height={} validator={} prev_hash={} output={} malformed={} current_tip_parent={} stale_for_local_tip={} too_far_future={}",
                            Self::runtime_log_timestamp(),
                            phase,
                            proof.height,
                            proof.validator,
                            hex::encode(*parent_hash),
                            proof.output,
                            malformed,
                            current_tip_parent,
                            stale_for_local_tip,
                            too_far_future,
                        );
                    }

                    keep
                });

                !proofs.is_empty()
            });

            let oversized_parents: Vec<[u8; 64]> = self
                .pending_proofs_by_prev_hash
                .iter()
                .filter_map(|(parent_hash, proofs)| {
                    if proofs.len() > MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT {
                        Some(*parent_hash)
                    } else {
                        None
                    }
                })
                .collect();

            for parent_hash in oversized_parents {
                if let Some(proofs) = self.pending_proofs_by_prev_hash.get_mut(&parent_hash) {
                    let parent_before = proofs.len();
                    proofs.truncate(MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT);
                    let removed = parent_before.saturating_sub(proofs.len());

                    if removed > 0 {
                        println!();
                        println!(
                            "{} [POR][PUZZLE][GC][PARENT_CAP] phase={} prev_hash={} removed={} kept={}",
                            Self::runtime_log_timestamp(),
                            phase,
                            hex::encode(parent_hash),
                            removed,
                            proofs.len(),
                        );
                    }
                }
            }

            while self.total_buffered_puzzle_proofs() > MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
                if !self.drop_one_buffered_puzzle_proof_for_liveness("global unknown-parent buffer cap")
                {
                    break;
                }
            }

            let after = self.total_buffered_puzzle_proofs();
            let processed = before.saturating_sub(after);

            if processed > 0 || replayed > 0 {
                println!();
                println!(
                    "{} [POR][PUZZLE][GC][SUMMARY] phase={} h={} prev_hash={} before={} replayed={} after={} max_total={} max_per_parent={} max_future_distance={}",
                    Self::runtime_log_timestamp(),
                    phase,
                    height,
                    hex::encode(prev_hash),
                    before,
                    replayed,
                    after,
                    MAX_BUFFERED_UNKNOWN_PARENT_PROOFS,
                    MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT,
                    MAX_UNKNOWN_PARENT_FUTURE_HEIGHT_DISTANCE,
                );
            }
        }

        fn log_buffered_puzzle_proof_liveness_warning(
            &self,
            height: u64,
            prev_hash: [u8; 64],
            phase: &'static str,
        ) {
            let total = self.total_buffered_puzzle_proofs();

            if total == 0 {
                return;
            }

            println!();
            println!(
                "{} [POR][PUZZLE][LIVENESS] phase={} h={} prev_hash={} buffered_unknown_parent_proofs={} action=not_blocking_local_proposal",
                Self::runtime_log_timestamp(),
                phase,
                height,
                hex::encode(prev_hash),
                total,
            );

            for (parent_hash, proofs) in self.pending_proofs_by_prev_hash.iter().take(8) {
                println!(
                    "{} [POR][PUZZLE][LIVENESS][BUCKET] prev_hash={} count={}",
                    Self::runtime_log_timestamp(),
                    hex::encode(parent_hash),
                    proofs.len(),
                );

                for proof in proofs.iter().take(4) {
                    println!(
                        "{} [POR][PUZZLE][LIVENESS][PROOF] height={} validator={} prev_hash={} output={}",
                        Self::runtime_log_timestamp(),
                        proof.height,
                        proof.validator,
                        hex::encode(proof.prev_block_hash),
                        proof.output,
                    );
                }
            }
        }

        fn buffer_verified_unknown_parent_proof(&mut self, proof: &PorPuzzleProof) -> bool {
            let existing_for_parent = self
                .pending_proofs_by_prev_hash
                .get(&proof.prev_block_hash)
                .map(std::vec::Vec::len)
                .unwrap_or(0);

            if self
                .pending_proofs_by_prev_hash
                .get(&proof.prev_block_hash)
                .map(|bucket| {
                    bucket
                        .iter()
                        .any(|existing| Self::same_proof_identity(existing, proof))
                })
                .unwrap_or(false)
            {
                println!();
                println!(
                    "{} [POR][PUZZLE][RECV][BUFFERED_DUP] height={} validator={} prev_hash={} output={} pending_for_parent={} total_pending={}",
                    Self::runtime_log_timestamp(),
                    proof.height,
                    proof.validator,
                    hex::encode(proof.prev_block_hash),
                    proof.output,
                    existing_for_parent,
                    self.total_buffered_puzzle_proofs(),
                );
                return true;
            }

            if existing_for_parent >= MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT {
                println!();
                println!(
                    "{} [POR][PUZZLE][RECV][DROP_PARENT_CAP] height={} validator={} prev_hash={} output={} pending_for_parent={} max_per_parent={} total_pending={}",
                    Self::runtime_log_timestamp(),
                    proof.height,
                    proof.validator,
                    hex::encode(proof.prev_block_hash),
                    proof.output,
                    existing_for_parent,
                    MAX_BUFFERED_UNKNOWN_PARENT_PROOFS_PER_PARENT,
                    self.total_buffered_puzzle_proofs(),
                );
                return true;
            }

            while self.total_buffered_puzzle_proofs() >= MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
                if !self.drop_one_buffered_puzzle_proof_for_liveness(
                    "global unknown-parent buffer cap before insert",
                ) {
                    break;
                }
            }

            if self.total_buffered_puzzle_proofs() >= MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
                println!();
                println!(
                    "{} [POR][PUZZLE][RECV][DROP_GLOBAL_CAP] height={} validator={} prev_hash={} output={} max_total={}",
                    Self::runtime_log_timestamp(),
                    proof.height,
                    proof.validator,
                    hex::encode(proof.prev_block_hash),
                    proof.output,
                    MAX_BUFFERED_UNKNOWN_PARENT_PROOFS,
                );
                return true;
            }

            self.pending_proofs_by_prev_hash
                .entry(proof.prev_block_hash)
                .or_default()
                .push(proof.clone());

            let pending_for_parent = self
                .pending_proofs_by_prev_hash
                .get(&proof.prev_block_hash)
                .map(std::vec::Vec::len)
                .unwrap_or(0);

            println!();
            println!(
                "{} [POR][PUZZLE][RECV][BUFFERED] height={} validator={} prev_hash={} output={} pending_for_parent={} total_pending={}",
                Self::runtime_log_timestamp(),
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
                proof.output,
                pending_for_parent,
                self.total_buffered_puzzle_proofs(),
            );

            true
        }

        fn record_verified_proof_in_active_pool(
            &mut self,
            proof: &PorPuzzleProof,
            path_label: &'static str,
        ) -> bool {
            if let Err(e) =
                self.puzzle_pool
                    .record_success_checked(proof.height, &proof.validator, proof.output)
            {
                println!();
                println!(
                    "{} [POR][PUZZLE][RECV][POOL_ERR] path={} height={} validator={} output={} err={}",
                    Self::runtime_log_timestamp(),
                    path_label,
                    proof.height,
                    proof.validator,
                    proof.output,
                    e
                );
                return false;
            }

            println!();
            println!(
                "{} [POR][PUZZLE][RECV][OK][{}] height={} validator={} prev_hash={} output={}",
                Self::runtime_log_timestamp(),
                path_label,
                proof.height,
                proof.validator,
                hex::encode(proof.prev_block_hash),
                proof.output
            );

            true
        }

        fn gc_buffered_puzzle_proofs_below(&mut self, height: u64) {
            let before = self.total_buffered_puzzle_proofs();

            let replayed = self.replay_buffered_puzzle_proofs_with_known_parents();

            self.pending_proofs_by_prev_hash.retain(|parent_hash, proofs| {
                proofs.retain(|proof| {
                    let keep = proof.height >= height && proof.height != 0 && proof.prev_block_hash != [0u8; 64];

                    if !keep {
                        println!();
                        println!(
                            "{} [POR][PUZZLE][GC] removed buffered proof height={} validator={} prev_hash={} output={} cutoff_height={}",
                            Self::runtime_log_timestamp(),
                            proof.height,
                            proof.validator,
                            hex::encode(*parent_hash),
                            proof.output,
                            height,
                        );
                    }

                    keep
                });
                !proofs.is_empty()
            });

            while self.total_buffered_puzzle_proofs() > MAX_BUFFERED_UNKNOWN_PARENT_PROOFS {
                if !self.drop_one_buffered_puzzle_proof_for_liveness(
                    "global unknown-parent buffer cap during gc_below",
                ) {
                    break;
                }
            }

            let after = self.total_buffered_puzzle_proofs();
            let processed = before.saturating_sub(after);

            if processed > 0 || replayed > 0 {
                println!();
                println!(
                    "{} [POR][PUZZLE][GC] removed_or_replayed={} replayed={} below_height={} remaining_buffered={}",
                    Self::runtime_log_timestamp(),
                    processed,
                    replayed,
                    height,
                    after
                );
            }
        }

        /// Replay previously buffered proofs that were waiting on `parent_hash`.
        ///
        /// Returns the number of proofs successfully admitted into the active pool.
        ///
        /// IMPORTANT:
        /// - callers should invoke this after the parent block becomes known locally
        /// - buffered proofs are already cryptographically verified on entry, so this
        ///   method only reclassifies and records them into the active puzzle pool
        pub fn replay_buffered_puzzle_proofs_for_parent(&mut self, parent_hash: [u8; 64]) -> usize {
            if !self.has_known_parent_hash(&parent_hash) {
                println!();
                println!(
                    "{} [POR][PUZZLE][REPLAY][SKIP] parent still unknown prev_hash={} buffered_for_parent={} total_pending={}",
                    Self::runtime_log_timestamp(),
                    hex::encode(parent_hash),
                    self.pending_buffered_puzzle_proof_count_for_parent(parent_hash),
                    self.total_buffered_puzzle_proofs(),
                );
                return 0;
            }

            let Some(buffered) = self.pending_proofs_by_prev_hash.remove(&parent_hash) else {
                return 0;
            };

            let parent_idx = match self.db_manager.get_block_by_hash(&parent_hash) {
                Some(parent_block) => parent_block.metadata.index,
                None => {
                    // Defensive: if the parent disappeared between the initial guard and now,
                    // re-buffer the proofs and exit safely.
                    for proof in buffered {
                        let _ = self.buffer_verified_unknown_parent_proof(&proof);
                    }
                    return 0;
                }
            };

            let mut admitted = 0usize;
            let total = buffered.len();

            println!();
            println!(
                "{} [POR][PUZZLE][REPLAY] parent_hash={} parent_idx={} buffered_count={}",
                Self::runtime_log_timestamp(),
                hex::encode(parent_hash),
                parent_idx,
                total,
            );

            for proof in buffered {
                let expected_h = parent_idx.saturating_add(1);
                let path_label = if expected_h == proof.height {
                    "REPLAY_MAIN"
                } else {
                    "REPLAY_BRANCH"
                };

                if self.record_verified_proof_in_active_pool(&proof, path_label) {
                    admitted = admitted.saturating_add(1);
                }
            }

            println!();
            println!(
                "{} [POR][PUZZLE][REPLAY][DONE] parent_hash={} admitted={} dropped={} remaining_pending={}",
                Self::runtime_log_timestamp(),
                hex::encode(parent_hash),
                admitted,
                total.saturating_sub(admitted),
                self.total_buffered_puzzle_proofs(),
            );

            admitted
        }

        /// Handle an incoming gossiped POR puzzle proof.
        ///
        /// Returns `true` if the proof was valid and either:
        /// - recorded into the active puzzle pool,
        /// - buffered because its parent is not yet known locally, or
        /// - safely ignored due to bounded orphan-buffer liveness guardrails
        ///
        /// Returns `false` if the proof was invalid.
        pub fn on_puzzle_proof(&mut self, proof: &PorPuzzleProof) -> bool {
            if proof.height == 0 {
                println!();
                println!(
                    "{} [POR][PUZZLE][RECV][INVALID] genesis-height puzzle proof is not allowed",
                    Self::runtime_log_timestamp(),
                );
                return false;
            }

            if let Err(e) = canon_wallet_id_checked(&proof.validator) {
                println!();
                println!(
                    "{} [POR][PUZZLE][RECV][INVALID] non-canonical validator wallet in proof: {:?}",
                    Self::runtime_log_timestamp(),
                    e
                );
                return false;
            }

            let parent_block = self.db_manager.get_block_by_hash(&proof.prev_block_hash);

            match parent_block.as_ref() {
                Some(parent_block) => {
                    let parent_idx = parent_block.metadata.index;
                    let expected_h = parent_idx.saturating_add(1);

                    if expected_h != proof.height {
                        println!();
                        println!(
                            "{} [POR][PUZZLE][RECV][BRANCH] proof for h={} builds on parent_idx={} (expected_h={}); treating as valid branch-level proof.",
                            Self::runtime_log_timestamp(),
                            proof.height,
                            parent_idx,
                            expected_h
                        );
                    } else {
                        println!();
                        println!(
                            "{} [POR][PUZZLE][RECV][MAIN] proof for h={} builds on local-known parent_idx={}",
                            Self::runtime_log_timestamp(),
                            proof.height,
                            parent_idx
                        );
                    }
                }
                None => {
                    println!();
                    println!(
                        "{} [POR][PUZZLE][RECV][WARN] unknown parent hash for proof h={} prev_hash={}; verifying and buffering proof until parent branch is known.",
                        Self::runtime_log_timestamp(),
                        proof.height,
                        hex::encode(proof.prev_block_hash)
                    );
                }
            }

            if !proof.verify_with_engine(&self.por_engine) {
                println!();
                println!(
                    "{} [POR][PUZZLE][RECV][INVALID] height={} validator={} prev_hash={} output={}",
                    Self::runtime_log_timestamp(),
                    proof.height,
                    proof.validator,
                    hex::encode(proof.prev_block_hash),
                    proof.output
                );
                return false;
            }

            match parent_block {
                Some(parent_block) => {
                    let parent_idx = parent_block.metadata.index;
                    let expected_h = parent_idx.saturating_add(1);
                    let path_label = if expected_h == proof.height {
                        "ACTIVE_MAIN"
                    } else {
                        "ACTIVE_BRANCH"
                    };

                    self.record_verified_proof_in_active_pool(proof, path_label)
                }
                None => self.buffer_verified_unknown_parent_proof(proof),
            }
        }

        fn should_skip_register_tx_for_wallet(
            &self,
            wallet_can: &str,
            height: u64,
        ) -> Result<bool, ErrorDetection> {
            let is_canonically_known = self.validator_state.is_canonically_known(wallet_can)?;
            let meta = self.validator_state.meta_for(wallet_can);

            println!(
                "{} [MINT][REG][CHECK] wallet={} h={} meta={:?} is_canonically_known={}",
                Self::runtime_log_timestamp(),
                wallet_can,
                height,
                meta,
                is_canonically_known
            );

            if is_canonically_known {
                return Ok(true);
            }

            Ok(false)
        }

        /// Collect deterministic RegisterNodeTx values for wallets that are present
        /// in the runtime registry but not yet canonical on-chain.
        ///
        /// IMPORTANT:
        /// - output is sorted deterministically by runtime-registry wallet order
        /// - duplicate/canonical wallets are skipped
        /// - runtime presence alone does NOT make a wallet canonical; it only causes
        ///   us to include a registration tx candidate
        /// - canonical founder/bootstrap membership is represented inside
        ///   `validator_state` via canonical chain replay, not hidden side-state
        /// - canonical founder wallet must NEVER be re-registered at a later height
        pub fn collect_register_node_txs_for_block(&self, height: u64) -> Vec<RegisterNodeTx> {
            let mut out = Vec::new();

            let wallets = self.wallet_registry.sorted_wallets();
            if wallets.is_empty() {
                return out;
            }

            println!();
            println!(
                "{} [MINT][REG] scanning {} runtime wallets for canonical registration at height={}",
                Self::runtime_log_timestamp(),
                wallets.len(),
                height
            );

            for wallet in wallets {
                let wallet_can = match canon_wallet_id_checked(&wallet) {
                    Ok(w) => w,
                    Err(e) => {
                        println!(
                            "{} [MINT][REG] skip non-canonical wallet={} at h={} err={:?}",
                            Self::runtime_log_timestamp(),
                            wallet,
                            height,
                            e
                        );
                        continue;
                    }
                };

                match self.should_skip_register_tx_for_wallet(&wallet_can, height) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        println!(
                            "{} [MINT][REG] WARN canonical registration guard failed for wallet={} at h={} err={:?}; skipping for safety",
                            Self::runtime_log_timestamp(),
                            wallet_can,
                            height,
                            e
                        );
                        continue;
                    }
                }

                if !self.wallet_registry.is_registered(&wallet_can) {
                    println!(
                        "{} [MINT][REG] skip wallet={} at h={} (no longer present in runtime registry)",
                        Self::runtime_log_timestamp(),
                        wallet_can,
                        height
                    );
                    continue;
                }

                match RegisterNodeTx::new(wallet_can.clone()) {
                    Ok(reg_tx) => {
                        println!(
                            "{} [MINT][REG] including RegisterNodeTx for wallet={} at height={}",
                            Self::runtime_log_timestamp(),
                            wallet_can,
                            height
                        );
                        out.push(reg_tx);
                    }
                    Err(e) => {
                        println!(
                            "{} [MINT][REG] ERROR constructing RegisterNodeTx for wallet={} at height={} err={:?}",
                            Self::runtime_log_timestamp(),
                            wallet_can,
                            height,
                            e
                        );
                    }
                }
            }

            if !out.is_empty() {
                println!(
                    "{} [MINT][REG] will include {} RegisterNodeTx in block at height={}",
                    Self::runtime_log_timestamp(),
                    out.len(),
                    height
                );
            }

            out
        }

        pub fn reward_eligible_at(&self, wallet: &str, height: u64) -> bool {
            self.validator_state.reward_eligible_at(wallet, height)
        }

        pub fn gc_puzzle_pool_below(&mut self, height: u64) {
            self.puzzle_pool.gc_below(height);
            self.gc_buffered_puzzle_proofs_below(height);
        }

        /// Check whether the currently staged local proof already matches the exact
        /// `(height, prev_hash, local_wallet)` context we are trying to mint on.
        fn has_staged_local_puzzle_for_current_context(
            &self,
            height: u64,
            prev_hash: [u8; 64],
        ) -> bool {
            match self.pending_puzzle_proof.as_ref() {
                Some(proof) => {
                    proof.height == height
                        && proof.prev_block_hash == prev_hash
                        && proof.validator.eq_ignore_ascii_case(&self.local_wallet)
                }
                None => false,
            }
        }

        /// Drop any staged local puzzle proof that no longer matches the current
        /// mint context.
        ///
        /// This prevents reusing a proof from an earlier height or parent.
        fn invalidate_stale_staged_local_puzzle(&mut self, height: u64, prev_hash: [u8; 64]) {
            let should_clear = match self.pending_puzzle_proof.as_ref() {
                Some(proof) => {
                    !(proof.height == height
                        && proof.prev_block_hash == prev_hash
                        && proof.validator.eq_ignore_ascii_case(&self.local_wallet))
                }
                None => false,
            };

            if should_clear {
                if let Some(proof) = self.pending_puzzle_proof.as_ref() {
                    println!();
                    println!(
                        "{} [POR][PUZZLE][CACHE] clearing stale staged proof old_height={} old_prev_hash={} new_height={} new_prev_hash={}",
                        Self::runtime_log_timestamp(),
                        proof.height,
                        hex::encode(proof.prev_block_hash),
                        height,
                        hex::encode(prev_hash),
                    );
                }
                self.pending_puzzle_proof = None;
            }
        }

        fn clear_staged_local_puzzle_proof_with_reason(&mut self, reason: &str) {
            if let Some(proof) = self.pending_puzzle_proof.take() {
                println!();
                println!(
                    "{} [POR][PUZZLE][CACHE] dropped staged local proof reason={} height={} validator={} prev_hash={}",
                    Self::runtime_log_timestamp(),
                    reason,
                    proof.height,
                    proof.validator,
                    hex::encode(proof.prev_block_hash),
                );
            }
        }

        /// Local proposal safety guard.
        ///
        /// IMPORTANT:
        /// - local proposal safety only
        /// - remote proposer validity remains deterministic and unaffected
        /// - unknown-parent proof buffers are orphan/side-branch hints and must not
        ///   globally block or freeze canonical-tip minting
        /// - do not add a `return Err(..)` based only on
        ///   `total_buffered_puzzle_proofs() > 0`; that recreates the liveness bug
        /// - only the actual local build context may block local production, such
        ///   as an unknown local parent, active recovery gate, stale validator
        ///   rebuild, or canonical-tip mismatch
        fn ensure_runtime_local_proposal_safety(
            &mut self,
            height: u64,
            prev_hash: [u8; 64],
            phase: &'static str,
        ) -> Result<(), ErrorDetection> {
            if !self.has_known_parent_hash(&prev_hash) {
                self.clear_staged_local_puzzle_proof_with_reason(
                    "local parent hash is not known while staging/building",
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local proposal blocked during {}: parent hash is not known locally for h={} prev_hash={}",
                        phase,
                        height,
                        hex::encode(prev_hash),
                    ),
                    tx_id: None,
                });
            }

            // Orphan/unknown-parent proof maintenance is intentionally non-blocking.
            // It may replay, prune, cap, or log buffered proofs, but it must never
            // reject a valid local proposal by itself.
            self.gc_buffered_puzzle_proofs_for_local_proposal(height, prev_hash, phase);
            self.log_buffered_puzzle_proof_liveness_warning(height, prev_hash, phase);

            if self.runtime_branch_hydration_active {
                self.clear_staged_local_puzzle_proof_with_reason(
                    "branch hydration / recovery still active",
                );
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local proposal blocked during {}: branch hydration / recovery still active",
                        phase,
                    ),
                    tx_id: None,
                });
            }

            if self.runtime_rejoin_catchup_gate_active {
                let catchup_reason = self
                    .runtime_rejoin_catchup_reason
                    .clone()
                    .unwrap_or_else(|| "runtime catch-up gate active".to_string());

                self.clear_staged_local_puzzle_proof_with_reason(&catchup_reason);
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local proposal blocked during {}: catch-up gate active ({})",
                        phase,
                        self.runtime_rejoin_catchup_reason
                            .as_deref()
                            .unwrap_or("unspecified"),
                    ),
                    tx_id: None,
                });
            }

            if let Some(rebuilt_tip) = self.validator_state_rebuilt_at_tip {
                let required_tip = height.saturating_sub(1);
                if rebuilt_tip < required_tip {
                    self.clear_staged_local_puzzle_proof_with_reason(
                        "validator state not rebuilt to required canonical tip",
                    );
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "local proposal blocked during {}: validator state rebuilt only through tip {}, required at least {} for block height {}",
                            phase, rebuilt_tip, required_tip, height,
                        ),
                        tx_id: None,
                    });
                }
            }

            if let (Some(runtime_tip_height), Some(runtime_tip_hash)) = (
                self.runtime_canonical_tip_height,
                self.runtime_canonical_tip_hash,
            ) {
                let required_tip = height.saturating_sub(1);
                if runtime_tip_height != required_tip || runtime_tip_hash != prev_hash {
                    self.clear_staged_local_puzzle_proof_with_reason(
                        "runtime canonical tip context mismatch",
                    );
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "local proposal blocked during {}: runtime canonical tip mismatch (observed_tip_height={} required_tip_height={} observed_tip_hash={} required_prev_hash={})",
                            phase,
                            runtime_tip_height,
                            required_tip,
                            hex::encode(runtime_tip_hash),
                            hex::encode(prev_hash),
                        ),
                        tx_id: None,
                    });
                }
            }

            Ok(())
        }

        /// Local runtime producer-policy check used before staging / reusing local puzzle work.
        ///
        /// IMPORTANT:
        /// - this is local producer policy only
        /// - it does NOT affect canonical leader truth
        fn ensure_local_runtime_mint_eligibility_for_staging(&self) -> Result<(), ErrorDetection> {
            let decision = self.committee_eligibility.decide_wallet(&self.local_wallet);

            if decision.eligible {
                return Ok(());
            }

            let reasons = if decision.reasons.is_empty() {
                "unknown".to_string()
            } else {
                decision
                    .reasons
                    .iter()
                    .map(|r| format!("{r:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            Err(ErrorDetection::ValidationError {
                message: format!(
                    "local mint suppressed by runtime policy for wallet {}: {}",
                    self.local_wallet, reasons
                ),
                tx_id: None,
            })
        }

        /// Ensure this node is allowed to stage / reuse local puzzle work for the
        /// current `(height, prev_hash)` context.
        ///
        /// IMPORTANT:
        /// - this is intentionally weaker than "am I the active round leader right now?"
        /// - it does NOT do any slot-elapsed / proposal-deadline calculation here
        /// - the previous time-based prestage gate is what broke height 1 minting
        ///
        /// We only require:
        /// - this wallet is in the canonical committee for the height
        /// - local runtime policy allows this node to attempt minting
        fn ensure_local_can_stage_puzzle_for_context(
            &self,
            height: u64,
            prev_hash: [u8; 64],
        ) -> Result<(), ErrorDetection> {
            let snapshot = LeaderSchedule::committee_snapshot(
                &self.validator_state,
                &self.committee_eligibility,
                &self.tm,
                prev_hash,
                height,
            )?;

            if !snapshot.contains_wallet(&self.local_wallet) {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local wallet {} is not in canonical committee at height {}",
                        self.local_wallet, height
                    ),
                    tx_id: None,
                });
            }

            self.ensure_local_runtime_mint_eligibility_for_staging()?;
            Ok(())
        }

        /// Ensure we have a staged local puzzle proof for the current mint context.
        ///
        /// This reuses an existing staged proof if it already matches the exact
        /// `(height, prev_hash, local_wallet)` context; otherwise it computes a new one.
        fn ensure_staged_local_puzzle_for_block(
            &mut self,
            height: u64,
            prev_hash: [u8; 64],
        ) -> Result<(), ErrorDetection> {
            self.ensure_runtime_local_proposal_safety(height, prev_hash, "prestage")?;
            self.invalidate_stale_staged_local_puzzle(height, prev_hash);

            if self.has_staged_local_puzzle_for_current_context(height, prev_hash) {
                println!();
                println!(
                    "{} [POR][PUZZLE][CACHE] reusing staged local proof for h={} prev_hash={}",
                    Self::runtime_log_timestamp(),
                    height,
                    hex::encode(prev_hash),
                );
                return Ok(());
            }

            self.ensure_local_can_stage_puzzle_for_context(height, prev_hash)?;
            self.run_local_puzzle_for_block(height, prev_hash)
        }

        /// Main consensus gate invoked by the block builder before assembly.
        ///
        /// IMPORTANT:
        /// - canonical proposer truth comes from `LeaderSchedule`
        /// - runtime/local suppression comes from `CommitteeEligibility`
        /// - final leader authorization still happens immediately before block assembly
        ///
        /// FIXED FLOW:
        /// -----------
        /// 1. invalidate stale staged proof if height/parent changed
        /// 2. stage or reuse local puzzle proof for `(height, prev_hash)`
        /// 3. do the final canonical "am I leader NOW?" authorization
        ///
        /// This preserves staged-proof reuse for failover retries without using the
        /// broken time-based prestage gate that was rejecting block 1 immediately.
        pub fn assert_can_build_block(
            &mut self,
            height: u64,
            prev_hash: [u8; 64],
            bypass_leader: bool,
        ) -> Result<(), ErrorDetection> {
            if bypass_leader {
                return Err(ErrorDetection::ValidationError {
                    message: "bypass_leader is disabled (fork lever)".into(),
                    tx_id: None,
                });
            }

            if height == 0 {
                return Err(ErrorDetection::ValidationError {
                    message: "assert_can_build_block called for height=0".into(),
                    tx_id: None,
                });
            }

            if prev_hash == [0u8; 64] {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "assert_can_build_block called with zero prev_hash for non-genesis height {}",
                        height
                    ),
                    tx_id: None,
                });
            }

            self.ensure_runtime_local_proposal_safety(height, prev_hash, "build_gate_precheck")?;
            self.ensure_staged_local_puzzle_for_block(height, prev_hash)?;
            self.ensure_runtime_local_proposal_safety(height, prev_hash, "build_gate_poststage")?;

            // Final canonical leader authorization happens AFTER the proof is
            // staged/reused, so later failover rounds do not pay full puzzle-start delay.
            let now = Self::now_unix()?;
            let auth = self.leader_schedule.assert_local_can_mint_now(
                &self.validator_state,
                &self.committee_eligibility,
                &self.tm,
                prev_hash,
                height,
                now,
            )?;

            let cfg = self.por_engine.config();

            println!();
            println!(
                "{} [MINT][GATE] h={} now={} elapsed={}s round={} in_round={}s τ={}s local={} canonical_leader={} puzzle_kind={:?} committee_len={} committee_hash={}",
                Self::runtime_log_timestamp(),
                auth.trace.decision.height,
                auth.trace.observed_time_unix,
                auth.trace.elapsed_secs,
                auth.trace.decision.round,
                auth.trace.in_round_secs,
                auth.trace.failover_window_secs,
                self.local_wallet,
                auth.trace.decision.leader,
                cfg.puzzle_kind,
                auth.trace.decision.committee_len,
                hex::encode(auth.trace.snapshot.committee_hash),
            );

            if !self.has_staged_local_puzzle_for_current_context(height, prev_hash) {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "staged local puzzle proof missing or mismatched for h={} prev_hash={}",
                        height,
                        hex::encode(prev_hash),
                    ),
                    tx_id: None,
                });
            }

            self.ensure_runtime_local_proposal_safety(height, prev_hash, "build_gate_final")?;

            Ok(())
        }

        fn run_local_puzzle_for_block(
            &mut self,
            height: u64,
            prev_hash: [u8; 64],
        ) -> Result<(), ErrorDetection> {
            if height == 0 {
                return Err(ErrorDetection::ValidationError {
                    message: "run_local_puzzle_for_block called for height=0".into(),
                    tx_id: None,
                });
            }

            if prev_hash == [0u8; 64] {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "run_local_puzzle_for_block called with zero prev_hash for height {}",
                        height
                    ),
                    tx_id: None,
                });
            }

            self.ensure_runtime_local_proposal_safety(height, prev_hash, "local_puzzle_solve")?;

            let cfg = self.por_engine.config();
            let kind = cfg.puzzle_kind;

            let header = self
                .por_engine
                .derive_puzzle(height, &self.local_wallet, prev_hash);

            let solution: PorPuzzleSolution = self.por_engine.solve_locally_checked(&header)?;

            self.puzzle_pool
                .record_success_checked(height, &self.local_wallet, solution.output)?;

            let proof = PorPuzzleProof::from_solution(&solution);

            if !proof.validator.eq_ignore_ascii_case(&self.local_wallet) {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local puzzle proof validator mismatch at h={}: proof.validator='{}' local_wallet='{}'",
                        height, proof.validator, self.local_wallet
                    ),
                    tx_id: None,
                });
            }

            if proof.height != height {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "local puzzle proof height mismatch: proof.height={} expected={}",
                        proof.height, height
                    ),
                    tx_id: None,
                });
            }

            if proof.prev_block_hash != prev_hash {
                return Err(ErrorDetection::ValidationError {
                    message: format!("local puzzle proof prev_hash mismatch at h={}", height),
                    tx_id: None,
                });
            }

            self.pending_puzzle_proof = Some(proof.clone());

            println!();
            println!(
                "{} [POR][PUZZLE] height={} validator={} kind={:?} param={} solved_in_ms={} (min_delay={}s, soft_cap={}ms)",
                Self::runtime_log_timestamp(),
                height,
                self.local_wallet,
                kind,
                header.param,
                solution.solved_in_ms,
                cfg.target_block_time.as_secs(),
                cfg.max_local_puzzle_ms
            );

            println!();
            println!(
                "{} [POR][PUZZLE][PROOF] staged proof: height={} validator={} output={} prev_hash={}",
                Self::runtime_log_timestamp(),
                proof.height,
                proof.validator,
                proof.output,
                hex::encode(proof.prev_block_hash),
            );

            if cfg.max_local_puzzle_ms > 0 && solution.solved_in_ms > cfg.max_local_puzzle_ms {
                println!();
                println!(
                    "{} [POR][PUZZLE][WARN] local puzzle solve exceeded soft cap: solved_ms={} cap_ms={}",
                    Self::runtime_log_timestamp(),
                    solution.solved_in_ms,
                    cfg.max_local_puzzle_ms
                );
            }

            Ok(())
        }

        #[inline]
        fn now_unix() -> Result<u64, ErrorDetection> {
            TimePolicy::now_unix_secs_runtime()
        }

        /// Runtime-only UTC display timestamp for operator logs.
        ///
        /// This intentionally reads wall-clock time only through `TimePolicy`.
        /// It must not be used for canonical replay or block validity.
        #[inline]
        fn runtime_log_timestamp() -> String {
            match Self::now_unix() {
                Ok(now_unix) => {
                    let Some(now_i64) = i64::try_from(now_unix).ok() else {
                        return format!("unix:{now_unix}");
                    };

                    DateTime::from_timestamp(now_i64, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                        .unwrap_or_else(|| format!("unix:{now_unix}"))
                }
                Err(..) => "time_unavailable".to_string(),
            }
        }
    }
}


use consensus::por_000_ephemeral_registration::RegistryData;
use consensus::por_001_consensus_config::PorConsensusConfig;
use consensus::por_002_puzzle_engine::PorPuzzleEngine;
use consensus::por_004_puzzle_proof::PorPuzzleProof;
use consensus::por_005_time_management::{TimeConfig, TimeManager};
use real_blockchain_000_consensus::BlockchainConsensus;
use storage::rocksdb_005_manager::RockDBManager;
use utility::alpha_002_error_detection_system::ErrorDetection;
use utility::helper::canon_wallet_id_checked;
use utility::time_policy::{ChainTimePolicyConfig, TimePolicy, UNIX_2000_SECS, UNIX_9999_SECS};

fn touch_error(error: &ErrorDetection) {
    match error {
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            let _ = tx_id.as_ref().map(String::len);
        }
        ErrorDetection::SerializationError { details } => {
            let _ = details.len();
        }
        ErrorDetection::StorageError { message } => {
            let _ = message.len();
        }
        ErrorDetection::DatabaseError { details } => {
            let _ = details.len();
        }
        ErrorDetection::NotFound { resource } => {
            let _ = resource.len();
        }
        ErrorDetection::TimestampError {
            message,
            details,
            source,
        } => {
            let _ = message.len();
            let _ = details.len();
            let _ = source.as_ref().map(String::len);
        }
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            touch_error(&e);
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

fn non_sentinel_hash(data: &[u8], salt: usize) -> [u8; 64] {
    let mut out = [0u8; 64];

    if data.is_empty() {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(salt as u8).wrapping_add(1);
        }
    } else {
        for i in 0..64 {
            let a = data[(i + salt) % data.len()];
            let b = data[(i.wrapping_mul(7).wrapping_add(salt)) % data.len()];
            out[i] = a ^ b ^ (i as u8).wrapping_add(salt as u8);
        }
    }

    if out == [0u8; 64] {
        out[0] = 1;
    }

    if out == [0xFFu8; 64] {
        out[0] = 0x7F;
    }

    out
}

fn canonical_wallet(data: &[u8], salt: usize) -> String {
    format!("r{}", hex::encode(non_sentinel_hash(data, salt)))
}

fn maybe_noncanonical_wallet(data: &[u8], salt: usize) -> String {
    match byte_at(data, salt, 0) % 6 {
        0 => String::new(),
        1 => "not-a-wallet".to_string(),
        2 => "r1234".to_string(),
        3 => format!("x{}", hex::encode(non_sentinel_hash(data, salt + 1))),
        4 => canonical_wallet(data, salt + 2).to_ascii_uppercase(),
        _ => canonical_wallet(data, salt + 3),
    }
}

fn bounded_height(data: &[u8], offset: usize) -> u64 {
    (read_u64(data, offset) % 32).saturating_add(1)
}

fn make_time_manager() -> Arc<TimeManager> {
    Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(946_684_800)))
}

fn make_valid_proof(height: u64, validator: &str, prev_hash: [u8; 64]) -> PorPuzzleProof {
    let cfg = PorConsensusConfig::from_globals();
    let engine = PorPuzzleEngine::new(cfg);
    let header = engine.derive_puzzle(height, validator, prev_hash);
    let solution = engine
        .solve_locally_checked(&header)
        .expect("fuzz puzzle solve must be bounded and infallible for valid input");
    PorPuzzleProof::from_solution(&solution)
}

fn make_consensus_with_parent(
    data: &[u8],
    local_wallet: String,
    parent_hash: [u8; 64],
    parent_index: u64,
) -> Option<(BlockchainConsensus, RockDBManager)> {
    let db = RockDBManager::new_for_fuzz(parent_index, parent_hash);
    let tm = make_time_manager();

    let mut consensus = touch_result(BlockchainConsensus::new(
        Arc::new(db.clone()),
        local_wallet.clone(),
        tm,
    ))?;

    let _ = touch_result(
        consensus
            .validator_state_mut()
            .seed_genesis_founder(&local_wallet, 946_684_800),
    );

    let mut reg = RegistryData::new();
    let _ = touch_result(reg.register_wallet_strict(&local_wallet, 0));

    if byte_at(data, 17, 0) & 1 == 1 {
        let other = canonical_wallet(data, 301);
        if other != local_wallet {
            let _ = touch_result(reg.register_wallet_strict(&other, 1));
        }
    }

    consensus.set_registry(reg);
    consensus.note_validator_state_rebuilt_to_tip(parent_index);

    Some((consensus, db))
}

fn exercise_constructor_edges(data: &[u8]) {
    let parent_hash = non_sentinel_hash(data, 11);
    let db = RockDBManager::new_for_fuzz(0, parent_hash);
    let tm = make_time_manager();

    let invalid_wallet = maybe_noncanonical_wallet(data, 19);
    let result = BlockchainConsensus::new(Arc::new(db.clone()), invalid_wallet.clone(), tm.clone());

    if canon_wallet_id_checked(&invalid_wallet).is_err() {
        assert!(
            result.is_err(),
            "invalid local wallet must not construct BlockchainConsensus"
        );
    }

    let valid_wallet = canonical_wallet(data, 23);
    let _ = touch_result(BlockchainConsensus::new(Arc::new(db), valid_wallet, tm));
}

fn exercise_registry_collection(data: &[u8]) {
    let local = canonical_wallet(data, 41);
    let parent = non_sentinel_hash(data, 47);
    let Some((mut consensus, _db)) = make_consensus_with_parent(data, local.clone(), parent, 0) else {
        return;
    };

    let height = bounded_height(data, 53);

    let known = consensus.collect_register_node_txs_for_block(height);
    for tx in &known {
        let wallet = touch_result(tx.wallet_str().map(|s| s.to_string()));
        if let Some(wallet) = wallet {
            assert!(
                wallet.len() == 129 && wallet.starts_with('r'),
                "RegisterNodeTx wallet must stay canonical"
            );
        }
    }

    let candidate = canonical_wallet(data, 61);
    if candidate != local {
        let mut reg = RegistryData::new();
        let _ = touch_result(reg.register_wallet_strict(&local, 0));
        let _ = touch_result(reg.register_wallet_strict(&candidate, height));

        consensus.set_registry(reg);

        let txs = consensus.collect_register_node_txs_for_block(height.saturating_add(1));

        for tx in &txs {
            let wallet = match touch_result(tx.wallet_str().map(|s| s.to_string())) {
                Some(w) => w,
                None => continue,
            };

            assert_ne!(
                wallet, local,
                "canonical founder/local wallet must not be re-registered"
            );
        }

        if let Some(first) = txs.first() {
            let _ = touch_result(
                consensus
                    .validator_state_mut()
                    .apply_register_tx(height.saturating_add(1), first),
            );
        }
    }
}

fn exercise_remote_proof_paths(data: &[u8]) {
    let local = canonical_wallet(data, 101);
    let known_parent = non_sentinel_hash(data, 109);
    let unknown_parent = non_sentinel_hash(data, 173);
    let parent_index = bounded_height(data, 181);

    let Some((mut consensus, db)) =
        make_consensus_with_parent(data, local.clone(), known_parent, parent_index)
    else {
        return;
    };

    let main_height = parent_index.saturating_add(1);
    let known_proof = make_valid_proof(main_height, &local, known_parent);

    assert!(
        consensus.on_puzzle_proof(&known_proof),
        "valid proof for known parent should be accepted"
    );

    let buffered_height = main_height.saturating_add(1 + u64::from(byte_at(data, 191, 0) % 7));
    let unknown_proof = make_valid_proof(buffered_height, &local, unknown_parent);

    let before = consensus.pending_buffered_puzzle_proof_total();
    assert!(
        consensus.on_puzzle_proof(&unknown_proof),
        "valid unknown-parent proof should be accepted into bounded buffer"
    );

    let after = consensus.pending_buffered_puzzle_proof_total();
    assert!(
        after >= before,
        "unknown-parent proof path must not reduce buffer before replay/GC"
    );

    let duplicate_before = consensus.pending_buffered_puzzle_proof_total();
    let _ = consensus.on_puzzle_proof(&unknown_proof);
    let duplicate_after = consensus.pending_buffered_puzzle_proof_total();

    assert!(
        duplicate_after <= duplicate_before.saturating_add(1),
        "duplicate unknown-parent proof must stay bounded"
    );

    assert_eq!(
        consensus.replay_buffered_puzzle_proofs_for_parent(unknown_parent),
        0,
        "unknown parent must not replay into active pool"
    );

    db.add_known_block_hash(unknown_parent, buffered_height.saturating_sub(1));
    let _ = consensus.replay_buffered_puzzle_proofs_for_parent(unknown_parent);

    assert_eq!(
        consensus.pending_buffered_puzzle_proof_count_for_parent(unknown_parent),
        0,
        "known parent replay should drain that parent bucket"
    );

    let zero_height = PorPuzzleProof {
        height: 0,
        validator: local.clone(),
        prev_block_hash: known_parent,
        output: known_proof.output,
    };
    assert!(
        !consensus.on_puzzle_proof(&zero_height),
        "height zero puzzle proof must be rejected"
    );

    let bad_validator = PorPuzzleProof {
        height: main_height,
        validator: maybe_noncanonical_wallet(data, 211),
        prev_block_hash: known_parent,
        output: known_proof.output,
    };

    if canon_wallet_id_checked(&bad_validator.validator).is_err() {
        assert!(
            !consensus.on_puzzle_proof(&bad_validator),
            "non-canonical validator proof must be rejected"
        );
    }

    let bad_output = PorPuzzleProof {
        height: main_height,
        validator: local,
        prev_block_hash: known_parent,
        output: known_proof.output ^ 0xA5,
    };
    let _ = consensus.on_puzzle_proof(&bad_output);
}

fn exercise_buffer_caps_and_clear(data: &[u8]) {
    let local = canonical_wallet(data, 251);
    let known_parent = non_sentinel_hash(data, 257);
    let parent_index = bounded_height(data, 263);

    let Some((mut consensus, _db)) =
        make_consensus_with_parent(data, local.clone(), known_parent, parent_index)
    else {
        return;
    };

    let proof_count = usize::from(byte_at(data, 271, 0) % 96).saturating_add(1);

    for i in 0..proof_count {
        let mut parent = non_sentinel_hash(data, 300 + i);
        parent[0] ^= i as u8;

        let height = parent_index
            .saturating_add(2)
            .saturating_add(u64::try_from(i % 6).unwrap_or(0));

        let proof = make_valid_proof(height, &local, parent);
        let _ = consensus.on_puzzle_proof(&proof);

        assert!(
            consensus.pending_buffered_puzzle_proof_total() <= 256,
            "global unknown-parent proof buffer must stay capped"
        );

        assert!(
            consensus.pending_buffered_puzzle_proof_count_for_parent(parent) <= 32,
            "per-parent unknown-parent proof buffer must stay capped"
        );
    }

    let removed = consensus.clear_buffered_unknown_parent_puzzle_proofs_for_liveness("fuzz clear");
    assert_eq!(
        consensus.pending_buffered_puzzle_proof_total(),
        0,
        "clear liveness valve must empty orphan proof buffer"
    );

    let _ = removed;
}

fn exercise_runtime_gates_and_build(data: &[u8]) {
    let local = canonical_wallet(data, 501);
    let parent = non_sentinel_hash(data, 509);
    let wrong_parent = non_sentinel_hash(data, 517);
    let parent_index = bounded_height(data, 523);
    let height = parent_index.saturating_add(1);

    let Some((mut consensus, _db)) =
        make_consensus_with_parent(data, local.clone(), parent, parent_index)
    else {
        return;
    };

    consensus.set_runtime_rejoin_catchup_gate(true, Some("fuzz catchup".into()));
    assert!(consensus.runtime_rejoin_catchup_gate_active());
    assert!(
        touch_result(consensus.assert_can_build_block(height, parent, false)).is_none(),
        "catch-up gate must fail closed for local block build"
    );

    consensus.set_runtime_rejoin_catchup_gate(false, None);
    assert!(!consensus.runtime_rejoin_catchup_gate_active());

    consensus.set_runtime_branch_hydration_active(true);
    assert!(consensus.runtime_branch_hydration_active());
    assert!(
        touch_result(consensus.assert_can_build_block(height, parent, false)).is_none(),
        "branch hydration gate must fail closed for local block build"
    );

    consensus.set_runtime_branch_hydration_active(false);
    assert!(!consensus.runtime_branch_hydration_active());

    consensus.set_runtime_canonical_tip_context(parent_index, wrong_parent);
    assert!(
        touch_result(consensus.assert_can_build_block(height, parent, false)).is_none(),
        "runtime canonical tip hash mismatch must fail closed"
    );

    consensus.set_runtime_canonical_tip_context(parent_index, parent);
    consensus.note_validator_state_rebuilt_to_tip(parent_index);

    let _ = touch_result(consensus.assert_can_build_block(height, parent, false));

    if let Some(proof) = consensus.pending_puzzle_proof() {
        assert_eq!(proof.height, height);
        assert_eq!(proof.prev_block_hash, parent);
        assert!(proof.validator.eq_ignore_ascii_case(&local));
    }

    let taken = consensus.take_pending_puzzle_proof();
    if let Some(proof) = taken {
        assert_eq!(proof.height, height);
    }

    assert!(
        consensus.take_pending_puzzle_proof().is_none(),
        "take_pending_puzzle_proof must be idempotent after clearing"
    );

    let _ = consensus.clear_pending_puzzle_proof();
    assert!(
        consensus.clear_pending_puzzle_proof().is_none(),
        "clear_pending_puzzle_proof must be idempotent"
    );

    consensus.clear_runtime_canonical_tip_context();
    consensus.reset_runtime_proposal_safety_state(parent_index, parent);
    assert_eq!(consensus.validator_state_rebuilt_at_tip(), Some(parent_index));

    let _ = consensus.reward_eligible_at(&local, height);
    consensus.gc_puzzle_pool_below(height);
}

fn exercise_time_policy(data: &[u8]) {
    let cfg = ChainTimePolicyConfig::from_genesis_and_globals(UNIX_2000_SECS);
    assert!(
        touch_result(cfg.validate()).is_some(),
        "chain time policy config from globals must be valid"
    );

    let slot = read_u64(data, 701) % 64;
    let slot_start = match touch_result(cfg.slot_start_unix_checked(slot)) {
        Some(v) => v,
        None => return,
    };

    let into_slot = u64::from(byte_at(data, 709, 0)) % cfg.block_interval_secs.max(1);
    let block_ts = slot_start.saturating_add(into_slot);

    assert!(
        touch_result(TimePolicy::validate_unix_secs_structural(
            "fuzz_block_timestamp",
            block_ts,
        ))
        .is_some(),
        "derived block timestamp must be structurally valid"
    );

    let derived = match touch_result(TimePolicy::derive_slot_from_block_timestamp(cfg, block_ts)) {
        Some(v) => v,
        None => return,
    };

    assert_eq!(
        derived.0, slot,
        "TimePolicy slot derivation must be deterministic from genesis + block timestamp"
    );

    let parent_slot = slot.saturating_sub(1);
    let parent_ts = match touch_result(cfg.slot_start_unix_checked(parent_slot)) {
        Some(v) => v,
        None => return,
    };

    let child_ts = parent_ts.saturating_add(cfg.block_interval_secs.max(1));
    assert!(
        touch_result(TimePolicy::validate_block_timestamp_against_parent(
            child_ts,
            parent_ts,
            cfg.block_interval_secs.max(1),
        ))
        .is_some(),
        "parent/child timestamp rule must be deterministic and wall-clock-free"
    );

    assert!(
        TimePolicy::validate_unix_secs_structural("too_old", UNIX_2000_SECS - 1).is_err(),
        "timestamps before UNIX_2000_SECS must be rejected"
    );

    assert!(
        TimePolicy::validate_unix_secs_structural("too_future", UNIX_9999_SECS + 1).is_err(),
        "absurd far-future timestamps must be rejected"
    );

    let runtime_now = match touch_result(TimePolicy::now_unix_secs_runtime()) {
        Some(v) => v,
        None => return,
    };

    assert!(
        touch_result(TimePolicy::validate_runtime_future_skew_secs_default(
            "runtime_now",
            runtime_now,
            runtime_now,
        ))
        .is_some(),
        "runtime wall-clock checks must go through TimePolicy runtime entry points"
    );
}

fuzz_target!(|data: &[u8]| {
    exercise_time_policy(data);
    exercise_constructor_edges(data);
    exercise_registry_collection(data);
    exercise_remote_proof_paths(data);
    exercise_buffer_caps_and_clear(data);
    exercise_runtime_gates_and_build(data);
});