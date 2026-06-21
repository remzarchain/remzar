//! src/utility/time_policy.rs

use chrono::Utc;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

/// Hard lower-bound sanity check for UNIX seconds.
pub const UNIX_2000_SECS: u64 = 946_684_800;

/// Hard lower-bound sanity check for UNIX milliseconds.
pub const UNIX_2000_MILLIS: u64 = UNIX_2000_SECS * 1_000;

/// Deterministic upper bound for UNIX seconds.
pub const UNIX_9999_SECS: u64 = 253_402_300_799;

/// Deterministic upper bound for UNIX milliseconds.
pub const UNIX_9999_MILLIS: u64 = UNIX_9999_SECS * 1_000;

/// Hard defensive cap for slot drift.
pub const MAX_SLOT_GATE_DRIFT_SECS: u64 = 24 * 60 * 60;

/// Hard defensive cap for block interval.
pub const MAX_BLOCK_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Minimal deterministic chain-time config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTimePolicyConfig {
    /// UNIX timestamp when slot 0 starts.
    pub genesis_time_unix: u64,

    /// Nominal slot/block interval in seconds.
    pub block_interval_secs: u64,

    /// Deterministic drift tolerance around slot boundaries.
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
pub struct TimePolicy;

impl TimePolicy {
    // ─────────────────────────────────────────────────────────────
    // Runtime wall-clock entry points
    // ─────────────────────────────────────────────────────────────

    /// Runtime wall-clock UNIX seconds.
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
    pub fn canonical_event_timestamp_from_block(
        label: &'static str,
        containing_block_ts: u64,
    ) -> Result<u64, ErrorDetection> {
        Self::validate_unix_secs_structural(label, containing_block_ts)?;
        Ok(containing_block_ts)
    }

    /// Optional deterministic check for a transaction timestamp inside a block.
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
