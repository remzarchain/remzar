//! src/consensus/por_008_validator_lifecycle.rs

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::time_policy::TimePolicy;

const MAX_LEASE_BLOCKS_HARD: u64 = 1_000_000;
const MAX_LIFECYCLE_DELAY_BLOCKS_HARD: u64 = 1_000_000;

/// Outcome of applying a canonical register-or-renew event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    Inserted,
    Renewed,
    Reactivated,
    NoChange,
}

/// Deterministic lifecycle config used by canonical validator checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorLifecycleConfig {
    /// How many blocks after join until a non-founder validator may propose.
    pub activation_delay_blocks: u64,

    /// Reward delay retained from the existing reward logic.
    pub reward_delay_blocks: u64,

    /// Canonical membership lease in blocks.
    pub lease_blocks: u64,
}

impl Default for ValidatorLifecycleConfig {
    fn default() -> Self {
        Self::from_globals()
    }
}

impl ValidatorLifecycleConfig {
    #[must_use]
    pub fn from_globals() -> Self {
        // Canonical validator lease expiry is separate from renewal frequency.
        let lease_blocks =
            GlobalConfiguration::CANONICAL_LEASE_BLOCKS.clamp(1, MAX_LEASE_BLOCKS_HARD);

        Self {
            activation_delay_blocks: GlobalConfiguration::VALIDATOR_ACTIVATION_DELAY_BLOCKS,
            reward_delay_blocks: GlobalConfiguration::REWARD_DELAY_BLOCKS as u64,
            lease_blocks,
        }
    }

    pub fn validate(&self) -> Result<(), ErrorDetection> {
        if self.lease_blocks == 0 {
            return Err(validation_err(
                "ValidatorLifecycleConfig invalid: lease_blocks must be >= 1",
            ));
        }

        if self.lease_blocks > MAX_LEASE_BLOCKS_HARD {
            return Err(validation_err(format!(
                "ValidatorLifecycleConfig invalid: lease_blocks={} exceeds hard cap {}",
                self.lease_blocks, MAX_LEASE_BLOCKS_HARD
            )));
        }

        if self.activation_delay_blocks > MAX_LIFECYCLE_DELAY_BLOCKS_HARD {
            return Err(validation_err(format!(
                "ValidatorLifecycleConfig invalid: activation_delay_blocks={} exceeds hard cap {}",
                self.activation_delay_blocks, MAX_LIFECYCLE_DELAY_BLOCKS_HARD
            )));
        }

        if self.reward_delay_blocks > MAX_LIFECYCLE_DELAY_BLOCKS_HARD {
            return Err(validation_err(format!(
                "ValidatorLifecycleConfig invalid: reward_delay_blocks={} exceeds hard cap {}",
                self.reward_delay_blocks, MAX_LIFECYCLE_DELAY_BLOCKS_HARD
            )));
        }

        Ok(())
    }
}

/// Canonical per-validator metadata.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidatorMeta {
    /// First block height at which this validator became active in the current era.
    pub join_height: u64,

    /// Timestamp associated with canonical join.
    pub join_timestamp: u64,

    /// Last block height at which canonical renewal was observed.
    pub last_renew_height: u64,

    /// Timestamp associated with the latest canonical renewal.
    pub last_renew_timestamp: u64,

    /// Optional explicit exit height.
    pub exit_height: Option<u64>,
}

impl ValidatorMeta {
    /// Canonical founder/bootstrap metadata.
    pub fn founder(join_timestamp: u64) -> Result<Self, ErrorDetection> {
        validate_timestamp("ValidatorMeta.founder.join_timestamp", join_timestamp)?;

        let meta = Self {
            join_height: 0,
            join_timestamp,
            last_renew_height: 0,
            last_renew_timestamp: join_timestamp,
            exit_height: None,
        };

        meta.validate_structural_invariants()?;
        Ok(meta)
    }

    /// Canonical metadata for a newly joining validator.
    pub fn joined(height: u64, join_timestamp: u64) -> Result<Self, ErrorDetection> {
        validate_timestamp("ValidatorMeta.joined.join_timestamp", join_timestamp)?;

        let meta = Self {
            join_height: height,
            join_timestamp,
            last_renew_height: height,
            last_renew_timestamp: join_timestamp,
            exit_height: None,
        };

        meta.validate_structural_invariants()?;
        Ok(meta)
    }

    /// Structural invariant validation that does NOT require a wallet string.
    fn validate_structural_invariants(&self) -> Result<(), ErrorDetection> {
        validate_timestamp("ValidatorMeta.join_timestamp", self.join_timestamp)?;
        validate_timestamp(
            "ValidatorMeta.last_renew_timestamp",
            self.last_renew_timestamp,
        )?;

        if self.last_renew_height < self.join_height {
            return Err(validation_err(format!(
                "ValidatorMeta invariant failed: last_renew_height={} < join_height={}",
                self.last_renew_height, self.join_height
            )));
        }

        if self.last_renew_timestamp < self.join_timestamp {
            return Err(validation_err(format!(
                "ValidatorMeta invariant failed: last_renew_timestamp={} < join_timestamp={}",
                self.last_renew_timestamp, self.join_timestamp
            )));
        }

        if let Some(exit_h) = self.exit_height {
            if exit_h == 0 {
                return Err(validation_err(
                    "ValidatorMeta invariant failed: exit_height=0 is invalid",
                ));
            }

            if exit_h <= self.join_height && self.join_height != 0 {
                return Err(validation_err(format!(
                    "ValidatorMeta invariant failed: exit_height={} <= join_height={}",
                    exit_h, self.join_height
                )));
            }
        }

        Ok(())
    }

    /// Defensive invariant validation with wallet validation.
    pub fn validate_invariants(&self, wallet: &str) -> Result<(), ErrorDetection> {
        let _ = canon_wallet_id_checked(wallet).map_err(|e| ErrorDetection::ValidationError {
            message: format!("ValidatorMeta invalid wallet '{}': {e}", wallet),
            tx_id: None,
        })?;

        self.validate_structural_invariants()
    }

    /// True iff the validator has NOT explicitly exited at `height`.
    #[must_use]
    pub fn not_explicitly_exited_at(&self, height: u64) -> bool {
        match self.exit_height {
            None => true,
            Some(exit_h) => height < exit_h,
        }
    }

    /// Height at which the canonical lease expires.
    #[must_use]
    pub fn lease_expiry_height(&self, cfg: ValidatorLifecycleConfig) -> u64 {
        self.last_renew_height.saturating_add(cfg.lease_blocks)
    }

    /// True iff the validator is still within its canonical lease at `height`.
    #[must_use]
    pub fn within_lease_at(&self, height: u64, cfg: ValidatorLifecycleConfig) -> bool {
        height <= self.lease_expiry_height(cfg)
    }

    /// True iff the validator is canonically active at `height`.
    #[must_use]
    pub fn is_active_at(&self, height: u64, cfg: ValidatorLifecycleConfig) -> bool {
        self.join_height <= height
            && self.not_explicitly_exited_at(height)
            && self.within_lease_at(height, cfg)
    }

    /// True iff the validator is canonically proposable at `height`.
    #[must_use]
    pub fn is_proposable_at(&self, height: u64, cfg: ValidatorLifecycleConfig) -> bool {
        if !self.is_active_at(height, cfg) {
            return false;
        }

        let eligible_h = if self.join_height == 0 {
            0
        } else {
            self.join_height.saturating_add(cfg.activation_delay_blocks)
        };

        eligible_h <= height
    }

    /// True iff the validator is reward-eligible at `height`.
    #[must_use]
    pub fn reward_eligible_at(&self, at_height: u64, cfg: ValidatorLifecycleConfig) -> bool {
        if self.join_height == 0 {
            return true;
        }

        at_height >= self.join_height.saturating_add(cfg.reward_delay_blocks)
    }

    /// Apply a canonical renewal to an already-known validator.
    pub fn renew_or_reactivate(
        &mut self,
        wallet: &str,
        height: u64,
        timestamp: u64,
    ) -> Result<RegisterOutcome, ErrorDetection> {
        validate_timestamp("ValidatorMeta.renew_or_reactivate.timestamp", timestamp)?;
        self.validate_invariants(wallet)?;

        match self.exit_height {
            None => {
                let mut changed = false;

                if height > self.last_renew_height {
                    self.last_renew_height = height;
                    changed = true;
                }

                if timestamp > self.last_renew_timestamp {
                    self.last_renew_timestamp = timestamp;
                    changed = true;
                }

                self.validate_invariants(wallet)?;
                Ok(if changed {
                    RegisterOutcome::Renewed
                } else {
                    RegisterOutcome::NoChange
                })
            }

            Some(exit_h) if exit_h > height => {
                // Out-of-order historical replay or duplicate register before the already-recorded exit.
                // Keep the stricter canonical state.
                Ok(RegisterOutcome::NoChange)
            }

            Some(_exit_h) => {
                if self.join_height == 0 {
                    // Founder semantics: never rewrite founder join_height away from 0.
                    self.last_renew_height = height.max(self.last_renew_height);
                    self.last_renew_timestamp = timestamp.max(self.last_renew_timestamp);
                    self.exit_height = None;
                } else {
                    self.join_height = height;
                    self.join_timestamp = timestamp;
                    self.last_renew_height = height;
                    self.last_renew_timestamp = timestamp;
                    self.exit_height = None;
                }

                self.validate_invariants(wallet)?;
                Ok(RegisterOutcome::Reactivated)
            }
        }
    }

    /// Set an explicit canonical exit height.
    pub fn mark_exit(&mut self, wallet: &str, height: u64) -> Result<bool, ErrorDetection> {
        self.validate_invariants(wallet)?;

        match self.exit_height {
            None => {
                self.exit_height = Some(height);
                self.validate_invariants(wallet)?;
                Ok(true)
            }
            Some(prev) if height < prev => {
                self.exit_height = Some(height);
                self.validate_invariants(wallet)?;
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }
}

/// Canonical lifecycle namespace.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatorLifecycle;

impl ValidatorLifecycle {
    #[must_use]
    pub fn config() -> ValidatorLifecycleConfig {
        ValidatorLifecycleConfig::from_globals()
    }

    pub fn founder_meta(join_timestamp: u64) -> Result<ValidatorMeta, ErrorDetection> {
        ValidatorMeta::founder(join_timestamp)
    }

    pub fn new_validator_meta(
        wallet: &str,
        height: u64,
        timestamp: u64,
    ) -> Result<ValidatorMeta, ErrorDetection> {
        let wallet_can =
            canon_wallet_id_checked(wallet).map_err(|e| ErrorDetection::ValidationError {
                message: format!("ValidatorLifecycle::new_validator_meta invalid wallet: {e}"),
                tx_id: None,
            })?;

        let meta = ValidatorMeta::joined(height, timestamp)?;
        meta.validate_invariants(&wallet_can)?;
        Ok(meta)
    }

    /// Apply canonical register-or-renew semantics directly into a map.
    pub fn apply_register_or_renew(
        map: &mut BTreeMap<String, ValidatorMeta>,
        wallet: &str,
        height: u64,
        timestamp: u64,
    ) -> Result<RegisterOutcome, ErrorDetection> {
        let wallet_can =
            canon_wallet_id_checked(wallet).map_err(|e| ErrorDetection::ValidationError {
                message: format!("ValidatorLifecycle::apply_register_or_renew invalid wallet: {e}"),
                tx_id: None,
            })?;

        Self::config().validate()?;
        validate_timestamp(
            "ValidatorLifecycle.apply_register_or_renew.timestamp",
            timestamp,
        )?;

        match map.get_mut(&wallet_can) {
            Some(meta) => {
                let outcome = meta.renew_or_reactivate(&wallet_can, height, timestamp)?;
                Ok(outcome)
            }
            None => {
                let meta = Self::new_validator_meta(&wallet_can, height, timestamp)?;
                map.insert(wallet_can.clone(), meta);
                Ok(RegisterOutcome::Inserted)
            }
        }
    }

    /// Explicit canonical exit helper.
    pub fn apply_exit(
        map: &mut BTreeMap<String, ValidatorMeta>,
        wallet: &str,
        height: u64,
    ) -> Result<bool, ErrorDetection> {
        let wallet_can =
            canon_wallet_id_checked(wallet).map_err(|e| ErrorDetection::ValidationError {
                message: format!("ValidatorLifecycle::apply_exit invalid wallet: {e}"),
                tx_id: None,
            })?;

        let Some(meta) = map.get_mut(&wallet_can) else {
            return Ok(false);
        };

        let changed = meta.mark_exit(&wallet_can, height)?;
        Ok(changed)
    }

    #[must_use]
    pub fn is_active_at(meta: &ValidatorMeta, height: u64) -> bool {
        meta.is_active_at(height, Self::config())
    }

    #[must_use]
    pub fn is_proposable_at(meta: &ValidatorMeta, height: u64) -> bool {
        meta.is_proposable_at(height, Self::config())
    }

    #[must_use]
    pub fn reward_eligible_at(meta: &ValidatorMeta, height: u64) -> bool {
        meta.reward_eligible_at(height, Self::config())
    }

    pub fn active_wallets_at(
        map: &BTreeMap<String, ValidatorMeta>,
        height: u64,
    ) -> Result<Vec<String>, ErrorDetection> {
        let cfg = Self::config();
        cfg.validate()?;

        let mut out: Vec<String> = map
            .iter()
            .filter_map(|(wallet, meta)| {
                if meta.is_active_at(height, cfg) {
                    Some(wallet.clone())
                } else {
                    None
                }
            })
            .collect();

        out.sort_unstable();
        Ok(out)
    }

    pub fn proposable_wallets_at(
        map: &BTreeMap<String, ValidatorMeta>,
        height: u64,
    ) -> Result<Vec<String>, ErrorDetection> {
        let cfg = Self::config();
        cfg.validate()?;

        let mut out: Vec<String> = map
            .iter()
            .filter_map(|(wallet, meta)| {
                if meta.is_proposable_at(height, cfg) {
                    Some(wallet.clone())
                } else {
                    None
                }
            })
            .collect();

        out.sort_unstable();
        Ok(out)
    }

    pub fn validate_map(map: &BTreeMap<String, ValidatorMeta>) -> Result<(), ErrorDetection> {
        Self::config().validate()?;

        for (wallet, meta) in map {
            meta.validate_invariants(wallet)?;
        }
        Ok(())
    }
}

#[inline]
fn validation_err(msg: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: msg.into(),
        tx_id: None,
    }
}

#[inline]
fn validate_timestamp(label: &'static str, ts: u64) -> Result<(), ErrorDetection> {
    TimePolicy::validate_unix_secs_structural(label, ts)
}
