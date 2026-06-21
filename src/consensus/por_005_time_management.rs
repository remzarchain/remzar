// time_management.rs — Centralized timing & slot clock for Remzar (PoR era)

use std::time::{Duration, Instant};

use crate::blockchain::genesis_002_file::GenesisFile;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::time_policy::{ChainTimePolicyConfig, TimePolicy};

/// Runtime timing configuration (seconds-first).
#[derive(Clone, Debug)]
pub struct TimeConfig {
    /// Block creation interval in **seconds**.
    pub block_interval_secs: u64,

    /// Effective puzzle interval in **seconds** (clamped to <= block interval).
    pub puzzle_interval_secs: u64,

    /// Minimum warm-up time after registration before a validator may propose.
    pub activation_warmup_secs: u64,

    /// UNIX timestamp (seconds) when slot 0 starts. All nodes align to this.
    pub genesis_time_unix: u64,

    /// Number of blocks to skip before rewards are issued.
    pub reward_delay_blocks: usize,

    /// Number of blocks a (re)joining validator must wait before being eligible
    /// to propose. Mirrors `GlobalConfiguration::QUARANTINE_BLOCKS`.
    pub quarantine_blocks: u64,

    /// Number of heights per epoch if you group slots into epochs.
    pub epoch_slots: u64,

    // ────────────────────────────────
    // ✅ PoR failover rounds settings
    // ────────────────────────────────
    /// τ (tau) = how long we give a leader before moving to the next leader
    /// within the same height.
    ///
    /// Recommended: τ >= puzzle_interval + slack.
    pub failover_window_secs: u64,

    /// Tail buffer inside a nominal slot reserved for propagation.
    /// NOTE: producer policy knob, not a hard consensus reject.
    pub slot_gossip_buffer_secs: u64,

    /// Proposal deadline inside the nominal slot (seconds from height start).
    /// NOTE: producer policy knob, not a hard consensus reject.
    pub failover_proposal_deadline_secs: u64,

    /// Max rounds that fit inside the proposal window (>=1).
    /// NOTE: producer policy knob, not a consensus cap.
    pub failover_max_rounds: u64,

    /// Tight drift allowance for deterministic timestamp gating.
    pub slot_gate_drift_secs: u64,
}

impl TimeConfig {
    /// Compute a robust, network-wide puzzle duration in seconds.
    fn effective_puzzle_secs() -> u64 {
        let slot_secs = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
        let raw_puzzle_secs = GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS.max(1);
        raw_puzzle_secs.min(slot_secs)
    }

    /// Compute failover parameters from globals with safe clamping.
    fn effective_failover_params(
        block_interval_secs: u64,
        puzzle_interval_secs: u64,
    ) -> (u64, u64, u64, u64, u64) {
        let bi = block_interval_secs.max(1);
        let pi = puzzle_interval_secs.max(1);

        let slack = GlobalConfiguration::FAILOVER_SLACK_SECS;
        let mut tau = GlobalConfiguration::FAILOVER_WINDOW_SECS.max(1);

        let min_tau = pi.saturating_add(slack).max(1);
        if tau < min_tau {
            tau = min_tau;
        }

        let mut gossip_buf = GlobalConfiguration::SLOT_GOSSIP_BUFFER_SECS;
        if gossip_buf >= bi {
            gossip_buf = 1;
        }

        let deadline = bi.saturating_sub(gossip_buf).max(1);

        let mut rounds = deadline.div_euclid(tau);
        if rounds == 0 {
            rounds = 1;
        }

        let drift = GlobalConfiguration::SLOT_GATE_DRIFT_SECS;

        (tau, gossip_buf, deadline, rounds, drift)
    }

    /// Build from a known `genesis_time_unix` using seconds-first globals.
    pub fn from_genesis_ts(genesis_time_unix: u64) -> Self {
        let block_interval_secs = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
        let puzzle_interval_secs = Self::effective_puzzle_secs();

        let (
            failover_window_secs,
            slot_gossip_buffer_secs,
            failover_proposal_deadline_secs,
            failover_max_rounds,
            slot_gate_drift_secs,
        ) = Self::effective_failover_params(block_interval_secs, puzzle_interval_secs);

        Self {
            block_interval_secs,
            puzzle_interval_secs,
            activation_warmup_secs: GlobalConfiguration::ACTIVATION_WARMUP_SECS,
            reward_delay_blocks: GlobalConfiguration::REWARD_DELAY_BLOCKS,
            genesis_time_unix: genesis_time_unix.max(1),
            quarantine_blocks: GlobalConfiguration::QUARANTINE_BLOCKS,
            epoch_slots: GlobalConfiguration::EPOCH_SLOTS,

            failover_window_secs: failover_window_secs.max(1),
            slot_gossip_buffer_secs,
            failover_proposal_deadline_secs,
            failover_max_rounds: failover_max_rounds.max(1),
            slot_gate_drift_secs,
        }
    }

    /// Load `genesis_block.timestamp` from a `genesis.json` and build config.
    pub fn from_genesis_file(path: &str) -> Result<Self, ErrorDetection> {
        let gf = GenesisFile::from_json_file(path)?;
        let cfg = Self::from_genesis_ts(gf.genesis_block.timestamp);
        cfg.validate()?;
        Ok(cfg)
    }

    /// Deterministic validation for the time configuration.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        TimePolicy::validate_unix_secs_structural(
            "TimeConfig.genesis_time_unix",
            self.genesis_time_unix,
        )?;

        self.chain_time_policy_config().validate()?;

        if self.puzzle_interval_secs == 0 {
            return Err(validation_err(
                "TimeConfig invalid: puzzle_interval_secs must be >= 1",
            ));
        }

        if self.puzzle_interval_secs > self.block_interval_secs.max(1) {
            return Err(validation_err(format!(
                "TimeConfig invalid: puzzle_interval_secs={} > block_interval_secs={}",
                self.puzzle_interval_secs, self.block_interval_secs
            )));
        }

        if self.failover_window_secs == 0 {
            return Err(validation_err(
                "TimeConfig invalid: failover_window_secs must be >= 1",
            ));
        }

        if self.failover_proposal_deadline_secs == 0 {
            return Err(validation_err(
                "TimeConfig invalid: failover_proposal_deadline_secs must be >= 1",
            ));
        }

        if self.failover_max_rounds == 0 {
            return Err(validation_err(
                "TimeConfig invalid: failover_max_rounds must be >= 1",
            ));
        }

        Ok(())
    }

    /// Build the deterministic chain-time validation config used by TimePolicy.
    #[inline]
    pub fn chain_time_policy_config(&self) -> ChainTimePolicyConfig {
        ChainTimePolicyConfig::new(
            self.genesis_time_unix,
            self.block_interval_secs.max(1),
            self.slot_gate_drift_secs,
        )
    }

    /// Derived: activation delay in *blocks* = ceil(warmup / block_interval).
    pub fn activation_delay_blocks(&self) -> u64 {
        let b = self.block_interval_secs.max(1);
        self.activation_warmup_secs.div_ceil(b)
    }

    /// SINGLE ELIGIBILITY RULE (ONE SOURCE OF TRUTH)
    #[inline]
    pub fn proposer_delay_blocks(&self) -> u64 {
        self.activation_delay_blocks().max(self.quarantine_blocks)
    }

    #[inline]
    pub fn block_interval(&self) -> Duration {
        Duration::from_secs(self.block_interval_secs.max(1))
    }

    #[inline]
    pub fn puzzle_interval(&self) -> Duration {
        Duration::from_secs(self.puzzle_interval_secs.max(1))
    }

    // ─────────────────────────── Failover accessors ───────────────────────────

    #[inline]
    pub fn failover_window(&self) -> Duration {
        Duration::from_secs(self.failover_window_secs.max(1))
    }

    #[inline]
    pub fn failover_window_secs(&self) -> u64 {
        self.failover_window_secs.max(1)
    }

    #[inline]
    pub fn slot_gossip_buffer_secs(&self) -> u64 {
        self.slot_gossip_buffer_secs
    }

    #[inline]
    pub fn proposal_deadline_secs(&self) -> u64 {
        self.failover_proposal_deadline_secs.max(1)
    }

    #[inline]
    pub fn max_rounds(&self) -> u64 {
        self.failover_max_rounds.max(1)
    }

    #[inline]
    pub fn slot_gate_drift_secs(&self) -> u64 {
        self.slot_gate_drift_secs
    }
}

/// Optional helper container for BFT round timeouts.
#[derive(Clone, Copy, Debug)]
pub struct ConsensusTimeouts {
    pub propose: Duration,
    pub prevote: Duration,
    pub precommit: Duration,
}

/// Derived, strongly-typed manager with helpers for consensus & scheduling.
#[derive(Clone, Debug)]
pub struct TimeManager {
    cfg: TimeConfig,
}

impl TimeManager {
    /// Construct from a ready `TimeConfig`.
    pub fn new(cfg: TimeConfig) -> Self {
        if let Err(e) = cfg.validate() {
            tracing::debug!(
                "[STARTUP][WARN] TimeManager config validation failed: {:?}",
                e
            );
        }
        Self { cfg }
    }

    /// Construct from a ready `TimeConfig` and fail fast if invalid.
    pub fn new_checked(cfg: TimeConfig) -> Result<Self, ErrorDetection> {
        cfg.validate()?;
        Ok(Self { cfg })
    }

    /// One-stop helper: load `genesis.json` and construct.
    pub fn new_from_genesis_file(path: &str) -> Result<Self, ErrorDetection> {
        Self::new_checked(TimeConfig::from_genesis_file(path)?)
    }

    // ─────────────────────────── Accessors ───────────────────────────

    #[inline]
    pub fn cfg(&self) -> &TimeConfig {
        &self.cfg
    }

    #[inline]
    pub fn block_interval(&self) -> Duration {
        self.cfg.block_interval()
    }

    #[inline]
    pub fn puzzle_interval(&self) -> Duration {
        self.cfg.puzzle_interval()
    }

    #[inline]
    pub fn block_interval_secs(&self) -> u64 {
        self.cfg.block_interval_secs.max(1)
    }

    #[inline]
    pub fn puzzle_interval_secs(&self) -> u64 {
        self.cfg.puzzle_interval_secs.max(1)
    }

    #[inline]
    pub fn activation_delay_blocks(&self) -> u64 {
        self.cfg.activation_delay_blocks()
    }

    #[inline]
    pub fn quarantine_blocks(&self) -> u64 {
        self.cfg.quarantine_blocks
    }

    /// SINGLE ELIGIBILITY RULE (ONE SOURCE OF TRUTH)
    #[inline]
    pub fn proposer_delay_blocks(&self) -> u64 {
        self.cfg.proposer_delay_blocks()
    }

    #[inline]
    pub fn epoch_slots(&self) -> u64 {
        self.cfg.epoch_slots.max(1)
    }

    // ─────────────────────────── Failover accessors ───────────────────────────

    /// τ (tau) — leader window length inside a height.
    #[inline]
    pub fn failover_window_secs(&self) -> u64 {
        self.cfg.failover_window_secs()
    }

    /// Max rounds per nominal slot (producer policy, >=1).
    #[inline]
    pub fn failover_max_rounds(&self) -> u64 {
        self.cfg.max_rounds()
    }

    /// Proposal deadline inside nominal slot (producer policy).
    #[inline]
    pub fn proposal_deadline_secs(&self) -> u64 {
        self.cfg.proposal_deadline_secs()
    }

    /// Tail buffer reserved for gossip (producer policy).
    #[inline]
    pub fn slot_gossip_buffer_secs(&self) -> u64 {
        self.cfg.slot_gossip_buffer_secs()
    }

    /// Tight drift allowed for deterministic timestamp gating.
    #[inline]
    pub fn slot_gate_drift_secs(&self) -> u64 {
        self.cfg.slot_gate_drift_secs()
    }

    /// Deterministic chain-time validation config used by TimePolicy.
    #[inline]
    pub fn chain_time_policy_config(&self) -> ChainTimePolicyConfig {
        self.cfg.chain_time_policy_config()
    }

    /// Scheduling helper: sync polling should be at least as fast as failover.
    #[inline]
    pub fn sync_poll_interval(&self) -> Duration {
        Duration::from_secs(self.failover_window_secs().max(1))
    }

    /// Scheduling helper: registry heartbeat should not be slower than failover.
    #[inline]
    pub fn registry_heartbeat_interval(&self, configured_secs: Option<u64>) -> Option<Duration> {
        configured_secs.map(|secs| {
            Duration::from_secs(secs.max(1)).min(Duration::from_secs(self.failover_window_secs()))
        })
    }

    /// Scheduling helper: first periodic tasks should align to the next slot.
    #[inline]
    pub fn start_after_next_slot(&self, now_unix: u64) -> Duration {
        let next_slot = self.current_slot(now_unix).saturating_add(1);
        let start_unix = self.slot_start_unix(next_slot);
        Duration::from_secs(start_unix.saturating_sub(now_unix))
    }

    /// Timeouts for a single consensus round as fractions of the block time.
    pub fn consensus_timeouts(&self) -> ConsensusTimeouts {
        let bi = self.block_interval();
        ConsensusTimeouts {
            propose: bi.mul_f64(0.60),
            prevote: bi.mul_f64(0.20),
            precommit: bi.mul_f64(0.20),
        }
    }

    // ───────────────────────────── Slot/Height clock ───────────────────────────

    /// Runtime wall-clock UNIX seconds.
    #[inline]
    pub fn now_unix() -> u64 {
        Self::now_unix_result().unwrap_or(0)
    }

    /// Runtime wall-clock UNIX seconds with explicit error reporting.
    #[inline]
    pub fn now_unix_result() -> Result<u64, ErrorDetection> {
        TimePolicy::now_unix_secs_runtime()
    }

    /// Deterministic slot number shared by all nodes for a supplied UNIX timestamp.
    #[inline]
    pub fn current_slot(&self, now_unix: u64) -> u64 {
        let elapsed = now_unix.saturating_sub(self.cfg.genesis_time_unix);
        let denom = self.block_interval_secs();
        elapsed.div_euclid(denom)
    }

    /// Checked deterministic slot number for a supplied UNIX timestamp.
    pub fn current_slot_checked(&self, now_unix: u64) -> Result<u64, ErrorDetection> {
        self.cfg.validate()?;
        self.chain_time_policy_config()
            .slot_for_timestamp_checked(now_unix)
    }

    /// UNIX start time of a given slot (deterministic schedule).
    #[inline]
    pub fn slot_start_unix(&self, slot: u64) -> u64 {
        self.cfg
            .genesis_time_unix
            .saturating_add(slot.saturating_mul(self.block_interval_secs()))
    }

    /// Checked UNIX start time of a given slot.
    pub fn slot_start_unix_checked(&self, slot: u64) -> Result<u64, ErrorDetection> {
        self.chain_time_policy_config()
            .slot_start_unix_checked(slot)
    }

    /// Alias: deterministic "height start".
    #[inline]
    pub fn height_start_unix(&self, height: u64) -> u64 {
        self.slot_start_unix(height)
    }

    /// Checked alias for deterministic "height start".
    pub fn height_start_unix_checked(&self, height: u64) -> Result<u64, ErrorDetection> {
        self.slot_start_unix_checked(height)
    }

    /// Seconds since deterministic height start (UNBOUNDED).
    #[inline]
    pub fn secs_since_height_start(&self, height: u64, now_unix: u64) -> u64 {
        let start = self.height_start_unix(height);
        now_unix.saturating_sub(start)
    }

    /// Determine the failover round for a given height at a given wall time (UNBOUNDED).
    #[inline]
    pub fn round_for_height_at_time(&self, height: u64, now_unix: u64) -> u64 {
        let tau = self.failover_window_secs().max(1);
        let since = self.secs_since_height_start(height, now_unix);
        since.div_euclid(tau)
    }

    /// Seconds elapsed since the start of `slot` (clamped to <= block interval_secs).
    #[inline]
    pub fn secs_into_slot(&self, slot: u64, now_unix: u64) -> u64 {
        let start = self.slot_start_unix(slot);
        let delta = now_unix.saturating_sub(start);
        delta.min(self.block_interval_secs())
    }

    /// Checked seconds elapsed since the start of `slot`.
    pub fn secs_into_slot_checked(&self, slot: u64, now_unix: u64) -> Result<u64, ErrorDetection> {
        self.chain_time_policy_config()
            .secs_into_slot_checked(slot, now_unix)
    }

    /// Determine the current failover round within the given slot using wall clock.
    #[inline]
    pub fn round_in_slot(&self, slot: u64, now_unix: u64) -> u64 {
        let tau = self.failover_window_secs().max(1);
        let deadline = self.proposal_deadline_secs().max(1);

        let mut t = self.secs_into_slot(slot, now_unix);
        if t >= deadline {
            t = deadline.saturating_sub(1);
        }

        let r = t.div_euclid(tau);
        r.min(self.failover_max_rounds().saturating_sub(1))
    }

    /// Consensus-side helper.
    pub fn round_for_height_from_block_timestamp(
        &self,
        height: u64,
        block_ts_unix: u64,
    ) -> Result<(u64, u64), ErrorDetection> {
        self.cfg.validate()?;
        TimePolicy::validate_unix_secs_structural("block.timestamp", block_ts_unix)?;

        let drift = self.slot_gate_drift_secs();
        let start = self.height_start_unix_checked(height)?;

        if block_ts_unix < self.cfg.genesis_time_unix.saturating_sub(drift) {
            return Err(validation_err(format!(
                "block timestamp {} is before genesis (genesis={})",
                block_ts_unix, self.cfg.genesis_time_unix
            )));
        }

        if block_ts_unix < start {
            let back = start.saturating_sub(block_ts_unix);
            if back > drift {
                return Err(validation_err(format!(
                    "block timestamp too far before height start: ts={} start={} back={}s drift={}s",
                    block_ts_unix, start, back, drift
                )));
            }

            let since = 0u64;
            let tau = self.failover_window_secs().max(1);
            let round = since.div_euclid(tau);
            return Ok((round, since));
        }

        let since = block_ts_unix.saturating_sub(start);
        let tau = self.failover_window_secs().max(1);
        let round = since.div_euclid(tau);

        Ok((round, since))
    }

    /// Timestamp helper.
    pub fn slot_and_round_from_block_timestamp(
        &self,
        block_ts_unix: u64,
    ) -> Result<(u64, u64, u64), ErrorDetection> {
        self.cfg.validate()?;

        let (slot, into) = TimePolicy::derive_slot_from_block_timestamp(
            self.chain_time_policy_config(),
            block_ts_unix,
        )?;

        let tau = self.failover_window_secs().max(1);
        let round = into.div_euclid(tau);

        Ok((slot, round, into))
    }

    /// Sleep until the *next* wall-clock slot boundary.
    pub fn sleep_until_next_slot(&self) {
        let now = Self::now_unix();
        let slot = self.current_slot(now);
        let next = self.slot_start_unix(slot.saturating_add(1));

        let mut remaining = next.saturating_sub(Self::now_unix());
        let bi = self.block_interval_secs();
        if remaining > bi {
            remaining = bi;
        }

        if remaining == 0 {
            return;
        }

        let _sleep_begin = Instant::now();
        std::thread::sleep(Duration::from_secs(remaining));

        let now2 = Self::now_unix();
        if now2 < next {
            let delta = next.saturating_sub(now2);
            if delta > 0 {
                std::thread::sleep(Duration::from_secs(delta));
            }
        }
    }

    // ───────────────────── Proposal gating helpers ──────────────────────

    /// Whether a validator is past the height-based activation delay *and* health gate.
    pub fn is_eligible_for_proposal(
        &self,
        now_height: u64,
        registration_inclusion_height: u64,
        is_fully_synced: bool,
    ) -> bool {
        now_height >= registration_inclusion_height.saturating_add(self.activation_delay_blocks())
            && is_fully_synced
    }

    /// Guardrail: warn loudly if globals drift from our runtime derivation.
    pub fn assert_activation_delay_consistent(&self) {
        let derived = self.activation_delay_blocks();
        let configured = GlobalConfiguration::VALIDATOR_ACTIVATION_DELAY_BLOCKS;
        if derived != configured {
            tracing::debug!(
                "[STARTUP][WARN] Activation delay mismatch: TimeManager={} blocks, GlobalConfiguration={} blocks. Canonical is TimeManager-derived.",
                derived,
                configured
            );
        }
    }

    /// Optional: warn if the runtime quarantine block setting differs from global constant.
    pub fn assert_quarantine_consistent(&self) {
        let configured = GlobalConfiguration::QUARANTINE_BLOCKS;
        if self.quarantine_blocks() != configured {
            tracing::debug!(
                "[STARTUP][WARN] Quarantine blocks mismatch: TimeManager={} blocks, GlobalConfiguration={} blocks.",
                self.quarantine_blocks(),
                configured
            );
        }
    }

    /// Warn if failover params look self-contradictory.
    pub fn assert_failover_consistent(&self) {
        let bi = self.block_interval_secs().max(1);
        let tau = self.failover_window_secs().max(1);
        let deadline = self.proposal_deadline_secs().max(1);
        let rounds = self.failover_max_rounds().max(1);
        let drift = self.slot_gate_drift_secs();

        if tau > bi {
            tracing::debug!(
                "[STARTUP][WARN] Failover window τ={}s is > block interval {}s; failover scheduling may be ineffective.",
                tau,
                bi
            );
        }

        if deadline > bi {
            tracing::debug!(
                "[STARTUP][WARN] Proposal deadline {}s is > block interval {}s; check SLOT_GOSSIP_BUFFER_SECS.",
                deadline,
                bi
            );
        }

        if rounds == 0 {
            tracing::debug!("[STARTUP][WARN] failover_max_rounds computed as 0; clamped to 1.");
        }

        if drift > 30 {
            tracing::debug!(
                "[STARTUP][WARN] SLOT_GATE_DRIFT_SECS={}s is unusually large; timestamp gating may be too permissive.",
                drift
            );
        }
    }

    // ────────────────────────── Epoch helpers (optional) ─────────────────────

    #[inline]
    pub fn epoch_of_height(&self, height: u64) -> u64 {
        let denom = self.epoch_slots().max(1);
        height.div_euclid(denom)
    }

    #[inline]
    pub fn slot_in_epoch(&self, height: u64) -> u64 {
        let denom = self.epoch_slots().max(1);
        height.rem_euclid(denom)
    }
}

#[inline]
fn validation_err(message: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: message.into(),
        tx_id: None,
    }
}
