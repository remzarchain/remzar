//! src/consensus/por_007_leader_schedule.rs

use crate::blockchain::validatorstate::ValidatorState;
use crate::consensus::por_005_time_management::TimeManager;
use crate::consensus::por_006_committee_eligibility::CommitteeEligibility;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::time_policy::TimePolicy;

use chrono::DateTime;
use std::collections::BTreeSet;

/// Domain separator for canonical committee snapshot hashing.
const COMMITTEE_HASH_DOMAIN: &[u8] = b"remzar:por:committee:v3|";

/// Domain separator for per-validator leader scoring.
const LEADER_SCORE_DOMAIN: &[u8] = b"remzar:por:leader-score:v3|";

/// Domain separator for trace fingerprinting / debugging.
const TRACE_HASH_DOMAIN: &[u8] = b"remzar:por:trace:v3|";

/// Hard cap to prevent pathological allocations if canonical state is corrupted.
const MAX_COMMITTEE_SIZE_HARD: usize = 100_000;

/// Frozen canonical committee for a single `(parent_hash, height)` context.
#[derive(Debug, Clone)]
pub struct CommitteeSnapshot {
    pub height: u64,
    pub parent_hash: [u8; 64],
    pub activation_delay_blocks: u64,
    pub validators: Vec<String>,
    pub committee_hash: [u8; 64],
}

impl CommitteeSnapshot {
    #[must_use]
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    #[must_use]
    pub fn contains_wallet(&self, wallet: &str) -> bool {
        self.validators
            .iter()
            .any(|v| v.eq_ignore_ascii_case(wallet))
    }
}

/// Chosen canonical leader for a specific round over a frozen committee snapshot.
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

/// Expanded trace useful for logs and debugging.
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

/// Result of local mint authorization.
#[derive(Debug, Clone)]
pub struct MintAuthorization {
    pub local_wallet: String,
    pub trace: LeaderTrace,
}

/// Leader schedule for the local node.
#[derive(Debug, Clone)]
pub struct LeaderSchedule {
    local_wallet: String,
}

impl LeaderSchedule {
    pub fn new(local_wallet: String) -> Result<Self, ErrorDetection> {
        let local_wallet = canon_wallet_id_checked(&local_wallet)?;
        Ok(Self { local_wallet })
    }

    #[must_use]
    pub fn local_wallet(&self) -> &str {
        &self.local_wallet
    }

    #[inline]
    fn validation_err(msg: impl Into<String>) -> ErrorDetection {
        ErrorDetection::ValidationError {
            message: msg.into(),
            tx_id: None,
        }
    }

    /// Runtime-only timestamp for leader-schedule diagnostics/logs.
    #[inline]
    fn runtime_log_timestamp() -> String {
        match TimePolicy::now_unix_secs_runtime() {
            Ok(now_unix) => {
                let Some(now_i64) = i64::try_from(now_unix).ok() else {
                    return format!("unix:{now_unix}");
                };

                DateTime::from_timestamp(now_i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| format!("unix:{now_unix}"))
            }
            Err(_) => "time_unavailable".to_string(),
        }
    }

    fn normalize_active_validators(
        raw: Vec<String>,
        height: u64,
    ) -> Result<Vec<String>, ErrorDetection> {
        if raw.is_empty() {
            return Err(Self::validation_err(format!(
                "no canonical validators at height {} (canonical validator set empty?)",
                height
            )));
        }

        if raw.len() > MAX_COMMITTEE_SIZE_HARD {
            return Err(Self::validation_err(format!(
                "canonical validator set too large at height {}: {} > hard cap {}",
                height,
                raw.len(),
                MAX_COMMITTEE_SIZE_HARD
            )));
        }

        let mut uniq = BTreeSet::<String>::new();
        for wallet in raw {
            uniq.insert(canon_wallet_id_checked(&wallet)?);
        }

        let validators: Vec<String> = uniq.into_iter().collect();

        if validators.is_empty() {
            return Err(Self::validation_err(format!(
                "canonical validator set collapsed to empty after canonicalization at height {}",
                height
            )));
        }

        if validators.len() > MAX_COMMITTEE_SIZE_HARD {
            return Err(Self::validation_err(format!(
                "canonical validator set too large at height {}: {} > hard cap {}",
                height,
                validators.len(),
                MAX_COMMITTEE_SIZE_HARD
            )));
        }

        Ok(validators)
    }

    fn validate_snapshot_invariants(snapshot: &CommitteeSnapshot) -> Result<(), ErrorDetection> {
        if snapshot.height == 0 {
            return Err(Self::validation_err(
                "committee snapshot created for height=0",
            ));
        }

        if snapshot.validators.is_empty() {
            return Err(Self::validation_err(format!(
                "committee snapshot empty at height {}",
                snapshot.height
            )));
        }

        if snapshot.validators.len() > MAX_COMMITTEE_SIZE_HARD {
            return Err(Self::validation_err(format!(
                "committee snapshot too large at height {}: {} > hard cap {}",
                snapshot.height,
                snapshot.validators.len(),
                MAX_COMMITTEE_SIZE_HARD
            )));
        }

        let mut uniq = BTreeSet::<String>::new();
        for v in &snapshot.validators {
            uniq.insert(canon_wallet_id_checked(v)?);
        }

        if uniq.len() != snapshot.validators.len() {
            return Err(Self::validation_err(format!(
                "committee snapshot contains duplicate/non-canonical validators at height {}",
                snapshot.height
            )));
        }

        let expected_hash = Self::compute_committee_hash(
            snapshot.parent_hash,
            snapshot.height,
            snapshot.activation_delay_blocks,
            &snapshot.validators,
        );

        if expected_hash != snapshot.committee_hash {
            return Err(Self::validation_err(format!(
                "committee snapshot hash mismatch at height {}",
                snapshot.height
            )));
        }

        Ok(())
    }

    /// Canonical validator set for height `height`.
    pub fn canonical_validators_for_height(
        validator_state: &ValidatorState,
        tm: &TimeManager,
        height: u64,
    ) -> Result<Vec<String>, ErrorDetection> {
        if height == 0 {
            return Err(Self::validation_err(
                "canonical_validators_for_height called for height=0",
            ));
        }

        let activation_delay_blocks = tm.proposer_delay_blocks();
        let raw = validator_state.proposable_at(height, activation_delay_blocks);
        Self::normalize_active_validators(raw, height)
    }

    /// Backward-compatible alias kept during rollout.
    pub fn active_validators_for_height(
        validator_state: &ValidatorState,
        _committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        height: u64,
    ) -> Result<Vec<String>, ErrorDetection> {
        Self::canonical_validators_for_height(validator_state, tm, height)
    }

    pub fn committee_snapshot(
        validator_state: &ValidatorState,
        _committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        parent_hash: [u8; 64],
        height: u64,
    ) -> Result<CommitteeSnapshot, ErrorDetection> {
        let validators = Self::canonical_validators_for_height(validator_state, tm, height)?;
        let activation_delay_blocks = tm.proposer_delay_blocks();
        let committee_hash =
            Self::compute_committee_hash(parent_hash, height, activation_delay_blocks, &validators);

        let snapshot = CommitteeSnapshot {
            height,
            parent_hash,
            activation_delay_blocks,
            validators,
            committee_hash,
        };

        Self::validate_snapshot_invariants(&snapshot)?;
        Ok(snapshot)
    }

    #[must_use]
    pub fn compute_committee_hash(
        parent_hash: [u8; 64],
        height: u64,
        activation_delay_blocks: u64,
        validators: &[String],
    ) -> [u8; 64] {
        let validators_total_len = validators.iter().map(String::len).sum::<usize>();
        let capacity = COMMITTEE_HASH_DOMAIN
            .len()
            .saturating_add(64)
            .saturating_add(8)
            .saturating_add(8)
            .saturating_add(validators_total_len)
            .saturating_add(validators.len());

        let mut preimage = Vec::with_capacity(capacity);

        preimage.extend_from_slice(COMMITTEE_HASH_DOMAIN);
        preimage.extend_from_slice(&parent_hash);
        preimage.extend_from_slice(&height.to_be_bytes());
        preimage.extend_from_slice(&activation_delay_blocks.to_be_bytes());

        for v in validators {
            preimage.extend_from_slice(b"|");
            preimage.extend_from_slice(v.as_bytes());
        }

        RemzarHash::compute_bytes_hash(&preimage)
    }

    #[must_use]
    pub fn leader_score(
        committee_hash: [u8; 64],
        parent_hash: [u8; 64],
        height: u64,
        round: u64,
        validator: &str,
    ) -> [u8; 64] {
        let capacity = LEADER_SCORE_DOMAIN
            .len()
            .saturating_add(64)
            .saturating_add(64)
            .saturating_add(8)
            .saturating_add(8)
            .saturating_add(1)
            .saturating_add(validator.len());
        let mut preimage = Vec::with_capacity(capacity);

        preimage.extend_from_slice(LEADER_SCORE_DOMAIN);
        preimage.extend_from_slice(&committee_hash);
        preimage.extend_from_slice(&parent_hash);
        preimage.extend_from_slice(&height.to_be_bytes());
        preimage.extend_from_slice(&round.to_be_bytes());
        preimage.extend_from_slice(b"|");
        preimage.extend_from_slice(validator.as_bytes());

        RemzarHash::compute_bytes_hash(&preimage)
    }

    pub fn ordered_validators_for_round(
        snapshot: &CommitteeSnapshot,
        round: u64,
    ) -> Result<Vec<String>, ErrorDetection> {
        Self::validate_snapshot_invariants(snapshot)?;

        let mut scored: Vec<([u8; 64], String)> = snapshot
            .validators
            .iter()
            .map(|v| {
                (
                    Self::leader_score(
                        snapshot.committee_hash,
                        snapshot.parent_hash,
                        snapshot.height,
                        round,
                        v,
                    ),
                    v.clone(),
                )
            })
            .collect();

        scored.sort_unstable_by(|(sa, wa), (sb, wb)| sa.cmp(sb).then_with(|| wa.cmp(wb)));

        Ok(scored.into_iter().map(|(_, v)| v).collect())
    }

    pub fn leader_for_round(
        snapshot: &CommitteeSnapshot,
        round: u64,
    ) -> Result<LeaderDecision, ErrorDetection> {
        Self::validate_snapshot_invariants(snapshot)?;

        let ordered = Self::ordered_validators_for_round(snapshot, round)?;

        let leader = ordered.first().cloned().ok_or_else(|| {
            Self::validation_err(format!(
                "leader_for_round failed: empty ordered committee at height {}",
                snapshot.height
            ))
        })?;

        let leader_index_in_snapshot = snapshot
            .validators
            .iter()
            .position(|v| v.eq_ignore_ascii_case(&leader))
            .ok_or_else(|| {
                Self::validation_err(format!(
                    "selected leader not found in frozen committee at height {}",
                    snapshot.height
                ))
            })?;

        Ok(LeaderDecision {
            height: snapshot.height,
            round,
            parent_hash: snapshot.parent_hash,
            committee_hash: snapshot.committee_hash,
            leader,
            leader_index_in_snapshot,
            committee_len: snapshot.validators.len(),
        })
    }

    /// Deterministic nominal height start time from genesis and block interval.
    #[must_use]
    pub fn height_start_unix(tm: &TimeManager, height: u64) -> u64 {
        let genesis = tm.cfg().genesis_time_unix.max(1);
        if height <= 1 {
            return genesis;
        }

        let delta = height
            .saturating_sub(1)
            .saturating_mul(tm.block_interval_secs().max(1));

        genesis.saturating_add(delta)
    }

    /// Derive the round from an explicit timestamp.
    pub fn round_for_height_from_timestamp(
        tm: &TimeManager,
        height: u64,
        observed_time_unix: u64,
    ) -> Result<(u64, u64, u64, u64), ErrorDetection> {
        if height == 0 {
            return Err(Self::validation_err(
                "round_for_height_from_timestamp called for height=0",
            ));
        }

        let tau = tm.failover_window_secs().max(1);
        let height_start = Self::height_start_unix(tm, height);

        if observed_time_unix < height_start {
            return Err(Self::validation_err(format!(
                "timestamp {} is earlier than nominal start {} for height {}",
                observed_time_unix, height_start, height
            )));
        }

        let elapsed = observed_time_unix.saturating_sub(height_start);
        let round = elapsed.div_euclid(tau);
        let round_start = height_start.saturating_add(round.saturating_mul(tau));
        let in_round = observed_time_unix.saturating_sub(round_start);

        Ok((round, elapsed, in_round, round_start))
    }

    /// Local mint-time round derivation.
    pub fn round_for_height_now(
        tm: &TimeManager,
        height: u64,
        now_unix: u64,
    ) -> Result<(u64, u64, u64, u64), ErrorDetection> {
        if height == 0 {
            return Err(Self::validation_err(
                "round_for_height_now called for height=0",
            ));
        }

        let height_start = Self::height_start_unix(tm, height);
        let drift = tm.slot_gate_drift_secs();

        if now_unix.saturating_add(drift) < height_start {
            return Err(Self::validation_err(format!(
                "too early to propose height {} (now={} height_start={} drift={}s)",
                height, now_unix, height_start, drift
            )));
        }

        Self::round_for_height_from_timestamp(tm, height, now_unix.max(height_start))
    }

    pub fn trace_for_timestamp(
        validator_state: &ValidatorState,
        committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        parent_hash: [u8; 64],
        height: u64,
        observed_time_unix: u64,
    ) -> Result<LeaderTrace, ErrorDetection> {
        let snapshot = Self::committee_snapshot(
            validator_state,
            committee_eligibility,
            tm,
            parent_hash,
            height,
        )?;
        let (round, elapsed_secs, in_round_secs, round_start_unix) =
            Self::round_for_height_from_timestamp(tm, height, observed_time_unix)?;

        let decision = Self::leader_for_round(&snapshot, round)?;

        Ok(LeaderTrace {
            snapshot,
            decision,
            observed_time_unix,
            height_start_unix: Self::height_start_unix(tm, height),
            round_start_unix,
            elapsed_secs,
            in_round_secs,
            failover_window_secs: tm.failover_window_secs().max(1),
        })
    }

    pub fn trace_for_now(
        validator_state: &ValidatorState,
        committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        parent_hash: [u8; 64],
        height: u64,
        now_unix: u64,
    ) -> Result<LeaderTrace, ErrorDetection> {
        let snapshot = Self::committee_snapshot(
            validator_state,
            committee_eligibility,
            tm,
            parent_hash,
            height,
        )?;
        let (round, elapsed_secs, in_round_secs, round_start_unix) =
            Self::round_for_height_now(tm, height, now_unix)?;

        let decision = Self::leader_for_round(&snapshot, round)?;

        Ok(LeaderTrace {
            snapshot,
            decision,
            observed_time_unix: now_unix,
            height_start_unix: Self::height_start_unix(tm, height),
            round_start_unix,
            elapsed_secs,
            in_round_secs,
            failover_window_secs: tm.failover_window_secs().max(1),
        })
    }

    /// Local pre-stage safety check:
    pub fn ensure_within_slot_proposal_window(
        tm: &TimeManager,
        elapsed_secs: u64,
    ) -> Result<(), ErrorDetection> {
        let deadline = tm.proposal_deadline_secs().max(1);

        if elapsed_secs >= deadline {
            return Err(Self::validation_err(format!(
                "too late in slot to prepare/propose safely (elapsed={}s deadline={}s)",
                elapsed_secs, deadline
            )));
        }

        Ok(())
    }

    /// Legacy round-local safety check retained for compatibility / diagnostics.
    pub fn ensure_enough_time_in_round_for_local_puzzle(
        tm: &TimeManager,
        in_round_secs: u64,
    ) -> Result<(), ErrorDetection> {
        let tau_secs = tm.failover_window_secs().max(1);
        let puzzle_secs = tm.puzzle_interval_secs().max(1);

        let need = puzzle_secs.saturating_add(1);
        let remaining = tau_secs.saturating_sub(in_round_secs);

        if remaining < need {
            return Err(Self::validation_err(format!(
                "too late in round to start puzzle safely (in_round={}s remaining={}s need>={}s)",
                in_round_secs, remaining, need
            )));
        }

        Ok(())
    }

    /// Local producer-policy guard.
    fn ensure_local_runtime_mint_eligibility(
        &self,
        committee_eligibility: &CommitteeEligibility,
    ) -> Result<(), ErrorDetection> {
        let decision = committee_eligibility.decide_wallet(&self.local_wallet);

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

        Err(Self::validation_err(format!(
            "local mint suppressed by runtime policy for wallet {}: {}",
            self.local_wallet, reasons
        )))
    }

    /// Local pre-stage authorization.
    pub fn assert_local_can_prestage_puzzle_now(
        &self,
        validator_state: &ValidatorState,
        committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        parent_hash: [u8; 64],
        height: u64,
        now_unix: u64,
    ) -> Result<LeaderTrace, ErrorDetection> {
        let trace = Self::trace_for_now(
            validator_state,
            committee_eligibility,
            tm,
            parent_hash,
            height,
            now_unix,
        )?;
        let fingerprint = Self::trace_fingerprint(&trace);

        let local_runtime_decision = committee_eligibility.decide_wallet(&self.local_wallet);
        let local_runtime_eligible = local_runtime_decision.eligible;
        let local_runtime_reasons = if local_runtime_decision.reasons.is_empty() {
            "[]".to_string()
        } else {
            format!("{:?}", local_runtime_decision.reasons)
        };

        tracing::debug!(
            "{} [LEADER][PRESTAGE] h={} now={} round={} in_round={}s elapsed={}s τ={}s local={} selected_leader={} committee_len={} committee_hash={} parent_hash={} trace_fp={} local_runtime_eligible={} local_runtime_reasons={}",
            Self::runtime_log_timestamp(),
            trace.decision.height,
            trace.observed_time_unix,
            trace.decision.round,
            trace.in_round_secs,
            trace.elapsed_secs,
            trace.failover_window_secs,
            self.local_wallet,
            trace.decision.leader,
            trace.decision.committee_len,
            hex::encode(trace.snapshot.committee_hash),
            hex::encode(trace.snapshot.parent_hash),
            hex::encode(fingerprint),
            local_runtime_eligible,
            local_runtime_reasons,
        );

        if !trace.snapshot.contains_wallet(&self.local_wallet) {
            return Err(Self::validation_err(format!(
                "local wallet {} is not in canonical committee at height {}",
                self.local_wallet, trace.decision.height
            )));
        }

        Self::ensure_within_slot_proposal_window(tm, trace.elapsed_secs)?;
        self.ensure_local_runtime_mint_eligibility(committee_eligibility)?;

        Ok(trace)
    }

    /// Local mint authorization.
    pub fn assert_local_can_mint_now(
        &self,
        validator_state: &ValidatorState,
        committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        parent_hash: [u8; 64],
        height: u64,
        now_unix: u64,
    ) -> Result<MintAuthorization, ErrorDetection> {
        let trace = Self::trace_for_now(
            validator_state,
            committee_eligibility,
            tm,
            parent_hash,
            height,
            now_unix,
        )?;

        let local_runtime_decision = committee_eligibility.decide_wallet(&self.local_wallet);
        let local_runtime_eligible = local_runtime_decision.eligible;
        let local_runtime_reasons = if local_runtime_decision.reasons.is_empty() {
            "[]".to_string()
        } else {
            format!("{:?}", local_runtime_decision.reasons)
        };

        let leader_match = trace
            .decision
            .leader
            .eq_ignore_ascii_case(&self.local_wallet);

        let local_in_committee = trace.snapshot.contains_wallet(&self.local_wallet);

        tracing::debug!(
            "{} [LEADER][CHECK] h={} round={} committee_len={} leader_match={} local_in_committee={} local_runtime_eligible={} local_runtime_reasons={}",
            Self::runtime_log_timestamp(),
            trace.decision.height,
            trace.decision.round,
            trace.decision.committee_len,
            leader_match,
            local_in_committee,
            local_runtime_eligible,
            local_runtime_reasons,
        );

        if !local_in_committee {
            return Err(Self::validation_err(format!(
                "local wallet is not in canonical committee at height {}",
                trace.decision.height
            )));
        }

        if !leader_match {
            return Err(Self::validation_err(format!(
                "not selected canonical leader for this height/round (h={}, round={})",
                trace.decision.height, trace.decision.round
            )));
        }

        self.ensure_local_runtime_mint_eligibility(committee_eligibility)?;

        Ok(MintAuthorization {
            local_wallet: self.local_wallet.clone(),
            trace,
        })
    }

    /// Proposer validation from explicit round.
    pub fn validate_proposer_for_round(
        validator_state: &ValidatorState,
        committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        parent_hash: [u8; 64],
        height: u64,
        round: u64,
        proposer: &str,
    ) -> Result<LeaderDecision, ErrorDetection> {
        let proposer = canon_wallet_id_checked(proposer)?;
        let snapshot = Self::committee_snapshot(
            validator_state,
            committee_eligibility,
            tm,
            parent_hash,
            height,
        )?;
        let decision = Self::leader_for_round(&snapshot, round)?;

        if !snapshot.contains_wallet(&proposer) {
            return Err(Self::validation_err(format!(
                "proposer '{}' is not in canonical committee for block height {} round {} committee_hash={}",
                proposer,
                height,
                round,
                hex::encode(snapshot.committee_hash),
            )));
        }

        if !decision.leader.eq_ignore_ascii_case(&proposer) {
            return Err(Self::validation_err(format!(
                "rogue proposer for block height {} round {}: proposer='{}' leader='{}' committee_hash={}",
                height,
                round,
                proposer,
                decision.leader,
                hex::encode(snapshot.committee_hash),
            )));
        }

        Ok(decision)
    }

    /// Proposer validation using the block's own timestamp.
    pub fn validate_proposer_from_block_timestamp(
        validator_state: &ValidatorState,
        committee_eligibility: &CommitteeEligibility,
        tm: &TimeManager,
        parent_hash: [u8; 64],
        height: u64,
        block_timestamp_unix: u64,
        proposer: &str,
    ) -> Result<LeaderTrace, ErrorDetection> {
        let proposer = canon_wallet_id_checked(proposer)?;
        let trace = Self::trace_for_timestamp(
            validator_state,
            committee_eligibility,
            tm,
            parent_hash,
            height,
            block_timestamp_unix,
        )?;

        if !trace.snapshot.contains_wallet(&proposer) {
            return Err(Self::validation_err(format!(
                "proposer '{}' is not in canonical committee for block height {} timestamp {} committee_hash={}",
                proposer,
                height,
                block_timestamp_unix,
                hex::encode(trace.snapshot.committee_hash),
            )));
        }

        if !trace.decision.leader.eq_ignore_ascii_case(&proposer) {
            return Err(Self::validation_err(format!(
                "rogue proposer for block height {} timestamp {} round {}: proposer='{}' leader='{}' committee_hash={}",
                height,
                block_timestamp_unix,
                trace.decision.round,
                proposer,
                trace.decision.leader,
                hex::encode(trace.snapshot.committee_hash),
            )));
        }

        Ok(trace)
    }

    /// Stable debug fingerprint for a leader trace.
    #[must_use]
    pub fn trace_fingerprint(trace: &LeaderTrace) -> [u8; 64] {
        let capacity = TRACE_HASH_DOMAIN
            .len()
            .saturating_add(64)
            .saturating_add(64)
            .saturating_add(8)
            .saturating_add(8)
            .saturating_add(trace.decision.leader.len());
        let mut preimage = Vec::with_capacity(capacity);

        preimage.extend_from_slice(TRACE_HASH_DOMAIN);
        preimage.extend_from_slice(&trace.snapshot.committee_hash);
        preimage.extend_from_slice(&trace.snapshot.parent_hash);
        preimage.extend_from_slice(&trace.snapshot.height.to_be_bytes());
        preimage.extend_from_slice(&trace.decision.round.to_be_bytes());
        preimage.extend_from_slice(trace.decision.leader.as_bytes());

        RemzarHash::compute_bytes_hash(&preimage)
    }
}
