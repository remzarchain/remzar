#![no_main]

use libfuzzer_sys::fuzz_target;

/* ─────────────────────────────────────────────────────────────
   Minimal utility shims
   ───────────────────────────────────────────────────────────── */

mod utility {
    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, tx_id } => {
                        write!(f, "ValidationError(message={message}, tx_id={tx_id:?})")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_BODY_LEN: usize = 128;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        #[inline]
        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            let Some(body) = b.get(1..) else {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            };

            if body.len() != REMZAR_WALLET_BODY_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            if !body.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }
    }

    pub mod hash_system_remzarhash {
        pub struct RemzarHash;

        impl RemzarHash {
            #[inline]
            pub fn compute_bytes_hash(input: &[u8]) -> [u8; 64] {
                let mut hasher = blake3::Hasher::new();
                hasher.update(input);

                let mut out = [0u8; 64];
                hasher.finalize_xof().fill(&mut out);
                out
            }
        }
    }

    pub mod time_policy {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::time::{SystemTime, UNIX_EPOCH};

        pub struct TimePolicy;

        impl TimePolicy {
            #[inline]
            pub fn now_unix_secs_runtime() -> Result<u64, ErrorDetection> {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .map_err(|_| ErrorDetection::ValidationError {
                        message: "runtime time unavailable".to_string(),
                        tx_id: None,
                    })
            }

            #[inline]
            pub fn validate_unix_secs_structural(
                field: &str,
                value: u64,
            ) -> Result<(), ErrorDetection> {
                const UNIX_2000_SECS: u64 = 946_684_800;
                const UNIX_9999_SECS: u64 = 253_402_300_799;

                if value < UNIX_2000_SECS || value > UNIX_9999_SECS {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "{field} outside supported UNIX seconds range: {value}"
                        ),
                        tx_id: None,
                    });
                }

                Ok(())
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Memory-only ValidatorState shim
   ───────────────────────────────────────────────────────────── */

mod blockchain {
    pub mod validatorstate {
        #[derive(Debug, Clone, Default)]
        pub struct ValidatorState {
            validators: Vec<String>,
        }

        impl ValidatorState {
            #[inline]
            pub fn new_for_fuzz(validators: Vec<String>) -> Self {
                Self { validators }
            }

            #[inline]
            pub fn proposable_at(
                &self,
                _height: u64,
                _activation_delay_blocks: u64,
            ) -> Vec<String> {
                self.validators.clone()
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Memory-only TimeManager + CommitteeEligibility shims
   ───────────────────────────────────────────────────────────── */

mod consensus {
    pub mod por_005_time_management {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::time_policy::TimePolicy;

        #[derive(Debug, Clone)]
        pub struct TimeConfig {
            pub genesis_time_unix: u64,
            pub block_interval_secs: u64,
            pub puzzle_interval_secs: u64,
            pub failover_window_secs: u64,
            pub proposal_deadline_secs: u64,
            pub slot_gate_drift_secs: u64,
            pub proposer_delay_blocks: u64,
        }

        #[derive(Debug, Clone)]
        pub struct TimeManager {
            cfg: TimeConfig,
        }

        impl TimeManager {
            #[inline]
            pub fn new_for_fuzz(cfg: TimeConfig) -> Self {
                Self { cfg }
            }

            #[inline]
            pub fn cfg(&self) -> &TimeConfig {
                &self.cfg
            }

            #[inline]
            pub fn proposer_delay_blocks(&self) -> u64 {
                self.cfg.proposer_delay_blocks
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
            pub fn failover_window_secs(&self) -> u64 {
                self.cfg.failover_window_secs.max(1)
            }

            #[inline]
            pub fn slot_gate_drift_secs(&self) -> u64 {
                self.cfg.slot_gate_drift_secs
            }

            #[inline]
            pub fn proposal_deadline_secs(&self) -> u64 {
                self.cfg.proposal_deadline_secs.max(1)
            }

            #[inline]
            pub fn failover_max_rounds(&self) -> u64 {
                self.proposal_deadline_secs()
                    .div_euclid(self.failover_window_secs())
                    .max(1)
            }

            #[inline]
            pub fn current_slot(&self, now_unix: u64) -> u64 {
                now_unix
                    .saturating_sub(self.cfg.genesis_time_unix.max(1))
                    .div_euclid(self.block_interval_secs())
            }

            #[inline]
            pub fn current_slot_checked(&self, now_unix: u64) -> Result<u64, ErrorDetection> {
                TimePolicy::validate_unix_secs_structural("fuzz_now_unix", now_unix)?;

                let genesis = self.cfg.genesis_time_unix.max(1);
                if now_unix < genesis {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "timestamp before genesis in fuzz TimeManager: now={now_unix} genesis={genesis}"
                        ),
                        tx_id: None,
                    });
                }

                Ok(self.current_slot(now_unix))
            }

            #[inline]
            pub fn slot_start_unix(&self, slot: u64) -> u64 {
                self.cfg.genesis_time_unix.max(1).saturating_add(
                    slot.saturating_mul(self.block_interval_secs()),
                )
            }

            #[inline]
            pub fn slot_start_unix_checked(&self, slot: u64) -> Result<u64, ErrorDetection> {
                let start = self.slot_start_unix(slot);
                TimePolicy::validate_unix_secs_structural("fuzz_slot_start_unix", start)?;
                Ok(start)
            }

            #[inline]
            pub fn secs_into_slot_checked(
                &self,
                slot: u64,
                now_unix: u64,
            ) -> Result<u64, ErrorDetection> {
                TimePolicy::validate_unix_secs_structural("fuzz_secs_into_slot_now", now_unix)?;

                let slot_start = self.slot_start_unix_checked(slot)?;

                if now_unix < slot_start {
                    return Ok(0);
                }

                Ok(now_unix.saturating_sub(slot_start))
            }

            #[inline]
            pub fn round_in_slot(&self, slot: u64, now_unix: u64) -> u64 {
                let slot_start = self.slot_start_unix(slot);
                let elapsed = now_unix.saturating_sub(slot_start);
                let raw_round = elapsed.div_euclid(self.failover_window_secs());
                raw_round.min(self.failover_max_rounds().saturating_sub(1))
            }

            #[inline]
            pub fn height_start_unix(&self, height: u64) -> u64 {
                let genesis = self.cfg.genesis_time_unix.max(1);

                if height <= 1 {
                    return genesis;
                }

                genesis.saturating_add(
                    height
                        .saturating_sub(1)
                        .saturating_mul(self.block_interval_secs()),
                )
            }

            #[inline]
            pub fn height_start_unix_checked(&self, height: u64) -> Result<u64, ErrorDetection> {
                let start = self.height_start_unix(height);
                TimePolicy::validate_unix_secs_structural("fuzz_height_start_unix", start)?;
                Ok(start)
            }
        }
    }
    pub mod por_006_committee_eligibility {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum IneligibilityReason {
            NotLive,
            NotSynced,
            TooFarBehind,
            NotEnoughPeers,
            NotEnoughWalletPeers,
            Isolated,
            FuzzDenied,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct CommitteeEligibilityDecision {
            pub wallet: String,
            pub eligible: bool,
            pub reasons: Vec<IneligibilityReason>,
        }

        #[derive(Debug, Clone)]
        pub struct CommitteeEligibility {
            runtime_eligible: bool,
        }

        impl CommitteeEligibility {
            #[inline]
            pub fn new_for_fuzz(runtime_eligible: bool) -> Self {
                Self { runtime_eligible }
            }

            #[inline]
            pub fn decide_wallet(&self, wallet: &str) -> CommitteeEligibilityDecision {
                if self.runtime_eligible {
                    CommitteeEligibilityDecision {
                        wallet: wallet.to_string(),
                        eligible: true,
                        reasons: Vec::new(),
                    }
                } else {
                    CommitteeEligibilityDecision {
                        wallet: wallet.to_string(),
                        eligible: false,
                        reasons: vec![IneligibilityReason::FuzzDenied],
                    }
                }
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Pull in the real production file.
   Do NOT use include!().
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/consensus/por_007_leader_schedule.rs"]
pub mod por_007_leader_schedule;

/* ─────────────────────────────────────────────────────────────
   Imports
   ───────────────────────────────────────────────────────────── */

use crate::blockchain::validatorstate::ValidatorState;
use crate::consensus::por_005_time_management::{TimeConfig, TimeManager};
use crate::consensus::por_006_committee_eligibility::CommitteeEligibility;
use crate::por_007_leader_schedule::{CommitteeSnapshot, LeaderSchedule};
use crate::utility::helper::canon_wallet_id_checked;

/* ─────────────────────────────────────────────────────────────
   Main fuzz entry
   ───────────────────────────────────────────────────────────── */

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] % 10;
    let body = &data[1..];

    match mode {
        0 => fuzz_new_and_wallet_canonicalization(body),
        1 => fuzz_canonical_committee_snapshot(body),
        2 => fuzz_committee_hash_and_score_determinism(body),
        3 => fuzz_ordered_validators_and_leader(body),
        4 => fuzz_round_math(body),
        5 => fuzz_trace_and_fingerprint(body),
        6 => fuzz_validate_proposer_for_round(body),
        7 => fuzz_validate_proposer_from_timestamp(body),
        8 => fuzz_local_authorization_paths(body),
        _ => fuzz_state_machine_mixed(body),
    }
});

/* ─────────────────────────────────────────────────────────────
   Fuzz cases
   ───────────────────────────────────────────────────────────── */

fn fuzz_new_and_wallet_canonicalization(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let wallet = make_wallet_or_invalid(&mut r);
    let result = LeaderSchedule::new(wallet.clone());

    match canon_wallet_id_checked(&wallet) {
        Ok(can) => {
            let schedule = result.expect("valid wallet should construct LeaderSchedule");
            assert_eq!(schedule.local_wallet(), can);
        }
        Err(_) => {
            assert!(result.is_err());
        }
    }
}

fn fuzz_canonical_committee_snapshot(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let raw_validators = make_validator_list(&mut r, 16);
    let validator_state = ValidatorState::new_for_fuzz(raw_validators.clone());
    let committee = CommitteeEligibility::new_for_fuzz(r.next_bool());
    let tm = make_time_manager(&mut r);
    let parent_hash = make_hash64(&mut r);
    let height = make_height(&mut r);

    let canon_result =
        LeaderSchedule::canonical_validators_for_height(&validator_state, &tm, height);

    let expected_canon = canonicalize_list_or_err(&raw_validators);

    if height == 0 || expected_canon.is_none() {
        assert!(canon_result.is_err());
        return;
    }

    let validators = canon_result.expect("valid canonical validators should pass");
    let expected = expected_canon.unwrap();

    assert_eq!(validators, expected);
    assert!(validators.windows(2).all(|w| w[0] <= w[1]));

    let active =
        LeaderSchedule::active_validators_for_height(&validator_state, &committee, &tm, height)
            .expect("active alias should match canonical validators");

    assert_eq!(active, validators);

    let snapshot =
        LeaderSchedule::committee_snapshot(&validator_state, &committee, &tm, parent_hash, height)
            .expect("valid snapshot should construct");

    assert_eq!(snapshot.height, height);
    assert_eq!(snapshot.parent_hash, parent_hash);
    assert_eq!(snapshot.activation_delay_blocks, tm.proposer_delay_blocks());
    assert_eq!(snapshot.validators, validators);
    assert_eq!(snapshot.len(), snapshot.validators.len());
    assert_eq!(snapshot.is_empty(), snapshot.validators.is_empty());

    let expected_hash = LeaderSchedule::compute_committee_hash(
        parent_hash,
        height,
        tm.proposer_delay_blocks(),
        &snapshot.validators,
    );

    assert_eq!(snapshot.committee_hash, expected_hash);

    for v in &snapshot.validators {
        assert!(snapshot.contains_wallet(v));
        assert!(snapshot.contains_wallet(&v.to_ascii_uppercase()));
    }
}

fn fuzz_committee_hash_and_score_determinism(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let parent_hash = make_hash64(&mut r);
    let height = make_nonzero_height(&mut r);
    let activation_delay = r.next_u64() % 64;

    let validators = make_canonical_validator_vec(&mut r, 1, 16);

    let h1 = LeaderSchedule::compute_committee_hash(
        parent_hash,
        height,
        activation_delay,
        &validators,
    );

    let h2 = LeaderSchedule::compute_committee_hash(
        parent_hash,
        height,
        activation_delay,
        &validators,
    );

    assert_eq!(h1, h2);

    let mut changed_parent = parent_hash;
    changed_parent[0] ^= 0x01;

    let changed_hash = LeaderSchedule::compute_committee_hash(
        changed_parent,
        height,
        activation_delay,
        &validators,
    );

    if changed_parent != parent_hash {
        assert_ne!(h1, changed_hash);
    }

    let round = r.next_u64();

    for v in &validators {
        let s1 = LeaderSchedule::leader_score(h1, parent_hash, height, round, v);
        let s2 = LeaderSchedule::leader_score(h1, parent_hash, height, round, v);

        assert_eq!(s1, s2);
    }
}

fn fuzz_ordered_validators_and_leader(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let parent_hash = make_hash64(&mut r);
    let height = make_nonzero_height(&mut r);
    let activation_delay = r.next_u64() % 64;
    let validators = make_canonical_validator_vec(&mut r, 1, 24);

    let committee_hash = LeaderSchedule::compute_committee_hash(
        parent_hash,
        height,
        activation_delay,
        &validators,
    );

    let snapshot = CommitteeSnapshot {
        height,
        parent_hash,
        activation_delay_blocks: activation_delay,
        validators: validators.clone(),
        committee_hash,
    };

    let round = r.next_u64();

    let ordered1 = LeaderSchedule::ordered_validators_for_round(&snapshot, round)
        .expect("valid snapshot should order validators");

    let ordered2 = LeaderSchedule::ordered_validators_for_round(&snapshot, round)
        .expect("valid snapshot should order validators deterministically");

    assert_eq!(ordered1, ordered2);
    assert_eq!(ordered1.len(), validators.len());

    let mut sorted_ordered = ordered1.clone();
    sorted_ordered.sort();

    let mut sorted_validators = validators.clone();
    sorted_validators.sort();

    assert_eq!(sorted_ordered, sorted_validators);

    let decision =
        LeaderSchedule::leader_for_round(&snapshot, round).expect("valid leader should exist");

    assert_eq!(decision.height, height);
    assert_eq!(decision.round, round);
    assert_eq!(decision.parent_hash, parent_hash);
    assert_eq!(decision.committee_hash, committee_hash);
    assert_eq!(decision.committee_len, validators.len());
    assert_eq!(decision.leader, ordered1[0]);
    assert!(decision.leader_index_in_snapshot < validators.len());
    assert_eq!(validators[decision.leader_index_in_snapshot], decision.leader);
}

fn fuzz_round_math(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let tm = make_time_manager(&mut r);
    let height = make_height(&mut r);

    if height == 0 {
        assert!(
            LeaderSchedule::round_for_height_from_timestamp(&tm, height, r.next_u64()).is_err()
        );
        assert!(LeaderSchedule::round_for_height_now(&tm, height, r.next_u64()).is_err());
        return;
    }

    let height_start = LeaderSchedule::height_start_unix(&tm, height);
    assert_eq!(height_start, tm.height_start_unix(height));

    /*
        Current production behavior:
        round derivation is height-local. It derives elapsed time from
        LeaderSchedule::height_start_unix(tm, height), not from a separate
        observed_slot/slot_start trace field.
    */
    let tau = tm.failover_window_secs().max(1);
    let observed = height_start.saturating_add(r.next_u64() % tau.saturating_mul(8).max(1));

    let (round, elapsed, in_round, round_start) =
        LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed)
            .expect("timestamp at or after height start should derive round");

    let expected_elapsed = observed.saturating_sub(height_start);
    let expected_round = expected_elapsed.div_euclid(tau);
    let expected_round_start = height_start.saturating_add(expected_round.saturating_mul(tau));
    let expected_in_round = observed.saturating_sub(expected_round_start);

    assert_eq!(round, expected_round);
    assert_eq!(elapsed, expected_elapsed);
    assert_eq!(round_start, expected_round_start);
    assert_eq!(in_round, expected_in_round);

    let now_result = LeaderSchedule::round_for_height_now(&tm, height, observed);
    let ts_result = LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed);

    match (now_result, ts_result) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(_), Err(_)) => {}
        (a, b) => panic!("round_for_height_now and timestamp helper diverged: {a:?} vs {b:?}"),
    }

    if height_start > 0 {
        assert!(
            LeaderSchedule::round_for_height_from_timestamp(
                &tm,
                height,
                height_start.saturating_sub(1),
            )
            .is_err(),
            "timestamp before height start must be rejected"
        );
    }

    let elapsed = r.next_u64() % 120;
    let slot_check = LeaderSchedule::ensure_within_slot_proposal_window(&tm, elapsed);

    if elapsed >= tm.proposal_deadline_secs().max(1) {
        assert!(slot_check.is_err());
    } else {
        assert!(slot_check.is_ok());
    }

    let in_round = r.next_u64() % 120;
    let round_check = LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, in_round);

    let tau_secs = tm.failover_window_secs().max(1);
    let puzzle_secs = tm.puzzle_interval_secs().max(1);
    let need = puzzle_secs.saturating_add(1);
    let remaining = tau_secs.saturating_sub(in_round);

    if remaining < need {
        assert!(round_check.is_err());
    } else {
        assert!(round_check.is_ok());
    }
}


fn fuzz_trace_and_fingerprint(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let validators = make_canonical_validator_vec(&mut r, 1, 16);
    let validator_state = ValidatorState::new_for_fuzz(validators);
    let committee = CommitteeEligibility::new_for_fuzz(r.next_bool());
    let tm = make_time_manager(&mut r);
    let parent_hash = make_hash64(&mut r);
    let height = make_nonzero_height(&mut r);

    let height_start = LeaderSchedule::height_start_unix(&tm, height);
    let observed = height_start.saturating_add(
        r.next_u64()
            % tm
                .failover_window_secs()
                .max(1)
                .saturating_mul(tm.failover_max_rounds().max(1).saturating_add(2))
                .max(1),
    );

    let trace = match LeaderSchedule::trace_for_timestamp(
        &validator_state,
        &committee,
        &tm,
        parent_hash,
        height,
        observed,
    ) {
        Ok(trace) => trace,
        Err(_) => return,
    };

    assert_eq!(trace.snapshot.height, height);
    assert_eq!(trace.snapshot.parent_hash, parent_hash);
    assert_eq!(trace.decision.height, height);
    assert_eq!(trace.decision.parent_hash, parent_hash);
    assert_eq!(trace.observed_time_unix, observed);
    assert_eq!(trace.height_start_unix, height_start);
    assert_eq!(trace.failover_window_secs, tm.failover_window_secs().max(1));

    let expected_elapsed = observed.saturating_sub(height_start);
    let expected_round = expected_elapsed.div_euclid(tm.failover_window_secs().max(1));
    let expected_round_start = height_start.saturating_add(
        expected_round.saturating_mul(tm.failover_window_secs().max(1)),
    );
    let expected_in_round = observed.saturating_sub(expected_round_start);

    assert_eq!(trace.elapsed_secs, expected_elapsed);
    assert_eq!(trace.decision.round, expected_round);
    assert_eq!(trace.round_start_unix, expected_round_start);
    assert_eq!(trace.in_round_secs, expected_in_round);

    let fp1 = LeaderSchedule::trace_fingerprint(&trace);
    let fp2 = LeaderSchedule::trace_fingerprint(&trace);
    assert_eq!(fp1, fp2);

    let trace_now = LeaderSchedule::trace_for_now(
        &validator_state,
        &committee,
        &tm,
        parent_hash,
        height,
        observed,
    )
    .expect("same valid timestamp should build now trace");

    assert_eq!(trace_now.decision.leader, trace.decision.leader);
    assert_eq!(trace_now.decision.round, trace.decision.round);
    assert_eq!(
        LeaderSchedule::trace_fingerprint(&trace_now),
        LeaderSchedule::trace_fingerprint(&trace)
    );
}


fn fuzz_validate_proposer_for_round(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let validators = make_canonical_validator_vec(&mut r, 1, 16);
    let validator_state = ValidatorState::new_for_fuzz(validators.clone());
    let committee = CommitteeEligibility::new_for_fuzz(r.next_bool());
    let tm = make_time_manager(&mut r);
    let parent_hash = make_hash64(&mut r);
    let height = make_nonzero_height(&mut r);

    /*
        Current production behavior:
        explicit proposer validation accepts the explicit round supplied by the
        caller. It does not cap the round by failover_max_rounds; timestamp-based
        validation derives the round from block timestamp separately.
    */
    let round = r.next_u64();

    let snapshot = LeaderSchedule::committee_snapshot(
        &validator_state,
        &committee,
        &tm,
        parent_hash,
        height,
    )
    .expect("snapshot should build");

    let decision =
        LeaderSchedule::leader_for_round(&snapshot, round).expect("leader should be selected");

    let ok = LeaderSchedule::validate_proposer_for_round(
        &validator_state,
        &committee,
        &tm,
        parent_hash,
        height,
        round,
        &decision.leader,
    )
    .expect("selected leader should validate for the explicit round");

    assert_eq!(ok.leader, decision.leader);
    assert_eq!(ok.round, round);

    let non_leader = validators
        .iter()
        .find(|v| !v.eq_ignore_ascii_case(&decision.leader))
        .cloned();

    if let Some(other) = non_leader {
        assert!(
            LeaderSchedule::validate_proposer_for_round(
                &validator_state,
                &committee,
                &tm,
                parent_hash,
                height,
                round,
                &other,
            )
            .is_err()
        );
    }

    let invalid = make_invalid_wallet(&mut r);
    assert!(
        LeaderSchedule::validate_proposer_for_round(
            &validator_state,
            &committee,
            &tm,
            parent_hash,
            height,
            round,
            &invalid,
        )
        .is_err()
    );
}

fn fuzz_validate_proposer_from_timestamp(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let validators = make_canonical_validator_vec(&mut r, 1, 16);
    let validator_state = ValidatorState::new_for_fuzz(validators.clone());
    let committee = CommitteeEligibility::new_for_fuzz(r.next_bool());
    let tm = make_time_manager(&mut r);
    let parent_hash = make_hash64(&mut r);
    let height = make_nonzero_height(&mut r);

    let height_start = LeaderSchedule::height_start_unix(&tm, height);
    let block_ts = height_start.saturating_add(
        r.next_u64()
            % tm
                .failover_window_secs()
                .max(1)
                .saturating_mul(tm.failover_max_rounds().max(1).saturating_add(2))
                .max(1),
    );

    let trace = match LeaderSchedule::trace_for_timestamp(
        &validator_state,
        &committee,
        &tm,
        parent_hash,
        height,
        block_ts,
    ) {
        Ok(trace) => trace,
        Err(_) => return,
    };

    let ok = LeaderSchedule::validate_proposer_from_block_timestamp(
        &validator_state,
        &committee,
        &tm,
        parent_hash,
        height,
        block_ts,
        &trace.decision.leader,
    )
    .expect("selected timestamp leader should validate");

    assert_eq!(ok.decision.leader, trace.decision.leader);
    assert_eq!(ok.decision.round, trace.decision.round);
    assert_eq!(ok.observed_time_unix, trace.observed_time_unix);
    assert_eq!(ok.height_start_unix, trace.height_start_unix);
    assert_eq!(ok.round_start_unix, trace.round_start_unix);
    assert_eq!(ok.elapsed_secs, trace.elapsed_secs);
    assert_eq!(ok.in_round_secs, trace.in_round_secs);
    assert_eq!(ok.failover_window_secs, trace.failover_window_secs);

    let non_leader = validators
        .iter()
        .find(|v| !v.eq_ignore_ascii_case(&trace.decision.leader))
        .cloned();

    if let Some(other) = non_leader {
        assert!(
            LeaderSchedule::validate_proposer_from_block_timestamp(
                &validator_state,
                &committee,
                &tm,
                parent_hash,
                height,
                block_ts,
                &other,
            )
            .is_err()
        );
    }

    if height_start > 0 {
        assert!(
            LeaderSchedule::validate_proposer_from_block_timestamp(
                &validator_state,
                &committee,
                &tm,
                parent_hash,
                height,
                height_start.saturating_sub(1),
                &trace.decision.leader,
            )
            .is_err(),
            "timestamp before height start must be rejected"
        );
    }
}


fn fuzz_local_authorization_paths(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let validators = make_canonical_validator_vec(&mut r, 1, 16);
    let validator_state = ValidatorState::new_for_fuzz(validators.clone());
    let tm = make_time_manager(&mut r);
    let parent_hash = make_hash64(&mut r);
    let height = make_nonzero_height(&mut r);

    let height_start = LeaderSchedule::height_start_unix(&tm, height);
    let proposal_window = tm
        .proposal_deadline_secs()
        .min(tm.block_interval_secs())
        .max(1);
    let now = height_start.saturating_add(r.next_u64() % proposal_window);

    let committee_ok = CommitteeEligibility::new_for_fuzz(true);

    let trace = match LeaderSchedule::trace_for_now(
        &validator_state,
        &committee_ok,
        &tm,
        parent_hash,
        height,
        now,
    ) {
        Ok(trace) => trace,
        Err(_) => return,
    };

    let local_wallet = match r.next_u8() % 3 {
        0 => trace.decision.leader.clone(),
        1 => validators[0].clone(),
        _ => make_valid_wallet(&mut r),
    };

    let schedule = match LeaderSchedule::new(local_wallet.clone()) {
        Ok(s) => s,
        Err(_) => return,
    };

    let prestage = schedule.assert_local_can_prestage_puzzle_now(
        &validator_state,
        &committee_ok,
        &tm,
        parent_hash,
        height,
        now,
    );

    if let Ok(prestage_trace) = &prestage {
        assert!(prestage_trace.snapshot.contains_wallet(&local_wallet));
    } else if !trace.snapshot.contains_wallet(&local_wallet) {
        assert!(prestage.is_err());
    }

    let mint = schedule.assert_local_can_mint_now(
        &validator_state,
        &committee_ok,
        &tm,
        parent_hash,
        height,
        now,
    );

    if let Ok(auth) = mint {
        assert_eq!(auth.local_wallet, schedule.local_wallet());
        assert_eq!(auth.trace.decision.leader, schedule.local_wallet());
    }

    let committee_bad = CommitteeEligibility::new_for_fuzz(false);

    let denied = schedule.assert_local_can_mint_now(
        &validator_state,
        &committee_bad,
        &tm,
        parent_hash,
        height,
        now,
    );

    if trace.decision.leader.eq_ignore_ascii_case(&local_wallet) {
        assert!(denied.is_err());
    }
}


fn fuzz_state_machine_mixed(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let steps = 1 + r.next_usize(16);

    for _ in 0..steps {
        match r.next_u8() % 9 {
            0 => fuzz_new_and_wallet_canonicalization(r.remaining_window(256)),
            1 => fuzz_canonical_committee_snapshot(r.remaining_window(512)),
            2 => fuzz_committee_hash_and_score_determinism(r.remaining_window(512)),
            3 => fuzz_ordered_validators_and_leader(r.remaining_window(512)),
            4 => fuzz_round_math(r.remaining_window(256)),
            5 => fuzz_trace_and_fingerprint(r.remaining_window(512)),
            6 => fuzz_validate_proposer_for_round(r.remaining_window(512)),
            7 => fuzz_validate_proposer_from_timestamp(r.remaining_window(512)),
            _ => fuzz_local_authorization_paths(r.remaining_window(512)),
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Helpers
   ───────────────────────────────────────────────────────────── */

fn make_time_manager(r: &mut FuzzBytes<'_>) -> TimeManager {
    let block_interval_secs = match r.next_u8() % 6 {
        0 => 1,
        1 => 7,
        2 => 30,
        3 => 60,
        4 => 120,
        _ => 1 + (r.next_u64() % 300),
    };

    let puzzle_interval_secs = match r.next_u8() % 5 {
        0 => 1,
        1 => block_interval_secs,
        2 => block_interval_secs.saturating_sub(1).max(1),
        3 => 7,
        _ => 1 + (r.next_u64() % block_interval_secs.max(1)),
    };

    /*
        Keep failover_window broad but bounded.
        Local mint checks may reject when window is too small; the fuzz test
        now treats that as valid behavior instead of assuming mint must pass.
    */
    let failover_window_secs = match r.next_u8() % 6 {
        0 => 1,
        1 => puzzle_interval_secs.saturating_add(1),
        2 => 7,
        3 => block_interval_secs,
        4 => block_interval_secs.saturating_add(1),
        _ => 1 + (r.next_u64() % 120),
    };

    let proposal_deadline_secs = match r.next_u8() % 6 {
        0 => 1,
        1 => block_interval_secs.saturating_sub(1).max(1),
        2 => block_interval_secs,
        3 => failover_window_secs,
        4 => 24,
        _ => 1 + (r.next_u64() % block_interval_secs.saturating_add(30).max(1)),
    };

    let genesis_time_unix = match r.next_u8() % 4 {
        0 => 1,
        1 => 946_684_800,
        2 => 1_700_000_000,
        _ => 1 + (r.next_u64() % 4_000_000_000),
    };

    let cfg = TimeConfig {
        genesis_time_unix,
        block_interval_secs,
        puzzle_interval_secs,
        failover_window_secs,
        proposal_deadline_secs,
        slot_gate_drift_secs: r.next_u64() % 10,
        proposer_delay_blocks: r.next_u64() % 16,
    };

    TimeManager::new_for_fuzz(cfg)
}

fn canonicalize_list_or_err(raw: &[String]) -> Option<Vec<String>> {
    if raw.is_empty() {
        return None;
    }

    let mut set = std::collections::BTreeSet::<String>::new();

    for w in raw {
        let can = canon_wallet_id_checked(w).ok()?;
        set.insert(can);
    }

    if set.is_empty() {
        None
    } else {
        Some(set.into_iter().collect())
    }
}

fn make_validator_list(r: &mut FuzzBytes<'_>, max_len: usize) -> Vec<String> {
    let count = r.next_usize(max_len.saturating_add(1));
    let mut out = Vec::with_capacity(count.saturating_add(1));

    for i in 0..count {
        match r.next_u8() % 6 {
            0 => out.push(make_valid_wallet_with_counter(r, i as u64)),
            1 => out.push(make_uppercase_wallet(r)),
            2 => out.push(format!(" {} ", make_valid_wallet_with_counter(r, i as u64))),
            3 => out.push(make_invalid_wallet(r)),
            4 => {
                let w = make_valid_wallet_with_counter(r, i as u64);
                out.push(w.clone());
                out.push(w);
            }
            _ => out.push(make_valid_wallet_with_counter(r, i as u64)),
        }
    }

    out
}

fn make_canonical_validator_vec(
    r: &mut FuzzBytes<'_>,
    min_len: usize,
    max_len: usize,
) -> Vec<String> {
    let safe_min = min_len.max(1);
    let safe_max = max_len.max(safe_min).min(64);

    let span = safe_max.saturating_sub(safe_min).saturating_add(1);
    let target = safe_min.saturating_add(r.next_usize(span));

    let mut out = Vec::with_capacity(target);

    /*
        Guaranteed bounded and guaranteed unique:
        no while-loop waiting for random uniqueness.
    */
    for i in 0..target {
        out.push(make_valid_wallet_with_counter(r, i as u64));
    }

    out.sort();
    out.dedup();

    if out.is_empty() {
        out.push(make_valid_wallet_with_counter(r, 0));
    }

    out
}

fn make_height(r: &mut FuzzBytes<'_>) -> u64 {
    match r.next_u8() % 8 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 10,
        4 => 1_000_000,
        5 => u64::MAX,
        _ => r.next_u64() % 1_000_000,
    }
}

fn make_nonzero_height(r: &mut FuzzBytes<'_>) -> u64 {
    make_height(r).max(1)
}

fn make_hash64(r: &mut FuzzBytes<'_>) -> [u8; 64] {
    let mut out = [0u8; 64];

    for b in &mut out {
        *b = r.next_u8();
    }

    out
}

fn push_hex_nibble(s: &mut String, n: u8) {
    let c = match n & 0x0F {
        0..=9 => char::from(b'0' + (n & 0x0F)),
        x => char::from(b'a' + (x - 10)),
    };

    s.push(c);
}

fn make_valid_wallet(r: &mut FuzzBytes<'_>) -> String {
    let mut s = String::with_capacity(129);
    s.push('r');

    for _ in 0..128 {
        push_hex_nibble(&mut s, r.next_u8());
    }

    s
}

fn make_valid_wallet_with_counter(r: &mut FuzzBytes<'_>, counter: u64) -> String {
    let mut s = String::with_capacity(129);
    s.push('r');

    /*
        First 16 hex chars encode the counter.
        That makes wallets unique for different counter values.
    */
    for b in counter.to_be_bytes() {
        push_hex_nibble(&mut s, b >> 4);
        push_hex_nibble(&mut s, b);
    }

    /*
        Remaining 112 hex chars still come from fuzz input.
    */
    for i in 16..128 {
        let mixed = r
            .next_u8()
            .wrapping_add((i as u8).wrapping_mul(17))
            .wrapping_add((counter as u8).wrapping_mul(31));

        push_hex_nibble(&mut s, mixed);
    }

    s
}

fn make_uppercase_wallet(r: &mut FuzzBytes<'_>) -> String {
    let s = make_valid_wallet(r);

    match r.next_u8() % 3 {
        0 => s.to_ascii_uppercase(),
        1 => {
            let mut out = s;
            out.replace_range(0..1, "R");
            out
        }
        _ => {
            let mut out = s;
            if out.len() == 129 {
                out.replace_range(1..2, "A");
            }
            out
        }
    }
}

fn make_invalid_wallet(r: &mut FuzzBytes<'_>) -> String {
    match r.next_u8() % 8 {
        0 => String::new(),
        1 => "not-a-wallet".to_string(),
        2 => "r".repeat(300),
        3 => {
            let mut s = make_valid_wallet(r);
            s.push('x');
            s
        }
        4 => {
            let mut s = make_valid_wallet(r);
            s.replace_range(1..2, "z");
            s
        }
        5 => {
            let mut s = make_valid_wallet(r);
            s.replace_range(0..1, "x");
            s
        }
        6 => make_fuzzy_string(r, 256),
        _ => "🚀".repeat(r.next_usize(64)),
    }
}

fn make_wallet_or_invalid(r: &mut FuzzBytes<'_>) -> String {
    match r.next_u8() % 5 {
        0 => make_valid_wallet(r),
        1 => make_uppercase_wallet(r),
        2 => format!(" {} ", make_valid_wallet(r)),
        _ => make_invalid_wallet(r),
    }
}

fn make_fuzzy_string(r: &mut FuzzBytes<'_>, max_chars: usize) -> String {
    let len = r.next_usize(max_chars.saturating_add(1));

    let mut s = String::new();

    for _ in 0..len {
        let b = r.next_u8();

        match b % 10 {
            0 => s.push(char::from(b'a' + (b % 26))),
            1 => s.push(char::from(b'A' + (b % 26))),
            2 => s.push(char::from(b'0' + (b % 10))),
            3 => s.push('r'),
            4 => s.push('R'),
            5 => s.push('_'),
            6 => s.push('-'),
            7 => s.push('é'),
            8 => s.push('雪'),
            _ => s.push('🚀'),
        }
    }

    s
}

/* ─────────────────────────────────────────────────────────────
   Deterministic byte reader
   ───────────────────────────────────────────────────────────── */

struct FuzzBytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FuzzBytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }

        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];

        for b in &mut out {
            *b = self.next_u8();
        }

        u64::from_le_bytes(out)
    }

    fn next_usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }

        (self.next_u64() as usize) % max_exclusive
    }

    fn remaining_window(&mut self, max_len: usize) -> &'a [u8] {
        if self.data.is_empty() || max_len == 0 {
            return &[];
        }

        let start = self.pos % self.data.len();
        let available = self.data.len().saturating_sub(start);
        let len = available.min(max_len);

        self.pos = self.pos.wrapping_add(len.max(1));

        &self.data[start..start + len]
    }
}