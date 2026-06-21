use remzar::consensus::por_006_committee_eligibility::{
    CommitteeEligibility, CommitteeEligibilityConfig, CommitteeEligibilityDecision,
    CommitteeMemberStatus, CommitteeStatusUpdate, IneligibilityReason,
};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::error::Error;
use std::io;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn strict_config() -> CommitteeEligibilityConfig {
    CommitteeEligibilityConfig {
        max_tip_lag_blocks: 2,
        min_peers_connected: 2,
        min_connected_wallet_peers: 1,
        require_non_isolated: true,
        require_synced: true,
    }
}

fn loose_config() -> CommitteeEligibilityConfig {
    CommitteeEligibilityConfig::default()
}

fn member_status(
    wallet_addr: &str,
    is_live: bool,
    has_synced: bool,
    local_tip: u64,
    network_tip: u64,
    peers_connected: usize,
    connected_wallet_peers: usize,
    is_isolated: bool,
) -> CommitteeMemberStatus {
    CommitteeMemberStatus {
        wallet: wallet_addr.to_string(),
        is_live,
        has_synced,
        local_tip,
        network_tip,
        peers_connected,
        connected_wallet_peers,
        is_isolated,
    }
}

fn status_update(
    is_live: bool,
    has_synced: bool,
    local_tip: u64,
    network_tip: u64,
    peers_connected: usize,
    connected_wallet_peers: usize,
) -> CommitteeStatusUpdate {
    CommitteeStatusUpdate {
        is_live,
        has_synced,
        local_tip,
        network_tip,
        peers_connected,
        connected_wallet_peers,
    }
}

fn validation_message<T>(result: Result<T, ErrorDetection>) -> TestResult<String> {
    match result {
        Ok(_) => Err(test_error("expected validation error but got Ok")),
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert_eq!(tx_id, None);
            Ok(message)
        }
        Err(other) => Err(Box::new(io::Error::other(format!(
            "unexpected error variant: {other:?}"
        )))),
    }
}

fn assert_reason(decision: &CommitteeEligibilityDecision, reason: IneligibilityReason) {
    assert!(decision.reasons.contains(&reason));
}

#[test]
fn test_01_default_config_has_rollout_friendly_values() {
    let cfg = CommitteeEligibilityConfig::default();

    assert_eq!(cfg.max_tip_lag_blocks, 2);
    assert_eq!(cfg.min_peers_connected, 0);
    assert_eq!(cfg.min_connected_wallet_peers, 0);
    assert!(!cfg.require_non_isolated);
    assert!(!cfg.require_synced);
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_02_from_globals_matches_default_config() {
    let cfg = CommitteeEligibilityConfig::from_globals();
    let default_cfg = CommitteeEligibilityConfig::default();

    assert_eq!(cfg, default_cfg);
}

#[test]
fn test_03_config_validate_rejects_wallet_peer_min_above_peer_min() -> TestResult {
    let cfg = CommitteeEligibilityConfig {
        max_tip_lag_blocks: 2,
        min_peers_connected: 1,
        min_connected_wallet_peers: 2,
        require_non_isolated: false,
        require_synced: false,
    };

    let message = validation_message(cfg.validate())?;

    assert!(message.contains("min_connected_wallet_peers=2 > min_peers_connected=1"));
    Ok(())
}

#[test]
fn test_04_member_status_tip_lag_is_network_minus_local_when_behind() {
    let status = member_status(&wallet(4), true, true, 10, 15, 1, 1, false);

    assert_eq!(status.tip_lag(), 5);
}

#[test]
fn test_05_member_status_tip_lag_saturates_to_zero_when_local_ahead() {
    let status = member_status(&wallet(5), true, true, 20, 10, 1, 1, false);

    assert_eq!(status.tip_lag(), 0);
}

#[test]
fn test_06_member_status_validate_invariants_accepts_valid_status() {
    let status = member_status(&wallet(6), true, true, 10, 10, 2, 1, false);

    assert!(status.validate_invariants().is_ok());
}

#[test]
fn test_07_member_status_validate_rejects_invalid_wallet() -> TestResult {
    let status = member_status("bad-wallet", true, true, 0, 0, 1, 1, false);

    let message = validation_message(status.validate_invariants())?;

    assert!(!message.is_empty());
    Ok(())
}

#[test]
fn test_08_member_status_validate_rejects_wallet_peers_above_total_peers() -> TestResult {
    let status = member_status(&wallet(8), true, true, 0, 0, 1, 2, false);

    let message = validation_message(status.validate_invariants())?;

    assert!(message.contains("connected_wallet_peers=2 > peers_connected=1"));
    Ok(())
}

#[test]
fn test_09_member_status_validate_rejects_isolated_with_wallet_peers() -> TestResult {
    let status = member_status(&wallet(9), true, true, 0, 0, 2, 1, true);

    let message = validation_message(status.validate_invariants())?;

    assert!(message.contains("is_isolated=true"));
    Ok(())
}

#[test]
fn test_10_status_update_is_isolated_when_connected_wallet_peers_is_zero() {
    let isolated = status_update(true, true, 1, 1, 5, 0);
    let not_isolated = status_update(true, true, 1, 1, 5, 1);

    assert!(isolated.is_isolated());
    assert!(!not_isolated.is_isolated());
}

#[test]
fn test_11_status_update_validate_rejects_wallet_peers_above_total_peers() -> TestResult {
    let update = status_update(true, true, 1, 1, 1, 2);

    let message = validation_message(update.validate_invariants())?;

    assert!(message.contains("connected_wallet_peers=2 > peers_connected=1"));
    Ok(())
}

#[test]
fn test_12_new_and_default_committee_start_empty() {
    let created = CommitteeEligibility::new(loose_config());
    let defaulted = CommitteeEligibility::default();

    assert!(created.is_empty());
    assert_eq!(created.len(), 0);
    assert!(created.live_wallets().is_empty());

    assert!(defaulted.is_empty());
    assert_eq!(defaulted.len(), 0);
    assert!(defaulted.live_wallets().is_empty());
}

#[test]
fn test_13_replace_live_wallets_canonicalizes_sorts_and_deduplicates() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(13);
    let wallet_b = wallet(14);

    eligibility.replace_live_wallets(vec![
        wallet_b.clone(),
        wallet_a.to_ascii_uppercase(),
        format!("  {wallet_a}  "),
    ])?;

    assert_eq!(eligibility.live_wallets(), vec![wallet_a, wallet_b]);
    Ok(())
}

#[test]
fn test_14_replace_live_wallets_invalid_input_does_not_mutate_existing_live_set() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let existing = wallet(14);

    eligibility.replace_live_wallets(vec![existing.clone()])?;

    assert!(
        eligibility
            .replace_live_wallets(vec![wallet(15), "bad-wallet".to_string()])
            .is_err()
    );

    assert_eq!(eligibility.live_wallets(), vec![existing]);
    Ok(())
}

#[test]
fn test_15_mark_wallet_live_true_canonicalizes_wallet() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let canonical = wallet(15);

    eligibility.mark_wallet_live(&canonical.to_ascii_uppercase(), true)?;

    assert!(eligibility.is_wallet_live(&canonical));
    assert_eq!(eligibility.live_wallets(), vec![canonical]);
    Ok(())
}

#[test]
fn test_16_mark_wallet_live_false_removes_wallet() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(16);

    eligibility.mark_wallet_live(&wallet_a, true)?;
    eligibility.mark_wallet_live(&wallet_a, false)?;

    assert!(!eligibility.is_wallet_live(&wallet_a));
    assert!(eligibility.live_wallets().is_empty());
    Ok(())
}

#[test]
fn test_17_is_wallet_live_returns_false_for_invalid_wallet() {
    let eligibility = CommitteeEligibility::with_default_config();

    assert!(!eligibility.is_wallet_live("bad-wallet"));
}

#[test]
fn test_18_live_wallet_without_status_is_ready_by_default() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(18);

    eligibility.mark_wallet_live(&wallet_a, true)?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.is_runtime_ready());
    assert!(decision.reasons.is_empty());
    assert_eq!(decision.wallet, wallet_a);
    Ok(())
}

#[test]
fn test_19_not_live_wallet_is_ineligible_with_not_live_reason() {
    let eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(19);

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(&decision, IneligibilityReason::NotLive);
}

#[test]
fn test_20_decide_wallet_canonicalizes_uppercase_candidate() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let canonical = wallet(20);

    eligibility.mark_wallet_live(&canonical, true)?;

    let decision = eligibility.decide_wallet(&canonical.to_ascii_uppercase());

    assert!(decision.eligible);
    assert_eq!(decision.wallet, canonical);
    Ok(())
}

#[test]
fn test_21_upsert_status_live_true_inserts_status_and_live_wallet() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(21);

    eligibility.upsert_status(member_status(
        &wallet_a.to_ascii_uppercase(),
        true,
        true,
        10,
        10,
        2,
        1,
        false,
    ))?;

    assert_eq!(eligibility.len(), 1);
    assert!(eligibility.is_wallet_live(&wallet_a));
    assert_eq!(
        eligibility
            .get_status(&wallet_a)
            .ok_or_else(|| test_error("status missing"))?
            .canonical_wallet(),
        wallet_a
    );
    Ok(())
}

#[test]
fn test_22_upsert_status_live_false_stores_status_but_removes_live_wallet() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(22);

    eligibility.mark_wallet_live(&wallet_a, true)?;
    eligibility.upsert_status(member_status(&wallet_a, false, true, 0, 0, 1, 1, false))?;

    assert_eq!(eligibility.len(), 1);
    assert!(!eligibility.is_wallet_live(&wallet_a));

    let decision = eligibility.decide_wallet(&wallet_a);
    assert!(!decision.eligible);
    assert_reason(&decision, IneligibilityReason::NotLive);
    Ok(())
}

#[test]
fn test_23_upsert_status_rejects_when_config_is_invalid() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    eligibility.config_mut().min_peers_connected = 1;
    eligibility.config_mut().min_connected_wallet_peers = 2;

    let result =
        eligibility.upsert_status(member_status(&wallet(23), true, true, 0, 0, 2, 2, false));

    assert!(result.is_err());
    assert!(eligibility.is_empty());
    Ok(())
}

#[test]
fn test_24_update_local_status_computes_isolated_from_wallet_peer_count() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(24);

    eligibility.update_local_status(&wallet_a, status_update(true, true, 10, 10, 5, 0))?;

    let status = eligibility
        .get_status(&wallet_a)
        .ok_or_else(|| test_error("status missing"))?;

    assert!(status.is_isolated);
    assert_eq!(status.peers_connected, 5);
    assert_eq!(status.connected_wallet_peers, 0);
    Ok(())
}

#[test]
fn test_25_update_remote_status_matches_local_status_behavior() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(25);

    eligibility.update_remote_status(&wallet_a, status_update(true, true, 10, 12, 3, 2))?;

    let status = eligibility
        .get_status(&wallet_a)
        .ok_or_else(|| test_error("status missing"))?;

    assert!(eligibility.is_wallet_live(&wallet_a));
    assert_eq!(status.tip_lag(), 2);
    assert!(!status.is_isolated);
    Ok(())
}

#[test]
fn test_26_require_synced_adds_not_synced_reason() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(26);

    eligibility.upsert_status(member_status(&wallet_a, true, false, 10, 10, 3, 1, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(&decision, IneligibilityReason::NotSynced);
    Ok(())
}

#[test]
fn test_27_tip_lag_above_config_adds_too_far_behind_reason() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(27);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 13, 3, 1, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::TooFarBehind {
            lag: 3,
            max_allowed: 2,
        },
    );
    Ok(())
}

#[test]
fn test_28_tip_lag_equal_to_config_limit_is_allowed() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(28);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 12, 3, 1, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_29_solo_live_wallet_skips_connectivity_and_isolation_checks() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(29);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_30_multi_node_adds_not_enough_peers_reason() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(30);
    let wallet_b = wallet(31);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 1, 1, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughPeers {
            connected: 1,
            min_required: 2,
        },
    );
    Ok(())
}

#[test]
fn test_31_multi_node_adds_not_enough_wallet_peers_reason() -> TestResult {
    let mut cfg = strict_config();
    cfg.min_peers_connected = 2;
    cfg.min_connected_wallet_peers = 2;

    let mut eligibility = CommitteeEligibility::new(cfg);
    let wallet_a = wallet(31);
    let wallet_b = wallet(32);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 3, 1, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughWalletPeers {
            connected: 1,
            min_required: 2,
        },
    );
    Ok(())
}

#[test]
fn test_32_multi_node_adds_isolated_reason_when_required() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(32);
    let wallet_b = wallet(33);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 3, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(&decision, IneligibilityReason::Isolated);
    Ok(())
}

#[test]
fn test_33_decision_accumulates_multiple_reasons_in_multi_node_mode() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(33);
    let wallet_b = wallet(34);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, false, 10, 99, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(&decision, IneligibilityReason::NotSynced);
    assert_reason(
        &decision,
        IneligibilityReason::TooFarBehind {
            lag: 89,
            max_allowed: 2,
        },
    );
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughPeers {
            connected: 0,
            min_required: 2,
        },
    );
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughWalletPeers {
            connected: 0,
            min_required: 1,
        },
    );
    assert_reason(&decision, IneligibilityReason::Isolated);
    Ok(())
}

#[test]
fn test_34_filter_candidates_keeps_only_runtime_ready_wallets() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(34);
    let wallet_b = wallet(35);
    let wallet_c = wallet(36);

    eligibility.mark_wallet_live(&wallet_a, true)?;
    eligibility.mark_wallet_live(&wallet_c, true)?;

    let kept = eligibility.filter_candidates(vec![wallet_a.clone(), wallet_b, wallet_c.clone()]);

    assert_eq!(kept, vec![wallet_a, wallet_c]);
    Ok(())
}

#[test]
fn test_35_filter_candidates_with_decisions_returns_kept_and_all_decisions() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(35);
    let wallet_b = wallet(36);

    eligibility.mark_wallet_live(&wallet_a, true)?;

    let (kept, decisions) =
        eligibility.filter_candidates_with_decisions(vec![wallet_a.clone(), wallet_b.clone()]);

    assert_eq!(kept, vec![wallet_a]);
    assert_eq!(decisions.len(), 2);
    assert!(decisions[0].eligible);
    assert!(!decisions[1].eligible);
    assert_eq!(decisions[1].wallet, wallet_b);
    Ok(())
}

#[test]
fn test_36_all_runtime_decisions_includes_live_wallets_and_status_only_wallets() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let live_without_status = wallet(36);
    let status_not_live = wallet(37);

    eligibility.mark_wallet_live(&live_without_status, true)?;
    eligibility.upsert_status(member_status(
        &status_not_live,
        false,
        true,
        0,
        0,
        0,
        0,
        true,
    ))?;

    let decisions = eligibility.all_runtime_decisions();

    assert_eq!(decisions.len(), 2);
    assert!(
        decisions
            .iter()
            .any(|d| d.wallet == live_without_status && d.eligible)
    );
    assert!(decisions.iter().any(|d| {
        d.wallet == status_not_live
            && !d.eligible
            && d.reasons.contains(&IneligibilityReason::NotLive)
    }));
    Ok(())
}

#[test]
fn test_37_remove_wallet_removes_live_and_status_entries() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(37);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 1, 1, 1, 1, false))?;

    assert!(eligibility.remove_wallet(&wallet_a));
    assert!(!eligibility.remove_wallet(&wallet_a));
    assert!(!eligibility.is_wallet_live(&wallet_a));
    assert!(eligibility.get_status(&wallet_a).is_none());
    assert!(eligibility.is_empty());
    Ok(())
}

#[test]
fn test_38_clear_removes_all_live_wallets_and_statuses() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();

    eligibility.upsert_status(member_status(&wallet(38), true, true, 1, 1, 1, 1, false))?;
    eligibility.mark_wallet_live(&wallet(39), true)?;

    eligibility.clear();

    assert!(eligibility.is_empty());
    assert_eq!(eligibility.len(), 0);
    assert!(eligibility.live_wallets().is_empty());
    Ok(())
}

#[test]
fn test_39_runtime_ready_aliases_match_decision_eligible_flag() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(39);

    eligibility.mark_wallet_live(&wallet_a, true)?;

    assert_eq!(
        eligibility.is_wallet_eligible(&wallet_a),
        eligibility.decide_wallet(&wallet_a).eligible
    );
    assert_eq!(
        eligibility.is_wallet_runtime_ready(&wallet_a),
        eligibility.decide_wallet(&wallet_a).eligible
    );
    Ok(())
}

#[test]
fn test_40_load_many_live_wallets_without_status_are_all_runtime_ready() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallets = (0_u64..128_u64).map(wallet).collect::<Vec<_>>();

    eligibility.replace_live_wallets(wallets.clone())?;

    let kept = eligibility.filter_candidates(wallets.clone());

    assert_eq!(kept, wallets);
    assert_eq!(eligibility.live_wallets().len(), 128);
    assert_eq!(eligibility.all_runtime_decisions().len(), 128);
    assert!(
        eligibility
            .all_runtime_decisions()
            .into_iter()
            .all(|decision| decision.eligible)
    );
    Ok(())
}

#[test]
fn test_41_config_clone_and_debug_preserve_fields() {
    let cfg = strict_config();
    let cloned = cfg.clone();
    let debug_text = format!("{cfg:?}");

    assert_eq!(cloned, cfg);
    assert!(debug_text.contains("CommitteeEligibilityConfig"));
    assert!(debug_text.contains("max_tip_lag_blocks"));
    assert!(debug_text.contains("min_peers_connected"));
    assert!(debug_text.contains("require_synced"));
}

#[test]
fn test_42_member_status_clone_eq_and_debug_preserve_fields() {
    let status = member_status(&wallet(42), true, true, 100, 101, 3, 2, false);
    let cloned = status.clone();
    let debug_text = format!("{status:?}");

    assert_eq!(cloned, status);
    assert_eq!(cloned.tip_lag(), 1);
    assert!(debug_text.contains("CommitteeMemberStatus"));
    assert!(debug_text.contains("wallet"));
    assert!(debug_text.contains("network_tip"));
}

#[test]
fn test_43_status_update_copy_eq_and_debug_preserve_fields() {
    let update = status_update(true, false, 10, 12, 4, 1);
    let copied = update;
    let debug_text = format!("{update:?}");

    assert_eq!(copied, update);
    assert!(!copied.is_isolated());
    assert!(debug_text.contains("CommitteeStatusUpdate"));
    assert!(debug_text.contains("has_synced"));
    assert!(debug_text.contains("connected_wallet_peers"));
}

#[test]
fn test_44_decision_constructors_and_runtime_ready_alias() {
    let wallet_a = wallet(44);
    let eligible = CommitteeEligibilityDecision::eligible(wallet_a.clone());
    let ineligible = CommitteeEligibilityDecision::ineligible(
        wallet_a.clone(),
        vec![IneligibilityReason::NotLive],
    );

    assert!(eligible.eligible);
    assert!(eligible.is_runtime_ready());
    assert!(eligible.reasons.is_empty());
    assert_eq!(eligible.wallet, wallet_a);

    assert!(!ineligible.eligible);
    assert!(!ineligible.is_runtime_ready());
    assert_eq!(ineligible.reasons, vec![IneligibilityReason::NotLive]);
}

#[test]
fn test_45_reason_clone_eq_and_debug_for_too_far_behind() {
    let reason = IneligibilityReason::TooFarBehind {
        lag: 9,
        max_allowed: 2,
    };
    let cloned = reason.clone();
    let debug_text = format!("{reason:?}");

    assert_eq!(cloned, reason);
    assert!(debug_text.contains("TooFarBehind"));
    assert!(debug_text.contains("lag"));
    assert!(debug_text.contains("max_allowed"));
}

#[test]
fn test_46_config_mut_can_make_config_invalid_and_validate_config_reports_it() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();

    eligibility.config_mut().min_peers_connected = 1;
    eligibility.config_mut().min_connected_wallet_peers = 2;

    let message = validation_message(eligibility.validate_config())?;

    assert!(message.contains("min_connected_wallet_peers=2 > min_peers_connected=1"));
    Ok(())
}

#[test]
fn test_47_new_with_invalid_config_stores_config_but_later_validation_reports_it() -> TestResult {
    let cfg = CommitteeEligibilityConfig {
        max_tip_lag_blocks: 2,
        min_peers_connected: 0,
        min_connected_wallet_peers: 1,
        require_non_isolated: false,
        require_synced: false,
    };

    let eligibility = CommitteeEligibility::new(cfg);

    assert!(eligibility.is_empty());
    assert!(eligibility.validate_config().is_err());
    Ok(())
}

#[test]
fn test_48_invalid_config_blocks_update_local_status_without_mutation() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    eligibility.config_mut().min_peers_connected = 0;
    eligibility.config_mut().min_connected_wallet_peers = 1;

    let result =
        eligibility.update_local_status(&wallet(48), status_update(true, true, 1, 1, 1, 1));

    assert!(result.is_err());
    assert!(eligibility.is_empty());
    Ok(())
}

#[test]
fn test_49_mark_wallet_live_invalid_wallet_errors_without_mutation() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(49);

    eligibility.mark_wallet_live(&wallet_a, true)?;

    assert!(eligibility.mark_wallet_live("bad-wallet", true).is_err());
    assert_eq!(eligibility.live_wallets(), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_50_replace_live_wallets_empty_iterator_clears_live_view() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();

    eligibility.replace_live_wallets(vec![wallet(50), wallet(51)])?;
    eligibility.replace_live_wallets(Vec::<String>::new())?;

    assert!(eligibility.live_wallets().is_empty());
    Ok(())
}

#[test]
fn test_51_get_status_accepts_uppercase_lookup_after_normalized_upsert() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(51);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 1, 1, false))?;

    let status = eligibility
        .get_status(&wallet_a.to_ascii_uppercase())
        .ok_or_else(|| test_error("status missing for uppercase lookup"))?;

    assert_eq!(status.wallet, wallet_a);
    Ok(())
}

#[test]
fn test_52_remove_wallet_accepts_uppercase_lookup() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(52);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 1, 1, false))?;

    assert!(eligibility.remove_wallet(&wallet_a.to_ascii_uppercase()));
    assert!(eligibility.is_empty());
    Ok(())
}

#[test]
fn test_53_remove_wallet_invalid_input_returns_false_and_preserves_state() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(53);

    eligibility.mark_wallet_live(&wallet_a, true)?;

    assert!(!eligibility.remove_wallet("bad-wallet"));
    assert_eq!(eligibility.live_wallets(), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_54_filter_candidates_preserves_original_candidate_string_for_kept_wallets() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let canonical = wallet(54);
    let uppercase = canonical.to_ascii_uppercase();

    eligibility.mark_wallet_live(&canonical, true)?;

    let kept = eligibility.filter_candidates(vec![uppercase.clone()]);

    assert_eq!(kept, vec![uppercase]);
    Ok(())
}

#[test]
fn test_55_filter_candidates_with_decisions_invalid_candidate_keeps_original_decision_wallet()
-> TestResult {
    let eligibility = CommitteeEligibility::with_default_config();

    let (kept, decisions) =
        eligibility.filter_candidates_with_decisions(vec!["bad-wallet".to_string()]);

    assert!(kept.is_empty());
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].wallet, "bad-wallet");
    assert!(!decisions[0].eligible);
    assert_reason(&decisions[0], IneligibilityReason::NotLive);
    Ok(())
}

#[test]
fn test_56_all_runtime_decisions_are_sorted_by_canonical_wallet() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(56);
    let wallet_b = wallet(57);
    let wallet_c = wallet(58);

    eligibility.mark_wallet_live(&wallet_c, true)?;
    eligibility.mark_wallet_live(&wallet_a, true)?;
    eligibility.mark_wallet_live(&wallet_b, true)?;

    let decision_wallets = eligibility
        .all_runtime_decisions()
        .into_iter()
        .map(|decision| decision.wallet)
        .collect::<Vec<_>>();

    assert_eq!(decision_wallets, vec![wallet_a, wallet_b, wallet_c]);
    Ok(())
}

#[test]
fn test_57_update_local_status_invalid_wallet_returns_error_without_status_insert() {
    let mut eligibility = CommitteeEligibility::with_default_config();

    let result =
        eligibility.update_local_status("bad-wallet", status_update(true, true, 10, 10, 1, 1));

    assert!(result.is_err());
    assert!(eligibility.is_empty());
}

#[test]
fn test_58_update_remote_status_invalid_update_invariant_returns_error_without_insert() {
    let mut eligibility = CommitteeEligibility::with_default_config();

    let result =
        eligibility.update_remote_status(&wallet(58), status_update(true, true, 10, 10, 1, 2));

    assert!(result.is_err());
    assert!(eligibility.is_empty());
}

#[test]
fn test_59_upsert_status_invalid_member_invariant_returns_error_without_insert() {
    let mut eligibility = CommitteeEligibility::with_default_config();

    let result =
        eligibility.upsert_status(member_status(&wallet(59), true, true, 1, 1, 1, 2, false));

    assert!(result.is_err());
    assert!(eligibility.is_empty());
}

#[test]
fn test_60_default_config_does_not_require_synced_when_lag_is_allowed() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(60);

    eligibility.upsert_status(member_status(&wallet_a, true, false, 10, 10, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_61_default_config_allows_isolation_and_zero_peers_in_multi_node_mode() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(61);
    let wallet_b = wallet(62);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_62_strict_multi_node_live_wallet_without_status_is_ready_by_rollout_default() -> TestResult
{
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(62);
    let wallet_b = wallet(63);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_63_strict_multi_node_healthy_status_is_ready() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(63);
    let wallet_b = wallet(64);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 100, 102, 2, 1, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_64_strict_multi_node_local_tip_ahead_is_not_too_far_behind() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(64);
    let wallet_b = wallet(65);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 200, 100, 2, 1, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_65_strict_multi_node_u64_max_lag_adds_too_far_behind_reason() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(65);
    let wallet_b = wallet(66);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(
        &wallet_a,
        true,
        true,
        0,
        u64::MAX,
        2,
        1,
        false,
    ))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::TooFarBehind {
            lag: u64::MAX,
            max_allowed: 2,
        },
    );
    Ok(())
}

#[test]
fn test_66_strict_multi_node_zero_peers_can_add_peer_reasons_without_isolated_flag() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(66);
    let wallet_b = wallet(67);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 0, 0, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughPeers {
            connected: 0,
            min_required: 2,
        },
    );
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughWalletPeers {
            connected: 0,
            min_required: 1,
        },
    );
    assert!(!decision.reasons.contains(&IneligibilityReason::Isolated));
    Ok(())
}

#[test]
fn test_67_solo_wallet_still_requires_synced_when_config_requires_synced() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(67);

    eligibility.upsert_status(member_status(&wallet_a, true, false, 10, 10, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(&decision, IneligibilityReason::NotSynced);
    Ok(())
}

#[test]
fn test_68_solo_wallet_still_requires_tip_lag_limit() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(68);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 99, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::TooFarBehind {
            lag: 89,
            max_allowed: 2,
        },
    );
    Ok(())
}

#[test]
fn test_69_len_counts_statuses_not_live_wallets() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();

    eligibility.mark_wallet_live(&wallet(69), true)?;
    eligibility.mark_wallet_live(&wallet(70), true)?;

    assert_eq!(eligibility.len(), 0);
    assert!(!eligibility.is_empty());
    Ok(())
}

#[test]
fn test_70_is_empty_false_when_status_exists_even_if_wallet_not_live() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(70);

    eligibility.upsert_status(member_status(&wallet_a, false, true, 0, 0, 0, 0, true))?;

    assert_eq!(eligibility.len(), 1);
    assert!(!eligibility.is_empty());
    assert!(eligibility.live_wallets().is_empty());
    Ok(())
}

#[test]
fn test_71_clear_preserves_config_values() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());

    eligibility.upsert_status(member_status(&wallet(71), true, true, 1, 1, 2, 1, false))?;
    eligibility.clear();

    assert!(eligibility.is_empty());
    assert_eq!(eligibility.config(), &strict_config());
    Ok(())
}

#[test]
fn test_72_config_mut_can_relax_connectivity_policy_after_status_insert() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(72);
    let wallet_b = wallet(73);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 0, 0, true))?;

    assert!(!eligibility.decide_wallet(&wallet_a).eligible);

    eligibility.config_mut().min_peers_connected = 0;
    eligibility.config_mut().min_connected_wallet_peers = 0;
    eligibility.config_mut().require_non_isolated = false;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn test_73_update_local_status_overwrites_previous_status() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(73);
    let wallet_b = wallet(74);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.update_local_status(&wallet_a, status_update(true, false, 1, 99, 0, 0))?;

    assert!(!eligibility.decide_wallet(&wallet_a).eligible);

    eligibility.update_local_status(&wallet_a, status_update(true, true, 100, 101, 3, 1))?;

    let status = eligibility
        .get_status(&wallet_a)
        .ok_or_else(|| test_error("status missing after overwrite"))?;
    let decision = eligibility.decide_wallet(&wallet_a);

    assert_eq!(status.local_tip, 100);
    assert_eq!(status.network_tip, 101);
    assert!(decision.eligible);
    Ok(())
}

#[test]
fn test_74_upsert_live_false_overwrites_existing_live_true_status() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(74);

    eligibility.upsert_status(member_status(&wallet_a, true, true, 1, 1, 1, 1, false))?;
    eligibility.upsert_status(member_status(&wallet_a, false, true, 2, 2, 1, 1, false))?;

    assert_eq!(eligibility.len(), 1);
    assert!(!eligibility.is_wallet_live(&wallet_a));
    assert!(!eligibility.decide_wallet(&wallet_a).eligible);
    Ok(())
}

#[test]
fn test_75_replace_live_wallets_does_not_remove_existing_status_entries() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let status_wallet = wallet(75);
    let live_wallet = wallet(76);

    eligibility.upsert_status(member_status(&status_wallet, true, true, 1, 1, 1, 1, false))?;
    eligibility.replace_live_wallets(vec![live_wallet.clone()])?;

    assert_eq!(eligibility.len(), 1);
    assert!(eligibility.get_status(&status_wallet).is_some());
    assert!(!eligibility.is_wallet_live(&status_wallet));
    assert!(eligibility.is_wallet_live(&live_wallet));

    let decisions = eligibility.all_runtime_decisions();
    assert_eq!(decisions.len(), 2);
    Ok(())
}

#[test]
fn test_76_filter_candidates_preserves_duplicate_candidates() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(76);

    eligibility.mark_wallet_live(&wallet_a, true)?;

    let kept = eligibility.filter_candidates(vec![wallet_a.clone(), wallet_a.clone()]);

    assert_eq!(kept, vec![wallet_a.clone(), wallet_a]);
    Ok(())
}

#[test]
fn test_77_filter_candidates_with_decisions_preserves_duplicate_decisions() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(77);

    eligibility.mark_wallet_live(&wallet_a, true)?;

    let (kept, decisions) =
        eligibility.filter_candidates_with_decisions(vec![wallet_a.clone(), wallet_a.clone()]);

    assert_eq!(kept, vec![wallet_a.clone(), wallet_a.clone()]);
    assert_eq!(decisions.len(), 2);
    assert!(decisions.iter().all(|decision| decision.wallet == wallet_a));
    assert!(decisions.iter().all(|decision| decision.eligible));
    Ok(())
}

#[test]
fn test_78_decide_invalid_wallet_returns_original_input_in_decision() {
    let eligibility = CommitteeEligibility::with_default_config();

    let decision = eligibility.decide_wallet("not-a-wallet");

    assert_eq!(decision.wallet, "not-a-wallet");
    assert!(!decision.eligible);
    assert_eq!(decision.reasons, vec![IneligibilityReason::NotLive]);
}

#[test]
fn test_79_load_many_statuses_all_healthy_under_strict_config_are_ready() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallets = (0_u64..64_u64).map(wallet).collect::<Vec<_>>();

    eligibility.replace_live_wallets(wallets.clone())?;

    for wallet_addr in &wallets {
        eligibility.upsert_status(member_status(
            wallet_addr,
            true,
            true,
            100,
            101,
            3,
            1,
            false,
        ))?;
    }

    assert_eq!(eligibility.len(), 64);

    for wallet_addr in wallets {
        let decision = eligibility.decide_wallet(&wallet_addr);
        assert!(decision.eligible);
        assert!(decision.reasons.is_empty());
    }

    Ok(())
}

#[test]
fn test_80_load_mixed_statuses_filter_candidates_keeps_only_ready_wallets() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallets = (80_u64..96_u64).map(wallet).collect::<Vec<_>>();

    eligibility.replace_live_wallets(wallets.clone())?;

    for (index, wallet_addr) in wallets.iter().enumerate() {
        if index % 2 == 0 {
            eligibility.upsert_status(member_status(
                wallet_addr,
                true,
                true,
                100,
                101,
                3,
                1,
                false,
            ))?;
        } else {
            eligibility.upsert_status(member_status(
                wallet_addr,
                true,
                false,
                100,
                101,
                3,
                1,
                false,
            ))?;
        }
    }

    let kept = eligibility.filter_candidates(wallets.clone());
    let expected = wallets
        .into_iter()
        .enumerate()
        .filter_map(|(index, wallet_addr)| {
            if index % 2 == 0 {
                Some(wallet_addr)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    assert_eq!(kept, expected);
    Ok(())
}

#[test]
fn test_81_edge_status_update_zero_peers_zero_wallet_peers_is_valid_and_isolated() {
    let update = status_update(true, true, 0, 0, 0, 0);

    assert!(update.validate_invariants().is_ok());
    assert!(update.is_isolated());
}

#[test]
fn test_82_edge_status_update_usize_max_peers_with_zero_wallet_peers_is_valid() {
    let update = status_update(true, true, 0, 0, usize::MAX, 0);

    assert!(update.validate_invariants().is_ok());
    assert!(update.is_isolated());
}

#[test]
fn test_83_edge_status_update_usize_max_peers_and_wallet_peers_is_valid() {
    let update = status_update(true, true, 0, 0, usize::MAX, usize::MAX);

    assert!(update.validate_invariants().is_ok());
    assert!(!update.is_isolated());
}

#[test]
fn test_84_edge_member_status_canonical_wallet_returns_stored_wallet_string() {
    let wallet_a = wallet(84);
    let status = member_status(&wallet_a, true, true, 1, 1, 1, 1, false);

    assert_eq!(status.canonical_wallet(), wallet_a);
}

#[test]
fn test_85_vector_member_status_uppercase_wallet_validates_but_upsert_normalizes() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let canonical = wallet(85);
    let uppercase = canonical.to_ascii_uppercase();
    let status = member_status(&uppercase, true, true, 10, 10, 1, 1, false);

    assert!(status.validate_invariants().is_ok());

    eligibility.upsert_status(status)?;

    let stored = eligibility
        .get_status(&canonical)
        .ok_or_else(|| test_error("normalized status missing"))?;

    assert_eq!(stored.wallet, canonical);
    assert_eq!(eligibility.live_wallets(), vec![canonical]);
    Ok(())
}

#[test]
fn test_86_vector_member_status_trimmed_wallet_upsert_normalizes() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let canonical = wallet(86);
    let trimmed = format!(" \n{}\t ", canonical.to_ascii_uppercase());

    eligibility.upsert_status(member_status(&trimmed, true, true, 10, 10, 1, 1, false))?;

    let stored = eligibility
        .get_status(&canonical)
        .ok_or_else(|| test_error("trimmed normalized status missing"))?;

    assert_eq!(stored.wallet, canonical);
    assert!(eligibility.is_wallet_live(&canonical));
    Ok(())
}

#[test]
fn test_87_edge_update_local_status_live_false_keeps_status_but_removes_live_wallet() -> TestResult
{
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(87);

    eligibility.update_local_status(&wallet_a, status_update(true, true, 10, 10, 1, 1))?;
    eligibility.update_local_status(&wallet_a, status_update(false, true, 11, 11, 1, 1))?;

    assert_eq!(eligibility.len(), 1);
    assert!(!eligibility.is_wallet_live(&wallet_a));
    assert!(eligibility.get_status(&wallet_a).is_some());

    let decision = eligibility.decide_wallet(&wallet_a);
    assert!(!decision.eligible);
    assert_eq!(decision.reasons, vec![IneligibilityReason::NotLive]);
    Ok(())
}

#[test]
fn test_88_edge_update_remote_status_live_false_keeps_status_but_removes_live_wallet() -> TestResult
{
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallet_a = wallet(88);

    eligibility.update_remote_status(&wallet_a, status_update(true, true, 10, 10, 1, 1))?;
    eligibility.update_remote_status(&wallet_a, status_update(false, true, 12, 12, 1, 1))?;

    assert_eq!(eligibility.len(), 1);
    assert!(!eligibility.is_wallet_live(&wallet_a));
    assert!(eligibility.get_status(&wallet_a).is_some());

    let decision = eligibility.decide_wallet(&wallet_a);
    assert!(!decision.eligible);
    assert_reason(&decision, IneligibilityReason::NotLive);
    Ok(())
}

#[test]
fn test_89_vector_tip_lag_boundaries_zero_equal_and_above_limit() -> TestResult {
    let mut cfg = strict_config();
    cfg.min_peers_connected = 0;
    cfg.min_connected_wallet_peers = 0;
    cfg.require_non_isolated = false;

    let mut eligibility = CommitteeEligibility::new(cfg);
    let zero_lag = wallet(890);
    let equal_lag = wallet(891);
    let above_lag = wallet(892);

    eligibility.replace_live_wallets(vec![
        zero_lag.clone(),
        equal_lag.clone(),
        above_lag.clone(),
    ])?;
    eligibility.upsert_status(member_status(&zero_lag, true, true, 10, 10, 0, 0, true))?;
    eligibility.upsert_status(member_status(&equal_lag, true, true, 10, 12, 0, 0, true))?;
    eligibility.upsert_status(member_status(&above_lag, true, true, 10, 13, 0, 0, true))?;

    assert!(eligibility.decide_wallet(&zero_lag).eligible);
    assert!(eligibility.decide_wallet(&equal_lag).eligible);

    let decision = eligibility.decide_wallet(&above_lag);
    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::TooFarBehind {
            lag: 3,
            max_allowed: 2,
        },
    );
    Ok(())
}

#[test]
fn test_90_vector_peer_count_boundaries_for_strict_multi_node() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(900);
    let wallet_b = wallet(901);
    let wallet_c = wallet(902);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b.clone(), wallet_c])?;

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 1, 1, false))?;
    eligibility.upsert_status(member_status(&wallet_b, true, true, 10, 10, 2, 1, false))?;

    let low_peer_decision = eligibility.decide_wallet(&wallet_a);
    assert!(!low_peer_decision.eligible);
    assert_reason(
        &low_peer_decision,
        IneligibilityReason::NotEnoughPeers {
            connected: 1,
            min_required: 2,
        },
    );

    let boundary_decision = eligibility.decide_wallet(&wallet_b);
    assert!(boundary_decision.eligible);
    Ok(())
}

#[test]
fn test_91_vector_wallet_peer_count_boundaries_for_strict_multi_node() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(910);
    let wallet_b = wallet(911);
    let wallet_c = wallet(912);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b.clone(), wallet_c])?;

    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 2, 0, true))?;
    eligibility.upsert_status(member_status(&wallet_b, true, true, 10, 10, 2, 1, false))?;

    let low_wallet_peer_decision = eligibility.decide_wallet(&wallet_a);
    assert!(!low_wallet_peer_decision.eligible);
    assert_reason(
        &low_wallet_peer_decision,
        IneligibilityReason::NotEnoughWalletPeers {
            connected: 0,
            min_required: 1,
        },
    );
    assert_reason(&low_wallet_peer_decision, IneligibilityReason::Isolated);

    let boundary_decision = eligibility.decide_wallet(&wallet_b);
    assert!(boundary_decision.eligible);
    Ok(())
}

#[test]
fn test_92_edge_strict_multi_node_isolated_false_with_zero_wallet_peers_only_wallet_peer_reason()
-> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(920);
    let wallet_b = wallet(921);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 2, 0, false))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughWalletPeers {
            connected: 0,
            min_required: 1,
        },
    );
    assert!(!decision.reasons.contains(&IneligibilityReason::Isolated));
    Ok(())
}

#[test]
fn test_93_edge_require_non_isolated_false_skips_isolated_reason_but_keeps_peer_reasons()
-> TestResult {
    let mut cfg = strict_config();
    cfg.require_non_isolated = false;

    let mut eligibility = CommitteeEligibility::new(cfg);
    let wallet_a = wallet(930);
    let wallet_b = wallet(931);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, true, 10, 10, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughPeers {
            connected: 0,
            min_required: 2,
        },
    );
    assert_reason(
        &decision,
        IneligibilityReason::NotEnoughWalletPeers {
            connected: 0,
            min_required: 1,
        },
    );
    assert!(!decision.reasons.contains(&IneligibilityReason::Isolated));
    Ok(())
}

#[test]
fn test_94_edge_require_synced_false_skips_not_synced_reason_but_keeps_lag_reason() -> TestResult {
    let mut cfg = strict_config();
    cfg.require_synced = false;
    cfg.min_peers_connected = 0;
    cfg.min_connected_wallet_peers = 0;
    cfg.require_non_isolated = false;

    let mut eligibility = CommitteeEligibility::new(cfg);
    let wallet_a = wallet(940);
    let wallet_b = wallet(941);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, false, 10, 20, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert!(!decision.reasons.contains(&IneligibilityReason::NotSynced));
    assert_reason(
        &decision,
        IneligibilityReason::TooFarBehind {
            lag: 10,
            max_allowed: 2,
        },
    );
    Ok(())
}

#[test]
fn test_95_vector_all_reason_enum_variants_are_constructible_and_debuggable() {
    let reasons = vec![
        IneligibilityReason::NotLive,
        IneligibilityReason::NotSynced,
        IneligibilityReason::TooFarBehind {
            lag: 5,
            max_allowed: 2,
        },
        IneligibilityReason::NotEnoughPeers {
            connected: 0,
            min_required: 2,
        },
        IneligibilityReason::NotEnoughWalletPeers {
            connected: 0,
            min_required: 1,
        },
        IneligibilityReason::Isolated,
    ];

    let debug_text = format!("{reasons:?}");

    assert!(debug_text.contains("NotLive"));
    assert!(debug_text.contains("NotSynced"));
    assert!(debug_text.contains("TooFarBehind"));
    assert!(debug_text.contains("NotEnoughPeers"));
    assert!(debug_text.contains("NotEnoughWalletPeers"));
    assert!(debug_text.contains("Isolated"));
}

#[test]
fn test_96_vector_decision_reason_order_matches_policy_evaluation_order() -> TestResult {
    let mut eligibility = CommitteeEligibility::new(strict_config());
    let wallet_a = wallet(960);
    let wallet_b = wallet(961);

    eligibility.replace_live_wallets(vec![wallet_a.clone(), wallet_b])?;
    eligibility.upsert_status(member_status(&wallet_a, true, false, 1, 10, 0, 0, true))?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert_eq!(
        decision.reasons,
        vec![
            IneligibilityReason::NotSynced,
            IneligibilityReason::TooFarBehind {
                lag: 9,
                max_allowed: 2,
            },
            IneligibilityReason::NotEnoughPeers {
                connected: 0,
                min_required: 2,
            },
            IneligibilityReason::NotEnoughWalletPeers {
                connected: 0,
                min_required: 1,
            },
            IneligibilityReason::Isolated,
        ]
    );
    Ok(())
}

#[test]
fn test_97_load_vector_replace_live_wallets_deduplicates_uppercase_and_trimmed_forms() -> TestResult
{
    let mut eligibility = CommitteeEligibility::with_default_config();
    let mut inputs = Vec::new();
    let mut expected = Vec::new();

    for seed in 970_u64..986_u64 {
        let canonical = wallet(seed);
        expected.push(canonical.clone());
        inputs.push(canonical.clone());
        inputs.push(canonical.to_ascii_uppercase());
        inputs.push(format!(" \n{canonical}\t "));
    }

    eligibility.replace_live_wallets(inputs)?;

    expected.sort();
    expected.dedup();

    assert_eq!(eligibility.live_wallets(), expected);
    Ok(())
}

#[test]
fn test_98_load_vector_filter_candidates_with_invalid_and_valid_candidates() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let live_wallets = (980_u64..988_u64).map(wallet).collect::<Vec<_>>();

    eligibility.replace_live_wallets(live_wallets.clone())?;

    let mut candidates = live_wallets.clone();
    candidates.push("bad-wallet".to_string());
    candidates.push(format!("x{}", "0".repeat(128)));
    candidates.push(format!("r{}", "z".repeat(128)));

    let (kept, decisions) = eligibility.filter_candidates_with_decisions(candidates);

    assert_eq!(kept, live_wallets);
    assert_eq!(decisions.len(), 11);
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| decision.eligible)
            .count(),
        8
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| !decision.eligible)
            .count(),
        3
    );
    Ok(())
}

#[test]
fn test_99_load_vector_all_runtime_decisions_after_removing_half_the_wallets() -> TestResult {
    let mut eligibility = CommitteeEligibility::with_default_config();
    let wallets = (990_u64..1_006_u64).map(wallet).collect::<Vec<_>>();

    eligibility.replace_live_wallets(wallets.clone())?;

    for wallet_addr in wallets.iter().step_by(2) {
        assert!(eligibility.remove_wallet(wallet_addr));
    }

    let decisions = eligibility.all_runtime_decisions();

    assert_eq!(decisions.len(), 8);
    assert!(
        decisions
            .iter()
            .all(CommitteeEligibilityDecision::is_runtime_ready)
    );

    let remaining = wallets
        .into_iter()
        .enumerate()
        .filter_map(|(index, wallet_addr)| {
            if index % 2 == 1 {
                Some(wallet_addr)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let decision_wallets = decisions
        .into_iter()
        .map(|decision| decision.wallet)
        .collect::<Vec<_>>();

    assert_eq!(decision_wallets, remaining);
    Ok(())
}

#[test]
fn test_100_adversarial_vector_invalid_config_decide_wallet_still_handles_live_no_status()
-> TestResult {
    let mut eligibility = CommitteeEligibility::new(CommitteeEligibilityConfig {
        max_tip_lag_blocks: 2,
        min_peers_connected: 0,
        min_connected_wallet_peers: 1,
        require_non_isolated: true,
        require_synced: true,
    });
    let wallet_a = wallet(100);

    assert!(eligibility.validate_config().is_err());

    eligibility.mark_wallet_live(&wallet_a, true)?;

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    Ok(())
}
