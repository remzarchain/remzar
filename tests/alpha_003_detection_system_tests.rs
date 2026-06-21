use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::alpha_003_detection_system::{DetectionOutcome, DetectionSystem};
use std::time::Duration;

type TestResult = Result<(), String>;

fn canonical_id_for_test(pid: &str) -> String {
    let trimmed = pid.trim();
    let cap = GlobalConfiguration::MAX_PEER_ID_B58_LEN;

    match trimmed.get(..cap) {
        Some(capped) => capped.to_ascii_lowercase(),
        None => trimmed.to_ascii_lowercase(),
    }
}

fn assert_validation_error(result: Result<(), ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { .. }) => Ok(()),
        other => Err(format!("expected ValidationError, got {other:?}")),
    }
}

fn assert_invalid_operation(result: Result<(), ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::InvalidOperation { .. }) => Ok(()),
        other => Err(format!("expected InvalidOperation, got {other:?}")),
    }
}

fn fixed_assert_validation_message_contains(err: ErrorDetection, expected: &str) {
    match err {
        ErrorDetection::ValidationError { message, .. } => {
            assert!(
                message.contains(expected),
                "expected validation message to contain `{expected}`, got `{message}`"
            );
        }
        other => panic!("expected ValidationError containing `{expected}`, got {other:?}"),
    }
}

fn fixed_lower_hash_128() -> String {
    "a".repeat(128)
}

fn fixed_upper_hash_128() -> String {
    "A".repeat(128)
}

fn fixed_mixed_hash_128() -> String {
    "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF\
     0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF"
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[test]
fn detection_system_001_new_uses_global_configuration_defaults() -> TestResult {
    let system = DetectionSystem::new();

    assert_eq!(
        system.current_reward,
        GlobalConfiguration::INITIAL_BLOCK_REWARD
    );
    assert_eq!(system.participant_reward.to_bits(), 0.0_f64.to_bits());
    assert_eq!(
        system.max_participants,
        GlobalConfiguration::MAX_ZAR_PARTICIPANTS
    );
    assert!(system.active_participants.is_empty());
    assert!(system.last_active.is_empty());
    assert!(system.booted_participants.is_empty());
    assert!(system.booted_at.is_empty());
    assert!(system.validator_stakes.is_empty());
    Ok(())
}

#[test]
fn detection_system_002_default_matches_new_state() -> TestResult {
    let direct = DetectionSystem::new();
    let defaulted = DetectionSystem::default();

    assert_eq!(defaulted.current_reward, direct.current_reward);
    assert_eq!(
        defaulted.participant_reward.to_bits(),
        direct.participant_reward.to_bits()
    );
    assert_eq!(defaulted.max_participants, direct.max_participants);
    assert_eq!(
        defaulted.active_participants.len(),
        direct.active_participants.len()
    );
    assert_eq!(defaulted.last_active.len(), direct.last_active.len());
    Ok(())
}

#[test]
fn detection_system_003_add_participant_trims_lowercases_and_records_activity() -> TestResult {
    let mut system = DetectionSystem::new();
    let input = "  PeerAlpha  ";
    let canonical = canonical_id_for_test(input);

    system
        .add_participant(input)
        .map_err(|e| format!("add_participant failed: {e:?}"))?;

    assert!(system.active_participants.contains(&canonical));
    assert!(system.last_active.contains_key(&canonical));
    assert_eq!(system.active_participants.len(), 1);
    assert_eq!(system.last_active.len(), 1);
    Ok(())
}

#[test]
fn detection_system_004_add_participant_rejects_exact_duplicate() -> TestResult {
    let mut system = DetectionSystem::new();

    system
        .add_participant("peer-a")
        .map_err(|e| format!("first add failed: {e:?}"))?;

    match system.add_participant("peer-a") {
        Err(ErrorDetection::AlreadyExists { message }) => {
            assert!(message.contains("already active"));
        }
        other => return Err(format!("expected AlreadyExists, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_005_add_participant_rejects_case_insensitive_duplicate() -> TestResult {
    let mut system = DetectionSystem::new();

    system
        .add_participant("Peer-A")
        .map_err(|e| format!("first add failed: {e:?}"))?;

    match system.add_participant("pEeR-a") {
        Err(ErrorDetection::AlreadyExists { message }) => {
            assert!(message.contains("already active"));
        }
        other => return Err(format!("expected AlreadyExists, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_006_add_participant_rejects_empty_or_whitespace_id() -> TestResult {
    let mut system = DetectionSystem::new();

    assert_validation_error(system.add_participant(""))?;
    assert_validation_error(system.add_participant("   "))?;
    assert!(system.active_participants.is_empty());
    Ok(())
}

#[test]
fn detection_system_007_add_participant_caps_long_identifier_to_peer_id_limit() {
    let mut ds = DetectionSystem::new();

    let long_id = "A".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN + 16);

    let err = ds
        .add_participant(&long_id)
        .expect_err("overlength participant id must be rejected, not capped");

    fixed_assert_validation_message_contains(err, "exceeds MAX_PEER_ID_B58_LEN");

    assert!(
        ds.active_participants.is_empty(),
        "rejected overlength participant must not be inserted"
    );

    assert!(
        ds.last_active.is_empty(),
        "rejected overlength participant must not create last_active entry"
    );
}

#[test]
fn detection_system_008_add_participant_respects_custom_capacity_one() -> TestResult {
    let mut system = DetectionSystem::new();
    system.max_participants = 1;

    system
        .add_participant("peer-one")
        .map_err(|e| format!("first add failed: {e:?}"))?;

    match system.add_participant("peer-two") {
        Err(ErrorDetection::CapacityError { message }) => {
            assert!(message.contains("Maximum participant limit reached"));
        }
        other => return Err(format!("expected CapacityError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_009_add_participant_rejects_when_effective_capacity_is_zero() -> TestResult {
    let mut system = DetectionSystem::new();
    system.max_participants = 0;

    match system.add_participant("peer-zero") {
        Err(ErrorDetection::CapacityError { message }) => {
            assert!(message.contains("Maximum participant limit reached"));
        }
        other => return Err(format!("expected CapacityError, got {other:?}")),
    }

    assert!(system.active_participants.is_empty());
    Ok(())
}

#[test]
fn detection_system_010_remove_participant_clears_active_last_active_and_stake() -> TestResult {
    let mut system = DetectionSystem::new();
    let pid = "StakePeer";
    let canonical = canonical_id_for_test(pid);

    system
        .add_participant(pid)
        .map_err(|e| format!("add failed: {e:?}"))?;
    system.validator_stakes.insert(canonical.clone(), 1_000);

    system
        .remove_participant("stakepeer")
        .map_err(|e| format!("remove failed: {e:?}"))?;

    assert!(!system.active_participants.contains(&canonical));
    assert!(!system.last_active.contains_key(&canonical));
    assert!(!system.validator_stakes.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_011_remove_missing_participant_returns_not_found() -> TestResult {
    let mut system = DetectionSystem::new();

    match system.remove_participant("missing-peer") {
        Err(ErrorDetection::NotFound { resource }) => {
            assert!(resource.contains("missing-peer"));
        }
        other => return Err(format!("expected NotFound, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_012_update_participant_activity_refreshes_existing_active_peer() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("PeerRefresh");

    system
        .add_participant("PeerRefresh")
        .map_err(|e| format!("add failed: {e:?}"))?;
    system.last_active.insert(canonical.clone(), 1);

    system
        .update_participant_activity(" peerrefresh ")
        .map_err(|e| format!("update failed: {e:?}"))?;

    let updated = system
        .last_active
        .get(&canonical)
        .copied()
        .ok_or_else(|| "missing refreshed last_active entry".to_string())?;

    assert!(updated >= 1);
    Ok(())
}

#[test]
fn detection_system_013_update_participant_activity_rejects_inactive_peer() -> TestResult {
    let mut system = DetectionSystem::new();

    match system.update_participant_activity("ghost-peer") {
        Err(ErrorDetection::NotFound { resource }) => {
            assert!(resource.contains("active participant"));
            assert!(resource.contains("ghost-peer"));
        }
        other => return Err(format!("expected NotFound, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_014_last_active_of_trims_and_lowercases_lookup() -> TestResult {
    let mut system = DetectionSystem::new();

    system
        .add_participant("PeerLookup")
        .map_err(|e| format!("add failed: {e:?}"))?;

    assert!(system.last_active_of(" peerlookup ").is_some());
    assert!(system.last_active_of(" PEERLOOKUP ").is_some());
    Ok(())
}

#[test]
fn detection_system_015_boot_inactive_participants_removes_state_and_records_boot() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("BootMe");

    system
        .add_participant("BootMe")
        .map_err(|e| format!("add failed: {e:?}"))?;
    system.last_active.insert(canonical.clone(), 0);
    system.validator_stakes.insert(canonical.clone(), 50);

    system.boot_inactive_participants(Duration::from_secs(0));

    assert!(!system.active_participants.contains(&canonical));
    assert!(!system.last_active.contains_key(&canonical));
    assert!(!system.validator_stakes.contains_key(&canonical));
    assert!(system.booted_participants.contains(&canonical));
    assert!(system.booted_at.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_016_boot_inactive_participants_keeps_recent_peer_with_huge_window() -> TestResult
{
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("RecentPeer");

    system
        .add_participant("RecentPeer")
        .map_err(|e| format!("add failed: {e:?}"))?;
    system.boot_inactive_participants(Duration::from_secs(u64::MAX));

    assert!(system.active_participants.contains(&canonical));
    assert!(!system.booted_participants.contains(&canonical));
    Ok(())
}

#[test]
fn detection_system_017_recently_booted_participant_cannot_rejoin() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("NoRejoin");

    system
        .add_participant("NoRejoin")
        .map_err(|e| format!("add failed: {e:?}"))?;
    system.last_active.insert(canonical, 0);
    system.boot_inactive_participants(Duration::from_secs(0));

    match system.add_participant("norejoin") {
        Err(ErrorDetection::PermissionDenied { message }) => {
            assert!(message.contains("booted recently"));
        }
        other => return Err(format!("expected PermissionDenied, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_018_stale_boot_list_entry_is_pruned_before_rejoin() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("OldBoot");

    system.booted_participants.insert(canonical.clone());
    system.booted_at.insert(canonical.clone(), 0);

    system
        .add_participant("OldBoot")
        .map_err(|e| format!("rejoin after stale boot prune failed: {e:?}"))?;

    assert!(system.active_participants.contains(&canonical));
    assert!(!system.booted_participants.contains(&canonical));
    assert!(!system.booted_at.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_019_validate_system_state_warns_when_no_active_validators() -> TestResult {
    let system = DetectionSystem::new();

    match system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?
    {
        DetectionOutcome::Warning(message) => {
            assert!(message.contains("No active validators"));
        }
        other => return Err(format!("expected Warning, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_020_validate_system_state_ok_when_active_set_is_valid() -> TestResult {
    let mut system = DetectionSystem::new();

    system
        .add_participant("healthy-peer")
        .map_err(|e| format!("add failed: {e:?}"))?;

    let outcome = system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?;

    assert_eq!(outcome, DetectionOutcome::Ok);
    Ok(())
}

#[test]
fn detection_system_021_validate_system_state_critical_when_booted_peer_is_active() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("SplitBrain");

    system
        .add_participant("SplitBrain")
        .map_err(|e| format!("add failed: {e:?}"))?;
    system.booted_participants.insert(canonical);

    match system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?
    {
        DetectionOutcome::Critical(message) => {
            assert!(message.contains("Booted participants present"));
        }
        other => return Err(format!("expected Critical, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_022_validate_system_state_critical_when_active_exceeds_effective_cap()
-> TestResult {
    let mut system = DetectionSystem::new();
    system.max_participants = 0;
    system.active_participants.insert("over-cap".to_string());

    match system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?
    {
        DetectionOutcome::Critical(message) => {
            assert!(message.contains("exceed maximum"));
        }
        other => return Err(format!("expected Critical, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_023_detect_double_spend_accepts_empty_single_and_unique_batches() -> TestResult
{
    let system = DetectionSystem::new();

    system
        .detect_double_spend(Vec::<String>::new())
        .map_err(|e| format!("empty batch failed: {e:?}"))?;

    system
        .detect_double_spend(vec!["tx-one".to_string()])
        .map_err(|e| format!("single batch failed: {e:?}"))?;

    system
        .detect_double_spend(vec![
            "tx-one".to_string(),
            "tx-two".to_string(),
            "tx-three".to_string(),
        ])
        .map_err(|e| format!("unique batch failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_024_detect_double_spend_rejects_duplicate_tx_id() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_double_spend(vec![
        "tx-dup".to_string(),
        "tx-ok".to_string(),
        "tx-dup".to_string(),
    ]) {
        Err(ErrorDetection::DoubleSpending { tx_id }) => {
            assert_eq!(tx_id, Some("tx-dup".to_string()));
        }
        other => return Err(format!("expected DoubleSpending, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_025_detect_double_spend_is_exact_string_case_sensitive() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_double_spend(vec!["TX-Case".to_string(), "tx-case".to_string()])
        .map_err(|e| format!("case-sensitive distinct tx ids failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_026_detect_double_spend_rejects_batches_over_max_txs_per_block() -> TestResult {
    let system = DetectionSystem::new();
    let max = GlobalConfiguration::MAX_TXS_PER_BLOCK;

    let too_many = (0..=max).map(|index| format!("tx-{index}"));

    assert_validation_error(system.detect_double_spend(too_many))?;
    Ok(())
}

#[test]
fn detection_system_027_detect_replay_accepts_unique_tx_signature_pairs() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_replay(vec![
            ("tx-1".to_string(), vec![1, 2, 3]),
            ("tx-2".to_string(), vec![1, 2, 3]),
            ("tx-3".to_string(), vec![3, 2, 1]),
        ])
        .map_err(|e| format!("unique replay scan failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_028_detect_replay_rejects_duplicate_tx_signature_pair() -> TestResult {
    let system = DetectionSystem::new();

    assert_invalid_operation(system.detect_replay(vec![
        ("tx-1".to_string(), vec![9, 9]),
        ("tx-1".to_string(), vec![9, 9]),
    ]))?;

    Ok(())
}

#[test]
fn detection_system_029_detect_replay_rejects_duplicate_tx_id_with_different_signature()
-> TestResult {
    let system = DetectionSystem::new();

    assert_invalid_operation(system.detect_replay(vec![
        ("tx-1".to_string(), vec![1]),
        ("tx-1".to_string(), vec![2]),
    ]))?;

    Ok(())
}

#[test]
fn detection_system_030_detect_replay_rejects_items_over_max_txs_per_block() -> TestResult {
    let system = DetectionSystem::new();
    let max = GlobalConfiguration::MAX_TXS_PER_BLOCK;

    let too_many = (0..=max).map(|index| (format!("tx-{index}"), vec![1, 2, 3]));

    assert_validation_error(system.detect_replay(too_many))?;
    Ok(())
}

#[test]
fn detection_system_031_detect_51_percent_attack_rejects_zero_total_hash_rate() -> TestResult {
    let system = DetectionSystem::new();

    assert_validation_error(system.detect_51_percent_attack(1, 0))?;
    Ok(())
}

#[test]
fn detection_system_032_detect_51_percent_attack_allows_exact_threshold_share() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_51_percent_attack(GlobalConfiguration::ATTACK_THRESHOLD, 100)
        .map_err(|e| format!("exact threshold should be allowed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_033_detect_51_percent_attack_rejects_above_threshold_share() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_51_percent_attack(GlobalConfiguration::ATTACK_THRESHOLD + 1, 100) {
        Err(ErrorDetection::BlockchainError { details }) => {
            assert!(details.contains("51% attack"));
            assert!(details.contains("52.00%"));
        }
        other => return Err(format!("expected BlockchainError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_034_detect_51_percent_attack_handles_u64_max_without_overflow() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_51_percent_attack(u64::MAX, u64::MAX) {
        Err(ErrorDetection::BlockchainError { details }) => {
            assert!(details.contains("51% attack"));
            assert!(details.contains("100.00%"));
        }
        other => return Err(format!("expected BlockchainError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_035_detect_sybil_attack_accepts_unique_canonical_node_ids() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_sybil_attack(vec![
            ("node-a".to_string(), 1),
            ("node-b".to_string(), 1),
            ("node-c".to_string(), 1),
        ])
        .map_err(|e| format!("unique sybil scan failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_036_detect_sybil_attack_rejects_case_insensitive_duplicate_ids() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_sybil_attack(vec![("Node-A".to_string(), 1), (" node-a ".to_string(), 9)]) {
        Err(ErrorDetection::BlockchainError { details }) => {
            assert!(details.contains("Sybil attack"));
            assert!(details.contains("node-a"));
        }
        other => return Err(format!("expected BlockchainError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_037_detect_sybil_attack_rejects_empty_node_id() -> TestResult {
    let system = DetectionSystem::new();

    assert_validation_error(system.detect_sybil_attack(vec![("   ".to_string(), 1)]))?;
    Ok(())
}

#[test]
fn detection_system_038_detect_sybil_attack_rejects_overlength_node_id() -> TestResult {
    let system = DetectionSystem::new();
    let too_long = "a".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN.saturating_add(1));

    assert_validation_error(system.detect_sybil_attack(vec![(too_long, 1)]))?;
    Ok(())
}

#[test]
fn detection_system_039_detect_sybil_attack_rejects_scan_over_max_identities() -> TestResult {
    let system = DetectionSystem::new();

    let too_many =
        (0..=GlobalConfiguration::MAX_IDENTITIES).map(|index| (format!("node-{index}"), 1_u64));

    assert_validation_error(system.detect_sybil_attack(too_many))?;
    Ok(())
}

#[test]
fn detection_system_040_block_hash_size_dataset_and_load_vectors() {
    let ds = DetectionSystem::new();

    let valid_hash = fixed_lower_hash_128();
    ds.check_block_hash_format(&valid_hash)
        .expect("128-char lowercase hex hash must be accepted");

    let too_short_legacy_32_byte_hash = "a".repeat(64);
    let err = ds
        .check_block_hash_format(&too_short_legacy_32_byte_hash)
        .expect_err("legacy 64-char / 32-byte hash must be rejected");

    fixed_assert_validation_message_contains(err, "Invalid block hash");

    let too_long_hash = "a".repeat(129);
    let err = ds
        .check_block_hash_format(&too_long_hash)
        .expect_err("129-char hash must be rejected");

    fixed_assert_validation_message_contains(err, "Invalid block hash");
}

#[test]
fn detection_system_041_clone_preserves_state_but_allows_independent_mutation() -> TestResult {
    let mut original = DetectionSystem::new();

    original
        .add_participant("ClonePeer")
        .map_err(|e| format!("add failed: {e:?}"))?;

    let canonical = canonical_id_for_test("ClonePeer");
    let mut cloned = original.clone();

    assert!(cloned.active_participants.contains(&canonical));

    cloned
        .remove_participant("clonepeer")
        .map_err(|e| format!("remove from clone failed: {e:?}"))?;

    assert!(!cloned.active_participants.contains(&canonical));
    assert!(original.active_participants.contains(&canonical));
    Ok(())
}

#[test]
fn detection_system_042_add_participant_trims_tabs_newlines_and_spaces() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("PeerWhitespace");

    system
        .add_participant("\n\t PeerWhitespace \t\n")
        .map_err(|e| format!("add whitespace participant failed: {e:?}"))?;

    assert!(system.active_participants.contains(&canonical));
    assert!(system.last_active.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_043_long_ids_with_same_prefix_collide_after_capping() {
    let mut ds = DetectionSystem::new();

    let base = "x".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN);
    let long_id_1 = format!("{base}a");
    let long_id_2 = format!("{base}b");

    let err_1 = ds
        .add_participant(&long_id_1)
        .expect_err("first overlength id must be rejected");

    fixed_assert_validation_message_contains(err_1, "exceeds MAX_PEER_ID_B58_LEN");

    let err_2 = ds
        .add_participant(&long_id_2)
        .expect_err("second overlength id must also be rejected");

    fixed_assert_validation_message_contains(err_2, "exceeds MAX_PEER_ID_B58_LEN");

    assert!(
        ds.active_participants.is_empty(),
        "overlength ids are rejected, so no capped-prefix collision should be stored"
    );
}

#[test]
fn detection_system_044_remove_participant_is_case_insensitive_and_trimmed() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("PeerRemove");

    system
        .add_participant("PeerRemove")
        .map_err(|e| format!("add failed: {e:?}"))?;

    system
        .remove_participant(" \t peerremove \n ")
        .map_err(|e| format!("remove failed: {e:?}"))?;

    assert!(!system.active_participants.contains(&canonical));
    assert!(!system.last_active.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_045_update_activity_accepts_overlength_id_with_same_capped_prefix() {
    let mut ds = DetectionSystem::new();

    let exact_id = "p".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN);

    ds.add_participant(&exact_id)
        .expect("exact max-length id should be accepted");

    let overlength_same_prefix = format!("{exact_id}z");

    let err = ds
        .update_participant_activity(&overlength_same_prefix)
        .expect_err("overlength heartbeat id must be rejected, not capped");

    fixed_assert_validation_message_contains(err, "exceeds MAX_PEER_ID_B58_LEN");

    assert!(
        ds.last_active_of(&exact_id).is_some(),
        "original exact-length participant should remain active"
    );
}

#[test]
fn detection_system_046_last_active_of_does_not_cap_overlength_lookup() {
    let mut ds = DetectionSystem::new();

    let exact_id = "q".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN);

    ds.add_participant(&exact_id)
        .expect("exact max-length id should be accepted");

    let overlength_same_prefix = format!("{exact_id}q");

    assert!(
        ds.last_active_of(&exact_id).is_some(),
        "exact id lookup should succeed"
    );

    assert!(
        ds.last_active_of(&overlength_same_prefix).is_none(),
        "overlength lookup must not be capped to the existing exact id"
    );
}

#[test]
fn detection_system_047_add_participant_prunes_unrelated_stale_boot_entry() -> TestResult {
    let mut system = DetectionSystem::new();
    let stale = canonical_id_for_test("StaleBootOnly");

    system.booted_participants.insert(stale.clone());
    system.booted_at.insert(stale.clone(), 0);

    system
        .add_participant("fresh-peer")
        .map_err(|e| format!("add after stale prune failed: {e:?}"))?;

    assert!(!system.booted_participants.contains(&stale));
    assert!(!system.booted_at.contains_key(&stale));
    assert!(system.active_participants.contains("fresh-peer"));
    Ok(())
}

#[test]
fn detection_system_048_booted_list_is_pruned_to_configured_cap() -> TestResult {
    let mut system = DetectionSystem::new();
    let boot_cap = GlobalConfiguration::MAX_VALIDATORS.min(GlobalConfiguration::MAX_IDENTITIES);
    let over_cap = boot_cap.saturating_add(2);

    for index in 0..over_cap {
        let pid = format!("booted-cap-{index}");
        system.booted_participants.insert(pid.clone());
        system.booted_at.insert(pid, u64::MAX);
    }

    system.boot_inactive_participants(Duration::from_secs(u64::MAX));

    assert!(system.booted_participants.len() <= boot_cap);
    assert!(system.booted_at.len() <= boot_cap);
    Ok(())
}

#[test]
fn detection_system_049_remove_participant_rejects_empty_or_whitespace_id() -> TestResult {
    let mut system = DetectionSystem::new();

    match system.remove_participant("") {
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert!(message.contains("Participant id cannot be empty"));
            assert_eq!(tx_id, None);
        }
        other => return Err(format!("expected ValidationError, got {other:?}")),
    }

    match system.remove_participant(" \t\n ") {
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert!(message.contains("Participant id cannot be empty"));
            assert_eq!(tx_id, None);
        }
        other => return Err(format!("expected ValidationError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_050_update_participant_activity_rejects_empty_or_whitespace_id() -> TestResult {
    let mut system = DetectionSystem::new();

    match system.update_participant_activity("") {
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert!(message.contains("Participant id cannot be empty"));
            assert_eq!(tx_id, None);
        }
        other => return Err(format!("expected ValidationError, got {other:?}")),
    }

    match system.update_participant_activity(" \n\t ") {
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert!(message.contains("Participant id cannot be empty"));
            assert_eq!(tx_id, None);
        }
        other => return Err(format!("expected ValidationError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_051_detect_sybil_attack_trims_and_lowercases_unique_ids() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_sybil_attack(vec![
            (" Node-A ".to_string(), 1),
            ("\tnode-b\n".to_string(), 2),
            ("NODE-C".to_string(), 3),
        ])
        .map_err(|e| format!("sybil unique trimmed ids failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_052_detect_sybil_attack_accepts_exact_max_length_node_id() -> TestResult {
    let system = DetectionSystem::new();
    let exact = "a".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN);

    system
        .detect_sybil_attack(vec![(exact, 1)])
        .map_err(|e| format!("exact max length node id failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_053_detect_sybil_attack_duplicate_empty_after_trim_is_validation_error() {
    let ds = DetectionSystem::new();

    let err = ds
        .detect_sybil_attack(vec![("   ".to_string(), 1), ("\t\n ".to_string(), 1)])
        .expect_err("empty-after-trim node id must be rejected as validation error");

    fixed_assert_validation_message_contains(err, "Participant id cannot be empty");
}

#[test]
fn detection_system_054_detect_51_percent_attack_allows_zero_attacker_hashrate() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_51_percent_attack(0, 100)
        .map_err(|e| format!("zero attacker hash rate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_055_detect_51_percent_attack_allows_large_below_threshold_values() -> TestResult
{
    let system = DetectionSystem::new();

    system
        .detect_51_percent_attack(u64::MAX / 4, u64::MAX)
        .map_err(|e| format!("large below-threshold values failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_056_detect_51_percent_attack_rejects_attacker_equal_total() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_51_percent_attack(777, 777) {
        Err(ErrorDetection::BlockchainError { details }) => {
            assert!(details.contains("51% attack"));
            assert!(details.contains("100.00%"));
        }
        other => return Err(format!("expected BlockchainError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_057_detect_51_percent_attack_exact_fractional_vector() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_51_percent_attack(511, 1_000) {
        Err(ErrorDetection::BlockchainError { details }) => {
            assert!(details.contains("51% attack"));
            assert!(details.contains("51.10%"));
        }
        other => return Err(format!("expected BlockchainError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_058_detect_double_spend_duplicate_empty_tx_id_is_detected() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_double_spend(vec![String::new(), "tx-ok".to_string(), String::new()]) {
        Err(ErrorDetection::DoubleSpending { tx_id }) => {
            assert_eq!(tx_id, Some(String::new()));
        }
        other => return Err(format!("expected DoubleSpending, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_059_detect_double_spend_duplicate_adjacent_tx_id_is_detected() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_double_spend(vec!["same".to_string(), "same".to_string()]) {
        Err(ErrorDetection::DoubleSpending { tx_id }) => {
            assert_eq!(tx_id, Some("same".to_string()));
        }
        other => return Err(format!("expected DoubleSpending, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_060_detect_replay_allows_same_signature_with_different_tx_ids() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_replay(vec![
            ("tx-a".to_string(), vec![7, 7, 7]),
            ("tx-b".to_string(), vec![7, 7, 7]),
        ])
        .map_err(|e| format!("same signature with different tx ids failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_061_detect_replay_duplicate_tx_with_empty_signature_is_detected() -> TestResult
{
    let system = DetectionSystem::new();

    assert_invalid_operation(system.detect_replay(vec![
        ("tx-empty-sig".to_string(), Vec::new()),
        ("tx-empty-sig".to_string(), Vec::new()),
    ]))?;

    Ok(())
}

#[test]
fn detection_system_062_detect_replay_allows_empty_signatures_for_unique_tx_ids() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_replay(vec![
            ("tx-empty-1".to_string(), Vec::new()),
            ("tx-empty-2".to_string(), Vec::new()),
        ])
        .map_err(|e| format!("unique tx ids with empty signatures failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_063_check_block_size_rejects_usize_max() -> TestResult {
    let system = DetectionSystem::new();

    assert_validation_error(system.check_block_size(usize::MAX))?;
    Ok(())
}

#[test]
fn detection_system_064_check_block_hash_format_accepts_uppercase_hex() {
    let ds = DetectionSystem::new();

    let uppercase_hash = fixed_upper_hash_128();

    ds.check_block_hash_format(&uppercase_hash)
        .expect("128-char uppercase hex hash should be accepted by hex::decode");
}

#[test]
fn detection_system_065_check_block_hash_format_rejects_empty_and_whitespace() -> TestResult {
    let system = DetectionSystem::new();

    assert_validation_error(system.check_block_hash_format(""))?;
    assert_validation_error(system.check_block_hash_format(" ".repeat(64).as_str()))?;
    Ok(())
}

#[test]
fn detection_system_066_check_block_hash_format_accepts_mixed_digit_hex_vector() {
    let ds = DetectionSystem::new();

    let mixed_hash = fixed_mixed_hash_128();

    assert_eq!(
        mixed_hash.len(),
        128,
        "test vector must be 128 hex chars / 64 bytes"
    );

    ds.check_block_hash_format(&mixed_hash)
        .expect("128-char mixed-case valid hex hash should be accepted");
}

#[test]
fn detection_system_067_verify_dataset_consistency_reports_first_failing_dataset() -> TestResult {
    let system = DetectionSystem::new();

    match system.verify_dataset_consistency(vec![
        ("headers".to_string(), true),
        ("accounts".to_string(), false),
        ("transactions".to_string(), false),
    ]) {
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert!(message.contains("accounts"));
            assert!(!message.contains("transactions"));
            assert_eq!(tx_id, None);
        }
        other => return Err(format!("expected ValidationError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_068_verify_dataset_consistency_accepts_unicode_dataset_names_when_ok()
-> TestResult {
    let system = DetectionSystem::new();

    system
        .verify_dataset_consistency(vec![
            ("状態".to_string(), true),
            ("данные".to_string(), true),
        ])
        .map_err(|e| format!("unicode dataset names failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_069_validate_state_cap_violation_takes_priority_over_boot_intersection()
-> TestResult {
    let mut system = DetectionSystem::new();
    system.max_participants = 0;
    system
        .active_participants
        .insert("priority-peer".to_string());
    system
        .booted_participants
        .insert("priority-peer".to_string());

    match system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?
    {
        DetectionOutcome::Critical(message) => {
            assert!(message.contains("exceed maximum"));
        }
        other => return Err(format!("expected cap Critical, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_070_validate_state_boot_intersection_takes_priority_over_ok_state() -> TestResult
{
    let mut system = DetectionSystem::new();

    system.active_participants.insert("boot-active".to_string());
    system.booted_participants.insert("boot-active".to_string());

    match system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?
    {
        DetectionOutcome::Critical(message) => {
            assert!(message.contains("Booted participants present"));
        }
        other => {
            return Err(format!(
                "expected boot intersection Critical, got {other:?}"
            ));
        }
    }

    Ok(())
}

#[test]
fn detection_system_071_stale_booted_same_id_is_pruned_before_add() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("StaleSameId");

    system.booted_participants.insert(canonical.clone());
    system.booted_at.insert(canonical.clone(), 0);

    system
        .add_participant("StaleSameId")
        .map_err(|e| format!("add after stale same-id prune failed: {e:?}"))?;

    assert!(system.active_participants.contains(&canonical));
    assert!(!system.booted_participants.contains(&canonical));
    Ok(())
}

#[test]
fn detection_system_072_effective_capacity_uses_max_validators_when_local_cap_is_higher()
-> TestResult {
    let mut system = DetectionSystem::new();
    system.max_participants = u64::MAX;

    for index in 0..GlobalConfiguration::MAX_VALIDATORS {
        system
            .active_participants
            .insert(format!("validator-cap-{index}"));
    }

    match system.add_participant("one-too-many") {
        Err(ErrorDetection::CapacityError { message }) => {
            assert!(message.contains("Maximum participant limit reached"));
        }
        other => return Err(format!("expected CapacityError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_073_add_participant_rolls_back_if_last_active_exceeds_identity_cap()
-> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("RollbackPeer");

    for index in 0..GlobalConfiguration::MAX_IDENTITIES {
        system
            .last_active
            .insert(format!("dummy-last-active-{index}"), 1);
    }

    match system.add_participant("RollbackPeer") {
        Err(ErrorDetection::CapacityError { message }) => {
            assert!(message.contains("last_active map exceeded MAX_IDENTITIES"));
        }
        other => return Err(format!("expected CapacityError, got {other:?}")),
    }

    assert!(!system.active_participants.contains(&canonical));
    assert!(!system.last_active.contains_key(&canonical));
    assert_eq!(
        system.last_active.len(),
        GlobalConfiguration::MAX_IDENTITIES
    );
    Ok(())
}

#[test]
fn detection_system_074_boot_inactive_prunes_old_boot_records_even_without_active_peers()
-> TestResult {
    let mut system = DetectionSystem::new();
    let stale = canonical_id_for_test("OldBootRecord");

    system.booted_participants.insert(stale.clone());
    system.booted_at.insert(stale.clone(), 0);

    system.boot_inactive_participants(Duration::from_secs(u64::MAX));

    assert!(!system.booted_participants.contains(&stale));
    assert!(!system.booted_at.contains_key(&stale));
    Ok(())
}

#[test]
fn detection_system_075_public_reward_and_cap_fields_can_be_mutated_without_side_effects()
-> TestResult {
    let mut system = DetectionSystem::new();

    system.current_reward = 123;
    system.participant_reward = 4.5;
    system.max_participants = 2;

    assert_eq!(system.current_reward, 123);
    assert_eq!(system.participant_reward.to_bits(), 4.5_f64.to_bits());
    assert_eq!(system.max_participants, 2);
    assert!(system.active_participants.is_empty());
    Ok(())
}

#[test]
fn detection_system_076_detection_outcome_equality_and_debug_vectors() -> TestResult {
    assert_eq!(DetectionOutcome::Ok, DetectionOutcome::Ok);
    assert_eq!(
        DetectionOutcome::Warning("warn".to_string()),
        DetectionOutcome::Warning("warn".to_string())
    );
    assert_eq!(
        DetectionOutcome::Critical("critical".to_string()),
        DetectionOutcome::Critical("critical".to_string())
    );

    assert!(format!("{:?}", DetectionOutcome::Ok).contains("Ok"));
    assert!(format!("{:?}", DetectionOutcome::Warning("w".to_string())).contains("Warning"));
    assert!(format!("{:?}", DetectionOutcome::Critical("c".to_string())).contains("Critical"));
    Ok(())
}

#[test]
fn detection_system_077_load_add_and_remove_many_participants() -> TestResult {
    let mut system = DetectionSystem::new();

    for index in 0..1_000 {
        system
            .add_participant(&format!("load-peer-{index}"))
            .map_err(|e| format!("load add failed at {index}: {e:?}"))?;
    }

    assert_eq!(system.active_participants.len(), 1_000);
    assert_eq!(system.last_active.len(), 1_000);

    for index in 0..1_000 {
        system
            .remove_participant(&format!("LOAD-PEER-{index}"))
            .map_err(|e| format!("load remove failed at {index}: {e:?}"))?;
    }

    assert!(system.active_participants.is_empty());
    assert!(system.last_active.is_empty());
    Ok(())
}

#[test]
fn detection_system_078_load_detect_replay_many_unique_items() -> TestResult {
    let system = DetectionSystem::new();

    let items = (0_u64..2_000_u64).map(|index| {
        let reduced = index.rem_euclid(251);
        let byte = u8::try_from(reduced).unwrap_or(0);
        (
            format!("replay-load-{index}"),
            vec![byte, byte.wrapping_add(1)],
        )
    });

    system
        .detect_replay(items)
        .map_err(|e| format!("load replay unique items failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_079_load_detect_sybil_many_unique_nodes() -> TestResult {
    let system = DetectionSystem::new();

    let nodes = (0..2_000).map(|index| (format!("sybil-load-node-{index}"), 1_u64));

    system
        .detect_sybil_attack(nodes)
        .map_err(|e| format!("load sybil unique nodes failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_080_load_detect_double_spend_many_unique_tx_ids() -> TestResult {
    let system = DetectionSystem::new();

    let tx_ids = (0..GlobalConfiguration::MAX_TXS_PER_BLOCK)
        .map(|index| format!("double-spend-load-{index}"));

    system
        .detect_double_spend(tx_ids)
        .map_err(|e| format!("load double-spend unique tx ids failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_081_add_participant_accepts_exact_max_length_identifier() -> TestResult {
    let mut system = DetectionSystem::new();
    let exact = "Z".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN);
    let canonical = "z".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN);

    system
        .add_participant(&exact)
        .map_err(|e| format!("exact max participant id failed: {e:?}"))?;

    assert!(system.active_participants.contains(&canonical));
    assert!(system.last_active.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_082_add_participant_preserves_internal_whitespace_after_boundary_trim()
-> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = "peer internal space";

    system
        .add_participant("  Peer Internal Space  ")
        .map_err(|e| format!("internal whitespace participant failed: {e:?}"))?;

    assert!(system.active_participants.contains(canonical));
    assert!(system.last_active.contains_key(canonical));
    Ok(())
}

#[test]
fn detection_system_083_boot_inactive_does_not_boot_future_timestamp_even_with_zero_window()
-> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("FuturePeer");

    system
        .add_participant("FuturePeer")
        .map_err(|e| format!("add failed: {e:?}"))?;
    system.last_active.insert(canonical.clone(), u64::MAX);

    system.boot_inactive_participants(Duration::from_secs(0));

    assert!(system.active_participants.contains(&canonical));
    assert!(system.last_active.contains_key(&canonical));
    assert!(!system.booted_participants.contains(&canonical));
    Ok(())
}

#[test]
fn detection_system_084_boot_prune_keeps_recent_future_timestamp_boot_record() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("FutureBootRecord");

    system.booted_participants.insert(canonical.clone());
    system.booted_at.insert(canonical.clone(), u64::MAX);

    system.boot_inactive_participants(Duration::from_secs(u64::MAX));

    assert!(system.booted_participants.contains(&canonical));
    assert!(system.booted_at.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_085_active_participant_without_last_active_is_not_booted_by_scan() -> TestResult
{
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("NoHeartbeatRecord");

    system.active_participants.insert(canonical.clone());

    system.boot_inactive_participants(Duration::from_secs(0));

    assert!(system.active_participants.contains(&canonical));
    assert!(!system.booted_participants.contains(&canonical));

    let outcome = system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?;
    assert_eq!(outcome, DetectionOutcome::Ok);
    Ok(())
}

#[test]
fn detection_system_086_remove_missing_active_peer_does_not_remove_orphan_stake() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("StakeOnly");

    system.validator_stakes.insert(canonical.clone(), 9_999);

    match system.remove_participant("StakeOnly") {
        Err(ErrorDetection::NotFound { resource }) => {
            assert!(resource.contains("StakeOnly"));
        }
        other => return Err(format!("expected NotFound, got {other:?}")),
    }

    assert_eq!(system.validator_stakes.get(&canonical), Some(&9_999));
    Ok(())
}

#[test]
fn detection_system_087_add_participant_does_not_create_default_stake_entry() -> TestResult {
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("NoStakeYet");

    system
        .add_participant("NoStakeYet")
        .map_err(|e| format!("add failed: {e:?}"))?;

    assert!(system.active_participants.contains(&canonical));
    assert!(!system.validator_stakes.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_088_sybil_duplicate_detection_ignores_weight_changes() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_sybil_attack(vec![
        ("same-node".to_string(), 1),
        ("SAME-NODE".to_string(), u64::MAX),
    ]) {
        Err(ErrorDetection::BlockchainError { details }) => {
            assert!(details.contains("Sybil attack"));
            assert!(details.contains("same-node"));
        }
        other => return Err(format!("expected BlockchainError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_089_sybil_unique_ids_accept_zero_and_max_weights() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_sybil_attack(vec![
            ("weight-zero".to_string(), 0),
            ("weight-max".to_string(), u64::MAX),
        ])
        .map_err(|e| format!("sybil unique weighted ids failed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_090_double_spend_limit_check_takes_priority_after_max_scan_count() -> TestResult
{
    let system = DetectionSystem::new();

    let unique = (0_u64..GlobalConfiguration::MAX_TXS_PER_BLOCK)
        .map(|index| format!("limit-priority-{index}"));
    let duplicate_after_limit = std::iter::once("limit-priority-0".to_string());
    let tx_ids = unique.chain(duplicate_after_limit);

    assert_validation_error(system.detect_double_spend(tx_ids))?;
    Ok(())
}

#[test]
fn detection_system_091_replay_limit_check_takes_priority_after_max_scan_count() -> TestResult {
    let system = DetectionSystem::new();

    let unique = (0_u64..GlobalConfiguration::MAX_TXS_PER_BLOCK)
        .map(|index| (format!("replay-limit-priority-{index}"), vec![1, 2, 3]));
    let duplicate_after_limit =
        std::iter::once(("replay-limit-priority-0".to_string(), vec![9, 9, 9]));
    let items = unique.chain(duplicate_after_limit);

    assert_validation_error(system.detect_replay(items))?;
    Ok(())
}

#[test]
fn detection_system_092_replay_duplicate_pair_error_message_identifies_pair_case() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_replay(vec![
        ("tx-pair".to_string(), vec![4, 5, 6]),
        ("tx-pair".to_string(), vec![4, 5, 6]),
    ]) {
        Err(ErrorDetection::InvalidOperation { operation }) => {
            assert!(operation.contains("duplicate (tx_id, sig) pair"));
            assert!(operation.contains("tx-pair"));
        }
        other => return Err(format!("expected InvalidOperation, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_093_replay_duplicate_tx_id_error_message_identifies_key_case() -> TestResult {
    let system = DetectionSystem::new();

    match system.detect_replay(vec![
        ("tx-key".to_string(), vec![1]),
        ("tx-key".to_string(), vec![2]),
    ]) {
        Err(ErrorDetection::InvalidOperation { operation }) => {
            assert!(operation.contains("duplicate tx_id"));
            assert!(operation.contains("tx-key"));
        }
        other => return Err(format!("expected InvalidOperation, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_094_detect_51_percent_attack_allows_exact_fractional_threshold() -> TestResult {
    let system = DetectionSystem::new();

    system
        .detect_51_percent_attack(510, 1_000)
        .map_err(|e| format!("exact 51.00 percent threshold should be allowed: {e:?}"))?;

    Ok(())
}

#[test]
fn detection_system_095_detect_51_percent_attack_rejects_tiny_total_above_threshold() -> TestResult
{
    let system = DetectionSystem::new();

    match system.detect_51_percent_attack(2, 3) {
        Err(ErrorDetection::BlockchainError { details }) => {
            assert!(details.contains("51% attack"));
            assert!(details.contains("66.66%"));
        }
        other => return Err(format!("expected BlockchainError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_096_block_hash_format_rejects_one_char_too_short_and_too_long() -> TestResult {
    let system = DetectionSystem::new();

    assert_validation_error(system.check_block_hash_format(&"a".repeat(63)))?;
    assert_validation_error(system.check_block_hash_format(&"a".repeat(65)))?;
    Ok(())
}

#[test]
fn detection_system_097_dataset_consistency_reports_empty_name_when_empty_dataset_fails()
-> TestResult {
    let system = DetectionSystem::new();

    match system.verify_dataset_consistency(vec![(String::new(), false)]) {
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert!(message.starts_with("Data inconsistency in "));
            assert_eq!(tx_id, None);
        }
        other => return Err(format!("expected ValidationError, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_098_validate_state_warns_even_with_orphan_last_active_and_stakes() -> TestResult
{
    let mut system = DetectionSystem::new();

    system
        .last_active
        .insert("orphan-live".to_string(), u64::MAX);
    system
        .validator_stakes
        .insert("orphan-stake".to_string(), 100);

    match system
        .validate_system_state()
        .map_err(|e| format!("validate failed: {e:?}"))?
    {
        DetectionOutcome::Warning(message) => {
            assert!(message.contains("No active validators"));
        }
        other => return Err(format!("expected Warning, got {other:?}")),
    }

    Ok(())
}

#[test]
fn detection_system_099_remove_active_peer_with_boot_record_leaves_boot_record_intact() -> TestResult
{
    let mut system = DetectionSystem::new();
    let canonical = canonical_id_for_test("RemoveBootedRecord");

    system.active_participants.insert(canonical.clone());
    system.last_active.insert(canonical.clone(), 1);
    system.booted_participants.insert(canonical.clone());
    system.booted_at.insert(canonical.clone(), u64::MAX);

    system
        .remove_participant("RemoveBootedRecord")
        .map_err(|e| format!("remove failed: {e:?}"))?;

    assert!(!system.active_participants.contains(&canonical));
    assert!(!system.last_active.contains_key(&canonical));
    assert!(system.booted_participants.contains(&canonical));
    assert!(system.booted_at.contains_key(&canonical));
    Ok(())
}

#[test]
fn detection_system_100_load_repeated_health_checks_and_block_vectors() {
    let mut ds = DetectionSystem::new();

    for i in 0..100usize {
        let peer_id = format!("load-peer-{i:03}");

        ds.add_participant(&peer_id)
            .unwrap_or_else(|e| panic!("add participant {peer_id} failed: {e:?}"));

        ds.validate_system_state()
            .unwrap_or_else(|e| panic!("validate state after {peer_id} failed: {e:?}"));

        let hash = format!("{:0128x}", i);

        assert_eq!(
            hash.len(),
            128,
            "generated load-test hash must be 128 hex chars"
        );

        ds.check_block_hash_format(&hash)
            .unwrap_or_else(|e| panic!("load hash format failed for {hash}: {e:?}"));
    }
}
