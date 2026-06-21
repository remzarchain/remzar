use fips204::ml_dsa_65;
use fips204::ml_dsa_65::PublicKey as VerifyingKey;
use fips204::traits::SerDes;
use remzar::consensus::por_000_ephemeral_registration::{
    EphemeralRegistry, NodeEphemeral, RegistryData,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::{canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn peer(seed: u64) -> String {
    format!("peer-{seed}")
}

fn snapshot_entry(wallet_addr: String, join_height: u64) -> (String, Option<VerifyingKey>, u64) {
    (wallet_addr, None, join_height)
}

fn reward_delay() -> TestResult<u64> {
    u64::try_from(GlobalConfiguration::REWARD_DELAY_BLOCKS)
        .map_err(|_| test_error("REWARD_DELAY_BLOCKS does not fit in u64"))
}

fn checked_add_u64(lhs: u64, rhs: u64, message: &'static str) -> TestResult<u64> {
    lhs.checked_add(rhs).ok_or_else(|| test_error(message))
}

fn node_wallet_count(node: &NodeEphemeral) -> TestResult<usize> {
    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;
    Ok(guard.wallets.len())
}

fn next_seed(state: &mut u64) -> u64 {
    let next = (*state)
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state = next;
    next
}

fn invalid_char_from_state(state: u64) -> char {
    match state.rem_euclid(8) {
        0 => 'g',
        1 => 'z',
        2 => '!',
        3 => 'O',
        4 => 'l',
        5 => ' ',
        6 => '_',
        _ => '/',
    }
}

fn invalid_body(state: &mut u64) -> String {
    let mut out = String::with_capacity(128);
    for _ in 0_u64..128_u64 {
        out.push(invalid_char_from_state(next_seed(state)));
    }
    out
}

#[test]
fn test_01_new_registry_and_alias_start_empty() {
    let registry = EphemeralRegistry::new();
    let alias_registry = RegistryData::new();

    assert!(registry.wallets.is_empty());
    assert!(registry.join_heights.is_empty());
    assert!(registry.identity_map.is_empty());
    assert!(registry.verifying_keys.is_empty());
    assert!(alias_registry.wallets.is_empty());
}

#[test]
fn test_02_clear_wipes_registered_wallet_height_identity_and_tip() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(1);

    registry.register_wallet_strict(&wallet_a, 10)?;
    registry.associate_identity("peer-a", &wallet_a)?;
    registry.set_tip_snapshot(&wallet_a, 99)?;
    registry.clear();

    assert!(registry.wallets.is_empty());
    assert!(registry.join_heights.is_empty());
    assert!(registry.identity_map.is_empty());
    assert_eq!(registry.tip_snapshot(&wallet_a), None);
    Ok(())
}

#[test]
fn test_03_strict_registration_accepts_canonical_wallet_vector() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(42);

    let registered = registry.register_wallet_strict(&wallet_a, 7)?;

    assert_eq!(registered, wallet_a);
    assert!(registry.is_registered(&wallet_a));
    assert_eq!(registry.snapshot_wallets_and_heights(), vec![(wallet_a, 7)]);
    Ok(())
}

#[test]
fn test_04_strict_registration_trims_and_canonicalizes_uppercase_wallet() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let canonical = wallet(0xabc);
    let uppercase_with_spaces = format!("  {}  ", canonical.to_ascii_uppercase());

    let registered = registry.register_wallet_strict(&uppercase_with_spaces, 11)?;

    assert_eq!(registered, canonical);
    assert_eq!(registered, canon_wallet_id_checked(&uppercase_with_spaces)?);
    assert!(registry.is_registered(&uppercase_with_spaces));
    Ok(())
}

#[test]
fn test_05_duplicate_wallet_registration_rejects_second_insert() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(9);

    registry.register_wallet_strict(&wallet_a, 1)?;
    let duplicate = registry.register_wallet_strict(&wallet_a, 2);

    assert!(duplicate.is_err());
    assert_eq!(registry.snapshot_wallets_and_heights(), vec![(wallet_a, 1)]);
    Ok(())
}

#[test]
fn test_06_invalid_wallet_too_short_rejects() {
    let mut registry = EphemeralRegistry::new();

    let result = registry.register_wallet_strict("r1234", 0);

    assert!(result.is_err());
    assert!(registry.wallets.is_empty());
}

#[test]
fn test_07_invalid_wallet_prefix_rejects() {
    let mut registry = EphemeralRegistry::new();
    let invalid = format!("x{}", "a".repeat(128));

    let result = registry.register_wallet_strict(&invalid, 0);

    assert!(result.is_err());
    assert!(registry.wallets.is_empty());
}

#[test]
fn test_08_invalid_wallet_non_hex_body_rejects() {
    let mut registry = EphemeralRegistry::new();
    let invalid = format!("r{}", "g".repeat(128));

    let result = registry.register_wallet_strict(&invalid, 0);

    assert!(result.is_err());
    assert!(registry.wallets.is_empty());
}

#[test]
fn test_09_is_registered_returns_false_for_invalid_wallet_inputs() {
    let registry = EphemeralRegistry::new();

    assert!(!registry.is_registered(""));
    assert!(!registry.is_registered("not-a-wallet"));
    assert!(!registry.is_registered(&format!("r{}", "z".repeat(128))));
}

#[test]
fn test_10_sorted_wallets_are_deterministic() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_c = wallet(3);
    let wallet_a = wallet(1);
    let wallet_b = wallet(2);

    registry.register_wallet_strict(&wallet_c, 30)?;
    registry.register_wallet_strict(&wallet_a, 10)?;
    registry.register_wallet_strict(&wallet_b, 20)?;

    assert_eq!(
        registry.sorted_wallets(),
        vec![wallet_a, wallet_b, wallet_c]
    );
    Ok(())
}

#[test]
fn test_11_set_join_height_preserves_first_seen_height() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(11);

    registry.register_wallet_strict(&wallet_a, 100)?;
    registry.set_join_height(&wallet_a, 5)?;

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 100)]
    );
    Ok(())
}

#[test]
fn test_12_eligibility_respects_reward_delay() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(12);
    let join_height = 50_u64;
    let eligible_height = checked_add_u64(
        join_height,
        reward_delay()?,
        "eligible height overflowed in test",
    )?;

    registry.register_wallet_strict(&wallet_a, join_height)?;

    assert!(!registry.eligible(&wallet_a, join_height));
    assert!(registry.eligible(&wallet_a, eligible_height));
    Ok(())
}

#[test]
fn test_13_eligibility_uses_saturating_join_height_addition() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(13);

    registry.register_wallet_strict(&wallet_a, u64::MAX)?;

    assert!(!registry.eligible(&wallet_a, u64::MAX.saturating_sub(1)));
    assert!(registry.eligible(&wallet_a, u64::MAX));
    Ok(())
}

#[test]
fn test_14_associate_identity_maps_peer_to_registered_wallet() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(14);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.associate_identity("peer-main", &wallet_a)?;

    assert_eq!(registry.wallet_for_peer("peer-main"), Some(wallet_a));
    Ok(())
}

#[test]
fn test_15_associate_identity_rejects_unregistered_wallet() {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(15);

    let result = registry.associate_identity("peer-main", &wallet_a);

    assert!(result.is_err());
    assert_eq!(registry.wallet_for_peer("peer-main"), None);
}

#[test]
fn test_16_associate_identity_rejects_empty_peer_id() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(16);

    registry.register_wallet_strict(&wallet_a, 1)?;

    assert!(registry.associate_identity("", &wallet_a).is_err());
    Ok(())
}

#[test]
fn test_17_associate_identity_rejects_peer_id_over_cap() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(17);
    let too_long_len = GlobalConfiguration::MAX_PEER_ID_B58_LEN
        .checked_add(1)
        .ok_or_else(|| test_error("peer id length overflowed in test"))?;
    let too_long_peer = "p".repeat(too_long_len);

    registry.register_wallet_strict(&wallet_a, 1)?;

    assert!(
        registry
            .associate_identity(&too_long_peer, &wallet_a)
            .is_err()
    );
    Ok(())
}

#[test]
fn test_18_associate_identity_rejects_non_ascii_peer_id() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(18);

    registry.register_wallet_strict(&wallet_a, 1)?;

    assert!(registry.associate_identity("peer-☃", &wallet_a).is_err());
    Ok(())
}

#[test]
fn test_19_associate_identity_allows_peer_remap_to_new_registered_wallet() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(19);
    let wallet_b = wallet(20);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.associate_identity("peer-shared", &wallet_a)?;
    registry.associate_identity("peer-shared", &wallet_b)?;

    assert_eq!(registry.wallet_for_peer("peer-shared"), Some(wallet_b));
    Ok(())
}

#[test]
fn test_20_unregister_wallet_removes_membership_metadata_identity_and_tip() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(21);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.associate_identity("peer-remove", &wallet_a)?;
    registry.set_tip_snapshot(&wallet_a, 88)?;

    assert!(registry.unregister_wallet(&wallet_a));
    assert!(!registry.is_registered(&wallet_a));
    assert_eq!(registry.wallet_for_peer("peer-remove"), None);
    assert_eq!(registry.tip_snapshot(&wallet_a), None);
    assert!(registry.join_heights.is_empty());
    Ok(())
}

#[test]
fn test_21_unregister_wallet_returns_false_for_invalid_or_missing_wallet() {
    let mut registry = EphemeralRegistry::new();

    assert!(!registry.unregister_wallet("bad-wallet"));
    assert!(!registry.unregister_wallet(&wallet(22)));
}

#[test]
fn test_22_unregister_by_peer_removes_mapped_wallet_and_peer_aliases() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(23);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.associate_identity("peer-primary", &wallet_a)?;
    registry.associate_identity("peer-secondary", &wallet_a)?;

    let removed = registry.unregister_by_peer("peer-primary");

    assert_eq!(removed, Some(wallet_a.clone()));
    assert!(!registry.is_registered(&wallet_a));
    assert_eq!(registry.wallet_for_peer("peer-primary"), None);
    assert_eq!(registry.wallet_for_peer("peer-secondary"), None);
    Ok(())
}

#[test]
fn test_23_unregister_by_peer_returns_none_for_unknown_peer() {
    let mut registry = EphemeralRegistry::new();

    assert_eq!(registry.unregister_by_peer("peer-missing"), None);
}

#[test]
fn test_24_set_tip_snapshot_records_tip_and_recent_tip_status() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(24);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.set_tip_snapshot(&wallet_a, 500)?;

    assert_eq!(registry.tip_snapshot(&wallet_a), Some(500));
    assert!(registry.has_recent_tip_snapshot(&wallet_a, 500));
    assert!(!registry.has_recent_tip_snapshot(&wallet_a, 501));
    Ok(())
}

#[test]
fn test_25_set_tip_snapshot_rejects_unregistered_wallet() {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(25);

    let result = registry.set_tip_snapshot(&wallet_a, 1);

    assert!(result.is_err());
    assert_eq!(registry.tip_snapshot(&wallet_a), None);
}

#[test]
fn test_26_max_tip_snapshot_tracks_highest_tip() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(26);
    let wallet_b = wallet(27);
    let wallet_c = wallet(28);

    assert_eq!(registry.max_tip_snapshot(), None);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.register_wallet_strict(&wallet_c, 3)?;
    registry.set_tip_snapshot(&wallet_a, 100)?;
    registry.set_tip_snapshot(&wallet_b, 300)?;
    registry.set_tip_snapshot(&wallet_c, 200)?;

    assert_eq!(registry.max_tip_snapshot(), Some(300));
    Ok(())
}

#[test]
fn test_27_wallets_with_tip_at_least_filters_missing_and_low_tips() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(29);
    let wallet_b = wallet(30);
    let wallet_c = wallet(31);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.register_wallet_strict(&wallet_c, 3)?;
    registry.set_tip_snapshot(&wallet_a, 10)?;
    registry.set_tip_snapshot(&wallet_c, 30)?;

    assert_eq!(registry.wallets_with_tip_at_least(20), vec![wallet_c]);
    Ok(())
}

#[test]
fn test_28_heartbeat_finalize_keeps_seen_wallets_and_drops_missed_wallets() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(32);
    let wallet_b = wallet(33);
    let wallet_c = wallet(34);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.register_wallet_strict(&wallet_c, 3)?;
    registry.associate_identity("peer-a", &wallet_a)?;
    registry.associate_identity("peer-b", &wallet_b)?;
    registry.associate_identity("peer-c", &wallet_c)?;

    registry.begin_heartbeat_round();
    registry.note_heartbeat_round(&wallet_a, 100)?;
    registry.note_heartbeat_round(&wallet_c, 300)?;
    registry.finalize_heartbeat_round();

    assert!(registry.is_registered(&wallet_a));
    assert!(!registry.is_registered(&wallet_b));
    assert!(registry.is_registered(&wallet_c));
    assert_eq!(registry.wallet_for_peer("peer-b"), None);
    assert_eq!(registry.wallet_for_peer("peer-a"), Some(wallet_a));
    assert_eq!(registry.wallet_for_peer("peer-c"), Some(wallet_c));
    Ok(())
}

#[test]
fn test_29_empty_heartbeat_round_finalize_clears_registry() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(35);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.set_tip_snapshot(&wallet_a, 123)?;
    registry.begin_heartbeat_round();
    registry.finalize_heartbeat_round();

    assert!(registry.wallets.is_empty());
    assert!(registry.join_heights.is_empty());
    assert_eq!(registry.tip_snapshot(&wallet_a), None);
    Ok(())
}

#[test]
fn test_30_note_heartbeat_can_register_wallet_with_neutral_join_height() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(36);

    let noted = registry.note_heartbeat_round(&wallet_a, 777)?;

    assert_eq!(noted, wallet_a);
    assert!(registry.is_registered(&noted));
    assert_eq!(registry.tip_snapshot(&noted), Some(777));
    assert_eq!(registry.snapshot_wallets_and_heights(), vec![(noted, 0)]);
    Ok(())
}

#[test]
fn test_31_heartbeat_preserves_existing_join_height_and_updates_tip() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(37);

    registry.register_wallet_strict(&wallet_a, 44)?;
    registry.begin_heartbeat_round();
    registry.note_heartbeat_round(&wallet_a, 1_000)?;
    registry.finalize_heartbeat_round();

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a.clone(), 44)]
    );
    assert_eq!(registry.tip_snapshot(&wallet_a), Some(1_000));
    Ok(())
}

#[test]
fn test_32_snapshot_wallets_and_heights_returns_sorted_height_pairs() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(38);
    let wallet_b = wallet(39);
    let wallet_c = wallet(40);

    registry.register_wallet_strict(&wallet_c, 30)?;
    registry.register_wallet_strict(&wallet_a, 10)?;
    registry.register_wallet_strict(&wallet_b, 20)?;

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 10), (wallet_b, 20), (wallet_c, 30)]
    );
    Ok(())
}

#[test]
fn test_33_rebuild_from_snapshot_checked_applies_valid_entries() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(41);
    let wallet_b = wallet(42);
    let entries = vec![
        snapshot_entry(wallet_b.clone(), 22),
        snapshot_entry(wallet_a.clone(), 11),
    ];

    registry.rebuild_from_snapshot_checked(entries)?;

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 11), (wallet_b, 22)]
    );
    Ok(())
}

#[test]
fn test_34_rebuild_from_snapshot_checked_rejects_invalid_entry_after_clearing_old_state()
-> TestResult {
    let mut registry = EphemeralRegistry::new();
    let old_wallet = wallet(43);

    registry.register_wallet_strict(&old_wallet, 1)?;

    let result =
        registry.rebuild_from_snapshot_checked(vec![snapshot_entry("not-a-wallet".to_string(), 9)]);

    assert!(result.is_err());
    assert!(registry.wallets.is_empty());
    assert!(registry.join_heights.is_empty());
    Ok(())
}

#[test]
fn test_35_rebuild_from_snapshot_unchecked_skips_invalid_entries_and_keeps_valid_entries() {
    let mut registry = EphemeralRegistry::new();
    let valid_wallet = wallet(44);
    let entries = vec![
        snapshot_entry("not-a-wallet".to_string(), 1),
        snapshot_entry(valid_wallet.clone(), 2),
    ];

    registry.rebuild_from_snapshot(entries);

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(valid_wallet, 2)]
    );
}

#[test]
fn test_36_register_wallet_from_vk_derives_wallet_and_lookup_round_trips_public_key_bytes()
-> TestResult {
    let mut registry = EphemeralRegistry::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;
    let vk_bytes = vk.clone().into_bytes();
    let expected_wallet = derive_wallet_id_from_pubkey_bytes(&vk_bytes);

    let registered = registry.register_wallet_from_vk(&vk, 77)?;
    let stored_vk = registry
        .lookup_verifying_key(&registered)
        .ok_or_else(|| test_error("verifying key was not stored"))?;

    assert_eq!(registered, expected_wallet);
    assert_eq!(stored_vk.into_bytes(), vk_bytes);
    Ok(())
}

#[test]
fn test_37_register_wallet_from_vk_rejects_duplicate_public_key_wallet() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;

    registry.register_wallet_from_vk(&vk, 1)?;
    let duplicate = registry.register_wallet_from_vk(&vk, 2);

    assert!(duplicate.is_err());
    assert_eq!(registry.verifying_keys.len(), 1);
    Ok(())
}

#[test]
fn test_38_node_ephemeral_wrappers_status_seed_evict_and_clear() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(45);
    let wallet_b = wallet(46);

    assert_eq!(node.status_line(), "[REGISTRY=EPHEMERAL][PoR] validators=0");

    node.register_wallet_strict(&wallet_a, 1)?;
    assert_eq!(node.status_line(), "[REGISTRY=EPHEMERAL][PoR] validators=1");

    node.seed_from_chain_snapshot_checked(vec![
        snapshot_entry(wallet_a.clone(), 10),
        snapshot_entry(wallet_b.clone(), 20),
    ])?;
    node.evict_inactive_validators_result(Duration::ZERO, Duration::from_secs(u64::MAX))?;

    assert_eq!(node_wallet_count(&node)?, 2);

    node.boot_clear_result()?;
    assert_eq!(node_wallet_count(&node)?, 0);
    Ok(())
}

#[test]
fn test_39_fuzz_invalid_wallet_inputs_never_mutate_registry() {
    let mut registry = EphemeralRegistry::new();
    let mut fuzz_state = 1_u64;
    let fixed_cases = vec![
        String::new(),
        "r".to_string(),
        format!("x{}", "a".repeat(128)),
        format!("r{}", "g".repeat(128)),
        format!("r{}", "a".repeat(127)),
        format!("r{}", "a".repeat(129)),
        "☃".to_string(),
        format!("r{}z", "a".repeat(127)),
    ];

    for candidate in fixed_cases {
        assert!(registry.register_wallet_strict(&candidate, 0).is_err());
        assert!(registry.wallets.is_empty());
    }

    for seed in 0_u64..128_u64 {
        let prefix = if seed.rem_euclid(2) == 0 { "x" } else { "r" };
        let candidate = format!("{prefix}{}", invalid_body(&mut fuzz_state));

        assert!(registry.register_wallet_strict(&candidate, seed).is_err());
        assert!(registry.wallets.is_empty());
    }
}

#[test]
fn test_40_property_adversarial_network_and_load_cap_behavior() -> TestResult {
    let mut registry = EphemeralRegistry::new();

    for seed in 100_u64..132_u64 {
        registry.register_wallet_strict(&wallet(seed), seed)?;
    }

    let snapshot = registry.snapshot_wallets_and_heights();
    let mut rebuilt = EphemeralRegistry::new();
    let rebuild_entries = snapshot
        .iter()
        .cloned()
        .map(|(wallet_addr, join_height)| snapshot_entry(wallet_addr, join_height));

    rebuilt.rebuild_from_snapshot_checked(rebuild_entries)?;
    assert_eq!(rebuilt.snapshot_wallets_and_heights(), snapshot);

    rebuilt.begin_heartbeat_round();

    let alive_seeds = [100_u64, 102_u64, 105_u64, 107_u64, 111_u64, 131_u64];
    let mut alive_wallets = BTreeSet::new();

    for seed in alive_seeds {
        let wallet_addr = wallet(seed);
        let inserted = alive_wallets.insert(wallet_addr.clone());
        assert!(inserted);
        rebuilt
            .note_heartbeat_round(&wallet_addr, checked_add_u64(seed, 1_000, "tip overflow")?)?;
    }

    rebuilt.finalize_heartbeat_round();

    for seed in 100_u64..132_u64 {
        let wallet_addr = wallet(seed);
        if alive_wallets.contains(&wallet_addr) {
            assert!(rebuilt.is_registered(&wallet_addr));
        } else {
            assert!(!rebuilt.is_registered(&wallet_addr));
        }
    }

    let mut loaded = EphemeralRegistry::new();
    let validator_cap = u64::try_from(GlobalConfiguration::MAX_VALIDATORS)
        .map_err(|_| test_error("MAX_VALIDATORS does not fit in u64"))?;

    for seed in 0_u64..validator_cap {
        loaded.register_wallet_strict(&wallet(seed), seed)?;
    }

    assert_eq!(loaded.wallets.len(), GlobalConfiguration::MAX_VALIDATORS);
    assert!(
        loaded
            .register_wallet_strict(&wallet(validator_cap), validator_cap)
            .is_err()
    );

    let node = NodeEphemeral::new();
    for seed in 200_u64..232_u64 {
        node.register_wallet_strict(&wallet(seed), seed)?;
        node.map_peer_identity(&peer(seed), &wallet(seed))?;
    }

    node.begin_heartbeat_round_result()?;
    for seed in 200_u64..216_u64 {
        node.note_heartbeat_round(
            &wallet(seed),
            checked_add_u64(seed, 2_000, "node tip overflow")?,
        )?;
    }
    node.finalize_heartbeat_round_result()?;

    assert_eq!(node_wallet_count(&node)?, 16);
    assert_eq!(node.max_tip_snapshot(), Some(2_215));
    Ok(())
}

#[test]
fn test_41_debug_output_reports_public_collection_lengths_without_requiring_vk_debug() -> TestResult
{
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(141);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.associate_identity("peer-debug", &wallet_a)?;
    registry.set_tip_snapshot(&wallet_a, 77)?;

    let debug_text = format!("{registry:?}");

    assert!(debug_text.contains("EphemeralRegistry"));
    assert!(debug_text.contains("wallets_len"));
    assert!(debug_text.contains("join_heights_len"));
    assert!(debug_text.contains("identity_map_len"));
    assert!(debug_text.contains("tip_snapshots_len"));
    Ok(())
}

#[test]
fn test_42_cloned_registry_preserves_snapshot_but_mutates_independently() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(142);
    let wallet_b = wallet(143);

    registry.register_wallet_strict(&wallet_a, 10)?;

    let mut cloned = registry.clone();
    cloned.register_wallet_strict(&wallet_b, 20)?;

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a.clone(), 10)]
    );
    assert_eq!(
        cloned.snapshot_wallets_and_heights(),
        vec![(wallet_a, 10), (wallet_b, 20)]
    );
    Ok(())
}

#[test]
fn test_43_node_from_registry_exposes_seeded_registry_state() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(144);
    let wallet_b = wallet(145);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;

    let node = NodeEphemeral::from_registry(registry);

    assert_eq!(node.status_line(), "[REGISTRY=EPHEMERAL][PoR] validators=2");
    assert_eq!(node_wallet_count(&node)?, 2);
    Ok(())
}

#[test]
fn test_44_node_default_matches_new_node_empty_state() -> TestResult {
    let node_new = NodeEphemeral::new();
    let node_default = NodeEphemeral::default();

    assert_eq!(
        node_new.status_line(),
        "[REGISTRY=EPHEMERAL][PoR] validators=0"
    );
    assert_eq!(
        node_default.status_line(),
        "[REGISTRY=EPHEMERAL][PoR] validators=0"
    );
    assert_eq!(node_wallet_count(&node_new)?, 0);
    assert_eq!(node_wallet_count(&node_default)?, 0);
    Ok(())
}

#[test]
fn test_45_node_boot_clear_non_result_clears_registry() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(146);

    node.register_wallet_strict(&wallet_a, 1)?;
    node.boot_clear();

    assert_eq!(node_wallet_count(&node)?, 0);
    assert_eq!(node.status_line(), "[REGISTRY=EPHEMERAL][PoR] validators=0");
    Ok(())
}

#[test]
fn test_46_node_set_join_height_preserves_original_join_height() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(147);

    node.register_wallet_strict(&wallet_a, 40)?;
    node.set_join_height(&wallet_a, 5)?;

    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;

    assert_eq!(guard.snapshot_wallets_and_heights(), vec![(wallet_a, 40)]);
    Ok(())
}

#[test]
fn test_47_node_set_join_height_rejects_unregistered_wallet() {
    let node = NodeEphemeral::new();

    assert!(node.set_join_height(&wallet(148), 1).is_err());
}

#[test]
fn test_48_node_set_tip_snapshot_rejects_invalid_wallet_input() {
    let node = NodeEphemeral::new();

    assert!(node.set_tip_snapshot("not-a-wallet", 1).is_err());
    assert_eq!(node.tip_snapshot("not-a-wallet"), None);
}

#[test]
fn test_49_node_tip_snapshot_canonicalizes_uppercase_wallet_input() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(149);
    let uppercase_with_spaces = format!("  {}  ", wallet_a.to_ascii_uppercase());

    node.register_wallet_strict(&wallet_a, 1)?;
    node.set_tip_snapshot(&uppercase_with_spaces, 321)?;

    assert_eq!(node.tip_snapshot(&wallet_a), Some(321));
    assert_eq!(node.tip_snapshot(&uppercase_with_spaces), Some(321));
    Ok(())
}

#[test]
fn test_50_node_wallets_with_tip_at_least_returns_sorted_wallets() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(150);
    let wallet_b = wallet(151);
    let wallet_c = wallet(152);

    node.register_wallet_strict(&wallet_c, 3)?;
    node.register_wallet_strict(&wallet_a, 1)?;
    node.register_wallet_strict(&wallet_b, 2)?;
    node.set_tip_snapshot(&wallet_c, 30)?;
    node.set_tip_snapshot(&wallet_a, 10)?;
    node.set_tip_snapshot(&wallet_b, 20)?;

    assert_eq!(node.wallets_with_tip_at_least(20), vec![wallet_b, wallet_c]);
    Ok(())
}

#[test]
fn test_51_node_empty_heartbeat_round_finalize_clears_registry() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(153);

    node.register_wallet_strict(&wallet_a, 1)?;
    node.begin_heartbeat_round();
    node.finalize_heartbeat_round();

    assert_eq!(node_wallet_count(&node)?, 0);
    assert_eq!(node.tip_snapshot(&wallet_a), None);
    Ok(())
}

#[test]
fn test_52_node_heartbeat_round_keeps_only_seen_wallets() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(154);
    let wallet_b = wallet(155);
    let wallet_c = wallet(156);

    node.register_wallet_strict(&wallet_a, 1)?;
    node.register_wallet_strict(&wallet_b, 2)?;
    node.register_wallet_strict(&wallet_c, 3)?;

    node.begin_heartbeat_round_result()?;
    node.note_heartbeat_round(&wallet_b, 2_000)?;
    node.finalize_heartbeat_round_result()?;

    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;

    assert!(!guard.is_registered(&wallet_a));
    assert!(guard.is_registered(&wallet_b));
    assert!(!guard.is_registered(&wallet_c));
    assert_eq!(guard.tip_snapshot(&wallet_b), Some(2_000));
    Ok(())
}

#[test]
fn test_53_node_unregister_wallet_removes_peer_identity_and_tip() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(157);

    node.register_wallet_strict(&wallet_a, 1)?;
    node.map_peer_identity("peer-node-remove", &wallet_a)?;
    node.set_tip_snapshot(&wallet_a, 999)?;

    assert!(node.unregister_wallet(&wallet_a));

    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;

    assert!(!guard.is_registered(&wallet_a));
    assert_eq!(guard.wallet_for_peer("peer-node-remove"), None);
    assert_eq!(guard.tip_snapshot(&wallet_a), None);
    Ok(())
}

#[test]
fn test_54_node_unregister_by_invalid_peer_returns_none_and_preserves_state() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(158);

    node.register_wallet_strict(&wallet_a, 1)?;
    node.map_peer_identity("peer-good", &wallet_a)?;

    assert_eq!(node.unregister_by_peer(""), None);
    assert_eq!(node_wallet_count(&node)?, 1);

    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;

    assert_eq!(guard.wallet_for_peer("peer-good"), Some(wallet_a));
    Ok(())
}

#[test]
fn test_55_rebuild_from_snapshot_checked_duplicate_wallet_returns_error_after_first_apply()
-> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(159);

    let result = registry.rebuild_from_snapshot_checked(vec![
        snapshot_entry(wallet_a.clone(), 10),
        snapshot_entry(wallet_a.clone(), 20),
    ]);

    assert!(result.is_err());
    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 10)]
    );
    Ok(())
}

#[test]
fn test_56_rebuild_from_snapshot_unchecked_skips_duplicate_and_continues_to_next_valid_entry() {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(160);
    let wallet_b = wallet(161);

    registry.rebuild_from_snapshot(vec![
        snapshot_entry(wallet_a.clone(), 10),
        snapshot_entry(wallet_a.clone(), 20),
        snapshot_entry(wallet_b.clone(), 30),
    ]);

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 10), (wallet_b, 30)]
    );
}

#[test]
fn test_57_rebuild_from_snapshot_checked_with_vk_derives_wallet_from_key_not_label() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;
    let expected_wallet = derive_wallet_id_from_pubkey_bytes(&vk.clone().into_bytes());

    registry.rebuild_from_snapshot_checked(vec![(
        "not-the-derived-wallet".to_string(),
        Some(vk),
        444,
    )])?;

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(expected_wallet.clone(), 444)]
    );
    assert!(registry.lookup_verifying_key(&expected_wallet).is_some());
    Ok(())
}

#[test]
fn test_58_rebuild_from_snapshot_checked_duplicate_vk_returns_error_and_keeps_first_key()
-> TestResult {
    let mut registry = EphemeralRegistry::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;
    let expected_wallet = derive_wallet_id_from_pubkey_bytes(&vk.clone().into_bytes());

    let result = registry.rebuild_from_snapshot_checked(vec![
        ("first".to_string(), Some(vk.clone()), 1),
        ("second".to_string(), Some(vk), 2),
    ]);

    assert!(result.is_err());
    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(expected_wallet.clone(), 1)]
    );
    assert!(registry.lookup_verifying_key(&expected_wallet).is_some());
    Ok(())
}

#[test]
fn test_59_lookup_verifying_key_returns_none_for_invalid_and_unregistered_wallets() {
    let registry = EphemeralRegistry::new();

    assert!(registry.lookup_verifying_key("not-a-wallet").is_none());
    assert!(registry.lookup_verifying_key(&wallet(162)).is_none());
}

#[test]
fn test_60_unregister_wallet_from_vk_registration_removes_stored_verifying_key() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;

    let wallet_addr = registry.register_wallet_from_vk(&vk, 1)?;

    assert!(registry.lookup_verifying_key(&wallet_addr).is_some());
    assert!(registry.unregister_wallet(&wallet_addr));
    assert!(registry.lookup_verifying_key(&wallet_addr).is_none());
    assert!(registry.verifying_keys.is_empty());
    Ok(())
}

#[test]
fn test_61_heartbeat_note_canonicalizes_uppercase_wallet() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(163);
    let uppercase_with_spaces = format!("  {}  ", wallet_a.to_ascii_uppercase());

    let registered = registry.note_heartbeat_round(&uppercase_with_spaces, 900)?;

    assert_eq!(registered, wallet_a);
    assert_eq!(registry.tip_snapshot(&uppercase_with_spaces), Some(900));
    Ok(())
}

#[test]
fn test_62_set_tip_snapshot_canonicalizes_uppercase_wallet_after_strict_registration() -> TestResult
{
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(164);
    let uppercase_with_spaces = format!("  {}  ", wallet_a.to_ascii_uppercase());

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.set_tip_snapshot(&uppercase_with_spaces, 555)?;

    assert_eq!(registry.tip_snapshot(&wallet_a), Some(555));
    Ok(())
}

#[test]
fn test_63_repeated_heartbeat_for_same_wallet_keeps_latest_tip() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(165);

    registry.begin_heartbeat_round();
    registry.note_heartbeat_round(&wallet_a, 100)?;
    registry.note_heartbeat_round(&wallet_a, 200)?;
    registry.note_heartbeat_round(&wallet_a, 300)?;
    registry.finalize_heartbeat_round();

    assert_eq!(registry.tip_snapshot(&wallet_a), Some(300));
    assert_eq!(registry.snapshot_wallets_and_heights(), vec![(wallet_a, 0)]);
    Ok(())
}

#[test]
fn test_64_finalize_without_begin_keeps_wallets_registered_in_current_seen_set() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(166);
    let wallet_b = wallet(167);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.finalize_heartbeat_round();

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 1), (wallet_b, 2)]
    );
    Ok(())
}

#[test]
fn test_65_begin_round_then_note_unknown_wallet_drops_old_wallet_and_keeps_new_wallet() -> TestResult
{
    let mut registry = EphemeralRegistry::new();
    let old_wallet = wallet(168);
    let new_wallet = wallet(169);

    registry.register_wallet_strict(&old_wallet, 10)?;
    registry.begin_heartbeat_round();
    registry.note_heartbeat_round(&new_wallet, 123)?;
    registry.finalize_heartbeat_round();

    assert!(!registry.is_registered(&old_wallet));
    assert!(registry.is_registered(&new_wallet));
    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(new_wallet, 0)]
    );
    Ok(())
}

#[test]
fn test_66_note_heartbeat_invalid_wallet_returns_error_and_does_not_mutate_registry() -> TestResult
{
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(170);

    registry.register_wallet_strict(&wallet_a, 10)?;
    registry.begin_heartbeat_round();

    assert!(registry.note_heartbeat_round("bad-wallet", 999).is_err());
    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 10)]
    );
    assert_eq!(registry.max_tip_snapshot(), None);
    Ok(())
}

#[test]
fn test_67_note_heartbeat_at_validator_capacity_rejects_new_wallet() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let validator_cap = u64::try_from(GlobalConfiguration::MAX_VALIDATORS)
        .map_err(|_| test_error("MAX_VALIDATORS does not fit in u64"))?;

    for seed in 0_u64..validator_cap {
        registry.register_wallet_strict(&wallet(seed), seed)?;
    }

    assert_eq!(registry.wallets.len(), GlobalConfiguration::MAX_VALIDATORS);
    assert!(
        registry
            .note_heartbeat_round(&wallet(validator_cap), validator_cap)
            .is_err()
    );
    assert_eq!(registry.wallets.len(), GlobalConfiguration::MAX_VALIDATORS);
    Ok(())
}

#[test]
fn test_68_identity_map_capacity_rejects_extra_peer_mapping() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(171);

    registry.register_wallet_strict(&wallet_a, 1)?;

    let identity_cap = u64::try_from(GlobalConfiguration::MAX_IDENTITIES)
        .map_err(|_| test_error("MAX_IDENTITIES does not fit in u64"))?;

    for seed in 0_u64..identity_cap {
        registry.associate_identity(&peer(seed), &wallet_a)?;
    }

    assert_eq!(
        registry.identity_map.len(),
        GlobalConfiguration::MAX_IDENTITIES
    );
    assert!(
        registry
            .associate_identity("peer-overflow", &wallet_a)
            .is_err()
    );
    assert_eq!(
        registry.identity_map.len(),
        GlobalConfiguration::MAX_IDENTITIES
    );
    Ok(())
}

#[test]
fn test_69_wallet_for_peer_returns_owned_clone_not_live_reference() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(172);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.associate_identity("peer-owned-clone", &wallet_a)?;

    let mut returned = registry
        .wallet_for_peer("peer-owned-clone")
        .ok_or_else(|| test_error("peer mapping missing"))?;
    returned.push_str("-mutated");

    assert_eq!(registry.wallet_for_peer("peer-owned-clone"), Some(wallet_a));
    assert!(returned.ends_with("-mutated"));
    Ok(())
}

#[test]
fn test_70_node_clone_shares_same_inner_registry() -> TestResult {
    let node = NodeEphemeral::new();
    let cloned = node.clone();
    let wallet_a = wallet(173);

    node.register_wallet_strict(&wallet_a, 1)?;

    assert_eq!(node_wallet_count(&cloned)?, 1);

    cloned.boot_clear_result()?;

    assert_eq!(node_wallet_count(&node)?, 0);
    assert_eq!(node_wallet_count(&cloned)?, 0);
    Ok(())
}

#[test]
fn test_71_node_ephemeral_handle_can_mutate_inner_registry_seen_by_node() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(174);
    let handle = node.ephemeral();

    {
        let mut guard = handle
            .lock()
            .map_err(|_| io::Error::other("node registry mutex poisoned"))?;
        guard.register_wallet_strict(&wallet_a, 1)?;
    }

    assert_eq!(node.status_line(), "[REGISTRY=EPHEMERAL][PoR] validators=1");
    assert_eq!(node_wallet_count(&node)?, 1);
    Ok(())
}

#[test]
fn test_72_node_seed_from_chain_snapshot_unchecked_skips_invalid_and_applies_valid() -> TestResult {
    let node = NodeEphemeral::new();
    let valid_wallet = wallet(175);

    node.seed_from_chain_snapshot(vec![
        snapshot_entry("invalid-wallet".to_string(), 1),
        snapshot_entry(valid_wallet.clone(), 2),
    ]);

    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;

    assert_eq!(
        guard.snapshot_wallets_and_heights(),
        vec![(valid_wallet, 2)]
    );
    Ok(())
}

#[test]
fn test_73_node_seed_from_chain_snapshot_checked_rejects_invalid_and_clears_previous_state()
-> TestResult {
    let node = NodeEphemeral::new();
    let old_wallet = wallet(176);

    node.register_wallet_strict(&old_wallet, 1)?;

    let result = node
        .seed_from_chain_snapshot_checked(vec![snapshot_entry("invalid-wallet".to_string(), 2)]);

    assert!(result.is_err());
    assert_eq!(node_wallet_count(&node)?, 0);
    Ok(())
}

#[test]
fn test_74_node_register_wallet_from_vk_stores_key_and_allows_tip_tracking() -> TestResult {
    let node = NodeEphemeral::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;
    let expected_wallet = derive_wallet_id_from_pubkey_bytes(&vk.clone().into_bytes());

    let registered = node.register_wallet_from_vk(&vk, 9)?;
    node.set_tip_snapshot(&registered, 808)?;

    assert_eq!(registered, expected_wallet);
    assert_eq!(node.tip_snapshot(&registered), Some(808));
    assert_eq!(node.max_tip_snapshot(), Some(808));

    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;

    assert!(guard.lookup_verifying_key(&registered).is_some());
    Ok(())
}

#[test]
fn test_75_node_unregister_by_peer_removes_wallet_registered_from_vk() -> TestResult {
    let node = NodeEphemeral::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;

    let wallet_addr = node.register_wallet_from_vk(&vk, 1)?;
    node.map_peer_identity("peer-vk-remove", &wallet_addr)?;

    assert_eq!(
        node.unregister_by_peer("peer-vk-remove"),
        Some(wallet_addr.clone())
    );
    assert_eq!(node_wallet_count(&node)?, 0);

    let handle = node.ephemeral();
    let guard = handle
        .lock()
        .map_err(|_| io::Error::other("node registry mutex poisoned"))?;

    assert!(guard.lookup_verifying_key(&wallet_addr).is_none());
    Ok(())
}

#[test]
fn test_76_adversarial_many_peer_aliases_to_one_wallet_all_removed_by_wallet_unregister()
-> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(177);

    registry.register_wallet_strict(&wallet_a, 1)?;

    for seed in 0_u64..32_u64 {
        registry.associate_identity(&format!("alias-peer-{seed}"), &wallet_a)?;
    }

    assert_eq!(registry.identity_map.len(), 32);
    assert!(registry.unregister_wallet(&wallet_a));
    assert!(registry.identity_map.is_empty());
    Ok(())
}

#[test]
fn test_77_property_snapshot_order_independent_across_forward_and_reverse_insertion() -> TestResult
{
    let mut forward = EphemeralRegistry::new();
    let mut reverse = EphemeralRegistry::new();

    for seed in 200_u64..232_u64 {
        forward.register_wallet_strict(&wallet(seed), seed)?;
    }

    for seed in (200_u64..232_u64).rev() {
        reverse.register_wallet_strict(&wallet(seed), seed)?;
    }

    assert_eq!(
        forward.snapshot_wallets_and_heights(),
        reverse.snapshot_wallets_and_heights()
    );
    Ok(())
}

#[test]
fn test_78_fuzz_peer_identity_inputs_reject_invalid_peers_without_mutation() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(178);
    let too_long_len = GlobalConfiguration::MAX_PEER_ID_B58_LEN
        .checked_add(1)
        .ok_or_else(|| test_error("peer id length overflowed in test"))?;
    let invalid_peers = vec![
        String::new(),
        "peer-☃".to_string(),
        "é".repeat(4),
        "p".repeat(too_long_len),
    ];

    registry.register_wallet_strict(&wallet_a, 1)?;

    for invalid_peer in invalid_peers {
        assert!(
            registry
                .associate_identity(&invalid_peer, &wallet_a)
                .is_err()
        );
        assert!(registry.identity_map.is_empty());
    }

    Ok(())
}

#[test]
fn test_79_load_repeated_heartbeat_rounds_preserve_join_heights_and_latest_tips() -> TestResult {
    let mut registry = EphemeralRegistry::new();

    for seed in 300_u64..364_u64 {
        registry.register_wallet_strict(&wallet(seed), seed)?;
    }

    for round in 0_u64..8_u64 {
        registry.begin_heartbeat_round();

        for seed in 300_u64..364_u64 {
            let tip = checked_add_u64(seed, round.saturating_mul(1_000), "tip overflow")?;
            registry.note_heartbeat_round(&wallet(seed), tip)?;
        }

        registry.finalize_heartbeat_round();
    }

    assert_eq!(registry.wallets.len(), 64);
    assert_eq!(registry.max_tip_snapshot(), Some(7_363));

    for seed in 300_u64..364_u64 {
        let wallet_addr = wallet(seed);
        let snapshot = registry.snapshot_wallets_and_heights();
        assert!(snapshot.contains(&(wallet_addr, seed)));
    }

    Ok(())
}

#[test]
fn test_80_adversarial_concurrent_node_registrations_are_serialized_by_mutex() -> TestResult {
    let node = NodeEphemeral::new();

    std::thread::scope(|scope| -> TestResult {
        let mut handles = Vec::new();

        for seed in 400_u64..432_u64 {
            let node_clone = node.clone();
            handles.push(scope.spawn(move || {
                node_clone
                    .register_wallet_strict(&wallet(seed), seed)
                    .map(|_| ())
            }));
        }

        for handle in handles {
            let joined = handle
                .join()
                .map_err(|_| io::Error::other("registration thread panicked"))?;
            joined?;
        }

        Ok(())
    })?;

    assert_eq!(node_wallet_count(&node)?, 32);

    node.begin_heartbeat_round_result()?;

    for seed in 400_u64..416_u64 {
        node.note_heartbeat_round(&wallet(seed), checked_add_u64(seed, 5_000, "tip overflow")?)?;
    }

    node.finalize_heartbeat_round_result()?;

    assert_eq!(node_wallet_count(&node)?, 16);
    assert_eq!(node.max_tip_snapshot(), Some(5_415));
    Ok(())
}

#[test]
fn test_81_vector_wallet_canonicalization_accepts_lower_upper_and_trimmed_inputs() -> TestResult {
    let canonical = wallet(181);
    let vector_cases = [
        ("lowercase", canonical.clone()),
        ("uppercase", canonical.to_ascii_uppercase()),
        (
            "trimmed-uppercase",
            format!(" \n{}\t ", canonical.to_ascii_uppercase()),
        ),
    ];

    for (_case_name, candidate) in vector_cases {
        assert_eq!(canon_wallet_id_checked(&candidate)?, canonical);
    }

    Ok(())
}

#[test]
fn test_82_vector_invalid_wallet_inputs_all_reject_without_registration() {
    let invalid_vectors = [
        String::new(),
        "r".to_string(),
        format!("r{}", "0".repeat(127)),
        format!("r{}", "0".repeat(129)),
        format!("x{}", "0".repeat(128)),
        format!("r{}", "z".repeat(128)),
        format!("r{} {}", "a".repeat(63), "a".repeat(64)),
        "☃".to_string(),
    ];

    let mut registry = EphemeralRegistry::new();

    for candidate in invalid_vectors {
        assert!(registry.register_wallet_strict(&candidate, 1).is_err());
        assert!(registry.wallets.is_empty());
    }
}

#[test]
fn test_83_vector_boundary_wallets_all_zero_and_all_f_are_valid() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let all_zero_wallet = format!("r{}", "0".repeat(128));
    let all_f_wallet = format!("r{}", "f".repeat(128));

    registry.register_wallet_strict(&all_f_wallet, 2)?;
    registry.register_wallet_strict(&all_zero_wallet, 1)?;

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(all_zero_wallet, 1), (all_f_wallet, 2)]
    );
    Ok(())
}

#[test]
fn test_84_vector_peer_id_exact_max_length_is_accepted() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(184);
    let max_peer = "p".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.associate_identity(&max_peer, &wallet_a)?;

    assert_eq!(registry.wallet_for_peer(&max_peer), Some(wallet_a));
    Ok(())
}

#[test]
fn test_85_vector_peer_id_boundary_max_plus_one_is_rejected() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(185);
    let too_long_len = GlobalConfiguration::MAX_PEER_ID_B58_LEN
        .checked_add(1)
        .ok_or_else(|| test_error("peer id length overflowed in test"))?;
    let too_long_peer = "p".repeat(too_long_len);

    registry.register_wallet_strict(&wallet_a, 1)?;

    assert!(
        registry
            .associate_identity(&too_long_peer, &wallet_a)
            .is_err()
    );
    assert!(registry.identity_map.is_empty());
    Ok(())
}

#[test]
fn test_86_edge_join_height_u64_max_is_preserved_in_snapshot() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(186);

    registry.register_wallet_strict(&wallet_a, u64::MAX)?;

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, u64::MAX)]
    );
    Ok(())
}

#[test]
fn test_87_edge_tip_snapshot_u64_max_is_supported() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(187);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.set_tip_snapshot(&wallet_a, u64::MAX)?;

    assert_eq!(registry.tip_snapshot(&wallet_a), Some(u64::MAX));
    assert_eq!(registry.max_tip_snapshot(), Some(u64::MAX));
    assert!(registry.has_recent_tip_snapshot(&wallet_a, u64::MAX));
    Ok(())
}

#[test]
fn test_88_edge_wallets_with_tip_at_least_zero_includes_missing_tip_wallets() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(188);
    let wallet_b = wallet(189);

    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.set_tip_snapshot(&wallet_b, 9)?;

    assert_eq!(
        registry.wallets_with_tip_at_least(0),
        vec![wallet_a, wallet_b]
    );
    Ok(())
}

#[test]
fn test_89_edge_has_recent_tip_snapshot_false_when_tip_is_missing_even_at_zero() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(190);

    registry.register_wallet_strict(&wallet_a, 1)?;

    assert!(!registry.has_recent_tip_snapshot(&wallet_a, 0));
    assert_eq!(registry.tip_snapshot(&wallet_a), None);
    Ok(())
}

#[test]
fn test_90_edge_max_tip_recalculates_after_highest_tip_wallet_removed() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(191);
    let wallet_b = wallet(192);
    let wallet_c = wallet(193);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.register_wallet_strict(&wallet_c, 3)?;
    registry.set_tip_snapshot(&wallet_a, 10)?;
    registry.set_tip_snapshot(&wallet_b, 99)?;
    registry.set_tip_snapshot(&wallet_c, 50)?;

    assert_eq!(registry.max_tip_snapshot(), Some(99));
    assert!(registry.unregister_wallet(&wallet_b));
    assert_eq!(registry.max_tip_snapshot(), Some(50));
    Ok(())
}

#[test]
fn test_91_edge_unregister_by_peer_keeps_unrelated_wallets_and_peer_mappings() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(194);
    let wallet_b = wallet(195);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.associate_identity("peer-a", &wallet_a)?;
    registry.associate_identity("peer-b", &wallet_b)?;

    assert_eq!(
        registry.unregister_by_peer("peer-a"),
        Some(wallet_a.clone())
    );
    assert!(!registry.is_registered(&wallet_a));
    assert!(registry.is_registered(&wallet_b));
    assert_eq!(registry.wallet_for_peer("peer-a"), None);
    assert_eq!(registry.wallet_for_peer("peer-b"), Some(wallet_b));
    Ok(())
}

#[test]
fn test_92_edge_evict_inactive_with_huge_boot_grace_preserves_recent_wallets() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(196);
    let wallet_b = wallet(197);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.evict_inactive_validators(Duration::ZERO, Duration::from_secs(u64::MAX));

    assert_eq!(
        registry.snapshot_wallets_and_heights(),
        vec![(wallet_a, 1), (wallet_b, 2)]
    );
    Ok(())
}

#[test]
fn test_93_edge_empty_checked_snapshot_clears_existing_registry_and_succeeds() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(198);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.rebuild_from_snapshot_checked(Vec::<(String, Option<VerifyingKey>, u64)>::new())?;

    assert!(registry.wallets.is_empty());
    assert!(registry.join_heights.is_empty());
    Ok(())
}

#[test]
fn test_94_edge_vk_registration_then_strict_same_derived_wallet_rejects_duplicate() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;
    let derived_wallet = derive_wallet_id_from_pubkey_bytes(&vk.clone().into_bytes());

    let registered = registry.register_wallet_from_vk(&vk, 1)?;
    let duplicate = registry.register_wallet_strict(&derived_wallet, 2);

    assert_eq!(registered, derived_wallet);
    assert!(duplicate.is_err());
    assert_eq!(registry.wallets.len(), 1);
    assert_eq!(registry.verifying_keys.len(), 1);
    Ok(())
}

#[test]
fn test_95_edge_strict_registration_then_vk_same_derived_wallet_rejects_duplicate() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let (vk, _sk) = ml_dsa_65::try_keygen().map_err(io::Error::other)?;
    let derived_wallet = derive_wallet_id_from_pubkey_bytes(&vk.clone().into_bytes());

    registry.register_wallet_strict(&derived_wallet, 1)?;
    let duplicate = registry.register_wallet_from_vk(&vk, 2);

    assert!(duplicate.is_err());
    assert_eq!(registry.wallets.len(), 1);
    assert!(registry.lookup_verifying_key(&derived_wallet).is_none());
    Ok(())
}

#[test]
fn test_96_edge_concurrent_duplicate_node_registration_allows_exactly_one_success() -> TestResult {
    let node = NodeEphemeral::new();
    let shared_wallet = wallet(199);

    let success_count = std::thread::scope(|scope| -> TestResult<usize> {
        let mut handles = Vec::new();

        for _ in 0_u64..16_u64 {
            let node_clone = node.clone();
            let wallet_clone = shared_wallet.clone();
            handles.push(
                scope.spawn(move || node_clone.register_wallet_strict(&wallet_clone, 1).is_ok()),
            );
        }

        let mut count = 0_usize;
        for handle in handles {
            let joined = handle
                .join()
                .map_err(|_| io::Error::other("duplicate registration thread panicked"))?;
            if joined {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| test_error("success count overflowed"))?;
            }
        }

        Ok(count)
    })?;

    assert_eq!(success_count, 1);
    assert_eq!(node_wallet_count(&node)?, 1);
    Ok(())
}

#[test]
fn test_97_vector_eligibility_heights_cover_before_at_and_after_delay() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let delay = reward_delay()?;
    let vector_cases = [
        (wallet(200), 0_u64),
        (wallet(201), 5_u64),
        (wallet(202), 123_u64),
    ];

    for (wallet_addr, join_height) in vector_cases {
        let eligible_height =
            checked_add_u64(join_height, delay, "eligibility vector height overflowed")?;
        registry.register_wallet_strict(&wallet_addr, join_height)?;

        if eligible_height > 0 {
            assert!(!registry.eligible(&wallet_addr, eligible_height.saturating_sub(1)));
        }
        assert!(registry.eligible(&wallet_addr, eligible_height));
        assert!(registry.eligible(
            &wallet_addr,
            checked_add_u64(eligible_height, 1, "eligibility after-height overflowed")?
        ));
    }

    Ok(())
}

#[test]
fn test_98_edge_finalize_heartbeat_removes_missed_wallet_tip_snapshot() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let wallet_a = wallet(203);
    let wallet_b = wallet(204);

    registry.register_wallet_strict(&wallet_a, 1)?;
    registry.register_wallet_strict(&wallet_b, 2)?;
    registry.set_tip_snapshot(&wallet_a, 10)?;
    registry.set_tip_snapshot(&wallet_b, 20)?;

    registry.begin_heartbeat_round();
    registry.note_heartbeat_round(&wallet_a, 30)?;
    registry.finalize_heartbeat_round();

    assert_eq!(registry.tip_snapshot(&wallet_a), Some(30));
    assert_eq!(registry.tip_snapshot(&wallet_b), None);
    assert!(!registry.is_registered(&wallet_b));
    Ok(())
}

#[test]
fn test_99_edge_node_empty_checked_snapshot_clears_existing_state() -> TestResult {
    let node = NodeEphemeral::new();
    let wallet_a = wallet(205);

    node.register_wallet_strict(&wallet_a, 1)?;
    node.seed_from_chain_snapshot_checked(Vec::<(String, Option<VerifyingKey>, u64)>::new())?;

    assert_eq!(node_wallet_count(&node)?, 0);
    assert_eq!(node.status_line(), "[REGISTRY=EPHEMERAL][PoR] validators=0");
    Ok(())
}

#[test]
fn test_100_vector_many_valid_wallets_register_and_snapshot_matches_expected_order() -> TestResult {
    let mut registry = EphemeralRegistry::new();
    let mut expected = Vec::new();

    for seed in 512_u64..544_u64 {
        let wallet_addr = wallet(seed);
        registry.register_wallet_strict(&wallet_addr, seed)?;
        expected.push((wallet_addr, seed));
    }

    assert_eq!(registry.wallets.len(), 32);
    assert_eq!(registry.snapshot_wallets_and_heights(), expected);
    Ok(())
}
