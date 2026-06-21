// tests/proptests_por_000_ephemeral_registration.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::consensus::por_000_ephemeral_registration::{EphemeralRegistry, NodeEphemeral};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::time::Duration;

fn wallet_from_tail_128(tail: &str) -> String {
    format!("r{tail}")
}

fn wallet_with_prefix(prefix: char, tail_127: &str) -> String {
    format!("r{prefix}{tail_127}")
}

fn peer_id(seed: u64) -> String {
    format!("peer_{seed}_abcdefghijklmnopqrstuvwxyz")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_register_wallet_strict_canonicalizes_wallet_and_records_join_height(
        upper_tail in "[0-9A-F]{128}",
        join_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let raw = format!(" \tR{upper_tail}\n");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        let registered = reg
            .register_wallet_strict(&raw, join_height)
            .expect("valid uppercase/trimmed wallet should register as canonical");

        prop_assert_eq!(
            registered.as_str(),
            expected.as_str(),
            "registered wallet must be canonicalized"
        );

        prop_assert!(
            reg.is_registered(&expected),
            "canonical wallet must be registered"
        );

        prop_assert_eq!(
            reg.join_heights.get(&expected).copied(),
            Some(join_height),
            "register_wallet_strict must record join height"
        );

        prop_assert_eq!(
            reg.snapshot_wallets_and_heights(),
            vec![(expected.clone(), join_height)],
            "snapshot must expose registered wallet and join height"
        );
    }

    // 02/25
    #[test]
    fn test_002_register_wallet_strict_rejects_duplicate_canonical_wallet_without_overwriting_join_height(
        tail in "[0-9a-f]{128}",
        first_join in any::<u64>(),
        second_join in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let lower = wallet_from_tail_128(&tail);
        let upper = format!(" \tR{}\n", tail.to_ascii_uppercase());

        let first = reg
            .register_wallet_strict(&lower, first_join)
            .expect("first canonical wallet registration should succeed");

        prop_assert_eq!(
            first.as_str(),
            lower.as_str(),
            "first registration should return canonical lowercase wallet"
        );

        prop_assert!(
            reg.register_wallet_strict(&upper, second_join).is_err(),
            "duplicate wallet with different case/whitespace must be rejected"
        );

        prop_assert_eq!(
            reg.wallets.len(),
            1,
            "duplicate registration must not add another wallet"
        );

        prop_assert_eq!(
            reg.join_heights.get(&lower).copied(),
            Some(first_join),
            "duplicate registration must not overwrite original join height"
        );
    }

    // 03/25
    #[test]
    fn test_003_register_wallet_strict_rejects_short_wrong_prefix_and_non_hex_wallets(
        short_tail in "[0-9a-f]{0,127}",
        valid_tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let short = wallet_from_tail_128(&short_tail);
        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);

        prop_assert!(
            reg.register_wallet_strict(&short, join_height).is_err(),
            "short wallet must be rejected"
        );

        prop_assert!(
            reg.register_wallet_strict(&wrong_prefix, join_height).is_err(),
            "wrong wallet prefix must be rejected"
        );

        prop_assert!(
            reg.register_wallet_strict(&non_hex, join_height).is_err(),
            "non-hex wallet body must be rejected"
        );

        prop_assert!(
            reg.wallets.is_empty(),
            "invalid registration attempts must not mutate wallet set"
        );

        prop_assert!(
            reg.join_heights.is_empty(),
            "invalid registration attempts must not mutate join heights"
        );
    }

    // 04/25
    #[test]
    fn test_004_set_join_height_requires_registered_wallet_and_never_overwrites_existing_join_height(
        tail in "[0-9a-f]{128}",
        first_join in any::<u64>(),
        second_join in any::<u64>(),
        unknown_tail in "[0-9a-f]{128}",
    ) {
        let mut reg = EphemeralRegistry::new();

        let wallet = wallet_from_tail_128(&tail);
        let unknown = format!("r{}", unknown_tail);

        reg.register_wallet_strict(&wallet, first_join)
            .expect("valid wallet should register");

        reg.set_join_height(&wallet, second_join)
            .expect("set_join_height should succeed for registered wallet");

        prop_assert_eq!(
            reg.join_heights.get(&wallet).copied(),
            Some(first_join),
            "set_join_height uses entry/or_insert and must not overwrite existing join height"
        );

        prop_assert!(
            reg.set_join_height(&unknown, second_join).is_err(),
            "set_join_height must reject unregistered wallets"
        );
    }

    // 05/25
    #[test]
    fn test_005_eligibility_matches_join_height_plus_reward_delay_rule(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        at_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();
        let wallet = wallet_from_tail_128(&tail);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("valid wallet should register");

        let delay = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
        let expected = at_height >= join_height.saturating_add(delay);

        prop_assert_eq!(
            reg.eligible(&wallet, at_height),
            expected,
            "eligibility must match at_height >= join_height + REWARD_DELAY_BLOCKS"
        );

        prop_assert!(
            !reg.eligible("not-a-wallet", at_height),
            "invalid wallet strings must never be eligible"
        );
    }

    // 06/25
    #[test]
    fn test_006_tip_snapshots_are_separate_from_join_heights_and_query_consistently(
        tail in "[0-9a-f]{127}",
        join_height in any::<u64>(),
        tip_a in any::<u64>(),
        tip_b in any::<u64>(),
        tip_c in any::<u64>(),
        min_tip in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let w0 = wallet_with_prefix('0', &tail);
        let w1 = wallet_with_prefix('1', &tail);
        let w2 = wallet_with_prefix('2', &tail);

        reg.register_wallet_strict(&w0, join_height)
            .expect("w0 should register");
        reg.register_wallet_strict(&w1, join_height.saturating_add(1))
            .expect("w1 should register");
        reg.register_wallet_strict(&w2, join_height.saturating_add(2))
            .expect("w2 should register");

        reg.set_tip_snapshot(&w0, tip_a)
            .expect("registered wallet tip snapshot should set");
        reg.set_tip_snapshot(&w1, tip_b)
            .expect("registered wallet tip snapshot should set");
        reg.set_tip_snapshot(&w2, tip_c)
            .expect("registered wallet tip snapshot should set");

        prop_assert_eq!(
            reg.join_heights.get(&w0).copied(),
            Some(join_height),
            "setting tip snapshot must not overwrite join_height"
        );

        prop_assert_eq!(reg.tip_snapshot(&w0), Some(tip_a));
        prop_assert_eq!(reg.tip_snapshot(&w1), Some(tip_b));
        prop_assert_eq!(reg.tip_snapshot(&w2), Some(tip_c));

        prop_assert_eq!(
            reg.max_tip_snapshot(),
            Some(tip_a.max(tip_b).max(tip_c)),
            "max_tip_snapshot must return maximum seen tip"
        );

        prop_assert_eq!(
            reg.has_recent_tip_snapshot(&w0, min_tip),
            tip_a >= min_tip,
            "has_recent_tip_snapshot must compare stored tip against min_tip"
        );

        let expected = reg
            .sorted_wallets()
            .into_iter()
            .filter(|w| reg.tip_snapshot(w).unwrap_or(0) >= min_tip)
            .collect::<Vec<_>>();

        prop_assert_eq!(
            reg.wallets_with_tip_at_least(min_tip),
            expected,
            "wallets_with_tip_at_least must return sorted wallets meeting threshold"
        );

        let unknown = wallet_with_prefix('f', &tail);

        prop_assert!(
            reg.set_tip_snapshot(&unknown, tip_a).is_err(),
            "set_tip_snapshot must reject unregistered wallets"
        );
    }

    // 07/25
    #[test]
    fn test_007_associate_identity_requires_valid_peer_and_registered_wallet(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        peer_seed in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let wallet = wallet_from_tail_128(&tail);
        let peer = peer_id(peer_seed);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("valid wallet should register");

        reg.associate_identity(&peer, &wallet)
            .expect("registered wallet should associate with valid ASCII peer id");

        let mapped = reg.wallet_for_peer(&peer);

        prop_assert_eq!(
            mapped.as_deref(),
            Some(wallet.as_str()),
            "wallet_for_peer must return associated wallet"
        );

        prop_assert!(
            reg.associate_identity("", &wallet).is_err(),
            "empty peer id must be rejected"
        );

        let too_long_peer = "a".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN.saturating_add(1));

        prop_assert!(
            reg.associate_identity(&too_long_peer, &wallet).is_err(),
            "peer id longer than configured cap must be rejected"
        );

        prop_assert!(
            reg.associate_identity("peeré", &wallet).is_err(),
            "non-ASCII peer id must be rejected"
        );

        let unknown_wallet = format!("r{}", "a".repeat(128));

        prop_assert!(
            reg.associate_identity("valid_ascii_peer", &unknown_wallet).is_err(),
            "identity association must reject unregistered wallet"
        );
    }

    // 08/25
    #[test]
    fn test_008_unregister_wallet_removes_wallet_metadata_tip_snapshot_and_identity(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        tip_snapshot in any::<u64>(),
        peer_seed in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let wallet = wallet_from_tail_128(&tail);
        let peer = peer_id(peer_seed);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("valid wallet should register");
        reg.set_tip_snapshot(&wallet, tip_snapshot)
            .expect("registered wallet tip snapshot should set");
        reg.associate_identity(&peer, &wallet)
            .expect("registered wallet should map to peer");

        prop_assert!(
            reg.unregister_wallet(&wallet),
            "unregister_wallet must return true for existing wallet"
        );

        prop_assert!(
            !reg.is_registered(&wallet),
            "unregistered wallet must no longer be registered"
        );

        prop_assert!(
            !reg.join_heights.contains_key(&wallet),
            "unregister_wallet must remove join height"
        );

        prop_assert_eq!(
            reg.tip_snapshot(&wallet),
            None,
            "unregister_wallet must remove tip snapshot"
        );

        prop_assert_eq!(
            reg.wallet_for_peer(&peer),
            None,
            "unregister_wallet must remove peer identity mappings"
        );

        prop_assert!(
            !reg.unregister_wallet(&wallet),
            "unregister_wallet must return false for already removed wallet"
        );
    }

    // 09/25
    #[test]
    fn test_009_unregister_by_peer_removes_wallet_and_all_peer_aliases_for_that_wallet(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        peer_seed_a in any::<u64>(),
        peer_seed_b in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let wallet = wallet_from_tail_128(&tail);
        let peer_a = peer_id(peer_seed_a);
        let peer_b = format!("{}_alias", peer_id(peer_seed_b));

        prop_assume!(peer_a != peer_b);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("valid wallet should register");

        reg.associate_identity(&peer_a, &wallet)
            .expect("peer A should associate");
        reg.associate_identity(&peer_b, &wallet)
            .expect("peer B should associate");

        let removed = reg.unregister_by_peer(&peer_a);

        prop_assert_eq!(
            removed.as_deref(),
            Some(wallet.as_str()),
            "unregister_by_peer must return removed wallet"
        );

        prop_assert!(
            !reg.is_registered(&wallet),
            "unregister_by_peer must remove wallet from registry"
        );

        prop_assert_eq!(
            reg.wallet_for_peer(&peer_a),
            None,
            "unregister_by_peer must remove triggering peer mapping"
        );

        prop_assert_eq!(
            reg.wallet_for_peer(&peer_b),
            None,
            "unregister_by_peer must remove all aliases for the removed wallet"
        );

        prop_assert_eq!(
            reg.unregister_by_peer(&peer_a),
            None,
            "unregister_by_peer must return None after wallet is already removed"
        );
    }

    // 10/25
    #[test]
    fn test_010_heartbeat_round_finalize_retains_only_wallets_seen_in_current_round(
        tail in "[0-9a-f]{127}",
        join_height in any::<u64>(),
        tip_a in any::<u64>(),
        tip_c in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let w0 = wallet_with_prefix('0', &tail);
        let w1 = wallet_with_prefix('1', &tail);
        let w2 = wallet_with_prefix('2', &tail);

        reg.register_wallet_strict(&w0, join_height)
            .expect("w0 should register");
        reg.register_wallet_strict(&w1, join_height.saturating_add(1))
            .expect("w1 should register");
        reg.register_wallet_strict(&w2, join_height.saturating_add(2))
            .expect("w2 should register");

        reg.associate_identity("peer0", &w0).expect("peer0 should map");
        reg.associate_identity("peer1", &w1).expect("peer1 should map");
        reg.associate_identity("peer2", &w2).expect("peer2 should map");

        reg.begin_heartbeat_round();

        reg.note_heartbeat_round(&w0, tip_a)
            .expect("w0 heartbeat should be recorded");
        reg.note_heartbeat_round(&w2, tip_c)
            .expect("w2 heartbeat should be recorded");

        reg.finalize_heartbeat_round();

        prop_assert!(reg.is_registered(&w0));
        prop_assert!(!reg.is_registered(&w1));
        prop_assert!(reg.is_registered(&w2));

        let peer0_wallet = reg.wallet_for_peer("peer0");
        let peer1_wallet = reg.wallet_for_peer("peer1");
        let peer2_wallet = reg.wallet_for_peer("peer2");

        prop_assert_eq!(
            peer0_wallet.as_deref(),
            Some(w0.as_str()),
            "identity for retained wallet w0 must remain"
        );

        prop_assert_eq!(
            peer1_wallet,
            None,
            "identity for unobserved wallet w1 must be removed"
        );

        prop_assert_eq!(
            peer2_wallet.as_deref(),
            Some(w2.as_str()),
            "identity for retained wallet w2 must remain"
        );

        prop_assert_eq!(reg.tip_snapshot(&w0), Some(tip_a));
        prop_assert_eq!(reg.tip_snapshot(&w1), None);
        prop_assert_eq!(reg.tip_snapshot(&w2), Some(tip_c));
    }

    // 11/25
    #[test]
    fn test_011_empty_heartbeat_round_finalize_clears_entire_ephemeral_registry(
        tail in "[0-9a-f]{127}",
        join_height in any::<u64>(),
        tip_snapshot in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let w0 = wallet_with_prefix('0', &tail);
        let w1 = wallet_with_prefix('1', &tail);

        reg.register_wallet_strict(&w0, join_height)
            .expect("w0 should register");
        reg.register_wallet_strict(&w1, join_height.saturating_add(1))
            .expect("w1 should register");

        reg.associate_identity("peer0", &w0).expect("peer0 should map");
        reg.associate_identity("peer1", &w1).expect("peer1 should map");

        reg.set_tip_snapshot(&w0, tip_snapshot)
            .expect("w0 tip snapshot should set");
        reg.set_tip_snapshot(&w1, tip_snapshot.saturating_add(1))
            .expect("w1 tip snapshot should set");

        reg.begin_heartbeat_round();
        reg.finalize_heartbeat_round();

        prop_assert!(reg.wallets.is_empty(), "wallets must be cleared");
        prop_assert!(reg.join_heights.is_empty(), "join heights must be cleared");
        prop_assert!(reg.identity_map.is_empty(), "identity map must be cleared");
        prop_assert!(reg.verifying_keys.is_empty(), "verifying keys must be cleared");
        prop_assert_eq!(reg.max_tip_snapshot(), None, "tip snapshots must be cleared");
    }

    // 12/25
    #[test]
    fn test_012_note_heartbeat_round_on_new_wallet_sets_neutral_join_height_and_tip_snapshot(
        tail in "[0-9a-f]{128}",
        tip_snapshot in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();
        let wallet = wallet_from_tail_128(&tail);

        let observed = reg
            .note_heartbeat_round(&wallet, tip_snapshot)
            .expect("heartbeat from valid wallet should be accepted");

        prop_assert_eq!(
            observed.as_str(),
            wallet.as_str(),
            "heartbeat should return canonical wallet"
        );

        prop_assert!(
            reg.is_registered(&wallet),
            "heartbeat should insert wallet into active RAM registry"
        );

        prop_assert_eq!(
            reg.join_heights.get(&wallet).copied(),
            Some(0),
            "first-seen heartbeat must use neutral join height 0"
        );

        prop_assert_eq!(
            reg.tip_snapshot(&wallet),
            Some(tip_snapshot),
            "heartbeat must store tip snapshot separately from join height"
        );
    }

    // 13/25
    #[test]
    fn test_013_note_heartbeat_round_preserves_existing_join_height_while_updating_tip_snapshot(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        tip_snapshot in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();
        let wallet = wallet_from_tail_128(&tail);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("wallet should register");

        reg.begin_heartbeat_round();

        reg.note_heartbeat_round(&wallet, tip_snapshot)
            .expect("heartbeat should be recorded for registered wallet");

        reg.finalize_heartbeat_round();

        prop_assert_eq!(
            reg.join_heights.get(&wallet).copied(),
            Some(join_height),
            "heartbeat must not overwrite original join height"
        );

        prop_assert_eq!(
            reg.tip_snapshot(&wallet),
            Some(tip_snapshot),
            "heartbeat must update runtime tip snapshot"
        );

        prop_assert!(
            reg.is_registered(&wallet),
            "wallet seen in heartbeat round must remain registered after finalize"
        );
    }

    // 14/25
    #[test]
    fn test_014_rebuild_from_snapshot_checked_clears_old_state_and_rebuilds_wallet_heights(
        tail in "[0-9a-f]{127}",
        old_tail in "[0-9a-f]{128}",
        count in 1usize..=10usize,
        base_height in any::<u64>(),
        old_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let old_wallet = wallet_from_tail_128(&old_tail);

        reg.register_wallet_strict(&old_wallet, old_height)
            .expect("old wallet should register before rebuild");

        let entries = (0..count)
            .map(|i| {
                let prefix = char::from_digit(i as u32, 16)
                    .expect("count is capped at 10, so prefix is valid hex");
                let wallet = wallet_with_prefix(prefix, &tail);
                let height = base_height.saturating_add(i as u64);
                (wallet, None, height)
            })
            .collect::<Vec<_>>();

        reg.rebuild_from_snapshot_checked(entries.clone())
            .expect("valid snapshot should rebuild");

        prop_assert!(
            !reg.is_registered(&old_wallet),
            "rebuild_from_snapshot_checked must clear previous registry state"
        );

        prop_assert_eq!(
            reg.wallets.len(),
            count,
            "registry must contain exactly snapshot wallets"
        );

        let expected = {
            let mut v = entries
                .into_iter()
                .map(|(wallet, _vk, height)| (wallet, height))
                .collect::<Vec<_>>();

            v.sort_unstable_by(|a, b| {
                let al = a.0.to_ascii_lowercase();
                let bl = b.0.to_ascii_lowercase();
                match al.cmp(&bl) {
                    std::cmp::Ordering::Equal => a.0.cmp(&b.0),
                    ordering => ordering,
                }
            });

            v
        };

        prop_assert_eq!(
            reg.snapshot_wallets_and_heights(),
            expected,
            "snapshot_wallets_and_heights must expose rebuilt wallets in canonical sort order"
        );
    }

    // 15/25
    #[test]
    fn test_015_node_ephemeral_wrapper_forwards_registry_operations_consistently(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        tip_snapshot in any::<u64>(),
        peer_seed in any::<u64>(),
    ) {
        let node = NodeEphemeral::new();

        let wallet = wallet_from_tail_128(&tail);
        let peer = peer_id(peer_seed);

        let registered = node
            .register_wallet_strict(&wallet, join_height)
            .expect("NodeEphemeral should register valid wallet");

        prop_assert_eq!(
            registered.as_str(),
            wallet.as_str(),
            "NodeEphemeral registration must return canonical wallet"
        );

        node.map_peer_identity(&peer, &wallet)
            .expect("NodeEphemeral should map peer identity");

        node.set_tip_snapshot(&wallet, tip_snapshot)
            .expect("NodeEphemeral should set tip snapshot");

        prop_assert_eq!(
            node.tip_snapshot(&wallet),
            Some(tip_snapshot),
            "NodeEphemeral tip_snapshot must read stored tip"
        );

        prop_assert_eq!(
            node.max_tip_snapshot(),
            Some(tip_snapshot),
            "NodeEphemeral max_tip_snapshot must read max stored tip"
        );

        prop_assert_eq!(
            node.wallets_with_tip_at_least(tip_snapshot),
            vec![wallet.clone()],
            "NodeEphemeral wallets_with_tip_at_least must return wallet at threshold"
        );

        let removed = node.unregister_by_peer(&peer);

        prop_assert_eq!(
            removed.as_deref(),
            Some(wallet.as_str()),
            "NodeEphemeral unregister_by_peer must return removed wallet"
        );

        prop_assert!(
            node.status_line().contains("validators=0"),
            "status_line must report zero validators after removal"
        );
    }

    // 16/25
    #[test]
    fn test_016_node_ephemeral_boot_clear_result_removes_existing_wallets(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
    ) {
        let node = NodeEphemeral::new();
        let wallet = wallet_from_tail_128(&tail);

        node.register_wallet_strict(&wallet, join_height)
            .expect("wallet should register");

        prop_assert!(
            node.status_line().contains("validators=1"),
            "status_line must report registered validator before boot clear"
        );

        node.boot_clear_result()
            .expect("boot_clear_result should clear non-poisoned registry");

        prop_assert!(
            node.status_line().contains("validators=0"),
            "status_line must report zero validators after boot clear"
        );
    }

    // 17/25
    #[test]
    fn test_017_sorted_wallets_and_snapshot_are_deterministic_after_out_of_order_registration(
        tail in "[0-9a-f]{127}",
        base_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let w2 = wallet_with_prefix('2', &tail);
        let w0 = wallet_with_prefix('0', &tail);
        let w1 = wallet_with_prefix('1', &tail);

        reg.register_wallet_strict(&w2, base_height.saturating_add(2))
            .expect("w2 should register");
        reg.register_wallet_strict(&w0, base_height)
            .expect("w0 should register");
        reg.register_wallet_strict(&w1, base_height.saturating_add(1))
            .expect("w1 should register");

        prop_assert_eq!(
            reg.sorted_wallets(),
            vec![w0.clone(), w1.clone(), w2.clone()],
            "sorted_wallets must return canonical deterministic order"
        );

        prop_assert_eq!(
            reg.snapshot_wallets_and_heights(),
            vec![
                (w0, base_height),
                (w1, base_height.saturating_add(1)),
                (w2, base_height.saturating_add(2)),
            ],
            "snapshot must follow deterministic sorted wallet order"
        );
    }

    // 18/25
    #[test]
    fn test_018_clear_removes_wallets_join_heights_identities_verifying_keys_and_tip_views(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        tip_snapshot in any::<u64>(),
        peer_seed in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let wallet = wallet_from_tail_128(&tail);
        let peer = peer_id(peer_seed);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("wallet should register");
        reg.associate_identity(&peer, &wallet)
            .expect("peer should associate");
        reg.set_tip_snapshot(&wallet, tip_snapshot)
            .expect("tip snapshot should set");

        reg.clear();

        prop_assert!(reg.wallets.is_empty(), "clear must remove wallets");
        prop_assert!(reg.join_heights.is_empty(), "clear must remove join heights");
        prop_assert!(reg.identity_map.is_empty(), "clear must remove identity mappings");
        prop_assert!(reg.verifying_keys.is_empty(), "clear must remove verifying keys");
        prop_assert_eq!(reg.wallet_for_peer(&peer), None, "clear must remove peer lookup");
        prop_assert_eq!(reg.tip_snapshot(&wallet), None, "clear must remove tip snapshot");
        prop_assert_eq!(reg.max_tip_snapshot(), None, "clear must remove max tip snapshot");
    }

    // 19/25
    #[test]
    fn test_019_rebuild_from_snapshot_checked_rejects_invalid_first_entry_and_leaves_empty_registry(
        valid_tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let old_wallet = wallet_from_tail_128(&valid_tail);
        reg.register_wallet_strict(&old_wallet, join_height)
            .expect("old wallet should register before rebuild");

        let invalid = format!("p{valid_tail}");
        let valid = wallet_from_tail_128(&valid_tail);

        let result = reg.rebuild_from_snapshot_checked(vec![
            (invalid, None, join_height),
            (valid, None, join_height.saturating_add(1)),
        ]);

        prop_assert!(
            result.is_err(),
            "checked snapshot rebuild must reject invalid first entry"
        );

        prop_assert!(
            reg.wallets.is_empty(),
            "checked rebuild clears old state before applying and invalid first entry leaves registry empty"
        );

        prop_assert!(
            reg.join_heights.is_empty(),
            "invalid checked rebuild must not leave join heights when first entry fails"
        );
    }

    // 20/25
    #[test]
    fn test_020_rebuild_from_snapshot_unchecked_skips_invalid_entries_and_applies_valid_entries(
        valid_tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let invalid = format!("p{valid_tail}");
        let valid = wallet_from_tail_128(&valid_tail);

        reg.rebuild_from_snapshot(vec![
            (invalid, None, join_height),
            (valid.clone(), None, join_height.saturating_add(1)),
        ]);

        prop_assert!(
            reg.is_registered(&valid),
            "unchecked snapshot rebuild should skip invalid entry and apply valid entry"
        );

        prop_assert_eq!(
            reg.snapshot_wallets_and_heights(),
            vec![(valid, join_height.saturating_add(1))],
            "unchecked rebuild must expose only successfully applied valid entries"
        );
    }

    // 21/25
    #[test]
    fn test_021_node_ephemeral_seed_from_chain_snapshot_checked_clears_old_state_and_rebuilds(
        old_tail in "[0-9a-f]{128}",
        new_tail in "[0-9a-f]{128}",
        old_height in any::<u64>(),
        new_height in any::<u64>(),
    ) {
        prop_assume!(old_tail != new_tail);

        let node = NodeEphemeral::new();

        let old_wallet = wallet_from_tail_128(&old_tail);
        let new_wallet = wallet_from_tail_128(&new_tail);

        node.register_wallet_strict(&old_wallet, old_height)
            .expect("old wallet should register");

        node.seed_from_chain_snapshot_checked(vec![
            (new_wallet.clone(), None, new_height),
        ])
        .expect("valid checked snapshot seed should rebuild node registry");

        prop_assert!(
            node.status_line().contains("validators=1"),
            "node registry should contain exactly one validator after checked rebuild"
        );

        let inner = node.ephemeral();
        let guard = inner.lock().expect("registry mutex should not be poisoned");

        prop_assert!(
            !guard.is_registered(&old_wallet),
            "checked snapshot seed must clear old wallet"
        );

        prop_assert!(
            guard.is_registered(&new_wallet),
            "checked snapshot seed must register new wallet"
        );

        prop_assert_eq!(
            guard.join_heights.get(&new_wallet).copied(),
            Some(new_height),
            "checked snapshot seed must preserve new join height"
        );
    }

    // 22/25
    #[test]
    fn test_022_node_ephemeral_boot_clear_non_result_removes_existing_wallets_and_tip_views(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        tip_snapshot in any::<u64>(),
    ) {
        let node = NodeEphemeral::new();
        let wallet = wallet_from_tail_128(&tail);

        node.register_wallet_strict(&wallet, join_height)
            .expect("wallet should register");
        node.set_tip_snapshot(&wallet, tip_snapshot)
            .expect("tip snapshot should set");

        prop_assert!(
            node.status_line().contains("validators=1"),
            "status_line must report one validator before boot_clear"
        );

        node.boot_clear();

        prop_assert!(
            node.status_line().contains("validators=0"),
            "status_line must report zero validators after boot_clear"
        );

        prop_assert_eq!(
            node.tip_snapshot(&wallet),
            None,
            "boot_clear must remove tip snapshot"
        );

        prop_assert_eq!(
            node.max_tip_snapshot(),
            None,
            "boot_clear must remove max tip snapshot"
        );
    }

    // 23/25
    #[test]
    fn test_023_unregister_by_peer_rejects_invalid_peer_ids_without_mutating_registry(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
        peer_seed in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let wallet = wallet_from_tail_128(&tail);
        let peer = peer_id(peer_seed);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("wallet should register");
        reg.associate_identity(&peer, &wallet)
            .expect("peer should associate");

        prop_assert_eq!(
            reg.unregister_by_peer(""),
            None,
            "empty peer id must be rejected and return None"
        );

        prop_assert_eq!(
            reg.unregister_by_peer("peeré"),
            None,
            "non-ASCII peer id must be rejected and return None"
        );

        let too_long_peer = "a".repeat(GlobalConfiguration::MAX_PEER_ID_B58_LEN.saturating_add(1));

        prop_assert_eq!(
            reg.unregister_by_peer(&too_long_peer),
            None,
            "too-long peer id must be rejected and return None"
        );

        prop_assert!(
            reg.is_registered(&wallet),
            "invalid peer unregister attempts must not remove wallet"
        );

        let mapped_after_invalid_unregisters = reg.wallet_for_peer(&peer);

        prop_assert_eq!(
            mapped_after_invalid_unregisters.as_deref(),
            Some(wallet.as_str()),
            "invalid peer unregister attempts must not remove valid peer mapping"
        );
    }

    // 24/25
    #[test]
    fn test_024_evict_inactive_validators_respects_boot_grace_for_newly_registered_wallet(
        tail in "[0-9a-f]{128}",
        join_height in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();
        let wallet = wallet_from_tail_128(&tail);

        reg.register_wallet_strict(&wallet, join_height)
            .expect("wallet should register");

        reg.evict_inactive_validators(
            Duration::from_secs(0),
            Duration::from_secs(u64::MAX),
        );

        prop_assert!(
            reg.is_registered(&wallet),
            "newly registered wallet must not be evicted while inside boot grace"
        );

        prop_assert_eq!(
            reg.join_heights.get(&wallet).copied(),
            Some(join_height),
            "eviction check inside boot grace must preserve join height"
        );
    }

    // 25/25
    #[test]
    fn test_025_public_registry_entrypoints_never_panic_for_arbitrary_public_inputs(
        wallet_text in ".{0,512}",
        peer_text in ".{0,512}",
        height in any::<u64>(),
        tip_snapshot in any::<u64>(),
        max_inactive_secs in any::<u64>(),
        boot_grace_secs in any::<u64>(),
    ) {
        let mut reg = EphemeralRegistry::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = reg.register_wallet_strict(&wallet_text, height);
            let _ = reg.is_registered(&wallet_text);
            let _ = reg.set_join_height(&wallet_text, height);
            let _ = reg.set_tip_snapshot(&wallet_text, tip_snapshot);
            let _ = reg.tip_snapshot(&wallet_text);
            let _ = reg.has_recent_tip_snapshot(&wallet_text, tip_snapshot);
            let _ = reg.eligible(&wallet_text, height);
            let _ = reg.lookup_verifying_key(&wallet_text);
            let _ = reg.associate_identity(&peer_text, &wallet_text);
            let _ = reg.wallet_for_peer(&peer_text);
            let _ = reg.unregister_by_peer(&peer_text);
            let _ = reg.unregister_wallet(&wallet_text);
            reg.begin_heartbeat_round();
            let _ = reg.note_heartbeat_round(&wallet_text, tip_snapshot);
            reg.finalize_heartbeat_round();
            reg.evict_inactive_validators(
                Duration::from_secs(max_inactive_secs),
                Duration::from_secs(boot_grace_secs),
            );
            let _ = reg.sorted_wallets();
            let _ = reg.snapshot_wallets_and_heights();
            let _ = reg.max_tip_snapshot();
            let _ = reg.wallets_with_tip_at_least(tip_snapshot);
        }));

        prop_assert!(
            result.is_ok(),
            "public EphemeralRegistry entrypoints must return values/errors, not panic, for arbitrary public inputs"
        );
    }
}
