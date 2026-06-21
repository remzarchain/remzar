use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::consensus::por_003_puzzle_pool::PorPuzzlePool;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn wallet_with_prefix(prefix: char, seed: u64) -> String {
    format!("{prefix}{seed:0128x}")
}

fn messy_wallet(seed: u64) -> String {
    format!(" \t{}\n", wallet(seed).to_ascii_uppercase())
}

fn non_hex_wallet(seed: u64) -> String {
    format!("rz{seed:0127x}")
}

fn long_wallet(extra_len: usize) -> String {
    format!("r{}{}", "a".repeat(128), "b".repeat(extra_len))
}

fn output(seed: u128) -> u128 {
    seed.saturating_add(1)
}

fn record_many_unique(
    pool: &mut PorPuzzlePool,
    height: u64,
    count: usize,
    start_seed: u64,
) -> usize {
    let mut inserted = 0usize;

    for i in 0..count {
        let seed = start_seed.saturating_add(i as u64);
        let result = pool.record_success_checked(height, &wallet(seed), output(seed as u128));

        if result.is_ok() {
            inserted = inserted.saturating_add(1);
        } else {
            break;
        }
    }

    inserted
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_pool_starts_empty_for_any_height(
        height in any::<u64>(),
    ) {
        let pool = PorPuzzlePool::new();

        prop_assert!(
            pool.winners_for_height(height).is_empty(),
            "new pool must have no winners for any height"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_none(),
            "new pool must have no entropy for any height"
        );
    }

    // 02/25
    #[test]
    fn test_002_default_pool_matches_new_empty_behavior(
        height in any::<u64>(),
    ) {
        let new_pool = PorPuzzlePool::new();
        let default_pool = PorPuzzlePool::default();

        prop_assert_eq!(
            default_pool.winners_for_height(height),
            new_pool.winners_for_height(height),
            "default pool winners must match new pool winners"
        );

        prop_assert_eq!(
            default_pool.entropy_for_height(height),
            new_pool.entropy_for_height(height),
            "default pool entropy must match new pool entropy"
        );
    }

    // 03/25
    #[test]
    fn test_003_record_success_checked_accepts_valid_wallet_and_output(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();
        let wallet = wallet(seed);
        let out = output(output_seed);

        pool.record_success_checked(height, &wallet, out)
            .expect("valid wallet/output should record successfully");

        prop_assert_eq!(
            pool.winners_for_height(height),
            vec![wallet],
            "valid record must create one canonical winner"
        );

        let entropy = pool.entropy_for_height(height)
            .expect("recording a winner must create entropy");

        prop_assert_eq!(
            entropy.len(),
            64,
            "entropy digest must be exactly 64 bytes"
        );
    }

    // 04/25
    #[test]
    fn test_004_record_success_checked_canonicalizes_uppercase_and_whitespace_wallet(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();

        let canonical = wallet(seed);
        let messy = messy_wallet(seed);

        pool.record_success_checked(height, &messy, output(output_seed))
            .expect("canonicalizable wallet should record successfully");

        prop_assert_eq!(
            pool.winners_for_height(height),
            vec![canonical],
            "pool must store canonical lowercase wallet"
        );
    }

    // 05/25
    #[test]
    fn test_005_record_success_checked_rejects_wrong_prefix_wallet(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();

        prop_assert!(
            pool.record_success_checked(
                height,
                &wallet_with_prefix('p', seed),
                output(output_seed),
            )
            .is_err(),
            "wrong-prefix wallet must be rejected"
        );

        prop_assert!(
            pool.winners_for_height(height).is_empty(),
            "rejected wrong-prefix wallet must not mutate winners"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_none(),
            "rejected wrong-prefix wallet must not create entropy"
        );
    }

    // 06/25
    #[test]
    fn test_006_record_success_checked_rejects_non_hex_wallet_body(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();

        prop_assert!(
            pool.record_success_checked(height, &non_hex_wallet(seed), output(output_seed))
                .is_err(),
            "non-hex wallet body must be rejected"
        );

        prop_assert!(
            pool.winners_for_height(height).is_empty(),
            "rejected non-hex wallet must not mutate winners"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_none(),
            "rejected non-hex wallet must not create entropy"
        );
    }

    // 07/25
    #[test]
    fn test_007_record_success_checked_rejects_short_wallet(
        height in any::<u64>(),
        short_body in "[0-9a-f]{0,127}",
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();
        let short = format!("r{short_body}");

        prop_assert!(
            pool.record_success_checked(height, &short, output(output_seed)).is_err(),
            "short wallet must be rejected"
        );

        prop_assert!(
            pool.winners_for_height(height).is_empty(),
            "rejected short wallet must not mutate winners"
        );
    }

    // 08/25
    #[test]
    fn test_008_record_success_checked_rejects_wallet_longer_than_pool_cap(
        height in any::<u64>(),
        extra_len in 128usize..512usize,
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();
        let too_long = long_wallet(extra_len);

        prop_assert!(
            too_long.len() > 256,
            "test setup must exceed pool wallet length cap"
        );

        prop_assert!(
            pool.record_success_checked(height, &too_long, output(output_seed)).is_err(),
            "wallet longer than pool cap must be rejected before storage"
        );

        prop_assert!(
            pool.winners_for_height(height).is_empty(),
            "rejected overlong wallet must not mutate winners"
        );
    }

    // 09/25
    #[test]
    fn test_009_recording_same_wallet_same_output_is_idempotent(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();
        let wallet = wallet(seed);
        let out = output(output_seed);

        pool.record_success_checked(height, &wallet, out)
            .expect("first insert should succeed");

        let winners_before = pool.winners_for_height(height);
        let entropy_before = pool.entropy_for_height(height);

        pool.record_success_checked(height, &wallet, out)
            .expect("same wallet/output should be idempotent");

        prop_assert_eq!(
            pool.winners_for_height(height),
            winners_before,
            "same wallet/output must not duplicate winners"
        );

        prop_assert_eq!(
            pool.entropy_for_height(height),
            entropy_before,
            "same wallet/output must not change entropy"
        );
    }

    // 10/25
    #[test]
    fn test_010_recording_same_wallet_different_output_overwrites_without_duplicate_winner(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_a_seed in any::<u128>(),
        delta in 1u128..=1_000_000u128,
    ) {
        let mut pool = PorPuzzlePool::new();
        let wallet = wallet(seed);
        let output_a = output(output_a_seed);
        let output_b = output_a.saturating_add(delta);

        pool.record_success_checked(height, &wallet, output_a)
            .expect("first insert should succeed");

        let entropy_before = pool.entropy_for_height(height)
            .expect("first insert should create entropy");

        pool.record_success_checked(height, &wallet, output_b)
            .expect("same wallet with different output should overwrite");

        prop_assert_eq!(
            pool.winners_for_height(height),
            vec![wallet],
            "overwrite must keep one winner entry"
        );

        let entropy_after = pool.entropy_for_height(height)
            .expect("overwrite should leave entropy present");

        if output_a != output_b {
            prop_assert_ne!(
                entropy_after,
                entropy_before,
                "changing a winner output must change entropy"
            );
        }
    }

    // 11/25
    #[test]
    fn test_011_winners_for_height_are_sorted_canonical_wallets(
        height in any::<u64>(),
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        prop_assume!(seed_a != seed_b);
        prop_assume!(seed_a != seed_c);
        prop_assume!(seed_b != seed_c);

        let mut pool = PorPuzzlePool::new();

        for seed in [seed_c, seed_a, seed_b] {
            pool.record_success_checked(height, &wallet(seed), output(seed as u128))
                .expect("valid winner should record");
        }

        let mut expected = vec![wallet(seed_a), wallet(seed_b), wallet(seed_c)];
        expected.sort();
        expected.dedup();

        prop_assert_eq!(
            pool.winners_for_height(height),
            expected,
            "winners_for_height must return deterministic sorted canonical wallets"
        );
    }

    // 12/25
    #[test]
    fn test_012_entropy_is_order_independent_for_same_height_winner_set(
        height in any::<u64>(),
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
        output_a in any::<u128>(),
        output_b in any::<u128>(),
        output_c in any::<u128>(),
    ) {
        prop_assume!(seed_a != seed_b);
        prop_assume!(seed_a != seed_c);
        prop_assume!(seed_b != seed_c);

        let mut pool_a = PorPuzzlePool::new();
        let mut pool_b = PorPuzzlePool::new();

        let entries = [
            (seed_a, output(output_a)),
            (seed_b, output(output_b)),
            (seed_c, output(output_c)),
        ];

        for (seed, out) in entries {
            pool_a.record_success_checked(height, &wallet(seed), out)
                .expect("pool A insert should succeed");
        }

        for (seed, out) in entries.into_iter().rev() {
            pool_b.record_success_checked(height, &wallet(seed), out)
                .expect("pool B insert should succeed");
        }

        prop_assert_eq!(
            pool_a.winners_for_height(height),
            pool_b.winners_for_height(height),
            "same winner set must produce same sorted winners independent of arrival order"
        );

        prop_assert_eq!(
            pool_a.entropy_for_height(height),
            pool_b.entropy_for_height(height),
            "same winner/output set must produce same entropy independent of arrival order"
        );
    }

    // 13/25
    #[test]
    fn test_013_entropy_changes_when_new_winner_is_added(
        height in any::<u64>(),
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        output_a in any::<u128>(),
        output_b in any::<u128>(),
    ) {
        prop_assume!(seed_a != seed_b);

        let mut pool = PorPuzzlePool::new();

        pool.record_success_checked(height, &wallet(seed_a), output(output_a))
            .expect("first winner should record");

        let entropy_one = pool.entropy_for_height(height)
            .expect("first winner should create entropy");

        pool.record_success_checked(height, &wallet(seed_b), output(output_b))
            .expect("second winner should record");

        let entropy_two = pool.entropy_for_height(height)
            .expect("second winner should keep entropy present");

        prop_assert_ne!(
            entropy_one,
            entropy_two,
            "adding a new winner must change entropy"
        );
    }

    // 14/25
    #[test]
    fn test_014_heights_are_isolated_for_winners_and_entropy(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let other_height = height.wrapping_add(1);
        prop_assume!(other_height != height);

        let mut pool = PorPuzzlePool::new();
        let wallet = wallet(seed);
        let out = output(output_seed);

        pool.record_success_checked(height, &wallet, out)
            .expect("valid winner should record at source height");

        prop_assert_eq!(
            pool.winners_for_height(height),
            vec![wallet],
            "source height must contain recorded winner"
        );

        prop_assert!(
            pool.winners_for_height(other_height).is_empty(),
            "other height must not inherit winners"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_some(),
            "source height must have entropy"
        );

        prop_assert!(
            pool.entropy_for_height(other_height).is_none(),
            "other height must not inherit entropy"
        );
    }

    // 15/25
    #[test]
    fn test_015_same_wallet_output_at_different_heights_has_independent_state(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let other_height = height.wrapping_add(1);
        prop_assume!(other_height != height);

        let mut pool = PorPuzzlePool::new();
        let wallet = wallet(seed);
        let out = output(output_seed);

        pool.record_success_checked(height, &wallet, out)
            .expect("first height insert should succeed");

        pool.record_success_checked(other_height, &wallet, out)
            .expect("second height insert should succeed");

        prop_assert_eq!(
            pool.winners_for_height(height),
            vec![wallet.clone()],
            "first height must retain its winner"
        );

        prop_assert_eq!(
            pool.winners_for_height(other_height),
            vec![wallet],
            "second height must retain its winner"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_some(),
            "first height must have entropy"
        );

        prop_assert!(
            pool.entropy_for_height(other_height).is_some(),
            "second height must have entropy"
        );
    }

    // 16/25
    #[test]
    fn test_016_record_success_wrapper_ignores_invalid_wallet_without_panic_or_mutation(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.record_success(height, &wallet_with_prefix('p', seed), output(output_seed));
        }));

        prop_assert!(
            result.is_ok(),
            "convenience record_success must ignore failures without panicking"
        );

        prop_assert!(
            pool.winners_for_height(height).is_empty(),
            "record_success with invalid wallet must not mutate winners"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_none(),
            "record_success with invalid wallet must not create entropy"
        );
    }

    // 17/25
    #[test]
    fn test_017_record_success_wrapper_records_valid_wallet(
        height in any::<u64>(),
        seed in any::<u64>(),
        output_seed in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();
        let wallet = wallet(seed);

        pool.record_success(height, &wallet, output(output_seed));

        prop_assert_eq!(
            pool.winners_for_height(height),
            vec![wallet],
            "convenience record_success must record valid winners"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_some(),
            "convenience record_success must create entropy for valid winners"
        );
    }

    // 18/25
    #[test]
    fn test_018_gc_below_removes_lower_heights_and_keeps_boundary_and_above(
        base_height in any::<u64>(),
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        seed_c in any::<u64>(),
    ) {
        prop_assume!(base_height <= u64::MAX.saturating_sub(2));

        let h0 = base_height;
        let h1 = base_height.saturating_add(1);
        let h2 = base_height.saturating_add(2);

        let mut pool = PorPuzzlePool::new();

        pool.record_success_checked(h0, &wallet(seed_a), 1)
            .expect("h0 insert should succeed");
        pool.record_success_checked(h1, &wallet(seed_b), 2)
            .expect("h1 insert should succeed");
        pool.record_success_checked(h2, &wallet(seed_c), 3)
            .expect("h2 insert should succeed");

        pool.gc_below(h1);

        prop_assert!(
            pool.winners_for_height(h0).is_empty(),
            "gc_below must remove heights below threshold"
        );

        prop_assert!(
            pool.entropy_for_height(h0).is_none(),
            "gc_below must remove entropy below threshold"
        );

        prop_assert!(
            !pool.winners_for_height(h1).is_empty(),
            "gc_below must keep boundary height"
        );

        prop_assert!(
            !pool.winners_for_height(h2).is_empty(),
            "gc_below must keep heights above boundary"
        );
    }

    // 19/25
    #[test]
    fn test_019_gc_below_zero_keeps_all_heights(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let mut pool = PorPuzzlePool::new();
        let wallet = wallet(seed);

        pool.record_success_checked(height, &wallet, 1)
            .expect("valid insert should succeed");

        pool.gc_below(0);

        prop_assert_eq!(
            pool.winners_for_height(height),
            vec![wallet],
            "gc_below(0) must keep every possible u64 height"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_some(),
            "gc_below(0) must keep entropy"
        );
    }

    // 20/25
    #[test]
    fn test_020_gc_below_max_removes_all_but_u64_max_height(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        prop_assume!(height < u64::MAX);

        let mut pool = PorPuzzlePool::new();

        pool.record_success_checked(height, &wallet(seed), 1)
            .expect("valid insert should succeed");

        pool.gc_below(u64::MAX);

        prop_assert!(
            pool.winners_for_height(height).is_empty(),
            "gc_below(u64::MAX) must remove all lower heights"
        );

        prop_assert!(
            pool.entropy_for_height(height).is_none(),
            "gc_below(u64::MAX) must remove all lower-height entropy"
        );
    }

    // 21/25
    #[test]
    fn test_021_clone_preserves_winners_and_entropy_but_allows_independent_mutation(
        height in any::<u64>(),
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        prop_assume!(seed_a != seed_b);

        let mut original = PorPuzzlePool::new();

        original.record_success_checked(height, &wallet(seed_a), 1)
            .expect("original insert should succeed");

        let mut cloned = original.clone();

        prop_assert_eq!(
            cloned.winners_for_height(height),
            original.winners_for_height(height),
            "clone must preserve winners"
        );

        prop_assert_eq!(
            cloned.entropy_for_height(height),
            original.entropy_for_height(height),
            "clone must preserve entropy"
        );

        cloned.record_success_checked(height, &wallet(seed_b), 2)
            .expect("cloned pool should accept independent mutation");

        prop_assert_ne!(
            cloned.winners_for_height(height),
            original.winners_for_height(height),
            "mutating clone must not mutate original winners"
        );

        prop_assert_ne!(
            cloned.entropy_for_height(height),
            original.entropy_for_height(height),
            "mutating clone must not mutate original entropy"
        );
    }

    // 22/25
    #[test]
    fn test_022_debug_output_is_available_without_exposing_secret_state_requirements(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let mut pool = PorPuzzlePool::new();

        pool.record_success_checked(height, &wallet(seed), 1)
            .expect("valid insert should succeed");

        let debug = format!("{:?}", pool);

        prop_assert!(
            debug.contains("winners"),
            "Debug output should include winners field name for diagnostics"
        );

        prop_assert!(
            debug.contains("entropy"),
            "Debug output should include entropy field name for diagnostics"
        );
    }

    // 23/25
    #[test]
    fn test_023_winner_cap_allows_existing_wallet_overwrite_even_after_many_unique_inserts(
        height in any::<u64>(),
        seed in 1u64..=1_000_000u64,
        replacement_output in any::<u128>(),
    ) {
        let mut pool = PorPuzzlePool::new();

        let bounded_count = GlobalConfiguration::MAX_BATCH_ITEMS.min(64).max(1);
        let inserted = record_many_unique(&mut pool, height, bounded_count, seed);

        prop_assert!(
            inserted >= 1,
            "test setup must insert at least one winner"
        );

        let first_wallet = wallet(seed);

        pool.record_success_checked(height, &first_wallet, output(replacement_output))
            .expect("existing wallet overwrite must be allowed even near/at winner cap");

        prop_assert!(
            pool.winners_for_height(height).contains(&first_wallet),
            "overwritten wallet must remain present"
        );
    }

    // 24/25
    #[test]
    fn test_024_winner_cap_rejects_new_wallet_when_configured_cap_is_reached_if_cap_is_small(
        height in any::<u64>(),
        seed in 1u64..=1_000_000u64,
    ) {
        let mut pool = PorPuzzlePool::new();
        let cap = GlobalConfiguration::MAX_BATCH_ITEMS;

        if cap <= 64 {
            let inserted = record_many_unique(&mut pool, height, cap, seed);

            prop_assert_eq!(
                inserted,
                cap,
                "test setup must fill winner cap exactly"
            );

            let new_seed = seed.saturating_add(cap as u64).saturating_add(1);

            prop_assert!(
                pool.record_success_checked(height, &wallet(new_seed), 999).is_err(),
                "new wallet above configured winner cap must be rejected"
            );
        } else {
            let inserted = record_many_unique(&mut pool, height, 64, seed);

            prop_assert_eq!(
                inserted,
                64,
                "when configured cap is large, bounded test inserts must still succeed"
            );

            prop_assert_eq!(
                pool.winners_for_height(height).len(),
                64,
                "bounded winner set should contain all inserted winners"
            );
        }
    }

    // 25/25
    #[test]
    fn test_025_public_entrypoints_never_panic_for_arbitrary_public_inputs(
        height in any::<u64>(),
        wallet_text in ".{0,512}",
        output_value in any::<u128>(),
        min_height in any::<u64>(),
    ) {
        let mut pool = PorPuzzlePool::new();

        let checked_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = pool.record_success_checked(height, &wallet_text, output_value);
        }));

        prop_assert!(
            checked_result.is_ok(),
            "record_success_checked must return Ok/Err, not panic, for arbitrary public wallet strings"
        );

        let wrapper_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.record_success(height, &wallet_text, output_value);
        }));

        prop_assert!(
            wrapper_result.is_ok(),
            "record_success wrapper must not panic for arbitrary public wallet strings"
        );

        let read_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = pool.winners_for_height(height);
            let _ = pool.entropy_for_height(height);
            pool.gc_below(min_height);
        }));

        prop_assert!(
            read_result.is_ok(),
            "read and GC public entrypoints must not panic for arbitrary heights"
        );
    }
}
