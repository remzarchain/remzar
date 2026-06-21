use remzar::consensus::por_003_puzzle_pool::{PorPuzzlePool, RemzarHash64};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::canon_wallet_id_checked;
use std::collections::BTreeMap;
use std::error::Error;
use std::io;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ENTROPY_TAG_FOR_TEST: &[u8] = b"por-puzzle-entropy-64-v1";

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn assert_validation_error_contains<T>(
    result: Result<T, ErrorDetection>,
    expected: &str,
) -> TestResult<String> {
    match result {
        Ok(_) => Err(test_error("expected validation error but got Ok")),
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert_eq!(tx_id, None);
            assert!(message.contains(expected));
            Ok(message)
        }
        Err(other) => Err(Box::new(io::Error::other(format!(
            "unexpected error variant: {other:?}"
        )))),
    }
}

fn reference_entropy_from_pairs(pairs: &[(String, u128)]) -> TestResult<RemzarHash64> {
    let mut map = BTreeMap::<String, u128>::new();

    for (wallet_addr, output) in pairs {
        let canonical = canon_wallet_id_checked(wallet_addr)?;
        map.insert(canonical, *output);
    }

    let mut cap = 0_usize;
    for wallet_addr in map.keys() {
        cap = cap
            .checked_add(wallet_addr.len())
            .and_then(|value| value.checked_add(16))
            .ok_or_else(|| test_error("reference entropy capacity overflowed"))?;
    }

    let mut preimage = Vec::with_capacity(cap);
    for (wallet_addr, output) in &map {
        preimage.extend_from_slice(wallet_addr.as_bytes());
        preimage.extend_from_slice(&output.to_be_bytes());
    }

    let h0 = RemzarHash::compute_bytes_hash(&preimage);

    let tagged_cap = ENTROPY_TAG_FOR_TEST
        .len()
        .checked_add(preimage.len())
        .ok_or_else(|| test_error("reference tagged capacity overflowed"))?;
    let mut tagged = Vec::with_capacity(tagged_cap);
    tagged.extend_from_slice(ENTROPY_TAG_FOR_TEST);
    tagged.extend_from_slice(&preimage);

    let h1 = RemzarHash::compute_bytes_hash(&tagged);

    let mut out = [0_u8; 64];
    out[..32].copy_from_slice(&h0[..32]);
    out[32..].copy_from_slice(&h1[..32]);

    Ok(out)
}

fn entropy_for_height_or_error(pool: &PorPuzzlePool, height: u64) -> TestResult<RemzarHash64> {
    pool.entropy_for_height(height)
        .ok_or_else(|| test_error("missing entropy for height"))
}

#[test]
fn test_01_new_pool_starts_empty() {
    let pool = PorPuzzlePool::new();

    assert!(pool.winners_for_height(1).is_empty());
    assert_eq!(pool.entropy_for_height(1), None);
}

#[test]
fn test_02_default_pool_starts_empty() {
    let pool = PorPuzzlePool::default();

    assert!(pool.winners_for_height(0).is_empty());
    assert_eq!(pool.entropy_for_height(0), None);
}

#[test]
fn test_03_record_success_checked_records_single_winner() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(3);

    pool.record_success_checked(10, &wallet_a, 123)?;

    assert_eq!(pool.winners_for_height(10), vec![wallet_a]);
    assert!(pool.entropy_for_height(10).is_some());
    Ok(())
}

#[test]
fn test_04_record_success_checked_canonicalizes_uppercase_wallet() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(4);
    let uppercase = canonical.to_ascii_uppercase();

    pool.record_success_checked(4, &uppercase, 44)?;

    assert_eq!(pool.winners_for_height(4), vec![canonical]);
    Ok(())
}

#[test]
fn test_05_record_success_checked_canonicalizes_trimmed_uppercase_wallet() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(5);
    let input = format!(" \n{}\t ", canonical.to_ascii_uppercase());

    pool.record_success_checked(5, &input, 55)?;

    assert_eq!(pool.winners_for_height(5), vec![canonical]);
    Ok(())
}

#[test]
fn test_06_record_success_checked_rejects_invalid_wallet_without_mutation() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    let message = assert_validation_error_contains(
        pool.record_success_checked(6, "not-a-wallet", 66),
        "Wallet",
    )?;

    assert!(!message.is_empty());
    assert!(pool.winners_for_height(6).is_empty());
    assert_eq!(pool.entropy_for_height(6), None);
    Ok(())
}

#[test]
fn test_07_record_success_checked_rejects_wallet_over_raw_length_cap() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let too_long_wallet = "r".repeat(257);

    let message = assert_validation_error_contains(
        pool.record_success_checked(7, &too_long_wallet, 77),
        "wallet too long",
    )?;

    assert!(message.contains("max=256"));
    assert!(pool.winners_for_height(7).is_empty());
    Ok(())
}

#[test]
fn test_08_record_success_wrapper_ignores_invalid_wallet_without_panic() {
    let mut pool = PorPuzzlePool::new();

    pool.record_success(8, "not-a-wallet", 88);

    assert!(pool.winners_for_height(8).is_empty());
    assert_eq!(pool.entropy_for_height(8), None);
}

#[test]
fn test_09_winners_for_height_are_sorted_by_canonical_wallet() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(1);
    let wallet_b = wallet(2);
    let wallet_c = wallet(3);

    pool.record_success_checked(9, &wallet_c, 30)?;
    pool.record_success_checked(9, &wallet_a, 10)?;
    pool.record_success_checked(9, &wallet_b, 20)?;

    assert_eq!(
        pool.winners_for_height(9),
        vec![wallet_a, wallet_b, wallet_c]
    );
    Ok(())
}

#[test]
fn test_10_winners_are_isolated_by_height() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(10);
    let wallet_b = wallet(11);

    pool.record_success_checked(10, &wallet_a, 100)?;
    pool.record_success_checked(11, &wallet_b, 110)?;

    assert_eq!(pool.winners_for_height(10), vec![wallet_a]);
    assert_eq!(pool.winners_for_height(11), vec![wallet_b]);
    assert!(pool.winners_for_height(12).is_empty());
    Ok(())
}

#[test]
fn test_11_entropy_for_height_is_64_bytes_after_success() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    pool.record_success_checked(11, &wallet(11), 111)?;

    let entropy = entropy_for_height_or_error(&pool, 11)?;
    assert_eq!(entropy.len(), 64);
    Ok(())
}

#[test]
fn test_12_entropy_matches_reference_for_single_winner_vector() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(12);
    let pairs = vec![(wallet_a.clone(), 12_345_u128)];

    pool.record_success_checked(12, &wallet_a, 12_345)?;

    assert_eq!(
        entropy_for_height_or_error(&pool, 12)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_13_entropy_matches_reference_for_multiple_winner_vector() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let pairs = vec![
        (wallet(13), 130_u128),
        (wallet(14), 140_u128),
        (wallet(15), 150_u128),
    ];

    for (wallet_addr, output) in &pairs {
        pool.record_success_checked(13, wallet_addr, *output)?;
    }

    assert_eq!(
        entropy_for_height_or_error(&pool, 13)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_14_entropy_is_order_independent_for_same_winner_map() -> TestResult {
    let pairs = vec![
        (wallet(20), 200_u128),
        (wallet(21), 210_u128),
        (wallet(22), 220_u128),
        (wallet(23), 230_u128),
    ];
    let mut forward = PorPuzzlePool::new();
    let mut reverse = PorPuzzlePool::new();

    for (wallet_addr, output) in &pairs {
        forward.record_success_checked(14, wallet_addr, *output)?;
    }

    for (wallet_addr, output) in pairs.iter().rev() {
        reverse.record_success_checked(14, wallet_addr, *output)?;
    }

    assert_eq!(
        entropy_for_height_or_error(&forward, 14)?,
        entropy_for_height_or_error(&reverse, 14)?
    );
    assert_eq!(
        forward.winners_for_height(14),
        reverse.winners_for_height(14)
    );
    Ok(())
}

#[test]
fn test_15_re_recording_same_wallet_same_output_preserves_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(15);

    pool.record_success_checked(15, &wallet_a, 777)?;
    let first_entropy = entropy_for_height_or_error(&pool, 15)?;

    pool.record_success_checked(15, &wallet_a, 777)?;
    let second_entropy = entropy_for_height_or_error(&pool, 15)?;

    assert_eq!(first_entropy, second_entropy);
    assert_eq!(pool.winners_for_height(15), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_16_re_recording_same_wallet_different_output_changes_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(16);

    pool.record_success_checked(16, &wallet_a, 1)?;
    let first_entropy = entropy_for_height_or_error(&pool, 16)?;

    pool.record_success_checked(16, &wallet_a, 2)?;
    let second_entropy = entropy_for_height_or_error(&pool, 16)?;

    assert_ne!(first_entropy, second_entropy);
    assert_eq!(pool.winners_for_height(16), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_17_overwriting_same_wallet_does_not_duplicate_winner() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(17);

    pool.record_success_checked(17, &wallet_a, 1)?;
    pool.record_success_checked(17, &wallet_a, 2)?;
    pool.record_success_checked(17, &wallet_a, 3)?;

    assert_eq!(pool.winners_for_height(17), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_18_entropy_zero_output_vector_matches_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(18);
    let pairs = vec![(wallet_a.clone(), 0_u128)];

    pool.record_success_checked(18, &wallet_a, 0)?;

    assert_eq!(
        entropy_for_height_or_error(&pool, 18)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_19_entropy_u128_max_output_vector_matches_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(19);
    let pairs = vec![(wallet_a.clone(), u128::MAX)];

    pool.record_success_checked(19, &wallet_a, u128::MAX)?;

    assert_eq!(
        entropy_for_height_or_error(&pool, 19)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_20_height_zero_is_accepted() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(20);

    pool.record_success_checked(0, &wallet_a, 20)?;

    assert_eq!(pool.winners_for_height(0), vec![wallet_a]);
    assert!(pool.entropy_for_height(0).is_some());
    Ok(())
}

#[test]
fn test_21_height_u64_max_is_accepted() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(21);

    pool.record_success_checked(u64::MAX, &wallet_a, 21)?;

    assert_eq!(pool.winners_for_height(u64::MAX), vec![wallet_a]);
    assert!(pool.entropy_for_height(u64::MAX).is_some());
    Ok(())
}

#[test]
fn test_22_gc_below_removes_lower_heights() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(22);

    pool.record_success_checked(10, &wallet_a, 10)?;
    pool.record_success_checked(20, &wallet_a, 20)?;
    pool.record_success_checked(30, &wallet_a, 30)?;

    pool.gc_below(20);

    assert!(pool.winners_for_height(10).is_empty());
    assert_eq!(pool.entropy_for_height(10), None);
    assert_eq!(pool.winners_for_height(20), vec![wallet_a.clone()]);
    assert_eq!(pool.winners_for_height(30), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_23_gc_below_keeps_exact_min_height() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(23);

    pool.record_success_checked(23, &wallet_a, 23)?;
    pool.gc_below(23);

    assert_eq!(pool.winners_for_height(23), vec![wallet_a]);
    assert!(pool.entropy_for_height(23).is_some());
    Ok(())
}

#[test]
fn test_24_gc_below_above_all_heights_clears_all_entries() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(24);

    pool.record_success_checked(1, &wallet_a, 1)?;
    pool.record_success_checked(2, &wallet_a, 2)?;
    pool.gc_below(3);

    assert!(pool.winners_for_height(1).is_empty());
    assert!(pool.winners_for_height(2).is_empty());
    assert_eq!(pool.entropy_for_height(1), None);
    assert_eq!(pool.entropy_for_height(2), None);
    Ok(())
}

#[test]
fn test_25_clone_preserves_data_but_mutates_independently() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(25);
    let wallet_b = wallet(26);

    pool.record_success_checked(25, &wallet_a, 25)?;

    let mut cloned = pool.clone();
    cloned.record_success_checked(25, &wallet_b, 26)?;

    assert_eq!(pool.winners_for_height(25), vec![wallet_a.clone()]);
    assert_eq!(cloned.winners_for_height(25), vec![wallet_a, wallet_b]);
    Ok(())
}

#[test]
fn test_26_debug_output_contains_struct_field_names() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    pool.record_success_checked(26, &wallet(26), 26)?;

    let debug_text = format!("{pool:?}");
    assert!(debug_text.contains("PorPuzzlePool"));
    assert!(debug_text.contains("winners"));
    assert!(debug_text.contains("entropy"));
    Ok(())
}

#[test]
fn test_27_failed_record_does_not_create_entropy_for_height() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    let _message = assert_validation_error_contains(
        pool.record_success_checked(27, "bad-wallet", 27),
        "Wallet",
    )?;

    assert!(pool.winners_for_height(27).is_empty());
    assert_eq!(pool.entropy_for_height(27), None);
    Ok(())
}

#[test]
fn test_28_too_long_wallet_error_mentions_actual_length_and_max() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let too_long_wallet = "x".repeat(300);

    let message = assert_validation_error_contains(
        pool.record_success_checked(28, &too_long_wallet, 28),
        "wallet too long",
    )?;

    assert!(message.contains("len=300"));
    assert!(message.contains("max=256"));
    Ok(())
}

#[test]
fn test_29_invalid_wallet_error_is_validation_error_with_no_tx_id() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    match pool.record_success_checked(29, "bad-wallet", 29) {
        Err(ErrorDetection::ValidationError { message, tx_id }) => {
            assert_eq!(tx_id, None);
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(()) => Err(test_error("expected invalid wallet to fail")),
        Err(other) => Err(Box::new(io::Error::other(format!(
            "unexpected error variant: {other:?}"
        )))),
    }
}

#[test]
fn test_30_multiple_outputs_same_height_keep_only_sorted_wallets_publicly() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(30);
    let wallet_b = wallet(31);

    pool.record_success_checked(30, &wallet_b, u128::MAX)?;
    pool.record_success_checked(30, &wallet_a, 0)?;

    assert_eq!(pool.winners_for_height(30), vec![wallet_a, wallet_b]);
    Ok(())
}

#[test]
fn test_31_same_wallet_across_different_heights_is_isolated() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(31);

    pool.record_success_checked(31, &wallet_a, 1)?;
    pool.record_success_checked(32, &wallet_a, 2)?;

    assert_eq!(pool.winners_for_height(31), vec![wallet_a.clone()]);
    assert_eq!(pool.winners_for_height(32), vec![wallet_a]);
    assert_ne!(
        entropy_for_height_or_error(&pool, 31)?,
        entropy_for_height_or_error(&pool, 32)?
    );
    Ok(())
}

#[test]
fn test_32_entropy_changes_when_output_changes_for_same_wallet() -> TestResult {
    let wallet_a = wallet(32);
    let first = reference_entropy_from_pairs(&[(wallet_a.clone(), 1)])?;
    let second = reference_entropy_from_pairs(&[(wallet_a, 2)])?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn test_33_entropy_changes_when_wallet_changes_for_same_output() -> TestResult {
    let first = reference_entropy_from_pairs(&[(wallet(33), 999)])?;
    let second = reference_entropy_from_pairs(&[(wallet(34), 999)])?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn test_34_entropy_same_for_identical_winner_maps_at_different_heights() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(34);

    pool.record_success_checked(34, &wallet_a, 340)?;
    pool.record_success_checked(35, &wallet_a, 340)?;

    assert_eq!(
        entropy_for_height_or_error(&pool, 34)?,
        entropy_for_height_or_error(&pool, 35)?
    );
    Ok(())
}

#[test]
fn test_35_record_success_wrapper_records_valid_input() {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(35);

    pool.record_success(35, &wallet_a, 35);

    assert_eq!(pool.winners_for_height(35), vec![wallet_a]);
    assert!(pool.entropy_for_height(35).is_some());
}

#[test]
fn test_36_record_success_wrapper_invalid_after_valid_does_not_corrupt_existing_height()
-> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(36);

    pool.record_success_checked(36, &wallet_a, 36)?;
    let before = entropy_for_height_or_error(&pool, 36)?;

    pool.record_success(36, "bad-wallet", 999);

    assert_eq!(pool.winners_for_height(36), vec![wallet_a]);
    assert_eq!(entropy_for_height_or_error(&pool, 36)?, before);
    Ok(())
}

#[test]
fn test_37_vector_sixteen_winners_match_expected_sorted_list_and_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let mut pairs = Vec::<(String, u128)>::new();

    for seed in (100_u64..116_u64).rev() {
        let wallet_addr = wallet(seed);
        let output = u128::from(seed).saturating_mul(10);
        pool.record_success_checked(37, &wallet_addr, output)?;
        pairs.push((wallet_addr, output));
    }

    let mut expected_wallets = pairs
        .iter()
        .map(|(wallet_addr, _output)| wallet_addr.clone())
        .collect::<Vec<_>>();
    expected_wallets.sort();

    assert_eq!(pool.winners_for_height(37), expected_wallets);
    assert_eq!(
        entropy_for_height_or_error(&pool, 37)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_38_vector_reverse_insert_order_has_same_entropy_as_forward_insert_order() -> TestResult {
    let mut forward = PorPuzzlePool::new();
    let mut reverse = PorPuzzlePool::new();
    let mut pairs = Vec::<(String, u128)>::new();

    for seed in 200_u64..216_u64 {
        pairs.push((wallet(seed), u128::from(seed).saturating_mul(17)));
    }

    for (wallet_addr, output) in &pairs {
        forward.record_success_checked(38, wallet_addr, *output)?;
    }

    for (wallet_addr, output) in pairs.iter().rev() {
        reverse.record_success_checked(38, wallet_addr, *output)?;
    }

    assert_eq!(
        entropy_for_height_or_error(&forward, 38)?,
        entropy_for_height_or_error(&reverse, 38)?
    );
    assert_eq!(
        forward.winners_for_height(38),
        reverse.winners_for_height(38)
    );
    Ok(())
}

#[test]
fn test_39_fuzz_invalid_wallet_inputs_are_rejected_without_mutation() {
    let mut pool = PorPuzzlePool::new();
    let invalid_wallets = [
        String::new(),
        "r".to_string(),
        "not-a-wallet".to_string(),
        format!("x{}", "0".repeat(128)),
        format!("r{}", "g".repeat(128)),
        format!("r{}", "0".repeat(127)),
        format!("r{}", "0".repeat(129)),
        "☃".to_string(),
        "x".repeat(300),
    ];

    for invalid_wallet in invalid_wallets {
        assert!(
            pool.record_success_checked(39, &invalid_wallet, 39)
                .is_err()
        );
        assert!(pool.winners_for_height(39).is_empty());
        assert_eq!(pool.entropy_for_height(39), None);
    }
}

#[test]
fn test_40_load_many_heights_then_gc_keeps_expected_tail() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    for height in 0_u64..128_u64 {
        let wallet_addr = wallet(height);
        pool.record_success_checked(height, &wallet_addr, u128::from(height))?;
    }

    for height in 0_u64..128_u64 {
        assert_eq!(pool.winners_for_height(height), vec![wallet(height)]);
        assert!(pool.entropy_for_height(height).is_some());
    }

    pool.gc_below(96);

    for height in 0_u64..96_u64 {
        assert!(pool.winners_for_height(height).is_empty());
        assert_eq!(pool.entropy_for_height(height), None);
    }

    for height in 96_u64..128_u64 {
        assert_eq!(pool.winners_for_height(height), vec![wallet(height)]);
        assert!(pool.entropy_for_height(height).is_some());
    }

    Ok(())
}

#[test]
fn test_41_gc_below_zero_keeps_all_entries() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(41);
    let wallet_b = wallet(42);

    pool.record_success_checked(0, &wallet_a, 41)?;
    pool.record_success_checked(1, &wallet_b, 42)?;
    pool.gc_below(0);

    assert_eq!(pool.winners_for_height(0), vec![wallet_a]);
    assert_eq!(pool.winners_for_height(1), vec![wallet_b]);
    assert!(pool.entropy_for_height(0).is_some());
    assert!(pool.entropy_for_height(1).is_some());
    Ok(())
}

#[test]
fn test_42_gc_below_u64_max_keeps_only_u64_max_height() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let low_wallet = wallet(42);
    let max_wallet = wallet(43);

    pool.record_success_checked(u64::MAX.saturating_sub(1), &low_wallet, 1)?;
    pool.record_success_checked(u64::MAX, &max_wallet, 2)?;
    pool.gc_below(u64::MAX);

    assert!(
        pool.winners_for_height(u64::MAX.saturating_sub(1))
            .is_empty()
    );
    assert_eq!(pool.entropy_for_height(u64::MAX.saturating_sub(1)), None);
    assert_eq!(pool.winners_for_height(u64::MAX), vec![max_wallet]);
    assert!(pool.entropy_for_height(u64::MAX).is_some());
    Ok(())
}

#[test]
fn test_43_repeated_gc_is_idempotent() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(43);
    let wallet_b = wallet(44);

    pool.record_success_checked(10, &wallet_a, 10)?;
    pool.record_success_checked(20, &wallet_b, 20)?;
    pool.gc_below(15);

    let winners_after_first = pool.winners_for_height(20);
    let entropy_after_first = entropy_for_height_or_error(&pool, 20)?;

    pool.gc_below(15);
    pool.gc_below(15);

    assert!(pool.winners_for_height(10).is_empty());
    assert_eq!(pool.winners_for_height(20), winners_after_first);
    assert_eq!(entropy_for_height_or_error(&pool, 20)?, entropy_after_first);
    Ok(())
}

#[test]
fn test_44_winners_for_height_returns_owned_vector_not_live_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(44);

    pool.record_success_checked(44, &wallet_a, 44)?;

    let mut winners = pool.winners_for_height(44);
    winners.push(wallet(45));

    assert_eq!(pool.winners_for_height(44), vec![wallet_a]);
    assert_eq!(winners.len(), 2);
    Ok(())
}

#[test]
fn test_45_entropy_for_height_returns_copy_not_live_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(45);

    pool.record_success_checked(45, &wallet_a, 45)?;

    let mut copied_entropy = entropy_for_height_or_error(&pool, 45)?;
    copied_entropy[0] ^= 0xFF;

    assert_ne!(copied_entropy, entropy_for_height_or_error(&pool, 45)?);
    Ok(())
}

#[test]
fn test_46_entropy_is_none_after_gc_removes_only_height() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(46);

    pool.record_success_checked(46, &wallet_a, 46)?;
    pool.gc_below(47);

    assert!(pool.winners_for_height(46).is_empty());
    assert_eq!(pool.entropy_for_height(46), None);
    Ok(())
}

#[test]
fn test_47_entropy_reference_for_uppercase_input_uses_canonical_lowercase_wallet() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(47);
    let uppercase = canonical.to_ascii_uppercase();
    let pairs = vec![(canonical.clone(), 47_u128)];

    pool.record_success_checked(47, &uppercase, 47)?;

    assert_eq!(pool.winners_for_height(47), vec![canonical]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 47)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_48_entropy_reference_for_trimmed_input_uses_canonical_wallet() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(48);
    let input = format!(" \r\n{}\t ", canonical.to_ascii_uppercase());
    let pairs = vec![(canonical.clone(), 48_u128)];

    pool.record_success_checked(48, &input, 48)?;

    assert_eq!(pool.winners_for_height(48), vec![canonical]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 48)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_49_vector_output_byte_order_zero_and_one_are_distinct() -> TestResult {
    let mut zero_pool = PorPuzzlePool::new();
    let mut one_pool = PorPuzzlePool::new();
    let wallet_a = wallet(49);

    zero_pool.record_success_checked(49, &wallet_a, 0)?;
    one_pool.record_success_checked(49, &wallet_a, 1)?;

    assert_ne!(
        entropy_for_height_or_error(&zero_pool, 49)?,
        entropy_for_height_or_error(&one_pool, 49)?
    );
    Ok(())
}

#[test]
fn test_50_vector_output_high_bit_changes_entropy() -> TestResult {
    let mut low_pool = PorPuzzlePool::new();
    let mut high_pool = PorPuzzlePool::new();
    let wallet_a = wallet(50);

    low_pool.record_success_checked(50, &wallet_a, 0)?;
    high_pool.record_success_checked(50, &wallet_a, 1_u128 << 127)?;

    assert_ne!(
        entropy_for_height_or_error(&low_pool, 50)?,
        entropy_for_height_or_error(&high_pool, 50)?
    );
    Ok(())
}

#[test]
fn test_51_vector_adjacent_wallets_with_same_output_have_distinct_entropy() -> TestResult {
    let mut first = PorPuzzlePool::new();
    let mut second = PorPuzzlePool::new();

    first.record_success_checked(51, &wallet(51), 777)?;
    second.record_success_checked(51, &wallet(52), 777)?;

    assert_ne!(
        entropy_for_height_or_error(&first, 51)?,
        entropy_for_height_or_error(&second, 51)?
    );
    Ok(())
}

#[test]
fn test_52_vector_same_height_same_wallet_different_outputs_match_reference_after_overwrite()
-> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(52);

    pool.record_success_checked(52, &wallet_a, 1)?;
    pool.record_success_checked(52, &wallet_a, u128::MAX)?;

    assert_eq!(
        entropy_for_height_or_error(&pool, 52)?,
        reference_entropy_from_pairs(&[(wallet_a.clone(), u128::MAX)])?
    );
    assert_eq!(pool.winners_for_height(52), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_53_vector_overwrite_then_add_second_wallet_matches_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(53);
    let wallet_b = wallet(54);

    pool.record_success_checked(53, &wallet_a, 1)?;
    pool.record_success_checked(53, &wallet_a, 2)?;
    pool.record_success_checked(53, &wallet_b, 3)?;

    let pairs = vec![(wallet_a.clone(), 2_u128), (wallet_b.clone(), 3_u128)];

    assert_eq!(pool.winners_for_height(53), vec![wallet_a, wallet_b]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 53)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_54_vector_add_second_wallet_then_overwrite_first_matches_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(54);
    let wallet_b = wallet(55);

    pool.record_success_checked(54, &wallet_a, 10)?;
    pool.record_success_checked(54, &wallet_b, 20)?;
    pool.record_success_checked(54, &wallet_a, 30)?;

    let pairs = vec![(wallet_a.clone(), 30_u128), (wallet_b.clone(), 20_u128)];

    assert_eq!(pool.winners_for_height(54), vec![wallet_a, wallet_b]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 54)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_55_record_success_wrapper_overwrites_existing_valid_output() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(55);

    pool.record_success_checked(55, &wallet_a, 1)?;
    pool.record_success(55, &wallet_a, 2);

    assert_eq!(
        entropy_for_height_or_error(&pool, 55)?,
        reference_entropy_from_pairs(&[(wallet_a.clone(), 2)])?
    );
    assert_eq!(pool.winners_for_height(55), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_56_record_success_wrapper_invalid_on_empty_height_stays_empty() {
    let mut pool = PorPuzzlePool::new();

    pool.record_success(56, "bad-wallet", 56);
    pool.record_success(56, &"x".repeat(300), 57);

    assert!(pool.winners_for_height(56).is_empty());
    assert_eq!(pool.entropy_for_height(56), None);
}

#[test]
fn test_57_record_success_wrapper_invalid_on_other_height_does_not_touch_valid_height() -> TestResult
{
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(57);

    pool.record_success_checked(57, &wallet_a, 57)?;
    let before = entropy_for_height_or_error(&pool, 57)?;

    pool.record_success(58, "bad-wallet", 58);

    assert_eq!(pool.winners_for_height(57), vec![wallet_a]);
    assert_eq!(entropy_for_height_or_error(&pool, 57)?, before);
    assert!(pool.winners_for_height(58).is_empty());
    Ok(())
}

#[test]
fn test_58_uppercase_duplicate_same_wallet_does_not_duplicate_public_winners() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(58);

    pool.record_success_checked(58, &canonical, 1)?;
    pool.record_success_checked(58, &canonical.to_ascii_uppercase(), 2)?;

    assert_eq!(pool.winners_for_height(58), vec![canonical.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 58)?,
        reference_entropy_from_pairs(&[(canonical, 2)])?
    );
    Ok(())
}

#[test]
fn test_59_trimmed_duplicate_same_wallet_does_not_duplicate_public_winners() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(59);
    let trimmed = format!(" \n{}\t", canonical.to_ascii_uppercase());

    pool.record_success_checked(59, &canonical, 1)?;
    pool.record_success_checked(59, &trimmed, 2)?;

    assert_eq!(pool.winners_for_height(59), vec![canonical.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 59)?,
        reference_entropy_from_pairs(&[(canonical, 2)])?
    );
    Ok(())
}

#[test]
fn test_60_vector_single_winner_outputs_are_ordered_by_output_bytes_in_entropy_reference()
-> TestResult {
    let wallet_a = wallet(60);
    let first = reference_entropy_from_pairs(&[(wallet_a.clone(), 0x01_u128)])?;
    let second = reference_entropy_from_pairs(&[(wallet_a, 0x0100_u128)])?;

    assert_ne!(first, second);
    Ok(())
}

#[test]
fn test_61_vector_winner_sorting_handles_all_zero_wallet_first() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let all_zero = format!("r{}", "0".repeat(128));
    let regular = wallet(61);

    pool.record_success_checked(61, &regular, 1)?;
    pool.record_success_checked(61, &all_zero, 2)?;

    assert_eq!(pool.winners_for_height(61), vec![all_zero, regular]);
    Ok(())
}

#[test]
fn test_62_vector_winner_sorting_handles_all_f_wallet_last() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let all_f = format!("r{}", "f".repeat(128));
    let regular = wallet(62);

    pool.record_success_checked(62, &all_f, 1)?;
    pool.record_success_checked(62, &regular, 2)?;

    assert_eq!(pool.winners_for_height(62), vec![regular, all_f]);
    Ok(())
}

#[test]
fn test_63_invalid_wallet_too_short_after_valid_same_height_does_not_change_entropy() -> TestResult
{
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(63);

    pool.record_success_checked(63, &wallet_a, 63)?;
    let before = entropy_for_height_or_error(&pool, 63)?;

    assert!(pool.record_success_checked(63, "r123", 999).is_err());

    assert_eq!(pool.winners_for_height(63), vec![wallet_a]);
    assert_eq!(entropy_for_height_or_error(&pool, 63)?, before);
    Ok(())
}

#[test]
fn test_64_invalid_wallet_bad_hex_after_valid_same_height_does_not_change_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(64);
    let bad_hex = format!("r{}", "g".repeat(128));

    pool.record_success_checked(64, &wallet_a, 64)?;
    let before = entropy_for_height_or_error(&pool, 64)?;

    assert!(pool.record_success_checked(64, &bad_hex, 999).is_err());

    assert_eq!(pool.winners_for_height(64), vec![wallet_a]);
    assert_eq!(entropy_for_height_or_error(&pool, 64)?, before);
    Ok(())
}

#[test]
fn test_65_invalid_wallet_bad_prefix_after_valid_same_height_does_not_change_entropy() -> TestResult
{
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(65);
    let bad_prefix = format!("x{}", "0".repeat(128));

    pool.record_success_checked(65, &wallet_a, 65)?;
    let before = entropy_for_height_or_error(&pool, 65)?;

    assert!(pool.record_success_checked(65, &bad_prefix, 999).is_err());

    assert_eq!(pool.winners_for_height(65), vec![wallet_a]);
    assert_eq!(entropy_for_height_or_error(&pool, 65)?, before);
    Ok(())
}

#[test]
fn test_66_invalid_wallet_too_long_after_valid_same_height_does_not_change_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(66);
    let too_long = "r".repeat(257);

    pool.record_success_checked(66, &wallet_a, 66)?;
    let before = entropy_for_height_or_error(&pool, 66)?;

    assert!(pool.record_success_checked(66, &too_long, 999).is_err());

    assert_eq!(pool.winners_for_height(66), vec![wallet_a]);
    assert_eq!(entropy_for_height_or_error(&pool, 66)?, before);
    Ok(())
}

#[test]
fn test_67_clone_entropy_matches_original_before_independent_mutation() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(67);

    pool.record_success_checked(67, &wallet_a, 67)?;

    let cloned = pool.clone();

    assert_eq!(pool.winners_for_height(67), cloned.winners_for_height(67));
    assert_eq!(
        entropy_for_height_or_error(&pool, 67)?,
        entropy_for_height_or_error(&cloned, 67)?
    );
    Ok(())
}

#[test]
fn test_68_clone_gc_does_not_affect_original() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(68);

    pool.record_success_checked(68, &wallet_a, 68)?;

    let mut cloned = pool.clone();
    cloned.gc_below(69);

    assert_eq!(pool.winners_for_height(68), vec![wallet_a]);
    assert!(pool.entropy_for_height(68).is_some());
    assert!(cloned.winners_for_height(68).is_empty());
    assert_eq!(cloned.entropy_for_height(68), None);
    Ok(())
}

#[test]
fn test_69_gc_then_re_record_same_height_recreates_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(69);

    pool.record_success_checked(69, &wallet_a, 69)?;
    pool.gc_below(70);

    assert_eq!(pool.entropy_for_height(69), None);

    pool.record_success_checked(69, &wallet_a, 690)?;

    assert_eq!(pool.winners_for_height(69), vec![wallet_a.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 69)?,
        reference_entropy_from_pairs(&[(wallet_a, 690)])?
    );
    Ok(())
}

#[test]
fn test_70_gc_keeps_entropy_consistent_for_surviving_multi_winner_height() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let pairs = vec![
        (wallet(70), 1_u128),
        (wallet(71), 2_u128),
        (wallet(72), 3_u128),
    ];

    for (wallet_addr, output) in &pairs {
        pool.record_success_checked(70, wallet_addr, *output)?;
    }
    pool.record_success_checked(69, &wallet(69), 69)?;

    pool.gc_below(70);

    assert_eq!(
        entropy_for_height_or_error(&pool, 70)?,
        reference_entropy_from_pairs(&pairs)?
    );
    assert_eq!(pool.entropy_for_height(69), None);
    Ok(())
}

#[test]
fn test_71_vector_empty_height_queries_are_stable() {
    let pool = PorPuzzlePool::new();

    for height in [0_u64, 1, 2, 100, u64::MAX] {
        assert!(pool.winners_for_height(height).is_empty());
        assert_eq!(pool.entropy_for_height(height), None);
    }
}

#[test]
fn test_72_vector_many_heights_same_wallet_have_same_single_winner_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(72);

    for height in 72_u64..80_u64 {
        pool.record_success_checked(height, &wallet_a, 123)?;
    }

    let expected = reference_entropy_from_pairs(&[(wallet_a.clone(), 123)])?;

    for height in 72_u64..80_u64 {
        assert_eq!(pool.winners_for_height(height), vec![wallet_a.clone()]);
        assert_eq!(entropy_for_height_or_error(&pool, height)?, expected);
    }

    Ok(())
}

#[test]
fn test_73_vector_many_heights_same_wallet_distinct_outputs_have_distinct_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(73);
    let mut entropies = Vec::new();

    for height in 73_u64..81_u64 {
        pool.record_success_checked(height, &wallet_a, u128::from(height))?;
        entropies.push(entropy_for_height_or_error(&pool, height)?);
    }

    entropies.sort();
    entropies.dedup();

    assert_eq!(entropies.len(), 8);
    Ok(())
}

#[test]
fn test_74_fuzz_style_valid_wallets_produce_sorted_unique_winners() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    for seed in (0_u64..64_u64).rev() {
        pool.record_success_checked(74, &wallet(seed), u128::from(seed))?;
    }

    let mut expected = (0_u64..64_u64).map(wallet).collect::<Vec<_>>();
    expected.sort();

    assert_eq!(pool.winners_for_height(74), expected);
    assert!(pool.entropy_for_height(74).is_some());
    Ok(())
}

#[test]
fn test_75_fuzz_style_overwrites_even_seeds_match_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let mut pairs = Vec::<(String, u128)>::new();

    for seed in 0_u64..32_u64 {
        let wallet_addr = wallet(seed);
        pool.record_success_checked(75, &wallet_addr, u128::from(seed))?;

        let final_output = if seed % 2 == 0 {
            u128::from(seed).saturating_add(10_000)
        } else {
            u128::from(seed)
        };

        if seed % 2 == 0 {
            pool.record_success_checked(75, &wallet_addr, final_output)?;
        }

        pairs.push((wallet_addr, final_output));
    }

    assert_eq!(
        entropy_for_height_or_error(&pool, 75)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_76_load_record_success_wrapper_many_valid_inputs() {
    let mut pool = PorPuzzlePool::new();

    for seed in 0_u64..128_u64 {
        pool.record_success(76, &wallet(seed), u128::from(seed));
    }

    let mut expected = (0_u64..128_u64).map(wallet).collect::<Vec<_>>();
    expected.sort();

    assert_eq!(pool.winners_for_height(76), expected);
    assert!(pool.entropy_for_height(76).is_some());
}

#[test]
fn test_77_load_record_success_wrapper_mixed_valid_invalid_inputs() {
    let mut pool = PorPuzzlePool::new();

    for seed in 0_u64..64_u64 {
        pool.record_success(77, &wallet(seed), u128::from(seed));
        pool.record_success(77, "bad-wallet", 999);
        pool.record_success(77, &format!("r{}", "z".repeat(128)), 999);
    }

    let mut expected = (0_u64..64_u64).map(wallet).collect::<Vec<_>>();
    expected.sort();

    assert_eq!(pool.winners_for_height(77), expected);
    assert!(pool.entropy_for_height(77).is_some());
}

#[test]
fn test_78_entropy_for_large_valid_winner_set_matches_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let mut pairs = Vec::<(String, u128)>::new();

    for seed in 300_u64..364_u64 {
        let wallet_addr = wallet(seed);
        let output = u128::from(seed).saturating_mul(u128::from(seed));
        pool.record_success_checked(78, &wallet_addr, output)?;
        pairs.push((wallet_addr, output));
    }

    assert_eq!(
        entropy_for_height_or_error(&pool, 78)?,
        reference_entropy_from_pairs(&pairs)?
    );
    Ok(())
}

#[test]
fn test_79_entropy_changes_after_each_new_distinct_winner() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let mut previous_entropy: Option<RemzarHash64> = None;

    for seed in 0_u64..32_u64 {
        pool.record_success_checked(79, &wallet(seed), u128::from(seed))?;
        let current_entropy = entropy_for_height_or_error(&pool, 79)?;

        if let Some(previous) = previous_entropy {
            assert_ne!(previous, current_entropy);
        }

        previous_entropy = Some(current_entropy);
    }

    Ok(())
}

#[test]
fn test_80_adversarial_many_duplicate_forms_keep_one_canonical_winner() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(80);
    let uppercase = canonical.to_ascii_uppercase();
    let trimmed_lower = format!("  {canonical}\n");
    let trimmed_upper = format!("\t{uppercase}\r\n");

    pool.record_success_checked(80, &canonical, 1)?;
    pool.record_success_checked(80, &uppercase, 2)?;
    pool.record_success_checked(80, &trimmed_lower, 3)?;
    pool.record_success_checked(80, &trimmed_upper, 4)?;

    assert_eq!(pool.winners_for_height(80), vec![canonical.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 80)?,
        reference_entropy_from_pairs(&[(canonical, 4)])?
    );
    Ok(())
}

#[test]
fn test_81_edge_all_zero_wallet_and_zero_output_entropy_matches_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let all_zero_wallet = format!("r{}", "0".repeat(128));

    pool.record_success_checked(81, &all_zero_wallet, 0)?;

    assert_eq!(pool.winners_for_height(81), vec![all_zero_wallet.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 81)?,
        reference_entropy_from_pairs(&[(all_zero_wallet, 0)])?
    );
    Ok(())
}

#[test]
fn test_82_edge_all_f_wallet_and_u128_max_output_entropy_matches_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let all_f_wallet = format!("r{}", "f".repeat(128));

    pool.record_success_checked(82, &all_f_wallet, u128::MAX)?;

    assert_eq!(pool.winners_for_height(82), vec![all_f_wallet.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 82)?,
        reference_entropy_from_pairs(&[(all_f_wallet, u128::MAX)])?
    );
    Ok(())
}

#[test]
fn test_83_vector_boundary_outputs_for_same_wallet_all_have_distinct_entropy() -> TestResult {
    let wallet_a = wallet(83);
    let outputs = [
        0_u128,
        1_u128,
        255_u128,
        256_u128,
        u128::from(u64::MAX),
        u128::MAX,
    ];
    let mut entropies = Vec::new();

    for output in outputs {
        let mut pool = PorPuzzlePool::new();
        pool.record_success_checked(83, &wallet_a, output)?;
        entropies.push(entropy_for_height_or_error(&pool, 83)?);
    }

    entropies.sort();
    entropies.dedup();

    assert_eq!(entropies.len(), outputs.len());
    Ok(())
}

#[test]
fn test_84_vector_boundary_heights_do_not_affect_identical_single_winner_entropy() -> TestResult {
    let wallet_a = wallet(84);
    let output = 84_u128;
    let mut pool = PorPuzzlePool::new();

    for height in [0_u64, 1_u64, u64::MAX.saturating_sub(1), u64::MAX] {
        pool.record_success_checked(height, &wallet_a, output)?;
    }

    let expected = reference_entropy_from_pairs(&[(wallet_a.clone(), output)])?;

    for height in [0_u64, 1_u64, u64::MAX.saturating_sub(1), u64::MAX] {
        assert_eq!(pool.winners_for_height(height), vec![wallet_a.clone()]);
        assert_eq!(entropy_for_height_or_error(&pool, height)?, expected);
    }

    Ok(())
}

#[test]
fn test_85_edge_gc_below_one_removes_height_zero_only() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let zero_wallet = wallet(850);
    let one_wallet = wallet(851);

    pool.record_success_checked(0, &zero_wallet, 0)?;
    pool.record_success_checked(1, &one_wallet, 1)?;

    pool.gc_below(1);

    assert!(pool.winners_for_height(0).is_empty());
    assert_eq!(pool.entropy_for_height(0), None);
    assert_eq!(pool.winners_for_height(1), vec![one_wallet]);
    assert!(pool.entropy_for_height(1).is_some());
    Ok(())
}

#[test]
fn test_86_edge_gc_below_u64_max_after_reinsert_at_max_keeps_max_only() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let near_max_wallet = wallet(860);
    let max_wallet = wallet(861);

    pool.record_success_checked(u64::MAX.saturating_sub(1), &near_max_wallet, 1)?;
    pool.record_success_checked(u64::MAX, &max_wallet, 2)?;
    pool.gc_below(u64::MAX);

    assert!(
        pool.winners_for_height(u64::MAX.saturating_sub(1))
            .is_empty()
    );
    assert_eq!(pool.entropy_for_height(u64::MAX.saturating_sub(1)), None);
    assert_eq!(pool.winners_for_height(u64::MAX), vec![max_wallet.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, u64::MAX)?,
        reference_entropy_from_pairs(&[(max_wallet, 2)])?
    );
    Ok(())
}

#[test]
fn test_87_vector_reinsert_after_gc_uses_new_output_only() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(87);

    pool.record_success_checked(87, &wallet_a, 1)?;
    pool.gc_below(88);
    pool.record_success_checked(87, &wallet_a, 999)?;

    assert_eq!(pool.winners_for_height(87), vec![wallet_a.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 87)?,
        reference_entropy_from_pairs(&[(wallet_a, 999)])?
    );
    Ok(())
}

#[test]
fn test_88_vector_same_wallet_same_output_reinsert_after_gc_recreates_same_entropy() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(88);

    pool.record_success_checked(88, &wallet_a, 888)?;
    let first = entropy_for_height_or_error(&pool, 88)?;

    pool.gc_below(89);
    pool.record_success_checked(88, &wallet_a, 888)?;

    let second = entropy_for_height_or_error(&pool, 88)?;

    assert_eq!(first, second);
    assert_eq!(pool.winners_for_height(88), vec![wallet_a]);
    Ok(())
}

#[test]
fn test_89_edge_public_winner_list_has_no_output_leakage() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(89);

    pool.record_success_checked(89, &wallet_a, u128::MAX)?;

    let winners = pool.winners_for_height(89);
    assert_eq!(winners, vec![wallet_a]);
    assert!(!winners[0].contains(&u128::MAX.to_string()));
    Ok(())
}

#[test]
fn test_90_vector_invalid_wallet_length_boundaries_reject_and_preserve_existing_entropy()
-> TestResult {
    let mut pool = PorPuzzlePool::new();
    let valid_wallet = wallet(90);

    pool.record_success_checked(90, &valid_wallet, 90)?;
    let before = entropy_for_height_or_error(&pool, 90)?;

    let invalid_short = format!("r{}", "0".repeat(127));
    let invalid_long = format!("r{}", "0".repeat(129));

    assert!(
        pool.record_success_checked(90, &invalid_short, 900)
            .is_err()
    );
    assert!(pool.record_success_checked(90, &invalid_long, 901).is_err());

    assert_eq!(pool.winners_for_height(90), vec![valid_wallet]);
    assert_eq!(entropy_for_height_or_error(&pool, 90)?, before);
    Ok(())
}

#[test]
fn test_91_vector_invalid_wallet_prefix_and_hex_reject_and_preserve_existing_entropy() -> TestResult
{
    let mut pool = PorPuzzlePool::new();
    let valid_wallet = wallet(91);

    pool.record_success_checked(91, &valid_wallet, 91)?;
    let before = entropy_for_height_or_error(&pool, 91)?;

    let invalid_prefix = format!("x{}", "0".repeat(128));
    let invalid_hex = format!("r{}", "z".repeat(128));

    assert!(
        pool.record_success_checked(91, &invalid_prefix, 910)
            .is_err()
    );
    assert!(pool.record_success_checked(91, &invalid_hex, 911).is_err());

    assert_eq!(pool.winners_for_height(91), vec![valid_wallet]);
    assert_eq!(entropy_for_height_or_error(&pool, 91)?, before);
    Ok(())
}

#[test]
fn test_92_edge_non_ascii_wallet_rejects_without_creating_height() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    let message =
        assert_validation_error_contains(pool.record_success_checked(92, "r☃", 92), "Wallet")?;

    assert!(!message.is_empty());
    assert!(pool.winners_for_height(92).is_empty());
    assert_eq!(pool.entropy_for_height(92), None);
    Ok(())
}

#[test]
fn test_93_vector_case_canonicalization_duplicate_chain_final_output_wins() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let canonical = wallet(93);
    let upper = canonical.to_ascii_uppercase();
    let lower_spaced = format!(" {canonical} ");
    let upper_spaced = format!("\n{upper}\t");

    pool.record_success_checked(93, &canonical, 1)?;
    pool.record_success_checked(93, &upper, 2)?;
    pool.record_success_checked(93, &lower_spaced, 3)?;
    pool.record_success_checked(93, &upper_spaced, 4)?;

    assert_eq!(pool.winners_for_height(93), vec![canonical.clone()]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 93)?,
        reference_entropy_from_pairs(&[(canonical, 4)])?
    );
    Ok(())
}

#[test]
fn test_94_vector_two_wallets_overwritten_in_reverse_order_match_reference() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(94);
    let wallet_b = wallet(95);

    pool.record_success_checked(94, &wallet_b, 1)?;
    pool.record_success_checked(94, &wallet_a, 2)?;
    pool.record_success_checked(94, &wallet_b, 3)?;
    pool.record_success_checked(94, &wallet_a, 4)?;

    let expected_pairs = vec![(wallet_a.clone(), 4_u128), (wallet_b.clone(), 3_u128)];

    assert_eq!(pool.winners_for_height(94), vec![wallet_a, wallet_b]);
    assert_eq!(
        entropy_for_height_or_error(&pool, 94)?,
        reference_entropy_from_pairs(&expected_pairs)?
    );
    Ok(())
}

#[test]
fn test_95_vector_entropy_domain_separator_changes_second_half_from_plain_hash() -> TestResult {
    let wallet_a = wallet(95);
    let pairs = vec![(wallet_a.clone(), 95_u128)];
    let entropy = reference_entropy_from_pairs(&pairs)?;

    let mut preimage = Vec::new();
    preimage.extend_from_slice(wallet_a.as_bytes());
    preimage.extend_from_slice(&95_u128.to_be_bytes());
    let plain = RemzarHash::compute_bytes_hash(&preimage);

    assert_eq!(&entropy[..32], &plain[..32]);
    assert_ne!(&entropy[32..], &plain[32..64]);
    Ok(())
}

#[test]
fn test_96_vector_entropy_second_half_matches_tagged_reference() -> TestResult {
    let wallet_a = wallet(96);
    let pairs = vec![(wallet_a.clone(), 96_u128)];
    let entropy = reference_entropy_from_pairs(&pairs)?;

    let mut preimage = Vec::new();
    preimage.extend_from_slice(wallet_a.as_bytes());
    preimage.extend_from_slice(&96_u128.to_be_bytes());

    let mut tagged = Vec::new();
    tagged.extend_from_slice(ENTROPY_TAG_FOR_TEST);
    tagged.extend_from_slice(&preimage);

    let tagged_hash = RemzarHash::compute_bytes_hash(&tagged);

    assert_eq!(&entropy[32..], &tagged_hash[..32]);
    Ok(())
}

#[test]
fn test_97_vector_entropy_first_half_matches_plain_reference() -> TestResult {
    let wallet_a = wallet(97);
    let pairs = vec![(wallet_a.clone(), 97_u128)];
    let entropy = reference_entropy_from_pairs(&pairs)?;

    let mut preimage = Vec::new();
    preimage.extend_from_slice(wallet_a.as_bytes());
    preimage.extend_from_slice(&97_u128.to_be_bytes());

    let plain = RemzarHash::compute_bytes_hash(&preimage);

    assert_eq!(&entropy[..32], &plain[..32]);
    Ok(())
}

#[test]
fn test_98_load_vector_gc_stair_step_preserves_expected_suffixes() -> TestResult {
    let mut pool = PorPuzzlePool::new();

    for height in 0_u64..32_u64 {
        pool.record_success_checked(height, &wallet(height), u128::from(height))?;
    }

    for min_height in [0_u64, 8, 16, 24, 32] {
        pool.gc_below(min_height);

        for height in 0_u64..32_u64 {
            if height < min_height {
                assert!(pool.winners_for_height(height).is_empty());
                assert_eq!(pool.entropy_for_height(height), None);
            } else {
                assert_eq!(pool.winners_for_height(height), vec![wallet(height)]);
                assert!(pool.entropy_for_height(height).is_some());
            }
        }
    }

    Ok(())
}

#[test]
fn test_99_load_vector_repeated_same_output_overwrites_keep_entropy_stable() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(99);

    pool.record_success_checked(99, &wallet_a, 9_999)?;
    let expected = entropy_for_height_or_error(&pool, 99)?;

    for _ in 0_u64..128_u64 {
        pool.record_success_checked(99, &wallet_a, 9_999)?;
        assert_eq!(entropy_for_height_or_error(&pool, 99)?, expected);
        assert_eq!(pool.winners_for_height(99), vec![wallet_a.clone()]);
    }

    Ok(())
}

#[test]
fn test_100_load_vector_repeated_output_changes_update_entropy_each_time() -> TestResult {
    let mut pool = PorPuzzlePool::new();
    let wallet_a = wallet(100);
    let mut previous: Option<RemzarHash64> = None;

    for output in 0_u128..64_u128 {
        pool.record_success_checked(100, &wallet_a, output)?;
        let current = entropy_for_height_or_error(&pool, 100)?;

        if let Some(previous_entropy) = previous {
            assert_ne!(previous_entropy, current);
        }

        assert_eq!(pool.winners_for_height(100), vec![wallet_a.clone()]);
        previous = Some(current);
    }

    Ok(())
}
