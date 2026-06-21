use remzar::{
    blockchain::halving_schedule::RewardHalving,
    utility::alpha_001_global_configuration::GlobalConfiguration,
};

type TestResult = Result<(), String>;

fn interval() -> u64 {
    GlobalConfiguration::HALVING_INTERVAL_BLOCKS
}

fn prefix() -> u64 {
    GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS
}

fn total_reward_blocks() -> u64 {
    GlobalConfiguration::TOTAL_REWARD_BLOCKS
}

fn max_reward_supply() -> u128 {
    GlobalConfiguration::MAX_REWARD_SUPPLY as u128
}

fn seq_len_u64() -> u64 {
    GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() as u64
}

fn sequence_end_height() -> u64 {
    interval().saturating_mul(seq_len_u64())
}

fn raw_nominal_issued_to(height: u64) -> u128 {
    let interval = interval();
    let height = height.min(total_reward_blocks());
    let full_periods = height / interval;
    let sequence_periods = full_periods.min(seq_len_u64());
    let take_n = usize::try_from(sequence_periods).unwrap_or(usize::MAX);

    let issued_sequence = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE
        .iter()
        .take(take_n)
        .map(|reward| (*reward as u128).saturating_mul(interval as u128))
        .sum::<u128>();

    let stabilized_intervals = full_periods.saturating_sub(seq_len_u64());
    let issued_stabilized = (GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128)
        .saturating_mul(stabilized_intervals as u128)
        .saturating_mul(interval as u128);

    let remainder_blocks = height % interval;
    let partial_reward = if remainder_blocks == 0 {
        0
    } else if full_periods < seq_len_u64() {
        let index = usize::try_from(full_periods).unwrap_or(usize::MAX);
        GlobalConfiguration::REWARD_REDUCTION_SEQUENCE
            .get(index)
            .copied()
            .unwrap_or(0) as u128
    } else {
        GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128
    };

    issued_sequence
        .saturating_add(issued_stabilized)
        .saturating_add((remainder_blocks as u128).saturating_mul(partial_reward))
}

fn expected_issued_to(height: u64) -> u128 {
    let height = height.min(total_reward_blocks());
    let prefix_height = prefix().min(height);

    raw_nominal_issued_to(height).saturating_sub(raw_nominal_issued_to(prefix_height))
}

fn expected_reward(height: u64) -> u64 {
    if interval() == 0 {
        return 0;
    }

    if height < prefix() {
        return 0;
    }

    if height >= total_reward_blocks() {
        return 0;
    }

    let issued_before = expected_issued_to(height);
    let remaining = max_reward_supply().saturating_sub(issued_before);

    if remaining == 0 {
        return 0;
    }

    let index_u64 = height / interval();
    let scheduled = match usize::try_from(index_u64) {
        Ok(index) => {
            if index < GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
                GlobalConfiguration::REWARD_REDUCTION_SEQUENCE[index] as u128
            } else if GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD == 0 {
                0
            } else {
                GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128
            }
        }
        Err(_) => 0,
    };

    u64::try_from(scheduled.min(remaining)).unwrap_or(u64::MAX)
}

fn expected_remaining_after_block(height: u64) -> u128 {
    let exclusive_height = height.saturating_add(1).min(total_reward_blocks());
    max_reward_supply().saturating_sub(expected_issued_to(exclusive_height))
}

fn assert_reward(height: u64) {
    assert_eq!(
        RewardHalving::get_block_reward(height),
        expected_reward(height),
        "reward mismatch at height {height}"
    );
}

fn assert_remaining_after(height: u64) {
    assert_eq!(
        RewardHalving::remaining_reward_supply_micro_after_block(height),
        expected_remaining_after_block(height),
        "remaining supply mismatch after height {height}"
    );
}

fn useful_heights() -> Vec<u64> {
    let mut heights = vec![
        0,
        1,
        prefix(),
        prefix().saturating_add(1),
        interval().saturating_sub(1),
        interval(),
        interval().saturating_add(1),
        sequence_end_height().saturating_sub(1),
        sequence_end_height(),
        sequence_end_height().saturating_add(1),
        total_reward_blocks().saturating_sub(1),
        total_reward_blocks(),
        total_reward_blocks().saturating_add(1),
        u64::MAX,
    ];

    for index in 0..GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len().min(16) {
        let base = interval().saturating_mul(index as u64);
        heights.push(base);
        heights.push(base.saturating_add(1));
        heights.push(base.saturating_add(interval().saturating_sub(1)));
    }

    heights.sort_unstable();
    heights.dedup();
    heights
}

#[test]
fn reward_halving_001_height_zero_matches_expected_reward() -> TestResult {
    assert_reward(0);
    Ok(())
}

#[test]
fn reward_halving_002_height_one_matches_expected_reward() -> TestResult {
    assert_reward(1);
    Ok(())
}

#[test]
fn reward_halving_003_rewardless_prefix_heights_are_zero() -> TestResult {
    for height in 0..prefix().min(32) {
        assert_eq!(RewardHalving::get_block_reward(height), 0);
    }

    Ok(())
}

#[test]
fn reward_halving_004_prefix_boundary_matches_expected_reward() -> TestResult {
    assert_reward(prefix());
    Ok(())
}

#[test]
fn reward_halving_005_prefix_plus_one_matches_expected_reward() -> TestResult {
    assert_reward(prefix().saturating_add(1));
    Ok(())
}

#[test]
fn reward_halving_006_first_interval_start_matches_expected_reward() -> TestResult {
    assert_reward(interval());
    Ok(())
}

#[test]
fn reward_halving_007_first_interval_end_matches_expected_reward() -> TestResult {
    assert_reward(interval().saturating_sub(1));
    Ok(())
}

#[test]
fn reward_halving_008_second_interval_start_matches_expected_reward() -> TestResult {
    assert_reward(interval().saturating_mul(2));
    Ok(())
}

#[test]
fn reward_halving_009_second_interval_middle_matches_expected_reward() -> TestResult {
    assert_reward(interval().saturating_mul(2).saturating_add(interval() / 2));
    Ok(())
}

#[test]
fn reward_halving_010_every_sampled_height_matches_expected_reward() -> TestResult {
    for height in useful_heights() {
        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_011_validate_block_reward_accepts_height_zero_vector() -> TestResult {
    RewardHalving::validate_block_reward(0, expected_reward(0))
}

#[test]
fn reward_halving_012_validate_block_reward_accepts_prefix_vector() -> TestResult {
    RewardHalving::validate_block_reward(prefix(), expected_reward(prefix()))
}

#[test]
fn reward_halving_013_validate_block_reward_accepts_interval_vector() -> TestResult {
    RewardHalving::validate_block_reward(interval(), expected_reward(interval()))
}

#[test]
fn reward_halving_014_validate_block_reward_accepts_last_reward_block_vector() -> TestResult {
    let height = total_reward_blocks().saturating_sub(1);

    RewardHalving::validate_block_reward(height, expected_reward(height))
}

#[test]
fn reward_halving_015_validate_block_reward_rejects_wrong_expected_value() -> TestResult {
    let height = prefix();
    let wrong = expected_reward(height).saturating_add(1);
    let err = RewardHalving::validate_block_reward(height, wrong)
        .expect_err("wrong expected reward should fail validation");

    assert!(err.contains("Reward mismatch"));
    assert!(err.contains(&height.to_string()));

    Ok(())
}

#[test]
fn reward_halving_016_rewards_at_rewardless_prefix_are_zero_until_prefix() -> TestResult {
    let check_count = prefix().min(128);

    for height in 0..check_count {
        assert_eq!(RewardHalving::get_block_reward(height), 0);
    }

    Ok(())
}

#[test]
fn reward_halving_017_reward_at_schedule_end_is_zero() -> TestResult {
    assert_eq!(RewardHalving::get_block_reward(total_reward_blocks()), 0);
    Ok(())
}

#[test]
fn reward_halving_018_reward_after_schedule_end_is_zero() -> TestResult {
    assert_eq!(
        RewardHalving::get_block_reward(total_reward_blocks().saturating_add(1)),
        0
    );

    Ok(())
}

#[test]
fn reward_halving_019_reward_at_u64_max_is_zero() -> TestResult {
    assert_eq!(RewardHalving::get_block_reward(u64::MAX), 0);
    Ok(())
}

#[test]
fn reward_halving_020_last_reward_block_matches_expected_reward() -> TestResult {
    assert_reward(total_reward_blocks().saturating_sub(1));
    Ok(())
}

#[test]
fn reward_halving_021_remaining_after_height_zero_matches_expected() -> TestResult {
    assert_remaining_after(0);
    Ok(())
}

#[test]
fn reward_halving_022_remaining_after_prefix_matches_expected() -> TestResult {
    assert_remaining_after(prefix());
    Ok(())
}

#[test]
fn reward_halving_023_remaining_after_interval_matches_expected() -> TestResult {
    assert_remaining_after(interval());
    Ok(())
}

#[test]
fn reward_halving_024_remaining_after_last_reward_block_matches_expected() -> TestResult {
    assert_remaining_after(total_reward_blocks().saturating_sub(1));
    Ok(())
}

#[test]
fn reward_halving_025_remaining_after_schedule_end_matches_expected() -> TestResult {
    assert_remaining_after(total_reward_blocks());
    Ok(())
}

#[test]
fn reward_halving_026_remaining_after_u64_max_matches_expected() -> TestResult {
    assert_remaining_after(u64::MAX);
    Ok(())
}

#[test]
fn reward_halving_027_remaining_supply_never_exceeds_max_supply() -> TestResult {
    for height in useful_heights() {
        assert!(
            RewardHalving::remaining_reward_supply_micro_after_block(height) <= max_reward_supply()
        );
    }

    Ok(())
}

#[test]
fn reward_halving_028_rewards_never_exceed_first_minted_reward() -> TestResult {
    let first_minted_reward = RewardHalving::get_block_reward(prefix());

    for height in useful_heights() {
        assert!(
            RewardHalving::get_block_reward(height) <= first_minted_reward,
            "reward at height {height} exceeded first minted reward"
        );
    }

    Ok(())
}

#[test]
fn reward_halving_029_rewards_match_reduction_sequence_for_sampled_sequence_periods() -> TestResult
{
    for (index, scheduled) in GlobalConfiguration::REWARD_REDUCTION_SEQUENCE
        .iter()
        .copied()
        .enumerate()
        .take(32)
    {
        let height = interval().saturating_mul(index as u64);

        if height >= prefix() && height < total_reward_blocks() {
            let remaining = max_reward_supply().saturating_sub(expected_issued_to(height));
            let expected = u64::try_from((scheduled as u128).min(remaining)).unwrap_or(u64::MAX);

            assert_eq!(RewardHalving::get_block_reward(height), expected);
        }
    }

    Ok(())
}

#[test]
fn reward_halving_030_interval_end_rewards_match_same_period_expected() -> TestResult {
    for index in 0..GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len().min(32) {
        let height = interval()
            .saturating_mul(index as u64)
            .saturating_add(interval().saturating_sub(1));

        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_031_sequence_end_boundary_matches_expected_reward() -> TestResult {
    assert_reward(sequence_end_height());
    Ok(())
}

#[test]
fn reward_halving_032_sequence_end_minus_one_matches_expected_reward() -> TestResult {
    assert_reward(sequence_end_height().saturating_sub(1));
    Ok(())
}

#[test]
fn reward_halving_033_sequence_end_plus_one_matches_expected_reward() -> TestResult {
    assert_reward(sequence_end_height().saturating_add(1));
    Ok(())
}

#[test]
fn reward_halving_034_stabilized_tail_start_matches_expected_reward() -> TestResult {
    let height = sequence_end_height().max(prefix());

    assert_reward(height);

    Ok(())
}

#[test]
fn reward_halving_035_stabilized_tail_midpoint_matches_expected_reward() -> TestResult {
    let start = sequence_end_height().max(prefix());
    let end = total_reward_blocks();

    let midpoint = start.saturating_add(end.saturating_sub(start) / 2);

    assert_reward(midpoint);

    Ok(())
}

#[test]
fn reward_halving_036_stabilized_tail_last_block_matches_expected_reward() -> TestResult {
    assert_reward(total_reward_blocks().saturating_sub(1));
    Ok(())
}

#[test]
fn reward_halving_037_remaining_supply_is_monotonic_non_increasing_for_samples() -> TestResult {
    let mut previous = max_reward_supply();

    for height in useful_heights() {
        let current = RewardHalving::remaining_reward_supply_micro_after_block(height);

        assert!(
            current <= previous,
            "remaining supply increased at height {height}: {current} > {previous}"
        );

        previous = current;
    }

    Ok(())
}

#[test]
fn reward_halving_038_remaining_supply_decreases_by_reward_for_adjacent_sample() -> TestResult {
    let height = prefix().max(1);
    let before = RewardHalving::remaining_reward_supply_micro_after_block(height.saturating_sub(1));
    let after = RewardHalving::remaining_reward_supply_micro_after_block(height);
    let reward = RewardHalving::get_block_reward(height) as u128;

    assert_eq!(before.saturating_sub(after), reward.min(before));

    Ok(())
}

#[test]
fn reward_halving_039_remaining_supply_after_rewardless_prefix_is_expected() -> TestResult {
    for height in 0..prefix().min(16) {
        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_040_total_issued_never_exceeds_max_supply_in_samples() -> TestResult {
    for height in useful_heights() {
        let issued = max_reward_supply().saturating_sub(
            RewardHalving::remaining_reward_supply_micro_after_block(height),
        );

        assert!(issued <= max_reward_supply());
    }

    Ok(())
}

#[test]
fn reward_halving_041_reward_is_zero_when_remaining_supply_is_zero_or_schedule_ended() -> TestResult
{
    let height = total_reward_blocks();

    assert_eq!(RewardHalving::get_block_reward(height), 0);

    Ok(())
}

#[test]
fn reward_halving_042_reward_is_clamped_to_remaining_supply() -> TestResult {
    for height in useful_heights() {
        let issued_before = expected_issued_to(height);
        let remaining = max_reward_supply().saturating_sub(issued_before);

        assert!((RewardHalving::get_block_reward(height) as u128) <= remaining);
    }

    Ok(())
}

#[test]
fn reward_halving_043_expected_issued_to_zero_is_zero() -> TestResult {
    assert_eq!(expected_issued_to(0), 0);
    Ok(())
}

#[test]
fn reward_halving_044_expected_issued_to_prefix_is_zero() -> TestResult {
    assert_eq!(expected_issued_to(prefix()), 0);
    Ok(())
}

#[test]
fn reward_halving_045_expected_issued_to_is_monotonic_for_samples() -> TestResult {
    let mut previous = 0_u128;

    for height in useful_heights() {
        let issued = expected_issued_to(height);

        assert!(issued >= previous);
        previous = issued;
    }

    Ok(())
}

#[test]
fn reward_halving_046_remaining_after_block_equals_max_minus_expected_issued() -> TestResult {
    for height in useful_heights() {
        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_047_validate_block_reward_message_contains_expected_and_actual() -> TestResult {
    let height = prefix();
    let actual = RewardHalving::get_block_reward(height);
    let wrong = actual.saturating_add(1);
    let err = RewardHalving::validate_block_reward(height, wrong)
        .expect_err("wrong reward should produce error text");

    assert!(err.contains("expected"));
    assert!(err.contains("got"));
    assert!(err.contains(&wrong.to_string()));
    assert!(err.contains(&actual.to_string()));

    Ok(())
}

#[test]
fn reward_halving_048_validate_block_reward_accepts_many_sampled_heights() -> TestResult {
    for height in useful_heights() {
        RewardHalving::validate_block_reward(height, expected_reward(height))?;
    }

    Ok(())
}

#[test]
fn reward_halving_049_first_32_blocks_match_expected_rewards() -> TestResult {
    for height in 0..32_u64 {
        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_050_first_32_blocks_remaining_supply_matches_expected() -> TestResult {
    for height in 0..32_u64 {
        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_051_first_16_interval_boundaries_match_expected_rewards() -> TestResult {
    for index in 0..16_u64 {
        assert_reward(interval().saturating_mul(index));
    }

    Ok(())
}

#[test]
fn reward_halving_052_first_16_interval_boundary_remaining_values_match_expected() -> TestResult {
    for index in 0..16_u64 {
        assert_remaining_after(interval().saturating_mul(index));
    }

    Ok(())
}

#[test]
fn reward_halving_053_first_16_interval_end_values_match_expected_rewards() -> TestResult {
    for index in 1..=16_u64 {
        assert_reward(interval().saturating_mul(index).saturating_sub(1));
    }

    Ok(())
}

#[test]
fn reward_halving_054_first_16_interval_end_remaining_values_match_expected() -> TestResult {
    for index in 1..=16_u64 {
        assert_remaining_after(interval().saturating_mul(index).saturating_sub(1));
    }

    Ok(())
}

#[test]
fn reward_halving_055_first_sequence_reward_is_used_after_prefix_when_applicable() -> TestResult {
    let height = prefix();

    assert_reward(height);

    Ok(())
}

#[test]
fn reward_halving_056_reward_before_prefix_is_zero_even_if_inside_first_interval() -> TestResult {
    let height = prefix().saturating_sub(1);

    if height < prefix() {
        assert_eq!(RewardHalving::get_block_reward(height), 0);
    } else {
        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_057_remaining_supply_at_block_before_prefix_matches_expected() -> TestResult {
    let height = prefix().saturating_sub(1);

    assert_remaining_after(height);

    Ok(())
}

#[test]
fn reward_halving_058_reward_at_total_minus_two_matches_expected_when_available() -> TestResult {
    let height = total_reward_blocks().saturating_sub(2);

    assert_reward(height);

    Ok(())
}

#[test]
fn reward_halving_059_reward_at_total_minus_three_matches_expected_when_available() -> TestResult {
    let height = total_reward_blocks().saturating_sub(3);

    assert_reward(height);

    Ok(())
}

#[test]
fn reward_halving_060_remaining_at_total_minus_two_matches_expected() -> TestResult {
    let height = total_reward_blocks().saturating_sub(2);

    assert_remaining_after(height);

    Ok(())
}

#[test]
fn reward_halving_061_remaining_at_total_minus_three_matches_expected() -> TestResult {
    let height = total_reward_blocks().saturating_sub(3);

    assert_remaining_after(height);

    Ok(())
}

#[test]
fn reward_halving_062_schedule_end_and_beyond_rewards_are_zero_vectors() -> TestResult {
    for delta in 0..16_u64 {
        assert_eq!(
            RewardHalving::get_block_reward(total_reward_blocks().saturating_add(delta)),
            0
        );
    }

    Ok(())
}

#[test]
fn reward_halving_063_schedule_end_and_beyond_remaining_values_match_expected() -> TestResult {
    for delta in 0..16_u64 {
        assert_remaining_after(total_reward_blocks().saturating_add(delta));
    }

    Ok(())
}

#[test]
fn reward_halving_064_u64_max_reward_and_remaining_are_safe() -> TestResult {
    assert_eq!(RewardHalving::get_block_reward(u64::MAX), 0);
    assert_remaining_after(u64::MAX);

    Ok(())
}

#[test]
fn reward_halving_065_u64_max_minus_one_reward_and_remaining_are_safe() -> TestResult {
    let height = u64::MAX.saturating_sub(1);

    assert_reward(height);
    assert_remaining_after(height);

    Ok(())
}

#[test]
fn reward_halving_066_reward_reduction_sequence_is_not_empty() -> TestResult {
    assert!(!GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.is_empty());
    Ok(())
}

#[test]
fn reward_halving_067_halving_interval_is_nonzero() -> TestResult {
    assert_ne!(interval(), 0);
    Ok(())
}

#[test]
fn reward_halving_068_total_reward_blocks_is_not_less_than_prefix() -> TestResult {
    assert!(total_reward_blocks() >= prefix());
    Ok(())
}

#[test]
fn reward_halving_069_max_reward_supply_is_nonzero() -> TestResult {
    assert!(max_reward_supply() > 0);
    Ok(())
}

#[test]
fn reward_halving_070_expected_schedule_samples_do_not_panic_or_overflow() -> TestResult {
    for height in useful_heights() {
        let _reward = expected_reward(height);
        let _remaining = expected_remaining_after_block(height);
    }

    Ok(())
}

#[test]
fn reward_halving_071_all_sequence_start_rewards_match_expected() -> TestResult {
    for index in 0..GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
        assert_reward(interval().saturating_mul(index as u64));
    }

    Ok(())
}

#[test]
fn reward_halving_072_all_sequence_end_rewards_match_expected() -> TestResult {
    for index in 1..=GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
        assert_reward(interval().saturating_mul(index as u64).saturating_sub(1));
    }

    Ok(())
}

#[test]
fn reward_halving_073_all_sequence_start_remaining_values_match_expected() -> TestResult {
    for index in 0..GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
        assert_remaining_after(interval().saturating_mul(index as u64));
    }

    Ok(())
}

#[test]
fn reward_halving_074_all_sequence_end_remaining_values_match_expected() -> TestResult {
    for index in 1..=GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
        assert_remaining_after(interval().saturating_mul(index as u64).saturating_sub(1));
    }

    Ok(())
}

#[test]
fn reward_halving_075_all_sequence_midpoint_rewards_match_expected() -> TestResult {
    for index in 0..GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
        let height = interval()
            .saturating_mul(index as u64)
            .saturating_add(interval() / 2);

        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_076_all_sequence_midpoint_remaining_values_match_expected() -> TestResult {
    for index in 0..GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
        let height = interval()
            .saturating_mul(index as u64)
            .saturating_add(interval() / 2);

        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_077_reward_values_are_never_above_sequence_or_stabilized_max() -> TestResult {
    let sequence_max = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
        .max(GlobalConfiguration::STABILIZED_BLOCK_REWARD);

    for height in useful_heights() {
        assert!(RewardHalving::get_block_reward(height) <= sequence_max);
    }

    Ok(())
}

#[test]
fn reward_halving_078_remaining_supply_after_schedule_end_is_stable_for_later_heights() -> TestResult
{
    let at_end = RewardHalving::remaining_reward_supply_micro_after_block(total_reward_blocks());

    for delta in 1..64_u64 {
        assert_eq!(
            RewardHalving::remaining_reward_supply_micro_after_block(
                total_reward_blocks().saturating_add(delta)
            ),
            at_end
        );
    }

    Ok(())
}

#[test]
fn reward_halving_079_remaining_supply_after_u64_max_equals_after_schedule_end() -> TestResult {
    assert_eq!(
        RewardHalving::remaining_reward_supply_micro_after_block(u64::MAX),
        RewardHalving::remaining_reward_supply_micro_after_block(total_reward_blocks())
    );

    Ok(())
}

#[test]
fn reward_halving_080_validate_block_reward_rejects_schedule_end_wrong_nonzero() -> TestResult {
    let err = RewardHalving::validate_block_reward(total_reward_blocks(), 1)
        .expect_err("schedule-end reward must be zero");

    assert!(err.contains("Reward mismatch"));

    Ok(())
}

#[test]
fn reward_halving_081_validate_block_reward_accepts_schedule_end_zero() -> TestResult {
    RewardHalving::validate_block_reward(total_reward_blocks(), 0)
}

#[test]
fn reward_halving_082_validate_block_reward_accepts_u64_max_zero() -> TestResult {
    RewardHalving::validate_block_reward(u64::MAX, 0)
}

#[test]
fn reward_halving_083_height_saturating_add_for_remaining_does_not_overflow() -> TestResult {
    assert_remaining_after(u64::MAX);
    Ok(())
}

#[test]
fn reward_halving_084_large_height_before_end_if_possible_matches_expected() -> TestResult {
    let height = total_reward_blocks().saturating_sub(interval().max(1));

    assert_reward(height);

    Ok(())
}

#[test]
fn reward_halving_085_large_height_before_end_remaining_matches_expected() -> TestResult {
    let height = total_reward_blocks().saturating_sub(interval().max(1));

    assert_remaining_after(height);

    Ok(())
}

#[test]
fn reward_halving_086_every_sampled_reward_validates_with_public_validator() -> TestResult {
    for height in useful_heights() {
        RewardHalving::validate_block_reward(height, RewardHalving::get_block_reward(height))?;
    }

    Ok(())
}

#[test]
fn reward_halving_087_adjacent_rewards_around_prefix_match_expected() -> TestResult {
    for delta in 0..8_u64 {
        assert_reward(prefix().saturating_add(delta));
    }

    Ok(())
}

#[test]
fn reward_halving_088_adjacent_remaining_around_prefix_match_expected() -> TestResult {
    for delta in 0..8_u64 {
        assert_remaining_after(prefix().saturating_add(delta));
    }

    Ok(())
}

#[test]
fn reward_halving_089_adjacent_rewards_around_sequence_end_match_expected() -> TestResult {
    let base = sequence_end_height();

    for offset in -4_i64..=4_i64 {
        let height = if offset.is_negative() {
            base.saturating_sub(offset.unsigned_abs())
        } else {
            base.saturating_add(offset as u64)
        };

        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_090_adjacent_remaining_around_sequence_end_match_expected() -> TestResult {
    let base = sequence_end_height();

    for offset in -4_i64..=4_i64 {
        let height = if offset.is_negative() {
            base.saturating_sub(offset.unsigned_abs())
        } else {
            base.saturating_add(offset as u64)
        };

        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_091_adjacent_rewards_around_total_end_match_expected() -> TestResult {
    let base = total_reward_blocks();

    for offset in -4_i64..=4_i64 {
        let height = if offset.is_negative() {
            base.saturating_sub(offset.unsigned_abs())
        } else {
            base.saturating_add(offset as u64)
        };

        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_092_adjacent_remaining_around_total_end_match_expected() -> TestResult {
    let base = total_reward_blocks();

    for offset in -4_i64..=4_i64 {
        let height = if offset.is_negative() {
            base.saturating_sub(offset.unsigned_abs())
        } else {
            base.saturating_add(offset as u64)
        };

        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_093_load_first_1000_rewards_match_expected() -> TestResult {
    for height in 0..1_000_u64 {
        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_094_load_first_1000_remaining_values_match_expected() -> TestResult {
    for height in 0..1_000_u64 {
        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_095_load_1000_interval_boundary_rewards_match_expected() -> TestResult {
    for index in 0..1_000_u64 {
        assert_reward(interval().saturating_mul(index));
    }

    Ok(())
}

#[test]
fn reward_halving_096_load_1000_interval_boundary_remaining_values_match_expected() -> TestResult {
    for index in 0..1_000_u64 {
        assert_remaining_after(interval().saturating_mul(index));
    }

    Ok(())
}

#[test]
fn reward_halving_097_fuzz_deterministic_heights_rewards_match_expected() -> TestResult {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;

    for _ in 0..512 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);

        let height = state % total_reward_blocks().saturating_add(1).max(1);

        assert_reward(height);
    }

    Ok(())
}

#[test]
fn reward_halving_098_fuzz_deterministic_heights_remaining_values_match_expected() -> TestResult {
    let mut state = 0xd1b5_4a32_d192_ed03_u64;

    for _ in 0..512 {
        state = state
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(3_037_000_493);

        let height = state % total_reward_blocks().saturating_add(1).max(1);

        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_099_final_vector_public_reward_and_remaining_are_consistent() -> TestResult {
    for height in useful_heights() {
        assert_reward(height);
        assert_remaining_after(height);
    }

    Ok(())
}

#[test]
fn reward_halving_100_final_validate_all_core_boundary_vectors() -> TestResult {
    for height in [
        0,
        1,
        prefix(),
        prefix().saturating_add(1),
        interval().saturating_sub(1),
        interval(),
        sequence_end_height().saturating_sub(1),
        sequence_end_height(),
        total_reward_blocks().saturating_sub(1),
        total_reward_blocks(),
        u64::MAX,
    ] {
        RewardHalving::validate_block_reward(height, expected_reward(height))?;
    }

    Ok(())
}
