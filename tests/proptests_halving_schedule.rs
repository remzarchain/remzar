use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::halving_schedule::RewardHalving;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

fn remaining_after(block_height: u64) -> u128 {
    RewardHalving::remaining_reward_supply_micro_after_block(block_height)
}

fn reward_at(block_height: u64) -> u64 {
    RewardHalving::get_block_reward(block_height)
}

fn max_reward_supply() -> u128 {
    GlobalConfiguration::MAX_REWARD_SUPPLY as u128
}

fn remaining_before(height: u64) -> u128 {
    if height == 0 {
        max_reward_supply()
    } else {
        remaining_after(height.saturating_sub(1))
    }
}

fn configured_max_reward() -> u64 {
    let max_sequence_reward = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE
        .iter()
        .copied()
        .max()
        .unwrap_or(0);

    max_sequence_reward.max(GlobalConfiguration::STABILIZED_BLOCK_REWARD)
}

fn configured_nominal_reward_at(height: u64) -> u128 {
    let interval = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;

    if interval == 0 {
        return 0;
    }

    if height < GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS {
        return 0;
    }

    if height >= GlobalConfiguration::TOTAL_REWARD_BLOCKS {
        return 0;
    }

    let index_u64 = height / interval;
    let index = match usize::try_from(index_u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if let Some(&reward) = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.get(index) {
        reward as u128
    } else if GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD == 0 {
        0
    } else {
        GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128
    }
}

fn expected_reward_by_public_accounting(height: u64) -> u64 {
    let before = remaining_before(height);
    let nominal = configured_nominal_reward_at(height);

    u64::try_from(nominal.min(before)).unwrap_or(u64::MAX)
}

fn nominal_issued_without_prefix_model(height: u64) -> u128 {
    let interval = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;
    let schedule_end = GlobalConfiguration::TOTAL_REWARD_BLOCKS;
    let sequence = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE;

    if interval == 0 {
        return max_reward_supply();
    }

    let height = height.min(schedule_end);
    let full_periods = height / interval;
    let seq_len_u64 = sequence.len() as u64;
    let seq_periods = full_periods.min(seq_len_u64);

    let take_n = usize::try_from(seq_periods).unwrap_or(sequence.len());
    let issued_sequence = sequence
        .iter()
        .take(take_n)
        .map(|&reward| (reward as u128).saturating_mul(interval as u128))
        .sum::<u128>();

    let stabilized_intervals = full_periods.saturating_sub(seq_len_u64);
    let issued_stabilized = (GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128)
        .saturating_mul(stabilized_intervals as u128)
        .saturating_mul(interval as u128);

    let remainder_blocks = height % interval;

    let partial_reward = if remainder_blocks == 0 {
        0
    } else if full_periods < seq_len_u64 {
        let index = usize::try_from(full_periods).unwrap_or(usize::MAX);
        sequence.get(index).copied().unwrap_or(0) as u128
    } else {
        GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128
    };

    let issued_partial = (remainder_blocks as u128).saturating_mul(partial_reward);

    issued_sequence
        .saturating_add(issued_stabilized)
        .saturating_add(issued_partial)
}

fn issued_to_model(height_exclusive: u64) -> u128 {
    let schedule_end = GlobalConfiguration::TOTAL_REWARD_BLOCKS;

    if schedule_end < GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS {
        return max_reward_supply();
    }

    let height = height_exclusive.min(schedule_end);
    let rewardless_prefix = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS.min(height);

    let nominal = nominal_issued_without_prefix_model(height);
    let prefix_offset = nominal_issued_without_prefix_model(rewardless_prefix);

    nominal.saturating_sub(prefix_offset)
}

fn remaining_after_model(block_height: u64) -> u128 {
    let height_exclusive = block_height
        .saturating_add(1)
        .min(GlobalConfiguration::TOTAL_REWARD_BLOCKS);

    max_reward_supply().saturating_sub(issued_to_model(height_exclusive))
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 001/25
    #[test]
    fn test_001_rewardless_prefix_blocks_always_have_zero_reward(
        seed in any::<u64>(),
    ) {
        let prefix = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS;

        if prefix > 0 {
            let height = seed % prefix;

            prop_assert_eq!(
                reward_at(height),
                0,
                "block height {} is inside rewardless prefix and must mint zero reward",
                height
            );
        } else {
            prop_assert_eq!(
                prefix,
                0,
                "no rewardless prefix configured"
            );
        }
    }

    // 002/25
    #[test]
    fn test_002_rewards_are_zero_at_or_after_total_reward_blocks(
        offset in any::<u64>(),
    ) {
        let height = GlobalConfiguration::TOTAL_REWARD_BLOCKS.saturating_add(offset);

        prop_assert_eq!(
            reward_at(height),
            0,
            "block height {} is at/after TOTAL_REWARD_BLOCKS and must mint zero reward",
            height
        );
    }

    // 003/25
    #[test]
    fn test_003_reward_never_exceeds_remaining_supply_before_block(
        height in any::<u64>(),
    ) {
        let max_supply = GlobalConfiguration::MAX_REWARD_SUPPLY as u128;

        let remaining_before_block = remaining_before(height);
        let reward = reward_at(height) as u128;
        let remaining_after_current = remaining_after(height);

        prop_assert!(
            reward <= remaining_before_block,
            "block reward must never exceed remaining supply before the block"
        );

        prop_assert!(
            remaining_after_current <= remaining_before_block,
            "remaining reward supply must not increase after accounting for a block"
        );

        prop_assert!(
            remaining_after_current <= max_supply,
            "remaining reward supply must never exceed MAX_REWARD_SUPPLY"
        );
    }

    // 004/25
    #[test]
    fn test_004_remaining_reward_supply_is_monotonic_non_increasing(
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        let low = a.min(b);
        let high = a.max(b);

        let remaining_low = remaining_after(low);
        let remaining_high = remaining_after(high);

        prop_assert!(
            remaining_high <= remaining_low,
            "remaining supply must be monotonic non-increasing as height increases"
        );
    }

    // 005/25
    #[test]
    fn test_005_block_reward_matches_drop_in_remaining_supply(
        height in any::<u64>(),
    ) {
        let remaining_before_block = remaining_before(height);
        let remaining_after_current = remaining_after(height);
        let minted_by_accounting = remaining_before_block.saturating_sub(remaining_after_current);
        let reward = reward_at(height) as u128;

        prop_assert_eq!(
            reward,
            minted_by_accounting,
            "get_block_reward(height) must equal the supply decrease caused by that block"
        );
    }

    // 006/25
    #[test]
    fn test_006_remaining_supply_is_stable_after_schedule_end(
        offset_a in any::<u64>(),
        offset_b in any::<u64>(),
    ) {
        let end = GlobalConfiguration::TOTAL_REWARD_BLOCKS;

        let height_a = end.saturating_add(offset_a);
        let height_b = end.saturating_add(offset_b);

        prop_assert_eq!(
            remaining_after(height_a),
            remaining_after(height_b),
            "remaining supply must stay stable after TOTAL_REWARD_BLOCKS"
        );

        prop_assert_eq!(
            reward_at(height_a),
            0,
            "reward must be zero after schedule end"
        );

        prop_assert_eq!(
            reward_at(height_b),
            0,
            "reward must be zero after schedule end"
        );
    }

    // 007/25
    #[test]
    fn test_007_validate_block_reward_accepts_actual_reward(
        height in any::<u64>(),
    ) {
        let actual = reward_at(height);

        prop_assert!(
            RewardHalving::validate_block_reward(height, actual).is_ok(),
            "validate_block_reward must accept the actual reward returned by get_block_reward"
        );
    }

    // 008/25
    #[test]
    fn test_008_validate_block_reward_rejects_wrong_reward(
        height in any::<u64>(),
    ) {
        let actual = reward_at(height);
        let wrong = actual.wrapping_add(1);

        prop_assume!(wrong != actual);

        prop_assert!(
            RewardHalving::validate_block_reward(height, wrong).is_err(),
            "validate_block_reward must reject an incorrect expected reward"
        );
    }

    // 009/25
    #[test]
    fn test_009_rewards_are_never_larger_than_configured_schedule_maximum(
        height in any::<u64>(),
    ) {
        let reward = reward_at(height);

        prop_assert!(
            reward <= configured_max_reward(),
            "block reward must not exceed the maximum configured schedule reward"
        );
    }

    // 010/25
    #[test]
    fn test_010_reward_schedule_configuration_is_safe_for_runtime_math(
        marker in any::<u8>(),
    ) {
        let _ = marker;

        prop_assert!(
            GlobalConfiguration::HALVING_INTERVAL_BLOCKS > 0,
            "HALVING_INTERVAL_BLOCKS must be nonzero to avoid divide-by-zero reward math"
        );

        prop_assert!(
            GlobalConfiguration::TOTAL_REWARD_BLOCKS >= GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS,
            "TOTAL_REWARD_BLOCKS must not end before the rewardless prefix"
        );

        prop_assert!(
            !GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.is_empty()
                || GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD > 0
                || GlobalConfiguration::TOTAL_REWARD_BLOCKS <= GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS,
            "a rewardable schedule needs either sequence rewards or stabilized tail rewards"
        );
    }

    // 011/25
    #[test]
    fn test_011_rewardless_prefix_does_not_reduce_remaining_reward_supply(
        seed in any::<u64>(),
    ) {
        let prefix = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS;

        if prefix > 0 {
            let height = seed % prefix;

            prop_assert_eq!(
                remaining_after(height),
                max_reward_supply(),
                "rewardless prefix blocks must not reduce remaining reward supply"
            );

            prop_assert_eq!(
                reward_at(height),
                0,
                "rewardless prefix blocks must not mint"
            );
        } else {
            prop_assert_eq!(
                prefix,
                0,
                "no rewardless prefix configured"
            );
        }
    }

    // 012/25
    #[test]
    fn test_012_block_reward_matches_configured_schedule_clamped_to_remaining_supply(
        height in any::<u64>(),
    ) {
        let expected = expected_reward_by_public_accounting(height);
        let actual = reward_at(height);

        prop_assert_eq!(
            actual,
            expected,
            "block reward must equal configured nominal schedule reward clamped to remaining supply"
        );
    }

    // 013/25
    #[test]
    fn test_013_first_rewardable_block_uses_configured_model_or_zero_when_schedule_has_ended(
        marker in any::<u8>(),
    ) {
        let _ = marker;

        let first_rewardable = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS;

        if first_rewardable < GlobalConfiguration::TOTAL_REWARD_BLOCKS {
            prop_assert_eq!(
                reward_at(first_rewardable),
                expected_reward_by_public_accounting(first_rewardable),
                "first rewardable block must follow the configured reward model"
            );

            prop_assert!(
                RewardHalving::validate_block_reward(first_rewardable, reward_at(first_rewardable)).is_ok(),
                "first rewardable block's actual reward must validate"
            );
        } else {
            prop_assert_eq!(
                reward_at(first_rewardable),
                0,
                "if rewardless prefix reaches schedule end, first rewardable height must mint zero"
            );
        }
    }

    // 014/25
    #[test]
    fn test_014_total_reward_blocks_is_an_exclusive_reward_boundary(
        marker in any::<u8>(),
    ) {
        let _ = marker;

        let end = GlobalConfiguration::TOTAL_REWARD_BLOCKS;

        prop_assert_eq!(
            reward_at(end),
            0,
            "TOTAL_REWARD_BLOCKS itself must not mint because the schedule end is exclusive"
        );

        prop_assert_eq!(
            remaining_after(end),
            remaining_after(end.saturating_add(1)),
            "remaining supply must be stable at and after the exclusive schedule end"
        );

        if end > 0 {
            let last_in_schedule = end - 1;

            prop_assert_eq!(
                reward_at(last_in_schedule),
                expected_reward_by_public_accounting(last_in_schedule),
                "last in-schedule block must still follow the configured reward model"
            );
        }
    }

    // 015/25
    #[test]
    fn test_015_halving_interval_boundary_rewards_match_configured_schedule_model(
        index_seed in any::<usize>(),
    ) {
        let interval = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;
        let sequence_len = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len();

        if interval > 0 && sequence_len > 0 {
            let index = index_seed % sequence_len;
            let index_u64 = u64::try_from(index)
                .expect("usize index should fit in u64 on supported test targets");

            if let Some(boundary_height) = index_u64.checked_mul(interval)
                && (GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS
                    ..GlobalConfiguration::TOTAL_REWARD_BLOCKS)
                    .contains(&boundary_height)
            {
                prop_assert_eq!(
                    reward_at(boundary_height),
                    expected_reward_by_public_accounting(boundary_height),
                    "reward at halving interval boundary must use the configured period reward"
                );
            }
        } else {
            prop_assert!(
                interval == 0 || sequence_len == 0,
                "test is vacuous only when there are no sequence boundaries"
            );
        }
    }

    // 016/25
    #[test]
    fn test_016_rewards_are_constant_inside_same_interval_when_not_cap_clipped(
        period_seed in any::<usize>(),
        offset_a in any::<u64>(),
        offset_b in any::<u64>(),
    ) {
        let interval = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;

        if interval > 1 {
            let max_periods_to_sample = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE
                .len()
                .saturating_add(1)
                .max(1);

            let period_index = period_seed % max_periods_to_sample;
            let period_index_u64 = u64::try_from(period_index)
                .expect("period index should fit in u64 on supported test targets");

            if let Some(period_start) = period_index_u64.checked_mul(interval) {
                let height_a = period_start.saturating_add(offset_a % interval);
                let height_b = period_start.saturating_add(offset_b % interval);

                if height_a >= GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS
                    && height_b >= GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS
                    && height_a < GlobalConfiguration::TOTAL_REWARD_BLOCKS
                    && height_b < GlobalConfiguration::TOTAL_REWARD_BLOCKS
                {
                    let nominal_a = configured_nominal_reward_at(height_a);
                    let nominal_b = configured_nominal_reward_at(height_b);

                    if nominal_a == nominal_b
                        && remaining_before(height_a) >= nominal_a
                        && remaining_before(height_b) >= nominal_b
                    {
                        prop_assert_eq!(
                            reward_at(height_a),
                            reward_at(height_b),
                            "two non-cap-clipped blocks in the same configured interval must have the same reward"
                        );
                    }
                }
            }
        } else {
            prop_assert!(
                interval <= 1,
                "single-block intervals do not have distinct same-period heights to compare"
            );
        }
    }

    // 017/25
    #[test]
    fn test_017_stabilized_tail_uses_stabilized_reward_model_when_reachable(
        offset in any::<u64>(),
    ) {
        let interval = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;
        let sequence_len = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len();

        if interval > 0 && GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD > 0 {
            let sequence_len_u64 = u64::try_from(sequence_len)
                .expect("sequence length should fit in u64 on supported test targets");

            if let Some(tail_start) = sequence_len_u64.checked_mul(interval)
                && tail_start < GlobalConfiguration::TOTAL_REWARD_BLOCKS
            {
                let remaining_tail_span = GlobalConfiguration::TOTAL_REWARD_BLOCKS
                    .saturating_sub(tail_start)
                    .max(1);

                let height = tail_start.saturating_add(offset % remaining_tail_span);

                if (GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS
                    ..GlobalConfiguration::TOTAL_REWARD_BLOCKS)
                    .contains(&height)
                {
                    let expected = expected_reward_by_public_accounting(height);

                    prop_assert_eq!(
                        configured_nominal_reward_at(height),
                        GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128,
                        "reachable tail height must use the configured stabilized nominal reward"
                    );

                    prop_assert_eq!(
                        reward_at(height),
                        expected,
                        "stabilized tail reward must be cap-clamped stabilized reward"
                    );
                }
            }
        } else {
            prop_assert!(
                interval == 0 || GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD == 0,
                "test is vacuous when no stabilized tail is configured"
            );
        }
    }

    // 018/25
    #[test]
    fn test_018_remaining_supply_matches_public_reward_sum_for_bounded_prefix(
        height in 0u64..=4096u64,
    ) {
        let mut minted = 0u128;

        for h in 0..=height {
            minted = minted.saturating_add(reward_at(h) as u128);
        }

        let expected_remaining = max_reward_supply().saturating_sub(minted);

        prop_assert_eq!(
            remaining_after(height),
            expected_remaining,
            "remaining supply after a bounded prefix must equal max supply minus public rewards minted"
        );
    }

    // 019/25
    #[test]
    fn test_019_reward_and_remaining_supply_are_deterministic_for_same_height(
        height in any::<u64>(),
    ) {
        prop_assert_eq!(
            reward_at(height),
            reward_at(height),
            "get_block_reward must be deterministic for the same height"
        );

        prop_assert_eq!(
            remaining_after(height),
            remaining_after(height),
            "remaining_reward_supply_micro_after_block must be deterministic for the same height"
        );

        let actual = reward_at(height);

        prop_assert_eq!(
            RewardHalving::validate_block_reward(height, actual).is_ok(),
            RewardHalving::validate_block_reward(height, actual).is_ok(),
            "validate_block_reward outcome must be deterministic for the same height and expected reward"
        );
    }

    // 020/25
    #[test]
    fn test_020_validate_block_reward_error_reports_height_expected_and_actual(
        height in any::<u64>(),
    ) {
        let actual = reward_at(height);
        let wrong = actual.wrapping_add(1);

        prop_assume!(wrong != actual);

        let err = RewardHalving::validate_block_reward(height, wrong)
            .expect_err("wrong reward must be rejected");

        prop_assert!(
            err.contains(&height.to_string()),
            "validation error should mention the block height"
        );

        prop_assert!(
            err.contains(&wrong.to_string()),
            "validation error should mention the supplied expected reward"
        );

        prop_assert!(
            err.contains(&actual.to_string()),
            "validation error should mention the actual reward"
        );
    }

    // 021/25
    #[test]
    fn test_021_validate_block_reward_accepts_zero_reward_on_non_minting_ranges(
        prefix_seed in any::<u64>(),
        end_offset in any::<u64>(),
    ) {
        let prefix = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS;

        if prefix > 0 {
            let rewardless_height = prefix_seed % prefix;

            prop_assert!(
                RewardHalving::validate_block_reward(rewardless_height, 0).is_ok(),
                "zero reward must validate inside rewardless prefix"
            );
        }

        let ended_height = GlobalConfiguration::TOTAL_REWARD_BLOCKS.saturating_add(end_offset);

        prop_assert!(
            RewardHalving::validate_block_reward(ended_height, 0).is_ok(),
            "zero reward must validate at or after schedule end"
        );
    }

    // 022/25
    #[test]
    fn test_022_no_height_mints_after_remaining_supply_is_exhausted(
        height in any::<u64>(),
    ) {
        let before = remaining_before(height);

        if before == 0 {
            prop_assert_eq!(
                reward_at(height),
                0,
                "once remaining reward supply is exhausted, no later height may mint"
            );

            prop_assert_eq!(
                remaining_after(height),
                0,
                "remaining supply should stay zero once exhausted"
            );
        } else {
            prop_assert!(
                reward_at(height) as u128 <= before,
                "while supply remains, reward must still be capped by remaining supply"
            );
        }
    }

    // 023/25
    #[test]
    fn test_023_extreme_heights_remain_bounded_and_non_minting_past_schedule(
        selector in 0u8..6u8,
    ) {
        let prefix = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS;
        let end = GlobalConfiguration::TOTAL_REWARD_BLOCKS;

        let height = match selector {
            0 => 0,
            1 => prefix,
            2 => prefix.saturating_sub(1),
            3 => end,
            4 => end.saturating_sub(1),
            _ => u64::MAX,
        };

        prop_assert!(
            remaining_after(height) <= max_reward_supply(),
            "remaining supply must stay bounded for edge-case heights"
        );

        if height >= end {
            prop_assert_eq!(
                reward_at(height),
                0,
                "edge-case height at/after schedule end must not mint"
            );
        }

        if height < prefix {
            prop_assert_eq!(
                reward_at(height),
                0,
                "edge-case height inside rewardless prefix must not mint"
            );
        }
    }

    // 024/25
    #[test]
    fn test_024_remaining_supply_matches_independent_schedule_accounting_model(
        height in any::<u64>(),
    ) {
        prop_assert_eq!(
            remaining_after(height),
            remaining_after_model(height),
            "remaining supply helper must match independent schedule accounting model"
        );
    }

    // 025/25
    #[test]
    fn test_025_public_reward_entrypoints_never_panic_for_arbitrary_heights_and_expected_rewards(
        height in any::<u64>(),
        expected in any::<u64>(),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = RewardHalving::get_block_reward(height);
            let _ = RewardHalving::remaining_reward_supply_micro_after_block(height);
            let _ = RewardHalving::validate_block_reward(height, expected);
        }));

        prop_assert!(
            result.is_ok(),
            "public reward halving entrypoints must return values or errors, not panic"
        );
    }
}
