use crate::utility::alpha_001_global_configuration::GlobalConfiguration;

pub struct RewardHalving;

impl RewardHalving {
    #[inline]
    fn fail_closed_issued() -> u128 {
        GlobalConfiguration::MAX_REWARD_SUPPLY as u128
    }

    /// Validate basic config invariants used by schedule math.
    #[inline]
    fn config_sane(interval: u64, schedule_end: u64) -> bool {
        if interval == 0 {
            return false;
        }
        // schedule_end should be >= rewardless prefix by construction, but don't assume.
        if schedule_end < GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS {
            return false;
        }
        true
    }

    /// Safe mul for u128; returns None on overflow.
    #[inline]
    fn checked_mul_u128(a: u128, b: u128) -> Option<u128> {
        a.checked_mul(b)
    }

    /// Safe add for u128; returns None on overflow.
    #[inline]
    fn checked_add_u128(a: u128, b: u128) -> Option<u128> {
        a.checked_add(b)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Schedule issuance accounting
    // ─────────────────────────────────────────────────────────────────────────

    /// Total nominal micro-AOS issued before `height` (exclusive).
    fn total_issued_to(height: u64) -> u128 {
        let interval = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;
        let seq = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE;
        let seq_len = seq.len() as u64;

        // Prevent divide-by-zero / invalid configuration.
        let schedule_end = GlobalConfiguration::TOTAL_REWARD_BLOCKS;
        if !Self::config_sane(interval, schedule_end) {
            return Self::fail_closed_issued();
        }

        let height = height.min(schedule_end);

        // number of full “sequence” periods
        let full_periods = match height.checked_div(interval) {
            Some(v) => v,
            None => return Self::fail_closed_issued(),
        };
        let seq_periods = full_periods.min(seq_len);

        // sum rewards for each stepped interval
        let issued_seq: u128 = {
            let take_n = usize::try_from(seq_periods).unwrap_or(usize::MAX);
            seq.iter()
                .take(take_n)
                .map(|&r| (r as u128).saturating_mul(interval as u128))
                .sum()
        };

        let stab_intervals = full_periods.saturating_sub(seq_len);

        // issued_stab = STABILIZED_BLOCK_REWARD * stab_intervals * interval
        let issued_stab: u128 = match Self::checked_mul_u128(
            GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128,
            stab_intervals as u128,
        )
        .and_then(|x| Self::checked_mul_u128(x, interval as u128))
        {
            Some(v) => v,
            None => {
                // Fail-closed: treat as fully issued.
                return Self::fail_closed_issued();
            }
        };

        let remainder_blocks = height % interval;

        let reward_for_partial: u128 = if remainder_blocks == 0 {
            0
        } else if full_periods < seq_len {
            // Current period reward is seq[full_periods]
            let idx = usize::try_from(full_periods).unwrap_or(usize::MAX);
            match seq.get(idx) {
                Some(&v) => v as u128,
                None => {
                    // Fail-closed: schedule math cannot be trusted.
                    return Self::fail_closed_issued();
                }
            }
        } else {
            // Past sequence -> stabilized reward
            GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128
        };

        let issued_partial: u128 =
            match Self::checked_mul_u128(remainder_blocks as u128, reward_for_partial) {
                Some(v) => v,
                None => {
                    // Fail-closed: treat as fully issued.
                    return Self::fail_closed_issued();
                }
            };

        let issued_nominal = match Self::checked_add_u128(issued_seq, issued_stab)
            .and_then(|x| Self::checked_add_u128(x, issued_partial))
        {
            Some(v) => v,
            None => return Self::fail_closed_issued(),
        };

        let rewardless_prefix = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS.min(height);
        if rewardless_prefix == 0 {
            return issued_nominal;
        }

        let prefix_height = rewardless_prefix;

        let prefix_full_periods = match prefix_height.checked_div(interval) {
            Some(v) => v,
            None => return Self::fail_closed_issued(),
        };
        let prefix_seq_periods = prefix_full_periods.min(seq_len);

        let prefix_issued_seq: u128 = {
            let take_n = usize::try_from(prefix_seq_periods).unwrap_or(usize::MAX);
            seq.iter()
                .take(take_n)
                .map(|&r| (r as u128).saturating_mul(interval as u128))
                .sum()
        };

        let prefix_stab_intervals = prefix_full_periods.saturating_sub(seq_len);

        let prefix_issued_stab: u128 = match Self::checked_mul_u128(
            GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128,
            prefix_stab_intervals as u128,
        )
        .and_then(|x| Self::checked_mul_u128(x, interval as u128))
        {
            Some(v) => v,
            None => {
                // Fail-closed: do not “refund” issuance incorrectly.
                return Self::fail_closed_issued();
            }
        };

        let prefix_remainder_blocks = prefix_height % interval;

        let prefix_reward_for_partial: u128 = if prefix_remainder_blocks == 0 {
            0
        } else if prefix_full_periods < seq_len {
            let idx = usize::try_from(prefix_full_periods).unwrap_or(usize::MAX);
            match seq.get(idx) {
                Some(&v) => v as u128,
                None => {
                    // Fail-closed: schedule math cannot be trusted.
                    return Self::fail_closed_issued();
                }
            }
        } else {
            GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128
        };

        let prefix_issued_partial: u128 = match Self::checked_mul_u128(
            prefix_remainder_blocks as u128,
            prefix_reward_for_partial,
        ) {
            Some(v) => v,
            None => return Self::fail_closed_issued(),
        };

        let prefix_offset = match Self::checked_add_u128(prefix_issued_seq, prefix_issued_stab)
            .and_then(|x| Self::checked_add_u128(x, prefix_issued_partial))
        {
            Some(v) => v,
            None => return Self::fail_closed_issued(),
        };

        issued_nominal.saturating_sub(prefix_offset)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WIRING: Remaining supply helper for console counters / telemetry
    // ─────────────────────────────────────────────────────────────────────────
    pub fn remaining_reward_supply_micro_after_block(block_height: u64) -> u128 {
        let schedule_end = GlobalConfiguration::TOTAL_REWARD_BLOCKS;

        // Remaining supply AFTER this block height is accounted for,
        // so compute issued_before at (block_height + 1) (exclusive).
        let height_exclusive = block_height.saturating_add(1).min(schedule_end);

        let issued_after = Self::total_issued_to(height_exclusive);
        let max_reward_supply = GlobalConfiguration::MAX_REWARD_SUPPLY as u128;

        max_reward_supply.saturating_sub(issued_after)
    }

    /// Returns the coinbase reward for `block_height` in micro-ZAR,
    /// but returns 0 once the cap is reached.
    #[inline]
    pub fn get_block_reward(block_height: u64) -> u64 {
        let interval = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;

        // Prevent divide-by-zero / invalid configuration.
        if interval == 0 {
            return 0;
        }

        // ─────────────────────────────────────────────────────────────────────
        // These heights never mint a reward by design.
        // ─────────────────────────────────────────────────────────────────────
        if block_height < GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS {
            return 0;
        }

        // Stop rewards after the configured schedule end (independent of cap).
        if block_height >= GlobalConfiguration::TOTAL_REWARD_BLOCKS {
            return 0;
        }

        let issued_before = Self::total_issued_to(block_height);
        let max_reward_supply = GlobalConfiguration::MAX_REWARD_SUPPLY as u128;

        // 1) Enforce the cap:
        if issued_before >= max_reward_supply {
            return 0;
        }

        // Remaining supply available for this block (prevents overshoot).
        let remaining = max_reward_supply.saturating_sub(issued_before);

        // 2) Otherwise, normal halving lookup:
        let index_u64 = match block_height.checked_div(interval) {
            Some(v) => v,
            None => {
                return 0;
            }
        };
        let index = match usize::try_from(index_u64) {
            Ok(v) => v,
            Err(_) => {
                // Fail-closed: if we can't index safely, do not mint.
                return 0;
            }
        };

        // Explicit bounds check to prevent index out of range
        if index >= GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() {
            // WIRING: stabilized tail (if any)
            if GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD == 0 {
                return 0;
            }

            // Still clamp stabilized reward to remaining cap.
            let stabilized = GlobalConfiguration::STABILIZED_BLOCK_REWARD as u128;
            return u64::try_from(stabilized.min(remaining)).unwrap_or(u64::MAX);
        }

        // Clamp scheduled reward to remaining cap (never exceed MAX_REWARD_SUPPLY).
        let scheduled = match GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.get(index) {
            Some(&v) => v as u128,
            None => {
                // Should be unreachable due to bounds check above, but stay fail-closed.
                return 0;
            }
        };
        u64::try_from(scheduled.min(remaining)).unwrap_or(u64::MAX)
    }

    /// Convenience helper for tests and economic sanity checks.
    pub fn validate_block_reward(block_height: u64, expected: u64) -> Result<(), String> {
        let actual = Self::get_block_reward(block_height);
        if actual != expected {
            Err(format!(
                "Reward mismatch at height {}: expected {}, got {}",
                block_height, expected, actual
            ))
        } else {
            Ok(())
        }
    }
}
