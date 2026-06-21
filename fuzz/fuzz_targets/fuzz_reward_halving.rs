// fuzz/fuzz_targets/fuzz_reward_halving.rs

#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_SEQUENCE_LEN: usize = 32;
const MAX_HEIGHT_CASES: usize = 64;

/// Keep generated values high enough to exercise cap math, but bounded enough
/// that a memory-only model cannot waste time in huge loops.
const MAX_INTERVAL_MODEL: u64 = 1_000_000;
const MAX_REWARD_MODEL: u64 = 10_000_000_000_000;
const MAX_TAIL_BLOCKS_MODEL: u64 = 10_000_000;
const MAX_PREFIX_BLOCKS_MODEL: u64 = 10_000_000;
const MAX_SUPPLY_MODEL: u64 = u64::MAX;

#[derive(Debug, Clone)]
struct RewardConfigModel {
    halving_interval_blocks: u64,
    reward_reduction_sequence: Vec<u64>,
    stabilized_block_reward: u64,
    blocks_for_stabilized_reward: u64,
    rewardless_prefix_blocks: u64,
    total_reward_blocks: u64,
    max_reward_supply: u64,
}

impl RewardConfigModel {
    fn fail_closed_issued(&self) -> u128 {
        u128::from(self.max_reward_supply)
    }

    fn config_sane(&self) -> bool {
        if self.halving_interval_blocks == 0 {
            return false;
        }

        if self.total_reward_blocks < self.rewardless_prefix_blocks {
            return false;
        }

        true
    }

    fn checked_mul_u128(a: u128, b: u128) -> Option<u128> {
        a.checked_mul(b)
    }

    fn checked_add_u128(a: u128, b: u128) -> Option<u128> {
        a.checked_add(b)
    }

    fn reward_for_period(&self, period: u64) -> Option<u128> {
        let seq_len = u64::try_from(self.reward_reduction_sequence.len()).unwrap_or(u64::MAX);

        if period < seq_len {
            let idx = usize::try_from(period).ok()?;
            self.reward_reduction_sequence.get(idx).map(|&v| u128::from(v))
        } else {
            Some(u128::from(self.stabilized_block_reward))
        }
    }

    fn total_issued_to(&self, height: u64) -> u128 {
        let interval = self.halving_interval_blocks;
        let seq_len = u64::try_from(self.reward_reduction_sequence.len()).unwrap_or(u64::MAX);
        let schedule_end = self.total_reward_blocks;

        if !self.config_sane() {
            return self.fail_closed_issued();
        }

        // Stop accounting at schedule end.
        let height = height.min(schedule_end);

        let full_periods = match height.checked_div(interval) {
            Some(v) => v,
            None => return self.fail_closed_issued(),
        };

        let seq_periods = full_periods.min(seq_len);

        let mut issued_seq = 0u128;
        let take_n = usize::try_from(seq_periods).unwrap_or(usize::MAX);

        for reward in self.reward_reduction_sequence.iter().take(take_n) {
            let interval_total = match Self::checked_mul_u128(u128::from(*reward), u128::from(interval)) {
                Some(v) => v,
                None => return self.fail_closed_issued(),
            };

            issued_seq = match Self::checked_add_u128(issued_seq, interval_total) {
                Some(v) => v,
                None => return self.fail_closed_issued(),
            };
        }

        // Stabilized tail after the explicit sequence.
        let stab_intervals = full_periods.saturating_sub(seq_len);

        let issued_stab = match Self::checked_mul_u128(
            u128::from(self.stabilized_block_reward),
            u128::from(stab_intervals),
        )
        .and_then(|x| Self::checked_mul_u128(x, u128::from(interval)))
        {
            Some(v) => v,
            None => return self.fail_closed_issued(),
        };

        let remainder_blocks = height % interval;

        let reward_for_partial = if remainder_blocks == 0 {
            0
        } else {
            match self.reward_for_period(full_periods) {
                Some(v) => v,
                None => return self.fail_closed_issued(),
            }
        };

        let issued_partial = match Self::checked_mul_u128(
            u128::from(remainder_blocks),
            reward_for_partial,
        ) {
            Some(v) => v,
            None => return self.fail_closed_issued(),
        };

        let issued_nominal = match Self::checked_add_u128(issued_seq, issued_stab)
            .and_then(|x| Self::checked_add_u128(x, issued_partial))
        {
            Some(v) => v,
            None => return self.fail_closed_issued(),
        };

        let rewardless_prefix = self.rewardless_prefix_blocks.min(height);
        if rewardless_prefix == 0 {
            return issued_nominal;
        }

        let prefix_offset = self.total_issued_without_prefix_correction(rewardless_prefix);
        issued_nominal.saturating_sub(prefix_offset)
    }

    fn total_issued_without_prefix_correction(&self, height: u64) -> u128 {
        let interval = self.halving_interval_blocks;
        let seq_len = u64::try_from(self.reward_reduction_sequence.len()).unwrap_or(u64::MAX);

        if !self.config_sane() {
            return self.fail_closed_issued();
        }

        let height = height.min(self.total_reward_blocks);

        let full_periods = match height.checked_div(interval) {
            Some(v) => v,
            None => return self.fail_closed_issued(),
        };

        let seq_periods = full_periods.min(seq_len);
        let mut issued_seq = 0u128;
        let take_n = usize::try_from(seq_periods).unwrap_or(usize::MAX);

        for reward in self.reward_reduction_sequence.iter().take(take_n) {
            let interval_total = match Self::checked_mul_u128(u128::from(*reward), u128::from(interval)) {
                Some(v) => v,
                None => return self.fail_closed_issued(),
            };

            issued_seq = match Self::checked_add_u128(issued_seq, interval_total) {
                Some(v) => v,
                None => return self.fail_closed_issued(),
            };
        }

        let stab_intervals = full_periods.saturating_sub(seq_len);

        let issued_stab = match Self::checked_mul_u128(
            u128::from(self.stabilized_block_reward),
            u128::from(stab_intervals),
        )
        .and_then(|x| Self::checked_mul_u128(x, u128::from(interval)))
        {
            Some(v) => v,
            None => return self.fail_closed_issued(),
        };

        let remainder_blocks = height % interval;

        let reward_for_partial = if remainder_blocks == 0 {
            0
        } else {
            match self.reward_for_period(full_periods) {
                Some(v) => v,
                None => return self.fail_closed_issued(),
            }
        };

        let issued_partial = match Self::checked_mul_u128(
            u128::from(remainder_blocks),
            reward_for_partial,
        ) {
            Some(v) => v,
            None => return self.fail_closed_issued(),
        };

        match Self::checked_add_u128(issued_seq, issued_stab)
            .and_then(|x| Self::checked_add_u128(x, issued_partial))
        {
            Some(v) => v,
            None => self.fail_closed_issued(),
        }
    }

    fn remaining_reward_supply_micro_after_block(&self, block_height: u64) -> u128 {
        let schedule_end = self.total_reward_blocks;
        let height_exclusive = block_height.saturating_add(1).min(schedule_end);
        let issued_after = self.total_issued_to(height_exclusive);

        u128::from(self.max_reward_supply).saturating_sub(issued_after)
    }

    fn get_block_reward(&self, block_height: u64) -> u64 {
        let interval = self.halving_interval_blocks;

        if interval == 0 {
            return 0;
        }

        if block_height < self.rewardless_prefix_blocks {
            return 0;
        }

        if block_height >= self.total_reward_blocks {
            return 0;
        }

        let issued_before = self.total_issued_to(block_height);
        let max_reward_supply = u128::from(self.max_reward_supply);

        if issued_before >= max_reward_supply {
            return 0;
        }

        let remaining = max_reward_supply.saturating_sub(issued_before);

        let index_u64 = match block_height.checked_div(interval) {
            Some(v) => v,
            None => return 0,
        };

        let index = match usize::try_from(index_u64) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        let scheduled = if index >= self.reward_reduction_sequence.len() {
            if self.blocks_for_stabilized_reward == 0 {
                return 0;
            }

            u128::from(self.stabilized_block_reward)
        } else {
            u128::from(self.reward_reduction_sequence[index])
        };

        u64::try_from(scheduled.min(remaining)).unwrap_or(u64::MAX)
    }

    fn expected_unclamped_reward(&self, block_height: u64) -> u128 {
        if self.halving_interval_blocks == 0 {
            return 0;
        }

        if block_height < self.rewardless_prefix_blocks {
            return 0;
        }

        if block_height >= self.total_reward_blocks {
            return 0;
        }

        let period = block_height / self.halving_interval_blocks;
        let idx = usize::try_from(period).unwrap_or(usize::MAX);

        if idx < self.reward_reduction_sequence.len() {
            u128::from(self.reward_reduction_sequence[idx])
        } else if self.blocks_for_stabilized_reward > 0 {
            u128::from(self.stabilized_block_reward)
        } else {
            0
        }
    }
}

#[derive(Debug)]
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take_u8(&mut self) -> u8 {
        if self.pos >= self.data.len() {
            return 0;
        }

        let b = self.data[self.pos];
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
    }

    fn take_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill(&mut out);
        u64::from_le_bytes(out)
    }

    fn take_usize_mod(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }

        usize::try_from(self.take_u64()).unwrap_or(0) % max
    }

    fn take_bool(&mut self) -> bool {
        self.take_u8() & 1 == 1
    }
}

fn config_from_cursor(cursor: &mut Cursor<'_>) -> RewardConfigModel {
    let interval = match cursor.take_u8() % 16 {
        0 => 0,
        _ => (cursor.take_u64() % MAX_INTERVAL_MODEL).saturating_add(1),
    };

    let seq_len = cursor.take_usize_mod(MAX_SEQUENCE_LEN.saturating_add(1));
    let mut sequence = Vec::with_capacity(seq_len);

    for _ in 0..seq_len {
        let reward = cursor.take_u64() % MAX_REWARD_MODEL.saturating_add(1);
        sequence.push(reward);
    }

    let stabilized_block_reward = cursor.take_u64() % MAX_REWARD_MODEL.saturating_add(1);
    let blocks_for_stabilized_reward = cursor.take_u64() % MAX_TAIL_BLOCKS_MODEL.saturating_add(1);
    let rewardless_prefix_blocks = cursor.take_u64() % MAX_PREFIX_BLOCKS_MODEL.saturating_add(1);

    let seq_len_u64 = u64::try_from(sequence.len()).unwrap_or(u64::MAX);

    let nominal_schedule_blocks = interval
        .saturating_mul(seq_len_u64)
        .saturating_add(blocks_for_stabilized_reward)
        .saturating_add(rewardless_prefix_blocks);

    let total_reward_blocks = match cursor.take_u8() % 8 {
        0 => 0,
        1 => rewardless_prefix_blocks.saturating_sub(1),
        2 => rewardless_prefix_blocks,
        3 => interval.saturating_mul(seq_len_u64),
        4 => nominal_schedule_blocks,
        _ => cursor.take_u64() % nominal_schedule_blocks.saturating_add(1).max(1),
    };

    let max_reward_supply = match cursor.take_u8() % 8 {
        0 => 0,
        1 => 1,
        2 => cursor.take_u64() % MAX_REWARD_MODEL.saturating_add(1),
        _ => cursor.take_u64().min(MAX_SUPPLY_MODEL),
    };

    RewardConfigModel {
        halving_interval_blocks: interval,
        reward_reduction_sequence: sequence,
        stabilized_block_reward,
        blocks_for_stabilized_reward,
        rewardless_prefix_blocks,
        total_reward_blocks,
        max_reward_supply,
    }
}

fn sane_small_regression_config() -> RewardConfigModel {
    RewardConfigModel {
        halving_interval_blocks: 4,
        reward_reduction_sequence: vec![50, 25, 12],
        stabilized_block_reward: 3,
        blocks_for_stabilized_reward: 8,
        rewardless_prefix_blocks: 2,
        total_reward_blocks: 22,
        max_reward_supply: 1_000,
    }
}

fn cap_regression_config() -> RewardConfigModel {
    RewardConfigModel {
        halving_interval_blocks: 1,
        reward_reduction_sequence: vec![10, 10, 10],
        stabilized_block_reward: 10,
        blocks_for_stabilized_reward: 0,
        rewardless_prefix_blocks: 0,
        total_reward_blocks: 3,
        max_reward_supply: 25,
    }
}

fn run_fixed_regressions() {
    let cfg = sane_small_regression_config();

    // Rewardless prefix: block 0 and block 1 mint nothing.
    assert_eq!(cfg.get_block_reward(0), 0);
    assert_eq!(cfg.get_block_reward(1), 0);

    // Still in first interval after prefix.
    assert_eq!(cfg.get_block_reward(2), 50);
    assert_eq!(cfg.get_block_reward(3), 50);

    // Boundary at interval 4 moves to second scheduled reward.
    assert_eq!(cfg.get_block_reward(4), 25);
    assert_eq!(cfg.get_block_reward(7), 25);

    // Boundary at interval 8 moves to third scheduled reward.
    assert_eq!(cfg.get_block_reward(8), 12);
    assert_eq!(cfg.get_block_reward(11), 12);

    // Past explicit sequence, stabilized tail reward applies.
    assert_eq!(cfg.get_block_reward(12), 3);

    // Schedule end is exclusive.
    assert_eq!(cfg.get_block_reward(cfg.total_reward_blocks), 0);
    assert_eq!(cfg.get_block_reward(u64::MAX), 0);

    // Cap clamps final issuance.
    let cap = cap_regression_config();
    assert_eq!(cap.get_block_reward(0), 10);
    assert_eq!(cap.get_block_reward(1), 10);
    assert_eq!(cap.get_block_reward(2), 5);
    assert_eq!(cap.get_block_reward(3), 0);

    // Invalid interval fails closed for rewards.
    let mut bad = cfg.clone();
    bad.halving_interval_blocks = 0;
    assert_eq!(bad.get_block_reward(2), 0);
    assert_eq!(bad.remaining_reward_supply_micro_after_block(2), 0);

    // Invalid total schedule before prefix fails closed for remaining supply.
    let mut bad = cfg.clone();
    bad.total_reward_blocks = 1;
    bad.rewardless_prefix_blocks = 2;
    assert_eq!(bad.remaining_reward_supply_micro_after_block(0), 0);
}

fn candidate_heights(cursor: &mut Cursor<'_>, cfg: &RewardConfigModel) -> Vec<u64> {
    let mut heights = Vec::new();

    heights.push(0);
    heights.push(1);
    heights.push(cfg.rewardless_prefix_blocks.saturating_sub(1));
    heights.push(cfg.rewardless_prefix_blocks);
    heights.push(cfg.rewardless_prefix_blocks.saturating_add(1));
    heights.push(cfg.total_reward_blocks.saturating_sub(1));
    heights.push(cfg.total_reward_blocks);
    heights.push(cfg.total_reward_blocks.saturating_add(1));
    heights.push(u64::MAX);

    if cfg.halving_interval_blocks > 0 {
        for period in 0..=5u64 {
            let base = cfg.halving_interval_blocks.saturating_mul(period);
            heights.push(base.saturating_sub(1));
            heights.push(base);
            heights.push(base.saturating_add(1));
        }

        let seq_len = u64::try_from(cfg.reward_reduction_sequence.len()).unwrap_or(u64::MAX);
        let seq_boundary = cfg.halving_interval_blocks.saturating_mul(seq_len);
        heights.push(seq_boundary.saturating_sub(1));
        heights.push(seq_boundary);
        heights.push(seq_boundary.saturating_add(1));
    }

    let extra = cursor.take_usize_mod(MAX_HEIGHT_CASES);
    for _ in 0..extra {
        let h = match cursor.take_u8() % 8 {
            0 => cursor.take_u64(),
            1 => cursor.take_u64() % cfg.total_reward_blocks.saturating_add(1).max(1),
            2 => cfg.rewardless_prefix_blocks.saturating_add(cursor.take_u64() % 128),
            3 => cfg.total_reward_blocks.saturating_add(cursor.take_u64() % 128),
            _ => cursor.take_u64() % 10_000_000,
        };
        heights.push(h);
    }

    heights
}

fn fuzz_reward_config(cursor: &mut Cursor<'_>) {
    let cfg = config_from_cursor(cursor);
    let heights = candidate_heights(cursor, &cfg);

    if cfg.halving_interval_blocks == 0 {
        for h in heights {
            assert_eq!(cfg.get_block_reward(h), 0);
        }
        return;
    }

    if !cfg.config_sane() {
        for h in heights {
            let reward = cfg.get_block_reward(h);
            assert!(u128::from(reward) <= u128::from(cfg.max_reward_supply));
            assert_eq!(cfg.remaining_reward_supply_micro_after_block(h), 0);
        }
        return;
    }

    let mut ordered = heights.clone();
    ordered.sort_unstable();
    ordered.dedup();

    let mut previous_remaining = u128::from(cfg.max_reward_supply);

    for h in ordered {
        let reward = cfg.get_block_reward(h);
        let reward_u128 = u128::from(reward);
        let issued_before = cfg.total_issued_to(h);
        let remaining_before = u128::from(cfg.max_reward_supply).saturating_sub(issued_before);
        let expected_unclamped = cfg.expected_unclamped_reward(h);
        let remaining_after = cfg.remaining_reward_supply_micro_after_block(h);

        assert!(reward_u128 <= u128::from(u64::MAX));
        assert!(reward_u128 <= u128::from(cfg.max_reward_supply));
        assert!(reward_u128 <= remaining_before);
        assert!(reward_u128 <= expected_unclamped);

        if h < cfg.rewardless_prefix_blocks {
            assert_eq!(reward, 0);
        }

        if h >= cfg.total_reward_blocks {
            assert_eq!(reward, 0);
        }

        if issued_before >= u128::from(cfg.max_reward_supply) {
            assert_eq!(reward, 0);
        }

        assert!(remaining_after <= u128::from(cfg.max_reward_supply));

        // Remaining supply must not increase as checked heights increase.
        assert!(remaining_after <= previous_remaining);
        previous_remaining = remaining_after;
    }
}

fn fuzz_supply_conservation(cursor: &mut Cursor<'_>) {
    let cfg = config_from_cursor(cursor);

    if !cfg.config_sane() || cfg.halving_interval_blocks == 0 {
        return;
    }

    let start = cursor.take_u64() % 10_000;
    let len = cursor.take_u64() % 512;

    let mut issued_sum = 0u128;

    for offset in 0..len {
        let h = start.saturating_add(offset);
        let reward = u128::from(cfg.get_block_reward(h));
        issued_sum = issued_sum.saturating_add(reward);
        assert!(issued_sum <= u128::from(cfg.max_reward_supply));
    }

    let before = cfg.remaining_reward_supply_micro_after_block(start.saturating_sub(1));
    let after = cfg.remaining_reward_supply_micro_after_block(start.saturating_add(len));
    assert!(after <= before);
}

fuzz_target!(|data: &[u8]| {
    run_fixed_regressions();

    let mut cursor = Cursor::new(data);

    match cursor.take_u8() % 3 {
        0 => fuzz_reward_config(&mut cursor),
        1 => fuzz_supply_conservation(&mut cursor),
        _ => {
            fuzz_reward_config(&mut cursor);
            fuzz_supply_conservation(&mut cursor);
        }
    }

    // Arbitrary extra regression path: no input should make extreme heights panic.
    if cursor.take_bool() {
        let cfg = config_from_cursor(&mut cursor);
        let _ = cfg.get_block_reward(u64::MAX);
        let _ = cfg.remaining_reward_supply_micro_after_block(u64::MAX);
        let _ = cfg.total_issued_to(u64::MAX);
    }
});