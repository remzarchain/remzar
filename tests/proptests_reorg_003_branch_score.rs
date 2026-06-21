use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::reorganization::reorg_003_branch_score::{
    BlockHash, BranchCandidate, BranchScore, BranchScoreConfig, BranchScoreMode, ReorgBranchScorer,
};

fn hash64(tag: u8, seed: u64) -> BlockHash {
    let fill = match tag {
        0 => 1,
        0xFF => 0xFE,
        value => value,
    };

    let mut out = [fill; 64];
    out[..8].copy_from_slice(&seed.to_be_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    if out == [0xFFu8; 64] {
        out[63] = 0xFE;
    }

    out
}

fn distinct_hash64(tag: u8, seed: u64, other: BlockHash) -> BlockHash {
    let mut out = hash64(tag, seed);

    if out == other {
        out[63] ^= 1;

        if out == [0u8; 64] || out == [0xFFu8; 64] {
            out[63] = 0x7F;
        }
    }

    out
}

fn ordered_hash_pair(seed: u64) -> (BlockHash, BlockHash) {
    let mut lower = [0x10u8; 64];
    let mut higher = [0x20u8; 64];

    lower[1..9].copy_from_slice(&seed.to_be_bytes());
    higher[1..9].copy_from_slice(&seed.to_be_bytes());

    debug_assert!(lower < higher);

    (lower, higher)
}

fn height_only_cfg(
    allow_equal_height_tiebreak: bool,
    prefer_lower_hash_on_tie: bool,
) -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::HeightOnly,
        allow_equal_height_tiebreak,
        prefer_lower_hash_on_tie,
    }
}

fn cumulative_por_cfg(
    allow_equal_height_tiebreak: bool,
    prefer_lower_hash_on_tie: bool,
) -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::CumulativePor,
        allow_equal_height_tiebreak,
        prefer_lower_hash_on_tie,
    }
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_default_config_is_height_only_without_equal_height_tiebreak_and_prefers_lower_hash(
        _case in any::<u8>(),
    ) {
        let cfg = BranchScoreConfig::default();

        match cfg.mode {
            BranchScoreMode::HeightOnly => {}
            BranchScoreMode::CumulativePor => {
                prop_assert!(false, "default branch score mode must be HeightOnly");
            }
        }

        prop_assert!(
            !cfg.allow_equal_height_tiebreak,
            "default config must not replace equal-height branches by tie-break"
        );

        prop_assert!(
            cfg.prefer_lower_hash_on_tie,
            "default config must prefer lower hash when tie-break is explicitly enabled"
        );
    }

    // 02/25
    #[test]
    fn test_002_branch_score_from_height_sets_height_zero_cumulative_por_and_tip_hash(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let tip_hash = hash64(0x11, seed);
        let score = BranchScore::from_height(height, tip_hash);

        prop_assert_eq!(score.height, height);
        prop_assert_eq!(score.cumulative_por, 0);
        prop_assert_eq!(score.tip_hash, tip_hash);
    }

    // 03/25
    #[test]
    fn test_003_branch_score_from_cumulative_por_sets_all_fields_exactly(
        height in any::<u64>(),
        cumulative_por in any::<u128>(),
        seed in any::<u64>(),
    ) {
        let tip_hash = hash64(0x12, seed);
        let score = BranchScore::from_cumulative_por(height, cumulative_por, tip_hash);

        prop_assert_eq!(score.height, height);
        prop_assert_eq!(score.cumulative_por, cumulative_por);
        prop_assert_eq!(score.tip_hash, tip_hash);
    }

    // 04/25
    #[test]
    fn test_004_branch_candidate_new_and_to_score_preserve_every_comparison_field(
        height in any::<u64>(),
        cumulative_por in any::<u128>(),
        seed in any::<u64>(),
    ) {
        let tip_hash = hash64(0x13, seed);
        let candidate = BranchCandidate::new(tip_hash, height, cumulative_por);
        let score = candidate.to_score();

        prop_assert_eq!(candidate.tip_hash, tip_hash);
        prop_assert_eq!(candidate.height, height);
        prop_assert_eq!(candidate.cumulative_por, cumulative_por);

        prop_assert_eq!(score.tip_hash, candidate.tip_hash);
        prop_assert_eq!(score.height, candidate.height);
        prop_assert_eq!(score.cumulative_por, candidate.cumulative_por);
    }

    // 05/25
    #[test]
    fn test_005_height_only_mode_higher_height_strictly_beats_lower_height_regardless_of_por(
        low_height in 0u64..1_000_000u64,
        height_gap in 1u64..1_000_000u64,
        low_por in any::<u128>(),
        high_por in any::<u128>(),
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = height_only_cfg(false, true);

        let lower = BranchScore::from_cumulative_por(
            low_height,
            high_por,
            hash64(0x14, seed_a),
        );

        let higher = BranchScore::from_cumulative_por(
            low_height.saturating_add(height_gap),
            low_por,
            hash64(0x15, seed_b),
        );

        prop_assert!(
            higher.is_strictly_better_than(&lower, &cfg),
            "HeightOnly mode must prefer higher height even if cumulative PoR is lower"
        );

        prop_assert!(
            !lower.is_strictly_better_than(&higher, &cfg),
            "HeightOnly mode must not let lower height beat higher height"
        );
    }

    // 06/25
    #[test]
    fn test_006_height_only_mode_ignores_cumulative_por_when_heights_differ(
        height in 1u64..1_000_000u64,
        por_gap in 1u128..1_000_000u128,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = height_only_cfg(false, true);

        let lower_height_high_por = BranchScore::from_cumulative_por(
            height.saturating_sub(1),
            u128::MAX,
            hash64(0x16, seed_a),
        );

        let higher_height_low_por = BranchScore::from_cumulative_por(
            height,
            u128::MAX.saturating_sub(por_gap),
            hash64(0x17, seed_b),
        );

        prop_assert!(
            higher_height_low_por.is_strictly_better_than(&lower_height_high_por, &cfg),
            "higher height must win in HeightOnly mode even against much higher PoR"
        );

        prop_assert!(
            !lower_height_high_por.is_strictly_better_than(&higher_height_low_por, &cfg),
            "higher PoR must not override height in HeightOnly mode"
        );
    }

    // 07/25
    #[test]
    fn test_007_height_only_equal_height_without_tiebreak_makes_distinct_hashes_indistinguishable(
        height in any::<u64>(),
        por_a in any::<u128>(),
        por_b in any::<u128>(),
        seed in any::<u64>(),
    ) {
        let cfg = height_only_cfg(false, true);
        let (lower_hash, higher_hash) = ordered_hash_pair(seed);

        let a = BranchScore::from_cumulative_por(height, por_a, lower_hash);
        let b = BranchScore::from_cumulative_por(height, por_b, higher_hash);

        prop_assert!(
            !a.is_strictly_better_than(&b, &cfg),
            "equal height without tiebreak must not let lower hash win"
        );

        prop_assert!(
            !b.is_strictly_better_than(&a, &cfg),
            "equal height without tiebreak must not let higher hash win"
        );

        prop_assert_eq!(
            BranchScore::choose_better(&a, &b, &cfg),
            None,
            "equal height without tiebreak must produce no winner"
        );
    }

    // 08/25
    #[test]
    fn test_008_height_only_equal_height_with_lower_hash_tiebreak_prefers_lower_hash(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let cfg = height_only_cfg(true, true);
        let (lower_hash, higher_hash) = ordered_hash_pair(seed);

        let lower = BranchScore::from_height(height, lower_hash);
        let higher = BranchScore::from_height(height, higher_hash);

        prop_assert!(
            lower.is_strictly_better_than(&higher, &cfg),
            "lower hash must win equal-height tie when prefer_lower_hash_on_tie=true"
        );

        prop_assert!(
            !higher.is_strictly_better_than(&lower, &cfg),
            "higher hash must lose equal-height tie when prefer_lower_hash_on_tie=true"
        );

        prop_assert_eq!(
            BranchScore::choose_better(&lower, &higher, &cfg),
            Some(lower_hash)
        );
    }

    // 09/25
    #[test]
    fn test_009_height_only_equal_height_with_higher_hash_tiebreak_prefers_higher_hash(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let cfg = height_only_cfg(true, false);
        let (lower_hash, higher_hash) = ordered_hash_pair(seed);

        let lower = BranchScore::from_height(height, lower_hash);
        let higher = BranchScore::from_height(height, higher_hash);

        prop_assert!(
            higher.is_strictly_better_than(&lower, &cfg),
            "higher hash must win equal-height tie when prefer_lower_hash_on_tie=false"
        );

        prop_assert!(
            !lower.is_strictly_better_than(&higher, &cfg),
            "lower hash must lose equal-height tie when prefer_lower_hash_on_tie=false"
        );

        prop_assert_eq!(
            BranchScore::choose_better(&lower, &higher, &cfg),
            Some(higher_hash)
        );
    }

    // 10/25
    #[test]
    fn test_010_equal_height_tiebreak_never_prefers_identical_hashes(
        height in any::<u64>(),
        seed in any::<u64>(),
        prefer_lower in any::<bool>(),
    ) {
        let cfg = height_only_cfg(true, prefer_lower);
        let hash = hash64(0x18, seed);

        let a = BranchScore::from_height(height, hash);
        let b = BranchScore::from_height(height, hash);

        prop_assert!(
            !a.is_strictly_better_than(&b, &cfg),
            "a score must not strictly beat an identical score"
        );

        prop_assert!(
            !b.is_strictly_better_than(&a, &cfg),
            "identical reverse comparison must also not strictly beat"
        );

        prop_assert_eq!(
            BranchScore::choose_better(&a, &b, &cfg),
            None,
            "identical branch scores must not produce a winner"
        );
    }

    // 11/25
    #[test]
    fn test_011_choose_better_height_only_returns_taller_tip_hash(
        height in 0u64..1_000_000u64,
        gap in 1u64..1_000_000u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = height_only_cfg(false, true);

        let shorter_hash = hash64(0x19, seed_a);
        let taller_hash = distinct_hash64(0x1A, seed_b, shorter_hash);

        let shorter = BranchScore::from_height(height, shorter_hash);
        let taller = BranchScore::from_height(height.saturating_add(gap), taller_hash);

        prop_assert_eq!(
            BranchScore::choose_better(&shorter, &taller, &cfg),
            Some(taller_hash),
            "choose_better must return taller branch tip hash in HeightOnly mode"
        );

        prop_assert_eq!(
            BranchScore::choose_better(&taller, &shorter, &cfg),
            Some(taller_hash),
            "choose_better must be order-independent for unequal heights"
        );
    }

    // 12/25
    #[test]
    fn test_012_cumulative_por_mode_higher_por_beats_lower_por_even_with_lower_height(
        high_height in 1u64..1_000_000u64,
        height_drop in 1u64..1_000u64,
        low_por in 0u128..1_000_000u128,
        por_gap in 1u128..1_000_000u128,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(false, true);

        let low_por_high_height = BranchScore::from_cumulative_por(
            high_height,
            low_por,
            hash64(0x1B, seed_a),
        );

        let high_por_lower_height = BranchScore::from_cumulative_por(
            high_height.saturating_sub(height_drop),
            low_por.saturating_add(por_gap),
            hash64(0x1C, seed_b),
        );

        prop_assert!(
            high_por_lower_height.is_strictly_better_than(&low_por_high_height, &cfg),
            "CumulativePor mode must prefer higher cumulative PoR before height"
        );

        prop_assert!(
            !low_por_high_height.is_strictly_better_than(&high_por_lower_height, &cfg),
            "higher height must not beat higher cumulative PoR in CumulativePor mode"
        );
    }

    // 13/25
    #[test]
    fn test_013_cumulative_por_mode_lower_por_never_beats_higher_por(
        height_a in any::<u64>(),
        height_b in any::<u64>(),
        high_por in 1u128..1_000_000u128,
        por_drop in 1u128..1_000_000u128,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(true, true);

        let high_score = BranchScore::from_cumulative_por(
            height_a,
            high_por,
            hash64(0x1D, seed_a),
        );

        let low_score = BranchScore::from_cumulative_por(
            height_b,
            high_por.saturating_sub(por_drop),
            hash64(0x1E, seed_b),
        );

        if high_score.cumulative_por > low_score.cumulative_por {
            prop_assert!(
                high_score.is_strictly_better_than(&low_score, &cfg),
                "higher cumulative PoR must strictly beat lower cumulative PoR"
            );

            prop_assert!(
                !low_score.is_strictly_better_than(&high_score, &cfg),
                "lower cumulative PoR must not beat higher cumulative PoR"
            );
        }
    }

    // 14/25
    #[test]
    fn test_014_cumulative_por_equal_por_falls_back_to_height(
        low_height in 0u64..1_000_000u64,
        height_gap in 1u64..1_000_000u64,
        por in any::<u128>(),
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(false, true);

        let lower = BranchScore::from_cumulative_por(
            low_height,
            por,
            hash64(0x1F, seed_a),
        );

        let higher = BranchScore::from_cumulative_por(
            low_height.saturating_add(height_gap),
            por,
            hash64(0x20, seed_b),
        );

        prop_assert!(
            higher.is_strictly_better_than(&lower, &cfg),
            "CumulativePor mode must use height fallback when PoR totals are equal"
        );

        prop_assert!(
            !lower.is_strictly_better_than(&higher, &cfg),
            "lower height must lose when PoR totals are equal"
        );
    }

    // 15/25
    #[test]
    fn test_015_cumulative_por_equal_por_equal_height_without_tiebreak_has_no_winner(
        height in any::<u64>(),
        por in any::<u128>(),
        seed in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(false, true);
        let (lower_hash, higher_hash) = ordered_hash_pair(seed);

        let lower = BranchScore::from_cumulative_por(height, por, lower_hash);
        let higher = BranchScore::from_cumulative_por(height, por, higher_hash);

        prop_assert_eq!(
            BranchScore::choose_better(&lower, &higher, &cfg),
            None,
            "equal PoR and equal height without tie-break must have no winner"
        );
    }

    // 16/25
    #[test]
    fn test_016_cumulative_por_equal_por_equal_height_with_lower_hash_tiebreak_selects_lower_hash(
        height in any::<u64>(),
        por in any::<u128>(),
        seed in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(true, true);
        let (lower_hash, higher_hash) = ordered_hash_pair(seed);

        let lower = BranchScore::from_cumulative_por(height, por, lower_hash);
        let higher = BranchScore::from_cumulative_por(height, por, higher_hash);

        prop_assert!(
            lower.is_strictly_better_than(&higher, &cfg),
            "lower hash must win exact PoR/height tie when lower-hash tie-break is enabled"
        );

        prop_assert_eq!(
            BranchScore::choose_better(&lower, &higher, &cfg),
            Some(lower_hash)
        );
    }

    // 17/25
    #[test]
    fn test_017_cumulative_por_equal_por_equal_height_with_higher_hash_tiebreak_selects_higher_hash(
        height in any::<u64>(),
        por in any::<u128>(),
        seed in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(true, false);
        let (lower_hash, higher_hash) = ordered_hash_pair(seed);

        let lower = BranchScore::from_cumulative_por(height, por, lower_hash);
        let higher = BranchScore::from_cumulative_por(height, por, higher_hash);

        prop_assert!(
            higher.is_strictly_better_than(&lower, &cfg),
            "higher hash must win exact PoR/height tie when higher-hash tie-break is enabled"
        );

        prop_assert_eq!(
            BranchScore::choose_better(&lower, &higher, &cfg),
            Some(higher_hash)
        );
    }

    // 18/25
    #[test]
    fn test_018_choose_better_is_symmetric_for_cumulative_por_winner(
        height_a in any::<u64>(),
        height_b in any::<u64>(),
        por in 0u128..1_000_000u128,
        por_gap in 1u128..1_000_000u128,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(false, true);

        let winner_hash = hash64(0x21, seed_a);
        let loser_hash = distinct_hash64(0x22, seed_b, winner_hash);

        let winner = BranchScore::from_cumulative_por(
            height_a,
            por.saturating_add(por_gap),
            winner_hash,
        );

        let loser = BranchScore::from_cumulative_por(
            height_b,
            por,
            loser_hash,
        );

        prop_assert_eq!(
            BranchScore::choose_better(&winner, &loser, &cfg),
            Some(winner_hash)
        );

        prop_assert_eq!(
            BranchScore::choose_better(&loser, &winner, &cfg),
            Some(winner_hash)
        );
    }

    // 19/25
    #[test]
    fn test_019_reorg_branch_scorer_default_height_only_matches_default_config_behavior(
        height in 0u64..1_000_000u64,
        gap in 1u64..1_000_000u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let scorer = ReorgBranchScorer::default_height_only();

        match scorer.config().mode {
            BranchScoreMode::HeightOnly => {}
            BranchScoreMode::CumulativePor => {
                prop_assert!(false, "default_height_only scorer must use HeightOnly mode");
            }
        }

        prop_assert!(!scorer.config().allow_equal_height_tiebreak);
        prop_assert!(scorer.config().prefer_lower_hash_on_tie);

        let current_hash = hash64(0x23, seed_a);
        let candidate_hash = distinct_hash64(0x24, seed_b, current_hash);

        let current = BranchCandidate::new(current_hash, height, u128::MAX);
        let candidate = BranchCandidate::new(candidate_hash, height.saturating_add(gap), 0);

        prop_assert_eq!(
            scorer.choose_tip(current, candidate),
            Some(candidate_hash),
            "default height-only scorer must choose taller candidate"
        );
    }

    // 20/25
    #[test]
    fn test_020_reorg_branch_scorer_new_preserves_custom_cumulative_por_config(
        height in any::<u64>(),
        current_por in 0u128..1_000_000u128,
        por_gap in 1u128..1_000_000u128,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let cfg = cumulative_por_cfg(true, false);
        let scorer = ReorgBranchScorer::new(cfg);

        match scorer.config().mode {
            BranchScoreMode::CumulativePor => {}
            BranchScoreMode::HeightOnly => {
                prop_assert!(false, "custom scorer must preserve CumulativePor mode");
            }
        }

        prop_assert!(scorer.config().allow_equal_height_tiebreak);
        prop_assert!(!scorer.config().prefer_lower_hash_on_tie);

        let current_hash = hash64(0x25, seed_a);
        let candidate_hash = distinct_hash64(0x26, seed_b, current_hash);

        let current = BranchCandidate::new(current_hash, height, current_por);
        let candidate = BranchCandidate::new(
            candidate_hash,
            height,
            current_por.saturating_add(por_gap),
        );

        prop_assert_eq!(
            scorer.choose_tip(current, candidate),
            Some(candidate_hash),
            "custom cumulative-PoR scorer must choose higher-PoR candidate"
        );
    }

    // 21/25
    #[test]
    fn test_021_choose_tip_returns_current_hash_when_current_strictly_beats_candidate(
        height in 1u64..1_000_000u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let scorer = ReorgBranchScorer::default_height_only();

        let current_hash = hash64(0x27, seed_a);
        let candidate_hash = distinct_hash64(0x28, seed_b, current_hash);

        let current = BranchCandidate::new(current_hash, height, 0);
        let candidate = BranchCandidate::new(candidate_hash, height.saturating_sub(1), u128::MAX);

        prop_assert_eq!(
            scorer.choose_tip(current, candidate),
            Some(current_hash),
            "choose_tip must return current hash when current remains strictly better"
        );

        prop_assert!(
            !scorer.candidate_beats_current(current, candidate),
            "candidate_beats_current must be false when current wins"
        );
    }

    // 22/25
    #[test]
    fn test_022_candidate_beats_current_is_true_exactly_when_choose_tip_returns_candidate_hash(
        current_height in 0u64..1_000_000u64,
        height_gap in 1u64..1_000_000u64,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let scorer = ReorgBranchScorer::default_height_only();

        let current_hash = hash64(0x29, seed_a);
        let candidate_hash = distinct_hash64(0x2A, seed_b, current_hash);

        let current = BranchCandidate::new(current_hash, current_height, 0);
        let candidate = BranchCandidate::new(
            candidate_hash,
            current_height.saturating_add(height_gap),
            0,
        );

        prop_assert_eq!(
            scorer.choose_tip(current, candidate),
            Some(candidate_hash)
        );

        prop_assert!(
            scorer.candidate_beats_current(current, candidate),
            "candidate_beats_current must agree with choose_tip returning candidate hash"
        );
    }

    // 23/25
    #[test]
    fn test_023_candidate_beats_current_is_false_when_branches_are_indistinguishable(
        height in any::<u64>(),
        por in any::<u128>(),
        seed in any::<u64>(),
    ) {
        let cfg = height_only_cfg(false, true);
        let scorer = ReorgBranchScorer::new(cfg);

        let hash = hash64(0x2B, seed);

        let current = BranchCandidate::new(hash, height, por);
        let candidate = BranchCandidate::new(hash, height, por);

        prop_assert_eq!(
            scorer.choose_tip(current, candidate),
            None,
            "indistinguishable branches must produce None"
        );

        prop_assert!(
            !scorer.candidate_beats_current(current, candidate),
            "candidate_beats_current must be false for indistinguishable branches"
        );
    }

    // 24/25
    #[test]
    fn test_024_equal_height_tiebreak_in_scorer_can_replace_current_with_candidate_lower_hash(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let scorer = ReorgBranchScorer::new(height_only_cfg(true, true));
        let (candidate_lower_hash, current_higher_hash) = ordered_hash_pair(seed);

        let current = BranchCandidate::new(current_higher_hash, height, 0);
        let candidate = BranchCandidate::new(candidate_lower_hash, height, 0);

        prop_assert_eq!(
            scorer.choose_tip(current, candidate),
            Some(candidate_lower_hash),
            "height-only scorer with lower-hash tie-break must replace current with lower-hash candidate"
        );

        prop_assert!(
            scorer.candidate_beats_current(current, candidate),
            "candidate lower hash must beat current higher hash when equal-height tie-break is enabled"
        );
    }

    // 25/25
    #[test]
    fn test_025_equal_height_tiebreak_disabled_prevents_replacement_even_when_candidate_hash_is_lower(
        height in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let scorer = ReorgBranchScorer::new(height_only_cfg(false, true));
        let (candidate_lower_hash, current_higher_hash) = ordered_hash_pair(seed);

        let current = BranchCandidate::new(current_higher_hash, height, 0);
        let candidate = BranchCandidate::new(candidate_lower_hash, height, 0);

        prop_assert_eq!(
            scorer.choose_tip(current, candidate),
            None,
            "without equal-height tie-break, lower candidate hash must not replace current"
        );

        prop_assert!(
            !scorer.candidate_beats_current(current, candidate),
            "candidate_beats_current must stay false when equal-height tie-break is disabled"
        );
    }
}
