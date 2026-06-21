use remzar::reorganization::reorg_003_branch_score::{
    BlockHash, BranchCandidate, BranchScore, BranchScoreConfig, BranchScoreMode, ReorgBranchScorer,
};

fn deterministic_hash(seed: u64) -> BlockHash {
    std::array::from_fn(|idx| {
        let idx_u64: u64 = u64::try_from(idx).unwrap_or_default();
        let value = seed
            .wrapping_mul(37)
            .wrapping_add(idx_u64.wrapping_mul(17))
            .wrapping_add(11);
        let bytes = value.to_le_bytes();

        match bytes.first() {
            Some(byte) => *byte,
            None => 0,
        }
    })
}

fn low_hash() -> BlockHash {
    [1u8; 64]
}

fn mid_hash() -> BlockHash {
    [5u8; 64]
}

fn high_hash() -> BlockHash {
    [9u8; 64]
}

fn height_cfg() -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::HeightOnly,
        allow_equal_height_tiebreak: false,
        prefer_lower_hash_on_tie: true,
    }
}

fn height_lower_tiebreak_cfg() -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::HeightOnly,
        allow_equal_height_tiebreak: true,
        prefer_lower_hash_on_tie: true,
    }
}

fn height_higher_tiebreak_cfg() -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::HeightOnly,
        allow_equal_height_tiebreak: true,
        prefer_lower_hash_on_tie: false,
    }
}

fn por_cfg() -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::CumulativePor,
        allow_equal_height_tiebreak: false,
        prefer_lower_hash_on_tie: true,
    }
}

fn por_lower_tiebreak_cfg() -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::CumulativePor,
        allow_equal_height_tiebreak: true,
        prefer_lower_hash_on_tie: true,
    }
}

fn por_higher_tiebreak_cfg() -> BranchScoreConfig {
    BranchScoreConfig {
        mode: BranchScoreMode::CumulativePor,
        allow_equal_height_tiebreak: true,
        prefer_lower_hash_on_tie: false,
    }
}

fn score_height(height: u64, hash: BlockHash) -> BranchScore {
    BranchScore::from_height(height, hash)
}

fn score_por(height: u64, cumulative_por: u128, hash: BlockHash) -> BranchScore {
    BranchScore::from_cumulative_por(height, cumulative_por, hash)
}

fn candidate(height: u64, cumulative_por: u128, hash: BlockHash) -> BranchCandidate {
    BranchCandidate::new(hash, height, cumulative_por)
}

#[test]
fn test_001_default_config_is_height_only_vector() {
    let cfg = BranchScoreConfig::default();

    assert!(matches!(cfg.mode, BranchScoreMode::HeightOnly));
}

#[test]
fn test_002_default_config_disables_equal_height_tiebreak_vector() {
    let cfg = BranchScoreConfig::default();

    assert!(!cfg.allow_equal_height_tiebreak);
}

#[test]
fn test_003_default_config_prefers_lower_hash_on_tie_vector() {
    let cfg = BranchScoreConfig::default();

    assert!(cfg.prefer_lower_hash_on_tie);
}

#[test]
fn test_004_branch_score_from_height_sets_height_vector() {
    let hash = deterministic_hash(4);
    let score = BranchScore::from_height(44, hash);

    assert_eq!(score.height, 44);
}

#[test]
fn test_005_branch_score_from_height_sets_zero_cumulative_por_vector() {
    let hash = deterministic_hash(5);
    let score = BranchScore::from_height(55, hash);

    assert_eq!(score.cumulative_por, 0);
}

#[test]
fn test_006_branch_score_from_height_preserves_tip_hash_vector() {
    let hash = deterministic_hash(6);
    let score = BranchScore::from_height(66, hash);

    assert_eq!(score.tip_hash, hash);
}

#[test]
fn test_007_branch_score_from_cumulative_por_sets_height_vector() {
    let hash = deterministic_hash(7);
    let score = BranchScore::from_cumulative_por(77, 7_777, hash);

    assert_eq!(score.height, 77);
}

#[test]
fn test_008_branch_score_from_cumulative_por_sets_score_vector() {
    let hash = deterministic_hash(8);
    let score = BranchScore::from_cumulative_por(88, 8_888, hash);

    assert_eq!(score.cumulative_por, 8_888);
}

#[test]
fn test_009_branch_score_from_cumulative_por_preserves_tip_hash_vector() {
    let hash = deterministic_hash(9);
    let score = BranchScore::from_cumulative_por(99, 9_999, hash);

    assert_eq!(score.tip_hash, hash);
}

#[test]
fn test_010_branch_candidate_new_preserves_fields_vector() {
    let hash = deterministic_hash(10);
    let candidate = BranchCandidate::new(hash, 10, 1_010);

    assert_eq!(candidate.tip_hash, hash);
    assert_eq!(candidate.height, 10);
    assert_eq!(candidate.cumulative_por, 1_010);
}

#[test]
fn test_011_branch_candidate_to_score_preserves_fields_vector() {
    let hash = deterministic_hash(11);
    let candidate = BranchCandidate::new(hash, 11, 1_111);
    let score = candidate.to_score();

    assert_eq!(score.tip_hash, hash);
    assert_eq!(score.height, 11);
    assert_eq!(score.cumulative_por, 1_111);
}

#[test]
fn test_012_reorg_branch_scorer_new_preserves_height_config_vector() {
    let scorer = ReorgBranchScorer::new(height_cfg());

    assert!(matches!(scorer.config().mode, BranchScoreMode::HeightOnly));
    assert!(!scorer.config().allow_equal_height_tiebreak);
}

#[test]
fn test_013_reorg_branch_scorer_new_preserves_por_config_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());

    assert!(matches!(
        scorer.config().mode,
        BranchScoreMode::CumulativePor
    ));
    assert!(!scorer.config().allow_equal_height_tiebreak);
}

#[test]
fn test_014_default_height_only_uses_default_config_vector() {
    let scorer = ReorgBranchScorer::default_height_only();

    assert!(matches!(scorer.config().mode, BranchScoreMode::HeightOnly));
    assert!(!scorer.config().allow_equal_height_tiebreak);
    assert!(scorer.config().prefer_lower_hash_on_tie);
}

#[test]
fn test_015_branch_score_copy_preserves_value_vector() {
    let original = score_por(15, 1_500, deterministic_hash(15));
    let copied = original;

    assert_eq!(copied, original);
}

#[test]
fn test_016_branch_score_clone_preserves_value_vector() {
    let original = score_por(16, 1_600, deterministic_hash(16));
    let cloned = original;

    assert_eq!(cloned, original);
}

#[test]
fn test_017_branch_candidate_copy_preserves_value_vector() {
    let original = candidate(17, 1_700, deterministic_hash(17));
    let copied = original;

    assert_eq!(copied, original);
}

#[test]
fn test_018_branch_candidate_clone_preserves_value_vector() {
    let original = candidate(18, 1_800, deterministic_hash(18));
    let cloned = original;

    assert_eq!(cloned, original);
}

#[test]
fn test_019_branch_score_debug_contains_height_vector() {
    let score = score_height(19, deterministic_hash(19));
    let rendered = format!("{score:?}");

    assert!(rendered.contains("height"));
}

#[test]
fn test_020_branch_candidate_debug_contains_cumulative_por_vector() {
    let candidate = candidate(20, 2_000, deterministic_hash(20));
    let rendered = format!("{candidate:?}");

    assert!(rendered.contains("cumulative_por"));
}

#[test]
fn test_021_height_only_higher_height_is_strictly_better_vector() {
    let cfg = height_cfg();
    let better = score_height(2, deterministic_hash(21));
    let worse = score_height(1, deterministic_hash(22));

    assert!(better.is_strictly_better_than(&worse, &cfg));
}

#[test]
fn test_022_height_only_lower_height_is_not_strictly_better_vector() {
    let cfg = height_cfg();
    let lower = score_height(1, deterministic_hash(23));
    let higher = score_height(2, deterministic_hash(24));

    assert!(!lower.is_strictly_better_than(&higher, &cfg));
}

#[test]
fn test_023_height_only_equal_height_without_tiebreak_is_not_better_vector() {
    let cfg = height_cfg();
    let a = score_height(5, low_hash());
    let b = score_height(5, high_hash());

    assert!(!a.is_strictly_better_than(&b, &cfg));
    assert!(!b.is_strictly_better_than(&a, &cfg));
}

#[test]
fn test_024_height_only_equal_height_lower_hash_wins_when_enabled_vector() {
    let cfg = height_lower_tiebreak_cfg();
    let lower = score_height(5, low_hash());
    let higher = score_height(5, high_hash());

    assert!(lower.is_strictly_better_than(&higher, &cfg));
    assert!(!higher.is_strictly_better_than(&lower, &cfg));
}

#[test]
fn test_025_height_only_equal_height_higher_hash_wins_when_configured_vector() {
    let cfg = height_higher_tiebreak_cfg();
    let lower = score_height(5, low_hash());
    let higher = score_height(5, high_hash());

    assert!(higher.is_strictly_better_than(&lower, &cfg));
    assert!(!lower.is_strictly_better_than(&higher, &cfg));
}

#[test]
fn test_026_height_only_equal_height_same_hash_never_tiebreaks_vector() {
    let cfg = height_lower_tiebreak_cfg();
    let hash = deterministic_hash(26);
    let a = score_height(5, hash);
    let b = score_height(5, hash);

    assert!(!a.is_strictly_better_than(&b, &cfg));
    assert!(!b.is_strictly_better_than(&a, &cfg));
}

#[test]
fn test_027_height_only_ignores_cumulative_por_when_height_differs_vector() {
    let cfg = height_cfg();
    let taller = score_por(10, 1, deterministic_hash(27));
    let shorter = score_por(9, u128::MAX, deterministic_hash(28));

    assert!(taller.is_strictly_better_than(&shorter, &cfg));
    assert!(!shorter.is_strictly_better_than(&taller, &cfg));
}

#[test]
fn test_028_height_only_ignores_cumulative_por_when_heights_equal_no_tiebreak_vector() {
    let cfg = height_cfg();
    let low_por = score_por(10, 1, low_hash());
    let high_por = score_por(10, u128::MAX, high_hash());

    assert!(!low_por.is_strictly_better_than(&high_por, &cfg));
    assert!(!high_por.is_strictly_better_than(&low_por, &cfg));
}

#[test]
fn test_029_height_only_choose_better_returns_taller_hash_vector() {
    let cfg = height_cfg();
    let taller = score_height(3, deterministic_hash(29));
    let shorter = score_height(2, deterministic_hash(30));

    assert_eq!(
        BranchScore::choose_better(&taller, &shorter, &cfg),
        Some(taller.tip_hash)
    );
}

#[test]
fn test_030_height_only_choose_better_returns_second_when_second_taller_vector() {
    let cfg = height_cfg();
    let shorter = score_height(2, deterministic_hash(31));
    let taller = score_height(3, deterministic_hash(32));

    assert_eq!(
        BranchScore::choose_better(&shorter, &taller, &cfg),
        Some(taller.tip_hash)
    );
}

#[test]
fn test_031_height_only_choose_better_equal_height_no_tiebreak_returns_none_vector() {
    let cfg = height_cfg();
    let a = score_height(3, low_hash());
    let b = score_height(3, high_hash());

    assert_eq!(BranchScore::choose_better(&a, &b, &cfg), None);
}

#[test]
fn test_032_height_only_choose_better_equal_height_lower_hash_returns_lower_vector() {
    let cfg = height_lower_tiebreak_cfg();
    let lower = score_height(3, low_hash());
    let higher = score_height(3, high_hash());

    assert_eq!(
        BranchScore::choose_better(&lower, &higher, &cfg),
        Some(low_hash())
    );
}

#[test]
fn test_033_height_only_choose_better_equal_height_lower_hash_when_lower_is_second_vector() {
    let cfg = height_lower_tiebreak_cfg();
    let higher = score_height(3, high_hash());
    let lower = score_height(3, low_hash());

    assert_eq!(
        BranchScore::choose_better(&higher, &lower, &cfg),
        Some(low_hash())
    );
}

#[test]
fn test_034_height_only_choose_better_equal_height_higher_hash_returns_higher_vector() {
    let cfg = height_higher_tiebreak_cfg();
    let lower = score_height(3, low_hash());
    let higher = score_height(3, high_hash());

    assert_eq!(
        BranchScore::choose_better(&lower, &higher, &cfg),
        Some(high_hash())
    );
}

#[test]
fn test_035_height_only_choose_better_same_score_same_hash_returns_none_vector() {
    let cfg = height_lower_tiebreak_cfg();
    let hash = deterministic_hash(35);
    let a = score_height(3, hash);
    let b = score_height(3, hash);

    assert_eq!(BranchScore::choose_better(&a, &b, &cfg), None);
}

#[test]
fn test_036_height_only_u64_max_height_beats_lower_height_edge() {
    let cfg = height_cfg();
    let max = score_height(u64::MAX, deterministic_hash(36));
    let lower = score_height(u64::MAX.saturating_sub(1), deterministic_hash(37));

    assert!(max.is_strictly_better_than(&lower, &cfg));
}

#[test]
fn test_037_height_only_zero_height_loses_to_one_edge() {
    let cfg = height_cfg();
    let zero = score_height(0, deterministic_hash(38));
    let one = score_height(1, deterministic_hash(39));

    assert!(!zero.is_strictly_better_than(&one, &cfg));
    assert!(one.is_strictly_better_than(&zero, &cfg));
}

#[test]
fn test_038_height_only_same_hash_different_height_higher_wins_vector() {
    let cfg = height_lower_tiebreak_cfg();
    let hash = deterministic_hash(38);
    let higher = score_height(9, hash);
    let lower = score_height(8, hash);

    assert!(higher.is_strictly_better_than(&lower, &cfg));
}

#[test]
fn test_039_height_only_tiebreak_does_not_override_height_vector() {
    let cfg = height_lower_tiebreak_cfg();
    let taller_higher_hash = score_height(10, high_hash());
    let shorter_lower_hash = score_height(9, low_hash());

    assert!(taller_higher_hash.is_strictly_better_than(&shorter_lower_hash, &cfg));
}

#[test]
fn test_040_height_only_choose_better_height_dominates_tiebreak_vector() {
    let cfg = height_higher_tiebreak_cfg();
    let taller_low_hash = score_height(10, low_hash());
    let shorter_high_hash = score_height(9, high_hash());

    assert_eq!(
        BranchScore::choose_better(&taller_low_hash, &shorter_high_hash, &cfg),
        Some(low_hash())
    );
}

#[test]
fn test_041_cumulative_por_higher_por_is_strictly_better_vector() {
    let cfg = por_cfg();
    let better = score_por(1, 200, deterministic_hash(41));
    let worse = score_por(100, 100, deterministic_hash(42));

    assert!(better.is_strictly_better_than(&worse, &cfg));
}

#[test]
fn test_042_cumulative_por_lower_por_is_not_strictly_better_vector() {
    let cfg = por_cfg();
    let lower = score_por(100, 100, deterministic_hash(43));
    let higher = score_por(1, 200, deterministic_hash(44));

    assert!(!lower.is_strictly_better_than(&higher, &cfg));
}

#[test]
fn test_043_cumulative_por_equal_por_higher_height_wins_vector() {
    let cfg = por_cfg();
    let taller = score_por(10, 500, deterministic_hash(45));
    let shorter = score_por(9, 500, deterministic_hash(46));

    assert!(taller.is_strictly_better_than(&shorter, &cfg));
}

#[test]
fn test_044_cumulative_por_equal_por_lower_height_loses_vector() {
    let cfg = por_cfg();
    let shorter = score_por(9, 500, deterministic_hash(47));
    let taller = score_por(10, 500, deterministic_hash(48));

    assert!(!shorter.is_strictly_better_than(&taller, &cfg));
}

#[test]
fn test_045_cumulative_por_equal_por_equal_height_no_tiebreak_returns_false_vector() {
    let cfg = por_cfg();
    let a = score_por(10, 500, low_hash());
    let b = score_por(10, 500, high_hash());

    assert!(!a.is_strictly_better_than(&b, &cfg));
    assert!(!b.is_strictly_better_than(&a, &cfg));
}

#[test]
fn test_046_cumulative_por_equal_por_equal_height_lower_hash_wins_vector() {
    let cfg = por_lower_tiebreak_cfg();
    let lower = score_por(10, 500, low_hash());
    let higher = score_por(10, 500, high_hash());

    assert!(lower.is_strictly_better_than(&higher, &cfg));
}

#[test]
fn test_047_cumulative_por_equal_por_equal_height_higher_hash_wins_vector() {
    let cfg = por_higher_tiebreak_cfg();
    let lower = score_por(10, 500, low_hash());
    let higher = score_por(10, 500, high_hash());

    assert!(higher.is_strictly_better_than(&lower, &cfg));
}

#[test]
fn test_048_cumulative_por_same_hash_equal_por_equal_height_not_better_vector() {
    let cfg = por_lower_tiebreak_cfg();
    let hash = deterministic_hash(48);
    let a = score_por(10, 500, hash);
    let b = score_por(10, 500, hash);

    assert!(!a.is_strictly_better_than(&b, &cfg));
}

#[test]
fn test_049_cumulative_por_choose_better_returns_higher_por_vector() {
    let cfg = por_cfg();
    let high_por = score_por(1, 900, deterministic_hash(49));
    let low_por = score_por(100, 800, deterministic_hash(50));

    assert_eq!(
        BranchScore::choose_better(&high_por, &low_por, &cfg),
        Some(high_por.tip_hash)
    );
}

#[test]
fn test_050_cumulative_por_choose_better_second_higher_por_vector() {
    let cfg = por_cfg();
    let low_por = score_por(100, 800, deterministic_hash(51));
    let high_por = score_por(1, 900, deterministic_hash(52));

    assert_eq!(
        BranchScore::choose_better(&low_por, &high_por, &cfg),
        Some(high_por.tip_hash)
    );
}

#[test]
fn test_051_cumulative_por_choose_better_equal_por_higher_height_vector() {
    let cfg = por_cfg();
    let taller = score_por(11, 900, deterministic_hash(53));
    let shorter = score_por(10, 900, deterministic_hash(54));

    assert_eq!(
        BranchScore::choose_better(&taller, &shorter, &cfg),
        Some(taller.tip_hash)
    );
}

#[test]
fn test_052_cumulative_por_choose_better_equal_all_no_tiebreak_returns_none_vector() {
    let cfg = por_cfg();
    let a = score_por(11, 900, low_hash());
    let b = score_por(11, 900, high_hash());

    assert_eq!(BranchScore::choose_better(&a, &b, &cfg), None);
}

#[test]
fn test_053_cumulative_por_choose_better_equal_all_lower_hash_vector() {
    let cfg = por_lower_tiebreak_cfg();
    let lower = score_por(11, 900, low_hash());
    let higher = score_por(11, 900, high_hash());

    assert_eq!(
        BranchScore::choose_better(&lower, &higher, &cfg),
        Some(low_hash())
    );
}

#[test]
fn test_054_cumulative_por_choose_better_equal_all_higher_hash_vector() {
    let cfg = por_higher_tiebreak_cfg();
    let lower = score_por(11, 900, low_hash());
    let higher = score_por(11, 900, high_hash());

    assert_eq!(
        BranchScore::choose_better(&lower, &higher, &cfg),
        Some(high_hash())
    );
}

#[test]
fn test_055_cumulative_por_u128_max_score_beats_lower_score_edge() {
    let cfg = por_cfg();
    let max = score_por(0, u128::MAX, deterministic_hash(55));
    let lower = score_por(
        u64::MAX,
        u128::MAX.saturating_sub(1),
        deterministic_hash(56),
    );

    assert!(max.is_strictly_better_than(&lower, &cfg));
}

#[test]
fn test_056_cumulative_por_zero_score_falls_back_to_height_edge() {
    let cfg = por_cfg();
    let taller = score_por(2, 0, deterministic_hash(57));
    let shorter = score_por(1, 0, deterministic_hash(58));

    assert!(taller.is_strictly_better_than(&shorter, &cfg));
}

#[test]
fn test_057_cumulative_por_score_dominates_height_edge() {
    let cfg = por_cfg();
    let high_score_low_height = score_por(1, 10, deterministic_hash(59));
    let low_score_high_height = score_por(u64::MAX, 9, deterministic_hash(60));

    assert!(high_score_low_height.is_strictly_better_than(&low_score_high_height, &cfg));
}

#[test]
fn test_058_cumulative_por_height_dominates_tiebreak_after_equal_score_vector() {
    let cfg = por_lower_tiebreak_cfg();
    let taller_high_hash = score_por(10, 100, high_hash());
    let shorter_low_hash = score_por(9, 100, low_hash());

    assert!(taller_high_hash.is_strictly_better_than(&shorter_low_hash, &cfg));
}

#[test]
fn test_059_cumulative_por_tiebreak_only_after_equal_score_and_height_vector() {
    let cfg = por_lower_tiebreak_cfg();
    let higher_score_high_hash = score_por(9, 101, high_hash());
    let lower_score_low_hash = score_por(10, 100, low_hash());

    assert!(higher_score_high_hash.is_strictly_better_than(&lower_score_low_hash, &cfg));
}

#[test]
fn test_060_cumulative_por_choose_better_same_hash_same_values_none_vector() {
    let cfg = por_lower_tiebreak_cfg();
    let hash = deterministic_hash(60);
    let a = score_por(10, 100, hash);
    let b = score_por(10, 100, hash);

    assert_eq!(BranchScore::choose_better(&a, &b, &cfg), None);
}

#[test]
fn test_061_scorer_height_only_candidate_higher_height_wins_vector() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(1, 0, deterministic_hash(61));
    let proposed = candidate(2, 0, deterministic_hash(62));

    assert_eq!(
        scorer.choose_tip(current, proposed),
        Some(proposed.tip_hash)
    );
}

#[test]
fn test_062_scorer_height_only_current_higher_height_remains_vector() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(2, 0, deterministic_hash(63));
    let proposed = candidate(1, 0, deterministic_hash(64));

    assert_eq!(scorer.choose_tip(current, proposed), Some(current.tip_hash));
}

#[test]
fn test_063_scorer_height_only_equal_height_no_tiebreak_returns_none_vector() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(2, 0, low_hash());
    let proposed = candidate(2, 0, high_hash());

    assert_eq!(scorer.choose_tip(current, proposed), None);
}

#[test]
fn test_064_scorer_height_only_equal_height_lower_candidate_wins_when_enabled_vector() {
    let scorer = ReorgBranchScorer::new(height_lower_tiebreak_cfg());
    let current = candidate(2, 0, high_hash());
    let proposed = candidate(2, 0, low_hash());

    assert_eq!(scorer.choose_tip(current, proposed), Some(low_hash()));
}

#[test]
fn test_065_scorer_height_only_equal_height_lower_current_remains_when_enabled_vector() {
    let scorer = ReorgBranchScorer::new(height_lower_tiebreak_cfg());
    let current = candidate(2, 0, low_hash());
    let proposed = candidate(2, 0, high_hash());

    assert_eq!(scorer.choose_tip(current, proposed), Some(low_hash()));
}

#[test]
fn test_066_scorer_height_only_equal_height_higher_candidate_wins_when_configured_vector() {
    let scorer = ReorgBranchScorer::new(height_higher_tiebreak_cfg());
    let current = candidate(2, 0, low_hash());
    let proposed = candidate(2, 0, high_hash());

    assert_eq!(scorer.choose_tip(current, proposed), Some(high_hash()));
}

#[test]
fn test_067_scorer_height_only_same_candidate_and_current_returns_none_vector() {
    let scorer = ReorgBranchScorer::new(height_lower_tiebreak_cfg());
    let current = candidate(2, 0, mid_hash());
    let proposed = current;

    assert_eq!(scorer.choose_tip(current, proposed), None);
}

#[test]
fn test_068_scorer_height_only_candidate_beats_current_true_vector() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(2, 0, deterministic_hash(68));
    let proposed = candidate(3, 0, deterministic_hash(69));

    assert!(scorer.candidate_beats_current(current, proposed));
}

#[test]
fn test_069_scorer_height_only_candidate_beats_current_false_when_current_wins_vector() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(3, 0, deterministic_hash(70));
    let proposed = candidate(2, 0, deterministic_hash(71));

    assert!(!scorer.candidate_beats_current(current, proposed));
}

#[test]
fn test_070_scorer_height_only_candidate_beats_current_false_when_none_vector() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(3, 0, low_hash());
    let proposed = candidate(3, 0, high_hash());

    assert!(!scorer.candidate_beats_current(current, proposed));
}

#[test]
fn test_071_scorer_cumulative_por_candidate_higher_por_wins_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(100, 10, deterministic_hash(71));
    let proposed = candidate(1, 11, deterministic_hash(72));

    assert_eq!(
        scorer.choose_tip(current, proposed),
        Some(proposed.tip_hash)
    );
}

#[test]
fn test_072_scorer_cumulative_por_current_higher_por_remains_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(1, 11, deterministic_hash(73));
    let proposed = candidate(100, 10, deterministic_hash(74));

    assert_eq!(scorer.choose_tip(current, proposed), Some(current.tip_hash));
}

#[test]
fn test_073_scorer_cumulative_por_equal_por_candidate_higher_height_wins_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(1, 11, deterministic_hash(75));
    let proposed = candidate(2, 11, deterministic_hash(76));

    assert_eq!(
        scorer.choose_tip(current, proposed),
        Some(proposed.tip_hash)
    );
}

#[test]
fn test_074_scorer_cumulative_por_equal_por_current_higher_height_remains_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(2, 11, deterministic_hash(77));
    let proposed = candidate(1, 11, deterministic_hash(78));

    assert_eq!(scorer.choose_tip(current, proposed), Some(current.tip_hash));
}

#[test]
fn test_075_scorer_cumulative_por_equal_score_height_no_tiebreak_none_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(2, 11, low_hash());
    let proposed = candidate(2, 11, high_hash());

    assert_eq!(scorer.choose_tip(current, proposed), None);
}

#[test]
fn test_076_scorer_cumulative_por_lower_hash_candidate_wins_when_enabled_vector() {
    let scorer = ReorgBranchScorer::new(por_lower_tiebreak_cfg());
    let current = candidate(2, 11, high_hash());
    let proposed = candidate(2, 11, low_hash());

    assert_eq!(scorer.choose_tip(current, proposed), Some(low_hash()));
}

#[test]
fn test_077_scorer_cumulative_por_higher_hash_candidate_wins_when_configured_vector() {
    let scorer = ReorgBranchScorer::new(por_higher_tiebreak_cfg());
    let current = candidate(2, 11, low_hash());
    let proposed = candidate(2, 11, high_hash());

    assert_eq!(scorer.choose_tip(current, proposed), Some(high_hash()));
}

#[test]
fn test_078_scorer_cumulative_por_candidate_beats_current_true_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(100, 100, deterministic_hash(78));
    let proposed = candidate(1, 101, deterministic_hash(79));

    assert!(scorer.candidate_beats_current(current, proposed));
}

#[test]
fn test_079_scorer_cumulative_por_candidate_beats_current_false_when_current_wins_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(1, 101, deterministic_hash(80));
    let proposed = candidate(100, 100, deterministic_hash(81));

    assert!(!scorer.candidate_beats_current(current, proposed));
}

#[test]
fn test_080_scorer_cumulative_por_candidate_beats_current_false_when_none_vector() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(2, 11, low_hash());
    let proposed = candidate(2, 11, high_hash());

    assert!(!scorer.candidate_beats_current(current, proposed));
}

#[test]
fn test_081_property_height_only_higher_height_wins_for_many_heights() {
    let cfg = height_cfg();

    for height in 0u64..64u64 {
        let taller = score_height(height.saturating_add(1), deterministic_hash(8_100 + height));
        let shorter = score_height(height, deterministic_hash(8_200 + height));
        assert!(taller.is_strictly_better_than(&shorter, &cfg));
    }
}

#[test]
fn test_082_property_height_only_equal_height_no_tiebreak_never_wins_for_many_hashes() {
    let cfg = height_cfg();

    for seed in 0u64..64u64 {
        let a = score_height(100, deterministic_hash(8_300 + seed));
        let b = score_height(100, deterministic_hash(8_400 + seed));
        assert!(!a.is_strictly_better_than(&b, &cfg));
        assert!(!b.is_strictly_better_than(&a, &cfg));
    }
}

#[test]
fn test_083_property_height_only_lower_hash_tiebreak_wins_for_many_equal_heights() {
    let cfg = height_lower_tiebreak_cfg();

    for height in 0u64..64u64 {
        let lower = score_height(height, low_hash());
        let higher = score_height(height, high_hash());
        assert!(lower.is_strictly_better_than(&higher, &cfg));
    }
}

#[test]
fn test_084_property_height_only_higher_hash_tiebreak_wins_for_many_equal_heights() {
    let cfg = height_higher_tiebreak_cfg();

    for height in 0u64..64u64 {
        let lower = score_height(height, low_hash());
        let higher = score_height(height, high_hash());
        assert!(higher.is_strictly_better_than(&lower, &cfg));
    }
}

#[test]
fn test_085_property_cumulative_por_higher_score_wins_for_many_scores() {
    let cfg = por_cfg();

    for por in 0u128..64u128 {
        let better = score_por(1, por.saturating_add(1), deterministic_hash(8_500));
        let worse = score_por(100, por, deterministic_hash(8_501));
        assert!(better.is_strictly_better_than(&worse, &cfg));
    }
}

#[test]
fn test_086_property_cumulative_por_equal_score_falls_back_to_height_for_many_heights() {
    let cfg = por_cfg();

    for height in 0u64..64u64 {
        let taller = score_por(height.saturating_add(1), 500, deterministic_hash(8_600));
        let shorter = score_por(height, 500, deterministic_hash(8_601));
        assert!(taller.is_strictly_better_than(&shorter, &cfg));
    }
}

#[test]
fn test_087_property_candidate_to_score_matches_branch_score_for_many_candidates() {
    for seed in 0u64..64u64 {
        let hash = deterministic_hash(8_700 + seed);
        let cand = candidate(seed, u128::from(seed).saturating_mul(10), hash);
        let score = cand.to_score();

        assert_eq!(score.height, cand.height);
        assert_eq!(score.cumulative_por, cand.cumulative_por);
        assert_eq!(score.tip_hash, cand.tip_hash);
    }
}

#[test]
fn test_088_property_choose_better_returns_none_for_same_score_and_hash_many_values() {
    let cfg = por_lower_tiebreak_cfg();

    for seed in 0u64..64u64 {
        let hash = deterministic_hash(8_800 + seed);
        let a = score_por(seed, u128::from(seed), hash);
        let b = score_por(seed, u128::from(seed), hash);

        assert_eq!(BranchScore::choose_better(&a, &b, &cfg), None);
    }
}

#[test]
fn test_089_fuzz_height_mode_deterministic_tip_choice_sequence() {
    let scorer = ReorgBranchScorer::default_height_only();
    let mut current = candidate(0, 0, deterministic_hash(8_900));

    for height in 1u64..64u64 {
        let proposed = candidate(height, 0, deterministic_hash(8_900 + height));
        assert!(scorer.candidate_beats_current(current, proposed));
        current = proposed;
    }

    assert_eq!(current.height, 63);
}

#[test]
fn test_090_fuzz_cumulative_por_mode_deterministic_tip_choice_sequence() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let mut current = candidate(0, 0, deterministic_hash(9_000));

    for por in 1u128..64u128 {
        let proposed = candidate(
            0,
            por,
            deterministic_hash(9_000 + u64::try_from(por).unwrap_or(0)),
        );
        assert!(scorer.candidate_beats_current(current, proposed));
        current = proposed;
    }

    assert_eq!(current.cumulative_por, 63);
}

#[test]
fn test_091_adversarial_height_only_shorter_high_por_cannot_replace_current() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(10, 1, low_hash());
    let adversary = candidate(9, u128::MAX, high_hash());

    assert_eq!(
        scorer.choose_tip(current, adversary),
        Some(current.tip_hash)
    );
    assert!(!scorer.candidate_beats_current(current, adversary));
}

#[test]
fn test_092_adversarial_cumulative_por_low_height_high_score_can_replace_current() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let current = candidate(10, 1, low_hash());
    let adversary = candidate(1, 2, high_hash());

    assert_eq!(
        scorer.choose_tip(current, adversary),
        Some(adversary.tip_hash)
    );
    assert!(scorer.candidate_beats_current(current, adversary));
}

#[test]
fn test_093_adversarial_equal_height_tiebreak_disabled_blocks_hash_manipulation() {
    let scorer = ReorgBranchScorer::default_height_only();
    let current = candidate(10, 0, high_hash());
    let adversary = candidate(10, 0, low_hash());

    assert_eq!(scorer.choose_tip(current, adversary), None);
    assert!(!scorer.candidate_beats_current(current, adversary));
}

#[test]
fn test_094_adversarial_lower_hash_tiebreak_allows_deterministic_replacement() {
    let scorer = ReorgBranchScorer::new(height_lower_tiebreak_cfg());
    let current = candidate(10, 0, high_hash());
    let adversary = candidate(10, 0, low_hash());

    assert_eq!(
        scorer.choose_tip(current, adversary),
        Some(adversary.tip_hash)
    );
}

#[test]
fn test_095_adversarial_higher_hash_tiebreak_allows_deterministic_replacement() {
    let scorer = ReorgBranchScorer::new(height_higher_tiebreak_cfg());
    let current = candidate(10, 0, low_hash());
    let adversary = candidate(10, 0, high_hash());

    assert_eq!(
        scorer.choose_tip(current, adversary),
        Some(adversary.tip_hash)
    );
}

#[test]
fn test_096_adversarial_same_hash_different_por_higher_por_wins() {
    let scorer = ReorgBranchScorer::new(por_lower_tiebreak_cfg());
    let hash = deterministic_hash(9_600);
    let current = candidate(10, 100, hash);
    let adversary = candidate(10, 101, hash);

    assert_eq!(scorer.choose_tip(current, adversary), Some(hash));
    assert!(scorer.candidate_beats_current(current, adversary));
}

#[test]
fn test_097_adversarial_same_hash_same_score_returns_none_even_with_tiebreak() {
    let scorer = ReorgBranchScorer::new(por_lower_tiebreak_cfg());
    let hash = deterministic_hash(9_700);
    let current = candidate(10, 100, hash);
    let adversary = candidate(10, 100, hash);

    assert_eq!(scorer.choose_tip(current, adversary), None);
}

#[test]
fn test_098_load_height_only_compare_256_candidates() {
    let scorer = ReorgBranchScorer::default_height_only();
    let mut current = candidate(0, 0, deterministic_hash(9_800));

    for height in 1u64..256u64 {
        let proposed = candidate(
            height,
            u128::from(height),
            deterministic_hash(9_800 + height),
        );
        let chosen = scorer.choose_tip(current, proposed);
        assert_eq!(chosen, Some(proposed.tip_hash));
        current = proposed;
    }

    assert_eq!(current.height, 255);
}

#[test]
fn test_099_load_cumulative_por_compare_256_candidates() {
    let scorer = ReorgBranchScorer::new(por_cfg());
    let mut current = candidate(0, 0, deterministic_hash(9_900));

    for step in 1u64..256u64 {
        let proposed = candidate(0, u128::from(step), deterministic_hash(9_900 + step));
        let chosen = scorer.choose_tip(current, proposed);
        assert_eq!(chosen, Some(proposed.tip_hash));
        current = proposed;
    }

    assert_eq!(current.cumulative_por, 255);
}

#[test]
fn test_100_end_to_end_mode_switch_changes_winner() {
    let current = candidate(10, 1, low_hash());
    let candidate_tip = candidate(9, 2, high_hash());

    let height_scorer = ReorgBranchScorer::default_height_only();
    let por_scorer = ReorgBranchScorer::new(por_cfg());

    assert_eq!(
        height_scorer.choose_tip(current, candidate_tip),
        Some(current.tip_hash)
    );
    assert_eq!(
        por_scorer.choose_tip(current, candidate_tip),
        Some(candidate_tip.tip_hash)
    );
}
