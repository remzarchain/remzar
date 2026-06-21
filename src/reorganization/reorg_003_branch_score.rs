// src/blockchain/reorg_003_branch_score.rs

use crate::network::p2p_006_reqresp::Hash;

/// Chain-wide block hash alias.
pub type BlockHash = Hash;

/// Configures how branch comparison is performed.
#[derive(Clone, Debug)]
pub struct BranchScoreConfig {
    /// Primary mode used to compare branches.
    pub mode: BranchScoreMode,

    /// Whether equal-height branches may be replaced using deterministic tie-break.
    pub allow_equal_height_tiebreak: bool,

    /// This gives deterministic behavior across nodes.
    pub prefer_lower_hash_on_tie: bool,
}

impl Default for BranchScoreConfig {
    fn default() -> Self {
        Self {
            mode: BranchScoreMode::HeightOnly,
            allow_equal_height_tiebreak: false,
            prefer_lower_hash_on_tie: true,
        }
    }
}

/// Score mode.
#[derive(Clone, Debug)]
pub enum BranchScoreMode {
    /// Longest chain wins.
    HeightOnly,

    /// Compare cumulative PoR score first; use height as fallback.
    CumulativePor,
}

/// A comparable branch score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchScore {
    pub height: u64,
    pub cumulative_por: u128,
    pub tip_hash: BlockHash,
}

impl BranchScore {
    /// Build a height-only score.
    pub fn from_height(height: u64, tip_hash: BlockHash) -> Self {
        Self {
            height,
            cumulative_por: 0,
            tip_hash,
        }
    }

    /// Build a score with explicit cumulative PoR value.
    pub fn from_cumulative_por(height: u64, cumulative_por: u128, tip_hash: BlockHash) -> Self {
        Self {
            height,
            cumulative_por,
            tip_hash,
        }
    }

    /// True if this score clearly beats the other score under the supplied config.
    pub fn is_strictly_better_than(&self, other: &Self, cfg: &BranchScoreConfig) -> bool {
        match cfg.mode {
            BranchScoreMode::HeightOnly => {
                if self.height > other.height {
                    return true;
                }
                if self.height < other.height {
                    return false;
                }

                if cfg.allow_equal_height_tiebreak {
                    return Self::tie_break(
                        self.tip_hash,
                        other.tip_hash,
                        cfg.prefer_lower_hash_on_tie,
                    );
                }

                false
            }
            BranchScoreMode::CumulativePor => {
                if self.cumulative_por > other.cumulative_por {
                    return true;
                }
                if self.cumulative_por < other.cumulative_por {
                    return false;
                }

                // Fallback to height when PoR totals are equal.
                if self.height > other.height {
                    return true;
                }
                if self.height < other.height {
                    return false;
                }

                if cfg.allow_equal_height_tiebreak {
                    return Self::tie_break(
                        self.tip_hash,
                        other.tip_hash,
                        cfg.prefer_lower_hash_on_tie,
                    );
                }

                false
            }
        }
    }

    /// Compare two scores and return the winning tip hash.
    pub fn choose_better(a: &Self, b: &Self, cfg: &BranchScoreConfig) -> Option<BlockHash> {
        if a.is_strictly_better_than(b, cfg) {
            return Some(a.tip_hash);
        }
        if b.is_strictly_better_than(a, cfg) {
            return Some(b.tip_hash);
        }
        None
    }

    /// Deterministic tie-break helper.
    fn tie_break(a: BlockHash, b: BlockHash, prefer_lower_hash: bool) -> bool {
        if a == b {
            return false;
        }

        if prefer_lower_hash { a < b } else { a > b }
    }
}

/// Minimal branch-candidate summary for scoring decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchCandidate {
    pub tip_hash: BlockHash,
    pub height: u64,
    pub cumulative_por: u128,
}

impl BranchCandidate {
    pub fn new(tip_hash: BlockHash, height: u64, cumulative_por: u128) -> Self {
        Self {
            tip_hash,
            height,
            cumulative_por,
        }
    }

    pub fn to_score(&self) -> BranchScore {
        BranchScore {
            height: self.height,
            cumulative_por: self.cumulative_por,
            tip_hash: self.tip_hash,
        }
    }
}

/// High-level branch scorer.
#[derive(Clone, Debug)]
pub struct ReorgBranchScorer {
    cfg: BranchScoreConfig,
}

impl ReorgBranchScorer {
    pub fn new(cfg: BranchScoreConfig) -> Self {
        Self { cfg }
    }

    pub fn default_height_only() -> Self {
        Self {
            cfg: BranchScoreConfig::default(),
        }
    }

    pub fn config(&self) -> &BranchScoreConfig {
        &self.cfg
    }

    /// Compare current canonical tip vs candidate tip.
    pub fn choose_tip(
        &self,
        current: BranchCandidate,
        candidate: BranchCandidate,
    ) -> Option<BlockHash> {
        let current_score = current.to_score();
        let candidate_score = candidate.to_score();

        if candidate_score.is_strictly_better_than(&current_score, &self.cfg) {
            return Some(candidate.tip_hash);
        }

        if current_score.is_strictly_better_than(&candidate_score, &self.cfg) {
            return Some(current.tip_hash);
        }

        None
    }

    /// Return true if candidate is better than current.
    pub fn candidate_beats_current(
        &self,
        current: BranchCandidate,
        candidate: BranchCandidate,
    ) -> bool {
        self.choose_tip(current, candidate) == Some(candidate.tip_hash)
    }
}
