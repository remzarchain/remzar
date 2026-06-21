// Proof of Registry

use std::time::Duration;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

/// Mandatory puzzle type for POR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PorPuzzleKind {
    /// Naive Fibonacci delay puzzle.
    ///
    /// Each leader must compute F(n) for some n derived from
    /// (prev_hash, height, validator). This is a tunable CPU delay,
    /// not cryptoeconomic security.
    FibonacciDelayDev,

    /// Tiny factorization delay puzzle.
    ///
    /// Each leader must factor a small composite derived from
    /// (prev_hash, height, validator). Also not cryptoeconomic
    /// security, just an adjustable CPU task.
    FactorizationDelayDev,
}

#[inline]
fn validation_err(msg: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: msg.into(),
        tx_id: None,
    }
}

/// Static configuration for the mandatory POR puzzle layer.
#[derive(Clone, Debug)]
pub struct PorConsensusConfig {
    /// Target **puzzle delay** for this node.
    ///
    /// This is interpreted as the per-node minimum wall-clock duration of
    /// `PorPuzzleEngine::solve_locally_checked` and is always derived from:
    ///
    ///   1 <= PUZZLE_CREATION_INTERVAL_SECS
    ///     <= BLOCK_CREATION_INTERVAL_SECS
    pub target_block_time: Duration,

    /// Which puzzle family this network uses.
    ///
    /// IMPORTANT:
    /// - This is consensus-critical.
    /// - It must be identical across all nodes.
    pub puzzle_kind: PorPuzzleKind,

    /// Soft upper bound on how long the local node is willing to spend
    /// solving its own puzzle, in milliseconds.
    ///
    /// This is for logging / monitoring only; it is not the consensus rule.
    /// We keep this equal to the configured puzzle delay in ms so logs
    /// line up cleanly (`solved_in_ms` ~= `soft_cap_ms`).
    pub max_local_puzzle_ms: u64,
}

impl PorConsensusConfig {
    /// Cap so future refactors / bad constants cannot explode logs/telemetry.
    const MAX_SOFT_PUZZLE_MS: u64 = 60 * 60 * 1_000; // 1 hour

    /// The mandatory network puzzle family.
    const MANDATORY_PUZZLE_KIND: PorPuzzleKind = PorPuzzleKind::FibonacciDelayDev;

    /// Compute a robust, network-wide puzzle duration in seconds.
    ///
    /// Guarantees:
    /// - Never less than 1 second.
    /// - Never greater than BLOCK_CREATION_INTERVAL_SECS.
    fn effective_puzzle_secs() -> u64 {
        let slot_secs = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
        let raw_puzzle_secs = GlobalConfiguration::PUZZLE_CREATION_INTERVAL_SECS.max(1);

        // Liveness guard: never let puzzle delay exceed the block slot.
        raw_puzzle_secs.min(slot_secs)
    }

    /// Validate invariants that matter for liveness and consistency.
    ///
    /// No panics; return a graceful error so callers can log once at the boundary.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        if self.target_block_time.as_secs() == 0 {
            return Err(validation_err(
                "PorConsensusConfig invalid: target_block_time is 0s",
            ));
        }

        if self.max_local_puzzle_ms == 0 {
            return Err(validation_err(
                "PorConsensusConfig invalid: max_local_puzzle_ms is 0 for mandatory puzzle mode",
            ));
        }

        let slot_secs = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
        if self.target_block_time.as_secs() > slot_secs {
            return Err(validation_err(format!(
                "PorConsensusConfig invalid: target_block_time={}s exceeds block slot={}s",
                self.target_block_time.as_secs(),
                slot_secs
            )));
        }

        if self.puzzle_kind != Self::MANDATORY_PUZZLE_KIND {
            return Err(validation_err(format!(
                "PorConsensusConfig invalid: puzzle_kind {:?} does not match mandatory network kind {:?}",
                self.puzzle_kind,
                Self::MANDATORY_PUZZLE_KIND
            )));
        }

        Ok(())
    }

    /// Build config from global constants using the mandatory puzzle family.
    ///
    /// Defaults to:
    /// - target_block_time   = clamped PUZZLE_CREATION_INTERVAL_SECS
    /// - puzzle_kind         = mandatory production puzzle family
    /// - max_local_puzzle_ms = target_block_time in milliseconds (bounded)
    pub fn from_globals() -> Self {
        let puzzle_secs = Self::effective_puzzle_secs();

        let soft_ms = puzzle_secs
            .saturating_mul(1_000)
            .clamp(1_000, Self::MAX_SOFT_PUZZLE_MS);

        Self {
            target_block_time: Duration::from_secs(puzzle_secs),
            puzzle_kind: Self::MANDATORY_PUZZLE_KIND,
            max_local_puzzle_ms: soft_ms,
        }
    }
}

impl Default for PorConsensusConfig {
    fn default() -> Self {
        Self::from_globals()
    }
}
