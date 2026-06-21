// Proof of Registry

use blake3::Hasher;
use std::time::{Duration, Instant};

use crate::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;

/* ============================ safety helpers ============================ */

#[inline]
fn validation_err(msg: String) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: msg,
        tx_id: None,
    }
}

/// Deterministic canonicalizer.
/// - If a wallet is invalid, we return a fixed marker string.
/// - This avoids “best effort” divergence and ensures derived headers are deterministic.
/// - Normal protocol paths should never hit this because callers already validate wallets.
#[inline]
fn canon_wallet_deterministic(addr: &str) -> String {
    canon_wallet_id_checked(addr).unwrap_or_else(|_| "por:<invalid-wallet>".to_string())
}

/// Hard safety caps to guarantee bounded work even if a peer sends a malicious header/solution.
const MAX_FIB_N: u32 = 44;
const MIN_FACT_DIFFICULTY: u32 = 1;
const MAX_FACT_DIFFICULTY: u32 = 4;

/// Bound worst-case trial division iterations (each loop checks one odd p).
const MAX_FACT_TRIAL_STEPS: u64 = 2_000_000;

/// Bound factor candidate value: if n grows too large, cap the work by failing gracefully.
const MAX_FACT_N: u64 = 1u64 << 48;

#[inline]
fn clamp_fib_n(n: u32) -> u32 {
    n.min(MAX_FIB_N)
}

#[inline]
fn clamp_fact_param(p: u32) -> u32 {
    p.clamp(MIN_FACT_DIFFICULTY, MAX_FACT_DIFFICULTY)
}

/// Validate/normalize a header so solving/verifying cannot be abused for unbounded work.
fn normalize_header(header: &PorPuzzleHeader) -> PorPuzzleHeader {
    let validator = canon_wallet_deterministic(&header.validator);

    let mut h = header.clone();
    h.validator = validator;

    match h.kind {
        PorPuzzleKind::FibonacciDelayDev => {
            h.param = clamp_fib_n(h.param);
            h
        }
        PorPuzzleKind::FactorizationDelayDev => {
            h.param = clamp_fact_param(h.param);
            h
        }
    }
}

/* ============================ types ============================ */

/// Header that uniquely defines a puzzle instance for
/// (height, validator, prev_hash, puzzle_kind).
#[derive(Clone, Debug)]
pub struct PorPuzzleHeader {
    pub height: u64,
    pub validator: String,
    pub prev_block_hash: [u8; 64],
    pub kind: PorPuzzleKind,
    pub param: u32,
}

/// Concrete solution to a puzzle.
#[derive(Clone, Debug)]
pub struct PorPuzzleSolution {
    pub header: PorPuzzleHeader,
    pub output: u128,
    pub solved_in_ms: u64,
}

/// Stateless puzzle engine (apart from configuration).
#[derive(Clone, Debug)]
pub struct PorPuzzleEngine {
    cfg: PorConsensusConfig,
}

impl PorPuzzleEngine {
    /// Construct a new puzzle engine with the given configuration.
    pub fn new(cfg: PorConsensusConfig) -> Self {
        Self { cfg }
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &PorConsensusConfig {
        &self.cfg
    }

    /// Construct from the mandatory global config.
    pub fn from_globals() -> Self {
        Self {
            cfg: PorConsensusConfig::from_globals(),
        }
    }

    /// Derive the deterministic puzzle header for (height, validator, prev_hash).
    pub fn derive_puzzle(
        &self,
        height: u64,
        validator_wallet: &str,
        prev_block_hash: [u8; 64],
    ) -> PorPuzzleHeader {
        let validator = canon_wallet_deterministic(validator_wallet);
        let kind = self.cfg.puzzle_kind;

        let mut hasher = Hasher::new();
        hasher.update(&prev_block_hash);
        hasher.update(&height.to_be_bytes());
        hasher.update(validator.as_bytes());
        let seed = hasher.finalize();
        let sb = seed.as_bytes();

        let target_secs = self.cfg.target_block_time.as_secs().max(1);

        let param = match kind {
            PorPuzzleKind::FibonacciDelayDev => {
                let base_n: u32 = if target_secs <= 10 {
                    26
                } else if target_secs <= 20 {
                    30
                } else if target_secs <= 40 {
                    32
                } else if target_secs <= 60 {
                    34
                } else {
                    36
                };

                let jitter: u32 = (sb[0] as u32) & 0x07;
                base_n.saturating_add(jitter).min(MAX_FIB_N)
            }

            PorPuzzleKind::FactorizationDelayDev => ((sb[0] as u32) & 0x03).saturating_add(1),
        };

        PorPuzzleHeader {
            height,
            validator,
            prev_block_hash,
            kind,
            param,
        }
    }

    /// Solve the puzzle locally for this node (graceful Result).
    pub fn solve_locally_checked(
        &self,
        header: &PorPuzzleHeader,
    ) -> Result<PorPuzzleSolution, ErrorDetection> {
        let start = Instant::now();

        let header = normalize_header(header);

        let output = match header.kind {
            PorPuzzleKind::FibonacciDelayDev => fib_iter_u128(header.param),
            PorPuzzleKind::FactorizationDelayDev => solve_factorization_dev(&header),
        };

        let min_duration: Duration = self.cfg.target_block_time;
        let elapsed = start.elapsed();
        if elapsed < min_duration {
            let remaining = min_duration.saturating_sub(elapsed);
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }

        let total = start.elapsed();
        let ms = total
            .as_secs()
            .saturating_mul(1000)
            .saturating_add(u64::from(total.subsec_millis()));

        Ok(PorPuzzleSolution {
            header,
            output,
            solved_in_ms: ms,
        })
    }

    /// Verify a puzzle solution for a given expected (height, validator, prev_hash).
    pub fn verify_checked(
        &self,
        solution: &PorPuzzleSolution,
        expected_height: u64,
        expected_validator: &str,
        expected_prev_block_hash: [u8; 64],
    ) -> Result<(), ErrorDetection> {
        let expected_header = self.derive_puzzle(
            expected_height,
            expected_validator,
            expected_prev_block_hash,
        );

        let normalized_solution_header = normalize_header(&solution.header);

        if normalized_solution_header.height != expected_header.height
            || normalized_solution_header.validator != expected_header.validator
            || normalized_solution_header.prev_block_hash != expected_header.prev_block_hash
            || normalized_solution_header.kind != expected_header.kind
            || normalized_solution_header.param != expected_header.param
        {
            return Err(validation_err(
                "Puzzle header mismatch (height/validator/hash/kind/param)".to_string(),
            ));
        }

        match normalized_solution_header.kind {
            PorPuzzleKind::FibonacciDelayDev => {
                let expected_output = fib_iter_u128(normalized_solution_header.param);
                if expected_output == solution.output {
                    Ok(())
                } else {
                    Err(validation_err(
                        "Fibonacci puzzle output mismatch".to_string(),
                    ))
                }
            }

            PorPuzzleKind::FactorizationDelayDev => {
                if verify_factorization_dev(&normalized_solution_header, solution.output) {
                    Ok(())
                } else {
                    Err(validation_err(
                        "Factorization puzzle output mismatch".to_string(),
                    ))
                }
            }
        }
    }

    /// Boolean wrapper.
    pub fn verify(
        &self,
        solution: &PorPuzzleSolution,
        expected_height: u64,
        expected_validator: &str,
        expected_prev_block_hash: [u8; 64],
    ) -> bool {
        self.verify_checked(
            solution,
            expected_height,
            expected_validator,
            expected_prev_block_hash,
        )
        .is_ok()
    }
}

/* ───────────────────────── Fibonacci puzzle ───────────────────────── */

fn fib_iter_u128(n: u32) -> u128 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }

    let mut a: u128 = 0;
    let mut b: u128 = 1;

    for _ in 0..n {
        let next = a.saturating_add(b);
        a = b;
        b = next;
    }

    a
}

/* ────────────────────── Factorization puzzle ─────────────────────── */

fn derive_n_from_header(header: &PorPuzzleHeader) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(&header.prev_block_hash);
    hasher.update(&header.height.to_be_bytes());
    hasher.update(header.validator.as_bytes());
    let seed = hasher.finalize();
    let sb = seed.as_bytes();

    let mut n: u64 = u64::from_be_bytes([sb[0], sb[1], sb[2], sb[3], sb[4], sb[5], sb[6], sb[7]]);
    n |= 1;
    n = n.max(3);

    let shift = header.param & 0x03;
    n >>= shift;

    n
}

fn solve_factorization_dev_checked(header: &PorPuzzleHeader) -> Result<u128, ErrorDetection> {
    let n = derive_n_from_header(header);

    if n > MAX_FACT_N {
        return Err(validation_err(format!(
            "Factorization puzzle n too large for safety (n={}, max={})",
            n, MAX_FACT_N
        )));
    }

    let mut candidate_p: u64 = 3;
    let mut found_p: Option<u64> = None;
    let mut steps: u64 = 0;

    while candidate_p.saturating_mul(candidate_p) <= n {
        if steps >= MAX_FACT_TRIAL_STEPS {
            return Err(validation_err(format!(
                "Factorization puzzle exceeded trial division step cap (cap={})",
                MAX_FACT_TRIAL_STEPS
            )));
        }

        if n.is_multiple_of(candidate_p) {
            found_p = Some(candidate_p);
            break;
        }
        candidate_p = candidate_p.saturating_add(2);
        steps = steps.saturating_add(1);
    }

    let p = found_p.unwrap_or(n);
    Ok(((n as u128) << 64) | (p as u128))
}

fn solve_factorization_dev(header: &PorPuzzleHeader) -> u128 {
    match solve_factorization_dev_checked(header) {
        Ok(v) => v,
        Err(_e) => {
            let n = derive_n_from_header(header);
            (n as u128) << 64
        }
    }
}

fn verify_factorization_dev_checked(
    header: &PorPuzzleHeader,
    packed: u128,
) -> Result<bool, ErrorDetection> {
    let n_expected = derive_n_from_header(header);

    if n_expected > MAX_FACT_N {
        return Err(validation_err(format!(
            "Factorization verify refused: n too large for safety (n={}, max={})",
            n_expected, MAX_FACT_N
        )));
    }

    let n_part = (packed >> 64) as u64;
    let p_part = (packed & 0xFFFF_FFFF_FFFF_FFFFu128) as u64;

    if n_part != n_expected {
        return Ok(false);
    }
    if p_part < 3 {
        return Ok(false);
    }
    if !n_expected.is_multiple_of(p_part) {
        return Ok(false);
    }

    Ok(true)
}

fn verify_factorization_dev(header: &PorPuzzleHeader, packed: u128) -> bool {
    verify_factorization_dev_checked(header, packed).unwrap_or_default()
}
