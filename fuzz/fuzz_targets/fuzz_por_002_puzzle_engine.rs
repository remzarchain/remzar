#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Duration;

mod utility {
    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, tx_id } => {
                        write!(f, "ValidationError(message={message}, tx_id={tx_id:?})")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const PUZZLE_CREATION_INTERVAL_SECS: u64 = 1;
        }
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_BODY_LEN: usize = 128;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        /*
            Minimal canonical wallet checker for this fuzz target.

            Rule:
            - trim whitespace
            - accept r or R
            - require 129 chars total
            - require 128 hex chars after prefix
            - return canonical r + lowercase hex
        */
        #[inline]
        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            let Some(body) = b.get(1..) else {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            };

            if body.len() != REMZAR_WALLET_BODY_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            if !body.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Pull in the real production config module.
   Do NOT use include!().
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/consensus/por_001_consensus_config.rs"]
pub mod por_001_consensus_config;

/* ─────────────────────────────────────────────────────────────
   por_002_puzzle_engine.rs expects:

       crate::consensus::por_001_consensus_config

   So re-export the real module under crate::consensus.
   ───────────────────────────────────────────────────────────── */

pub mod consensus {
    pub use crate::por_001_consensus_config;
}

/* ─────────────────────────────────────────────────────────────
   Pull in the real production puzzle engine.
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/consensus/por_002_puzzle_engine.rs"]
pub mod por_002_puzzle_engine;

/* ─────────────────────────────────────────────────────────────
   Imports from local modules, not remzar::...
   ───────────────────────────────────────────────────────────── */

use crate::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use crate::por_002_puzzle_engine::{
    PorPuzzleEngine, PorPuzzleHeader, PorPuzzleSolution,
};
use crate::utility::helper::canon_wallet_id_checked;

/* ─────────────────────────────────────────────────────────────
   Main fuzz entry
   ───────────────────────────────────────────────────────────── */

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] % 8;
    let body = &data[1..];

    match mode {
        0 => fuzz_config_validation(body),
        1 => fuzz_derive_determinism(body),
        2 => fuzz_invalid_wallet_determinism(body),
        3 => fuzz_fibonacci_solve_verify(body),
        4 => fuzz_mismatch_rejection(body),
        5 => fuzz_attacker_header_normalization(body),
        6 => fuzz_factorization_verify_path(body),
        _ => fuzz_mixed_sequence(body),
    }
});

/* ─────────────────────────────────────────────────────────────
   Config helpers
   ───────────────────────────────────────────────────────────── */

fn zero_delay_cfg(kind: PorPuzzleKind) -> PorConsensusConfig {
    /*
        This is intentional for fuzzing.

        solve_locally_checked() enforces cfg.target_block_time by sleeping.
        Production uses 1 second from globals. Fuzzing must not sleep per input.
    */
    PorConsensusConfig {
        target_block_time: Duration::from_millis(0),
        puzzle_kind: kind,
        max_local_puzzle_ms: 1,
    }
}

fn derive_only_cfg(kind: PorPuzzleKind, secs: u64) -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_secs(secs),
        puzzle_kind: kind,
        max_local_puzzle_ms: secs.saturating_mul(1_000).max(1),
    }
}

fn engine_zero_delay(kind: PorPuzzleKind) -> PorPuzzleEngine {
    PorPuzzleEngine::new(zero_delay_cfg(kind))
}

fn engine_derive_only(kind: PorPuzzleKind, secs: u64) -> PorPuzzleEngine {
    PorPuzzleEngine::new(derive_only_cfg(kind, secs))
}

/* ─────────────────────────────────────────────────────────────
   Individual fuzz exercises
   ───────────────────────────────────────────────────────────── */

fn fuzz_config_validation(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let kind = choose_kind(&mut r);

    let secs = match r.next_u8() % 8 {
        0 => 0,
        1 => 1,
        2 => 30,
        3 => 31,
        4 => u64::MAX,
        5 => r.next_u64() % 120,
        6 => 3600,
        _ => r.next_u64(),
    };

    let max_ms = match r.next_u8() % 6 {
        0 => 0,
        1 => 1,
        2 => 1_000,
        3 => secs.saturating_mul(1_000),
        4 => u64::MAX,
        _ => r.next_u64(),
    };

    let cfg = PorConsensusConfig {
        target_block_time: Duration::from_secs(secs),
        puzzle_kind: kind,
        max_local_puzzle_ms: max_ms,
    };

    let _ = cfg.validate();

    let global_cfg = PorConsensusConfig::from_globals();
    assert!(global_cfg.validate().is_ok());

    let default_cfg = PorConsensusConfig::default();
    assert!(default_cfg.validate().is_ok());
}

fn fuzz_derive_determinism(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let kind = choose_kind(&mut r);
    let secs = match r.next_u8() % 6 {
        0 => 0,
        1 => 1,
        2 => 10,
        3 => 30,
        4 => 60,
        _ => 120,
    };

    let engine = engine_derive_only(kind, secs);

    let height = r.next_u64();
    let wallet = make_wallet_or_invalid(&mut r);
    let prev = make_hash64(&mut r);

    let h1 = engine.derive_puzzle(height, &wallet, prev);
    let h2 = engine.derive_puzzle(height, &wallet, prev);

    assert_eq!(h1.height, h2.height);
    assert_eq!(h1.validator, h2.validator);
    assert_eq!(h1.prev_block_hash, h2.prev_block_hash);
    assert_eq!(h1.kind, h2.kind);
    assert_eq!(h1.param, h2.param);

    assert_eq!(h1.height, height);
    assert_eq!(h1.prev_block_hash, prev);
    assert_eq!(h1.kind, kind);

    match h1.kind {
        PorPuzzleKind::FibonacciDelayDev => {
            assert!(h1.param <= 44);
        }
        PorPuzzleKind::FactorizationDelayDev => {
            assert!((1..=4).contains(&h1.param));
        }
    }
}

fn fuzz_invalid_wallet_determinism(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let kind = choose_kind(&mut r);
    let engine = engine_derive_only(kind, 1);

    let height = r.next_u64();
    let prev = make_hash64(&mut r);
    let wallet = make_fuzzy_string(&mut r, 256);

    let h1 = engine.derive_puzzle(height, &wallet, prev);
    let h2 = engine.derive_puzzle(height, &wallet, prev);

    assert_eq!(h1.validator, h2.validator);
    assert_eq!(h1.param, h2.param);

    if canon_wallet_id_checked(&wallet).is_err() {
        assert_eq!(h1.validator, "por:<invalid-wallet>");
    }
}

fn fuzz_fibonacci_solve_verify(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);

    let height = r.next_u64();
    let wallet = make_valid_wallet(&mut r);
    let prev = make_hash64(&mut r);

    let header = engine.derive_puzzle(height, &wallet, prev);

    assert_eq!(header.kind, PorPuzzleKind::FibonacciDelayDev);
    assert!(header.param <= 44);

    let solution = match engine.solve_locally_checked(&header) {
        Ok(s) => s,
        Err(_) => return,
    };

    assert_eq!(solution.header.height, header.height);
    assert_eq!(solution.header.validator, header.validator);
    assert_eq!(solution.header.prev_block_hash, header.prev_block_hash);
    assert_eq!(solution.header.kind, header.kind);
    assert_eq!(solution.header.param, header.param);

    assert_eq!(solution.output, fib_expected(header.param));

    assert!(engine.verify_checked(&solution, height, &wallet, prev).is_ok());
    assert!(engine.verify(&solution, height, &wallet, prev));
}

fn fuzz_mismatch_rejection(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);

    let height = r.next_u64();
    let wallet = make_valid_wallet(&mut r);
    let prev = make_hash64(&mut r);

    let header = engine.derive_puzzle(height, &wallet, prev);

    let solution = match engine.solve_locally_checked(&header) {
        Ok(s) => s,
        Err(_) => return,
    };

    assert!(engine.verify_checked(&solution, height, &wallet, prev).is_ok());

    /*
        Wrong height must reject.
    */
    assert!(
        engine
            .verify_checked(&solution, height.wrapping_add(1), &wallet, prev)
            .is_err()
    );

    /*
        Wrong previous hash must reject.
    */
    let mut wrong_prev = prev;
    wrong_prev[0] ^= 0x01;

    assert!(
        engine
            .verify_checked(&solution, height, &wallet, wrong_prev)
            .is_err()
    );

    /*
        Wrong validator must reject.
    */
    let wrong_wallet = make_different_valid_wallet(&wallet);

    assert!(
        engine
            .verify_checked(&solution, height, &wrong_wallet, prev)
            .is_err()
    );

    /*
        Wrong output must reject.
    */
    let mut bad_solution = solution.clone();
    bad_solution.output ^= 1;

    assert!(
        engine
            .verify_checked(&bad_solution, height, &wallet, prev)
            .is_err()
    );
}

fn fuzz_attacker_header_normalization(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);

    let attacker_header = PorPuzzleHeader {
        height: r.next_u64(),
        validator: make_fuzzy_string(&mut r, 384),
        prev_block_hash: make_hash64(&mut r),
        kind: PorPuzzleKind::FibonacciDelayDev,
        param: match r.next_u8() % 5 {
            0 => 0,
            1 => 1,
            2 => 44,
            3 => 45,
            _ => u32::MAX,
        },
    };

    /*
        This should never panic, even with invalid wallet strings
        and huge Fibonacci params. Production normalize_header()
        should clamp Fibonacci params to <= 44.
    */
    let solution = match engine.solve_locally_checked(&attacker_header) {
        Ok(s) => s,
        Err(_) => return,
    };

    assert_eq!(solution.header.kind, PorPuzzleKind::FibonacciDelayDev);
    assert!(solution.header.param <= 44);
    assert_eq!(solution.output, fib_expected(solution.header.param));

    if canon_wallet_id_checked(&attacker_header.validator).is_err() {
        assert_eq!(solution.header.validator, "por:<invalid-wallet>");
    }
}

fn fuzz_factorization_verify_path(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_derive_only(PorPuzzleKind::FactorizationDelayDev, 1);

    let height = r.next_u64();
    let wallet = make_wallet_or_invalid(&mut r);
    let prev = make_hash64(&mut r);

    let header = engine.derive_puzzle(height, &wallet, prev);

    assert_eq!(header.kind, PorPuzzleKind::FactorizationDelayDev);
    assert!((1..=4).contains(&header.param));

    let solution = PorPuzzleSolution {
        header: header.clone(),
        output: r.next_u128(),
        solved_in_ms: r.next_u64(),
    };

    let _ = engine.verify_checked(&solution, height, &wallet, prev);
    let _ = engine.verify(&solution, height, &wallet, prev);

    /*
        Header mismatch should still reject cleanly.
    */
    let mut wrong_prev = prev;
    wrong_prev[0] ^= 0xA5;

    let _ = engine.verify_checked(&solution, height, &wallet, wrong_prev);
}

fn fuzz_mixed_sequence(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let steps = 1 + r.next_usize(16);

    for _ in 0..steps {
        match r.next_u8() % 7 {
            0 => fuzz_config_validation(r.remaining_window(256)),
            1 => fuzz_derive_determinism(r.remaining_window(256)),
            2 => fuzz_invalid_wallet_determinism(r.remaining_window(256)),
            3 => fuzz_fibonacci_solve_verify(r.remaining_window(256)),
            4 => fuzz_mismatch_rejection(r.remaining_window(256)),
            5 => fuzz_attacker_header_normalization(r.remaining_window(256)),
            _ => fuzz_factorization_verify_path(r.remaining_window(256)),
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Independent Fibonacci oracle
   ───────────────────────────────────────────────────────────── */

fn fib_expected(n: u32) -> u128 {
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

/* ─────────────────────────────────────────────────────────────
   Input construction helpers
   ───────────────────────────────────────────────────────────── */

fn choose_kind(r: &mut FuzzBytes<'_>) -> PorPuzzleKind {
    match r.next_u8() & 1 {
        0 => PorPuzzleKind::FibonacciDelayDev,
        _ => PorPuzzleKind::FactorizationDelayDev,
    }
}

fn make_hash64(r: &mut FuzzBytes<'_>) -> [u8; 64] {
    let mut out = [0u8; 64];

    for b in &mut out {
        *b = r.next_u8();
    }

    out
}

fn make_valid_wallet(r: &mut FuzzBytes<'_>) -> String {
    let mut s = String::with_capacity(129);
    s.push('r');

    for _ in 0..128 {
        let n = r.next_u8() % 16;
        let c = match n {
            0..=9 => char::from(b'0' + n),
            _ => char::from(b'a' + (n - 10)),
        };
        s.push(c);
    }

    s
}

fn make_different_valid_wallet(existing: &str) -> String {
    let mut s = existing.to_string();

    if s.len() != 129 {
        return "r22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222".to_string();
    }

    /*
        Flip the last hex char while keeping the address canonical.
    */
    let last = s.pop().unwrap_or('0');

    let replacement = match last {
        '0' => '1',
        '1' => '2',
        '2' => '3',
        '3' => '4',
        '4' => '5',
        '5' => '6',
        '6' => '7',
        '7' => '8',
        '8' => '9',
        '9' => 'a',
        'a' => 'b',
        'b' => 'c',
        'c' => 'd',
        'd' => 'e',
        'e' => 'f',
        _ => '0',
    };

    s.push(replacement);
    s
}

fn make_wallet_or_invalid(r: &mut FuzzBytes<'_>) -> String {
    match r.next_u8() % 6 {
        0 => make_valid_wallet(r),
        1 => {
            let mut s = make_valid_wallet(r);
            s.replace_range(0..1, "R");
            s
        }
        2 => String::new(),
        3 => make_fuzzy_string(r, 256),
        4 => {
            let mut s = make_valid_wallet(r);
            s.push('x');
            s
        }
        _ => {
            let mut s = make_valid_wallet(r);
            s.replace_range(1..2, "z");
            s
        }
    }
}

fn make_fuzzy_string(r: &mut FuzzBytes<'_>, max_chars: usize) -> String {
    let len = r.next_usize(max_chars.saturating_add(1));

    let mut s = String::new();

    for _ in 0..len {
        let b = r.next_u8();

        match b % 10 {
            0 => s.push(char::from(b'a' + (b % 26))),
            1 => s.push(char::from(b'A' + (b % 26))),
            2 => s.push(char::from(b'0' + (b % 10))),
            3 => s.push('r'),
            4 => s.push('R'),
            5 => s.push('_'),
            6 => s.push('-'),
            7 => s.push('é'),
            8 => s.push('雪'),
            _ => s.push('🚀'),
        }
    }

    s
}

/* ─────────────────────────────────────────────────────────────
   Deterministic byte reader
   ───────────────────────────────────────────────────────────── */

struct FuzzBytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FuzzBytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }

        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];

        for b in &mut out {
            *b = self.next_u8();
        }

        u64::from_le_bytes(out)
    }

    fn next_u128(&mut self) -> u128 {
        let mut out = [0u8; 16];

        for b in &mut out {
            *b = self.next_u8();
        }

        u128::from_le_bytes(out)
    }

    fn next_usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }

        (self.next_u64() as usize) % max_exclusive
    }

    fn remaining_window(&mut self, max_len: usize) -> &'a [u8] {
        if self.data.is_empty() || max_len == 0 {
            return &[];
        }

        let start = self.pos % self.data.len();
        let available = self.data.len().saturating_sub(start);
        let len = available.min(max_len);

        self.pos = self.pos.wrapping_add(len.max(1));

        &self.data[start..start + len]
    }
}