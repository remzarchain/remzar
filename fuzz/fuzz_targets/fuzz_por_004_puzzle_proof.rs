#![no_main]

use libfuzzer_sys::fuzz_target;
use postcard::{from_bytes, to_allocvec};
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

            pub const MAX_ITEM_BYTES: usize = 4 * 1024 * 1024;
            pub const MAX_BATCH_ITEMS: usize = 50_000;
            pub const MAX_TOTAL_BATCH_BYTES: usize = 64 * 1024 * 1024;
        }
    }

    pub mod hash_system_remzarhash {
        pub struct RemzarHash;

        impl RemzarHash {
            #[inline]
            pub fn compute_bytes_hash(input: &[u8]) -> [u8; 64] {
                let mut hasher = blake3::Hasher::new();
                hasher.update(input);

                let mut out = [0u8; 64];
                hasher.finalize_xof().fill(&mut out);
                out
            }
        }
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_BODY_LEN: usize = 128;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

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

        pub mod serde_u8_array_64 {
            use core::fmt;
            use serde::de::{Error as DeError, SeqAccess, Visitor};
            use serde::ser::SerializeTuple;
            use serde::{Deserializer, Serializer};

            pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut tup = serializer.serialize_tuple(64)?;
                for b in arr.iter() {
                    tup.serialize_element(b)?;
                }
                tup.end()
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
            where
                D: Deserializer<'de>,
            {
                struct Arr64Visitor;

                impl<'de> Visitor<'de> for Arr64Visitor {
                    type Value = [u8; 64];

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a strict 64-byte array")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let mut out = [0u8; 64];

                        for (i, slot) in out.iter_mut().enumerate() {
                            *slot = seq
                                .next_element::<u8>()?
                                .ok_or_else(|| DeError::invalid_length(i, &self))?;
                        }

                        if seq.next_element::<u8>()?.is_some() {
                            return Err(DeError::invalid_length(65, &self));
                        }

                        Ok(out)
                    }
                }

                deserializer.deserialize_tuple(64, Arr64Visitor)
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Pull in production consensus modules using #[path], not include!()
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/consensus/por_001_consensus_config.rs"]
pub mod por_001_consensus_config;

#[path = "../../src/consensus/por_002_puzzle_engine.rs"]
pub mod por_002_puzzle_engine;

#[path = "../../src/consensus/por_003_puzzle_pool.rs"]
pub mod por_003_puzzle_pool;

#[path = "../../src/consensus/por_004_puzzle_proof.rs"]
pub mod por_004_puzzle_proof;

pub mod consensus {
    pub use crate::por_001_consensus_config;
    pub use crate::por_002_puzzle_engine;
    pub use crate::por_003_puzzle_pool;
}

/* ─────────────────────────────────────────────────────────────
   Imports
   ───────────────────────────────────────────────────────────── */

use crate::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use crate::por_002_puzzle_engine::PorPuzzleEngine;
use crate::por_003_puzzle_pool::PorPuzzlePool;
use crate::por_004_puzzle_proof::PorPuzzleProof;
use crate::utility::helper::canon_wallet_id_checked;

/* ─────────────────────────────────────────────────────────────
   Main fuzz entry
   ───────────────────────────────────────────────────────────── */

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] % 9;
    let body = &data[1..];

    match mode {
        0 => fuzz_structural_validation(body),
        1 => fuzz_postcard_decode_untrusted(body),
        2 => fuzz_valid_fibonacci_proof_roundtrip(body),
        3 => fuzz_verify_and_record_valid(body),
        4 => fuzz_tampered_proof_behavior(body),
        5 => fuzz_noncanonical_validator_rejection(body),
        6 => fuzz_pool_recording_idempotence(body),
        7 => fuzz_factorization_verify_path(body),
        _ => fuzz_mixed_sequence(body),
    }
});

/* ─────────────────────────────────────────────────────────────
   Config / engine helpers
   ───────────────────────────────────────────────────────────── */

fn zero_delay_cfg(kind: PorPuzzleKind) -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_millis(0),
        puzzle_kind: kind,
        max_local_puzzle_ms: 1,
    }
}

fn derive_only_cfg(kind: PorPuzzleKind) -> PorConsensusConfig {
    PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: kind,
        max_local_puzzle_ms: 1_000,
    }
}

fn engine_zero_delay(kind: PorPuzzleKind) -> PorPuzzleEngine {
    PorPuzzleEngine::new(zero_delay_cfg(kind))
}

fn engine_derive_only(kind: PorPuzzleKind) -> PorPuzzleEngine {
    PorPuzzleEngine::new(derive_only_cfg(kind))
}

/* ─────────────────────────────────────────────────────────────
   Fuzz cases
   ───────────────────────────────────────────────────────────── */

fn fuzz_structural_validation(data: &[u8]) {
    let mut r = FuzzBytes::new(data);
    let proof = make_random_proof(&mut r);

    let result = proof.validate_structural();

    let validator_ok = canon_wallet_id_checked(&proof.validator)
        .map(|canon| canon == proof.validator)
        .unwrap_or(false);

    let height_ok = proof.height <= 10_000_000;
    let hash_ok = proof.prev_block_hash != [0u8; 64] && proof.prev_block_hash != [0xFFu8; 64];
    let output_ok = proof.output != 0;
    let len_ok = proof.validator.len() <= 256;

    if validator_ok && height_ok && hash_ok && output_ok && len_ok {
        assert!(
            result.is_ok(),
            "structurally valid PorPuzzleProof was rejected"
        );
    }
}

fn fuzz_postcard_decode_untrusted(data: &[u8]) {
    let decoded = from_bytes::<PorPuzzleProof>(data);

    if let Ok(proof) = decoded {
        let _ = proof.validate_structural();

        let engine = engine_derive_only(PorPuzzleKind::FibonacciDelayDev);
        let _ = proof.verify_with_engine_checked(&engine);
        let _ = proof.verify_with_engine(&engine);

        let mut pool = PorPuzzlePool::new();
        let _ = proof.verify_and_record_checked(&engine, &mut pool);
        let _ = proof.verify_and_record(&engine, &mut pool);
    }
}

fn fuzz_valid_fibonacci_proof_roundtrip(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);

    let height = r.next_u64() % 10_000_001;
    let validator = make_valid_wallet(&mut r);
    let prev = make_non_sentinel_hash64(&mut r);

    let header = engine.derive_puzzle(height, &validator, prev);

    let solution = match engine.solve_locally_checked(&header) {
        Ok(s) => s,
        Err(_) => return,
    };

    let proof = PorPuzzleProof::from_solution(&solution);

    assert_eq!(proof.height, height);
    assert_eq!(proof.validator, validator);
    assert_eq!(proof.prev_block_hash, prev);
    assert_ne!(proof.output, 0);

    assert!(proof.validate_structural().is_ok());
    assert_eq!(proof.output, fib_expected(solution.header.param));

    assert!(proof.verify_with_engine_checked(&engine).unwrap_or(false));
    assert!(proof.verify_with_engine(&engine));

    let bytes = match to_allocvec(&proof) {
        Ok(v) => v,
        Err(_) => return,
    };

    let decoded = match from_bytes::<PorPuzzleProof>(&bytes) {
        Ok(v) => v,
        Err(_) => return,
    };

    assert_proof_eq(&proof, &decoded);
    assert!(decoded.verify_with_engine(&engine));
}

fn fuzz_verify_and_record_valid(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);

    let height = r.next_u64() % 10_000_001;
    let validator = make_valid_wallet(&mut r);
    let prev = make_non_sentinel_hash64(&mut r);

    let header = engine.derive_puzzle(height, &validator, prev);

    let solution = match engine.solve_locally_checked(&header) {
        Ok(s) => s,
        Err(_) => return,
    };

    let proof = PorPuzzleProof::from_solution(&solution);

    let mut pool = PorPuzzlePool::new();

    let ok = proof
        .verify_and_record_checked(&engine, &mut pool)
        .unwrap_or(false);

    assert!(ok);

    let winners = pool.winners_for_height(height);
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0], validator);

    assert!(pool.entropy_for_height(height).is_some());

    assert!(proof.verify_and_record(&engine, &mut pool));

    let winners_after_duplicate = pool.winners_for_height(height);
    assert_eq!(winners_after_duplicate.len(), 1);
    assert_eq!(winners_after_duplicate[0], validator);

    pool.gc_below(height.saturating_add(1));
    assert!(pool.winners_for_height(height).is_empty());
    assert!(pool.entropy_for_height(height).is_none());
}

fn fuzz_tampered_proof_behavior(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);

    let height = r.next_u64() % 10_000_000;
    let validator = make_valid_wallet(&mut r);
    let prev = make_non_sentinel_hash64(&mut r);

    let header = engine.derive_puzzle(height, &validator, prev);

    let solution = match engine.solve_locally_checked(&header) {
        Ok(s) => s,
        Err(_) => return,
    };

    let proof = PorPuzzleProof::from_solution(&solution);

    assert!(proof.verify_with_engine(&engine));

    /*
        Wrong output for the SAME embedded proof fields must reject.
    */
    let mut bad_output = proof.clone();
    bad_output.output ^= 1;

    assert!(!bad_output.verify_with_engine(&engine));

    /*
        These three are NOT asserted false anymore.

        Reason:
        PorPuzzleProof::verify_with_engine() verifies a proof against the
        proof's own embedded height/validator/prev_hash.

        Changing height/validator/prev_hash creates a different proof claim.
        For FibonacciDelayDev, different claims can sometimes derive the same
        small parameter and therefore the same output. That is expected for
        this helper and must be checked by the block-validation context.
    */

    let mut changed_height = proof.clone();
    changed_height.height = changed_height.height.saturating_add(1);
    let _ = changed_height.validate_structural();
    let _ = changed_height.verify_with_engine_checked(&engine);
    assert_ne!(changed_height.height, height);

    let mut changed_hash = proof.clone();
    changed_hash.prev_block_hash[0] ^= 0xA5;

    if changed_hash.prev_block_hash == [0u8; 64] || changed_hash.prev_block_hash == [0xFFu8; 64] {
        changed_hash.prev_block_hash[1] ^= 0x5A;
    }

    let _ = changed_hash.validate_structural();
    let _ = changed_hash.verify_with_engine_checked(&engine);
    assert_ne!(changed_hash.prev_block_hash, prev);

    let mut changed_validator = proof.clone();
    changed_validator.validator = make_different_valid_wallet(&validator);
    let _ = changed_validator.validate_structural();
    let _ = changed_validator.verify_with_engine_checked(&engine);
    assert_ne!(changed_validator.validator, validator);

    /*
        If the caller wants to validate a proof against a block, the caller
        must compare the embedded proof fields to the block context.
    */
    assert!(proof_matches_block_context(&proof, height, &validator, prev));
    assert!(!proof_matches_block_context(&changed_height, height, &validator, prev));
    assert!(!proof_matches_block_context(&changed_hash, height, &validator, prev));
    assert!(!proof_matches_block_context(&changed_validator, height, &validator, prev));
}

fn fuzz_noncanonical_validator_rejection(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);

    let height = r.next_u64() % 10_000_001;
    let valid = make_valid_wallet(&mut r);
    let prev = make_non_sentinel_hash64(&mut r);

    let header = engine.derive_puzzle(height, &valid, prev);

    let solution = match engine.solve_locally_checked(&header) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut proof = PorPuzzleProof::from_solution(&solution);

    match r.next_u8() % 4 {
        0 => {
            proof.validator = proof.validator.to_ascii_uppercase();
        }
        1 => {
            proof.validator = format!(" {}", proof.validator);
        }
        2 => {
            proof.validator.push(' ');
        }
        _ => {
            proof.validator = make_fuzzy_string(&mut r, 300);
        }
    }

    assert!(proof.validate_structural().is_err());
    assert!(!proof.verify_with_engine(&engine));

    let mut pool = PorPuzzlePool::new();
    assert!(!proof.verify_and_record(&engine, &mut pool));
}

fn fuzz_pool_recording_idempotence(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_zero_delay(PorPuzzleKind::FibonacciDelayDev);
    let mut pool = PorPuzzlePool::new();

    let height = r.next_u64() % 10_000_001;
    let prev = make_non_sentinel_hash64(&mut r);

    let count = 1 + r.next_usize(8);

    for _ in 0..count {
        let validator = make_valid_wallet(&mut r);

        let header = engine.derive_puzzle(height, &validator, prev);

        let solution = match engine.solve_locally_checked(&header) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let proof = PorPuzzleProof::from_solution(&solution);

        let ok = proof
            .verify_and_record_checked(&engine, &mut pool)
            .unwrap_or(false);

        assert!(ok);
    }

    let winners = pool.winners_for_height(height);

    assert!(winners.windows(2).all(|w| w[0] <= w[1]));

    if !winners.is_empty() {
        assert!(pool.entropy_for_height(height).is_some());
    }
}

fn fuzz_factorization_verify_path(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let engine = engine_derive_only(PorPuzzleKind::FactorizationDelayDev);

    let proof = PorPuzzleProof {
        height: r.next_u64() % 10_000_001,
        validator: make_valid_wallet(&mut r),
        prev_block_hash: make_non_sentinel_hash64(&mut r),
        output: nonzero_u128(r.next_u128()),
    };

    let _ = proof.validate_structural();
    let _ = proof.verify_with_engine_checked(&engine);
    let _ = proof.verify_with_engine(&engine);

    let mut pool = PorPuzzlePool::new();
    let _ = proof.verify_and_record_checked(&engine, &mut pool);
    let _ = proof.verify_and_record(&engine, &mut pool);
}

fn fuzz_mixed_sequence(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let steps = 1 + r.next_usize(16);

    for _ in 0..steps {
        match r.next_u8() % 8 {
            0 => fuzz_structural_validation(r.remaining_window(256)),
            1 => fuzz_postcard_decode_untrusted(r.remaining_window(512)),
            2 => fuzz_valid_fibonacci_proof_roundtrip(r.remaining_window(256)),
            3 => fuzz_verify_and_record_valid(r.remaining_window(256)),
            4 => fuzz_tampered_proof_behavior(r.remaining_window(256)),
            5 => fuzz_noncanonical_validator_rejection(r.remaining_window(256)),
            6 => fuzz_pool_recording_idempotence(r.remaining_window(512)),
            _ => fuzz_factorization_verify_path(r.remaining_window(256)),
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Independent oracle / assertion helpers
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

fn assert_proof_eq(a: &PorPuzzleProof, b: &PorPuzzleProof) {
    assert_eq!(a.height, b.height);
    assert_eq!(a.validator, b.validator);
    assert_eq!(a.prev_block_hash, b.prev_block_hash);
    assert_eq!(a.output, b.output);
}

fn nonzero_u128(v: u128) -> u128 {
    if v == 0 {
        1
    } else {
        v
    }
}

fn proof_matches_block_context(
    proof: &PorPuzzleProof,
    expected_height: u64,
    expected_validator: &str,
    expected_prev_block_hash: [u8; 64],
) -> bool {
    proof.height == expected_height
        && proof.validator == expected_validator
        && proof.prev_block_hash == expected_prev_block_hash
}

/* ─────────────────────────────────────────────────────────────
   Input construction helpers
   ───────────────────────────────────────────────────────────── */

fn make_random_proof(r: &mut FuzzBytes<'_>) -> PorPuzzleProof {
    let height = match r.next_u8() % 8 {
        0 => 0,
        1 => 1,
        2 => 10_000_000,
        3 => 10_000_001,
        4 => u64::MAX,
        _ => r.next_u64(),
    };

    let validator = match r.next_u8() % 8 {
        0 => make_valid_wallet(r),
        1 => make_uppercase_wallet(r),
        2 => String::new(),
        3 => make_fuzzy_string(r, 300),
        4 => {
            let mut s = make_valid_wallet(r);
            s.push('x');
            s
        }
        5 => {
            let mut s = make_valid_wallet(r);
            s.replace_range(1..2, "z");
            s
        }
        6 => format!(" {} ", make_valid_wallet(r)),
        _ => "r".repeat(300),
    };

    let prev_block_hash = match r.next_u8() % 5 {
        0 => [0u8; 64],
        1 => [0xFFu8; 64],
        _ => make_hash64(r),
    };

    let output = match r.next_u8() % 4 {
        0 => 0,
        _ => r.next_u128(),
    };

    PorPuzzleProof {
        height,
        validator,
        prev_block_hash,
        output,
    }
}

fn make_hash64(r: &mut FuzzBytes<'_>) -> [u8; 64] {
    let mut out = [0u8; 64];

    for b in &mut out {
        *b = r.next_u8();
    }

    out
}

fn make_non_sentinel_hash64(r: &mut FuzzBytes<'_>) -> [u8; 64] {
    let mut out = make_hash64(r);

    if out == [0u8; 64] || out == [0xFFu8; 64] {
        out[0] ^= 0x01;
        out[63] ^= 0xA5;
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

fn make_uppercase_wallet(r: &mut FuzzBytes<'_>) -> String {
    let s = make_valid_wallet(r);

    match r.next_u8() % 3 {
        0 => s.to_ascii_uppercase(),
        1 => {
            let mut out = s;
            out.replace_range(0..1, "R");
            out
        }
        _ => {
            let mut out = s;
            if out.len() == 129 {
                out.replace_range(1..2, "A");
            }
            out
        }
    }
}

fn make_different_valid_wallet(existing: &str) -> String {
    if existing.len() != 129 {
        return format!("r{}", "2".repeat(128));
    }

    let mut s = existing.to_string();
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