// fuzz/fuzz_targets/fuzz_block_003_puzzleproof.rs

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use std::fmt;

use postcard::{from_bytes, to_allocvec};

type Hash64 = [u8; 64];

const MAX_VALIDATOR_LEN: usize = 256;
const MAX_REASONABLE_HEIGHT: u64 = 10_000_000;
const REMZAR_WALLET_LEN: usize = 129;
const REMZAR_WALLET_BODY_LEN: usize = 128;
const REMZAR_WALLET_PREFIX: u8 = b'r';
const ZERO_HASH_64: Hash64 = [0u8; 64];
const FF_HASH_64: Hash64 = [0xFFu8; 64];

const MAX_FIB_N: u32 = 44;
const MIN_FACT_DIFFICULTY: u32 = 1;
const MAX_FACT_DIFFICULTY: u32 = 4;
const MAX_FACT_TRIAL_STEPS: u64 = 2_000_000;
const MAX_FACT_N: u64 = 1u64 << 48;

// ─────────────────────────────────────────────────────────────────────────────
// Local error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum FuzzError {
    Validation(String),
    Serialization(String),
}

impl fmt::Display for FuzzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "validation error: {msg}"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

fn validation_err(msg: impl Into<String>) -> FuzzError {
    FuzzError::Validation(msg.into())
}

mod serde_u8_array_64 {
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

// ─────────────────────────────────────────────────────────────────────────────
// BlockPuzzleProof Helper
// ─────────────────────────────────────────────────────────────────────────────

fn hash64(bytes: &[u8]) -> Hash64 {
    let mut h = blake3::Hasher::new();
    h.update(bytes);

    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

fn hash64_with_domain(domain: &[u8], bytes: &[u8]) -> Hash64 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(bytes);

    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

fn non_sentinel_hash64(domain: &[u8], bytes: &[u8]) -> Hash64 {
    let mut out = hash64_with_domain(domain, bytes);

    if out == ZERO_HASH_64 || out == FF_HASH_64 {
        out[0] ^= 0x01;
    }

    out
}

fn derive_wallet_id_from_bytes(bytes: &[u8]) -> String {
    format!("r{}", hex::encode(hash64_with_domain(b"wallet", bytes)))
}

fn canon_wallet_id_checked(id: &str) -> Result<String, FuzzError> {
    let s = id.trim();

    if s.len() != REMZAR_WALLET_LEN {
        return Err(validation_err("Wallet address is invalid or incomplete"));
    }

    let lower = s.to_ascii_lowercase();
    let b = lower.as_bytes();

    if b.first() != Some(&REMZAR_WALLET_PREFIX) {
        return Err(validation_err("Wallet address is invalid or incomplete"));
    }

    if !b.get(1..).is_some_and(|body| {
        body.len() == REMZAR_WALLET_BODY_LEN
            && body
                .iter()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return Err(validation_err("Wallet address is invalid or incomplete"));
    }

    Ok(lower)
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory model of the gossip proof referenced by BlockPuzzleProof
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MemoryPorPuzzleProof {
    height: u64,
    validator: String,

    #[serde(with = "serde_u8_array_64")]
    prev_block_hash: Hash64,

    output: u128,
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory model of src/blockchain/block_003_puzzleproof.rs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BlockPuzzleProof {
    height: u64,
    validator: String,

    #[serde(with = "serde_u8_array_64")]
    prev_block_hash: Hash64,

    output: u128,
}

impl BlockPuzzleProof {
    fn canonical_validator_checked(validator: &str) -> Result<String, FuzzError> {
        if validator.len() > MAX_VALIDATOR_LEN {
            return Err(validation_err(format!(
                "BlockPuzzleProof.validator too long (len={}, max={})",
                validator.len(),
                MAX_VALIDATOR_LEN
            )));
        }

        canon_wallet_id_checked(validator)
    }

    fn new(
        height: u64,
        validator: String,
        prev_block_hash: Hash64,
        output: u128,
    ) -> Result<Self, FuzzError> {
        let validator = Self::canonical_validator_checked(&validator)?;

        let proof = Self {
            height,
            validator,
            prev_block_hash,
            output,
        };

        proof.validate_structural()?;
        Ok(proof)
    }

    fn from_gossip(proof: &MemoryPorPuzzleProof) -> Result<Self, FuzzError> {
        Self::new(
            proof.height,
            proof.validator.clone(),
            proof.prev_block_hash,
            proof.output,
        )
    }

    fn to_gossip(&self) -> MemoryPorPuzzleProof {
        MemoryPorPuzzleProof {
            height: self.height,
            validator: self.validator.clone(),
            prev_block_hash: self.prev_block_hash,
            output: self.output,
        }
    }

    fn validate_structural(&self) -> Result<(), FuzzError> {
        if self.height > MAX_REASONABLE_HEIGHT {
            return Err(validation_err(format!(
                "BlockPuzzleProof.height out of bounds: {}",
                self.height
            )));
        }

        if self.validator.trim().is_empty() {
            return Err(validation_err("BlockPuzzleProof.validator is empty"));
        }

        if self.validator.len() > MAX_VALIDATOR_LEN {
            return Err(validation_err(format!(
                "BlockPuzzleProof.validator too long (len={}, max={})",
                self.validator.len(),
                MAX_VALIDATOR_LEN
            )));
        }

        let canon = canon_wallet_id_checked(&self.validator)?;
        if canon != self.validator {
            return Err(validation_err(
                "BlockPuzzleProof.validator is not canonical",
            ));
        }

        if self.prev_block_hash == ZERO_HASH_64 || self.prev_block_hash == FF_HASH_64 {
            return Err(validation_err(
                "BlockPuzzleProof.prev_block_hash is an invalid sentinel",
            ));
        }

        if self.output == 0 {
            return Err(validation_err("BlockPuzzleProof.output cannot be 0"));
        }

        Ok(())
    }

    fn verify_with_engine_checked(
        &self,
        engine: &MemoryPorPuzzleEngine,
    ) -> Result<bool, FuzzError> {
        self.validate_structural()?;
        Ok(engine.verify_proof(self))
    }

    fn verify_with_engine(&self, engine: &MemoryPorPuzzleEngine) -> bool {
        self.verify_with_engine_checked(engine).unwrap_or(false)
    }

    fn commitment_bytes(&self) -> Result<Hash64, FuzzError> {
        let bytes = to_allocvec(self)
            .map_err(|e| FuzzError::Serialization(format!("Serialize failed: {e}")))?;
        Ok(hash64(&bytes))
    }

    fn commitment_hex(&self) -> Result<String, FuzzError> {
        Ok(hex::encode(self.commitment_bytes()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PuzzleKind {
    FibonacciDelayDev,
    FactorizationDelayDev,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryPorPuzzleHeader {
    height: u64,
    validator: String,
    prev_block_hash: Hash64,
    kind: PuzzleKind,
    param: u32,
}

#[derive(Debug, Clone)]
struct MemoryPorPuzzleEngine {
    kind: PuzzleKind,
    target_secs: u64,
}

impl MemoryPorPuzzleEngine {
    fn new(kind: PuzzleKind, target_secs: u64) -> Self {
        Self {
            kind,
            target_secs: target_secs.max(1),
        }
    }

    fn derive_puzzle(
        &self,
        height: u64,
        validator_wallet: &str,
        prev_block_hash: Hash64,
    ) -> MemoryPorPuzzleHeader {
        let validator = canon_wallet_id_checked(validator_wallet)
            .unwrap_or_else(|_| "por:<invalid-wallet>".to_string());

        let mut hasher = blake3::Hasher::new();
        hasher.update(&prev_block_hash);
        hasher.update(&height.to_be_bytes());
        hasher.update(validator.as_bytes());
        let seed = hasher.finalize();
        let sb = seed.as_bytes();

        let param = match self.kind {
            PuzzleKind::FibonacciDelayDev => {
                let base_n: u32 = if self.target_secs <= 10 {
                    26
                } else if self.target_secs <= 20 {
                    30
                } else if self.target_secs <= 40 {
                    32
                } else if self.target_secs <= 60 {
                    34
                } else {
                    36
                };

                let jitter: u32 = u32::from(sb[0]) & 0x07;
                base_n.saturating_add(jitter).min(MAX_FIB_N)
            }
            PuzzleKind::FactorizationDelayDev => (u32::from(sb[0]) & 0x03).saturating_add(1),
        };

        MemoryPorPuzzleHeader {
            height,
            validator,
            prev_block_hash,
            kind: self.kind,
            param,
        }
    }

    fn solve_output(&self, height: u64, validator: &str, prev_block_hash: Hash64) -> u128 {
        let header = self.derive_puzzle(height, validator, prev_block_hash);
        solve_output_for_header(&header)
    }

    fn verify_proof(&self, proof: &BlockPuzzleProof) -> bool {
        let expected_header = self.derive_puzzle(
            proof.height,
            &proof.validator,
            proof.prev_block_hash,
        );

        match expected_header.kind {
            PuzzleKind::FibonacciDelayDev => {
                let expected_output = fib_iter_u128(expected_header.param);
                expected_output == proof.output
            }
            PuzzleKind::FactorizationDelayDev => {
                verify_factorization_dev(&expected_header, proof.output)
            }
        }
    }
}

fn clamp_fib_n(n: u32) -> u32 {
    n.min(MAX_FIB_N)
}

fn clamp_fact_param(p: u32) -> u32 {
    p.clamp(MIN_FACT_DIFFICULTY, MAX_FACT_DIFFICULTY)
}

fn normalize_header(header: &MemoryPorPuzzleHeader) -> MemoryPorPuzzleHeader {
    let mut h = header.clone();
    h.validator = canon_wallet_id_checked(&h.validator)
        .unwrap_or_else(|_| "por:<invalid-wallet>".to_string());

    match h.kind {
        PuzzleKind::FibonacciDelayDev => {
            h.param = clamp_fib_n(h.param);
            h
        }
        PuzzleKind::FactorizationDelayDev => {
            h.param = clamp_fact_param(h.param);
            h
        }
    }
}

fn solve_output_for_header(header: &MemoryPorPuzzleHeader) -> u128 {
    let header = normalize_header(header);

    match header.kind {
        PuzzleKind::FibonacciDelayDev => fib_iter_u128(header.param),
        PuzzleKind::FactorizationDelayDev => solve_factorization_dev(&header),
    }
}

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

fn derive_n_from_header(header: &MemoryPorPuzzleHeader) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&header.prev_block_hash);
    hasher.update(&header.height.to_be_bytes());
    hasher.update(header.validator.as_bytes());
    let seed = hasher.finalize();
    let sb = seed.as_bytes();

    let mut n: u64 = u64::from_be_bytes([
        sb[0], sb[1], sb[2], sb[3], sb[4], sb[5], sb[6], sb[7],
    ]);
    n |= 1;
    n = n.max(3);

    let shift = header.param & 0x03;
    n >>= shift;

    n
}

fn solve_factorization_dev_checked(header: &MemoryPorPuzzleHeader) -> Result<u128, FuzzError> {
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
    Ok((u128::from(n) << 64) | u128::from(p))
}

fn solve_factorization_dev(header: &MemoryPorPuzzleHeader) -> u128 {
    match solve_factorization_dev_checked(header) {
        Ok(v) => v,
        Err(_) => u128::from(derive_n_from_header(header)) << 64,
    }
}

fn verify_factorization_dev_checked(
    header: &MemoryPorPuzzleHeader,
    packed: u128,
) -> Result<bool, FuzzError> {
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

fn verify_factorization_dev(header: &MemoryPorPuzzleHeader, packed: u128) -> bool {
    verify_factorization_dev_checked(header, packed).unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz input shaping
// ─────────────────────────────────────────────────────────────────────────────

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];
    if let Some(slice) = data.get(offset..offset.saturating_add(8)) {
        let len = slice.len().min(8);
        out[..len].copy_from_slice(&slice[..len]);
    }
    u64::from_le_bytes(out)
}

fn read_u128(data: &[u8], offset: usize) -> u128 {
    let mut out = [0u8; 16];
    if let Some(slice) = data.get(offset..offset.saturating_add(16)) {
        let len = slice.len().min(16);
        out[..len].copy_from_slice(&slice[..len]);
    }
    u128::from_le_bytes(out)
}

fn selector(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}

fn ascii_lossy_bounded(bytes: &[u8], max_len: usize) -> String {
    let take = bytes.len().min(max_len);
    String::from_utf8_lossy(&bytes[..take]).into_owned()
}

fn make_validator(data: &[u8]) -> String {
    let canonical = derive_wallet_id_from_bytes(data);

    match selector(data, 24) % 10 {
        0 => canonical,
        1 => canonical.to_ascii_uppercase(),
        2 => format!(" {canonical} "),
        3 => "".to_string(),
        4 => "r".to_string(),
        5 => format!("r{}", "0".repeat(128)),
        6 => format!("r{}", "g".repeat(128)),
        7 => format!("x{}", "0".repeat(128)),
        8 => format!("r{}", "a".repeat(300)),
        _ => ascii_lossy_bounded(data.get(25..).unwrap_or_default(), 300),
    }
}

fn make_prev_hash(data: &[u8]) -> Hash64 {
    match selector(data, 25) % 5 {
        0 => ZERO_HASH_64,
        1 => FF_HASH_64,
        2 => {
            let mut out = [0u8; 64];
            if let Some(slice) = data.get(26..) {
                let len = slice.len().min(64);
                out[..len].copy_from_slice(&slice[..len]);
            }
            out
        }
        _ => non_sentinel_hash64(b"prev", data),
    }
}

fn make_engine(data: &[u8]) -> MemoryPorPuzzleEngine {
    let kind = if selector(data, 26) & 1 == 0 {
        PuzzleKind::FibonacciDelayDev
    } else {
        PuzzleKind::FactorizationDelayDev
    };

    let target_secs = 1 + u64::from(selector(data, 27) % 90);
    MemoryPorPuzzleEngine::new(kind, target_secs)
}

fn mutate_output(output: u128) -> u128 {
    let mutated = output.wrapping_add(1);
    if mutated == 0 { 1 } else { mutated }
}

// ─────────────────────────────────────────────────────────────────────────────
// Invariant checks
// ─────────────────────────────────────────────────────────────────────────────

fn fuzz_untrusted_postcard_decode(data: &[u8]) {
    if let Ok(proof) = from_bytes::<BlockPuzzleProof>(data) {
        let _ = proof.validate_structural();
        let _ = proof.commitment_bytes();
        let _ = proof.commitment_hex();

        let gossip = proof.to_gossip();
        let _ = BlockPuzzleProof::from_gossip(&gossip);

        if let Ok(serialized) = to_allocvec(&proof) {
            let decoded = from_bytes::<BlockPuzzleProof>(&serialized)
                .expect("serializing then deserializing BlockPuzzleProof must roundtrip");
            assert_eq!(proof, decoded);
        }
    }

    if let Ok(gossip) = from_bytes::<MemoryPorPuzzleProof>(data) {
        let _ = BlockPuzzleProof::from_gossip(&gossip);
    }
}

fn assert_valid_proof_invariants(proof: &BlockPuzzleProof) {
    assert!(proof.validate_structural().is_ok());
    assert_eq!(proof.validator, canon_wallet_id_checked(&proof.validator).unwrap());
    assert!(proof.height <= MAX_REASONABLE_HEIGHT);
    assert!(proof.validator.len() <= MAX_VALIDATOR_LEN);
    assert_ne!(proof.prev_block_hash, ZERO_HASH_64);
    assert_ne!(proof.prev_block_hash, FF_HASH_64);
    assert_ne!(proof.output, 0);

    let gossip = proof.to_gossip();
    assert_eq!(gossip.height, proof.height);
    assert_eq!(gossip.validator, proof.validator);
    assert_eq!(gossip.prev_block_hash, proof.prev_block_hash);
    assert_eq!(gossip.output, proof.output);

    let from_gossip = BlockPuzzleProof::from_gossip(&gossip)
        .expect("valid proof converted to gossip must convert back");
    assert_eq!(*proof, from_gossip);

    let encoded = to_allocvec(proof).expect("valid proof must serialize");
    let decoded = from_bytes::<BlockPuzzleProof>(&encoded).expect("valid proof must deserialize");
    assert_eq!(*proof, decoded);

    let commitment_a = proof.commitment_bytes().expect("commitment bytes must compute");
    let commitment_b = proof.commitment_bytes().expect("commitment bytes must be deterministic");
    assert_eq!(commitment_a, commitment_b);

    let commitment_hex = proof.commitment_hex().expect("commitment hex must compute");
    assert_eq!(commitment_hex.len(), 128);
    assert!(commitment_hex.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(hex::decode(commitment_hex).unwrap().len(), 64);
}

fn fuzz_constructor_and_structural_rules(data: &[u8]) {
    let raw_height = read_u64(data, 0);
    let raw_output = read_u128(data, 8);
    let validator = make_validator(data);
    let prev_hash = make_prev_hash(data);

    let constructed = BlockPuzzleProof::new(raw_height, validator.clone(), prev_hash, raw_output);

    if let Ok(proof) = constructed {
        assert_valid_proof_invariants(&proof);

        let zero_output = BlockPuzzleProof {
            output: 0,
            ..proof.clone()
        };
        assert!(zero_output.validate_structural().is_err());

        let zero_hash = BlockPuzzleProof {
            prev_block_hash: ZERO_HASH_64,
            ..proof.clone()
        };
        assert!(zero_hash.validate_structural().is_err());

        let ff_hash = BlockPuzzleProof {
            prev_block_hash: FF_HASH_64,
            ..proof.clone()
        };
        assert!(ff_hash.validate_structural().is_err());

        let too_high = BlockPuzzleProof {
            height: MAX_REASONABLE_HEIGHT.saturating_add(1),
            ..proof.clone()
        };
        assert!(too_high.validate_structural().is_err());

        let uppercase_direct = BlockPuzzleProof {
            validator: proof.validator.to_ascii_uppercase(),
            ..proof.clone()
        };
        assert!(uppercase_direct.validate_structural().is_err());
    }

    let canonical = derive_wallet_id_from_bytes(data);
    let uppercase = canonical.to_ascii_uppercase();
    let good_hash = non_sentinel_hash64(b"canonicalization-prev", data);
    let good_height = raw_height % (MAX_REASONABLE_HEIGHT + 1);
    let good_output = if raw_output == 0 { 1 } else { raw_output };

    let from_uppercase = BlockPuzzleProof::new(good_height, uppercase, good_hash, good_output)
        .expect("constructor should canonicalize uppercase wallet input");
    assert_eq!(from_uppercase.validator, canonical);
    assert_valid_proof_invariants(&from_uppercase);
}

fn fuzz_engine_verification_model(data: &[u8]) {
    let height = read_u64(data, 0) % (MAX_REASONABLE_HEIGHT + 1);
    let validator = derive_wallet_id_from_bytes(data);
    let prev_hash = non_sentinel_hash64(b"engine-prev", data);

    let fib_engine = MemoryPorPuzzleEngine::new(
        PuzzleKind::FibonacciDelayDev,
        1 + u64::from(selector(data, 28) % 90),
    );

    let fib_output = fib_engine.solve_output(height, &validator, prev_hash);
    let fib_proof = BlockPuzzleProof::new(height, validator.clone(), prev_hash, fib_output)
        .expect("fresh Fibonacci proof must be structurally valid");

    assert!(fib_proof.verify_with_engine_checked(&fib_engine).unwrap());
    assert!(fib_proof.verify_with_engine(&fib_engine));

    // Mutating the output for the SAME proof parameters must fail.
    let wrong_fib = BlockPuzzleProof {
        output: mutate_output(fib_output),
        ..fib_proof.clone()
    };
    assert!(!wrong_fib.verify_with_engine(&fib_engine));

    // IMPORTANT:
    // Do NOT blindly assert that changing height must fail.
    //
    // In the Fibonacci puzzle, the derived header includes height, but the final
    // consensus output is only fib(param). The param has limited range, so two
    // different heights may derive the same param and therefore the same output.
    //
    // Only assert failure when the new height derives a DIFFERENT expected output.
    let wrong_height_value = height.saturating_add(1).min(MAX_REASONABLE_HEIGHT);
    if wrong_height_value != height {
        let expected_output_for_wrong_height =
            fib_engine.solve_output(wrong_height_value, &validator, prev_hash);

        let wrong_height = BlockPuzzleProof {
            height: wrong_height_value,
            ..fib_proof.clone()
        };

        if expected_output_for_wrong_height != fib_output {
            assert!(!wrong_height.verify_with_engine(&fib_engine));
        } else {
            assert!(wrong_height.verify_with_engine(&fib_engine));
        }
    }

    // Factorization may deliberately
    // refuse unsafe derived n values, so this path asserts only consistency
    // between checked and boolean wrappers.
    let engine = make_engine(data);
    let output = engine.solve_output(height, &validator, prev_hash);

    if let Ok(proof) = BlockPuzzleProof::new(height, validator, prev_hash, output.max(1)) {
        let checked = proof.verify_with_engine_checked(&engine).unwrap_or(false);
        let boolean = proof.verify_with_engine(&engine);
        assert_eq!(checked, boolean);
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_untrusted_postcard_decode(data);
    fuzz_constructor_and_structural_rules(data);
    fuzz_engine_verification_model(data);
});