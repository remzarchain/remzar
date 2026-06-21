// src/cryptography/ml_dsa_65_002_merkleproof.rs

use serde::{Deserialize, Serialize};
use std::vec::Vec as StdVec;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::Hash64;

use tracing::{error, warn};

/// **Merkle Proof Structure**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub transaction_hash: Hash64,
    pub sibling_hashes: StdVec<Hash64>,
    pub path: StdVec<bool>,
    pub merkle_root: Hash64,
}

// ──────────────────────────────────────────────────────────────────────────
// Constants / local safety policy
// ──────────────────────────────────────────────────────────────────────────

/// Merkle proofs are small; this blocks hostile oversized payloads early.
const MAX_MERKLE_PROOF_ENCODED_BYTES_ABSOLUTE: usize = 256 * 1024;

/// Hard absolute proof depth cap, independent of config.
const MAX_PROOF_DEPTH_ABSOLUTE: usize = 4096;

/// Canonical empty-tree dummy leaf marker.
const EMPTY_BLOCK_DUMMY_LEAF: &[u8] = b"remzar_empty_block_mint";

// ──────────────────────────────────────────────────────────────────────────
// Fault-injection hook (runtime env based; no Cargo feature required)
// ──────────────────────────────────────────────────────────────────────────

#[inline]
fn maybe_fault(op: &'static str) -> Result<(), ErrorDetection> {
    if std::env::var_os(format!("REMZAR_FAIL_{}", op)).is_some() {
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: format!("Fault injection triggered at operation: {op}"),
        });
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// Blake3 helpers (64-byte output via XOF)
// ──────────────────────────────────────────────────────────────────────────

#[inline]
fn blake3_hash64_leaf(data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();

    // Optional domain separation (OFF by default).
    // Must match other call sites (guardian/batch signing leaf hashing).
    if GlobalConfiguration::DOMAIN_SEPARATION_ON {
        hasher.update(GlobalConfiguration::DOMAIN_TAG);
    }

    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

#[inline]
fn blake3_hash64_node(preimage: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(preimage);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

#[inline]
fn blake3_hash64_two(left64: &[u8; 64], right64: &[u8; 64]) -> [u8; 64] {
    // Avoid heap allocation: fixed 128-byte buffer.
    let mut buf = [0u8; 128];
    buf[..64].copy_from_slice(left64);
    buf[64..].copy_from_slice(right64);
    blake3_hash64_node(&buf)
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

#[inline]
fn validate_batch_bounds(batch_data: &[&[u8]]) -> Result<(), ErrorDetection> {
    if batch_data.len() > GlobalConfiguration::MAX_BATCH_ITEMS {
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: format!(
                "Batch item count {} exceeds MAX_BATCH_ITEMS {}",
                batch_data.len(),
                GlobalConfiguration::MAX_BATCH_ITEMS
            ),
        });
    }

    let mut total: usize = 0;
    for (i, item) in batch_data.iter().enumerate() {
        let len = item.len();
        if len > GlobalConfiguration::MAX_ITEM_BYTES {
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: format!(
                    "Batch element #{i} size {len} exceeds MAX_ITEM_BYTES {}",
                    GlobalConfiguration::MAX_ITEM_BYTES
                ),
            });
        }
        total = total.saturating_add(len);
        if total > GlobalConfiguration::MAX_TOTAL_BATCH_BYTES {
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: format!(
                    "Total batch bytes {total} exceeds MAX_TOTAL_BATCH_BYTES {}",
                    GlobalConfiguration::MAX_TOTAL_BATCH_BYTES
                ),
            });
        }
    }

    Ok(())
}

#[inline]
fn max_merkle_depth_for_leaves(n: usize) -> usize {
    // Depth ~ ceil(log2(n)). Add a small slack of +2.
    if n <= 1 {
        return 0;
    }
    let mut pow2 = 1usize;
    let mut depth = 0usize;
    while pow2 < n {
        pow2 <<= 1;
        depth = depth.saturating_add(1);
        if depth > 63 {
            break;
        }
    }
    depth.saturating_add(2)
}

#[inline]
fn derived_proof_depth_cap() -> usize {
    max_merkle_depth_for_leaves(GlobalConfiguration::MAX_BATCH_ITEMS)
}

#[inline]
fn max_sibling_vector_capacity() -> usize {
    derived_proof_depth_cap().min(MAX_PROOF_DEPTH_ABSOLUTE)
}

#[inline]
fn validate_hash_list_bounds(hashes: &[[u8; 64]]) -> Result<(), ErrorDetection> {
    if hashes.len() > GlobalConfiguration::MAX_BATCH_ITEMS {
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: format!(
                "Hash count {} exceeds MAX_BATCH_ITEMS {}",
                hashes.len(),
                GlobalConfiguration::MAX_BATCH_ITEMS
            ),
        });
    }
    Ok(())
}

#[inline]
fn validate_levels_shape(levels: &[StdVec<Hash64>]) -> Result<(), ErrorDetection> {
    if levels.is_empty() {
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: "Merkle levels are empty".into(),
        });
    }

    for (depth, level) in levels.iter().enumerate() {
        if level.is_empty() {
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: format!("Merkle level {depth} is empty"),
            });
        }
    }

    for (depth, pair) in levels.windows(2).enumerate() {
        let cur = pair
            .first()
            .ok_or_else(|| ErrorDetection::MerkleProofGenerationError {
                reason: "Malformed Merkle levels: missing current level".into(),
            })?
            .len();

        let next = pair
            .get(1)
            .ok_or_else(|| ErrorDetection::MerkleProofGenerationError {
                reason: "Malformed Merkle levels: missing next level".into(),
            })?
            .len();

        let expected = cur.div_ceil(2);
        let next_depth =
            depth
                .checked_add(1)
                .ok_or_else(|| ErrorDetection::MerkleProofGenerationError {
                    reason: "Merkle depth overflow".into(),
                })?;

        if next != expected {
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: format!(
                    "Malformed Merkle levels: level {} len {} -> level {} len {}, expected {}",
                    depth, cur, next_depth, next, expected
                ),
            });
        }
    }

    let last = levels
        .last()
        .ok_or_else(|| ErrorDetection::MerkleProofGenerationError {
            reason: "Merkle levels missing final level".into(),
        })?;

    if last.len() != 1 {
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: format!(
                "Final Merkle level must contain exactly one node, got {}",
                last.len()
            ),
        });
    }

    Ok(())
}

#[inline]
fn validate_merkle_proof_shape(proof: &MerkleProof) -> Result<(), ErrorDetection> {
    if proof.sibling_hashes.len() != proof.path.len() {
        return Err(ErrorDetection::SerializationError {
            details: format!(
                "Malformed proof: sibling count {} != path count {}",
                proof.sibling_hashes.len(),
                proof.path.len()
            ),
        });
    }

    if proof.sibling_hashes.len() > MAX_PROOF_DEPTH_ABSOLUTE {
        return Err(ErrorDetection::SerializationError {
            details: format!(
                "Malformed proof: depth {} exceeds absolute cap {}",
                proof.sibling_hashes.len(),
                MAX_PROOF_DEPTH_ABSOLUTE
            ),
        });
    }

    let derived_cap = derived_proof_depth_cap();
    if proof.sibling_hashes.len() > derived_cap {
        return Err(ErrorDetection::SerializationError {
            details: format!(
                "Malformed proof: depth {} exceeds derived cap {}",
                proof.sibling_hashes.len(),
                derived_cap
            ),
        });
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// Compute Merkle root (Bitcoin-style: duplicates last if odd).
// ──────────────────────────────────────────────────────────────────────────
pub fn compute_merkle_root(
    hashes: &[[u8; 64]],
) -> Result<([u8; 64], StdVec<StdVec<Hash64>>), ErrorDetection> {
    maybe_fault("MERKLE_COMPUTE_PRE")?;
    validate_hash_list_bounds(hashes)?;

    // ---------- inject dummy leaf if empty ----------
    let input_hashes: StdVec<[u8; 64]> = if hashes.is_empty() {
        // Deterministic dummy leaf (64-byte leaf-hash pipeline)
        let dummy = blake3_hash64_leaf(EMPTY_BLOCK_DUMMY_LEAF);
        vec![dummy]
    } else {
        hashes.to_vec()
    };

    // ---------- convert to Hash64 ----------
    let mut nodes: StdVec<Hash64> = input_hashes
        .iter()
        .map(|&h| Hash64::from_bytes(h))
        .collect();

    if nodes.is_empty() {
        error!("compute_merkle_root: produced empty node list after input normalization");
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: "Merkle root computation produced no leaves".into(),
        });
    }

    let mut levels: StdVec<StdVec<Hash64>> = vec![nodes.clone()];

    // ---------- build tree ----------
    while nodes.len() > 1 {
        let mut parents: StdVec<Hash64> = StdVec::with_capacity(nodes.len().div_ceil(2));

        for pair in nodes.chunks(2) {
            // concat (left||right) – duplicate last if odd
            let left = match pair.first() {
                Some(v) => v,
                None => {
                    // Defensive: chunks(2) should never yield an empty slice.
                    // Return a deterministic value without panicking.
                    let out = blake3_hash64_node(&[0u8; 128]);
                    parents.push(Hash64::from_bytes(out));
                    continue;
                }
            };

            let right = if let Some(r) = pair.get(1) { r } else { left };

            // Align with helper.rs: do not rely on tuple-field access
            let out = blake3_hash64_two(left.as_bytes(), right.as_bytes());
            parents.push(Hash64::from_bytes(out));
        }

        if parents.is_empty() {
            error!("compute_merkle_root: parent layer unexpectedly empty");
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: "Merkle root computation produced empty parent layer".into(),
            });
        }

        levels.push(parents.clone());
        nodes = parents;
    }

    validate_levels_shape(&levels)?;

    let mut root = [0u8; 64];
    let only = nodes
        .first()
        .ok_or_else(|| ErrorDetection::MerkleProofGenerationError {
            reason: "Merkle root computation produced no nodes".into(),
        })?;

    root.copy_from_slice(only.as_bytes());

    maybe_fault("MERKLE_COMPUTE_POST")?;
    Ok((root, levels))
}

// ──────────────────────────────────────────────────────────────────────────
// Generate a Merkle proof for `target_transaction` (raw bytes) given a slice
// of *raw* transactions (`batch_data`).
// ──────────────────────────────────────────────────────────────────────────
pub fn generate_merkle_proof(
    batch_data: &[&[u8]],
    target_transaction: &[u8],
) -> Result<MerkleProof, ErrorDetection> {
    maybe_fault("MERKLE_PROOF_GENERATE_PRE")?;

    if batch_data.is_empty() {
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: "Batch data is empty".into(),
        });
    }

    // Bound batch inputs to prevent DoS / stalls.
    validate_batch_bounds(batch_data)?;

    // Also bound target tx size to same per-item cap (policy check).
    if target_transaction.len() > GlobalConfiguration::MAX_ITEM_BYTES {
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: format!(
                "Target transaction size {} exceeds MAX_ITEM_BYTES {}",
                target_transaction.len(),
                GlobalConfiguration::MAX_ITEM_BYTES
            ),
        });
    }

    // 1) hash every tx with BLAKE3-XOF(64) — leaf hashing pipeline
    let hashed: StdVec<[u8; 64]> = batch_data
        .iter()
        .map(|&tx| blake3_hash64_leaf(tx))
        .collect();

    if hashed.is_empty() {
        error!("generate_merkle_proof: hashed batch unexpectedly empty");
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: "Hashed batch is empty".into(),
        });
    }

    // 2) build tree & root
    let (root, levels) = compute_merkle_root(&hashed)?;
    validate_levels_shape(&levels)?;

    // 3) hash the target tx (leaf hashing pipeline)
    let target = Hash64::from_bytes(blake3_hash64_leaf(target_transaction));

    // 4) find index in leaf level
    let leaf_level = levels
        .first()
        .ok_or_else(|| ErrorDetection::MerkleProofGenerationError {
            reason: "Merkle levels missing leaf level".into(),
        })?;

    let mut idx = leaf_level
        .iter()
        .position(|h| h.as_bytes() == target.as_bytes())
        .ok_or_else(|| ErrorDetection::MerkleProofGenerationError {
            reason: "Target transaction not found in batch.".into(),
        })?;

    // 5) collect siblings + path flags
    let mut siblings = StdVec::with_capacity(max_sibling_vector_capacity());
    let mut path = StdVec::with_capacity(max_sibling_vector_capacity()); // true = left

    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        if idx >= level.len() {
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: format!(
                    "Malformed merkle level: idx {} out of bounds (len={})",
                    idx,
                    level.len()
                ),
            });
        }

        let is_left = idx % 2 == 0;
        path.push(is_left);

        let sib_idx = if is_left {
            idx.saturating_add(1)
        } else {
            idx.saturating_sub(1)
        };

        // If out of bounds, this node was duplicated (odd count rule) -> sibling is itself.
        let sib = if let Some(s) = level.get(sib_idx) {
            *s
        } else if let Some(s) = level.get(idx) {
            *s
        } else {
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: format!(
                    "Malformed merkle level: idx {} out of bounds (len={})",
                    idx,
                    level.len()
                ),
            });
        };
        siblings.push(sib);

        idx /= 2;
    }

    let proof = MerkleProof {
        transaction_hash: target,
        sibling_hashes: siblings,
        path,
        merkle_root: Hash64::from_bytes(root),
    };

    validate_merkle_proof_shape(&proof).map_err(|e| {
        ErrorDetection::MerkleProofGenerationError {
            reason: format!("Generated malformed Merkle proof: {e:?}"),
        }
    })?;

    let computed_ok = verify_merkle_proof(&proof, &root);
    if !computed_ok {
        error!("generate_merkle_proof: internally generated proof failed self-verification");
        return Err(ErrorDetection::MerkleProofGenerationError {
            reason: "Generated Merkle proof failed self-verification".into(),
        });
    }

    maybe_fault("MERKLE_PROOF_GENERATE_POST")?;
    Ok(proof)
}

// ──────────────────────────────────────────────────────────────────────────
// postcard helpers
// ──────────────────────────────────────────────────────────────────────────

/// Serialize a Merkle proof after validating invariants.
///
/// Keeps the existing postcard format for compatibility.
pub fn serialize_merkle_proof(proof: &MerkleProof) -> Result<StdVec<u8>, ErrorDetection> {
    maybe_fault("MERKLE_PROOF_SERIALIZE_PRE")?;
    validate_merkle_proof_shape(proof)?;

    let encoded = postcard::to_stdvec(proof).map_err(|e| ErrorDetection::SerializationError {
        details: format!("Serialize Merkle proof: {e}"),
    })?;

    if encoded.len() > MAX_MERKLE_PROOF_ENCODED_BYTES_ABSOLUTE {
        error!(
            "serialize_merkle_proof: encoded proof size {} exceeds absolute cap {}",
            encoded.len(),
            MAX_MERKLE_PROOF_ENCODED_BYTES_ABSOLUTE
        );
        return Err(ErrorDetection::SerializationError {
            details: format!(
                "Serialized Merkle proof too large: {} bytes exceeds cap {}",
                encoded.len(),
                MAX_MERKLE_PROOF_ENCODED_BYTES_ABSOLUTE
            ),
        });
    }

    maybe_fault("MERKLE_PROOF_SERIALIZE_POST")?;
    Ok(encoded)
}

pub fn deserialize_merkle_proof(data: &[u8]) -> Result<MerkleProof, ErrorDetection> {
    maybe_fault("MERKLE_PROOF_DESERIALIZE_PRE")?;

    if data.is_empty() {
        return Err(ErrorDetection::SerializationError {
            details: "Deserialize Merkle proof: empty input".to_string(),
        });
    }

    if data.len() > MAX_MERKLE_PROOF_ENCODED_BYTES_ABSOLUTE {
        error!(
            "deserialize_merkle_proof: input size {} exceeds absolute cap {}",
            data.len(),
            MAX_MERKLE_PROOF_ENCODED_BYTES_ABSOLUTE
        );
        return Err(ErrorDetection::SerializationError {
            details: format!(
                "Deserialize Merkle proof: input too large ({} bytes > {})",
                data.len(),
                MAX_MERKLE_PROOF_ENCODED_BYTES_ABSOLUTE
            ),
        });
    }

    let proof: MerkleProof =
        postcard::from_bytes(data).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Deserialize Merkle proof: {e}"),
        })?;

    validate_merkle_proof_shape(&proof)?;

    // Canonical round-trip check: re-encode and compare bytes.
    // This makes decode stricter and fail-closed for storage/network artifacts.
    let reencoded =
        postcard::to_stdvec(&proof).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Re-serialize Merkle proof after decode: {e}"),
        })?;

    if reencoded != data {
        warn!("deserialize_merkle_proof: non-canonical postcard encoding rejected");
        return Err(ErrorDetection::SerializationError {
            details: "Deserialize Merkle proof: non-canonical encoding rejected".to_string(),
        });
    }

    maybe_fault("MERKLE_PROOF_DESERIALIZE_POST")?;
    Ok(proof)
}

// ──────────────────────────────────────────────────────────────────────────
// Verify the proof against a signed Merkle root.
// ──────────────────────────────────────────────────────────────────────────
pub fn verify_merkle_proof(proof: &MerkleProof, signed_merkle_root: &[u8; 64]) -> bool {
    // 1) Path and siblings must match 1:1.
    if proof.sibling_hashes.len() != proof.path.len() {
        warn!(
            "verify_merkle_proof: malformed proof (siblings={}, path={})",
            proof.sibling_hashes.len(),
            proof.path.len()
        );
        return false;
    }

    // 2) Depth sanity: reject absurd depths (DoS guard).
    if proof.sibling_hashes.len() > MAX_PROOF_DEPTH_ABSOLUTE {
        warn!(
            "verify_merkle_proof: proof depth too large ({})",
            proof.sibling_hashes.len()
        );
        return false;
    }

    // Derived cap from MAX_BATCH_ITEMS (paranoia: allow small slack).
    let derived_cap = derived_proof_depth_cap();
    if proof.sibling_hashes.len() > derived_cap {
        warn!(
            "verify_merkle_proof: proof depth {} exceeds derived cap {}",
            proof.sibling_hashes.len(),
            derived_cap
        );
        return false;
    }

    // 3) Empty-depth proof only valid when tx hash == root AND proof root == signed root.
    if proof.sibling_hashes.is_empty() {
        let tx_matches_signed = proof.transaction_hash.as_bytes() == signed_merkle_root;
        let proof_root_matches_signed = proof.merkle_root.as_bytes() == signed_merkle_root;

        if !(tx_matches_signed && proof_root_matches_signed) {
            warn!("verify_merkle_proof: empty proof but tx/root do not both match signed root");
            return false;
        }
        return true;
    }

    // ---- compute root ----
    let mut computed: [u8; 64] = *proof.transaction_hash.as_bytes();

    for (depth, sibling) in proof.sibling_hashes.iter().enumerate() {
        let left = match proof.path.get(depth) {
            Some(v) => *v,
            None => {
                warn!(
                    "verify_merkle_proof: malformed proof (path index out of bounds at depth {})",
                    depth
                );
                return false;
            }
        };

        let out = if left {
            blake3_hash64_two(&computed, sibling.as_bytes())
        } else {
            blake3_hash64_two(sibling.as_bytes(), &computed)
        };
        computed = out;
    }

    let computed_matches_signed = &computed == signed_merkle_root;
    if !computed_matches_signed {
        warn!("verify_merkle_proof: computed root mismatch with signed root");
        return false;
    }

    let computed_matches_embedded = proof.merkle_root.as_bytes() == &computed;
    if !computed_matches_embedded {
        warn!("verify_merkle_proof: computed root mismatch with embedded proof root");
        return false;
    }

    true
}
