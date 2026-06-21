//! Batch (Post-Quantum) Signing for Merkle Roots

use crate::cryptography::ml_dsa_65_002_merkleproof::compute_merkle_root;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

use fips204::ml_dsa_65;
use fips204::traits::{Signer, Verifier};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::vec::Vec;
use tracing::{error, warn};

/// Consensus signing context for ML-DSA.
const CONSENSUS_CTX: &[u8] = b"";

/// Hard absolute cap for raw signature bytes.
const MAX_SIGNATURE_BYTES_ABSOLUTE: usize = ml_dsa_65::SIG_LEN;

/// One BLAKE3-XOF transaction hash is always 64 bytes.
const HASH_BYTES_PER_ITEM: usize = 64;

/// Cap on the temporary hash-vector allocation used for Merkle construction.
const MAX_HASH_VECTOR_BYTES_ABSOLUTE: usize = 8 * 1024 * 1024;

pub struct MlDsa65BatchSignature;

impl MlDsa65BatchSignature {
    #[inline]
    fn maybe_fault(op: &'static str) -> Result<(), ErrorDetection> {
        if std::env::var_os(format!("REMZAR_FAIL_{}", op)).is_some() {
            return Err(ErrorDetection::CryptographicError {
                message: format!("Fault injection triggered at operation: {op}"),
            });
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation / invariants
    // ─────────────────────────────────────────────────────────────────────────

    #[inline]
    fn validate_batch_input(batch_data: &[&[u8]]) -> Result<(), ErrorDetection> {
        // Empty batches are allowed here by design (compute_merkle_root injects dummy leaf).
        if batch_data.len() > GlobalConfiguration::MAX_BATCH_ITEMS {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch item count {} exceeds MAX_BATCH_ITEMS {}",
                    batch_data.len(),
                    GlobalConfiguration::MAX_BATCH_ITEMS
                ),
                tx_id: None,
            });
        }

        let hash_vec_bytes = batch_data
            .len()
            .checked_mul(HASH_BYTES_PER_ITEM)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Batch hash-vector size overflow".to_string(),
                tx_id: None,
            })?;

        if hash_vec_bytes > MAX_HASH_VECTOR_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch hash-vector allocation {} bytes exceeds absolute cap {}",
                    hash_vec_bytes, MAX_HASH_VECTOR_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        let mut total: usize = 0;
        for (i, item) in batch_data.iter().enumerate() {
            let len = item.len();

            if len > GlobalConfiguration::MAX_ITEM_BYTES {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Batch element #{i} size {len} exceeds MAX_ITEM_BYTES {}",
                        GlobalConfiguration::MAX_ITEM_BYTES
                    ),
                    tx_id: None,
                });
            }

            total = total
                .checked_add(len)
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: format!("Total batch bytes overflow at element #{i}"),
                    tx_id: None,
                })?;

            if total > GlobalConfiguration::MAX_TOTAL_BATCH_BYTES {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Total batch bytes {} exceeds MAX_TOTAL_BATCH_BYTES {}",
                        total,
                        GlobalConfiguration::MAX_TOTAL_BATCH_BYTES
                    ),
                    tx_id: None,
                });
            }
        }

        Ok(())
    }

    #[inline]
    fn validate_signature_len(signature_bytes: &[u8]) -> Result<(), ErrorDetection> {
        if signature_bytes.len() > MAX_SIGNATURE_BYTES_ABSOLUTE {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Signature length {} exceeds absolute cap {}",
                    signature_bytes.len(),
                    MAX_SIGNATURE_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        if signature_bytes.len() != GlobalConfiguration::GUARDIAN_SIG_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Signature length mismatch: expected {} bytes, got {}",
                    GlobalConfiguration::GUARDIAN_SIG_LEN,
                    signature_bytes.len()
                ),
                tx_id: None,
            });
        }

        if signature_bytes.len() != ml_dsa_65::SIG_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "ML-DSA-65 signature length mismatch: expected {} bytes, got {}",
                    ml_dsa_65::SIG_LEN,
                    signature_bytes.len()
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_consensus_constants() -> Result<(), ErrorDetection> {
        if GlobalConfiguration::GUARDIAN_SIG_LEN != ml_dsa_65::SIG_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Consensus configuration mismatch: GUARDIAN_SIG_LEN={} but ml_dsa_65::SIG_LEN={}",
                    GlobalConfiguration::GUARDIAN_SIG_LEN,
                    ml_dsa_65::SIG_LEN
                ),
                tx_id: None,
            });
        }

        if GlobalConfiguration::MAX_BATCH_ITEMS.saturating_mul(HASH_BYTES_PER_ITEM)
            > MAX_HASH_VECTOR_BYTES_ABSOLUTE
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Consensus configuration mismatch: MAX_BATCH_ITEMS={} can require more than {} hash-vector bytes",
                    GlobalConfiguration::MAX_BATCH_ITEMS,
                    MAX_HASH_VECTOR_BYTES_ABSOLUTE
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_merkle_root(root: &[u8; 64]) -> Result<(), ErrorDetection> {
        if root.iter().all(|b| *b == 0) {
            return Err(ErrorDetection::MerkleProofGenerationError {
                reason: "Merkle root is all-zero; refusing to sign/verify suspicious root".into(),
            });
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hashing
    // ─────────────────────────────────────────────────────────────────────────

    #[inline]
    fn hash_data(data: &[u8]) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();

        // Optional domain separation (OFF by default).
        if GlobalConfiguration::DOMAIN_SEPARATION_ON {
            hasher.update(GlobalConfiguration::DOMAIN_TAG);
        }

        hasher.update(data);

        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);
        out
    }

    #[inline]
    fn hash_data_checked(data: &[u8]) -> Result<[u8; 64], ErrorDetection> {
        match catch_unwind(AssertUnwindSafe(|| Self::hash_data(data))) {
            Ok(hash) => Ok(hash),
            Err(_) => {
                error!("Batch hashing panicked");
                Err(ErrorDetection::CryptographicError {
                    message: "Batch hashing failed safely after panic".to_string(),
                })
            }
        }
    }

    fn compute_transaction_hashes(batch_data: &[&[u8]]) -> Result<Vec<[u8; 64]>, ErrorDetection> {
        Self::maybe_fault("BATCH_HASH_PRE")?;

        let mut hashes: Vec<[u8; 64]> = Vec::new();
        hashes.try_reserve_exact(batch_data.len()).map_err(|_| {
            ErrorDetection::ValidationError {
                message: format!(
                    "Unable to reserve batch hash vector for {} item(s)",
                    batch_data.len()
                ),
                tx_id: None,
            }
        })?;

        for data in batch_data.iter().copied() {
            hashes.push(Self::hash_data_checked(data)?);
        }

        // Empty is allowed here because Merkle root computation injects a dummy leaf.
        if !batch_data.is_empty() && hashes.len() != batch_data.len() {
            error!(
                "Batch hash count mismatch: expected {}, got {}",
                batch_data.len(),
                hashes.len()
            );
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch hash count mismatch: expected {}, got {}",
                    batch_data.len(),
                    hashes.len()
                ),
                tx_id: None,
            });
        }

        Self::maybe_fault("BATCH_HASH_POST")?;
        Ok(hashes)
    }

    fn compute_batch_merkle_root(batch_data: &[&[u8]]) -> Result<[u8; 64], ErrorDetection> {
        let transaction_hashes = Self::compute_transaction_hashes(batch_data)?;

        let merkle_result = catch_unwind(AssertUnwindSafe(|| {
            compute_merkle_root(&transaction_hashes)
        }));

        let (merkle_root, _levels) = match merkle_result {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                error!("Failed to compute Merkle root for batch: {err:?}");
                return Err(ErrorDetection::MerkleProofGenerationError {
                    reason: format!("Failed to compute Merkle root: {err:?}"),
                });
            }
            Err(_) => {
                error!("Merkle root computation panicked");
                return Err(ErrorDetection::MerkleProofGenerationError {
                    reason: "Merkle root computation failed safely after panic".to_string(),
                });
            }
        };

        Self::validate_merkle_root(&merkle_root)?;
        Ok(merkle_root)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signing / verification
    // ─────────────────────────────────────────────────────────────────────────

    pub fn sign_batch(
        signing_key: &ml_dsa_65::PrivateKey,
        batch_data: &[&[u8]],
    ) -> Result<Vec<u8>, ErrorDetection> {
        Self::maybe_fault("BATCH_SIGN_PRE")?;
        Self::validate_consensus_constants()?;

        // Bound untrusted input to avoid CPU/memory stalls.
        Self::validate_batch_input(batch_data)?;

        let merkle_root = Self::compute_batch_merkle_root(batch_data)?;

        // Sign the Merkle root bytes directly (no prehash adapter needed).
        let signature: [u8; ml_dsa_65::SIG_LEN] = match catch_unwind(AssertUnwindSafe(|| {
            signing_key.try_sign(&merkle_root, CONSENSUS_CTX)
        })) {
            Ok(Ok(sig)) => sig,
            Ok(Err(e)) => {
                error!("Batch signing failed: {e}");
                return Err(ErrorDetection::CryptographicError {
                    message: format!("Batch signing failed: {e}"),
                });
            }
            Err(_) => {
                error!("Batch signing panicked");
                return Err(ErrorDetection::CryptographicError {
                    message: "Batch signing failed safely after signer panic".to_string(),
                });
            }
        };

        let out = signature.to_vec();

        // Defensive invariant: produced signature must always be exact-size.
        if out.len() != ml_dsa_65::SIG_LEN {
            error!(
                "Batch signing produced invalid signature length: expected {}, got {}",
                ml_dsa_65::SIG_LEN,
                out.len()
            );
            return Err(ErrorDetection::CryptographicError {
                message: format!(
                    "Batch signing produced invalid signature length: expected {}, got {}",
                    ml_dsa_65::SIG_LEN,
                    out.len()
                ),
            });
        }

        Self::maybe_fault("BATCH_SIGN_POST")?;
        Ok(out)
    }

    /// **Verify a batch** of transactions:
    /// 1) Validate signature length before hashing work,
    /// 2) Validate batch size/item bounds before hashing work,
    /// 3) Hash each transaction,
    /// 4) Compute the Merkle Root (injecting a dummy leaf if necessary),
    /// 5) Verify the signature matches the Merkle Root bytes.
    pub fn verify_batch(
        verifying_key: &ml_dsa_65::PublicKey,
        batch_data: &[&[u8]],
        signature_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        Self::maybe_fault("BATCH_VERIFY_PRE")?;
        Self::validate_consensus_constants()?;

        // Signature length is deliberately checked before hashing/Merkle work so
        // malformed signatures cannot force expensive batch hashing.
        Self::validate_signature_len(signature_bytes)?;

        // Bound untrusted input to avoid CPU/memory stalls.
        Self::validate_batch_input(batch_data)?;

        let merkle_root = Self::compute_batch_merkle_root(batch_data)?;

        // Convert signature bytes to fixed-size array.
        let sig_array: &[u8; ml_dsa_65::SIG_LEN] = signature_bytes.try_into().map_err(|_| {
            error!("Failed to convert signature bytes to fixed-size array");
            ErrorDetection::SerializationError {
                details: "Failed to convert signature bytes to fixed-size array".to_string(),
            }
        })?;

        let verified = match catch_unwind(AssertUnwindSafe(|| {
            verifying_key.verify(&merkle_root, sig_array, CONSENSUS_CTX)
        })) {
            Ok(v) => v,
            Err(_) => {
                error!("Batch verification panicked");
                return Err(ErrorDetection::CryptographicError {
                    message: "Batch verification failed safely after verifier panic".to_string(),
                });
            }
        };

        if !verified {
            warn!("Batch verification failed: signature/root mismatch");
            return Err(ErrorDetection::SignatureVerificationFailed {
                message: "Batch verification failed".to_string(),
            });
        }

        Self::maybe_fault("BATCH_VERIFY_POST")?;
        Ok(())
    }
}
