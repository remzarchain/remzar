use crate::cryptography::ml_dsa_65_002_merkleproof::compute_merkle_root;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

use fips204::ml_dsa_65;
use fips204::traits::{Signer, Verifier};
use std::vec::Vec;
use tracing::{error, warn};

const CONSENSUS_CTX: &[u8] = b"";
const MAX_SIGNATURE_BYTES_ABSOLUTE: usize = ml_dsa_65::SIG_LEN;

/// **Guardian Node Signature System**
pub struct GuardianSignature;

impl GuardianSignature {
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

            total = total.saturating_add(len);
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

        Ok(())
    }

    #[inline]
    fn validate_merkle_root(root: &[u8; 64]) -> Result<(), ErrorDetection> {
        // Structural defensive check.
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

    /// Compute the 64-byte transaction hashes for each batch element using BLAKE3-XOF(64).
    #[inline]
    fn compute_transaction_hashes(batch_data: &[&[u8]]) -> Result<Vec<[u8; 64]>, ErrorDetection> {
        Self::maybe_fault("GUARDIAN_HASH_PRE")?;

        let hashes: Vec<[u8; 64]> = batch_data
            .iter()
            .map(|&data| {
                let mut hasher = blake3::Hasher::new();

                if GlobalConfiguration::DOMAIN_SEPARATION_ON {
                    hasher.update(GlobalConfiguration::DOMAIN_TAG);
                }

                hasher.update(data);

                let mut out = [0u8; 64];
                hasher.finalize_xof().fill(&mut out);
                out
            })
            .collect();

        if !batch_data.is_empty() && hashes.len() != batch_data.len() {
            error!(
                "Guardian hash count mismatch: expected {}, got {}",
                batch_data.len(),
                hashes.len()
            );
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Guardian hash count mismatch: expected {}, got {}",
                    batch_data.len(),
                    hashes.len()
                ),
                tx_id: None,
            });
        }

        Self::maybe_fault("GUARDIAN_HASH_POST")?;
        Ok(hashes)
    }

    #[inline]
    fn compute_batch_merkle_root(batch_data: &[&[u8]]) -> Result<[u8; 64], ErrorDetection> {
        let transaction_hashes = Self::compute_transaction_hashes(batch_data)?;

        let (merkle_root, _levels) = compute_merkle_root(&transaction_hashes).map_err(|err| {
            error!("Failed to compute guardian Merkle root: {err:?}");
            ErrorDetection::MerkleProofGenerationError {
                reason: format!("Failed to compute Merkle root: {err:?}"),
            }
        })?;

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
        Self::maybe_fault("GUARDIAN_SIGN_PRE")?;
        Self::validate_consensus_constants()?;

        // Paranoia: bound all untrusted inputs (DoS/stall prevention).
        Self::validate_batch_input(batch_data)?;

        let merkle_root = Self::compute_batch_merkle_root(batch_data)?;

        let signature: [u8; ml_dsa_65::SIG_LEN] = signing_key
            .try_sign(&merkle_root, CONSENSUS_CTX)
            .map_err(|e| {
                error!("Guardian Node signing failed: {e}");
                ErrorDetection::CryptographicError {
                    message: format!("Guardian Node signing failed: {e}"),
                }
            })?;

        let out = signature.to_vec();

        if out.len() != ml_dsa_65::SIG_LEN {
            error!(
                "Guardian Node signing produced invalid signature length: expected {}, got {}",
                ml_dsa_65::SIG_LEN,
                out.len()
            );
            return Err(ErrorDetection::CryptographicError {
                message: format!(
                    "Guardian Node signing produced invalid signature length: expected {}, got {}",
                    ml_dsa_65::SIG_LEN,
                    out.len()
                ),
            });
        }

        Self::maybe_fault("GUARDIAN_SIGN_POST")?;
        Ok(out)
    }

    /// **Verifies a batch signature using the guardian node's verifying key.**
    pub fn verify_batch(
        verifying_key: &ml_dsa_65::PublicKey,
        batch_data: &[&[u8]],
        signature_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        Self::maybe_fault("GUARDIAN_VERIFY_PRE")?;
        Self::validate_consensus_constants()?;

        Self::validate_signature_len(signature_bytes)?;
        Self::validate_batch_input(batch_data)?;

        let merkle_root = Self::compute_batch_merkle_root(batch_data)?;

        let sig_array: &[u8; ml_dsa_65::SIG_LEN] = signature_bytes.try_into().map_err(|_| {
            error!("Failed to convert guardian signature bytes to fixed-size array");
            ErrorDetection::SerializationError {
                details: "Failed to convert guardian signature bytes to fixed-size array"
                    .to_string(),
            }
        })?;

        if !verifying_key.verify(&merkle_root, sig_array, CONSENSUS_CTX) {
            warn!("Guardian Node signature verification failed: signature/root mismatch");
            return Err(ErrorDetection::SignatureVerificationFailed {
                message: "Guardian Node signature verification failed".to_string(),
            });
        }

        Self::maybe_fault("GUARDIAN_VERIFY_POST")?;
        Ok(())
    }
}
