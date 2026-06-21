// src/utility/hash_system_remzarhash.rs

use blake3::Hasher;
use hex;
use postcard::to_allocvec;
use rayon::prelude::*;
use serde::Serialize;

use crate::utility::alpha_002_error_detection_system::ErrorDetection;

pub struct RemzarHash;

impl RemzarHash {
    // ---------------------------------------------------------------------
    // future-proof limits
    // ---------------------------------------------------------------------

    /// Hard cap to avoid unbounded allocations during serialization.
    const MAX_SERIALIZED_BYTES: usize = 4 * 1024 * 1024;

    /// Enforce upper bound on serialized payload size.
    #[inline]
    fn ensure_size_limit(len: usize, context: &'static str) -> Result<(), ErrorDetection> {
        if len > Self::MAX_SERIALIZED_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{context} serialized size {len} exceeds MAX_SERIALIZED_BYTES {}",
                    Self::MAX_SERIALIZED_BYTES
                ),
                tx_id: None,
            });
        }
        Ok(())
    }

    /// Validate that an expected hex string has an exact length and valid hex chars.
    /// This does not change crypto; it only rejects malformed inputs cleanly.
    #[inline]
    fn validate_expected_hex(
        expected: &str,
        hex_len: usize,
        context: &'static str,
    ) -> Result<(), ErrorDetection> {
        if expected.len() != hex_len {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{context} expected hex length {hex_len}, got {}",
                    expected.len()
                ),
                tx_id: None,
            });
        }
        // Ensure it's valid hex. We don't need the bytes here; we just want strict validation.
        hex::decode(expected).map_err(|e| ErrorDetection::ValidationError {
            message: format!("{context} expected is not valid hex: {e}"),
            tx_id: None,
        })?;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // 64-byte BLAKE3 helpers (XOF)
    // ---------------------------------------------------------------------

    /// Canonical 64-byte Blake3 digest (XOF output).
    #[inline]
    fn blake3_xof64(bytes: &[u8]) -> [u8; 64] {
        let mut h = Hasher::new();
        h.update(bytes);
        let mut out = [0u8; 64];
        h.finalize_xof().fill(&mut out);
        out
    }

    /// Canonical 64-byte Blake3 digest as lowercase hex (128 chars).
    #[inline]
    fn blake3_xof64_hex(bytes: &[u8]) -> String {
        hex::encode(Self::blake3_xof64(bytes))
    }

    // --- Raw-byte helpers --------------------------------------------------
    pub fn compute_bytes_hash(bytes: &[u8]) -> [u8; 64] {
        Self::blake3_xof64(bytes)
    }

    pub fn compute_bytes_hash_hex(bytes: &[u8]) -> String {
        // Same digest, safer/cleaner encoding path (no panics).
        // 64 bytes => 128 hex chars.
        Self::blake3_xof64_hex(bytes)
    }

    // --- Serializable payload helpers ------------------------------------
    pub fn compute_data_hash<T: Serialize + ?Sized>(data: &T) -> Result<String, ErrorDetection> {
        let bytes = to_allocvec(data).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;
        Self::ensure_size_limit(bytes.len(), "compute_data_hash")?;
        Ok(Self::compute_bytes_hash_hex(&bytes))
    }

    pub fn compute_data_hash_batch<T: Serialize + Send + Sync>(
        items: &[T],
    ) -> Result<Vec<String>, ErrorDetection> {
        if items.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "At least one item is required".into(),
                tx_id: None,
            });
        }
        items.par_iter().map(Self::compute_data_hash).collect()
    }

    pub fn verify_data_hash<T: Serialize + ?Sized>(
        data: &T,
        expected: &str,
    ) -> Result<bool, ErrorDetection> {
        // RemzarHash Blake3 hex is 64 bytes => 128 hex chars.
        Self::validate_expected_hex(expected, 128, "verify_data_hash")?;
        Ok(Self::compute_data_hash(data)? == expected)
    }

    pub fn verify_data_hash_batch<T: Serialize + Send + Sync>(
        items: &[T],
        expected: &[String],
    ) -> Result<Vec<bool>, ErrorDetection> {
        if items.len() != expected.len() {
            return Err(ErrorDetection::ValidationError {
                message: "Items / expected length mismatch".into(),
                tx_id: None,
            });
        }

        // Paranoia: validate all expected upfront so caller gets a clean error
        // instead of partial results.
        for (i, exp) in expected.iter().enumerate() {
            Self::validate_expected_hex(exp, 128, "verify_data_hash_batch")?;
            let _ = i;
        }

        // IMPORTANT: do NOT swallow errors. Propagate.
        items
            .par_iter()
            .zip(expected.par_iter())
            .map(|(item, exp)| Ok(Self::compute_data_hash(item)? == *exp))
            .collect::<Result<Vec<bool>, ErrorDetection>>()
    }

    // --- Truncated digests ------------------------------------------------
    pub fn compute_truncated_hash<T: Serialize + ?Sized>(
        data: &T,
    ) -> Result<String, ErrorDetection> {
        let bytes = to_allocvec(data).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;
        Self::ensure_size_limit(bytes.len(), "compute_truncated_hash")?;
        let digest = Self::compute_bytes_hash(&bytes);
        Ok(hex::encode(&digest[..8]))
    }

    pub fn compute_truncated_hash_batch<T: Serialize + Send + Sync>(
        items: &[T],
    ) -> Result<Vec<String>, ErrorDetection> {
        if items.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "At least one item is required".into(),
                tx_id: None,
            });
        }
        items.par_iter().map(Self::compute_truncated_hash).collect()
    }

    pub fn verify_truncated_hash<T: Serialize + ?Sized>(
        data: &T,
        expected: &str,
    ) -> Result<bool, ErrorDetection> {
        // Truncated is 8 bytes => 16 hex chars.
        Self::validate_expected_hex(expected, 16, "verify_truncated_hash")?;
        Ok(Self::compute_truncated_hash(data)? == expected)
    }

    pub fn verify_truncated_hash_batch<T: Serialize + Send + Sync>(
        items: &[T],
        expected: &[String],
    ) -> Result<Vec<bool>, ErrorDetection> {
        if items.len() != expected.len() {
            return Err(ErrorDetection::ValidationError {
                message: "Items / expected length mismatch".into(),
                tx_id: None,
            });
        }

        for exp in expected.iter() {
            Self::validate_expected_hex(exp, 16, "verify_truncated_hash_batch")?;
        }

        items
            .par_iter()
            .zip(expected.par_iter())
            .map(|(item, exp)| Ok(Self::compute_truncated_hash(item)? == *exp))
            .collect::<Result<Vec<bool>, ErrorDetection>>()
    }

    // --- Merkle root ------------------------------------------------------
    pub fn compute_merkle_root<T: Serialize + Send + Sync>(
        transactions: &[T],
    ) -> Result<String, ErrorDetection> {
        let mut h = Hasher::new();
        if transactions.is_empty() {
            h.update(b"EMPTY_MERKLE_ROOT");
        } else {
            let blobs: Vec<Vec<u8>> = transactions
                .par_iter()
                .map(|tx| {
                    to_allocvec(tx).map_err(|e| ErrorDetection::SerializationError {
                        details: e.to_string(),
                    })
                })
                .collect::<Result<_, _>>()?;

            // cap each blob and total processing footprint hints.
            // (We can't perfectly cap total without changing structure, but this prevents extreme single items.)
            for b in &blobs {
                Self::ensure_size_limit(b.len(), "compute_merkle_root(tx)")?;
                h.update(b);
            }
        }

        let mut out = [0u8; 64];
        h.finalize_xof().fill(&mut out);
        Ok(hex::encode(out))
    }

    // --- Header hashing ---------------------------------------------------
    pub fn compute_header_hash_bytes(prev: &[u8; 64], merkle: &[u8; 64], nonce: u64) -> [u8; 64] {
        let mut h = Hasher::new();
        h.update(prev);
        h.update(merkle);
        h.update(&nonce.to_be_bytes());

        let mut out = [0u8; 64];
        h.finalize_xof().fill(&mut out);
        out
    }

    pub fn compute_header_hash_hex(prev: &[u8; 64], merkle: &[u8; 64], nonce: u64) -> String {
        hex::encode(Self::compute_header_hash_bytes(prev, merkle, nonce))
    }

    pub fn verify_header_hash(
        prev: &[u8; 64],
        merkle: &[u8; 64],
        nonce: u64,
        expected: &str,
    ) -> bool {
        // Keep signature intact (bool). Still paranoia-validate without panicking.
        // If expected is malformed, treat it as "not verified" (false).
        if Self::validate_expected_hex(expected, 128, "verify_header_hash").is_err() {
            return false;
        }
        Self::compute_header_hash_hex(prev, merkle, nonce) == expected
    }

    pub fn compute_header_struct_hash_hex<T: Serialize + ?Sized>(
        header: &T,
        nonce: u8,
    ) -> Result<String, ErrorDetection> {
        let mut h = Hasher::new();
        let bytes = to_allocvec(header).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;
        Self::ensure_size_limit(bytes.len(), "compute_header_struct_hash_hex")?;
        h.update(&bytes);
        h.update(&[nonce]);

        let mut out = [0u8; 64];
        h.finalize_xof().fill(&mut out);
        Ok(hex::encode(out))
    }

    // --- Genesis & dummy --------------------------------------------------
    pub fn compute_dummy_hash() -> String {
        // 64 bytes => 128 hex chars
        Self::compute_bytes_hash_hex(b"remzar_empty_block_mint")
    }

    fn genesis_prehash() -> [u8; 64] {
        [0u8; 64]
    }

    pub fn compute_genesis_hash() -> [u8; 64] {
        Self::compute_bytes_hash(&Self::genesis_prehash())
    }

    pub fn compute_genesis_hash_with_ts(ts: u64) -> [u8; 64] {
        let mut preimage = Vec::with_capacity(72);
        preimage.extend(&Self::genesis_prehash());
        preimage.extend(&ts.to_be_bytes());
        Self::compute_bytes_hash(&preimage)
    }
}
