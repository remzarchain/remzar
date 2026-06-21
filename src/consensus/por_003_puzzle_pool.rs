// src/consensus/por_003_puzzle_pool.rs

use std::collections::BTreeMap;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::canon_wallet_id_checked;

pub type RemzarHash64 = [u8; 64];

const ENTROPY_TAG: &[u8] = b"por-puzzle-entropy-64-v1";

#[inline(always)]
fn entropy_hash64(preimage: &[u8]) -> RemzarHash64 {
    let h0_64: [u8; 64] = RemzarHash::compute_bytes_hash(preimage);

    let cap = ENTROPY_TAG.len().saturating_add(preimage.len());
    let mut tagged = Vec::with_capacity(cap);
    tagged.extend_from_slice(ENTROPY_TAG);
    tagged.extend_from_slice(preimage);

    let h1_64: [u8; 64] = RemzarHash::compute_bytes_hash(&tagged);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h0_64[..32]);
    out[32..].copy_from_slice(&h1_64[..32]);
    out
}

/// In-memory puzzle winner pool, keyed by block height.
#[derive(Default, Debug, Clone)]
pub struct PorPuzzlePool {
    // height -> map of canonical wallet addresses ("r"+lower-hex) -> puzzle output (u128)
    winners: BTreeMap<u64, BTreeMap<String, u128>>,
    // height -> 64-byte entropy hash derived from all (wallet, output) pairs
    entropy: BTreeMap<u64, RemzarHash64>,
}

impl PorPuzzlePool {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn validation_err(msg: String) -> ErrorDetection {
        ErrorDetection::ValidationError {
            message: msg,
            tx_id: None,
        }
    }

    #[inline]
    fn max_winners_per_height() -> usize {
        // Reuse existing paranoia cap. If you later add a dedicated constant (recommended),
        // swap it here without touching call sites.
        GlobalConfiguration::MAX_BATCH_ITEMS
    }

    #[inline]
    fn max_wallet_len() -> usize {
        // Canonical wallet format in this codebase:
        // ASCII "r" + 128 lowercase hex = 129 chars.
        256
    }

    /// Record that `wallet` successfully solved the puzzle at `height`
    pub fn record_success_checked(
        &mut self,
        height: u64,
        wallet: &str,
        output: u128,
    ) -> Result<(), ErrorDetection> {
        // 1) Validate + canonicalize wallet (single source of truth).
        //
        // NOTE: This is intentionally strict to prevent garbage keys bloating RAM.
        if wallet.len() > Self::max_wallet_len() {
            return Err(Self::validation_err(format!(
                "PorPuzzlePool: wallet too long (len={}, max={})",
                wallet.len(),
                Self::max_wallet_len()
            )));
        }

        let canon = canon_wallet_id_checked(wallet)?;

        if canon.len() > Self::max_wallet_len() {
            return Err(Self::validation_err(format!(
                "PorPuzzlePool: canonical wallet too long (len={}, max={})",
                canon.len(),
                Self::max_wallet_len()
            )));
        }

        // 2) Insert/overwrite this wallet's output in the per-height winner map.
        let winners_for_height = self.winners.entry(height).or_default();

        // Hard cap: prevent unbounded growth per height.
        // If the key already exists, allow overwrite without increasing size.
        let exists = winners_for_height.contains_key(&canon);
        if !exists && winners_for_height.len() >= Self::max_winners_per_height() {
            return Err(Self::validation_err(format!(
                "PorPuzzlePool: too many winners for height {} (len={}, max={})",
                height,
                winners_for_height.len(),
                Self::max_winners_per_height()
            )));
        }

        // Only recompute entropy if the insert changes the map (reduces useless work).
        let prev = winners_for_height.insert(canon, output);
        let changed = match prev {
            None => true,
            Some(old) => old != output,
        };

        if !changed {
            return Ok(());
        }

        // 3) Recompute entropy deterministically from the entire winner map.
        let winners_map = winners_for_height;

        // Checked capacity to avoid overflow (paranoia).
        // Each entry contributes wallet.len() + 16 bytes (u128).
        let mut cap: usize = 0;
        for (w, _) in winners_map.iter() {
            cap = cap
                .checked_add(w.len())
                .and_then(|v| v.checked_add(16))
                .ok_or_else(|| {
                    Self::validation_err("PorPuzzlePool: preimage capacity overflow".to_string())
                })?;
        }

        // Optional additional cap: total bytes hashed for this height.
        // This prevents “many medium wallets” from forcing huge hashing work.
        let max_total = GlobalConfiguration::MAX_TOTAL_BATCH_BYTES;
        if cap > max_total {
            return Err(Self::validation_err(format!(
                "PorPuzzlePool: entropy preimage too large for height {} (bytes={}, max={})",
                height, cap, max_total
            )));
        }

        let mut preimage = Vec::with_capacity(cap);
        for (addr, out) in winners_map.iter() {
            preimage.extend_from_slice(addr.as_bytes());
            preimage.extend_from_slice(&out.to_be_bytes());
        }

        let h = entropy_hash64(&preimage);
        self.entropy.insert(height, h);

        Ok(())
    }

    /// Convenience wrapper (no panics): failures are ignored here.
    /// Call `record_success_checked` if you want the caller to log.
    pub fn record_success(&mut self, height: u64, wallet: &str, output: u128) {
        _ = self.record_success_checked(height, wallet, output);
    }

    /// Return the canonical, sorted list of puzzle winners for `height`.
    ///
    /// Since we use a BTreeMap<String, u128> internally, `.keys()` are already
    /// in deterministic order.
    pub fn winners_for_height(&self, height: u64) -> Vec<String> {
        self.winners
            .get(&height)
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Return the 64-byte entropy hash for `height` if there were any winners.
    pub fn entropy_for_height(&self, height: u64) -> Option<RemzarHash64> {
        self.entropy.get(&height).copied()
    }

    /// Optional: clear old entries to keep memory bounded.
    pub fn gc_below(&mut self, min_height: u64) {
        self.winners.retain(|h, _| *h >= min_height);
        self.entropy.retain(|h, _| *h >= min_height);
    }
}
