//! src/utility/alpha_003_detection_system.rs

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::time_policy::TimePolicy;

use hex;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::debug;

/// Outcome used by high-level health checks.
#[derive(Debug, PartialEq, Eq)]
pub enum DetectionOutcome {
    Ok,
    Warning(String),
    Critical(String),
}

/// Tracks live participants, validator stakes, and enforces
/// network-wide safety rules — double-spend, Sybil, 51 % attack, etc.
#[derive(Clone)]
pub struct DetectionSystem {
    /* ─────────────── economic & consensus state ─────────────── */
    pub current_reward: u64,
    pub participant_reward: f64,
    pub max_participants: u64,
    pub active_participants: HashSet<String>,
    pub last_active: HashMap<String, u64>,

    // bounded boot list with TTL tracking (prevents unbounded growth)
    pub booted_participants: HashSet<String>,
    pub booted_at: HashMap<String, u64>,

    // stake map (canonical id → stake)
    pub validator_stakes: HashMap<String, u64>,
}

impl DetectionSystem {
    /* ───────────────────────── constructors ───────────────────────── */

    #[inline]
    pub fn new() -> Self {
        Self {
            current_reward: GlobalConfiguration::INITIAL_BLOCK_REWARD,
            participant_reward: 0.0,
            max_participants: GlobalConfiguration::MAX_ZAR_PARTICIPANTS,
            active_participants: HashSet::new(),
            last_active: HashMap::new(),
            booted_participants: HashSet::new(),
            booted_at: HashMap::new(),
            validator_stakes: HashMap::new(),
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // WIRING: canonicalization + bounds
    // ────────────────────────────────────────────────────────────────────

    /// Runtime timestamp helper with explicit error reporting.
    #[inline]
    fn now_unix_result() -> Result<u64, ErrorDetection> {
        TimePolicy::now_unix_secs_runtime()
    }

    /// Runtime timestamp helper retained for existing call sites.
    #[inline]
    fn now_unix() -> u64 {
        Self::now_unix_result().unwrap_or(0)
    }

    /// Canonicalize an identifier string for storage.
    #[inline]
    fn canon_id(&self, pid: &str) -> Result<String, ErrorDetection> {
        let trimmed = pid.trim();
        if trimmed.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Participant id cannot be empty".into(),
                tx_id: None,
            });
        }

        let cap = GlobalConfiguration::MAX_PEER_ID_B58_LEN;
        if trimmed.len() > cap {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Participant id exceeds MAX_PEER_ID_B58_LEN: {} > {}",
                    trimmed.len(),
                    cap
                ),
                tx_id: None,
            });
        }

        if !trimmed.is_ascii() {
            return Err(ErrorDetection::ValidationError {
                message: "Participant id must be ASCII".into(),
                tx_id: None,
            });
        }

        Ok(trimmed.to_ascii_lowercase())
    }

    /// Effective cap: min(MAX_AOS_PARTICIPANTS, MAX_VALIDATORS).
    #[inline]
    fn effective_participant_cap(&self) -> u64 {
        let a = self.max_participants;
        let b = GlobalConfiguration::MAX_VALIDATORS as u64;
        a.min(b)
    }

    /// Prune boot list entries older than a TTL window to prevent unbounded growth.
    fn prune_booted(&mut self) {
        let ttl_secs = GlobalConfiguration::DEAD_PEER_EVICTION_SECS
            .saturating_add(GlobalConfiguration::HEARTBEAT_GRACE_SECS);
        let ttl = Duration::from_secs(ttl_secs);

        let now = Self::now_unix();

        let stale: Vec<String> = self
            .booted_at
            .iter()
            .filter_map(|(pid, ts)| {
                if Duration::from_secs(now.saturating_sub(*ts)) > ttl {
                    Some(pid.clone())
                } else {
                    None
                }
            })
            .collect();

        for pid in stale {
            self.booted_at.remove(&pid);
            self.booted_participants.remove(&pid);
        }
    }

    /* ───────────────────── participant management ─────────────────── */

    /// Add a participant. Accepts any casing; stores canonical string.
    pub fn add_participant(&mut self, pid: &str) -> Result<(), ErrorDetection> {
        // WIRING: keep boot list bounded.
        self.prune_booted();

        let canonical = self.canon_id(pid)?;
        let cap = self.effective_participant_cap();

        if (self.active_participants.len() as u64) >= cap {
            return Err(ErrorDetection::CapacityError {
                message: format!("Maximum participant limit reached ({cap})"),
            });
        }

        // Reject duplicates.
        if self.active_participants.contains(&canonical) {
            return Err(ErrorDetection::AlreadyExists {
                message: format!("Participant {pid} already active"),
            });
        }

        // Respect recent boot list.
        if self.booted_participants.contains(&canonical) {
            return Err(ErrorDetection::PermissionDenied {
                message: format!("Participant {pid} was booted recently and cannot rejoin"),
            });
        }

        let now = Self::now_unix_result()?;

        // Canonicalize storage.
        self.active_participants.insert(canonical.clone());
        self.last_active.insert(canonical.clone(), now);

        // Paranoia: prevent auxiliary maps from growing beyond configured limits.
        if self.last_active.len() > GlobalConfiguration::MAX_IDENTITIES {
            self.active_participants.remove(&canonical);
            self.last_active.remove(&canonical);
            return Err(ErrorDetection::CapacityError {
                message: format!(
                    "last_active map exceeded MAX_IDENTITIES ({})",
                    GlobalConfiguration::MAX_IDENTITIES
                ),
            });
        }

        debug!("👤 Participant {pid} joined the validator set");
        Ok(())
    }

    /// Remove a participant (canonical).
    pub fn remove_participant(&mut self, pid: &str) -> Result<(), ErrorDetection> {
        let canonical = self.canon_id(pid)?;

        let removed = self.active_participants.remove(&canonical);

        if removed {
            self.last_active.remove(&canonical);
            self.validator_stakes.remove(&canonical);
            debug!("👤 Participant {pid} removed from validator set");
            Ok(())
        } else {
            Err(ErrorDetection::NotFound {
                resource: format!("participant {pid}"),
            })
        }
    }

    /// Boot any participants whose last heartbeat exceeds `max_inactive`.
    /// Cleans keys while enforcing canonical storage.
    pub fn boot_inactive_participants(&mut self, max_inactive: Duration) {
        // WIRING: keep boot list bounded.
        self.prune_booted();

        let now = Self::now_unix();

        // Evaluate by canonical keys present in last_active.
        let to_boot: Vec<String> = self
            .last_active
            .iter()
            .filter_map(|(pid, ts)| {
                if Duration::from_secs(now.saturating_sub(*ts)) > max_inactive {
                    Some(pid.clone())
                } else {
                    None
                }
            })
            .collect();

        for pid in to_boot {
            self.active_participants.remove(&pid);
            self.last_active.remove(&pid);
            self.validator_stakes.remove(&pid);

            // Record boot + timestamp.
            self.booted_participants.insert(pid.clone());
            self.booted_at.insert(pid.clone(), now);

            debug!("⏰ Booted inactive participant {pid}");
        }

        self.enforce_boot_cap();
    }

    /// Record activity (heartbeat). Accepts any casing; stores canonical liveness.
    pub fn update_participant_activity(&mut self, pid: &str) -> Result<(), ErrorDetection> {
        let canonical = self.canon_id(pid)?;
        let now = Self::now_unix_result()?;

        // Only accept heartbeats from active participants.
        if !self.active_participants.contains(&canonical) {
            return Err(ErrorDetection::NotFound {
                resource: format!("active participant {pid}"),
            });
        }

        self.last_active.insert(canonical, now);
        Ok(())
    }

    /// Convenience (read-only): lookup of last_active (canonicalized).
    pub fn last_active_of(&self, pid: &str) -> Option<u64> {
        let canonical = self.canon_id(pid).ok()?;
        self.last_active.get(&canonical).copied()
    }

    /// Paranoia: if booted sets grow too large, prune oldest by time.
    /// Bounded-memory policy; does not panic.
    fn enforce_boot_cap(&mut self) {
        let boot_cap = GlobalConfiguration::MAX_VALIDATORS.min(GlobalConfiguration::MAX_IDENTITIES);
        if self.booted_participants.len() <= boot_cap {
            return;
        }

        let mut entries: Vec<(String, u64)> = self
            .booted_at
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        entries.sort_by_key(|(_, t)| *t);

        let over = self.booted_participants.len().saturating_sub(boot_cap);
        for (pid, _) in entries.into_iter().take(over) {
            self.booted_participants.remove(&pid);
            self.booted_at.remove(&pid);
        }
    }

    /* ───────────────────────── tx-level rules ─────────────────────── */

    /// Detect duplicate tx-ids in the same batch (double spend).
    /// cap batch size to prevent DoS.
    pub fn detect_double_spend(
        &self,
        tx_ids: impl IntoIterator<Item = String>,
    ) -> Result<(), ErrorDetection> {
        let mut seen = HashSet::new();
        let mut count: usize = 0;

        let max_txs_per_block =
            usize::try_from(GlobalConfiguration::MAX_TXS_PER_BLOCK).unwrap_or(usize::MAX);

        for tx in tx_ids {
            count = count.saturating_add(1);
            if count > max_txs_per_block {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Too many tx_ids to scan for double-spend: {count} > {}",
                        GlobalConfiguration::MAX_TXS_PER_BLOCK
                    ),
                    tx_id: None,
                });
            }

            if !seen.insert(tx.clone()) {
                debug!("🚨 Double spend detected (tx_id = {tx})");
                return Err(ErrorDetection::DoubleSpending { tx_id: Some(tx) });
            }
        }
        Ok(())
    }

    /// Detect replay (duplicate (tx_id, sig) tuples or duplicate tx_id keys).
    /// cap items scanned to prevent DoS.
    pub fn detect_replay(
        &self,
        items: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Result<(), ErrorDetection> {
        let mut seen_keys = HashSet::new();
        let mut seen_pairs = HashSet::new();
        let mut count: usize = 0;

        let max_txs_per_block =
            usize::try_from(GlobalConfiguration::MAX_TXS_PER_BLOCK).unwrap_or(usize::MAX);

        for (tx, sig) in items {
            count = count.saturating_add(1);
            if count > max_txs_per_block {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Too many items to scan for replay: {count} > {}",
                        GlobalConfiguration::MAX_TXS_PER_BLOCK
                    ),
                    tx_id: None,
                });
            }

            // Check duplicate (tx_id, sig) pair.
            if !seen_pairs.insert((tx.clone(), sig.clone())) {
                return Err(ErrorDetection::InvalidOperation {
                    operation: format!("Replay attack (duplicate (tx_id, sig) pair: tx_id = {tx})"),
                });
            }
            // Check duplicate tx_id key.
            if !seen_keys.insert(tx.clone()) {
                return Err(ErrorDetection::InvalidOperation {
                    operation: format!("Replay attack (duplicate tx_id: {tx})"),
                });
            }
        }
        Ok(())
    }

    /* ──────────────────────── network threats ─────────────────────── */

    /// 51 % attack check using configured threshold.
    pub fn detect_51_percent_attack(
        &self,
        attacker_hash_rate: u64,
        total_hash_rate: u64,
    ) -> Result<(), ErrorDetection> {
        if total_hash_rate == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Total hash rate is zero; cannot compute percentage".into(),
                tx_id: None,
            });
        }

        // attacker_share_percent = attacker * 100 / total
        // detect if attacker_share_percent > ATTACK_THRESHOLD.
        let threshold_pct = GlobalConfiguration::ATTACK_THRESHOLD;

        // Compare attacker*100 > total*threshold using u128 to avoid overflow.
        let left = (attacker_hash_rate as u128).saturating_mul(100u128);
        let right = (total_hash_rate as u128).saturating_mul(threshold_pct as u128);

        if left > right {
            // Optional log percent as integer + fractional (2dp) using integer math.
            // percent_x100 = attacker * 10000 / total.
            let pct_x100 = (attacker_hash_rate as u128)
                .saturating_mul(10_000u128)
                .checked_div(total_hash_rate as u128)
                .unwrap_or(0);

            let pct_int = pct_x100.checked_div(100u128).unwrap_or(0);
            let pct_frac = pct_x100.checked_rem(100u128).unwrap_or(0);

            debug!(
                "🚨 51 % attack detected – attacker share = {}.{:02}%",
                pct_int, pct_frac
            );

            return Err(ErrorDetection::BlockchainError {
                details: format!("51% attack (attacker share = {}.{:02}%)", pct_int, pct_frac),
            });
        }

        Ok(())
    }

    /// Duplicate peer-ids in advertised node list → Sybil.
    /// canonicalize + cap scan.
    pub fn detect_sybil_attack(
        &self,
        nodes: impl IntoIterator<Item = (String, u64)>,
    ) -> Result<(), ErrorDetection> {
        let mut ids = HashSet::new();
        let mut count: usize = 0;

        for (id, _weight) in nodes {
            count = count.saturating_add(1);
            if count > GlobalConfiguration::MAX_IDENTITIES {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Too many node ids to scan for sybil: {count} > {}",
                        GlobalConfiguration::MAX_IDENTITIES
                    ),
                    tx_id: None,
                });
            }

            let canon = self.canon_id(&id)?;

            if !ids.insert(canon.clone()) {
                debug!("🚨 Sybil attack detected (duplicate id = {canon})");
                return Err(ErrorDetection::BlockchainError {
                    details: format!("Sybil attack: duplicate node id {canon}"),
                });
            }
        }
        Ok(())
    }

    /* ───────────────────────── block checks ───────────────────────── */

    pub fn check_block_size(&self, size: usize) -> Result<(), ErrorDetection> {
        let max_block_size =
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX);

        if size > max_block_size {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Block size {size} exceeds max {}",
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
                tx_id: None,
            });
        }
        Ok(())
    }

    pub fn check_block_hash_format(&self, hex_hash: &str) -> Result<(), ErrorDetection> {
        let h = hex_hash.trim();

        // Remzar migrated to 64-byte hashes, encoded as 128 lowercase hex chars.
        if h.len() != 128 || hex::decode(h).is_err() {
            return Err(ErrorDetection::ValidationError {
                message: format!("Invalid block hash {hex_hash}"),
                tx_id: None,
            });
        }
        Ok(())
    }

    /* ─────────────────────── data consistency ─────────────────────── */

    pub fn verify_dataset_consistency(
        &self,
        datasets: impl IntoIterator<Item = (String, bool)>,
    ) -> Result<(), ErrorDetection> {
        for (name, ok) in datasets {
            if !ok {
                return Err(ErrorDetection::ValidationError {
                    message: format!("Data inconsistency in {name}"),
                    tx_id: None,
                });
            }
        }
        Ok(())
    }

    /* ─────────────────────── system-wide sanity ───────────────────── */

    pub fn validate_system_state(&self) -> Result<DetectionOutcome, ErrorDetection> {
        let cap = self.effective_participant_cap();

        if (self.active_participants.len() as u64) > cap {
            return Ok(DetectionOutcome::Critical(
                "Active participants exceed maximum allowed".into(),
            ));
        }

        if self
            .booted_participants
            .intersection(&self.active_participants)
            .next()
            .is_some()
        {
            return Ok(DetectionOutcome::Critical(
                "Booted participants present in active set".into(),
            ));
        }

        if self.active_participants.is_empty() {
            return Ok(DetectionOutcome::Warning(
                "No active validators in the set".into(),
            ));
        }

        Ok(DetectionOutcome::Ok)
    }
}

impl Default for DetectionSystem {
    fn default() -> Self {
        Self::new()
    }
}
