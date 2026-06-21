// src/consensus/por_000_ephemeral_registration.rs

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::time_policy::TimePolicy;
use fips204::ml_dsa_65::PublicKey as VerifyingKey;
use fips204::traits::SerDes;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/* ============================ utilities ============================ */

#[inline]
fn validation_err(msg: String) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: msg,
        tx_id: None,
    }
}

#[inline]
fn now_unix() -> u64 {
    TimePolicy::now_unix_secs_runtime().unwrap_or(0)
}

#[inline]
fn ensure_under_cap(cur: usize, cap: usize, what: &str) -> Result<(), ErrorDetection> {
    if cur >= cap {
        return Err(validation_err(format!(
            "Ephemeral registry cap reached for {} (cur={}, cap={})",
            what, cur, cap
        )));
    }
    Ok(())
}

#[inline]
fn validate_peer_id_b58(peer_id_b58: &str) -> Result<(), ErrorDetection> {
    if peer_id_b58.is_empty() {
        return Err(validation_err("peer_id_b58 is empty".to_string()));
    }

    let max_len = GlobalConfiguration::MAX_PEER_ID_B58_LEN;
    if peer_id_b58.len() > max_len {
        return Err(validation_err(format!(
            "peer_id_b58 too long (len={}, max={})",
            peer_id_b58.len(),
            max_len
        )));
    }

    if !peer_id_b58.is_ascii() {
        return Err(validation_err("peer_id_b58 must be ASCII".to_string()));
    }

    Ok(())
}

/// Deterministic, case-insensitive sort.
fn canon_sort(v: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = v.into_iter().collect();
    v.sort_unstable_by(|a, b| {
        let al = a.to_ascii_lowercase();
        let bl = b.to_ascii_lowercase();
        match al.cmp(&bl) {
            std::cmp::Ordering::Equal => a.cmp(b),
            o => o,
        }
    });
    v
}

/// Address from verifying key: "r" + blake3_xof64(vk_bytes) as lowercase hex.
#[inline]
fn addr_from_vk(vk: &VerifyingKey) -> String {
    let vk_bytes = vk.clone().into_bytes();
    crate::utility::helper::derive_wallet_id_from_pubkey_bytes(&vk_bytes)
}

/* ========================== EphemeralRegistry ========================== */

#[derive(Default, Clone)]
pub struct EphemeralRegistry {
    /// Active validator wallets (canonical strings).
    pub wallets: BTreeSet<String>,

    /// Wallet -> first-seen / join height.
    ///
    /// This is membership metadata. It must NOT be overwritten by heartbeat tip
    /// snapshots.
    pub join_heights: BTreeMap<String, u64>,

    /// PeerId -> wallet
    pub identity_map: BTreeMap<String, String>,

    /// Optional wallet -> verifying key
    pub verifying_keys: BTreeMap<String, VerifyingKey>,

    /// Wallets that have heartbeated in the current heartbeat round.
    heartbeat_round_seen: BTreeSet<String>,

    /// Latest heartbeat tip snapshot for each wallet.
    ///
    /// This is runtime health metadata and is separate from `join_heights`.
    tip_snapshots: BTreeMap<String, u64>,

    /// Time-based liveness tracking (RAM-only), stored as unix seconds.
    last_seen_at: BTreeMap<String, u64>,
    joined_at: BTreeMap<String, u64>,
}

// Manual Debug to avoid requiring `VerifyingKey: Debug`.
impl core::fmt::Debug for EphemeralRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralRegistry")
            .field("wallets_len", &self.wallets.len())
            .field("join_heights_len", &self.join_heights.len())
            .field("identity_map_len", &self.identity_map.len())
            .field("verifying_keys_len", &self.verifying_keys.len())
            .field("heartbeat_round_seen_len", &self.heartbeat_round_seen.len())
            .field("tip_snapshots_len", &self.tip_snapshots.len())
            .field("last_seen_at_len", &self.last_seen_at.len())
            .field("joined_at_len", &self.joined_at.len())
            .finish()
    }
}

/// Back-compat alias.
pub type RegistryData = EphemeralRegistry;

impl EphemeralRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.wallets.clear();
        self.join_heights.clear();
        self.identity_map.clear();
        self.verifying_keys.clear();
        self.heartbeat_round_seen.clear();
        self.tip_snapshots.clear();
        self.last_seen_at.clear();
        self.joined_at.clear();
    }

    pub fn sorted_wallets(&self) -> Vec<String> {
        canon_sort(self.wallets.iter().cloned())
    }

    pub fn is_registered(&self, addr: &str) -> bool {
        match canon_wallet_id_checked(addr) {
            Ok(can) => self.wallets.contains(&can),
            Err(_) => false,
        }
    }

    pub fn wallet_for_peer(&self, peer_id_b58: &str) -> Option<String> {
        self.identity_map.get(peer_id_b58).cloned()
    }

    pub fn tip_snapshot(&self, addr: &str) -> Option<u64> {
        let can = canon_wallet_id_checked(addr).ok()?;
        self.tip_snapshots.get(&can).copied()
    }

    pub fn has_recent_tip_snapshot(&self, addr: &str, min_tip: u64) -> bool {
        self.tip_snapshot(addr).is_some_and(|tip| tip >= min_tip)
    }

    pub fn max_tip_snapshot(&self) -> Option<u64> {
        self.tip_snapshots.values().copied().max()
    }

    pub fn wallets_with_tip_at_least(&self, min_tip: u64) -> Vec<String> {
        self.sorted_wallets()
            .into_iter()
            .filter(|w| self.tip_snapshots.get(w).copied().unwrap_or(0) >= min_tip)
            .collect()
    }

    pub fn register_wallet_strict(
        &mut self,
        wallet_addr: &str,
        join_height: u64,
    ) -> Result<String, ErrorDetection> {
        ensure_under_cap(
            self.wallets.len(),
            GlobalConfiguration::MAX_VALIDATORS,
            "validators",
        )?;

        let addr = canon_wallet_id_checked(wallet_addr)?;

        if !self.wallets.insert(addr.clone()) {
            return Err(validation_err(format!(
                "Wallet {} already registered (ephemeral)",
                addr
            )));
        }

        self.join_heights.entry(addr.clone()).or_insert(join_height);
        self.heartbeat_round_seen.insert(addr.clone());

        let now = now_unix();
        self.last_seen_at.insert(addr.clone(), now);
        self.joined_at.entry(addr.clone()).or_insert(now);

        Ok(addr)
    }

    pub fn register_wallet_from_vk(
        &mut self,
        vk: &VerifyingKey,
        join_height: u64,
    ) -> Result<String, ErrorDetection> {
        ensure_under_cap(
            self.wallets.len(),
            GlobalConfiguration::MAX_VALIDATORS,
            "validators",
        )?;
        ensure_under_cap(
            self.verifying_keys.len(),
            GlobalConfiguration::MAX_VERIFYING_KEYS,
            "verifying_keys",
        )?;

        let addr = addr_from_vk(vk);

        if !self.wallets.insert(addr.clone()) {
            return Err(validation_err(format!(
                "Wallet {} already registered (ephemeral)",
                addr
            )));
        }

        self.join_heights.entry(addr.clone()).or_insert(join_height);
        self.verifying_keys.insert(addr.clone(), vk.clone());
        self.heartbeat_round_seen.insert(addr.clone());

        let now = now_unix();
        self.last_seen_at.insert(addr.clone(), now);
        self.joined_at.entry(addr.clone()).or_insert(now);

        Ok(addr)
    }

    pub fn associate_identity(
        &mut self,
        peer_id_b58: &str,
        wallet_addr: &str,
    ) -> Result<(), ErrorDetection> {
        validate_peer_id_b58(peer_id_b58)?;
        ensure_under_cap(
            self.identity_map.len(),
            GlobalConfiguration::MAX_IDENTITIES,
            "identity_map",
        )?;

        let can = canon_wallet_id_checked(wallet_addr)?;

        if !self.wallets.contains(&can) {
            return Err(validation_err(format!(
                "Wallet {} is not registered (ephemeral)",
                can
            )));
        }

        self.identity_map.insert(peer_id_b58.to_string(), can);
        Ok(())
    }

    pub fn set_join_height(
        &mut self,
        wallet_addr: &str,
        height: u64,
    ) -> Result<(), ErrorDetection> {
        let can = canon_wallet_id_checked(wallet_addr)?;

        if !self.wallets.contains(&can) {
            return Err(validation_err(format!(
                "Wallet {} is not registered (ephemeral)",
                can
            )));
        }

        self.join_heights.entry(can).or_insert(height);
        Ok(())
    }

    pub fn set_tip_snapshot(
        &mut self,
        wallet_addr: &str,
        tip_snapshot: u64,
    ) -> Result<(), ErrorDetection> {
        let can = canon_wallet_id_checked(wallet_addr)?;

        if !self.wallets.contains(&can) {
            return Err(validation_err(format!(
                "Wallet {} is not registered (ephemeral)",
                can
            )));
        }

        self.tip_snapshots.insert(can, tip_snapshot);
        Ok(())
    }

    pub fn eligible(&self, addr: &str, at_height: u64) -> bool {
        let can = match canon_wallet_id_checked(addr) {
            Ok(c) => c,
            Err(_) => return false,
        };

        match self.join_heights.get(&can) {
            Some(&jh) => {
                let delay = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
                at_height >= jh.saturating_add(delay)
            }
            None => false,
        }
    }

    pub fn lookup_verifying_key(&self, addr: &str) -> Option<VerifyingKey> {
        let can = canon_wallet_id_checked(addr).ok()?;
        self.verifying_keys.get(&can).cloned()
    }

    pub fn unregister_wallet(&mut self, wallet_addr: &str) -> bool {
        let addr = match canon_wallet_id_checked(wallet_addr) {
            Ok(a) => a,
            Err(_) => return false,
        };

        let existed = self.wallets.remove(&addr);
        if existed {
            self.join_heights.remove(&addr);
            self.verifying_keys.remove(&addr);
            self.heartbeat_round_seen.remove(&addr);
            self.tip_snapshots.remove(&addr);
            self.last_seen_at.remove(&addr);
            self.joined_at.remove(&addr);
            self.identity_map.retain(|_, w| w != &addr);
        }

        existed
    }

    pub fn unregister_by_peer(&mut self, peer_id_b58: &str) -> Option<String> {
        if validate_peer_id_b58(peer_id_b58).is_err() {
            return None;
        }

        if let Some(wallet) = self.identity_map.remove(peer_id_b58) {
            let addr = wallet;
            self.identity_map.retain(|_, w| w != &addr);
            self.wallets.remove(&addr);
            self.join_heights.remove(&addr);
            self.verifying_keys.remove(&addr);
            self.heartbeat_round_seen.remove(&addr);
            self.tip_snapshots.remove(&addr);
            self.last_seen_at.remove(&addr);
            self.joined_at.remove(&addr);
            Some(addr)
        } else {
            None
        }
    }

    pub fn evict_inactive_validators(&mut self, max_inactive: Duration, boot_grace: Duration) {
        let now = now_unix();
        let mut to_evict: Vec<String> = Vec::new();

        for wallet in &self.wallets {
            let last_seen = self.last_seen_at.get(wallet).copied().unwrap_or(0);

            let joined = self.joined_at.get(wallet).copied().unwrap_or(0);

            let since_last_secs = now.saturating_sub(last_seen);
            let since_join_secs = now.saturating_sub(joined);

            let since_last = Duration::from_secs(since_last_secs);
            let since_join = Duration::from_secs(since_join_secs);

            if since_join <= boot_grace {
                continue;
            }

            if since_last > max_inactive {
                to_evict.push(wallet.clone());
            }
        }

        for wallet in to_evict {
            self.wallets.remove(&wallet);
            self.join_heights.remove(&wallet);
            self.verifying_keys.remove(&wallet);
            self.heartbeat_round_seen.remove(&wallet);
            self.tip_snapshots.remove(&wallet);
            self.last_seen_at.remove(&wallet);
            self.joined_at.remove(&wallet);
            self.identity_map.retain(|_, w| w != &wallet);
        }
    }

    // ---------------------------------------------------------------------
    // HEARTBEAT-BASED LIVENESS
    // ---------------------------------------------------------------------

    pub fn begin_heartbeat_round(&mut self) {
        self.heartbeat_round_seen.clear();
    }

    pub fn note_heartbeat_round(
        &mut self,
        wallet_addr: &str,
        tip_snapshot: u64,
    ) -> Result<String, ErrorDetection> {
        ensure_under_cap(
            self.wallets.len(),
            GlobalConfiguration::MAX_VALIDATORS,
            "validators",
        )?;

        let addr = canon_wallet_id_checked(wallet_addr)?;

        self.heartbeat_round_seen.insert(addr.clone());
        self.wallets.insert(addr.clone());

        // Preserve previous join height if it already exists.
        // If the wallet is first seen only via heartbeat, leave a neutral 0
        // until proper registration/replay fills the real join height.
        self.join_heights.entry(addr.clone()).or_insert(0);

        // Store runtime tip metadata separately.
        self.tip_snapshots.insert(addr.clone(), tip_snapshot);

        let now = now_unix();
        self.last_seen_at.insert(addr.clone(), now);
        self.joined_at.entry(addr.clone()).or_insert(now);

        Ok(addr)
    }

    pub fn finalize_heartbeat_round(&mut self) {
        if self.heartbeat_round_seen.is_empty() {
            self.wallets.clear();
            self.join_heights.clear();
            self.identity_map.clear();
            self.verifying_keys.clear();
            self.tip_snapshots.clear();
            self.last_seen_at.clear();
            self.joined_at.clear();
            return;
        }

        self.wallets
            .retain(|addr| self.heartbeat_round_seen.contains(addr));

        self.join_heights
            .retain(|addr, _| self.wallets.contains(addr));
        self.verifying_keys
            .retain(|addr, _| self.wallets.contains(addr));
        self.tip_snapshots
            .retain(|addr, _| self.wallets.contains(addr));
        self.identity_map
            .retain(|_, wallet| self.wallets.contains(wallet));
        self.last_seen_at
            .retain(|addr, _| self.wallets.contains(addr));
        self.joined_at.retain(|addr, _| self.wallets.contains(addr));
    }

    // ---------------------------------------------------------------------
    // Snapshot & rebuild helpers
    // ---------------------------------------------------------------------

    pub fn snapshot_wallets_and_heights(&self) -> Vec<(String, u64)> {
        self.sorted_wallets()
            .into_iter()
            .map(|w| {
                let h = *self.join_heights.get(&w).unwrap_or(&0);
                (w, h)
            })
            .collect()
    }

    pub fn rebuild_from_snapshot<I>(&mut self, entries: I)
    where
        I: IntoIterator<Item = (String, Option<VerifyingKey>, u64)>,
    {
        self.clear();

        let mut applied: usize = 0;
        let cap = GlobalConfiguration::MAX_SNAPSHOT_ENTRIES;

        for (wallet, vk_opt, join_height) in entries {
            if applied >= cap {
                tracing::debug!(
                    "[EPHEMERAL] rebuild_from_snapshot: snapshot entry cap reached (cap={}); stopping apply",
                    cap
                );
                break;
            }

            let res = if let Some(vk) = vk_opt {
                self.register_wallet_from_vk(&vk, join_height)
            } else {
                self.register_wallet_strict(&wallet, join_height)
            };

            match res {
                Ok(addr) => {
                    let now = now_unix();
                    self.last_seen_at.insert(addr.clone(), now);
                    self.joined_at.entry(addr.clone()).or_insert(now);
                    applied = applied.saturating_add(1);
                }
                Err(e) => {
                    tracing::debug!(
                        "[EPHEMERAL] rebuild_from_snapshot: failed to register wallet={} at height={} : {:?}",
                        wallet,
                        join_height,
                        e
                    );
                }
            }
        }

        tracing::debug!(
            "[EPHEMERAL] rebuild_from_snapshot: applied snapshot; validators={}",
            self.wallets.len()
        );
    }

    pub fn rebuild_from_snapshot_checked<I>(&mut self, entries: I) -> Result<(), ErrorDetection>
    where
        I: IntoIterator<Item = (String, Option<VerifyingKey>, u64)>,
    {
        self.clear();

        let mut applied: usize = 0;
        let cap = GlobalConfiguration::MAX_SNAPSHOT_ENTRIES;

        for (wallet, vk_opt, join_height) in entries {
            if applied >= cap {
                return Err(validation_err(format!("Snapshot too large (cap={})", cap)));
            }

            let res = if let Some(vk) = vk_opt {
                self.register_wallet_from_vk(&vk, join_height)
            } else {
                self.register_wallet_strict(&wallet, join_height)
            };

            let addr = res.map_err(|e| {
                validation_err(format!(
                    "Snapshot entry failed (wallet={}, height={}): {:?}",
                    wallet, join_height, e
                ))
            })?;

            let now = now_unix();
            self.last_seen_at.insert(addr.clone(), now);
            self.joined_at.entry(addr.clone()).or_insert(now);
            applied = applied.saturating_add(1);
        }

        Ok(())
    }
}

/* =========================== NodeEphemeral =========================== */

#[derive(Clone)]
pub struct NodeEphemeral {
    inner: Arc<Mutex<EphemeralRegistry>>,
}

impl NodeEphemeral {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EphemeralRegistry::new())),
        }
    }

    pub fn from_registry(reg: EphemeralRegistry) -> Self {
        Self {
            inner: Arc::new(Mutex::new(reg)),
        }
    }

    pub fn ephemeral(&self) -> Arc<Mutex<EphemeralRegistry>> {
        self.inner.clone()
    }

    pub fn boot_clear(&self) {
        if let Ok(mut e) = self.inner.lock() {
            e.clear();
        }
    }

    pub fn boot_clear_result(&self) -> Result<(), ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => {
                e.clear();
                Ok(())
            }
            Err(_) => Err(validation_err(
                "EphemeralRegistry mutex poisoned (boot_clear)".to_string(),
            )),
        }
    }

    fn mutex_poison_error<T>() -> Result<T, ErrorDetection> {
        Err(validation_err(
            "EphemeralRegistry mutex poisoned".to_string(),
        ))
    }

    #[inline(always)]
    fn safe_log_id(value: &str) -> String {
        let trimmed = value.trim();

        if trimmed.is_empty() {
            return "empty".to_string();
        }

        let chars: Vec<char> = trimmed.chars().collect();
        let len = chars.len();

        if len <= 12 {
            return format!("len{}", len);
        }

        let head: String = chars.iter().take(6).copied().collect();
        let tail: String = chars.iter().skip(len.saturating_sub(6)).copied().collect();

        format!("{}...{}:len{}", head, tail, len)
    }

    pub fn register_wallet_strict(
        &self,
        wallet_addr: &str,
        join_height: u64,
    ) -> Result<String, ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => e.register_wallet_strict(wallet_addr, join_height),
            Err(_) => Self::mutex_poison_error(),
        }
    }

    pub fn register_wallet_from_vk(
        &self,
        vk: &VerifyingKey,
        join_height: u64,
    ) -> Result<String, ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => e.register_wallet_from_vk(vk, join_height),
            Err(_) => Self::mutex_poison_error(),
        }
    }

    pub fn map_peer_identity(
        &self,
        peer_id_b58: &str,
        wallet_addr: &str,
    ) -> Result<(), ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => e.associate_identity(peer_id_b58, wallet_addr),
            Err(_) => Self::mutex_poison_error(),
        }
    }

    pub fn set_join_height(&self, wallet_addr: &str, height: u64) -> Result<(), ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => e.set_join_height(wallet_addr, height),
            Err(_) => Self::mutex_poison_error(),
        }
    }

    pub fn set_tip_snapshot(
        &self,
        wallet_addr: &str,
        tip_snapshot: u64,
    ) -> Result<(), ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => e.set_tip_snapshot(wallet_addr, tip_snapshot),
            Err(_) => Self::mutex_poison_error(),
        }
    }

    pub fn tip_snapshot(&self, wallet_addr: &str) -> Option<u64> {
        match self.inner.lock() {
            Ok(e) => e.tip_snapshot(wallet_addr),
            Err(_) => None,
        }
    }

    pub fn max_tip_snapshot(&self) -> Option<u64> {
        match self.inner.lock() {
            Ok(e) => e.max_tip_snapshot(),
            Err(_) => None,
        }
    }

    pub fn wallets_with_tip_at_least(&self, min_tip: u64) -> Vec<String> {
        match self.inner.lock() {
            Ok(e) => e.wallets_with_tip_at_least(min_tip),
            Err(_) => Vec::new(),
        }
    }

    pub fn status_line(&self) -> String {
        let n = self.inner.lock().map(|e| e.wallets.len()).unwrap_or(0);
        format!("[REGISTRY=EPHEMERAL][PoR] validators={n}")
    }

    pub fn seed_from_chain_snapshot<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (String, Option<VerifyingKey>, u64)>,
    {
        if let Ok(mut reg) = self.inner.lock() {
            tracing::debug!(
                "[EPHEMERAL] seed_from_chain_snapshot: clearing existing registry (validators={})",
                reg.wallets.len()
            );
            reg.rebuild_from_snapshot(entries);
            tracing::debug!(
                "[EPHEMERAL] seed_from_chain_snapshot: registry rebuilt; validators={}",
                reg.wallets.len()
            );
        } else {
            tracing::debug!(
                "[EPHEMERAL] seed_from_chain_snapshot: FAILED (EphemeralRegistry mutex poisoned)"
            );
        }
    }

    pub fn seed_from_chain_snapshot_checked<I>(&self, entries: I) -> Result<(), ErrorDetection>
    where
        I: IntoIterator<Item = (String, Option<VerifyingKey>, u64)>,
    {
        match self.inner.lock() {
            Ok(mut reg) => reg.rebuild_from_snapshot_checked(entries),
            Err(_) => Err(validation_err(
                "EphemeralRegistry mutex poisoned (seed_from_chain_snapshot_checked)".to_string(),
            )),
        }
    }

    pub fn evict_inactive_validators(&self, max_inactive: Duration, boot_grace: Duration) {
        if let Ok(mut e) = self.inner.lock() {
            e.evict_inactive_validators(max_inactive, boot_grace);
        }
    }

    pub fn evict_inactive_validators_result(
        &self,
        max_inactive: Duration,
        boot_grace: Duration,
    ) -> Result<(), ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => {
                e.evict_inactive_validators(max_inactive, boot_grace);
                Ok(())
            }
            Err(_) => Err(validation_err(
                "EphemeralRegistry mutex poisoned (evict_inactive_validators)".to_string(),
            )),
        }
    }

    pub fn begin_heartbeat_round(&self) {
        if let Ok(mut e) = self.inner.lock() {
            e.begin_heartbeat_round();
        }
    }

    pub fn begin_heartbeat_round_result(&self) -> Result<(), ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => {
                e.begin_heartbeat_round();
                Ok(())
            }
            Err(_) => Err(validation_err(
                "EphemeralRegistry mutex poisoned (begin_heartbeat_round)".to_string(),
            )),
        }
    }

    pub fn note_heartbeat_round(
        &self,
        wallet_addr: &str,
        tip_snapshot: u64,
    ) -> Result<String, ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => e.note_heartbeat_round(wallet_addr, tip_snapshot),
            Err(_) => Self::mutex_poison_error(),
        }
    }

    pub fn finalize_heartbeat_round(&self) {
        if let Ok(mut e) = self.inner.lock() {
            e.finalize_heartbeat_round();
        }
    }

    pub fn finalize_heartbeat_round_result(&self) -> Result<(), ErrorDetection> {
        match self.inner.lock() {
            Ok(mut e) => {
                e.finalize_heartbeat_round();
                Ok(())
            }
            Err(_) => Err(validation_err(
                "EphemeralRegistry mutex poisoned (finalize_heartbeat_round)".to_string(),
            )),
        }
    }

    pub fn unregister_by_peer(&self, peer_id_b58: &str) -> Option<String> {
        match self.inner.lock() {
            Ok(mut e) => {
                let removed = e.unregister_by_peer(peer_id_b58);
                if let Some(ref wallet) = removed {
                    tracing::debug!(
                        "[EPHEMERAL] unregister_by_peer: removed wallet={} for peer={}",
                        Self::safe_log_id(wallet),
                        Self::safe_log_id(peer_id_b58)
                    );
                } else {
                    tracing::debug!(
                        "[EPHEMERAL] unregister_by_peer: no wallet mapped for peer={}",
                        Self::safe_log_id(peer_id_b58)
                    );
                }
                removed
            }
            Err(_) => {
                tracing::debug!(
                    "[EPHEMERAL] unregister_by_peer: FAILED (EphemeralRegistry mutex poisoned) for peer={}",
                    Self::safe_log_id(peer_id_b58)
                );
                None
            }
        }
    }

    pub fn unregister_wallet(&self, wallet_addr: &str) -> bool {
        match self.inner.lock() {
            Ok(mut e) => {
                let removed = e.unregister_wallet(wallet_addr);
                if removed {
                    tracing::debug!(
                        "[EPHEMERAL] unregister_wallet: removed wallet={}",
                        Self::safe_log_id(wallet_addr)
                    );
                } else {
                    tracing::debug!(
                        "[EPHEMERAL] unregister_wallet: wallet not present or invalid: {}",
                        Self::safe_log_id(wallet_addr)
                    );
                }
                removed
            }
            Err(_) => {
                tracing::debug!(
                    "[EPHEMERAL] unregister_wallet: FAILED (EphemeralRegistry mutex poisoned) for wallet={}",
                    Self::safe_log_id(wallet_addr)
                );
                false
            }
        }
    }
}

impl Default for NodeEphemeral {
    fn default() -> Self {
        Self::new()
    }
}
