// src/consensus/committee_eligibility.rs

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeMemberStatus {
    pub wallet: String,
    pub is_live: bool,
    pub has_synced: bool,
    pub local_tip: u64,
    pub network_tip: u64,
    pub peers_connected: usize,
    pub connected_wallet_peers: usize,
    pub is_isolated: bool,
}

impl CommitteeMemberStatus {
    #[must_use]
    pub fn canonical_wallet(&self) -> &str {
        &self.wallet
    }

    #[must_use]
    pub fn tip_lag(&self) -> u64 {
        self.network_tip.saturating_sub(self.local_tip)
    }

    pub fn validate_invariants(&self) -> Result<(), ErrorDetection> {
        let _ = canon_wallet_id_checked(&self.wallet)?;

        if self.connected_wallet_peers > self.peers_connected {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "CommitteeMemberStatus invariant failed for {}: connected_wallet_peers={} > peers_connected={}",
                    self.wallet, self.connected_wallet_peers, self.peers_connected
                ),
                tx_id: None,
            });
        }

        if self.is_isolated && self.connected_wallet_peers > 0 {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "CommitteeMemberStatus invariant failed for {}: is_isolated=true but connected_wallet_peers={}",
                    self.wallet, self.connected_wallet_peers
                ),
                tx_id: None,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitteeStatusUpdate {
    pub is_live: bool,
    pub has_synced: bool,
    pub local_tip: u64,
    pub network_tip: u64,
    pub peers_connected: usize,
    pub connected_wallet_peers: usize,
}

impl CommitteeStatusUpdate {
    #[must_use]
    pub fn is_isolated(self) -> bool {
        self.connected_wallet_peers == 0
    }

    pub fn validate_invariants(self) -> Result<(), ErrorDetection> {
        if self.connected_wallet_peers > self.peers_connected {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "CommitteeStatusUpdate invariant failed: connected_wallet_peers={} > peers_connected={}",
                    self.connected_wallet_peers, self.peers_connected
                ),
                tx_id: None,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeEligibilityDecision {
    pub wallet: String,
    pub eligible: bool,
    pub reasons: Vec<IneligibilityReason>,
}

impl CommitteeEligibilityDecision {
    #[must_use]
    pub fn eligible(wallet: String) -> Self {
        Self {
            wallet,
            eligible: true,
            reasons: Vec::new(),
        }
    }

    #[must_use]
    pub fn ineligible(wallet: String, reasons: Vec<IneligibilityReason>) -> Self {
        Self {
            wallet,
            eligible: false,
            reasons,
        }
    }

    #[must_use]
    pub fn is_runtime_ready(&self) -> bool {
        self.eligible
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IneligibilityReason {
    NotLive,
    NotSynced,
    TooFarBehind {
        lag: u64,
        max_allowed: u64,
    },
    NotEnoughPeers {
        connected: usize,
        min_required: usize,
    },
    NotEnoughWalletPeers {
        connected: usize,
        min_required: usize,
    },
    Isolated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeEligibilityConfig {
    pub max_tip_lag_blocks: u64,
    pub min_peers_connected: usize,
    pub min_connected_wallet_peers: usize,
    pub require_non_isolated: bool,
    pub require_synced: bool,
}

impl Default for CommitteeEligibilityConfig {
    fn default() -> Self {
        Self {
            max_tip_lag_blocks: 2,
            min_peers_connected: 0,
            min_connected_wallet_peers: 0,
            require_non_isolated: false,
            require_synced: false,
        }
    }
}

impl CommitteeEligibilityConfig {
    #[must_use]
    pub fn from_globals() -> Self {
        let _ = GlobalConfiguration::MAX_VALIDATORS;
        Self::default()
    }

    pub fn validate(&self) -> Result<(), ErrorDetection> {
        if self.min_connected_wallet_peers > self.min_peers_connected {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "CommitteeEligibilityConfig invalid: min_connected_wallet_peers={} > min_peers_connected={}",
                    self.min_connected_wallet_peers, self.min_peers_connected
                ),
                tx_id: None,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CommitteeEligibility {
    live_wallets: BTreeSet<String>,
    statuses: BTreeMap<String, CommitteeMemberStatus>,
    config: CommitteeEligibilityConfig,
}

impl CommitteeEligibility {
    pub fn new(config: CommitteeEligibilityConfig) -> Self {
        drop(config.validate());

        Self {
            live_wallets: BTreeSet::new(),
            statuses: BTreeMap::new(),
            config,
        }
    }

    #[must_use]
    pub fn with_default_config() -> Self {
        Self::new(CommitteeEligibilityConfig::from_globals())
    }

    #[must_use]
    pub fn config(&self) -> &CommitteeEligibilityConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut CommitteeEligibilityConfig {
        &mut self.config
    }

    pub fn validate_config(&self) -> Result<(), ErrorDetection> {
        self.config.validate()
    }

    pub fn clear(&mut self) {
        self.live_wallets.clear();
        self.statuses.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.statuses.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.statuses.is_empty() && self.live_wallets.is_empty()
    }

    #[must_use]
    pub fn live_wallets(&self) -> Vec<String> {
        self.live_wallets.iter().cloned().collect()
    }

    /// Replace the runtime live-wallet view.
    pub fn replace_live_wallets<I>(&mut self, wallets: I) -> Result<(), ErrorDetection>
    where
        I: IntoIterator<Item = String>,
    {
        let mut normalized = BTreeSet::new();
        for wallet in wallets {
            normalized.insert(canon_wallet_id_checked(&wallet)?);
        }
        self.live_wallets = normalized;
        Ok(())
    }

    pub fn mark_wallet_live(&mut self, wallet: &str, is_live: bool) -> Result<(), ErrorDetection> {
        let can = canon_wallet_id_checked(wallet)?;
        if is_live {
            self.live_wallets.insert(can);
        } else {
            self.live_wallets.remove(&can);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_wallet_live(&self, wallet: &str) -> bool {
        match canon_wallet_id_checked(wallet) {
            Ok(can) => self.live_wallets.contains(&can),
            Err(_) => false,
        }
    }

    #[must_use]
    pub fn get_status(&self, wallet: &str) -> Option<&CommitteeMemberStatus> {
        let can = canon_wallet_id_checked(wallet).ok()?;
        self.statuses.get(&can)
    }

    #[must_use]
    pub fn remove_wallet(&mut self, wallet: &str) -> bool {
        match canon_wallet_id_checked(wallet) {
            Ok(can) => {
                let a = self.statuses.remove(&can).is_some();
                let b = self.live_wallets.remove(&can);
                a || b
            }
            Err(_) => false,
        }
    }

    pub fn upsert_status(&mut self, status: CommitteeMemberStatus) -> Result<(), ErrorDetection> {
        self.validate_config()?;

        let can = canon_wallet_id_checked(&status.wallet)?;
        let normalized = CommitteeMemberStatus {
            wallet: can.clone(),
            ..status
        };

        normalized.validate_invariants()?;

        if normalized.is_live {
            self.live_wallets.insert(can.clone());
        } else {
            self.live_wallets.remove(&can);
        }

        self.statuses.insert(can, normalized);
        Ok(())
    }

    pub fn update_local_status(
        &mut self,
        wallet: &str,
        update: CommitteeStatusUpdate,
    ) -> Result<(), ErrorDetection> {
        self.validate_config()?;
        update.validate_invariants()?;

        let can = canon_wallet_id_checked(wallet)?;

        self.upsert_status(CommitteeMemberStatus {
            wallet: can,
            is_live: update.is_live,
            has_synced: update.has_synced,
            local_tip: update.local_tip,
            network_tip: update.network_tip,
            peers_connected: update.peers_connected,
            connected_wallet_peers: update.connected_wallet_peers,
            is_isolated: update.is_isolated(),
        })
    }

    pub fn update_remote_status(
        &mut self,
        wallet: &str,
        update: CommitteeStatusUpdate,
    ) -> Result<(), ErrorDetection> {
        self.validate_config()?;
        update.validate_invariants()?;

        let can = canon_wallet_id_checked(wallet)?;

        self.upsert_status(CommitteeMemberStatus {
            wallet: can,
            is_live: update.is_live,
            has_synced: update.has_synced,
            local_tip: update.local_tip,
            network_tip: update.network_tip,
            peers_connected: update.peers_connected,
            connected_wallet_peers: update.connected_wallet_peers,
            is_isolated: update.is_isolated(),
        })
    }

    /// Runtime/local mint-readiness decision for a wallet.
    #[must_use]
    pub fn decide_wallet(&self, wallet: &str) -> CommitteeEligibilityDecision {
        let can = match canon_wallet_id_checked(wallet) {
            Ok(w) => w,
            Err(_) => {
                return CommitteeEligibilityDecision::ineligible(
                    wallet.to_string(),
                    vec![IneligibilityReason::NotLive],
                );
            }
        };

        if !self.live_wallets.contains(&can) {
            return CommitteeEligibilityDecision::ineligible(
                can,
                vec![IneligibilityReason::NotLive],
            );
        }

        let status = match self.statuses.get(&can) {
            Some(s) => s,
            None => {
                // Conservative but rollout-friendly choice:
                // live wallet + no explicit runtime status => ready by default.
                return CommitteeEligibilityDecision::eligible(can);
            }
        };

        let mut reasons = Vec::new();

        if self.config.require_synced && !status.has_synced {
            reasons.push(IneligibilityReason::NotSynced);
        }

        let lag = status.tip_lag();
        if lag > self.config.max_tip_lag_blocks {
            reasons.push(IneligibilityReason::TooFarBehind {
                lag,
                max_allowed: self.config.max_tip_lag_blocks,
            });
        }

        if self.should_enforce_connectivity_checks(&can) {
            if status.peers_connected < self.config.min_peers_connected {
                reasons.push(IneligibilityReason::NotEnoughPeers {
                    connected: status.peers_connected,
                    min_required: self.config.min_peers_connected,
                });
            }

            if status.connected_wallet_peers < self.config.min_connected_wallet_peers {
                reasons.push(IneligibilityReason::NotEnoughWalletPeers {
                    connected: status.connected_wallet_peers,
                    min_required: self.config.min_connected_wallet_peers,
                });
            }

            if self.config.require_non_isolated && status.is_isolated {
                reasons.push(IneligibilityReason::Isolated);
            }
        }

        if reasons.is_empty() {
            CommitteeEligibilityDecision::eligible(can)
        } else {
            CommitteeEligibilityDecision::ineligible(can, reasons)
        }
    }

    /// Compatibility alias.
    #[must_use]
    pub fn is_wallet_eligible(&self, wallet: &str) -> bool {
        self.decide_wallet(wallet).eligible
    }

    /// Preferred explicit name for new call sites.
    #[must_use]
    pub fn is_wallet_runtime_ready(&self, wallet: &str) -> bool {
        self.decide_wallet(wallet).eligible
    }

    /// Compatibility helper retained for rollout.
    #[must_use]
    pub fn filter_candidates(&self, candidates: impl IntoIterator<Item = String>) -> Vec<String> {
        candidates
            .into_iter()
            .filter(|wallet| self.is_wallet_eligible(wallet))
            .collect()
    }

    /// Compatibility helper retained for rollout.
    #[must_use]
    pub fn filter_candidates_with_decisions(
        &self,
        candidates: impl IntoIterator<Item = String>,
    ) -> (Vec<String>, Vec<CommitteeEligibilityDecision>) {
        let mut kept = Vec::new();
        let mut decisions = Vec::new();

        for wallet in candidates {
            let decision = self.decide_wallet(&wallet);
            if decision.eligible {
                kept.push(wallet);
            }
            decisions.push(decision);
        }

        (kept, decisions)
    }

    /// Return all currently known runtime decisions for observability.
    #[must_use]
    pub fn all_runtime_decisions(&self) -> Vec<CommitteeEligibilityDecision> {
        let mut wallets: BTreeSet<String> = self.live_wallets.clone();
        wallets.extend(self.statuses.keys().cloned());

        wallets
            .into_iter()
            .map(|wallet| self.decide_wallet(&wallet))
            .collect()
    }

    #[must_use]
    fn live_validator_count(&self) -> usize {
        self.live_wallets.len()
    }

    #[must_use]
    fn is_local_solo_candidate(&self, wallet: &str) -> bool {
        self.live_wallets.len() == 1
            && self
                .live_wallets
                .first()
                .is_some_and(|only| only.eq_ignore_ascii_case(wallet))
    }

    #[must_use]
    fn should_enforce_connectivity_checks(&self, wallet: &str) -> bool {
        let live_count = self.live_validator_count();
        if live_count <= 1 {
            return false;
        }

        !self.is_local_solo_candidate(wallet)
    }
}
