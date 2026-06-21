//! Orchestration engine extracted from the unified orchestration loop.

use super::blockchain_002_orchestration_display::OrchestrationDisplay;
use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
use crate::consensus::por_000_ephemeral_registration::NodeEphemeral;
use crate::consensus::por_005_time_management::TimeManager;
use crate::consensus::por_006_committee_eligibility::CommitteeStatusUpdate;
use crate::network::p2p_006_reqresp::Hash;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::network::{
    p2p_003_behaviour::RemzarBehaviour, p2p_008_broadcast::Broadcaster,
    p2p_013_peer_mesh::PeerMeshAnnounce,
};
use crate::runtime::p2p_001_sync_builders::P2pSync;
use crate::runtime::p2p_001_sync_builders::REGISTRATION_TOPIC;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::{
    alpha_001_global_configuration::GlobalConfiguration,
    alpha_002_error_detection_system::ErrorDetection,
    helper::{canon_wallet_id_checked, has_quorum, quorum_threshold_checked},
    time_policy::TimePolicy,
};
use crate::{
    blockchain::{
        blockchain_001_builder::BlockchainBuilder, transaction_002_tx_register::RegisterNodeTx,
        transaction_004_tx_kind::TxKind, transaction_005_tx_account_tree::AccountModelTree,
        transaction_005_tx_batch::TransactionBatch,
    },
    reorganization::{
        reorg_001_block_index::ReorgBlockIndex, reorg_002_chain_view::ReorgChainView,
        reorg_004_batch_index::ReorgBatchIndex, reorg_005_fork_choice::ForkAction,
        reorg_006_manager::ReorgManager,
    },
    storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus},
};
use chrono::DateTime;
use fips204::ml_dsa_65;
use libp2p::swarm::Swarm;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as TokioMutex;

pub type SigningKey = ml_dsa_65::PrivateKey;

pub struct OrchestrationEngineArgs {
    pub db: Arc<RockDBManager>,
    pub node_ephemeral: NodeEphemeral,
    pub mempool: Arc<crate::blockchain::mempool::MemPool>,
    pub sync_engine: Arc<TokioMutex<P2pSync>>,
    pub signing_key: Arc<SigningKey>,
    pub tm: Arc<TimeManager>,
    pub reorg_manager: ReorgManager,
    pub local_wallet: String,
    pub console_bus: ConsoleBus,
}

/// Unified miner runtime state (canonical on-chain registry + EPHEMERAL
/// runtime registry + PoR-based mint orchestration).
pub struct OrchestrationEngine {
    pub db: Arc<RockDBManager>,
    pub node: NodeEphemeral,
    pub mempool: Arc<crate::blockchain::mempool::MemPool>,
    pub sync_engine: Arc<TokioMutex<P2pSync>>,
    pub signing_key: Arc<SigningKey>,
    pub tm: Arc<TimeManager>,
    pub local_wallet: String,
    pub reorg_manager: ReorgManager,
    pub ever_seen_wallet_peer: AtomicBool,
    pub mining_intent: bool,
    pub registry_heartbeat_secs: Option<u64>,
    pub last_canonical_register_tip: AtomicU64,
    pub display: OrchestrationDisplay,
}

#[derive(Debug, Clone, Copy)]
struct MintSyncSnapshot {
    has_synced: bool,
    is_syncing: bool,
    has_background_sync_work: bool,
    last_synced_index: Option<u64>,
}

impl MintSyncSnapshot {
    #[inline(always)]
    fn proposal_ready(self) -> bool {
        self.has_synced && !self.is_syncing && !self.has_background_sync_work
    }
}

/// Founder/offline reboot repair scan limit.
const MAX_FOUNDER_REBOOT_TIP_REPAIR_SCAN_DEPTH: u64 = 512;

impl OrchestrationEngine {
    /// Runtime-only UTC timestamp for logs and terminal output.
    fn runtime_log_timestamp() -> String {
        match TimePolicy::now_unix_secs_runtime() {
            Ok(now_unix) => {
                let Ok(now_i64) = i64::try_from(now_unix) else {
                    return format!("unix:{now_unix}");
                };

                DateTime::from_timestamp(now_i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| format!("unix:{now_unix}"))
            }
            Err(..) => "time_unavailable".to_string(),
        }
    }

    /// Redacted wallet fingerprint for operator diagnostics.
    fn safe_wallet_id(wallet: &str) -> String {
        let trimmed = wallet.trim();

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

    /// Short hash for safe production diagnostics.
    fn short_hash(hash: &[u8; 64]) -> String {
        const SHORT_HASH_EDGE_BYTES: usize = 4;
        const SHORT_HASH_FULL_BYTES: usize = 8;

        let hash_bytes: &[u8] = hash.as_ref();

        if hash_bytes.len() <= SHORT_HASH_FULL_BYTES {
            return hex::encode(hash_bytes);
        }

        let Some(prefix) = hash_bytes.get(..SHORT_HASH_EDGE_BYTES) else {
            return hex::encode(hash_bytes);
        };

        let suffix_start = hash_bytes.len().saturating_sub(SHORT_HASH_EDGE_BYTES);
        let Some(suffix) = hash_bytes.get(suffix_start..) else {
            return hex::encode(hash_bytes);
        };

        format!("{}...{}", hex::encode(prefix), hex::encode(suffix))
    }

    pub fn new(args: OrchestrationEngineArgs) -> Self {
        Self {
            display: OrchestrationDisplay::new(Arc::clone(&args.db), args.console_bus),
            db: args.db,
            node: args.node_ephemeral,
            mempool: args.mempool,
            sync_engine: args.sync_engine,
            signing_key: args.signing_key,
            tm: args.tm,
            local_wallet: canon_wallet_id_checked(&args.local_wallet)
                .unwrap_or_else(|_| args.local_wallet.clone()),
            reorg_manager: args.reorg_manager,
            ever_seen_wallet_peer: AtomicBool::new(false),
            mining_intent: true,
            registry_heartbeat_secs: Some(GlobalConfiguration::HEARTBEAT_TX_INTERVAL_SECS),
            last_canonical_register_tip: AtomicU64::new(u64::MAX),
        }
    }

    fn local_wallet_live_in_ephemeral(&self) -> bool {
        let reg = self.node.ephemeral();
        match reg.lock() {
            Ok(e) => e.is_registered(&self.local_wallet),
            Err(_) => false,
        }
    }

    fn ephemeral_wallet_count(&self) -> usize {
        let reg = self.node.ephemeral();
        match reg.lock() {
            Ok(e) => e.sorted_wallets().len(),
            Err(_) => 0,
        }
    }

    fn connected_wallet_peers(&self, sw: &Swarm<RemzarBehaviour>) -> usize {
        let reg = self.node.ephemeral();
        match reg.lock() {
            Ok(e) => sw
                .connected_peers()
                .filter_map(|peer_id| e.wallet_for_peer(&peer_id.to_base58()))
                .filter(|w| !w.trim().is_empty())
                .count(),
            Err(_) => 0,
        }
    }

    fn build_local_peer_mesh_announce(
        &self,
        swarm: &Swarm<RemzarBehaviour>,
    ) -> Result<PeerMeshAnnounce, ErrorDetection> {
        let peer_id = *swarm.local_peer_id();
        let listen_addrs: Vec<_> = swarm.listeners().cloned().collect();

        let timestamp_unix =
            TimePolicy::now_unix_secs_runtime().map_err(|e| ErrorDetection::ProtocolError {
                message: format!(
                    "Failed to derive peer mesh announce timestamp via TimePolicy: {e:?}"
                ),
            })?;

        PeerMeshAnnounce::from_local(
            peer_id,
            &listen_addrs,
            if self.local_wallet.trim().is_empty() {
                None
            } else {
                Some(self.local_wallet.as_str())
            },
            timestamp_unix,
        )
        .map_err(|e| ErrorDetection::ProtocolError {
            message: format!("Failed to build local PeerMeshAnnounce: {e}"),
        })
    }

    /// Allow exactly one canonical register/renew emission per observed local tip height.
    fn should_emit_canonical_register_for_tip(&self, tip_now: u64) -> bool {
        self.last_canonical_register_tip
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |prev| {
                if prev != u64::MAX
                    && tip_now.saturating_sub(prev)
                        < GlobalConfiguration::CANONICAL_RENEW_INTERVAL_BLOCKS
                {
                    None
                } else {
                    Some(tip_now)
                }
            })
            .is_ok()
    }

    /// Stage and gossip the canonical RegisterNode renew tx.
    fn emit_canonical_register_renewal(&self, swarm: &mut Swarm<RemzarBehaviour>, tip_now: u64) {
        if self.local_wallet.is_empty() {
            return;
        }

        if !self.local_wallet_live_in_ephemeral() {
            return;
        }

        if !self.should_emit_canonical_register_for_tip(tip_now) {
            return;
        }

        let reg_tx = match RegisterNodeTx::new(self.local_wallet.clone()) {
            Ok(tx) => tx,
            Err(..) => {
                return;
            }
        };

        let kind = TxKind::RegisterNode(reg_tx);

        if kind.validate().is_err() {
            return;
        }

        drop(self.mempool.add_tx_kind(&kind));

        let has_subscribers = swarm.behaviour().gossipsub.all_peers().next().is_some();

        if !has_subscribers {
            return;
        }

        drop(Broadcaster::new(swarm).send_tx_kind(&kind));
    }

    fn update_local_runtime_mint_policy(
        &self,
        miner: &mut BlockchainBuilder,
        has_synced: bool,
        local_tip: u64,
        network_tip: u64,
        peers_connected: usize,
        connected_wallet_peers: usize,
    ) {
        let is_live = self.local_wallet_live_in_ephemeral();

        let update = CommitteeStatusUpdate {
            is_live,
            has_synced,
            local_tip,
            network_tip,
            peers_connected,
            connected_wallet_peers,
        };

        if let Err(e) = update.validate_invariants() {
            tracing::debug!(
                "{} [RUNTIME_POLICY] WARN: invalid local runtime status wallet={} err={:?}",
                Self::runtime_log_timestamp(),
                self.local_wallet,
                e
            );
            return;
        }

        if let Err(e) = miner
            .consensus_mut()
            .committee_eligibility_mut()
            .update_local_status(&self.local_wallet, update)
        {
            tracing::debug!(
                "{} [RUNTIME_POLICY] WARN: failed to update local runtime mint policy wallet={} err={:?}",
                Self::runtime_log_timestamp(),
                self.local_wallet,
                e
            );
        }
    }

    fn should_self_demote_from_advertising(
        &self,
        _validators_now: usize,
        _has_synced: bool,
        _connected_wallet_peers: usize,
    ) -> bool {
        false
    }

    async fn mint_sync_snapshot(&self) -> MintSyncSnapshot {
        let syn = self.sync_engine.lock().await;

        MintSyncSnapshot {
            has_synced: syn.has_synced(),
            is_syncing: syn.is_syncing(),
            has_background_sync_work: syn.has_background_sync_work(),
            last_synced_index: syn.last_synced_index(),
        }
    }

    fn clear_staged_local_puzzle_proof(&self, miner: &mut BlockchainBuilder, reason: &str) {
        if let Some(proof) = miner.take_pending_puzzle_proof() {
            tracing::debug!(
                "{} [MINT][POR][DROP] clearing staged local puzzle proof reason={} height={} validator_local={} prev_hash_present={}",
                Self::runtime_log_timestamp(),
                reason,
                proof.height,
                proof.validator.eq_ignore_ascii_case(&self.local_wallet),
                proof.prev_block_hash != [0u8; 64],
            );
        }
    }

    fn verify_block_is_hash_indexed(&self, height: u64, hash: Hash) -> bool {
        self.db
            .get_block_by_hash(&hash)
            .map(|block| block.metadata.index == height && block.block_hash == hash)
            .unwrap_or(false)
    }

    fn truncate_legacy_canonical_projection_above_tip(&self, new_tip: u64, old_tip: u64) -> bool {
        if old_tip <= new_tip {
            return true;
        }

        let mut ok = true;

        for stale_h in new_tip.saturating_add(1)..=old_tip {
            let block_key = format!("block_{:010}", stale_h);
            if let Err(e) = self.db.delete(
                GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
                block_key.as_bytes(),
            ) {
                ok = false;
                tracing::debug!(
                    "{} [FOUNDER][REBOOT][REPAIR] ERROR: failed to delete stale block projection h={} key={} err={:?}",
                    Self::runtime_log_timestamp(),
                    stale_h,
                    block_key,
                    e
                );
            }

            let batch_key = format!("tx_batch_{:010}", stale_h);
            drop(self.db.delete(
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                batch_key.as_bytes(),
            ));
        }

        if let Err(e) = self
            .db
            .delete_canonical_hash_range(new_tip.saturating_add(1), old_tip)
        {
            ok = false;
            tracing::debug!(
                "{} [FOUNDER][REBOOT][REPAIR] ERROR: failed to delete stale canonical hash range {}..={} err={:?}",
                Self::runtime_log_timestamp(),
                new_tip.saturating_add(1),
                old_tip,
                e
            );
        }

        ok
    }

    /// Founder/node-1 reboot recovery preflight.
    fn repair_founder_reboot_tip_for_mint(
        &self,
        chain: &mut AccountModelTree,
        miner: &mut BlockchainBuilder,
        reason: &str,
    ) -> bool {
        let original_tip = self.db.get_tip_height().unwrap_or(0);
        let scan_floor = original_tip.saturating_sub(MAX_FOUNDER_REBOOT_TIP_REPAIR_SCAN_DEPTH);
        let chain_view = ReorgChainView::new(Arc::clone(&self.db));
        let block_index = ReorgBlockIndex::new(Arc::clone(&self.db));

        tracing::debug!(
            "{} [BOOTSTRAP][REBOOT][PREFLIGHT] reason={} original_tip={} scan_floor={} action=verify_local_parent_before_mint",
            Self::runtime_log_timestamp(),
            reason,
            original_tip,
            scan_floor,
        );

        for height in (scan_floor..=original_tip).rev() {
            let block = match self.db.get_block_by_index(height) {
                Ok(Some(block)) => block,
                Ok(None) => {
                    if height == original_tip {
                        tracing::debug!(
                            "{} [FOUNDER][REBOOT][REPAIR] current tip block missing by height h={}; scanning backward",
                            Self::runtime_log_timestamp(),
                            height,
                        );
                    }
                    continue;
                }
                Err(_) => {
                    continue;
                }
            };

            let hash = block.block_hash;
            let bytes = match block.serialize_for_storage() {
                Ok(bytes) => bytes,
                Err(_) => {
                    continue;
                }
            };

            let mut repaired_hash_index = false;

            if !self.verify_block_is_hash_indexed(height, hash) {
                tracing::debug!(
                    "{} [FOUNDER][REBOOT][REPAIR] missing/stale block_by_hash for local canonical block h={} hash={}; rebuilding hash index from block_{{height}} bytes",
                    Self::runtime_log_timestamp(),
                    height,
                    hex::encode(hash),
                );

                if self.db.index_block_by_hash(&hash, &bytes).is_err() {
                    continue;
                }

                repaired_hash_index = true;

                if !self.verify_block_is_hash_indexed(height, hash) {
                    continue;
                }
            }

            if height < original_tip {
                tracing::debug!(
                    "{} [BOOTSTRAP][REBOOT][REPAIR] current tip unusable; rolling local canonical tip back from h={} to h={} action=rollback_to_usable_parent",
                    Self::runtime_log_timestamp(),
                    original_tip,
                    height,
                );

                if chain.reload_from_db_to_height(height).is_err() {
                    continue;
                }

                if !self.truncate_legacy_canonical_projection_above_tip(height, original_tip) {
                    miner.consensus_mut().clear_runtime_canonical_tip_context();
                    return false;
                }

                drop(chain.commit());

                drop(chain.flush_balances());
            }

            if self.db.set_latest_block_index(height).is_err() {
                miner.consensus_mut().clear_runtime_canonical_tip_context();
                return false;
            }

            if self.db.set_tip_height(height).is_err() {
                miner.consensus_mut().clear_runtime_canonical_tip_context();
                return false;
            }

            if self.db.set_addr_index_height(height).is_err() {
                miner.consensus_mut().clear_runtime_canonical_tip_context();
                return false;
            }

            if chain_view.set_hash_at_height(height, &hash).is_err() {
                miner.consensus_mut().clear_runtime_canonical_tip_context();
                return false;
            }

            if chain_view.set_tip(&hash, height).is_err() {
                miner.consensus_mut().clear_runtime_canonical_tip_context();
                return false;
            }

            if let Ok(true) = block_index.has_meta(&hash) {
                drop(block_index.mark_canonical(&hash));
            }

            if repaired_hash_index || height < original_tip {
                self.clear_staged_local_puzzle_proof(
                    miner,
                    "bootstrap reboot repaired canonical tip storage before mint",
                );
            }

            miner
                .consensus_mut()
                .reset_runtime_proposal_safety_state(height, hash);

            drop(self.db.flush_blockchain_db());

            tracing::debug!(
                "{} [BOOTSTRAP][REBOOT][READY] reason={} canonical_tip={} hash_index_ok={} repaired_hash_index={} rolled_back={}",
                Self::runtime_log_timestamp(),
                reason,
                height,
                true,
                repaired_hash_index,
                height < original_tip,
            );

            return true;
        }

        tracing::debug!(
            "{} [BOOTSTRAP][REBOOT][FATAL] no usable local canonical tip found; mint disabled until local DB is repaired/restored original_tip={} scan_floor={}",
            Self::runtime_log_timestamp(),
            original_tip,
            scan_floor,
        );
        false
    }

    fn refresh_miner_validator_state(
        &self,
        chain: &mut AccountModelTree,
        miner: &mut BlockchainBuilder,
        reason: &str,
    ) -> bool {
        if !self.repair_founder_reboot_tip_for_mint(chain, miner, reason) {
            return false;
        }

        match miner.validator_state_mut().rebuild_from_chain(None) {
            Ok(()) => {
                let tip_now = self.db.get_tip_height().unwrap_or(0);

                miner
                    .consensus_mut()
                    .note_validator_state_rebuilt_to_tip(tip_now);

                match self.db.get_block_by_index(tip_now).ok().flatten() {
                    Some(tip_block)
                        if self.verify_block_is_hash_indexed(tip_now, tip_block.block_hash) =>
                    {
                        miner
                            .consensus_mut()
                            .set_runtime_canonical_tip_context(tip_now, tip_block.block_hash);

                        tracing::debug!(
                            "{} [VALIDATORS] refreshed canonical ValidatorState from chain ({}) and aligned consensus safety to VERIFIED tip={} hash_indexed=true",
                            Self::runtime_log_timestamp(),
                            reason,
                            tip_now,
                        );
                    }
                    Some(_tip_block) => {
                        miner.consensus_mut().clear_runtime_canonical_tip_context();

                        tracing::debug!(
                            "{} [VALIDATORS] ERROR: rebuilt ValidatorState but tip hash is not indexed h={} hash_indexed=false; refusing to mint this tick",
                            Self::runtime_log_timestamp(),
                            tip_now,
                        );
                        return false;
                    }
                    None => {
                        miner.consensus_mut().clear_runtime_canonical_tip_context();

                        tracing::debug!(
                            "{} [VALIDATORS] refreshed canonical ValidatorState from chain ({}) but could not load canonical tip block at height {}; cleared runtime tip context",
                            Self::runtime_log_timestamp(),
                            reason,
                            tip_now
                        );
                        return false;
                    }
                }

                true
            }
            Err(e) => {
                tracing::debug!(
                    "{} [VALIDATORS] WARN: failed to rebuild canonical ValidatorState from chain ({}): {:?}",
                    Self::runtime_log_timestamp(),
                    reason,
                    e
                );
                false
            }
        }
    }

    pub fn refresh_wallet_peer_latch(&self, sw: &Swarm<RemzarBehaviour>) {
        if self.ever_seen_wallet_peer.load(Ordering::Relaxed) {
            return;
        }

        let connected_wallet_peers_now = self.connected_wallet_peers(sw);

        if connected_wallet_peers_now > 0 {
            self.ever_seen_wallet_peer.store(true, Ordering::Relaxed);
            tracing::debug!(
                "{} [REBOOT] latch armed: observed connected wallet peer(s) during runtime (count={})",
                Self::runtime_log_timestamp(),
                connected_wallet_peers_now
            );
        }
    }

    pub async fn seed_sync(&self, swarm: &mut Swarm<RemzarBehaviour>) {
        tracing::debug!(
            "{} Seed sync: polling peers for height…",
            Self::runtime_log_timestamp()
        );
        let mut syn = self.sync_engine.lock().await;
        syn.poll_peers_for_height(swarm);
    }

    pub fn initialize_miner(&self) -> Option<BlockchainBuilder> {
        tracing::debug!(
            "{} Miner init: intent={} wallet_present={}",
            Self::runtime_log_timestamp(),
            self.mining_intent,
            !self.local_wallet.is_empty()
        );

        if self.local_wallet.is_empty() || !self.mining_intent {
            return None;
        }

        let present = {
            let reg = self.node.ephemeral();
            match reg.lock() {
                Ok(e) => e.is_registered(&self.local_wallet),
                Err(_) => {
                    tracing::debug!(
                        "{} [EPHEMERAL] WARN: registry mutex poisoned during miner init; disabling miner",
                        Self::runtime_log_timestamp()
                    );
                    false
                }
            }
        };

        tracing::debug!(
            "{} [EPHEMERAL] contains_local_wallet={}",
            Self::runtime_log_timestamp(),
            present
        );

        if !present {
            return None;
        }

        let signing_key = Arc::clone(&self.signing_key);

        match BlockchainBuilder::new(
            Arc::clone(&self.db),
            Arc::clone(&self.mempool),
            self.local_wallet.clone(),
            Arc::clone(&self.tm),
            signing_key,
        ) {
            Ok(mut m) => {
                if let Err(e) = m.validator_state_mut().rebuild_from_chain(None) {
                    tracing::debug!(
                        "{} [VALIDATORS] WARN: failed to rebuild ValidatorState from chain at startup: {:?}",
                        Self::runtime_log_timestamp(),
                        e
                    );
                }

                match m.validator_state_mut().multi_validator_ever_seen() {
                    Ok(v) => {
                        tracing::debug!(
                            "{} [CONSENSUS] multi_validator_ever_seen(canonical)={}",
                            Self::runtime_log_timestamp(),
                            v
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            "{} [CONSENSUS] WARN: failed to read multi_validator_ever_seen(canonical): {:?}",
                            Self::runtime_log_timestamp(),
                            e
                        );
                    }
                }

                tracing::debug!("{} Miner constructed OK", Self::runtime_log_timestamp());
                Some(m)
            }
            Err(_) => None,
        }
    }

    pub fn print_new_blocks_since(
        &self,
        chain: &AccountModelTree,
        last_logged_tip: &mut u64,
        last_minted_height: &mut Option<u64>,
    ) {
        self.display
            .print_new_blocks_since(chain, last_logged_tip, last_minted_height);
    }

    /// Persist a newly accepted local block into the reorg/fork graph.
    fn persist_local_block_into_reorg_graph(
        &self,
        block: &crate::blockchain::block_002_blocks::Block,
        old_tip_height: u64,
        old_tip_hash: Option<Hash>,
        maybe_batch_bytes: Option<&[u8]>,
    ) -> Result<(), ErrorDetection> {
        let block_index = ReorgBlockIndex::new(Arc::clone(&self.db));
        let chain_view = ReorgChainView::new(Arc::clone(&self.db));
        let batch_index = ReorgBatchIndex::new(Arc::clone(&self.db));

        let cumulative_score = match block_index.get_meta(&block.metadata.previous_hash)? {
            Some(parent_meta) => parent_meta.cumulative_score.saturating_add(1),
            None => block.metadata.index as u128,
        };

        let meta = ForkBlockMeta {
            parent_hash: block.metadata.previous_hash,
            height: block.metadata.index,
            cumulative_score,
            status: ForkBlockStatus::Validated,
            received_at_unix_secs: TimePolicy::now_unix_secs_runtime()?,
        };

        block_index.ingest_validated_block(block, meta, maybe_batch_bytes)?;

        let extends_old_canonical_tip = old_tip_hash
            .is_some_and(|h| h == block.metadata.previous_hash)
            && block.metadata.index == old_tip_height.saturating_add(1);

        if extends_old_canonical_tip {
            chain_view.set_hash_at_height(block.metadata.index, &block.block_hash)?;
            block_index.mark_canonical(&block.block_hash)?;
            chain_view.set_tip(&block.block_hash, block.metadata.index)?;

            if let Some(batch_bytes) = maybe_batch_bytes {
                batch_index.set_canonical_batch_at_height(block.metadata.index, batch_bytes)?;
            }

            tracing::debug!(
                "{} [REORG][INGEST] local canonical ingest complete height={} hash_present=true status=canonical",
                Self::runtime_log_timestamp(),
                block.metadata.index,
            );
        } else {
            block_index.mark_side_branch(&block.block_hash)?;

            tracing::debug!(
                "{} [REORG][INGEST] local block stored height={} hash_present=true status=side_branch_candidate",
                Self::runtime_log_timestamp(),
                block.metadata.index,
            );
        }

        Ok(())
    }

    /// Shared mint attempt body used by both:
    /// - the normal slot-boundary mint tick
    /// - the in-slot failover retry tick
    #[allow(clippy::too_many_arguments)]
    async fn handle_mint_attempt_common(
        &self,
        chain: &mut AccountModelTree,
        swarm: &mut Swarm<RemzarBehaviour>,
        miner: &mut Option<BlockchainBuilder>,
        last_logged_tip: &mut u64,
        last_minted_height: &mut Option<u64>,
        attempt_ticks: &mut u64,
        is_founder_mode: bool,
        attempt_label: &'static str,
        is_failover_retry: bool,
    ) {
        *attempt_ticks = (*attempt_ticks).saturating_add(1);

        tracing::debug!(
            "{} [{} #{}] entering mint branch",
            Self::runtime_log_timestamp(),
            attempt_label,
            *attempt_ticks
        );

        if is_failover_retry {
            tracing::debug!(
                "{} [FAILOVER RETRY] same-slot canonical retry; outer_block_interval={}s failover_window={}s",
                Self::runtime_log_timestamp(),
                self.tm.block_interval().as_secs(),
                self.tm.failover_window_secs().max(1)
            );
        }

        if let Some(miner) = miner {
            let validators_len: usize;
            {
                let reg = self.node.ephemeral();
                match reg.lock() {
                    Ok(e) => {
                        let snapshot = e.clone();
                        let ws = e.sorted_wallets();

                        miner.set_registry(snapshot);

                        validators_len = ws.len();
                    }
                    Err(_) => {
                        tracing::debug!(
                            "{} [EPHEMERAL] ERROR: registry mutex poisoned; skipping mint tick",
                            Self::runtime_log_timestamp()
                        );
                        self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                        return;
                    }
                }
            }

            if !self.refresh_miner_validator_state(chain, miner, "mint_tick_preflight") {
                self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                return;
            }

            let connected_peers = swarm.connected_peers().count();
            let gossip_mesh_peers = swarm.behaviour().gossipsub.all_peers().count();
            let connected_wallet_peers = self.connected_wallet_peers(swarm);
            let tip_now = self.db.get_tip_height().unwrap_or(0);

            let multi_validator_ever_seen = match miner
                .validator_state_mut()
                .multi_validator_ever_seen()
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(
                        "{} [CONSENSUS] WARN: failed to read multi_validator_ever_seen(canonical); defaulting to true (safe). err={:?}",
                        Self::runtime_log_timestamp(),
                        e
                    );
                    true
                }
            };

            let allow_solo_genesis = {
                let reg = self.node.ephemeral();
                match reg.lock() {
                    Ok(e) => {
                        let ws = e.sorted_wallets();

                        let is_solo_wallet = ws.len() == 1
                            && ws
                                .first()
                                .is_some_and(|w| w.eq_ignore_ascii_case(&self.local_wallet));

                        let allow = is_founder_mode && is_solo_wallet && !multi_validator_ever_seen;

                        tracing::debug!(
                            "{} [MINT] bootstrap_guard: bootstrap_mode={} local_only_validator={} wallets={} tip_now={} peers_connected={} multi_validator_ever_seen(canonical)={} decision={}",
                            Self::runtime_log_timestamp(),
                            is_founder_mode,
                            is_solo_wallet,
                            ws.len(),
                            tip_now,
                            connected_peers,
                            multi_validator_ever_seen,
                            if allow { "allow" } else { "deny" }
                        );

                        allow
                    }
                    Err(_) => {
                        tracing::debug!(
                            "{} [MINT] ERROR: registry mutex poisoned while computing bootstrap_guard; bootstrap_path_allowed=false this tick",
                            Self::runtime_log_timestamp()
                        );
                        false
                    }
                }
            };

            tracing::debug!(
                "{} [MINT] peers_connected={} gossip_mesh_peers={} bootstrap_path_allowed={}",
                Self::runtime_log_timestamp(),
                connected_peers,
                gossip_mesh_peers,
                allow_solo_genesis
            );

            let next_h = tip_now.saturating_add(1);
            let slot_now = match TimePolicy::now_unix_secs_runtime() {
                Ok(now_unix) => self.tm.current_slot(now_unix),
                Err(e) => {
                    tracing::debug!(
                        "{} [MINT] ERROR: runtime time unavailable while deriving current slot via TimePolicy: {:?}",
                        Self::runtime_log_timestamp(),
                        e
                    );
                    self.clear_staged_local_puzzle_proof(
                        miner,
                        "runtime time unavailable while deriving slot",
                    );
                    self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                    return;
                }
            };

            tracing::debug!(
                "{} [MINT] tip_now={} next_h={} slot_now={} (rule: allow if slot_now+1 >= next_h)",
                Self::runtime_log_timestamp(),
                tip_now,
                next_h,
                slot_now
            );

            let sync_snapshot = self.mint_sync_snapshot().await;
            let sync_in_progress_now =
                sync_snapshot.is_syncing || sync_snapshot.has_background_sync_work;

            tracing::debug!(
                "{} [MINT] sync_gate: has_synced={} is_syncing={} background_sync={} last_synced_index={:?}",
                Self::runtime_log_timestamp(),
                sync_snapshot.has_synced,
                sync_snapshot.is_syncing,
                sync_snapshot.has_background_sync_work,
                sync_snapshot.last_synced_index,
            );

            let local_wallet_live = self.local_wallet_live_in_ephemeral();
            let live_committee_seen =
                connected_wallet_peers.saturating_add(usize::from(local_wallet_live));

            let quorum_needed = match quorum_threshold_checked(validators_len) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(
                        "{} [MINT][QUORUM] ERROR: failed to compute quorum threshold validators_len={} err={:?}",
                        Self::runtime_log_timestamp(),
                        validators_len,
                        e
                    );
                    self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                    return;
                }
            };

            let has_committee_quorum_now = has_quorum(live_committee_seen, validators_len);

            tracing::debug!(
                "{} [MINT][QUORUM] validators_len={} quorum_needed={} local_wallet_live={} connected_wallet_peers={} live_committee_seen={} has_quorum={}",
                Self::runtime_log_timestamp(),
                validators_len,
                quorum_needed,
                local_wallet_live,
                connected_wallet_peers,
                live_committee_seen,
                has_committee_quorum_now
            );

            let proposal_ready_now = allow_solo_genesis || sync_snapshot.proposal_ready();

            self.update_local_runtime_mint_policy(
                miner,
                proposal_ready_now,
                tip_now,
                tip_now,
                connected_peers,
                connected_wallet_peers,
            );

            if !proposal_ready_now {
                tracing::debug!(
                    "{} [MINT] CATCH-UP-ONLY: refusing {} while unsynced/rejoining (has_synced={} is_syncing={} background_sync={} last_synced_index={:?} tip_now={} allow_solo_genesis={}).",
                    Self::runtime_log_timestamp(),
                    attempt_label,
                    sync_snapshot.has_synced,
                    sync_snapshot.is_syncing,
                    sync_snapshot.has_background_sync_work,
                    sync_snapshot.last_synced_index,
                    tip_now,
                    allow_solo_genesis
                );
                self.clear_staged_local_puzzle_proof(miner, "runtime catch-up gate active");
                self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                return;
            }

            if sync_in_progress_now && !allow_solo_genesis {
                tracing::debug!(
                    "{} [MINT] CATCH-UP-ONLY: refusing {} because sync/hydration work is still active (has_synced={} is_syncing={} background_sync={} last_synced_index={:?}).",
                    Self::runtime_log_timestamp(),
                    attempt_label,
                    sync_snapshot.has_synced,
                    sync_snapshot.is_syncing,
                    sync_snapshot.has_background_sync_work,
                    sync_snapshot.last_synced_index
                );
                self.clear_staged_local_puzzle_proof(
                    miner,
                    "background sync or hydration still active",
                );
                self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                return;
            }

            if validators_len == 1
                && !allow_solo_genesis
                && connected_wallet_peers > 0
                && tip_now > 0
            {
                tracing::debug!(
                    "{} [MINT] SOLO-GUARD TRIGGERED: non-founder single-validator view (tip_now={}, wallet_peers={}); refusing to mint until registry syncs.",
                    Self::runtime_log_timestamp(),
                    tip_now,
                    connected_wallet_peers
                );
                self.clear_staged_local_puzzle_proof(
                    miner,
                    "solo-guard triggered during registry convergence",
                );
                self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                return;
            }

            let nakamoto_mode = std::env::var("REMZAR_NAKAMOTO")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true);

            let isolated_now = connected_wallet_peers == 0;
            let quorum_missing_now = !has_committee_quorum_now;

            if quorum_missing_now {
                if nakamoto_mode && allow_solo_genesis {
                    tracing::debug!(
                        "{} [MINT] BOOTSTRAP: quorum missing but founder bootstrap allowed (nakamoto_mode={}, multi_validator_ever_seen(canonical)={}, seen={}, need={}).",
                        Self::runtime_log_timestamp(),
                        nakamoto_mode,
                        multi_validator_ever_seen,
                        live_committee_seen,
                        quorum_needed
                    );
                } else {
                    tracing::debug!(
                        "{} [MINT] QUORUM GUARD: halting mint (nakamoto_mode={}, allow_solo_genesis={}, multi_validator_ever_seen(canonical)={}, isolated_now={}, wallet_peers={}, live_committee_seen={}, quorum_needed={}).",
                        Self::runtime_log_timestamp(),
                        nakamoto_mode,
                        allow_solo_genesis,
                        multi_validator_ever_seen,
                        isolated_now,
                        connected_wallet_peers,
                        live_committee_seen,
                        quorum_needed
                    );
                    self.clear_staged_local_puzzle_proof(miner, "committee quorum missing");
                    self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                    return;
                }
            }

            if slot_now.saturating_add(1) < next_h {
                tracing::debug!(
                    "{} [MINT] SKIP: slot_now({})+1 < next_h({}) — waiting for slots to catch up.",
                    Self::runtime_log_timestamp(),
                    slot_now,
                    next_h
                );
                self.clear_staged_local_puzzle_proof(miner, "slot timing not ready yet");
                self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                return;
            }

            let prev_hash = match self.db.get_latest_block_hash() {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!(
                        "{} [MINT][PREFLIGHT] result=skip reason=latest_hash_unavailable h={} tip={} local_wallet_id={} err_kind={:?}",
                        Self::runtime_log_timestamp(),
                        next_h,
                        tip_now,
                        Self::safe_wallet_id(&self.local_wallet),
                        std::mem::discriminant(&e)
                    );
                    self.clear_staged_local_puzzle_proof(
                        miner,
                        "latest hash unavailable before canonical preflight",
                    );
                    self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                    return;
                }
            };

            // Canonical consensus preflight.
            match miner
                .consensus()
                .local_wallet_can_attempt_mint_at(next_h, prev_hash)
            {
                Ok(()) => {
                    tracing::debug!(
                        "{} [MINT][PREFLIGHT] result=pass h={} tip={} prev_hash={} local_wallet_id={} failover_retry={} quorum_seen={} quorum_needed={} local_live={} wallet_peers={}",
                        Self::runtime_log_timestamp(),
                        next_h,
                        tip_now,
                        Self::short_hash(&prev_hash),
                        Self::safe_wallet_id(&self.local_wallet),
                        is_failover_retry,
                        live_committee_seen,
                        quorum_needed,
                        local_wallet_live,
                        connected_wallet_peers
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "{} [MINT][PREFLIGHT] result=skip reason=canonical_or_runtime_denied h={} tip={} prev_hash={} local_wallet_id={} failover_retry={} quorum_seen={} quorum_needed={} local_live={} wallet_peers={} err_kind={:?}",
                        Self::runtime_log_timestamp(),
                        next_h,
                        tip_now,
                        Self::short_hash(&prev_hash),
                        Self::safe_wallet_id(&self.local_wallet),
                        is_failover_retry,
                        live_committee_seen,
                        quorum_needed,
                        local_wallet_live,
                        connected_wallet_peers,
                        std::mem::discriminant(&e)
                    );
                    self.clear_staged_local_puzzle_proof(
                        miner,
                        "canonical consensus preflight denied local mint attempt",
                    );
                    self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                    return;
                }
            }

            let mint_sync_gate_passed = proposal_ready_now;

            tracing::debug!(
                "{} [MINT] PROCEED: canonical preflight passed; asking miner to create block at height {} (mint_sync_gate_passed={} failover_retry={} has_synced={} is_syncing={} background_sync={})",
                Self::runtime_log_timestamp(),
                next_h,
                mint_sync_gate_passed,
                is_failover_retry,
                sync_snapshot.has_synced,
                sync_snapshot.is_syncing,
                sync_snapshot.has_background_sync_work
            );

            match miner.create_new_block(mint_sync_gate_passed) {
                Ok(block) => {
                    tracing::debug!(
                        "{} [MINT] new block created index={} hash_present=true",
                        Self::runtime_log_timestamp(),
                        block.metadata.index,
                    );

                    let tip_idx_usize = chain.latest_block_height();
                    let tip_idx = match u64::try_from(tip_idx_usize) {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::debug!(
                                "{} [REORG][INGEST] ERROR: latest_block_height usize->u64 conversion failed: {}",
                                Self::runtime_log_timestamp(),
                                tip_idx_usize
                            );
                            self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
                            return;
                        }
                    };

                    let ancestor_hash = chain
                        .get_block_by_index(tip_idx_usize)
                        .ok()
                        .map(|b| b.block_hash);

                    let legacy_key = format!("tx_batch_{:010}", block.metadata.index);
                    let key = block.batch_key.clone().unwrap_or(legacy_key);

                    let mut mint_failed = false;
                    let mut state_committed = false;
                    let mut block_added_to_chain = false;
                    let mut reorg_batch_bytes: Option<Vec<u8>> = None;

                    match self.db.read(
                        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                        key.as_bytes(),
                    ) {
                        Ok(Some(bytes)) => {
                            reorg_batch_bytes = Some(bytes.clone());

                            match TransactionBatch::deserialize(&bytes) {
                                Ok(batch) => {
                                    tracing::debug!(
                                        "{} [MINT] applying batch at height {} ({} txs)",
                                        Self::runtime_log_timestamp(),
                                        block.metadata.index,
                                        batch.transactions.len()
                                    );

                                    if batch.index != block.metadata.index {
                                        tracing::debug!(
                                            "{} [MINT] ERROR: batch index mismatch (batch.index={} block.index={})",
                                            Self::runtime_log_timestamp(),
                                            batch.index,
                                            block.metadata.index
                                        );
                                        mint_failed = true;
                                    } else {
                                        if let Err(e) = chain.add_block(block.clone()) {
                                            tracing::debug!(
                                                "{} [MINT] ERROR: chain.add_block failed before batch apply at index {}: {:?}",
                                                Self::runtime_log_timestamp(),
                                                block.metadata.index,
                                                e
                                            );
                                            mint_failed = true;
                                        } else {
                                            block_added_to_chain = true;
                                        }
                                    }

                                    if !mint_failed && let Err(e) = chain.apply_batch(&batch) {
                                        tracing::debug!(
                                            "{} [MINT] ERROR: failed to apply batch at height {}: {:?}",
                                            Self::runtime_log_timestamp(),
                                            block.metadata.index,
                                            e
                                        );
                                        mint_failed = true;
                                    }

                                    if !mint_failed {
                                        let height = block.metadata.index;
                                        let ts = block.metadata.timestamp;
                                        let signer_wallet = block.miner_wallet().to_string();
                                        let db_arc = Arc::clone(&self.db);

                                        for kind in &batch.transactions {
                                            match kind {
                                                TxKind::NftMint(mint_tx) => {
                                                    if let Err(e) =
                                                        crate::tokens::nft_001::apply_nft_mint(
                                                            &db_arc,
                                                            mint_tx,
                                                            &signer_wallet,
                                                            height,
                                                            ts,
                                                        )
                                                    {
                                                        tracing::debug!(
                                                            "{} [MINT][NFT] ERROR: failed to apply NftMint at height {}: {:?}",
                                                            Self::runtime_log_timestamp(),
                                                            height,
                                                            e
                                                        );
                                                        mint_failed = true;
                                                        break;
                                                    }
                                                }
                                                TxKind::NftTransfer(transfer_tx) => {
                                                    if let Err(e) =
                                                        crate::tokens::nft_001::apply_nft_transfer(
                                                            &db_arc,
                                                            transfer_tx,
                                                            &signer_wallet,
                                                            height,
                                                            ts,
                                                        )
                                                    {
                                                        match &e {
                                                            ErrorDetection::ValidationError {
                                                                message,
                                                                ..
                                                            } if message.starts_with(
                                                                "NFT transfer denied: signer ",
                                                            ) =>
                                                            {
                                                                tracing::debug!(
                                                                    "{} [MINT][NFT] WARN: skipping invalid NftTransfer at height {}: {}",
                                                                    Self::runtime_log_timestamp(),
                                                                    height,
                                                                    message
                                                                );
                                                            }
                                                            _ => {
                                                                tracing::debug!(
                                                                    "{} [MINT][NFT] ERROR: failed to apply NftTransfer at height {}: {:?}",
                                                                    Self::runtime_log_timestamp(),
                                                                    height,
                                                                    e
                                                                );
                                                                mint_failed = true;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }

                                        if !mint_failed
                                            && let Err(e) = miner
                                                .validator_state_mut()
                                                .apply_block(&block, &batch)
                                        {
                                            tracing::debug!(
                                                "{} [MINT][VALIDATORS] WARN: failed to update ValidatorState at height {}: {:?}",
                                                Self::runtime_log_timestamp(),
                                                block.metadata.index,
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "{} [MINT] WARN: failed to deserialize batch bytes at height {}: {:?}",
                                        Self::runtime_log_timestamp(),
                                        block.metadata.index,
                                        e
                                    );
                                    mint_failed = true;
                                }
                            }
                        }
                        Ok(None) => {
                            tracing::debug!(
                                "{} [MINT] INFO: no batch bytes found for height {}, continuing (empty batch)",
                                Self::runtime_log_timestamp(),
                                block.metadata.index
                            );

                            if let Err(e) = chain.add_block(block.clone()) {
                                tracing::debug!(
                                    "{} [MINT] ERROR: chain.add_block failed at index {}: {:?}",
                                    Self::runtime_log_timestamp(),
                                    block.metadata.index,
                                    e
                                );
                                mint_failed = true;
                            } else {
                                block_added_to_chain = true;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                "{} [MINT] WARN: failed to read batch bytes at height {}: {:?}",
                                Self::runtime_log_timestamp(),
                                block.metadata.index,
                                e
                            );
                            mint_failed = true;
                        }
                    }

                    if mint_failed {
                        tracing::debug!(
                            "{} [MINT] ERROR: mint aborted at height {}; rolling back local in-memory state (pre-commit)",
                            Self::runtime_log_timestamp(),
                            block.metadata.index
                        );

                        if let Some(h) = ancestor_hash {
                            _ = crate::blockchain::transaction_005_tx_account_tree::ChainLogic::rollback_to(
                                chain, h,
                            );
                        } else {
                            chain.reload_from_db();
                        }
                    } else {
                        if !block_added_to_chain {
                            tracing::debug!(
                                "{} [MINT] ERROR: internal invariant violation: mint succeeded but block was never inserted at index {}",
                                Self::runtime_log_timestamp(),
                                block.metadata.index,
                            );
                            mint_failed = true;
                        }

                        if !mint_failed {
                            if let Err(e) = chain.commit() {
                                tracing::debug!(
                                    "{} [MINT] ERROR: chain.commit failed at index {}: {:?}",
                                    Self::runtime_log_timestamp(),
                                    block.metadata.index,
                                    e
                                );
                                mint_failed = true;
                            } else {
                                state_committed = true;
                            }
                        }

                        if mint_failed {
                            if !state_committed {
                                if let Some(h) = ancestor_hash {
                                    _ = crate::blockchain::transaction_005_tx_account_tree::ChainLogic::rollback_to(
                                        chain, h,
                                    );
                                } else {
                                    chain.reload_from_db();
                                }
                            }
                        } else {
                            let reorg_graph_ready = match self.persist_local_block_into_reorg_graph(
                                &block,
                                tip_idx,
                                ancestor_hash,
                                reorg_batch_bytes.as_deref(),
                            ) {
                                Ok(()) => true,
                                Err(e) => {
                                    tracing::debug!(
                                        "{} [REORG][INGEST] ERROR: failed to persist local block into fork graph at height {}: {:?}",
                                        Self::runtime_log_timestamp(),
                                        block.metadata.index,
                                        e
                                    );
                                    false
                                }
                            };

                            if let Err(e) = chain.flush_balances() {
                                tracing::debug!(
                                    "{} [MINT] WARN: chain.flush_balances failed at index {}: {:?}",
                                    Self::runtime_log_timestamp(),
                                    block.metadata.index,
                                    e
                                );
                            }

                            if let Err(e) = self.db.flush_blockchain_db() {
                                tracing::debug!(
                                    "{} [MINT] WARN: flush_blockchain_db failed at index {}: {:?}",
                                    Self::runtime_log_timestamp(),
                                    block.metadata.index,
                                    e
                                );
                            }

                            tracing::debug!(
                                "{} [MINT] block persisted & chain committed at index {}",
                                Self::runtime_log_timestamp(),
                                block.metadata.index
                            );

                            if let Err(e) = Broadcaster::new(swarm).send_block(&block) {
                                tracing::debug!(
                                    "{} [MINT] WARN: broadcast block failed: {:?}",
                                    Self::runtime_log_timestamp(),
                                    e
                                );
                            } else {
                                tracing::debug!(
                                    "{} [MINT] broadcasted block {}",
                                    Self::runtime_log_timestamp(),
                                    block.metadata.index
                                );
                            }

                            *last_minted_height = Some(block.metadata.index);

                            {
                                let mut syn = self.sync_engine.lock().await;
                                syn.on_local_tip_advanced();
                                tracing::debug!(
                                    "{} [MINT] sync engine notified of local tip advance",
                                    Self::runtime_log_timestamp()
                                );
                            }

                            if reorg_graph_ready {
                                match self.reorg_manager.handle_new_block(
                                    &block,
                                    chain,
                                    Some(miner),
                                ) {
                                    Ok(ForkAction::Stay) => {}
                                    Ok(ForkAction::Reorg(plan)) => {
                                        tracing::debug!(
                                            "{} [REORG] applied reorg after local mint: old_tip={} new_tip={} common_ancestor={}",
                                            Self::runtime_log_timestamp(),
                                            plan.old_tip_height,
                                            plan.new_tip_height,
                                            plan.common_ancestor_height,
                                        );

                                        tracing::debug!(
                                            "[REORG] plan from local mint: detach={:?} attach={:?}",
                                            plan.detach_heights(),
                                            plan.attach_heights(),
                                        );

                                        tracing::debug!(
                                            "[REORG] hashes: old_tip_hash={} new_tip_hash={} ancestor_hash={}",
                                            Self::short_hash(&plan.old_tip_hash),
                                            Self::short_hash(&plan.new_tip_hash),
                                            Self::short_hash(&plan.common_ancestor_hash),
                                        );
                                    }
                                    Ok(ForkAction::NeedMoreData {
                                        missing_hash,
                                        context,
                                    }) => {
                                        tracing::debug!(
                                            "{} [REORG] local mint fork-choice needs more data at height {}: missing_hash={} context={}",
                                            Self::runtime_log_timestamp(),
                                            block.metadata.index,
                                            hex::encode(missing_hash),
                                            context
                                        );
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "{} [REORG] ERROR handle_new_block after local mint at height {}: {:?}",
                                            Self::runtime_log_timestamp(),
                                            block.metadata.index,
                                            e
                                        );
                                    }
                                }
                            } else {
                                tracing::debug!(
                                    "{} [REORG] SKIP handle_new_block at height {} because fork-graph ingest failed",
                                    Self::runtime_log_timestamp(),
                                    block.metadata.index
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("{e:?}");
                    tracing::debug!(
                        "{} [MINT] mint skipped: {}",
                        Self::runtime_log_timestamp(),
                        msg
                    );
                }
            }

            if mint_sync_gate_passed {
                if let Some(proof) = miner.take_pending_puzzle_proof() {
                    let has_subscribers = swarm.behaviour().gossipsub.all_peers().next().is_some();
                    let validator_local = proof.validator.eq_ignore_ascii_case(&self.local_wallet);
                    let prev_hash_present = proof.prev_block_hash != [0u8; 64];

                    tracing::debug!(
                        "{} [MINT][POR] will_publish_puzzle_proof_gossip={} h={} validator_local={} prev_hash_present={}",
                        Self::runtime_log_timestamp(),
                        has_subscribers,
                        proof.height,
                        validator_local,
                        prev_hash_present
                    );

                    if has_subscribers {
                        match Broadcaster::new(swarm).send_por_puzzle_proof(&proof) {
                            Ok(()) => {
                                tracing::debug!(
                                    "{} [MINT][POR] puzzle proof published h={} validator_local={}",
                                    Self::runtime_log_timestamp(),
                                    proof.height,
                                    validator_local
                                );
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "{} [MINT][POR] WARN publish puzzle proof failed: {:?}",
                                    Self::runtime_log_timestamp(),
                                    e
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            "{} [MINT][POR] skip puzzle proof gossip: no peers subscribed yet.",
                            Self::runtime_log_timestamp()
                        );
                    }
                }
            } else {
                self.clear_staged_local_puzzle_proof(
                    miner,
                    "mint sync gate did not pass after attempt",
                );
            }
        } else {
            tracing::debug!(
                "{} [MINT] miner is None (intent={}, wallet='{}').",
                Self::runtime_log_timestamp(),
                self.mining_intent,
                self.local_wallet
            );
        }

        self.print_new_blocks_since(chain, last_logged_tip, last_minted_height);
    }

    /// Normal slot-boundary mint entry point.
    ///
    /// This is the existing 30-second slot-edge path.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_mint_tick(
        &self,
        chain: &mut AccountModelTree,
        swarm: &mut Swarm<RemzarBehaviour>,
        miner: &mut Option<BlockchainBuilder>,
        last_logged_tip: &mut u64,
        last_minted_height: &mut Option<u64>,
        mint_ticks: &mut u64,
        is_founder_mode: bool,
    ) {
        self.handle_mint_attempt_common(
            chain,
            swarm,
            miner,
            last_logged_tip,
            last_minted_height,
            mint_ticks,
            is_founder_mode,
            "MINT TICK",
            false,
        )
        .await;
    }

    /// Same-slot failover retry entry point.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_failover_retry_tick(
        &self,
        chain: &mut AccountModelTree,
        swarm: &mut Swarm<RemzarBehaviour>,
        miner: &mut Option<BlockchainBuilder>,
        last_logged_tip: &mut u64,
        last_minted_height: &mut Option<u64>,
        failover_retry_ticks: &mut u64,
        is_founder_mode: bool,
    ) {
        self.handle_mint_attempt_common(
            chain,
            swarm,
            miner,
            last_logged_tip,
            last_minted_height,
            failover_retry_ticks,
            is_founder_mode,
            "FAILOVER RETRY",
            true,
        )
        .await;
    }

    pub async fn handle_sync_tick(&self, swarm: &mut Swarm<RemzarBehaviour>, sync_ticks: &mut u64) {
        *sync_ticks = (*sync_ticks).saturating_add(1);
        let mut syn = self.sync_engine.lock().await;
        syn.poll_peers_for_height(swarm);
    }

    pub async fn handle_registry_tick(
        &self,
        swarm: &mut Swarm<RemzarBehaviour>,
        miner: &mut Option<BlockchainBuilder>,
        registry_ticks: &mut u64,
    ) {
        *registry_ticks = (*registry_ticks).saturating_add(1);

        {
            if *registry_ticks == 1 {
                tracing::debug!(
                    "{} [REGISTRY][HB] boot grace: skipping finalize_round on first tick",
                    Self::runtime_log_timestamp()
                );
            } else {
                // Runtime dead-peer eviction.
                //
                // Canonical renewal stays slow:
                //     CANONICAL_RENEW_INTERVAL_BLOCKS = 10
                //
                // Runtime dead-peer eviction stays fast:
                //     DEAD_PEER_EVICTION_BLOCKS = 1
                //
                // With 30s blocks:
                //     DEAD_PEER_EVICTION_SECS = 30s
                let max_inactive = Duration::from_secs(
                    GlobalConfiguration::DEAD_PEER_EVICTION_SECS
                        + GlobalConfiguration::HEARTBEAT_GRACE_SECS,
                );

                let boot_grace = Duration::from_secs(GlobalConfiguration::HEARTBEAT_GRACE_SECS);

                self.node
                    .evict_inactive_validators(max_inactive, boot_grace);

                self.node.finalize_heartbeat_round();
            }

            self.node.begin_heartbeat_round();

            if !self.local_wallet.is_empty() {
                let tip_snapshot = self.db.get_tip_height().unwrap_or(0);

                match self
                    .node
                    .note_heartbeat_round(&self.local_wallet, tip_snapshot)
                {
                    Ok(_addr) => {}
                    Err(e) => {
                        tracing::debug!(
                            "{} [REGISTRY][HB] ERROR local heartbeat wallet={} err={:?}",
                            Self::runtime_log_timestamp(),
                            self.local_wallet,
                            e
                        );
                    }
                }
            } else {
                tracing::debug!(
                    "{} [REGISTRY][HB] local wallet empty; skipping local heartbeat.",
                    Self::runtime_log_timestamp()
                );
            }
        }

        let tip_now = self.db.get_tip_height().unwrap_or(0);
        let validators_now = self.ephemeral_wallet_count();
        let peers_connected = swarm.connected_peers().count();
        let connected_wallet_peers = self.connected_wallet_peers(swarm);

        let sync_snapshot = self.mint_sync_snapshot().await;
        let registry_ready_now = sync_snapshot.proposal_ready();

        if let Some(m) = miner {
            self.update_local_runtime_mint_policy(
                m,
                registry_ready_now,
                tip_now,
                tip_now,
                peers_connected,
                connected_wallet_peers,
            );

            m.heartbeat();
        } else {
            tracing::debug!(
                "{} [REGISTRY] miner is None; skipping heartbeat",
                Self::runtime_log_timestamp()
            );
        }

        if !self.local_wallet.is_empty() && registry_ready_now {
            self.emit_canonical_register_renewal(swarm, tip_now);
        }

        if !self.local_wallet.is_empty() {
            let self_demoted = self.should_self_demote_from_advertising(
                validators_now,
                registry_ready_now,
                connected_wallet_peers,
            );

            if self_demoted {
                tracing::debug!(
                    "{} [REGISTRY] self-demoted from runtime advertising (validators_now={} synced={} wallet_peers={})",
                    Self::runtime_log_timestamp(),
                    validators_now,
                    registry_ready_now,
                    connected_wallet_peers
                );
            } else {
                let has_subscribers = swarm.behaviour().gossipsub.all_peers().next().is_some();

                // Keep the old runtime/ephemeral registration gossip path.
                if let Ok(reg_tx) = RegisterNodeTx::new(self.local_wallet.clone()) {
                    if has_subscribers
                        && let Err(e) = Broadcaster::new(swarm).send_register_node(&reg_tx)
                    {
                        tracing::debug!(
                            "{} [REGISTRATION] WARN publish register gossip failed: {}",
                            Self::runtime_log_timestamp(),
                            e
                        );
                    }
                } else {
                    tracing::debug!(
                        "{} [REGISTRATION] ERROR: failed to construct RegisterNodeTx for wallet {}",
                        Self::runtime_log_timestamp(),
                        self.local_wallet
                    );
                }

                match self.build_local_peer_mesh_announce(swarm) {
                    Ok(ann) => {
                        if has_subscribers
                            && let Err(e) = Broadcaster::new(swarm).send_peer_mesh_announce(&ann)
                        {
                            tracing::debug!(
                                "{} [PEER_MESH] WARN publish peer mesh gossip failed: {}",
                                Self::runtime_log_timestamp(),
                                e
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "{} [PEER_MESH] WARN failed to build local peer mesh announce: {:?}",
                            Self::runtime_log_timestamp(),
                            e
                        );
                    }
                }
            }

            if miner.is_none() && self.mining_intent {
                let present = {
                    let reg = self.node.ephemeral();
                    match reg.lock() {
                        Ok(e) => e.is_registered(&self.local_wallet),
                        Err(_) => {
                            tracing::debug!(
                                "{} [REGISTRY] ERROR: registry mutex poisoned while checking local_wallet; miner remains disabled",
                                Self::runtime_log_timestamp()
                            );
                            false
                        }
                    }
                };

                tracing::debug!(
                    "{} [REGISTRY] miner=None && intent=true; has_local_wallet={}",
                    Self::runtime_log_timestamp(),
                    present
                );

                if present {
                    match BlockchainBuilder::new(
                        Arc::clone(&self.db),
                        Arc::clone(&self.mempool),
                        self.local_wallet.clone(),
                        Arc::clone(&self.tm),
                        Arc::clone(&self.signing_key),
                    ) {
                        Ok(mut m_new) => {
                            if let Err(e) = m_new.validator_state_mut().rebuild_from_chain(None) {
                                tracing::debug!(
                                    "{} [REGISTRY][VALIDATORS] WARN: failed to rebuild ValidatorState when enabling miner: {:?}",
                                    Self::runtime_log_timestamp(),
                                    e
                                );
                            }

                            match m_new.validator_state_mut().multi_validator_ever_seen() {
                                Ok(v) => {
                                    tracing::debug!(
                                        "{} [CONSENSUS] multi_validator_ever_seen(canonical)={}",
                                        Self::runtime_log_timestamp(),
                                        v
                                    );
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "{} [CONSENSUS] WARN: failed to read multi_validator_ever_seen(canonical): {:?}",
                                        Self::runtime_log_timestamp(),
                                        e
                                    );
                                }
                            }

                            tracing::debug!(
                                "{} 🟢 Mining enabled after wallet registration.",
                                Self::runtime_log_timestamp()
                            );
                            *miner = Some(m_new);
                        }
                        Err(e) => {
                            tracing::debug!(
                                "{} [REGISTRY] ERROR enabling miner after registration: {:?}",
                                Self::runtime_log_timestamp(),
                                e
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        "{} [REGISTRY] local wallet not yet present; miner remains disabled.",
                        Self::runtime_log_timestamp()
                    );
                }
            }
        } else {
            tracing::debug!(
                "{} [REGISTRY] no local wallet; skipping registration gossip.",
                Self::runtime_log_timestamp()
            );
        }
    }

    pub async fn handle_net_cmd(
        &self,
        swarm: &mut Swarm<RemzarBehaviour>,
        cmd: Option<NetCmd>,
    ) -> bool {
        tracing::debug!(
            "{} [NETCMD] received: {:?}",
            Self::runtime_log_timestamp(),
            cmd.as_ref().map(std::mem::discriminant)
        );

        match cmd {
            Some(NetCmd::SendTx(tx)) => {
                tracing::debug!("{} [NETCMD] SendTx", Self::runtime_log_timestamp());
                _ = Broadcaster::new(swarm).send_transaction(&tx);
                false
            }
            Some(NetCmd::SendTxKind(kind)) => {
                tracing::debug!("{} [NETCMD] SendTxKind", Self::runtime_log_timestamp());

                let tag = kind.tag();

                if let Err(e) = self.mempool.add_tx_kind(&kind) {
                    tracing::debug!(
                        "{} [NETCMD] ERROR mempool.add_tx_kind failed tag={} err={:?}",
                        Self::runtime_log_timestamp(),
                        tag,
                        e
                    );
                } else {
                    tracing::debug!(
                        "{} [NETCMD] mempool.add_tx_kind OK tag={}",
                        Self::runtime_log_timestamp(),
                        tag
                    );
                }

                if let Err(e) = Broadcaster::new(swarm).send_tx_kind(&kind) {
                    tracing::debug!(
                        "{} [NETCMD] WARN SendTxKind broadcast failed: {:?}",
                        Self::runtime_log_timestamp(),
                        e
                    );
                }

                false
            }
            Some(NetCmd::SendBlock(bl)) => {
                tracing::debug!(
                    "{} [NETCMD] SendBlock index={}",
                    Self::runtime_log_timestamp(),
                    bl.metadata.index
                );
                _ = Broadcaster::new(swarm).send_block(&bl);
                false
            }
            Some(NetCmd::SendRegister(r)) => {
                let has_subscribers = swarm.behaviour().gossipsub.all_peers().next().is_some();
                tracing::debug!(
                    "{} [NETCMD] SendRegister has_subscribers={}",
                    Self::runtime_log_timestamp(),
                    has_subscribers
                );

                // Canonical path: stage RegisterNode as TxKind and gossip it as TxKind.
                let kind = TxKind::RegisterNode(r.clone());

                if let Err(e) = kind.validate() {
                    tracing::debug!(
                        "{} [NETCMD] ERROR invalid RegisterNode TxKind: {:?}",
                        Self::runtime_log_timestamp(),
                        e
                    );
                } else {
                    if let Err(e) = self.mempool.add_tx_kind(&kind) {
                        tracing::debug!(
                            "{} [NETCMD] WARN mempool.add_tx_kind(RegisterNode) failed: {:?}",
                            Self::runtime_log_timestamp(),
                            e
                        );
                    } else {
                        tracing::debug!(
                            "{} [NETCMD] staged RegisterNode in mempool as canonical TxKind",
                            Self::runtime_log_timestamp()
                        );
                    }

                    if has_subscribers {
                        if let Err(e) = Broadcaster::new(swarm).send_tx_kind(&kind) {
                            tracing::debug!(
                                "{} [NETCMD] WARN canonical RegisterNode txkind broadcast failed: {:?}",
                                Self::runtime_log_timestamp(),
                                e
                            );
                        } else {
                            tracing::debug!(
                                "{} [NETCMD] canonical RegisterNode txkind broadcasted",
                                Self::runtime_log_timestamp()
                            );
                        }
                    }
                }

                // Keep the old runtime/ephemeral register gossip path too.
                if has_subscribers {
                    tracing::debug!(
                        "{} [NETCMD] publishing register tx via Broadcaster to topic {}",
                        Self::runtime_log_timestamp(),
                        REGISTRATION_TOPIC
                    );
                    if let Err(e) = Broadcaster::new(swarm).send_register_node(&r) {
                        tracing::debug!(
                            "{} [NETCMD] WARN publish register gossip failed: {}",
                            Self::runtime_log_timestamp(),
                            e
                        );
                    } else {
                        tracing::debug!(
                            "{} [NETCMD] register tx published",
                            Self::runtime_log_timestamp()
                        );
                    }
                } else {
                    tracing::debug!(
                        "{} [NETCMD] skip register gossip: no peers subscribed.",
                        Self::runtime_log_timestamp()
                    );
                }

                false
            }
            Some(NetCmd::SendPeerMeshAnnounce(ann)) => {
                let has_subscribers = swarm.behaviour().gossipsub.all_peers().next().is_some();
                let peer_id_safe = Self::safe_wallet_id(ann.peer_id.as_str());

                tracing::debug!(
                    "{} [NETCMD] SendPeerMeshAnnounce has_subscribers={} peer={} addrs={}",
                    Self::runtime_log_timestamp(),
                    has_subscribers,
                    peer_id_safe.as_str(),
                    ann.listen_addrs.len()
                );

                if has_subscribers {
                    match Broadcaster::new(swarm).send_peer_mesh_announce(&ann) {
                        Ok(()) => {
                            tracing::debug!(
                                "{} [NETCMD] peer mesh announce broadcasted peer={} addrs={}",
                                Self::runtime_log_timestamp(),
                                peer_id_safe.as_str(),
                                ann.listen_addrs.len()
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                "{} [NETCMD] WARN publish peer mesh announce failed: {:?}",
                                Self::runtime_log_timestamp(),
                                e
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        "{} [NETCMD] skip peer mesh gossip: no peers subscribed.",
                        Self::runtime_log_timestamp()
                    );
                }

                false
            }
            Some(NetCmd::SendAosPuzzleProof(proof)) => {
                let has_subscribers = swarm.behaviour().gossipsub.all_peers().next().is_some();
                let validator_safe = Self::safe_wallet_id(&proof.validator);

                tracing::debug!(
                    "{} [NETCMD] SendAosPuzzleProof has_subscribers={} h={} validator={}",
                    Self::runtime_log_timestamp(),
                    has_subscribers,
                    proof.height,
                    validator_safe.as_str()
                );

                if has_subscribers {
                    match Broadcaster::new(swarm).send_por_puzzle_proof(&proof) {
                        Ok(()) => {
                            tracing::debug!(
                                "{} [NETCMD] AOS puzzle proof broadcasted h={} validator={}",
                                Self::runtime_log_timestamp(),
                                proof.height,
                                validator_safe.as_str()
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                "{} [NETCMD] WARN publish AOS puzzle proof failed: {:?}",
                                Self::runtime_log_timestamp(),
                                e
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        "{} [NETCMD] skip AOS puzzle proof gossip: no peers subscribed.",
                        Self::runtime_log_timestamp()
                    );
                }

                false
            }
            Some(NetCmd::SendChat(chat)) => {
                tracing::debug!(
                    "{} [NETCMD] SendChat from={} to={}",
                    Self::runtime_log_timestamp(),
                    Self::safe_wallet_id(&chat.from_wallet),
                    Self::safe_wallet_id(&chat.to_wallet)
                );

                if let Err(e) = Broadcaster::new(swarm).send_chat(&chat) {
                    tracing::debug!(
                        "{} [NETCMD] WARN chat broadcast failed: {:?}",
                        Self::runtime_log_timestamp(),
                        e
                    );
                } else {
                    tracing::debug!(
                        "{} [NETCMD] chat broadcasted",
                        Self::runtime_log_timestamp()
                    );
                }

                false
            }
            Some(NetCmd::SendFileChunk(chunk)) => {
                tracing::debug!(
                    "{} [NETCMD] SendFileChunk (off-chain file sharing)",
                    Self::runtime_log_timestamp()
                );

                if let Err(e) = Broadcaster::new(swarm).send_file_chunk(&chunk) {
                    tracing::debug!(
                        "{} [NETCMD] WARN file chunk broadcast failed: {:?}",
                        Self::runtime_log_timestamp(),
                        e
                    );
                } else {
                    tracing::debug!(
                        "{} [NETCMD] file chunk broadcasted",
                        Self::runtime_log_timestamp()
                    );
                }

                false
            }
            None => {
                tracing::debug!(
                    "{} [NETCMD] channel closed; disabling net_rx",
                    Self::runtime_log_timestamp()
                );
                true
            }
        }
    }

    pub async fn route_non_gossip_swarm_event(
        &self,
        event: libp2p::swarm::SwarmEvent<crate::network::p2p_003_behaviour::OutEvent>,
        swarm: &mut Swarm<RemzarBehaviour>,
        miner: Option<&mut BlockchainBuilder>,
    ) {
        if let libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } = &event {
            let peer_str = peer_id.to_base58();
            if let Some(wallet) = self.node.unregister_by_peer(&peer_str) {
                tracing::debug!(
                    "{} [REGISTRY] peer disconnected; unregistering validator wallet={} peer={}",
                    Self::runtime_log_timestamp(),
                    Self::safe_wallet_id(&wallet),
                    Self::safe_wallet_id(&peer_str)
                );
            } else {
                tracing::debug!(
                    "{} [REGISTRY] peer disconnected; no validator mapped for peer={}",
                    Self::runtime_log_timestamp(),
                    Self::safe_wallet_id(&peer_str)
                );
            }
        }

        let mut syn = self.sync_engine.lock().await;
        syn.on_swarm_event(event, swarm, miner);
    }

    pub fn init_boot_heartbeat_round(&self) {
        let initial_validators = {
            let reg = self.node.ephemeral();
            reg.lock().map(|e| e.wallets.len()).unwrap_or(0)
        };

        tracing::debug!(
            "{} [REGISTRY][HB] initializing first heartbeat round validators={}",
            Self::runtime_log_timestamp(),
            initial_validators
        );

        self.node.begin_heartbeat_round();

        if !self.local_wallet.is_empty() {
            let tip_snapshot = self.db.get_tip_height().unwrap_or(0);

            match self
                .node
                .note_heartbeat_round(&self.local_wallet, tip_snapshot)
            {
                Ok(_addr) => {
                    tracing::debug!(
                        "{} [REGISTRY][HB][BOOT] local_heartbeat_recorded=true wallet_present=true tip_snapshot={}",
                        Self::runtime_log_timestamp(),
                        tip_snapshot
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "{} [REGISTRY][HB][BOOT] ERROR local_heartbeat_recorded=false wallet_present=true tip_snapshot={} err_kind={:?}",
                        Self::runtime_log_timestamp(),
                        tip_snapshot,
                        std::mem::discriminant(&e)
                    );
                }
            }
        } else {
            tracing::debug!(
                "{} [REGISTRY][HB][BOOT] wallet_present=false; skipping boot heartbeat.",
                Self::runtime_log_timestamp()
            );
        }
    }

    pub fn log_ephemeral_boot_snapshot(&self) -> usize {
        let n_validators: usize = {
            let reg = self.node.ephemeral();
            match reg.lock() {
                Ok(e) => e.sorted_wallets().len().max(1),
                Err(_) => {
                    tracing::debug!(
                        "{} [EPHEMERAL] WARN: registry mutex poisoned during boot; assuming n_validators=1 for logs",
                        Self::runtime_log_timestamp()
                    );
                    1
                }
            }
        };

        n_validators
    }
}
