//! Top-level orchestration runner extracted from the unified orchestration loop.

use std::{sync::Arc, time::Duration};

use chrono::DateTime;
use futures::{StreamExt, future};
use libp2p::swarm::{Swarm, SwarmEvent};
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tracing::info;

use crate::blockchain::{
    blockchain_001_builder::BlockchainBuilder, transaction_005_tx_account_tree::AccountModelTree,
};
use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
use crate::consensus::por_000_ephemeral_registration::NodeEphemeral;
use crate::consensus::por_005_time_management::TimeManager;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::network::{
    p2p_003_behaviour::{OutEvent, RemzarBehaviour},
    p2p_008_broadcast::Broadcaster,
};
use crate::reorganization::reorg_006_manager::ReorgManager;
use crate::runtime::p2p_001_sync_builders::P2pSync;
use crate::runtime::p2p_005_sync_gossipsub::handle_gossipsub;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::{alpha_002_error_detection_system::ErrorDetection, time_policy::TimePolicy};

use super::blockchain_003_orchestration_engine::{
    OrchestrationEngine, OrchestrationEngineArgs, SigningKey,
};

pub struct OrchestrationLoopArgs {
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

pub struct OrchestrationLoop {
    pub engine: OrchestrationEngine,
}

impl OrchestrationLoop {
    pub fn new(args: OrchestrationLoopArgs) -> Self {
        Self {
            engine: OrchestrationEngine::new(OrchestrationEngineArgs {
                db: args.db,
                node_ephemeral: args.node_ephemeral,
                mempool: args.mempool,
                sync_engine: args.sync_engine,
                signing_key: args.signing_key,
                tm: args.tm,
                reorg_manager: args.reorg_manager,
                local_wallet: args.local_wallet,
                console_bus: args.console_bus,
            }),
        }
    }

    /// Runtime wall-clock UNIX seconds for orchestration scheduling.
    #[inline]
    fn now_unix_runtime() -> Result<u64, ErrorDetection> {
        TimePolicy::now_unix_secs_runtime()
    }

    /// Runtime-only UTC timestamp string for logs.
    fn runtime_log_timestamp() -> String {
        match TimePolicy::now_unix_secs_runtime() {
            Ok(now_unix) => {
                let Some(now_i64) = i64::try_from(now_unix).ok() else {
                    return format!("unix:{now_unix}");
                };

                DateTime::from_timestamp(now_i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| format!("unix:{now_unix}"))
            }
            Err(_) => "time_unavailable".to_string(),
        }
    }

    pub async fn run_loop(
        &self,
        chain: &mut AccountModelTree,
        swarm: &mut Swarm<RemzarBehaviour>,
        mut shutdown_rx: oneshot::Receiver<()>,
        mut net_rx: Option<mpsc::Receiver<NetCmd>>,
        opts: &NodeOpts,
    ) -> Result<(), ErrorDetection> {
        tracing::debug!(
            "{} Joining all gossip topics at startup…",
            Self::runtime_log_timestamp()
        );
        Broadcaster::new(swarm).join_all_topics().ok();

        let is_founder_mode: bool = opts.founder;

        tracing::debug!(
            "{} [BOOT] node_mode={} local_wallet_present={}",
            Self::runtime_log_timestamp(),
            if is_founder_mode {
                "bootstrap"
            } else {
                "standard"
            },
            !self.engine.local_wallet.is_empty()
        );

        // `bi` is the OUTER slot length (e.g. 30 seconds).
        // We do NOT change this. It remains the only thing that opens a new
        // slot/height mint window.
        let bi = self.engine.tm.block_interval();

        // `tau` is the deterministic failover retry window INSIDE the slot.
        // It is NOT allowed to become a second outer mint clock.
        let tau_secs = self.engine.tm.failover_window_secs().max(1);
        let tau = Duration::from_secs(tau_secs);

        let now_unix = Self::now_unix_runtime()?;
        let next_slot = self.engine.tm.current_slot(now_unix).saturating_add(1);
        let start_unix = self.engine.tm.slot_start_unix(next_slot);
        let start_after = Duration::from_secs(start_unix.saturating_sub(now_unix));

        let n_validators = self.engine.log_ephemeral_boot_snapshot();

        tracing::debug!(
            "{} Timers aligned: block_interval={}s failover_window={}s next_slot={} start_after={}s n_validators={}",
            Self::runtime_log_timestamp(),
            bi.as_secs(),
            tau.as_secs(),
            next_slot,
            start_after.as_secs(),
            n_validators
        );

        self.engine.init_boot_heartbeat_round();

        // Anchor all slot-related timers to the same aligned slot start.
        let aligned_slot_start = Instant::now()
            .checked_add(start_after)
            .unwrap_or_else(Instant::now);

        // Main slot-boundary mint attempt.
        // This preserves the chain's normal 30-second cadence and is the ONLY
        // place where a new slot target height is opened.
        let mut mint_interval = interval_at(aligned_slot_start, bi);
        mint_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Lightweight failover poll cadence.
        //
        // IMPORTANT:
        // - this is NOT the retry window itself
        // - it is only a frequent poll so we can detect exactly when a slot has
        //   crossed into a later failover round
        // - actual retry attempts are still gated by elapsed time + per-round latches
        //
        // Safety guard:
        // if tau >= bi, failover retries are useless / degenerate, so disable the poll.
        let failover_poll = Duration::from_millis(250);
        let mut failover_poll_interval = if tau < bi {
            let mut iv = interval_at(aligned_slot_start, failover_poll);
            iv.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Some(iv)
        } else {
            None
        };

        tracing::debug!(
            "{} [BOOT][FAILOVER] slot={}s tau={}s retry_poll={}ms retry_inside_slot={}",
            Self::runtime_log_timestamp(),
            bi.as_secs(),
            tau.as_secs(),
            failover_poll.as_millis(),
            failover_poll_interval.is_some(),
        );

        // Stronger remote-health path:
        // sync should run at failover cadence, not only block cadence.
        let mut sync_interval = interval_at(Instant::now(), tau);
        sync_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut kad_interval = interval_at(Instant::now(), Duration::from_secs(45));
        kad_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut display_interval = if self.engine.display.log_sequence {
            let mut iv = interval_at(Instant::now(), Duration::from_secs(10));
            iv.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Some(iv)
        } else {
            None
        };

        // Registry heartbeat should not be slower than failover cadence.
        let registry_period = self
            .engine
            .registry_heartbeat_secs
            .map(|secs| Duration::from_secs(secs.max(1)).min(tau));

        let mut registry_interval = if let Some(period) = registry_period {
            let mut iv = interval_at(Instant::now(), period);
            iv.set_missed_tick_behavior(MissedTickBehavior::Delay);
            Some(iv)
        } else {
            None
        };

        let mut last_logged_tip = self.engine.db.get_tip_height().unwrap_or(0);
        let mut last_minted_height: Option<u64> = None;

        let mut mint_ticks: u64 = 0;
        let mut failover_retry_ticks: u64 = 0;
        let mut sync_ticks: u64 = 0;
        let mut registry_ticks: u64 = 0;

        let mut active_slot: Option<u64> = None;
        let mut active_slot_start_unix: Option<u64> = None;
        let mut active_target_height: Option<u64> = None;
        let mut active_slot_resolved: bool = true;
        let mut active_last_attempted_round: Option<u64> = None;

        self.engine.refresh_wallet_peer_latch(swarm);

        // Immediate sync seed before entering steady-state loop.
        self.engine.seed_sync(swarm).await;

        let mut miner: Option<BlockchainBuilder> = self.engine.initialize_miner();

        // Immediate early registry heartbeat so runtime health and local
        // self-demotion logic are populated before the first mint window.
        if registry_interval.is_some() {
            self.engine
                .handle_registry_tick(swarm, &mut miner, &mut registry_ticks)
                .await;
        }

        loop {
            tokio::select! {
                // Normal slot-boundary mint attempt.
                //
                // This is the ONLY place that opens a new slot target.
                _ = mint_interval.tick() => {
                    let open_now_unix = Self::now_unix_runtime()?;
                    let slot_now = self.engine.tm.current_slot(open_now_unix);
                    let slot_start_unix = self.engine.tm.slot_start_unix(slot_now);
                    let target_height = self.engine.db.get_tip_height().unwrap_or(0).saturating_add(1);

                    active_slot = Some(slot_now);
                    active_slot_start_unix = Some(slot_start_unix);
                    active_target_height = Some(target_height);
                    active_slot_resolved = false;

                    // Round 0 is consumed by the normal slot-boundary mint attempt.
                    let initial_round = open_now_unix
                        .saturating_sub(slot_start_unix)
                        .div_euclid(tau_secs);
                    active_last_attempted_round = Some(initial_round);

                    tracing::debug!(
                        "{} [SLOT][OPEN] slot={} slot_start={} target_height={} block_interval={}s failover_window={}s initial_round={}",
                        Self::runtime_log_timestamp(),
                        slot_now,
                        slot_start_unix,
                        target_height,
                        bi.as_secs(),
                        tau.as_secs(),
                        initial_round,
                    );

                    self.engine.handle_mint_tick(
                        chain,
                        swarm,
                        &mut miner,
                        &mut last_logged_tip,
                        &mut last_minted_height,
                        &mut mint_ticks,
                        is_founder_mode,
                    ).await;

                    let tip_after = self.engine.db.get_tip_height().unwrap_or(0);
                    if tip_after >= target_height {
                        active_slot_resolved = true;
                        tracing::debug!(
                            "{} [SLOT][RESOLVED] slot={} target_height={} tip_after={}",
                            Self::runtime_log_timestamp(),
                            slot_now,
                            target_height,
                            tip_after
                        );
                    } else {
                        tracing::debug!(
                            "{} [SLOT][PENDING] slot={} target_height={} tip_after={} waiting for next failover round",
                            Self::runtime_log_timestamp(),
                            slot_now,
                            target_height,
                            tip_after
                        );
                    }
                }

                // In-slot failover retry polling.
                //
                // This may retry ONLY the currently active slot target height.
                // It must never open a new height inside the same 30s window.
                Some(_) = async {
                    if let Some(iv) = failover_poll_interval.as_mut() {
                        iv.tick().await;
                        Some(())
                    } else {
                        None::<()>
                    }
                } => {
                    let retry_now_unix = Self::now_unix_runtime()?;
                    let slot_now = self.engine.tm.current_slot(retry_now_unix);

                    if let (Some(slot_id), Some(slot_start_unix), Some(target_height)) =
                        (active_slot, active_slot_start_unix, active_target_height)
                    {
                        // If the slot is already resolved, do nothing.
                        if active_slot_resolved {
                            continue;
                        }
                        // If the wall clock has moved to a new slot, retries for the
                        // previous slot are no longer allowed.
                        else if slot_now != slot_id {
                            tracing::debug!(
                                "{} [FAILOVER] skip retry: slot advanced (active_slot={} current_slot={} target_height={})",
                                Self::runtime_log_timestamp(),
                                slot_id,
                                slot_now,
                                target_height
                            );
                            active_slot_resolved = true;
                        } else {
                            let tip_now = self.engine.db.get_tip_height().unwrap_or(0);

                            // If someone already filled the target height, resolve the slot
                            // and do not retry.
                            if tip_now >= target_height {
                                active_slot_resolved = true;
                                tracing::debug!(
                                    "{} [FAILOVER] target already resolved inside slot={} target_height={} tip_now={}",
                                    Self::runtime_log_timestamp(),
                                    slot_id,
                                    target_height,
                                    tip_now
                                );
                            } else {
                                let elapsed_in_slot =
                                    retry_now_unix.saturating_sub(slot_start_unix);
                                let proposal_deadline_secs =
                                    self.engine.tm.proposal_deadline_secs().max(1);
                                let current_round = elapsed_in_slot.div_euclid(tau_secs);

                                // Never retry before slot_start + tau.
                                if elapsed_in_slot < tau_secs {
                                    continue;
                                }

                                // Do not retry beyond the proposal window.
                                if elapsed_in_slot >= proposal_deadline_secs {
                                    tracing::debug!(
                                        "{} [FAILOVER] skip retry: past proposal deadline slot={} target_height={} elapsed={}s deadline={}s",
                                        Self::runtime_log_timestamp(),
                                        slot_id,
                                        target_height,
                                        elapsed_in_slot,
                                        proposal_deadline_secs
                                    );
                                    active_slot_resolved = true;
                                    continue;
                                }

                                // Retry at most once per round transition.
                                if let Some(last_round) = active_last_attempted_round
                                    && current_round <= last_round
                                {
                                    continue;
                                }
                                active_last_attempted_round = Some(current_round);

                                tracing::debug!(
                                    "{} [FAILOVER] retrying unresolved slot={} target_height={} tip_now={} elapsed={}s round={} tau={}s",
                                    Self::runtime_log_timestamp(),
                                    slot_id,
                                    target_height,
                                    tip_now,
                                    elapsed_in_slot,
                                    current_round,
                                    tau.as_secs(),
                                );

                                self.engine.handle_failover_retry_tick(
                                    chain,
                                    swarm,
                                    &mut miner,
                                    &mut last_logged_tip,
                                    &mut last_minted_height,
                                    &mut failover_retry_ticks,
                                    is_founder_mode,
                                ).await;

                                let tip_after = self.engine.db.get_tip_height().unwrap_or(0);
                                if tip_after >= target_height {
                                    active_slot_resolved = true;
                                    tracing::debug!(
                                        "{} [FAILOVER] resolved slot={} target_height={} tip_after={} round={}",
                                        Self::runtime_log_timestamp(),
                                        slot_id,
                                        target_height,
                                        tip_after,
                                        current_round
                                    );
                                } else {
                                    tracing::debug!(
                                        "{} [FAILOVER] still pending slot={} target_height={} tip_after={} round={}",
                                        Self::runtime_log_timestamp(),
                                        slot_id,
                                        target_height,
                                        tip_after,
                                        current_round
                                    );
                                }
                            }
                        }
                    }
                }

                _ = sync_interval.tick() => {
                    self.engine.handle_sync_tick(swarm, &mut sync_ticks).await;
                }

                _ = kad_interval.tick() => {
                    let _ = swarm
                        .behaviour_mut()
                        .kademlia
                        .get_closest_peers(libp2p::PeerId::random());
                }

                Some(_) = async {
                    if let Some(iv) = registry_interval.as_mut() {
                        iv.tick().await;
                        Some(())
                    } else {
                        None::<()>
                    }
                } => {
                    self.engine
                        .handle_registry_tick(swarm, &mut miner, &mut registry_ticks)
                        .await;
                }

                Some(_) = async {
                    if let Some(iv) = display_interval.as_mut() {
                        iv.tick().await;
                        Some(())
                    } else {
                        None::<()>
                    }
                } => {
                    self.engine.print_new_blocks_since(
                        chain,
                        &mut last_logged_tip,
                        &mut last_minted_height,
                    );
                }

                cmd = async {
                    if let Some(rx) = net_rx.as_mut() {
                        rx.recv().await
                    } else {
                        future::pending::<Option<NetCmd>>().await
                    }
                } => {
                    let receiver_closed = self.engine.handle_net_cmd(swarm, cmd).await;
                    if receiver_closed {
                        net_rx = None;
                    }
                }

                raw_opt = swarm.next() => {
                    let raw = match raw_opt {
                        Some(ev) => ev,
                        None => {
                            break;
                        }
                    };

                    match raw {
                        SwarmEvent::Behaviour(OutEvent::Gossip(ge)) => {
                            match *ge {
                                libp2p::gossipsub::Event::Message {
                                    propagation_source,
                                    message_id,
                                    message,
                                } => {
                                    let src = propagation_source;

                                    let rebuilt_event = libp2p::gossipsub::Event::Message {
                                        propagation_source,
                                        message_id,
                                        message,
                                    };

                                    let mut syn_guard = self.engine.sync_engine.lock().await;
                                    let reg_arc = self.engine.node.ephemeral();

                                    if let Ok(mut reg_guard) = reg_arc.lock() {
                                        handle_gossipsub(
                                            rebuilt_event,
                                            src,
                                            swarm,
                                            chain,
                                            &self.engine.db,
                                            &self.engine.db,
                                            &self.engine.mempool,
                                            &mut reg_guard,
                                            &mut syn_guard,
                                            miner.as_mut(),
                                            &self.engine.local_wallet,
                                            opts,
                                        );
                                    } else {
                                        tracing::debug!(
                                            "{} [GOSSIP] WARN: failed to lock ephemeral registry mutex",
                                            Self::runtime_log_timestamp()
                                        );
                                    }

                                    self.engine.refresh_wallet_peer_latch(swarm);
                                    self.engine.print_new_blocks_since(
                                        chain,
                                        &mut last_logged_tip,
                                        &mut last_minted_height,
                                    );
                                }

                                other_gossip_event => {
                                    self.engine
                                        .route_non_gossip_swarm_event(
                                            SwarmEvent::Behaviour(
                                                OutEvent::Gossip(Box::new(other_gossip_event))
                                            ),
                                            swarm,
                                            miner.as_mut(),
                                        )
                                        .await;

                                    self.engine.refresh_wallet_peer_latch(swarm);
                                    self.engine.print_new_blocks_since(
                                        chain,
                                        &mut last_logged_tip,
                                        &mut last_minted_height,
                                    );
                                }
                            }
                        }

                        other => {
                            self.engine
                                .route_non_gossip_swarm_event(other, swarm, miner.as_mut())
                                .await;

                            self.engine.refresh_wallet_peer_latch(swarm);
                            self.engine.print_new_blocks_since(
                                chain,
                                &mut last_logged_tip,
                                &mut last_minted_height,
                            );
                        }
                    }
                }

                _ = &mut shutdown_rx => {
                    info!("OrchestrationLoop: shutdown signal received");
                    tracing::debug!(
                        "{} [SHUTDOWN] OrchestrationLoop got shutdown signal; exiting loop.",
                        Self::runtime_log_timestamp()
                    );
                    break;
                }
            }
        }

        tracing::debug!(
            "{} OrchestrationLoop exiting normally.",
            Self::runtime_log_timestamp()
        );
        Ok(())
    }

    pub async fn run_until_ctrl_c(
        &self,
        chain: &mut AccountModelTree,
        swarm: &mut Swarm<RemzarBehaviour>,
        net_rx: Option<mpsc::Receiver<NetCmd>>,
        opts: &NodeOpts,
    ) -> Result<(), ErrorDetection> {
        let (_tx, rx) = oneshot::channel::<()>();
        tracing::debug!(
            "{} run_until_ctrl_c waiting (Ctrl-C)…",
            Self::runtime_log_timestamp()
        );
        tokio::select! {
            r = self.run_loop(chain, swarm, rx, net_rx, opts) => r,
            _ = tokio::signal::ctrl_c() => {
                tracing::debug!(
                    "{} Ctrl-C caught; stopping OrchestrationLoop.",
                    Self::runtime_log_timestamp()
                );
                Ok(())
            },
        }
    }
}
