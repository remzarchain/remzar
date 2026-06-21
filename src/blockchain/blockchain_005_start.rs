//! Blockchain Startup Module

use std::sync::Arc;

use crate::blockchain::blockchain_004_orchestration_run::{
    OrchestrationLoop, OrchestrationLoopArgs,
};
use crate::blockchain::mempool::MemPool;
use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
use crate::consensus::por_000_ephemeral_registration::{NodeEphemeral, RegistryData};
use crate::consensus::por_005_time_management::{TimeConfig, TimeManager};
use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::reorganization::reorg_006_manager::ReorgManager;
use crate::runtime::p2p_001_sync_builders::P2pSync;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::alpha_003_detection_system::DetectionSystem;
use crate::utility::helper::canon_wallet_id_checked;

use fips204::ml_dsa_65;
use libp2p::Swarm;
use tokio::sync::{Mutex as TokioMutex, mpsc};

type SigningKey = ml_dsa_65::PrivateKey;

pub struct StartBlockchain {
    pub db_manager: Arc<RockDBManager>,
    pub wallet_registry: RegistryData,
    pub local_wallet: String,
    pub sync_engine: Arc<TokioMutex<P2pSync>>,
    pub signing_key: Arc<SigningKey>,
    pub console_bus: ConsoleBus,
}

impl StartBlockchain {
    #[must_use]
    pub fn new(
        db_manager: RockDBManager,
        local_wallet: String,
        sync_engine: Arc<TokioMutex<P2pSync>>,
        signing_key: Arc<SigningKey>,
    ) -> Self {
        println!("[BOOT] StartBlockchain::new called");
        Self {
            db_manager: Arc::new(db_manager),
            wallet_registry: RegistryData::new(),
            local_wallet,
            sync_engine,
            signing_key,
            console_bus: ConsoleBus::new(),
        }
    }

    /// Build a TimeManager:
    fn build_time_manager(&self) -> Arc<TimeManager> {
        // Try env var first
        if let Ok(path) = std::env::var("REMZAR_GENESIS_PATH") {
            match TimeManager::new_from_genesis_file(&path) {
                Ok(tm) => return Arc::new(tm),
                Err(e) => {
                    eprintln!(
                        "[BOOT][TIME] Failed to load TimeManager from {}: {:?}. Falling back to DB genesis…",
                        path, e
                    );
                }
            }
        }

        // Try block #0 in DB
        if let Ok(Some(block0)) = self.db_manager.get_block_by_index(0) {
            let ts = block0.metadata.timestamp;
            let cfg = TimeConfig::from_genesis_ts(ts);
            return Arc::new(TimeManager::new(cfg));
        }

        // Last resort: current time
        let fallback = TimeConfig::from_genesis_ts(TimeManager::now_unix());
        Arc::new(TimeManager::new(fallback))
    }

    /// Kick off the unified orchestration loop. (async)
    pub async fn run(
        &self,
        swarm: &mut Swarm<RemzarBehaviour>,
        opts: &NodeOpts,
    ) -> Result<(), ErrorDetection> {
        println!("[BOOT] StartBlockchain::run: Starting up…");

        /* 0️⃣ TimeManager (slot clock) */
        let tm = self.build_time_manager();

        /* 1️⃣ Shared DetectionSystem (used by MemPool) */
        let detection_system = Arc::new(DetectionSystem::new());

        /* 2️⃣ MemPool */
        let mempool = Arc::new(MemPool::new(
            Arc::clone(&self.db_manager),
            Arc::clone(&detection_system),
        ));

        /* 3️⃣ AccountModelTree (in-memory state) */
        let mut account_model_tree = AccountModelTree::load_state((*self.db_manager).clone())?;

        /* 4️⃣ EPHEMERAL registry (no pacemaker.rs integration anymore) */
        let mut my_id = self.local_wallet.clone();
        // Ensure canonical "r"+lower-hex form if the caller passed mixed case.
        my_id = canon_wallet_id_checked(&my_id)?;

        let node_ephemeral = {
            // API: in-memory registry only.
            let ne = NodeEphemeral::new();

            // Register self so the local validator appears in-memory immediately.
            // If already canonical & valid, this is idempotent.
            _ = ne.register_wallet_strict(&my_id, /*join_height*/ 0);

            ne
        };

        /* 5️⃣ Reorg manager (validator-aware, wraps ReFork) */
        let reorg_manager = ReorgManager::mainnet_default(Arc::clone(&self.db_manager));

        /* 6️⃣ Unified orchestration loop (expects NodeEphemeral, not RocksDB) */
        let ol = OrchestrationLoop::new(OrchestrationLoopArgs {
            db: Arc::clone(&self.db_manager),
            node_ephemeral,
            mempool: Arc::clone(&mempool),
            sync_engine: Arc::clone(&self.sync_engine),

            // pass signing key through OrchestrationLoopArgs
            signing_key: Arc::clone(&self.signing_key),

            tm: Arc::clone(&tm),
            reorg_manager,
            local_wallet: my_id.clone(),
            console_bus: self.console_bus.clone(),
        });

        println!("[BOOT] Launching OrchestrationLoop…");

        ol.run_until_ctrl_c(
            &mut account_model_tree,
            swarm,
            None::<mpsc::Receiver<NetCmd>>,
            opts,
        )
        .await?;

        println!("[BOOT] StartBlockchain::run: exited cleanly");
        Ok(())
    }
}
