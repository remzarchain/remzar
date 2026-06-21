//! src/commandline/s_03_start_node.rs

use crate::blockchain::block_001_metadata::BlockMetadata;
use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::blockchain_004_orchestration_run::{
    OrchestrationLoop, OrchestrationLoopArgs,
};
use crate::blockchain::genesis_002_file::GenesisFile;
use crate::blockchain::mempool::MemPool;
use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::blockchain::validatorstate::ValidatorState;
use crate::consensus::por_000_ephemeral_registration::{NodeEphemeral, RegistryData};
use crate::consensus::por_005_time_management::{TimeConfig, TimeManager};
use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::network::p2p_001_transport::build_transport;
use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::network::p2p_004_peerdiscovery::{add_peerdiscovery_peers, kick_off_peerdiscovery};
use crate::network::p2p_010_netcmd::NetCmd;
use crate::network::p2p_011_peerbook::PeerBook;
use crate::reorganization::reorg_006_manager::ReorgManager;
use crate::runtime::p2p_001_sync_builders::P2pSync;
use crate::runtime::p2p_006_sync_runtime::{NodeOpts, load_or_generate_identity};
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::storage::rocksdb_007_db_guard::{DbGuard, enforce_db_ownership};
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::alpha_003_detection_system::DetectionSystem;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::blocks_match;
use crate::utility::logging_data::JsonLogger;
use crate::utility::time_policy::TimePolicy;
use colored::Colorize;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::{
    Multiaddr, PeerId,
    core::{muxing::StreamMuxerBox, transport::Boxed},
    swarm::{Config, Swarm},
};
use rust_rocksdb::IteratorMode;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

pub struct S03StartNode<'a> {
    pub node_registry: &'a mut Option<RegistryData>,
    pub node_ephemeral: &'a mut Option<NodeEphemeral>,
    pub db_manager: &'a mut Arc<RockDBManager>,
    pub p2p_running: &'a mut bool,
    pub p2p_handle: &'a mut Option<(JoinHandle<()>, oneshot::Sender<()>)>,
    pub net_tx: &'a mut Option<tokio::sync::mpsc::Sender<NetCmd>>,
    pub console_bus: crate::commandline::s_04_view_blockchain_console::ConsoleBus,
    pub chain: &'a mut Option<AccountModelTree>,
    pub local_wallet: &'a mut String,
    pub blockchain_db_guard: &'a mut Option<DbGuard>,
}

pub struct S03StartNodeArgs<'a> {
    pub node_registry: &'a mut Option<RegistryData>,
    pub node_ephemeral: &'a mut Option<NodeEphemeral>,
    pub db_manager: &'a mut Arc<RockDBManager>,
    pub p2p_running: &'a mut bool,
    pub p2p_handle: &'a mut Option<(JoinHandle<()>, oneshot::Sender<()>)>,
    pub net_tx: &'a mut Option<tokio::sync::mpsc::Sender<NetCmd>>,
    pub console_bus: crate::commandline::s_04_view_blockchain_console::ConsoleBus,
    pub chain: &'a mut Option<AccountModelTree>,
    pub local_wallet: &'a mut String,
    pub blockchain_db_guard: &'a mut Option<DbGuard>,
}

impl<'a> S03StartNode<'a> {
    pub fn new(args: S03StartNodeArgs<'a>) -> Self {
        Self {
            node_registry: args.node_registry,
            node_ephemeral: args.node_ephemeral,
            db_manager: args.db_manager,
            p2p_running: args.p2p_running,
            p2p_handle: args.p2p_handle,
            net_tx: args.net_tx,
            console_bus: args.console_bus,
            chain: args.chain,
            local_wallet: args.local_wallet,
            blockchain_db_guard: args.blockchain_db_guard,
        }
    }

    /* ─────────── non-founder node bootstrap guard ─────────── */

    async fn bootstrap_tcp_online(addr: &Multiaddr) -> bool {
        use libp2p::multiaddr::Protocol;
        use std::net::{IpAddr, SocketAddr};
        use tokio::net::TcpStream;
        use tokio::time::{Duration, timeout};

        let mut ip: Option<IpAddr> = None;
        let mut port: Option<u16> = None;

        for p in addr.iter() {
            match p {
                Protocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
                Protocol::Ip6(v6) => ip = Some(IpAddr::V6(v6)),
                Protocol::Tcp(tcp_port) => port = Some(tcp_port),
                _ => {}
            }
        }

        let Some(ip) = ip else {
            return false;
        };

        let Some(port) = port else {
            return false;
        };

        let socket = SocketAddr::new(ip, port);

        timeout(Duration::from_secs(3), TcpStream::connect(socket))
            .await
            .is_ok_and(|r| r.is_ok())
    }

    /* ─────────── small io helpers (graceful) ─────────── */

    fn flush_stdout(stage: &'static str) -> Result<(), ErrorDetection> {
        use std::io::Write;
        std::io::stdout()
            .flush()
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to flush stdout ({stage}): {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })
    }

    fn read_line_capped(stage: &'static str, cap: usize) -> Result<String, ErrorDetection> {
        use std::io;
        let mut s = String::new();
        io::stdin()
            .read_line(&mut s)
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read input ({stage}): {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;
        if s.len() > cap {
            return Err(ErrorDetection::ValidationError {
                message: format!("Input too long ({stage}): max {} bytes", cap),
                tx_id: None,
            });
        }
        Ok(s)
    }

    fn confirm_yes_no(prompt: &str, stage: &'static str) -> Result<bool, ErrorDetection> {
        for _ in 0..GlobalConfiguration::MAX_ATTEMPTS {
            print!("{}", prompt);
            Self::flush_stdout(stage)?;
            let line = Self::read_line_capped(stage, GlobalConfiguration::MAX_INPUT_BYTES)?;
            match line.trim().to_ascii_lowercase().as_str() {
                "yes" => return Ok(true),
                "no" => return Ok(false),
                _ => {
                    println!("{}", "❌ Please type 'yes' or 'no'.".red());
                }
            }
        }
        Ok(false)
    }

    fn canonicalize_wallet(addr: &str, label: &str) -> Result<String, ErrorDetection> {
        use crate::utility::helper::canon_wallet_id_checked;

        canon_wallet_id_checked(addr).map_err(|e| ErrorDetection::ValidationError {
            message: format!("{label} wallet address is invalid or incomplete: {e}"),
            tx_id: None,
        })
    }

    /* ─────────── guard helpers ─────────── */

    fn ensure_node_stopped(&self) -> Result<(), ErrorDetection> {
        if *self.p2p_running {
            return Err(ErrorDetection::ProtocolError {
                message:
                    "P2P node is running; stop it first (menu 7 → stop) before mutating chain/registry"
                        .into(),
            });
        }
        Ok(())
    }

    /* ─────────── founder/genesis key helpers ─────────── */

    fn compute_genesis_founder_key_hash(founder_key_hex: &str) -> String {
        let preimage_capacity = GlobalConfiguration::GENESIS_FOUNDER_KEY_HASH_DOMAIN
            .len()
            .saturating_add(founder_key_hex.len());

        let mut preimage = Vec::with_capacity(preimage_capacity);

        preimage.extend_from_slice(GlobalConfiguration::GENESIS_FOUNDER_KEY_HASH_DOMAIN);
        preimage.extend_from_slice(founder_key_hex.as_bytes());

        let hash = RemzarHash::compute_bytes_hash_hex(&preimage);

        preimage.zeroize();

        hash
    }

    fn constant_time_eq(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut diff = 0u8;

        for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
            diff |= x ^ y;
        }

        diff == 0
    }

    fn is_ascii_hex_exact(s: &str, len: usize) -> bool {
        s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /* ─────────── founder/binding helpers ─────────── */

    fn read_founder_from_registry(&self) -> Option<String> {
        if let Ok(Some(block0)) = self.db_manager.get_block_by_index(0) {
            let miner = block0.miner_wallet().trim().to_string();
            if !miner.is_empty() {
                return Some(miner);
            }
        }

        if let Some(reg) = self.node_registry.as_ref()
            && let Some(first) = reg.sorted_wallets().into_iter().next()
        {
            return Some(first);
        }

        None
    }

    fn try_bootstrap_miner_wallet(&mut self) {
        if !self.local_wallet.is_empty() {
            return;
        }

        if let Some(ne) = self.node_ephemeral.as_ref() {
            let eph = ne.ephemeral();
            if let Ok(e) = eph.lock()
                && let Some(id) = e.sorted_wallets().into_iter().next()
                && let Ok(canon) = Self::canonicalize_wallet(&id, "Local")
            {
                *self.local_wallet = canon;
                return;
            }
        }

        if let Some(founder) = self.read_founder_from_registry() {
            if let Ok(canon) = Self::canonicalize_wallet(&founder, "Local") {
                *self.local_wallet = canon;
            } else {
                *self.local_wallet = founder;
            }
        }
    }

    fn read_founder_from_block0(db: &RockDBManager) -> Result<Option<String>, ErrorDetection> {
        let Some(block0) = db.get_block_by_index(0)? else {
            return Ok(None);
        };

        let miner = block0.miner_wallet().trim().to_string();
        if miner.is_empty() {
            return Ok(None);
        }

        let founder = Self::canonicalize_wallet(&miner, "Founder-from-block0")?;
        Ok(Some(founder))
    }

    fn ensure_canonical_founder_bootstrap(
        db: &RockDBManager,
    ) -> Result<Option<String>, ErrorDetection> {
        let Some(block0) = db.get_block_by_index(0)? else {
            return Ok(None);
        };

        let miner = block0.miner_wallet().trim().to_string();
        if miner.is_empty() {
            return Ok(None);
        }

        let founder_wallet = Self::canonicalize_wallet(&miner, "Founder-from-block0")?;
        let founder_join_timestamp = block0.metadata.timestamp;

        if founder_join_timestamp < GlobalConfiguration::MIN_TIMESTAMP_SECS {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Canonical founder bootstrap repair failed: block0 timestamp below minimum: {}",
                    founder_join_timestamp
                ),
                tx_id: None,
            });
        }

        let mut vs = ValidatorState::load_or_new(db.clone())?;

        if vs.is_canonically_known(&founder_wallet)? {
            let Some(meta) = vs.meta_for(&founder_wallet) else {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Canonical founder bootstrap repair failed: founder {} is known but metadata is missing",
                        founder_wallet
                    ),
                    tx_id: None,
                });
            };

            if meta.join_height != 0 {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Canonical founder bootstrap verification failed: founder {} has join_height {}, expected 0",
                        founder_wallet, meta.join_height
                    ),
                    tx_id: None,
                });
            }

            if meta.exit_height.is_some() {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Canonical founder bootstrap verification failed: founder {} has exit_height {:?}, expected None",
                        founder_wallet, meta.exit_height
                    ),
                    tx_id: None,
                });
            }

            if meta.join_timestamp < GlobalConfiguration::MIN_TIMESTAMP_SECS {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Canonical founder bootstrap verification failed: founder {} has invalid join_timestamp {}",
                        founder_wallet, meta.join_timestamp
                    ),
                    tx_id: None,
                });
            }

            return Ok(Some(founder_wallet));
        }

        vs.seed_genesis_founder(&founder_wallet, founder_join_timestamp)?;

        Ok(Some(founder_wallet))
    }

    fn verify_canonical_founder_bootstrap(
        db: &RockDBManager,
    ) -> Result<Option<String>, ErrorDetection> {
        let Some(founder_wallet) = Self::read_founder_from_block0(db)? else {
            return Ok(None);
        };

        let vs = ValidatorState::load_or_new(db.clone())?;
        let meta = vs.meta_for(&founder_wallet);
        let is_canonically_known = vs.is_canonically_known(&founder_wallet)?;

        let founder_ok = meta.as_ref().is_some_and(|m| {
            m.join_height == 0
                && m.exit_height.is_none()
                && m.join_timestamp >= GlobalConfiguration::MIN_TIMESTAMP_SECS
        });

        if !is_canonically_known || !founder_ok {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Canonical founder bootstrap verification failed for founder {} \
                    (is_canonically_known={} meta={:?})",
                    founder_wallet, is_canonically_known, meta
                ),
                tx_id: None,
            });
        }

        Ok(Some(founder_wallet))
    }

    fn reconcile_and_verify_canonical_founder_bootstrap(
        db: &RockDBManager,
    ) -> Result<Option<String>, ErrorDetection> {
        let maybe_founder = Self::ensure_canonical_founder_bootstrap(db)?;
        let Some(founder_wallet) = maybe_founder else {
            return Ok(None);
        };

        match Self::verify_canonical_founder_bootstrap(db)? {
            Some(verified) if verified.eq_ignore_ascii_case(&founder_wallet) => {
                Ok(Some(founder_wallet))
            }
            Some(verified) => Err(ErrorDetection::ValidationError {
                message: format!(
                    "Founder bootstrap verification mismatch: reconciled founder {} but verified founder {}",
                    founder_wallet, verified
                ),
                tx_id: None,
            }),
            None => Err(ErrorDetection::ValidationError {
                message: format!(
                    "Founder bootstrap verification unexpectedly returned None after reconciling founder {}",
                    founder_wallet
                ),
                tx_id: None,
            }),
        }
    }

    /* ─────────── Blockchain initialization (genesis) ─────────── */

    pub fn initialize_blockchain(
        &mut self,
        opts: &NodeOpts,
        force: bool,
        genesis_path: &str,
        founder_addr: &str,
    ) -> Result<RockDBManager, ErrorDetection> {
        use crate::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};

        self.ensure_node_stopped()?;

        let founder_addr = Self::canonicalize_wallet(founder_addr, "Founder")?;

        {
            let gp = std::path::Path::new(genesis_path);
            let meta = std::fs::metadata(gp).map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to stat genesis file {}: {e}", gp.display()),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;
            if !meta.is_file()
                || meta.len() == 0
                || meta.len() > GlobalConfiguration::MAX_GENESIS_JSON_BYTES
            {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Genesis file invalid size/type at {} (len={})",
                        gp.display(),
                        meta.len()
                    ),
                    tx_id: None,
                });
            }
        }

        let dir_for_db =
            DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to init DirectoryDB (for blockchain DB): {e}"),
            })?;

        PeerBook::configure_storage_dir(dir_for_db.peerlist_path.clone());

        let blockchain_db_dir = dir_for_db.blockchain_path;
        let blockchain_db_dir_str = blockchain_db_dir.to_string_lossy().to_string();

        /* 1️⃣  Optional wipe */
        if force {
            let db_dir = &blockchain_db_dir;
            if db_dir.exists() {
                println!("⚠️  Existing blockchain DB will be removed (force).");

                let ok = Self::confirm_yes_no(
                    &format!(
                        "{} ",
                        "Are you sure you want to continue? (yes/no):".yellow()
                    ),
                    "initialize_blockchain.force_confirm",
                )?;
                if !ok {
                    return Err(ErrorDetection::ValidationError {
                        message: "Aborted: Blockchain DB not removed".into(),
                        tx_id: None,
                    });
                }

                std::fs::remove_dir_all(db_dir).map_err(|e| ErrorDetection::StorageError {
                    message: format!("Failed to remove old DB: {e}"),
                })?;
                println!("{}", "✅ Existing blockchain DB removed.".green());
            }
        }

        /* Load & validate deterministic genesis */
        let genesis_file = GenesisFile::from_json_file(genesis_path)?;
        genesis_file.validate()?;

        /* Open (or create) RocksDB */
        let mgr = RockDBManager::new_blockchain(opts, &blockchain_db_dir_str)?;

        /* Existing chain & not forcing → resume */
        if !force && mgr.get_latest_block()?.is_some() {
            println!("{}", "✅ Blockchain exists – resuming.".green());

            match Self::reconcile_and_verify_canonical_founder_bootstrap(&mgr)? {
                Some(_founder) => {}
                None => {
                    return Err(ErrorDetection::ValidationError {
                        message:
                            "Existing chain resumed, but block0 does not expose founder wallet. \
                            Refusing to continue because canonical founder bootstrap cannot be verified."
                                .into(),
                        tx_id: None,
                    });
                }
            }

            return Ok(mgr);
        }

        /* No chain (or --force) → build from genesis */
        println!(
            "{}",
            "🔄 No chain found (or --force) – loading genesis.".cyan()
        );

        let md0 = BlockMetadata::from_genesis(genesis_file.genesis_block)?;

        // Genesis block must carry the founder wallet canonically so that every
        // syncing node can reconstruct founder/bootstrap semantics from shared chain data.
        let block0 = Block::new(md0, None, founder_addr.clone(), 0)?;
        let bytes = block0.serialize_for_storage()?;

        // canonical storage path
        mgr.store_latest_block(&bytes, 0)?;
        mgr.index_block_by_hash(&block0.block_hash, &bytes)?;
        mgr.store_metadata("latest_block_index", &0u64.to_be_bytes())?;
        mgr.set_tip_height(0)?;

        // -----------------------------------------------------------------
        // seed genesis into the reorg/fork graph as well
        // -----------------------------------------------------------------
        let received_at_unix_secs = TimePolicy::now_unix_secs_runtime()?;

        let genesis_meta = ForkBlockMeta {
            parent_hash: block0.metadata.previous_hash,
            height: 0,
            cumulative_score: 0,
            status: ForkBlockStatus::Canonical,
            received_at_unix_secs,
        };

        // Durable fork truth: block_meta_by_hash
        mgr.store_block_meta_by_hash(&block0.block_hash, &genesis_meta)?;

        // Canonical reorg projection: height -> hash
        mgr.set_canonical_hash_at_height(0, &block0.block_hash)?;

        // Canonical reorg tip view
        mgr.set_canonical_tip(&block0.block_hash, 0)?;

        // Founder bootstrap is seeded into canonical validator state.
        {
            let mut vs = ValidatorState::load_or_new(mgr.clone())?;
            vs.seed_genesis_founder(&founder_addr, block0.metadata.timestamp)?;
        }

        match Self::verify_canonical_founder_bootstrap(&mgr)? {
            Some(_founder) => {}
            None => {
                return Err(ErrorDetection::ValidationError {
                    message:
                        "Genesis initialization completed, but founder bootstrap could not be verified from block0."
                            .into(),
                    tx_id: None,
                });
            }
        }

        println!("{}", "✅ Genesis block stored.".green());
        println!("{}", "✅ Genesis seeded into reorg graph.".green());

        *self.local_wallet = founder_addr;

        println!("{}", "✅ Blockchain initialised from genesis.".green());
        Ok(mgr)
    }

    // ──────────────────────────────────────────────────────────────────────
    // 3) Initialize P2P & Blockchain (resume if possible, otherwise genesis).
    // ──────────────────────────────────────────────────────────────────────
    pub async fn start_node(&mut self, json_logger: &JsonLogger) -> Result<(), ErrorDetection> {
        _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_ansi(true)
            .try_init();

        // Always have an EPHEMERAL registry available
        if self.node_ephemeral.is_none() {
            *self.node_ephemeral = Some(NodeEphemeral::new());
        }
        let node_ephemeral = match self.node_ephemeral.as_ref() {
            Some(ne) => ne.clone(),
            None => {
                return Err(ErrorDetection::ValidationError {
                    message: "NodeEphemeral missing after initialization".to_string(),
                    tx_id: None,
                });
            }
        };

        // Guard: don't start twice
        if *self.p2p_running {
            println!("{}", "ℹ️ P2P node is already running.".yellow());
            return Ok(());
        }

        // =============================
        // STEP 0: FOUNDER PROMPT!
        // =============================

        println!("{}", "Welcome to Remzar Blockchain!".bright_green().bold());
        let mut is_founder_input = String::new();
        print!("Are you the original founder? (yes/no): ");
        _ = io::stdout().flush();
        if let Err(e) = io::stdin().read_line(&mut is_founder_input) {
            println!("❌ Failed to read input: {e}");
            return Ok(());
        }

        let is_founder = match is_founder_input.trim().to_ascii_lowercase().as_str() {
            "yes" => true,
            "no" => false,
            _ => {
                println!(
                    "{}",
                    "❌ Invalid response. Please type 'yes' or 'no' only. Returning to menu.".red()
                );
                return Ok(());
            }
        };

        let mut founder_authenticated = false;

        if is_founder {
            if !Self::is_ascii_hex_exact(
                GlobalConfiguration::GENESIS_FOUNDER_KEY_EXPECTED_HASH,
                GlobalConfiguration::GENESIS_FOUNDER_KEY_HASH_HEX_LEN,
            ) {
                return Err(ErrorDetection::ValidationError {
                    message: "GlobalConfiguration::GENESIS_FOUNDER_KEY_EXPECTED_HASH is malformed"
                        .into(),
                    tx_id: None,
                });
            }

            let founder_key_path = Path::new(GlobalConfiguration::GENESIS_FOUNDER_KEY_PATH);

            let meta = match fs::metadata(founder_key_path) {
                Ok(meta) => meta,
                Err(_) => {
                    println!("{}", "❌ Founder permission only. Exit to Menu.".red());
                    return Ok(());
                }
            };

            if !meta.is_file() || meta.len() == 0 {
                println!("{}", "❌ founder.key is missing or not a file.".red());
                return Ok(());
            }

            if meta.len() > GlobalConfiguration::GENESIS_FOUNDER_KEY_MAX_FILE_BYTES {
                println!("{}", "❌ founder.key is too large. Exiting to menu.".red());
                return Ok(());
            }

            match fs::read_to_string(founder_key_path) {
                Ok(key_str) => {
                    let mut key = key_str.trim().to_ascii_lowercase();

                    if !Self::is_ascii_hex_exact(
                        &key,
                        GlobalConfiguration::GENESIS_FOUNDER_KEY_HEX_LEN,
                    ) {
                        println!(
                            "{}",
                            "❌ Invalid founder.key format. Exiting to menu.".red()
                        );
                        key.zeroize();
                        return Ok(());
                    }

                    let actual_hash = Self::compute_genesis_founder_key_hash(&key);

                    if Self::constant_time_eq(
                        &actual_hash,
                        GlobalConfiguration::GENESIS_FOUNDER_KEY_EXPECTED_HASH,
                    ) {
                        founder_authenticated = true;
                        println!("{}", "✅ Founder key located and accepted.".green());
                    } else {
                        println!(
                            "{}",
                            "❌ Founder key rejected. Not the official founder key.".red()
                        );
                        key.zeroize();
                        return Ok(());
                    }

                    key.zeroize();
                }
                Err(_) => {
                    println!("{}", "❌ Founder permission only. Exit to Menu.".red());
                    return Ok(());
                }
            }
        }

        // =============================
        // STEP 1: GENESIS/DB CHECK FIRST!
        // =============================

        let opts_for_db = NodeOpts {
            founder: is_founder,
            identity_file: "identity.key".into(),
            listen: "/ip4/0.0.0.0/tcp/36213".into(),
            bootstrap: vec![],
            log: "info".into(),
            data_dir: "data".into(),
            wallet_address: self.local_wallet.clone(),
        };

        let genesis_path =
            std::env::var("REMZAR_GENESIS_PATH").unwrap_or_else(|_| "genesis.json".to_string());

        let dir_for_db = DirectoryDB::from_node_opts(&opts_for_db).map_err(|e| {
            let msg = format!("Failed to init DirectoryDB (for DB path): {e}");
            json_logger
                .log_error_event("blockchain", "DirectoryInitFailedForDbPath", &msg)
                .ok();
            ErrorDetection::DatabaseError { details: msg }
        })?;

        PeerBook::configure_storage_dir(dir_for_db.peerlist_path.clone());

        let blockchain_db_dir = dir_for_db.blockchain_path.clone();
        let blockchain_db_dir_str = blockchain_db_dir.to_string_lossy().to_string();

        if self.blockchain_db_guard.is_none() {
            let id_path_for_guard = Path::new(&opts_for_db.identity_file);
            let id_keys_for_guard = match load_or_generate_identity(id_path_for_guard) {
                Ok(keys) => keys,
                Err(e) => {
                    let msg = format!("Failed to load/generate identity (for DB guard): {e}");
                    json_logger
                        .log_error_event("p2p", "IdentityKeyFailedForDbGuard", &msg)
                        .ok();
                    return Err(ErrorDetection::ProtocolError { message: msg });
                }
            };

            let peer_id_for_guard = PeerId::from(id_keys_for_guard.public());
            let node_id_for_guard = peer_id_for_guard.to_string();

            let guard = enforce_db_ownership(&blockchain_db_dir, &node_id_for_guard)?;
            *self.blockchain_db_guard = Some(guard);
        }

        let needs_genesis = {
            let tmp_mgr = RockDBManager::new_blockchain(&opts_for_db, &blockchain_db_dir_str)
                .map_err(|e| {
                    let msg = format!("Failed to create blockchain DB: {e}");
                    json_logger
                        .log_error_event("blockchain", "TmpBlockchainDbFailed", &msg)
                        .ok();
                    ErrorDetection::DatabaseError { details: msg }
                })?;

            if tmp_mgr.get_latest_block().ok().flatten().is_some() {
                match Self::reconcile_and_verify_canonical_founder_bootstrap(&tmp_mgr)? {
                    Some(_founder) => {}
                    None => {
                        return Err(ErrorDetection::ValidationError {
                        message:
                            "Existing chain found, but founder wallet could not be derived from block0. \
                            Refusing startup because canonical founder bootstrap cannot be verified."
                                .into(),
                        tx_id: None,
                    });
                    }
                }
            }

            tmp_mgr.get_latest_block().ok().flatten().is_none()
        };

        let chain_already_exists = !needs_genesis;

        if needs_genesis {
            if is_founder && founder_authenticated {
                if !Path::new(&genesis_path).exists() {
                    println!(
                        "❌ genesis.json file is required to initialize the blockchain as founder. \
                        Please supply it before starting the node."
                    );
                    std::process::exit(1);
                }

                println!();
                println!("{}", "📄 Genesis required: No blockchain found.".yellow());
                println!(
                "{}",
                "Loading the genesis.json and initializing the blockchain as founder. (Press Enter to continue)"
                    .cyan()
            );
                _ = {
                    let mut dummy = String::new();
                    std::io::stdin().read_line(&mut dummy)
                };

                // Do NOT manually delete RocksDB's LOCK file.
                println!(
                    "Skipping manual DB LOCK cleanup before genesis initialization for '{}'",
                    blockchain_db_dir.display()
                );

                println!(
                    "Enter the founder wallet address (this will be the initial validator/leader):"
                );

                use crate::utility::helper::canon_wallet_id_checked;

                let founder_addr_canon = loop {
                    let mut input = String::new();
                    if let Err(e) = std::io::stdin().read_line(&mut input) {
                        println!("❌ Failed to read input: {e}");
                        continue;
                    }

                    let trimmed = input.trim();

                    if trimmed.is_empty() {
                        println!("❌ Wallet address cannot be empty. Try again:");
                        continue;
                    }

                    match canon_wallet_id_checked(trimmed) {
                        Ok(canon) => {
                            break canon;
                        }
                        Err(_e) => {
                            println!(
                                "❌ Invalid wallet format (expected 'r' + 128 hex chars, total len 129). Try again:"
                            );
                            continue;
                        }
                    }
                };

                let db = match self.initialize_blockchain(
                    &opts_for_db,
                    false,
                    &genesis_path,
                    &founder_addr_canon,
                ) {
                    Ok(db) => db,
                    Err(e) => {
                        json_logger
                            .log_error_event(
                                "blockchain",
                                "InitializeBlockchainFailed",
                                "initialize_blockchain failed (see console for details)",
                            )
                            .ok();
                        return Err(e);
                    }
                };

                match Self::verify_canonical_founder_bootstrap(&db)? {
                    Some(_founder) => {}
                    None => {
                        return Err(ErrorDetection::ValidationError {
                        message:
                            "Founder bootstrap could not be verified from block0 after genesis init."
                                .into(),
                        tx_id: None,
                    });
                    }
                }

                match db.flush_blockchain_db() {
                    Ok(_) => {}
                    Err(e) => {
                        json_logger
                            .log_error_event(
                                "blockchain",
                                "FlushBlockchainDbFailed",
                                "flush_blockchain_db failed (see console for details)",
                            )
                            .ok();
                        return Err(e);
                    }
                }

                drop(db);

                println!(
                    "Dropped genesis DB handle; not deleting LOCK file for '{}'",
                    blockchain_db_dir.display()
                );

                println!();
                println!("✅ Genesis block loaded and blockchain initialized as founder.");
                println!();

                _ = node_ephemeral.register_wallet_strict(&founder_addr_canon, 0);
                _ = node_ephemeral.set_join_height(&founder_addr_canon, 0);
                println!(
                    "✅ Ephemeral registry initialized (founder registered in memory): {}",
                    founder_addr_canon
                );

                *self.local_wallet = founder_addr_canon;
            } else {
                println!(
                    "{}",
                    "⏳ No local blockchain found. Proceeding to P2P sync...".yellow()
                );
            }
        }

        // =========================================
        // STEP 2: NOW PROMPT FOR NETWORK SETTINGS
        // =========================================

        let mut listen_ip = String::new();
        print!("Enter the IP address this node should LISTEN on (default: 0.0.0.0): ");
        io::stdout().flush().ok();
        if io::stdin().read_line(&mut listen_ip).is_err() {
            println!("⚠️  Failed to read input for IP address, using default 0.0.0.0.");
            listen_ip = String::from("0.0.0.0");
        }
        let listen_ip = listen_ip.trim();
        let listen_ip = if listen_ip.is_empty() {
            "0.0.0.0"
        } else {
            listen_ip
        };

        let mut listen_port = String::new();
        print!("Enter the PORT this node should LISTEN on (default: 36213): ");
        io::stdout().flush().ok();
        if io::stdin().read_line(&mut listen_port).is_err() {
            println!("⚠️  Failed to read input for port, using default 36213.");
            listen_port = String::from("36213");
        }
        let listen_port = listen_port.trim();
        let listen_port = if listen_port.is_empty() {
            "36213"
        } else {
            listen_port
        };

        let listen_addr = format!("/ip4/{}/tcp/{}", listen_ip, listen_port);

        let mut is_founder_node = String::new();
        print!("Is this the FOUNDER node (the 'boot' node everyone else connects to)? (yes/no): ");
        io::stdout().flush().ok();
        if io::stdin().read_line(&mut is_founder_node).is_err() {
            println!("⚠️  Failed to read input. Defaulting to 'no'.");
            is_founder_node = String::from("no");
        }
        let is_founder_node = is_founder_node.trim().eq_ignore_ascii_case("yes");

        if is_founder_node && !founder_authenticated {
            println!("{}", "❌ Founder permission only. Exit to Menu".red());
            return Ok(());
        }

        // -----------------------------------------
        // Bootstrap (multi): require /p2p/<PeerId>
        // -----------------------------------------
        let mut bootstrap_lines: Vec<String> = Vec::new();

        if !is_founder_node {
            println!();
            println!("Enter one or more bootstrap peers as FULL multiaddrs, one per line.");
            println!(
                "Format : /ip4/<IP>/tcp/<PORT>/p2p/<PeerId>  (or /dnsaddr/<host>/p2p/<PeerId>)"
            );
            println!("Example: /ip4/10.0.0.20/tcp/36213/p2p/12D3KooW...");
            println!("Press Enter on an empty line to finish.");
            println!();

            let mut seen_peer_ids = HashSet::<String>::new();

            loop {
                print!("Bootstrap multiaddr: ");
                io::stdout().flush().ok();

                let mut line = String::new();
                if io::stdin().read_line(&mut line).is_err() {
                    println!("⚠️  Failed to read input, stopping bootstrap entry.");
                    break;
                }
                let line = line.trim().to_string();
                if line.is_empty() {
                    break;
                }

                let addr: Multiaddr = match line.parse::<Multiaddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        println!("❌ Invalid multiaddr '{}': {}", line, e);
                        continue;
                    }
                };

                let pid_str = match addr.iter().last() {
                    Some(Protocol::P2p(mh)) => mh.to_string(),
                    _ => {
                        println!("❌ '{}' is missing trailing /p2p/<PeerId> component.", line);
                        continue;
                    }
                };

                if pid_str.parse::<PeerId>().is_err() {
                    println!("❌ '{}' has an invalid PeerId at the end.", line);
                    continue;
                }

                if !seen_peer_ids.insert(pid_str.clone()) {
                    println!("ℹ️  Skipping duplicate PeerId {}", pid_str);
                    continue;
                }

                println!("✅ added {}", line);
                bootstrap_lines.push(line);
            }

            if !bootstrap_lines.is_empty() {
                let mut by_peer: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
                for s in &bootstrap_lines {
                    if let Ok(addr) = s.parse::<Multiaddr>()
                        && let Some(Protocol::P2p(mh)) = addr.iter().last()
                        && let Ok(pid) = mh.to_string().parse::<PeerId>()
                    {
                        by_peer.entry(pid).or_default().insert(addr);
                    }
                }

                let mut peerbook = PeerBook::load_or_init();
                let mut total_peers = 0usize;

                for (pid, set) in by_peer.into_iter() {
                    let addrs: Vec<Multiaddr> = set.into_iter().collect();
                    peerbook.upsert(&pid, addrs, /*mark_success=*/ false);
                    total_peers = total_peers.saturating_add(1);
                }

                if let Err(e) = peerbook.save() {
                    println!("❌ Failed to save bootstrap peers: {}", e);
                } else {
                    println!(
                        "💾 Saved {} bootstrap peer(s) to data/peerlist.json",
                        total_peers
                    );
                }
            }
        }

        // =========================================================
        // COLD REBOOT GUARD
        //
        // Rule:
        // - Founder may reboot the chain.
        // - Non-founder may join only if the founder/bootnode is reachable.
        // - Non-founder may NOT restart an existing chain alone from local DB.
        // =========================================================
        let mut non_founder_bootstrap_verified_online = false;

        if chain_already_exists && !is_founder && !founder_authenticated {
            if bootstrap_lines.is_empty() {
                println!("{}", "❌ Non-founder cold reboot denied.".red());
                println!(
                    "{}",
                    "Founder bootnode is required when restarting an existing chain.".yellow()
                );
                println!(
                    "{}",
                    "Please start Node 1/founder first, then try again.".yellow()
                );
                return Ok(());
            }

            for s in &bootstrap_lines {
                let Ok(addr) = s.parse::<Multiaddr>() else {
                    continue;
                };

                if Self::bootstrap_tcp_online(&addr).await {
                    non_founder_bootstrap_verified_online = true;
                    break;
                }
            }

            if !non_founder_bootstrap_verified_online {
                println!("{}", "❌ Founder bootnode is offline.".red());
                println!(
                    "{}",
                    "Please wait until Node 1/founder is back online.".yellow()
                );
                println!(
                    "{}",
                    "Non-founder nodes cannot solo reboot the chain from local DB.".red()
                );
                return Ok(());
            }
        }

        let bootstrap: Vec<String> = bootstrap_lines.clone();

        // =========================================
        // STEP 3 (+3A): wallet resolution
        // =========================================

        // =========================================================
        // FOUNDER REBOOT RULE (NO AUTO-DETECT, NO EPHEMERAL PICKUP)
        // - If the chain already exists AND founder is authenticated,
        //   we REQUIRE an explicit wallet choice (old or new).
        // - This keeps reboot behavior deterministic and user-driven.
        // =========================================================

        use dialoguer::Password;
        use fips204::ml_dsa_65;
        use fips204::traits::{SerDes, Signer};
        use zeroize::Zeroize;

        use crate::utility::helper::{
            canon_wallet_id_checked, wallet_id_matches_pubkey_bytes_checked,
        };

        let mut signing_key_cached: Option<Arc<ml_dsa_65::PrivateKey>> = None;

        let prove_wallet_ownership_or_menu = |wallet_addr: &mut String| -> Result<
            Option<Arc<ml_dsa_65::PrivateKey>>,
            ErrorDetection,
        > {
            if wallet_addr.trim().is_empty() {
                return Ok(None);
            }

            let canon_wallet = match canon_wallet_id_checked(wallet_addr.as_str()) {
                Ok(w) => w,
                Err(e) => {
                    println!("{}", format!("❌ {e}. Returning to menu.").red());
                    wallet_addr.clear();
                    return Ok(None);
                }
            };
            *wallet_addr = canon_wallet;

            let mut passphrase = match Password::new()
                .with_prompt("🔒 Enter passphrase for this wallet")
                .allow_empty_password(false)
                .interact()
            {
                Ok(p) => p,
                Err(e) => {
                    println!(
                        "{}",
                        format!("❌ Failed to read passphrase: {e}. Returning to menu.").red()
                    );
                    wallet_addr.clear();
                    return Ok(None);
                }
            };

            let directory = match DirectoryDB::from_node_opts(&opts_for_db) {
                Ok(d) => d,
                Err(e) => {
                    passphrase.zeroize();
                    let msg = format!("Failed to initialise directories: {e}");
                    json_logger
                        .log_error_event("wallet", "WalletInitDirectoriesFailed", &msg)
                        .ok();
                    println!("{}", format!("❌ {msg}. Returning to menu.").red());
                    wallet_addr.clear();
                    return Ok(None);
                }
            };

            let wallet_file = directory
                .wallets_path
                .join(format!("{}.wallet", wallet_addr));
            if !wallet_file.exists() {
                passphrase.zeroize();
                println!(
                    "{}",
                    format!(
                        "❌ Wallet file not found at {}. Returning to menu.",
                        wallet_file.display()
                    )
                    .red()
                );
                wallet_addr.clear();
                return Ok(None);
            }

            let mut encrypted_pk = match fs::read(&wallet_file) {
                Ok(b) => b,
                Err(e) => {
                    passphrase.zeroize();
                    let msg = format!("Failed to read wallet file: {e}");
                    json_logger
                        .log_error_event("wallet", "WalletReadFileFailed", &msg)
                        .ok();
                    println!("{}", format!("❌ {msg}. Returning to menu.").red());
                    wallet_addr.clear();
                    return Ok(None);
                }
            };

            let sk_arc: Arc<ml_dsa_65::PrivateKey> = match Cryption::decrypt_private_key_bytes(
                &encrypted_pk,
                &passphrase,
            ) {
                Ok(mut sk_bytes) => {
                    if sk_bytes.len() != ml_dsa_65::SK_LEN {
                        let got = sk_bytes.len();

                        sk_bytes.zeroize();
                        passphrase.zeroize();
                        encrypted_pk.zeroize();

                        let log_msg = format!(
                            "Wallet decrypted but secret length mismatch: expected {} bytes, got {}",
                            ml_dsa_65::SK_LEN,
                            got
                        );
                        json_logger
                            .log_error_event("wallet", "WalletDecryptLengthMismatch", &log_msg)
                            .ok();
                        println!("{}", format!("❌ {log_msg}. Returning to menu.").red());

                        wallet_addr.clear();
                        return Ok(None);
                    }

                    let sk_arr: [u8; ml_dsa_65::SK_LEN] = match sk_bytes.as_slice().try_into() {
                        Ok(a) => a,
                        Err(_) => {
                            sk_bytes.zeroize();
                            passphrase.zeroize();
                            encrypted_pk.zeroize();

                            let log_msg = "Failed to convert decrypted secret into fixed-size ML-DSA-65 array.";
                            json_logger
                                .log_error_event("wallet", "WalletKeyArrayConvertFailed", log_msg)
                                .ok();
                            println!("{}", format!("❌ {log_msg} Returning to menu.").red());

                            wallet_addr.clear();
                            return Ok(None);
                        }
                    };

                    sk_bytes.zeroize();

                    let sk = match ml_dsa_65::PrivateKey::try_from_bytes(sk_arr) {
                        Ok(k) => k,
                        Err(e) => {
                            passphrase.zeroize();
                            encrypted_pk.zeroize();

                            let log_msg = format!("Invalid ML-DSA-65 secret key bytes: {e}");
                            json_logger
                                .log_error_event("wallet", "WalletKeyReconstructFailed", &log_msg)
                                .ok();
                            println!("{}", format!("❌ {log_msg}. Returning to menu.").red());

                            wallet_addr.clear();
                            return Ok(None);
                        }
                    };

                    let pk = sk.get_public_key();
                    let pk_bytes = pk.into_bytes();

                    match wallet_id_matches_pubkey_bytes_checked(wallet_addr.as_str(), &pk_bytes) {
                        Ok(canon) => {
                            *wallet_addr = canon;
                        }
                        Err(e) => {
                            passphrase.zeroize();
                            encrypted_pk.zeroize();

                            let log_msg =
                                format!("Unlocked key does not match wallet address: {e}");
                            json_logger
                                .log_error_event("wallet", "WalletAddressMismatch", &log_msg)
                                .ok();
                            println!("{}", format!("❌ {log_msg}. Returning to menu.").red());

                            wallet_addr.clear();
                            return Ok(None);
                        }
                    }

                    Arc::new(sk)
                }
                Err(e) => {
                    passphrase.zeroize();
                    encrypted_pk.zeroize();

                    let log_msg = format!("Wallet decryption failed: {e}");
                    json_logger
                        .log_error_event("wallet", "WalletDecryptFailed", &log_msg)
                        .ok();
                    println!("{}", format!("❌ {log_msg}. Returning to menu.").red());

                    wallet_addr.clear();
                    return Ok(None);
                }
            };

            passphrase.zeroize();
            encrypted_pk.zeroize();

            Ok(Some(sk_arc))
        };

        if is_founder
            && founder_authenticated
            && !chain_already_exists
            && !self.local_wallet.trim().is_empty()
            && signing_key_cached.is_none()
        {
            if let Ok(canon) = canon_wallet_id_checked(self.local_wallet.as_str()) {
                *self.local_wallet = canon;
            }

            signing_key_cached = prove_wallet_ownership_or_menu(self.local_wallet)?;
            if self.local_wallet.is_empty() {
                return Ok(());
            }
        }

        if is_founder && founder_authenticated && chain_already_exists {
            self.local_wallet.clear();

            loop {
                print!(
                    "“Solo bootstrap mode” after a restart, you must use original validator wallet.” 
                            💳 Enter wallet: "
                );
                io::stdout().flush().ok();

                let mut w = String::new();
                if io::stdin().read_line(&mut w).is_err() {
                    println!("⚠️  Failed to read input, try again.");
                    continue;
                }

                let trimmed = w.trim();
                if trimmed.is_empty() {
                    println!(
                        "No wallet provided; founder node will run in observer mode unless you register later."
                    );
                    break;
                }

                let canon = match canon_wallet_id_checked(trimmed) {
                    Ok(c) => c,
                    Err(_) => {
                        println!("❌ Invalid wallet format (must be 'r' + 128 hex). Try again:");
                        continue;
                    }
                };

                *self.local_wallet = canon;

                signing_key_cached = prove_wallet_ownership_or_menu(self.local_wallet)?;
                if self.local_wallet.is_empty() {
                    return Ok(());
                }

                println!("🔑 Using wallet: {}", self.local_wallet);
                break;
            }
        } else {
            let was_empty = self.local_wallet.is_empty();
            self.try_bootstrap_miner_wallet();
            if was_empty && !self.local_wallet.is_empty() {
                if let Ok(canon) = canon_wallet_id_checked(self.local_wallet.as_str()) {
                    *self.local_wallet = canon;
                }

                println!("🔑 Using auto-detected wallet: {}", self.local_wallet);

                signing_key_cached = prove_wallet_ownership_or_menu(self.local_wallet)?;
                if self.local_wallet.is_empty() {
                    return Ok(());
                }
            }

            if self.local_wallet.is_empty() && is_founder {
                let maybe_founder_wallet = {
                    let e = node_ephemeral.ephemeral();
                    match e.lock() {
                        Ok(reg) => {
                            if reg.wallets.len() == 1 {
                                reg.sorted_wallets().into_iter().next()
                            } else {
                                None
                            }
                        }
                        Err(_) => {
                            return Err(ErrorDetection::ValidationError {
                                message: "Failed to lock EPHEMERAL registry (mutex poisoned)"
                                    .to_string(),
                                tx_id: None,
                            });
                        }
                    }
                };

                if let Some(w) = maybe_founder_wallet {
                    *self.local_wallet = match canon_wallet_id_checked(&w) {
                        Ok(c) => c,
                        Err(_) => {
                            println!("❌ EPHEMERAL founder wallet is invalid. Running observer.");
                            String::new()
                        }
                    };

                    if !self.local_wallet.is_empty() {
                        println!(
                            "🔑 Using founder wallet from EPHEMERAL registry: {}",
                            self.local_wallet
                        );

                        signing_key_cached = prove_wallet_ownership_or_menu(self.local_wallet)?;
                        if self.local_wallet.is_empty() {
                            return Ok(());
                        }
                    }
                }
            }

            if self.local_wallet.is_empty() && !is_founder {
                loop {
                    print!("💳 Enter your wallet address for mining (leave blank to observe): ");
                    io::stdout().flush().ok();

                    let mut w = String::new();
                    if io::stdin().read_line(&mut w).is_err() {
                        println!("⚠️  Failed to read input, try again.");
                        continue;
                    }

                    let trimmed = w.trim();
                    if trimmed.is_empty() {
                        println!(
                            "👀 No wallet provided; node will run in observer mode unless you register later."
                        );
                        break;
                    }

                    let canon = match canon_wallet_id_checked(trimmed) {
                        Ok(c) => c,
                        Err(_) => {
                            println!(
                                "❌ Invalid wallet format (must be 'r' + 128 hex). Try again:"
                            );
                            continue;
                        }
                    };

                    *self.local_wallet = canon;

                    signing_key_cached = prove_wallet_ownership_or_menu(self.local_wallet)?;
                    if self.local_wallet.is_empty() {
                        return Ok(());
                    }

                    let wallet_canon = match canon_wallet_id_checked(self.local_wallet.as_str()) {
                        Ok(wc) => wc,
                        Err(_) => {
                            println!("❌ Wallet address is invalid or incomplete. Try again:");
                            self.local_wallet.clear();
                            signing_key_cached = None;
                            continue;
                        }
                    };
                    *self.local_wallet = wallet_canon.clone();

                    let binding_path =
                        std::path::Path::new(&opts_for_db.data_dir).join(".wallet_binding");

                    if binding_path.exists() {
                        let expected = std::fs::read_to_string(&binding_path).map_err(|e| {
                            ErrorDetection::StorageError {
                                message: format!(
                                    "Failed to read wallet binding file {}: {e}",
                                    binding_path.display()
                                ),
                            }
                        })?;
                        let expected = expected.trim().to_string();

                        if expected != wallet_canon {
                            println!(
                                "{}",
                                format!(
                                    "❌ Wallet mismatch for this node.\n\
                                            - bound wallet: {}\n\
                                            - provided wallet: {}\n\
                                            Use the bound wallet, or leave blank for observer.",
                                    expected, wallet_canon
                                )
                                .red()
                            );

                            self.local_wallet.clear();
                            signing_key_cached = None;
                            continue;
                        }
                    } else {
                        std::fs::write(&binding_path, format!("{wallet_canon}\n")).map_err(
                            |e| ErrorDetection::StorageError {
                                message: format!(
                                    "Failed to write wallet binding file {}: {e}",
                                    binding_path.display()
                                ),
                            },
                        )?;
                    }

                    println!("🔑 Using wallet: {}", self.local_wallet);
                    break;
                }
            }
        }

        println!(
            "🔎 Local wallet set to: {}",
            if self.local_wallet.is_empty() {
                "<empty/observer>"
            } else {
                self.local_wallet.as_str()
            }
        );

        let opts = NodeOpts {
            founder: is_founder,
            identity_file: "identity.key".into(),
            listen: listen_addr,
            bootstrap,
            log: "info".into(),
            data_dir: "data".into(),
            wallet_address: self.local_wallet.clone(),
        };

        let id_path = Path::new(&opts.identity_file);
        let id_keys = match load_or_generate_identity(id_path) {
            Ok(keys) => keys,
            Err(e) => {
                let msg = format!("Failed to load/generate identity: {e}");
                json_logger
                    .log_error_event("p2p", "IdentityKeyFailed", &msg)
                    .ok();
                return Err(ErrorDetection::ProtocolError { message: msg });
            }
        };
        let identity_status = "registered";

        let peer_id = PeerId::from(id_keys.public());
        info!("▶ Local PeerId: {peer_id}");

        // =========================================
        // STEP 4: Transport & Behaviour & Swarm setup
        // =========================================
        type Transport = Boxed<(PeerId, StreamMuxerBox)>;
        let transport: Transport = build_transport(id_keys.clone()).map_err(|e| {
            let msg = format!("Failed to build transport: {e}");
            json_logger
                .log_error_event("p2p", "BuildTransportFailed", &msg)
                .ok();
            ErrorDetection::ProtocolError { message: msg }
        })?;

        let cfg = Config::with_tokio_executor()
            .with_idle_connection_timeout(std::time::Duration::from_secs(120));

        let mut behaviour = RemzarBehaviour::new(id_keys.clone()).map_err(|e| {
            let msg = format!("Failed to initialize RemzarBehaviour: {e}");
            json_logger
                .log_error_event("p2p", "RemzarBehaviourInitFailed", &msg)
                .ok();
            ErrorDetection::ProtocolError { message: msg }
        })?;

        use libp2p::gossipsub::IdentTopic;
        for t in [
            "remzar",
            "remzar/register",
            "remzar/blocks",
            "remzar/vote",
            "remzar/tx",
        ] {
            behaviour
                .gossipsub
                .subscribe(&IdentTopic::new(t))
                .map_err(|e| {
                    let msg = format!("Failed to subscribe to gossipsub topic '{}': {e}", t);
                    json_logger
                        .log_error_event("p2p", "GossipsubSubscribeFailed", &msg)
                        .ok();
                    ErrorDetection::ProtocolError { message: msg }
                })?;
        }

        let mut swarm = Swarm::new(transport, behaviour, peer_id, cfg);

        {
            use crate::network::p2p_008_broadcast::Broadcaster;
            let mut b = Broadcaster::new(&mut swarm);
            b.join_all_topics().map_err(|e| {
                let msg = format!("Failed to join gossip topics: {e}");
                json_logger
                    .log_error_event("p2p", "JoinAllTopicsFailed", &msg)
                    .ok();
                ErrorDetection::ProtocolError { message: msg }
            })?;
        }

        swarm
            .listen_on(opts.listen.parse().map_err(|e: libp2p::multiaddr::Error| {
                ErrorDetection::ValidationError {
                    message: e.to_string(),
                    tx_id: None,
                }
            })?)
            .map_err(|e| {
                let msg = format!("Failed to listen on {}: {e}", opts.listen);
                json_logger
                    .log_error_event("p2p", "SwarmListenFailed", &msg)
                    .ok();
                ErrorDetection::ProtocolError { message: msg }
            })?;
        info!("▶ Listening on {}", opts.listen);

        // =========================================
        // STEP 5: Peer bootstrapping (PeerBook-based)
        // =========================================
        // PRODUCTION RULES:
        // - Bootstrap is an entry point, NOT a permanent topology restriction.
        // - Non-founders may start from explicit /p2p/<PeerId> seeds,
        //   but after that they MUST be allowed to expand from PeerBook
        //   and Kademlia/Identify-driven discovery.
        // =========================================
        let detection = Arc::new(DetectionSystem::new());
        let mut peerbook = PeerBook::load_or_init();

        // Local PeerId string for self-filtering.
        let local_peer_id_str = peer_id.to_string();

        // Collect candidate dial addresses here.
        let mut all_addrs: Vec<Multiaddr> = Vec::new();
        let mut seen_addr_strings = HashSet::<String>::new();

        // ---------------------------------------------------------
        // A) Validate and store operator-provided bootstrap seeds.
        // ---------------------------------------------------------
        if !opts.bootstrap.is_empty() {
            let mut by_peer: std::collections::BTreeMap<PeerId, HashSet<Multiaddr>> =
                std::collections::BTreeMap::new();

            for s in &opts.bootstrap {
                match s.parse::<Multiaddr>() {
                    Ok(addr) => {
                        let pid = match addr.iter().last() {
                            Some(Protocol::P2p(mh)) => match mh.to_string().parse::<PeerId>() {
                                Ok(pid) => pid,
                                Err(_) => {
                                    println!("❌ Invalid PeerId in bootstrap: {}", s);
                                    continue;
                                }
                            },
                            _ => {
                                println!("❌ Missing /p2p/<PeerId> in bootstrap: {}", s);
                                continue;
                            }
                        };

                        if pid == peer_id {
                            println!(
                                "❌ Bootstrap PeerId cannot be this node's own PeerId: {}",
                                s
                            );
                            continue;
                        }

                        by_peer.entry(pid).or_default().insert(addr);
                    }
                    Err(e) => {
                        println!("❌ Invalid multiaddr '{}': {e}", s);
                    }
                }
            }

            let mut upserted = 0usize;

            for (pid, set) in by_peer {
                let addrs: Vec<Multiaddr> = set.into_iter().collect();

                // Save explicit operator bootstrap peers as sticky seeds.
                peerbook.upsert(&pid, addrs.clone(), /*mark_success=*/ false);
                peerbook.add_tag(&pid, "seed");
                upserted = upserted.saturating_add(1);

                // Also queue them for immediate dialing.
                for addr in addrs {
                    let key = addr.to_string();
                    if seen_addr_strings.insert(key) {
                        all_addrs.push(addr);
                    }
                }
            }

            if upserted > 0 {
                if let Err(e) = peerbook.save() {
                    let msg = format!("Failed to save peerbook: {e}");
                    json_logger
                        .log_error_event("p2p", "PeerBookSaveFailed", &msg)
                        .ok();
                    return Err(ErrorDetection::ProtocolError { message: msg });
                } else {
                    println!("💾 Saved {} bootstrap peer(s) into peerbook", upserted);
                }
            }
        }

        // ---------------------------------------------------------
        // B) Expand from PeerBook for ALL nodes, including non-founders.
        // ---------------------------------------------------------
        for (_pid, addrs) in peerbook.top_n(64) {
            for addr in addrs {
                let key = addr.to_string();
                if seen_addr_strings.insert(key) {
                    all_addrs.push(addr);
                }
            }
        }

        // ---------------------------------------------------------
        // C) Final dial candidate filtering.
        // ---------------------------------------------------------
        let mut seen_peer_ids = HashSet::<String>::new();
        all_addrs.retain(|addr| {
            let pid_str = match addr.iter().last() {
                Some(Protocol::P2p(mh)) => mh.to_string(),
                _ => return false,
            };

            if pid_str == local_peer_id_str {
                return false;
            }

            seen_peer_ids.insert(pid_str)
        });

        // ---------------------------------------------------------
        // D) Seed discovery from the addresses we know now.
        // ---------------------------------------------------------
        if let Err(e) = add_peerdiscovery_peers(swarm.behaviour_mut(), &all_addrs, &detection) {
            let msg = format!("Failed to add peer discovery peers: {e}");
            json_logger
                .log_error_event("p2p", "PeerDiscoveryFailed", &msg)
                .ok();
            return Err(e);
        }

        // ---------------------------------------------------------
        // E) Dial all currently known candidate peers once at startup.
        // ---------------------------------------------------------
        let mut dial_attempts = 0usize;
        let mut dial_accepted = 0usize;
        let mut dial_failed = 0usize;

        if all_addrs.is_empty() {
            let msg = "No startup dial candidates available yet; continuing startup and listening for peers.".to_string();

            json_logger
                .log_error_event("p2p", "NoDialCandidatesAtStartup", &msg)
                .ok();

            println!("ℹ️  {}", msg);
        } else {
            for addr in &all_addrs {
                dial_attempts = dial_attempts.saturating_add(1);

                match swarm.dial(addr.clone()) {
                    Ok(_) => {
                        dial_accepted = dial_accepted.saturating_add(1);
                        info!("▶ Dialling peer {}", addr);
                    }
                    Err(e) => {
                        dial_failed = dial_failed.saturating_add(1);

                        let msg =
                            format!("Failed to dial bootstrap/discovered peer {}: {}", addr, e);

                        json_logger
                            .log_error_event("p2p", "DialBootstrapFailed", &msg)
                            .ok();

                        println!("⚠️  {}", msg);
                    }
                }
            }

            println!(
                "🌐 Startup dial summary: attempts={} accepted={} failed={}",
                dial_attempts, dial_accepted, dial_failed
            );

            // Log this, but DO NOT fail startup.
            if dial_attempts > 0 && dial_accepted == 0 {
                let msg = "All startup dial attempts failed; continuing startup so the node can still listen, accept inbound peers, and recover via later discovery.".to_string();

                json_logger
                    .log_error_event("p2p", "AllDialAttemptsFailedAtStartup", &msg)
                    .ok();

                println!("⚠️  {}", msg);
            }
        }

        // ---------------------------------------------------------
        // F) Kick off Kademlia discovery for ALL nodes.
        // ---------------------------------------------------------
        if let Err(e) = kick_off_peerdiscovery(swarm.behaviour_mut()) {
            let msg = format!("Failed to kick off peer discovery: {e}");
            json_logger
                .log_error_event("p2p", "KickOffPeerDiscoveryFailed", &msg)
                .ok();
            return Err(ErrorDetection::ProtocolError { message: msg });
        }

        // =========================================
        // STEP 6: Validate block 0
        // =========================================

        // =========================================================
        // (STEP 6): Resolve REAL blockchain DB path for FINAL opts
        // This prevents re-opening a different directory than STEP 1A guarded.
        // =========================================================
        let dir_for_chain = DirectoryDB::from_node_opts(&opts).map_err(|e| {
            let msg = format!("Failed to init DirectoryDB (for chain DB path): {e}");
            json_logger
                .log_error_event("blockchain", "DirectoryInitFailedForChainDbPath", &msg)
                .ok();
            ErrorDetection::DatabaseError { details: msg }
        })?;
        let blockchain_db_dir_str_final =
            dir_for_chain.blockchain_path.to_string_lossy().to_string();
        // =========================================================

        let db_mgr =
            RockDBManager::new_blockchain(&opts, &blockchain_db_dir_str_final).map_err(|e| {
                let msg = format!("Failed to create blockchain DB: {e}");
                json_logger
                    .log_error_event("blockchain", "NewBlockchainDbFailed", &msg)
                    .ok();
                ErrorDetection::DatabaseError { details: msg }
            })?;

        let local_block0_opt = db_mgr.get_block_by_index(0).map_err(|e| {
            let msg = format!("Failed to fetch block 0 from DB: {e}");
            json_logger
                .log_error_event("blockchain", "FetchBlock0Failed", &msg)
                .ok();
            ErrorDetection::DatabaseError { details: msg }
        })?;

        // ─────────────────────────────────────────────────────────────────────
        // Non-founder wallet hard-stop (persisted binding)
        // ─────────────────────────────────────────────────────────────────────
        if !(self.local_wallet.trim().is_empty() || is_founder && founder_authenticated) {
            use crate::utility::helper::canon_wallet_id_checked;

            let wallet_canon = canon_wallet_id_checked(self.local_wallet.as_str())?;
            *self.local_wallet = wallet_canon.clone();

            let binding_path = std::path::Path::new(&opts.data_dir).join(".wallet_binding");

            if binding_path.exists() {
                let expected = std::fs::read_to_string(&binding_path).map_err(|e| {
                    ErrorDetection::StorageError {
                        message: format!(
                            "Failed to read wallet binding file {}: {e}",
                            binding_path.display()
                        ),
                    }
                })?;
                let expected = expected.trim().to_string();

                let expected_canon = canon_wallet_id_checked(&expected).map_err(|_e| {
                    ErrorDetection::StorageError {
                        message: format!(
                            "Wallet binding file {} is invalid/corrupted.",
                            binding_path.display()
                        ),
                    }
                })?;

                if expected_canon != wallet_canon {
                    return Err(ErrorDetection::ProtocolError {
                        message: format!(
                            "Wallet mismatch for this node.\n\
                                - bound wallet: {}\n\
                                - provided wallet: {}\n\
                                Refusing to start to prevent validator identity changes.\n\
                                If you intended to migrate this node, delete {} (dangerous).",
                            expected_canon,
                            wallet_canon,
                            binding_path.display()
                        ),
                    });
                }
            } else {
                std::fs::write(&binding_path, format!("{wallet_canon}\n")).map_err(|e| {
                    ErrorDetection::StorageError {
                        message: format!(
                            "Failed to write wallet binding file {}: {e}",
                            binding_path.display()
                        ),
                    }
                })?;
            }
        }

        if is_founder && founder_authenticated {
            let expected_genesis_block = GenesisFile::load_genesis_block_from_json(&genesis_path)?;

            if let Some(local_block0) = local_block0_opt.clone() {
                if !blocks_match(&local_block0, &expected_genesis_block) {
                    println!(
                        "{}",
                        "❌ Local block 0 does not match your supplied genesis.json!".red()
                    );
                    println!(
                        "💡 This means you are either on a different chain, or your DB/genesis file is corrupted."
                    );
                    println!(
                        "💡 Fix this by getting the correct DB/genesis.json, or wipe your DB and rejoin."
                    );

                    fn hex_preview(bytes: &[u8], edge: usize) -> String {
                        let h = hex::encode(bytes);

                        if h.len() <= edge.saturating_mul(2) {
                            return h;
                        }

                        let head = h.get(..edge).unwrap_or(&h);
                        let tail_start = h.len().saturating_sub(edge);
                        let tail = h.get(tail_start..).unwrap_or(&h);

                        format!("{head}…{tail} (hex_len={})", h.len())
                    }

                    fn write_dump(json_logger: &JsonLogger, path: &std::path::Path, bytes: &[u8]) {
                        if let Some(parent) = path.parent()
                            && let Err(e) = std::fs::create_dir_all(parent)
                        {
                            json_logger
                                .log_error_event(
                                    "debug",
                                    "CreateDumpDirFailed",
                                    &format!("create_dir_all('{}') failed: {e}", parent.display()),
                                )
                                .ok();
                            return;
                        }

                        if let Err(e) = std::fs::write(path, bytes) {
                            json_logger
                                .log_error_event(
                                    "debug",
                                    "WriteDumpFailed",
                                    &format!("write('{}') failed: {e}", path.display()),
                                )
                                .ok();
                        }
                    }

                    fn write_text(json_logger: &JsonLogger, path: &std::path::Path, s: &str) {
                        if let Some(parent) = path.parent()
                            && let Err(e) = std::fs::create_dir_all(parent)
                        {
                            json_logger
                                .log_error_event(
                                    "debug",
                                    "CreateDumpDirFailed",
                                    &format!("create_dir_all('{}') failed: {e}", parent.display()),
                                )
                                .ok();
                            return;
                        }

                        if let Err(e) = std::fs::write(path, s.as_bytes()) {
                            json_logger
                                .log_error_event(
                                    "debug",
                                    "WriteTextDumpFailed",
                                    &format!("write('{}') failed: {e}", path.display()),
                                )
                                .ok();
                        }
                    }

                    println!("\n================ GENESIS MISMATCH (COMPACT) ================");

                    let raw_genesis = std::fs::read_to_string(&genesis_path).unwrap_or_else(|e| {
                        format!("[FATAL] Could not read genesis.json: {:?}", e)
                    });

                    let expected_bytes = expected_genesis_block
                        .serialize_for_storage()
                        .unwrap_or_else(|_| Vec::new());

                    let local_bytes = local_block0
                        .serialize_for_storage()
                        .unwrap_or_else(|_| Vec::new());

                    println!("\n--- EXPECTED (GenesisBlock) ---");
                    println!(
                        "expected.genesis_hash = {}",
                        hex::encode(expected_genesis_block.genesis_hash)
                    );
                    println!(
                        "expected.prev_hash    = {}",
                        hex::encode(expected_genesis_block.prev_hash)
                    );
                    println!(
                        "expected.merkle_root  = {}",
                        hex::encode(expected_genesis_block.merkle_root)
                    );
                    println!(
                        "expected.timestamp    = {}",
                        expected_genesis_block.timestamp
                    );
                    println!("expected.data         = {}", expected_genesis_block.data);
                    println!("expected.bytes.len    = {}", expected_bytes.len());
                    if !expected_bytes.is_empty() {
                        println!(
                            "expected.bytes.preview= {}",
                            hex_preview(&expected_bytes, 64)
                        );
                    }

                    println!("\n--- LOCAL (DB block#0) ---");
                    println!("local.hash_hex        = {}", local_block0.hash_hex());
                    println!("local.index           = {}", local_block0.metadata.index);
                    println!(
                        "local.prev_hash       = {}",
                        hex::encode(local_block0.metadata.previous_hash)
                    );
                    println!(
                        "local.merkle_root     = {}",
                        hex::encode(local_block0.metadata.merkle_root)
                    );
                    println!(
                        "local.timestamp       = {}",
                        local_block0.metadata.timestamp
                    );
                    println!("local.miner           = {}", local_block0.miner);
                    println!("local.reward          = {}", local_block0.reward);
                    println!("local.bytes.len       = {}", local_bytes.len());
                    if !local_bytes.is_empty() {
                        println!("local.bytes.preview   = {}", hex_preview(&local_bytes, 64));
                    }

                    let dump_dir = std::path::PathBuf::from("debug_genesis_dump");

                    write_text(
                        json_logger,
                        &dump_dir.join("genesis.json.raw.txt"),
                        &raw_genesis,
                    );

                    if let Ok(s) = serde_json::to_string_pretty(&expected_genesis_block) {
                        write_text(
                            json_logger,
                            &dump_dir.join("expected.genesis_block.json"),
                            &s,
                        );
                    } else {
                        write_text(
                            json_logger,
                            &dump_dir.join("expected.genesis_block.debug.txt"),
                            &format!("{:#?}", expected_genesis_block),
                        );
                    }

                    write_text(
                        json_logger,
                        &dump_dir.join("local.block0.debug.txt"),
                        &format!("{:#?}", local_block0),
                    );

                    write_text(
                        json_logger,
                        &dump_dir.join("expected.block0.bytes.hex"),
                        &hex::encode(&expected_bytes),
                    );
                    write_text(
                        json_logger,
                        &dump_dir.join("local.block0.bytes.hex"),
                        &hex::encode(&local_bytes),
                    );

                    write_dump(
                        json_logger,
                        &dump_dir.join("expected.block0.bytes.bin"),
                        &expected_bytes,
                    );
                    write_dump(
                        json_logger,
                        &dump_dir.join("local.block0.bytes.bin"),
                        &local_bytes,
                    );

                    println!("\n--- FULL DUMPS WRITTEN (OPEN THESE FILES) ---");
                    println!("  {}", dump_dir.join("genesis.json.raw.txt").display());
                    println!(
                        "  {}",
                        dump_dir.join("expected.genesis_block.json").display()
                    );
                    println!("  {}", dump_dir.join("local.block0.debug.txt").display());
                    println!("  {}", dump_dir.join("expected.block0.bytes.hex").display());
                    println!("  {}", dump_dir.join("local.block0.bytes.hex").display());
                    println!("=============================================================\n");

                    std::process::exit(1);
                }
            } else {
                println!(
                    "{}",
                    "❌ Critical error: Block 0 missing after DB open. Aborting.".red()
                );
                std::process::exit(1);
            }
        } else if local_block0_opt.is_none() {
            println!(
                "{}",
                "⏳ No local block 0 yet; will sync from peers...".yellow()
            );
        }

        let mut chain = AccountModelTree::with_manager(db_mgr.clone());
        chain.reload_from_db();
        *self.chain = Some(chain.clone());

        if let Ok(Some(_)) = db_mgr.get_latest_block() {
            let rdb = db_mgr.open_db_blockchain().map_err(|e| {
                let msg = format!("Failed to open blockchain DB: {e}");
                json_logger
                    .log_error_event("blockchain", "OpenBlockchainDbFailed", &msg)
                    .ok();
                ErrorDetection::DatabaseError { details: msg }
            })?;
            if let Some(cf) = rdb.cf_handle(GlobalConfiguration::ACCOUNT_COLUMN_NAME) {
                for item in rdb.iterator_cf(cf, IteratorMode::Start) {
                    let (k, v) = item.map_err(|e| {
                        let msg = format!("Error iterating account column: {e}");
                        json_logger
                            .log_error_event("blockchain", "IterateAccountColumnFailed", &msg)
                            .ok();
                        ErrorDetection::StorageError { message: msg }
                    })?;
                    let addr = String::from_utf8_lossy(&k).to_string();
                    let bal: u64 = postcard::from_bytes(&v).map_err(|e| {
                        let msg = format!("Failed to deserialize balance: {e}");
                        json_logger
                            .log_error_event("blockchain", "DeserializeBalanceFailed", &msg)
                            .ok();
                        ErrorDetection::SerializationError { details: msg }
                    })?;
                    chain.set_balance(&addr, bal);
                }
            }
            drop(rdb);
        }

        let db = Arc::new(db_mgr);
        *self.db_manager = Arc::clone(&db);

        let (net_tx, net_rx) = tokio::sync::mpsc::channel::<NetCmd>(512);

        let detection_system = Arc::new(DetectionSystem::new());
        let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection_system));
        *self.chain = Some(chain.clone());

        {
            let e = node_ephemeral.ephemeral();
            let snapshot: RegistryData = match e.lock() {
                Ok(guard) => guard.clone(),
                Err(_) => {
                    return Err(ErrorDetection::ValidationError {
                        message:
                            "Failed to lock EPHEMERAL registry for menu snapshot (mutex poisoned)"
                                .to_string(),
                        tx_id: None,
                    });
                }
            };
            *self.node_registry = Some(snapshot);
        }

        let peerbook_handle = Arc::new(std::sync::Mutex::new(
            crate::network::p2p_011_peerbook::PeerBook::load_or_init(),
        ));

        let reorg_manager_for_sync = ReorgManager::mainnet_default(Arc::clone(&db));

        let sync_engine = Arc::new(tokio::sync::Mutex::new(P2pSync::new(
            chain.clone(),
            Arc::clone(&db),
            Arc::clone(&mempool),
            Arc::clone(&peerbook_handle),
            dir_for_chain.peerlist_path.clone(),
            Some(GlobalConfiguration::GENESIS_HASH_HEX.to_string()),
            reorg_manager_for_sync,
        )));

        {
            let mut sync = sync_engine.lock().await;
            sync.seed_kad_from_peerbook(&mut swarm);
        }

        // =========================================
        // STEP 7: NON-FOUNDER SYNC
        // =========================================

        {
            let mut sync = sync_engine.lock().await;
            sync.poll_peers_for_height(&mut swarm);
        }

        if !is_founder {
            println!(
                "{}",
                if identity_status == "registered" {
                    "⏳ Waiting to synchronize blockchain from peers before mining...".yellow()
                } else {
                    "⏳ Waiting to synchronize blockchain from peers before observer mode..."
                        .yellow()
                }
            );

            let mut poll_timer = tokio::time::interval(std::time::Duration::from_secs(5));

            let stall_seconds: u64 = 90;
            let stall_window = std::time::Duration::from_secs(stall_seconds);

            let mut saw_any_progress = false;

            let mut last_progress_at = std::time::Instant::now();
            let mut last_downloaded: u64 = 0;
            let mut last_total: u64 = 0;

            loop {
                tokio::select! {
                    raw = swarm.select_next_some() => {
                        let mut syn = sync_engine.lock().await;
                        syn.on_swarm_event(raw, &mut swarm, None);

                        let d = syn.downloaded as u64;
                        let t = syn.total_to_download as u64;

                        if d > 0 || t > 0 {
                            saw_any_progress = true;
                        }

                        if d != last_downloaded || t != last_total {
                            last_downloaded = d;
                            last_total = t;
                            last_progress_at = std::time::Instant::now();
                        }
                    }
                    _ = poll_timer.tick() => {
                        let mut syn = sync_engine.lock().await;
                        syn.poll_peers_for_height(&mut swarm);

                        let d = syn.downloaded as u64;
                        let t = syn.total_to_download as u64;

                        if d > 0 || t > 0 {
                            saw_any_progress = true;
                        }

                        if d != last_downloaded || t != last_total {
                            last_downloaded = d;
                            last_total = t;
                            last_progress_at = std::time::Instant::now();
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
                }

                {
                    let syn = sync_engine.lock().await;
                    if !syn.is_syncing() {
                        break;
                    }
                    print!(
                        "\r🔄 Sync progress: {:.1}% ({} / {})   ",
                        syn.sync_percent(),
                        syn.downloaded,
                        syn.total_to_download
                    );
                    io::stdout().flush().ok();
                }

                if std::time::Instant::now().duration_since(last_progress_at) >= stall_window {
                    println!();
                    if saw_any_progress {
                        println!(
                            "{}",
                            format!(
                                "⚠️ Sync appears stalled (no progress for {}s). Returning to menu.",
                                stall_seconds
                            )
                            .yellow()
                        );
                    } else {
                        println!(
                            "{}",
                            format!(
                                "⚠️ Could not reach any usable bootstrap peers within {}s (no progress). Returning to menu.",
                                stall_seconds
                            )
                            .yellow()
                        );
                    }
                    return Ok(());
                }
            }
            println!("\n✅ Blockchain sync complete.");

            chain.reload_from_db();

            let next_height = self
                .db_manager
                .get_tip_height()
                .unwrap_or(0)
                .saturating_add(1);

            let scheduled = {
                let e = node_ephemeral.ephemeral();
                let e = match e.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        return Err(ErrorDetection::ValidationError {
                            message: "Failed to lock EPHEMERAL registry for leader preview (mutex poisoned)"
                                .to_string(),
                            tx_id: None,
                        });
                    }
                };

                let ws = e.sorted_wallets();
                if ws.is_empty() {
                    None
                } else {
                    let height_usize = match usize::try_from(next_height) {
                        Ok(v) => v,
                        Err(_) => {
                            return Err(ErrorDetection::ValidationError {
                                message: format!(
                                    "Next height {} cannot fit into usize for leader preview",
                                    next_height
                                ),
                                tx_id: None,
                            });
                        }
                    };
                    let len = ws.len();
                    let idx = height_usize.checked_rem(len).unwrap_or(0);
                    ws.get(idx).cloned()
                }
            };

            match scheduled {
                Some(leader) => println!(
                    "🏁 Scheduled validator for height #{}: {}",
                    next_height, leader
                ),
                None => tracing::debug!(
                    "No eligible validators at height #{}; deferring proposal.",
                    next_height
                ),
            }

            {
                let e = node_ephemeral.ephemeral();
                let snapshot: RegistryData = match e.lock() {
                    Ok(guard) => guard.clone(),
                    Err(_) => {
                        return Err(ErrorDetection::ValidationError {
                            message: "Failed to lock EPHEMERAL registry for menu refresh (mutex poisoned)"
                                .to_string(),
                            tx_id: None,
                        });
                    }
                };
                *self.node_registry = Some(snapshot);
            }
        }

        let mut bc_input = String::new();

        if !is_founder {
            if identity_status == "registered" {
                println!(
                    "{}",
                    "🚀 Auto-start: Mining will be enabled (registered identity).".green()
                );
            } else {
                println!(
                    "{}",
                    "👀 Auto-start: Running in observer mode (unregistered identity).".yellow()
                );
            }
        } else {
            println!(
                "{}",
                if identity_status == "registered" {
                    "📈 Start blockchain mining? (yes/no)".cyan()
                } else {
                    "📈 Start blockchain in observer mode? (yes/no)".cyan()
                }
            );

            if std::io::stdin().read_line(&mut bc_input).is_err() {
                println!("❌ Failed to read blockchain prompt. Exiting to menu.");
                *self.p2p_running = false;
                return Ok(());
            }

            if bc_input.trim().eq_ignore_ascii_case("no") {
                println!("{}", "❌ Blockchain start cancelled.".red());
                *self.p2p_running = false;
                return Ok(());
            }
        }

        // =========================================
        /* STEP 8: SPAWN P2P + MINER TASK + LOOP */
        // =========================================
        let local_wallet = self.local_wallet.clone();

        let non_founder_existing_chain_without_verified_bootnode = chain_already_exists
            && !is_founder
            && !founder_authenticated
            && !non_founder_bootstrap_verified_online;

        let mining_intent = if non_founder_existing_chain_without_verified_bootnode {
            println!(
                "{}",
                "❌ Mining disabled: non-founder cannot solo reboot an existing chain without the founder bootnode online."
                    .red()
            );
            false
        } else if is_founder {
            identity_status == "registered" && bc_input.trim().eq_ignore_ascii_case("yes")
        } else {
            identity_status == "registered"
        };

        // =========================================================
        // STRICT ADMISSION GUARD (non-founder)
        // =========================================================
        if !is_founder && local_wallet.is_empty() {
            println!(
                "{}",
                "🟡 Non-founder node has no wallet; running in observer mode (mining disabled)."
                    .yellow()
            );
        }

        let allow_ephemeral_autoregister = mining_intent && !local_wallet.is_empty();
        // =========================================================

        if allow_ephemeral_autoregister {
            let need_autoregister = {
                let eph = node_ephemeral.ephemeral();
                let e = match eph.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        return Err(ErrorDetection::ValidationError {
                            message:
                                "Failed to lock EPHEMERAL registry for autoregister check (mutex poisoned)"
                                    .to_string(),
                            tx_id: None,
                        });
                    }
                };
                !e.wallets.contains(&local_wallet)
            };

            if need_autoregister {
                let tip = match self.db_manager.get_tip_height() {
                    Ok(h) => h,
                    Err(e) => {
                        let msg = format!(
                            "Failed to read tip height during EPHEMERAL auto-registration: {e:?}"
                        );
                        return Err(ErrorDetection::DatabaseError { details: msg });
                    }
                };

                _ = node_ephemeral.register_wallet_strict(&local_wallet, tip);
                _ = node_ephemeral.set_join_height(&local_wallet, tip);
                println!(
                    "🔑 Auto-registered local wallet in EPHEMERAL registry: {} (join_height={})",
                    local_wallet, tip
                );
            }
        }

        let wallet_registered_now = {
            let eph = node_ephemeral.ephemeral();
            let e = match eph.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    return Err(ErrorDetection::ValidationError {
                        message:
                            "Failed to lock EPHEMERAL registry for wallet membership check (mutex poisoned)"
                                .to_string(),
                        tx_id: None,
                    });
                }
            };
            !local_wallet.is_empty() && e.wallets.contains(&local_wallet)
        };

        let initial_miner_allowed = mining_intent && wallet_registered_now;

        let db_for_task = Arc::clone(&db);
        let mempool_for_task = Arc::clone(&mempool);
        let mut chain_for_task = chain;
        let mut swarm = swarm;

        let tm_for_task: Arc<TimeManager> = {
            if let Ok(path) = std::env::var("REMZAR_GENESIS_PATH") {
                match TimeManager::new_from_genesis_file(&path) {
                    Ok(tm) => Arc::new(tm),
                    Err(_) => {
                        if let Ok(Some(b0)) = db_for_task.get_block_by_index(0) {
                            Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(
                                b0.metadata.timestamp,
                            )))
                        } else {
                            Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(
                                TimeManager::now_unix(),
                            )))
                        }
                    }
                }
            } else if let Ok(Some(b0)) = db_for_task.get_block_by_index(0) {
                Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(
                    b0.metadata.timestamp,
                )))
            } else {
                Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(
                    TimeManager::now_unix(),
                )))
            }
        };

        let wallet_for_loop = local_wallet;

        let reorg_manager_for_loop = ReorgManager::mainnet_default(Arc::clone(&db_for_task));

        let console_bus_for_loop = self.console_bus.clone();

        // =========================================================
        // signing_key comes from STEP 3 cache (NO PROMPT HERE)
        // - If wallet empty: generate observer key (never decrypt, never prompt)
        // - If wallet set: REQUIRE cached key from STEP 3 (otherwise hard-stop)
        // =========================================================

        let signing_key_for_loop: Arc<fips204::ml_dsa_65::PrivateKey> = if wallet_for_loop
            .trim()
            .is_empty()
        {
            let (_pk, sk) = fips204::ml_dsa_65::try_keygen().map_err(|e| {
                ErrorDetection::CryptographicError {
                    message: format!("ML-DSA-65 keygen failed (observer fallback): {e}"),
                }
            })?;
            Arc::new(sk)
        } else {
            match signing_key_cached.as_ref() {
                Some(k) => Arc::clone(k),
                None => {
                    return Err(ErrorDetection::ValidationError {
                        message: "Wallet is set but signing key was not cached in STEP 3; refusing to prompt in STEP 8."
                            .to_string(),
                        tx_id: None,
                    });
                }
            }
        };

        // =========================================================

        let mut orchestrator = OrchestrationLoop::new(OrchestrationLoopArgs {
            db: Arc::clone(&db_for_task),
            node_ephemeral: node_ephemeral.clone(),
            mempool: Arc::clone(&mempool_for_task),
            sync_engine: Arc::clone(&sync_engine),
            signing_key: Arc::clone(&signing_key_for_loop),
            tm: Arc::clone(&tm_for_task),
            reorg_manager: reorg_manager_for_loop,
            local_wallet: wallet_for_loop,
            console_bus: console_bus_for_loop,
        });

        orchestrator.engine.display.log_sequence = false;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // =========================================================
        // ✅ WIRING (STEP 8): capture REAL opts fields for run_loop
        // =========================================================
        let opts_founder = opts.founder;
        let opts_identity_file = opts.identity_file.clone();
        let opts_listen = opts.listen.clone();
        let opts_bootstrap = opts.bootstrap.clone();
        let opts_log = opts.log.clone();
        let opts_data_dir = opts.data_dir.clone();
        let opts_wallet_address = opts.wallet_address.clone();
        // =========================================================

        let handle = tokio::spawn(async move {
            let opts_for_loop = NodeOpts {
                founder: opts_founder,
                identity_file: opts_identity_file,
                listen: opts_listen,
                bootstrap: opts_bootstrap,
                log: opts_log,
                data_dir: opts_data_dir,
                wallet_address: opts_wallet_address,
            };

            if let Err(e) = orchestrator
                .run_loop(
                    &mut chain_for_task,
                    &mut swarm,
                    shutdown_rx,
                    Some(net_rx),
                    &opts_for_loop,
                )
                .await
            {
                tracing::error!("Orchestration loop exited with error: {e:?}");
            }
        });

        *self.net_tx = Some(net_tx);
        *self.p2p_handle = Some((handle, shutdown_tx));
        *self.p2p_running = true;

        if initial_miner_allowed {
            println!("{}", "✅ P2P node running. Mining enabled.".green());
        } else if identity_status == "registered" {
            println!(
                "{}",
                "🟡 P2P node running. Mining disabled (awaiting wallet registration).".yellow()
            );
        } else {
            println!();
            println!(
                "{}",
                " P2P node running in observer mode (no identity / intent).".yellow()
            );
        }

        Ok(())
    }
}
