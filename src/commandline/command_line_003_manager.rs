use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::commandline::s_03_startnode::S03StartNode;
use crate::consensus::por_000_ephemeral_registration::NodeEphemeral;
use crate::consensus::por_000_ephemeral_registration::RegistryData;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::network::p2p_014_chat::ChatMessage;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::storage::rocksdb_007_db_guard::DbGuard;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};

/// **CommandManager**
pub struct CommandManager {
    /* ── high-level state ─────────────────────────── */
    node_registry: Option<RegistryData>,

    // EPHEMERAL in-memory registry for this process
    node_ephemeral: Option<NodeEphemeral>,

    /* ── persistent CLI/database handle ───────────── */
    db_manager: Arc<RockDBManager>,

    /* ── live P2P runtime state ───────────────────── */
    p2p_running: bool,
    /// (join_handle, shutdown_tx)
    p2p_handle: Option<(JoinHandle<()>, oneshot::Sender<()>)>,

    /// Channel used by the CLI to ask the background task to broadcast.
    net_tx: Option<tokio::sync::mpsc::Sender<NetCmd>>,

    /// View console for live blocks
    console_bus: crate::commandline::s_04_view_blockchain_console::ConsoleBus,

    /// In-memory account-tree once the node is running.
    chain: Option<AccountModelTree>,

    /* ── identity persistence ─────────────────────── */
    /// Always load the same identity.key from this PathBuf
    identity_path: PathBuf,

    /// Local wallet address (for BlockMint)
    local_wallet: String,

    /* ── audit state ───────────────────── */
    /// Directory where we’ll write JSON audit files
    pub audit_dir: PathBuf,
    /// Temp directory for HTML/PDF scratch files
    pub pdf_dir: PathBuf,

    /// Hold the guard for the life of the running node
    blockchain_db_guard: Option<DbGuard>,
}

impl CommandManager {
    /* ─────────── constructor(s) ─────────── */

    /// Original constructor (no audit support).
    pub fn new_no_signals(opts: &NodeOpts, identity_path: PathBuf) -> Result<Self, ErrorDetection> {
        // CLI RocksDB (safe; not the blockchain DB)
        let db_manager =
            Arc::new(
                RockDBManager::new(opts).map_err(|e| ErrorDetection::DatabaseError {
                    details: format!("Failed to create CLI RocksDB: {}", e),
                })?,
            );

        Ok(Self {
            node_registry: None,
            db_manager,
            p2p_running: false,
            p2p_handle: None,
            net_tx: None,
            console_bus: crate::commandline::s_04_view_blockchain_console::ConsoleBus::new(),
            chain: None,
            identity_path,
            local_wallet: String::new(),
            audit_dir: PathBuf::new(),
            pdf_dir: PathBuf::new(),
            node_ephemeral: None,
            blockchain_db_guard: None,
        })
    }

    /// Constructor with audit/export folders.
    pub fn new_with_audit(
        opts: &NodeOpts,
        audit_db_path: &str,
        pdf_dir_path: &str,
        identity_path: PathBuf,
    ) -> Result<Self, ErrorDetection> {
        // 1) CLI RocksDB
        let db_manager =
            Arc::new(
                RockDBManager::new(opts).map_err(|e| ErrorDetection::DatabaseError {
                    details: format!("Failed to create CLI RocksDB: {}", e),
                })?,
            );

        // 2) Audit output directory
        let audit_dir = PathBuf::from(audit_db_path);
        fs::create_dir_all(&audit_dir).map_err(|e| ErrorDetection::StorageError {
            message: format!("Failed to create audit directory: {}", e),
        })?;

        // 3) PDF scratch directory
        fs::create_dir_all(pdf_dir_path).map_err(|e| ErrorDetection::StorageError {
            message: e.to_string(),
        })?;
        let pdf_dir = PathBuf::from(pdf_dir_path);

        Ok(Self {
            node_registry: None,
            db_manager,
            p2p_running: false,
            p2p_handle: None,
            net_tx: None,
            console_bus: crate::commandline::s_04_view_blockchain_console::ConsoleBus::new(),
            chain: None,
            identity_path,
            local_wallet: String::new(),
            audit_dir,
            pdf_dir,
            node_ephemeral: None,
            blockchain_db_guard: None,
        })
    }

    /* ─────────── guard helpers ─────────── */

    /// Ensure network thread exists (i.e., node is running).
    fn ensure_node_running(&self) -> Result<(), ErrorDetection> {
        if !self.p2p_running {
            return Err(ErrorDetection::ProtocolError {
                message: "P2P node not running; start it (menu 7) first".into(),
            });
        }
        Ok(())
    }

    /* ─────────── getters ─────────── */

    pub fn db_manager(&self) -> Arc<RockDBManager> {
        Arc::clone(&self.db_manager)
    }
    pub fn is_p2p_running(&self) -> bool {
        self.p2p_running
    }
    pub fn identity_path(&self) -> &std::path::Path {
        &self.identity_path
    }
    pub fn local_wallet(&self) -> &str {
        &self.local_wallet
    }
    pub fn console_bus(&self) -> crate::commandline::s_04_view_blockchain_console::ConsoleBus {
        self.console_bus.clone()
    }

    /* ─────────── network channel helper ─────────── */

    pub fn attach_net_tx(&mut self, tx: tokio::sync::mpsc::Sender<NetCmd>) {
        self.net_tx = Some(tx);
    }

    pub fn send_net_cmd(&self, cmd: NetCmd) -> Result<(), ErrorDetection> {
        let tx = self
            .net_tx
            .as_ref()
            .ok_or_else(|| ErrorDetection::ProtocolError {
                message: "Network thread not running".into(),
            })?;
        tx.try_send(cmd).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => ErrorDetection::ProtocolError {
                message: "Too many pending broadcasts; please wait".into(),
            },
            tokio::sync::mpsc::error::TrySendError::Closed(_) => ErrorDetection::ProtocolError {
                message: "Network thread has shut down".into(),
            },
        })
    }

    /* ─────────── chain handle helpers ─────────── */

    pub fn chain_mut(&mut self) -> Result<&mut AccountModelTree, ErrorDetection> {
        self.chain
            .as_mut()
            .ok_or_else(|| ErrorDetection::ProtocolError {
                message: "P2P node not running; call `start_node` first".into(),
            })
    }

    pub fn replace_chain(&mut self, chain: AccountModelTree) -> Result<(), ErrorDetection> {
        self.ensure_node_running()?;
        self.chain = Some(chain);
        Ok(())
    }

    pub fn take_chain(&mut self) -> Result<AccountModelTree, ErrorDetection> {
        self.ensure_node_running()?;
        self.chain
            .take()
            .ok_or_else(|| ErrorDetection::ProtocolError {
                message: "P2P node must be running before using chain".into(),
            })
    }

    /* ─────────── P2P lifecycle (graceful) ─────────── */

    pub fn mark_started(&mut self) -> Result<(), ErrorDetection> {
        if self.p2p_running {
            return Err(ErrorDetection::ProtocolError {
                message: "P2P node already running; refusing to start twice".into(),
            });
        }
        self.p2p_running = true;
        Ok(())
    }

    pub fn set_p2p_handle(
        &mut self,
        handle: JoinHandle<()>,
        shutdown_tx: oneshot::Sender<()>,
    ) -> Result<(), ErrorDetection> {
        if !self.p2p_running {
            return Err(ErrorDetection::ProtocolError {
                message: "Cannot set P2P handle before mark_started()".into(),
            });
        }
        self.p2p_handle = Some((handle, shutdown_tx));
        Ok(())
    }

    pub async fn stop_node(&mut self) -> Result<(), ErrorDetection> {
        if !self.p2p_running {
            return Err(ErrorDetection::ProtocolError {
                message: "P2P node is not running".into(),
            });
        }

        if let Some((mut handle, shutdown_tx)) = self.p2p_handle.take() {
            _ = shutdown_tx.send(());
            let timeout_dur = Duration::from_secs(GlobalConfiguration::JOIN_TIMEOUT_SECS);
            let slept = tokio::time::sleep(timeout_dur);
            tokio::pin!(slept);

            tokio::select! {
                join_result = &mut handle => {
                    if let Err(join_err) = join_result {
                        tracing::warn!("Network task join failed: {join_err}");
                    }
                }
                _ = &mut slept => {
                    tracing::warn!(
                        "Network task did not stop within {}s; aborting",
                        GlobalConfiguration::JOIN_TIMEOUT_SECS
                    );
                    handle.abort();
                    _ = handle.await;
                }
            }
        }

        // Clear runtime bits so subsequent starts are clean.
        self.p2p_running = false;
        self.net_tx = None;
        self.chain = None;

        // WIRING: release DB ownership lock + file handle
        self.blockchain_db_guard = None;

        Ok(())
    }

    /* ─────────── Registry (reload) ─────────── */
    // EPHEMERAL-ONLY snapshot (no RocksDB registry access of any kind).
    pub fn reload_registry_from_db(&mut self) -> Result<(), ErrorDetection> {
        let mut new_registry = RegistryData::new();

        if let Some(ne) = &self.node_ephemeral {
            let eph = ne.ephemeral(); // Arc<Mutex<EphemeralRegistry>>
            match eph.lock() {
                Ok(e) => {
                    for w in e.sorted_wallets() {
                        new_registry.wallets.insert(w);
                    }
                    new_registry.identity_map = e.identity_map.clone();
                    new_registry.join_heights = e.join_heights.clone();
                }
                Err(_) => {
                    // Graceful: we don’t panic; we keep going with empty snapshot.
                    tracing::warn!("reload_registry_from_db: ephemeral registry lock poisoned");
                }
            }
        } else {
            tracing::info!(
                "reload_registry_from_db: NodeEphemeral not initialized; using empty snapshot"
            );
        }

        self.node_registry = Some(new_registry);
        Ok(())
    }

    /* ─────────── Blockchain initialization empty helper ─────────── */

    pub fn initialize_blockchain_empty(
        &self,
        opts: &NodeOpts,
    ) -> Result<RockDBManager, ErrorDetection> {
        if self.p2p_running {
            return Err(ErrorDetection::ProtocolError {
                message: "P2P node is running; stop it before initializing an empty blockchain"
                    .into(),
            });
        }

        // WIRING: always resolve the REAL blockchain DB path (DirectoryDB)
        let dir_for_db =
            DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to init DirectoryDB (for empty blockchain DB): {e}"),
            })?;
        let blockchain_db_dir_str = dir_for_db.blockchain_path.to_string_lossy().to_string();

        RockDBManager::new_blockchain(opts, &blockchain_db_dir_str).map_err(|e| {
            ErrorDetection::DatabaseError {
                details: format!("Failed to create empty blockchain DB: {e}"),
            }
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // (1) SETUP DATABASE (Persistent, RocksDB) - CLI DB
    // ─────────────────────────────────────────────────────────────────────
    pub fn setup_database(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_01_setup_database::S01SetupDatabase;

        let mut section = S01SetupDatabase::new();
        section.setup_database(opts, json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 2) Generate a new wallet (CLI DB) — hardened (input caps + secret zeroize + atomic write)
    // ─────────────────────────────────────────────────────────────────────
    pub fn generate_wallet(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_02_generate_wallet::S02GenerateWallet;

        let mut section = S02GenerateWallet::new();
        section.generate_wallet(opts, json_logger)
    }

    // ──────────────────────────────────────────────────────────────────────
    // 3) Initialize P2P & Blockchain (resume if possible, otherwise genesis)
    // ──────────────────────────────────────────────────────────────────────
    pub async fn start_node(&mut self, json_logger: &JsonLogger) -> Result<(), ErrorDetection> {
        let mut section = S03StartNode::new(crate::commandline::s_03_startnode::S03StartNodeArgs {
            node_registry: &mut self.node_registry,
            node_ephemeral: &mut self.node_ephemeral,
            db_manager: &mut self.db_manager,
            p2p_running: &mut self.p2p_running,
            p2p_handle: &mut self.p2p_handle,
            net_tx: &mut self.net_tx,
            console_bus: self.console_bus.clone(),
            chain: &mut self.chain,
            local_wallet: &mut self.local_wallet,
            blockchain_db_guard: &mut self.blockchain_db_guard,
        });

        Box::pin(section.start_node(json_logger)).await
    }

    // ─────────────────────────────────────────────────────────────────────
    // 4) View Blockchain Console (Real-Time Viewing) — hardened (Option B bus)
    // ─────────────────────────────────────────────────────────────────────
    pub fn view_blockchain_console(&self, node_opts: &NodeOpts) -> Result<(), ErrorDetection> {
        use crate::commandline::s_04_view_blockchain_console::BlockchainConsoleView;

        // CommandManager MUST hold a ConsoleBus field (self.console_bus).
        // This is the shared bus the OrchestrationLoop publishes to.
        let mut view = BlockchainConsoleView::new(self.console_bus.clone());

        // Blocking call (menu flow)
        view.run_blocking(node_opts)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 5) Send Coins – write to mempool & broadcast (non-blocking CLI)
    // ─────────────────────────────────────────────────────────────────────
    pub fn send_remzar(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_05_send_remzar::S05SendRemzar;

        let mut section =
            S05SendRemzar::new(self.db_manager(), &mut self.chain, self.net_tx.clone());
        section.send_remzar(opts, json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 6) Receive Coins — read-only “live” watcher for incoming transactions
    // ─────────────────────────────────────────────────────────────────────
    pub fn receive_remzar(
        &self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_06_receive_remzar::S06ReceiveRemzar;

        let mut section = S06ReceiveRemzar::new();
        section.receive_remzar(opts, json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 7) VIEW PARTICIPANT STATUS (Prefers persistent; DB-gated leader calc)
    // ─────────────────────────────────────────────────────────────────────
    pub fn view_status(&mut self) -> Result<(), ErrorDetection> {
        use crate::commandline::s_07_view_status::S07ViewStatus;
        use std::sync::Arc;

        let mut section = S07ViewStatus::new();

        section.view_status(
            self.node_ephemeral.as_ref(),
            Arc::clone(&self.db_manager),
            &self.local_wallet,
            self.identity_path(),
        )
    }

    // ─────────────────────────────────────────────────────────────────────
    // 8) Check Balance – authoritative read from ACCOUNT CF
    // ─────────────────────────────────────────────────────────────────────
    pub fn check_balance(
        &self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_08_check_balance::S08CheckBalance;
        use std::sync::Arc;

        let section = S08CheckBalance::new();

        section.check_balance(
            opts,
            Arc::clone(&self.db_manager),
            self.chain.as_ref().cloned(),
            json_logger,
        )
    }

    // ─────────────────────────────────────────────────────────────────────
    // 9) List wallets (CLI DB)
    // ─────────────────────────────────────────────────────────────────────
    pub fn list_wallets(&self, json_logger: &JsonLogger) -> Result<(), ErrorDetection> {
        use crate::commandline::s_09_list_wallets::S09ListWallets;

        let section = S09ListWallets::new();
        section.list_wallets(json_logger)
    }

    // ──────────────────────────────────────────────────────────────
    // 10) Create Certificate (hash, nft, documents, etc)
    // ──────────────────────────────────────────────────────────────
    pub fn create_certificates(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_10_create_certificates::S10CreateCertificates;
        use std::sync::Arc;

        self.ensure_node_running()?;

        let db_manager = Arc::clone(&self.db_manager);
        let local_wallet = self.local_wallet.clone();
        let audit_dir = self.audit_dir.clone();
        let pdf_dir = self.pdf_dir.clone();

        let mut section = S10CreateCertificates::new();
        let mut send_net_cmd_cb = |cmd: NetCmd| self.send_net_cmd(cmd);

        section.create_certificates(
            opts,
            db_manager,
            &local_wallet,
            &audit_dir,
            &pdf_dir,
            json_logger,
            &mut send_net_cmd_cb,
        )
    }

    // ───────────────────────────────────────────────────────────────────────────────
    // 11) Send Chat (message to message via p2p)
    // ──────────────────────────────────────────────────────────────────────────────
    pub fn send_message(&mut self, opts: &NodeOpts) -> Result<(), ErrorDetection> {
        use crate::commandline::s_11_send_chat::S11SendChat;
        use crate::network::p2p_010_netcmd::NetCmd;
        use colored::Colorize;

        // Must have the node + network running so we can use net_tx.
        self.ensure_node_running()?;

        let mut send_chat = S11SendChat::new();

        let chat_msg = match send_chat.send_message(opts) {
            Ok(Some(chat_msg)) => chat_msg,
            Ok(None) => return Ok(()),
            Err(e) => return Err(e),
        };

        // Best-effort local log, same behavior as original flow.
        self.save_outgoing_chat_json(opts, &chat_msg);

        // Send to background P2P task via NetCmd::SendChat
        if let Err(e) = self.send_net_cmd(NetCmd::SendChat(chat_msg)) {
            println!("{}", "❌ Failed to queue chat message for sending.".red());
            println!("   Details: {:?}", e);
            return Err(e);
        }

        println!("{}", "✅ Chat message queued for delivery.".green());
        Ok(())
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // 12) Send File (file sharing via p2p)
    // ──────────────────────────────────────────────────────────────────────────────
    pub fn send_files(&mut self, opts: &NodeOpts) -> Result<(), ErrorDetection> {
        use crate::commandline::s_12_send_file::S12SendFile;

        // Must have the node + network running so we can use net_tx.
        self.ensure_node_running()?;

        let mut send_file = S12SendFile::new();

        let mut send_net_cmd_cb = |cmd: NetCmd| self.send_net_cmd(cmd);

        send_file.send_files(opts, &mut send_net_cmd_cb)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 13) Wallet utilities – either view private key *or* recover address
    // Hardened: input caps + attempt caps + strict address + zeroize + safer temp write
    // ─────────────────────────────────────────────────────────────────────
    pub fn debug_open_encrypted_key(
        &mut self,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_13_wallet_utilities::S13WalletUtilities;

        let mut wallet_utilities = S13WalletUtilities::new();
        wallet_utilities.debug_open_encrypted_key(json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 14) Backup Wallet (CLI DB) — hardened (input caps + attempt caps + zeroize + atomic copy)
    // ─────────────────────────────────────────────────────────────────────
    pub fn debug_backup_wallet(
        &self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_14_backup_wallet::S14BackupWallet;

        let backup_wallet = S14BackupWallet::new();
        backup_wallet.debug_backup_wallet(opts, json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 15) Debug Wallet Storage Keys (CLI DB) — hardened (caps + zeroize + path checks)
    // ─────────────────────────────────────────────────────────────────────
    pub fn debug_keys(&self, json_logger: &JsonLogger) -> Result<(), ErrorDetection> {
        use crate::commandline::s_15_debug_wallet_storage_keys::S15DebugWalletStorageKeys;

        let debug_keys = S15DebugWalletStorageKeys::new();
        debug_keys.debug_keys(json_logger)
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // 16) Debug Log Information (exports latest ~1MB to JSON) — hardened (NO new deps)
    // ──────────────────────────────────────────────────────────────────────────────
    pub fn debug_logs(
        &self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_16_debug_logs::S16DebugLogs;

        let debug_logs = S16DebugLogs::new();
        debug_logs.debug_logs(opts, json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 17. Debug: Audit Report (interactive wrapper)
    // ─────────────────────────────────────────────────────────────────────────────

    pub fn debug_audit_report(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_17_debug_audit_report::S17DebugAuditReport;

        let mut audit = S17DebugAuditReport::new();
        audit.debug_audit_report(opts, json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //       18.  Games
    // ─────────────────────────────────────────────────────────────────────────────

    pub fn play_slot_machine(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use crate::commandline::s_18_games::S18Games;
        use std::sync::Arc;

        // Must be running (game broadcasts burn+optional payout)
        self.ensure_node_running()?;

        // Open blockchain DB (same pattern as send_remzar)
        let db = self.db_manager.open_db_blockchain().map_err(|e| {
            let msg = format!("Slot: failed to open blockchain DB: {e}");
            json_logger
                .log_error_event("slot", "OpenDbFailed", &msg)
                .ok();
            ErrorDetection::DatabaseError { details: msg }
        })?;

        let net_tx = self
            .net_tx
            .clone()
            .ok_or_else(|| ErrorDetection::ProtocolError {
                message: "Network thread not running".into(),
            })?;

        // Callback inputs: pass only what the extracted module actually needs.
        let db_manager = Arc::clone(&self.db_manager);
        let chain_opt = self.chain.as_mut();

        let mut games = S18Games::new();
        games.play_slot_machine(opts, &db, db_manager, net_tx, chain_opt, json_logger)
    }

    // ─────────────────────────────────────────────────────────────────────
    // 19) Frequently Asked Questions (FAQ)
    // ─────────────────────────────────────────────────────────────────────
    pub fn faq(&self) -> Result<(), ErrorDetection> {
        use crate::commandline::s_19_frequently_asked_questions::S19FrequentlyAskedQuestions;

        S19FrequentlyAskedQuestions::faq()
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 20.  Exit
    // ─────────────────────────────────────────────────────────────────────────────
    /// Handles exiting the application with warnings and confirmation.
    pub fn exit(&mut self, json_logger: &JsonLogger) -> Result<bool, ErrorDetection> {
        use crate::commandline::s_20_exit::S20Exit;

        // Delegate to the extracted Exit flow module (keeps behavior 1-to-1).
        let mut exit_flow = S20Exit::new();
        exit_flow.exit(json_logger)
    }

    //─────────────────────────────────────────────────────────────────────
    // Additional methods required for CLI interactivity
    //─────────────────────────────────────────────────────────────────────
    /// Best-effort: append an outgoing chat JSON line to
    ///   <data_dir>/sender.message/sent_chat.jsonl
    fn save_outgoing_chat_json(&self, opts: &NodeOpts, chat: &ChatMessage) {
        use std::fs::{self, OpenOptions};
        use std::io::Write;
        use std::path::PathBuf;

        // Defensive caps (best-effort logging should not explode)
        const MAX_LOG_MESSAGE_BYTES: usize = 2_048;

        // FOLDER CHANGE: sender.message instead of json.chat
        let mut dir = PathBuf::from(&opts.data_dir);
        dir.push("sender.message");

        if let Err(e) = fs::create_dir_all(&dir) {
            tracing::warn!(
                "[CHAT] failed to create sent chat directory {}: {}",
                dir.display(),
                e
            );
            return;
        }

        let file_path = dir.join("sent_chat.jsonl");
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    "[CHAT] failed to open sent chat file {}: {}",
                    file_path.display(),
                    e
                );
                return;
            }
        };

        // Decode the plaintext for logging. If it fails (shouldn't), mark it.
        let mut message = match chat.plaintext() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    "[CHAT] failed to decode plaintext for outgoing chat log: {:?}",
                    e
                );
                "<decode_failed>".to_string()
            }
        };

        // Defensive: cap log message size.
        if message.len() > MAX_LOG_MESSAGE_BYTES {
            message.truncate(MAX_LOG_MESSAGE_BYTES);
        }

        let record = serde_json::json!({
            "from_wallet": chat.from_wallet,
            "to_wallet": chat.to_wallet,
            "timestamp_ms": chat.timestamp_ms,
            "message": message,
        });

        let line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(_) => "{\"error\":\"serialize_failed\"}".to_string(),
        };

        if let Err(e) = writeln!(file, "{}", line) {
            tracing::warn!(
                "[CHAT] failed to append outgoing chat to {}: {}",
                file_path.display(),
                e
            );
        }
    }
}
