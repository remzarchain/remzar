//! src/commandline/command_line_001_interface.rs
//! Top-level CLI parsing and blockchain-command dispatch.

use crate::commandline::command_line_003_manager::CommandManager;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

/* ─────────────── CommandHandler ─────────────── */

pub struct CommandHandler {
    manager: CommandManager,
    opts: NodeOpts,

    /// Set to true when the user successfully requested exit.
    /// This avoids calling `std::process::exit` directly (graceful shutdown).
    exit_requested: bool,
}

impl CommandHandler {
    /// Construct a new handler.
    pub fn new(manager: CommandManager, opts: NodeOpts) -> Self {
        Self {
            manager,
            opts,
            exit_requested: false,
        }
    }

    /// Expose a mutable reference to the inner manager.
    pub fn manager_mut(&mut self) -> &mut CommandManager {
        &mut self.manager
    }

    /// Whether the handler has been asked to exit.
    pub fn exit_requested(&self) -> bool {
        self.exit_requested
    }

    /// Start the P2P runtime if it is not already running.
    async fn ensure_node_started(
        &mut self,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        if self.manager.is_p2p_running() {
            println!("{}", "✅ Blockchain has already started.".green());
            return Ok(());
        }
        Box::pin(self.manager.start_node(json_logger)).await
    }

    /// Dispatch one blockchain sub-command.
    pub async fn handle_command(
        &mut self,
        command: BlockchainSubcommand,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        use BlockchainSubcommand::*;

        match command {
            /* ───── 1–2: database / wallet creation ───── */
            SetupDatabase => self.manager.setup_database(&self.opts, json_logger),
            GenerateWallet => self.manager.generate_wallet(&self.opts, json_logger),

            /* ───── 3: networking ───── */
            StartNode => self.ensure_node_started(json_logger).await,

            /* ───── 4: blockchain console ───── */
            ViewConsole => self.manager.view_blockchain_console(&self.opts),

            /* ───── 5–7: send / receive / status ───── */
            SendRemzar => {
                self.ensure_node_started(json_logger).await?;
                self.manager.send_remzar(&self.opts, json_logger)
            }
            ReceiveRemzar => self.manager.receive_remzar(&self.opts, json_logger),
            ViewStatus => self.manager.view_status(),

            /* ───── 8: balance ───── */
            CheckBalance => self.manager.check_balance(&self.opts, json_logger),

            /* ───── 9: wallet utilities ───── */
            ListWallets => self.manager.list_wallets(json_logger),

            /* ───── 10–12: certificates / chat / file ───── */
            // Menu 10 uses enum variant `CreateNft`, but calls `create_certificates`.
            CreateNft => self.manager.create_certificates(&self.opts, json_logger),

            // Defensive guard: chat is a P2P feature; ensure the runtime is up.
            SendChat => {
                self.ensure_node_started(json_logger).await?;
                self.manager.send_message(&self.opts)
            }

            // Defensive guard: file transfer is a P2P feature; ensure the runtime is up.
            SendFile => {
                self.ensure_node_started(json_logger).await?;
                self.manager.send_files(&self.opts)
            }

            /* ───── 13–17: debug group ───── */
            OpenEncryptedKey => self.manager.debug_open_encrypted_key(json_logger),
            BackupWallet => self.manager.debug_backup_wallet(&self.opts, json_logger),
            DebugKeys => self.manager.debug_keys(json_logger),
            DebugLogInfo => self.manager.debug_logs(&self.opts, json_logger),
            AuditReport => {
                self.manager.debug_audit_report(&self.opts, json_logger)?;
                Ok(())
            }

            /* ───── 18: slot machine game ───── */
            PlaySlots => {
                // Defensive guard: game requires a running P2P runtime.
                // Auto-start is cheap and prevents "works sometimes" states.
                self.ensure_node_started(json_logger).await?;
                self.manager.play_slot_machine(&self.opts, json_logger)
            }

            /* ───── 19: FAQ ───── */
            Faq => self.manager.faq(),

            /* ───── 20: exit ───── */
            Exit => {
                println!("{}", "🔄 Closing RocksDB before exiting...".cyan());
                let should_exit = self.manager.exit(json_logger)?;
                if should_exit {
                    println!("{}", "✅ RocksDB closed successfully.".green());
                    // Graceful wiring: do not hard-exit the process here.
                    // Let the caller observe `exit_requested()` and terminate naturally.
                    self.exit_requested = true;
                    Ok(())
                } else {
                    println!("{}", "❎ Exit canceled; returning to menu.".yellow());
                    Ok(())
                }
            }
        }
    }
}

/* ───────────────  Root CLI  ─────────────── */

#[derive(Parser, Debug)]
#[command(name = "remzar")]
#[command(about = "Remzar blockchain CLI & P2P node")]
pub struct BlockchainCommands {
    /// Path to the genesis JSON file (overrides env, default is ./genesis.json)
    #[arg(long, short = 'g', env = "REMZAR_GENESIS_PATH")]
    pub genesis: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Root-level sub-commands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// launch the libp2p networking node
    Node(NodeOpts),

    /// any of the 20 blockchain maintenance commands
    #[command(flatten)]
    Chain(BlockchainSubcommand),
}

/* ───────── Blockchain-maintenance sub-commands ───────── */

#[derive(Subcommand, Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
pub enum BlockchainSubcommand {
    SetupDatabase,
    GenerateWallet,
    StartNode,
    ViewConsole,
    SendRemzar,
    ReceiveRemzar,
    ViewStatus,
    CheckBalance,
    ListWallets,
    CreateNft,
    SendChat,
    SendFile,
    OpenEncryptedKey,
    BackupWallet,
    DebugKeys,
    DebugLogInfo,
    AuditReport,
    PlaySlots,
    Faq,
    Exit,
}

/* ---- helpers for interactive menu ---- */

impl BlockchainSubcommand {
    pub fn from_choice(choice: u32) -> Option<Self> {
        use BlockchainSubcommand::*;
        match choice {
            1 => Some(SetupDatabase),
            2 => Some(GenerateWallet),
            3 => Some(StartNode),
            4 => Some(ViewConsole),
            5 => Some(SendRemzar),
            6 => Some(ReceiveRemzar),
            7 => Some(ViewStatus),
            8 => Some(CheckBalance),
            9 => Some(ListWallets),
            10 => Some(CreateNft),
            11 => Some(SendChat),
            12 => Some(SendFile),
            13 => Some(OpenEncryptedKey),
            14 => Some(BackupWallet),
            15 => Some(DebugKeys),
            16 => Some(DebugLogInfo),
            17 => Some(AuditReport),
            18 => Some(PlaySlots),
            19 => Some(Faq),
            20 => Some(Exit),
            _ => None,
        }
    }

    pub fn all() -> Vec<(&'static str, Self)> {
        use BlockchainSubcommand::*;
        vec![
            ("Setup Database", SetupDatabase),
            ("Generate Wallet", GenerateWallet),
            ("Start Node", StartNode),
            ("View Blockchain Console", ViewConsole),
            ("Send REMZAR", SendRemzar),
            ("Receive REMZAR", ReceiveRemzar),
            ("View Participant Status", ViewStatus),
            ("Balance of Wallet", CheckBalance),
            ("List Wallets", ListWallets),
            ("Create Certificates (mint)", CreateNft),
            ("Send Chat (p2p message)", SendChat),
            ("Send File (p2p file sharing)", SendFile),
            ("Debug: Open Encrypted Private Key", OpenEncryptedKey),
            ("Debug: Backup Wallet", BackupWallet),
            ("Debug: List Raw Database Keys", DebugKeys),
            ("Debug: Log Information", DebugLogInfo),
            ("Debug: Audit Report", AuditReport),
            ("Slot Machine Game", PlaySlots),
            ("FAQ (MUST READ)", Faq),
            ("Exit", Exit),
        ]
    }
}
