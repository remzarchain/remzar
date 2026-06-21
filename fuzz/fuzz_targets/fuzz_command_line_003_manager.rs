#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const JOIN_TIMEOUT_SECS: u64 = 1;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
            StorageError {
                message: String,
            },
            DatabaseError {
                details: String,
            },
            ProtocolError {
                message: String,
            },
            NotFound {
                resource: String,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, .. } => write!(f, "{message}"),
                    Self::SerializationError { details } => write!(f, "{details}"),
                    Self::StorageError { message } => write!(f, "{message}"),
                    Self::DatabaseError { details } => write!(f, "{details}"),
                    Self::ProtocolError { message } => write!(f, "{message}"),
                    Self::NotFound { resource } => write!(f, "{resource} not found"),
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod logging_data {
        #[derive(Debug, Clone, Default)]
        pub struct JsonLogger;

        impl JsonLogger {
            pub fn new_for_fuzz() -> Self {
                Self
            }

            pub fn log_error_event(
                &self,
                _component: &str,
                _event: &str,
                _message: &str,
            ) -> Result<(), ()> {
                Ok(())
            }
        }
    }
}

mod runtime {
    pub mod p2p_006_sync_runtime {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct NodeOpts {
            pub data_dir: String,
        }

        impl NodeOpts {
            pub fn new_for_fuzz(data_dir: String) -> Self {
                Self { data_dir }
            }
        }
    }
}

mod storage {
    pub mod rocksdb_007_db_guard {
        #[derive(Debug)]
        pub struct DbGuard;
    }

    pub mod rocksdb_000_directory {
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use std::path::PathBuf;

        #[derive(Debug, Clone)]
        pub struct DirectoryDB {
            pub blockchain_path: PathBuf,
        }

        impl DirectoryDB {
            pub fn from_node_opts(opts: &NodeOpts) -> Result<Self, String> {
                let mut p = PathBuf::from(&opts.data_dir);
                p.push("blockchain_db");
                Ok(Self { blockchain_path: p })
            }
        }
    }

    pub mod rocksdb_005_manager {
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone, Default)]
        pub struct MockBlockchainDb;

        #[derive(Debug, Clone, Default)]
        pub struct RockDBManager {
            writes: Arc<Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>>,
            blockchain_open_should_fail: bool,
        }

        impl RockDBManager {
            pub fn new(_opts: &NodeOpts) -> Result<Self, String> {
                Ok(Self::default())
            }

            pub fn new_blockchain(_opts: &NodeOpts, _path: &str) -> Result<Self, String> {
                Ok(Self::default())
            }

            pub fn open_db_blockchain(&self) -> Result<MockBlockchainDb, String> {
                if self.blockchain_open_should_fail {
                    Err("mock blockchain open failure".into())
                } else {
                    Ok(MockBlockchainDb)
                }
            }

            pub fn write(
                &self,
                column: &str,
                key: &[u8],
                value: &[u8],
            ) -> Result<(), ErrorDetection> {
                let mut g = self.writes.lock().map_err(|_| ErrorDetection::StorageError {
                    message: "mock db write lock poisoned".into(),
                })?;
                g.push((column.to_string(), key.to_vec(), value.to_vec()));
                Ok(())
            }
        }
    }
}

mod blockchain {
    pub mod transaction_005_tx_account_tree {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct AccountModelTree {
            pub marker: u64,
        }

        impl AccountModelTree {
            pub fn new_for_fuzz(marker: u64) -> Self {
                Self { marker }
            }

            pub fn commit(&self) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn flush_balances(&self) -> Result<(), ErrorDetection> {
                Ok(())
            }
        }
    }
}

mod consensus {
    pub mod por_000_ephemeral_registration {
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone, Default)]
        pub struct RegistryData {
            pub wallets: HashSet<String>,
            pub identity_map: HashMap<String, String>,
            pub join_heights: HashMap<String, u64>,
        }

        impl RegistryData {
            pub fn new() -> Self {
                Self::default()
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct EphemeralRegistry {
            pub wallets: HashSet<String>,
            pub identity_map: HashMap<String, String>,
            pub join_heights: HashMap<String, u64>,
        }

        impl EphemeralRegistry {
            pub fn sorted_wallets(&self) -> Vec<String> {
                let mut wallets: Vec<String> = self.wallets.iter().cloned().collect();
                wallets.sort();
                wallets
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct NodeEphemeral {
            inner: Arc<Mutex<EphemeralRegistry>>,
        }

        impl NodeEphemeral {
            pub fn new_for_fuzz(wallet: String) -> Self {
                let mut reg = EphemeralRegistry::default();
                reg.wallets.insert(wallet.clone());
                reg.identity_map.insert(wallet.clone(), "peer-fuzz".to_string());
                reg.join_heights.insert(wallet, 0);
                Self {
                    inner: Arc::new(Mutex::new(reg)),
                }
            }

            pub fn ephemeral(&self) -> Arc<Mutex<EphemeralRegistry>> {
                Arc::clone(&self.inner)
            }
        }
    }
}

mod network {
    pub mod p2p_014_chat {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct ChatMessage {
            pub from_wallet: String,
            pub to_wallet: String,
            pub timestamp_ms: u64,
            plaintext: String,
        }

        impl ChatMessage {
            pub fn new_for_fuzz(message: String) -> Self {
                Self {
                    from_wallet: "rfuzz_sender".to_string(),
                    to_wallet: "rfuzz_receiver".to_string(),
                    timestamp_ms: 1_700_000_000_000,
                    plaintext: message,
                }
            }

            pub fn plaintext(&self) -> Result<String, String> {
                Ok(self.plaintext.clone())
            }
        }
    }

    pub mod p2p_010_netcmd {
        use crate::network::p2p_014_chat::ChatMessage;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum NetCmd {
            SendChat(ChatMessage),
            FuzzBytes(Vec<u8>),
        }
    }
}

mod commandline {
    pub mod s_04_view_blockchain_console {
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, Default)]
        pub struct ConsoleBus;

        impl ConsoleBus {
            pub fn new() -> Self {
                Self
            }
        }

        #[derive(Debug, Clone)]
        pub struct BlockchainConsoleView {
            _bus: ConsoleBus,
        }

        impl BlockchainConsoleView {
            pub fn new(bus: ConsoleBus) -> Self {
                Self { _bus: bus }
            }

            pub fn run_blocking(&self, _opts: &NodeOpts) -> Result<(), ErrorDetection> {
                Ok(())
            }
        }
    }

    pub mod s_01_setup_database {
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;

        pub struct S01SetupDatabase;
        impl S01SetupDatabase {
            pub fn new() -> Self { Self }
            pub fn setup_database(&mut self, _opts: &NodeOpts, _logger: &JsonLogger) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod s_02_generate_wallet {
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;

        pub struct S02GenerateWallet;
        impl S02GenerateWallet {
            pub fn new() -> Self { Self }
            pub fn generate_wallet(&mut self, _opts: &NodeOpts, _logger: &JsonLogger) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod s_03_startnode {
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
        use crate::consensus::por_000_ephemeral_registration::{NodeEphemeral, RegistryData};
        use crate::network::p2p_010_netcmd::NetCmd;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::storage::rocksdb_007_db_guard::DbGuard;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        use std::sync::Arc;
        use tokio::{sync::{mpsc, oneshot}, task::JoinHandle};

        pub struct S03StartNodeArgs<'a> {
            pub node_registry: &'a mut Option<RegistryData>,
            pub node_ephemeral: &'a mut Option<NodeEphemeral>,
            pub db_manager: &'a mut Arc<RockDBManager>,
            pub p2p_running: &'a mut bool,
            pub p2p_handle: &'a mut Option<(JoinHandle<()>, oneshot::Sender<()>)>,
            pub net_tx: &'a mut Option<mpsc::Sender<NetCmd>>,
            pub console_bus: ConsoleBus,
            pub chain: &'a mut Option<AccountModelTree>,
            pub local_wallet: &'a mut String,
            pub blockchain_db_guard: &'a mut Option<DbGuard>,
        }

        pub struct S03StartNode<'a> {
            args: S03StartNodeArgs<'a>,
        }

        impl<'a> S03StartNode<'a> {
            pub fn new(args: S03StartNodeArgs<'a>) -> Self {
                Self { args }
            }

            pub async fn start_node(&mut self, _logger: &JsonLogger) -> Result<(), ErrorDetection> {
                if *self.args.p2p_running {
                    return Err(ErrorDetection::ProtocolError {
                        message: "P2P node already running".into(),
                    });
                }

                *self.args.p2p_running = true;
                *self.args.local_wallet = "rfuzz_startnode_wallet".to_string();
                *self.args.chain = Some(AccountModelTree::new_for_fuzz(99));
                *self.args.node_ephemeral = Some(NodeEphemeral::new_for_fuzz(
                    self.args.local_wallet.clone(),
                ));
                *self.args.node_registry = Some(RegistryData::new());
                let (tx, _rx) = mpsc::channel(8);
                *self.args.net_tx = Some(tx);
                let _ = &self.args.db_manager;
                let _ = &self.args.p2p_handle;
                let _ = &self.args.console_bus;
                let _ = &self.args.blockchain_db_guard;
                Ok(())
            }
        }
    }

    macro_rules! simple_section {
        ($mod_name:ident, $type_name:ident, $method_name:ident) => {
            pub mod $mod_name {
                use crate::runtime::p2p_006_sync_runtime::NodeOpts;
                use crate::utility::alpha_002_error_detection_system::ErrorDetection;
                use crate::utility::logging_data::JsonLogger;

                pub struct $type_name;
                impl $type_name {
                    pub fn new() -> Self { Self }
                    pub fn $method_name(&self, _opts: &NodeOpts, _logger: &JsonLogger) -> Result<(), ErrorDetection> { Ok(()) }
                }
            }
        };
    }

    pub mod s_05_send_remzar {
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::network::p2p_010_netcmd::NetCmd;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        use std::sync::Arc;
        use tokio::sync::mpsc;

        pub struct S05SendRemzar;
        impl S05SendRemzar {
            pub fn new(
                _db: Arc<RockDBManager>,
                _chain: &mut Option<AccountModelTree>,
                _net_tx: Option<mpsc::Sender<NetCmd>>,
            ) -> Self { Self }

            pub fn send_remzar(&mut self, _opts: &NodeOpts, _logger: &JsonLogger) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    simple_section!(s_06_receive_remzar, S06ReceiveRemzar, receive_remzar);

    pub mod s_07_view_status {
        use crate::consensus::por_000_ephemeral_registration::NodeEphemeral;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::path::Path;
        use std::sync::Arc;

        pub struct S07ViewStatus;
        impl S07ViewStatus {
            pub fn new() -> Self { Self }
            pub fn view_status(
                &mut self,
                _ephemeral: Option<&NodeEphemeral>,
                _db: Arc<RockDBManager>,
                _local_wallet: &str,
                _identity_path: &Path,
            ) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod s_08_check_balance {
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        use std::sync::Arc;

        pub struct S08CheckBalance;
        impl S08CheckBalance {
            pub fn new() -> Self { Self }
            pub fn check_balance(
                &self,
                _opts: &NodeOpts,
                _db: Arc<RockDBManager>,
                _chain: Option<AccountModelTree>,
                _logger: &JsonLogger,
            ) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod s_09_list_wallets {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;

        pub struct S09ListWallets;
        impl S09ListWallets {
            pub fn new() -> Self { Self }
            pub fn list_wallets(&self, _logger: &JsonLogger) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod s_10_create_certificates {
        use crate::network::p2p_010_netcmd::NetCmd;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        use std::path::PathBuf;
        use std::sync::Arc;

        pub struct S10CreateCertificates;
        impl S10CreateCertificates {
            pub fn new() -> Self { Self }
            #[allow(clippy::too_many_arguments)]
            pub fn create_certificates<F>(
                &mut self,
                _opts: &NodeOpts,
                _db: Arc<RockDBManager>,
                _local_wallet: &str,
                _audit_dir: &PathBuf,
                _pdf_dir: &PathBuf,
                _logger: &JsonLogger,
                send_net_cmd: &mut F,
            ) -> Result<(), ErrorDetection>
            where
                F: FnMut(NetCmd) -> Result<(), ErrorDetection>,
            {
                let _ = send_net_cmd(NetCmd::FuzzBytes(vec![1, 2, 3]));
                Ok(())
            }
        }
    }

    pub mod s_11_send_chat {
        use crate::network::p2p_014_chat::ChatMessage;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub struct S11SendChat;
        impl S11SendChat {
            pub fn new() -> Self { Self }
            pub fn send_message(&mut self, _opts: &NodeOpts) -> Result<Option<ChatMessage>, ErrorDetection> {
                Ok(Some(ChatMessage::new_for_fuzz("hello from fuzz".to_string())))
            }
        }
    }

    pub mod s_12_send_file {
        use crate::network::p2p_010_netcmd::NetCmd;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub struct S12SendFile;
        impl S12SendFile {
            pub fn new() -> Self { Self }
            pub fn send_files<F>(&mut self, _opts: &NodeOpts, send_net_cmd: &mut F) -> Result<(), ErrorDetection>
            where
                F: FnMut(NetCmd) -> Result<(), ErrorDetection>,
            {
                let _ = send_net_cmd(NetCmd::FuzzBytes(vec![4, 5, 6]));
                Ok(())
            }
        }
    }

    pub mod s_13_wallet_utilities {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        pub struct S13WalletUtilities;
        impl S13WalletUtilities {
            pub fn new() -> Self { Self }
            pub fn debug_open_encrypted_key(&mut self, _logger: &JsonLogger) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    simple_section!(s_14_backup_wallet, S14BackupWallet, debug_backup_wallet);

    pub mod s_15_debug_wallet_storage_keys {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        pub struct S15DebugWalletStorageKeys;
        impl S15DebugWalletStorageKeys {
            pub fn new() -> Self { Self }
            pub fn debug_keys(&self, _logger: &JsonLogger) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    simple_section!(s_16_debug_logs, S16DebugLogs, debug_logs);
    simple_section!(s_17_debug_audit_report, S17DebugAuditReport, debug_audit_report);

    pub mod s_18_games {
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::network::p2p_010_netcmd::NetCmd;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::storage::rocksdb_005_manager::{MockBlockchainDb, RockDBManager};
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        use std::sync::Arc;
        use tokio::sync::mpsc;

        pub struct S18Games;
        impl S18Games {
            pub fn new() -> Self { Self }
            pub fn play_slot_machine(
                &mut self,
                _opts: &NodeOpts,
                _db: &MockBlockchainDb,
                _db_manager: Arc<RockDBManager>,
                net_tx: mpsc::Sender<NetCmd>,
                _chain_opt: Option<&mut AccountModelTree>,
                _logger: &JsonLogger,
            ) -> Result<(), ErrorDetection> {
                let _ = net_tx.try_send(NetCmd::FuzzBytes(vec![7, 8, 9]));
                Ok(())
            }
        }
    }

    pub mod s_19_frequently_asked_questions {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        pub struct S19FrequentlyAskedQuestions;
        impl S19FrequentlyAskedQuestions {
            pub fn faq() -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod s_20_exit {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::logging_data::JsonLogger;
        pub struct S20Exit;
        impl S20Exit {
            pub fn new() -> Self { Self }
            pub fn exit(&mut self, _logger: &JsonLogger) -> Result<bool, ErrorDetection> { Ok(false) }
        }
    }
}

#[path = "../../src/commandline/command_line_003_manager.rs"]
mod command_line_003_manager;

use blockchain::transaction_005_tx_account_tree::AccountModelTree;
use command_line_003_manager::CommandManager;
use network::p2p_010_netcmd::NetCmd;
use network::p2p_014_chat::ChatMessage;
use runtime::p2p_006_sync_runtime::NodeOpts;
use utility::alpha_002_error_detection_system::ErrorDetection;
use utility::logging_data::JsonLogger;

fn touch_error(error: &ErrorDetection) {
    let _ = error.to_string();
    match error {
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            let _ = tx_id.as_ref().map(|s| s.len());
        }
        ErrorDetection::SerializationError { details }
        | ErrorDetection::DatabaseError { details } => {
            let _ = details.len();
        }
        ErrorDetection::StorageError { message }
        | ErrorDetection::ProtocolError { message } => {
            let _ = message.len();
        }
        ErrorDetection::NotFound { resource } => {
            let _ = resource.len();
        }
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            touch_error(&error);
            None
        }
    }
}

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = byte_at(data, offset + i, i as u8);
    }
    u64::from_le_bytes(out)
}

fn safe_suffix(data: &[u8], salt: usize) -> String {
    format!(
        "{:016x}_{:02x}_{:02x}",
        read_u64(data, salt),
        byte_at(data, salt + 9, 0),
        byte_at(data, salt + 10, 0)
    )
}

fn make_opts(data: &[u8], salt: usize) -> (NodeOpts, PathBuf, PathBuf, PathBuf) {
    let mut base = std::env::temp_dir();
    base.push(format!("remzar_command_manager_fuzz_{}", safe_suffix(data, salt)));

    let audit = base.join("audit");
    let pdf = base.join("pdf");
    let identity = base.join("identity.key");

    let _ = std::fs::create_dir_all(&base);

    (
        NodeOpts::new_for_fuzz(base.to_string_lossy().to_string()),
        identity,
        audit,
        pdf,
    )
}

fn new_manager(data: &[u8], salt: usize) -> Option<(CommandManager, NodeOpts, JsonLogger)> {
    let (opts, identity, audit, pdf) = make_opts(data, salt);
    let logger = JsonLogger::new_for_fuzz();

    let manager = if byte_at(data, salt + 50, 0) & 1 == 0 {
        touch_result(CommandManager::new_no_signals(&opts, identity))?
    } else {
        touch_result(CommandManager::new_with_audit(
            &opts,
            &audit.to_string_lossy(),
            &pdf.to_string_lossy(),
            identity,
        ))?
    };

    Some((manager, opts, logger))
}

fn exercise_constructors_and_getters(data: &[u8]) {
    let Some((mut manager, opts, logger)) = new_manager(data, 0) else {
        return;
    };

    let _ = manager.db_manager();
    assert!(!manager.is_p2p_running());
    let _ = manager.identity_path().display().to_string();
    let _ = manager.local_wallet().len();
    let _ = manager.console_bus();

    let _ = touch_result(manager.setup_database(&opts, &logger));
    let _ = touch_result(manager.generate_wallet(&opts, &logger));
    let _ = touch_result(manager.receive_remzar(&opts, &logger));
    let _ = touch_result(manager.view_blockchain_console(&opts));
    let _ = touch_result(manager.check_balance(&opts, &logger));
    let _ = touch_result(manager.list_wallets(&logger));
    let _ = touch_result(manager.debug_open_encrypted_key(&logger));
    let _ = touch_result(manager.debug_backup_wallet(&opts, &logger));
    let _ = touch_result(manager.debug_keys(&logger));
    let _ = touch_result(manager.debug_logs(&opts, &logger));
    let _ = touch_result(manager.debug_audit_report(&opts, &logger));
    let _ = touch_result(manager.faq());

    if let Some(confirmed) = touch_result(manager.exit(&logger)) {
        assert!(!confirmed);
    }
}

fn exercise_lifecycle_guards(data: &[u8]) {
    let Some((mut manager, opts, logger)) = new_manager(data, 100) else {
        return;
    };

    assert!(!manager.is_p2p_running());
    let _ = touch_result(manager.chain_mut());
    let _ = touch_result(manager.take_chain());
    let _ = touch_result(manager.replace_chain(AccountModelTree::new_for_fuzz(1)));
    let _ = touch_result(manager.create_certificates(&opts, &logger));
    let _ = touch_result(manager.send_message(&opts));
    let _ = touch_result(manager.send_files(&opts));
    let _ = touch_result(manager.play_slot_machine(&opts, &logger));
    let _ = touch_result(manager.initialize_blockchain_empty(&opts));

    let _ = touch_result(manager.mark_started());
    assert!(manager.is_p2p_running());

    // Starting twice must reject cleanly.
    let _ = touch_result(manager.mark_started());

    let chain = AccountModelTree::new_for_fuzz(read_u64(data, 111));
    let _ = touch_result(manager.replace_chain(chain.clone()));
    if let Some(ch) = touch_result(manager.chain_mut()) {
        ch.marker = ch.marker.saturating_add(1);
    }
    let _ = touch_result(manager.take_chain());
    let _ = touch_result(manager.take_chain());

    // Destructive init while running must reject.
    let _ = touch_result(manager.initialize_blockchain_empty(&opts));
}

fn exercise_network_channel(data: &[u8]) {
    let Some((mut manager, _opts, _logger)) = new_manager(data, 200) else {
        return;
    };

    let msg = ChatMessage::new_for_fuzz("fuzz network command".to_string());

    // No network channel yet: must fail cleanly.
    let _ = touch_result(manager.send_net_cmd(NetCmd::SendChat(msg.clone())));

    // Capacity-one channel lets us exercise success then Full.
    let (tx, _rx) = mpsc::channel(1);
    manager.attach_net_tx(tx);
    let _ = touch_result(manager.send_net_cmd(NetCmd::SendChat(msg.clone())));
    let _ = touch_result(manager.send_net_cmd(NetCmd::SendChat(msg.clone())));

    // Dropped receiver gives Closed.
    let (tx_closed, rx_closed) = mpsc::channel(1);
    drop(rx_closed);
    manager.attach_net_tx(tx_closed);
    let _ = touch_result(manager.send_net_cmd(NetCmd::SendChat(msg)));
}

fn exercise_public_command_methods(data: &[u8]) {
    let Some((mut manager, opts, logger)) = new_manager(data, 300) else {
        return;
    };

    let (tx, mut rx) = mpsc::channel(32);
    manager.attach_net_tx(tx);
    let _ = touch_result(manager.mark_started());
    let _ = touch_result(manager.replace_chain(AccountModelTree::new_for_fuzz(300)));

    let _ = touch_result(manager.create_certificates(&opts, &logger));
    let _ = touch_result(manager.send_remzar(&opts, &logger));
    let _ = touch_result(manager.view_status());
    let _ = touch_result(manager.check_balance(&opts, &logger));
    let _ = touch_result(manager.send_message(&opts));
    let _ = touch_result(manager.send_files(&opts));
    let _ = touch_result(manager.play_slot_machine(&opts, &logger));
    let _ = touch_result(manager.reload_registry_from_db());

    // Drain a few mock NetCmds so mpsc queue behavior is observable to the fuzzer.
    for _ in 0..4 {
        match rx.try_recv() {
            Ok(cmd) => match cmd {
                NetCmd::SendChat(chat) => {
                    let _ = chat.plaintext();
                }
                NetCmd::FuzzBytes(bytes) => {
                    let _ = bytes.len();
                }
            },
            Err(_) => break,
        }
    }
}

fn exercise_async_start_stop(data: &[u8]) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        return;
    };

    rt.block_on(async move {
        let Some((mut manager, opts, logger)) = new_manager(data, 400) else {
            return;
        };

        // Stop before start must fail cleanly.
        let _ = touch_result(manager.stop_node().await);

        if byte_at(data, 411, 0) & 1 == 0 {
            // Exercise the extracted S03StartNode wrapper path.
            let _ = touch_result(manager.start_node(&logger).await);
            let _ = touch_result(manager.reload_registry_from_db());
            let _ = touch_result(manager.stop_node().await);
            assert!(!manager.is_p2p_running());
        } else {
            // Exercise mark_started + explicit handle + graceful shutdown path.
            let _ = touch_result(manager.mark_started());
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let handle = tokio::spawn(async move {
                let _ = shutdown_rx.await;
            });
            let _ = touch_result(manager.set_p2p_handle(handle, shutdown_tx));
            let _ = touch_result(manager.replace_chain(AccountModelTree::new_for_fuzz(411)));
            let _ = touch_result(manager.stop_node().await);
            assert!(!manager.is_p2p_running());
        }

        // After stop, guarded methods should reject again.
        let _ = touch_result(manager.create_certificates(&opts, &logger));
        let _ = touch_result(manager.take_chain());
    });
}

fuzz_target!(|data: &[u8]| {
    exercise_constructors_and_getters(data);
    exercise_lifecycle_guards(data);
    exercise_network_channel(data);
    exercise_public_command_methods(data);
    exercise_async_start_stop(data);
});
