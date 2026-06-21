use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::commandline::command_line_003_manager::CommandManager;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::{Mode, RockDBManager};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::logging_data::JsonLogger;

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(case_name: &str) -> TestResult<Self> {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "remzar_cmd_mgr_{case_name}_{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self.path.exists() {
            match fs::remove_dir_all(&self.path) {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

fn boxed_error(message: &str) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message.to_owned()))
}

fn string_error(message: String) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message))
}

fn path_to_string(path: &Path) -> TestResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn node_opts(root: &Path) -> TestResult<NodeOpts> {
    Ok(NodeOpts {
        identity_file: path_to_string(&root.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "off".to_owned(),
        data_dir: path_to_string(root)?,
        wallet_address: String::new(),
        founder: false,
    })
}

fn make_logger(root: &Path) -> TestResult<JsonLogger> {
    let directory = DirectoryDB::from_base_dir(root).map_err(string_error)?;
    directory.create_log_directory().map_err(string_error)?;
    JsonLogger::new(&directory).map_err(string_error)
}

fn make_manager(case_name: &str) -> TestResult<(TempRoot, NodeOpts, CommandManager)> {
    let temp = TempRoot::new(case_name)?;
    let opts = node_opts(temp.path())?;
    let identity_path = temp.path().join("identity.key");
    let manager = CommandManager::new_no_signals(&opts, identity_path)?;
    Ok((temp, opts, manager))
}

fn make_chain(manager: &CommandManager) -> AccountModelTree {
    let db_manager = manager.db_manager();
    AccountModelTree::with_manager((*db_manager).clone())
}

fn expect_error<T>(result: Result<T, ErrorDetection>) -> TestResult<ErrorDetection> {
    match result {
        Ok(_) => Err(boxed_error("expected operation to fail")),
        Err(error) => Ok(error),
    }
}

fn assert_error_contains<T>(result: Result<T, ErrorDetection>, needle: &str) -> TestResult {
    let error = expect_error(result)?;
    let message = error.to_string();
    assert!(
        message.contains(needle),
        "error message did not contain '{needle}': {message}"
    );
    Ok(())
}

fn run_async<F>(future: F) -> TestResult<F::Output>
where
    F: std::future::Future,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(future))
}

#[test]
fn manager_01_new_no_signals_starts_not_running() -> TestResult {
    let (_temp, _opts, manager) = make_manager("01_new_not_running")?;
    assert!(!manager.is_p2p_running());
    Ok(())
}

#[test]
fn manager_02_new_no_signals_preserves_identity_path() -> TestResult {
    let temp = TempRoot::new("02_identity_path")?;
    let opts = node_opts(temp.path())?;
    let identity_path = temp.path().join("custom").join("identity.key");
    let manager = CommandManager::new_no_signals(&opts, identity_path.clone())?;
    assert_eq!(manager.identity_path(), identity_path.as_path());
    Ok(())
}

#[test]
fn manager_03_new_no_signals_local_wallet_is_empty() -> TestResult {
    let (_temp, _opts, manager) = make_manager("03_empty_wallet")?;
    assert!(manager.local_wallet().is_empty());
    Ok(())
}

#[test]
fn manager_04_new_no_signals_db_manager_is_cli_mode() -> TestResult {
    let (_temp, _opts, manager) = make_manager("04_cli_mode")?;
    assert_eq!(manager.db_manager().mode, Mode::CLI);
    Ok(())
}

#[test]
fn manager_05_new_no_signals_audit_and_pdf_dirs_are_empty_paths() -> TestResult {
    let (_temp, _opts, manager) = make_manager("05_empty_audit_pdf")?;
    assert!(manager.audit_dir.as_os_str().is_empty());
    assert!(manager.pdf_dir.as_os_str().is_empty());
    Ok(())
}

#[test]
fn manager_06_console_bus_getter_is_cloneable() -> TestResult {
    let (_temp, _opts, manager) = make_manager("06_console_bus")?;
    let _bus_one = manager.console_bus();
    let _bus_two = manager.console_bus();
    Ok(())
}

#[test]
fn manager_07_new_with_audit_creates_audit_and_pdf_dirs() -> TestResult {
    let temp = TempRoot::new("07_new_with_audit")?;
    let opts = node_opts(temp.path())?;
    let audit_dir = temp.path().join("audit");
    let pdf_dir = temp.path().join("pdf");
    let manager = CommandManager::new_with_audit(
        &opts,
        &path_to_string(&audit_dir)?,
        &path_to_string(&pdf_dir)?,
        temp.path().join("identity.key"),
    )?;

    assert!(audit_dir.is_dir());
    assert!(pdf_dir.is_dir());
    assert_eq!(manager.audit_dir, audit_dir);
    assert_eq!(manager.pdf_dir, pdf_dir);
    Ok(())
}

#[test]
fn manager_08_new_with_audit_reuses_existing_dirs() -> TestResult {
    let temp = TempRoot::new("08_existing_audit_pdf")?;
    let opts = node_opts(temp.path())?;
    let audit_dir = temp.path().join("audit");
    let pdf_dir = temp.path().join("pdf");
    fs::create_dir_all(&audit_dir)?;
    fs::create_dir_all(&pdf_dir)?;

    let manager = CommandManager::new_with_audit(
        &opts,
        &path_to_string(&audit_dir)?,
        &path_to_string(&pdf_dir)?,
        temp.path().join("identity.key"),
    )?;

    assert_eq!(manager.audit_dir, audit_dir);
    assert_eq!(manager.pdf_dir, pdf_dir);
    Ok(())
}

#[test]
fn manager_09_mark_started_sets_running_true() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("09_mark_started")?;
    manager.mark_started()?;
    assert!(manager.is_p2p_running());
    Ok(())
}

#[test]
fn manager_10_mark_started_twice_rejects_second_start() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("10_mark_twice")?;
    manager.mark_started()?;
    assert_error_contains(manager.mark_started(), "already running")
}

#[test]
fn manager_11_set_p2p_handle_before_mark_started_is_rejected() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("11_handle_before_start")?;
    run_async(async {
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async {});
        assert_error_contains(
            manager.set_p2p_handle(handle, shutdown_tx),
            "before mark_started",
        )
    })?
}

#[test]
fn manager_12_set_p2p_handle_after_mark_started_succeeds() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("12_handle_after_start")?;
    run_async(async {
        manager.mark_started()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = shutdown_rx.await;
        });
        manager.set_p2p_handle(handle, shutdown_tx)?;
        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_13_stop_node_when_not_running_is_rejected() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("13_stop_not_running")?;
    run_async(async { assert_error_contains(manager.stop_node().await, "not running") })?
}

#[test]
fn manager_14_stop_node_running_without_handle_clears_running_flag() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("14_stop_no_handle")?;
    run_async(async {
        manager.mark_started()?;
        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_15_stop_node_running_with_shutdown_handle_completes() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("15_stop_with_handle")?;
    run_async(async {
        manager.mark_started()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = shutdown_rx.await;
        });
        manager.set_p2p_handle(handle, shutdown_tx)?;
        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_16_chain_mut_before_running_is_rejected() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("16_chain_mut_before_running")?;
    assert_error_contains(manager.chain_mut(), "start_node")
}

#[test]
fn manager_17_replace_chain_before_running_is_rejected() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("17_replace_before_running")?;
    let chain = make_chain(&manager);
    assert_error_contains(manager.replace_chain(chain), "P2P node not running")
}

#[test]
fn manager_18_take_chain_before_running_is_rejected() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("18_take_before_running")?;
    assert_error_contains(manager.take_chain(), "P2P node not running")
}

#[test]
fn manager_19_replace_chain_after_mark_started_makes_chain_mut_available() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("19_replace_after_start")?;
    manager.mark_started()?;
    let chain = make_chain(&manager);
    manager.replace_chain(chain)?;
    assert!(manager.chain_mut().is_ok());
    Ok(())
}

#[test]
fn manager_20_take_chain_after_replace_returns_chain_then_slot_is_empty() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("20_take_after_replace")?;
    manager.mark_started()?;
    let chain = make_chain(&manager);
    manager.replace_chain(chain)?;
    let _taken = manager.take_chain()?;
    assert_error_contains(manager.chain_mut(), "start_node")
}

#[test]
fn manager_21_take_chain_when_running_but_empty_is_rejected() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("21_take_empty")?;
    manager.mark_started()?;
    assert_error_contains(manager.take_chain(), "P2P node must be running")
}

#[test]
fn manager_22_stop_node_clears_chain_slot() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("22_stop_clears_chain")?;
    run_async(async {
        manager.mark_started()?;
        let chain = make_chain(&manager);
        manager.replace_chain(chain)?;
        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());
        assert_error_contains(manager.chain_mut(), "start_node")
    })?
}

#[test]
fn manager_23_stop_node_allows_mark_started_again() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("23_restart_after_stop")?;
    run_async(async {
        manager.mark_started()?;
        manager.stop_node().await?;
        manager.mark_started()?;
        assert!(manager.is_p2p_running());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_24_reload_registry_without_ephemeral_succeeds() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("24_reload_no_ephemeral")?;
    manager.reload_registry_from_db()?;
    Ok(())
}

#[test]
fn manager_25_reload_registry_after_start_node_guard_succeeds() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("25_reload_after_guard")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        manager.reload_registry_from_db()?;
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_26_initialize_blockchain_empty_creates_blockchain_manager() -> TestResult {
    let (_temp, opts, manager) = make_manager("26_empty_chain_manager")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    assert_eq!(blockchain.mode, Mode::Blockchain);
    Ok(())
}

#[test]
fn manager_27_initialize_blockchain_empty_creates_blockchain_directory() -> TestResult {
    let (_temp, opts, manager) = make_manager("27_empty_chain_dir")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    let dir = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    assert!(dir.blockchain_path.is_dir());
    drop(blockchain);
    Ok(())
}

#[test]
fn manager_28_initialize_blockchain_empty_has_no_latest_block() -> TestResult {
    let (_temp, opts, manager) = make_manager("28_empty_chain_no_latest")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    assert!(blockchain.get_latest_block()?.is_none());
    Ok(())
}

#[test]
fn manager_29_initialize_blockchain_empty_rejects_when_running() -> TestResult {
    let (_temp, opts, mut manager) = make_manager("29_empty_chain_running")?;
    manager.mark_started()?;
    assert_error_contains(
        manager.initialize_blockchain_empty(&opts),
        "P2P node is running",
    )
}

#[test]
fn manager_30_create_certificates_requires_running_node() -> TestResult {
    let (temp, opts, mut manager) = make_manager("30_create_certs_requires_running")?;
    let logger = make_logger(temp.path())?;
    assert_error_contains(
        manager.create_certificates(&opts, &logger),
        "P2P node not running",
    )
}

#[test]
fn manager_31_send_message_requires_running_node() -> TestResult {
    let (_temp, opts, mut manager) = make_manager("31_send_message_requires_running")?;
    assert_error_contains(manager.send_message(&opts), "P2P node not running")
}

#[test]
fn manager_32_send_files_requires_running_node() -> TestResult {
    let (_temp, opts, mut manager) = make_manager("32_send_files_requires_running")?;
    assert_error_contains(manager.send_files(&opts), "P2P node not running")
}

#[test]
fn manager_33_play_slot_machine_requires_running_node() -> TestResult {
    let (temp, opts, mut manager) = make_manager("33_slot_requires_running")?;
    let logger = make_logger(temp.path())?;
    assert_error_contains(
        manager.play_slot_machine(&opts, &logger),
        "P2P node not running",
    )
}

#[test]
fn manager_34_start_node_already_running_delegation_returns_ok() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("34_start_guard")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_35_start_node_already_running_is_idempotent() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("35_start_guard_twice")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_36_start_node_guard_does_not_change_empty_local_wallet() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("36_start_guard_wallet")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.local_wallet().is_empty());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_37_logger_works_with_manager_temp_dirs() -> TestResult {
    let (temp, _opts, _manager) = make_manager("37_logger")?;
    let logger = make_logger(temp.path())?;
    logger
        .log_error_event("command_manager", "TestEvent", "manager logger test")
        .map_err(string_error)?;
    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;
    Ok(())
}

#[test]
fn manager_38_faq_returns_ok_without_runtime() -> TestResult {
    let (_temp, _opts, manager) = make_manager("38_faq")?;
    manager.faq()?;
    Ok(())
}

#[test]
fn manager_39_multiple_managers_use_isolated_data_dirs() -> TestResult {
    let (_temp_a, _opts_a, manager_a) = make_manager("39_isolated_a")?;
    let (_temp_b, _opts_b, manager_b) = make_manager("39_isolated_b")?;

    assert_ne!(
        manager_a.db_manager().directory.db_path,
        manager_b.db_manager().directory.db_path
    );
    assert_eq!(manager_a.db_manager().mode, Mode::CLI);
    assert_eq!(manager_b.db_manager().mode, Mode::CLI);
    Ok(())
}

#[test]
fn manager_40_initialize_blockchain_empty_can_be_reopened_readonly() -> TestResult {
    let (_temp, opts, manager) = make_manager("40_empty_readonly")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    let path = blockchain.directory.blockchain_path.clone();
    drop(blockchain);

    let readonly = RockDBManager::from_existing_readonly(&opts, &path)?;
    assert_eq!(readonly.mode, Mode::Blockchain);
    assert!(readonly.get_latest_block()?.is_none());
    Ok(())
}

#[test]
fn manager_41_new_no_signals_creates_cli_database_directory() -> TestResult {
    let (_temp, opts, manager) = make_manager("41_cli_dir_created")?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    assert!(directory.db_path.is_dir());
    assert_eq!(manager.db_manager().directory.db_path, directory.db_path);
    Ok(())
}

#[test]
fn manager_42_new_no_signals_accepts_existing_stale_cli_lock_file() -> TestResult {
    let temp = TempRoot::new("42_cli_lock")?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    fs::create_dir_all(&directory.db_path)?;
    fs::write(directory.db_path.join("LOCK"), b"locked")?;

    let identity_path = temp.path().join("identity.key");
    let manager = CommandManager::new_no_signals(&opts, identity_path.clone())
        .map_err(|e| string_error(format!("{e:?}")))?;

    assert_eq!(manager.identity_path(), identity_path.as_path());
    assert!(!manager.is_p2p_running());
    Ok(())
}

#[test]
fn manager_43_new_with_audit_accepts_existing_stale_cli_lock_file() -> TestResult {
    let temp = TempRoot::new("43_audit_cli_lock")?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    fs::create_dir_all(&directory.db_path)?;
    fs::write(directory.db_path.join("LOCK"), b"locked")?;

    let audit_dir = temp.path().join("audit");
    let pdf_dir = temp.path().join("pdf");
    let identity_path = temp.path().join("identity.key");

    let manager = CommandManager::new_with_audit(
        &opts,
        &path_to_string(&audit_dir)?,
        &path_to_string(&pdf_dir)?,
        identity_path.clone(),
    )
    .map_err(|e| string_error(format!("{e:?}")))?;

    assert_eq!(manager.identity_path(), identity_path.as_path());
    assert_eq!(manager.audit_dir, audit_dir);
    assert_eq!(manager.pdf_dir, pdf_dir);
    assert!(!manager.is_p2p_running());
    Ok(())
}

#[test]
fn manager_44_new_with_audit_rejects_audit_path_that_is_file() -> TestResult {
    let temp = TempRoot::new("44_audit_path_file")?;
    let opts = node_opts(temp.path())?;
    let audit_file = temp.path().join("audit-file");
    fs::write(&audit_file, b"not a dir")?;

    let result = CommandManager::new_with_audit(
        &opts,
        &path_to_string(&audit_file)?,
        &path_to_string(&temp.path().join("pdf"))?,
        temp.path().join("identity.key"),
    );

    assert_error_contains(result, "Failed to create audit directory")
}

#[test]
fn manager_45_new_with_audit_rejects_pdf_path_that_is_file() -> TestResult {
    let temp = TempRoot::new("45_pdf_path_file")?;
    let opts = node_opts(temp.path())?;
    let pdf_file = temp.path().join("pdf-file");
    fs::write(&pdf_file, b"not a dir")?;

    let result = CommandManager::new_with_audit(
        &opts,
        &path_to_string(&temp.path().join("audit"))?,
        &path_to_string(&pdf_file)?,
        temp.path().join("identity.key"),
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn manager_46_new_with_audit_creates_nested_audit_and_pdf_dirs() -> TestResult {
    let temp = TempRoot::new("46_nested_audit_pdf")?;
    let opts = node_opts(temp.path())?;
    let audit_dir = temp.path().join("deep").join("audit").join("reports");
    let pdf_dir = temp.path().join("deep").join("pdf").join("scratch");

    let manager = CommandManager::new_with_audit(
        &opts,
        &path_to_string(&audit_dir)?,
        &path_to_string(&pdf_dir)?,
        temp.path().join("identity.key"),
    )?;

    assert!(audit_dir.is_dir());
    assert!(pdf_dir.is_dir());
    assert_eq!(manager.audit_dir, audit_dir);
    assert_eq!(manager.pdf_dir, pdf_dir);
    Ok(())
}

#[test]
fn manager_47_new_with_audit_preserves_relative_identity_path() -> TestResult {
    let temp = TempRoot::new("47_relative_identity")?;
    let opts = node_opts(temp.path())?;
    let identity_path = PathBuf::from("relative-identity.key");

    let manager = CommandManager::new_with_audit(
        &opts,
        &path_to_string(&temp.path().join("audit"))?,
        &path_to_string(&temp.path().join("pdf"))?,
        identity_path.clone(),
    )?;

    assert_eq!(manager.identity_path(), identity_path.as_path());
    Ok(())
}

#[test]
fn manager_48_new_no_signals_db_manager_arc_clones_point_to_same_directory() -> TestResult {
    let (_temp, _opts, manager) = make_manager("48_db_arc_clone")?;
    let one = manager.db_manager();
    let two = manager.db_manager();

    assert_eq!(one.directory.db_path, two.directory.db_path);
    assert_eq!(one.mode, Mode::CLI);
    assert_eq!(two.mode, Mode::CLI);
    Ok(())
}

#[test]
fn manager_49_console_bus_clone_does_not_require_running_node() -> TestResult {
    let (_temp, _opts, manager) = make_manager("49_console_clone_stopped")?;
    assert!(!manager.is_p2p_running());
    let _console_a = manager.console_bus();
    let _console_b = manager.console_bus();
    Ok(())
}

#[test]
fn manager_50_mark_started_does_not_change_identity_or_wallet() -> TestResult {
    let temp = TempRoot::new("50_mark_preserves_identity_wallet")?;
    let opts = node_opts(temp.path())?;
    let identity_path = temp.path().join("id").join("node.key");
    let mut manager = CommandManager::new_no_signals(&opts, identity_path.clone())?;

    manager.mark_started()?;

    assert!(manager.is_p2p_running());
    assert_eq!(manager.identity_path(), identity_path.as_path());
    assert!(manager.local_wallet().is_empty());
    Ok(())
}

#[test]
fn manager_51_stop_node_without_handle_keeps_identity_path() -> TestResult {
    let temp = TempRoot::new("51_stop_preserves_identity")?;
    let opts = node_opts(temp.path())?;
    let identity_path = temp.path().join("identity.key");
    let mut manager = CommandManager::new_no_signals(&opts, identity_path.clone())?;

    run_async(async {
        manager.mark_started()?;
        manager.stop_node().await?;
        assert_eq!(manager.identity_path(), identity_path.as_path());
        Ok(())
    })?
}

#[test]
fn manager_52_replace_chain_twice_while_running_succeeds() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("52_replace_twice")?;
    manager.mark_started()?;

    let first = make_chain(&manager);
    manager.replace_chain(first)?;
    assert!(manager.chain_mut().is_ok());

    let second = make_chain(&manager);
    manager.replace_chain(second)?;
    assert!(manager.chain_mut().is_ok());
    Ok(())
}

#[test]
fn manager_53_take_chain_then_replace_chain_again_succeeds() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("53_take_then_replace")?;
    manager.mark_started()?;

    let first = make_chain(&manager);
    manager.replace_chain(first)?;
    let _taken = manager.take_chain()?;
    assert_error_contains(manager.chain_mut(), "start_node")?;

    let second = make_chain(&manager);
    manager.replace_chain(second)?;
    assert!(manager.chain_mut().is_ok());
    Ok(())
}

#[test]
fn manager_54_chain_mut_returns_same_slot_after_multiple_calls() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("54_chain_mut_repeat")?;
    manager.mark_started()?;
    let chain = make_chain(&manager);
    manager.replace_chain(chain)?;

    assert!(manager.chain_mut().is_ok());
    assert!(manager.chain_mut().is_ok());
    Ok(())
}

#[test]
fn manager_55_stop_node_after_take_chain_still_succeeds() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("55_stop_after_take_chain")?;

    run_async(async {
        manager.mark_started()?;
        let chain = make_chain(&manager);
        manager.replace_chain(chain)?;
        let _taken = manager.take_chain()?;
        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_56_stop_node_clears_net_tx_channel_by_requiring_fresh_runtime_for_send_paths()
-> TestResult {
    let (_temp, opts, mut manager) = make_manager("56_stop_clears_net_tx_effect")?;

    run_async(async {
        manager.mark_started()?;
        let (tx, _rx) = tokio::sync::mpsc::channel::<remzar::network::p2p_010_netcmd::NetCmd>(1);
        manager.attach_net_tx(tx);
        manager.stop_node().await?;
        assert_error_contains(manager.send_message(&opts), "P2P node not running")
    })?
}

#[test]
fn manager_57_set_p2p_handle_with_already_finished_task_stops_cleanly() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("57_finished_handle")?;

    run_async(async {
        manager.mark_started()?;
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async {});
        manager.set_p2p_handle(handle, shutdown_tx)?;
        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_58_stop_node_sends_shutdown_signal_to_handle() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("58_shutdown_signal")?;

    run_async(async {
        manager.mark_started()?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            let _ = done_tx.send(());
        });

        manager.set_p2p_handle(handle, shutdown_tx)?;
        manager.stop_node().await?;

        assert!(done_rx.await.is_ok());
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_59_stop_node_then_stop_again_is_rejected() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("59_stop_twice")?;

    run_async(async {
        manager.mark_started()?;
        manager.stop_node().await?;
        assert_error_contains(manager.stop_node().await, "not running")
    })?
}

#[test]
fn manager_60_start_stop_cycle_three_times_without_handle() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("60_three_cycles")?;

    run_async(async {
        for _ in 0..3 {
            manager.mark_started()?;
            assert!(manager.is_p2p_running());
            manager.stop_node().await?;
            assert!(!manager.is_p2p_running());
        }
        Ok(())
    })?
}

#[test]
fn manager_61_start_guard_then_stop_then_start_guard_again() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("61_guard_restart")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        manager.stop_node().await?;

        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_62_start_guard_does_not_create_identity_file() -> TestResult {
    let temp = TempRoot::new("62_guard_no_identity_file")?;
    let opts = node_opts(temp.path())?;
    let identity_path = temp.path().join("identity.key");
    let mut manager = CommandManager::new_no_signals(&opts, identity_path.clone())?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(!identity_path.exists());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_63_start_guard_does_not_create_blockchain_directory() -> TestResult {
    let temp = TempRoot::new("63_guard_no_blockchain_dir")?;
    let opts = node_opts(temp.path())?;
    let mut manager = CommandManager::new_no_signals(&opts, temp.path().join("identity.key"))?;
    let logger = make_logger(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(!directory.blockchain_path.exists());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_64_initialize_blockchain_empty_after_stop_succeeds() -> TestResult {
    let (_temp, opts, mut manager) = make_manager("64_empty_after_stop")?;

    run_async(async {
        manager.mark_started()?;
        manager.stop_node().await?;
        let blockchain = manager.initialize_blockchain_empty(&opts)?;
        assert_eq!(blockchain.mode, Mode::Blockchain);
        Ok(())
    })?
}

#[test]
fn manager_65_initialize_blockchain_empty_twice_after_dropping_first_succeeds() -> TestResult {
    let (_temp, opts, manager) = make_manager("65_empty_twice")?;

    let first = manager.initialize_blockchain_empty(&opts)?;
    assert_eq!(first.mode, Mode::Blockchain);
    drop(first);

    let second = manager.initialize_blockchain_empty(&opts)?;
    assert_eq!(second.mode, Mode::Blockchain);
    Ok(())
}

#[test]
fn manager_66_initialize_blockchain_empty_path_matches_directory_db() -> TestResult {
    let (_temp, opts, manager) = make_manager("66_empty_path_match")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;

    assert_eq!(
        blockchain.directory.blockchain_path,
        directory.blockchain_path
    );
    Ok(())
}

#[test]
fn manager_67_initialize_blockchain_empty_read_global_missing_latest_index() -> TestResult {
    let (_temp, opts, manager) = make_manager("67_empty_missing_latest_index")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;

    let raw = blockchain.read(
        remzar::utility::alpha_001_global_configuration::GlobalConfiguration::GLOBAL_COLUMN_NAME,
        b"latest_block_index",
    )?;

    assert!(raw.is_none());
    Ok(())
}

#[test]
fn manager_68_initialize_blockchain_empty_read_global_missing_tip_height() -> TestResult {
    let (_temp, opts, manager) = make_manager("68_empty_missing_tip")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;

    let raw = blockchain.read(
        remzar::utility::alpha_001_global_configuration::GlobalConfiguration::GLOBAL_COLUMN_NAME,
        b"tip_height",
    )?;

    assert!(raw.is_none());
    Ok(())
}

#[test]
fn manager_69_initialize_blockchain_empty_readonly_reopen_preserves_empty_latest_block()
-> TestResult {
    let (_temp, opts, manager) = make_manager("69_empty_readonly_latest")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    let path = blockchain.directory.blockchain_path.clone();
    drop(blockchain);

    let readonly = RockDBManager::from_existing_readonly(&opts, &path)?;
    assert!(readonly.get_latest_block()?.is_none());
    Ok(())
}

#[test]
fn manager_70_initialize_blockchain_empty_then_cli_db_manager_still_available() -> TestResult {
    let (_temp, opts, manager) = make_manager("70_cli_available_after_empty_chain")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    assert_eq!(blockchain.mode, Mode::Blockchain);

    let cli = manager.db_manager();
    assert_eq!(cli.mode, Mode::CLI);
    assert!(cli.directory.db_path.is_dir());
    Ok(())
}

#[test]
fn manager_71_reload_registry_repeatedly_without_ephemeral_is_idempotent() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("71_reload_repeat_empty")?;

    for _ in 0..5 {
        manager.reload_registry_from_db()?;
    }

    assert!(!manager.is_p2p_running());
    Ok(())
}

#[test]
fn manager_72_reload_registry_after_start_guard_is_idempotent() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("72_reload_repeat_guard")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;

        for _ in 0..5 {
            manager.reload_registry_from_db()?;
        }

        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_73_reload_registry_after_stop_still_succeeds() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("73_reload_after_stop")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        manager.stop_node().await?;
        manager.reload_registry_from_db()?;
        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_74_nonrunning_guard_methods_return_protocol_errors_vector() -> TestResult {
    let (temp, opts, mut manager) = make_manager("74_nonrunning_guards")?;
    let logger = make_logger(temp.path())?;

    let create_certificates_error = expect_error(manager.create_certificates(&opts, &logger))?;
    assert!(
        create_certificates_error
            .to_string()
            .contains("P2P node not running")
    );

    let send_message_error = expect_error(manager.send_message(&opts))?;
    assert!(
        send_message_error
            .to_string()
            .contains("P2P node not running")
    );

    let send_files_error = expect_error(manager.send_files(&opts))?;
    assert!(
        send_files_error
            .to_string()
            .contains("P2P node not running")
    );

    let play_error = expect_error(manager.play_slot_machine(&opts, &logger))?;
    assert!(play_error.to_string().contains("P2P node not running"));

    Ok(())
}

#[test]
fn manager_75_start_guard_initializes_ephemeral_registry_without_entering_interactive_flow()
-> TestResult {
    let (temp, _opts, mut manager) = make_manager("75_start_guard_ephemeral")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());
        manager.reload_registry_from_db()?;
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_76_start_guard_preserves_empty_local_wallet() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("76_start_guard_wallet")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        assert!(manager.local_wallet().is_empty());
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.local_wallet().is_empty());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_77_start_guard_does_not_create_identity_file() -> TestResult {
    let temp = TempRoot::new("77_start_guard_no_identity_file")?;
    let opts = node_opts(temp.path())?;
    let identity_path = temp.path().join("identity.key");
    let mut manager = CommandManager::new_no_signals(&opts, identity_path.clone())?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(!identity_path.exists());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_78_start_guard_does_not_create_blockchain_directory() -> TestResult {
    let temp = TempRoot::new("78_start_guard_no_blockchain_dir")?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    let mut manager = CommandManager::new_no_signals(&opts, temp.path().join("identity.key"))?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(!directory.blockchain_path.exists());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_79_start_guard_can_be_called_twice_without_blocking() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("79_start_guard_twice")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_80_start_guard_then_stop_then_start_guard_again() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("80_guard_restart")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());

        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_81_logger_multiple_error_events_flush_successfully() -> TestResult {
    let (temp, _opts, _manager) = make_manager("81_logger_many")?;
    let logger = make_logger(temp.path())?;

    for idx in 0..10usize {
        logger
            .log_error_event("command_manager", "VectorLog", &format!("event {idx}"))
            .map_err(string_error)?;
    }

    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;
    Ok(())
}

#[test]
fn manager_82_faq_can_be_called_repeatedly_without_runtime() -> TestResult {
    let (_temp, _opts, manager) = make_manager("82_faq_repeat")?;

    for _ in 0..3 {
        manager.faq()?;
    }

    Ok(())
}

#[test]
fn manager_83_vector_new_no_signals_many_isolated_managers() -> TestResult {
    let mut db_paths = Vec::new();

    for idx in 0..6usize {
        let case_name = format!("83_isolated_{idx}");
        let (_temp, _opts, manager) = make_manager(&case_name)?;
        db_paths.push(manager.db_manager().directory.db_path.clone());
    }

    for left in 0..db_paths.len() {
        for right in left.saturating_add(1)..db_paths.len() {
            assert_ne!(db_paths[left], db_paths[right]);
        }
    }

    Ok(())
}

#[test]
fn manager_84_vector_start_stop_many_isolated_managers() -> TestResult {
    run_async(async {
        for idx in 0..4usize {
            let case_name = format!("84_start_stop_{idx}");
            let (_temp, _opts, mut manager) = make_manager(&case_name)?;
            manager.mark_started()?;
            assert!(manager.is_p2p_running());
            manager.stop_node().await?;
            assert!(!manager.is_p2p_running());
        }

        Ok(())
    })?
}

#[test]
fn manager_85_vector_empty_blockchain_many_isolated_managers() -> TestResult {
    for idx in 0..4usize {
        let case_name = format!("85_empty_chain_{idx}");
        let (_temp, opts, manager) = make_manager(&case_name)?;
        let blockchain = manager.initialize_blockchain_empty(&opts)?;
        assert_eq!(blockchain.mode, Mode::Blockchain);
        assert!(blockchain.get_latest_block()?.is_none());
        drop(blockchain);
    }

    Ok(())
}

#[test]
fn manager_86_new_with_audit_vector_many_paths() -> TestResult {
    for idx in 0..4usize {
        let temp = TempRoot::new(&format!("86_audit_vec_{idx}"))?;
        let opts = node_opts(temp.path())?;
        let audit_dir = temp.path().join(format!("audit-{idx}"));
        let pdf_dir = temp.path().join(format!("pdf-{idx}"));

        let manager = CommandManager::new_with_audit(
            &opts,
            &path_to_string(&audit_dir)?,
            &path_to_string(&pdf_dir)?,
            temp.path().join(format!("identity-{idx}.key")),
        )?;

        assert!(manager.audit_dir.is_dir());
        assert!(manager.pdf_dir.is_dir());
    }

    Ok(())
}

#[test]
fn manager_87_identity_path_vector_preserves_unusual_file_names() -> TestResult {
    for file_name in ["identity.key", "node identity.key", "IDENTITY.KEY"] {
        let temp = TempRoot::new("87_identity_names")?;
        let opts = node_opts(temp.path())?;
        let identity_path = temp.path().join(file_name);
        let manager = CommandManager::new_no_signals(&opts, identity_path.clone())?;
        assert_eq!(manager.identity_path(), identity_path.as_path());
    }

    Ok(())
}

#[test]
fn manager_88_initialize_blockchain_empty_after_failed_running_attempt_succeeds_after_stop()
-> TestResult {
    let (_temp, opts, mut manager) = make_manager("88_empty_after_failed_running")?;

    run_async(async {
        manager.mark_started()?;
        assert!(manager.initialize_blockchain_empty(&opts).is_err());
        manager.stop_node().await?;

        let blockchain = manager.initialize_blockchain_empty(&opts)?;
        assert_eq!(blockchain.mode, Mode::Blockchain);
        drop(blockchain);
        Ok(())
    })?
}

#[test]
fn manager_89_chain_slot_after_stop_can_be_replaced_after_restart() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("89_chain_restart_replace")?;

    run_async(async {
        manager.mark_started()?;
        let first = make_chain(&manager);
        manager.replace_chain(first)?;
        manager.stop_node().await?;

        manager.mark_started()?;
        let second = make_chain(&manager);
        manager.replace_chain(second)?;
        assert!(manager.chain_mut().is_ok());
        manager.stop_node().await?;
        Ok(())
    })?
}

#[test]
fn manager_90_completed_task_handle_stop_then_restart_with_new_handle() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("90_completed_handle_restart")?;

    run_async(async {
        manager.mark_started()?;
        let (shutdown_tx_one, _shutdown_rx_one) = tokio::sync::oneshot::channel::<()>();
        let handle_one = tokio::spawn(async {});
        manager.set_p2p_handle(handle_one, shutdown_tx_one)?;
        manager.stop_node().await?;

        manager.mark_started()?;
        let (shutdown_tx_two, _shutdown_rx_two) = tokio::sync::oneshot::channel::<()>();
        let handle_two = tokio::spawn(async {});
        manager.set_p2p_handle(handle_two, shutdown_tx_two)?;
        manager.stop_node().await?;

        assert!(!manager.is_p2p_running());
        Ok(())
    })?
}

#[test]
fn manager_91_shutdown_signal_handle_stop_then_stop_rejects() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("91_signal_then_stop_again")?;

    run_async(async {
        manager.mark_started()?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = shutdown_rx.await;
        });

        manager.set_p2p_handle(handle, shutdown_tx)?;
        manager.stop_node().await?;

        assert_error_contains(manager.stop_node().await, "not running")
    })?
}

#[test]
fn manager_92_start_guard_then_reload_registry_then_stop_then_reload_again() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("92_guard_reload_stop_reload")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        manager.mark_started()?;
        manager.start_node(&logger).await?;
        manager.reload_registry_from_db()?;
        manager.stop_node().await?;
        manager.reload_registry_from_db()?;
        Ok(())
    })?
}

#[test]
fn manager_93_stop_node_clears_chain_but_not_cli_db_manager() -> TestResult {
    let (_temp, _opts, mut manager) = make_manager("93_stop_preserves_cli_db")?;

    run_async(async {
        let original_db_path = manager.db_manager().directory.db_path.clone();

        manager.mark_started()?;
        let chain = make_chain(&manager);
        manager.replace_chain(chain)?;
        manager.stop_node().await?;

        assert_eq!(manager.db_manager().directory.db_path, original_db_path);
        assert_eq!(manager.db_manager().mode, Mode::CLI);
        assert_error_contains(manager.chain_mut(), "start_node")
    })?
}

#[test]
fn manager_94_initialize_empty_blockchain_does_not_change_p2p_running_flag() -> TestResult {
    let (_temp, opts, manager) = make_manager("94_empty_no_running_change")?;
    assert!(!manager.is_p2p_running());

    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    assert_eq!(blockchain.mode, Mode::Blockchain);
    assert!(!manager.is_p2p_running());

    drop(blockchain);
    Ok(())
}

#[test]
fn manager_95_logger_after_empty_blockchain_init_still_writes() -> TestResult {
    let (temp, opts, manager) = make_manager("95_logger_after_empty_chain")?;
    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    assert_eq!(blockchain.mode, Mode::Blockchain);
    drop(blockchain);

    let logger = make_logger(temp.path())?;
    logger
        .log_error_event("command_manager", "AfterEmptyBlockchain", "ok")
        .map_err(string_error)?;
    logger.flush().map_err(string_error)?;
    Ok(())
}

#[test]
fn manager_96_constructor_then_drop_then_recreate_same_data_dir_succeeds() -> TestResult {
    let temp = TempRoot::new("96_recreate_same_dir")?;
    let opts = node_opts(temp.path())?;
    let identity_path = temp.path().join("identity.key");

    {
        let manager = CommandManager::new_no_signals(&opts, identity_path.clone())?;
        assert_eq!(manager.db_manager().mode, Mode::CLI);
    }

    let recreated = CommandManager::new_no_signals(&opts, identity_path)?;
    assert_eq!(recreated.db_manager().mode, Mode::CLI);
    Ok(())
}

#[test]
fn manager_97_stop_node_clears_chain_and_allows_empty_blockchain_init() -> TestResult {
    let (_temp, opts, mut manager) = make_manager("97_stop_then_empty_chain")?;

    run_async(async {
        manager.mark_started()?;
        let chain = make_chain(&manager);
        manager.replace_chain(chain)?;
        manager.stop_node().await?;

        let blockchain = manager.initialize_blockchain_empty(&opts)?;
        assert_eq!(blockchain.mode, Mode::Blockchain);
        assert!(blockchain.get_latest_block()?.is_none());
        drop(blockchain);

        Ok(())
    })?
}

#[test]
fn manager_98_start_guard_safe_lifecycle_smoke_without_interactive_sections() -> TestResult {
    let (temp, _opts, mut manager) = make_manager("98_safe_lifecycle_guard")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        assert!(!manager.is_p2p_running());
        manager.reload_registry_from_db()?;

        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());

        let chain = make_chain(&manager);
        manager.replace_chain(chain)?;
        assert!(manager.chain_mut().is_ok());

        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());

        manager.reload_registry_from_db()?;
        Ok(())
    })?
}

#[test]
fn manager_99_combined_empty_blockchain_and_logger_smoke_test() -> TestResult {
    let (temp, opts, manager) = make_manager("99_empty_chain_logger_smoke")?;
    let logger = make_logger(temp.path())?;

    let blockchain = manager.initialize_blockchain_empty(&opts)?;
    assert_eq!(blockchain.mode, Mode::Blockchain);
    assert!(blockchain.get_latest_block()?.is_none());
    drop(blockchain);

    logger
        .log_error_event("command_manager", "CombinedSmoke", "complete")
        .map_err(string_error)?;
    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;

    Ok(())
}

#[test]
fn manager_100_full_noninteractive_lifecycle_smoke_test() -> TestResult {
    let (temp, opts, mut manager) = make_manager("100_noninteractive_smoke")?;
    let logger = make_logger(temp.path())?;

    run_async(async {
        assert!(!manager.is_p2p_running());
        assert!(manager.local_wallet().is_empty());

        let blockchain = manager.initialize_blockchain_empty(&opts)?;
        assert_eq!(blockchain.mode, Mode::Blockchain);
        assert!(blockchain.get_latest_block()?.is_none());
        drop(blockchain);

        manager.reload_registry_from_db()?;

        manager.mark_started()?;
        manager.start_node(&logger).await?;
        assert!(manager.is_p2p_running());

        let chain = make_chain(&manager);
        manager.replace_chain(chain)?;
        assert!(manager.chain_mut().is_ok());

        manager.stop_node().await?;
        assert!(!manager.is_p2p_running());

        manager.reload_registry_from_db()?;
        logger
            .log_error_event("command_manager", "CombinedSmoke", "complete")
            .map_err(string_error)?;

        Ok(())
    })?
}
