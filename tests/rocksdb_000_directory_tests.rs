#![forbid(unsafe_op_in_unsafe_fn)]

mod runtime {
    pub mod p2p_006_sync_runtime {
        #[derive(Debug, Clone)]
        pub struct NodeOpts {
            pub identity_file: String,
            pub listen: String,
            pub bootstrap: Vec<String>,
            pub log: String,
            pub data_dir: String,
            pub wallet_address: String,
            pub founder: bool,
        }
    }
}

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const WALLETS_DIR: &str = "000.wallets";
            pub const DATABASE_DIR_NAME: &str = "001.database_db";
            pub const BLOCKCHAIN_DATABASE_DIR: &str = "002.blockchain_db";
            pub const REGISTRY_DIR_NAME: &str = "003.registry_db";
            pub const LOG_DATABASE_DIR: &str = "004.log_db";
            pub const AUDIT_REPORTS_DIR: &str = "005.audit_reports";
            pub const ACCOUNTMODEL_DATABASE_DIR: &str = "006.accountmodel_db";
            pub const PEER_LIST_DIR: &str = "007.peerlist";
            pub const SIDECHAIN_DATABASE_DIR: &str = "008.sidechain_db";
            pub const TOTAL_DB_DIRS: usize = 9;

            pub const GENESIS_VALIDATOR: &str = "r0000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000";
        }
    }
}

#[path = "../src/storage/rocksdb_000_directory.rs"]
mod rocksdb_000_directory;

use rocksdb_000_directory::DirectoryDB;
use runtime::p2p_006_sync_runtime::NodeOpts;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use utility::alpha_001_global_configuration::GlobalConfiguration;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_rocksdb_000_directory_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            make_writable_recursive(&root);
            let _remove_result = fs::remove_dir_all(&root);
        }

        match fs::create_dir_all(&root) {
            Ok(()) => Self { root },
            Err(err) => panic!("failed to create temp root '{}': {err}", root.display()),
        }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn child(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        make_writable_recursive(&self.root);
        let _remove_result = fs::remove_dir_all(&self.root);
    }
}

fn make_writable_recursive(path: &Path) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(_) => return,
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = metadata.permissions();
        let mode = permissions.mode();
        permissions.set_mode(mode | 0o700);
        if fs::set_permissions(path, permissions).is_err() {}
    }

    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            if fs::set_permissions(path, permissions).is_err() {}
        }
    }

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let entries = match fs::read_dir(path) {
            Ok(value) => value,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            make_writable_recursive(&entry.path());
        }
    }
}

fn assert_ok<T, E>(result: Result<T, E>, label: &str) -> T
where
    E: Debug,
{
    match result {
        Ok(value) => value,
        Err(err) => panic!("{label} failed: {err:?}"),
    }
}

fn assert_err<T, E>(result: Result<T, E>, label: &str) -> E
where
    T: Debug,
    E: Debug,
{
    match result {
        Ok(value) => panic!("{label} unexpectedly succeeded: {value:?}"),
        Err(err) => err,
    }
}

fn assert_directory_exists(path: &Path) {
    assert!(
        path.is_dir(),
        "expected directory to exist: {}",
        path.display()
    );
}

fn assert_path_is_not_symlink(path: &Path) {
    let metadata = assert_ok(
        fs::symlink_metadata(path),
        "symlink metadata check should succeed",
    );
    assert!(
        !metadata.file_type().is_symlink(),
        "path must not be a symlink: {}",
        path.display()
    );
}

#[cfg(windows)]
fn is_windows_symlink_privilege_error(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(1314)
}

#[cfg(not(windows))]
fn is_windows_symlink_privilege_error(_err: &std::io::Error) -> bool {
    false
}

fn all_directory_refs(dir: &DirectoryDB) -> [(&'static str, &Path); 9] {
    [
        ("wallets_path", dir.wallets_path.as_path()),
        ("db_path", dir.db_path.as_path()),
        ("blockchain_path", dir.blockchain_path.as_path()),
        ("registry_path", dir.registry_path.as_path()),
        ("accountmodel_path", dir.accountmodel_path.as_path()),
        ("sidechain_path", dir.sidechain_path.as_path()),
        ("log_path", dir.log_path.as_path()),
        ("audit_reports_path", dir.audit_reports_path.as_path()),
        ("peerlist_path", dir.peerlist_path.as_path()),
    ]
}

fn all_directory_paths(dir: &DirectoryDB) -> Vec<PathBuf> {
    all_directory_refs(dir)
        .iter()
        .map(|(_, path)| (*path).to_path_buf())
        .collect()
}

fn setup_all_directories(dir: &DirectoryDB) {
    assert_ok(dir.create_wallets_directory(), "create wallets directory");
    assert_ok(dir.create_db_directory(), "create db directory");
    assert_ok(
        dir.create_blockchain_directory(),
        "create blockchain directory",
    );
    assert_ok(dir.create_registry_directory(), "create registry directory");
    assert_ok(
        dir.create_accountmodel_directory(),
        "create accountmodel directory",
    );
    assert_ok(
        dir.create_sidechain_directory(),
        "create sidechain directory",
    );
    assert_ok(dir.create_log_directory(), "create log directory");
    assert_ok(
        dir.create_audit_reports_directory(),
        "create audit reports directory",
    );
    assert_ok(dir.create_peerlist_directory(), "create peerlist directory");
}

fn make_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_owned(),
        listen: "/ip4/127.0.0.1/tcp/36213".to_owned(),
        bootstrap: Vec::new(),
        log: "info".to_owned(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder: false,
    }
}

fn env_lock() -> MutexGuard<'static, ()> {
    match ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn with_remzar_data_dir<T>(value: &Path, action: impl FnOnce() -> T) -> T {
    let _guard = env_lock();
    let original = std::env::var_os("REMZAR_DATA_DIR");

    unsafe {
        std::env::set_var("REMZAR_DATA_DIR", value);
    }

    let output = action();

    unsafe {
        match original {
            Some(previous) => std::env::set_var("REMZAR_DATA_DIR", previous),
            None => std::env::remove_var("REMZAR_DATA_DIR"),
        }
    }

    output
}

fn create_dir_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)
    }
}

fn set_readonly(path: &Path, readonly: bool) {
    let metadata = assert_ok(fs::metadata(path), "read metadata before permission change");
    let mut permissions = metadata.permissions();
    permissions.set_readonly(readonly);
    assert_ok(
        fs::set_permissions(path, permissions),
        "set readonly permission",
    );
}

fn deterministic_name(seed: usize) -> String {
    let mut value = seed as u64;
    let mut out = String::from("case");

    for _ in 0..12 {
        value = value
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let bucket = ((value >> 32) % 36) as u8;
        let ch = if bucket < 10 {
            char::from(b'0' + bucket)
        } else {
            char::from(b'a' + (bucket - 10))
        };
        out.push(ch);
    }

    out
}

#[test]
fn t01_vector_from_base_dir_maps_all_expected_leaf_names() {
    let temp = TempTree::new("t01");
    let base = temp.child("base");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    assert_eq!(
        dir.wallets_path,
        base.join(GlobalConfiguration::WALLETS_DIR)
    );
    assert_eq!(
        dir.db_path,
        base.join(GlobalConfiguration::DATABASE_DIR_NAME)
    );
    assert_eq!(
        dir.blockchain_path,
        base.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
    assert_eq!(
        dir.registry_path,
        base.join(GlobalConfiguration::REGISTRY_DIR_NAME)
    );
    assert_eq!(
        dir.accountmodel_path,
        base.join(GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR)
    );
    assert_eq!(
        dir.sidechain_path,
        base.join(GlobalConfiguration::SIDECHAIN_DATABASE_DIR)
    );
    assert_eq!(
        dir.log_path,
        base.join(GlobalConfiguration::LOG_DATABASE_DIR)
    );
    assert_eq!(
        dir.audit_reports_path,
        base.join(GlobalConfiguration::AUDIT_REPORTS_DIR)
    );
    assert_eq!(
        dir.peerlist_path,
        base.join(GlobalConfiguration::PEER_LIST_DIR)
    );
}

#[test]
fn t02_vector_from_base_dir_produces_total_configured_directories() {
    let temp = TempTree::new("t02");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_eq!(
        all_directory_refs(&dir).len(),
        GlobalConfiguration::TOTAL_DB_DIRS
    );
}

#[test]
fn t03_vector_all_directory_paths_are_unique() {
    let temp = TempTree::new("t03");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let paths = all_directory_paths(&dir);
    let unique_paths: BTreeSet<PathBuf> = paths.iter().cloned().collect();

    assert_eq!(unique_paths.len(), GlobalConfiguration::TOTAL_DB_DIRS);
}

#[test]
fn t04_vector_all_directory_paths_stay_under_base_path() {
    let temp = TempTree::new("t04");
    let base = temp.child("base");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    for (name, path) in all_directory_refs(&dir) {
        assert!(
            path.starts_with(&base),
            "{name} must stay under base: {}",
            path.display()
        );
    }
}

#[test]
fn t05_vector_as_ref_returns_db_path() {
    let temp = TempTree::new("t05");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_eq!(dir.as_ref(), dir.db_path.as_path());
}

#[test]
fn t06_vector_clone_preserves_every_directory_path() {
    let temp = TempTree::new("t06");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let cloned = dir.clone();

    assert_eq!(all_directory_paths(&dir), all_directory_paths(&cloned));
}

#[test]
fn t07_vector_debug_output_contains_public_field_names() {
    let temp = TempTree::new("t07");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let debug = format!("{dir:?}");

    for field in [
        "wallets_path",
        "db_path",
        "blockchain_path",
        "registry_path",
        "accountmodel_path",
        "sidechain_path",
        "log_path",
        "audit_reports_path",
        "peerlist_path",
    ] {
        assert!(debug.contains(field), "debug output missing {field}");
    }
}

#[test]
fn t08_vector_from_node_opts_uses_cli_data_dir() {
    let temp = TempTree::new("t08");
    let data_dir = temp.child("node_data");
    let opts = make_node_opts(&data_dir);
    let dir = assert_ok(DirectoryDB::from_node_opts(&opts), "from_node_opts");

    assert_eq!(
        dir.blockchain_path,
        data_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
    assert_eq!(
        dir.peerlist_path,
        data_dir.join(GlobalConfiguration::PEER_LIST_DIR)
    );
}

#[test]
fn t09_edge_base_data_dir_honors_absolute_env_override() {
    let temp = TempTree::new("t09");
    let override_dir = temp.child("env_override");

    with_remzar_data_dir(&override_dir, || {
        let actual = assert_ok(DirectoryDB::base_data_dir(), "base_data_dir");
        assert_eq!(actual, override_dir);
    });
}

#[test]
fn t10_edge_base_data_dir_honors_relative_env_override() {
    let relative = PathBuf::from("relative-remzar-data-root");

    with_remzar_data_dir(&relative, || {
        let actual = assert_ok(DirectoryDB::base_data_dir(), "base_data_dir");
        assert_eq!(actual, relative);
    });
}

#[test]
fn t11_create_wallets_directory_creates_expected_directory() {
    let temp = TempTree::new("t11");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_wallets_directory(), "create_wallets_directory");
    assert_directory_exists(&dir.wallets_path);
    assert_path_is_not_symlink(&dir.wallets_path);
}

#[test]
fn t12_create_db_directory_creates_expected_directory() {
    let temp = TempTree::new("t12");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_db_directory(), "create_db_directory");
    assert_directory_exists(&dir.db_path);
    assert_path_is_not_symlink(&dir.db_path);
}

#[test]
fn t13_create_blockchain_directory_creates_expected_directory() {
    let temp = TempTree::new("t13");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.create_blockchain_directory(),
        "create_blockchain_directory",
    );
    assert_directory_exists(&dir.blockchain_path);
    assert_path_is_not_symlink(&dir.blockchain_path);
}

#[test]
fn t14_create_registry_directory_creates_expected_directory() {
    let temp = TempTree::new("t14");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_registry_directory(), "create_registry_directory");
    assert_directory_exists(&dir.registry_path);
    assert_path_is_not_symlink(&dir.registry_path);
}

#[test]
fn t15_create_accountmodel_directory_creates_expected_directory() {
    let temp = TempTree::new("t15");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.create_accountmodel_directory(),
        "create_accountmodel_directory",
    );
    assert_directory_exists(&dir.accountmodel_path);
    assert_path_is_not_symlink(&dir.accountmodel_path);
}

#[test]
fn t16_create_sidechain_directory_creates_expected_directory() {
    let temp = TempTree::new("t16");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.create_sidechain_directory(),
        "create_sidechain_directory",
    );
    assert_directory_exists(&dir.sidechain_path);
    assert_path_is_not_symlink(&dir.sidechain_path);
}

#[test]
fn t17_create_log_directory_creates_expected_directory() {
    let temp = TempTree::new("t17");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_log_directory(), "create_log_directory");
    assert_directory_exists(&dir.log_path);
    assert_path_is_not_symlink(&dir.log_path);
}

#[test]
fn t18_create_audit_reports_directory_creates_expected_directory() {
    let temp = TempTree::new("t18");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.create_audit_reports_directory(),
        "create_audit_reports_directory",
    );
    assert_directory_exists(&dir.audit_reports_path);
    assert_path_is_not_symlink(&dir.audit_reports_path);
}

#[test]
fn t19_create_peerlist_directory_creates_expected_directory() {
    let temp = TempTree::new("t19");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_peerlist_directory(), "create_peerlist_directory");
    assert_directory_exists(&dir.peerlist_path);
    assert_path_is_not_symlink(&dir.peerlist_path);
}

#[test]
fn t20_edge_all_create_methods_are_idempotent_on_existing_directories() {
    let temp = TempTree::new("t20");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    setup_all_directories(&dir);

    for (name, path) in all_directory_refs(&dir) {
        assert_directory_exists(path);
        assert_path_is_not_symlink(path);
        assert!(
            path.starts_with(temp.root()),
            "{name} escaped temp root: {}",
            path.display()
        );
    }
}

#[test]
fn t21_setup_database_creates_wallets_target() {
    let temp = TempTree::new("t21");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.wallets_path),
        "setup_database wallets",
    );
    assert_directory_exists(&dir.wallets_path);
}

#[test]
fn t22_setup_database_creates_db_target() {
    let temp = TempTree::new("t22");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.setup_database(&dir.db_path), "setup_database db");
    assert_directory_exists(&dir.db_path);
}

#[test]
fn t23_setup_database_creates_blockchain_target() {
    let temp = TempTree::new("t23");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.blockchain_path),
        "setup_database blockchain",
    );
    assert_directory_exists(&dir.blockchain_path);
}

#[test]
fn t24_setup_database_creates_registry_target() {
    let temp = TempTree::new("t24");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.registry_path),
        "setup_database registry",
    );
    assert_directory_exists(&dir.registry_path);
}

#[test]
fn t25_setup_database_creates_accountmodel_target() {
    let temp = TempTree::new("t25");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.accountmodel_path),
        "setup_database accountmodel",
    );
    assert_directory_exists(&dir.accountmodel_path);
}

#[test]
fn t26_setup_database_creates_sidechain_target() {
    let temp = TempTree::new("t26");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.sidechain_path),
        "setup_database sidechain",
    );
    assert_directory_exists(&dir.sidechain_path);
}

#[test]
fn t27_setup_database_creates_log_target() {
    let temp = TempTree::new("t27");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.setup_database(&dir.log_path), "setup_database log");
    assert_directory_exists(&dir.log_path);
}

#[test]
fn t28_setup_database_creates_audit_reports_target() {
    let temp = TempTree::new("t28");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.audit_reports_path),
        "setup_database audit reports",
    );
    assert_directory_exists(&dir.audit_reports_path);
}

#[test]
fn t29_setup_database_creates_peerlist_target() {
    let temp = TempTree::new("t29");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.peerlist_path),
        "setup_database peerlist",
    );
    assert_directory_exists(&dir.peerlist_path);
}

#[test]
fn t30_adversarial_setup_database_rejects_unknown_target_and_lists_expected_targets() {
    let temp = TempTree::new("t30");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let invalid_target = temp.child("malicious_unknown_target");

    let err = assert_err(
        dir.setup_database(&invalid_target),
        "setup_database invalid target",
    );

    assert!(err.contains("Invalid target for setup_database"));
    assert!(err.contains("wallets_path"));
    assert!(err.contains("db_path"));
    assert!(err.contains("blockchain_path"));
    assert!(err.contains("registry_path"));
    assert!(err.contains("accountmodel_path"));
    assert!(err.contains("sidechain_path"));
    assert!(err.contains("log_path"));
    assert!(err.contains("audit_reports_path"));
    assert!(err.contains("peerlist_path"));
    assert!(err.contains(&invalid_target.display().to_string()));
}

#[test]
fn t31_validate_directories_passes_after_all_directories_exist() {
    let temp = TempTree::new("t31");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    assert_ok(dir.validate_directories(), "validate_directories");
}

#[test]
fn t32_edge_validate_directories_reports_missing_directories() {
    let temp = TempTree::new("t32");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories with missing directories",
    );

    for (_, path) in all_directory_refs(&dir) {
        assert!(
            err.contains(&path.display().to_string()),
            "error must mention missing path {}",
            path.display()
        );
    }

    assert!(err.contains("Missing directory"));
    assert!(err.contains("Failed to check metadata"));
}

#[test]
fn t33_edge_validate_directories_reports_partial_missing_directories() {
    let temp = TempTree::new("t33");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_wallets_directory(), "create wallets directory");
    assert_ok(dir.create_db_directory(), "create db directory");

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories with partial directories",
    );

    assert!(!err.contains(&format!(
        "Missing directory: {}",
        dir.wallets_path.display()
    )));
    assert!(!err.contains(&format!("Missing directory: {}", dir.db_path.display())));
    assert!(err.contains(&dir.blockchain_path.display().to_string()));
    assert!(err.contains(&dir.peerlist_path.display().to_string()));
}

#[test]
fn t34_edge_create_directory_creates_missing_parent_directories() {
    let temp = TempTree::new("t34");
    let deeply_nested_base = temp.child("a").join("b").join("c").join("node");
    let dir = assert_ok(
        DirectoryDB::from_base_dir(&deeply_nested_base),
        "from_base_dir",
    );

    assert_ok(
        dir.create_blockchain_directory(),
        "create nested blockchain directory",
    );

    assert_directory_exists(&dir.blockchain_path);
    assert!(dir.blockchain_path.starts_with(&deeply_nested_base));
}

#[test]
fn t35_adversarial_create_directory_rejects_existing_readonly_directory() {
    let temp = TempTree::new("t35");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        fs::create_dir_all(&dir.wallets_path),
        "pre-create wallets directory",
    );
    set_readonly(&dir.wallets_path, true);

    let err = assert_err(
        dir.create_wallets_directory(),
        "create_wallets_directory against readonly dir",
    );

    set_readonly(&dir.wallets_path, false);
    assert!(err.contains("No write permissions"));
    assert!(err.contains(&dir.wallets_path.display().to_string()));
}

#[test]
fn t36_adversarial_validate_directories_detects_readonly_directory() {
    let temp = TempTree::new("t36");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    set_readonly(&dir.peerlist_path, true);

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories with readonly peerlist",
    );

    set_readonly(&dir.peerlist_path, false);
    assert!(err.contains("Permission error"));
    assert!(err.contains("No write permissions"));
    assert!(err.contains(&dir.peerlist_path.display().to_string()));
}

#[test]
fn t37_adversarial_create_directory_rejects_symlink_target() {
    let temp = TempTree::new("t37");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let real_target = temp.child("real_wallet_target");

    assert_ok(
        fs::create_dir_all(&real_target),
        "create real symlink target",
    );

    match create_dir_symlink(&real_target, &dir.wallets_path) {
        Ok(()) => {
            let err = assert_err(
                dir.create_wallets_directory(),
                "create_wallets_directory against symlink",
            );

            assert!(err.contains("Refusing to use symlinked directory"));
            assert!(err.contains(&dir.wallets_path.display().to_string()));
        }
        Err(err) if is_windows_symlink_privilege_error(&err) => {
            assert!(
                !dir.wallets_path.exists(),
                "wallet symlink path should not exist after Windows refused symlink creation"
            );
            assert!(
                real_target.is_dir(),
                "real symlink target should still exist after Windows refused symlink creation"
            );
        }
        Err(err) => {
            panic!("create directory symlink failed unexpectedly: {err}");
        }
    }
}

#[test]
fn t38_adversarial_validate_directories_detects_symlink_directory() {
    let temp = TempTree::new("t38");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    assert_ok(
        fs::remove_dir_all(&dir.log_path),
        "remove real log directory",
    );

    let real_target = temp.child("real_log_target");
    assert_ok(
        fs::create_dir_all(&real_target),
        "create real symlink target",
    );

    match create_dir_symlink(&real_target, &dir.log_path) {
        Ok(()) => {
            let err = assert_err(
                dir.validate_directories(),
                "validate_directories with symlink log dir",
            );

            assert!(err.contains("Symlink detected"));
            assert!(err.contains("Refusing to use symlinked DB directories"));
            assert!(err.contains(&dir.log_path.display().to_string()));
        }
        Err(err) if is_windows_symlink_privilege_error(&err) => {
            assert!(
                !dir.log_path.exists(),
                "log symlink path should not exist after Windows refused symlink creation"
            );
            assert!(
                real_target.is_dir(),
                "real symlink target should still exist after Windows refused symlink creation"
            );

            assert_ok(
                dir.create_log_directory(),
                "recreate log directory after Windows refused symlink creation",
            );
            assert_ok(
                dir.validate_directories(),
                "validate directories after recreating real log directory",
            );
        }
        Err(err) => {
            panic!("create log directory symlink failed unexpectedly: {err}");
        }
    }
}

#[test]
fn t39_fuzz_property_generated_base_paths_keep_expected_shape() {
    let temp = TempTree::new("t39");

    for seed in 0..128 {
        let generated = deterministic_name(seed);
        let base = temp.child(&generated).join("node-data");
        let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir fuzz case");

        assert_eq!(
            dir.wallets_path
                .file_name()
                .and_then(|value| value.to_str()),
            Some(GlobalConfiguration::WALLETS_DIR)
        );
        assert_eq!(
            dir.db_path.file_name().and_then(|value| value.to_str()),
            Some(GlobalConfiguration::DATABASE_DIR_NAME)
        );
        assert_eq!(
            dir.blockchain_path
                .file_name()
                .and_then(|value| value.to_str()),
            Some(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
        );
        assert_eq!(
            dir.peerlist_path
                .file_name()
                .and_then(|value| value.to_str()),
            Some(GlobalConfiguration::PEER_LIST_DIR)
        );

        for (name, path) in all_directory_refs(&dir) {
            assert!(
                path.starts_with(&base),
                "fuzz seed {seed}: {name} escaped base {}",
                base.display()
            );
        }
    }
}

#[test]
fn t40_adversarial_network_sim_and_load_many_nodes_create_validate_in_parallel() {
    let temp = TempTree::new("t40");
    let mut handles = Vec::new();

    for node_id in 0..32usize {
        let base = temp.child(&format!("node_{node_id:02}"));
        handles.push(thread::spawn(move || -> Result<(), String> {
            let dir = DirectoryDB::from_base_dir(&base)?;
            setup_all_directories(&dir);
            dir.validate_directories()?;

            for (name, path) in all_directory_refs(&dir) {
                if !path.starts_with(&base) {
                    return Err(format!(
                        "node {node_id}: {name} escaped base {}",
                        base.display()
                    ));
                }

                if !path.is_dir() {
                    return Err(format!(
                        "node {node_id}: {name} was not created as a directory: {}",
                        path.display()
                    ));
                }
            }

            Ok(())
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("worker returned error: {err}"),
            Err(_) => panic!("worker panicked"),
        }
    }
}

#[test]
fn t41_vector_directory_leaf_names_match_expected_order() {
    let temp = TempTree::new("t41");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    let expected = [
        ("wallets_path", GlobalConfiguration::WALLETS_DIR),
        ("db_path", GlobalConfiguration::DATABASE_DIR_NAME),
        (
            "blockchain_path",
            GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR,
        ),
        ("registry_path", GlobalConfiguration::REGISTRY_DIR_NAME),
        (
            "accountmodel_path",
            GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR,
        ),
        (
            "sidechain_path",
            GlobalConfiguration::SIDECHAIN_DATABASE_DIR,
        ),
        ("log_path", GlobalConfiguration::LOG_DATABASE_DIR),
        ("audit_reports_path", GlobalConfiguration::AUDIT_REPORTS_DIR),
        ("peerlist_path", GlobalConfiguration::PEER_LIST_DIR),
    ];

    for ((actual_name, actual_path), (expected_name, expected_leaf)) in
        all_directory_refs(&dir).into_iter().zip(expected)
    {
        assert_eq!(actual_name, expected_name);
        assert_eq!(
            actual_path.file_name().and_then(|value| value.to_str()),
            Some(expected_leaf)
        );
    }
}

#[test]
fn t42_vector_setup_database_accepts_cloned_path_values() {
    let temp = TempTree::new("t42");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    for (name, path) in all_directory_refs(&dir) {
        let cloned_path = path.to_path_buf();
        assert_ok(
            dir.setup_database(&cloned_path),
            &format!("setup_database cloned {name}"),
        );
        assert_directory_exists(&cloned_path);
    }
}

#[test]
fn t43_vector_setup_database_can_create_all_targets_from_loop() {
    let temp = TempTree::new("t43");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    for (name, path) in all_directory_refs(&dir) {
        assert_ok(dir.setup_database(path), &format!("setup_database {name}"));
        assert_directory_exists(path);
    }

    assert_ok(dir.validate_directories(), "validate_directories");
}

#[test]
fn t44_vector_create_methods_work_in_reverse_order() {
    let temp = TempTree::new("t44");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_peerlist_directory(), "create peerlist");
    assert_ok(dir.create_audit_reports_directory(), "create audit reports");
    assert_ok(dir.create_log_directory(), "create log");
    assert_ok(dir.create_sidechain_directory(), "create sidechain");
    assert_ok(dir.create_accountmodel_directory(), "create accountmodel");
    assert_ok(dir.create_registry_directory(), "create registry");
    assert_ok(dir.create_blockchain_directory(), "create blockchain");
    assert_ok(dir.create_db_directory(), "create db");
    assert_ok(dir.create_wallets_directory(), "create wallets");

    assert_ok(dir.validate_directories(), "validate_directories");
}

#[test]
fn t45_vector_from_node_opts_preserves_relative_data_dir() {
    let data_dir = PathBuf::from("relative-node-data-for-directory-tests");
    let opts = make_node_opts(&data_dir);
    let dir = assert_ok(DirectoryDB::from_node_opts(&opts), "from_node_opts");

    assert_eq!(
        dir.wallets_path,
        data_dir.join(GlobalConfiguration::WALLETS_DIR)
    );
    assert_eq!(
        dir.blockchain_path,
        data_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
}

#[test]
fn t46_edge_from_node_opts_allows_empty_data_dir_without_creating_anything() {
    let opts = make_node_opts(Path::new(""));
    let dir = assert_ok(DirectoryDB::from_node_opts(&opts), "from_node_opts");

    assert_eq!(
        dir.wallets_path,
        PathBuf::from(GlobalConfiguration::WALLETS_DIR)
    );
    assert_eq!(
        dir.peerlist_path,
        PathBuf::from(GlobalConfiguration::PEER_LIST_DIR)
    );
}

#[test]
fn t47_edge_from_base_dir_with_spaces_and_unicode_preserves_path() {
    let temp = TempTree::new("t47");
    let base = temp.child("node data with spaces").join("unicode_δ_测试");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    assert_eq!(
        dir.log_path,
        base.join(GlobalConfiguration::LOG_DATABASE_DIR)
    );
    assert_eq!(
        dir.audit_reports_path,
        base.join(GlobalConfiguration::AUDIT_REPORTS_DIR)
    );
}

#[test]
fn t48_edge_from_node_opts_with_spaces_and_unicode_preserves_path() {
    let temp = TempTree::new("t48");
    let data_dir = temp.child("node data").join("validator_λ");
    let opts = make_node_opts(&data_dir);
    let dir = assert_ok(DirectoryDB::from_node_opts(&opts), "from_node_opts");

    assert_eq!(
        dir.accountmodel_path,
        data_dir.join(GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR)
    );
    assert_eq!(
        dir.sidechain_path,
        data_dir.join(GlobalConfiguration::SIDECHAIN_DATABASE_DIR)
    );
}

#[test]
fn t49_edge_from_base_dir_with_dot_component_keeps_joined_paths_under_base() {
    let temp = TempTree::new("t49");
    let base = temp.child(".").join("node");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    for (name, path) in all_directory_refs(&dir) {
        assert!(
            path.starts_with(&base),
            "{name} must stay under dotted base: {}",
            path.display()
        );
    }
}

#[test]
fn t50_edge_from_base_dir_with_nested_parent_components_is_lexically_preserved() {
    let temp = TempTree::new("t50");
    let base = temp.child("outer").join("..").join("inner");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    assert_eq!(
        dir.db_path,
        base.join(GlobalConfiguration::DATABASE_DIR_NAME)
    );
    assert_eq!(
        dir.registry_path,
        base.join(GlobalConfiguration::REGISTRY_DIR_NAME)
    );
}

#[test]
fn t51_edge_validate_reports_only_removed_directory_after_successful_setup() {
    let temp = TempTree::new("t51");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    assert_ok(fs::remove_dir_all(&dir.registry_path), "remove registry");

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories after removing registry",
    );

    assert!(err.contains("Missing directory"));
    assert!(err.contains(&dir.registry_path.display().to_string()));
    assert!(!err.contains(&format!(
        "Missing directory: {}",
        dir.wallets_path.display()
    )));
}

#[test]
fn t52_edge_validate_reports_multiple_removed_directories() {
    let temp = TempTree::new("t52");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    assert_ok(
        fs::remove_dir_all(&dir.blockchain_path),
        "remove blockchain",
    );
    assert_ok(fs::remove_dir_all(&dir.peerlist_path), "remove peerlist");

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories after removing two directories",
    );

    assert!(err.contains(&dir.blockchain_path.display().to_string()));
    assert!(err.contains(&dir.peerlist_path.display().to_string()));
}

#[test]
fn t53_edge_setup_database_rejects_base_root_itself() {
    let temp = TempTree::new("t53");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    let err = assert_err(
        dir.setup_database(temp.root()),
        "setup_database with base root",
    );

    assert!(err.contains("Invalid target for setup_database"));
    assert!(err.contains(&temp.root().display().to_string()));
}

#[test]
fn t54_edge_setup_database_rejects_parent_directory() {
    let temp = TempTree::new("t54");
    let base = temp.child("base");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");
    let parent = base
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| temp.root().to_path_buf());

    let err = assert_err(
        dir.setup_database(&parent),
        "setup_database with parent directory",
    );

    assert!(err.contains("Invalid target for setup_database"));
    assert!(err.contains(&parent.display().to_string()));
}

#[test]
fn t55_adversarial_setup_database_rejects_same_leaf_name_under_different_base() {
    let temp = TempTree::new("t55");
    let base_a = temp.child("node_a");
    let base_b = temp.child("node_b");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base_a), "from_base_dir");
    let spoofed_wallet_path = base_b.join(GlobalConfiguration::WALLETS_DIR);

    let err = assert_err(
        dir.setup_database(&spoofed_wallet_path),
        "setup_database spoofed same leaf",
    );

    assert!(err.contains("Invalid target for setup_database"));
    assert!(err.contains(&spoofed_wallet_path.display().to_string()));
}

#[test]
fn t56_adversarial_setup_database_rejects_child_inside_valid_target() {
    let temp = TempTree::new("t56");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let nested_inside_wallets = dir.wallets_path.join("nested");

    let err = assert_err(
        dir.setup_database(&nested_inside_wallets),
        "setup_database nested child",
    );

    assert!(err.contains("Invalid target for setup_database"));
    assert!(!nested_inside_wallets.exists());
}

#[test]
fn t57_adversarial_invalid_setup_target_does_not_create_directory() {
    let temp = TempTree::new("t57");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let invalid = temp.child("invalid-target");

    let _err = assert_err(
        dir.setup_database(&invalid),
        "setup_database invalid target",
    );

    assert!(
        !invalid.exists(),
        "invalid target must not be created: {}",
        invalid.display()
    );
}

#[test]
fn t58_property_create_only_one_directory_when_single_create_method_is_called() {
    let temp = TempTree::new("t58");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_db_directory(), "create db directory");

    assert_directory_exists(&dir.db_path);
    assert!(!dir.wallets_path.exists());
    assert!(!dir.blockchain_path.exists());
    assert!(!dir.registry_path.exists());
    assert!(!dir.accountmodel_path.exists());
    assert!(!dir.sidechain_path.exists());
    assert!(!dir.log_path.exists());
    assert!(!dir.audit_reports_path.exists());
    assert!(!dir.peerlist_path.exists());
}

#[test]
fn t59_property_setup_database_only_creates_requested_target() {
    let temp = TempTree::new("t59");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(
        dir.setup_database(&dir.audit_reports_path),
        "setup_database audit reports",
    );

    assert_directory_exists(&dir.audit_reports_path);
    assert!(!dir.wallets_path.exists());
    assert!(!dir.db_path.exists());
    assert!(!dir.blockchain_path.exists());
    assert!(!dir.registry_path.exists());
    assert!(!dir.accountmodel_path.exists());
    assert!(!dir.sidechain_path.exists());
    assert!(!dir.log_path.exists());
    assert!(!dir.peerlist_path.exists());
}

#[test]
fn t60_property_repeated_validate_after_success_is_stable() {
    let temp = TempTree::new("t60");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);

    for _ in 0..10 {
        assert_ok(dir.validate_directories(), "repeated validate_directories");
    }
}

#[test]
fn t61_property_repeated_setup_database_after_success_is_stable() {
    let temp = TempTree::new("t61");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    for _ in 0..10 {
        for (name, path) in all_directory_refs(&dir) {
            assert_ok(
                dir.setup_database(path),
                &format!("repeated setup_database {name}"),
            );
        }
    }

    assert_ok(dir.validate_directories(), "validate_directories");
}

#[test]
fn t62_property_from_base_dir_is_deterministic_for_same_base() {
    let temp = TempTree::new("t62");
    let base = temp.child("deterministic");
    let first = assert_ok(DirectoryDB::from_base_dir(&base), "first from_base_dir");
    let second = assert_ok(DirectoryDB::from_base_dir(&base), "second from_base_dir");

    assert_eq!(all_directory_paths(&first), all_directory_paths(&second));
}

#[test]
fn t63_property_from_base_dir_differs_for_different_bases() {
    let temp = TempTree::new("t63");
    let first = assert_ok(
        DirectoryDB::from_base_dir(&temp.child("node_1")),
        "first from_base_dir",
    );
    let second = assert_ok(
        DirectoryDB::from_base_dir(&temp.child("node_2")),
        "second from_base_dir",
    );

    for ((first_name, first_path), (second_name, second_path)) in all_directory_refs(&first)
        .into_iter()
        .zip(all_directory_refs(&second))
    {
        assert_eq!(first_name, second_name);
        assert_ne!(first_path, second_path);
    }
}

#[test]
fn t64_property_as_ref_tracks_cloned_db_path() {
    let temp = TempTree::new("t64");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let cloned = dir.clone();

    assert_eq!(cloned.as_ref(), cloned.db_path.as_path());
    assert_eq!(dir.as_ref(), cloned.as_ref());
}

#[test]
fn t65_property_error_message_for_invalid_target_contains_every_configured_path() {
    let temp = TempTree::new("t65");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let invalid = temp.child("not-one-of-the-nine");

    let err = assert_err(
        dir.setup_database(&invalid),
        "setup_database invalid target",
    );

    for (name, path) in all_directory_refs(&dir) {
        assert!(
            err.contains(name),
            "invalid target error missing field name {name}"
        );
        assert!(
            err.contains(&path.display().to_string()),
            "invalid target error missing path {}",
            path.display()
        );
    }
}

#[test]
fn t66_fuzz_property_generated_node_opts_map_to_expected_paths() {
    let temp = TempTree::new("t66");

    for seed in 0..96 {
        let generated = deterministic_name(seed);
        let data_dir = temp.child("opts").join(generated);
        let opts = make_node_opts(&data_dir);
        let dir = assert_ok(
            DirectoryDB::from_node_opts(&opts),
            "from_node_opts fuzz case",
        );

        assert_eq!(
            dir.wallets_path,
            data_dir.join(GlobalConfiguration::WALLETS_DIR)
        );
        assert_eq!(
            dir.db_path,
            data_dir.join(GlobalConfiguration::DATABASE_DIR_NAME)
        );
        assert_eq!(
            dir.peerlist_path,
            data_dir.join(GlobalConfiguration::PEER_LIST_DIR)
        );
    }
}

#[test]
fn t67_fuzz_property_generated_invalid_targets_are_rejected() {
    let temp = TempTree::new("t67");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    for seed in 0..64 {
        let generated = deterministic_name(seed);
        let invalid = temp.child("invalid").join(generated);
        let err = assert_err(
            dir.setup_database(&invalid),
            "setup_database fuzz invalid target",
        );

        assert!(err.contains("Invalid target for setup_database"));
        assert!(err.contains(&invalid.display().to_string()));
        assert!(!invalid.exists());
    }
}

#[test]
fn t68_fuzz_property_generated_valid_bases_create_and_validate() {
    let temp = TempTree::new("t68");

    for seed in 0..32 {
        let generated = deterministic_name(seed);
        let base = temp.child("valid").join(generated);
        let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir fuzz base");

        setup_all_directories(&dir);
        assert_ok(dir.validate_directories(), "validate fuzz base");
    }
}

#[test]
fn t69_adversarial_network_sim_separate_nodes_do_not_share_directory_paths() {
    let temp = TempTree::new("t69");
    let mut all_paths = BTreeSet::new();

    for node_id in 0..16 {
        let base = temp.child(&format!("node_{node_id}"));
        let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

        for (_name, path) in all_directory_refs(&dir) {
            assert!(
                all_paths.insert(path.to_path_buf()),
                "duplicate path found across simulated nodes: {}",
                path.display()
            );
        }
    }

    assert_eq!(all_paths.len(), 16 * GlobalConfiguration::TOTAL_DB_DIRS);
}

#[test]
fn t70_adversarial_network_sim_node_opts_separate_nodes_validate_independently() {
    let temp = TempTree::new("t70");

    for node_id in 0..12 {
        let data_dir = temp.child(&format!("node_opts_{node_id}"));
        let opts = make_node_opts(&data_dir);
        let dir = assert_ok(DirectoryDB::from_node_opts(&opts), "from_node_opts");

        setup_all_directories(&dir);
        assert_ok(
            dir.validate_directories(),
            "validate node opts directory set",
        );
    }
}

#[test]
fn t71_adversarial_network_sim_one_broken_node_does_not_break_other_node_paths() {
    let temp = TempTree::new("t71");
    let healthy = assert_ok(
        DirectoryDB::from_base_dir(&temp.child("healthy")),
        "healthy from_base_dir",
    );
    let broken = assert_ok(
        DirectoryDB::from_base_dir(&temp.child("broken")),
        "broken from_base_dir",
    );

    setup_all_directories(&healthy);
    setup_all_directories(&broken);
    assert_ok(
        fs::remove_dir_all(&broken.peerlist_path),
        "remove broken peerlist",
    );

    assert_ok(healthy.validate_directories(), "healthy validate");
    let err = assert_err(broken.validate_directories(), "broken validate");

    assert!(err.contains(&broken.peerlist_path.display().to_string()));
    assert!(!err.contains(&healthy.peerlist_path.display().to_string()));
}

#[test]
fn t72_load_create_validate_64_directory_sets_sequentially() {
    let temp = TempTree::new("t72");

    for index in 0..64 {
        let base = temp.child(&format!("load_node_{index:02}"));
        let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir load");
        setup_all_directories(&dir);
        assert_ok(dir.validate_directories(), "validate load node");
    }
}

#[test]
fn t73_load_setup_database_uses_all_targets_for_32_nodes() {
    let temp = TempTree::new("t73");

    for node_id in 0..32 {
        let base = temp.child(&format!("setup_node_{node_id:02}"));
        let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir load");

        for (name, path) in all_directory_refs(&dir) {
            assert_ok(dir.setup_database(path), &format!("setup target {name}"));
        }

        assert_ok(dir.validate_directories(), "validate setup load node");
    }
}

#[test]
fn t74_load_clone_512_directory_structs_without_path_mutation() {
    let temp = TempTree::new("t74");
    let original = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");
    let original_paths = all_directory_paths(&original);

    let clones: Vec<DirectoryDB> = (0..512).map(|_| original.clone()).collect();

    for cloned in clones {
        assert_eq!(all_directory_paths(&cloned), original_paths);
    }
}

#[test]
fn t75_load_many_base_constructions_are_unique_and_under_temp_root() {
    let temp = TempTree::new("t75");
    let mut seen = BTreeSet::new();

    for index in 0..128 {
        let base = temp.child(&format!("base_{index:03}"));
        let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir load");

        for (name, path) in all_directory_refs(&dir) {
            assert!(
                path.starts_with(temp.root()),
                "{name} escaped temp root: {}",
                path.display()
            );
            assert!(
                seen.insert(path.to_path_buf()),
                "duplicate generated path: {}",
                path.display()
            );
        }
    }

    assert_eq!(seen.len(), 128 * GlobalConfiguration::TOTAL_DB_DIRS);
}

#[test]
fn t76_load_parallel_from_base_dir_path_construction_is_deterministic() {
    let temp = TempTree::new("t76");
    let mut handles = Vec::new();

    for node_id in 0..48usize {
        let base = temp.child(&format!("parallel_construct_{node_id:02}"));
        handles.push(thread::spawn(move || -> Result<Vec<PathBuf>, String> {
            let dir = DirectoryDB::from_base_dir(&base)?;
            Ok(all_directory_paths(&dir))
        }));
    }

    for handle in handles {
        let paths = match handle.join() {
            Ok(Ok(paths)) => paths,
            Ok(Err(err)) => panic!("worker returned error: {err}"),
            Err(_) => panic!("worker panicked"),
        };

        assert_eq!(paths.len(), GlobalConfiguration::TOTAL_DB_DIRS);
    }
}

#[test]
fn t77_load_parallel_create_only_peerlist_for_many_nodes() {
    let temp = TempTree::new("t77");
    let mut handles = Vec::new();

    for node_id in 0..40usize {
        let base = temp.child(&format!("peerlist_node_{node_id:02}"));
        handles.push(thread::spawn(move || -> Result<PathBuf, String> {
            let dir = DirectoryDB::from_base_dir(&base)?;
            dir.create_peerlist_directory()?;
            Ok(dir.peerlist_path)
        }));
    }

    for handle in handles {
        let path = match handle.join() {
            Ok(Ok(path)) => path,
            Ok(Err(err)) => panic!("worker returned error: {err}"),
            Err(_) => panic!("worker panicked"),
        };

        assert_directory_exists(&path);
    }
}

#[test]
fn t78_load_parallel_setup_all_for_many_nodes() {
    let temp = TempTree::new("t78");
    let mut handles = Vec::new();

    for node_id in 0..24usize {
        let base = temp.child(&format!("parallel_full_{node_id:02}"));
        handles.push(thread::spawn(move || -> Result<(), String> {
            let dir = DirectoryDB::from_base_dir(&base)?;

            for (_name, path) in all_directory_refs(&dir) {
                dir.setup_database(path)?;
            }

            dir.validate_directories()
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("worker returned error: {err}"),
            Err(_) => panic!("worker panicked"),
        }
    }
}

#[test]
fn t79_adversarial_validate_detects_symlink_even_after_other_directories_are_valid() {
    let temp = TempTree::new("t79");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    assert_ok(
        fs::remove_dir_all(&dir.audit_reports_path),
        "remove audit reports directory",
    );

    let real_target = temp.child("real_audit_reports_target");
    assert_ok(
        fs::create_dir_all(&real_target),
        "create real symlink target",
    );

    match create_dir_symlink(&real_target, &dir.audit_reports_path) {
        Ok(()) => {
            let err = assert_err(
                dir.validate_directories(),
                "validate_directories with audit reports symlink",
            );

            assert!(err.contains("Symlink detected"));
            assert!(err.contains(&dir.audit_reports_path.display().to_string()));
        }
        Err(err) if is_windows_symlink_privilege_error(&err) => {
            assert!(
                !dir.audit_reports_path.exists(),
                "audit reports symlink path should not exist after Windows refused symlink creation"
            );
            assert!(
                real_target.is_dir(),
                "real symlink target should still exist after Windows refused symlink creation"
            );

            assert_ok(
                dir.create_audit_reports_directory(),
                "recreate audit reports directory after Windows refused symlink creation",
            );
            assert_ok(
                dir.validate_directories(),
                "validate directories after recreating real audit reports directory",
            );
        }
        Err(err) => {
            panic!("create audit reports symlink failed unexpectedly: {err}");
        }
    }
}

#[test]
fn t80_adversarial_load_parallel_invalid_targets_are_all_rejected() {
    let temp = TempTree::new("t80");
    let mut handles = Vec::new();

    for node_id in 0..32usize {
        let base = temp.child(&format!("invalid_parallel_{node_id:02}"));
        handles.push(thread::spawn(move || -> Result<(), String> {
            let dir = DirectoryDB::from_base_dir(&base)?;
            let invalid = base.join("not-a-configured-target");
            let err = dir
                .setup_database(&invalid)
                .expect_err("invalid setup target must be rejected");

            if !err.contains("Invalid target for setup_database") {
                return Err(format!("unexpected invalid target error: {err}"));
            }

            if invalid.exists() {
                return Err(format!(
                    "invalid target was unexpectedly created: {}",
                    invalid.display()
                ));
            }

            Ok(())
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("worker returned error: {err}"),
            Err(_) => panic!("worker panicked"),
        }
    }
}

#[test]
fn t81_vector_every_configured_path_has_base_as_direct_parent() {
    let temp = TempTree::new("t81");
    let base = temp.child("base");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    for (name, path) in all_directory_refs(&dir) {
        assert_eq!(
            path.parent(),
            Some(base.as_path()),
            "{name} should have base as direct parent"
        );
    }
}

#[test]
fn t82_vector_configured_leaf_name_set_matches_global_configuration() {
    let temp = TempTree::new("t82");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    let actual: BTreeSet<String> = all_directory_refs(&dir)
        .iter()
        .map(|(_, path)| {
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .to_owned()
        })
        .collect();

    let expected: BTreeSet<String> = [
        GlobalConfiguration::WALLETS_DIR,
        GlobalConfiguration::DATABASE_DIR_NAME,
        GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR,
        GlobalConfiguration::REGISTRY_DIR_NAME,
        GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR,
        GlobalConfiguration::SIDECHAIN_DATABASE_DIR,
        GlobalConfiguration::LOG_DATABASE_DIR,
        GlobalConfiguration::AUDIT_REPORTS_DIR,
        GlobalConfiguration::PEER_LIST_DIR,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    assert_eq!(actual, expected);
}

#[test]
fn t83_vector_all_leaf_names_are_non_empty() {
    let temp = TempTree::new("t83");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    for (name, path) in all_directory_refs(&dir) {
        let leaf = path.file_name().and_then(|value| value.to_str());
        assert!(leaf.is_some(), "{name} must have a valid UTF-8 leaf name");
        assert_ne!(
            leaf.unwrap_or_default(),
            "",
            "{name} leaf must not be empty"
        );
    }
}

#[test]
fn t84_edge_create_directory_fails_when_base_path_is_regular_file() {
    let temp = TempTree::new("t84");
    let base_file = temp.child("base_is_file");

    assert_ok(fs::write(&base_file, b"not a directory"), "write base file");

    let dir = assert_ok(DirectoryDB::from_base_dir(&base_file), "from_base_dir");
    let err = assert_err(
        dir.create_db_directory(),
        "create_db_directory with file base",
    );

    assert!(err.contains("Failed to create directory"));
    assert!(err.contains(&dir.db_path.display().to_string()));
    assert!(!dir.db_path.exists());
}

#[test]
fn t85_edge_setup_database_fails_when_valid_target_parent_is_regular_file() {
    let temp = TempTree::new("t85");
    let base_file = temp.child("base_file_for_setup");

    assert_ok(fs::write(&base_file, b"not a directory"), "write base file");

    let dir = assert_ok(DirectoryDB::from_base_dir(&base_file), "from_base_dir");
    let err = assert_err(
        dir.setup_database(&dir.wallets_path),
        "setup_database with file parent",
    );

    assert!(err.contains("Failed to create directory"));
    assert!(err.contains(&dir.wallets_path.display().to_string()));
    assert!(!dir.wallets_path.exists());
}

#[test]
fn t86_edge_validate_reports_missing_paths_when_base_path_is_regular_file() {
    let temp = TempTree::new("t86");
    let base_file = temp.child("base_file_for_validate");

    assert_ok(fs::write(&base_file, b"not a directory"), "write base file");

    let dir = assert_ok(DirectoryDB::from_base_dir(&base_file), "from_base_dir");
    let err = assert_err(
        dir.validate_directories(),
        "validate_directories with file base",
    );

    assert!(err.contains("Missing directory"));
    assert!(err.contains("Failed to check metadata"));
    assert!(err.contains(&dir.blockchain_path.display().to_string()));
}

#[test]
fn t87_edge_create_directory_rejects_readonly_file_at_target_path() {
    let temp = TempTree::new("t87");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(fs::write(&dir.log_path, b"log file"), "write target file");
    set_readonly(&dir.log_path, true);

    let err = assert_err(
        dir.create_log_directory(),
        "create_log_directory with readonly file target",
    );

    set_readonly(&dir.log_path, false);

    assert!(err.contains("No write permissions"));
    assert!(err.contains(&dir.log_path.display().to_string()));
}

#[test]
fn t88_edge_validate_reports_permission_error_for_readonly_file_at_configured_path() {
    let temp = TempTree::new("t88");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    assert_ok(
        fs::remove_dir_all(&dir.accountmodel_path),
        "remove accountmodel directory",
    );
    assert_ok(
        fs::write(&dir.accountmodel_path, b"readonly file"),
        "write readonly file at accountmodel path",
    );
    set_readonly(&dir.accountmodel_path, true);

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories with readonly file target",
    );

    set_readonly(&dir.accountmodel_path, false);

    assert!(err.contains("Permission error"));
    assert!(err.contains("No write permissions"));
    assert!(err.contains(&dir.accountmodel_path.display().to_string()));
}

#[test]
fn t89_edge_from_base_dir_does_not_create_missing_base_or_children() {
    let temp = TempTree::new("t89");
    let base = temp.child("missing").join("nested").join("base");

    assert!(!base.exists());

    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    assert!(!base.exists());
    for (name, path) in all_directory_refs(&dir) {
        assert!(
            !path.exists(),
            "{name} should not be created by from_base_dir alone"
        );
    }
}

#[test]
fn t90_edge_create_peerlist_directory_creates_missing_base_parents() {
    let temp = TempTree::new("t90");
    let base = temp.child("missing_parent").join("node").join("data");
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    assert!(!base.exists());

    assert_ok(
        dir.create_peerlist_directory(),
        "create_peerlist_directory with missing parents",
    );

    assert_directory_exists(&base);
    assert_directory_exists(&dir.peerlist_path);
}

#[test]
fn t91_edge_base_path_with_trailing_separator_is_preserved_by_join_logic() {
    let temp = TempTree::new("t91");
    let base_string = format!("{}/", temp.child("trailing_separator").display());
    let base = PathBuf::from(base_string);
    let dir = assert_ok(DirectoryDB::from_base_dir(&base), "from_base_dir");

    assert_eq!(
        dir.db_path,
        base.join(GlobalConfiguration::DATABASE_DIR_NAME)
    );
    assert_eq!(
        dir.blockchain_path,
        base.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );
}

#[test]
fn t92_vector_from_node_opts_ignores_non_directory_runtime_fields() {
    let temp = TempTree::new("t92");
    let data_dir = temp.child("same_data_dir");

    let mut first = make_node_opts(&data_dir);
    first.identity_file = "first_identity.key".to_owned();
    first.listen = "/ip4/127.0.0.1/tcp/11111".to_owned();
    first.bootstrap = vec!["/ip4/127.0.0.1/tcp/22222".to_owned()];
    first.log = "debug".to_owned();
    first.wallet_address = "wallet_a".to_owned();
    first.founder = false;

    let mut second = make_node_opts(&data_dir);
    second.identity_file = "second_identity.key".to_owned();
    second.listen = "/ip4/0.0.0.0/tcp/33333".to_owned();
    second.bootstrap = vec!["invalid-bootstrap".to_owned()];
    second.log = "trace".to_owned();
    second.wallet_address = "wallet_b".to_owned();
    second.founder = true;

    let first_dir = assert_ok(DirectoryDB::from_node_opts(&first), "first from_node_opts");
    let second_dir = assert_ok(
        DirectoryDB::from_node_opts(&second),
        "second from_node_opts",
    );

    assert_eq!(
        all_directory_paths(&first_dir),
        all_directory_paths(&second_dir)
    );
}

#[test]
fn t93_vector_from_node_opts_different_data_dirs_create_different_directory_sets() {
    let temp = TempTree::new("t93");

    let first_opts = make_node_opts(&temp.child("node_a"));
    let second_opts = make_node_opts(&temp.child("node_b"));

    let first_dir = assert_ok(
        DirectoryDB::from_node_opts(&first_opts),
        "first from_node_opts",
    );
    let second_dir = assert_ok(
        DirectoryDB::from_node_opts(&second_opts),
        "second from_node_opts",
    );

    for ((first_name, first_path), (second_name, second_path)) in all_directory_refs(&first_dir)
        .into_iter()
        .zip(all_directory_refs(&second_dir))
    {
        assert_eq!(first_name, second_name);
        assert_ne!(first_path, second_path);
    }
}

#[test]
fn t94_vector_displayed_paths_contain_their_configured_leaf_names() {
    let temp = TempTree::new("t94");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    for (name, path) in all_directory_refs(&dir) {
        let leaf = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();

        assert!(
            path.display().to_string().contains(leaf),
            "{name} display should contain leaf name"
        );
    }
}

#[test]
fn t95_vector_setup_database_returns_ok_for_each_exact_configured_target_after_creation() {
    let temp = TempTree::new("t95");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);

    for (name, path) in all_directory_refs(&dir) {
        assert_ok(
            dir.setup_database(path),
            &format!("setup_database exact configured target {name}"),
        );
        assert_directory_exists(path);
    }
}

#[test]
fn t96_edge_base_data_dir_honors_empty_env_override_as_empty_path() {
    with_remzar_data_dir(Path::new(""), || {
        let actual = assert_ok(DirectoryDB::base_data_dir(), "base_data_dir");
        assert_eq!(actual, PathBuf::from(""));
    });
}

#[test]
fn t97_edge_base_data_dir_honors_unicode_env_override() {
    let temp = TempTree::new("t97");
    let override_dir = temp.child("env_unicode_λ_测试");

    with_remzar_data_dir(&override_dir, || {
        let actual = assert_ok(DirectoryDB::base_data_dir(), "base_data_dir");
        assert_eq!(actual, override_dir);
    });
}

#[test]
fn t98_edge_validate_fails_after_directory_removal_then_passes_after_recreate() {
    let temp = TempTree::new("t98");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);
    assert_ok(
        fs::remove_dir_all(&dir.sidechain_path),
        "remove sidechain directory",
    );

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories after sidechain removal",
    );

    assert!(err.contains(&dir.sidechain_path.display().to_string()));

    assert_ok(
        dir.create_sidechain_directory(),
        "recreate sidechain directory",
    );
    assert_ok(
        dir.validate_directories(),
        "validate_directories after recreate",
    );
}

#[test]
fn t99_edge_validate_error_for_multiple_missing_directories_is_newline_joined() {
    let temp = TempTree::new("t99");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    assert_ok(dir.create_wallets_directory(), "create wallets only");

    let err = assert_err(
        dir.validate_directories(),
        "validate_directories with multiple missing directories",
    );

    assert!(
        err.contains('\n'),
        "multiple validation errors should be joined by newlines"
    );
    assert!(err.contains(&dir.db_path.display().to_string()));
    assert!(err.contains(&dir.peerlist_path.display().to_string()));
}

#[test]
fn t100_vector_created_root_entries_match_configured_directory_leaf_set() {
    let temp = TempTree::new("t100");
    let dir = assert_ok(DirectoryDB::from_base_dir(temp.root()), "from_base_dir");

    setup_all_directories(&dir);

    let actual: BTreeSet<String> = assert_ok(fs::read_dir(temp.root()), "read temp root")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();

    let expected: BTreeSet<String> = [
        GlobalConfiguration::WALLETS_DIR,
        GlobalConfiguration::DATABASE_DIR_NAME,
        GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR,
        GlobalConfiguration::REGISTRY_DIR_NAME,
        GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR,
        GlobalConfiguration::SIDECHAIN_DATABASE_DIR,
        GlobalConfiguration::LOG_DATABASE_DIR,
        GlobalConfiguration::AUDIT_REPORTS_DIR,
        GlobalConfiguration::PEER_LIST_DIR,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    assert_eq!(actual, expected);
}
