use remzar::commandline::s_01_setup_database::S01SetupDatabase;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::logging_data::JsonLogger;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_01_setup_database_tests_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            make_writable_recursive(&root);
            if fs::remove_dir_all(&root).is_err() {}
        }

        match fs::create_dir_all(&root) {
            Ok(()) => Self { root },
            Err(err) => panic!("failed to create temp root '{}': {err}", root.display()),
        }
    }

    fn child(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        make_writable_recursive(&self.root);
        if fs::remove_dir_all(&self.root).is_err() {}
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

fn make_node_opts_custom(
    data_dir: &Path,
    identity_file: &str,
    listen: &str,
    bootstrap: Vec<String>,
    log: &str,
    founder: bool,
) -> NodeOpts {
    NodeOpts {
        identity_file: identity_file.to_owned(),
        listen: listen.to_owned(),
        bootstrap,
        log: log.to_owned(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder,
    }
}

fn directory_from_opts(opts: &NodeOpts) -> DirectoryDB {
    assert_ok(
        DirectoryDB::from_node_opts(opts),
        "DirectoryDB::from_node_opts",
    )
}

fn make_logger(opts: &NodeOpts) -> JsonLogger {
    let directory = directory_from_opts(opts);
    assert_ok(directory.create_log_directory(), "create_log_directory");
    assert_ok(JsonLogger::new(&directory), "JsonLogger::new")
}

fn seed_initialized(opts: &NodeOpts) {
    let manager = assert_ok(RockDBManager::new(opts), "RockDBManager::new");
    assert_ok(
        manager.store_metadata("status", b"initialized"),
        "store initialized status",
    );
}

fn read_status(opts: &NodeOpts) -> Option<Vec<u8>> {
    let manager = assert_ok(RockDBManager::new(opts), "RockDBManager::new for read");
    assert_ok(manager.get_metadata("status"), "get status metadata")
}

fn assert_status_is_initialized(opts: &NodeOpts) {
    match read_status(opts) {
        Some(bytes) => assert_eq!(bytes.as_slice(), b"initialized"),
        None => panic!("status metadata was missing"),
    }
}

fn run_initialized_setup(opts: &NodeOpts) {
    seed_initialized(opts);

    {
        let logger = make_logger(opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(opts, &logger),
            "S01SetupDatabase::setup_database",
        );
        assert_ok(logger.flush_logs_cf(), "flush_logs_cf after setup");
    }

    assert_status_is_initialized(opts);
}

fn create_cli_lock(opts: &NodeOpts, contents: &[u8]) -> PathBuf {
    let directory = directory_from_opts(opts);
    assert_ok(
        directory.setup_database(&directory.db_path),
        "setup cli database directory",
    );
    let lock_path = directory.db_path.join("LOCK");
    assert_ok(fs::write(&lock_path, contents), "write CLI LOCK file");
    lock_path
}

fn run_setup_with_existing_stale_lock(opts: &NodeOpts, contents: &[u8]) -> PathBuf {
    seed_status_value(opts, b"initialized");
    let lock_path = create_cli_lock(opts, contents);

    {
        let logger = make_logger(opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(opts, &logger),
            "setup with existing stale LOCK file",
        );
        assert_ok(
            logger.flush_logs_cf(),
            "flush logs cf after stale lock setup",
        );
    }

    assert_status_is_initialized(opts);
    lock_path
}

fn generated_suffix(seed: usize) -> String {
    let mut value = seed;
    let mut output = format!("case_{seed}_");

    for _ in 0..8 {
        value = value.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let digit = value % 10;
        output.push_str(&digit.to_string());
    }

    output
}

fn seed_status_value(opts: &NodeOpts, value: &[u8]) {
    let manager = assert_ok(
        RockDBManager::new(opts),
        "RockDBManager::new for seed_status_value",
    );
    assert_ok(
        manager.store_metadata("status", value),
        "store custom status value",
    );
}

fn seed_metadata_value(opts: &NodeOpts, key: &str, value: &[u8]) {
    let manager = assert_ok(
        RockDBManager::new(opts),
        "RockDBManager::new for seed_metadata_value",
    );
    assert_ok(manager.store_metadata(key, value), "store metadata value");
}

fn assert_metadata_equals(opts: &NodeOpts, key: &str, expected: &[u8]) {
    let manager = assert_ok(
        RockDBManager::new(opts),
        "RockDBManager::new for assert_metadata_equals",
    );
    let actual = assert_ok(manager.get_metadata(key), "get metadata value");

    match actual {
        Some(bytes) => assert_eq!(bytes.as_slice(), expected),
        None => panic!("metadata key '{key}' was missing"),
    }
}

fn assert_metadata_missing(opts: &NodeOpts, key: &str) {
    let manager = assert_ok(
        RockDBManager::new(opts),
        "RockDBManager::new for assert_metadata_missing",
    );
    let actual = assert_ok(manager.get_metadata(key), "get metadata value");

    match actual {
        Some(bytes) => panic!("metadata key '{key}' unexpectedly existed with {bytes:?}"),
        None => {}
    }
}

fn deterministic_value(seed: usize, repeat: usize) -> Vec<u8> {
    let mut bytes = Vec::new();

    for index in 0..repeat {
        let token = format!("{seed}:{index};");
        bytes.extend_from_slice(token.as_bytes());
    }

    bytes
}

fn run_setup_once_with_seeded_initialized_status(opts: &NodeOpts) {
    seed_status_value(opts, b"initialized");

    {
        let logger = make_logger(opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(opts, &logger),
            "setup once with seeded initialized status",
        );
        assert_ok(logger.flush_logs_cf(), "flush logs cf");
    }

    assert_status_is_initialized(opts);
}

#[test]
fn test_01_new_constructor_runs_initialized_setup() {
    let temp = TempTree::new("test_01");
    let opts = make_node_opts(&temp.child("node"));
    let mut section = S01SetupDatabase::new();

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup with new constructor",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_02_default_constructor_runs_initialized_setup() {
    let temp = TempTree::new("test_02");
    let opts = make_node_opts(&temp.child("node"));
    let mut section = S01SetupDatabase;

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup with default constructor",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_03_initialized_status_returns_ok() {
    let temp = TempTree::new("test_03");
    let opts = make_node_opts(&temp.child("node"));

    run_initialized_setup(&opts);
}

#[test]
fn test_04_initialized_status_is_preserved() {
    let temp = TempTree::new("test_04");
    let opts = make_node_opts(&temp.child("node"));

    run_initialized_setup(&opts);
    assert_status_is_initialized(&opts);
}

#[test]
fn test_05_initialized_status_is_idempotent_across_two_runs() {
    let temp = TempTree::new("test_05");
    let opts = make_node_opts(&temp.child("node"));

    run_initialized_setup(&opts);
    run_initialized_setup(&opts);
    assert_status_is_initialized(&opts);
}

#[test]
fn test_06_initialized_status_is_idempotent_across_five_runs() {
    let temp = TempTree::new("test_06");
    let opts = make_node_opts(&temp.child("node"));

    for _ in 0..5 {
        run_initialized_setup(&opts);
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_07_initialized_status_survives_manager_reopen() {
    let temp = TempTree::new("test_07");
    let opts = make_node_opts(&temp.child("node"));

    run_initialized_setup(&opts);

    let reopened = read_status(&opts);
    match reopened {
        Some(bytes) => assert_eq!(bytes.as_slice(), b"initialized"),
        None => panic!("reopened manager did not find initialized status"),
    }
}

#[test]
fn test_08_nested_data_dir_runs_initialized_setup() {
    let temp = TempTree::new("test_08");
    let opts = make_node_opts(&temp.child("a").join("b").join("c").as_path().to_path_buf());

    run_initialized_setup(&opts);
}

#[test]
fn test_09_data_dir_with_spaces_runs_initialized_setup() {
    let temp = TempTree::new("test_09");
    let opts = make_node_opts(&temp.child("node with spaces"));

    run_initialized_setup(&opts);
}

#[test]
fn test_10_data_dir_with_unicode_runs_initialized_setup() {
    let temp = TempTree::new("test_10");
    let opts = make_node_opts(&temp.child("node_測試_данные"));

    run_initialized_setup(&opts);
}

#[test]
fn test_11_custom_identity_file_does_not_break_initialized_setup() {
    let temp = TempTree::new("test_11");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "custom_identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "info",
        false,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_12_custom_listen_address_does_not_break_initialized_setup() {
    let temp = TempTree::new("test_12");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/0.0.0.0/tcp/46321",
        Vec::new(),
        "info",
        false,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_13_custom_log_level_does_not_break_initialized_setup() {
    let temp = TempTree::new("test_13");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "debug",
        false,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_14_founder_true_does_not_break_initialized_setup() {
    let temp = TempTree::new("test_14");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "info",
        true,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_15_single_bootstrap_is_ignored_when_database_already_initialized() {
    let temp = TempTree::new("test_15");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        vec!["/ip4/127.0.0.1/tcp/36214".to_owned()],
        "info",
        false,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_16_many_bootstraps_are_ignored_when_database_already_initialized() {
    let temp = TempTree::new("test_16");
    let mut bootstrap = Vec::new();

    for port in ["36214", "36215", "36216", "36217", "36218"] {
        bootstrap.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        bootstrap,
        "info",
        false,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_17_malformed_bootstrap_is_ignored_when_database_already_initialized() {
    let temp = TempTree::new("test_17");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        vec!["not-a-valid-multiaddr".to_owned()],
        "info",
        false,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_18_long_bootstrap_is_ignored_when_database_already_initialized() {
    let temp = TempTree::new("test_18");
    let long_bootstrap = format!("/ip4/127.0.0.1/tcp/36213/{}", "x".repeat(256));
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        vec![long_bootstrap],
        "info",
        false,
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_19_stale_lock_file_does_not_block_initialized_setup() {
    let temp = TempTree::new("test_19");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, b"locked");

    assert!(lock_path.exists(), "stale LOCK file should still exist");
}

#[test]
fn test_20_stale_lock_file_is_not_treated_as_rocksdb_in_use() {
    let temp = TempTree::new("test_20");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, b"locked");

    assert!(lock_path.exists(), "stale LOCK file should not block setup");
}

#[test]
fn test_21_stale_lock_file_is_preserved_after_successful_setup() {
    let temp = TempTree::new("test_21");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, b"keep-me");

    assert!(
        lock_path.exists(),
        "LOCK file should remain under RocksDB ownership"
    );
}

#[test]
fn test_22_stale_lock_file_contents_do_not_block_initialized_setup() {
    let temp = TempTree::new("test_22");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, b"preserve-lock-bytes");

    assert!(lock_path.exists(), "LOCK file should remain after setup");
}

#[test]
fn test_23_logger_flush_logs_cf_after_stale_lock_setup_succeeds() {
    let temp = TempTree::new("test_23");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    let lock_path = create_cli_lock(&opts, b"locked");

    let logger = make_logger(&opts);
    let mut section = S01SetupDatabase::new();
    assert_ok(
        section.setup_database(&opts, &logger),
        "setup with stale lock should succeed",
    );
    assert_ok(logger.flush_logs_cf(), "flush log column family");
    assert!(lock_path.exists(), "stale LOCK file should still exist");
}

#[test]
fn test_24_logger_flush_after_stale_lock_setup_succeeds() {
    let temp = TempTree::new("test_24");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    let lock_path = create_cli_lock(&opts, b"locked");

    let logger = make_logger(&opts);
    let mut section = S01SetupDatabase::new();
    assert_ok(
        section.setup_database(&opts, &logger),
        "setup with stale lock should succeed",
    );
    assert_ok(logger.flush(), "flush logger DB");
    assert!(lock_path.exists(), "stale LOCK file should still exist");
}

#[test]
fn test_25_log_error_event_before_setup_does_not_break_initialized_setup() {
    let temp = TempTree::new("test_25");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        assert_ok(
            logger.log_error_event("test", "BeforeSetup", "pre-flight log"),
            "pre setup log_error_event",
        );

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after pre-flight log",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_26_log_error_event_after_setup_succeeds() {
    let temp = TempTree::new("test_26");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();

        assert_ok(section.setup_database(&opts, &logger), "setup");
        assert_ok(
            logger.log_error_event("test", "AfterSetup", "post-flight log"),
            "post setup log_error_event",
        );
        assert_ok(logger.flush_logs_cf(), "flush logs after post-flight log");
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_27_vector_multiple_data_roots_initialize_independently() {
    let temp = TempTree::new("test_27");

    for name in ["alpha", "bravo", "charlie", "delta"] {
        let opts = make_node_opts(&temp.child(name));
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_28_vector_multiple_identity_names_initialize_independently() {
    let temp = TempTree::new("test_28");

    for identity_file in ["a.key", "b.key", "validator.key", "node_identity.key"] {
        let opts = make_node_opts_custom(
            &temp.child(identity_file),
            identity_file,
            "/ip4/127.0.0.1/tcp/36213",
            Vec::new(),
            "info",
            false,
        );
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_29_property_repeated_same_opts_keeps_single_initialized_state() {
    let temp = TempTree::new("test_29");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    for _ in 0..10 {
        {
            let logger = make_logger(&opts);
            let mut section = S01SetupDatabase::new();
            assert_ok(section.setup_database(&opts, &logger), "repeat setup");
        }

        assert_status_is_initialized(&opts);
    }
}

#[test]
fn test_30_property_two_nodes_do_not_cross_contaminate_status() {
    let temp = TempTree::new("test_30");
    let opts_a = make_node_opts(&temp.child("node_a"));
    let opts_b = make_node_opts(&temp.child("node_b"));

    run_initialized_setup(&opts_a);
    run_initialized_setup(&opts_b);

    assert_status_is_initialized(&opts_a);
    assert_status_is_initialized(&opts_b);
}

#[test]
fn test_31_property_four_nodes_do_not_cross_contaminate_status() {
    let temp = TempTree::new("test_31");
    let opts = [
        make_node_opts(&temp.child("node_a")),
        make_node_opts(&temp.child("node_b")),
        make_node_opts(&temp.child("node_c")),
        make_node_opts(&temp.child("node_d")),
    ];

    for opt in &opts {
        run_initialized_setup(opt);
    }

    for opt in &opts {
        assert_status_is_initialized(opt);
    }
}

#[test]
fn test_32_fuzz_deterministic_data_dir_names_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_32");

    for seed in 0..10 {
        let suffix = generated_suffix(seed);
        let opts = make_node_opts(&temp.child(&suffix));
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_33_fuzz_bootstrap_patterns_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_33");

    for seed in 0..16 {
        let bootstrap = vec![
            generated_suffix(seed),
            format!("/ip4/127.0.0.1/tcp/{}", 30_000usize.wrapping_add(seed)),
        ];
        let opts = make_node_opts_custom(
            &temp.child(&generated_suffix(seed.wrapping_add(100))),
            "identity.key",
            "/ip4/127.0.0.1/tcp/36213",
            bootstrap,
            "info",
            false,
        );
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_34_fuzz_identity_file_names_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_34");

    for seed in 0..12 {
        let identity = format!("identity_{}.key", generated_suffix(seed));
        let opts = make_node_opts_custom(
            &temp.child(&generated_suffix(seed.wrapping_add(200))),
            &identity,
            "/ip4/127.0.0.1/tcp/36213",
            Vec::new(),
            "info",
            false,
        );
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_35_fuzz_log_level_strings_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_35");

    for log in [
        "trace",
        "debug",
        "info",
        "warn",
        "error",
        "custom-log-level",
    ] {
        let opts = make_node_opts_custom(
            &temp.child(log),
            "identity.key",
            "/ip4/127.0.0.1/tcp/36213",
            Vec::new(),
            log,
            false,
        );
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_36_adversarial_parallel_unique_nodes_initialize_successfully() {
    let mut handles = Vec::new();

    for node_id in 0..4 {
        handles.push(thread::spawn(move || {
            let temp = TempTree::new(&format!("test_36_{node_id}"));
            let opts = make_node_opts(&temp.child("node"));
            run_initialized_setup(&opts);
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("parallel initialized setup worker panicked"),
        }
    }
}

#[test]
fn test_37_adversarial_parallel_malformed_bootstraps_do_not_break_initialized_setup() {
    let mut handles = Vec::new();

    for node_id in 0..4 {
        handles.push(thread::spawn(move || {
            let temp = TempTree::new(&format!("test_37_{node_id}"));
            let bootstrap = vec![
                "bad-bootstrap".to_owned(),
                format!("not/a/multiaddr/{node_id}"),
            ];
            let opts = make_node_opts_custom(
                &temp.child("node"),
                "identity.key",
                "/ip4/127.0.0.1/tcp/36213",
                bootstrap,
                "info",
                false,
            );
            run_initialized_setup(&opts);
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("parallel adversarial bootstrap worker panicked"),
        }
    }
}

#[test]
fn test_38_adversarial_stale_lock_file_does_not_override_initialized_status() {
    let temp = TempTree::new("test_38");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);
    let lock_path = create_cli_lock(&opts, b"locked-after-initialized");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "stale lock after initialized status should not block setup",
        );
    }

    assert!(lock_path.exists(), "stale LOCK file should still exist");
    assert_status_is_initialized(&opts);
}

#[test]
fn test_39_load_twenty_unique_initialized_nodes() {
    let temp = TempTree::new("test_39");

    for seed in 0..20 {
        let opts = make_node_opts(&temp.child(&format!("load_node_{seed}")));
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_40_load_twenty_five_repeated_initialized_runs_same_node() {
    let temp = TempTree::new("test_40");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    for _ in 0..25 {
        {
            let logger = make_logger(&opts);
            let mut section = S01SetupDatabase::new();
            assert_ok(
                section.setup_database(&opts, &logger),
                "load repeated initialized setup",
            );
            assert_ok(logger.flush_logs_cf(), "load flush logs cf");
        }

        assert_status_is_initialized(&opts);
    }
}

#[test]
fn test_41_new_instances_can_run_against_same_initialized_database() {
    let temp = TempTree::new("test_41");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        let mut first = S01SetupDatabase::new();
        assert_ok(first.setup_database(&opts, &logger), "first setup instance");

        let mut second = S01SetupDatabase::new();
        assert_ok(
            second.setup_database(&opts, &logger),
            "second setup instance",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_42_default_instances_can_run_against_same_initialized_database() {
    let temp = TempTree::new("test_42");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        let mut first = S01SetupDatabase::default();
        assert_ok(
            first.setup_database(&opts, &logger),
            "first default instance",
        );

        let mut second = S01SetupDatabase::default();
        assert_ok(
            second.setup_database(&opts, &logger),
            "second default instance",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_43_new_and_default_instances_are_interchangeable() {
    let temp = TempTree::new("test_43");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);

        let mut first = S01SetupDatabase::new();
        assert_ok(first.setup_database(&opts, &logger), "new instance setup");

        let mut second = S01SetupDatabase::default();
        assert_ok(
            second.setup_database(&opts, &logger),
            "default instance setup",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_44_initialized_status_exact_vector_round_trip() {
    let temp = TempTree::new("test_44");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    assert_metadata_equals(&opts, "status", b"initialized");
}

#[test]
fn test_45_initialized_status_length_matches_expected_vector() {
    let temp = TempTree::new("test_45");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    let status = read_status(&opts);
    match status {
        Some(bytes) => assert_eq!(bytes.len(), b"initialized".len()),
        None => panic!("initialized status was missing"),
    }
}

#[test]
fn test_46_setup_preserves_unrelated_ascii_metadata() {
    let temp = TempTree::new("test_46");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "custom_ascii", b"custom-value");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&opts, &logger), "setup");
    }

    assert_metadata_equals(&opts, "custom_ascii", b"custom-value");
}

#[test]
fn test_47_setup_preserves_unrelated_binary_metadata() {
    let temp = TempTree::new("test_47");
    let opts = make_node_opts(&temp.child("node"));
    let value = [0_u8, 1_u8, 2_u8, 3_u8, 255_u8];

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "custom_binary", &value);

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&opts, &logger), "setup");
    }

    assert_metadata_equals(&opts, "custom_binary", &value);
}

#[test]
fn test_48_setup_preserves_empty_metadata_value() {
    let temp = TempTree::new("test_48");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "empty_value", b"");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&opts, &logger), "setup");
    }

    assert_metadata_equals(&opts, "empty_value", b"");
}

#[test]
fn test_49_setup_preserves_long_metadata_value() {
    let temp = TempTree::new("test_49");
    let opts = make_node_opts(&temp.child("node"));
    let value = deterministic_value(49, 128);

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "long_value", &value);

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&opts, &logger), "setup");
    }

    assert_metadata_equals(&opts, "long_value", &value);
}

#[test]
fn test_50_setup_preserves_unicode_metadata_key() {
    let temp = TempTree::new("test_50");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "ключ_測試", b"unicode-key-value");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&opts, &logger), "setup");
    }

    assert_metadata_equals(&opts, "ключ_測試", b"unicode-key-value");
}

#[test]
fn test_51_setup_preserves_slash_metadata_key() {
    let temp = TempTree::new("test_51");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "nested/status/check", b"path-like-key");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&opts, &logger), "setup");
    }

    assert_metadata_equals(&opts, "nested/status/check", b"path-like-key");
}

#[test]
fn test_52_logger_empty_fields_before_setup_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_52");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        assert_ok(logger.log_error_event("", "", ""), "log empty fields");

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after empty log",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_53_logger_unicode_fields_before_setup_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_53");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        assert_ok(
            logger.log_error_event("資料庫", "事件_測試", "unicode message ✅"),
            "log unicode fields",
        );

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after unicode log",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_54_logger_quote_fields_before_setup_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_54");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        assert_ok(
            logger.log_error_event(
                "database",
                "QuoteEvent",
                "message with \"quotes\" and backslash \\",
            ),
            "log quote fields",
        );

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after quote log",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_55_logger_long_message_before_setup_do_not_break_initialized_setup() {
    let temp = TempTree::new("test_55");
    let opts = make_node_opts(&temp.child("node"));
    let message = deterministic_value(55, 256);
    let message_string = String::from_utf8_lossy(&message).into_owned();

    seed_initialized(&opts);

    {
        let logger = make_logger(&opts);
        assert_ok(
            logger.log_error_event("database", "LongMessage", &message_string),
            "log long message",
        );

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after long log",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_56_empty_stale_lock_file_does_not_block_initialized_setup() {
    let temp = TempTree::new("test_56");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, b"");

    assert!(
        lock_path.exists(),
        "empty stale LOCK file should still exist"
    );
}

#[test]
fn test_57_unicode_stale_lock_file_contents_do_not_block_initialized_setup() {
    let temp = TempTree::new("test_57");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, "鎖定".as_bytes());

    assert!(
        lock_path.exists(),
        "unicode stale LOCK file should still exist"
    );
}

#[test]
fn test_58_large_stale_lock_file_contents_do_not_block_initialized_setup() {
    let temp = TempTree::new("test_58");
    let opts = make_node_opts(&temp.child("node"));
    let contents = deterministic_value(58, 512);

    let lock_path = run_setup_with_existing_stale_lock(&opts, &contents);

    assert!(
        lock_path.exists(),
        "large stale LOCK file should still exist"
    );
}

#[test]
fn test_59_stale_lock_file_does_not_block_custom_metadata_preservation() {
    let temp = TempTree::new("test_59");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "before_lock", b"value");
    let lock_path = create_cli_lock(&opts, b"locked");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup with stale lock and custom metadata",
        );
    }

    assert!(lock_path.exists(), "stale LOCK file should still exist");
    assert_metadata_equals(&opts, "before_lock", b"value");
    assert_status_is_initialized(&opts);
}

#[test]
fn test_60_stale_lock_file_does_not_block_initialized_status() {
    let temp = TempTree::new("test_60");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, b"locked");

    assert!(lock_path.exists(), "stale LOCK file should still exist");
    assert_status_is_initialized(&opts);
}

#[test]
fn test_61_remove_stale_lock_then_initialized_setup_still_succeeds() {
    let temp = TempTree::new("test_61");
    let opts = make_node_opts(&temp.child("node"));

    let lock_path = run_setup_with_existing_stale_lock(&opts, b"locked");

    assert_ok(fs::remove_file(&lock_path), "remove stale lock file");
    run_setup_once_with_seeded_initialized_status(&opts);
}

#[test]
fn test_62_non_lock_file_does_not_block_initialized_setup() {
    let temp = TempTree::new("test_62");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    let directory = directory_from_opts(&opts);
    let note_path = directory.db_path.join("NOT_A_LOCK");
    assert_ok(
        fs::write(note_path, b"not a lock"),
        "write non-lock marker file",
    );

    run_initialized_setup(&opts);
}

#[test]
fn test_63_extra_file_in_cli_db_directory_is_preserved() {
    let temp = TempTree::new("test_63");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);

    let directory = directory_from_opts(&opts);
    let marker_path = directory.db_path.join("marker.txt");
    assert_ok(fs::write(&marker_path, b"keep"), "write marker file");

    run_initialized_setup(&opts);

    let marker = assert_ok(fs::read(marker_path), "read marker file");
    assert_eq!(marker.as_slice(), b"keep");
}

#[test]
fn test_64_missing_custom_metadata_stays_missing_after_initialized_setup() {
    let temp = TempTree::new("test_64");
    let opts = make_node_opts(&temp.child("node"));

    seed_initialized(&opts);
    assert_metadata_missing(&opts, "missing_before_setup");

    run_initialized_setup(&opts);

    assert_metadata_missing(&opts, "missing_before_setup");
}

#[test]
fn test_65_parent_directory_precreated_initialized_setup_succeeds() {
    let temp = TempTree::new("test_65");
    let parent = temp.child("parent");

    assert_ok(fs::create_dir_all(&parent), "create parent directory");

    let opts = make_node_opts(&parent.join("node"));
    run_initialized_setup(&opts);
}

#[test]
fn test_66_data_dir_with_many_segments_initialized_setup_succeeds() {
    let temp = TempTree::new("test_66");
    let path = temp
        .child("a")
        .join("b")
        .join("c")
        .join("d")
        .join("e")
        .join("node");

    let opts = make_node_opts(&path);
    run_initialized_setup(&opts);
}

#[test]
fn test_67_data_dir_with_dash_and_underscore_initialized_setup_succeeds() {
    let temp = TempTree::new("test_67");
    let opts = make_node_opts(&temp.child("node-with_dash_123"));

    run_initialized_setup(&opts);
}

#[test]
fn test_68_status_uppercase_initialized_vector_is_not_equal_to_canonical() {
    let temp = TempTree::new("test_68");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"INITIALIZED");

    let status = read_status(&opts);
    match status {
        Some(bytes) => assert_ne!(bytes.as_slice(), b"initialized"),
        None => panic!("status metadata was missing"),
    }
}

#[test]
fn test_69_status_trailing_space_vector_is_not_equal_to_canonical() {
    let temp = TempTree::new("test_69");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized ");

    let status = read_status(&opts);
    match status {
        Some(bytes) => assert_ne!(bytes.as_slice(), b"initialized"),
        None => panic!("status metadata was missing"),
    }
}

#[test]
fn test_70_status_leading_space_vector_is_not_equal_to_canonical() {
    let temp = TempTree::new("test_70");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b" initialized");

    let status = read_status(&opts);
    match status {
        Some(bytes) => assert_ne!(bytes.as_slice(), b"initialized"),
        None => panic!("status metadata was missing"),
    }
}

#[test]
fn test_71_status_binary_vector_is_not_equal_to_canonical() {
    let temp = TempTree::new("test_71");
    let opts = make_node_opts(&temp.child("node"));
    let binary = [0_u8, b'i', b'n', b'i', b't'];

    seed_status_value(&opts, &binary);

    let status = read_status(&opts);
    match status {
        Some(bytes) => assert_ne!(bytes.as_slice(), b"initialized"),
        None => panic!("status metadata was missing"),
    }
}

#[test]
fn test_72_status_empty_vector_round_trips() {
    let temp = TempTree::new("test_72");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"");
    assert_metadata_equals(&opts, "status", b"");
}

#[test]
fn test_73_status_long_vector_round_trips() {
    let temp = TempTree::new("test_73");
    let opts = make_node_opts(&temp.child("node"));
    let value = deterministic_value(73, 200);

    seed_status_value(&opts, &value);
    assert_metadata_equals(&opts, "status", &value);
}

#[test]
fn test_74_manual_overwrite_to_initialized_allows_setup() {
    let temp = TempTree::new("test_74");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"not_initialized");
    seed_status_value(&opts, b"initialized");

    run_setup_once_with_seeded_initialized_status(&opts);
}

#[test]
fn test_75_vector_listen_addresses_work_when_initialized() {
    let temp = TempTree::new("test_75");

    for listen in [
        "/ip4/127.0.0.1/tcp/36213",
        "/ip4/0.0.0.0/tcp/36213",
        "/ip6/::1/tcp/36213",
    ] {
        let safe_name = listen
            .chars()
            .map(|ch| match ch {
                '/' | ':' | '.' => '_',
                other => other,
            })
            .collect::<String>();

        let opts = make_node_opts_custom(
            &temp.child(&safe_name),
            "identity.key",
            listen,
            Vec::new(),
            "info",
            false,
        );

        run_initialized_setup(&opts);
    }
}

#[test]
fn test_76_vector_identity_file_names_with_spaces_work_when_initialized() {
    let temp = TempTree::new("test_76");

    for identity_file in [
        "identity one.key",
        "identity two.key",
        "validator identity.key",
    ] {
        let opts = make_node_opts_custom(
            &temp.child(identity_file),
            identity_file,
            "/ip4/127.0.0.1/tcp/36213",
            Vec::new(),
            "info",
            false,
        );

        run_initialized_setup(&opts);
    }
}

#[test]
fn test_77_vector_log_levels_work_when_initialized() {
    let temp = TempTree::new("test_77");

    for log_level in ["trace", "debug", "info", "warn", "error"] {
        let opts = make_node_opts_custom(
            &temp.child(log_level),
            "identity.key",
            "/ip4/127.0.0.1/tcp/36213",
            Vec::new(),
            log_level,
            false,
        );

        run_initialized_setup(&opts);
    }
}

#[test]
fn test_78_vector_bootstrap_sizes_work_when_initialized() {
    let temp = TempTree::new("test_78");

    for count in 0..6 {
        let mut bootstrap = Vec::new();

        for index in 0..count {
            bootstrap.push(format!(
                "/ip4/127.0.0.1/tcp/{}",
                37_000usize.wrapping_add(index)
            ));
        }

        let opts = make_node_opts_custom(
            &temp.child(&format!("node_{count}")),
            "identity.key",
            "/ip4/127.0.0.1/tcp/36213",
            bootstrap,
            "info",
            false,
        );

        run_initialized_setup(&opts);
    }
}

#[test]
fn test_79_property_custom_metadata_preserved_across_repeated_setup_runs() {
    let temp = TempTree::new("test_79");
    let opts = make_node_opts(&temp.child("node"));
    let value = deterministic_value(79, 64);

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "property_value", &value);

    for _ in 0..8 {
        {
            let logger = make_logger(&opts);
            let mut section = S01SetupDatabase::new();
            assert_ok(section.setup_database(&opts, &logger), "repeated setup");
        }

        assert_metadata_equals(&opts, "property_value", &value);
    }
}

#[test]
fn test_80_property_status_initialized_preserved_across_logger_flushes() {
    let temp = TempTree::new("test_80");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    {
        let logger = make_logger(&opts);
        for index in 0..5 {
            assert_ok(
                logger.log_error_event("database", "FlushProperty", &format!("event {index}")),
                "log flush property event",
            );
            assert_ok(logger.flush_logs_cf(), "flush logs cf");
        }

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after flushes",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_81_fuzz_custom_metadata_values_round_trip() {
    let temp = TempTree::new("test_81");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    for seed in 0..12 {
        let key = format!("fuzz_value_{seed}");
        let value = deterministic_value(seed, seed.wrapping_add(1));
        seed_metadata_value(&opts, &key, &value);
        assert_metadata_equals(&opts, &key, &value);
    }
}

#[test]
fn test_82_fuzz_status_values_round_trip_without_setup_prompt() {
    let temp = TempTree::new("test_82");

    for seed in 0..12 {
        let opts = make_node_opts(&temp.child(&format!("node_{seed}")));
        let value = deterministic_value(seed, seed.wrapping_add(2));
        seed_status_value(&opts, &value);
        assert_metadata_equals(&opts, "status", &value);
    }
}

#[test]
fn test_83_adversarial_parallel_stale_lock_unique_nodes_succeed() {
    let mut handles = Vec::new();

    for node_id in 0..6 {
        handles.push(thread::spawn(move || {
            let temp = TempTree::new(&format!("test_83_{node_id}"));
            let opts = make_node_opts(&temp.child("node"));
            let lock_path = run_setup_with_existing_stale_lock(&opts, b"parallel-lock");

            assert!(
                lock_path.exists(),
                "parallel stale LOCK file should still exist"
            );
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("parallel stale lock setup worker panicked"),
        }
    }
}

#[test]
fn test_84_adversarial_parallel_unique_nodes_with_logs_succeed() {
    let mut handles = Vec::new();

    for node_id in 0..6 {
        handles.push(thread::spawn(move || {
            let temp = TempTree::new(&format!("test_84_{node_id}"));
            let opts = make_node_opts(&temp.child("node"));

            seed_status_value(&opts, b"initialized");

            {
                let logger = make_logger(&opts);
                assert_ok(
                    logger.log_error_event("database", "ParallelLog", &format!("node {node_id}")),
                    "parallel pre-log",
                );

                let mut section = S01SetupDatabase::new();
                assert_ok(section.setup_database(&opts, &logger), "parallel setup");
            }

            assert_status_is_initialized(&opts);
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("parallel log setup worker panicked"),
        }
    }
}

#[test]
fn test_85_adversarial_same_data_dir_different_opts_sequentially_succeeds_when_initialized() {
    let temp = TempTree::new("test_85");
    let data_dir = temp.child("shared_node");

    let first = make_node_opts_custom(
        &data_dir,
        "identity_a.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "info",
        false,
    );
    let second = make_node_opts_custom(
        &data_dir,
        "identity_b.key",
        "/ip4/127.0.0.1/tcp/46213",
        vec!["not-a-real-bootstrap".to_owned()],
        "debug",
        true,
    );

    seed_status_value(&first, b"initialized");

    {
        let logger = make_logger(&first);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&first, &logger), "first setup");
    }

    {
        let logger = make_logger(&second);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&second, &logger), "second setup");
    }

    assert_status_is_initialized(&first);
    assert_status_is_initialized(&second);
}

#[test]
fn test_86_load_thirty_unique_initialized_nodes() {
    let temp = TempTree::new("test_86");

    for seed in 0..30 {
        let opts = make_node_opts(&temp.child(&format!("load_unique_{seed}")));
        run_initialized_setup(&opts);
    }
}

#[test]
fn test_87_load_fifteen_repeated_runs_preserve_custom_metadata() {
    let temp = TempTree::new("test_87");
    let opts = make_node_opts(&temp.child("node"));
    let value = deterministic_value(87, 96);

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "load_custom", &value);

    for _ in 0..15 {
        {
            let logger = make_logger(&opts);
            let mut section = S01SetupDatabase::new();
            assert_ok(
                section.setup_database(&opts, &logger),
                "load repeated setup",
            );
        }

        assert_metadata_equals(&opts, "load_custom", &value);
    }
}

#[test]
fn test_88_load_ten_stale_lock_nodes_succeed_cleanly() {
    let temp = TempTree::new("test_88");

    for seed in 0..10 {
        let opts = make_node_opts(&temp.child(&format!("locked_node_{seed}")));
        let lock_path = run_setup_with_existing_stale_lock(&opts, b"locked");

        assert!(
            lock_path.exists(),
            "load stale LOCK file should still exist"
        );
    }
}

#[test]
fn test_89_load_logger_multiple_events_then_setup() {
    let temp = TempTree::new("test_89");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    {
        let logger = make_logger(&opts);

        for seed in 0..25 {
            assert_ok(
                logger.log_error_event("database", "LoadLogger", &format!("event {seed}")),
                "load logger event",
            );
        }

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after logger load",
        );
        assert_ok(logger.flush_logs_cf(), "flush logs after logger load");
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_90_load_many_flush_calls_are_idempotent() {
    let temp = TempTree::new("test_90");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    {
        let logger = make_logger(&opts);

        for _ in 0..10 {
            assert_ok(logger.flush(), "logger flush");
            assert_ok(logger.flush_logs_cf(), "logger flush logs cf");
        }

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup after many flushes",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_91_metadata_value_can_be_read_after_setup_and_manager_reopen() {
    let temp = TempTree::new("test_91");
    let opts = make_node_opts(&temp.child("node"));
    let value = deterministic_value(91, 40);

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "reopen_key", &value);

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();
        assert_ok(section.setup_database(&opts, &logger), "setup");
    }

    assert_metadata_equals(&opts, "reopen_key", &value);
}

#[test]
fn test_92_status_initialized_can_be_read_after_multiple_manager_reopens() {
    let temp = TempTree::new("test_92");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    for _ in 0..6 {
        assert_status_is_initialized(&opts);
    }

    run_setup_once_with_seeded_initialized_status(&opts);
}

#[test]
fn test_93_logger_db_handle_exists_during_initialized_setup() {
    let temp = TempTree::new("test_93");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    {
        let logger = make_logger(&opts);
        let db_handle = logger.db();
        assert!(
            std::sync::Arc::strong_count(db_handle) >= 1,
            "logger DB Arc should have at least one strong reference"
        );

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "setup with logger db handle",
        );
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_94_error_event_can_be_logged_after_stale_lock_setup() {
    let temp = TempTree::new("test_94");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");
    let lock_path = create_cli_lock(&opts, b"locked");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();

        assert_ok(
            section.setup_database(&opts, &logger),
            "setup with stale lock should succeed",
        );

        assert_ok(
            logger.log_error_event("database", "AfterStaleLockSetup", "manual follow-up log"),
            "manual log after stale lock setup",
        );
        assert_ok(logger.flush_logs_cf(), "flush after stale lock setup log");
    }

    assert!(lock_path.exists(), "stale LOCK file should still exist");
    assert_status_is_initialized(&opts);
}

#[test]
fn test_95_error_event_with_large_payload_can_be_logged_after_stale_lock_setup() {
    let temp = TempTree::new("test_95");
    let opts = make_node_opts(&temp.child("node"));
    let payload = deterministic_value(95, 512);
    let message = String::from_utf8_lossy(&payload).into_owned();

    seed_status_value(&opts, b"initialized");
    let lock_path = create_cli_lock(&opts, b"locked");

    {
        let logger = make_logger(&opts);
        let mut section = S01SetupDatabase::new();

        assert_ok(
            section.setup_database(&opts, &logger),
            "setup with stale lock should succeed",
        );

        assert_ok(
            logger.log_error_event("database", "LargeAfterStaleLockSetup", &message),
            "large manual log after stale lock setup",
        );
        assert_ok(logger.flush(), "flush after large stale lock setup log");
    }

    assert!(lock_path.exists(), "stale LOCK file should still exist");
    assert_status_is_initialized(&opts);
}

#[test]
fn test_96_many_custom_keys_survive_initialized_setup() {
    let temp = TempTree::new("test_96");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    for seed in 0..20 {
        let key = format!("many_custom_key_{seed}");
        let value = deterministic_value(seed, 8);
        seed_metadata_value(&opts, &key, &value);
    }

    run_setup_once_with_seeded_initialized_status(&opts);

    for seed in 0..20 {
        let key = format!("many_custom_key_{seed}");
        let value = deterministic_value(seed, 8);
        assert_metadata_equals(&opts, &key, &value);
    }
}

#[test]
fn test_97_alternating_logger_and_setup_runs_keep_status_initialized() {
    let temp = TempTree::new("test_97");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    for seed in 0..8 {
        {
            let logger = make_logger(&opts);
            assert_ok(
                logger.log_error_event("database", "AlternatingRun", &format!("run {seed}")),
                "alternating log",
            );

            let mut section = S01SetupDatabase::new();
            assert_ok(section.setup_database(&opts, &logger), "alternating setup");
        }

        assert_status_is_initialized(&opts);
    }
}

#[test]
fn test_98_vector_seeded_status_can_be_corrected_to_canonical_then_setup() {
    let temp = TempTree::new("test_98");
    let opts = make_node_opts(&temp.child("node"));

    for value in [
        b"no".as_slice(),
        b"pending".as_slice(),
        b"initialized".as_slice(),
    ] {
        seed_status_value(&opts, value);
    }

    run_setup_once_with_seeded_initialized_status(&opts);
}

#[test]
fn test_99_load_many_sequential_setup_sections_same_initialized_database() {
    let temp = TempTree::new("test_99");
    let opts = make_node_opts(&temp.child("node"));

    seed_status_value(&opts, b"initialized");

    {
        let logger = make_logger(&opts);

        for _ in 0..20 {
            let mut section = S01SetupDatabase::new();
            assert_ok(
                section.setup_database(&opts, &logger),
                "sequential setup section",
            );
        }

        assert_ok(logger.flush_logs_cf(), "final flush logs cf");
    }

    assert_status_is_initialized(&opts);
}

#[test]
fn test_100_final_comprehensive_initialized_setup_preserves_logs_and_metadata() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let audit_value = deterministic_value(100, 100);

    seed_status_value(&opts, b"initialized");
    seed_metadata_value(&opts, "audit_vector", &audit_value);

    {
        let logger = make_logger(&opts);

        assert_ok(
            logger.log_error_event("database", "BeforeFinalSetup", "before final setup"),
            "before final setup log",
        );

        let mut section = S01SetupDatabase::new();
        assert_ok(
            section.setup_database(&opts, &logger),
            "final comprehensive setup",
        );

        assert_ok(
            logger.log_error_event("database", "AfterFinalSetup", "after final setup"),
            "after final setup log",
        );

        assert_ok(logger.flush(), "final logger flush");
        assert_ok(logger.flush_logs_cf(), "final logger flush logs cf");
    }

    assert_status_is_initialized(&opts);
    assert_metadata_equals(&opts, "audit_vector", &audit_value);
}
