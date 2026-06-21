use remzar::commandline::s_16_debug_logs::S16DebugLogs;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_002_schema::RockDbSchema;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::logging_data::JsonLogger;
use rust_rocksdb::IteratorMode;
use serde_json::Value;
use std::fmt::Debug;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

const CHILD_TEST_ENV: &str = "REMZAR_S16_CHILD_TEST";
const CHILD_ROOT_ENV: &str = "REMZAR_S16_CHILD_ROOT";
const CHILD_SCENARIO_ENV: &str = "REMZAR_S16_CHILD_SCENARIO";

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_16_debug_logs_tests_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            make_writable_recursive(&root);
            let _ = fs::remove_dir_all(&root);
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
        let _ = fs::remove_dir_all(&self.root);
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
        let _ = fs::set_permissions(path, permissions);
    }

    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
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

fn export_path(opts: &NodeOpts) -> PathBuf {
    directory_from_opts(opts)
        .log_path
        .join("remzar_error_log.json")
}

fn tmp_export_path(opts: &NodeOpts) -> PathBuf {
    let mut tmp = export_path(opts);
    tmp.set_extension("json.tmp");
    tmp
}

fn put_log_raw(logger: &JsonLogger, key: &str, value: &[u8]) {
    let db = logger.db();
    let cf = db
        .cf_handle(RockDbSchema::logs_column_name())
        .unwrap_or_else(|| {
            panic!(
                "missing logs column family '{}'",
                RockDbSchema::logs_column_name()
            )
        });

    assert_ok(db.put_cf(&cf, key.as_bytes(), value), "put raw log entry");
}

fn read_raw_log_values(logger: &JsonLogger) -> Vec<Vec<u8>> {
    let db = logger.db();
    let cf = db
        .cf_handle(RockDbSchema::logs_column_name())
        .unwrap_or_else(|| {
            panic!(
                "missing logs column family '{}'",
                RockDbSchema::logs_column_name()
            )
        });

    let mut values = Vec::new();

    for item in db.iterator_cf(&cf, IteratorMode::Start) {
        let (_key, value) = assert_ok(item, "read log iterator item");
        values.push(value.to_vec());
    }

    values
}

fn seed_logs_for_scenario(scenario: &str, logger: &JsonLogger) {
    match scenario {
        "none" => {}
        "one_json" => {
            put_log_raw(logger, "log_001", br#"{"event":"alpha","n":1}"#);
        }
        "two_json" => {
            put_log_raw(logger, "log_001", br#"{"event":"oldest","n":1}"#);
            put_log_raw(logger, "log_002", br#"{"event":"newest","n":2}"#);
        }
        "malformed" => {
            put_log_raw(logger, "log_001", b"not valid json");
        }
        "non_utf8" => {
            put_log_raw(logger, "log_001", &[0xff, 0xfe, 0xfd, 0x00, 0x41]);
        }
        "unicode_json" => {
            put_log_raw(
                logger,
                "log_001",
                "{\"event\":\"unicode\",\"message\":\"測試✅\"}".as_bytes(),
            );
        }
        "array_json" => {
            put_log_raw(logger, "log_001", br#"[1,2,3]"#);
        }
        "number_json" => {
            put_log_raw(logger, "log_001", b"12345");
        }
        "bool_json" => {
            put_log_raw(logger, "log_001", b"true");
        }
        "null_json" => {
            put_log_raw(logger, "log_001", b"null");
        }
        "json_string" => {
            put_log_raw(logger, "log_001", br#""plain string log""#);
        }
        "nested_object" => {
            put_log_raw(
                logger,
                "log_001",
                br#"{"outer":{"inner":[1,2,{"ok":true}]},"level":"debug"}"#,
            );
        }
        "nested_array" => {
            put_log_raw(logger, "log_001", br#"[{"a":1},{"b":2}]"#);
        }
        "large_parse" => {
            let raw = format!("\"{}\"", "a".repeat(70 * 1024));
            put_log_raw(logger, "log_001", raw.as_bytes());
        }
        "too_large" => {
            put_log_raw(logger, "log_001", &vec![b'x'; (256 * 1024) + 1]);
        }
        "single_cap_exact" => {
            put_log_raw(logger, "log_001", &vec![b'a'; 256 * 1024]);
        }
        "single_cap_plus_one" => {
            put_log_raw(logger, "log_001", &vec![b'a'; (256 * 1024) + 1]);
        }
        "mixed" => {
            put_log_raw(logger, "log_001", br#"{"event":"good"}"#);
            put_log_raw(logger, "log_002", b"{bad-json");
            put_log_raw(logger, "log_003", &[0xff, 0x00, 0x42]);
        }
        "over_budget" => {
            let value = format!("\"{}\"", "b".repeat(200 * 1024));
            for index in 0..6 {
                put_log_raw(logger, &format!("log_{index:03}"), value.as_bytes());
            }
        }
        "many_small_10" => {
            for index in 0..10 {
                let value = format!(r#"{{"idx":{index},"kind":"small"}}"#);
                put_log_raw(logger, &format!("log_{index:03}"), value.as_bytes());
            }
        }
        "many_small_50" => {
            for index in 0..50 {
                let value = format!(r#"{{"idx":{index},"kind":"small50"}}"#);
                put_log_raw(logger, &format!("log_{index:03}"), value.as_bytes());
            }
        }
        "duplicate_values" => {
            put_log_raw(logger, "log_001", br#"{"same":true}"#);
            put_log_raw(logger, "log_002", br#"{"same":true}"#);
        }
        "large_and_small" => {
            put_log_raw(logger, "log_001", &vec![b'z'; (256 * 1024) + 7]);
            put_log_raw(logger, "log_002", br#"{"event":"after-large"}"#);
        }
        "empty_entry" => {
            put_log_raw(logger, "log_001", b"");
        }
        "whitespace_entry" => {
            put_log_raw(logger, "log_001", b"     \r\n\t   ");
        }
        "invalid_brace" => {
            put_log_raw(logger, "log_001", b"{");
        }
        "prompt_logs" => {
            put_log_raw(
                logger,
                "log_001",
                br#"{"event":"available-but-user-says-no"}"#,
            );
        }
        other => panic!("unknown child log scenario: {other}"),
    }
}

fn maybe_run_child(test_name: &str) -> bool {
    let child_test = match std::env::var(CHILD_TEST_ENV) {
        Ok(value) => value,
        Err(_) => return false,
    };

    if child_test != test_name {
        return false;
    }

    let root = PathBuf::from(
        std::env::var(CHILD_ROOT_ENV)
            .unwrap_or_else(|_| panic!("{CHILD_ROOT_ENV} was not set for child test")),
    );
    let scenario = std::env::var(CHILD_SCENARIO_ENV)
        .unwrap_or_else(|_| panic!("{CHILD_SCENARIO_ENV} was not set for child test"));

    assert_ok(fs::create_dir_all(&root), "create child node root");

    let opts = make_node_opts(&root);
    let logger = make_logger(&opts);

    seed_logs_for_scenario(&scenario, &logger);

    let section = S16DebugLogs::new();
    assert_ok(
        section.debug_logs(&opts, &logger),
        "S16DebugLogs::debug_logs child run",
    );

    true
}

struct ChildRun {
    stdout: String,
    stderr: String,
    output_file: Option<String>,
    output_bytes: Option<Vec<u8>>,
    tmp_exists: bool,
    out_path: PathBuf,
}

fn run_debug_logs_child(test_name: &str, scenario: &str, stdin_input: &str) -> ChildRun {
    let temp = TempTree::new(test_name);
    let node_root = temp.child("node");
    assert_ok(fs::create_dir_all(&node_root), "create parent node root");

    let opts = make_node_opts(&node_root);
    let out_path = export_path(&opts);
    let tmp_path = tmp_export_path(&opts);

    let mut child = assert_ok(
        Command::new(std::env::current_exe().expect("current_exe should be available"))
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env(CHILD_TEST_ENV, test_name)
            .env(CHILD_ROOT_ENV, node_root.to_string_lossy().to_string())
            .env(CHILD_SCENARIO_ENV, scenario)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn(),
        "spawn child test process",
    );

    {
        let stdin = child
            .stdin
            .as_mut()
            .unwrap_or_else(|| panic!("child stdin was not piped"));
        assert_ok(
            stdin.write_all(stdin_input.as_bytes()),
            "write child stdin input",
        );
    }

    let output = assert_ok(child.wait_with_output(), "wait for child process");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        output.status.success(),
        "child test failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );

    let output_bytes = fs::read(&out_path).ok();
    let output_file = output_bytes
        .as_ref()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());

    ChildRun {
        stdout,
        stderr,
        output_file,
        output_bytes,
        tmp_exists: tmp_path.exists(),
        out_path,
    }
}

fn exported_values(run: &ChildRun) -> Vec<Value> {
    let text = run
        .output_file
        .as_ref()
        .unwrap_or_else(|| panic!("expected export file at {}", run.out_path.display()));

    let value: Value = assert_ok(serde_json::from_str(text), "parse exported JSON file");
    match value {
        Value::Array(values) => values,
        other => panic!("expected exported JSON array, got {other:?}"),
    }
}

fn assert_no_export(run: &ChildRun) {
    assert!(
        run.output_file.is_none(),
        "expected no export file, got {:?}",
        run.out_path
    );
}

// ─────────────────────────────────────────────────────────────
// 001–020: constructors, paths, logger DB, and raw log setup
// ─────────────────────────────────────────────────────────────

#[test]
fn test_001_new_constructor_creates_section() {
    let _section = S16DebugLogs::new();
}

#[test]
fn test_002_default_constructor_creates_section() {
    let _section = S16DebugLogs::default();
}

#[test]
fn test_003_new_and_default_are_zero_sized() {
    assert_eq!(std::mem::size_of::<S16DebugLogs>(), 0);
}

#[test]
fn test_004_temp_tree_creates_unique_root() {
    let first = TempTree::new("test_004_a");
    let second = TempTree::new("test_004_b");

    assert_ne!(first.root, second.root);
    assert!(first.root.exists());
    assert!(second.root.exists());
}

#[test]
fn test_005_node_opts_preserves_data_dir_string() {
    let temp = TempTree::new("test_005");
    let node = temp.child("node");
    let opts = make_node_opts(&node);

    assert_eq!(opts.data_dir, node.to_string_lossy());
}

#[test]
fn test_006_directory_from_opts_builds_paths() {
    let temp = TempTree::new("test_006");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert!(directory.log_path.ends_with("004.log_db"));
}

#[test]
fn test_007_create_log_directory_succeeds() {
    let temp = TempTree::new("test_007");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(directory.create_log_directory(), "create_log_directory");
    assert!(directory.log_path.exists());
}

#[test]
fn test_008_json_logger_new_succeeds() {
    let temp = TempTree::new("test_008");
    let opts = make_node_opts(&temp.child("node"));
    let _logger = make_logger(&opts);
}

#[test]
fn test_009_logger_exposes_logs_column_family() {
    let temp = TempTree::new("test_009");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);
    let db = logger.db();

    assert!(db.cf_handle(RockDbSchema::logs_column_name()).is_some());
}

#[test]
fn test_010_export_path_uses_expected_filename() {
    let temp = TempTree::new("test_010");
    let opts = make_node_opts(&temp.child("node"));
    let path = export_path(&opts);

    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("remzar_error_log.json")
    );
}

#[test]
fn test_011_tmp_export_path_uses_tmp_extension() {
    let temp = TempTree::new("test_011");
    let opts = make_node_opts(&temp.child("node"));
    let path = tmp_export_path(&opts);

    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("remzar_error_log.json.tmp")
    );
}

#[test]
fn test_012_logger_logs_cf_starts_empty() {
    let temp = TempTree::new("test_012");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert!(read_raw_log_values(&logger).is_empty());
}

#[test]
fn test_013_put_raw_json_log_persists_one_value() {
    let temp = TempTree::new("test_013");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    put_log_raw(&logger, "log_001", br#"{"event":"one"}"#);

    assert_eq!(read_raw_log_values(&logger).len(), 1);
}

#[test]
fn test_014_put_multiple_raw_logs_persists_all_values() {
    let temp = TempTree::new("test_014");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    put_log_raw(&logger, "log_001", b"one");
    put_log_raw(&logger, "log_002", b"two");
    put_log_raw(&logger, "log_003", b"three");

    assert_eq!(read_raw_log_values(&logger).len(), 3);
}

#[test]
fn test_015_put_non_utf8_log_persists_raw_bytes() {
    let temp = TempTree::new("test_015");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    put_log_raw(&logger, "log_001", &[0xff, 0xfe, 0xfd]);

    let values = read_raw_log_values(&logger);
    assert_eq!(values, vec![vec![0xff, 0xfe, 0xfd]]);
}

#[test]
fn test_016_put_empty_log_entry_persists() {
    let temp = TempTree::new("test_016");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    put_log_raw(&logger, "log_001", b"");

    assert_eq!(read_raw_log_values(&logger), vec![Vec::<u8>::new()]);
}

#[test]
fn test_017_log_error_event_writes_to_logger_db() {
    let temp = TempTree::new("test_017");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("test", "S16TestEvent", "hello"),
        "log_error_event",
    );

    assert!(!read_raw_log_values(&logger).is_empty());
}

#[test]
fn test_018_flush_logs_cf_succeeds_after_raw_put() {
    let temp = TempTree::new("test_018");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    put_log_raw(&logger, "log_001", br#"{"flush":true}"#);
    assert_ok(logger.flush_logs_cf(), "flush_logs_cf");
}

#[test]
fn test_019_flush_succeeds_after_raw_put() {
    let temp = TempTree::new("test_019");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    put_log_raw(&logger, "log_001", br#"{"flush":"all"}"#);
    assert_ok(logger.flush(), "flush");
}

#[test]
fn test_020_logger_db_arc_has_strong_reference() {
    let temp = TempTree::new("test_020");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);
    let db = logger.db();

    assert!(std::sync::Arc::strong_count(&db) >= 1);
}

// ─────────────────────────────────────────────────────────────
// 021–050: real interactive export behavior via child stdin
// ─────────────────────────────────────────────────────────────

#[test]
fn test_021_debug_logs_no_answer_returns_without_export() {
    if maybe_run_child("test_021_debug_logs_no_answer_returns_without_export") {
        return;
    }

    let run = run_debug_logs_child(
        "test_021_debug_logs_no_answer_returns_without_export",
        "prompt_logs",
        "no\n",
    );

    assert_no_export(&run);
    assert!(run.stdout.contains("Returning to the menu"));
    assert!(run.stderr.is_empty() || !run.stderr.contains("panicked"));
}

#[test]
fn test_022_debug_logs_short_n_answer_returns_without_export() {
    if maybe_run_child("test_022_debug_logs_short_n_answer_returns_without_export") {
        return;
    }

    let run = run_debug_logs_child(
        "test_022_debug_logs_short_n_answer_returns_without_export",
        "prompt_logs",
        "n\n",
    );

    assert_no_export(&run);
    assert!(run.stdout.contains("Returning to the menu"));
}

#[test]
fn test_023_debug_logs_empty_db_yes_returns_without_export() {
    if maybe_run_child("test_023_debug_logs_empty_db_yes_returns_without_export") {
        return;
    }

    let run = run_debug_logs_child(
        "test_023_debug_logs_empty_db_yes_returns_without_export",
        "none",
        "yes\n",
    );

    assert_no_export(&run);
    assert!(run.stdout.contains("No logs available to export"));
}

#[test]
fn test_024_debug_logs_exports_single_json_object() {
    if maybe_run_child("test_024_debug_logs_exports_single_json_object") {
        return;
    }

    let run = run_debug_logs_child(
        "test_024_debug_logs_exports_single_json_object",
        "one_json",
        "yes\n",
    );

    assert!(run.stdout.contains("Exported latest logs"));
    assert!(!run.tmp_exists);
    assert!(
        run.output_bytes
            .as_ref()
            .is_some_and(|bytes| !bytes.is_empty())
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["event"], "alpha");
    assert_eq!(values[0]["n"], 1);
}

#[test]
fn test_025_debug_logs_short_y_exports_single_json_object() {
    if maybe_run_child("test_025_debug_logs_short_y_exports_single_json_object") {
        return;
    }

    let run = run_debug_logs_child(
        "test_025_debug_logs_short_y_exports_single_json_object",
        "one_json",
        "y\n",
    );

    assert!(!run.tmp_exists);

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["event"], "alpha");
}

#[test]
fn test_026_debug_logs_invalid_then_yes_exports() {
    if maybe_run_child("test_026_debug_logs_invalid_then_yes_exports") {
        return;
    }

    let run = run_debug_logs_child(
        "test_026_debug_logs_invalid_then_yes_exports",
        "one_json",
        "maybe\nyes\n",
    );

    assert!(run.stdout.contains("Invalid response"));
    let values = exported_values(&run);
    assert_eq!(values[0]["event"], "alpha");
}

#[test]
fn test_027_debug_logs_too_long_prompt_then_yes_exports_and_logs_error() {
    if maybe_run_child("test_027_debug_logs_too_long_prompt_then_yes_exports_and_logs_error") {
        return;
    }

    let run = run_debug_logs_child(
        "test_027_debug_logs_too_long_prompt_then_yes_exports_and_logs_error",
        "one_json",
        "this-input-is-definitely-too-long\nyes\n",
    );

    assert!(run.stdout.contains("Input too long"));
    let values = exported_values(&run);
    assert!(values.iter().any(|value| value["event"] == "alpha"));
    assert!(values.len() >= 1);
}

#[test]
fn test_028_debug_logs_five_invalid_attempts_returns_no_export() {
    if maybe_run_child("test_028_debug_logs_five_invalid_attempts_returns_no_export") {
        return;
    }

    let run = run_debug_logs_child(
        "test_028_debug_logs_five_invalid_attempts_returns_no_export",
        "one_json",
        "bad\nbad\nbad\nbad\nbad\n",
    );

    assert_no_export(&run);
    assert!(run.stdout.contains("Too many invalid attempts"));
}

#[test]
fn test_029_debug_logs_preserves_oldest_to_newest_order() {
    if maybe_run_child("test_029_debug_logs_preserves_oldest_to_newest_order") {
        return;
    }

    let run = run_debug_logs_child(
        "test_029_debug_logs_preserves_oldest_to_newest_order",
        "two_json",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 2);
    assert_eq!(values[0]["event"], "oldest");
    assert_eq!(values[1]["event"], "newest");
}

#[test]
fn test_030_debug_logs_wraps_malformed_utf8_string_as_malformed() {
    if maybe_run_child("test_030_debug_logs_wraps_malformed_utf8_string_as_malformed") {
        return;
    }

    let run = run_debug_logs_child(
        "test_030_debug_logs_wraps_malformed_utf8_string_as_malformed",
        "malformed",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["malformed"], "not valid json");
}

#[test]
fn test_031_debug_logs_wraps_non_utf8_as_hex() {
    if maybe_run_child("test_031_debug_logs_wraps_non_utf8_as_hex") {
        return;
    }

    let run = run_debug_logs_child(
        "test_031_debug_logs_wraps_non_utf8_as_hex",
        "non_utf8",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["non_utf8_hex"], "fffefd0041");
    assert_eq!(values[0]["bytes"], 5);
}

#[test]
fn test_032_debug_logs_exports_unicode_json_without_loss() {
    if maybe_run_child("test_032_debug_logs_exports_unicode_json_without_loss") {
        return;
    }

    let run = run_debug_logs_child(
        "test_032_debug_logs_exports_unicode_json_without_loss",
        "unicode_json",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["message"], "測試✅");
}

#[test]
fn test_033_debug_logs_exports_json_array_entry() {
    if maybe_run_child("test_033_debug_logs_exports_json_array_entry") {
        return;
    }

    let run = run_debug_logs_child(
        "test_033_debug_logs_exports_json_array_entry",
        "array_json",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], serde_json::json!([1, 2, 3]));
}

#[test]
fn test_034_debug_logs_exports_json_number_entry() {
    if maybe_run_child("test_034_debug_logs_exports_json_number_entry") {
        return;
    }

    let run = run_debug_logs_child(
        "test_034_debug_logs_exports_json_number_entry",
        "number_json",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values, vec![serde_json::json!(12345)]);
}

#[test]
fn test_035_debug_logs_exports_json_bool_entry() {
    if maybe_run_child("test_035_debug_logs_exports_json_bool_entry") {
        return;
    }

    let run = run_debug_logs_child(
        "test_035_debug_logs_exports_json_bool_entry",
        "bool_json",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values, vec![serde_json::json!(true)]);
}

#[test]
fn test_036_debug_logs_exports_json_null_entry() {
    if maybe_run_child("test_036_debug_logs_exports_json_null_entry") {
        return;
    }

    let run = run_debug_logs_child(
        "test_036_debug_logs_exports_json_null_entry",
        "null_json",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values, vec![Value::Null]);
}

#[test]
fn test_037_debug_logs_exports_json_string_entry() {
    if maybe_run_child("test_037_debug_logs_exports_json_string_entry") {
        return;
    }

    let run = run_debug_logs_child(
        "test_037_debug_logs_exports_json_string_entry",
        "json_string",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values, vec![serde_json::json!("plain string log")]);
}

#[test]
fn test_038_debug_logs_exports_nested_object() {
    if maybe_run_child("test_038_debug_logs_exports_nested_object") {
        return;
    }

    let run = run_debug_logs_child(
        "test_038_debug_logs_exports_nested_object",
        "nested_object",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values[0]["outer"]["inner"][2]["ok"], true);
    assert_eq!(values[0]["level"], "debug");
}

#[test]
fn test_039_debug_logs_exports_nested_array() {
    if maybe_run_child("test_039_debug_logs_exports_nested_array") {
        return;
    }

    let run = run_debug_logs_child(
        "test_039_debug_logs_exports_nested_array",
        "nested_array",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values[0][0]["a"], 1);
    assert_eq!(values[0][1]["b"], 2);
}

#[test]
fn test_040_debug_logs_large_utf8_entry_skips_json_parse() {
    if maybe_run_child("test_040_debug_logs_large_utf8_entry_skips_json_parse") {
        return;
    }

    let run = run_debug_logs_child(
        "test_040_debug_logs_large_utf8_entry_skips_json_parse",
        "large_parse",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert!(
        values[0]["raw"]
            .as_str()
            .is_some_and(|raw| raw.len() > 64 * 1024)
    );
    assert!(
        values[0]["note"]
            .as_str()
            .is_some_and(|note| note.contains("too large to JSON-parse"))
    );
}

#[test]
fn test_041_debug_logs_too_large_entry_emits_skipped_marker() {
    if maybe_run_child("test_041_debug_logs_too_large_entry_emits_skipped_marker") {
        return;
    }

    let run = run_debug_logs_child(
        "test_041_debug_logs_too_large_entry_emits_skipped_marker",
        "too_large",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["skipped"], "entry_too_large");
    assert!(
        values[0]["bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 256 * 1024)
    );
}

#[test]
fn test_042_debug_logs_exact_single_entry_cap_is_exported() {
    if maybe_run_child("test_042_debug_logs_exact_single_entry_cap_is_exported") {
        return;
    }

    let run = run_debug_logs_child(
        "test_042_debug_logs_exact_single_entry_cap_is_exported",
        "single_cap_exact",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 1);
    assert!(
        values[0]["raw"]
            .as_str()
            .is_some_and(|raw| raw.len() == 256 * 1024)
    );
}

#[test]
fn test_043_debug_logs_single_entry_cap_plus_one_is_skipped() {
    if maybe_run_child("test_043_debug_logs_single_entry_cap_plus_one_is_skipped") {
        return;
    }

    let run = run_debug_logs_child(
        "test_043_debug_logs_single_entry_cap_plus_one_is_skipped",
        "single_cap_plus_one",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values[0]["skipped"], "entry_too_large");
}

#[test]
fn test_044_debug_logs_mixed_good_malformed_and_non_utf8_entries() {
    if maybe_run_child("test_044_debug_logs_mixed_good_malformed_and_non_utf8_entries") {
        return;
    }

    let run = run_debug_logs_child(
        "test_044_debug_logs_mixed_good_malformed_and_non_utf8_entries",
        "mixed",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 3);
    assert_eq!(values[0]["event"], "good");
    assert_eq!(values[1]["malformed"], "{bad-json");
    assert_eq!(values[2]["non_utf8_hex"], "ff0042");
}

#[test]
fn test_045_debug_logs_total_budget_limits_export_count() {
    if maybe_run_child("test_045_debug_logs_total_budget_limits_export_count") {
        return;
    }

    let run = run_debug_logs_child(
        "test_045_debug_logs_total_budget_limits_export_count",
        "over_budget",
        "yes\n",
    );

    let values = exported_values(&run);
    assert!(!values.is_empty());
    assert!(values.len() < 6);
}

#[test]
fn test_046_debug_logs_many_small_entries_exports_all_ten() {
    if maybe_run_child("test_046_debug_logs_many_small_entries_exports_all_ten") {
        return;
    }

    let run = run_debug_logs_child(
        "test_046_debug_logs_many_small_entries_exports_all_ten",
        "many_small_10",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 10);
    assert_eq!(values[0]["idx"], 0);
    assert_eq!(values[9]["idx"], 9);
}

#[test]
fn test_047_debug_logs_many_small_entries_exports_all_fifty() {
    if maybe_run_child("test_047_debug_logs_many_small_entries_exports_all_fifty") {
        return;
    }

    let run = run_debug_logs_child(
        "test_047_debug_logs_many_small_entries_exports_all_fifty",
        "many_small_50",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 50);
    assert_eq!(values[0]["idx"], 0);
    assert_eq!(values[49]["idx"], 49);
}

#[test]
fn test_048_debug_logs_duplicate_values_are_not_deduplicated() {
    if maybe_run_child("test_048_debug_logs_duplicate_values_are_not_deduplicated") {
        return;
    }

    let run = run_debug_logs_child(
        "test_048_debug_logs_duplicate_values_are_not_deduplicated",
        "duplicate_values",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 2);
    assert_eq!(values[0], values[1]);
}

#[test]
fn test_049_debug_logs_large_and_small_exports_marker_then_small() {
    if maybe_run_child("test_049_debug_logs_large_and_small_exports_marker_then_small") {
        return;
    }

    let run = run_debug_logs_child(
        "test_049_debug_logs_large_and_small_exports_marker_then_small",
        "large_and_small",
        "yes\n",
    );

    let values = exported_values(&run);
    assert_eq!(values.len(), 2);
    assert_eq!(values[0]["skipped"], "entry_too_large");
    assert_eq!(values[1]["event"], "after-large");
}

#[test]
fn test_050_debug_logs_output_is_pretty_json_array() {
    if maybe_run_child("test_050_debug_logs_output_is_pretty_json_array") {
        return;
    }

    let run = run_debug_logs_child(
        "test_050_debug_logs_output_is_pretty_json_array",
        "one_json",
        "yes\n",
    );

    let output = run
        .output_file
        .as_ref()
        .unwrap_or_else(|| panic!("expected output file"));
    assert!(output.starts_with("[\n"));
    assert!(output.contains("  {"));
    assert!(output.ends_with("]\n") || output.ends_with(']'));
}
