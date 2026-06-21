use remzar::storage::rocksdb_007_db_guard::enforce_db_ownership;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

type TestResult = Result<(), String>;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Result<Self, String> {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_db_guard_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            let _remove_result = fs::remove_dir_all(&root);
        }

        fs::create_dir_all(&root)
            .map_err(|err| format!("failed to create temp root '{}': {err}", root.display()))?;

        Ok(Self { root })
    }

    fn child(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _remove_result = fs::remove_dir_all(&self.root);
    }
}

fn debug_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn storage_error_message<T>(result: Result<T, ErrorDetection>) -> Result<String, String> {
    match result {
        Ok(_) => Err("expected StorageError but got Ok".to_owned()),
        Err(ErrorDetection::StorageError { message }) => Ok(message),
        Err(other) => Err(format!("unexpected error variant: {other:?}")),
    }
}

fn database_error_details<T>(result: Result<T, ErrorDetection>) -> Result<String, String> {
    match result {
        Ok(_) => Err("expected DatabaseError but got Ok".to_owned()),
        Err(ErrorDetection::DatabaseError { details }) => Ok(details),
        Err(other) => Err(format!("unexpected error variant: {other:?}")),
    }
}

fn validation_error_message<T>(result: Result<T, ErrorDetection>) -> Result<String, String> {
    match result {
        Ok(_) => Err("expected ValidationError but got Ok".to_owned()),
        Err(ErrorDetection::ValidationError { message, .. }) => Ok(message),
        Err(other) => Err(format!("unexpected error variant: {other:?}")),
    }
}

fn owner_path(db_dir: &Path) -> Result<PathBuf, String> {
    Ok(fs::canonicalize(db_dir).map_err(debug_err)?.join("OWNER"))
}

fn lock_path(db_dir: &Path) -> Result<PathBuf, String> {
    Ok(fs::canonicalize(db_dir)
        .map_err(debug_err)?
        .join(".remzar_db.lock"))
}

fn read_owner(db_dir: &Path) -> Result<String, String> {
    fs::read_to_string(owner_path(db_dir)?).map_err(debug_err)
}

fn write_owner_raw(db_dir: &Path, value: &[u8]) -> TestResult {
    fs::create_dir_all(db_dir).map_err(debug_err)?;
    fs::write(db_dir.join("OWNER"), value).map_err(debug_err)
}

fn assert_owner_text(db_dir: &Path, expected: &str) -> TestResult {
    let actual = read_owner(db_dir)?;

    assert_eq!(actual, expected);

    Ok(())
}

#[test]
fn db_guard_001_creates_missing_db_directory() -> TestResult {
    let temp = TempTree::new("db_guard_001")?;
    let db_dir = temp.child("missing_db");

    assert!(!db_dir.exists());

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.is_dir());
    assert!(guard.db_dir.is_dir());

    Ok(())
}

#[test]
fn db_guard_002_creates_owner_file_for_new_directory() -> TestResult {
    let temp = TempTree::new("db_guard_002")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_003_creates_lock_file_for_new_directory() -> TestResult {
    let temp = TempTree::new("db_guard_003")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(lock_path(&db_dir)?.is_file());

    Ok(())
}

#[test]
fn db_guard_004_returns_canonical_db_dir() -> TestResult {
    let temp = TempTree::new("db_guard_004")?;
    let db_dir = temp.child("db");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_eq!(guard.db_dir, fs::canonicalize(&db_dir).map_err(debug_err)?);

    Ok(())
}

#[test]
fn db_guard_005_dot_component_path_returns_canonical_db_dir() -> TestResult {
    let temp = TempTree::new("db_guard_005")?;
    let db_dir = temp.child("base").join(".").join("db");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_eq!(guard.db_dir, fs::canonicalize(&db_dir).map_err(debug_err)?);

    Ok(())
}

#[test]
fn db_guard_006_reacquire_same_owner_after_drop_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_006")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_007_second_guard_same_owner_while_locked_fails() -> TestResult {
    let temp = TempTree::new("db_guard_007")?;
    let db_dir = temp.child("db");

    let _first_guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    let details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(details.contains("already in use"));
    assert!(details.contains("lock held"));

    Ok(())
}

#[test]
fn db_guard_008_second_guard_different_owner_while_locked_fails_on_lock() -> TestResult {
    let temp = TempTree::new("db_guard_008")?;
    let db_dir = temp.child("db");

    let _first_guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    let details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    assert!(details.contains("already in use"));
    assert!(details.contains("lock held"));

    Ok(())
}

#[test]
fn db_guard_009_different_owner_after_drop_fails_on_owner_mismatch() -> TestResult {
    let temp = TempTree::new("db_guard_009")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    assert!(details.contains("DB ownership mismatch"));
    assert!(details.contains("node-a"));
    assert!(details.contains("node-b"));

    Ok(())
}

#[test]
fn db_guard_010_owner_mismatch_does_not_modify_owner_file() -> TestResult {
    let temp = TempTree::new("db_guard_010")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_011_existing_owner_without_newline_same_node_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_011")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a")
}

#[test]
fn db_guard_012_existing_owner_with_newline_same_node_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_012")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a\n")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_013_existing_owner_with_extra_newlines_same_node_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_013")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a\n\n")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a\n\n")
}

#[test]
fn db_guard_014_existing_owner_with_surrounding_spaces_matches_trimmed_owner() -> TestResult {
    let temp = TempTree::new("db_guard_014")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"  node-a  \n")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "  node-a  \n")
}

#[test]
fn db_guard_015_existing_owner_case_sensitive_mismatch_fails() -> TestResult {
    let temp = TempTree::new("db_guard_015")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"Node-A\n")?;

    let details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(details.contains("DB ownership mismatch"));
    assert!(details.contains("Node-A"));
    assert!(details.contains("node-a"));

    Ok(())
}

#[test]
fn db_guard_016_empty_node_id_is_rejected_without_creating_directory() -> TestResult {
    let temp = TempTree::new("db_guard_016")?;
    let db_dir = temp.child("db");

    let message = validation_error_message(enforce_db_ownership(&db_dir, ""))?;

    assert!(message.contains("non-empty"));
    assert!(!db_dir.exists());

    Ok(())
}
#[test]
fn db_guard_017_empty_node_id_is_rejected_even_when_directory_exists() -> TestResult {
    let temp = TempTree::new("db_guard_017")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(&db_dir).map_err(debug_err)?;

    let message = validation_error_message(enforce_db_ownership(&db_dir, ""))?;

    assert!(message.contains("non-empty"));
    assert!(!db_dir.join("OWNER").exists());

    Ok(())
}
#[test]
fn db_guard_018_unicode_node_id_round_trips() -> TestResult {
    let temp = TempTree::new("db_guard_018")?;
    let db_dir = temp.child("db");
    let node_id = "node-δ-测试";

    let _guard = enforce_db_ownership(&db_dir, node_id).map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-δ-测试\n")
}

#[test]
fn db_guard_019_unicode_node_id_reacquires_successfully() -> TestResult {
    let temp = TempTree::new("db_guard_019")?;
    let db_dir = temp.child("db");
    let node_id = "node-δ-测试";

    {
        let _guard = enforce_db_ownership(&db_dir, node_id).map_err(debug_err)?;
    }

    let _guard = enforce_db_ownership(&db_dir, node_id).map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-δ-测试\n")
}

#[test]
fn db_guard_020_too_long_node_id_is_rejected_without_owner_file() -> TestResult {
    let temp = TempTree::new("db_guard_020")?;
    let db_dir = temp.child("db");
    let node_id = format!("node-{}", "x".repeat(4096));

    let message = validation_error_message(enforce_db_ownership(&db_dir, &node_id))?;

    assert!(message.contains("too long"));
    assert!(!db_dir.exists());

    Ok(())
}
#[test]
fn db_guard_021_node_id_with_internal_spaces_round_trips() -> TestResult {
    let temp = TempTree::new("db_guard_021")?;
    let db_dir = temp.child("db");
    let node_id = "node with internal spaces";

    let _guard = enforce_db_ownership(&db_dir, node_id).map_err(debug_err)?;

    assert_owner_text(&db_dir, "node with internal spaces\n")
}

#[test]
fn db_guard_022_node_id_with_hyphen_round_trips() -> TestResult {
    let temp = TempTree::new("db_guard_022")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-alpha-001").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-alpha-001\n")
}

#[test]
fn db_guard_023_node_id_with_underscore_round_trips() -> TestResult {
    let temp = TempTree::new("db_guard_023")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node_alpha_001").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node_alpha_001\n")
}

#[test]
fn db_guard_024_node_id_with_colon_round_trips() -> TestResult {
    let temp = TempTree::new("db_guard_024")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node:alpha:001").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node:alpha:001\n")
}

#[test]
fn db_guard_025_node_id_with_null_byte_is_rejected() -> TestResult {
    let temp = TempTree::new("db_guard_025")?;
    let db_dir = temp.child("db");
    let node_id = "node\0alpha";

    let message = validation_error_message(enforce_db_ownership(&db_dir, node_id))?;

    assert!(message.contains("ASCII control bytes"));
    assert!(!db_dir.exists());

    Ok(())
}
#[test]
fn db_guard_026_node_id_with_internal_newline_is_rejected() -> TestResult {
    let temp = TempTree::new("db_guard_026")?;
    let db_dir = temp.child("db");
    let node_id = "node\nalpha";

    let message = validation_error_message(enforce_db_ownership(&db_dir, node_id))?;

    assert!(message.contains("ASCII control bytes"));
    assert!(!db_dir.exists());

    Ok(())
}
#[test]
fn db_guard_027_node_id_with_trailing_space_is_rejected() -> TestResult {
    let temp = TempTree::new("db_guard_027")?;
    let db_dir = temp.child("db");
    let node_id = "node-a ";

    let message = validation_error_message(enforce_db_ownership(&db_dir, node_id))?;

    assert!(message.contains("leading/trailing whitespace"));
    assert!(!db_dir.exists());

    Ok(())
}
#[test]
fn db_guard_028_node_id_with_leading_space_is_rejected() -> TestResult {
    let temp = TempTree::new("db_guard_028")?;
    let db_dir = temp.child("db");
    let node_id = " node-a";

    let message = validation_error_message(enforce_db_ownership(&db_dir, node_id))?;

    assert!(message.contains("leading/trailing whitespace"));
    assert!(!db_dir.exists());

    Ok(())
}
#[test]
fn db_guard_029_existing_invalid_utf8_owner_returns_storage_error() -> TestResult {
    let temp = TempTree::new("db_guard_029")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, &[0xff, 0xfe, 0xfd])?;

    let message = storage_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(message.contains("Failed reading OWNER file"));

    Ok(())
}

#[test]
fn db_guard_030_owner_path_as_directory_returns_storage_error() -> TestResult {
    let temp = TempTree::new("db_guard_030")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join("OWNER")).map_err(debug_err)?;

    let message = storage_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(message.contains("Failed reading OWNER file"));

    Ok(())
}

#[test]
fn db_guard_031_lock_path_as_directory_returns_database_error() -> TestResult {
    let temp = TempTree::new("db_guard_031")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join(".remzar_db.lock")).map_err(debug_err)?;

    let details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(details.contains("Failed to open lockfile"));
    assert!(details.contains(".remzar_db.lock"));

    Ok(())
}

#[test]
fn db_guard_032_legacy_owner_tmp_directory_is_ignored_when_owner_missing() -> TestResult {
    let temp = TempTree::new("db_guard_032")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join("OWNER.tmp")).map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(
        &db_dir, "node-a
",
    )?;
    assert!(db_dir.join("OWNER.tmp").is_dir());

    Ok(())
}
#[test]
fn db_guard_033_legacy_owner_tmp_file_is_ignored_when_owner_missing() -> TestResult {
    let temp = TempTree::new("db_guard_033")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(&db_dir).map_err(debug_err)?;
    fs::write(db_dir.join("OWNER.tmp"), b"old-temp").map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(
        &db_dir, "node-a
",
    )?;
    assert_eq!(
        fs::read(db_dir.join("OWNER.tmp")).map_err(debug_err)?,
        b"old-temp"
    );

    Ok(())
}
#[test]
fn db_guard_034_leftover_owner_tmp_directory_is_ignored_when_owner_exists() -> TestResult {
    let temp = TempTree::new("db_guard_034")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a\n")?;
    fs::create_dir_all(db_dir.join("OWNER.tmp")).map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.join("OWNER.tmp").is_dir());
    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_035_db_dir_path_that_is_plain_file_returns_storage_error() -> TestResult {
    let temp = TempTree::new("db_guard_035")?;
    let db_dir = temp.child("not_a_directory");

    fs::write(&db_dir, b"plain file").map_err(debug_err)?;

    let message = storage_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(!message.is_empty());

    Ok(())
}

#[test]
fn db_guard_036_db_dir_parent_that_is_plain_file_returns_storage_error() -> TestResult {
    let temp = TempTree::new("db_guard_036")?;
    let parent_file = temp.child("parent_file");

    fs::write(&parent_file, b"plain file").map_err(debug_err)?;

    let db_dir = parent_file.join("child_db");
    let message = storage_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(!message.is_empty());

    Ok(())
}

#[test]
fn db_guard_037_nested_missing_directory_is_created() -> TestResult {
    let temp = TempTree::new("db_guard_037")?;
    let db_dir = temp.child("a").join("b").join("c").join("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.is_dir());
    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_038_directory_with_spaces_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_038")?;
    let db_dir = temp.child("db with spaces");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(guard.db_dir.is_dir());
    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_039_directory_with_unicode_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_039")?;
    let db_dir = temp.child("db_δ_测试");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(guard.db_dir.is_dir());
    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_040_directory_with_dots_and_dashes_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_040")?;
    let db_dir = temp.child("db.with.dots-and-dashes");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(guard.db_dir.is_dir());
    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_041_lock_released_after_guard_drop_allows_same_owner() -> TestResult {
    let temp = TempTree::new("db_guard_041")?;
    let db_dir = temp.child("db");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    drop(guard);

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_042_lock_released_after_owner_mismatch_error() -> TestResult {
    let temp = TempTree::new("db_guard_042")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_043_lock_released_after_invalid_owner_read_error() -> TestResult {
    let temp = TempTree::new("db_guard_043")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, &[0xff, 0xfe])?;

    let _message = storage_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    fs::write(db_dir.join("OWNER"), b"node-a\n").map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_044_lock_file_is_not_truncated_on_successful_open() -> TestResult {
    let temp = TempTree::new("db_guard_044")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(&db_dir).map_err(debug_err)?;
    fs::write(db_dir.join(".remzar_db.lock"), b"old-lock-contents").map_err(debug_err)?;

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
        assert!(lock_path(&db_dir)?.is_file());
    }

    // On Windows, the lockfile may not be readable while the lock is held.
    // Read it only after DbGuard drops. The hardened guard must not truncate it.
    let contents = fs::read(lock_path(&db_dir)?).map_err(debug_err)?;
    assert_eq!(contents, b"old-lock-contents");

    Ok(())
}

#[test]
fn db_guard_045_existing_empty_owner_is_rejected_as_invalid_owner() -> TestResult {
    let temp = TempTree::new("db_guard_045")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"")?;

    let message = validation_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(message.contains("non-empty"));
    assert_owner_text(&db_dir, "")
}
#[test]
fn db_guard_046_existing_empty_owner_does_not_get_rewritten() -> TestResult {
    let temp = TempTree::new("db_guard_046")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"")?;

    let _message = validation_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    assert_owner_text(&db_dir, "")
}
#[test]
fn db_guard_047_existing_whitespace_only_owner_is_rejected() -> TestResult {
    let temp = TempTree::new("db_guard_047")?;
    let db_dir = temp.child("db");

    write_owner_raw(
        &db_dir, b" 
	",
    )?;

    let message = validation_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(message.contains("non-empty"));
    assert_owner_text(
        &db_dir, " 
	",
    )
}
#[test]
fn db_guard_048_space_node_id_is_rejected_before_owner_read() -> TestResult {
    let temp = TempTree::new("db_guard_048")?;
    let db_dir = temp.child("db");

    write_owner_raw(
        &db_dir, b" 
",
    )?;

    let message = validation_error_message(enforce_db_ownership(&db_dir, " "))?;

    assert!(message.contains("non-empty"));
    assert_owner_text(
        &db_dir, " 
",
    )
}
#[test]
fn db_guard_049_existing_owner_with_tabs_trim_matches_node_id() -> TestResult {
    let temp = TempTree::new("db_guard_049")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"\tnode-a\t\n")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_050_existing_owner_with_carriage_return_trim_matches_node_id() -> TestResult {
    let temp = TempTree::new("db_guard_050")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a\r\n")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_051_owner_mismatch_message_contains_canonical_dir() -> TestResult {
    let temp = TempTree::new("db_guard_051")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a\n")?;

    let details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;
    let canonical = fs::canonicalize(&db_dir).map_err(debug_err)?;

    assert!(details.contains(&canonical.display().to_string()));

    Ok(())
}

#[test]
fn db_guard_052_lock_held_message_contains_canonical_dir() -> TestResult {
    let temp = TempTree::new("db_guard_052")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    let details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;
    let canonical = fs::canonicalize(&db_dir).map_err(debug_err)?;

    assert!(details.contains(&canonical.display().to_string()));

    Ok(())
}

#[test]
fn db_guard_053_multiple_sequential_same_owner_reacquires_succeed() -> TestResult {
    let temp = TempTree::new("db_guard_053")?;
    let db_dir = temp.child("db");

    for _ in 0..10 {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_054_multiple_sequential_mismatched_owner_attempts_do_not_change_owner() -> TestResult {
    let temp = TempTree::new("db_guard_054")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    for index in 0..10 {
        let node_id = format!("node-b-{index}");
        let _details = database_error_details(enforce_db_ownership(&db_dir, &node_id))?;
    }

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_055_owner_file_is_not_created_when_lock_file_open_fails() -> TestResult {
    let temp = TempTree::new("db_guard_055")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join(".remzar_db.lock")).map_err(debug_err)?;

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(!db_dir.join("OWNER").exists());

    Ok(())
}

#[test]
fn db_guard_056_owner_file_is_created_when_legacy_owner_tmp_is_directory() -> TestResult {
    let temp = TempTree::new("db_guard_056")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join("OWNER.tmp")).map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(
        &db_dir, "node-a
",
    )?;
    assert!(db_dir.join("OWNER.tmp").is_dir());

    Ok(())
}
#[test]
fn db_guard_057_lock_file_exists_after_owner_mismatch() -> TestResult {
    let temp = TempTree::new("db_guard_057")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    assert!(lock_path(&db_dir)?.is_file());

    Ok(())
}

#[test]
fn db_guard_058_owner_file_exists_after_owner_mismatch() -> TestResult {
    let temp = TempTree::new("db_guard_058")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_059_canonical_spelling_and_dot_spelling_conflict_while_locked() -> TestResult {
    let temp = TempTree::new("db_guard_059")?;
    let db_dir = temp.child("base").join("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    let dot_spelling = temp.child("base").join(".").join("db");
    let details = database_error_details(enforce_db_ownership(&dot_spelling, "node-a"))?;

    assert!(details.contains("already in use"));

    Ok(())
}

#[test]
fn db_guard_060_canonical_spelling_and_dot_spelling_reacquire_after_drop() -> TestResult {
    let temp = TempTree::new("db_guard_060")?;
    let db_dir = temp.child("base").join("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let dot_spelling = temp.child("base").join(".").join("db");
    let _guard = enforce_db_ownership(&dot_spelling, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_061_parallel_only_one_guard_can_hold_same_directory() -> TestResult {
    let temp = TempTree::new("db_guard_061")?;
    let db_dir = temp.child("db");

    let first_guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    let second_path = db_dir.clone();

    let handle = thread::spawn(move || -> Result<String, String> {
        database_error_details(enforce_db_ownership(&second_path, "node-a"))
    });

    let details = match handle.join() {
        Ok(result) => result?,
        Err(_) => return Err("lock worker panicked".to_owned()),
    };

    assert!(details.contains("already in use"));

    drop(first_guard);

    Ok(())
}

#[test]
fn db_guard_062_parallel_reacquire_after_guard_drop_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_062")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let second_path = db_dir.clone();
    let handle = thread::spawn(move || -> Result<PathBuf, String> {
        let guard = enforce_db_ownership(&second_path, "node-a").map_err(debug_err)?;

        Ok(guard.db_dir)
    });

    let canonical = match handle.join() {
        Ok(result) => result?,
        Err(_) => return Err("reacquire worker panicked".to_owned()),
    };

    assert_eq!(canonical, fs::canonicalize(&db_dir).map_err(debug_err)?);

    Ok(())
}

#[test]
fn db_guard_063_parallel_distinct_directories_can_be_guarded() -> TestResult {
    let temp = TempTree::new("db_guard_063")?;
    let mut handles = Vec::new();

    for index in 0..16 {
        let db_dir = temp.child(&format!("db_{index:02}"));

        handles.push(thread::spawn(move || -> Result<String, String> {
            let node_id = format!("node-{index:02}");
            let guard = enforce_db_ownership(&db_dir, &node_id).map_err(debug_err)?;

            assert!(guard.db_dir.is_dir());

            Ok(fs::read_to_string(db_dir.join("OWNER")).map_err(debug_err)?)
        }));
    }

    for (index, handle) in handles.into_iter().enumerate() {
        let owner = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel distinct directory worker panicked".to_owned()),
        };

        assert_eq!(owner, format!("node-{index:02}\n"));
    }

    Ok(())
}

#[test]
fn db_guard_064_parallel_distinct_directories_create_lock_files() -> TestResult {
    let temp = TempTree::new("db_guard_064")?;
    let mut handles = Vec::new();

    for index in 0..16 {
        let db_dir = temp.child(&format!("db_{index:02}"));

        handles.push(thread::spawn(move || -> Result<bool, String> {
            let node_id = format!("node-{index:02}");
            let guard = enforce_db_ownership(&db_dir, &node_id).map_err(debug_err)?;
            let lock_file_exists = guard.db_dir.join(".remzar_db.lock").is_file();

            Ok(lock_file_exists)
        }));
    }

    for handle in handles {
        let exists = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel lock file worker panicked".to_owned()),
        };

        assert!(exists);
    }

    Ok(())
}

#[test]
fn db_guard_065_vector_valid_node_ids_round_trip() -> TestResult {
    let temp = TempTree::new("db_guard_065")?;
    let node_ids = [
        "node-a",
        "node-001",
        "NODE_UPPER",
        "node.with.dots",
        "node:with:colon",
        "node_δ_测试",
    ];

    for (index, node_id) in node_ids.into_iter().enumerate() {
        let db_dir = temp.child(&format!("db_{index:02}"));
        let _guard = enforce_db_ownership(&db_dir, node_id).map_err(debug_err)?;

        assert_owner_text(
            &db_dir,
            &format!(
                "{node_id}
"
            ),
        )?;
    }

    Ok(())
}
#[test]
fn db_guard_066_vector_owner_trim_cases_match_node_id() -> TestResult {
    let temp = TempTree::new("db_guard_066")?;
    let cases = [
        b"node-a\n".as_slice(),
        b"node-a\r\n".as_slice(),
        b" node-a ".as_slice(),
        b"\tnode-a\t".as_slice(),
        b"\nnode-a\n".as_slice(),
    ];

    for (index, owner_bytes) in cases.into_iter().enumerate() {
        let db_dir = temp.child(&format!("db_{index:02}"));

        write_owner_raw(&db_dir, owner_bytes)?;

        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    Ok(())
}

#[test]
fn db_guard_067_vector_owner_mismatch_cases_fail() -> TestResult {
    let temp = TempTree::new("db_guard_067")?;
    let cases = [
        b"node-b\n".as_slice(),
        b"NODE-A\n".as_slice(),
        b"node-a-x\n".as_slice(),
        b"x-node-a\n".as_slice(),
    ];

    for (index, owner_bytes) in cases.into_iter().enumerate() {
        let db_dir = temp.child(&format!("db_{index:02}"));

        write_owner_raw(&db_dir, owner_bytes)?;

        let details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

        assert!(details.contains("DB ownership mismatch"));
    }

    Ok(())
}

#[test]
fn db_guard_068_vector_nested_directories_are_created() -> TestResult {
    let temp = TempTree::new("db_guard_068")?;

    for index in 0..12 {
        let db_dir = temp
            .child("nested")
            .join(format!("level-{index}"))
            .join("a")
            .join("b")
            .join("db");

        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

        assert!(db_dir.is_dir());
    }

    Ok(())
}

#[test]
fn db_guard_069_load_repeated_create_and_reacquire_same_owner() -> TestResult {
    let temp = TempTree::new("db_guard_069")?;
    let db_dir = temp.child("db");

    for _ in 0..100 {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_070_load_many_distinct_directories() -> TestResult {
    let temp = TempTree::new("db_guard_070")?;

    for index in 0..100 {
        let db_dir = temp.child(&format!("db_{index:03}"));
        let node_id = format!("node-{index:03}");

        let _guard = enforce_db_ownership(&db_dir, &node_id).map_err(debug_err)?;

        assert_owner_text(&db_dir, &format!("{node_id}\n"))?;
    }

    Ok(())
}

#[test]
fn db_guard_071_load_many_mismatch_attempts_preserve_owner() -> TestResult {
    let temp = TempTree::new("db_guard_071")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    for index in 0..100 {
        let node_id = format!("other-node-{index:03}");
        let details = database_error_details(enforce_db_ownership(&db_dir, &node_id))?;

        assert!(details.contains("DB ownership mismatch"));
    }

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_072_owner_file_can_be_repaired_after_invalid_utf8() -> TestResult {
    let temp = TempTree::new("db_guard_072")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, &[0xff, 0xfe])?;

    let _message = storage_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    fs::write(db_dir.join("OWNER"), b"node-a\n").map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_073_owner_file_can_be_repaired_after_directory_owner_error() -> TestResult {
    let temp = TempTree::new("db_guard_073")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join("OWNER")).map_err(debug_err)?;

    let _message = storage_error_message(enforce_db_ownership(&db_dir, "node-a"))?;

    fs::remove_dir_all(db_dir.join("OWNER")).map_err(debug_err)?;
    fs::write(db_dir.join("OWNER"), b"node-a\n").map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_074_lock_file_directory_can_be_repaired() -> TestResult {
    let temp = TempTree::new("db_guard_074")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join(".remzar_db.lock")).map_err(debug_err)?;

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

    fs::remove_dir_all(db_dir.join(".remzar_db.lock")).map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_075_legacy_owner_tmp_directory_does_not_block_owner_creation() -> TestResult {
    let temp = TempTree::new("db_guard_075")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join("OWNER.tmp")).map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.join("OWNER.tmp").is_dir());
    assert_owner_text(
        &db_dir, "node-a
",
    )
}
#[test]
fn db_guard_076_existing_owner_is_not_rewritten_on_successful_match() -> TestResult {
    let temp = TempTree::new("db_guard_076")?;
    let db_dir = temp.child("db");
    let original = b"  node-a  \n\n";

    write_owner_raw(&db_dir, original)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    let contents = fs::read(db_dir.join("OWNER")).map_err(debug_err)?;

    assert_eq!(contents, original);

    Ok(())
}

#[test]
fn db_guard_077_owner_created_by_atomic_rename_leaves_no_tmp_file() -> TestResult {
    let temp = TempTree::new("db_guard_077")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(!db_dir.join("OWNER.tmp").exists());

    Ok(())
}

#[test]
fn db_guard_078_lock_and_owner_are_created_in_same_canonical_dir() -> TestResult {
    let temp = TempTree::new("db_guard_078")?;
    let db_dir = temp.child("db");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_eq!(guard.db_dir.join("OWNER"), owner_path(&db_dir)?);
    assert_eq!(guard.db_dir.join(".remzar_db.lock"), lock_path(&db_dir)?);

    Ok(())
}

#[test]
fn db_guard_079_owner_mismatch_error_leaves_lock_available_for_owner() -> TestResult {
    let temp = TempTree::new("db_guard_079")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_080_lock_error_does_not_change_existing_owner() -> TestResult {
    let temp = TempTree::new("db_guard_080")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_081_vector_created_files_are_regular_files() -> TestResult {
    let temp = TempTree::new("db_guard_081")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.join("OWNER").is_file());
    assert!(db_dir.join(".remzar_db.lock").is_file());

    Ok(())
}

#[test]
fn db_guard_082_vector_owner_file_name_is_exact() -> TestResult {
    let temp = TempTree::new("db_guard_082")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.join("OWNER").exists());

    let entries = fs::read_dir(&db_dir)
        .map_err(debug_err)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();

    assert!(
        entries.iter().any(|name| name == "OWNER"),
        "expected exact OWNER entry in directory listing: {entries:?}"
    );

    assert!(
        !entries.iter().any(|name| name == "owner"),
        "did not expect a separate lowercase owner entry: {entries:?}"
    );

    Ok(())
}

#[test]
fn db_guard_083_vector_lock_file_name_is_exact() -> TestResult {
    let temp = TempTree::new("db_guard_083")?;
    let db_dir = temp.child("db");

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.join(".remzar_db.lock").exists());
    assert!(!db_dir.join("remzar_db.lock").exists());

    Ok(())
}

#[test]
fn db_guard_084_edge_existing_owner_with_no_final_newline_is_preserved() -> TestResult {
    let temp = TempTree::new("db_guard_084")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a")
}

#[test]
fn db_guard_085_edge_existing_owner_with_crlf_is_preserved() -> TestResult {
    let temp = TempTree::new("db_guard_085")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node-a\r\n")?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a\r\n")
}

#[test]
fn db_guard_086_edge_owner_with_internal_space_is_not_trimmed_in_middle() -> TestResult {
    let temp = TempTree::new("db_guard_086")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node a\n")?;

    let _guard = enforce_db_ownership(&db_dir, "node a").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_087_edge_owner_with_internal_space_mismatch_fails() -> TestResult {
    let temp = TempTree::new("db_guard_087")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node a\n")?;

    let details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

    assert!(details.contains("DB ownership mismatch"));

    Ok(())
}

#[test]
fn db_guard_088_edge_existing_owner_with_unicode_matches() -> TestResult {
    let temp = TempTree::new("db_guard_088")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, "node-δ-测试\n".as_bytes())?;

    let _guard = enforce_db_ownership(&db_dir, "node-δ-测试").map_err(debug_err)?;

    Ok(())
}

#[test]
fn db_guard_089_edge_existing_owner_with_unicode_mismatch_fails() -> TestResult {
    let temp = TempTree::new("db_guard_089")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, "node-δ-测试\n".as_bytes())?;

    let details = database_error_details(enforce_db_ownership(&db_dir, "node-other"))?;

    assert!(details.contains("DB ownership mismatch"));

    Ok(())
}

#[test]
fn db_guard_090_edge_owner_with_null_byte_is_rejected_even_for_same_raw_id() -> TestResult {
    let temp = TempTree::new("db_guard_090")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node\0a\n")?;

    let message = validation_error_message(enforce_db_ownership(&db_dir, "node\0a"))?;

    assert!(message.contains("ASCII control bytes"));
    assert_owner_text(&db_dir, "node\0a\n")
}
#[test]
fn db_guard_091_edge_owner_with_null_byte_is_rejected_before_mismatch_compare() -> TestResult {
    let temp = TempTree::new("db_guard_091")?;
    let db_dir = temp.child("db");

    write_owner_raw(&db_dir, b"node\0a\n")?;

    let message = validation_error_message(enforce_db_ownership(&db_dir, "node"))?;

    assert!(message.contains("ASCII control bytes"));
    assert_owner_text(&db_dir, "node\0a\n")
}
#[test]
fn db_guard_092_edge_precreated_empty_directory_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_092")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(&db_dir).map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, "node-a\n")
}

#[test]
fn db_guard_093_edge_precreated_directory_with_unrelated_file_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_093")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(&db_dir).map_err(debug_err)?;
    fs::write(db_dir.join("unrelated.txt"), b"keep me").map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_eq!(
        fs::read(db_dir.join("unrelated.txt")).map_err(debug_err)?,
        b"keep me"
    );

    Ok(())
}

#[test]
fn db_guard_094_edge_precreated_directory_with_subdirectory_succeeds() -> TestResult {
    let temp = TempTree::new("db_guard_094")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(db_dir.join("subdir")).map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(db_dir.join("subdir").is_dir());

    Ok(())
}

#[test]
fn db_guard_095_edge_owner_mismatch_with_unrelated_files_preserves_unrelated_files() -> TestResult {
    let temp = TempTree::new("db_guard_095")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(&db_dir).map_err(debug_err)?;
    fs::write(db_dir.join("unrelated.txt"), b"keep me").map_err(debug_err)?;
    fs::write(db_dir.join("OWNER"), b"node-a\n").map_err(debug_err)?;

    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-b"))?;

    assert_eq!(
        fs::read(db_dir.join("unrelated.txt")).map_err(debug_err)?,
        b"keep me"
    );

    Ok(())
}

#[test]
fn db_guard_096_edge_lock_conflict_with_unrelated_files_preserves_unrelated_files() -> TestResult {
    let temp = TempTree::new("db_guard_096")?;
    let db_dir = temp.child("db");

    fs::create_dir_all(&db_dir).map_err(debug_err)?;
    fs::write(db_dir.join("unrelated.txt"), b"keep me").map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    let _details = database_error_details(enforce_db_ownership(&db_dir, "node-a"))?;

    assert_eq!(
        fs::read(db_dir.join("unrelated.txt")).map_err(debug_err)?,
        b"keep me"
    );

    Ok(())
}

#[test]
fn db_guard_097_vector_guard_db_dir_starts_with_temp_root_canonical() -> TestResult {
    let temp = TempTree::new("db_guard_097")?;
    let db_dir = temp.child("db");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    let canonical_root = fs::canonicalize(&temp.root).map_err(debug_err)?;

    assert!(guard.db_dir.starts_with(canonical_root));

    Ok(())
}

#[test]
fn db_guard_098_vector_owner_and_lock_paths_are_inside_guard_db_dir() -> TestResult {
    let temp = TempTree::new("db_guard_098")?;
    let db_dir = temp.child("db");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert!(guard.db_dir.join("OWNER").starts_with(&guard.db_dir));
    assert!(
        guard
            .db_dir
            .join(".remzar_db.lock")
            .starts_with(&guard.db_dir)
    );

    Ok(())
}

#[test]
fn db_guard_099_vector_owner_created_once_then_preserved_on_match() -> TestResult {
    let temp = TempTree::new("db_guard_099")?;
    let db_dir = temp.child("db");

    {
        let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;
    }

    fs::write(db_dir.join("OWNER"), b" node-a \n").map_err(debug_err)?;

    let _guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_owner_text(&db_dir, " node-a \n")
}

#[test]
fn db_guard_100_vector_final_owner_and_lock_state_after_success() -> TestResult {
    let temp = TempTree::new("db_guard_100")?;
    let db_dir = temp.child("db");

    let guard = enforce_db_ownership(&db_dir, "final-node").map_err(debug_err)?;

    assert_eq!(guard.db_dir, fs::canonicalize(&db_dir).map_err(debug_err)?);
    assert!(guard.db_dir.join("OWNER").is_file());
    assert!(guard.db_dir.join(".remzar_db.lock").is_file());
    assert_owner_text(&db_dir, "final-node\n")
}

#[test]
fn db_guard_101_guard_exposes_canonical_owner_and_lock_paths() -> TestResult {
    let temp = TempTree::new("db_guard_101")?;
    let db_dir = temp.child("base").join(".").join("db");

    let guard = enforce_db_ownership(&db_dir, "node-a").map_err(debug_err)?;

    assert_eq!(guard.owner_path, guard.db_dir.join("OWNER"));
    assert_eq!(guard.lock_path, guard.db_dir.join(".remzar_db.lock"));
    assert_eq!(guard.owner_path, owner_path(&db_dir)?);
    assert_eq!(guard.lock_path, lock_path(&db_dir)?);

    Ok(())
}

#[test]
fn db_guard_102_node_id_at_256_bytes_round_trips() -> TestResult {
    let temp = TempTree::new("db_guard_102")?;
    let db_dir = temp.child("db");
    let node_id = "n".repeat(256);

    let _guard = enforce_db_ownership(&db_dir, &node_id).map_err(debug_err)?;

    assert_owner_text(&db_dir, &format!("{node_id}\n"))
}
#[test]
fn db_guard_103_node_id_over_256_bytes_is_rejected_without_owner_file() -> TestResult {
    let temp = TempTree::new("db_guard_103")?;
    let db_dir = temp.child("db");
    let node_id = "n".repeat(257);

    let message = validation_error_message(enforce_db_ownership(&db_dir, &node_id))?;

    assert!(message.contains("too long"));
    assert!(!db_dir.exists());

    Ok(())
}

#[test]
fn db_guard_104_node_id_with_forward_slash_is_rejected_without_owner_file() -> TestResult {
    let temp = TempTree::new("db_guard_104")?;
    let db_dir = temp.child("db");

    let message = validation_error_message(enforce_db_ownership(&db_dir, "node/with/slash"))?;

    assert!(message.contains("path separators"));
    assert!(!db_dir.exists());

    Ok(())
}

#[test]
fn db_guard_105_node_id_with_backslash_is_rejected_without_owner_file() -> TestResult {
    let temp = TempTree::new("db_guard_105")?;
    let db_dir = temp.child("db");

    let message = validation_error_message(enforce_db_ownership(&db_dir, "node\\with\\backslash"))?;

    assert!(message.contains("path separators"));
    assert!(!db_dir.exists());

    Ok(())
}
