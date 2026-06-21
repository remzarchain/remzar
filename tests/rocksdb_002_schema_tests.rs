use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use remzar::storage::rocksdb_002_schema::RockDbSchema;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use rust_rocksdb::DB;
use std::collections::BTreeSet;
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
            "remzar_rocksdb_002_schema_{test_name}_{}_{}",
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

fn make_directory(temp: &TempTree, name: &str) -> Result<DirectoryDB, String> {
    DirectoryDB::from_base_dir(&temp.child(name))
}

fn expected_full_cf_names() -> Vec<&'static str> {
    vec![
        "default",
        GlobalConfiguration::META_DATA_COLUMN_NAME,
        GlobalConfiguration::GLOBAL_COLUMN_NAME,
        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME,
        GlobalConfiguration::STATE_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        GlobalConfiguration::REWARD_COLUMN_NAME,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        GlobalConfiguration::LOGS_COLUMN_NAME,
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::IDENTITY_COLUMN_NAME,
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
    ]
}

fn expected_log_cf_names() -> Vec<&'static str> {
    vec!["default", GlobalConfiguration::LOGS_COLUMN_NAME]
}

fn list_cf_set(path: &Path) -> Result<BTreeSet<String>, String> {
    let opts = RockDbSchema::robust_db_options();

    DB::list_cf(&opts, path)
        .map(|names| names.into_iter().collect::<BTreeSet<_>>())
        .map_err(debug_err)
}

fn expected_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn assert_cf_set_equals(path: &Path, expected: &[&str]) -> TestResult {
    let actual = list_cf_set(path)?;

    assert_eq!(actual, expected_set(expected));

    Ok(())
}

fn database_error_details<T>(result: Result<T, ErrorDetection>) -> Result<String, String> {
    match result {
        Ok(_) => Err("expected database error but got Ok".to_owned()),
        Err(ErrorDetection::DatabaseError { details }) => Ok(details),
        Err(other) => Err(format!("unexpected error variant: {other:?}")),
    }
}

fn create_default_only_db(path: &Path) -> TestResult {
    let opts = RockDbSchema::robust_db_options();
    let db = DB::open(&opts, path).map_err(debug_err)?;
    drop(db);

    Ok(())
}

#[test]
fn schema_001_meta_data_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_001")?;

    assert_eq!(
        RockDbSchema::meta_data_column_name(),
        GlobalConfiguration::META_DATA_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_002_global_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_002")?;

    assert_eq!(
        RockDbSchema::global_column_name(),
        GlobalConfiguration::GLOBAL_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_003_account_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_003")?;

    assert_eq!(
        RockDbSchema::account_column_name(),
        GlobalConfiguration::ACCOUNT_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_004_network_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_004")?;

    assert_eq!(
        RockDbSchema::network_column_name(),
        GlobalConfiguration::NETWORK_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_005_sidechain_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_005")?;

    assert_eq!(
        RockDbSchema::sidechain_column_name(),
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_006_state_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_006")?;

    assert_eq!(
        RockDbSchema::state_column_name(),
        GlobalConfiguration::STATE_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_007_transaction_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_007")?;

    assert_eq!(
        RockDbSchema::transaction_column_name(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_008_transaction_batch_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_008")?;

    assert_eq!(
        RockDbSchema::transaction_batch_column_name(),
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_009_reward_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_009")?;

    assert_eq!(
        RockDbSchema::reward_column_name(),
        GlobalConfiguration::REWARD_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_010_reward_batch_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_010")?;

    assert_eq!(
        RockDbSchema::reward_batch_column_name(),
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_011_blockmint_data_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_011")?;

    assert_eq!(
        RockDbSchema::blockmint_data_column_name(),
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_012_logs_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_012")?;

    assert_eq!(
        RockDbSchema::logs_column_name(),
        GlobalConfiguration::LOGS_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_013_block_to_hash_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_013")?;

    assert_eq!(
        RockDbSchema::block_to_hash_column_name(),
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_014_tx_to_hash_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_014")?;

    assert_eq!(
        RockDbSchema::tx_to_hash_column_name(),
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_015_block_meta_by_hash_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_015")?;

    assert_eq!(
        RockDbSchema::block_meta_by_hash_column_name(),
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_016_batch_by_block_hash_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_016")?;

    assert_eq!(
        RockDbSchema::batch_by_block_hash_column_name(),
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_017_canonical_height_to_hash_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_017")?;

    assert_eq!(
        RockDbSchema::canonical_height_to_hash_column_name(),
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_018_canonical_chain_view_column_name_matches_global_configuration() -> TestResult {
    let _temp = TempTree::new("schema_018")?;

    assert_eq!(
        RockDbSchema::canonical_chain_view_column_name(),
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn schema_019_robust_db_options_can_create_default_only_database() -> TestResult {
    let temp = TempTree::new("schema_019")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn schema_020_snapshot_audit_options_can_create_database() -> TestResult {
    let temp = TempTree::new("schema_020")?;
    let path = temp.child("audit_snapshot_db");
    let opts = RockDbSchema::snapshot_audit_data();

    let db = DB::open(&opts, &path).map_err(debug_err)?;
    drop(db);

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn schema_021_snapshot_blockmint_options_can_create_database() -> TestResult {
    let temp = TempTree::new("schema_021")?;
    let path = temp.child("blockmint_snapshot_db");
    let opts = RockDbSchema::snapshot_blockmint_data();

    let db = DB::open(&opts, &path).map_err(debug_err)?;
    drop(db);

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn schema_022_snapshot_accountmodel_options_can_create_database() -> TestResult {
    let temp = TempTree::new("schema_022")?;
    let path = temp.child("accountmodel_snapshot_db");
    let opts = RockDbSchema::snapshot_accountmodel_data();

    let db = DB::open(&opts, &path).map_err(debug_err)?;
    drop(db);

    assert!(path.is_dir());

    Ok(())
}

#[test]
fn schema_023_open_cli_db_creates_full_schema_column_families() -> TestResult {
    let temp = TempTree::new("schema_023")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.db_path, &expected_full_cf_names())
}

#[test]
fn schema_024_open_blockchain_db_creates_full_schema_column_families() -> TestResult {
    let temp = TempTree::new("schema_024")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())
}

#[test]
fn schema_025_open_state_db_uses_blockchain_path_with_full_schema() -> TestResult {
    let temp = TempTree::new("schema_025")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_state_db(&directory).map_err(debug_err)?;
    drop(db);

    assert!(directory.blockchain_path.is_dir());
    assert!(!directory.accountmodel_path.exists());
    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())
}

#[test]
fn schema_026_open_registry_db_creates_full_schema_column_families() -> TestResult {
    let temp = TempTree::new("schema_026")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.registry_path, &expected_full_cf_names())
}

#[test]
fn schema_027_open_log_db_creates_default_and_logs_column_families_only() -> TestResult {
    let temp = TempTree::new("schema_027")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.log_path, &expected_log_cf_names())
}

#[test]
fn schema_028_validate_column_families_passes_for_full_blockchain_schema() -> TestResult {
    let temp = TempTree::new("schema_028")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(&directory.blockchain_path, &expected_full_cf_names())?;

    Ok(())
}

#[test]
fn schema_029_validate_column_families_passes_for_log_schema() -> TestResult {
    let temp = TempTree::new("schema_029")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(&directory.log_path, &expected_log_cf_names())?;

    Ok(())
}

#[test]
fn schema_030_validate_column_families_fails_when_required_cf_is_missing() -> TestResult {
    let temp = TempTree::new("schema_030")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    let err = RockDbSchema::validate_column_families(
        &directory.log_path,
        &[GlobalConfiguration::TRANSACTION_COLUMN_NAME],
    )
    .expect_err("transaction_data must be missing from log-only DB");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains(GlobalConfiguration::TRANSACTION_COLUMN_NAME));

    Ok(())
}

#[test]
fn schema_031_validate_column_families_fails_for_missing_database_path() -> TestResult {
    let temp = TempTree::new("schema_031")?;
    let missing_path = temp.child("missing_db");

    let err = RockDbSchema::validate_column_families(&missing_path, &["default"])
        .expect_err("missing database path must fail column family listing");

    assert!(err.contains("Failed to list column families"));

    Ok(())
}

#[test]
fn schema_032_validate_db_integrity_passes_for_default_only_database() -> TestResult {
    let temp = TempTree::new("schema_032")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    RockDbSchema::validate_db_integrity(&path)?;

    Ok(())
}

#[test]
fn schema_033_validate_db_integrity_fails_for_missing_database_path() -> TestResult {
    let temp = TempTree::new("schema_033")?;
    let missing_path = temp.child("missing_db");

    let err = RockDbSchema::validate_db_integrity(&missing_path)
        .expect_err("missing database path must fail integrity validation");

    assert!(err.contains("might be missing or corrupted"));
    assert!(err.contains(&missing_path.display().to_string()));

    Ok(())
}

#[test]
fn schema_034_open_cli_db_error_mentions_cli_and_path_when_parent_is_file() -> TestResult {
    let temp = TempTree::new("schema_034")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let directory = DirectoryDB::from_base_dir(&file_base)?;
    let details = database_error_details(RockDbSchema::open_cli_db(&directory))?;

    assert!(details.contains("Failed to open CLI RocksDB"));
    assert!(details.contains(&directory.db_path.display().to_string()));

    Ok(())
}

#[test]
fn schema_035_open_blockchain_db_error_mentions_blockchain_and_path_when_parent_is_file()
-> TestResult {
    let temp = TempTree::new("schema_035")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let directory = DirectoryDB::from_base_dir(&file_base)?;
    let details = database_error_details(RockDbSchema::open_blockchain_db(&directory))?;

    assert!(details.contains("Failed to open Blockchain RocksDB"));
    assert!(details.contains(&directory.blockchain_path.display().to_string()));

    Ok(())
}

#[test]
fn schema_036_open_registry_db_error_mentions_registry_and_path_when_parent_is_file() -> TestResult
{
    let temp = TempTree::new("schema_036")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let directory = DirectoryDB::from_base_dir(&file_base)?;
    let details = database_error_details(RockDbSchema::open_registry_db(&directory))?;

    assert!(details.contains("Failed to open Registry RocksDB"));
    assert!(details.contains(&directory.registry_path.display().to_string()));

    Ok(())
}

#[test]
fn schema_037_open_log_db_error_mentions_log_and_path_when_parent_is_file() -> TestResult {
    let temp = TempTree::new("schema_037")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let directory = DirectoryDB::from_base_dir(&file_base)?;
    let details = database_error_details(RockDbSchema::open_log_db(&directory))?;

    assert!(details.contains("Failed to open Log RocksDB"));
    assert!(details.contains(&directory.log_path.display().to_string()));

    Ok(())
}

#[test]
fn schema_038_cf_descriptors_and_schema_expected_full_names_match() -> TestResult {
    let descriptor_names = CFDescriptors::get_cf_descriptors()
        .into_iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect::<Vec<_>>();

    let expected_names = expected_full_cf_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert_eq!(descriptor_names, expected_names);

    Ok(())
}

#[test]
fn schema_039_load_repeated_log_database_creation_uses_same_two_cf_schema() -> TestResult {
    let temp = TempTree::new("schema_039")?;

    for index in 0..24 {
        let directory = make_directory(&temp, &format!("node_{index:02}"))?;
        let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
        drop(db);

        assert_cf_set_equals(&directory.log_path, &expected_log_cf_names())?;
    }

    Ok(())
}

#[test]
fn schema_040_adversarial_parallel_blockchain_database_open_uses_isolated_full_schemas()
-> TestResult {
    let temp = TempTree::new("schema_040")?;
    let mut handles = Vec::new();

    for index in 0..16 {
        let base = temp.child(&format!("parallel_node_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<BTreeSet<String>, String> {
                let directory = DirectoryDB::from_base_dir(&base)?;
                let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
                drop(db);

                list_cf_set(&directory.blockchain_path)
            },
        ));
    }

    let expected = expected_set(&expected_full_cf_names());

    for handle in handles {
        let actual = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel database worker panicked".to_owned()),
        };

        assert_eq!(actual, expected);
    }

    Ok(())
}

#[test]
fn schema_041_validate_column_families_passes_for_default_on_cli_db() -> TestResult {
    let temp = TempTree::new("schema_041")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(&directory.db_path, &["default"])?;

    Ok(())
}

#[test]
fn schema_042_validate_column_families_passes_for_blockchain_subset() -> TestResult {
    let temp = TempTree::new("schema_042")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(
        &directory.blockchain_path,
        &[
            "default",
            GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
            GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
        ],
    )?;

    Ok(())
}

#[test]
fn schema_043_validate_column_families_passes_for_registry_subset() -> TestResult {
    let temp = TempTree::new("schema_043")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(
        &directory.registry_path,
        &[
            "default",
            GlobalConfiguration::NETWORK_COLUMN_NAME,
            GlobalConfiguration::REWARD_COLUMN_NAME,
        ],
    )?;

    Ok(())
}

#[test]
fn schema_044_validate_column_families_passes_for_log_cf_only() -> TestResult {
    let temp = TempTree::new("schema_044")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(
        &directory.log_path,
        &[GlobalConfiguration::LOGS_COLUMN_NAME],
    )?;

    Ok(())
}

#[test]
fn schema_045_validate_column_families_accepts_duplicate_expected_full_schema_entries() -> TestResult
{
    let temp = TempTree::new("schema_045")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(
        &directory.blockchain_path,
        &[
            "default",
            "default",
            GlobalConfiguration::STATE_COLUMN_NAME,
            GlobalConfiguration::STATE_COLUMN_NAME,
        ],
    )?;

    Ok(())
}

#[test]
fn schema_046_validate_column_families_accepts_duplicate_expected_log_entries() -> TestResult {
    let temp = TempTree::new("schema_046")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(
        &directory.log_path,
        &[
            "default",
            "default",
            GlobalConfiguration::LOGS_COLUMN_NAME,
            GlobalConfiguration::LOGS_COLUMN_NAME,
        ],
    )?;

    Ok(())
}

#[test]
fn schema_047_validate_column_families_error_mentions_found_list() -> TestResult {
    let temp = TempTree::new("schema_047")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    let err = RockDbSchema::validate_column_families(
        &directory.log_path,
        &[GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME],
    )
    .expect_err("blockmint CF must be missing from log DB");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains("Found:"));
    assert!(err.contains(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME));
    assert!(err.contains(GlobalConfiguration::LOGS_COLUMN_NAME));

    Ok(())
}

#[test]
fn schema_048_default_only_database_fails_when_logs_cf_is_required() -> TestResult {
    let temp = TempTree::new("schema_048")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    let err =
        RockDbSchema::validate_column_families(&path, &[GlobalConfiguration::LOGS_COLUMN_NAME])
            .expect_err("logs CF must be missing from default-only database");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains(GlobalConfiguration::LOGS_COLUMN_NAME));

    Ok(())
}

#[test]
fn schema_049_open_cli_db_upgrades_default_only_db_to_full_schema() -> TestResult {
    let temp = TempTree::new("schema_049")?;
    let directory = make_directory(&temp, "node")?;

    create_default_only_db(&directory.db_path)?;

    let db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.db_path, &expected_full_cf_names())
}

#[test]
fn schema_050_open_log_db_upgrades_default_only_db_to_log_schema() -> TestResult {
    let temp = TempTree::new("schema_050")?;
    let directory = make_directory(&temp, "node")?;

    create_default_only_db(&directory.log_path)?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.log_path, &expected_log_cf_names())
}

#[test]
fn schema_051_open_blockchain_db_twice_sequentially_keeps_full_schema() -> TestResult {
    let temp = TempTree::new("schema_051")?;
    let directory = make_directory(&temp, "node")?;

    let first = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(first);

    let second = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(second);

    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())
}

#[test]
fn schema_052_open_registry_db_twice_sequentially_keeps_full_schema() -> TestResult {
    let temp = TempTree::new("schema_052")?;
    let directory = make_directory(&temp, "node")?;

    let first = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(first);

    let second = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(second);

    assert_cf_set_equals(&directory.registry_path, &expected_full_cf_names())
}

#[test]
fn schema_053_open_log_db_twice_sequentially_keeps_log_schema() -> TestResult {
    let temp = TempTree::new("schema_053")?;
    let directory = make_directory(&temp, "node")?;

    let first = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(first);

    let second = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(second);

    assert_cf_set_equals(&directory.log_path, &expected_log_cf_names())
}

#[test]
fn schema_054_open_state_db_after_blockchain_db_uses_same_full_schema_path() -> TestResult {
    let temp = TempTree::new("schema_054")?;
    let directory = make_directory(&temp, "node")?;

    let blockchain_db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(blockchain_db);

    let state_db = RockDbSchema::open_state_db(&directory).map_err(debug_err)?;
    drop(state_db);

    assert!(directory.blockchain_path.is_dir());
    assert!(!directory.accountmodel_path.exists());
    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())
}

#[test]
fn schema_055_open_blockchain_db_after_state_db_uses_same_full_schema_path() -> TestResult {
    let temp = TempTree::new("schema_055")?;
    let directory = make_directory(&temp, "node")?;

    let state_db = RockDbSchema::open_state_db(&directory).map_err(debug_err)?;
    drop(state_db);

    let blockchain_db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(blockchain_db);

    assert!(directory.blockchain_path.is_dir());
    assert!(!directory.accountmodel_path.exists());
    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())
}

#[test]
fn schema_056_cli_and_blockchain_databases_use_separate_paths() -> TestResult {
    let temp = TempTree::new("schema_056")?;
    let directory = make_directory(&temp, "node")?;

    let cli_db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
    drop(cli_db);

    let blockchain_db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(blockchain_db);

    assert_ne!(directory.db_path, directory.blockchain_path);
    assert_cf_set_equals(&directory.db_path, &expected_full_cf_names())?;
    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())?;

    Ok(())
}

#[test]
fn schema_057_registry_and_log_databases_use_separate_schemas_and_paths() -> TestResult {
    let temp = TempTree::new("schema_057")?;
    let directory = make_directory(&temp, "node")?;

    let registry_db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(registry_db);

    let log_db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(log_db);

    assert_ne!(directory.registry_path, directory.log_path);
    assert_cf_set_equals(&directory.registry_path, &expected_full_cf_names())?;
    assert_cf_set_equals(&directory.log_path, &expected_log_cf_names())?;

    Ok(())
}

#[test]
fn schema_058_log_schema_is_subset_of_full_schema_names() -> TestResult {
    let full = expected_set(&expected_full_cf_names());

    for name in expected_log_cf_names() {
        assert!(
            full.contains(name),
            "log schema name missing from full schema: {name}"
        );
    }

    Ok(())
}

#[test]
fn schema_059_expected_full_schema_has_no_duplicate_names() -> TestResult {
    let names = expected_full_cf_names();
    let unique = expected_set(&names);

    assert_eq!(names.len(), unique.len());

    Ok(())
}

#[test]
fn schema_060_expected_log_schema_has_no_duplicate_names() -> TestResult {
    let names = expected_log_cf_names();
    let unique = expected_set(&names);

    assert_eq!(names.len(), unique.len());

    Ok(())
}

#[test]
fn schema_061_validate_db_integrity_passes_for_snapshot_audit_database() -> TestResult {
    let temp = TempTree::new("schema_061")?;
    let path = temp.child("audit_snapshot_db");
    let opts = RockDbSchema::snapshot_audit_data();

    let db = DB::open(&opts, &path).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_db_integrity(&path)?;

    Ok(())
}

#[test]
fn schema_062_validate_db_integrity_passes_for_snapshot_blockmint_database() -> TestResult {
    let temp = TempTree::new("schema_062")?;
    let path = temp.child("blockmint_snapshot_db");
    let opts = RockDbSchema::snapshot_blockmint_data();

    let db = DB::open(&opts, &path).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_db_integrity(&path)?;

    Ok(())
}

#[test]
fn schema_063_validate_db_integrity_passes_for_snapshot_accountmodel_database() -> TestResult {
    let temp = TempTree::new("schema_063")?;
    let path = temp.child("accountmodel_snapshot_db");
    let opts = RockDbSchema::snapshot_accountmodel_data();

    let db = DB::open(&opts, &path).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_db_integrity(&path)?;

    Ok(())
}

#[test]
fn schema_064_validate_column_families_with_empty_expected_list_passes_on_existing_db() -> TestResult
{
    let temp = TempTree::new("schema_064")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    RockDbSchema::validate_column_families(&path, &[])?;

    Ok(())
}

#[test]
fn schema_065_validate_column_families_with_empty_expected_list_fails_on_missing_db() -> TestResult
{
    let temp = TempTree::new("schema_065")?;
    let missing_path = temp.child("missing_db");

    let err = RockDbSchema::validate_column_families(&missing_path, &[])
        .expect_err("missing db should fail even when expected CF list is empty");

    assert!(err.contains("Failed to list column families"));

    Ok(())
}

#[test]
fn schema_066_validate_column_families_reports_first_missing_required_cf() -> TestResult {
    let temp = TempTree::new("schema_066")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    let first_missing = GlobalConfiguration::STATE_COLUMN_NAME;
    let second_missing = GlobalConfiguration::TRANSACTION_COLUMN_NAME;

    let err = RockDbSchema::validate_column_families(
        &directory.log_path,
        &[first_missing, second_missing],
    )
    .expect_err("state CF must be missing from log DB");

    assert!(err.contains(first_missing));

    Ok(())
}

#[test]
fn schema_067_validate_column_families_missing_name_is_case_sensitive() -> TestResult {
    let temp = TempTree::new("schema_067")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    let uppercase = GlobalConfiguration::STATE_COLUMN_NAME.to_ascii_uppercase();

    let err = RockDbSchema::validate_column_families(&directory.blockchain_path, &[&uppercase])
        .expect_err("uppercase CF name must not match lowercase production CF");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains(&uppercase));

    Ok(())
}

#[test]
fn schema_068_validate_column_families_missing_name_with_trailing_space_is_distinct() -> TestResult
{
    let temp = TempTree::new("schema_068")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    let name_with_space = format!("{} ", GlobalConfiguration::STATE_COLUMN_NAME);

    let err =
        RockDbSchema::validate_column_families(&directory.blockchain_path, &[&name_with_space])
            .expect_err("CF name with trailing space must not match exact production CF");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains(&name_with_space));

    Ok(())
}

#[test]
fn schema_069_open_cli_db_creates_parent_database_directory() -> TestResult {
    let temp = TempTree::new("schema_069")?;
    let directory = make_directory(&temp, "node")?;

    assert!(!directory.db_path.exists());

    let db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
    drop(db);

    assert!(directory.db_path.is_dir());

    Ok(())
}

#[test]
fn schema_070_open_blockchain_db_creates_parent_database_directory() -> TestResult {
    let temp = TempTree::new("schema_070")?;
    let directory = make_directory(&temp, "node")?;

    assert!(!directory.blockchain_path.exists());

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    assert!(directory.blockchain_path.is_dir());

    Ok(())
}

#[test]
fn schema_071_open_registry_db_creates_parent_database_directory() -> TestResult {
    let temp = TempTree::new("schema_071")?;
    let directory = make_directory(&temp, "node")?;

    assert!(!directory.registry_path.exists());

    let db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(db);

    assert!(directory.registry_path.is_dir());

    Ok(())
}

#[test]
fn schema_072_open_log_db_creates_parent_database_directory() -> TestResult {
    let temp = TempTree::new("schema_072")?;
    let directory = make_directory(&temp, "node")?;

    assert!(!directory.log_path.exists());

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    assert!(directory.log_path.is_dir());

    Ok(())
}

#[test]
fn schema_073_open_state_db_creates_blockchain_directory_not_accountmodel_directory() -> TestResult
{
    let temp = TempTree::new("schema_073")?;
    let directory = make_directory(&temp, "node")?;

    assert!(!directory.blockchain_path.exists());
    assert!(!directory.accountmodel_path.exists());

    let db = RockDbSchema::open_state_db(&directory).map_err(debug_err)?;
    drop(db);

    assert!(directory.blockchain_path.is_dir());
    assert!(!directory.accountmodel_path.exists());

    Ok(())
}

#[test]
fn schema_074_open_all_main_schema_databases_on_one_directory() -> TestResult {
    let temp = TempTree::new("schema_074")?;
    let directory = make_directory(&temp, "node")?;

    let cli_db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
    drop(cli_db);

    let blockchain_db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(blockchain_db);

    let registry_db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(registry_db);

    let log_db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(log_db);

    assert_cf_set_equals(&directory.db_path, &expected_full_cf_names())?;
    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())?;
    assert_cf_set_equals(&directory.registry_path, &expected_full_cf_names())?;
    assert_cf_set_equals(&directory.log_path, &expected_log_cf_names())?;

    Ok(())
}

#[test]
fn schema_075_open_state_db_and_registry_db_do_not_share_paths() -> TestResult {
    let temp = TempTree::new("schema_075")?;
    let directory = make_directory(&temp, "node")?;

    let state_db = RockDbSchema::open_state_db(&directory).map_err(debug_err)?;
    drop(state_db);

    let registry_db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(registry_db);

    assert_ne!(directory.blockchain_path, directory.registry_path);
    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())?;
    assert_cf_set_equals(&directory.registry_path, &expected_full_cf_names())?;

    Ok(())
}

#[test]
fn schema_076_load_repeated_cli_database_creation_uses_full_schema() -> TestResult {
    let temp = TempTree::new("schema_076")?;

    for index in 0..24 {
        let directory = make_directory(&temp, &format!("node_{index:02}"))?;
        let db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
        drop(db);

        assert_cf_set_equals(&directory.db_path, &expected_full_cf_names())?;
    }

    Ok(())
}

#[test]
fn schema_077_load_repeated_registry_database_creation_uses_full_schema() -> TestResult {
    let temp = TempTree::new("schema_077")?;

    for index in 0..24 {
        let directory = make_directory(&temp, &format!("node_{index:02}"))?;
        let db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
        drop(db);

        assert_cf_set_equals(&directory.registry_path, &expected_full_cf_names())?;
    }

    Ok(())
}

#[test]
fn schema_078_load_repeated_state_database_creation_uses_blockchain_path() -> TestResult {
    let temp = TempTree::new("schema_078")?;

    for index in 0..24 {
        let directory = make_directory(&temp, &format!("node_{index:02}"))?;
        let db = RockDbSchema::open_state_db(&directory).map_err(debug_err)?;
        drop(db);

        assert!(directory.blockchain_path.is_dir());
        assert!(!directory.accountmodel_path.exists());
        assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())?;
    }

    Ok(())
}

#[test]
fn schema_079_adversarial_parallel_log_database_open_uses_isolated_log_schemas() -> TestResult {
    let temp = TempTree::new("schema_079")?;
    let mut handles = Vec::new();

    for index in 0..16 {
        let base = temp.child(&format!("parallel_log_node_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<BTreeSet<String>, String> {
                let directory = DirectoryDB::from_base_dir(&base)?;
                let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
                drop(db);

                list_cf_set(&directory.log_path)
            },
        ));
    }

    let expected = expected_set(&expected_log_cf_names());

    for handle in handles {
        let actual = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel log database worker panicked".to_owned()),
        };

        assert_eq!(actual, expected);
    }

    Ok(())
}

#[test]
fn schema_080_adversarial_parallel_cli_database_open_uses_isolated_full_schemas() -> TestResult {
    let temp = TempTree::new("schema_080")?;
    let mut handles = Vec::new();

    for index in 0..16 {
        let base = temp.child(&format!("parallel_cli_node_{index:02}"));

        handles.push(thread::spawn(
            move || -> Result<BTreeSet<String>, String> {
                let directory = DirectoryDB::from_base_dir(&base)?;
                let db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
                drop(db);

                list_cf_set(&directory.db_path)
            },
        ));
    }

    let expected = expected_set(&expected_full_cf_names());

    for handle in handles {
        let actual = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("parallel cli database worker panicked".to_owned()),
        };

        assert_eq!(actual, expected);
    }

    Ok(())
}

#[test]
fn schema_081_vector_all_public_column_name_getters_are_non_empty() -> TestResult {
    let names = [
        RockDbSchema::meta_data_column_name(),
        RockDbSchema::global_column_name(),
        RockDbSchema::account_column_name(),
        RockDbSchema::network_column_name(),
        RockDbSchema::sidechain_column_name(),
        RockDbSchema::state_column_name(),
        RockDbSchema::transaction_column_name(),
        RockDbSchema::transaction_batch_column_name(),
        RockDbSchema::reward_column_name(),
        RockDbSchema::reward_batch_column_name(),
        RockDbSchema::blockmint_data_column_name(),
        RockDbSchema::logs_column_name(),
        RockDbSchema::block_to_hash_column_name(),
        RockDbSchema::tx_to_hash_column_name(),
        RockDbSchema::block_meta_by_hash_column_name(),
        RockDbSchema::batch_by_block_hash_column_name(),
        RockDbSchema::canonical_height_to_hash_column_name(),
        RockDbSchema::canonical_chain_view_column_name(),
    ];

    for name in names {
        assert!(!name.is_empty());
    }

    Ok(())
}

#[test]
fn schema_082_vector_all_public_column_name_getters_are_in_full_schema() -> TestResult {
    let full_schema = expected_set(&expected_full_cf_names());

    let getter_names = [
        RockDbSchema::meta_data_column_name(),
        RockDbSchema::global_column_name(),
        RockDbSchema::account_column_name(),
        RockDbSchema::network_column_name(),
        RockDbSchema::sidechain_column_name(),
        RockDbSchema::state_column_name(),
        RockDbSchema::transaction_column_name(),
        RockDbSchema::transaction_batch_column_name(),
        RockDbSchema::reward_column_name(),
        RockDbSchema::reward_batch_column_name(),
        RockDbSchema::blockmint_data_column_name(),
        RockDbSchema::logs_column_name(),
        RockDbSchema::block_to_hash_column_name(),
        RockDbSchema::tx_to_hash_column_name(),
        RockDbSchema::block_meta_by_hash_column_name(),
        RockDbSchema::batch_by_block_hash_column_name(),
        RockDbSchema::canonical_height_to_hash_column_name(),
        RockDbSchema::canonical_chain_view_column_name(),
    ];

    for name in getter_names {
        assert!(
            full_schema.contains(name),
            "getter name missing from full schema: {name}"
        );
    }

    Ok(())
}

#[test]
fn schema_083_vector_logs_column_name_is_in_log_schema() -> TestResult {
    let log_schema = expected_set(&expected_log_cf_names());

    assert!(log_schema.contains(RockDbSchema::logs_column_name()));
    assert!(log_schema.contains("default"));

    Ok(())
}

#[test]
fn schema_084_vector_full_schema_contains_default_and_total_columns() -> TestResult {
    let full_schema = expected_full_cf_names();

    assert_eq!(full_schema.len(), GlobalConfiguration::TOTAL_COLUMNS + 1);
    assert_eq!(full_schema[0], "default");

    Ok(())
}

#[test]
fn schema_085_vector_log_schema_contains_exactly_default_and_logs() -> TestResult {
    let log_schema = expected_log_cf_names();

    assert_eq!(
        log_schema,
        vec!["default", GlobalConfiguration::LOGS_COLUMN_NAME]
    );

    Ok(())
}

#[test]
fn schema_086_edge_validate_column_families_is_order_independent_for_required_names() -> TestResult
{
    let temp = TempTree::new("schema_086")?;
    let directory = make_directory(&temp, "node")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    RockDbSchema::validate_column_families(
        &directory.blockchain_path,
        &[
            GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            "default",
            GlobalConfiguration::META_DATA_COLUMN_NAME,
        ],
    )?;

    Ok(())
}

#[test]
fn schema_087_edge_validate_column_families_is_case_sensitive_for_default() -> TestResult {
    let temp = TempTree::new("schema_087")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    let err = RockDbSchema::validate_column_families(&path, &["DEFAULT"])
        .expect_err("uppercase DEFAULT must not match default CF");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains("DEFAULT"));

    Ok(())
}

#[test]
fn schema_088_edge_validate_column_families_treats_trailing_space_as_distinct() -> TestResult {
    let temp = TempTree::new("schema_088")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    let err = RockDbSchema::validate_column_families(&path, &["default "])
        .expect_err("default with trailing space must not match default CF");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains("default "));

    Ok(())
}

#[test]
fn schema_089_edge_validate_column_families_treats_leading_space_as_distinct() -> TestResult {
    let temp = TempTree::new("schema_089")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    let err = RockDbSchema::validate_column_families(&path, &[" default"])
        .expect_err("default with leading space must not match default CF");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains(" default"));

    Ok(())
}

#[test]
fn schema_090_edge_validate_column_families_unknown_unicode_name_is_missing() -> TestResult {
    let temp = TempTree::new("schema_090")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    let missing = "unknown_δ_测试";
    let err = RockDbSchema::validate_column_families(&path, &[missing])
        .expect_err("unknown unicode CF must be missing");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains(missing));

    Ok(())
}

#[test]
fn schema_091_edge_validate_column_families_unknown_punctuation_name_is_missing() -> TestResult {
    let temp = TempTree::new("schema_091")?;
    let path = temp.child("default_only_db");

    create_default_only_db(&path)?;

    let missing = "future.cf-name:v2@network#1";
    let err = RockDbSchema::validate_column_families(&path, &[missing])
        .expect_err("unknown punctuation CF must be missing");

    assert!(err.contains("Missing required column family"));
    assert!(err.contains(missing));

    Ok(())
}

#[test]
fn schema_092_edge_validate_column_families_fails_when_db_path_is_plain_file() -> TestResult {
    let temp = TempTree::new("schema_092")?;
    let file_path = temp.child("plain_file_not_db");

    fs::write(&file_path, b"not rocksdb").map_err(debug_err)?;

    let err = RockDbSchema::validate_column_families(&file_path, &["default"])
        .expect_err("plain file path must fail CF listing");

    assert!(err.contains("Failed to list column families"));

    Ok(())
}

#[test]
fn schema_093_edge_validate_db_integrity_fails_when_path_is_plain_file() -> TestResult {
    let temp = TempTree::new("schema_093")?;
    let file_path = temp.child("plain_file_not_db");

    fs::write(&file_path, b"not rocksdb").map_err(debug_err)?;

    let err = RockDbSchema::validate_db_integrity(&file_path)
        .expect_err("plain file path must fail integrity validation");

    assert!(err.contains("might be missing or corrupted"));
    assert!(err.contains(&file_path.display().to_string()));

    Ok(())
}

#[test]
fn schema_094_edge_open_state_db_error_mentions_accountmodel_even_though_path_is_blockchain()
-> TestResult {
    let temp = TempTree::new("schema_094")?;
    let file_base = temp.child("base_file");

    fs::write(&file_base, b"not a directory").map_err(debug_err)?;

    let directory = DirectoryDB::from_base_dir(&file_base)?;
    let details = database_error_details(RockDbSchema::open_state_db(&directory))?;

    assert!(details.contains("Failed to open AccountModelTree RocksDB"));
    assert!(details.contains(&directory.blockchain_path.display().to_string()));

    Ok(())
}

#[test]
fn schema_095_edge_open_cli_db_with_spaces_in_base_path() -> TestResult {
    let temp = TempTree::new("schema_095")?;
    let directory = make_directory(&temp, "node with spaces")?;

    let db = RockDbSchema::open_cli_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.db_path, &expected_full_cf_names())
}

#[test]
fn schema_096_edge_open_blockchain_db_with_dotted_base_name() -> TestResult {
    let temp = TempTree::new("schema_096")?;
    let directory = make_directory(&temp, "node.with.dots")?;

    let db = RockDbSchema::open_blockchain_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.blockchain_path, &expected_full_cf_names())
}

#[test]
fn schema_097_edge_open_registry_db_with_dash_base_name() -> TestResult {
    let temp = TempTree::new("schema_097")?;
    let directory = make_directory(&temp, "node-with-dashes")?;

    let db = RockDbSchema::open_registry_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.registry_path, &expected_full_cf_names())
}

#[test]
fn schema_098_edge_open_log_db_with_underscore_base_name() -> TestResult {
    let temp = TempTree::new("schema_098")?;
    let directory = make_directory(&temp, "node_with_underscores")?;

    let db = RockDbSchema::open_log_db(&directory).map_err(debug_err)?;
    drop(db);

    assert_cf_set_equals(&directory.log_path, &expected_log_cf_names())
}

#[test]
fn schema_099_vector_full_schema_column_family_names_are_all_safe_ascii_identifiers() -> TestResult
{
    for name in expected_full_cf_names() {
        assert!(
            name.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
            "unsafe full schema CF name: {name}"
        );
    }

    Ok(())
}

#[test]
fn schema_100_vector_log_schema_column_family_names_are_subset_of_full_schema() -> TestResult {
    let full_schema = expected_set(&expected_full_cf_names());

    for name in expected_log_cf_names() {
        assert!(full_schema.contains(name));
    }

    Ok(())
}
