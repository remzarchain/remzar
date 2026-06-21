use remzar::privacy::privacy_001_private_receive_wallet::{
    PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_METADATA_DIR, PRIVATE_RECEIVE_RECORD_EXT,
    PRIVATE_RECEIVE_VERSION, PrivateRW, PrivateReceiveWalletReceipt, PrivateReceiveWalletRecord,
};
use remzar::privacy::privacy_003_private_wallet_index::{
    MAX_PRIVATE_INDEX_ENTRIES_PER_OWNER, MAX_PRIVATE_INDEX_JSON_BYTES, MAX_PRIVATE_INDEX_OWNERS,
    MAX_PRIVATE_INDEX_TOTAL_ENTRIES, PRIVATE_WALLET_INDEX_BACKUP_FILE_NAME,
    PRIVATE_WALLET_INDEX_FILE_NAME, PRIVATE_WALLET_INDEX_KIND, PRIVATE_WALLET_INDEX_TMP_FILE_NAME,
    PrivateWI, PrivateWalletIndexAddOwnedRequest, PrivateWalletIndexAddRequest,
    PrivateWalletIndexEntry, PrivateWalletIndexFile,
};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const UNIX_2000_SECS: u64 = 946_684_800;
const PWI_TEST_MAX_LABEL_LEN: usize = 96;
const PWI_TEST_MAX_CONTEXT_LEN: usize = 256;

struct TestDataDir {
    root: PathBuf,
}

impl TestDataDir {
    fn as_data_dir_string(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }
}

impl Drop for TestDataDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn test_data_dir(label: &str) -> TestDataDir {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after UNIX_EPOCH")
        .as_nanos();

    let root = std::env::temp_dir().join(format!(
        "remzar_pwi_tests_{label}_{}_{}",
        std::process::id(),
        nanos
    ));

    fs::create_dir_all(&root).expect("test temp dir should be created");

    TestDataDir { root }
}

fn node_opts_for(dir: &TestDataDir, wallet_address: &str) -> NodeOpts {
    NodeOpts {
        identity_file: dir.root.join("identity.key").to_string_lossy().into_owned(),
        data_dir: dir.as_data_dir_string(),
        wallet_address: wallet_address.to_string(),
        ..NodeOpts::default()
    }
}

fn wallet_with_body_char(ch: char) -> String {
    assert!(matches!(ch, '0'..='9' | 'a'..='f'));
    format!("r{}", ch.to_string().repeat(128))
}

fn wallet_a() -> String {
    wallet_with_body_char('a')
}

fn wallet_b() -> String {
    wallet_with_body_char('b')
}

fn wallet_c() -> String {
    wallet_with_body_char('c')
}

fn wallet_d() -> String {
    wallet_with_body_char('d')
}

fn uppercase_wallet_a() -> String {
    format!("R{}", "A".repeat(128))
}

fn uppercase_wallet_b() -> String {
    format!("R{}", "B".repeat(128))
}

fn invoice_for(wallet: &str) -> String {
    format!(
        "{}:v{}:{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, wallet
    )
}

fn assert_err_contains<T, E: std::fmt::Debug>(result: Result<T, E>, expected: &str) {
    match result {
        Ok(_) => panic!("expected error containing '{expected}', got Ok"),
        Err(error) => {
            let text = format!("{error:?}");
            assert!(
                text.contains(expected),
                "expected error containing '{expected}', got: {text}"
            );
        }
    }
}

fn valid_entry(owner_wallet: &str, one_time_wallet: &str) -> PrivateWalletIndexEntry {
    valid_entry_with_times(
        owner_wallet,
        one_time_wallet,
        UNIX_2000_SECS,
        UNIX_2000_SECS + 1,
    )
}

fn valid_entry_with_times(
    owner_wallet: &str,
    one_time_wallet: &str,
    created_unix_secs: u64,
    indexed_unix_secs: u64,
) -> PrivateWalletIndexEntry {
    PrivateWalletIndexEntry {
        version: PRIVATE_RECEIVE_VERSION,
        owner_wallet: owner_wallet.to_string(),
        one_time_wallet: one_time_wallet.to_string(),
        invoice: invoice_for(one_time_wallet),
        wallet_file_name: PrivateRW::wallet_file_name(one_time_wallet),
        created_unix_secs,
        indexed_unix_secs,
        label: None,
        context: None,
    }
}

fn valid_index(entries: Vec<PrivateWalletIndexEntry>) -> PrivateWalletIndexFile {
    let mut entries_by_owner: BTreeMap<String, Vec<PrivateWalletIndexEntry>> = BTreeMap::new();

    for entry in entries {
        entries_by_owner
            .entry(entry.owner_wallet.clone())
            .or_default()
            .push(entry);
    }

    PrivateWalletIndexFile {
        kind: PRIVATE_WALLET_INDEX_KIND.to_string(),
        version: PRIVATE_RECEIVE_VERSION,
        created_unix_secs: UNIX_2000_SECS,
        updated_unix_secs: UNIX_2000_SECS + 1,
        entries_by_owner,
    }
}

fn valid_receipt(owner_wallet: &str, one_time_wallet: &str) -> PrivateReceiveWalletReceipt {
    PrivateReceiveWalletReceipt {
        version: PRIVATE_RECEIVE_VERSION,
        owner_wallet: owner_wallet.to_string(),
        one_time_wallet: one_time_wallet.to_string(),
        invoice: invoice_for(one_time_wallet),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_path: "/tmp/remzar/test.wallet".to_string(),
        metadata_file_path: "/tmp/remzar/private_receive/test.prw.json".to_string(),
    }
}

fn valid_record(owner_wallet: &str, one_time_wallet: &str) -> PrivateReceiveWalletRecord {
    PrivateReceiveWalletRecord {
        version: PRIVATE_RECEIVE_VERSION,
        kind: "remzar_private_receive_wallet".to_string(),
        owner_wallet: owner_wallet.to_string(),
        one_time_wallet: one_time_wallet.to_string(),
        invoice: invoice_for(one_time_wallet),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_name: PrivateRW::wallet_file_name(one_time_wallet),
    }
}

fn directory_for(opts: &NodeOpts) -> DirectoryDB {
    DirectoryDB::from_node_opts(opts).expect("DirectoryDB should initialize")
}

fn create_wallets_dir(opts: &NodeOpts) -> DirectoryDB {
    let directory = directory_for(opts);
    directory
        .create_wallets_directory()
        .expect("wallets directory should be created");
    directory
}

fn create_one_time_wallet_placeholder(opts: &NodeOpts, one_time_wallet: &str) -> PathBuf {
    let directory = create_wallets_dir(opts);
    let path = PrivateRW::wallet_file_path(&directory.wallets_path, one_time_wallet);

    fs::write(&path, b"one-time-wallet-placeholder")
        .expect("one-time wallet placeholder should be written");

    path
}

fn write_raw_index_bytes(opts: &NodeOpts, bytes: &[u8]) -> PathBuf {
    let directory = create_wallets_dir(opts);
    let index_path = PrivateWI::index_file_path(&directory.wallets_path);
    let parent = index_path.parent().expect("index path should have parent");

    fs::create_dir_all(parent).expect("private receive dir should be created");
    fs::write(&index_path, bytes).expect("raw index bytes should be written");

    index_path
}

fn write_private_receive_record(opts: &NodeOpts, record: &PrivateReceiveWalletRecord) -> PathBuf {
    let directory = create_wallets_dir(opts);
    let metadata_file =
        PrivateRW::metadata_file_path(&directory.wallets_path, &record.one_time_wallet);
    let parent = metadata_file
        .parent()
        .expect("metadata file should have parent");

    fs::create_dir_all(parent).expect("metadata directory should be created");

    let bytes = serde_json::to_vec_pretty(record).expect("record should serialize");
    fs::write(&metadata_file, bytes).expect("record should be written");

    metadata_file
}

#[test]
fn test_001_constants_are_expected_private_wallet_index_values() {
    assert_eq!(PRIVATE_WALLET_INDEX_KIND, "remzar_private_wallet_index");
    assert_eq!(
        PRIVATE_WALLET_INDEX_FILE_NAME,
        "private_wallet_index_v1.json"
    );
    assert_eq!(
        PRIVATE_WALLET_INDEX_BACKUP_FILE_NAME,
        "private_wallet_index_v1.json.bak"
    );
    assert_eq!(
        PRIVATE_WALLET_INDEX_TMP_FILE_NAME,
        "private_wallet_index_v1.json.tmp"
    );
    assert_eq!(MAX_PRIVATE_INDEX_OWNERS, 100_000);
    assert_eq!(MAX_PRIVATE_INDEX_ENTRIES_PER_OWNER, 100_000);
    assert_eq!(MAX_PRIVATE_INDEX_TOTAL_ENTRIES, 1_000_000);
    assert_eq!(MAX_PRIVATE_INDEX_JSON_BYTES, 128 * 1024 * 1024);
}

#[test]
fn test_002_private_wi_is_stateless_default_constructible_and_zero_sized() {
    let via_new = PrivateWI::new();
    let via_default = PrivateWI::default();

    assert_eq!(format!("{via_new:?}"), format!("{via_default:?}"));
    assert_eq!(std::mem::size_of::<PrivateWI>(), 0);
}

#[test]
fn test_003_wallet_test_vectors_are_exact_canonical_length() {
    assert_eq!(wallet_a().len(), 129);
    assert_eq!(wallet_b().len(), 129);
    assert_eq!(wallet_c().len(), 129);
    assert_eq!(wallet_d().len(), 129);
    assert!(wallet_a().starts_with('r'));
}

#[test]
fn test_004_index_path_helpers_join_private_receive_directory_and_expected_names() {
    let wallets_path = PathBuf::from("wallets");

    assert_eq!(
        PrivateWI::index_file_path(&wallets_path),
        wallets_path
            .join(PRIVATE_RECEIVE_METADATA_DIR)
            .join(PRIVATE_WALLET_INDEX_FILE_NAME)
    );

    assert_eq!(
        PrivateWI::index_tmp_file_path(&wallets_path),
        wallets_path
            .join(PRIVATE_RECEIVE_METADATA_DIR)
            .join(PRIVATE_WALLET_INDEX_TMP_FILE_NAME)
    );

    assert_eq!(
        PrivateWI::index_backup_file_path(&wallets_path),
        wallets_path
            .join(PRIVATE_RECEIVE_METADATA_DIR)
            .join(PRIVATE_WALLET_INDEX_BACKUP_FILE_NAME)
    );
}

#[test]
fn test_005_index_path_from_opts_resolves_to_directory_wallets_private_receive_index() {
    let dir = test_data_dir("005_index_path_from_opts");
    let opts = node_opts_for(&dir, &wallet_a());

    let directory = directory_for(&opts);
    let expected = PrivateWI::index_file_path(&directory.wallets_path);

    let actual = PrivateWI::index_path_from_opts(&opts).expect("index path should resolve");

    assert_eq!(actual, expected);
}

#[test]
fn test_006_validate_entry_accepts_valid_entry() {
    let entry = valid_entry(&wallet_a(), &wallet_b());

    PrivateWI::validate_entry(&entry).expect("valid entry should validate");
}

#[test]
fn test_007_entry_instance_methods_validate_and_short_one_time_wallet() {
    let entry = valid_entry(&wallet_a(), &wallet_b());

    entry
        .validate()
        .expect("entry instance validate should pass");

    let short = entry
        .short_one_time_wallet()
        .expect("short one-time wallet should format");

    assert_eq!(short, "rbbbbbbbb...bbbbbbbb");
}

#[test]
fn test_008_validate_entry_rejects_core_invariant_failures() {
    let mut wrong_version = valid_entry(&wallet_a(), &wallet_b());
    wrong_version.version = PRIVATE_RECEIVE_VERSION + 1;
    assert_err_contains(
        PrivateWI::validate_entry(&wrong_version),
        "entry version mismatch",
    );

    let mut same_wallet = valid_entry(&wallet_a(), &wallet_b());
    same_wallet.one_time_wallet = same_wallet.owner_wallet.clone();
    same_wallet.invoice = invoice_for(&same_wallet.one_time_wallet);
    same_wallet.wallet_file_name = PrivateRW::wallet_file_name(&same_wallet.one_time_wallet);
    assert_err_contains(
        PrivateWI::validate_entry(&same_wallet),
        "owner and one-time wallet cannot be the same",
    );

    let mut invoice_mismatch = valid_entry(&wallet_a(), &wallet_b());
    invoice_mismatch.invoice = invoice_for(&wallet_c());
    assert_err_contains(
        PrivateWI::validate_entry(&invoice_mismatch),
        "invoice does not match one-time wallet",
    );

    let mut raw_wallet_invoice = valid_entry(&wallet_a(), &wallet_b());
    raw_wallet_invoice.invoice = raw_wallet_invoice.one_time_wallet.clone();
    assert_err_contains(
        PrivateWI::validate_entry(&raw_wallet_invoice),
        "invoice is not canonical",
    );
}

#[test]
fn test_009_validate_entry_rejects_filename_timestamp_and_metadata_failures() {
    let mut bad_file = valid_entry(&wallet_a(), &wallet_b());
    bad_file.wallet_file_name = "wrong.wallet".to_string();
    assert_err_contains(
        PrivateWI::validate_entry(&bad_file),
        "wallet_file_name mismatch",
    );

    let mut zero_created = valid_entry(&wallet_a(), &wallet_b());
    zero_created.created_unix_secs = 0;
    assert_err_contains(
        PrivateWI::validate_entry(&zero_created),
        "created_unix_secs cannot be zero",
    );

    let mut zero_indexed = valid_entry(&wallet_a(), &wallet_b());
    zero_indexed.indexed_unix_secs = 0;
    assert_err_contains(
        PrivateWI::validate_entry(&zero_indexed),
        "indexed_unix_secs cannot be zero",
    );

    let mut empty_label = valid_entry(&wallet_a(), &wallet_b());
    empty_label.label = Some("   ".to_string());
    assert_err_contains(
        PrivateWI::validate_entry(&empty_label),
        "label cannot be empty",
    );

    let mut bad_context = valid_entry(&wallet_a(), &wallet_b());
    bad_context.context = Some("bad\ncontext".to_string());
    assert_err_contains(
        PrivateWI::validate_entry(&bad_context),
        "context contains control characters",
    );
}

#[test]
fn test_010_validate_index_file_accepts_valid_empty_index() {
    let index = valid_index(Vec::new());

    PrivateWI::validate_index_file(&index).expect("valid empty index should validate");
}

#[test]
fn test_011_index_file_instance_methods_validate_total_entries_and_owner_count() {
    let index = valid_index(vec![
        valid_entry(&wallet_a(), &wallet_b()),
        valid_entry(&wallet_a(), &wallet_c()),
    ]);

    index
        .validate()
        .expect("index instance validate should pass");

    assert_eq!(index.total_entries(), 2);
    assert_eq!(index.owner_count(), 1);
}

#[test]
fn test_012_validate_index_file_rejects_header_failures() {
    let mut wrong_kind = valid_index(Vec::new());
    wrong_kind.kind = "wrong_kind".to_string();
    assert_err_contains(
        PrivateWI::validate_index_file(&wrong_kind),
        "Invalid private wallet index kind",
    );

    let mut wrong_version = valid_index(Vec::new());
    wrong_version.version = PRIVATE_RECEIVE_VERSION + 1;
    assert_err_contains(
        PrivateWI::validate_index_file(&wrong_version),
        "index version mismatch",
    );

    let mut zero_created = valid_index(Vec::new());
    zero_created.created_unix_secs = 0;
    assert_err_contains(
        PrivateWI::validate_index_file(&zero_created),
        "created_unix_secs cannot be zero",
    );

    let mut zero_updated = valid_index(Vec::new());
    zero_updated.updated_unix_secs = 0;
    assert_err_contains(
        PrivateWI::validate_index_file(&zero_updated),
        "updated_unix_secs cannot be zero",
    );
}

#[test]
fn test_013_validate_index_file_rejects_noncanonical_owner_key() {
    let mut index = valid_index(Vec::new());
    index.entries_by_owner.insert(
        uppercase_wallet_a(),
        vec![valid_entry(&wallet_a(), &wallet_b())],
    );

    assert_err_contains(
        PrivateWI::validate_index_file(&index),
        "owner key is not canonical",
    );
}

#[test]
fn test_014_validate_index_file_rejects_owner_mismatch_and_duplicate_one_time_wallets() {
    let mut owner_mismatch = valid_index(Vec::new());
    owner_mismatch
        .entries_by_owner
        .insert(wallet_a(), vec![valid_entry(&wallet_c(), &wallet_b())]);

    assert_err_contains(
        PrivateWI::validate_index_file(&owner_mismatch),
        "entry owner_wallet does not match owner map key",
    );

    let mut duplicate = valid_index(Vec::new());
    duplicate
        .entries_by_owner
        .insert(wallet_a(), vec![valid_entry(&wallet_a(), &wallet_b())]);
    duplicate
        .entries_by_owner
        .insert(wallet_c(), vec![valid_entry(&wallet_c(), &wallet_b())]);

    assert_err_contains(
        PrivateWI::validate_index_file(&duplicate),
        "Duplicate one-time wallet",
    );
}

#[test]
fn test_015_load_or_new_returns_valid_empty_index_when_file_missing() {
    let dir = test_data_dir("015_load_or_new_missing");
    let opts = node_opts_for(&dir, &wallet_a());

    let index = PrivateWI::new()
        .load_or_new(&opts)
        .expect("missing index should create empty in-memory index");

    assert_eq!(index.kind, PRIVATE_WALLET_INDEX_KIND);
    assert_eq!(index.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(index.total_entries(), 0);
    assert_eq!(index.owner_count(), 0);
    assert!(index.created_unix_secs >= UNIX_2000_SECS);
    assert!(index.updated_unix_secs >= UNIX_2000_SECS);
}

#[test]
fn test_016_load_index_returns_not_found_when_file_missing() {
    let dir = test_data_dir("016_load_index_missing");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().load_index(&opts),
        "Private wallet index not found",
    );
}

#[test]
fn test_017_save_index_then_load_index_roundtrips_valid_empty_index() {
    let dir = test_data_dir("017_save_load_empty");
    let opts = node_opts_for(&dir, &wallet_a());

    let index = valid_index(Vec::new());

    PrivateWI::new()
        .save_index(&opts, &index)
        .expect("empty index should save");

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("saved index should load");

    assert_eq!(loaded, index);
}

#[test]
fn test_018_save_index_then_load_index_roundtrips_single_entry() {
    let dir = test_data_dir("018_save_load_single");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = valid_entry(&wallet_a(), &wallet_b());
    let index = valid_index(vec![entry.clone()]);

    PrivateWI::new()
        .save_index(&opts, &index)
        .expect("index should save");

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("index should load");

    assert_eq!(loaded.total_entries(), 1);
    assert_eq!(
        loaded
            .entries_by_owner
            .get(&wallet_a())
            .unwrap()
            .first()
            .unwrap(),
        &entry
    );
}

#[test]
fn test_019_save_index_canonicalizes_uppercase_owner_wallet_and_invoice() {
    let dir = test_data_dir("019_save_canonicalizes");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut entry = valid_entry(&uppercase_wallet_a(), &uppercase_wallet_b());
    entry.invoice = invoice_for(&uppercase_wallet_b());
    entry.wallet_file_name = PrivateRW::wallet_file_name(&uppercase_wallet_b());

    let mut entries_by_owner = BTreeMap::new();
    entries_by_owner.insert(uppercase_wallet_a(), vec![entry]);

    let index = PrivateWalletIndexFile {
        kind: PRIVATE_WALLET_INDEX_KIND.to_string(),
        version: PRIVATE_RECEIVE_VERSION,
        created_unix_secs: UNIX_2000_SECS,
        updated_unix_secs: UNIX_2000_SECS + 1,
        entries_by_owner,
    };

    PrivateWI::new()
        .save_index(&opts, &index)
        .expect("save should canonicalize index before writing");

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("canonicalized index should load");

    let loaded_entry = loaded
        .entries_by_owner
        .get(&wallet_a())
        .expect("canonical owner key should exist")
        .first()
        .expect("entry should exist");

    assert_eq!(loaded_entry.owner_wallet, wallet_a());
    assert_eq!(loaded_entry.one_time_wallet, wallet_b());
    assert_eq!(loaded_entry.invoice, invoice_for(&wallet_b()));
    assert_eq!(
        loaded_entry.wallet_file_name,
        PrivateRW::wallet_file_name(&wallet_b())
    );
}

#[test]
fn test_020_load_index_rejects_malformed_json_file() {
    let dir = test_data_dir("020_malformed_index");
    let opts = node_opts_for(&dir, &wallet_a());

    write_raw_index_bytes(&opts, b"{ this is not valid json");

    assert_err_contains(
        PrivateWI::new().load_index(&opts),
        "Failed to decode private wallet index",
    );
}

#[test]
fn test_021_add_entry_minimal_creates_index_file_and_entry() {
    let dir = test_data_dir("021_add_minimal");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .expect("minimal entry should add");

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
    assert_eq!(
        entry.wallet_file_name,
        PrivateRW::wallet_file_name(&wallet_b())
    );
    assert_eq!(entry.created_unix_secs, UNIX_2000_SECS);
    assert!(entry.indexed_unix_secs >= UNIX_2000_SECS);

    let index_path = PrivateWI::index_path_from_opts(&opts).expect("index path should resolve");
    assert!(index_path.exists());
}

#[test]
fn test_022_add_entry_owned_accepts_owned_values() {
    let dir = test_data_dir("022_add_owned");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry_owned(
            &opts,
            PrivateWalletIndexAddOwnedRequest {
                owner_wallet: wallet_a(),
                one_time_wallet: wallet_b(),
                invoice: Some(invoice_for(&wallet_b())),
                wallet_file_name: Some(PrivateRW::wallet_file_name(&wallet_b())),
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some("  owned label  ".to_string()),
                context: Some("  owned context  ".to_string()),
                require_one_time_wallet_file: false,
            },
        )
        .expect("owned add should succeed");

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.label.as_deref(), Some("owned label"));
    assert_eq!(entry.context.as_deref(), Some("owned context"));
}

#[test]
fn test_023_add_entry_trims_label_and_context() {
    let dir = test_data_dir("023_add_trim_metadata");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some("   invoice label   "),
                context: Some("   invoice context   "),
                require_one_time_wallet_file: false,
            },
        )
        .expect("entry should add");

    assert_eq!(entry.label.as_deref(), Some("invoice label"));
    assert_eq!(entry.context.as_deref(), Some("invoice context"));
}

#[test]
fn test_024_add_entry_rejects_invalid_owner_and_invalid_one_time_wallet() {
    let dir = test_data_dir("024_add_invalid_wallets");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: "not-a-wallet",
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "Invalid Remzar wallet address for private wallet index",
    );

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: "not-a-wallet",
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "Invalid Remzar wallet address for private wallet index",
    );
}

#[test]
fn test_025_add_entry_rejects_invoice_mismatch() {
    let dir = test_data_dir("025_add_invoice_mismatch");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: Some(&invoice_for(&wallet_c())),
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "request invoice does not match one-time wallet",
    );
}

#[test]
fn test_026_add_entry_accepts_raw_wallet_invoice_input_but_stores_canonical_invoice() {
    let dir = test_data_dir("026_add_raw_invoice");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: Some(&wallet_b()),
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .expect("raw wallet invoice input should normalize");

    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
}

#[test]
fn test_027_add_entry_rejects_wallet_file_name_mismatch() {
    let dir = test_data_dir("027_add_bad_wallet_file_name");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: Some("wrong.wallet"),
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "request wallet_file_name mismatch",
    );
}

#[test]
fn test_028_add_entry_rejects_zero_created_unix_secs() {
    let dir = test_data_dir("028_add_zero_created");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(0),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "request created_unix_secs cannot be zero",
    );
}

#[test]
fn test_029_add_entry_require_wallet_file_missing_returns_not_found() {
    let dir = test_data_dir("029_require_missing_wallet_file");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: true,
            },
        ),
        "One-time private receive wallet file not found",
    );
}

#[test]
fn test_030_add_entry_require_wallet_file_existing_succeeds() {
    let dir = test_data_dir("030_require_existing_wallet_file");
    let opts = node_opts_for(&dir, &wallet_a());

    let wallet_file = create_one_time_wallet_placeholder(&opts, &wallet_b());
    assert!(wallet_file.exists());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: true,
            },
        )
        .expect("entry should add when wallet file exists");

    assert_eq!(entry.one_time_wallet, wallet_b());
}

#[test]
fn test_031_add_entry_replaces_same_owner_same_one_time_wallet() {
    let dir = test_data_dir("031_replace_same_owner");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: Some("first"),
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("first entry should add");

    let replaced = wi
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS + 10),
                label: Some("second"),
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .expect("same owner/same one-time wallet should replace");

    assert_eq!(replaced.label.as_deref(), Some("second"));

    let entries = wi
        .list_for_owner(&opts, &wallet_a())
        .expect("owner entries should list");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].label.as_deref(), Some("second"));
    assert_eq!(entries[0].created_unix_secs, UNIX_2000_SECS + 10);
}

#[test]
fn test_032_add_entry_rejects_same_one_time_wallet_under_different_owner() {
    let dir = test_data_dir("032_conflicting_owner");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("first owner should add");

    assert_err_contains(
        wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_c(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS + 1),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "already indexed under a different owner",
    );
}

#[test]
fn test_033_query_methods_list_count_contains_and_lookup_owner() {
    let dir = test_data_dir("033_query_methods");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("first entry should add");

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_c(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS + 1),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("second entry should add");

    assert_eq!(wi.count_for_owner(&opts, &wallet_a()).unwrap(), 2);
    assert_eq!(wi.count_for_owner(&opts, &wallet_d()).unwrap(), 0);

    assert!(wi.contains_one_time_wallet(&opts, &wallet_b()).unwrap());
    assert!(!wi.contains_one_time_wallet(&opts, &wallet_d()).unwrap());

    assert_eq!(
        wi.lookup_owner(&opts, &wallet_b()).unwrap(),
        Some(wallet_a())
    );
    assert_eq!(wi.lookup_owner(&opts, &wallet_d()).unwrap(), None);
}

#[test]
fn test_034_list_for_owner_canonicalizes_uppercase_owner_lookup() {
    let dir = test_data_dir("034_uppercase_owner_lookup");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("entry should add");

    let entries = wi
        .list_for_owner(&opts, &uppercase_wallet_a())
        .expect("uppercase owner lookup should canonicalize");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].owner_wallet, wallet_a());
    assert_eq!(entries[0].one_time_wallet, wallet_b());
}

#[test]
fn test_035_lookup_entry_returns_owner_and_entry_details() {
    let dir = test_data_dir("035_lookup_entry");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: Some("lookup label"),
            context: Some("lookup context"),
            require_one_time_wallet_file: false,
        },
    )
    .expect("entry should add");

    let lookup = wi
        .lookup_entry(&opts, &uppercase_wallet_b())
        .expect("lookup should not fail")
        .expect("entry should exist");

    assert_eq!(lookup.owner_wallet, wallet_a());
    assert_eq!(lookup.entry.one_time_wallet, wallet_b());
    assert_eq!(lookup.entry.label.as_deref(), Some("lookup label"));
    assert_eq!(lookup.entry.context.as_deref(), Some("lookup context"));
}

#[test]
fn test_036_list_all_entries_sorts_by_created_time_then_owner_then_one_time_wallet() {
    let dir = test_data_dir("036_list_all_sorted");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_c(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS + 20),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("later entry should add");

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS + 10),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("earlier entry should add");

    let all = wi.list_all_entries(&opts).expect("all entries should list");

    assert_eq!(all.len(), 2);
    assert_eq!(all[0].one_time_wallet, wallet_b());
    assert_eq!(all[1].one_time_wallet, wallet_c());
}

#[test]
fn test_037_remove_one_time_wallet_removes_existing_entry_and_persists_change() {
    let dir = test_data_dir("037_remove_existing");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: Some("remove me"),
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .expect("entry should add");

    let removed = wi
        .remove_one_time_wallet(&opts, &wallet_b())
        .expect("remove should succeed")
        .expect("entry should be removed");

    assert_eq!(removed.one_time_wallet, wallet_b());
    assert_eq!(removed.label.as_deref(), Some("remove me"));

    assert!(!wi.contains_one_time_wallet(&opts, &wallet_b()).unwrap());
    assert_eq!(wi.count_for_owner(&opts, &wallet_a()).unwrap(), 0);

    let loaded = wi.load_index(&opts).expect("index should still load");
    assert_eq!(loaded.total_entries(), 0);
}

#[test]
fn test_038_remove_one_time_wallet_returns_none_when_absent() {
    let dir = test_data_dir("038_remove_absent");
    let opts = node_opts_for(&dir, &wallet_a());

    let removed = PrivateWI::new()
        .remove_one_time_wallet(&opts, &wallet_b())
        .expect("remove absent should not fail");

    assert_eq!(removed, None);
}

#[test]
fn test_039_add_from_receipt_and_add_from_record_create_expected_entries() {
    let dir = test_data_dir("039_add_from_receipt_record");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    let receipt = valid_receipt(&wallet_a(), &wallet_b());
    let receipt_entry = wi
        .add_from_receipt(
            &opts,
            &receipt,
            Some("receipt label"),
            Some("receipt context"),
            false,
        )
        .expect("receipt should import");

    assert_eq!(receipt_entry.owner_wallet, wallet_a());
    assert_eq!(receipt_entry.one_time_wallet, wallet_b());
    assert_eq!(receipt_entry.invoice, invoice_for(&wallet_b()));
    assert_eq!(receipt_entry.label.as_deref(), Some("receipt label"));
    assert_eq!(receipt_entry.context.as_deref(), Some("receipt context"));

    let record = valid_record(&wallet_a(), &wallet_c());
    let record_entry = wi
        .add_from_record(
            &opts,
            &record,
            Some("record label"),
            Some("record context"),
            false,
        )
        .expect("record should import");

    assert_eq!(record_entry.owner_wallet, wallet_a());
    assert_eq!(record_entry.one_time_wallet, wallet_c());
    assert_eq!(record_entry.invoice, invoice_for(&wallet_c()));
    assert_eq!(
        record_entry.wallet_file_name,
        PrivateRW::wallet_file_name(&wallet_c())
    );
    assert_eq!(record_entry.label.as_deref(), Some("record label"));
    assert_eq!(record_entry.context.as_deref(), Some("record context"));

    assert_eq!(wi.count_for_owner(&opts, &wallet_a()).unwrap(), 2);
}

#[test]
fn test_040_rebuild_from_private_receive_records_builds_index_from_prw_json_files() {
    let dir = test_data_dir("040_rebuild_from_records");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    let record_b = valid_record(&wallet_a(), &wallet_b());
    let record_c = valid_record(&wallet_a(), &wallet_c());

    let path_b = write_private_receive_record(&opts, &record_b);
    let path_c = write_private_receive_record(&opts, &record_c);

    assert!(path_b.exists());
    assert!(path_c.exists());
    assert!(
        path_b
            .to_string_lossy()
            .ends_with(PRIVATE_RECEIVE_RECORD_EXT)
    );
    assert!(
        path_c
            .to_string_lossy()
            .ends_with(PRIVATE_RECEIVE_RECORD_EXT)
    );

    let directory = directory_for(&opts);
    let ignored_file = PrivateRW::metadata_dir_path(&directory.wallets_path).join("ignored.txt");
    fs::write(&ignored_file, b"not a prw record").expect("ignored file should be written");

    let rebuilt = wi
        .rebuild_from_private_receive_records(&opts, false)
        .expect("rebuild should succeed");

    assert_eq!(rebuilt.kind, PRIVATE_WALLET_INDEX_KIND);
    assert_eq!(rebuilt.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(rebuilt.total_entries(), 2);
    assert_eq!(rebuilt.owner_count(), 1);

    let entries = wi
        .list_for_owner(&opts, &wallet_a())
        .expect("rebuilt owner entries should list");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].one_time_wallet, wallet_b());
    assert_eq!(entries[1].one_time_wallet, wallet_c());

    for entry in entries {
        assert_eq!(
            entry.context.as_deref(),
            Some("rebuilt_from_private_receive_record")
        );
        entry.validate().expect("rebuilt entry should validate");
    }

    let index_path = PrivateWI::index_path_from_opts(&opts).expect("index path should resolve");
    assert!(index_path.exists());
}

#[test]
fn test_041_validate_entry_rejects_invalid_owner_and_one_time_wallet() {
    let mut bad_owner = valid_entry(&wallet_a(), &wallet_b());
    bad_owner.owner_wallet = "not-a-wallet".to_string();

    assert_err_contains(
        PrivateWI::validate_entry(&bad_owner),
        "Invalid Remzar wallet address for private wallet index",
    );

    let mut bad_one_time = valid_entry(&wallet_a(), &wallet_b());
    bad_one_time.one_time_wallet = "not-a-wallet".to_string();

    assert_err_contains(
        PrivateWI::validate_entry(&bad_one_time),
        "Invalid Remzar wallet address for private wallet index",
    );
}

#[test]
fn test_042_validate_entry_accepts_uppercase_wallet_fields_when_canonical_dependent_fields_match() {
    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.owner_wallet = uppercase_wallet_a();
    entry.one_time_wallet = uppercase_wallet_b();
    entry.invoice = invoice_for(&wallet_b());
    entry.wallet_file_name = PrivateRW::wallet_file_name(&wallet_b());

    PrivateWI::validate_entry(&entry)
        .expect("entry validation should canonicalize uppercase wallet fields");
}

#[test]
fn test_043_validate_entry_rejects_uppercase_invoice_as_not_canonical() {
    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.invoice = invoice_for(&uppercase_wallet_b());

    assert_err_contains(
        PrivateWI::validate_entry(&entry),
        "invoice is not canonical",
    );
}

#[test]
fn test_044_validate_entry_rejects_uppercase_wallet_file_name_as_not_canonical() {
    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.wallet_file_name = PrivateRW::wallet_file_name(&uppercase_wallet_b());

    assert_err_contains(
        PrivateWI::validate_entry(&entry),
        "wallet_file_name mismatch",
    );
}

#[test]
fn test_045_validate_entry_rejects_label_too_long_and_control_characters() {
    let mut too_long = valid_entry(&wallet_a(), &wallet_b());
    too_long.label = Some("x".repeat(PWI_TEST_MAX_LABEL_LEN + 1));

    assert_err_contains(PrivateWI::validate_entry(&too_long), "label too long");

    let mut tab_label = valid_entry(&wallet_a(), &wallet_b());
    tab_label.label = Some("bad\tlabel".to_string());

    assert_err_contains(
        PrivateWI::validate_entry(&tab_label),
        "label contains control characters",
    );

    let mut null_label = valid_entry(&wallet_a(), &wallet_b());
    null_label.label = Some("bad\0label".to_string());

    assert_err_contains(
        PrivateWI::validate_entry(&null_label),
        "label contains control characters",
    );
}

#[test]
fn test_046_validate_entry_rejects_context_too_long_and_control_characters() {
    let mut too_long = valid_entry(&wallet_a(), &wallet_b());
    too_long.context = Some("x".repeat(PWI_TEST_MAX_CONTEXT_LEN + 1));

    assert_err_contains(PrivateWI::validate_entry(&too_long), "context too long");

    let mut tab_context = valid_entry(&wallet_a(), &wallet_b());
    tab_context.context = Some("bad\tcontext".to_string());

    assert_err_contains(
        PrivateWI::validate_entry(&tab_context),
        "context contains control characters",
    );

    let mut null_context = valid_entry(&wallet_a(), &wallet_b());
    null_context.context = Some("bad\0context".to_string());

    assert_err_contains(
        PrivateWI::validate_entry(&null_context),
        "context contains control characters",
    );
}

#[test]
fn test_047_validate_entry_accepts_max_length_label_and_context() {
    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.label = Some("l".repeat(PWI_TEST_MAX_LABEL_LEN));
    entry.context = Some("c".repeat(PWI_TEST_MAX_CONTEXT_LEN));

    PrivateWI::validate_entry(&entry).expect("max length label/context should validate");
}

#[test]
fn test_048_validate_entry_accepts_non_ascii_label_and_context_within_byte_limits() {
    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.label = Some("é".repeat(48));
    entry.context = Some("é".repeat(128));

    assert_eq!(entry.label.as_ref().unwrap().len(), PWI_TEST_MAX_LABEL_LEN);
    assert_eq!(
        entry.context.as_ref().unwrap().len(),
        PWI_TEST_MAX_CONTEXT_LEN
    );

    PrivateWI::validate_entry(&entry)
        .expect("non-ASCII metadata within byte limits should validate");
}

#[test]
fn test_049_validate_index_file_rejects_duplicate_same_owner_one_time_wallet() {
    let mut index = valid_index(Vec::new());
    index.entries_by_owner.insert(
        wallet_a(),
        vec![
            valid_entry(&wallet_a(), &wallet_b()),
            valid_entry(&wallet_a(), &wallet_b()),
        ],
    );

    assert_err_contains(
        PrivateWI::validate_index_file(&index),
        "Duplicate one-time wallet",
    );
}

#[test]
fn test_050_validate_index_file_rejects_invalid_entry_inside_index() {
    let mut bad_entry = valid_entry(&wallet_a(), &wallet_b());
    bad_entry.created_unix_secs = 0;

    let index = valid_index(vec![bad_entry]);

    assert_err_contains(
        PrivateWI::validate_index_file(&index),
        "created_unix_secs cannot be zero",
    );
}

#[test]
fn test_051_validate_index_file_accepts_multiple_owners_with_unique_one_time_wallets() {
    let index = valid_index(vec![
        valid_entry(&wallet_a(), &wallet_b()),
        valid_entry(&wallet_c(), &wallet_d()),
    ]);

    PrivateWI::validate_index_file(&index).expect("multi-owner index should validate");

    assert_eq!(index.owner_count(), 2);
    assert_eq!(index.total_entries(), 2);
}

#[test]
fn test_052_entry_json_roundtrip_preserves_fields_and_validates() {
    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.label = Some("json label".to_string());
    entry.context = Some("json context".to_string());

    let json = serde_json::to_string_pretty(&entry).expect("entry should serialize");
    let decoded: PrivateWalletIndexEntry =
        serde_json::from_str(&json).expect("entry should deserialize");

    assert_eq!(decoded, entry);
    decoded.validate().expect("decoded entry should validate");
}

#[test]
fn test_053_index_json_roundtrip_preserves_fields_and_validates() {
    let index = valid_index(vec![
        valid_entry(&wallet_a(), &wallet_b()),
        valid_entry(&wallet_c(), &wallet_d()),
    ]);

    let json = serde_json::to_string_pretty(&index).expect("index should serialize");
    let decoded: PrivateWalletIndexFile =
        serde_json::from_str(&json).expect("index should deserialize");

    assert_eq!(decoded, index);
    decoded.validate().expect("decoded index should validate");
}

#[test]
fn test_054_load_index_canonicalizes_raw_wallet_invoice_in_saved_json() {
    let dir = test_data_dir("054_load_canonicalizes_raw_invoice");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.invoice = wallet_b();

    let index = valid_index(vec![entry]);
    let bytes = serde_json::to_vec_pretty(&index).expect("index should serialize");

    write_raw_index_bytes(&opts, &bytes);

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("load should canonicalize raw wallet invoice");

    let entry = loaded
        .entries_by_owner
        .get(&wallet_a())
        .unwrap()
        .first()
        .unwrap();

    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
}

#[test]
fn test_055_load_index_canonicalizes_uppercase_owner_key_entry_wallets_and_file_name() {
    let dir = test_data_dir("055_load_canonicalizes_uppercase");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut entry = valid_entry(&uppercase_wallet_a(), &uppercase_wallet_b());
    entry.invoice = invoice_for(&uppercase_wallet_b());
    entry.wallet_file_name = PrivateRW::wallet_file_name(&uppercase_wallet_b());

    let mut entries_by_owner = BTreeMap::new();
    entries_by_owner.insert(uppercase_wallet_a(), vec![entry]);

    let index = PrivateWalletIndexFile {
        kind: PRIVATE_WALLET_INDEX_KIND.to_string(),
        version: PRIVATE_RECEIVE_VERSION,
        created_unix_secs: UNIX_2000_SECS,
        updated_unix_secs: UNIX_2000_SECS + 1,
        entries_by_owner,
    };

    let bytes = serde_json::to_vec_pretty(&index).expect("index should serialize");
    write_raw_index_bytes(&opts, &bytes);

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("load should canonicalize index");

    assert!(loaded.entries_by_owner.contains_key(&wallet_a()));
    assert!(!loaded.entries_by_owner.contains_key(&uppercase_wallet_a()));

    let entry = loaded
        .entries_by_owner
        .get(&wallet_a())
        .unwrap()
        .first()
        .unwrap();

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
    assert_eq!(
        entry.wallet_file_name,
        PrivateRW::wallet_file_name(&wallet_b())
    );
}

#[test]
fn test_056_load_index_deduplicates_same_owner_duplicate_entries_during_canonicalization() {
    let dir = test_data_dir("056_load_dedup_same_owner");
    let opts = node_opts_for(&dir, &wallet_a());

    let index = valid_index(vec![
        valid_entry_with_times(&wallet_a(), &wallet_b(), UNIX_2000_SECS, UNIX_2000_SECS + 1),
        valid_entry_with_times(&wallet_a(), &wallet_b(), UNIX_2000_SECS, UNIX_2000_SECS + 2),
    ]);

    let bytes = serde_json::to_vec_pretty(&index).expect("index should serialize");
    write_raw_index_bytes(&opts, &bytes);

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("load should canonicalize and deduplicate same-owner duplicates");

    assert_eq!(loaded.total_entries(), 1);
    assert_eq!(
        loaded.entries_by_owner.get(&wallet_a()).unwrap()[0].one_time_wallet,
        wallet_b()
    );
}

#[test]
fn test_057_load_index_rejects_duplicate_one_time_wallet_across_different_owners() {
    let dir = test_data_dir("057_load_duplicate_across_owners");
    let opts = node_opts_for(&dir, &wallet_a());

    let index = valid_index(vec![
        valid_entry(&wallet_a(), &wallet_b()),
        valid_entry(&wallet_c(), &wallet_b()),
    ]);

    let bytes = serde_json::to_vec_pretty(&index).expect("index should serialize");
    write_raw_index_bytes(&opts, &bytes);

    assert_err_contains(
        PrivateWI::new().load_index(&opts),
        "Duplicate one-time wallet",
    );
}

#[test]
fn test_058_save_index_creates_private_receive_directory_and_index_file() {
    let dir = test_data_dir("058_save_creates_dirs");
    let opts = node_opts_for(&dir, &wallet_a());
    let directory = directory_for(&opts);

    let private_receive_dir = PrivateRW::metadata_dir_path(&directory.wallets_path);
    assert!(!private_receive_dir.exists());

    PrivateWI::new()
        .save_index(&opts, &valid_index(Vec::new()))
        .expect("save should create directories");

    assert!(private_receive_dir.exists());
    assert!(PrivateWI::index_file_path(&directory.wallets_path).exists());
}

#[test]
fn test_059_save_index_rejects_invalid_index_kind() {
    let dir = test_data_dir("059_save_invalid_kind");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut index = valid_index(Vec::new());
    index.kind = "wrong_kind".to_string();

    assert_err_contains(
        PrivateWI::new().save_index(&opts, &index),
        "Invalid private wallet index kind",
    );
}

#[test]
fn test_060_save_index_replaces_existing_index_and_removes_tmp_and_backup_files() {
    let dir = test_data_dir("060_save_replace_cleanup");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.save_index(&opts, &valid_index(Vec::new()))
        .expect("initial index should save");

    let replacement = valid_index(vec![valid_entry(&wallet_a(), &wallet_b())]);

    wi.save_index(&opts, &replacement)
        .expect("replacement index should save");

    let directory = directory_for(&opts);
    assert!(PrivateWI::index_file_path(&directory.wallets_path).exists());
    assert!(!PrivateWI::index_tmp_file_path(&directory.wallets_path).exists());
    assert!(!PrivateWI::index_backup_file_path(&directory.wallets_path).exists());

    let loaded = wi.load_index(&opts).expect("replacement should load");
    assert_eq!(loaded.total_entries(), 1);
}

#[test]
fn test_061_add_entry_with_created_time_none_uses_runtime_time() {
    let dir = test_data_dir("061_add_runtime_created");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: None,
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .expect("entry should add with runtime created time");

    assert!(entry.created_unix_secs >= UNIX_2000_SECS);
    assert!(entry.indexed_unix_secs >= UNIX_2000_SECS);
}

#[test]
fn test_062_add_entry_rejects_owner_equal_to_one_time_wallet() {
    let dir = test_data_dir("062_add_owner_equals_one_time");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_a(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "owner and one-time wallet cannot be the same",
    );
}

#[test]
fn test_063_add_entry_canonicalizes_uppercase_owner_and_one_time_wallet() {
    let dir = test_data_dir("063_add_uppercase_canonicalizes");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &uppercase_wallet_a(),
                one_time_wallet: &uppercase_wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .expect("uppercase wallets should canonicalize");

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
    assert_eq!(
        entry.wallet_file_name,
        PrivateRW::wallet_file_name(&wallet_b())
    );
}

#[test]
fn test_064_add_entry_accepts_uppercase_invoice_input_and_stores_canonical_invoice() {
    let dir = test_data_dir("064_add_uppercase_invoice");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: Some(&invoice_for(&uppercase_wallet_b())),
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .expect("uppercase invoice input should normalize");

    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
}

#[test]
fn test_065_add_entry_rejects_empty_label_and_empty_context() {
    let dir = test_data_dir("065_add_empty_metadata");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some("   "),
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "label cannot be empty",
    );

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: Some("   "),
                require_one_time_wallet_file: false,
            },
        ),
        "context cannot be empty",
    );
}

#[test]
fn test_066_add_entry_rejects_too_long_label_and_context() {
    let dir = test_data_dir("066_add_long_metadata");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some(&"x".repeat(PWI_TEST_MAX_LABEL_LEN + 1)),
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "label too long",
    );

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: Some(&"x".repeat(PWI_TEST_MAX_CONTEXT_LEN + 1)),
                require_one_time_wallet_file: false,
            },
        ),
        "context too long",
    );
}

#[test]
fn test_067_add_entry_rejects_control_characters_in_label_and_context() {
    let dir = test_data_dir("067_add_control_metadata");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some("bad\nlabel"),
                context: None,
                require_one_time_wallet_file: false,
            },
        ),
        "label contains control characters",
    );

    assert_err_contains(
        PrivateWI::new().add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: Some("bad\ncontext"),
                require_one_time_wallet_file: false,
            },
        ),
        "context contains control characters",
    );
}

#[test]
fn test_068_add_entry_owned_accepts_none_optional_fields() {
    let dir = test_data_dir("068_add_owned_none");
    let opts = node_opts_for(&dir, &wallet_a());

    let entry = PrivateWI::new()
        .add_entry_owned(
            &opts,
            PrivateWalletIndexAddOwnedRequest {
                owner_wallet: wallet_a(),
                one_time_wallet: wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .expect("owned request with none fields should add");

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.label, None);
    assert_eq!(entry.context, None);
}

#[test]
fn test_069_add_entry_persists_multiple_owners_and_counts_correctly() {
    let dir = test_data_dir("069_multiple_owners");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_c(),
            one_time_wallet: &wallet_d(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS + 1),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    let index = wi.load_index(&opts).expect("index should load");

    assert_eq!(index.owner_count(), 2);
    assert_eq!(index.total_entries(), 2);
    assert_eq!(wi.count_for_owner(&opts, &wallet_a()).unwrap(), 1);
    assert_eq!(wi.count_for_owner(&opts, &wallet_c()).unwrap(), 1);
}

#[test]
fn test_070_list_for_owner_returns_entries_sorted_by_created_time() {
    let dir = test_data_dir("070_owner_sorted");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_d(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS + 30),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS + 10),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_c(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS + 20),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    let entries = wi.list_for_owner(&opts, &wallet_a()).unwrap();

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].one_time_wallet, wallet_b());
    assert_eq!(entries[1].one_time_wallet, wallet_c());
    assert_eq!(entries[2].one_time_wallet, wallet_d());
}

#[test]
fn test_071_query_methods_reject_invalid_wallet_inputs() {
    let dir = test_data_dir("071_query_invalid_inputs");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    assert_err_contains(
        wi.list_for_owner(&opts, "not-a-wallet"),
        "Invalid Remzar wallet address for private wallet index",
    );

    assert_err_contains(
        wi.count_for_owner(&opts, "not-a-wallet"),
        "Invalid Remzar wallet address for private wallet index",
    );

    assert_err_contains(
        wi.contains_one_time_wallet(&opts, "not-a-wallet"),
        "Invalid Remzar wallet address for private wallet index",
    );

    assert_err_contains(
        wi.lookup_owner(&opts, "not-a-wallet"),
        "Invalid Remzar wallet address for private wallet index",
    );

    assert_err_contains(
        wi.lookup_entry(&opts, "not-a-wallet"),
        "Invalid Remzar wallet address for private wallet index",
    );
}

#[test]
fn test_072_lookup_owner_and_entry_canonicalize_uppercase_one_time_wallet() {
    let dir = test_data_dir("072_lookup_uppercase");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: Some("upper lookup"),
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    assert_eq!(
        wi.lookup_owner(&opts, &uppercase_wallet_b()).unwrap(),
        Some(wallet_a())
    );

    let lookup = wi
        .lookup_entry(&opts, &uppercase_wallet_b())
        .unwrap()
        .expect("lookup should exist");

    assert_eq!(lookup.owner_wallet, wallet_a());
    assert_eq!(lookup.entry.one_time_wallet, wallet_b());
    assert_eq!(lookup.entry.label.as_deref(), Some("upper lookup"));
}

#[test]
fn test_073_remove_one_time_wallet_canonicalizes_uppercase_lookup() {
    let dir = test_data_dir("073_remove_uppercase");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: None,
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    let removed = wi
        .remove_one_time_wallet(&opts, &uppercase_wallet_b())
        .expect("remove should succeed")
        .expect("entry should be removed");

    assert_eq!(removed.one_time_wallet, wallet_b());
    assert_eq!(wi.lookup_owner(&opts, &wallet_b()).unwrap(), None);
}

#[test]
fn test_074_remove_one_time_wallet_rejects_invalid_wallet_input() {
    let dir = test_data_dir("074_remove_invalid");
    let opts = node_opts_for(&dir, &wallet_a());

    assert_err_contains(
        PrivateWI::new().remove_one_time_wallet(&opts, "not-a-wallet"),
        "Invalid Remzar wallet address for private wallet index",
    );
}

#[test]
fn test_075_remove_one_time_wallet_does_not_delete_wallet_file_or_prw_record() {
    let dir = test_data_dir("075_remove_keeps_files");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    let wallet_file = create_one_time_wallet_placeholder(&opts, &wallet_b());
    let record = valid_record(&wallet_a(), &wallet_b());
    let record_file = write_private_receive_record(&opts, &record);

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: None,
            context: None,
            require_one_time_wallet_file: true,
        },
    )
    .unwrap();

    let removed = wi.remove_one_time_wallet(&opts, &wallet_b()).unwrap();
    assert!(removed.is_some());

    assert!(wallet_file.exists(), "remove must not delete wallet file");
    assert!(
        record_file.exists(),
        "remove must not delete .prw.json record"
    );
}

#[test]
fn test_076_add_from_receipt_rejects_invalid_receipt() {
    let dir = test_data_dir("076_bad_receipt");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut receipt = valid_receipt(&wallet_a(), &wallet_b());
    receipt.invoice = invoice_for(&wallet_c());

    assert_err_contains(
        PrivateWI::new().add_from_receipt(&opts, &receipt, None, None, false),
        "invoice does not match one-time wallet",
    );
}

#[test]
fn test_077_add_from_record_rejects_invalid_record() {
    let dir = test_data_dir("077_bad_record");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut record = valid_record(&wallet_a(), &wallet_b());
    record.wallet_file_name = "wrong.wallet".to_string();

    assert_err_contains(
        PrivateWI::new().add_from_record(&opts, &record, None, None, false),
        "wallet_file_name does not match one-time wallet",
    );
}

#[test]
fn test_078_add_from_receipt_requires_wallet_file_when_requested() {
    let dir = test_data_dir("078_receipt_require_file");
    let opts = node_opts_for(&dir, &wallet_a());
    let receipt = valid_receipt(&wallet_a(), &wallet_b());

    assert_err_contains(
        PrivateWI::new().add_from_receipt(&opts, &receipt, None, None, true),
        "One-time private receive wallet file not found",
    );

    create_one_time_wallet_placeholder(&opts, &wallet_b());

    let entry = PrivateWI::new()
        .add_from_receipt(&opts, &receipt, None, None, true)
        .expect("receipt import should succeed when wallet file exists");

    assert_eq!(entry.one_time_wallet, wallet_b());
}

#[test]
fn test_079_add_from_record_requires_wallet_file_when_requested() {
    let dir = test_data_dir("079_record_require_file");
    let opts = node_opts_for(&dir, &wallet_a());
    let record = valid_record(&wallet_a(), &wallet_b());

    assert_err_contains(
        PrivateWI::new().add_from_record(&opts, &record, None, None, true),
        "One-time private receive wallet file not found",
    );

    create_one_time_wallet_placeholder(&opts, &wallet_b());

    let entry = PrivateWI::new()
        .add_from_record(&opts, &record, None, None, true)
        .expect("record import should succeed when wallet file exists");

    assert_eq!(entry.one_time_wallet, wallet_b());
}

#[test]
fn test_080_rebuild_from_private_receive_records_with_no_records_saves_empty_index() {
    let dir = test_data_dir("080_rebuild_empty");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    let rebuilt = wi
        .rebuild_from_private_receive_records(&opts, false)
        .expect("rebuild with no records should succeed");

    assert_eq!(rebuilt.total_entries(), 0);
    assert_eq!(rebuilt.owner_count(), 0);

    let index_path = PrivateWI::index_path_from_opts(&opts).unwrap();
    assert!(index_path.exists());

    let loaded = wi
        .load_index(&opts)
        .expect("empty rebuilt index should load");
    assert_eq!(loaded.total_entries(), 0);
}

#[test]
fn test_081_rebuild_from_private_receive_records_requires_wallet_files_when_requested() {
    let dir = test_data_dir("081_rebuild_require_file");
    let opts = node_opts_for(&dir, &wallet_a());

    let record = valid_record(&wallet_a(), &wallet_b());
    write_private_receive_record(&opts, &record);

    assert_err_contains(
        PrivateWI::new().rebuild_from_private_receive_records(&opts, true),
        "One-time private receive wallet file not found",
    );

    create_one_time_wallet_placeholder(&opts, &wallet_b());

    let rebuilt = PrivateWI::new()
        .rebuild_from_private_receive_records(&opts, true)
        .expect("rebuild should succeed once wallet file exists");

    assert_eq!(rebuilt.total_entries(), 1);
}

#[test]
fn test_082_rebuild_from_private_receive_records_rejects_malformed_prw_json() {
    let dir = test_data_dir("082_rebuild_malformed_record");
    let opts = node_opts_for(&dir, &wallet_a());

    let directory = create_wallets_dir(&opts);
    let metadata_dir = PrivateRW::metadata_dir_path(&directory.wallets_path);
    fs::create_dir_all(&metadata_dir).expect("metadata dir should exist");

    let bad_record = metadata_dir.join(format!("{}.{}", wallet_b(), PRIVATE_RECEIVE_RECORD_EXT));
    fs::write(&bad_record, b"{ not valid json").expect("bad record should be written");

    assert_err_contains(
        PrivateWI::new().rebuild_from_private_receive_records(&opts, false),
        "Failed to decode private receive record",
    );
}

#[test]
fn test_083_rebuild_from_private_receive_records_rejects_invalid_record_content() {
    let dir = test_data_dir("083_rebuild_invalid_record");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut record = valid_record(&wallet_a(), &wallet_b());
    record.invoice = invoice_for(&wallet_c());

    write_private_receive_record(&opts, &record);

    assert_err_contains(
        PrivateWI::new().rebuild_from_private_receive_records(&opts, false),
        "invoice does not match one-time wallet",
    );
}

#[test]
fn test_084_rebuild_from_private_receive_records_rejects_record_over_one_megabyte() {
    let dir = test_data_dir("084_rebuild_huge_record");
    let opts = node_opts_for(&dir, &wallet_a());

    let directory = create_wallets_dir(&opts);
    let metadata_dir = PrivateRW::metadata_dir_path(&directory.wallets_path);
    fs::create_dir_all(&metadata_dir).expect("metadata dir should exist");

    let huge_record = metadata_dir.join(format!("{}.{}", wallet_b(), PRIVATE_RECEIVE_RECORD_EXT));
    fs::write(&huge_record, vec![b'x'; (1024 * 1024) + 1]).expect("huge record should be written");

    assert_err_contains(
        PrivateWI::new().rebuild_from_private_receive_records(&opts, false),
        "Private receive record too large",
    );
}

#[test]
fn test_085_rebuild_from_private_receive_records_ignores_similar_but_wrong_extension() {
    let dir = test_data_dir("085_rebuild_ignores_wrong_extension");
    let opts = node_opts_for(&dir, &wallet_a());

    let directory = create_wallets_dir(&opts);
    let metadata_dir = PrivateRW::metadata_dir_path(&directory.wallets_path);
    fs::create_dir_all(&metadata_dir).expect("metadata dir should exist");

    let wrong_extension = metadata_dir.join(format!("{}.prw.txt", wallet_b()));
    fs::write(
        &wrong_extension,
        b"{ not valid json but should be ignored }",
    )
    .expect("wrong-extension file should be written");

    let rebuilt = PrivateWI::new()
        .rebuild_from_private_receive_records(&opts, false)
        .expect("wrong-extension files should be ignored");

    assert_eq!(rebuilt.total_entries(), 0);
}

#[test]
fn test_086_rebuild_from_private_receive_records_replaces_existing_index_contents() {
    let dir = test_data_dir("086_rebuild_replaces_existing");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_d(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: Some("old"),
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    let record = valid_record(&wallet_a(), &wallet_b());
    write_private_receive_record(&opts, &record);

    let rebuilt = wi
        .rebuild_from_private_receive_records(&opts, false)
        .expect("rebuild should replace index from records");

    assert_eq!(rebuilt.total_entries(), 1);
    assert!(wi.contains_one_time_wallet(&opts, &wallet_b()).unwrap());
    assert!(!wi.contains_one_time_wallet(&opts, &wallet_d()).unwrap());
}

#[test]
fn test_087_index_file_serialization_omits_none_label_and_context_fields() {
    let entry = valid_entry(&wallet_a(), &wallet_b());
    let index = valid_index(vec![entry]);

    let json = serde_json::to_string_pretty(&index).expect("index should serialize");

    assert!(json.contains(PRIVATE_WALLET_INDEX_KIND));
    assert!(json.contains(&wallet_b()));
    assert!(!json.contains("\"label\""));
    assert!(!json.contains("\"context\""));
}

#[test]
fn test_088_index_file_serialization_includes_some_label_and_context_fields() {
    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.label = Some("stored label".to_string());
    entry.context = Some("stored context".to_string());

    let index = valid_index(vec![entry]);
    let json = serde_json::to_string_pretty(&index).expect("index should serialize");

    assert!(json.contains("\"label\""));
    assert!(json.contains("\"context\""));
    assert!(json.contains("stored label"));
    assert!(json.contains("stored context"));
}

#[test]
fn test_089_lookup_entry_json_roundtrip_preserves_owner_and_entry() {
    let dir = test_data_dir("089_lookup_json_roundtrip");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    wi.add_entry(
        &opts,
        PrivateWalletIndexAddRequest {
            owner_wallet: &wallet_a(),
            one_time_wallet: &wallet_b(),
            invoice: None,
            wallet_file_name: None,
            created_unix_secs: Some(UNIX_2000_SECS),
            label: Some("lookup json"),
            context: None,
            require_one_time_wallet_file: false,
        },
    )
    .unwrap();

    let lookup = wi
        .lookup_entry(&opts, &wallet_b())
        .unwrap()
        .expect("lookup should exist");

    let json = serde_json::to_string_pretty(&lookup).expect("lookup should serialize");

    let decoded: remzar::privacy::privacy_003_private_wallet_index::PrivateWalletOwnerLookup =
        serde_json::from_str(&json).expect("lookup should deserialize");

    assert_eq!(decoded, lookup);
}

#[test]
fn test_090_saved_index_contains_no_tmp_or_backup_file_after_first_save() {
    let dir = test_data_dir("090_no_tmp_backup_first_save");
    let opts = node_opts_for(&dir, &wallet_a());
    let directory = directory_for(&opts);

    PrivateWI::new()
        .save_index(&opts, &valid_index(Vec::new()))
        .expect("index should save");

    assert!(PrivateWI::index_file_path(&directory.wallets_path).exists());
    assert!(!PrivateWI::index_tmp_file_path(&directory.wallets_path).exists());
    assert!(!PrivateWI::index_backup_file_path(&directory.wallets_path).exists());
}

#[test]
fn test_091_load_index_ignores_bad_map_key_and_rebuilds_from_entry_owner_wallet() {
    let dir = test_data_dir("091_load_ignores_bad_map_key");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut index = valid_index(Vec::new());
    index.entries_by_owner.insert(
        "not-a-wallet".to_string(),
        vec![valid_entry(&wallet_a(), &wallet_b())],
    );

    let bytes = serde_json::to_vec_pretty(&index).expect("index should serialize");
    write_raw_index_bytes(&opts, &bytes);

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("load_index should canonicalize by entry.owner_wallet, not old map key");

    assert_eq!(loaded.owner_count(), 1);
    assert_eq!(loaded.total_entries(), 1);

    assert!(
        !loaded.entries_by_owner.contains_key("not-a-wallet"),
        "bad JSON map key should not survive canonicalization"
    );

    let entries = loaded
        .entries_by_owner
        .get(&wallet_a())
        .expect("canonical owner key should exist");

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].owner_wallet, wallet_a());
    assert_eq!(entries[0].one_time_wallet, wallet_b());
    assert_eq!(entries[0].invoice, invoice_for(&wallet_b()));
}

#[test]
fn test_092_load_index_rejects_json_with_invalid_entry_wallet() {
    let dir = test_data_dir("092_load_invalid_entry_wallet");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.one_time_wallet = "not-a-wallet".to_string();

    let index = valid_index(vec![entry]);
    let bytes = serde_json::to_vec_pretty(&index).expect("index should serialize");
    write_raw_index_bytes(&opts, &bytes);

    assert_err_contains(
        PrivateWI::new().load_index(&opts),
        "Invalid Remzar wallet address for private wallet index",
    );
}

#[test]
fn test_093_save_index_canonicalizes_trimmed_label_and_context() {
    let dir = test_data_dir("093_save_trims_metadata");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.label = Some("   label after save   ".to_string());
    entry.context = Some("   context after save   ".to_string());

    let index = valid_index(vec![entry]);

    PrivateWI::new()
        .save_index(&opts, &index)
        .expect("save should trim metadata");

    let loaded = PrivateWI::new()
        .load_index(&opts)
        .expect("index should load");
    let entry = loaded
        .entries_by_owner
        .get(&wallet_a())
        .unwrap()
        .first()
        .unwrap();

    assert_eq!(entry.label.as_deref(), Some("label after save"));
    assert_eq!(entry.context.as_deref(), Some("context after save"));
}

#[test]
fn test_094_save_index_rejects_empty_label_after_trim() {
    let dir = test_data_dir("094_save_empty_label");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.label = Some("   ".to_string());

    let index = valid_index(vec![entry]);

    assert_err_contains(
        PrivateWI::new().save_index(&opts, &index),
        "label cannot be empty",
    );
}

#[test]
fn test_095_save_index_rejects_empty_context_after_trim() {
    let dir = test_data_dir("095_save_empty_context");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut entry = valid_entry(&wallet_a(), &wallet_b());
    entry.context = Some("   ".to_string());

    let index = valid_index(vec![entry]);

    assert_err_contains(
        PrivateWI::new().save_index(&opts, &index),
        "context cannot be empty",
    );
}

#[test]
fn test_096_wallet_file_requirement_uses_canonical_wallet_file_name_for_uppercase_input() {
    let dir = test_data_dir("096_require_file_uppercase");
    let opts = node_opts_for(&dir, &wallet_a());

    let wallet_file = create_one_time_wallet_placeholder(&opts, &wallet_b());
    assert!(wallet_file.exists());

    let entry = PrivateWI::new()
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &uppercase_wallet_a(),
                one_time_wallet: &uppercase_wallet_b(),
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: true,
            },
        )
        .expect("uppercase one-time input should check canonical lowercase wallet file");

    assert_eq!(entry.one_time_wallet, wallet_b());
}

#[test]
fn test_097_add_entry_from_record_with_uppercase_fields_canonicalizes_output() {
    let dir = test_data_dir("097_record_uppercase_fields");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut record = valid_record(&wallet_a(), &wallet_b());
    record.owner_wallet = uppercase_wallet_a();
    record.one_time_wallet = uppercase_wallet_b();
    record.invoice = invoice_for(&wallet_b());
    record.wallet_file_name = PrivateRW::wallet_file_name(&wallet_b());

    let entry = PrivateWI::new()
        .add_from_record(&opts, &record, None, None, false)
        .expect("record import should canonicalize uppercase fields");

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
}

#[test]
fn test_098_add_entry_from_receipt_with_uppercase_fields_canonicalizes_output() {
    let dir = test_data_dir("098_receipt_uppercase_fields");
    let opts = node_opts_for(&dir, &wallet_a());

    let mut receipt = valid_receipt(&wallet_a(), &wallet_b());
    receipt.owner_wallet = uppercase_wallet_a();
    receipt.one_time_wallet = uppercase_wallet_b();
    receipt.invoice = invoice_for(&wallet_b());

    let entry = PrivateWI::new()
        .add_from_receipt(&opts, &receipt, None, None, false)
        .expect("receipt import should canonicalize uppercase fields");

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
}

#[test]
fn test_099_remove_only_target_entry_when_owner_has_multiple_entries() {
    let dir = test_data_dir("099_remove_one_of_many");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    for (wallet, offset) in [(wallet_b(), 1), (wallet_c(), 2), (wallet_d(), 3)] {
        wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &wallet_a(),
                one_time_wallet: &wallet,
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS + offset),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        )
        .unwrap();
    }

    let removed = wi.remove_one_time_wallet(&opts, &wallet_c()).unwrap();
    assert!(removed.is_some());

    let entries = wi.list_for_owner(&opts, &wallet_a()).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].one_time_wallet, wallet_b());
    assert_eq!(entries[1].one_time_wallet, wallet_d());
}

#[test]
fn test_100_end_to_end_add_save_load_lookup_remove_rebuild_from_records() {
    let dir = test_data_dir("100_end_to_end_index");
    let opts = node_opts_for(&dir, &wallet_a());
    let wi = PrivateWI::new();

    let wallet_file_b = create_one_time_wallet_placeholder(&opts, &wallet_b());
    assert!(wallet_file_b.exists());

    let entry = wi
        .add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &uppercase_wallet_a(),
                one_time_wallet: &uppercase_wallet_b(),
                invoice: Some(&invoice_for(&uppercase_wallet_b())),
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some("  final label  "),
                context: Some("  final context  "),
                require_one_time_wallet_file: true,
            },
        )
        .expect("entry should add end-to-end");

    assert_eq!(entry.owner_wallet, wallet_a());
    assert_eq!(entry.one_time_wallet, wallet_b());
    assert_eq!(entry.invoice, invoice_for(&wallet_b()));
    assert_eq!(entry.label.as_deref(), Some("final label"));
    assert_eq!(entry.context.as_deref(), Some("final context"));

    let loaded = wi.load_index(&opts).expect("index should load");
    assert_eq!(loaded.total_entries(), 1);
    assert_eq!(loaded.owner_count(), 1);

    let lookup = wi
        .lookup_entry(&opts, &uppercase_wallet_b())
        .unwrap()
        .expect("lookup should find entry");

    assert_eq!(lookup.owner_wallet, wallet_a());
    assert_eq!(lookup.entry.one_time_wallet, wallet_b());

    let removed = wi
        .remove_one_time_wallet(&opts, &uppercase_wallet_b())
        .unwrap()
        .expect("entry should remove");

    assert_eq!(removed.one_time_wallet, wallet_b());
    assert!(!wi.contains_one_time_wallet(&opts, &wallet_b()).unwrap());

    let record = valid_record(&wallet_a(), &wallet_b());
    write_private_receive_record(&opts, &record);

    let rebuilt = wi
        .rebuild_from_private_receive_records(&opts, true)
        .expect("rebuild should restore entry from .prw.json record and wallet file");

    assert_eq!(rebuilt.total_entries(), 1);
    assert!(wi.contains_one_time_wallet(&opts, &wallet_b()).unwrap());

    let rebuilt_entry = wi
        .lookup_entry(&opts, &wallet_b())
        .unwrap()
        .expect("rebuilt lookup should exist")
        .entry;

    assert_eq!(rebuilt_entry.owner_wallet, wallet_a());
    assert_eq!(rebuilt_entry.one_time_wallet, wallet_b());
    assert_eq!(
        rebuilt_entry.context.as_deref(),
        Some("rebuilt_from_private_receive_record")
    );
}
