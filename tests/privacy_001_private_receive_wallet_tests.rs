use remzar::privacy::privacy_001_private_receive_wallet::{
    MAX_PRIVATE_RECEIVE_INVOICE_LEN, PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_METADATA_DIR,
    PRIVATE_RECEIVE_RECORD_EXT, PRIVATE_RECEIVE_VERSION, PrivateRW,
    PrivateReceiveCreateOwnedRequest, PrivateReceiveCreateRequest, PrivateReceiveWalletReceipt,
    PrivateReceiveWalletRecord, WALLET_FILE_EXT,
};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_PASSPHRASE: &str = "remzar-private-receive-test-passphrase-2026";
const UNIX_2000_SECS: u64 = 946_684_800;

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

struct EnvVarGuard {
    key: &'static str,
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(self.key);
        }
    }
}

fn set_env_var_for_test(key: &'static str, value: &str) -> EnvVarGuard {
    unsafe {
        std::env::set_var(key, value);
    }
    EnvVarGuard { key }
}

fn global_create_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn test_data_dir(label: &str) -> TestDataDir {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after UNIX_EPOCH")
        .as_nanos();

    let root = std::env::temp_dir().join(format!(
        "remzar_prw_tests_{label}_{}_{}",
        std::process::id(),
        nanos
    ));

    fs::create_dir_all(&root).expect("test temp data dir should be created");

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

fn uppercase_wallet_a() -> String {
    format!("R{}", "A".repeat(128))
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

fn valid_receipt() -> PrivateReceiveWalletReceipt {
    let owner = wallet_a();
    let one_time = wallet_b();

    PrivateReceiveWalletReceipt {
        version: PRIVATE_RECEIVE_VERSION,
        owner_wallet: owner,
        one_time_wallet: one_time.clone(),
        invoice: PrivateRW::make_invoice(&one_time).expect("valid invoice"),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_path: "/tmp/remzar/test.wallet".to_string(),
        metadata_file_path: "/tmp/remzar/private_receive/test.prw.json".to_string(),
    }
}

fn valid_record() -> PrivateReceiveWalletRecord {
    let owner = wallet_a();
    let one_time = wallet_b();

    PrivateReceiveWalletRecord {
        version: PRIVATE_RECEIVE_VERSION,
        kind: "remzar_private_receive_wallet".to_string(),
        owner_wallet: owner,
        one_time_wallet: one_time.clone(),
        invoice: PrivateRW::make_invoice(&one_time).expect("valid invoice"),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_name: PrivateRW::wallet_file_name(&one_time),
    }
}

fn create_owner_wallet_placeholder(opts: &NodeOpts, owner_wallet: &str) -> PathBuf {
    let directory = DirectoryDB::from_node_opts(opts).expect("DirectoryDB should initialize");
    directory
        .create_wallets_directory()
        .expect("wallets directory should be created");

    let owner_file = PrivateRW::wallet_file_path(&directory.wallets_path, owner_wallet);
    fs::write(&owner_file, b"owner-wallet-placeholder-for-test")
        .expect("owner wallet placeholder should be written");

    owner_file
}

fn uppercase_wallet_with_body_char_41_to_100(ch: char) -> String {
    assert!(matches!(ch, 'A'..='F'));
    format!("R{}", ch.to_string().repeat(128))
}

fn write_record_for_test(opts: &NodeOpts, record: &PrivateReceiveWalletRecord) -> PathBuf {
    let directory = DirectoryDB::from_node_opts(opts).expect("DirectoryDB should initialize");
    directory
        .create_wallets_directory()
        .expect("wallets directory should be created");

    let metadata_file =
        PrivateRW::metadata_file_path(&directory.wallets_path, &record.one_time_wallet);

    let parent = metadata_file
        .parent()
        .expect("metadata file should have parent");

    fs::create_dir_all(parent).expect("metadata parent should be created");

    let bytes = serde_json::to_vec_pretty(record).expect("record should serialize");
    fs::write(&metadata_file, bytes).expect("record should be written");

    metadata_file
}

#[test]
fn test_001_constants_are_expected_private_receive_values() {
    assert_eq!(PRIVATE_RECEIVE_VERSION, 1);
    assert_eq!(PRIVATE_RECEIVE_INVOICE_PREFIX, "remzar-private-receive");
    assert_eq!(PRIVATE_RECEIVE_METADATA_DIR, "private_receive");
    assert_eq!(WALLET_FILE_EXT, "wallet");
    assert_eq!(PRIVATE_RECEIVE_RECORD_EXT, "prw.json");
    assert_eq!(MAX_PRIVATE_RECEIVE_INVOICE_LEN, 512);
}

#[test]
fn test_002_private_rw_is_stateless_default_constructible_and_zero_sized() {
    let via_new = PrivateRW::new();
    let via_default = PrivateRW::default();

    assert_eq!(format!("{via_new:?}"), format!("{via_default:?}"));
    assert_eq!(std::mem::size_of::<PrivateRW>(), 0);
}

#[test]
fn test_003_wallet_file_name_appends_wallet_extension() {
    let wallet = wallet_a();

    assert_eq!(
        PrivateRW::wallet_file_name(&wallet),
        format!("{wallet}.{WALLET_FILE_EXT}")
    );
}

#[test]
fn test_004_wallet_file_path_joins_wallets_path_and_file_name() {
    let wallets_path = PathBuf::from("wallets");
    let wallet = wallet_a();

    assert_eq!(
        PrivateRW::wallet_file_path(&wallets_path, &wallet),
        wallets_path.join(format!("{wallet}.{WALLET_FILE_EXT}"))
    );
}

#[test]
fn test_005_metadata_dir_path_joins_private_receive_subdir() {
    let wallets_path = PathBuf::from("wallets");

    assert_eq!(
        PrivateRW::metadata_dir_path(&wallets_path),
        wallets_path.join(PRIVATE_RECEIVE_METADATA_DIR)
    );
}

#[test]
fn test_006_metadata_file_path_uses_private_receive_dir_and_prw_json_extension() {
    let wallets_path = PathBuf::from("wallets");
    let wallet = wallet_b();

    assert_eq!(
        PrivateRW::metadata_file_path(&wallets_path, &wallet),
        wallets_path
            .join(PRIVATE_RECEIVE_METADATA_DIR)
            .join(format!("{wallet}.{PRIVATE_RECEIVE_RECORD_EXT}"))
    );
}

#[test]
fn test_007_make_invoice_accepts_canonical_wallet_and_formats_v1_invoice() {
    let wallet = wallet_a();

    let invoice = PrivateRW::make_invoice(&wallet).expect("canonical wallet should make invoice");

    assert_eq!(
        invoice,
        format!("{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}:{wallet}")
    );
    assert!(invoice.len() <= MAX_PRIVATE_RECEIVE_INVOICE_LEN);
}

#[test]
fn test_008_make_invoice_trims_and_canonicalizes_uppercase_wallet() {
    let uppercase = uppercase_wallet_a();

    let invoice = PrivateRW::make_invoice(&format!("  {uppercase}\n"))
        .expect("uppercase boundary wallet should canonicalize");

    assert_eq!(
        invoice,
        format!(
            "{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}:{}",
            wallet_a()
        )
    );
}

#[test]
fn test_009_make_invoice_rejects_empty_wallet() {
    assert_err_contains(PrivateRW::make_invoice(""), "Wallet address");
}

#[test]
fn test_010_make_invoice_rejects_non_hex_wallet_body() {
    let bad_wallet = format!("r{}", "g".repeat(128));

    assert_err_contains(PrivateRW::make_invoice(&bad_wallet), "Wallet address");
}

#[test]
fn test_011_parse_invoice_or_address_accepts_valid_invoice() {
    let wallet = wallet_a();
    let invoice = PrivateRW::make_invoice(&wallet).expect("valid invoice");

    let parsed = PrivateRW::parse_invoice_or_address(&invoice).expect("invoice should parse");

    assert_eq!(parsed, wallet);
}

#[test]
fn test_012_parse_invoice_or_address_trims_valid_invoice() {
    let wallet = wallet_b();
    let invoice = PrivateRW::make_invoice(&wallet).expect("valid invoice");

    let parsed =
        PrivateRW::parse_invoice_or_address(&format!("\n\t {invoice} \r\n")).expect("parse");

    assert_eq!(parsed, wallet);
}

#[test]
fn test_013_parse_invoice_or_address_accepts_raw_wallet_address() {
    let wallet = wallet_c();

    let parsed = PrivateRW::parse_invoice_or_address(&wallet).expect("raw wallet should parse");

    assert_eq!(parsed, wallet);
}

#[test]
fn test_014_parse_invoice_or_address_canonicalizes_uppercase_raw_wallet() {
    let parsed =
        PrivateRW::parse_invoice_or_address(&uppercase_wallet_a()).expect("uppercase should parse");

    assert_eq!(parsed, wallet_a());
}

#[test]
fn test_015_parse_invoice_or_address_canonicalizes_uppercase_wallet_inside_invoice() {
    let invoice = format!(
        "{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}:{}",
        uppercase_wallet_a()
    );

    let parsed = PrivateRW::parse_invoice_or_address(&invoice).expect("invoice should parse");

    assert_eq!(parsed, wallet_a());
}

#[test]
fn test_016_parse_invoice_or_address_rejects_empty_input() {
    assert_err_contains(
        PrivateRW::parse_invoice_or_address(" \n\t "),
        "cannot be empty",
    );
}

#[test]
fn test_017_parse_invoice_or_address_rejects_oversized_input() {
    let too_long = "x".repeat(MAX_PRIVATE_RECEIVE_INVOICE_LEN + 1);

    assert_err_contains(PrivateRW::parse_invoice_or_address(&too_long), "too long");
}

#[test]
fn test_018_parse_invoice_or_address_rejects_unsupported_version() {
    let invoice = format!("{PRIVATE_RECEIVE_INVOICE_PREFIX}:v2:{}", wallet_a());

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&invoice),
        "Unsupported private receive invoice version",
    );
}

#[test]
fn test_019_parse_invoice_or_address_rejects_missing_wallet_separator() {
    let invoice = format!("{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}");

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&invoice),
        "Expected remzar-private-receive:v1:<wallet>",
    );
}

#[test]
fn test_020_parse_invoice_or_address_rejects_empty_invoice_wallet() {
    let invoice = format!("{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}:");

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&invoice),
        "wallet address is empty",
    );
}

#[test]
fn test_021_parse_invoice_or_address_rejects_too_many_colon_separators() {
    let invoice = format!(
        "{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}:{}:extra",
        wallet_a()
    );

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&invoice),
        "too many ':' separators",
    );
}

#[test]
fn test_022_parse_invoice_or_address_rejects_unknown_colon_payload() {
    let payload = format!("not-private:v1:{}", wallet_a());

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&payload),
        "Expected remzar-private-receive:v1:<wallet> or raw wallet address",
    );
}

#[test]
fn test_023_parse_invoice_or_address_rejects_invalid_wallet_inside_invoice() {
    let invoice =
        format!("{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}:not-a-wallet");

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&invoice),
        "Invalid private receive invoice wallet address",
    );
}

#[test]
fn test_024_is_private_receive_invoice_returns_true_for_valid_invoice() {
    let invoice = PrivateRW::make_invoice(&wallet_a()).expect("valid invoice");

    assert!(PrivateRW::is_private_receive_invoice(&invoice));
}

#[test]
fn test_025_is_private_receive_invoice_trims_input_before_checking_prefix() {
    let invoice = PrivateRW::make_invoice(&wallet_a()).expect("valid invoice");

    assert!(PrivateRW::is_private_receive_invoice(&format!(
        "\n {invoice}\t"
    )));
}

#[test]
fn test_026_is_private_receive_invoice_returns_false_for_raw_wallet() {
    assert!(!PrivateRW::is_private_receive_invoice(&wallet_a()));
}

#[test]
fn test_027_is_private_receive_invoice_is_prefix_only_not_full_validation() {
    let malformed =
        format!("{PRIVATE_RECEIVE_INVOICE_PREFIX}:v{PRIVATE_RECEIVE_VERSION}:not-a-wallet");

    assert!(PrivateRW::is_private_receive_invoice(&malformed));
    assert!(PrivateRW::parse_invoice_or_address(&malformed).is_err());
}

#[test]
fn test_028_validate_receipt_accepts_valid_receipt() {
    let receipt = valid_receipt();

    PrivateRW::validate_receipt(&receipt).expect("valid receipt should pass");
}

#[test]
fn test_029_validate_receipt_rejects_wrong_version() {
    let mut receipt = valid_receipt();
    receipt.version = PRIVATE_RECEIVE_VERSION + 1;

    assert_err_contains(
        PrivateRW::validate_receipt(&receipt),
        "receipt version mismatch",
    );
}

#[test]
fn test_030_validate_receipt_rejects_same_owner_and_one_time_wallet() {
    let mut receipt = valid_receipt();
    receipt.one_time_wallet = receipt.owner_wallet.clone();
    receipt.invoice = PrivateRW::make_invoice(&receipt.one_time_wallet).expect("valid invoice");

    assert_err_contains(PrivateRW::validate_receipt(&receipt), "cannot be the same");
}

#[test]
fn test_031_validate_receipt_rejects_invoice_that_does_not_match_one_time_wallet() {
    let mut receipt = valid_receipt();
    receipt.invoice = PrivateRW::make_invoice(&wallet_c()).expect("valid invoice");

    assert_err_contains(
        PrivateRW::validate_receipt(&receipt),
        "invoice does not match one-time wallet",
    );
}

#[test]
fn test_032_validate_receipt_rejects_zero_created_timestamp() {
    let mut receipt = valid_receipt();
    receipt.created_unix_secs = 0;

    assert_err_contains(PrivateRW::validate_receipt(&receipt), "created_unix_secs=0");
}

#[test]
fn test_033_validate_receipt_rejects_empty_wallet_file_path() {
    let mut receipt = valid_receipt();
    receipt.wallet_file_path = " \n\t ".to_string();

    assert_err_contains(
        PrivateRW::validate_receipt(&receipt),
        "wallet_file_path is empty",
    );
}

#[test]
fn test_034_validate_receipt_rejects_empty_metadata_file_path() {
    let mut receipt = valid_receipt();
    receipt.metadata_file_path = " \n\t ".to_string();

    assert_err_contains(
        PrivateRW::validate_receipt(&receipt),
        "metadata_file_path is empty",
    );
}

#[test]
fn test_035_validate_record_accepts_valid_record() {
    let record = valid_record();

    PrivateRW::validate_record(&record).expect("valid record should pass");
}

#[test]
fn test_036_validate_record_rejects_wrong_version() {
    let mut record = valid_record();
    record.version = PRIVATE_RECEIVE_VERSION + 1;

    assert_err_contains(
        PrivateRW::validate_record(&record),
        "record version mismatch",
    );
}

#[test]
fn test_037_validate_record_rejects_wrong_kind() {
    let mut record = valid_record();
    record.kind = "wrong_kind".to_string();

    assert_err_contains(
        PrivateRW::validate_record(&record),
        "Invalid private receive record kind",
    );
}

#[test]
fn test_038_validate_record_rejects_core_record_invariant_failures() {
    let mut same_wallet_record = valid_record();
    same_wallet_record.one_time_wallet = same_wallet_record.owner_wallet.clone();
    same_wallet_record.invoice =
        PrivateRW::make_invoice(&same_wallet_record.one_time_wallet).expect("valid invoice");
    same_wallet_record.wallet_file_name =
        PrivateRW::wallet_file_name(&same_wallet_record.one_time_wallet);

    assert_err_contains(
        PrivateRW::validate_record(&same_wallet_record),
        "cannot be the same",
    );

    let mut mismatched_invoice_record = valid_record();
    mismatched_invoice_record.invoice =
        PrivateRW::make_invoice(&wallet_c()).expect("valid invoice");

    assert_err_contains(
        PrivateRW::validate_record(&mismatched_invoice_record),
        "invoice does not match one-time wallet",
    );

    let mut zero_timestamp_record = valid_record();
    zero_timestamp_record.created_unix_secs = 0;

    assert_err_contains(
        PrivateRW::validate_record(&zero_timestamp_record),
        "created_unix_secs=0",
    );

    let mut bad_wallet_file_name_record = valid_record();
    bad_wallet_file_name_record.wallet_file_name = "wrong.wallet".to_string();

    assert_err_contains(
        PrivateRW::validate_record(&bad_wallet_file_name_record),
        "wallet_file_name does not match one-time wallet",
    );
}

#[test]
fn test_039_create_receive_wallet_writes_wallet_metadata_and_loads_record() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("039_create_success");
    let opts = node_opts_for(&dir, &owner);

    let owner_file = create_owner_wallet_placeholder(&opts, &owner);
    assert!(owner_file.exists());

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &format!("  {}  ", uppercase_wallet_a()),
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: true,
            },
        )
        .expect("private receive wallet creation should succeed");

    assert_eq!(receipt.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(receipt.owner_wallet, owner);
    assert_ne!(receipt.owner_wallet, receipt.one_time_wallet);
    assert!(receipt.created_unix_secs >= UNIX_2000_SECS);
    assert!(PrivateRW::is_private_receive_invoice(&receipt.invoice));

    let parsed_invoice =
        PrivateRW::parse_invoice_or_address(&receipt.invoice).expect("receipt invoice parses");
    assert_eq!(parsed_invoice, receipt.one_time_wallet);

    let wallet_path = Path::new(&receipt.wallet_file_path);
    let metadata_path = Path::new(&receipt.metadata_file_path);

    assert!(wallet_path.exists(), "wallet file should exist");
    assert!(metadata_path.exists(), "metadata file should exist");

    assert_eq!(
        wallet_path.file_name().unwrap().to_string_lossy(),
        PrivateRW::wallet_file_name(&receipt.one_time_wallet)
    );
    assert_eq!(
        metadata_path.file_name().unwrap().to_string_lossy(),
        format!("{}.{}", receipt.one_time_wallet, PRIVATE_RECEIVE_RECORD_EXT)
    );

    let encrypted_wallet_bytes = fs::read(wallet_path).expect("wallet file should be readable");
    assert!(
        encrypted_wallet_bytes.len() >= 32,
        "encrypted wallet file should not be empty or tiny"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(wallet_path)
            .expect("wallet file metadata should be readable")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600, "wallet file should be private on Unix");
    }

    let loaded_record = PrivateRW::load_record_by_one_time_wallet(&opts, &receipt.one_time_wallet)
        .expect("record should load by one-time wallet");

    assert_eq!(loaded_record.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(loaded_record.kind, "remzar_private_receive_wallet");
    assert_eq!(loaded_record.owner_wallet, receipt.owner_wallet);
    assert_eq!(loaded_record.one_time_wallet, receipt.one_time_wallet);
    assert_eq!(loaded_record.invoice, receipt.invoice);
    assert_eq!(
        loaded_record.wallet_file_name,
        PrivateRW::wallet_file_name(&receipt.one_time_wallet)
    );

    PrivateRW::validate_record(&loaded_record).expect("loaded record should validate");

    let metadata_bytes = fs::read(metadata_path).expect("metadata file should be readable");
    let decoded_record: PrivateReceiveWalletRecord =
        serde_json::from_slice(&metadata_bytes).expect("metadata should be valid JSON record");

    assert_eq!(decoded_record, loaded_record);

    let owned_receipt = PrivateRW::new()
        .create_receive_wallet_owned(
            &opts,
            PrivateReceiveCreateOwnedRequest {
                owner_wallet: owner.clone(),
                passphrase: TEST_PASSPHRASE.to_string(),
                require_owner_wallet_file: true,
            },
        )
        .expect("owned request creation should also succeed");

    assert_eq!(owned_receipt.owner_wallet, owner);
    assert_ne!(owned_receipt.one_time_wallet, receipt.one_time_wallet);
    assert!(Path::new(&owned_receipt.wallet_file_path).exists());
    assert!(Path::new(&owned_receipt.metadata_file_path).exists());
}

#[test]
fn test_040_create_receive_wallet_rejects_bad_inputs_missing_owner_and_fault_injection() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("040_create_failures");
    let opts = node_opts_for(&dir, &owner);
    let rw = PrivateRW::new();

    assert_err_contains(
        rw.create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: "not-a-wallet",
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        ),
        "Invalid owner wallet",
    );

    assert_err_contains(
        rw.create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: " \n\t ",
                require_owner_wallet_file: false,
            },
        ),
        "passphrase cannot be empty",
    );

    let too_large_passphrase = "x".repeat((16 * 1024) + 1);
    assert_err_contains(
        rw.create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: &too_large_passphrase,
                require_owner_wallet_file: false,
            },
        ),
        "passphrase is too large",
    );

    assert_err_contains(
        rw.create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: true,
            },
        ),
        "Owner wallet file not found",
    );

    let _fault = set_env_var_for_test("REMZAR_FAIL_PRIVATE_RW_CREATE_PRE", "1");

    assert_err_contains(
        rw.create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        ),
        "Fault injection triggered",
    );
}

#[test]
fn test_041_parse_raw_wallet_trims_and_canonicalizes_uppercase() {
    let input = format!(" \n\t{}  \r\n", uppercase_wallet_a());

    let parsed = PrivateRW::parse_invoice_or_address(&input).expect("wallet should parse");

    assert_eq!(parsed, wallet_a());
}

#[test]
fn test_042_parse_raw_wallet_rejects_embedded_colon_payload() {
    let input = format!("{}:{}", wallet_a(), wallet_b());

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Expected remzar-private-receive:v1:<wallet> or raw wallet address",
    );
}

#[test]
fn test_043_parse_invoice_is_case_sensitive_for_prefix() {
    let input = format!(
        "Remzar-private-receive:v{}:{}",
        PRIVATE_RECEIVE_VERSION,
        wallet_a()
    );

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Expected remzar-private-receive:v1:<wallet> or raw wallet address",
    );
}

#[test]
fn test_044_parse_invoice_rejects_uppercase_version_marker() {
    let input = format!(
        "{}:V{}:{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        wallet_a()
    );

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Unsupported private receive invoice version",
    );
}

#[test]
fn test_045_parse_invoice_rejects_empty_version_marker() {
    let input = format!("{}::{}", PRIVATE_RECEIVE_INVOICE_PREFIX, wallet_a());

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Unsupported private receive invoice version",
    );
}

#[test]
fn test_046_parse_invoice_rejects_whitespace_only_wallet_part() {
    let input = format!(
        "{}:v{}:   ",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
    );

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Private receive invoice wallet address is empty",
    );
}

#[test]
fn test_047_parse_invoice_rejects_short_wallet_address() {
    let input = format!(
        "{}:v{}:r{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        "a".repeat(127)
    );

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Invalid private receive invoice wallet address",
    );
}

#[test]
fn test_048_parse_invoice_rejects_long_wallet_address() {
    let input = format!(
        "{}:v{}:r{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        "a".repeat(129)
    );

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Invalid private receive invoice wallet address",
    );
}

#[test]
fn test_049_parse_raw_wallet_rejects_missing_r_prefix() {
    let input = "a".repeat(128);

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Invalid private receive wallet address",
    );
}

#[test]
fn test_050_parse_raw_wallet_rejects_wrong_prefix() {
    let input = format!("p{}", "a".repeat(128));

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Invalid private receive wallet address",
    );
}

#[test]
fn test_051_parse_raw_wallet_rejects_internal_newline() {
    let input = format!("r{}{}", "a".repeat(64), "\n".to_string() + &"a".repeat(64));

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Invalid private receive wallet address",
    );
}

#[test]
fn test_052_parse_raw_wallet_accepts_mixed_case_hex_and_returns_lowercase() {
    // 16 hex chars * 8 = 128 hex chars, plus "r" prefix = 129 total chars.
    let body = "AaBbCcDdEeFf0123".repeat(8);
    let input = format!("r{body}");

    assert_eq!(input.len(), 129);

    let parsed = PrivateRW::parse_invoice_or_address(&input).expect("mixed-case hex should parse");

    assert_eq!(parsed, input.to_lowercase());
}

#[test]
fn test_053_invoice_has_expected_shape_and_reasonable_length() {
    let invoice = PrivateRW::make_invoice(&wallet_a()).expect("valid invoice");

    assert!(invoice.starts_with(&format!(
        "{}:v{}:",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
    )));
    assert!(invoice.ends_with(&wallet_a()));
    assert_eq!(
        invoice,
        format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX,
            PRIVATE_RECEIVE_VERSION,
            wallet_a()
        )
    );
    assert!(invoice.len() < MAX_PRIVATE_RECEIVE_INVOICE_LEN);
}

#[test]
fn test_054_validate_receipt_accepts_uppercase_wallet_fields_when_invoice_matches() {
    let one_time_upper = uppercase_wallet_with_body_char_41_to_100('B');

    let receipt = PrivateReceiveWalletReceipt {
        version: PRIVATE_RECEIVE_VERSION,
        owner_wallet: uppercase_wallet_a(),
        one_time_wallet: one_time_upper,
        invoice: PrivateRW::make_invoice(&wallet_b()).expect("valid invoice"),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_path: "/tmp/remzar/test.wallet".to_string(),
        metadata_file_path: "/tmp/remzar/private_receive/test.prw.json".to_string(),
    };

    PrivateRW::validate_receipt(&receipt).expect("uppercase fields should validate canonically");
}

#[test]
fn test_055_validate_receipt_rejects_invalid_owner_wallet() {
    let mut receipt = valid_receipt();
    receipt.owner_wallet = "not-a-wallet".to_string();

    assert_err_contains(PrivateRW::validate_receipt(&receipt), "Wallet address");
}

#[test]
fn test_056_validate_receipt_rejects_invalid_one_time_wallet() {
    let mut receipt = valid_receipt();
    receipt.one_time_wallet = "not-a-wallet".to_string();

    assert_err_contains(PrivateRW::validate_receipt(&receipt), "Wallet address");
}

#[test]
fn test_057_validate_receipt_rejects_invalid_invoice_payload() {
    let mut receipt = valid_receipt();
    receipt.invoice = "not-private:v1:not-a-wallet".to_string();

    assert_err_contains(
        PrivateRW::validate_receipt(&receipt),
        "Expected remzar-private-receive:v1:<wallet> or raw wallet address",
    );
}

#[test]
fn test_058_receipt_json_roundtrip_preserves_all_fields() {
    let receipt = valid_receipt();

    let bytes = serde_json::to_vec_pretty(&receipt).expect("receipt should serialize");
    let decoded: PrivateReceiveWalletReceipt =
        serde_json::from_slice(&bytes).expect("receipt should deserialize");

    assert_eq!(decoded, receipt);
    PrivateRW::validate_receipt(&decoded).expect("decoded receipt should validate");
}

#[test]
fn test_059_record_json_roundtrip_preserves_all_fields() {
    let record = valid_record();

    let bytes = serde_json::to_vec_pretty(&record).expect("record should serialize");
    let decoded: PrivateReceiveWalletRecord =
        serde_json::from_slice(&bytes).expect("record should deserialize");

    assert_eq!(decoded, record);
    PrivateRW::validate_record(&decoded).expect("decoded record should validate");
}

#[test]
fn test_060_validate_record_accepts_uppercase_wallet_fields_when_filename_is_canonical() {
    let one_time_upper = uppercase_wallet_with_body_char_41_to_100('B');

    let record = PrivateReceiveWalletRecord {
        version: PRIVATE_RECEIVE_VERSION,
        kind: "remzar_private_receive_wallet".to_string(),
        owner_wallet: uppercase_wallet_a(),
        one_time_wallet: one_time_upper,
        invoice: PrivateRW::make_invoice(&wallet_b()).expect("valid invoice"),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_name: PrivateRW::wallet_file_name(&wallet_b()),
    };

    PrivateRW::validate_record(&record).expect("record should validate canonically");
}

#[test]
fn test_061_validate_record_rejects_invalid_owner_wallet() {
    let mut record = valid_record();
    record.owner_wallet = "not-a-wallet".to_string();

    assert_err_contains(PrivateRW::validate_record(&record), "Wallet address");
}

#[test]
fn test_062_validate_record_rejects_invalid_one_time_wallet() {
    let mut record = valid_record();
    record.one_time_wallet = "not-a-wallet".to_string();

    assert_err_contains(PrivateRW::validate_record(&record), "Wallet address");
}

#[test]
fn test_063_validate_record_rejects_invalid_invoice_payload() {
    let mut record = valid_record();
    record.invoice = "not-private:v1:not-a-wallet".to_string();

    assert_err_contains(
        PrivateRW::validate_record(&record),
        "Expected remzar-private-receive:v1:<wallet> or raw wallet address",
    );
}

#[test]
fn test_064_validate_record_rejects_wrong_wallet_file_extension() {
    let mut record = valid_record();
    record.wallet_file_name = format!("{}.txt", record.one_time_wallet);

    assert_err_contains(
        PrivateRW::validate_record(&record),
        "wallet_file_name does not match one-time wallet",
    );
}

#[test]
fn test_065_load_record_by_one_time_wallet_reads_manually_written_valid_record() {
    let owner = wallet_a();
    let dir = test_data_dir("065_load_manual_record");
    let opts = node_opts_for(&dir, &owner);

    let record = valid_record();
    let metadata_file = write_record_for_test(&opts, &record);

    assert!(metadata_file.exists());

    let loaded = PrivateRW::load_record_by_one_time_wallet(&opts, &record.one_time_wallet)
        .expect("record should load");

    assert_eq!(loaded, record);
}

#[test]
fn test_066_load_record_by_one_time_wallet_canonicalizes_uppercase_lookup() {
    let owner = wallet_a();
    let dir = test_data_dir("066_load_uppercase_lookup");
    let opts = node_opts_for(&dir, &owner);

    let record = valid_record();
    write_record_for_test(&opts, &record);

    let loaded = PrivateRW::load_record_by_one_time_wallet(
        &opts,
        &uppercase_wallet_with_body_char_41_to_100('B'),
    )
    .expect("uppercase lookup should canonicalize to lowercase metadata path");

    assert_eq!(loaded, record);
}

#[test]
fn test_067_load_record_by_one_time_wallet_rejects_invalid_lookup_wallet() {
    let owner = wallet_a();
    let dir = test_data_dir("067_load_invalid_lookup");
    let opts = node_opts_for(&dir, &owner);

    assert_err_contains(
        PrivateRW::load_record_by_one_time_wallet(&opts, "not-a-wallet"),
        "Wallet address",
    );
}

#[test]
fn test_068_load_record_by_one_time_wallet_errors_when_metadata_missing() {
    let owner = wallet_a();
    let dir = test_data_dir("068_load_missing_record");
    let opts = node_opts_for(&dir, &owner);

    assert_err_contains(
        PrivateRW::load_record_by_one_time_wallet(&opts, &wallet_b()),
        "Failed to read private receive metadata",
    );
}

#[test]
fn test_069_load_record_by_one_time_wallet_rejects_malformed_json_file() {
    let owner = wallet_a();
    let dir = test_data_dir("069_load_malformed_json");
    let opts = node_opts_for(&dir, &owner);

    let directory = DirectoryDB::from_node_opts(&opts).expect("DirectoryDB should initialize");
    directory
        .create_wallets_directory()
        .expect("wallets directory should be created");

    let metadata_file = PrivateRW::metadata_file_path(&directory.wallets_path, &wallet_b());
    fs::create_dir_all(metadata_file.parent().unwrap()).expect("metadata dir should be created");
    fs::write(&metadata_file, b"{ this is not valid json").expect("bad json should be written");

    assert_err_contains(
        PrivateRW::load_record_by_one_time_wallet(&opts, &wallet_b()),
        "Failed to decode private receive metadata",
    );
}

#[test]
fn test_070_load_record_by_one_time_wallet_rejects_wrong_version_record_on_disk() {
    let owner = wallet_a();
    let dir = test_data_dir("070_load_wrong_version");
    let opts = node_opts_for(&dir, &owner);

    let mut record = valid_record();
    record.version = PRIVATE_RECEIVE_VERSION + 99;
    write_record_for_test(&opts, &record);

    assert_err_contains(
        PrivateRW::load_record_by_one_time_wallet(&opts, &record.one_time_wallet),
        "record version mismatch",
    );
}

#[test]
fn test_071_load_record_by_one_time_wallet_rejects_wrong_kind_record_on_disk() {
    let owner = wallet_a();
    let dir = test_data_dir("071_load_wrong_kind");
    let opts = node_opts_for(&dir, &owner);

    let mut record = valid_record();
    record.kind = "wrong_kind".to_string();
    write_record_for_test(&opts, &record);

    assert_err_contains(
        PrivateRW::load_record_by_one_time_wallet(&opts, &record.one_time_wallet),
        "Invalid private receive record kind",
    );
}

#[test]
fn test_072_load_record_by_one_time_wallet_rejects_mismatched_invoice_record_on_disk() {
    let owner = wallet_a();
    let dir = test_data_dir("072_load_mismatched_invoice");
    let opts = node_opts_for(&dir, &owner);

    let mut record = valid_record();
    record.invoice = PrivateRW::make_invoice(&wallet_c()).expect("valid invoice");
    write_record_for_test(&opts, &record);

    assert_err_contains(
        PrivateRW::load_record_by_one_time_wallet(&opts, &record.one_time_wallet),
        "invoice does not match one-time wallet",
    );
}

#[test]
fn test_073_metadata_paths_keep_wallet_and_metadata_files_separate() {
    let wallets_path = PathBuf::from("wallets");
    let one_time = wallet_b();

    let wallet_file = PrivateRW::wallet_file_path(&wallets_path, &one_time);
    let metadata_file = PrivateRW::metadata_file_path(&wallets_path, &one_time);

    assert_ne!(wallet_file, metadata_file);
    assert_eq!(wallet_file.parent().unwrap(), wallets_path.as_path());
    assert_eq!(
        metadata_file.parent().unwrap(),
        wallets_path.join(PRIVATE_RECEIVE_METADATA_DIR).as_path()
    );
}

#[test]
fn test_074_create_receive_wallet_succeeds_without_owner_file_when_not_required() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("074_create_no_owner_required");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("creation should succeed without owner file when not required");

    assert_eq!(receipt.owner_wallet, owner);
    assert!(Path::new(&receipt.wallet_file_path).exists());
    assert!(Path::new(&receipt.metadata_file_path).exists());
}

#[test]
fn test_075_create_receive_wallet_canonicalizes_uppercase_owner() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("075_create_uppercase_owner");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &uppercase_wallet_a(),
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("uppercase owner should canonicalize");

    assert_eq!(receipt.owner_wallet, owner);
}

#[test]
fn test_076_create_receive_wallet_creates_metadata_directory_automatically() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("076_create_metadata_dir");
    let opts = node_opts_for(&dir, &owner);

    let directory = DirectoryDB::from_node_opts(&opts).expect("DirectoryDB should initialize");
    let metadata_dir = PrivateRW::metadata_dir_path(&directory.wallets_path);

    assert!(!metadata_dir.exists());

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("creation should succeed");

    assert!(metadata_dir.exists());
    assert!(metadata_dir.is_dir());
    assert!(Path::new(&receipt.metadata_file_path).starts_with(&metadata_dir));
}

#[test]
fn test_077_create_receive_wallet_returns_receipt_that_validates() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("077_create_receipt_validates");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("creation should succeed");

    PrivateRW::validate_receipt(&receipt).expect("created receipt should validate");
}

#[test]
fn test_078_create_receive_wallet_does_not_store_plaintext_passphrase_in_wallet_or_metadata() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("078_no_plaintext_passphrase");
    let opts = node_opts_for(&dir, &owner);
    let passphrase = "super-secret-private-receive-passphrase-that-should-not-be-stored";

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase,
                require_owner_wallet_file: false,
            },
        )
        .expect("creation should succeed");

    let wallet_bytes = fs::read(&receipt.wallet_file_path).expect("wallet file should read");
    let metadata_bytes = fs::read(&receipt.metadata_file_path).expect("metadata should read");
    let needle = passphrase.as_bytes();

    assert!(
        !wallet_bytes
            .windows(needle.len())
            .any(|window| window == needle),
        "wallet file must not contain plaintext passphrase"
    );
    assert!(
        !metadata_bytes
            .windows(needle.len())
            .any(|window| window == needle),
        "metadata file must not contain plaintext passphrase"
    );
}

#[test]
fn test_079_create_receive_wallet_twice_produces_distinct_one_time_wallets() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("079_create_twice_distinct");
    let opts = node_opts_for(&dir, &owner);

    let first = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("first creation should succeed");

    let second = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("second creation should succeed");

    assert_ne!(first.one_time_wallet, second.one_time_wallet);
    assert_ne!(first.invoice, second.invoice);
    assert_ne!(first.wallet_file_path, second.wallet_file_path);
    assert_ne!(first.metadata_file_path, second.metadata_file_path);
}

#[test]
fn test_080_create_receive_wallet_loaded_record_matches_receipt() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("080_record_matches_receipt");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("creation should succeed");

    let record = PrivateRW::load_record_by_one_time_wallet(&opts, &receipt.one_time_wallet)
        .expect("record should load");

    assert_eq!(record.version, receipt.version);
    assert_eq!(record.owner_wallet, receipt.owner_wallet);
    assert_eq!(record.one_time_wallet, receipt.one_time_wallet);
    assert_eq!(record.invoice, receipt.invoice);
    assert_eq!(record.created_unix_secs, receipt.created_unix_secs);
    assert_eq!(
        record.wallet_file_name,
        PrivateRW::wallet_file_name(&receipt.one_time_wallet)
    );
}

#[test]
fn test_081_create_receive_wallet_with_required_owner_accepts_uppercase_owner_input() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("081_required_owner_uppercase");
    let opts = node_opts_for(&dir, &owner);

    create_owner_wallet_placeholder(&opts, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &uppercase_wallet_a(),
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: true,
            },
        )
        .expect("required owner lookup should canonicalize uppercase owner");

    assert_eq!(receipt.owner_wallet, owner);
}

#[test]
fn test_082_create_receive_wallet_accepts_single_non_whitespace_passphrase_character() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("082_single_char_passphrase");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: "x",
                require_owner_wallet_file: false,
            },
        )
        .expect("single non-whitespace passphrase should be accepted");

    assert!(Path::new(&receipt.wallet_file_path).exists());
}

#[test]
fn test_083_create_receive_wallet_accepts_passphrase_with_surrounding_spaces_if_not_empty() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("083_spaced_passphrase");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: "  valid passphrase with spaces  ",
                require_owner_wallet_file: false,
            },
        )
        .expect("non-empty passphrase with spaces should be accepted");

    assert!(Path::new(&receipt.wallet_file_path).exists());
}

#[test]
fn test_084_create_receive_wallet_accepts_unicode_passphrase() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("084_unicode_passphrase");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: "秘密-remzar-🔐-private-receive",
                require_owner_wallet_file: false,
            },
        )
        .expect("unicode passphrase should be accepted");

    assert!(Path::new(&receipt.wallet_file_path).exists());
}

#[test]
fn test_085_create_receive_wallet_post_fault_returns_error_after_real_generation_path() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let _fault = set_env_var_for_test("REMZAR_FAIL_PRIVATE_RW_CREATE_POST", "1");

    let owner = wallet_a();
    let dir = test_data_dir("085_post_fault");
    let opts = node_opts_for(&dir, &owner);

    assert_err_contains(
        PrivateRW::new().create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        ),
        "Fault injection triggered",
    );
}

#[test]
fn test_086_create_receive_wallet_owned_propagates_pre_fault_error() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let _fault = set_env_var_for_test("REMZAR_FAIL_PRIVATE_RW_CREATE_PRE", "1");

    let owner = wallet_a();
    let dir = test_data_dir("086_owned_pre_fault");
    let opts = node_opts_for(&dir, &owner);

    assert_err_contains(
        PrivateRW::new().create_receive_wallet_owned(
            &opts,
            PrivateReceiveCreateOwnedRequest {
                owner_wallet: owner,
                passphrase: TEST_PASSPHRASE.to_string(),
                require_owner_wallet_file: false,
            },
        ),
        "Fault injection triggered",
    );
}

#[test]
fn test_087_parse_invoice_generated_by_real_create_flow() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("087_parse_real_invoice");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("creation should succeed");

    let parsed = PrivateRW::parse_invoice_or_address(&receipt.invoice)
        .expect("real generated invoice should parse");

    assert_eq!(parsed, receipt.one_time_wallet);
}

#[test]
fn test_088_make_invoice_rejects_wallet_with_extra_trailing_hex_character() {
    let too_long_wallet = format!("{}a", wallet_a());

    assert_err_contains(PrivateRW::make_invoice(&too_long_wallet), "Wallet address");
}

#[test]
fn test_089_make_invoice_rejects_wallet_with_leading_non_wallet_text() {
    let bad_wallet = format!("prefix{}", wallet_a());

    assert_err_contains(PrivateRW::make_invoice(&bad_wallet), "Wallet address");
}

#[test]
fn test_090_is_private_receive_invoice_returns_false_for_v2_prefix() {
    let input = format!("{}:v2:{}", PRIVATE_RECEIVE_INVOICE_PREFIX, wallet_a());

    assert!(!PrivateRW::is_private_receive_invoice(&input));
}

#[test]
fn test_091_is_private_receive_invoice_returns_false_when_prefix_is_not_at_start() {
    let invoice = PrivateRW::make_invoice(&wallet_a()).expect("valid invoice");
    let input = format!("prefix-{invoice}");

    assert!(!PrivateRW::is_private_receive_invoice(&input));
}

#[test]
fn test_092_validate_record_accepts_uppercase_one_time_with_lowercase_wallet_file_name() {
    let one_time_upper = uppercase_wallet_with_body_char_41_to_100('B');

    let record = PrivateReceiveWalletRecord {
        version: PRIVATE_RECEIVE_VERSION,
        kind: "remzar_private_receive_wallet".to_string(),
        owner_wallet: wallet_a(),
        one_time_wallet: one_time_upper,
        invoice: PrivateRW::make_invoice(&wallet_b()).expect("valid invoice"),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_name: PrivateRW::wallet_file_name(&wallet_b()),
    };

    PrivateRW::validate_record(&record)
        .expect("uppercase one-time wallet should validate with canonical filename");
}

#[test]
fn test_093_validate_record_rejects_uppercase_wallet_file_name_when_canonical_lowercase_expected() {
    let one_time_upper = uppercase_wallet_with_body_char_41_to_100('B');

    let record = PrivateReceiveWalletRecord {
        version: PRIVATE_RECEIVE_VERSION,
        kind: "remzar_private_receive_wallet".to_string(),
        owner_wallet: wallet_a(),
        one_time_wallet: one_time_upper.clone(),
        invoice: PrivateRW::make_invoice(&wallet_b()).expect("valid invoice"),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_name: PrivateRW::wallet_file_name(&one_time_upper),
    };

    assert_err_contains(
        PrivateRW::validate_record(&record),
        "wallet_file_name does not match one-time wallet",
    );
}

#[test]
fn test_094_path_helpers_are_pure_formatters_and_do_not_validate_wallet_text() {
    let wallets_path = PathBuf::from("wallets");
    let malformed = "not-a-wallet";

    assert_eq!(
        PrivateRW::wallet_file_name(malformed),
        "not-a-wallet.wallet"
    );
    assert_eq!(
        PrivateRW::wallet_file_path(&wallets_path, malformed),
        wallets_path.join("not-a-wallet.wallet")
    );
    assert_eq!(
        PrivateRW::metadata_file_path(&wallets_path, malformed),
        wallets_path
            .join(PRIVATE_RECEIVE_METADATA_DIR)
            .join("not-a-wallet.prw.json")
    );
}

#[test]
fn test_095_invoice_parser_regression_invoice_prefix_starts_with_r_but_parses_as_invoice() {
    let invoice = format!(
        "{}:v{}:{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        wallet_a()
    );

    assert!(invoice.starts_with('r'));

    let parsed = PrivateRW::parse_invoice_or_address(&invoice)
        .expect("invoice must be parsed before raw r-address logic");

    assert_eq!(parsed, wallet_a());
}

#[test]
fn test_096_parse_invoice_rejects_prefix_with_no_version_or_wallet() {
    let input = format!("{PRIVATE_RECEIVE_INVOICE_PREFIX}:");

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Expected remzar-private-receive:v1:<wallet>",
    );
}

#[test]
fn test_097_parse_raw_wallet_rejects_internal_space() {
    let input = format!("r{} {}", "a".repeat(64), "a".repeat(63));

    assert_eq!(input.len(), 129);

    assert_err_contains(
        PrivateRW::parse_invoice_or_address(&input),
        "Invalid private receive wallet address",
    );
}

#[test]
fn test_098_validate_receipt_accepts_raw_one_time_wallet_in_invoice_field() {
    let mut receipt = valid_receipt();
    receipt.invoice = receipt.one_time_wallet.clone();

    PrivateRW::validate_receipt(&receipt)
        .expect("receipt validator currently accepts raw wallet through parse_invoice_or_address");
}

#[test]
fn test_099_validate_record_accepts_raw_one_time_wallet_in_invoice_field() {
    let mut record = valid_record();
    record.invoice = record.one_time_wallet.clone();

    PrivateRW::validate_record(&record)
        .expect("record validator currently accepts raw wallet through parse_invoice_or_address");
}

#[test]
fn test_100_end_to_end_create_then_load_record_using_whitespace_uppercase_lookup() {
    let _guard = global_create_lock()
        .lock()
        .expect("global create lock should not be poisoned");

    let owner = wallet_a();
    let dir = test_data_dir("100_end_to_end_uppercase_lookup");
    let opts = node_opts_for(&dir, &owner);

    let receipt = PrivateRW::new()
        .create_receive_wallet(
            &opts,
            PrivateReceiveCreateRequest {
                owner_wallet: &owner,
                passphrase: TEST_PASSPHRASE,
                require_owner_wallet_file: false,
            },
        )
        .expect("creation should succeed");

    let uppercase_lookup = format!(" \n\t{}  ", receipt.one_time_wallet.to_uppercase());

    let loaded = PrivateRW::load_record_by_one_time_wallet(&opts, &uppercase_lookup)
        .expect("load should trim and canonicalize uppercase one-time wallet");

    assert_eq!(loaded.owner_wallet, receipt.owner_wallet);
    assert_eq!(loaded.one_time_wallet, receipt.one_time_wallet);
    assert_eq!(loaded.invoice, receipt.invoice);
    assert_eq!(
        loaded.wallet_file_name,
        PrivateRW::wallet_file_name(&receipt.one_time_wallet)
    );

    PrivateRW::validate_record(&loaded).expect("loaded record should validate");
}
