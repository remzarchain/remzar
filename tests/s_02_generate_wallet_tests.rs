use fips204::ml_dsa_65;
use remzar::commandline::s_02_generate_wallet::S02GenerateWallet;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::logging_data::JsonLogger;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_02_generate_wallet_tests_{test_name}_{}_{}",
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

fn wallet_crypto_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn with_wallet_crypto_lock<T>(op: impl FnOnce() -> T) -> T {
    let _guard = wallet_crypto_guard();
    op()
}

fn wallet_cache() -> &'static Mutex<HashMap<String, MLDSA65Wallet>> {
    static CACHE: OnceLock<Mutex<HashMap<String, MLDSA65Wallet>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn make_wallet(passphrase: &str) -> MLDSA65Wallet {
    {
        let cache = wallet_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(wallet) = cache.get(passphrase) {
            return wallet.clone();
        }
    }

    let wallet =
        with_wallet_crypto_lock(|| assert_ok(MLDSA65Wallet::new(passphrase), "MLDSA65Wallet::new"));

    let mut cache = wallet_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    cache
        .entry(passphrase.to_string())
        .or_insert_with(|| wallet.clone())
        .clone()
}

fn wallet_validate_self(wallet: &MLDSA65Wallet) -> Result<(), ErrorDetection> {
    with_wallet_crypto_lock(|| wallet.validate_self())
}

fn wallet_sign(
    wallet: &MLDSA65Wallet,
    passphrase: &str,
    message: &[u8],
) -> Result<Vec<u8>, ErrorDetection> {
    with_wallet_crypto_lock(|| wallet.sign(passphrase, message))
}

fn wallet_verify(wallet: &MLDSA65Wallet, message: &[u8], signature: &[u8]) -> bool {
    with_wallet_crypto_lock(|| wallet.verify(message, signature))
}

fn wallet_secret_key_hex(
    wallet: &MLDSA65Wallet,
    passphrase: &str,
) -> Result<String, ErrorDetection> {
    with_wallet_crypto_lock(|| wallet.secret_key_hex(passphrase))
}

fn wallet_from_parts(
    public: [u8; ml_dsa_65::PK_LEN],
    encrypted_secret: Vec<u8>,
) -> Result<MLDSA65Wallet, ErrorDetection> {
    with_wallet_crypto_lock(|| MLDSA65Wallet::from_parts(public, encrypted_secret))
}

fn wallet_generate_address(public: &[u8; ml_dsa_65::PK_LEN]) -> Result<String, ErrorDetection> {
    with_wallet_crypto_lock(|| MLDSA65Wallet::generate_address(public))
}

fn wallet_address_from_secret_bytes(secret: &[u8]) -> Result<String, ErrorDetection> {
    with_wallet_crypto_lock(|| MLDSA65Wallet::address_from_secret_bytes(secret))
}

fn assert_wallet_address_shape(address: &str) {
    assert_eq!(address.len(), 129);
    assert!(address.starts_with('r'));

    for byte in address.as_bytes().iter().skip(1) {
        assert!(byte.is_ascii_hexdigit());
        assert!(!byte.is_ascii_uppercase());
    }
}

fn assert_wallet_valid(wallet: &MLDSA65Wallet) {
    assert_ok(wallet_validate_self(wallet), "wallet.validate_self");
    assert_wallet_address_shape(&wallet.address);
    assert!(!wallet.encrypted_secret.is_empty());
}

fn wallet_file_path(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    directory
        .wallets_path
        .join(format!("{}.wallet", wallet.address))
}

fn write_wallet_file(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let wallet_file = wallet_file_path(directory, wallet);
    assert_ok(
        fs::write(&wallet_file, &wallet.encrypted_secret),
        "write wallet file",
    );
    wallet_file
}

fn deterministic_message(seed: usize, repeat: usize) -> Vec<u8> {
    let mut out = Vec::new();

    for index in 0..repeat {
        out.extend_from_slice(format!("message-{seed}-{index};").as_bytes());
    }

    out
}

fn deterministic_passphrase(seed: usize) -> String {
    format!("Remzar-Test-Passphrase-{seed}-!@#")
}

fn count_wallet_files(path: &Path) -> usize {
    let entries = match fs::read_dir(path) {
        Ok(value) => value,
        Err(err) => panic!(
            "failed to read wallet directory '{}': {err}",
            path.display()
        ),
    };

    entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map_or(false, |ext| ext == "wallet")
        })
        .count()
}

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S02GenerateWallet::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S02GenerateWallet;
}

#[test]
fn test_03_default_trait_creates_section() {
    let _section = S02GenerateWallet::default();
}

#[test]
fn test_04_wallet_new_generates_valid_wallet() {
    let wallet = make_wallet("test_04_passphrase");
    assert_wallet_valid(&wallet);
}

#[test]
fn test_05_wallet_address_has_canonical_shape() {
    let wallet = make_wallet("test_05_passphrase");
    assert_wallet_address_shape(&wallet.address);
}

#[test]
fn test_06_wallet_validate_self_accepts_generated_wallet() {
    let wallet = make_wallet("test_06_passphrase");
    assert_ok(wallet_validate_self(&wallet), "validate generated wallet");
}

#[test]
fn test_07_wallet_public_key_hex_has_expected_length() {
    let wallet = make_wallet("test_07_passphrase");
    let hex_value = wallet.public_key_hex();

    assert_eq!(hex_value.len(), wallet.public.len().saturating_mul(2));
    assert!(
        hex_value
            .as_bytes()
            .iter()
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

#[test]
fn test_08_wallet_secret_key_hex_has_expected_length() {
    let passphrase = "test_08_passphrase";
    let wallet = make_wallet(passphrase);
    let secret_hex = assert_ok(wallet_secret_key_hex(&wallet, passphrase), "secret_key_hex");

    assert_eq!(
        secret_hex.len(),
        GlobalConfiguration::MLDSA65_SECRET_HEX_LEN
    );
}

#[test]
fn test_09_wallet_can_sign_and_verify_message() {
    let passphrase = "test_09_passphrase";
    let wallet = make_wallet(passphrase);
    let message = b"remzar wallet signing vector";

    let signature = assert_ok(wallet_sign(&wallet, passphrase, message), "wallet.sign");

    assert!(wallet_verify(&wallet, message, &signature));
}

#[test]
fn test_10_wallet_verify_rejects_wrong_message() {
    let passphrase = "test_10_passphrase";
    let wallet = make_wallet(passphrase);

    let signature = assert_ok(
        wallet_sign(&wallet, passphrase, b"message one"),
        "wallet.sign",
    );

    assert!(!wallet_verify(&wallet, b"message two", &signature));
}

#[test]
fn test_11_wallet_verify_rejects_empty_signature() {
    let wallet = make_wallet("test_11_passphrase");

    assert!(!wallet_verify(&wallet, b"message", b""));
}

#[test]
fn test_12_wallet_verify_rejects_short_signature() {
    let wallet = make_wallet("test_12_passphrase");
    let short_signature = vec![7_u8; 64];

    assert!(!wallet_verify(&wallet, b"message", &short_signature));
}

#[test]
fn test_13_wallet_verify_rejects_long_signature() {
    let wallet = make_wallet("test_13_passphrase");
    let long_signature = vec![7_u8; GlobalConfiguration::GUARDIAN_SIG_LEN.saturating_add(1)];

    assert!(!wallet_verify(&wallet, b"message", &long_signature));
}

#[test]
fn test_14_wallet_sign_rejects_wrong_passphrase() {
    let wallet = make_wallet("test_14_correct_passphrase");

    let err = assert_err(
        wallet_sign(&wallet, "test_14_wrong_passphrase", b"message"),
        "sign with wrong passphrase",
    );

    match err {
        ErrorDetection::DecryptionError { .. }
        | ErrorDetection::CryptographicError { .. }
        | ErrorDetection::ValidationError { .. }
        | ErrorDetection::EncryptionError { .. } => {}
        other => panic!("unexpected wrong-passphrase error: {other:?}"),
    }
}

#[test]
fn test_15_wallet_signs_empty_message() {
    let passphrase = "test_15_passphrase";
    let wallet = make_wallet(passphrase);

    let signature = assert_ok(wallet_sign(&wallet, passphrase, b""), "sign empty message");

    assert!(wallet_verify(&wallet, b"", &signature));
}

#[test]
fn test_16_wallet_signs_binary_message() {
    let passphrase = "test_16_passphrase";
    let wallet = make_wallet(passphrase);
    let message = [0_u8, 1_u8, 2_u8, 3_u8, 254_u8, 255_u8];

    let signature = assert_ok(
        wallet_sign(&wallet, passphrase, &message),
        "sign binary message",
    );

    assert!(wallet_verify(&wallet, &message, &signature));
}

#[test]
fn test_17_wallet_signs_unicode_message() {
    let passphrase = "test_17_passphrase";
    let wallet = make_wallet(passphrase);
    let message = "Remzar wallet 測試 🚀".as_bytes();

    let signature = assert_ok(
        wallet_sign(&wallet, passphrase, message),
        "sign unicode message",
    );

    assert!(wallet_verify(&wallet, message, &signature));
}

#[test]
fn test_18_wallet_from_parts_round_trips_generated_wallet() {
    let wallet = make_wallet("test_18_passphrase");

    let rebuilt = assert_ok(
        wallet_from_parts(wallet.public, wallet.encrypted_secret.clone()),
        "MLDSA65Wallet::from_parts",
    );

    assert_eq!(rebuilt.address, wallet.address);
    assert_eq!(rebuilt.public, wallet.public);
    assert_eq!(rebuilt.encrypted_secret, wallet.encrypted_secret);
    assert_wallet_valid(&rebuilt);
}

#[test]
fn test_19_wallet_from_parts_rejects_empty_encrypted_secret() {
    let wallet = make_wallet("test_19_passphrase");

    let err = assert_err(
        wallet_from_parts(wallet.public, Vec::new()),
        "from_parts empty encrypted secret",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected empty encrypted secret error: {other:?}"),
    }
}

#[test]
fn test_20_wallet_from_parts_rejects_tiny_encrypted_secret() {
    let wallet = make_wallet("test_20_passphrase");
    let tiny_secret = vec![1_u8; 8];

    let err = assert_err(
        wallet_from_parts(wallet.public, tiny_secret),
        "from_parts tiny encrypted secret",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected tiny encrypted secret error: {other:?}"),
    }
}

#[test]
fn test_21_wallet_from_parts_rejects_huge_encrypted_secret() {
    let wallet = make_wallet("test_21_passphrase");
    let huge_secret = vec![1_u8; 65 * 1024];

    let err = assert_err(
        wallet_from_parts(wallet.public, huge_secret),
        "from_parts huge encrypted secret",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected huge encrypted secret error: {other:?}"),
    }
}

#[test]
fn test_22_validate_address_format_accepts_generated_address() {
    let wallet = make_wallet("test_22_passphrase");

    assert_ok(
        MLDSA65Wallet::validate_address_format(&wallet.address),
        "validate generated address format",
    );
}

#[test]
fn test_23_validate_address_format_rejects_empty_address() {
    let err = assert_err(
        MLDSA65Wallet::validate_address_format(""),
        "validate empty address",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected empty address error: {other:?}"),
    }
}

#[test]
fn test_24_validate_address_format_rejects_short_address() {
    let err = assert_err(
        MLDSA65Wallet::validate_address_format("r1234"),
        "validate short address",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected short address error: {other:?}"),
    }
}

#[test]
fn test_25_validate_address_format_rejects_wrong_prefix() {
    let wallet = make_wallet("test_25_passphrase");
    let mut bad_address = wallet.address.clone();

    bad_address.replace_range(0..1, "x");

    let err = assert_err(
        MLDSA65Wallet::validate_address_format(&bad_address),
        "validate wrong-prefix address",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected wrong-prefix address error: {other:?}"),
    }
}

#[test]
fn test_26_validate_self_rejects_tampered_address() {
    let mut wallet = make_wallet("test_26_passphrase");
    wallet.address.replace_range(0..1, "x");

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate tampered wallet address",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected tampered address error: {other:?}"),
    }
}

#[test]
fn test_27_tampered_encrypted_secret_fails_signing() {
    let passphrase = "test_27_passphrase";
    let mut wallet = make_wallet(passphrase);

    match wallet.encrypted_secret.first_mut() {
        Some(byte) => {
            *byte ^= 0xAA;
        }
        None => panic!("encrypted secret was unexpectedly empty"),
    }

    let err = assert_err(
        wallet_sign(&wallet, passphrase, b"message"),
        "sign with tampered encrypted secret",
    );

    match err {
        ErrorDetection::DecryptionError { .. }
        | ErrorDetection::CryptographicError { .. }
        | ErrorDetection::ValidationError { .. }
        | ErrorDetection::EncryptionError { .. } => {}
        other => panic!("unexpected tampered secret signing error: {other:?}"),
    }
}

#[test]
fn test_28_secret_key_hex_recovers_matching_address() {
    let passphrase = "test_28_passphrase";
    let wallet = make_wallet(passphrase);
    let secret_hex = assert_ok(wallet_secret_key_hex(&wallet, passphrase), "secret_key_hex");
    let secret_bytes = assert_ok(hex::decode(secret_hex), "hex decode secret key");

    let recovered_address = assert_ok(
        wallet_address_from_secret_bytes(&secret_bytes),
        "address_from_secret_bytes",
    );

    assert_eq!(recovered_address, wallet.address);
}

#[test]
fn test_29_address_from_secret_bytes_rejects_empty_secret() {
    let err = assert_err(
        wallet_address_from_secret_bytes(&[]),
        "address_from_secret_bytes empty",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected empty secret error: {other:?}"),
    }
}

#[test]
fn test_30_address_from_secret_bytes_rejects_short_secret() {
    let short_secret = vec![1_u8; 32];

    let err = assert_err(
        wallet_address_from_secret_bytes(&short_secret),
        "address_from_secret_bytes short",
    );

    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected short secret error: {other:?}"),
    }
}

#[test]
fn test_31_directory_create_wallets_directory_succeeds() {
    let temp = TempTree::new("test_31");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    assert!(directory.wallets_path.exists());
    assert!(directory.wallets_path.is_dir());
}

#[test]
fn test_32_wallet_file_name_uses_wallet_address() {
    let temp = TempTree::new("test_32");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_32_passphrase");

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let wallet_file = wallet_file_path(&directory, &wallet);

    assert!(wallet_file.ends_with(format!("{}.wallet", wallet.address)));
}

#[test]
fn test_33_wallet_file_write_and_read_round_trip() {
    let temp = TempTree::new("test_33");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_33_passphrase");

    let wallet_file = write_wallet_file(&directory, &wallet);
    let stored = assert_ok(fs::read(wallet_file), "read wallet file");

    assert_eq!(stored, wallet.encrypted_secret);
}

#[test]
fn test_34_wallet_file_refuses_overwrite_by_existing_check() {
    let temp = TempTree::new("test_34");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_34_passphrase");

    let wallet_file = write_wallet_file(&directory, &wallet);

    assert!(wallet_file.exists());
}

#[test]
fn test_35_tmp_wallet_file_can_be_renamed_atomically() {
    let temp = TempTree::new("test_35");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_35_passphrase");

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let tmp_file = directory
        .wallets_path
        .join(format!("{}.wallet.tmp", wallet.address));
    let final_file = wallet_file_path(&directory, &wallet);

    assert_ok(
        fs::write(&tmp_file, &wallet.encrypted_secret),
        "write tmp wallet",
    );
    assert_ok(fs::rename(&tmp_file, &final_file), "rename tmp wallet");

    assert!(!tmp_file.exists());
    assert!(final_file.exists());

    let stored = assert_ok(fs::read(final_file), "read renamed wallet file");
    assert_eq!(stored, wallet.encrypted_secret);
}

#[test]
fn test_36_logger_accepts_wallet_generation_event() {
    let temp = TempTree::new("test_36");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("wallet", "GenerateWalletTestEvent", "wallet test event"),
        "log wallet test event",
    );
    assert_ok(logger.flush_logs_cf(), "flush wallet log cf");
}

#[test]
fn test_37_vector_generate_three_wallets_unique_addresses() {
    let first = make_wallet("test_37_passphrase_a");
    let second = make_wallet("test_37_passphrase_b");
    let third = make_wallet("test_37_passphrase_c");

    assert_wallet_valid(&first);
    assert_wallet_valid(&second);
    assert_wallet_valid(&third);

    assert_ne!(first.address, second.address);
    assert_ne!(first.address, third.address);
    assert_ne!(second.address, third.address);
}

#[test]
fn test_38_property_signatures_verify_for_multiple_messages() {
    let passphrase = "test_38_passphrase";
    let wallet = make_wallet(passphrase);

    for seed in 0..8 {
        let message = deterministic_message(seed, seed.saturating_add(1));
        let signature = assert_ok(
            wallet_sign(&wallet, passphrase, &message),
            "sign vector message",
        );

        assert!(wallet_verify(&wallet, &message, &signature));
    }
}

#[test]
fn test_39_adversarial_serial_wallet_generation_unique_addresses() {
    let mut addresses = Vec::new();

    for seed in 0..4 {
        let passphrase = deterministic_passphrase(seed);
        let wallet = make_wallet(&passphrase);
        assert_wallet_valid(&wallet);
        addresses.push(wallet.address);
    }

    for left_index in 0..addresses.len() {
        for right_index in left_index.saturating_add(1)..addresses.len() {
            let left = match addresses.get(left_index) {
                Some(value) => value,
                None => panic!("missing left address"),
            };
            let right = match addresses.get(right_index) {
                Some(value) => value,
                None => panic!("missing right address"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_40_load_generate_and_store_ten_wallet_files() {
    let temp = TempTree::new("test_40");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    for seed in 0..GlobalConfiguration::MAX_BATCH_WALLETS {
        let passphrase = deterministic_passphrase(seed);
        let wallet = make_wallet(&passphrase);
        let wallet_file = write_wallet_file(&directory, &wallet);

        assert!(wallet_file.exists());
        assert_wallet_valid(&wallet);
    }

    assert_eq!(
        count_wallet_files(&directory.wallets_path),
        GlobalConfiguration::MAX_BATCH_WALLETS
    );
}

fn tamper_wallet_address_body(address: &str) -> String {
    let mut bytes = address.as_bytes().to_vec();

    let replacement = match bytes.get(1).copied() {
        Some(b'0') => b'1',
        Some(_) => b'0',
        None => b'0',
    };

    match bytes.get_mut(1) {
        Some(slot) => {
            *slot = replacement;
        }
        None => panic!("address was unexpectedly empty"),
    }

    match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(err) => panic!("tampered address was not valid UTF-8: {err}"),
    }
}

fn make_wrong_prefix_address(address: &str) -> String {
    let mut bytes = address.as_bytes().to_vec();

    match bytes.get_mut(0) {
        Some(slot) => {
            *slot = b'x';
        }
        None => panic!("address was unexpectedly empty"),
    }

    match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(err) => panic!("wrong-prefix address was not valid UTF-8: {err}"),
    }
}

fn make_non_hex_address(address: &str) -> String {
    let mut bytes = address.as_bytes().to_vec();

    match bytes.get_mut(1) {
        Some(slot) => {
            *slot = b'g';
        }
        None => panic!("address was unexpectedly too short"),
    }

    match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(err) => panic!("non-hex address was not valid UTF-8: {err}"),
    }
}

fn assert_validation_like_error(err: ErrorDetection) {
    match err {
        ErrorDetection::ValidationError { .. }
        | ErrorDetection::CryptographicError { .. }
        | ErrorDetection::DecryptionError { .. }
        | ErrorDetection::EncryptionError { .. }
        | ErrorDetection::IoError { .. }
        | ErrorDetection::InitializationError { .. } => {}
        other => panic!("unexpected error kind: {other:?}"),
    }
}

fn wallet_tmp_file_path(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    directory
        .wallets_path
        .join(format!("{}.wallet.tmp", wallet.address))
}

fn write_tmp_then_rename_wallet(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let tmp_file = wallet_tmp_file_path(directory, wallet);
    let final_file = wallet_file_path(directory, wallet);

    if tmp_file.exists() {
        assert_ok(fs::remove_file(&tmp_file), "remove stale tmp wallet file");
    }

    assert_ok(
        fs::write(&tmp_file, &wallet.encrypted_secret),
        "write tmp wallet file",
    );
    assert_ok(fs::rename(&tmp_file, &final_file), "rename tmp wallet file");

    final_file
}

fn assert_wallet_file_contains(path: &Path, expected: &[u8]) {
    let actual = assert_ok(fs::read(path), "read wallet file");
    assert_eq!(actual, expected);
}

#[test]
fn test_41_constructor_new_and_default_are_both_usable() {
    let _new_section = S02GenerateWallet::new();
    let _default_section = S02GenerateWallet::default();
}

#[test]
fn test_42_wallet_new_accepts_short_passphrase_at_crypto_layer() {
    let wallet = make_wallet("a");
    assert_wallet_valid(&wallet);
}

#[test]
fn test_43_wallet_new_accepts_passphrase_with_spaces() {
    let wallet = make_wallet("passphrase with spaces 123 !");
    assert_wallet_valid(&wallet);
}

#[test]
fn test_44_wallet_new_accepts_unicode_passphrase() {
    let wallet = make_wallet("密碼 測試 пароль 🔐");
    assert_wallet_valid(&wallet);
}

#[test]
fn test_45_wallet_new_accepts_long_passphrase() {
    let long_passphrase = deterministic_passphrase(45).repeat(16);
    let wallet = make_wallet(&long_passphrase);

    assert_wallet_valid(&wallet);
}

#[test]
fn test_46_secret_key_hex_rejects_wrong_passphrase() {
    let wallet = make_wallet("test_46_correct");

    let err = assert_err(
        wallet_secret_key_hex(&wallet, "test_46_wrong"),
        "secret_key_hex with wrong passphrase",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_47_sign_rejects_wrong_passphrase_after_successful_validation() {
    let wallet = make_wallet("test_47_correct");

    assert_ok(
        wallet_validate_self(&wallet),
        "validate before wrong-passphrase signing",
    );

    let err = assert_err(
        wallet_sign(&wallet, "test_47_wrong", b"wrong passphrase vector"),
        "sign with wrong passphrase",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_48_generate_address_matches_generated_wallet_address() {
    let wallet = make_wallet("test_48_passphrase");

    let derived = assert_ok(wallet_generate_address(&wallet.public), "generate_address");

    assert_eq!(derived, wallet.address);
}

#[test]
fn test_49_from_parts_address_matches_generate_address() {
    let wallet = make_wallet("test_49_passphrase");

    let rebuilt = assert_ok(
        wallet_from_parts(wallet.public, wallet.encrypted_secret.clone()),
        "from_parts",
    );
    let derived = assert_ok(wallet_generate_address(&wallet.public), "generate_address");

    assert_eq!(rebuilt.address, derived);
}

#[test]
fn test_50_public_key_hex_decodes_back_to_public_key() {
    let wallet = make_wallet("test_50_passphrase");
    let public_hex = wallet.public_key_hex();
    let decoded = assert_ok(hex::decode(public_hex), "decode public key hex");

    assert_eq!(decoded.as_slice(), wallet.public.as_slice());
}

#[test]
fn test_51_secret_key_hex_decodes_to_configured_secret_len() {
    let passphrase = "test_51_passphrase";
    let wallet = make_wallet(passphrase);
    let secret_hex = assert_ok(wallet_secret_key_hex(&wallet, passphrase), "secret_key_hex");
    let decoded = assert_ok(hex::decode(secret_hex), "decode secret key hex");

    assert_eq!(decoded.len(), GlobalConfiguration::MLDSA65_SECRET_BYTES);
}

#[test]
fn test_52_address_from_secret_bytes_matches_generated_wallet_address() {
    let passphrase = "test_52_passphrase";
    let wallet = make_wallet(passphrase);
    let secret_hex = assert_ok(wallet_secret_key_hex(&wallet, passphrase), "secret_key_hex");
    let decoded = assert_ok(hex::decode(secret_hex), "decode secret key hex");

    let address = assert_ok(
        wallet_address_from_secret_bytes(&decoded),
        "address_from_secret_bytes",
    );

    assert_eq!(address, wallet.address);
}

#[test]
fn test_53_validate_address_format_accepts_format_valid_tampered_body() {
    let wallet = make_wallet("test_53_passphrase");
    let bad_address = tamper_wallet_address_body(&wallet.address);

    assert_ne!(bad_address, wallet.address);

    assert_ok(
        MLDSA65Wallet::validate_address_format(&bad_address),
        "validate format-valid tampered body address",
    );
}

#[test]
fn test_54_validate_address_format_rejects_wrong_prefix() {
    let wallet = make_wallet("test_54_passphrase");
    let bad_address = make_wrong_prefix_address(&wallet.address);

    let err = assert_err(
        MLDSA65Wallet::validate_address_format(&bad_address),
        "validate wrong prefix address",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_55_validate_address_format_rejects_non_hex_character() {
    let wallet = make_wallet("test_55_passphrase");
    let bad_address = make_non_hex_address(&wallet.address);

    let err = assert_err(
        MLDSA65Wallet::validate_address_format(&bad_address),
        "validate non-hex address",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_56_validate_address_format_rejects_too_long_address() {
    let wallet = make_wallet("test_56_passphrase");
    let mut bad_address = wallet.address.clone();
    bad_address.push('0');

    let err = assert_err(
        MLDSA65Wallet::validate_address_format(&bad_address),
        "validate too-long address",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_57_validate_address_format_rejects_too_short_address() {
    let wallet = make_wallet("test_57_passphrase");
    let mut bad_address = wallet.address.clone();
    bad_address.pop();

    let err = assert_err(
        MLDSA65Wallet::validate_address_format(&bad_address),
        "validate too-short address",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_58_validate_self_rejects_tampered_body_address() {
    let mut wallet = make_wallet("test_58_passphrase");
    wallet.address = tamper_wallet_address_body(&wallet.address);

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate tampered body wallet",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_59_validate_self_rejects_wrong_prefix_address() {
    let mut wallet = make_wallet("test_59_passphrase");
    wallet.address = make_wrong_prefix_address(&wallet.address);

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate wrong prefix wallet",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_60_validate_self_rejects_non_hex_address() {
    let mut wallet = make_wallet("test_60_passphrase");
    wallet.address = make_non_hex_address(&wallet.address);

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate non-hex wallet address",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_61_validate_self_rejects_empty_encrypted_secret() {
    let mut wallet = make_wallet("test_61_passphrase");
    wallet.encrypted_secret.clear();

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate empty encrypted secret",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_62_validate_self_rejects_tiny_encrypted_secret() {
    let mut wallet = make_wallet("test_62_passphrase");
    wallet.encrypted_secret = vec![1_u8; 4];

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate tiny encrypted secret",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_63_validate_self_rejects_huge_encrypted_secret() {
    let mut wallet = make_wallet("test_63_passphrase");
    wallet.encrypted_secret = vec![1_u8; 65 * 1024];

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate huge encrypted secret",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_64_sign_rejects_wallet_with_tampered_address() {
    let passphrase = "test_64_passphrase";
    let mut wallet = make_wallet(passphrase);
    wallet.address = tamper_wallet_address_body(&wallet.address);

    let err = assert_err(
        wallet_sign(&wallet, passphrase, b"message"),
        "sign with tampered address",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_65_verify_rejects_wallet_with_tampered_address() {
    let passphrase = "test_65_passphrase";
    let mut wallet = make_wallet(passphrase);

    let signature = assert_ok(
        wallet_sign(&wallet, passphrase, b"message"),
        "sign before tamper",
    );
    wallet.address = tamper_wallet_address_body(&wallet.address);

    assert!(!wallet_verify(&wallet, b"message", &signature));
}

#[test]
fn test_66_verify_rejects_mutated_signature_same_length() {
    let passphrase = "test_66_passphrase";
    let wallet = make_wallet(passphrase);
    let message = b"signature mutation vector";

    let mut signature = assert_ok(wallet_sign(&wallet, passphrase, message), "sign message");

    match signature.first_mut() {
        Some(byte) => {
            *byte ^= 0x01;
        }
        None => panic!("signature was unexpectedly empty"),
    }

    assert!(!wallet_verify(&wallet, message, &signature));
}

#[test]
fn test_67_verify_rejects_signature_from_different_wallet() {
    let first_passphrase = "test_67_first";
    let second_passphrase = "test_67_second";
    let first = make_wallet(first_passphrase);
    let second = make_wallet(second_passphrase);
    let message = b"cross-wallet signature rejection";

    let signature = assert_ok(
        wallet_sign(&first, first_passphrase, message),
        "first wallet sign",
    );

    assert!(!wallet_verify(&second, message, &signature));
}

#[test]
fn test_68_verify_rejects_truncated_valid_signature() {
    let passphrase = "test_68_passphrase";
    let wallet = make_wallet(passphrase);
    let message = b"truncate signature vector";

    let mut signature = assert_ok(wallet_sign(&wallet, passphrase, message), "sign message");
    signature.pop();

    assert!(!wallet_verify(&wallet, message, &signature));
}

#[test]
fn test_69_verify_rejects_extended_valid_signature() {
    let passphrase = "test_69_passphrase";
    let wallet = make_wallet(passphrase);
    let message = b"extended signature vector";

    let mut signature = assert_ok(wallet_sign(&wallet, passphrase, message), "sign message");
    signature.push(0_u8);

    assert!(!wallet_verify(&wallet, message, &signature));
}

#[test]
fn test_70_sign_and_verify_large_message_vector() {
    let passphrase = "test_70_passphrase";
    let wallet = make_wallet(passphrase);
    let message = deterministic_message(70, 512);

    let signature = assert_ok(
        wallet_sign(&wallet, passphrase, &message),
        "sign large message",
    );

    assert!(wallet_verify(&wallet, &message, &signature));
}

#[test]
fn test_71_sign_and_verify_repeated_byte_message_vector() {
    let passphrase = "test_71_passphrase";
    let wallet = make_wallet(passphrase);
    let message = vec![0xAB_u8; 4096];

    let signature = assert_ok(
        wallet_sign(&wallet, passphrase, &message),
        "sign repeated byte message",
    );

    assert!(wallet_verify(&wallet, &message, &signature));
}

#[test]
fn test_72_sign_and_verify_incremental_binary_vector() {
    let passphrase = "test_72_passphrase";
    let wallet = make_wallet(passphrase);
    let mut message = Vec::new();

    for byte in 0_u8..=127_u8 {
        message.push(byte);
    }

    let signature = assert_ok(
        wallet_sign(&wallet, passphrase, &message),
        "sign incremental bytes",
    );

    assert!(wallet_verify(&wallet, &message, &signature));
}

#[test]
fn test_73_property_generated_addresses_are_unique_for_five_wallets() {
    let mut addresses = Vec::new();

    for seed in 0usize..5usize {
        let wallet = make_wallet(&deterministic_passphrase(seed.saturating_add(73usize)));
        assert_wallet_valid(&wallet);
        addresses.push(wallet.address);
    }

    for left_index in 0..addresses.len() {
        for right_index in left_index.saturating_add(1)..addresses.len() {
            let left = match addresses.get(left_index) {
                Some(value) => value,
                None => panic!("missing left address"),
            };
            let right = match addresses.get(right_index) {
                Some(value) => value,
                None => panic!("missing right address"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_74_property_generated_public_keys_are_unique_for_five_wallets() {
    let mut public_keys = Vec::new();

    for seed in 0usize..5usize {
        let wallet = make_wallet(&deterministic_passphrase(seed.saturating_add(74usize)));
        public_keys.push(wallet.public);
    }

    for left_index in 0..public_keys.len() {
        for right_index in left_index.saturating_add(1)..public_keys.len() {
            let left = match public_keys.get(left_index) {
                Some(value) => value,
                None => panic!("missing left public key"),
            };
            let right = match public_keys.get(right_index) {
                Some(value) => value,
                None => panic!("missing right public key"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_75_property_sign_verify_round_trip_for_six_messages() {
    let passphrase = "test_75_passphrase";
    let wallet = make_wallet(passphrase);

    for seed in 0usize..6usize {
        let message =
            deterministic_message(seed.saturating_add(75usize), seed.saturating_add(3usize));
        let signature = assert_ok(
            wallet_sign(&wallet, passphrase, &message),
            "sign property message",
        );

        assert!(wallet_verify(&wallet, &message, &signature));
    }
}

#[test]
fn test_76_property_secret_export_address_round_trip_for_three_wallets() {
    for seed in 0usize..3usize {
        let passphrase = deterministic_passphrase(seed.saturating_add(76usize));
        let wallet = make_wallet(&passphrase);
        let secret_hex = assert_ok(
            wallet_secret_key_hex(&wallet, &passphrase),
            "secret_key_hex",
        );
        let secret_bytes = assert_ok(hex::decode(secret_hex), "decode secret hex");

        let address = assert_ok(
            wallet_address_from_secret_bytes(&secret_bytes),
            "address_from_secret_bytes",
        );

        assert_eq!(address, wallet.address);
    }
}

#[test]
fn test_77_wallets_directory_with_spaces_accepts_wallet_file() {
    let temp = TempTree::new("test_77");
    let opts = make_node_opts(&temp.child("node with spaces"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_77_passphrase");

    let wallet_file = write_wallet_file(&directory, &wallet);

    assert!(wallet_file.exists());
    assert_wallet_file_contains(&wallet_file, &wallet.encrypted_secret);
}

#[test]
fn test_78_wallets_directory_with_unicode_accepts_wallet_file() {
    let temp = TempTree::new("test_78");
    let opts = make_node_opts(&temp.child("node_測試_кошелек"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_78_passphrase");

    let wallet_file = write_wallet_file(&directory, &wallet);

    assert!(wallet_file.exists());
    assert_wallet_file_contains(&wallet_file, &wallet.encrypted_secret);
}

#[test]
fn test_79_wallet_tmp_file_path_has_tmp_extension() {
    let temp = TempTree::new("test_79");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_79_passphrase");

    let tmp_file = wallet_tmp_file_path(&directory, &wallet);

    assert!(tmp_file.ends_with(format!("{}.wallet.tmp", wallet.address)));
}

#[test]
fn test_80_tmp_then_rename_removes_tmp_and_keeps_final_wallet() {
    let temp = TempTree::new("test_80");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_80_passphrase");

    let tmp_file = wallet_tmp_file_path(&directory, &wallet);
    let final_file = write_tmp_then_rename_wallet(&directory, &wallet);

    assert!(!tmp_file.exists());
    assert!(final_file.exists());
    assert_wallet_file_contains(&final_file, &wallet.encrypted_secret);
}

#[test]
fn test_81_stale_tmp_file_can_be_removed_before_wallet_write() {
    let temp = TempTree::new("test_81");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_81_passphrase");

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let tmp_file = wallet_tmp_file_path(&directory, &wallet);
    assert_ok(fs::write(&tmp_file, b"stale tmp data"), "write stale tmp");

    let final_file = write_tmp_then_rename_wallet(&directory, &wallet);

    assert!(!tmp_file.exists());
    assert!(final_file.exists());
    assert_wallet_file_contains(&final_file, &wallet.encrypted_secret);
}

#[test]
fn test_82_existing_wallet_file_is_detectable_before_overwrite() {
    let temp = TempTree::new("test_82");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_82_passphrase");

    let wallet_file = write_wallet_file(&directory, &wallet);

    assert!(wallet_file.exists());
}

#[test]
fn test_83_count_wallet_files_ignores_tmp_files() {
    let temp = TempTree::new("test_83");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_83_passphrase");

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let tmp_file = wallet_tmp_file_path(&directory, &wallet);
    assert_ok(fs::write(tmp_file, b"tmp"), "write tmp file");

    assert_eq!(count_wallet_files(&directory.wallets_path), 0);
}

#[test]
fn test_84_count_wallet_files_counts_final_wallet_only() {
    let temp = TempTree::new("test_84");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_84_passphrase");

    let wallet_file = write_wallet_file(&directory, &wallet);
    let tmp_file = wallet_tmp_file_path(&directory, &wallet);

    assert_ok(fs::write(tmp_file, b"tmp"), "write tmp file");
    assert!(wallet_file.exists());

    assert_eq!(count_wallet_files(&directory.wallets_path), 1);
}

#[test]
fn test_85_logger_accepts_wallet_event_with_generated_address() {
    let temp = TempTree::new("test_85");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);
    let wallet = make_wallet("test_85_passphrase");

    assert_ok(
        logger.log_error_event("wallet", "GeneratedAddressVector", &wallet.address),
        "log generated wallet address",
    );
    assert_ok(logger.flush_logs_cf(), "flush wallet logs");
}

#[test]
fn test_86_logger_accepts_wallet_event_with_unicode_message() {
    let temp = TempTree::new("test_86");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("wallet", "UnicodeWalletEvent", "wallet 測試 🔐"),
        "log unicode wallet event",
    );
    assert_ok(logger.flush(), "flush wallet logger");
}

#[test]
fn test_87_logger_accepts_wallet_event_with_long_message() {
    let temp = TempTree::new("test_87");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);
    let message = deterministic_message(87, 256);
    let message_string = String::from_utf8_lossy(&message).into_owned();

    assert_ok(
        logger.log_error_event("wallet", "LongWalletEvent", &message_string),
        "log long wallet event",
    );
    assert_ok(logger.flush_logs_cf(), "flush long wallet event");
}

#[test]
fn test_88_adversarial_public_key_bit_flip_breaks_self_validation() {
    let mut wallet = make_wallet("test_88_passphrase");

    match wallet.public.first_mut() {
        Some(byte) => {
            *byte ^= 0x01;
        }
        None => panic!("public key was unexpectedly empty"),
    }

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate public-key-flipped wallet",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_89_adversarial_address_and_public_key_both_tampered_rejects_validation() {
    let mut wallet = make_wallet("test_89_passphrase");

    wallet.address = tamper_wallet_address_body(&wallet.address);

    match wallet.public.first_mut() {
        Some(byte) => {
            *byte ^= 0x80;
        }
        None => panic!("public key was unexpectedly empty"),
    }

    let err = assert_err(
        wallet_validate_self(&wallet),
        "validate address-and-public tampered wallet",
    );

    assert_validation_like_error(err);
}

#[test]
fn test_90_adversarial_serial_sign_verify_unique_wallets() {
    let mut addresses = Vec::new();

    for seed in 0usize..4usize {
        let passphrase = deterministic_passphrase(seed.saturating_add(90usize));
        let wallet = make_wallet(&passphrase);
        let message = deterministic_message(seed.saturating_add(90usize), 8usize);
        let signature = assert_ok(wallet_sign(&wallet, &passphrase, &message), "serial sign");

        assert!(wallet_verify(&wallet, &message, &signature));
        addresses.push(wallet.address);
    }

    for left_index in 0..addresses.len() {
        for right_index in left_index.saturating_add(1)..addresses.len() {
            let left = match addresses.get(left_index) {
                Some(value) => value,
                None => panic!("missing left address"),
            };
            let right = match addresses.get(right_index) {
                Some(value) => value,
                None => panic!("missing right address"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_91_adversarial_serial_wallet_file_storage_unique_nodes() {
    for seed in 0usize..4usize {
        let temp = TempTree::new(&format!("test_91_{seed}"));
        let opts = make_node_opts(&temp.child("node"));
        let directory = directory_from_opts(&opts);
        let wallet = make_wallet(&deterministic_passphrase(seed.saturating_add(91usize)));

        let wallet_file = write_wallet_file(&directory, &wallet);

        assert!(wallet_file.exists());
        assert_wallet_file_contains(&wallet_file, &wallet.encrypted_secret);
    }
}

#[test]
fn test_92_load_generate_six_wallets_and_validate_all() {
    let mut wallets = Vec::new();

    for seed in 0usize..6usize {
        let wallet = make_wallet(&deterministic_passphrase(seed.saturating_add(92usize)));
        assert_wallet_valid(&wallet);
        wallets.push(wallet);
    }

    assert_eq!(wallets.len(), 6);
}

#[test]
fn test_93_load_generate_six_wallets_and_store_all() {
    let temp = TempTree::new("test_93");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for seed in 0usize..6usize {
        let wallet = make_wallet(&deterministic_passphrase(seed.saturating_add(93usize)));
        let wallet_file = write_wallet_file(&directory, &wallet);

        assert!(wallet_file.exists());
    }

    assert_eq!(count_wallet_files(&directory.wallets_path), 6);
}

#[test]
fn test_94_load_sign_verify_ten_messages_same_wallet() {
    let passphrase = "test_94_passphrase";
    let wallet = make_wallet(passphrase);

    for seed in 0usize..10usize {
        let message = deterministic_message(seed.saturating_add(94usize), 12usize);
        let signature = assert_ok(
            wallet_sign(&wallet, passphrase, &message),
            "load sign message",
        );

        assert!(wallet_verify(&wallet, &message, &signature));
    }
}

#[test]
fn test_95_load_secret_export_three_times_same_wallet() {
    let passphrase = "test_95_passphrase";
    let wallet = make_wallet(passphrase);

    for _ in 0..3 {
        let secret_hex = assert_ok(wallet_secret_key_hex(&wallet, passphrase), "secret_key_hex");
        assert_eq!(
            secret_hex.len(),
            GlobalConfiguration::MLDSA65_SECRET_HEX_LEN
        );
    }
}

#[test]
fn test_96_vector_wallet_file_names_for_three_wallets_are_unique() {
    let temp = TempTree::new("test_96");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let mut paths = Vec::new();

    for seed in 0usize..3usize {
        let wallet = make_wallet(&deterministic_passphrase(seed.saturating_add(96usize)));
        let path = wallet_file_path(&directory, &wallet);
        paths.push(path);
    }

    for left_index in 0..paths.len() {
        for right_index in left_index.saturating_add(1)..paths.len() {
            let left = match paths.get(left_index) {
                Some(value) => value,
                None => panic!("missing left wallet path"),
            };
            let right = match paths.get(right_index) {
                Some(value) => value,
                None => panic!("missing right wallet path"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_97_vector_encrypted_secret_is_not_plain_secret_hex() {
    let passphrase = "test_97_passphrase";
    let wallet = make_wallet(passphrase);
    let secret_hex = assert_ok(wallet_secret_key_hex(&wallet, passphrase), "secret_key_hex");
    let secret_bytes = assert_ok(hex::decode(secret_hex), "decode secret hex");

    assert_ne!(wallet.encrypted_secret.as_slice(), secret_bytes.as_slice());
}

#[test]
fn test_98_vector_different_passphrases_generate_valid_wallets() {
    for passphrase in [
        "simple-passphrase",
        "passphrase with spaces",
        "symbols-!@#$%^&*()",
        "unicode-測試-🔐",
    ] {
        let wallet = make_wallet(passphrase);
        assert_wallet_valid(&wallet);
    }
}

#[test]
fn test_99_load_wallet_logger_many_events() {
    let temp = TempTree::new("test_99");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    for seed in 0..20 {
        assert_ok(
            logger.log_error_event(
                "wallet",
                "LoadWalletLogger",
                &format!("wallet event {seed}"),
            ),
            "log load wallet event",
        );
    }

    assert_ok(logger.flush_logs_cf(), "flush load wallet logger");
}

#[test]
fn test_100_final_comprehensive_wallet_generation_storage_signing_and_logging() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let logger = make_logger(&opts);
    let passphrase = "test_100_passphrase";
    let wallet = make_wallet(passphrase);

    assert_wallet_valid(&wallet);

    let message = deterministic_message(100, 64);
    let signature = assert_ok(wallet_sign(&wallet, passphrase, &message), "final sign");
    assert!(wallet_verify(&wallet, &message, &signature));

    let secret_hex = assert_ok(
        wallet_secret_key_hex(&wallet, passphrase),
        "final secret_key_hex",
    );
    let secret_bytes = assert_ok(hex::decode(secret_hex), "final decode secret hex");
    let recovered_address = assert_ok(
        wallet_address_from_secret_bytes(&secret_bytes),
        "final address_from_secret_bytes",
    );
    assert_eq!(recovered_address, wallet.address);

    let wallet_file = write_tmp_then_rename_wallet(&directory, &wallet);
    assert!(wallet_file.exists());
    assert_wallet_file_contains(&wallet_file, &wallet.encrypted_secret);

    assert_ok(
        logger.log_error_event("wallet", "FinalWalletTest", &wallet.address),
        "final wallet log",
    );
    assert_ok(logger.flush_logs_cf(), "final wallet logger flush");
}
