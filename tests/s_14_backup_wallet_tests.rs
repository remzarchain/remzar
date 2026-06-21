use fips204::ml_dsa_65;
use remzar::commandline::s_14_backup_wallet::S14BackupWallet;
use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, wallet_id_matches_pubkey_bytes_checked,
};
use remzar::utility::logging_data::JsonLogger;
use std::fmt::Debug;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;
use zeroize::Zeroize;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PRIMARY_WALLET: OnceLock<WalletFixture> = OnceLock::new();
static SECONDARY_WALLET: OnceLock<WalletFixture> = OnceLock::new();

#[derive(Clone)]
struct WalletFixture {
    address: String,
    public: [u8; ml_dsa_65::PK_LEN],
    encrypted_secret: Vec<u8>,
    secret: Vec<u8>,
    passphrase: &'static str,
}

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_14_backup_wallet_tests_{test_name}_{}_{}",
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

fn assert_validation_error(err: ErrorDetection) {
    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("expected ValidationError, got {other:?}"),
    }
}

fn assert_decrypt_like_error(err: ErrorDetection) {
    match err {
        ErrorDetection::DecryptionError { .. }
        | ErrorDetection::ValidationError { .. }
        | ErrorDetection::EncryptionError { .. }
        | ErrorDetection::CryptographicError { .. } => {}
        other => panic!("unexpected decrypt-like error: {other:?}"),
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

fn build_wallet_fixture(passphrase: &'static str) -> WalletFixture {
    let wallet = assert_ok(MLDSA65Wallet::new(passphrase), "MLDSA65Wallet::new");
    let secret = assert_ok(
        Cryption::decrypt_private_key_bytes(&wallet.encrypted_secret, passphrase),
        "decrypt wallet secret",
    );

    WalletFixture {
        address: wallet.address,
        public: wallet.public,
        encrypted_secret: wallet.encrypted_secret,
        secret,
        passphrase,
    }
}

fn primary_fixture() -> WalletFixture {
    PRIMARY_WALLET
        .get_or_init(|| build_wallet_fixture("s14_primary_passphrase"))
        .clone()
}

fn secondary_fixture() -> WalletFixture {
    SECONDARY_WALLET
        .get_or_init(|| build_wallet_fixture("s14_secondary_passphrase"))
        .clone()
}

fn make_wallet(passphrase: &str) -> MLDSA65Wallet {
    assert_ok(MLDSA65Wallet::new(passphrase), "MLDSA65Wallet::new")
}

fn wallet_from_label(label: &str) -> String {
    format!("r{}", RemzarHash::compute_bytes_hash_hex(label.as_bytes()))
}

fn assert_wallet_shape(wallet: &str) {
    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
    assert!(wallet.starts_with('r'));
    assert!(
        wallet
            .as_bytes()
            .iter()
            .skip(1)
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

fn wallet_file_path(directory: &DirectoryDB, address: &str) -> PathBuf {
    directory.wallets_path.join(format!("{address}.wallet"))
}

fn tmp_wallet_file_path(directory: &DirectoryDB, address: &str) -> PathBuf {
    directory.wallets_path.join(format!("{address}.wallet.tmp"))
}

fn backup_file_path(backup_dir: &Path, address: &str) -> PathBuf {
    backup_dir.join(format!("{address}.wallet"))
}

fn tmp_backup_file_path(backup_dir: &Path, address: &str) -> PathBuf {
    backup_dir.join(format!("{address}.wallet.tmp"))
}

fn write_wallet_file(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let path = wallet_file_path(directory, &wallet.address);
    assert_ok(
        fs::write(&path, &wallet.encrypted_secret),
        "write wallet file",
    );
    path
}

fn write_fixture_wallet_file(directory: &DirectoryDB, fixture: &WalletFixture) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let path = wallet_file_path(directory, &fixture.address);
    assert_ok(
        fs::write(&path, &fixture.encrypted_secret),
        "write fixture wallet file",
    );
    path
}

fn read_file_bytes(path: &Path) -> Vec<u8> {
    assert_ok(fs::read(path), "read file bytes")
}

fn assert_file_bytes_eq(path: &Path, expected: &[u8]) {
    assert_eq!(read_file_bytes(path), expected);
}

fn validate_wallet_file_like_s14(
    wallet_file: &Path,
    max_wallet_file_bytes: u64,
) -> Result<(), ErrorDetection> {
    let meta = fs::metadata(wallet_file).map_err(|e| ErrorDetection::IoError {
        message: format!(
            "Failed to stat wallet file '{}': {e}",
            wallet_file.display()
        ),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    if !meta.is_file() {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Wallet path is not a regular file: {}",
                wallet_file.display()
            ),
            tx_id: None,
        });
    }

    if meta.len() == 0 {
        return Err(ErrorDetection::ValidationError {
            message: format!("Wallet file is empty/corrupt: {}", wallet_file.display()),
            tx_id: None,
        });
    }

    if meta.len() > max_wallet_file_bytes {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Wallet file too large: {} bytes exceeds safety max {}",
                meta.len(),
                max_wallet_file_bytes
            ),
            tx_id: None,
        });
    }

    Ok(())
}

fn verify_wallet_decrypt_matches_address_like_s14(
    wallet_file: &Path,
    passphrase: &str,
    expected_wallet: &str,
) -> Result<(), ErrorDetection> {
    let mut encrypted_sk = fs::read(wallet_file).map_err(|e| ErrorDetection::IoError {
        message: format!(
            "Failed to read wallet file '{}': {e}",
            wallet_file.display()
        ),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    let mut plaintext =
        Cryption::decrypt_private_key_bytes(&encrypted_sk, passphrase).map_err(|e| {
            encrypted_sk.zeroize();

            ErrorDetection::DecryptionError {
                message: format!("Failed to decrypt wallet file: {e}"),
            }
        })?;

    encrypted_sk.zeroize();

    let mut secret_bytes: Vec<u8> = if plaintext.len() == ml_dsa_65::SK_LEN {
        let out = plaintext.clone();
        plaintext.zeroize();
        out
    } else {
        let mut secret_hex = match std::str::from_utf8(&plaintext) {
            Ok(s) => s.trim().to_ascii_lowercase(),
            Err(_) => {
                plaintext.zeroize();

                return Err(ErrorDetection::ValidationError {
                    message: "decrypted secret is not raw bytes or UTF-8 hex".to_owned(),
                    tx_id: None,
                });
            }
        };

        plaintext.zeroize();

        if secret_hex.len() != ml_dsa_65::SK_LEN.saturating_mul(2)
            || !secret_hex.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            let got = secret_hex.len();
            secret_hex.zeroize();

            return Err(ErrorDetection::ValidationError {
                message: format!("decrypted secret hex has unexpected length: {got}"),
                tx_id: None,
            });
        }

        let decoded = hex::decode(&secret_hex).map_err(|e| ErrorDetection::ValidationError {
            message: format!("failed to decode decrypted secret hex: {e:?}"),
            tx_id: None,
        })?;

        secret_hex.zeroize();
        decoded
    };

    if secret_bytes.len() != ml_dsa_65::SK_LEN {
        let got = secret_bytes.len();
        secret_bytes.zeroize();

        return Err(ErrorDetection::ValidationError {
            message: format!(
                "decrypted secret length mismatch: expected {}, got {}",
                ml_dsa_65::SK_LEN,
                got
            ),
            tx_id: None,
        });
    }

    let recovered = MLDSA65Wallet::address_from_secret_bytes(&secret_bytes).map_err(|e| {
        secret_bytes.zeroize();

        ErrorDetection::ValidationError {
            message: format!("unable to derive wallet address from secret: {e}"),
            tx_id: None,
        }
    })?;

    secret_bytes.zeroize();

    if recovered != expected_wallet {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "decrypted secret does not match requested wallet address. expected={expected_wallet} recovered={recovered}"
            ),
            tx_id: None,
        });
    }

    Ok(())
}

fn atomic_backup_copy_like_s14(
    wallet_file: &Path,
    live_wallet_dir: &Path,
    backup_path: &Path,
    wallet_address: &str,
    max_wallet_file_bytes: u64,
) -> Result<PathBuf, ErrorDetection> {
    validate_wallet_file_like_s14(wallet_file, max_wallet_file_bytes)?;

    if !backup_path.exists() {
        fs::create_dir_all(backup_path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to create backup directory: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;
    } else if !backup_path.is_dir() {
        return Err(ErrorDetection::ValidationError {
            message: format!("Backup path is not a directory: {}", backup_path.display()),
            tx_id: None,
        });
    }

    if backup_path == live_wallet_dir {
        return Err(ErrorDetection::ValidationError {
            message: "Refusing to back up into the live wallets directory.".to_owned(),
            tx_id: None,
        });
    }

    let backup_file = backup_file_path(backup_path, wallet_address);
    if backup_file.exists() {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Refusing to overwrite existing backup file: {}",
                backup_file.display()
            ),
            tx_id: None,
        });
    }

    let tmp_backup = tmp_backup_file_path(backup_path, wallet_address);

    if let Err(e) = fs::remove_file(&tmp_backup)
        && e.kind() != ErrorKind::NotFound
    {
        return Err(ErrorDetection::IoError {
            message: format!("Failed to remove temp backup file: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        });
    }

    fs::copy(wallet_file, &tmp_backup).map_err(|e| ErrorDetection::IoError {
        message: format!("Failed to back up wallet tmp copy: {e}"),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    fs::rename(&tmp_backup, &backup_file).map_err(|e| {
        if let Err(remove_err) = fs::remove_file(&tmp_backup)
            && remove_err.kind() != ErrorKind::NotFound
        {}

        ErrorDetection::IoError {
            message: format!(
                "Failed to finalize backup file (rename {} -> {}): {e}",
                tmp_backup.display(),
                backup_file.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        }
    })?;

    Ok(backup_file)
}

fn make_legacy_hex_wallet_file(directory: &DirectoryDB, fixture: &WalletFixture) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let secret_hex = hex::encode(&fixture.secret);
    let encrypted = assert_ok(
        Cryption::encrypt_private_key_bytes(secret_hex.as_bytes(), fixture.passphrase),
        "encrypt legacy hex secret",
    );

    let path = wallet_file_path(directory, &fixture.address);
    assert_ok(fs::write(&path, encrypted), "write legacy hex wallet file");
    path
}

fn assert_backup_success(
    directory: &DirectoryDB,
    wallet_file: &Path,
    backup_dir: &Path,
    wallet_address: &str,
    expected_bytes: &[u8],
) -> PathBuf {
    let backup = assert_ok(
        atomic_backup_copy_like_s14(
            wallet_file,
            &directory.wallets_path,
            backup_dir,
            wallet_address,
            512 * 1024,
        ),
        "atomic backup copy",
    );

    assert!(backup.exists());
    assert_file_bytes_eq(&backup, expected_bytes);
    assert!(!tmp_backup_file_path(backup_dir, wallet_address).exists());

    backup
}

fn assert_secret_matches_address(fixture: &WalletFixture) {
    let recovered = assert_ok(
        MLDSA65Wallet::address_from_secret_bytes(&fixture.secret),
        "address_from_secret_bytes",
    );

    assert_eq!(recovered, fixture.address);
}

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S14BackupWallet::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S14BackupWallet::default();
}

#[test]
fn test_03_unit_struct_constructor_creates_section() {
    let _section = S14BackupWallet;
}

#[test]
fn test_04_wallet_from_label_has_expected_shape() {
    let wallet = wallet_from_label("test_04");

    assert_wallet_shape(&wallet);
}

#[test]
fn test_05_primary_fixture_wallet_has_expected_shape() {
    assert_wallet_shape(&primary_fixture().address);
}

#[test]
fn test_06_secondary_fixture_wallet_has_expected_shape() {
    assert_wallet_shape(&secondary_fixture().address);
}

#[test]
fn test_07_primary_wallet_canonicalizes() {
    let wallet = primary_fixture().address;
    let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon primary wallet");

    assert_eq!(canonical, wallet);
}

#[test]
fn test_08_canon_wallet_accepts_uppercase() {
    let wallet = wallet_from_label("test_08");
    let canonical = assert_ok(
        canon_wallet_id_checked(&wallet.to_ascii_uppercase()),
        "canon uppercase wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_09_canon_wallet_accepts_outer_whitespace() {
    let wallet = wallet_from_label("test_09");
    let canonical = assert_ok(
        canon_wallet_id_checked(&format!("  {wallet}  ")),
        "canon padded wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_10_canon_wallet_rejects_empty() {
    let err = assert_err(canon_wallet_id_checked(""), "canon empty wallet");

    assert_validation_error(err);
}

#[test]
fn test_11_canon_wallet_rejects_short() {
    let err = assert_err(canon_wallet_id_checked("r1234"), "canon short wallet");

    assert_validation_error(err);
}

#[test]
fn test_12_canon_wallet_rejects_wrong_prefix() {
    let wallet = wallet_from_label("test_12");
    let bad = format!("x{}", &wallet[1..]);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong prefix");

    assert_validation_error(err);
}

#[test]
fn test_13_canon_wallet_rejects_non_hex_body() {
    let mut wallet = wallet_from_label("test_13");
    wallet.replace_range(1..2, "g");

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon non-hex");

    assert_validation_error(err);
}

#[test]
fn test_14_wallet_validate_address_format_accepts_primary() {
    let fixture = primary_fixture();

    assert_ok(
        MLDSA65Wallet::validate_address_format(&fixture.address),
        "validate primary address",
    );
}

#[test]
fn test_15_wallet_validate_address_format_accepts_uppercase() {
    let fixture = primary_fixture();

    assert_ok(
        MLDSA65Wallet::validate_address_format(&fixture.address.to_ascii_uppercase()),
        "validate uppercase primary address",
    );
}

#[test]
fn test_16_wallet_validate_address_format_rejects_short() {
    let err = assert_err(
        MLDSA65Wallet::validate_address_format("r1234"),
        "validate short wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_17_primary_wallet_matches_public_key() {
    let fixture = primary_fixture();

    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&fixture.address, &fixture.public),
        "wallet matches public key",
    );
}

#[test]
fn test_18_primary_wallet_rejects_secondary_public_key() {
    let primary = primary_fixture();
    let secondary = secondary_fixture();

    let err = assert_err(
        wallet_id_matches_pubkey_bytes_checked(&primary.address, &secondary.public),
        "primary should reject secondary public key",
    );

    assert_validation_error(err);
}

#[test]
fn test_19_primary_secret_recovers_primary_address() {
    assert_secret_matches_address(&primary_fixture());
}

#[test]
fn test_20_secondary_secret_recovers_secondary_address() {
    assert_secret_matches_address(&secondary_fixture());
}

#[test]
fn test_21_wallets_directory_creation_succeeds() {
    let temp = TempTree::new("test_21");
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
fn test_22_wallet_file_path_uses_address() {
    let temp = TempTree::new("test_22");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = wallet_file_path(&directory, &fixture.address);

    assert!(path.ends_with(format!("{}.wallet", fixture.address)));
}

#[test]
fn test_23_tmp_wallet_file_path_uses_tmp_suffix() {
    let temp = TempTree::new("test_23");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = tmp_wallet_file_path(&directory, &fixture.address);

    assert!(path.ends_with(format!("{}.wallet.tmp", fixture.address)));
}

#[test]
fn test_24_write_wallet_file_round_trips_bytes() {
    let temp = TempTree::new("test_24");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);

    assert_file_bytes_eq(&path, &fixture.encrypted_secret);
}

#[test]
fn test_25_validate_wallet_file_accepts_real_wallet() {
    let temp = TempTree::new("test_25");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let path = write_fixture_wallet_file(&directory, &primary_fixture());

    assert_ok(
        validate_wallet_file_like_s14(&path, 512 * 1024),
        "validate wallet file",
    );
}

#[test]
fn test_26_validate_wallet_file_rejects_missing_file() {
    let temp = TempTree::new("test_26");
    let path = temp.child("missing.wallet");

    let err = assert_err(
        validate_wallet_file_like_s14(&path, 512 * 1024),
        "validate missing file",
    );

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_27_validate_wallet_file_rejects_directory() {
    let temp = TempTree::new("test_27");
    let dir = temp.child("wallet_dir");

    assert_ok(fs::create_dir_all(&dir), "create wallet dir");

    let err = assert_err(
        validate_wallet_file_like_s14(&dir, 512 * 1024),
        "validate directory",
    );

    assert_validation_error(err);
}

#[test]
fn test_28_validate_wallet_file_rejects_empty_file() {
    let temp = TempTree::new("test_28");
    let path = temp.child("empty.wallet");

    assert_ok(fs::write(&path, b""), "write empty wallet");

    let err = assert_err(
        validate_wallet_file_like_s14(&path, 512 * 1024),
        "validate empty file",
    );

    assert_validation_error(err);
}

#[test]
fn test_29_validate_wallet_file_rejects_too_large_file() {
    let temp = TempTree::new("test_29");
    let path = temp.child("large.wallet");

    assert_ok(fs::write(&path, vec![1_u8; 65]), "write large wallet");

    let err = assert_err(
        validate_wallet_file_like_s14(&path, 64),
        "validate too-large file",
    );

    assert_validation_error(err);
}

#[test]
fn test_30_verify_wallet_decrypt_matches_address_accepts_real_wallet() {
    let temp = TempTree::new("test_30");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(&path, fixture.passphrase, &fixture.address),
        "verify decrypt matches address",
    );
}

#[test]
fn test_31_verify_wallet_decrypt_matches_address_rejects_wrong_passphrase() {
    let temp = TempTree::new("test_31");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&path, "wrong", &fixture.address),
        "verify wrong passphrase",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_32_verify_wallet_decrypt_matches_address_rejects_wrong_expected_wallet() {
    let temp = TempTree::new("test_32");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let first = primary_fixture();
    let second = secondary_fixture();
    let path = write_fixture_wallet_file(&directory, &first);

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&path, first.passphrase, &second.address),
        "verify wrong expected wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_33_verify_wallet_decrypt_matches_address_rejects_tampered_file() {
    let temp = TempTree::new("test_33");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = read_file_bytes(&path);

    match bytes.first_mut() {
        Some(byte) => *byte ^= 0xAA,
        None => panic!("wallet file unexpectedly empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered file");

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&path, fixture.passphrase, &fixture.address),
        "verify tampered file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_34_verify_wallet_decrypt_matches_address_rejects_missing_file() {
    let temp = TempTree::new("test_34");
    let path = temp.child("missing.wallet");

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(
            &path,
            primary_fixture().passphrase,
            &primary_fixture().address,
        ),
        "verify missing file",
    );

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_35_verify_wallet_decrypt_matches_address_accepts_legacy_hex_file() {
    let temp = TempTree::new("test_35");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = make_legacy_hex_wallet_file(&directory, &fixture);

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(&path, fixture.passphrase, &fixture.address),
        "verify legacy hex wallet file",
    );
}

#[test]
fn test_36_atomic_backup_creates_backup_directory() {
    let temp = TempTree::new("test_36");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    assert!(!backup_dir.exists());

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
    assert!(backup_dir.is_dir());
}

#[test]
fn test_37_atomic_backup_copies_exact_wallet_bytes() {
    let temp = TempTree::new("test_37");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert_eq!(read_file_bytes(&backup), read_file_bytes(&wallet_file));
}

#[test]
fn test_38_atomic_backup_removes_tmp_backup_after_success() {
    let temp = TempTree::new("test_38");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    let _backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(!tmp_backup_file_path(&backup_dir, &fixture.address).exists());
}

#[test]
fn test_39_atomic_backup_refuses_overwrite_existing_backup() {
    let temp = TempTree::new("test_39");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    let _backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    let err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &backup_dir,
            &fixture.address,
            512 * 1024,
        ),
        "backup overwrite existing file",
    );

    assert_validation_error(err);
}

#[test]
fn test_40_atomic_backup_refuses_live_wallet_directory() {
    let temp = TempTree::new("test_40");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);

    let err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &directory.wallets_path,
            &fixture.address,
            512 * 1024,
        ),
        "backup into live wallet dir",
    );

    assert_validation_error(err);
}

#[test]
fn test_41_atomic_backup_rejects_backup_path_that_is_file() {
    let temp = TempTree::new("test_41");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_path = temp.child("backup_is_file");

    assert_ok(
        fs::write(&backup_path, b"not a dir"),
        "write backup path file",
    );

    let err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &backup_path,
            &fixture.address,
            512 * 1024,
        ),
        "backup path is file",
    );

    assert_validation_error(err);
}

#[test]
fn test_42_atomic_backup_removes_stale_tmp_before_copy() {
    let temp = TempTree::new("test_42");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    assert_ok(fs::create_dir_all(&backup_dir), "create backup dir");
    let tmp = tmp_backup_file_path(&backup_dir, &fixture.address);
    assert_ok(fs::write(&tmp, b"stale tmp"), "write stale tmp");

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
    assert!(!tmp.exists());
}

#[test]
fn test_43_atomic_backup_rejects_empty_wallet_file() {
    let temp = TempTree::new("test_43");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let wallet = wallet_from_label("test_43_wallet");
    let wallet_file = wallet_file_path(&directory, &wallet);
    assert_ok(fs::write(&wallet_file, b""), "write empty wallet file");

    let err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &temp.child("backup"),
            &wallet,
            512 * 1024,
        ),
        "backup empty wallet file",
    );

    assert_validation_error(err);
}

#[test]
fn test_44_atomic_backup_rejects_too_large_wallet_file() {
    let temp = TempTree::new("test_44");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let wallet = wallet_from_label("test_44_wallet");
    let wallet_file = wallet_file_path(&directory, &wallet);
    assert_ok(
        fs::write(&wallet_file, vec![1_u8; 65]),
        "write large wallet file",
    );

    let err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &temp.child("backup"),
            &wallet,
            64,
        ),
        "backup too large wallet file",
    );

    assert_validation_error(err);
}

#[test]
fn test_45_atomic_backup_with_spaces_in_backup_path_succeeds() {
    let temp = TempTree::new("test_45");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup with spaces");

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
}

#[test]
fn test_46_atomic_backup_with_unicode_backup_path_succeeds() {
    let temp = TempTree::new("test_46");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup_測試");

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
}

#[test]
fn test_47_backup_file_path_uses_wallet_address() {
    let temp = TempTree::new("test_47");
    let wallet = wallet_from_label("test_47");
    let path = backup_file_path(&temp.root, &wallet);

    assert!(path.ends_with(format!("{wallet}.wallet")));
}

#[test]
fn test_48_tmp_backup_file_path_uses_tmp_suffix() {
    let temp = TempTree::new("test_48");
    let wallet = wallet_from_label("test_48");
    let path = tmp_backup_file_path(&temp.root, &wallet);

    assert!(path.ends_with(format!("{wallet}.wallet.tmp")));
}

#[test]
fn test_49_backup_copy_does_not_modify_source_file() {
    let temp = TempTree::new("test_49");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let before = read_file_bytes(&wallet_file);

    let _backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    let after = read_file_bytes(&wallet_file);
    assert_eq!(before, after);
}

#[test]
fn test_50_backup_copy_distinct_wallets_make_distinct_files() {
    let temp = TempTree::new("test_50");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let first = primary_fixture();
    let second = secondary_fixture();
    let first_file = write_fixture_wallet_file(&directory, &first);
    let second_file = write_fixture_wallet_file(&directory, &second);
    let backup_dir = temp.child("backup");

    let first_backup = assert_backup_success(
        &directory,
        &first_file,
        &backup_dir,
        &first.address,
        &first.encrypted_secret,
    );
    let second_backup = assert_backup_success(
        &directory,
        &second_file,
        &backup_dir,
        &second.address,
        &second.encrypted_secret,
    );

    assert_ne!(first_backup, second_backup);
}

#[test]
fn test_51_verify_then_backup_flow_succeeds() {
    let temp = TempTree::new("test_51");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(
            &wallet_file,
            fixture.passphrase,
            &fixture.address,
        ),
        "verify before backup",
    );

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
}

#[test]
fn test_52_wrong_passphrase_prevents_verify_then_backup_flow() {
    let temp = TempTree::new("test_52");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&wallet_file, "wrong", &fixture.address),
        "wrong passphrase before backup",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_53_wrong_expected_wallet_prevents_verify_then_backup_flow() {
    let temp = TempTree::new("test_53");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let first = primary_fixture();
    let second = secondary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &first);

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(
            &wallet_file,
            first.passphrase,
            &second.address,
        ),
        "wrong wallet before backup",
    );

    assert_validation_error(err);
}

#[test]
fn test_54_wallet_file_metadata_is_file() {
    let temp = TempTree::new("test_54");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let path = write_fixture_wallet_file(&directory, &primary_fixture());
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(metadata.is_file());
}

#[test]
fn test_55_wallet_file_metadata_is_nonempty() {
    let temp = TempTree::new("test_55");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let path = write_fixture_wallet_file(&directory, &primary_fixture());
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(metadata.len() > 0);
}

#[test]
fn test_56_wallet_file_metadata_matches_encrypted_secret_len() {
    let temp = TempTree::new("test_56");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert_eq!(
        metadata.len(),
        u64::try_from(fixture.encrypted_secret.len()).unwrap_or(0)
    );
}

#[test]
fn test_57_backup_file_metadata_matches_source_len() {
    let temp = TempTree::new("test_57");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    let source_meta = assert_ok(fs::metadata(wallet_file), "source metadata");
    let backup_meta = assert_ok(fs::metadata(backup), "backup metadata");

    assert_eq!(source_meta.len(), backup_meta.len());
}

#[test]
fn test_58_backup_file_can_be_verified_after_copy() {
    let temp = TempTree::new("test_58");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(
            &backup,
            fixture.passphrase,
            &fixture.address,
        ),
        "verify backup copy",
    );
}

#[test]
fn test_59_backup_file_rejects_wrong_passphrase_after_copy() {
    let temp = TempTree::new("test_59");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&backup, "wrong", &fixture.address),
        "verify backup wrong passphrase",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_60_backup_file_tamper_after_copy_rejects_verification() {
    let temp = TempTree::new("test_60");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    let mut bytes = read_file_bytes(&backup);
    match bytes.first_mut() {
        Some(byte) => *byte ^= 0x01,
        None => panic!("backup unexpectedly empty"),
    }
    assert_ok(fs::write(&backup, &bytes), "write tampered backup");

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(
            &backup,
            fixture.passphrase,
            &fixture.address,
        ),
        "verify tampered backup",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_61_logger_accepts_backup_prompt_event() {
    let temp = TempTree::new("test_61");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("wallet", "BackupPromptReadFailed", "test event"),
        "log backup prompt event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_62_logger_accepts_wallet_file_not_found_event() {
    let temp = TempTree::new("test_62");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("wallet", "WalletFileNotFound", "missing wallet"),
        "log wallet file missing",
    );
    assert_ok(logger.flush(), "flush logger");
}

#[test]
fn test_63_logger_accepts_unicode_backup_message() {
    let temp = TempTree::new("test_63");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("wallet", "BackupUnicode", "backup 測試 🔐"),
        "log unicode backup",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_64_vector_canonicalize_wallet_inputs() {
    for label in ["alpha", "beta", "gamma", "delta", "epsilon"] {
        let wallet = wallet_from_label(label);
        let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon vector wallet");
        assert_eq!(canonical, wallet);
    }
}

#[test]
fn test_65_vector_reject_invalid_wallet_inputs() {
    for input in ["", "r", "r1234", "x1234", "not-a-wallet"] {
        let err = assert_err(
            canon_wallet_id_checked(input),
            "reject invalid vector wallet",
        );
        assert_validation_error(err);
    }
}

#[test]
fn test_66_vector_validate_real_wallet_files() {
    let temp = TempTree::new("test_66");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..3usize {
        let wallet = make_wallet(&format!("test_66_passphrase_{index}"));
        let path = write_wallet_file(&directory, &wallet);

        assert_ok(
            validate_wallet_file_like_s14(&path, 512 * 1024),
            "validate vector wallet file",
        );
    }
}

#[test]
fn test_67_vector_verify_three_wallet_files() {
    let temp = TempTree::new("test_67");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..3usize {
        let passphrase = format!("test_67_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        assert_ok(
            verify_wallet_decrypt_matches_address_like_s14(&path, &passphrase, &wallet.address),
            "verify vector wallet file",
        );
    }
}

#[test]
fn test_68_vector_wrong_passphrases_reject_three_wallet_files() {
    let temp = TempTree::new("test_68");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..3usize {
        let passphrase = format!("test_68_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        let err = assert_err(
            verify_wallet_decrypt_matches_address_like_s14(&path, "wrong", &wallet.address),
            "verify wrong vector wallet file",
        );

        assert_decrypt_like_error(err);
    }
}

#[test]
fn test_69_vector_backup_three_wallet_files() {
    let temp = TempTree::new("test_69");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let backup_dir = temp.child("backup");

    for index in 0usize..3usize {
        let wallet = make_wallet(&format!("test_69_passphrase_{index}"));
        let path = write_wallet_file(&directory, &wallet);

        let backup = assert_backup_success(
            &directory,
            &path,
            &backup_dir,
            &wallet.address,
            &wallet.encrypted_secret,
        );

        assert!(backup.exists());
    }
}

#[test]
fn test_70_vector_backup_paths_are_unique() {
    let temp = TempTree::new("test_70");
    let backup_dir = temp.child("backup");
    let mut paths = Vec::new();

    for index in 0usize..5usize {
        let wallet = wallet_from_label(&format!("test_70_wallet_{index}"));
        paths.push(backup_file_path(&backup_dir, &wallet));
    }

    for left_index in 0usize..paths.len() {
        for right_index in left_index.saturating_add(1)..paths.len() {
            let left = match paths.get(left_index) {
                Some(value) => value,
                None => panic!("missing left path"),
            };
            let right = match paths.get(right_index) {
                Some(value) => value,
                None => panic!("missing right path"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_71_edge_long_passphrase_wallet_verifies() {
    let temp = TempTree::new("test_71");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "long-passphrase-".repeat(16);
    let wallet = make_wallet(&passphrase);
    let path = write_wallet_file(&directory, &wallet);

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(&path, &passphrase, &wallet.address),
        "verify long passphrase wallet",
    );
}

#[test]
fn test_72_edge_unicode_passphrase_wallet_verifies() {
    let temp = TempTree::new("test_72");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "密碼 backup кошелек 🔐";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(&path, passphrase, &wallet.address),
        "verify unicode passphrase wallet",
    );
}

#[test]
fn test_73_edge_wallets_directory_with_spaces_succeeds() {
    let temp = TempTree::new("test_73");
    let opts = make_node_opts(&temp.child("node with spaces"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_73_passphrase");
    let path = write_wallet_file(&directory, &wallet);

    assert!(path.exists());
}

#[test]
fn test_74_edge_wallets_directory_with_unicode_succeeds() {
    let temp = TempTree::new("test_74");
    let opts = make_node_opts(&temp.child("node_測試_backup"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_74_passphrase");
    let path = write_wallet_file(&directory, &wallet);

    assert!(path.exists());
}

#[test]
fn test_75_edge_backup_directory_nested_creation_succeeds() {
    let temp = TempTree::new("test_75");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("a").join("b").join("c");

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
}

#[test]
fn test_76_edge_existing_backup_directory_succeeds() {
    let temp = TempTree::new("test_76");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    assert_ok(fs::create_dir_all(&backup_dir), "precreate backup dir");

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
}

#[test]
fn test_77_edge_backup_empty_nonwallet_source_rejected() {
    let temp = TempTree::new("test_77");
    let live = temp.child("live");
    let backup = temp.child("backup");
    let wallet = wallet_from_label("test_77_wallet");

    assert_ok(fs::create_dir_all(&live), "create live dir");
    let source = live.join(format!("{wallet}.wallet"));
    assert_ok(fs::write(&source, b""), "write empty source");

    let err = assert_err(
        atomic_backup_copy_like_s14(&source, &live, &backup, &wallet, 512 * 1024),
        "backup empty nonwallet source",
    );

    assert_validation_error(err);
}

#[test]
fn test_78_adversarial_tamper_first_byte_rejects_verify() {
    let temp = TempTree::new("test_78");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = read_file_bytes(&path);

    match bytes.first_mut() {
        Some(byte) => *byte ^= 0x11,
        None => panic!("wallet file empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet");

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&path, fixture.passphrase, &fixture.address),
        "verify first-byte tamper",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_79_adversarial_tamper_middle_byte_rejects_verify() {
    let temp = TempTree::new("test_79");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = read_file_bytes(&path);
    let middle = bytes.len() / 2;

    match bytes.get_mut(middle) {
        Some(byte) => *byte ^= 0x22,
        None => panic!("wallet file missing middle"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet");

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&path, fixture.passphrase, &fixture.address),
        "verify middle-byte tamper",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_80_adversarial_tamper_last_byte_rejects_verify() {
    let temp = TempTree::new("test_80");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = read_file_bytes(&path);

    match bytes.last_mut() {
        Some(byte) => *byte ^= 0x44,
        None => panic!("wallet file empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet");

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&path, fixture.passphrase, &fixture.address),
        "verify last-byte tamper",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_81_adversarial_random_wallet_file_rejects_verify() {
    let temp = TempTree::new("test_81");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let wallet = wallet_from_label("test_81_wallet");
    let path = wallet_file_path(&directory, &wallet);
    assert_ok(fs::write(&path, vec![0xAB_u8; 256]), "write random wallet");

    let err = assert_err(
        verify_wallet_decrypt_matches_address_like_s14(&path, "test_81_passphrase", &wallet),
        "verify random wallet file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_82_adversarial_existing_backup_file_not_overwritten() {
    let temp = TempTree::new("test_82");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    assert_ok(fs::create_dir_all(&backup_dir), "create backup dir");
    let backup_file = backup_file_path(&backup_dir, &fixture.address);
    assert_ok(
        fs::write(&backup_file, b"existing"),
        "write existing backup",
    );

    let err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &backup_dir,
            &fixture.address,
            512 * 1024,
        ),
        "backup existing file",
    );

    assert_validation_error(err);
    assert_eq!(read_file_bytes(&backup_file), b"existing");
}

#[test]
fn test_83_adversarial_stale_tmp_with_existing_backup_refuses_overwrite() {
    let temp = TempTree::new("test_83");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child("backup");

    assert_ok(fs::create_dir_all(&backup_dir), "create backup dir");
    assert_ok(
        fs::write(backup_file_path(&backup_dir, &fixture.address), b"existing"),
        "write existing backup",
    );
    assert_ok(
        fs::write(
            tmp_backup_file_path(&backup_dir, &fixture.address),
            b"stale",
        ),
        "write stale tmp",
    );

    let err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &backup_dir,
            &fixture.address,
            512 * 1024,
        ),
        "backup existing file with stale tmp",
    );

    assert_validation_error(err);
}

#[test]
fn test_84_adversarial_backup_from_directory_source_rejected() {
    let temp = TempTree::new("test_84");
    let live = temp.child("live");
    let backup = temp.child("backup");
    let wallet = wallet_from_label("test_84_wallet");
    let source_dir = live.join(format!("{wallet}.wallet"));

    assert_ok(fs::create_dir_all(&source_dir), "create source dir");

    let err = assert_err(
        atomic_backup_copy_like_s14(&source_dir, &live, &backup, &wallet, 512 * 1024),
        "backup directory source",
    );

    assert_validation_error(err);
}

#[test]
fn test_85_property_backup_preserves_decryptability() {
    let temp = TempTree::new("test_85");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(
            &backup,
            fixture.passphrase,
            &fixture.address,
        ),
        "backup preserves decryptability",
    );
}

#[test]
fn test_86_property_copy_hash_matches_source_hash() {
    let temp = TempTree::new("test_86");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    let source_hash = RemzarHash::compute_bytes_hash_hex(&read_file_bytes(&wallet_file));
    let backup_hash = RemzarHash::compute_bytes_hash_hex(&read_file_bytes(&backup));

    assert_eq!(source_hash, backup_hash);
}

#[test]
fn test_87_property_distinct_wallet_backups_have_distinct_hashes() {
    let temp = TempTree::new("test_87");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let first = primary_fixture();
    let second = secondary_fixture();
    let first_file = write_fixture_wallet_file(&directory, &first);
    let second_file = write_fixture_wallet_file(&directory, &second);
    let backup_dir = temp.child("backup");

    let first_backup = assert_backup_success(
        &directory,
        &first_file,
        &backup_dir,
        &first.address,
        &first.encrypted_secret,
    );
    let second_backup = assert_backup_success(
        &directory,
        &second_file,
        &backup_dir,
        &second.address,
        &second.encrypted_secret,
    );

    let first_hash = RemzarHash::compute_bytes_hash_hex(&read_file_bytes(&first_backup));
    let second_hash = RemzarHash::compute_bytes_hash_hex(&read_file_bytes(&second_backup));

    assert_ne!(first_hash, second_hash);
}

#[test]
fn test_88_property_backup_destination_does_not_equal_source() {
    let temp = TempTree::new("test_88");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &temp.child("backup"),
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert_ne!(wallet_file, backup);
}

#[test]
fn test_89_property_wallet_address_length_matches_backup_filename_stem() {
    let wallet = wallet_from_label("test_89_wallet");
    let filename = format!("{wallet}.wallet");

    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
    assert!(filename.starts_with(&wallet));
}

#[test]
fn test_90_property_backup_file_extension_is_wallet() {
    let wallet = wallet_from_label("test_90_wallet");
    let path = backup_file_path(Path::new("backup"), &wallet);

    assert_eq!(path.extension().and_then(|s| s.to_str()), Some("wallet"));
}

#[test]
fn test_91_load_create_five_wallet_files() {
    let temp = TempTree::new("test_91");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_91_passphrase_{index}"));
        let path = write_wallet_file(&directory, &wallet);

        assert!(path.exists());
    }
}

#[test]
fn test_92_load_verify_five_wallet_files() {
    let temp = TempTree::new("test_92");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..5usize {
        let passphrase = format!("test_92_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        assert_ok(
            verify_wallet_decrypt_matches_address_like_s14(&path, &passphrase, &wallet.address),
            "load verify wallet",
        );
    }
}

#[test]
fn test_93_load_backup_five_wallet_files() {
    let temp = TempTree::new("test_93");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let backup_dir = temp.child("backup");

    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_93_passphrase_{index}"));
        let path = write_wallet_file(&directory, &wallet);
        let backup = assert_backup_success(
            &directory,
            &path,
            &backup_dir,
            &wallet.address,
            &wallet.encrypted_secret,
        );

        assert!(backup.exists());
    }
}

#[test]
fn test_94_load_validate_ten_backup_paths() {
    let temp = TempTree::new("test_94");
    let backup_dir = temp.child("backup");

    for index in 0usize..10usize {
        let wallet = wallet_from_label(&format!("test_94_wallet_{index}"));
        let path = backup_file_path(&backup_dir, &wallet);

        assert!(path.ends_with(format!("{wallet}.wallet")));
    }
}

#[test]
fn test_95_load_canonicalize_twenty_wallet_labels() {
    for index in 0usize..20usize {
        let wallet = wallet_from_label(&format!("test_95_wallet_{index}"));
        let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon load wallet");

        assert_eq!(canonical, wallet);
    }
}

#[test]
fn test_96_load_logger_many_backup_events() {
    let temp = TempTree::new("test_96");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    for index in 0usize..20usize {
        assert_ok(
            logger.log_error_event("wallet", "LoadBackupWallet", &format!("event {index}")),
            "log load backup event",
        );
    }

    assert_ok(logger.flush_logs_cf(), "flush load logger");
}

#[test]
fn test_97_load_stale_tmp_cleanup_for_three_wallets() {
    let temp = TempTree::new("test_97");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let backup_dir = temp.child("backup");

    assert_ok(fs::create_dir_all(&backup_dir), "create backup dir");

    for index in 0usize..3usize {
        let wallet = make_wallet(&format!("test_97_passphrase_{index}"));
        let wallet_file = write_wallet_file(&directory, &wallet);
        let tmp = tmp_backup_file_path(&backup_dir, &wallet.address);

        assert_ok(fs::write(&tmp, b"stale"), "write stale tmp");

        let backup = assert_backup_success(
            &directory,
            &wallet_file,
            &backup_dir,
            &wallet.address,
            &wallet.encrypted_secret,
        );

        assert!(backup.exists());
        assert!(!tmp.exists());
    }
}

#[test]
fn test_98_load_backup_hashes_for_five_wallets_are_distinct() {
    let temp = TempTree::new("test_98");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let backup_dir = temp.child("backup");
    let mut hashes = Vec::new();

    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_98_passphrase_{index}"));
        let wallet_file = write_wallet_file(&directory, &wallet);
        let backup = assert_backup_success(
            &directory,
            &wallet_file,
            &backup_dir,
            &wallet.address,
            &wallet.encrypted_secret,
        );

        hashes.push(RemzarHash::compute_bytes_hash_hex(&read_file_bytes(
            &backup,
        )));
    }

    for left_index in 0usize..hashes.len() {
        for right_index in left_index.saturating_add(1)..hashes.len() {
            let left = match hashes.get(left_index) {
                Some(value) => value,
                None => panic!("missing left hash"),
            };
            let right = match hashes.get(right_index) {
                Some(value) => value,
                None => panic!("missing right hash"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_99_load_backup_uuid_named_parent_directory_succeeds() {
    let temp = TempTree::new("test_99");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let wallet_file = write_fixture_wallet_file(&directory, &fixture);
    let backup_dir = temp.child(&format!("backup_{}", Uuid::new_v4()));

    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &fixture.address,
        &fixture.encrypted_secret,
    );

    assert!(backup.exists());
}

#[test]
fn test_100_final_backup_wallet_verify_copy_refuse_overwrite_and_log_flow() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let logger = make_logger(&opts);
    let passphrase = "test_100_passphrase";
    let wallet = make_wallet(passphrase);

    assert_wallet_shape(&wallet.address);
    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&wallet.address, &wallet.public),
        "final wallet public binding",
    );

    let wallet_file = write_wallet_file(&directory, &wallet);
    assert_ok(
        validate_wallet_file_like_s14(&wallet_file, 512 * 1024),
        "final validate wallet file",
    );
    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(&wallet_file, passphrase, &wallet.address),
        "final verify wallet decrypt binding",
    );

    let backup_dir = temp.child("final_backup");
    let backup = assert_backup_success(
        &directory,
        &wallet_file,
        &backup_dir,
        &wallet.address,
        &wallet.encrypted_secret,
    );

    assert_eq!(read_file_bytes(&backup), read_file_bytes(&wallet_file));

    let overwrite_err = assert_err(
        atomic_backup_copy_like_s14(
            &wallet_file,
            &directory.wallets_path,
            &backup_dir,
            &wallet.address,
            512 * 1024,
        ),
        "final overwrite refusal",
    );
    assert_validation_error(overwrite_err);

    assert_ok(
        verify_wallet_decrypt_matches_address_like_s14(&backup, passphrase, &wallet.address),
        "final verify backup copy",
    );

    assert_ok(
        logger.log_error_event("wallet", "FinalBackupWalletTest", &wallet.address),
        "final log backup wallet event",
    );
    assert_ok(logger.flush_logs_cf(), "final flush logs");
}
