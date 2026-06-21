use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::commandline::s_08_check_balance::S08CheckBalance;
use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    format_remzar_trim, from_micro_units,
};
use remzar::utility::logging_data::JsonLogger;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_08_check_balance_tests_{test_name}_{}_{}",
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
        ErrorDetection::ValidationError { .. }
        | ErrorDetection::DecryptionError { .. }
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

fn make_manager(opts: &NodeOpts) -> RockDBManager {
    assert_ok(RockDBManager::new(opts), "RockDBManager::new")
}

fn make_wallet(passphrase: &str) -> MLDSA65Wallet {
    assert_ok(MLDSA65Wallet::new(passphrase), "MLDSA65Wallet::new")
}

fn wallet_file_path(directory: &DirectoryDB, wallet_addr: &str) -> PathBuf {
    directory.wallets_path.join(format!("{wallet_addr}.wallet"))
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

fn decrypt_wallet_secret(encrypted: &[u8], passphrase: &str) -> Vec<u8> {
    assert_ok(
        Cryption::decrypt_private_key_bytes(encrypted, passphrase),
        "decrypt wallet secret",
    )
}

fn derived_address_from_secret(secret: &[u8]) -> String {
    let sk_arr: [u8; ml_dsa_65::SK_LEN] = match secret.try_into() {
        Ok(value) => value,
        Err(_) => panic!("secret bytes did not fit ML-DSA-65 secret array"),
    };

    let sk = assert_ok(
        ml_dsa_65::PrivateKey::try_from_bytes(sk_arr),
        "PrivateKey::try_from_bytes",
    );
    let pk = sk.get_public_key();
    let public_bytes = pk.into_bytes();

    derive_wallet_id_from_pubkey_bytes(&public_bytes)
}

fn authenticate_wallet_file_like_s08(
    wallet_file: &Path,
    passphrase: &str,
    expected_wallet_addr: &str,
) -> Result<String, ErrorDetection> {
    let meta = fs::metadata(wallet_file).map_err(|e| ErrorDetection::IoError {
        message: format!("metadata failed: {e}"),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    if !meta.is_file() {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet path is not a regular file.".to_owned(),
            tx_id: None,
        });
    }

    let enc_len = usize::try_from(meta.len()).map_err(|_| ErrorDetection::ValidationError {
        message: "Wallet file size is too large for this platform.".to_owned(),
        tx_id: None,
    })?;

    if enc_len < Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet file is too small or corrupt.".to_owned(),
            tx_id: None,
        });
    }

    if enc_len > GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet file exceeds encrypted blob size limits.".to_owned(),
            tx_id: None,
        });
    }

    let mut encrypted = fs::read(wallet_file).map_err(|e| ErrorDetection::IoError {
        message: format!("read failed: {e}"),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    let mut plaintext =
        Cryption::decrypt_private_key_bytes(&encrypted, passphrase).map_err(|e| {
            encrypted.zeroize();
            ErrorDetection::ValidationError {
                message: format!("Wallet authentication failed: {e}"),
                tx_id: None,
            }
        })?;

    encrypted.zeroize();

    let secret_bytes = if plaintext.len() == ml_dsa_65::SK_LEN {
        plaintext.clone()
    } else {
        let secret_hex = match std::str::from_utf8(&plaintext) {
            Ok(value) => value.trim().to_owned(),
            Err(_) => {
                plaintext.zeroize();
                return Err(ErrorDetection::ValidationError {
                    message: "wallet secret is not raw bytes or UTF-8 hex".to_owned(),
                    tx_id: None,
                });
            }
        };

        if secret_hex.len() != ml_dsa_65::SK_LEN.saturating_mul(2)
            || !secret_hex.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            plaintext.zeroize();
            return Err(ErrorDetection::ValidationError {
                message: "wallet secret hex has unexpected format".to_owned(),
                tx_id: None,
            });
        }

        let bytes = hex::decode(secret_hex).map_err(|e| ErrorDetection::ValidationError {
            message: format!("hex decode failed: {e}"),
            tx_id: None,
        })?;

        plaintext.zeroize();
        bytes
    };

    let derived = derived_address_from_secret(&secret_bytes);
    let expected = canon_wallet_id_checked(expected_wallet_addr)?;

    if derived != expected {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet file does not belong to the entered wallet address.".to_owned(),
            tx_id: None,
        });
    }

    Ok(derived)
}

fn write_account_balance(manager: &RockDBManager, wallet: &str, balance: u64) {
    let bytes = assert_ok(postcard::to_allocvec(&balance), "serialize balance");
    assert_ok(
        manager.write(
            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
            wallet.as_bytes(),
            &bytes,
        ),
        "write account balance",
    );
}

fn read_account_balance_direct(manager: &RockDBManager, wallet: &str) -> Option<u64> {
    let maybe_bytes = assert_ok(
        manager.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, wallet.as_bytes()),
        "read account balance",
    );

    maybe_bytes.map(|bytes| assert_ok(postcard::from_bytes::<u64>(&bytes), "decode balance"))
}

fn read_account_balance_or_zero(manager: &RockDBManager, wallet: &str) -> u64 {
    match manager.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, wallet.as_bytes()) {
        Ok(Some(bytes)) => postcard::from_bytes::<u64>(&bytes).unwrap_or(0),
        Ok(None) | Err(_) => 0,
    }
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

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S08CheckBalance::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S08CheckBalance;
}

#[test]
fn test_03_default_trait_creates_section() {
    let _section = S08CheckBalance::default();
}

#[test]
fn test_04_wallet_from_label_has_expected_shape() {
    let wallet = wallet_from_label("test_04");

    assert_wallet_shape(&wallet);
}

#[test]
fn test_05_generated_wallet_address_has_expected_shape() {
    let wallet = make_wallet("test_05_passphrase");

    assert_wallet_shape(&wallet.address);
}

#[test]
fn test_06_canon_generated_wallet_address_succeeds() {
    let wallet = make_wallet("test_06_passphrase");
    let canonical = assert_ok(
        canon_wallet_id_checked(&wallet.address),
        "canon generated wallet",
    );

    assert_eq!(canonical, wallet.address);
}

#[test]
fn test_07_canon_uppercase_wallet_address_canonicalizes() {
    let wallet = make_wallet("test_07_passphrase");
    let canonical = assert_ok(
        canon_wallet_id_checked(&wallet.address.to_ascii_uppercase()),
        "canon uppercase wallet",
    );

    assert_eq!(canonical, wallet.address);
}

#[test]
fn test_08_canon_whitespace_padded_wallet_address_canonicalizes() {
    let wallet = make_wallet("test_08_passphrase");
    let padded = format!("  {}  ", wallet.address);
    let canonical = assert_ok(canon_wallet_id_checked(&padded), "canon padded wallet");

    assert_eq!(canonical, wallet.address);
}

#[test]
fn test_09_canon_empty_wallet_rejects() {
    let err = assert_err(canon_wallet_id_checked(""), "canon empty wallet");

    assert_validation_error(err);
}

#[test]
fn test_10_canon_short_wallet_rejects() {
    let err = assert_err(canon_wallet_id_checked("r1234"), "canon short wallet");

    assert_validation_error(err);
}

#[test]
fn test_11_canon_wrong_prefix_wallet_rejects() {
    let wallet = wallet_from_label("test_11");
    let bad = format!("x{}", &wallet[1..]);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong prefix");

    assert_validation_error(err);
}

#[test]
fn test_12_canon_non_hex_wallet_rejects() {
    let mut wallet = wallet_from_label("test_12");
    wallet.replace_range(1..2, "g");

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon non-hex wallet");

    assert_validation_error(err);
}

#[test]
fn test_13_canon_too_long_wallet_rejects() {
    let mut wallet = wallet_from_label("test_13");
    wallet.push('0');

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon too-long wallet");

    assert_validation_error(err);
}

#[test]
fn test_14_format_remzar_trim_zero_is_not_empty() {
    let formatted = format_remzar_trim(0);

    assert!(!formatted.is_empty());
}

#[test]
fn test_15_format_remzar_trim_one_micro_contains_decimal_digit() {
    let formatted = format_remzar_trim(1);

    assert!(formatted.contains('1'));
}

#[test]
fn test_16_format_remzar_trim_one_remzar_contains_one() {
    let formatted = format_remzar_trim(100_000_000);

    assert!(formatted.contains('1'));
}

#[test]
fn test_17_from_micro_units_one_remzar_is_one() {
    assert_eq!(from_micro_units(100_000_000), 1.0);
}

#[test]
fn test_18_from_micro_units_half_remzar_is_half() {
    assert_eq!(from_micro_units(50_000_000), 0.5);
}

#[test]
fn test_19_from_micro_units_one_micro_is_fraction() {
    assert_eq!(from_micro_units(1), 0.00000001);
}

#[test]
fn test_20_wallets_directory_creation_succeeds() {
    let temp = TempTree::new("test_20");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(
        directory.create_wallets_directory(),
        "create wallets directory",
    );

    assert!(directory.wallets_path.exists());
    assert!(directory.wallets_path.is_dir());
}

#[test]
fn test_21_wallet_file_path_uses_wallet_address() {
    let temp = TempTree::new("test_21");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_21_passphrase");
    let path = wallet_file_path(&directory, &wallet.address);

    assert!(path.ends_with(format!("{}.wallet", wallet.address)));
}

#[test]
fn test_22_write_wallet_file_round_trips_bytes() {
    let temp = TempTree::new("test_22");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_22_passphrase");

    let path = write_wallet_file(&directory, &wallet);
    let stored = assert_ok(fs::read(path), "read wallet file");

    assert_eq!(stored, wallet.encrypted_secret);
}

#[test]
fn test_23_authenticate_wallet_file_like_s08_accepts_valid_wallet() {
    let temp = TempTree::new("test_23");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_23_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate wallet file",
    );

    assert_eq!(derived, wallet.address);
}

#[test]
fn test_24_authenticate_wallet_file_like_s08_accepts_uppercase_expected_address() {
    let temp = TempTree::new("test_24");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_24_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address.to_ascii_uppercase()),
        "authenticate wallet file uppercase expected",
    );

    assert_eq!(derived, wallet.address);
}

#[test]
fn test_25_authenticate_wallet_file_like_s08_rejects_wrong_passphrase() {
    let temp = TempTree::new("test_25");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_25_passphrase");
    let path = write_wallet_file(&directory, &wallet);

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, "wrong_passphrase", &wallet.address),
        "authenticate wrong passphrase",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_26_authenticate_wallet_file_like_s08_rejects_wrong_expected_wallet() {
    let temp = TempTree::new("test_26");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_26_passphrase";
    let wallet = make_wallet(passphrase);
    let other = make_wallet("test_26_other_passphrase");
    let path = write_wallet_file(&directory, &wallet);

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, passphrase, &other.address),
        "authenticate wrong expected wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_27_authenticate_wallet_file_like_s08_rejects_missing_wallet_file() {
    let temp = TempTree::new("test_27");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_27_passphrase");
    let path = wallet_file_path(&directory, &wallet.address);

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, "test_27_passphrase", &wallet.address),
        "authenticate missing wallet file",
    );

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError for missing wallet file, got {other:?}"),
    }
}

#[test]
fn test_28_authenticate_wallet_file_like_s08_rejects_directory_path() {
    let temp = TempTree::new("test_28");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    assert_ok(
        directory.create_wallets_directory(),
        "create wallets directory",
    );
    let wallet = make_wallet("test_28_passphrase");

    let err = assert_err(
        authenticate_wallet_file_like_s08(
            &directory.wallets_path,
            "test_28_passphrase",
            &wallet.address,
        ),
        "authenticate directory path",
    );

    assert_validation_error(err);
}

#[test]
fn test_29_authenticate_wallet_file_like_s08_rejects_too_small_file() {
    let temp = TempTree::new("test_29");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_29_passphrase");

    assert_ok(
        directory.create_wallets_directory(),
        "create wallets directory",
    );
    let path = wallet_file_path(&directory, &wallet.address);
    assert_ok(fs::write(&path, b"small"), "write small wallet file");

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, "test_29_passphrase", &wallet.address),
        "authenticate too-small wallet file",
    );

    assert_validation_error(err);
}

#[test]
fn test_30_authenticate_wallet_file_like_s08_rejects_tampered_file() {
    let temp = TempTree::new("test_30");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_30_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let mut bytes = assert_ok(fs::read(&path), "read wallet file");
    match bytes.first_mut() {
        Some(byte) => {
            *byte ^= 0xAA;
        }
        None => panic!("wallet file unexpectedly empty"),
    }
    assert_ok(fs::write(&path, &bytes), "write tampered wallet file");

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate tampered wallet file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_31_decrypt_wallet_secret_derives_wallet_address() {
    let passphrase = "test_31_passphrase";
    let wallet = make_wallet(passphrase);
    let mut secret = decrypt_wallet_secret(&wallet.encrypted_secret, passphrase);

    let derived = derived_address_from_secret(&secret);

    secret.zeroize();
    assert_eq!(derived, wallet.address);
}

#[test]
fn test_32_decrypt_wallet_secret_rejects_wrong_passphrase() {
    let wallet = make_wallet("test_32_passphrase");

    let err = assert_err(
        Cryption::decrypt_private_key_bytes(&wallet.encrypted_secret, "wrong"),
        "decrypt wrong passphrase",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_33_decrypt_wallet_secret_rejects_empty_blob() {
    let err = assert_err(
        Cryption::decrypt_private_key_bytes(&[], "test_33_passphrase"),
        "decrypt empty blob",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_34_decrypt_wallet_secret_rejects_short_blob() {
    let short = vec![0_u8; 12];

    let err = assert_err(
        Cryption::decrypt_private_key_bytes(&short, "test_34_passphrase"),
        "decrypt short blob",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_35_wallet_encrypted_blob_meets_s08_min_size() {
    let wallet = make_wallet("test_35_passphrase");

    assert!(wallet.encrypted_secret.len() >= Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES);
}

#[test]
fn test_36_wallet_encrypted_blob_is_under_global_max() {
    let wallet = make_wallet("test_36_passphrase");

    assert!(wallet.encrypted_secret.len() <= GlobalConfiguration::MAX_ENCRYPTED_BLOB_BYTES);
}

#[test]
fn test_37_wallet_encrypted_blob_is_not_plain_secret_bytes() {
    let passphrase = "test_37_passphrase";
    let wallet = make_wallet(passphrase);
    let mut secret = decrypt_wallet_secret(&wallet.encrypted_secret, passphrase);

    assert_ne!(wallet.encrypted_secret.as_slice(), secret.as_slice());

    secret.zeroize();
}

#[test]
fn test_38_account_balance_missing_reads_none() {
    let temp = TempTree::new("test_38");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_38_wallet");

    assert!(read_account_balance_direct(&manager, &wallet).is_none());
}

#[test]
fn test_39_account_balance_write_and_read_zero() {
    let temp = TempTree::new("test_39");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_39_wallet");

    write_account_balance(&manager, &wallet, 0);

    assert_eq!(read_account_balance_direct(&manager, &wallet), Some(0));
}

#[test]
fn test_40_account_balance_write_and_read_one_micro() {
    let temp = TempTree::new("test_40");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_40_wallet");

    write_account_balance(&manager, &wallet, 1);

    assert_eq!(read_account_balance_direct(&manager, &wallet), Some(1));
}

#[test]
fn test_41_account_balance_write_and_read_one_remzar() {
    let temp = TempTree::new("test_41");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_41_wallet");

    write_account_balance(&manager, &wallet, 100_000_000);

    assert_eq!(
        read_account_balance_direct(&manager, &wallet),
        Some(100_000_000)
    );
}

#[test]
fn test_42_account_balance_overwrite_updates_value() {
    let temp = TempTree::new("test_42");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_42_wallet");

    write_account_balance(&manager, &wallet, 10);
    write_account_balance(&manager, &wallet, 20);

    assert_eq!(read_account_balance_direct(&manager, &wallet), Some(20));
}

#[test]
fn test_43_account_balance_corrupt_bytes_read_or_zero_returns_zero() {
    let temp = TempTree::new("test_43");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_43_wallet");

    let corrupt_varint = [0x80_u8];

    assert_ok(
        manager.write(
            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
            wallet.as_bytes(),
            &corrupt_varint,
        ),
        "write corrupt balance",
    );

    assert_eq!(read_account_balance_or_zero(&manager, &wallet), 0);
}

#[test]
fn test_44_account_model_tree_set_get_balance() {
    let temp = TempTree::new("test_44");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_44_wallet");

    tree.set_balance(&wallet, 44);

    assert_eq!(tree.get_balance(&wallet), 44);
}

#[test]
fn test_45_account_model_tree_missing_balance_is_zero() {
    let temp = TempTree::new("test_45");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_45_wallet");

    assert_eq!(tree.get_balance(&wallet), 0);
}

#[test]
fn test_46_account_model_tree_update_balance_accumulates() {
    let temp = TempTree::new("test_46");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_46_wallet");

    assert_ok(tree.update_balance(&wallet, 10), "update balance first");
    assert_ok(tree.update_balance(&wallet, 15), "update balance second");

    assert_eq!(tree.get_balance(&wallet), 25);
}

#[test]
fn test_47_account_model_tree_increment_balance_accumulates() {
    let temp = TempTree::new("test_47");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_47_wallet");

    assert_ok(tree.increment_balance(&wallet, 30), "increment first");
    assert_ok(tree.increment_balance(&wallet, 12), "increment second");

    assert_eq!(tree.get_balance(&wallet), 42);
}

#[test]
fn test_48_account_model_tree_decrement_balance_succeeds() {
    let temp = TempTree::new("test_48");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_48_wallet");

    tree.set_balance(&wallet, 100);
    assert_ok(tree.decrement_balance(&wallet, 40), "decrement balance");

    assert_eq!(tree.get_balance(&wallet), 60);
}

#[test]
fn test_49_account_model_tree_decrement_missing_fails() {
    let temp = TempTree::new("test_49");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_49_wallet");

    let err = assert_err(tree.decrement_balance(&wallet, 1), "decrement missing");

    match err {
        ErrorDetection::NotFound { .. } => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn test_50_account_model_tree_decrement_underflow_fails() {
    let temp = TempTree::new("test_50");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_50_wallet");

    tree.set_balance(&wallet, 5);
    let err = assert_err(tree.decrement_balance(&wallet, 6), "decrement underflow");

    assert_validation_error(err);
}

#[test]
fn test_51_account_model_tree_get_balance_decimal() {
    let temp = TempTree::new("test_51");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_51_wallet");

    tree.set_balance(&wallet, 150_000_000);

    assert_eq!(tree.get_balance_decimal(&wallet), 1.5);
}

#[test]
fn test_52_account_model_tree_get_balances_contains_wallet() {
    let temp = TempTree::new("test_52");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_52_wallet");

    tree.set_balance(&wallet, 52);

    let balances = tree.get_balances();
    let value = match balances.get(&wallet) {
        Some(v) => *v,
        None => panic!("balance missing from get_balances"),
    };

    assert_eq!(value, 52);
}

#[test]
fn test_53_logger_accepts_check_balance_event() {
    let temp = TempTree::new("test_53");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("balance", "CheckBalanceTestEvent", "test event"),
        "log check balance event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_54_logger_accepts_wallet_address_message() {
    let temp = TempTree::new("test_54");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);
    let wallet = wallet_from_label("test_54_wallet");

    assert_ok(
        logger.log_error_event("balance", "CheckBalanceWallet", &wallet),
        "log wallet address",
    );
    assert_ok(logger.flush(), "flush logs");
}

#[test]
fn test_55_logger_accepts_unicode_message() {
    let temp = TempTree::new("test_55");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("balance", "Unicode", "balance 測試 🪙"),
        "log unicode balance event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_56_vector_format_remzar_trim_nonempty_for_common_amounts() {
    for amount in [0_u64, 1, 10, 100_000_000, 250_000_000, 1_234_567_890] {
        let formatted = format_remzar_trim(amount);
        assert!(!formatted.is_empty());
    }
}

#[test]
fn test_57_vector_account_balance_reads_common_amounts() {
    let temp = TempTree::new("test_57");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for amount in [0_u64, 1, 10, 100_000_000, 250_000_000] {
        let wallet = wallet_from_label(&format!("test_57_wallet_{amount}"));
        write_account_balance(&manager, &wallet, amount);
        assert_eq!(read_account_balance_direct(&manager, &wallet), Some(amount));
    }
}

#[test]
fn test_58_vector_authenticate_three_wallet_files() {
    let temp = TempTree::new("test_58");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..3usize {
        let passphrase = format!("test_58_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        let derived = assert_ok(
            authenticate_wallet_file_like_s08(&path, &passphrase, &wallet.address),
            "authenticate vector wallet file",
        );

        assert_eq!(derived, wallet.address);
    }
}

#[test]
fn test_59_vector_wrong_passphrases_reject_three_wallet_files() {
    let temp = TempTree::new("test_59");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..3usize {
        let passphrase = format!("test_59_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        let err = assert_err(
            authenticate_wallet_file_like_s08(&path, "wrong-passphrase", &wallet.address),
            "authenticate wrong vector passphrase",
        );

        assert_decrypt_like_error(err);
    }
}

#[test]
fn test_60_vector_wallet_file_names_are_unique() {
    let temp = TempTree::new("test_60");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let first = make_wallet("test_60_first");
    let second = make_wallet("test_60_second");
    let first_path = wallet_file_path(&directory, &first.address);
    let second_path = wallet_file_path(&directory, &second.address);

    assert_ne!(first_path, second_path);
}

#[test]
fn test_61_edge_wallet_file_with_spaces_data_dir_authenticates() {
    let temp = TempTree::new("test_61");
    let opts = make_node_opts(&temp.child("node with spaces"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_61_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate space dir wallet",
    );

    assert_eq!(derived, wallet.address);
}

#[test]
fn test_62_edge_wallet_file_with_unicode_data_dir_authenticates() {
    let temp = TempTree::new("test_62");
    let opts = make_node_opts(&temp.child("node_測試_balance"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_62_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate unicode dir wallet",
    );

    assert_eq!(derived, wallet.address);
}

#[test]
fn test_63_edge_account_balance_with_unicode_data_dir_round_trips() {
    let temp = TempTree::new("test_63");
    let opts = make_node_opts(&temp.child("node_ баланс"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_63_wallet");

    write_account_balance(&manager, &wallet, 63);

    assert_eq!(read_account_balance_direct(&manager, &wallet), Some(63));
}

#[test]
fn test_64_edge_account_balance_with_spaces_data_dir_round_trips() {
    let temp = TempTree::new("test_64");
    let opts = make_node_opts(&temp.child("node with spaces"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_64_wallet");

    write_account_balance(&manager, &wallet, 64);

    assert_eq!(read_account_balance_direct(&manager, &wallet), Some(64));
}

#[test]
fn test_65_edge_very_long_passphrase_wallet_authenticates() {
    let temp = TempTree::new("test_65");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "long-passphrase-".repeat(32);
    let wallet = make_wallet(&passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, &passphrase, &wallet.address),
        "authenticate long passphrase wallet",
    );

    assert_eq!(derived, wallet.address);
}

#[test]
fn test_66_edge_unicode_passphrase_wallet_authenticates() {
    let temp = TempTree::new("test_66");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "密碼 balance тест 🪙";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate unicode passphrase wallet",
    );

    assert_eq!(derived, wallet.address);
}

#[test]
fn test_67_edge_corrupt_account_balance_empty_bytes_reads_zero() {
    let temp = TempTree::new("test_67");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_67_wallet");

    assert_ok(
        manager.write(
            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
            wallet.as_bytes(),
            b"",
        ),
        "write empty corrupt balance",
    );

    assert_eq!(read_account_balance_or_zero(&manager, &wallet), 0);
}

#[test]
fn test_68_edge_corrupt_account_balance_large_bytes_reads_zero() {
    let temp = TempTree::new("test_68");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = wallet_from_label("test_68_wallet");
    let bad = vec![0xAB_u8; 128];

    assert_ok(
        manager.write(
            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
            wallet.as_bytes(),
            &bad,
        ),
        "write large corrupt balance",
    );

    assert_eq!(read_account_balance_or_zero(&manager, &wallet), 0);
}

#[test]
fn test_69_property_wallet_address_derivation_is_stable_for_same_secret() {
    let passphrase = "test_69_passphrase";
    let wallet = make_wallet(passphrase);
    let mut secret = decrypt_wallet_secret(&wallet.encrypted_secret, passphrase);

    let first = derived_address_from_secret(&secret);
    let second = derived_address_from_secret(&secret);

    secret.zeroize();

    assert_eq!(first, second);
    assert_eq!(first, wallet.address);
}

#[test]
fn test_70_property_different_wallets_have_different_addresses() {
    let first = make_wallet("test_70_first");
    let second = make_wallet("test_70_second");

    assert_ne!(first.address, second.address);
}

#[test]
fn test_71_property_different_wallet_files_authenticate_to_their_own_addresses() {
    let temp = TempTree::new("test_71");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let first_pass = "test_71_first";
    let second_pass = "test_71_second";
    let first = make_wallet(first_pass);
    let second = make_wallet(second_pass);
    let first_path = write_wallet_file(&directory, &first);
    let second_path = write_wallet_file(&directory, &second);

    let first_derived = assert_ok(
        authenticate_wallet_file_like_s08(&first_path, first_pass, &first.address),
        "authenticate first wallet",
    );
    let second_derived = assert_ok(
        authenticate_wallet_file_like_s08(&second_path, second_pass, &second.address),
        "authenticate second wallet",
    );

    assert_eq!(first_derived, first.address);
    assert_eq!(second_derived, second.address);
    assert_ne!(first_derived, second_derived);
}

#[test]
fn test_72_property_cross_wallet_authentication_fails() {
    let temp = TempTree::new("test_72");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let first_pass = "test_72_first";
    let second_pass = "test_72_second";
    let first = make_wallet(first_pass);
    let second = make_wallet(second_pass);
    let first_path = write_wallet_file(&directory, &first);

    let err = assert_err(
        authenticate_wallet_file_like_s08(&first_path, first_pass, &second.address),
        "cross-wallet authentication",
    );

    assert_validation_error(err);
}

#[test]
fn test_73_property_account_balance_many_wallets_independent() {
    let temp = TempTree::new("test_73");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for index in 0u64..8u64 {
        let wallet = wallet_from_label(&format!("test_73_wallet_{index}"));
        write_account_balance(&manager, &wallet, index);
    }

    for index in 0u64..8u64 {
        let wallet = wallet_from_label(&format!("test_73_wallet_{index}"));
        assert_eq!(read_account_balance_direct(&manager, &wallet), Some(index));
    }
}

#[test]
fn test_74_property_account_model_tree_many_wallets_independent() {
    let temp = TempTree::new("test_74");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);

    for index in 0u64..8u64 {
        let wallet = wallet_from_label(&format!("test_74_wallet_{index}"));
        tree.set_balance(&wallet, index.saturating_mul(10));
    }

    for index in 0u64..8u64 {
        let wallet = wallet_from_label(&format!("test_74_wallet_{index}"));
        assert_eq!(tree.get_balance(&wallet), index.saturating_mul(10));
    }
}

#[test]
fn test_75_adversarial_tamper_last_byte_wallet_file_rejects() {
    let temp = TempTree::new("test_75");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_75_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);
    let mut bytes = assert_ok(fs::read(&path), "read wallet file");

    match bytes.last_mut() {
        Some(byte) => {
            *byte ^= 0x01;
        }
        None => panic!("wallet file unexpectedly empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet file");

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate last-byte tampered wallet file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_76_adversarial_tamper_middle_byte_wallet_file_rejects() {
    let temp = TempTree::new("test_76");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_76_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);
    let mut bytes = assert_ok(fs::read(&path), "read wallet file");

    let mid = bytes.len() / 2;
    match bytes.get_mut(mid) {
        Some(byte) => {
            *byte ^= 0x55;
        }
        None => panic!("wallet file missing midpoint byte"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet file");

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate middle-byte tampered wallet file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_77_adversarial_wallet_file_with_random_large_plain_bytes_rejects() {
    let temp = TempTree::new("test_77");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_77_passphrase");

    assert_ok(
        directory.create_wallets_directory(),
        "create wallets directory",
    );
    let path = wallet_file_path(&directory, &wallet.address);
    let bad = vec![0xCD_u8; Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES];
    assert_ok(fs::write(&path, &bad), "write random wallet bytes");

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, "test_77_passphrase", &wallet.address),
        "authenticate random wallet bytes",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_78_adversarial_wrong_expected_address_with_valid_format_rejects() {
    let temp = TempTree::new("test_78");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_78_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);
    let wrong = wallet_from_label("test_78_wrong_wallet");

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, passphrase, &wrong),
        "authenticate valid wrong expected address",
    );

    assert_validation_error(err);
}

#[test]
fn test_79_adversarial_wrong_expected_address_with_invalid_format_rejects() {
    let temp = TempTree::new("test_79");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_79_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, passphrase, "not-a-wallet"),
        "authenticate invalid expected address",
    );

    assert_validation_error(err);
}

#[test]
fn test_80_adversarial_account_balance_key_is_wallet_specific() {
    let temp = TempTree::new("test_80");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let first = wallet_from_label("test_80_first");
    let second = wallet_from_label("test_80_second");

    write_account_balance(&manager, &first, 80);

    assert_eq!(read_account_balance_direct(&manager, &first), Some(80));
    assert!(read_account_balance_direct(&manager, &second).is_none());
}

#[test]
fn test_81_load_authenticate_five_wallet_files() {
    let temp = TempTree::new("test_81");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..5usize {
        let passphrase = format!("test_81_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        let derived = assert_ok(
            authenticate_wallet_file_like_s08(&path, &passphrase, &wallet.address),
            "load authenticate wallet file",
        );

        assert_eq!(derived, wallet.address);
    }
}

#[test]
fn test_82_load_write_and_read_twenty_account_balances() {
    let temp = TempTree::new("test_82");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for index in 0u64..20u64 {
        let wallet = wallet_from_label(&format!("test_82_wallet_{index}"));
        write_account_balance(&manager, &wallet, index.saturating_mul(100));
    }

    for index in 0u64..20u64 {
        let wallet = wallet_from_label(&format!("test_82_wallet_{index}"));
        assert_eq!(
            read_account_balance_direct(&manager, &wallet),
            Some(index.saturating_mul(100))
        );
    }
}

#[test]
fn test_83_load_account_model_tree_twenty_balances() {
    let temp = TempTree::new("test_83");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);

    for index in 0u64..20u64 {
        let wallet = wallet_from_label(&format!("test_83_wallet_{index}"));
        tree.set_balance(&wallet, index);
    }

    assert_eq!(tree.get_balances().len(), 20);
}

#[test]
fn test_84_load_format_many_balances_nonempty() {
    for index in 0u64..50u64 {
        let formatted = format_remzar_trim(index.saturating_mul(12_345));
        assert!(!formatted.is_empty());
    }
}

#[test]
fn test_85_load_canonicalize_many_wallets() {
    for index in 0usize..50usize {
        let wallet = wallet_from_label(&format!("test_85_wallet_{index}"));
        let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon load wallet");
        assert_eq!(canonical, wallet);
    }
}

#[test]
fn test_86_load_reject_many_invalid_wallets() {
    for index in 0usize..20usize {
        let wallet = format!("invalid_wallet_{index}");
        let err = assert_err(
            canon_wallet_id_checked(&wallet),
            "reject load invalid wallet",
        );
        assert_validation_error(err);
    }
}

#[test]
fn test_87_wallet_file_size_metadata_matches_written_secret_len() {
    let temp = TempTree::new("test_87");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_87_passphrase");
    let path = write_wallet_file(&directory, &wallet);
    let meta = assert_ok(fs::metadata(path), "wallet metadata");

    let size = match usize::try_from(meta.len()) {
        Ok(value) => value,
        Err(_) => panic!("wallet metadata len did not fit usize"),
    };

    assert_eq!(size, wallet.encrypted_secret.len());
}

#[test]
fn test_88_wallet_file_size_metadata_above_minimum() {
    let temp = TempTree::new("test_88");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_88_passphrase");
    let path = write_wallet_file(&directory, &wallet);
    let meta = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(meta.len() >= Cryption::MIN_ENCRYPTED_BLOB_FOR_ML_DSA_SECRET_BYTES as u64);
}

#[test]
fn test_89_balance_hash_wallet_label_is_stable() {
    let first = wallet_from_label("test_89");
    let second = wallet_from_label("test_89");

    assert_eq!(first, second);
}

#[test]
fn test_90_balance_hash_wallet_labels_are_distinct() {
    let first = wallet_from_label("test_90_first");
    let second = wallet_from_label("test_90_second");

    assert_ne!(first, second);
}

#[test]
fn test_91_manager_can_store_zero_balance_for_generated_wallet() {
    let temp = TempTree::new("test_91");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = make_wallet("test_91_passphrase");

    write_account_balance(&manager, &wallet.address, 0);

    assert_eq!(
        read_account_balance_direct(&manager, &wallet.address),
        Some(0)
    );
}

#[test]
fn test_92_manager_can_store_large_balance_for_generated_wallet() {
    let temp = TempTree::new("test_92");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let wallet = make_wallet("test_92_passphrase");
    let balance = GlobalConfiguration::MAX_SUPPLY;

    write_account_balance(&manager, &wallet.address, balance);

    assert_eq!(
        read_account_balance_direct(&manager, &wallet.address),
        Some(balance)
    );
}

#[test]
fn test_93_tree_increment_over_supply_fails() {
    let temp = TempTree::new("test_93");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_93_wallet");

    tree.set_balance(&wallet, GlobalConfiguration::MAX_SUPPLY);

    let err = assert_err(tree.increment_balance(&wallet, 1), "increment over supply");

    assert_validation_error(err);
}

#[test]
fn test_94_tree_update_over_supply_fails() {
    let temp = TempTree::new("test_94");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = wallet_from_label("test_94_wallet");

    tree.set_balance(&wallet, GlobalConfiguration::MAX_SUPPLY);

    let err = assert_err(tree.update_balance(&wallet, 1), "update over supply");

    assert_validation_error(err);
}

#[test]
fn test_95_authentication_then_balance_read_flow() {
    let temp = TempTree::new("test_95");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let manager = make_manager(&opts);
    let passphrase = "test_95_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);
    let balance = 950_000_000;

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate flow wallet",
    );
    write_account_balance(&manager, &wallet.address, balance);

    assert_eq!(derived, wallet.address);
    assert_eq!(
        read_account_balance_direct(&manager, &wallet.address),
        Some(balance)
    );
}

#[test]
fn test_96_authentication_failure_does_not_create_balance_entry() {
    let temp = TempTree::new("test_96");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let manager = make_manager(&opts);
    let wallet = make_wallet("test_96_passphrase");
    let path = write_wallet_file(&directory, &wallet);

    let err = assert_err(
        authenticate_wallet_file_like_s08(&path, "wrong", &wallet.address),
        "authenticate failure",
    );

    assert_decrypt_like_error(err);
    assert!(read_account_balance_direct(&manager, &wallet.address).is_none());
}

#[test]
fn test_97_corrupt_balance_entry_does_not_break_wallet_authentication() {
    let temp = TempTree::new("test_97");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let manager = make_manager(&opts);
    let passphrase = "test_97_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let corrupt_varint = [0x80_u8];

    assert_ok(
        manager.write(
            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
            wallet.address.as_bytes(),
            &corrupt_varint,
        ),
        "write corrupt balance",
    );

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate with corrupt balance present",
    );

    assert_eq!(derived, wallet.address);
    assert_eq!(read_account_balance_or_zero(&manager, &wallet.address), 0);
}

#[test]
fn test_98_wallet_authentication_does_not_require_balance_entry() {
    let temp = TempTree::new("test_98");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let manager = make_manager(&opts);
    let passphrase = "test_98_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate without balance",
    );

    assert_eq!(derived, wallet.address);
    assert!(read_account_balance_direct(&manager, &wallet.address).is_none());
}

#[test]
fn test_99_wallet_authentication_and_zero_balance_flow() {
    let temp = TempTree::new("test_99");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let manager = make_manager(&opts);
    let passphrase = "test_99_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "authenticate zero balance flow",
    );
    write_account_balance(&manager, &wallet.address, 0);

    assert_eq!(derived, wallet.address);
    assert_eq!(
        read_account_balance_direct(&manager, &wallet.address),
        Some(0)
    );
}

#[test]
fn test_100_final_check_balance_dependencies_wallet_auth_balance_format_and_logger() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let manager = make_manager(&opts);
    let logger = make_logger(&opts);
    let passphrase = "test_100_passphrase";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&directory, &wallet);
    let balance = 1_234_567_890;

    let derived = assert_ok(
        authenticate_wallet_file_like_s08(&path, passphrase, &wallet.address),
        "final authenticate wallet",
    );
    write_account_balance(&manager, &wallet.address, balance);

    let read_back = match read_account_balance_direct(&manager, &wallet.address) {
        Some(value) => value,
        None => panic!("final balance missing"),
    };

    let formatted = format_remzar_trim(read_back);

    assert_eq!(derived, wallet.address);
    assert_eq!(read_back, balance);
    assert!(!formatted.is_empty());

    assert_ok(
        logger.log_error_event("balance", "FinalCheckBalanceTest", &formatted),
        "final log balance event",
    );
    assert_ok(logger.flush_logs_cf(), "final flush logs cf");
}
