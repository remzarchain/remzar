use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use remzar::commandline::s_13_wallet_utilities::S13WalletUtilities;
use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    wallet_id_matches_pubkey_bytes_checked,
};
use remzar::utility::logging_data::JsonLogger;
use std::fmt::Debug;
use std::fs;
use std::io::Write;
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
            "remzar_s_13_wallet_utilities_tests_{test_name}_{}_{}",
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
        .get_or_init(|| build_wallet_fixture("s13_primary_passphrase"))
        .clone()
}

fn secondary_fixture() -> WalletFixture {
    SECONDARY_WALLET
        .get_or_init(|| build_wallet_fixture("s13_secondary_passphrase"))
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

fn assert_wallet_valid(wallet: &MLDSA65Wallet) {
    assert_wallet_shape(&wallet.address);
    assert_ok(wallet.validate_self(), "wallet validate_self");
    assert_ok(
        MLDSA65Wallet::validate_address_format(&wallet.address),
        "validate address format",
    );
    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&wallet.address, &wallet.public),
        "wallet address matches public key",
    );
}

fn deterministic_message(seed: usize, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for index in 0usize..len {
        let value = seed.wrapping_add(index.wrapping_mul(31)) % 251;
        out.push(u8::try_from(value).unwrap_or(0));
    }

    out
}

fn wallet_file_path(directory: &DirectoryDB, address: &str) -> PathBuf {
    directory.wallets_path.join(format!("{address}.wallet"))
}

fn wallet_tmp_file_path(directory: &DirectoryDB, address: &str) -> PathBuf {
    directory.wallets_path.join(format!("{address}.wallet.tmp"))
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

fn assert_wallet_file_contains(path: &Path, expected: &[u8]) {
    let stored = assert_ok(fs::read(path), "read wallet file");
    assert_eq!(stored, expected);
}

fn validate_wallet_file_like_s13(
    path: &Path,
    max_wallet_file_bytes: u64,
) -> Result<(), ErrorDetection> {
    let meta = fs::metadata(path).map_err(|e| ErrorDetection::IoError {
        message: format!("Failed to stat wallet file '{}': {e}", path.display()),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    if !meta.is_file() {
        return Err(ErrorDetection::ValidationError {
            message: format!("Wallet path is not a regular file: {}", path.display()),
            tx_id: None,
        });
    }

    if meta.len() == 0 {
        return Err(ErrorDetection::ValidationError {
            message: format!("Wallet file is empty/corrupt: {}", path.display()),
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

fn decrypt_wallet_secret_to_hex_like_s13(
    wallet_file: &Path,
    passphrase: &str,
) -> Result<String, ErrorDetection> {
    let mut encrypted_pk = fs::read(wallet_file).map_err(|e| ErrorDetection::IoError {
        message: format!(
            "Failed to read wallet file '{}': {e}",
            wallet_file.display()
        ),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    let mut plaintext =
        Cryption::decrypt_private_key_bytes(&encrypted_pk, passphrase).map_err(|e| {
            encrypted_pk.zeroize();
            ErrorDetection::DecryptionError {
                message: format!("Failed to decrypt private key: {e}"),
            }
        })?;

    encrypted_pk.zeroize();

    if plaintext.len() == ml_dsa_65::SK_LEN {
        let secret_hex = hex::encode(&plaintext);
        plaintext.zeroize();
        return Ok(secret_hex);
    }

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

    Ok(secret_hex)
}

fn recover_address_from_secret_hex_like_s13(secret_hex: &str) -> Result<String, ErrorDetection> {
    let trimmed = secret_hex.trim();

    if trimmed.is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: "private key cannot be empty".to_owned(),
            tx_id: None,
        });
    }

    if trimmed.len() > GlobalConfiguration::MAX_PRIVKEY_HEX_INPUT_LEN {
        return Err(ErrorDetection::ValidationError {
            message: "private key input too long".to_owned(),
            tx_id: None,
        });
    }

    if trimmed.len() != GlobalConfiguration::MLDSA65_SECRET_HEX_LEN {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "private key must be exactly {} hex characters",
                GlobalConfiguration::MLDSA65_SECRET_HEX_LEN
            ),
            tx_id: None,
        });
    }

    let mut bytes = hex::decode(trimmed).map_err(|e| ErrorDetection::ValidationError {
        message: format!("private key is not valid hex: {e}"),
        tx_id: None,
    })?;

    if bytes.len() != ml_dsa_65::SK_LEN {
        bytes.zeroize();
        return Err(ErrorDetection::ValidationError {
            message: "private key decoded to wrong length".to_owned(),
            tx_id: None,
        });
    }

    let recovered = MLDSA65Wallet::address_from_secret_bytes(&bytes);
    bytes.zeroize();
    recovered
}

fn private_key_from_secret_bytes(secret: &[u8]) -> ml_dsa_65::PrivateKey {
    let sk_arr: [u8; ml_dsa_65::SK_LEN] = match secret.try_into() {
        Ok(value) => value,
        Err(_) => panic!("secret bytes did not fit ML-DSA-65 secret array"),
    };

    assert_ok(
        ml_dsa_65::PrivateKey::try_from_bytes(sk_arr),
        "PrivateKey::try_from_bytes",
    )
}

fn derive_address_from_secret_bytes(secret: &[u8]) -> String {
    let sk = private_key_from_secret_bytes(secret);
    let pk = sk.get_public_key();
    let public_bytes = pk.into_bytes();

    derive_wallet_id_from_pubkey_bytes(&public_bytes)
}

fn assert_secret_hex_shape(secret_hex: &str) {
    assert_eq!(secret_hex.len(), ml_dsa_65::SK_LEN.saturating_mul(2));
    assert!(
        secret_hex
            .as_bytes()
            .iter()
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

fn write_tmp_then_rename_wallet(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let tmp = wallet_tmp_file_path(directory, &wallet.address);
    let final_path = wallet_file_path(directory, &wallet.address);

    if tmp.exists() {
        assert_ok(fs::remove_file(&tmp), "remove stale tmp wallet");
    }

    assert_ok(
        fs::write(&tmp, &wallet.encrypted_secret),
        "write tmp wallet",
    );
    assert_ok(fs::rename(&tmp, &final_path), "rename tmp wallet");

    final_path
}

fn write_temp_secret_file(dir: &Path, secret_hex: &str) -> PathBuf {
    let path = dir.join(format!("decrypted_{}.txt", Uuid::new_v4()));
    let mut file = assert_ok(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path),
        "create temp secret file",
    );
    assert_ok(
        file.write_all(secret_hex.as_bytes()),
        "write temp secret file",
    );
    assert_ok(file.flush(), "flush temp secret file");
    path
}

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S13WalletUtilities::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S13WalletUtilities;
}

#[test]
fn test_03_unit_struct_constructor_creates_section() {
    let _section = S13WalletUtilities;
}

#[test]
fn test_04_wallet_from_label_has_expected_shape() {
    let wallet = wallet_from_label("test_04");

    assert_wallet_shape(&wallet);
}

#[test]
fn test_05_primary_fixture_wallet_has_expected_shape() {
    let fixture = primary_fixture();

    assert_wallet_shape(&fixture.address);
}

#[test]
fn test_06_secondary_fixture_wallet_has_expected_shape() {
    let fixture = secondary_fixture();

    assert_wallet_shape(&fixture.address);
}

#[test]
fn test_07_canon_wallet_accepts_generated_address() {
    let fixture = primary_fixture();
    let canonical = assert_ok(
        canon_wallet_id_checked(&fixture.address),
        "canon generated wallet",
    );

    assert_eq!(canonical, fixture.address);
}

#[test]
fn test_08_canon_wallet_accepts_uppercase_address() {
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

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong prefix wallet");

    assert_validation_error(err);
}

#[test]
fn test_13_canon_wallet_rejects_non_hex_body() {
    let mut wallet = wallet_from_label("test_13");
    wallet.replace_range(1..2, "g");

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon non-hex wallet");

    assert_validation_error(err);
}

#[test]
fn test_14_canon_wallet_rejects_too_long() {
    let mut wallet = wallet_from_label("test_14");
    wallet.push('0');

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon too-long wallet");

    assert_validation_error(err);
}

#[test]
fn test_15_wallet_validate_address_format_accepts_generated() {
    let fixture = primary_fixture();

    assert_ok(
        MLDSA65Wallet::validate_address_format(&fixture.address),
        "validate generated address",
    );
}

#[test]
fn test_16_wallet_validate_address_format_accepts_uppercase() {
    let fixture = primary_fixture();

    assert_ok(
        MLDSA65Wallet::validate_address_format(&fixture.address.to_ascii_uppercase()),
        "validate uppercase address",
    );
}

#[test]
fn test_17_wallet_validate_address_format_rejects_short() {
    let err = assert_err(
        MLDSA65Wallet::validate_address_format("r1234"),
        "validate short address",
    );

    assert_validation_error(err);
}

#[test]
fn test_18_primary_wallet_matches_public_key() {
    let fixture = primary_fixture();

    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&fixture.address, &fixture.public),
        "primary wallet matches public key",
    );
}

#[test]
fn test_19_primary_wallet_rejects_secondary_public_key() {
    let primary = primary_fixture();
    let secondary = secondary_fixture();

    let err = assert_err(
        wallet_id_matches_pubkey_bytes_checked(&primary.address, &secondary.public),
        "primary wallet should reject secondary public key",
    );

    assert_validation_error(err);
}

#[test]
fn test_20_derive_wallet_id_from_public_key_matches_wallet_address() {
    let fixture = primary_fixture();
    let derived = derive_wallet_id_from_pubkey_bytes(&fixture.public);

    assert_eq!(derived, fixture.address);
}

#[test]
fn test_21_address_from_secret_bytes_matches_wallet_address() {
    let fixture = primary_fixture();
    let recovered = assert_ok(
        MLDSA65Wallet::address_from_secret_bytes(&fixture.secret),
        "address_from_secret_bytes",
    );

    assert_eq!(recovered, fixture.address);
}

#[test]
fn test_22_address_from_secret_bytes_rejects_empty_secret() {
    let err = assert_err(
        MLDSA65Wallet::address_from_secret_bytes(&[]),
        "address_from_secret_bytes empty",
    );

    assert_validation_error(err);
}

#[test]
fn test_23_address_from_secret_bytes_rejects_short_secret() {
    let secret = vec![0_u8; 32];

    let err = assert_err(
        MLDSA65Wallet::address_from_secret_bytes(&secret),
        "address_from_secret_bytes short",
    );

    assert_validation_error(err);
}

#[test]
fn test_24_secret_key_hex_has_expected_shape() {
    let fixture = primary_fixture();
    let wallet = MLDSA65Wallet {
        public: fixture.public,
        address: fixture.address,
        encrypted_secret: fixture.encrypted_secret,
    };

    let secret_hex = assert_ok(wallet.secret_key_hex(fixture.passphrase), "secret_key_hex");

    assert_secret_hex_shape(&secret_hex);
}

#[test]
fn test_25_secret_key_hex_decodes_to_secret_length() {
    let fixture = primary_fixture();
    let wallet = MLDSA65Wallet {
        public: fixture.public,
        address: fixture.address,
        encrypted_secret: fixture.encrypted_secret,
    };

    let secret_hex = assert_ok(wallet.secret_key_hex(fixture.passphrase), "secret_key_hex");
    let bytes = assert_ok(hex::decode(secret_hex), "decode secret hex");

    assert_eq!(bytes.len(), ml_dsa_65::SK_LEN);
}

#[test]
fn test_26_secret_key_hex_wrong_passphrase_rejects() {
    let fixture = primary_fixture();
    let wallet = MLDSA65Wallet {
        public: fixture.public,
        address: fixture.address,
        encrypted_secret: fixture.encrypted_secret,
    };

    let err = assert_err(
        wallet.secret_key_hex("wrong passphrase"),
        "secret_key_hex wrong",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_27_decrypt_wallet_secret_to_hex_like_s13_accepts_wallet_file() {
    let temp = TempTree::new("test_27");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);

    let secret_hex = assert_ok(
        decrypt_wallet_secret_to_hex_like_s13(&path, fixture.passphrase),
        "decrypt wallet secret to hex",
    );

    assert_secret_hex_shape(&secret_hex);
}

#[test]
fn test_28_decrypt_wallet_secret_to_hex_like_s13_recovers_address() {
    let temp = TempTree::new("test_28");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);

    let secret_hex = assert_ok(
        decrypt_wallet_secret_to_hex_like_s13(&path, fixture.passphrase),
        "decrypt wallet secret to hex",
    );
    let bytes = assert_ok(hex::decode(secret_hex), "decode secret hex");
    let recovered = assert_ok(
        MLDSA65Wallet::address_from_secret_bytes(&bytes),
        "address_from_secret_bytes",
    );

    assert_eq!(recovered, fixture.address);
}

#[test]
fn test_29_decrypt_wallet_secret_to_hex_like_s13_rejects_wrong_passphrase() {
    let temp = TempTree::new("test_29");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);

    let err = assert_err(
        decrypt_wallet_secret_to_hex_like_s13(&path, "wrong passphrase"),
        "decrypt with wrong passphrase",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_30_decrypt_wallet_secret_to_hex_like_s13_rejects_missing_file() {
    let temp = TempTree::new("test_30");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let path = wallet_file_path(&directory, &primary_fixture().address);

    let err = assert_err(
        decrypt_wallet_secret_to_hex_like_s13(&path, primary_fixture().passphrase),
        "decrypt missing wallet file",
    );

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_31_decrypt_wallet_secret_to_hex_like_s13_rejects_tampered_file() {
    let temp = TempTree::new("test_31");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = assert_ok(fs::read(&path), "read wallet file");

    match bytes.first_mut() {
        Some(byte) => {
            *byte ^= 0xAA;
        }
        None => panic!("wallet file unexpectedly empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet file");

    let err = assert_err(
        decrypt_wallet_secret_to_hex_like_s13(&path, fixture.passphrase),
        "decrypt tampered file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_32_validate_wallet_file_like_s13_accepts_real_wallet_file() {
    let temp = TempTree::new("test_32");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let path = write_fixture_wallet_file(&directory, &primary_fixture());

    assert_ok(
        validate_wallet_file_like_s13(&path, 512 * 1024),
        "validate wallet file",
    );
}

#[test]
fn test_33_validate_wallet_file_like_s13_rejects_missing_file() {
    let temp = TempTree::new("test_33");
    let path = temp.child("missing.wallet");

    let err = assert_err(
        validate_wallet_file_like_s13(&path, 512 * 1024),
        "validate missing wallet file",
    );

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_34_validate_wallet_file_like_s13_rejects_directory() {
    let temp = TempTree::new("test_34");
    let dir = temp.child("wallet_dir");

    assert_ok(fs::create_dir_all(&dir), "create directory");

    let err = assert_err(
        validate_wallet_file_like_s13(&dir, 512 * 1024),
        "validate directory as wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_35_validate_wallet_file_like_s13_rejects_empty_file() {
    let temp = TempTree::new("test_35");
    let path = temp.child("empty.wallet");

    assert_ok(fs::write(&path, b""), "write empty file");

    let err = assert_err(
        validate_wallet_file_like_s13(&path, 512 * 1024),
        "validate empty wallet file",
    );

    assert_validation_error(err);
}

#[test]
fn test_36_validate_wallet_file_like_s13_rejects_too_large_file() {
    let temp = TempTree::new("test_36");
    let path = temp.child("large.wallet");

    assert_ok(fs::write(&path, vec![1_u8; 65]), "write large file");

    let err = assert_err(
        validate_wallet_file_like_s13(&path, 64),
        "validate too-large wallet file",
    );

    assert_validation_error(err);
}

#[test]
fn test_37_recover_address_from_secret_hex_like_s13_accepts_secret_hex() {
    let fixture = primary_fixture();
    let secret_hex = hex::encode(&fixture.secret);
    let recovered = assert_ok(
        recover_address_from_secret_hex_like_s13(&secret_hex),
        "recover address from secret hex",
    );

    assert_eq!(recovered, fixture.address);
}

#[test]
fn test_38_recover_address_from_secret_hex_like_s13_accepts_uppercase_hex() {
    let fixture = primary_fixture();
    let secret_hex = hex::encode(&fixture.secret).to_ascii_uppercase();
    let recovered = assert_ok(
        recover_address_from_secret_hex_like_s13(&secret_hex),
        "recover address from uppercase secret hex",
    );

    assert_eq!(recovered, fixture.address);
}

#[test]
fn test_39_recover_address_from_secret_hex_like_s13_accepts_outer_whitespace() {
    let fixture = primary_fixture();
    let secret_hex = format!("  {}  ", hex::encode(&fixture.secret));
    let recovered = assert_ok(
        recover_address_from_secret_hex_like_s13(&secret_hex),
        "recover address from padded secret hex",
    );

    assert_eq!(recovered, fixture.address);
}

#[test]
fn test_40_recover_address_from_secret_hex_like_s13_rejects_empty() {
    let err = assert_err(
        recover_address_from_secret_hex_like_s13(""),
        "recover empty secret hex",
    );

    assert_validation_error(err);
}

#[test]
fn test_41_recover_address_from_secret_hex_like_s13_rejects_short() {
    let err = assert_err(
        recover_address_from_secret_hex_like_s13("abcd"),
        "recover short secret hex",
    );

    assert_validation_error(err);
}

#[test]
fn test_42_recover_address_from_secret_hex_like_s13_rejects_non_hex() {
    let mut secret_hex = hex::encode(&primary_fixture().secret);
    secret_hex.replace_range(0..1, "g");

    let err = assert_err(
        recover_address_from_secret_hex_like_s13(&secret_hex),
        "recover non-hex secret",
    );

    assert_validation_error(err);
}

#[test]
fn test_43_recover_address_from_secret_hex_like_s13_rejects_too_long() {
    let mut secret_hex = hex::encode(&primary_fixture().secret);
    secret_hex.push('0');

    let err = assert_err(
        recover_address_from_secret_hex_like_s13(&secret_hex),
        "recover too-long secret",
    );

    assert_validation_error(err);
}

#[test]
fn test_44_public_key_hex_has_expected_shape() {
    let wallet = make_wallet("test_44_passphrase");
    let public_hex = wallet.public_key_hex();

    assert_eq!(public_hex.len(), ml_dsa_65::PK_LEN.saturating_mul(2));
    assert!(
        public_hex
            .as_bytes()
            .iter()
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

#[test]
fn test_45_public_key_hex_decodes_to_public_len() {
    let wallet = make_wallet("test_45_passphrase");
    let public_hex = wallet.public_key_hex();
    let public_bytes = assert_ok(hex::decode(public_hex), "decode public hex");

    assert_eq!(public_bytes.len(), ml_dsa_65::PK_LEN);
}

#[test]
fn test_46_sign_and_verify_message_succeeds() {
    let passphrase = "test_46_passphrase";
    let wallet = make_wallet(passphrase);
    let message = deterministic_message(46, 64);
    let signature = assert_ok(wallet.sign(passphrase, &message), "wallet sign");

    assert!(wallet.verify(&message, &signature));
}

#[test]
fn test_47_sign_rejects_wrong_passphrase() {
    let wallet = make_wallet("test_47_passphrase");
    let message = deterministic_message(47, 64);

    let err = assert_err(wallet.sign("wrong", &message), "sign wrong passphrase");

    assert_decrypt_like_error(err);
}

#[test]
fn test_48_verify_rejects_mutated_message() {
    let passphrase = "test_48_passphrase";
    let wallet = make_wallet(passphrase);
    let message = deterministic_message(48, 64);
    let mut mutated = message.clone();
    let signature = assert_ok(wallet.sign(passphrase, &message), "wallet sign");

    match mutated.first_mut() {
        Some(byte) => {
            *byte ^= 0x01;
        }
        None => panic!("message unexpectedly empty"),
    }

    assert!(!wallet.verify(&mutated, &signature));
}

#[test]
fn test_49_verify_rejects_mutated_signature() {
    let passphrase = "test_49_passphrase";
    let wallet = make_wallet(passphrase);
    let message = deterministic_message(49, 64);
    let mut signature = assert_ok(wallet.sign(passphrase, &message), "wallet sign");

    match signature.first_mut() {
        Some(byte) => {
            *byte ^= 0x01;
        }
        None => panic!("signature unexpectedly empty"),
    }

    assert!(!wallet.verify(&message, &signature));
}

#[test]
fn test_50_verify_rejects_short_signature() {
    let passphrase = "test_50_passphrase";
    let wallet = make_wallet(passphrase);
    let message = deterministic_message(50, 64);
    let mut signature = assert_ok(wallet.sign(passphrase, &message), "wallet sign");

    signature.pop();

    assert!(!wallet.verify(&message, &signature));
}

#[test]
fn test_51_verify_rejects_long_signature() {
    let passphrase = "test_51_passphrase";
    let wallet = make_wallet(passphrase);
    let message = deterministic_message(51, 64);
    let mut signature = assert_ok(wallet.sign(passphrase, &message), "wallet sign");

    signature.push(0);

    assert!(!wallet.verify(&message, &signature));
}

#[test]
fn test_52_signature_length_matches_mldsa65_constant() {
    let passphrase = "test_52_passphrase";
    let wallet = make_wallet(passphrase);
    let message = deterministic_message(52, 64);
    let signature = assert_ok(wallet.sign(passphrase, &message), "wallet sign");

    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
}

#[test]
fn test_53_wallet_from_parts_reconstructs_valid_wallet() {
    let fixture = primary_fixture();
    let wallet = assert_ok(
        MLDSA65Wallet::from_parts(fixture.public, fixture.encrypted_secret),
        "MLDSA65Wallet::from_parts",
    );

    assert_eq!(wallet.address, fixture.address);
    assert_wallet_valid(&wallet);
}

#[test]
fn test_54_wallet_from_parts_rejects_empty_encrypted_secret() {
    let fixture = primary_fixture();
    let err = assert_err(
        MLDSA65Wallet::from_parts(fixture.public, Vec::new()),
        "from_parts empty encrypted secret",
    );

    assert_validation_error(err);
}

#[test]
fn test_55_wallet_from_parts_rejects_short_encrypted_secret() {
    let fixture = primary_fixture();
    let err = assert_err(
        MLDSA65Wallet::from_parts(fixture.public, vec![1_u8; 4]),
        "from_parts short encrypted secret",
    );

    assert_validation_error(err);
}

#[test]
fn test_56_wallet_validate_self_accepts_real_wallet() {
    let wallet = make_wallet("test_56_passphrase");

    assert_ok(wallet.validate_self(), "validate_self");
}

#[test]
fn test_57_wallet_validate_self_rejects_tampered_address_prefix() {
    let mut wallet = make_wallet("test_57_passphrase");
    wallet.address.replace_range(0..1, "x");

    let err = assert_err(wallet.validate_self(), "validate tampered prefix");

    assert_validation_error(err);
}

#[test]
fn test_58_wallet_validate_self_rejects_tampered_address_body_nonhex() {
    let mut wallet = make_wallet("test_58_passphrase");
    wallet.address.replace_range(1..2, "g");

    let err = assert_err(wallet.validate_self(), "validate tampered body nonhex");

    assert_validation_error(err);
}

#[test]
fn test_59_wallet_validate_self_rejects_tampered_public_key() {
    let mut wallet = make_wallet("test_59_passphrase");
    wallet.public[0] ^= 0x01;

    let err = assert_err(wallet.validate_self(), "validate tampered public key");

    assert_validation_error(err);
}

#[test]
fn test_60_wallet_secret_key_hex_wrong_wallet_binding_rejected_by_from_parts_sign() {
    let first = primary_fixture();
    let second = secondary_fixture();

    let wallet = assert_ok(
        MLDSA65Wallet::from_parts(first.public, second.encrypted_secret),
        "from_parts mismatched encrypted secret still has valid structure",
    );

    let err = assert_err(
        wallet.secret_key_hex(second.passphrase),
        "secret_key_hex mismatched secret",
    );

    assert_validation_error(err);
}

#[test]
fn test_61_wallet_file_path_uses_wallet_address() {
    let temp = TempTree::new("test_61");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = wallet_file_path(&directory, &fixture.address);

    assert!(path.ends_with(format!("{}.wallet", fixture.address)));
}

#[test]
fn test_62_wallet_tmp_file_path_uses_tmp_suffix() {
    let temp = TempTree::new("test_62");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = wallet_tmp_file_path(&directory, &fixture.address);

    assert!(path.ends_with(format!("{}.wallet.tmp", fixture.address)));
}

#[test]
fn test_63_write_wallet_file_round_trips_encrypted_secret() {
    let temp = TempTree::new("test_63");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);

    assert_wallet_file_contains(&path, &fixture.encrypted_secret);
}

#[test]
fn test_64_write_wallet_file_creates_wallets_directory() {
    let temp = TempTree::new("test_64");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();

    assert!(!directory.wallets_path.exists());

    let _path = write_fixture_wallet_file(&directory, &fixture);

    assert!(directory.wallets_path.exists());
    assert!(directory.wallets_path.is_dir());
}

#[test]
fn test_65_tmp_then_rename_wallet_removes_tmp_and_keeps_final() {
    let temp = TempTree::new("test_65");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_65_passphrase");

    let tmp = wallet_tmp_file_path(&directory, &wallet.address);
    let final_path = write_tmp_then_rename_wallet(&directory, &wallet);

    assert!(!tmp.exists());
    assert!(final_path.exists());
    assert_wallet_file_contains(&final_path, &wallet.encrypted_secret);
}

#[test]
fn test_66_stale_tmp_file_is_removed_before_rename_flow() {
    let temp = TempTree::new("test_66");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_66_passphrase");

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let tmp = wallet_tmp_file_path(&directory, &wallet.address);
    assert_ok(fs::write(&tmp, b"stale"), "write stale tmp");

    let final_path = write_tmp_then_rename_wallet(&directory, &wallet);

    assert!(!tmp.exists());
    assert!(final_path.exists());
}

#[test]
fn test_67_temp_secret_file_write_and_delete() {
    let temp = TempTree::new("test_67");
    let secret_hex = hex::encode(&primary_fixture().secret);
    let path = write_temp_secret_file(&temp.root, &secret_hex);

    assert!(path.exists());
    assert_eq!(
        assert_ok(fs::read_to_string(&path), "read temp secret file"),
        secret_hex
    );

    assert_ok(fs::remove_file(&path), "remove temp secret file");
    assert!(!path.exists());
}

#[test]
fn test_68_temp_secret_file_unique_names() {
    let temp = TempTree::new("test_68");
    let secret_hex = hex::encode(&primary_fixture().secret);
    let first = write_temp_secret_file(&temp.root, &secret_hex);
    let second = write_temp_secret_file(&temp.root, &secret_hex);

    assert_ne!(first, second);
}

#[test]
fn test_69_logger_accepts_wallet_menu_event() {
    let temp = TempTree::new("test_69");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("wallet", "WalletMenuOpened", "Wallet menu opened"),
        "log wallet menu event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_70_logger_accepts_address_mismatch_event() {
    let temp = TempTree::new("test_70");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event(
            "wallet",
            "WalletUtilsAddressMismatch",
            &primary_fixture().address,
        ),
        "log address mismatch event",
    );
    assert_ok(logger.flush(), "flush logger");
}

#[test]
fn test_71_logger_accepts_unicode_wallet_message() {
    let temp = TempTree::new("test_71");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("wallet", "WalletUnicode", "wallet 測試 🔐"),
        "log unicode wallet event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_72_vector_canonicalize_common_wallet_inputs() {
    for label in ["alpha", "beta", "gamma", "delta", "epsilon"] {
        let wallet = wallet_from_label(label);
        let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon vector wallet");
        assert_eq!(canonical, wallet);
    }
}

#[test]
fn test_73_vector_reject_invalid_wallet_inputs() {
    for input in ["", "r", "r1234", "x1234", "not-a-wallet"] {
        let err = assert_err(
            canon_wallet_id_checked(input),
            "reject invalid vector wallet",
        );
        assert_validation_error(err);
    }
}

#[test]
fn test_74_vector_secret_export_round_trip_three_wallets() {
    for index in 0usize..3usize {
        let passphrase = format!("test_74_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let secret_hex = assert_ok(wallet.secret_key_hex(&passphrase), "secret_key_hex");
        let recovered = assert_ok(
            recover_address_from_secret_hex_like_s13(&secret_hex),
            "recover address from vector secret",
        );

        assert_eq!(recovered, wallet.address);
    }
}

#[test]
fn test_75_vector_sign_verify_six_messages() {
    let passphrase = "test_75_passphrase";
    let wallet = make_wallet(passphrase);

    for index in 0usize..6usize {
        let message = deterministic_message(index, index.saturating_add(1));
        let signature = assert_ok(wallet.sign(passphrase, &message), "sign vector message");
        assert!(wallet.verify(&message, &signature));
    }
}

#[test]
fn test_76_vector_signature_rejects_wrong_message_for_six_messages() {
    let passphrase = "test_76_passphrase";
    let wallet = make_wallet(passphrase);

    for index in 0usize..6usize {
        let message = deterministic_message(index, 32);
        let wrong = deterministic_message(index.saturating_add(99), 32);
        let signature = assert_ok(wallet.sign(passphrase, &message), "sign vector message");

        assert!(!wallet.verify(&wrong, &signature));
    }
}

#[test]
fn test_77_vector_decrypt_wallet_files_three_times() {
    let temp = TempTree::new("test_77");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..3usize {
        let passphrase = format!("test_77_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);
        let secret_hex = assert_ok(
            decrypt_wallet_secret_to_hex_like_s13(&path, &passphrase),
            "decrypt vector wallet file",
        );

        assert_secret_hex_shape(&secret_hex);
    }
}

#[test]
fn test_78_vector_wrong_passphrases_reject_three_wallet_files() {
    let temp = TempTree::new("test_78");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..3usize {
        let passphrase = format!("test_78_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        let err = assert_err(
            decrypt_wallet_secret_to_hex_like_s13(&path, "wrong-passphrase"),
            "decrypt wrong vector wallet file",
        );

        assert_decrypt_like_error(err);
    }
}

#[test]
fn test_79_wallets_directory_with_spaces_accepts_wallet_file() {
    let temp = TempTree::new("test_79");
    let opts = make_node_opts(&temp.child("node with spaces"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_79_passphrase");

    let path = write_wallet_file(&directory, &wallet);

    assert!(path.exists());
    assert_wallet_file_contains(&path, &wallet.encrypted_secret);
}

#[test]
fn test_80_wallets_directory_with_unicode_accepts_wallet_file() {
    let temp = TempTree::new("test_80");
    let opts = make_node_opts(&temp.child("node_測試_wallet"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_80_passphrase");

    let path = write_wallet_file(&directory, &wallet);

    assert!(path.exists());
    assert_wallet_file_contains(&path, &wallet.encrypted_secret);
}

#[test]
fn test_81_edge_long_passphrase_wallet_exports_secret() {
    let passphrase = "long-passphrase-".repeat(32);
    let wallet = make_wallet(&passphrase);
    let secret_hex = assert_ok(
        wallet.secret_key_hex(&passphrase),
        "secret_key_hex long passphrase",
    );

    assert_secret_hex_shape(&secret_hex);
}

#[test]
fn test_82_edge_unicode_passphrase_wallet_exports_secret() {
    let passphrase = "密碼 кошелек 🔐";
    let wallet = make_wallet(passphrase);
    let secret_hex = assert_ok(
        wallet.secret_key_hex(passphrase),
        "secret_key_hex unicode passphrase",
    );

    assert_secret_hex_shape(&secret_hex);
}

#[test]
fn test_83_edge_private_key_hex_length_constant_matches_mldsa_secret_len() {
    assert_eq!(
        GlobalConfiguration::MLDSA65_SECRET_HEX_LEN,
        ml_dsa_65::SK_LEN.saturating_mul(2)
    );
}

#[test]
fn test_84_edge_private_key_max_input_is_at_least_secret_hex_len() {
    const {
        assert!(
            GlobalConfiguration::MAX_PRIVKEY_HEX_INPUT_LEN
                >= GlobalConfiguration::MLDSA65_SECRET_HEX_LEN
        );
    }
}

#[test]
fn test_85_edge_recover_rejects_odd_length_hex() {
    let mut secret_hex = hex::encode(&primary_fixture().secret);
    secret_hex.pop();

    let err = assert_err(
        recover_address_from_secret_hex_like_s13(&secret_hex),
        "recover odd length hex",
    );

    assert_validation_error(err);
}

#[test]
fn test_86_adversarial_tamper_wallet_file_first_byte_rejects() {
    let temp = TempTree::new("test_86");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = assert_ok(fs::read(&path), "read wallet file");

    match bytes.first_mut() {
        Some(byte) => {
            *byte ^= 0x11;
        }
        None => panic!("wallet file unexpectedly empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered file");

    let err = assert_err(
        decrypt_wallet_secret_to_hex_like_s13(&path, fixture.passphrase),
        "decrypt first-byte tampered wallet",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_87_adversarial_tamper_wallet_file_middle_byte_rejects() {
    let temp = TempTree::new("test_87");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = assert_ok(fs::read(&path), "read wallet file");
    let middle = bytes.len() / 2;

    match bytes.get_mut(middle) {
        Some(byte) => {
            *byte ^= 0x22;
        }
        None => panic!("wallet file missing middle byte"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered file");

    let err = assert_err(
        decrypt_wallet_secret_to_hex_like_s13(&path, fixture.passphrase),
        "decrypt middle-byte tampered wallet",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_88_adversarial_tamper_wallet_file_last_byte_rejects() {
    let temp = TempTree::new("test_88");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&directory, &fixture);
    let mut bytes = assert_ok(fs::read(&path), "read wallet file");

    match bytes.last_mut() {
        Some(byte) => {
            *byte ^= 0x44;
        }
        None => panic!("wallet file unexpectedly empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered file");

    let err = assert_err(
        decrypt_wallet_secret_to_hex_like_s13(&path, fixture.passphrase),
        "decrypt last-byte tampered wallet",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_89_adversarial_random_wallet_file_bytes_reject() {
    let temp = TempTree::new("test_89");
    let path = temp.child("random.wallet");

    assert_ok(
        fs::write(&path, vec![0xAB_u8; 256]),
        "write random wallet file",
    );

    let err = assert_err(
        decrypt_wallet_secret_to_hex_like_s13(&path, "test_89_passphrase"),
        "decrypt random wallet file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_90_adversarial_cross_wallet_secret_hex_recovers_different_address() {
    let first = primary_fixture();
    let second = secondary_fixture();
    let second_secret_hex = hex::encode(&second.secret);
    let recovered = assert_ok(
        recover_address_from_secret_hex_like_s13(&second_secret_hex),
        "recover second wallet address",
    );

    assert_ne!(recovered, first.address);
    assert_eq!(recovered, second.address);
}

#[test]
fn test_91_load_generate_five_wallets_validate_all() {
    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_91_passphrase_{index}"));
        assert_wallet_valid(&wallet);
    }
}

#[test]
fn test_92_load_export_five_wallet_secrets() {
    for index in 0usize..5usize {
        let passphrase = format!("test_92_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let secret_hex = assert_ok(wallet.secret_key_hex(&passphrase), "export load secret");
        assert_secret_hex_shape(&secret_hex);
    }
}

#[test]
fn test_93_load_recover_five_wallet_addresses_from_secret_hex() {
    for index in 0usize..5usize {
        let passphrase = format!("test_93_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let secret_hex = assert_ok(wallet.secret_key_hex(&passphrase), "secret_key_hex");
        let recovered = assert_ok(
            recover_address_from_secret_hex_like_s13(&secret_hex),
            "recover load address",
        );

        assert_eq!(recovered, wallet.address);
    }
}

#[test]
fn test_94_load_sign_verify_ten_messages() {
    let passphrase = "test_94_passphrase";
    let wallet = make_wallet(passphrase);

    for index in 0usize..10usize {
        let message = deterministic_message(index.saturating_add(94), 24);
        let signature = assert_ok(wallet.sign(passphrase, &message), "sign load message");
        assert!(wallet.verify(&message, &signature));
    }
}

#[test]
fn test_95_load_write_five_wallet_files() {
    let temp = TempTree::new("test_95");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_95_passphrase_{index}"));
        let path = write_wallet_file(&directory, &wallet);
        assert!(path.exists());
        assert_wallet_file_contains(&path, &wallet.encrypted_secret);
    }
}

#[test]
fn test_96_load_wallet_paths_are_unique() {
    let temp = TempTree::new("test_96");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let mut paths = Vec::new();

    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_96_passphrase_{index}"));
        paths.push(wallet_file_path(&directory, &wallet.address));
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
fn test_97_load_logger_many_wallet_events() {
    let temp = TempTree::new("test_97");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    for index in 0usize..20usize {
        assert_ok(
            logger.log_error_event("wallet", "LoadWalletUtilities", &format!("event {index}")),
            "log load wallet event",
        );
    }

    assert_ok(logger.flush_logs_cf(), "flush load logger");
}

#[test]
fn test_98_property_derived_address_from_secret_is_stable() {
    let fixture = primary_fixture();

    let first = derive_address_from_secret_bytes(&fixture.secret);
    let second = derive_address_from_secret_bytes(&fixture.secret);

    assert_eq!(first, second);
    assert_eq!(first, fixture.address);
}

#[test]
fn test_99_property_encrypted_secret_is_not_plain_secret() {
    let fixture = primary_fixture();

    assert_ne!(
        fixture.encrypted_secret.as_slice(),
        fixture.secret.as_slice()
    );
}

#[test]
fn test_100_final_wallet_utilities_secret_export_recover_file_temp_and_log_flow() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let logger = make_logger(&opts);
    let passphrase = "test_100_passphrase";
    let wallet = make_wallet(passphrase);

    assert_wallet_valid(&wallet);

    let wallet_file = write_wallet_file(&directory, &wallet);
    assert_ok(
        validate_wallet_file_like_s13(&wallet_file, 512 * 1024),
        "final validate wallet file",
    );

    let secret_hex = assert_ok(
        decrypt_wallet_secret_to_hex_like_s13(&wallet_file, passphrase),
        "final decrypt wallet secret",
    );
    assert_secret_hex_shape(&secret_hex);

    let recovered = assert_ok(
        recover_address_from_secret_hex_like_s13(&secret_hex),
        "final recover address",
    );
    assert_eq!(recovered, wallet.address);

    let temp_secret = write_temp_secret_file(&temp.root, &secret_hex);
    assert!(temp_secret.exists());
    assert_eq!(
        assert_ok(fs::read_to_string(&temp_secret), "final read temp secret"),
        secret_hex
    );
    assert_ok(fs::remove_file(&temp_secret), "final remove temp secret");
    assert!(!temp_secret.exists());

    let message = deterministic_message(100, 64);
    let signature = assert_ok(wallet.sign(passphrase, &message), "final sign");
    assert!(wallet.verify(&message, &signature));

    assert_ok(
        logger.log_error_event("wallet", "FinalWalletUtilitiesTest", &wallet.address),
        "final log wallet utilities event",
    );
    assert_ok(logger.flush_logs_cf(), "final flush logs");
}
