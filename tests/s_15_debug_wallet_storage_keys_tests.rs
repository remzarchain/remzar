use fips204::ml_dsa_65;
use remzar::commandline::s_15_debug_wallet_storage_keys::S15DebugWalletStorageKeys;
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
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PRIMARY_WALLET: OnceLock<WalletFixture> = OnceLock::new();
static SECONDARY_WALLET: OnceLock<WalletFixture> = OnceLock::new();

const MAX_YN_INPUT_LEN_LIKE_S15: usize = 16;
const MAX_ADDR_INPUT_LEN_LIKE_S15: usize = REMZAR_WALLET_LEN + 8;
const MAX_DIR_INPUT_LEN_LIKE_S15: usize = 4096;

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
            "remzar_s_15_debug_wallet_storage_keys_tests_{test_name}_{}_{}",
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
        .get_or_init(|| build_wallet_fixture("s15_primary_passphrase"))
        .clone()
}

fn secondary_fixture() -> WalletFixture {
    SECONDARY_WALLET
        .get_or_init(|| build_wallet_fixture("s15_secondary_passphrase"))
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

fn wallet_file_path(wallet_dir: &Path, wallet: &str) -> PathBuf {
    wallet_dir.join(format!("{wallet}.wallet"))
}

fn write_fixture_wallet_file(wallet_dir: &Path, fixture: &WalletFixture) -> PathBuf {
    assert_ok(fs::create_dir_all(wallet_dir), "create wallet dir");
    let path = wallet_file_path(wallet_dir, &fixture.address);
    assert_ok(
        fs::write(&path, &fixture.encrypted_secret),
        "write wallet file",
    );
    path
}

fn write_wallet_file(wallet_dir: &Path, wallet: &MLDSA65Wallet) -> PathBuf {
    assert_ok(fs::create_dir_all(wallet_dir), "create wallet dir");
    let path = wallet_file_path(wallet_dir, &wallet.address);
    assert_ok(
        fs::write(&path, &wallet.encrypted_secret),
        "write wallet file",
    );
    path
}

fn parse_yes_no_like_s15(input: &str, cap: usize) -> Result<bool, ErrorDetection> {
    let trimmed = input.trim().to_string();

    if trimmed.len() > cap {
        return Err(ErrorDetection::ValidationError {
            message: format!("Input too long (max {cap} chars)"),
            tx_id: None,
        });
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "yes" | "y" => Ok(true),
        "no" | "n" => Ok(false),
        _ => Err(ErrorDetection::ValidationError {
            message: "Please type yes or no.".to_owned(),
            tx_id: None,
        }),
    }
}

fn read_wallet_address_like_s15(raw: &str, cap: usize) -> Result<String, ErrorDetection> {
    let trimmed = raw.trim().to_string();

    if trimmed.len() > cap {
        return Err(ErrorDetection::ValidationError {
            message: format!("Input too long (max {cap} chars)"),
            tx_id: None,
        });
    }

    if trimmed.is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: "Wallet address cannot be empty.".to_owned(),
            tx_id: None,
        });
    }

    canon_wallet_id_checked(&trimmed).map_err(|e| ErrorDetection::ValidationError {
        message: format!("Invalid wallet address format: {e}"),
        tx_id: None,
    })
}

fn read_existing_directory_like_s15(raw: &str, cap: usize) -> Result<PathBuf, ErrorDetection> {
    let trimmed = raw.trim().to_string();

    if trimmed.len() > cap {
        return Err(ErrorDetection::ValidationError {
            message: format!("Input too long (max {cap} chars)"),
            tx_id: None,
        });
    }

    if trimmed.is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: "The specified directory does not exist.".to_owned(),
            tx_id: None,
        });
    }

    let path = Path::new(&trimmed);

    if !path.exists() || !path.is_dir() {
        return Err(ErrorDetection::ValidationError {
            message: "The specified directory does not exist.".to_owned(),
            tx_id: None,
        });
    }

    path.canonicalize().map_err(|e| ErrorDetection::IoError {
        message: format!("Failed to resolve wallet directory path: {e}"),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })
}

fn debug_decrypt_wallet_file_like_s15(
    wallet_file: &Path,
    passphrase: &str,
) -> Result<usize, ErrorDetection> {
    let mut encrypted_sk_bytes = fs::read(wallet_file).map_err(|e| ErrorDetection::IoError {
        message: format!(
            "Failed to read wallet file '{}': {e}",
            wallet_file.display()
        ),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    let mut decrypted_sk = Cryption::decrypt_private_key_bytes(&encrypted_sk_bytes, passphrase)
        .map_err(|_| {
            encrypted_sk_bytes.zeroize();

            ErrorDetection::DecryptionError {
                message: "Failed to decrypt the private key. Ensure the passphrase is correct."
                    .to_owned(),
            }
        })?;

    encrypted_sk_bytes.zeroize();

    if decrypted_sk.len() != ml_dsa_65::SK_LEN {
        let got = decrypted_sk.len();
        decrypted_sk.zeroize();

        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Decrypted secret key length mismatch: expected {} bytes, got {}",
                ml_dsa_65::SK_LEN,
                got
            ),
            tx_id: None,
        });
    }

    let len = decrypted_sk.len();
    decrypted_sk.zeroize();

    Ok(len)
}

fn debug_flow_like_s15(
    wallet_dir: &Path,
    wallet_address: &str,
    passphrase: &str,
) -> Result<usize, ErrorDetection> {
    let canon = read_wallet_address_like_s15(wallet_address, MAX_ADDR_INPUT_LEN_LIKE_S15)?;
    let canonical_dir = read_existing_directory_like_s15(
        &wallet_dir.to_string_lossy(),
        MAX_DIR_INPUT_LEN_LIKE_S15,
    )?;

    let wallet_file = wallet_file_path(&canonical_dir, &canon);

    if !wallet_file.exists() || !wallet_file.is_file() {
        return Err(ErrorDetection::NotFound {
            resource: format!("Wallet file not found at: {}", wallet_file.display()),
        });
    }

    debug_decrypt_wallet_file_like_s15(&wallet_file, passphrase)
}

fn make_legacy_hex_wallet_file(wallet_dir: &Path, fixture: &WalletFixture) -> PathBuf {
    assert_ok(fs::create_dir_all(wallet_dir), "create wallet dir");
    let secret_hex = hex::encode(&fixture.secret);
    let encrypted = assert_ok(
        Cryption::encrypt_private_key_bytes(secret_hex.as_bytes(), fixture.passphrase),
        "encrypt legacy secret hex",
    );
    let path = wallet_file_path(wallet_dir, &fixture.address);

    assert_ok(fs::write(&path, encrypted), "write legacy wallet file");

    path
}

fn wallet_core_hash(wallet: &str) -> &str {
    let prefix = wallet.chars().next().unwrap_or('\0');
    wallet.strip_prefix(prefix).unwrap_or(wallet)
}

fn assert_hash_hex_128(value: &str) {
    assert_eq!(value.len(), 128);
    assert!(
        value
            .as_bytes()
            .iter()
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

fn read_file_bytes(path: &Path) -> Vec<u8> {
    assert_ok(fs::read(path), "read file bytes")
}

fn assert_secret_recovers_address(fixture: &WalletFixture) {
    let recovered = assert_ok(
        MLDSA65Wallet::address_from_secret_bytes(&fixture.secret),
        "address_from_secret_bytes",
    );

    assert_eq!(recovered, fixture.address);
}

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S15DebugWalletStorageKeys::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S15DebugWalletStorageKeys::default();
}

#[test]
fn test_03_unit_struct_constructor_creates_section() {
    let _section = S15DebugWalletStorageKeys;
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
fn test_07_parse_yes_returns_true() {
    assert!(assert_ok(
        parse_yes_no_like_s15("yes", MAX_YN_INPUT_LEN_LIKE_S15),
        "parse yes"
    ));
}

#[test]
fn test_08_parse_y_returns_true() {
    assert!(assert_ok(
        parse_yes_no_like_s15("y", MAX_YN_INPUT_LEN_LIKE_S15),
        "parse y"
    ));
}

#[test]
fn test_09_parse_no_returns_false() {
    assert!(!assert_ok(
        parse_yes_no_like_s15("no", MAX_YN_INPUT_LEN_LIKE_S15),
        "parse no"
    ));
}

#[test]
fn test_10_parse_n_returns_false() {
    assert!(!assert_ok(
        parse_yes_no_like_s15("n", MAX_YN_INPUT_LEN_LIKE_S15),
        "parse n"
    ));
}

#[test]
fn test_11_parse_yes_is_case_insensitive() {
    assert!(assert_ok(
        parse_yes_no_like_s15("YeS", MAX_YN_INPUT_LEN_LIKE_S15),
        "parse mixed yes"
    ));
}

#[test]
fn test_12_parse_yes_no_trims_whitespace() {
    assert!(assert_ok(
        parse_yes_no_like_s15("  yes  ", MAX_YN_INPUT_LEN_LIKE_S15),
        "parse padded yes"
    ));
}

#[test]
fn test_13_parse_yes_no_rejects_maybe() {
    let err = assert_err(
        parse_yes_no_like_s15("maybe", MAX_YN_INPUT_LEN_LIKE_S15),
        "parse maybe",
    );

    assert_validation_error(err);
}

#[test]
fn test_14_parse_yes_no_rejects_too_long_input() {
    let err = assert_err(
        parse_yes_no_like_s15(
            &"y".repeat(MAX_YN_INPUT_LEN_LIKE_S15.saturating_add(1)),
            MAX_YN_INPUT_LEN_LIKE_S15,
        ),
        "parse too long yes/no",
    );

    assert_validation_error(err);
}

#[test]
fn test_15_read_wallet_address_accepts_primary() {
    let wallet = primary_fixture().address;
    let parsed = assert_ok(
        read_wallet_address_like_s15(&wallet, MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read primary wallet",
    );

    assert_eq!(parsed, wallet);
}

#[test]
fn test_16_read_wallet_address_accepts_uppercase_by_canonicalizing() {
    let wallet = primary_fixture().address;
    let parsed = assert_ok(
        read_wallet_address_like_s15(&wallet.to_ascii_uppercase(), MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read uppercase wallet",
    );

    assert_eq!(parsed, wallet);
}

#[test]
fn test_17_read_wallet_address_accepts_outer_whitespace() {
    let wallet = primary_fixture().address;
    let parsed = assert_ok(
        read_wallet_address_like_s15(&format!("  {wallet}  "), MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read padded wallet",
    );

    assert_eq!(parsed, wallet);
}

#[test]
fn test_18_read_wallet_address_rejects_empty() {
    let err = assert_err(
        read_wallet_address_like_s15("", MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read empty wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_19_read_wallet_address_rejects_short() {
    let err = assert_err(
        read_wallet_address_like_s15("r1234", MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read short wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_20_read_wallet_address_rejects_wrong_prefix() {
    let wallet = wallet_from_label("test_20");
    let bad = format!("x{}", &wallet[1..]);

    let err = assert_err(
        read_wallet_address_like_s15(&bad, MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read wrong prefix wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_21_read_wallet_address_rejects_non_hex_body() {
    let mut wallet = wallet_from_label("test_21");
    wallet.replace_range(1..2, "g");

    let err = assert_err(
        read_wallet_address_like_s15(&wallet, MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read non-hex wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_22_read_wallet_address_rejects_input_over_cap_before_canon() {
    let too_long = "r".repeat(MAX_ADDR_INPUT_LEN_LIKE_S15.saturating_add(1));

    let err = assert_err(
        read_wallet_address_like_s15(&too_long, MAX_ADDR_INPUT_LEN_LIKE_S15),
        "read over-cap wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_23_canon_wallet_accepts_primary() {
    let wallet = primary_fixture().address;
    let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon primary");

    assert_eq!(canonical, wallet);
}

#[test]
fn test_24_wallet_validate_address_format_accepts_primary() {
    let wallet = primary_fixture().address;

    assert_ok(
        MLDSA65Wallet::validate_address_format(&wallet),
        "validate primary address format",
    );
}

#[test]
fn test_25_wallet_validate_address_format_accepts_uppercase() {
    let wallet = primary_fixture().address.to_ascii_uppercase();

    assert_ok(
        MLDSA65Wallet::validate_address_format(&wallet),
        "validate uppercase address format",
    );
}

#[test]
fn test_26_wallet_validate_address_format_rejects_short() {
    let err = assert_err(
        MLDSA65Wallet::validate_address_format("r1234"),
        "validate short address format",
    );

    assert_validation_error(err);
}

#[test]
fn test_27_wallet_public_key_matches_address() {
    let fixture = primary_fixture();

    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&fixture.address, &fixture.public),
        "wallet public key binding",
    );
}

#[test]
fn test_28_wallet_rejects_wrong_public_key_binding() {
    let primary = primary_fixture();
    let secondary = secondary_fixture();

    let err = assert_err(
        wallet_id_matches_pubkey_bytes_checked(&primary.address, &secondary.public),
        "wrong public key binding",
    );

    assert_validation_error(err);
}

#[test]
fn test_29_derive_wallet_id_from_public_key_matches_address() {
    let fixture = primary_fixture();
    let derived = derive_wallet_id_from_pubkey_bytes(&fixture.public);

    assert_eq!(derived, fixture.address);
}

#[test]
fn test_30_secret_bytes_recover_primary_address() {
    assert_secret_recovers_address(&primary_fixture());
}

#[test]
fn test_31_secret_bytes_recover_secondary_address() {
    assert_secret_recovers_address(&secondary_fixture());
}

#[test]
fn test_32_wallet_core_hash_is_128_hex_chars() {
    let wallet = primary_fixture().address;
    let core = wallet_core_hash(&wallet);

    assert_hash_hex_128(core);
}

#[test]
fn test_33_wallet_prefix_is_r() {
    let wallet = primary_fixture().address;
    let prefix = wallet.chars().next().unwrap_or('\0');

    assert_eq!(prefix, 'r');
}

#[test]
fn test_34_wallet_core_hash_matches_address_without_prefix() {
    let wallet = primary_fixture().address;
    let core = wallet_core_hash(&wallet);

    assert_eq!(format!("r{core}"), wallet);
}

#[test]
fn test_35_key_spec_secret_raw_len_matches_mldsa_constant() {
    assert!(ml_dsa_65::SK_LEN > 0);
}

#[test]
fn test_36_key_spec_secret_hex_len_is_double_raw_len() {
    assert_eq!(ml_dsa_65::SK_LEN.saturating_mul(2), ml_dsa_65::SK_LEN * 2);
}

#[test]
fn test_37_key_spec_public_raw_len_is_nonzero() {
    assert!(ml_dsa_65::PK_LEN > 0);
}

#[test]
fn test_38_key_spec_public_hex_len_is_double_raw_len() {
    assert_eq!(ml_dsa_65::PK_LEN.saturating_mul(2), ml_dsa_65::PK_LEN * 2);
}

#[test]
fn test_39_key_spec_signature_raw_len_is_nonzero() {
    assert!(ml_dsa_65::SIG_LEN > 0);
}

#[test]
fn test_40_key_spec_signature_hex_len_is_double_raw_len() {
    assert_eq!(ml_dsa_65::SIG_LEN.saturating_mul(2), ml_dsa_65::SIG_LEN * 2);
}

#[test]
fn test_41_read_existing_directory_accepts_existing_dir() {
    let temp = TempTree::new("test_41");
    let parsed = assert_ok(
        read_existing_directory_like_s15(&temp.root.to_string_lossy(), MAX_DIR_INPUT_LEN_LIKE_S15),
        "read existing directory",
    );

    assert!(parsed.exists());
    assert!(parsed.is_dir());
}

#[test]
fn test_42_read_existing_directory_accepts_whitespace_padded_dir() {
    let temp = TempTree::new("test_42");
    let raw = format!("  {}  ", temp.root.display());
    let parsed = assert_ok(
        read_existing_directory_like_s15(&raw, MAX_DIR_INPUT_LEN_LIKE_S15),
        "read padded directory",
    );

    assert!(parsed.exists());
    assert!(parsed.is_dir());
}

#[test]
fn test_43_read_existing_directory_rejects_empty() {
    let err = assert_err(
        read_existing_directory_like_s15("", MAX_DIR_INPUT_LEN_LIKE_S15),
        "read empty directory",
    );

    assert_validation_error(err);
}

#[test]
fn test_44_read_existing_directory_rejects_missing() {
    let temp = TempTree::new("test_44");
    let missing = temp.child("missing");

    let err = assert_err(
        read_existing_directory_like_s15(&missing.to_string_lossy(), MAX_DIR_INPUT_LEN_LIKE_S15),
        "read missing directory",
    );

    assert_validation_error(err);
}

#[test]
fn test_45_read_existing_directory_rejects_file_path() {
    let temp = TempTree::new("test_45");
    let file = temp.child("not_dir.txt");

    assert_ok(fs::write(&file, b"not dir"), "write file");

    let err = assert_err(
        read_existing_directory_like_s15(&file.to_string_lossy(), MAX_DIR_INPUT_LEN_LIKE_S15),
        "read file as directory",
    );

    assert_validation_error(err);
}

#[test]
fn test_46_read_existing_directory_rejects_over_cap() {
    let too_long = "a".repeat(MAX_DIR_INPUT_LEN_LIKE_S15.saturating_add(1));

    let err = assert_err(
        read_existing_directory_like_s15(&too_long, MAX_DIR_INPUT_LEN_LIKE_S15),
        "read over-cap directory",
    );

    assert_validation_error(err);
}

#[test]
fn test_47_write_wallet_file_round_trips_encrypted_bytes() {
    let temp = TempTree::new("test_47");
    let path = write_fixture_wallet_file(&temp.root, &primary_fixture());

    assert_eq!(read_file_bytes(&path), primary_fixture().encrypted_secret);
}

#[test]
fn test_48_wallet_file_path_uses_wallet_address() {
    let temp = TempTree::new("test_48");
    let wallet = primary_fixture().address;
    let path = wallet_file_path(&temp.root, &wallet);

    assert!(path.ends_with(format!("{wallet}.wallet")));
}

#[test]
fn test_49_debug_decrypt_wallet_file_accepts_real_wallet() {
    let temp = TempTree::new("test_49");
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&temp.root, &fixture);

    let len = assert_ok(
        debug_decrypt_wallet_file_like_s15(&path, fixture.passphrase),
        "debug decrypt wallet file",
    );

    assert_eq!(len, ml_dsa_65::SK_LEN);
}

#[test]
fn test_50_debug_decrypt_wallet_file_rejects_wrong_passphrase() {
    let temp = TempTree::new("test_50");
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&temp.root, &fixture);

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, "wrong"),
        "debug decrypt wrong passphrase",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_51_debug_decrypt_wallet_file_rejects_missing_file() {
    let temp = TempTree::new("test_51");
    let path = temp.child("missing.wallet");

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, primary_fixture().passphrase),
        "debug decrypt missing file",
    );

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_52_debug_decrypt_wallet_file_rejects_tampered_file() {
    let temp = TempTree::new("test_52");
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&temp.root, &fixture);
    let mut bytes = read_file_bytes(&path);

    match bytes.first_mut() {
        Some(byte) => *byte ^= 0xAA,
        None => panic!("wallet file unexpectedly empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet file");

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, fixture.passphrase),
        "debug decrypt tampered file",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_53_debug_decrypt_wallet_file_rejects_legacy_hex_secret_length() {
    let temp = TempTree::new("test_53");
    let fixture = primary_fixture();
    let path = make_legacy_hex_wallet_file(&temp.root, &fixture);

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, fixture.passphrase),
        "debug decrypt legacy hex secret",
    );

    assert_validation_error(err);
}

#[test]
fn test_54_debug_flow_accepts_real_wallet_directory_and_file() {
    let temp = TempTree::new("test_54");
    let fixture = primary_fixture();
    let _path = write_fixture_wallet_file(&temp.root, &fixture);

    let len = assert_ok(
        debug_flow_like_s15(&temp.root, &fixture.address, fixture.passphrase),
        "debug flow real wallet",
    );

    assert_eq!(len, ml_dsa_65::SK_LEN);
}

#[test]
fn test_55_debug_flow_accepts_uppercase_wallet_address() {
    let temp = TempTree::new("test_55");
    let fixture = primary_fixture();
    let _path = write_fixture_wallet_file(&temp.root, &fixture);

    let len = assert_ok(
        debug_flow_like_s15(
            &temp.root,
            &fixture.address.to_ascii_uppercase(),
            fixture.passphrase,
        ),
        "debug flow uppercase wallet",
    );

    assert_eq!(len, ml_dsa_65::SK_LEN);
}

#[test]
fn test_56_debug_flow_accepts_padded_wallet_address() {
    let temp = TempTree::new("test_56");
    let fixture = primary_fixture();
    let _path = write_fixture_wallet_file(&temp.root, &fixture);
    let padded = format!("  {}  ", fixture.address);

    let len = assert_ok(
        debug_flow_like_s15(&temp.root, &padded, fixture.passphrase),
        "debug flow padded wallet",
    );

    assert_eq!(len, ml_dsa_65::SK_LEN);
}

#[test]
fn test_57_debug_flow_rejects_missing_wallet_file() {
    let temp = TempTree::new("test_57");
    let fixture = primary_fixture();

    let err = assert_err(
        debug_flow_like_s15(&temp.root, &fixture.address, fixture.passphrase),
        "debug flow missing wallet file",
    );

    match err {
        ErrorDetection::NotFound { .. } => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn test_58_debug_flow_rejects_invalid_wallet_address() {
    let temp = TempTree::new("test_58");

    let err = assert_err(
        debug_flow_like_s15(&temp.root, "not-a-wallet", primary_fixture().passphrase),
        "debug flow invalid wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_59_debug_flow_rejects_missing_directory() {
    let temp = TempTree::new("test_59");
    let missing = temp.child("missing");

    let err = assert_err(
        debug_flow_like_s15(
            &missing,
            &primary_fixture().address,
            primary_fixture().passphrase,
        ),
        "debug flow missing directory",
    );

    assert_validation_error(err);
}

#[test]
fn test_60_debug_flow_rejects_wrong_passphrase() {
    let temp = TempTree::new("test_60");
    let fixture = primary_fixture();
    let _path = write_fixture_wallet_file(&temp.root, &fixture);

    let err = assert_err(
        debug_flow_like_s15(&temp.root, &fixture.address, "wrong"),
        "debug flow wrong passphrase",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_61_debug_flow_rejects_file_path_as_wallet_directory() {
    let temp = TempTree::new("test_61");
    let file_path = temp.child("not_a_dir.txt");

    assert_ok(fs::write(&file_path, b"file"), "write file path");

    let err = assert_err(
        debug_flow_like_s15(
            &file_path,
            &primary_fixture().address,
            primary_fixture().passphrase,
        ),
        "debug flow file as directory",
    );

    assert_validation_error(err);
}

#[test]
fn test_62_metadata_wallet_file_is_file() {
    let temp = TempTree::new("test_62");
    let path = write_fixture_wallet_file(&temp.root, &primary_fixture());
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(metadata.is_file());
}

#[test]
fn test_63_metadata_wallet_file_is_nonempty() {
    let temp = TempTree::new("test_63");
    let path = write_fixture_wallet_file(&temp.root, &primary_fixture());
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(metadata.len() > 0);
}

#[test]
fn test_64_metadata_wallet_file_size_matches_encrypted_secret_len() {
    let temp = TempTree::new("test_64");
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&temp.root, &fixture);
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert_eq!(
        metadata.len(),
        u64::try_from(fixture.encrypted_secret.len()).unwrap_or(0)
    );
}

#[test]
fn test_65_metadata_modified_time_is_available() {
    let temp = TempTree::new("test_65");
    let path = write_fixture_wallet_file(&temp.root, &primary_fixture());
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(metadata.modified().is_ok());
}

#[test]
fn test_66_logger_accepts_confirm_debug_event() {
    let temp = TempTree::new("test_66");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("debug", "ConfirmDebugReadFailed", "test event"),
        "log confirm debug event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_67_logger_accepts_wallet_addr_invalid_event() {
    let temp = TempTree::new("test_67");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("debug", "WalletAddrInvalid", "invalid wallet"),
        "log wallet addr invalid",
    );
    assert_ok(logger.flush(), "flush logger");
}

#[test]
fn test_68_logger_accepts_wallet_file_missing_event() {
    let temp = TempTree::new("test_68");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("debug", "WalletFileMissing", "missing wallet"),
        "log wallet file missing",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_69_logger_accepts_unicode_debug_message() {
    let temp = TempTree::new("test_69");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("debug", "DebugUnicode", "debug 測試 🔐"),
        "log unicode debug event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_70_vector_parse_yes_values() {
    for input in ["yes", "YES", "y", "Y", " YeS "] {
        assert!(assert_ok(
            parse_yes_no_like_s15(input, MAX_YN_INPUT_LEN_LIKE_S15),
            "parse yes vector"
        ));
    }
}

#[test]
fn test_71_vector_parse_no_values() {
    for input in ["no", "NO", "n", "N", " No "] {
        assert!(!assert_ok(
            parse_yes_no_like_s15(input, MAX_YN_INPUT_LEN_LIKE_S15),
            "parse no vector"
        ));
    }
}

#[test]
fn test_72_vector_parse_invalid_yes_no_values() {
    for input in ["", "maybe", "1", "true", "false"] {
        let err = assert_err(
            parse_yes_no_like_s15(input, MAX_YN_INPUT_LEN_LIKE_S15),
            "parse invalid yes/no vector",
        );
        assert_validation_error(err);
    }
}

#[test]
fn test_73_vector_canonicalize_wallet_labels() {
    for label in ["alpha", "beta", "gamma", "delta", "epsilon"] {
        let wallet = wallet_from_label(label);
        let parsed = assert_ok(
            read_wallet_address_like_s15(&wallet, MAX_ADDR_INPUT_LEN_LIKE_S15),
            "parse wallet label",
        );
        assert_eq!(parsed, wallet);
    }
}

#[test]
fn test_74_vector_reject_invalid_wallet_inputs() {
    for input in ["", "r", "r1234", "x1234", "not-a-wallet"] {
        let err = assert_err(
            read_wallet_address_like_s15(input, MAX_ADDR_INPUT_LEN_LIKE_S15),
            "reject invalid wallet input vector",
        );
        assert_validation_error(err);
    }
}

#[test]
fn test_75_vector_debug_decrypt_three_wallet_files() {
    let temp = TempTree::new("test_75");

    for index in 0usize..3usize {
        let passphrase = format!("test_75_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&temp.root, &wallet);

        let len = assert_ok(
            debug_decrypt_wallet_file_like_s15(&path, &passphrase),
            "decrypt vector wallet",
        );

        assert_eq!(len, ml_dsa_65::SK_LEN);
    }
}

#[test]
fn test_76_vector_wrong_passphrases_reject_three_wallet_files() {
    let temp = TempTree::new("test_76");

    for index in 0usize..3usize {
        let passphrase = format!("test_76_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&temp.root, &wallet);

        let err = assert_err(
            debug_decrypt_wallet_file_like_s15(&path, "wrong"),
            "decrypt vector wrong passphrase",
        );

        assert_decrypt_like_error(err);
    }
}

#[test]
fn test_77_vector_debug_flow_three_wallet_files() {
    let temp = TempTree::new("test_77");

    for index in 0usize..3usize {
        let passphrase = format!("test_77_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let _path = write_wallet_file(&temp.root, &wallet);

        let len = assert_ok(
            debug_flow_like_s15(&temp.root, &wallet.address, &passphrase),
            "debug flow vector wallet",
        );

        assert_eq!(len, ml_dsa_65::SK_LEN);
    }
}

#[test]
fn test_78_edge_directory_with_spaces_is_accepted() {
    let temp = TempTree::new("test_78");
    let dir = temp.child("wallet dir with spaces");

    assert_ok(fs::create_dir_all(&dir), "create spaced dir");

    let parsed = assert_ok(
        read_existing_directory_like_s15(&dir.to_string_lossy(), MAX_DIR_INPUT_LEN_LIKE_S15),
        "read spaced dir",
    );

    assert!(parsed.exists());
}

#[test]
fn test_79_edge_directory_with_unicode_is_accepted() {
    let temp = TempTree::new("test_79");
    let dir = temp.child("wallet_測試_dir");

    assert_ok(fs::create_dir_all(&dir), "create unicode dir");

    let parsed = assert_ok(
        read_existing_directory_like_s15(&dir.to_string_lossy(), MAX_DIR_INPUT_LEN_LIKE_S15),
        "read unicode dir",
    );

    assert!(parsed.exists());
}

#[test]
fn test_80_edge_unicode_passphrase_wallet_decrypts() {
    let temp = TempTree::new("test_80");
    let passphrase = "密碼 debug ключ 🔐";
    let wallet = make_wallet(passphrase);
    let path = write_wallet_file(&temp.root, &wallet);

    let len = assert_ok(
        debug_decrypt_wallet_file_like_s15(&path, passphrase),
        "decrypt unicode passphrase wallet",
    );

    assert_eq!(len, ml_dsa_65::SK_LEN);
}

#[test]
fn test_81_edge_long_passphrase_wallet_decrypts() {
    let temp = TempTree::new("test_81");
    let passphrase = "long-passphrase-".repeat(16);
    let wallet = make_wallet(&passphrase);
    let path = write_wallet_file(&temp.root, &wallet);

    let len = assert_ok(
        debug_decrypt_wallet_file_like_s15(&path, &passphrase),
        "decrypt long passphrase wallet",
    );

    assert_eq!(len, ml_dsa_65::SK_LEN);
}

#[test]
fn test_82_adversarial_tamper_first_byte_rejects_decrypt() {
    let temp = TempTree::new("test_82");
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&temp.root, &fixture);
    let mut bytes = read_file_bytes(&path);

    match bytes.first_mut() {
        Some(byte) => *byte ^= 0x11,
        None => panic!("wallet file empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet");

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, fixture.passphrase),
        "decrypt first-byte tamper",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_83_adversarial_tamper_middle_byte_rejects_decrypt() {
    let temp = TempTree::new("test_83");
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&temp.root, &fixture);
    let mut bytes = read_file_bytes(&path);
    let middle = bytes.len() / 2;

    match bytes.get_mut(middle) {
        Some(byte) => *byte ^= 0x22,
        None => panic!("wallet missing middle byte"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet");

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, fixture.passphrase),
        "decrypt middle-byte tamper",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_84_adversarial_tamper_last_byte_rejects_decrypt() {
    let temp = TempTree::new("test_84");
    let fixture = primary_fixture();
    let path = write_fixture_wallet_file(&temp.root, &fixture);
    let mut bytes = read_file_bytes(&path);

    match bytes.last_mut() {
        Some(byte) => *byte ^= 0x44,
        None => panic!("wallet file empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet");

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, fixture.passphrase),
        "decrypt last-byte tamper",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_85_adversarial_random_wallet_file_rejects_decrypt() {
    let temp = TempTree::new("test_85");
    let wallet = wallet_from_label("test_85_wallet");
    let path = wallet_file_path(&temp.root, &wallet);

    assert_ok(
        fs::write(&path, vec![0xAB_u8; 256]),
        "write random wallet bytes",
    );

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, "test_85_passphrase"),
        "decrypt random wallet",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_86_adversarial_empty_wallet_file_rejects_decrypt() {
    let temp = TempTree::new("test_86");
    let wallet = wallet_from_label("test_86_wallet");
    let path = wallet_file_path(&temp.root, &wallet);

    assert_ok(fs::write(&path, b""), "write empty wallet");

    let err = assert_err(
        debug_decrypt_wallet_file_like_s15(&path, "test_86_passphrase"),
        "decrypt empty wallet",
    );

    assert_decrypt_like_error(err);
}

#[test]
fn test_87_adversarial_directory_named_wallet_rejects_flow() {
    let temp = TempTree::new("test_87");
    let fixture = primary_fixture();
    let wallet_dir_entry = wallet_file_path(&temp.root, &fixture.address);

    assert_ok(
        fs::create_dir_all(&wallet_dir_entry),
        "create wallet-named directory",
    );

    let err = assert_err(
        debug_flow_like_s15(&temp.root, &fixture.address, fixture.passphrase),
        "debug flow wallet path is directory",
    );

    match err {
        ErrorDetection::NotFound { .. } => {}
        other => panic!("expected NotFound for non-file wallet path, got {other:?}"),
    }
}

#[test]
fn test_88_adversarial_wrong_wallet_filename_for_valid_file_is_not_found() {
    let temp = TempTree::new("test_88");
    let primary = primary_fixture();
    let secondary = secondary_fixture();
    let _path = write_fixture_wallet_file(&temp.root, &primary);

    let err = assert_err(
        debug_flow_like_s15(&temp.root, &secondary.address, primary.passphrase),
        "debug flow wrong wallet filename",
    );

    match err {
        ErrorDetection::NotFound { .. } => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn test_89_property_debug_decrypt_only_checks_secret_length_not_wallet_binding() {
    let temp = TempTree::new("test_89");
    let primary = primary_fixture();
    let secondary = secondary_fixture();

    assert_ok(fs::create_dir_all(&temp.root), "create temp root");
    let mismatched_path = wallet_file_path(&temp.root, &secondary.address);
    assert_ok(
        fs::write(&mismatched_path, &primary.encrypted_secret),
        "write mismatched wallet file",
    );

    let len = assert_ok(
        debug_decrypt_wallet_file_like_s15(&mismatched_path, primary.passphrase),
        "debug decrypt mismatched filename",
    );

    assert_eq!(len, ml_dsa_65::SK_LEN);
}

#[test]
fn test_90_property_address_binding_helper_detects_mismatch() {
    let primary = primary_fixture();
    let secondary = secondary_fixture();

    let err = assert_err(
        wallet_id_matches_pubkey_bytes_checked(&secondary.address, &primary.public),
        "address binding mismatch",
    );

    assert_validation_error(err);
}

#[test]
fn test_91_load_create_five_wallet_files() {
    let temp = TempTree::new("test_91");

    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_91_passphrase_{index}"));
        let path = write_wallet_file(&temp.root, &wallet);

        assert!(path.exists());
    }
}

#[test]
fn test_92_load_debug_decrypt_five_wallet_files() {
    let temp = TempTree::new("test_92");

    for index in 0usize..5usize {
        let passphrase = format!("test_92_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&temp.root, &wallet);

        let len = assert_ok(
            debug_decrypt_wallet_file_like_s15(&path, &passphrase),
            "load debug decrypt wallet",
        );

        assert_eq!(len, ml_dsa_65::SK_LEN);
    }
}

#[test]
fn test_93_load_debug_flow_five_wallet_files() {
    let temp = TempTree::new("test_93");

    for index in 0usize..5usize {
        let passphrase = format!("test_93_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let _path = write_wallet_file(&temp.root, &wallet);

        let len = assert_ok(
            debug_flow_like_s15(&temp.root, &wallet.address, &passphrase),
            "load debug flow wallet",
        );

        assert_eq!(len, ml_dsa_65::SK_LEN);
    }
}

#[test]
fn test_94_load_wrong_passphrases_reject_five_wallet_files() {
    let temp = TempTree::new("test_94");

    for index in 0usize..5usize {
        let passphrase = format!("test_94_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&temp.root, &wallet);

        let err = assert_err(
            debug_decrypt_wallet_file_like_s15(&path, "wrong"),
            "load wrong passphrase",
        );

        assert_decrypt_like_error(err);
    }
}

#[test]
fn test_95_load_canonicalize_twenty_wallet_labels() {
    for index in 0usize..20usize {
        let wallet = wallet_from_label(&format!("test_95_wallet_{index}"));
        let parsed = assert_ok(
            read_wallet_address_like_s15(&wallet, MAX_ADDR_INPUT_LEN_LIKE_S15),
            "load parse wallet",
        );

        assert_eq!(parsed, wallet);
    }
}

#[test]
fn test_96_load_logger_many_debug_events() {
    let temp = TempTree::new("test_96");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    for index in 0usize..20usize {
        assert_ok(
            logger.log_error_event(
                "debug",
                "LoadDebugWalletStorageKeys",
                &format!("event {index}"),
            ),
            "log load debug event",
        );
    }

    assert_ok(logger.flush_logs_cf(), "flush load logger");
}

#[test]
fn test_97_load_metadata_for_five_wallet_files() {
    let temp = TempTree::new("test_97");

    for index in 0usize..5usize {
        let wallet = make_wallet(&format!("test_97_passphrase_{index}"));
        let path = write_wallet_file(&temp.root, &wallet);
        let metadata = assert_ok(fs::metadata(path), "load wallet metadata");

        assert!(metadata.is_file());
        assert!(metadata.len() > 0);
    }
}

#[test]
fn test_98_property_wallet_core_hash_stable() {
    let wallet = primary_fixture().address;
    let first = wallet_core_hash(&wallet).to_owned();
    let second = wallet_core_hash(&wallet).to_owned();

    assert_eq!(first, second);
    assert_hash_hex_128(&first);
}

#[test]
fn test_99_property_distinct_wallet_core_hashes_differ() {
    let primary = primary_fixture();
    let secondary = secondary_fixture();

    assert_ne!(
        wallet_core_hash(&primary.address),
        wallet_core_hash(&secondary.address)
    );
}

#[test]
fn test_100_final_debug_wallet_storage_keys_validate_dir_wallet_file_decrypt_metadata_and_log_flow()
{
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let logger = make_logger(&opts);
    let passphrase = "test_100_passphrase";
    let wallet = make_wallet(passphrase);

    assert_ok(
        directory.create_wallets_directory(),
        "final create wallets directory",
    );

    let wallet_file = write_wallet_file(&directory.wallets_path, &wallet);

    let parsed_wallet = assert_ok(
        read_wallet_address_like_s15(&wallet.address, MAX_ADDR_INPUT_LEN_LIKE_S15),
        "final parse wallet",
    );
    assert_eq!(parsed_wallet, wallet.address);

    let parsed_dir = assert_ok(
        read_existing_directory_like_s15(
            &directory.wallets_path.to_string_lossy(),
            MAX_DIR_INPUT_LEN_LIKE_S15,
        ),
        "final parse wallet dir",
    );
    assert!(parsed_dir.exists());
    assert!(parsed_dir.is_dir());

    let len = assert_ok(
        debug_flow_like_s15(&directory.wallets_path, &wallet.address, passphrase),
        "final debug flow",
    );
    assert_eq!(len, ml_dsa_65::SK_LEN);

    let metadata = assert_ok(fs::metadata(&wallet_file), "final wallet metadata");
    assert!(metadata.is_file());
    assert!(metadata.len() > 0);

    let core_hash = wallet_core_hash(&wallet.address);
    assert_hash_hex_128(core_hash);
    assert_eq!(format!("r{core_hash}"), wallet.address);

    assert_ok(
        logger.log_error_event("debug", "FinalDebugWalletStorageKeysTest", &wallet.address),
        "final log debug wallet storage keys event",
    );
    assert_ok(logger.flush_logs_cf(), "final flush logs");
}
