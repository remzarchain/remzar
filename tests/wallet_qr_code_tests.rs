// tests/wallet_qr_code_tests.rs

use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;
use remzar::utility::wallet_qr_code::{QRWallet, QRWalletReceipt};

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

type TestResult = Result<(), String>;

const TEST_PASSPHRASE: &str = "remzar-wallet-qr-test-passphrase-2026!";
const OTHER_PASSPHRASE: &str = "remzar-wallet-qr-other-passphrase-2026!";

static TEST_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static OTHER_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_wallet() -> &'static MLDSA65Wallet {
    TEST_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(TEST_PASSPHRASE).expect("test wallet generation should succeed")
    })
}

fn other_wallet() -> &'static MLDSA65Wallet {
    OTHER_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(OTHER_PASSPHRASE).expect("other wallet generation should succeed")
    })
}

fn temp_dir(label: &str) -> Result<PathBuf, String> {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e:?}"))?
        .as_nanos();

    let path = std::env::temp_dir().join(format!(
        "remzar_wallet_qr_code_tests_{}_{}_{}_{}",
        std::process::id(),
        nanos,
        counter,
        label
    ));

    if path.exists() {
        fs::remove_dir_all(&path)
            .map_err(|e| format!("failed to remove stale temp dir {}: {e}", path.display()))?;
    }

    fs::create_dir_all(&path)
        .map_err(|e| format!("failed to create temp dir {}: {e}", path.display()))?;

    Ok(path)
}

fn node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "info".to_string(),
        data_dir: data_dir.display().to_string(),
        wallet_address: String::new(),
        founder: false,
    }
}

fn ok<T>(result: Result<T, ErrorDetection>, context: &str) -> Result<T, String> {
    result.map_err(|e| format!("{context}: {e:?}"))
}

fn assert_validation_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected ValidationError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected ValidationError, got Err({error:?})")),
    }
}

fn assert_cryptographic_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::CryptographicError { message }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected CryptographicError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected CryptographicError, got Err({error:?})")),
    }
}

fn assert_any_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Ok(_) => Err("expected Err(_), got Ok(_)".to_string()),
        Err(_) => Ok(()),
    }
}

fn assert_png(bytes: &[u8]) {
    assert!(bytes.len() > 8);
    assert_eq!(
        &bytes[..8],
        &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n']
    );
}

fn write_wallet_file(opts: &NodeOpts, wallet: &MLDSA65Wallet) -> Result<PathBuf, String> {
    let directory = DirectoryDB::from_node_opts(opts)
        .map_err(|e| format!("DirectoryDB::from_node_opts failed: {e}"))?;

    directory
        .create_wallets_directory()
        .map_err(|e| format!("create_wallets_directory failed: {e}"))?;

    let wallet_path = directory
        .wallets_path
        .join(format!("{}.wallet", wallet.address));

    fs::write(&wallet_path, &wallet.encrypted_secret)
        .map_err(|e| format!("failed to write wallet file {}: {e}", wallet_path.display()))?;

    Ok(wallet_path)
}

fn wallet_file_path(opts: &NodeOpts, wallet_address: &str) -> Result<PathBuf, String> {
    let directory = DirectoryDB::from_node_opts(opts)
        .map_err(|e| format!("DirectoryDB::from_node_opts failed: {e}"))?;

    Ok(directory
        .wallets_path
        .join(format!("{wallet_address}.wallet")))
}

fn read_qr_png(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("failed to read QR PNG {}: {e}", path.display()))
}

fn assert_receipt_shape(receipt: &QRWalletReceipt, wallet_address: &str) {
    assert_eq!(receipt.wallet_address, wallet_address);
    assert_eq!(receipt.wallet_address.len(), REMZAR_WALLET_LEN);
    assert_eq!(receipt.qr_payload_bytes_len, REMZAR_WALLET_LEN);
    assert!(receipt.qr_png_path.exists());
    assert_eq!(
        receipt.qr_png_path.extension().and_then(|s| s.to_str()),
        Some("png")
    );
}

#[test]
fn wallet_qr_001_qr_payload_is_exact_wallet_address() -> TestResult {
    let wallet = test_wallet();

    let payload = ok(
        QRWallet::qr_payload(&wallet.address),
        "qr_payload should succeed",
    )?;

    assert_eq!(payload, wallet.address);
    assert_eq!(payload.len(), REMZAR_WALLET_LEN);
    Ok(())
}

#[test]
fn wallet_qr_002_qr_payload_canonicalizes_uppercase_wallet_address() -> TestResult {
    let wallet = test_wallet();
    let uppercase = wallet.address.to_ascii_uppercase();

    let payload = ok(
        QRWallet::qr_payload(&uppercase),
        "qr_payload should canonicalize uppercase",
    )?;

    assert_eq!(payload, wallet.address);
    assert_eq!(payload, payload.to_ascii_lowercase());
    Ok(())
}

#[test]
fn wallet_qr_003_qr_payload_trims_surrounding_whitespace() -> TestResult {
    let wallet = test_wallet();

    let payload = ok(
        QRWallet::qr_payload(&format!("  {}  ", wallet.address)),
        "qr_payload should trim",
    )?;

    assert_eq!(payload, wallet.address);
    Ok(())
}

#[test]
fn wallet_qr_004_qr_payload_rejects_empty_address() -> TestResult {
    assert_validation_error(QRWallet::qr_payload(""))?;
    Ok(())
}

#[test]
fn wallet_qr_005_qr_payload_rejects_short_address() -> TestResult {
    assert_validation_error(QRWallet::qr_payload("r1234"))?;
    Ok(())
}

#[test]
fn wallet_qr_006_qr_payload_rejects_long_address() -> TestResult {
    let long_address = format!("r{}", "a".repeat(129));

    assert_validation_error(QRWallet::qr_payload(&long_address))?;
    Ok(())
}

#[test]
fn wallet_qr_007_qr_payload_rejects_wrong_prefix() -> TestResult {
    let bad = format!("x{}", "a".repeat(128));

    assert_validation_error(QRWallet::qr_payload(&bad))?;
    Ok(())
}

#[test]
fn wallet_qr_008_qr_payload_rejects_non_hex_body() -> TestResult {
    let bad = format!("r{}", "g".repeat(128));

    assert_validation_error(QRWallet::qr_payload(&bad))?;
    Ok(())
}

#[test]
fn wallet_qr_009_public_constants_match_wallet_format_expectations() -> TestResult {
    assert_eq!(QRWallet::WALLET_QR_DIR_NAME, "qr_code_wallet");
    assert_eq!(QRWallet::WALLET_ADDRESS_LEN, REMZAR_WALLET_LEN);
    assert_eq!(QRWallet::MAX_QR_PAYLOAD_BYTES, 256);
    assert_eq!(QRWallet::QR_MIN_WIDTH, 512);
    assert_eq!(QRWallet::QR_MIN_HEIGHT, 512);
    assert!(QRWallet::MAX_QR_PNG_BYTES >= 512);
    assert!(QRWallet::MAX_WALLET_FILE_BYTES >= 4096);
    Ok(())
}

#[test]
fn wallet_qr_010_build_qr_png_bytes_returns_png() -> TestResult {
    let wallet = test_wallet();

    let bytes = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "build_qr_png_bytes should succeed",
    )?;

    assert_png(&bytes);
    assert!(bytes.len() < QRWallet::MAX_QR_PNG_BYTES);
    Ok(())
}

#[test]
fn wallet_qr_011_build_qr_png_bytes_is_deterministic_for_same_wallet() -> TestResult {
    let wallet = test_wallet();

    let first = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "first qr png should build",
    )?;
    let second = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "second qr png should build",
    )?;

    assert_eq!(first, second);
    assert_png(&first);
    Ok(())
}

#[test]
fn wallet_qr_012_build_qr_png_bytes_uppercase_input_matches_canonical_lowercase() -> TestResult {
    let wallet = test_wallet();

    let lowercase = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "lowercase qr should build",
    )?;
    let uppercase = ok(
        QRWallet::build_qr_png_bytes(&wallet.address.to_ascii_uppercase()),
        "uppercase qr should build",
    )?;

    assert_eq!(lowercase, uppercase);
    Ok(())
}

#[test]
fn wallet_qr_013_build_qr_png_bytes_rejects_invalid_address() -> TestResult {
    assert_validation_error(QRWallet::build_qr_png_bytes("not-a-wallet"))?;
    Ok(())
}

#[test]
fn wallet_qr_014_two_different_wallet_addresses_produce_different_qr_images() -> TestResult {
    let first = test_wallet();
    let second = other_wallet();

    let first_png = ok(
        QRWallet::build_qr_png_bytes(&first.address),
        "first qr should build",
    )?;
    let second_png = ok(
        QRWallet::build_qr_png_bytes(&second.address),
        "second qr should build",
    )?;

    assert_ne!(first.address, second.address);
    assert_ne!(first_png, second_png);
    Ok(())
}

#[test]
fn wallet_qr_015_wallet_qr_output_dir_creates_dedicated_folder() -> TestResult {
    let data_dir = temp_dir("output-dir")?;
    let opts = node_opts(&data_dir);

    let qr_dir = ok(
        QRWallet::wallet_qr_output_dir(&opts),
        "wallet_qr_output_dir should succeed",
    )?;

    assert!(qr_dir.exists());
    assert!(qr_dir.is_dir());
    assert_eq!(
        qr_dir.file_name().and_then(|s| s.to_str()),
        Some("qr_code_wallet")
    );
    assert_eq!(qr_dir.parent(), Some(data_dir.as_path()));
    Ok(())
}

#[test]
fn wallet_qr_016_wallet_qr_output_dir_is_idempotent() -> TestResult {
    let data_dir = temp_dir("output-dir-idempotent")?;
    let opts = node_opts(&data_dir);

    let first = ok(
        QRWallet::wallet_qr_output_dir(&opts),
        "first output dir call should succeed",
    )?;
    let second = ok(
        QRWallet::wallet_qr_output_dir(&opts),
        "second output dir call should succeed",
    )?;

    assert_eq!(first, second);
    assert!(second.exists());
    Ok(())
}

#[test]
fn wallet_qr_017_wallet_qr_output_dir_creates_missing_data_dir_tree() -> TestResult {
    let root = temp_dir("missing-root")?;
    let data_dir = root.join("missing").join("nested").join("data");
    let opts = node_opts(&data_dir);

    let qr_dir = ok(
        QRWallet::wallet_qr_output_dir(&opts),
        "output dir should create missing data dir tree",
    )?;

    assert!(qr_dir.exists());
    assert_eq!(qr_dir, data_dir.join("qr_code_wallet"));
    Ok(())
}

#[test]
fn wallet_qr_018_wallet_qr_output_dir_rejects_data_dir_that_is_file() -> TestResult {
    let dir = temp_dir("data-dir-file-root")?;
    let file_data_dir = dir.join("data-file");
    fs::write(&file_data_dir, b"I am not a directory")
        .map_err(|e| format!("failed to write data dir file: {e}"))?;
    let opts = node_opts(&file_data_dir);

    assert_validation_error(QRWallet::wallet_qr_output_dir(&opts))?;
    Ok(())
}

#[test]
fn wallet_qr_019_load_owned_wallet_succeeds_for_real_wallet_file_and_passphrase() -> TestResult {
    let data_dir = temp_dir("load-owned")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let loaded = ok(
        QRWallet::load_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "load_owned_wallet should succeed",
    )?;

    assert_eq!(loaded.address, wallet.address);
    assert_eq!(loaded.public, wallet.public);
    loaded
        .validate_self()
        .map_err(|e| format!("loaded wallet should self-validate: {e:?}"))?;
    Ok(())
}

#[test]
fn wallet_qr_020_load_owned_wallet_canonicalizes_uppercase_input() -> TestResult {
    let data_dir = temp_dir("load-uppercase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let loaded = ok(
        QRWallet::load_owned_wallet(&opts, &wallet.address.to_ascii_uppercase(), TEST_PASSPHRASE),
        "load_owned_wallet should canonicalize uppercase",
    )?;

    assert_eq!(loaded.address, wallet.address);
    Ok(())
}

#[test]
fn wallet_qr_021_load_owned_wallet_trims_input() -> TestResult {
    let data_dir = temp_dir("load-trimmed")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let loaded = ok(
        QRWallet::load_owned_wallet(&opts, &format!("  {}  ", wallet.address), TEST_PASSPHRASE),
        "load_owned_wallet should trim address",
    )?;

    assert_eq!(loaded.address, wallet.address);
    Ok(())
}

#[test]
fn wallet_qr_022_load_owned_wallet_rejects_invalid_wallet_address_before_file_lookup() -> TestResult
{
    let data_dir = temp_dir("load-invalid-address")?;
    let opts = node_opts(&data_dir);

    assert_validation_error(QRWallet::load_owned_wallet(
        &opts,
        "not-a-wallet",
        TEST_PASSPHRASE,
    ))?;

    assert!(!data_dir.join("000.wallets").exists());
    Ok(())
}

#[test]
fn wallet_qr_023_load_owned_wallet_rejects_missing_wallet_file() -> TestResult {
    let data_dir = temp_dir("missing-wallet-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    assert_any_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;

    assert!(data_dir.join("000.wallets").exists());
    Ok(())
}

#[test]
fn wallet_qr_024_load_owned_wallet_rejects_empty_wallet_file() -> TestResult {
    let data_dir = temp_dir("empty-wallet-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;
    fs::write(&wallet_path, b"").map_err(|e| format!("failed to write empty wallet file: {e}"))?;

    assert_validation_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_025_load_owned_wallet_rejects_wallet_path_that_is_directory() -> TestResult {
    let data_dir = temp_dir("wallet-path-directory")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(&wallet_path)
        .map_err(|e| format!("failed to create directory at wallet path: {e}"))?;

    assert_validation_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_026_load_owned_wallet_rejects_oversized_wallet_file() -> TestResult {
    let data_dir = temp_dir("oversized-wallet-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;
    fs::write(
        &wallet_path,
        vec![7_u8; QRWallet::MAX_WALLET_FILE_BYTES as usize + 1],
    )
    .map_err(|e| format!("failed to write oversized wallet file: {e}"))?;

    assert_validation_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_027_load_owned_wallet_rejects_corrupt_wallet_file() -> TestResult {
    let data_dir = temp_dir("corrupt-wallet-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;
    fs::write(&wallet_path, b"corrupt encrypted secret")
        .map_err(|e| format!("failed to write corrupt wallet file: {e}"))?;

    assert_any_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_028_load_owned_wallet_rejects_wrong_passphrase() -> TestResult {
    let data_dir = temp_dir("wrong-passphrase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    assert_cryptographic_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        "wrong-passphrase",
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_029_load_owned_wallet_rejects_empty_passphrase() -> TestResult {
    let data_dir = temp_dir("empty-passphrase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    assert_validation_error(QRWallet::load_owned_wallet(&opts, &wallet.address, ""))?;
    Ok(())
}

#[test]
fn wallet_qr_030_load_owned_wallet_rejects_absurdly_long_passphrase() -> TestResult {
    let data_dir = temp_dir("long-passphrase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let too_long = "x".repeat(QRWallet::MAX_PASSPHRASE_BYTES + 1);

    assert_validation_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        &too_long,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_031_load_owned_wallet_detects_wallet_file_address_mismatch() -> TestResult {
    let data_dir = temp_dir("wallet-file-address-mismatch")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    let other = other_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;

    fs::write(&wallet_path, &other.encrypted_secret)
        .map_err(|e| format!("failed to write mismatched wallet file: {e}"))?;

    assert_validation_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        OTHER_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_032_generate_for_owned_wallet_writes_png_and_returns_receipt() -> TestResult {
    let data_dir = temp_dir("generate-owned")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate_for_owned_wallet should succeed",
    )?;

    assert_receipt_shape(&receipt, &wallet.address);
    let png = read_qr_png(&receipt.qr_png_path)?;
    assert_png(&png);
    Ok(())
}

#[test]
fn wallet_qr_033_generate_for_owned_wallet_output_path_is_data_dir_qr_code_wallet() -> TestResult {
    let data_dir = temp_dir("generate-path")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate_for_owned_wallet should succeed",
    )?;

    assert_eq!(
        receipt.qr_png_path.parent(),
        Some(data_dir.join("qr_code_wallet").as_path())
    );
    assert!(receipt.qr_png_path.starts_with(&data_dir));
    Ok(())
}

#[test]
fn wallet_qr_034_generate_for_owned_wallet_file_name_contains_wallet_address_and_suffix()
-> TestResult {
    let data_dir = temp_dir("generate-file-name")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate_for_owned_wallet should succeed",
    )?;

    let file_name = receipt
        .qr_png_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "QR PNG file name should be UTF-8".to_string())?;

    assert!(file_name.starts_with("wallet_"));
    assert!(file_name.contains(&wallet.address));
    assert!(file_name.ends_with("_qr.png"));
    Ok(())
}

#[test]
fn wallet_qr_035_generate_for_owned_wallet_overwrites_stale_existing_png() -> TestResult {
    let data_dir = temp_dir("overwrite-stale-png")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let first = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "first generate should succeed",
    )?;

    fs::write(&first.qr_png_path, b"stale-png")
        .map_err(|e| format!("failed to write stale png: {e}"))?;

    let second = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "second generate should succeed",
    )?;

    assert_eq!(first.qr_png_path, second.qr_png_path);

    let bytes = read_qr_png(&second.qr_png_path)?;
    assert_png(&bytes);
    assert_ne!(bytes, b"stale-png");
    Ok(())
}

#[test]
fn wallet_qr_036_generate_for_owned_wallet_is_idempotent_for_same_wallet() -> TestResult {
    let data_dir = temp_dir("idempotent-generate")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let first = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "first generate should succeed",
    )?;
    let first_bytes = read_qr_png(&first.qr_png_path)?;

    let second = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "second generate should succeed",
    )?;
    let second_bytes = read_qr_png(&second.qr_png_path)?;

    assert_eq!(first.qr_png_path, second.qr_png_path);
    assert_eq!(first_bytes, second_bytes);
    Ok(())
}

#[test]
fn wallet_qr_037_generate_for_owned_wallet_canonicalizes_uppercase_input_and_path() -> TestResult {
    let data_dir = temp_dir("generate-uppercase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(
            &opts,
            &wallet.address.to_ascii_uppercase(),
            TEST_PASSPHRASE,
        ),
        "generate_for_owned_wallet should canonicalize uppercase",
    )?;

    assert_eq!(receipt.wallet_address, wallet.address);

    let file_name = receipt
        .qr_png_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "QR PNG file name should be UTF-8".to_string())?;

    assert!(file_name.contains(&wallet.address));
    assert_eq!(file_name, file_name.to_ascii_lowercase());
    Ok(())
}

#[test]
fn wallet_qr_038_generate_for_owned_wallet_rejects_invalid_address_and_writes_no_qr_dir()
-> TestResult {
    let data_dir = temp_dir("generate-invalid-address")?;
    let opts = node_opts(&data_dir);

    assert_validation_error(QRWallet::generate_for_owned_wallet(
        &opts,
        "not-a-wallet",
        TEST_PASSPHRASE,
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_039_generate_for_owned_wallet_rejects_wrong_passphrase_and_writes_no_png() -> TestResult
{
    let data_dir = temp_dir("generate-wrong-passphrase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    assert_cryptographic_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        "wrong-passphrase",
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_040_generate_for_owned_wallet_rejects_missing_wallet_file_and_writes_no_qr_dir()
-> TestResult {
    let data_dir = temp_dir("generate-missing-wallet")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    assert_any_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_041_write_qr_png_for_verified_wallet_succeeds_without_wallet_file_lookup() -> TestResult
{
    let data_dir = temp_dir("write-verified")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let receipt = ok(
        QRWallet::write_qr_png_for_verified_wallet(&opts, wallet),
        "write_qr_png_for_verified_wallet should succeed",
    )?;

    assert_receipt_shape(&receipt, &wallet.address);
    let bytes = read_qr_png(&receipt.qr_png_path)?;
    assert_png(&bytes);
    Ok(())
}

#[test]
fn wallet_qr_042_write_qr_png_for_verified_wallet_rejects_mutated_wallet_address() -> TestResult {
    let data_dir = temp_dir("write-mutated-address")?;
    let opts = node_opts(&data_dir);
    let mut wallet = test_wallet().clone();
    wallet.address = other_wallet().address.clone();

    assert_validation_error(QRWallet::write_qr_png_for_verified_wallet(&opts, &wallet))?;
    Ok(())
}

#[test]
fn wallet_qr_043_write_qr_png_for_verified_wallet_rejects_mutated_public_key_binding() -> TestResult
{
    let data_dir = temp_dir("write-mutated-public")?;
    let opts = node_opts(&data_dir);
    let mut wallet = test_wallet().clone();
    wallet.public = other_wallet().public;

    assert_validation_error(QRWallet::write_qr_png_for_verified_wallet(&opts, &wallet))?;
    Ok(())
}

#[test]
fn wallet_qr_044_write_qr_png_for_verified_wallet_rejects_empty_encrypted_secret() -> TestResult {
    let data_dir = temp_dir("write-empty-secret")?;
    let opts = node_opts(&data_dir);
    let mut wallet = test_wallet().clone();
    wallet.encrypted_secret.clear();

    assert_validation_error(QRWallet::write_qr_png_for_verified_wallet(&opts, &wallet))?;
    Ok(())
}

#[test]
fn wallet_qr_045_generate_for_owned_wallet_creates_only_png_in_qr_directory() -> TestResult {
    let data_dir = temp_dir("only-png")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let qr_dir = receipt
        .qr_png_path
        .parent()
        .ok_or_else(|| "QR PNG path should have parent".to_string())?;

    let entries = fs::read_dir(qr_dir)
        .map_err(|e| format!("failed to read QR dir {}: {e}", qr_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to collect QR dir entries: {e}"))?;

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path(), receipt.qr_png_path);
    Ok(())
}

#[test]
fn wallet_qr_046_receipt_serializes_and_deserializes_as_public_metadata_only() -> TestResult {
    let data_dir = temp_dir("receipt-json")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let json = serde_json::to_string_pretty(&receipt)
        .map_err(|e| format!("receipt serialization failed: {e}"))?;

    assert!(json.contains(&wallet.address));
    assert!(json.contains("qr_png_path"));
    assert!(json.contains("qr_payload_bytes_len"));
    assert!(!json.contains(TEST_PASSPHRASE));
    assert!(!json.contains(&hex::encode(wallet.public)));
    assert!(!json.contains(&hex::encode(&wallet.encrypted_secret)));

    let decoded: QRWalletReceipt =
        serde_json::from_str(&json).map_err(|e| format!("receipt deserialize failed: {e}"))?;

    assert_eq!(decoded, receipt);
    Ok(())
}

#[test]
fn wallet_qr_047_qr_payload_contains_no_metadata_prefixes_or_suffixes() -> TestResult {
    let wallet = test_wallet();

    let payload = ok(
        QRWallet::qr_payload(&wallet.address),
        "qr_payload should succeed",
    )?;

    assert_eq!(payload, wallet.address);
    assert!(!payload.contains("Wallet"));
    assert!(!payload.contains("Address"));
    assert!(!payload.contains("Remzar"));
    assert!(!payload.contains('\n'));
    assert!(!payload.contains(' '));
    assert!(!payload.contains('{'));
    assert!(!payload.contains('}'));
    assert!(!payload.contains(':'));
    Ok(())
}

#[test]
fn wallet_qr_048_build_qr_png_bytes_is_public_address_only_and_needs_no_wallet_file() -> TestResult
{
    let wallet = test_wallet();

    let bytes = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "build_qr_png_bytes should succeed without wallet file",
    )?;

    assert_png(&bytes);
    assert_eq!(
        ok(
            QRWallet::qr_payload(&wallet.address),
            "payload should build"
        )?,
        wallet.address
    );
    Ok(())
}

#[test]
fn wallet_qr_049_loaded_wallet_signature_secret_can_still_self_validate_after_load() -> TestResult {
    let data_dir = temp_dir("loaded-self-validate")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let loaded = ok(
        QRWallet::load_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "load_owned_wallet should succeed",
    )?;

    loaded
        .validate_self()
        .map_err(|e| format!("loaded wallet validate_self failed: {e:?}"))?;

    assert_eq!(loaded.address, wallet.address);
    assert_eq!(loaded.public, wallet.public);
    assert!(!loaded.encrypted_secret.is_empty());
    Ok(())
}

#[test]
fn wallet_qr_050_passphrase_string_can_be_zeroized_after_generate_without_affecting_output()
-> TestResult {
    let data_dir = temp_dir("zeroize-after-generate")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();
    write_wallet_file(&opts, wallet)?;

    let mut passphrase = TEST_PASSPHRASE.to_string();

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, &passphrase),
        "generate should succeed",
    )?;

    passphrase.zeroize();

    assert_receipt_shape(&receipt, &wallet.address);

    let bytes = read_qr_png(&receipt.qr_png_path)?;
    assert_png(&bytes);

    assert_eq!(
        ok(
            QRWallet::qr_payload(&wallet.address),
            "payload should build"
        )?,
        wallet.address
    );

    Ok(())
}

#[test]
fn wallet_qr_051_qr_payload_accepts_all_zero_valid_wallet_vector() -> TestResult {
    let address = format!("r{}", "0".repeat(128));

    let payload = ok(
        QRWallet::qr_payload(&address),
        "all-zero valid wallet payload should succeed",
    )?;

    assert_eq!(payload, address);
    assert_eq!(payload.len(), REMZAR_WALLET_LEN);
    Ok(())
}

#[test]
fn wallet_qr_052_qr_payload_accepts_all_f_valid_wallet_vector() -> TestResult {
    let address = format!("r{}", "f".repeat(128));

    let payload = ok(
        QRWallet::qr_payload(&address),
        "all-f valid wallet payload should succeed",
    )?;

    assert_eq!(payload, address);
    assert_eq!(payload.len(), REMZAR_WALLET_LEN);
    Ok(())
}

#[test]
fn wallet_qr_053_build_qr_png_bytes_accepts_all_zero_valid_wallet_vector() -> TestResult {
    let address = format!("r{}", "0".repeat(128));

    let bytes = ok(
        QRWallet::build_qr_png_bytes(&address),
        "all-zero valid wallet QR should build",
    )?;

    assert_png(&bytes);
    Ok(())
}

#[test]
fn wallet_qr_054_build_qr_png_bytes_accepts_all_f_valid_wallet_vector() -> TestResult {
    let address = format!("r{}", "f".repeat(128));

    let bytes = ok(
        QRWallet::build_qr_png_bytes(&address),
        "all-f valid wallet QR should build",
    )?;

    assert_png(&bytes);
    Ok(())
}

#[test]
fn wallet_qr_055_all_zero_and_all_f_valid_wallet_vectors_produce_different_qr_pngs() -> TestResult {
    let zero = format!("r{}", "0".repeat(128));
    let ffff = format!("r{}", "f".repeat(128));

    let zero_png = ok(QRWallet::build_qr_png_bytes(&zero), "zero QR should build")?;
    let f_png = ok(QRWallet::build_qr_png_bytes(&ffff), "f QR should build")?;

    assert_ne!(zero, ffff);
    assert_ne!(zero_png, f_png);
    Ok(())
}

#[test]
fn wallet_qr_056_qr_payload_rejects_internal_space() -> TestResult {
    let bad = format!("r{} {}", "a".repeat(63), "b".repeat(64));

    assert_validation_error(QRWallet::qr_payload(&bad))?;
    Ok(())
}

#[test]
fn wallet_qr_057_qr_payload_rejects_internal_newline() -> TestResult {
    let bad = format!("r{}\n{}", "a".repeat(63), "b".repeat(64));

    assert_validation_error(QRWallet::qr_payload(&bad))?;
    Ok(())
}

#[test]
fn wallet_qr_058_qr_payload_rejects_internal_tab() -> TestResult {
    let bad = format!("r{}\t{}", "a".repeat(63), "b".repeat(64));

    assert_validation_error(QRWallet::qr_payload(&bad))?;
    Ok(())
}

#[test]
fn wallet_qr_059_qr_payload_rejects_hex_without_prefix() -> TestResult {
    assert_validation_error(QRWallet::qr_payload(&"a".repeat(128)))?;
    Ok(())
}

#[test]
fn wallet_qr_060_qr_payload_accepts_uppercase_r_prefix_by_canonicalizing() -> TestResult {
    let wallet = test_wallet();
    let mut upper_prefix = wallet.address.clone();
    upper_prefix.replace_range(0..1, "R");

    let payload = ok(
        QRWallet::qr_payload(&upper_prefix),
        "uppercase R prefix should canonicalize",
    )?;

    assert_eq!(payload, wallet.address);
    Ok(())
}

#[test]
fn wallet_qr_061_qr_payload_rejects_nul_byte_inside_address() -> TestResult {
    let bad = format!("r{}\0{}", "a".repeat(63), "b".repeat(64));

    assert_validation_error(QRWallet::qr_payload(&bad))?;
    Ok(())
}

#[test]
fn wallet_qr_062_qr_payload_contains_no_public_key_encrypted_secret_or_passphrase() -> TestResult {
    let wallet = test_wallet();

    let payload = ok(
        QRWallet::qr_payload(&wallet.address),
        "qr_payload should succeed",
    )?;

    assert_eq!(payload, wallet.address);
    assert!(!payload.contains(TEST_PASSPHRASE));
    assert!(!payload.contains(&hex::encode(wallet.public)));
    assert!(!payload.contains(&hex::encode(&wallet.encrypted_secret)));
    Ok(())
}

#[test]
fn wallet_qr_063_wallet_qr_output_dir_rejects_qr_dir_path_that_is_file() -> TestResult {
    let data_dir = temp_dir("qr-dir-is-file")?;
    let opts = node_opts(&data_dir);

    fs::write(data_dir.join("qr_code_wallet"), b"I am a file")
        .map_err(|e| format!("failed to create qr_code_wallet file: {e}"))?;

    assert_validation_error(QRWallet::wallet_qr_output_dir(&opts))?;
    Ok(())
}

#[test]
fn wallet_qr_064_generate_for_owned_wallet_rejects_qr_dir_path_that_is_file() -> TestResult {
    let data_dir = temp_dir("generate-qr-dir-is-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    fs::write(data_dir.join("qr_code_wallet"), b"I am a file")
        .map_err(|e| format!("failed to create qr_code_wallet file: {e}"))?;

    assert_validation_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_065_write_qr_png_for_verified_wallet_rejects_qr_dir_path_that_is_file() -> TestResult {
    let data_dir = temp_dir("write-verified-qr-dir-is-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    fs::write(data_dir.join("qr_code_wallet"), b"I am a file")
        .map_err(|e| format!("failed to create qr_code_wallet file: {e}"))?;

    assert_validation_error(QRWallet::write_qr_png_for_verified_wallet(&opts, wallet))?;
    Ok(())
}

#[test]
fn wallet_qr_066_generate_for_two_owned_wallets_creates_two_png_files() -> TestResult {
    let data_dir = temp_dir("two-owned-wallets")?;
    let opts = node_opts(&data_dir);
    let first = test_wallet();
    let second = other_wallet();

    write_wallet_file(&opts, first)?;
    write_wallet_file(&opts, second)?;

    let first_receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &first.address, TEST_PASSPHRASE),
        "first wallet QR should generate",
    )?;
    let second_receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &second.address, OTHER_PASSPHRASE),
        "second wallet QR should generate",
    )?;

    assert_ne!(first_receipt.wallet_address, second_receipt.wallet_address);
    assert_ne!(first_receipt.qr_png_path, second_receipt.qr_png_path);

    let qr_dir = data_dir.join("qr_code_wallet");
    let entries = fs::read_dir(&qr_dir)
        .map_err(|e| format!("failed to read qr dir {}: {e}", qr_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to collect qr entries: {e}"))?;

    assert_eq!(entries.len(), 2);
    assert!(first_receipt.qr_png_path.exists());
    assert!(second_receipt.qr_png_path.exists());
    Ok(())
}

#[test]
fn wallet_qr_067_generate_for_two_owned_wallets_outputs_different_png_bytes() -> TestResult {
    let data_dir = temp_dir("two-owned-wallets-different-bytes")?;
    let opts = node_opts(&data_dir);
    let first = test_wallet();
    let second = other_wallet();

    write_wallet_file(&opts, first)?;
    write_wallet_file(&opts, second)?;

    let first_receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &first.address, TEST_PASSPHRASE),
        "first wallet QR should generate",
    )?;
    let second_receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &second.address, OTHER_PASSPHRASE),
        "second wallet QR should generate",
    )?;

    let first_png = read_qr_png(&first_receipt.qr_png_path)?;
    let second_png = read_qr_png(&second_receipt.qr_png_path)?;

    assert_png(&first_png);
    assert_png(&second_png);
    assert_ne!(first_png, second_png);
    Ok(())
}

#[test]
fn wallet_qr_068_load_owned_wallet_rejects_one_byte_wallet_file() -> TestResult {
    let data_dir = temp_dir("one-byte-wallet-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;
    fs::write(&wallet_path, [1_u8])
        .map_err(|e| format!("failed to write one-byte wallet file: {e}"))?;

    assert_any_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_069_load_owned_wallet_rejects_truncated_real_wallet_file() -> TestResult {
    let data_dir = temp_dir("truncated-real-wallet-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;

    let truncated_len = wallet.encrypted_secret.len().min(16);
    fs::write(&wallet_path, &wallet.encrypted_secret[..truncated_len])
        .map_err(|e| format!("failed to write truncated wallet file: {e}"))?;

    assert_any_error(QRWallet::load_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_070_generate_for_owned_wallet_corrupt_wallet_file_leaves_no_qr_dir() -> TestResult {
    let data_dir = temp_dir("corrupt-generate-no-qr-dir")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = wallet_file_path(&opts, &wallet.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;
    fs::write(&wallet_path, b"corrupt")
        .map_err(|e| format!("failed to write corrupt wallet file: {e}"))?;

    assert_any_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_071_generate_for_owned_wallet_address_mismatch_leaves_no_qr_dir() -> TestResult {
    let data_dir = temp_dir("address-mismatch-no-qr-dir")?;
    let opts = node_opts(&data_dir);
    let requested = test_wallet();
    let actual_file_wallet = other_wallet();

    let wallet_path = wallet_file_path(&opts, &requested.address)?;
    fs::create_dir_all(
        wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;
    fs::write(&wallet_path, &actual_file_wallet.encrypted_secret)
        .map_err(|e| format!("failed to write mismatched wallet file: {e}"))?;

    assert_validation_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &requested.address,
        OTHER_PASSPHRASE,
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_072_generated_png_matches_build_qr_png_bytes_for_same_wallet() -> TestResult {
    let data_dir = temp_dir("generated-matches-build")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let generated = read_qr_png(&receipt.qr_png_path)?;
    let expected = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "build_qr_png_bytes should succeed",
    )?;

    assert_eq!(generated, expected);
    Ok(())
}

#[test]
fn wallet_qr_073_write_verified_png_matches_build_qr_png_bytes_for_same_wallet() -> TestResult {
    let data_dir = temp_dir("write-verified-matches-build")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let receipt = ok(
        QRWallet::write_qr_png_for_verified_wallet(&opts, wallet),
        "write verified should succeed",
    )?;

    let generated = read_qr_png(&receipt.qr_png_path)?;
    let expected = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "build_qr_png_bytes should succeed",
    )?;

    assert_eq!(generated, expected);
    Ok(())
}

#[test]
fn wallet_qr_074_generate_for_owned_wallet_leaves_no_png_tmp_file() -> TestResult {
    let data_dir = temp_dir("no-temp-after-generate")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let tmp_path = receipt.qr_png_path.with_extension("png.tmp");

    assert!(receipt.qr_png_path.exists());
    assert!(!tmp_path.exists());
    Ok(())
}

#[test]
fn wallet_qr_075_generate_for_owned_wallet_removes_stale_png_tmp_file() -> TestResult {
    let data_dir = temp_dir("stale-temp-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let qr_dir = data_dir.join("qr_code_wallet");
    fs::create_dir_all(&qr_dir).map_err(|e| format!("failed to create qr dir: {e}"))?;

    let expected_png = qr_dir.join(format!("wallet_{}_qr.png", wallet.address));
    let tmp_path = expected_png.with_extension("png.tmp");

    fs::write(&tmp_path, b"stale-temp")
        .map_err(|e| format!("failed to write stale temp file: {e}"))?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed and replace stale temp",
    )?;

    assert_eq!(receipt.qr_png_path, expected_png);
    assert!(receipt.qr_png_path.exists());
    assert!(!tmp_path.exists());

    let bytes = read_qr_png(&receipt.qr_png_path)?;
    assert_png(&bytes);
    Ok(())
}

#[test]
fn wallet_qr_076_generate_for_owned_wallet_rejects_output_png_path_that_is_directory() -> TestResult
{
    let data_dir = temp_dir("output-png-path-is-directory")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let qr_dir = data_dir.join("qr_code_wallet");
    fs::create_dir_all(&qr_dir).map_err(|e| format!("failed to create qr dir: {e}"))?;

    let expected_png = qr_dir.join(format!("wallet_{}_qr.png", wallet.address));
    fs::create_dir_all(&expected_png)
        .map_err(|e| format!("failed to create directory at output png path: {e}"))?;

    assert_validation_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_077_generate_for_owned_wallet_rejects_tmp_path_that_is_directory() -> TestResult {
    let data_dir = temp_dir("tmp-path-is-directory")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let qr_dir = data_dir.join("qr_code_wallet");
    fs::create_dir_all(&qr_dir).map_err(|e| format!("failed to create qr dir: {e}"))?;

    let expected_png = qr_dir.join(format!("wallet_{}_qr.png", wallet.address));
    let tmp_path = expected_png.with_extension("png.tmp");

    fs::create_dir_all(&tmp_path)
        .map_err(|e| format!("failed to create directory at tmp path: {e}"))?;

    assert_validation_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        TEST_PASSPHRASE,
    ))?;
    Ok(())
}

#[test]
fn wallet_qr_078_generate_for_owned_wallet_allows_existing_qr_directory_with_other_file()
-> TestResult {
    let data_dir = temp_dir("existing-qr-dir-other-file")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let qr_dir = data_dir.join("qr_code_wallet");
    fs::create_dir_all(&qr_dir).map_err(|e| format!("failed to create qr dir: {e}"))?;

    let keep_file = qr_dir.join("keep.txt");
    fs::write(&keep_file, b"keep me").map_err(|e| format!("failed to write keep file: {e}"))?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    assert!(keep_file.exists());
    assert!(receipt.qr_png_path.exists());

    let entries = fs::read_dir(&qr_dir)
        .map_err(|e| format!("failed to read qr dir: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to collect qr entries: {e}"))?;

    assert_eq!(entries.len(), 2);
    Ok(())
}

#[test]
fn wallet_qr_079_load_owned_wallet_does_not_create_qr_output_directory() -> TestResult {
    let data_dir = temp_dir("load-does-not-create-qr-dir")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let loaded = ok(
        QRWallet::load_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "load owned wallet should succeed",
    )?;

    assert_eq!(loaded.address, wallet.address);
    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_080_write_qr_png_for_verified_wallet_does_not_require_wallets_directory() -> TestResult
{
    let data_dir = temp_dir("write-verified-no-wallets-dir")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let receipt = ok(
        QRWallet::write_qr_png_for_verified_wallet(&opts, wallet),
        "write verified should succeed",
    )?;

    assert!(receipt.qr_png_path.exists());
    assert!(!data_dir.join("000.wallets").exists());
    assert!(data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_081_write_qr_png_for_verified_wallet_works_for_second_wallet() -> TestResult {
    let data_dir = temp_dir("write-verified-second-wallet")?;
    let opts = node_opts(&data_dir);
    let wallet = other_wallet();

    let receipt = ok(
        QRWallet::write_qr_png_for_verified_wallet(&opts, wallet),
        "write verified should succeed for second wallet",
    )?;

    assert_receipt_shape(&receipt, &wallet.address);

    let bytes = read_qr_png(&receipt.qr_png_path)?;
    assert_png(&bytes);
    Ok(())
}

#[test]
fn wallet_qr_082_generate_for_owned_wallet_with_trimmed_address_returns_canonical_receipt()
-> TestResult {
    let data_dir = temp_dir("generate-trimmed-address")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(
            &opts,
            &format!("  {}  ", wallet.address),
            TEST_PASSPHRASE,
        ),
        "generate should succeed with trimmed address",
    )?;

    assert_eq!(receipt.wallet_address, wallet.address);
    assert_receipt_shape(&receipt, &wallet.address);
    Ok(())
}

#[test]
fn wallet_qr_083_generate_for_owned_wallet_rejects_absurdly_long_passphrase_and_no_qr_dir()
-> TestResult {
    let data_dir = temp_dir("generate-long-passphrase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let too_long = "x".repeat(QRWallet::MAX_PASSPHRASE_BYTES + 1);

    assert_validation_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        &too_long,
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_084_generate_for_owned_wallet_rejects_empty_passphrase_and_no_qr_dir() -> TestResult {
    let data_dir = temp_dir("generate-empty-passphrase")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    assert_validation_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &wallet.address,
        "",
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_085_receipt_debug_string_contains_public_path_but_not_secrets() -> TestResult {
    let data_dir = temp_dir("receipt-debug")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let debug = format!("{receipt:?}");

    assert!(debug.contains(&wallet.address));
    assert!(debug.contains("qr_png_path"));
    assert!(!debug.contains(TEST_PASSPHRASE));
    assert!(!debug.contains(&hex::encode(wallet.public)));
    assert!(!debug.contains(&hex::encode(&wallet.encrypted_secret)));
    Ok(())
}

#[test]
fn wallet_qr_086_receipt_clone_and_equality_are_stable() -> TestResult {
    let data_dir = temp_dir("receipt-clone-eq")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let cloned = receipt.clone();

    assert_eq!(receipt, cloned);
    assert_eq!(receipt.wallet_address, cloned.wallet_address);
    assert_eq!(receipt.qr_png_path, cloned.qr_png_path);
    assert_eq!(receipt.qr_payload_bytes_len, cloned.qr_payload_bytes_len);
    Ok(())
}

#[test]
fn wallet_qr_087_receipt_json_roundtrip_preserves_public_metadata() -> TestResult {
    let data_dir = temp_dir("receipt-json-roundtrip")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let json =
        serde_json::to_string(&receipt).map_err(|e| format!("serialize receipt failed: {e}"))?;
    let decoded: QRWalletReceipt =
        serde_json::from_str(&json).map_err(|e| format!("deserialize receipt failed: {e}"))?;

    assert_eq!(decoded, receipt);
    assert_eq!(decoded.wallet_address, wallet.address);
    assert_eq!(decoded.qr_payload_bytes_len, REMZAR_WALLET_LEN);
    Ok(())
}

#[test]
fn wallet_qr_088_qr_output_file_permissions_are_readable_after_write() -> TestResult {
    let data_dir = temp_dir("readable-output")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let meta =
        fs::metadata(&receipt.qr_png_path).map_err(|e| format!("failed to stat qr png: {e}"))?;

    assert!(meta.is_file());
    assert!(meta.len() > 8);
    Ok(())
}

#[test]
fn wallet_qr_089_qr_png_size_is_under_declared_cap_for_real_wallet() -> TestResult {
    let wallet = test_wallet();

    let bytes = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "build qr should succeed",
    )?;

    assert_png(&bytes);
    assert!(bytes.len() <= QRWallet::MAX_QR_PNG_BYTES);
    Ok(())
}

#[test]
fn wallet_qr_090_qr_png_size_is_under_declared_cap_for_synthetic_extreme_vectors() -> TestResult {
    let zero = format!("r{}", "0".repeat(128));
    let ffff = format!("r{}", "f".repeat(128));

    let zero_png = ok(QRWallet::build_qr_png_bytes(&zero), "zero png should build")?;
    let f_png = ok(QRWallet::build_qr_png_bytes(&ffff), "f png should build")?;

    assert_png(&zero_png);
    assert_png(&f_png);
    assert!(zero_png.len() <= QRWallet::MAX_QR_PNG_BYTES);
    assert!(f_png.len() <= QRWallet::MAX_QR_PNG_BYTES);
    Ok(())
}

#[test]
fn wallet_qr_091_generate_for_owned_wallet_does_not_write_json_or_pdf_files() -> TestResult {
    let data_dir = temp_dir("no-json-no-pdf")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let qr_dir = receipt
        .qr_png_path
        .parent()
        .ok_or_else(|| "qr path should have parent".to_string())?;

    for entry in fs::read_dir(qr_dir).map_err(|e| format!("failed to read qr dir: {e}"))? {
        let path = entry
            .map_err(|e| format!("failed to read dir entry: {e}"))?
            .path();
        let ext = path.extension().and_then(|s| s.to_str());
        assert_ne!(ext, Some("json"));
        assert_ne!(ext, Some("pdf"));
    }

    Ok(())
}

#[test]
fn wallet_qr_092_generate_for_owned_wallet_does_not_modify_wallet_file_bytes() -> TestResult {
    let data_dir = temp_dir("wallet-file-not-modified")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = write_wallet_file(&opts, wallet)?;
    let before = fs::read(&wallet_path)
        .map_err(|e| format!("failed to read wallet before generate: {e}"))?;

    let _receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let after =
        fs::read(&wallet_path).map_err(|e| format!("failed to read wallet after generate: {e}"))?;

    assert_eq!(before, after);
    Ok(())
}

#[test]
fn wallet_qr_093_load_owned_wallet_does_not_modify_wallet_file_bytes() -> TestResult {
    let data_dir = temp_dir("load-wallet-not-modified")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    let wallet_path = write_wallet_file(&opts, wallet)?;
    let before =
        fs::read(&wallet_path).map_err(|e| format!("failed to read wallet before load: {e}"))?;

    let _loaded = ok(
        QRWallet::load_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "load should succeed",
    )?;

    let after =
        fs::read(&wallet_path).map_err(|e| format!("failed to read wallet after load: {e}"))?;

    assert_eq!(before, after);
    Ok(())
}

#[test]
fn wallet_qr_094_generate_for_owned_wallet_replaces_output_with_same_canonical_bytes() -> TestResult
{
    let data_dir = temp_dir("replace-same-canonical-bytes")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let first = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "first generate should succeed",
    )?;
    let first_bytes = read_qr_png(&first.qr_png_path)?;

    fs::write(&first.qr_png_path, b"bad replacement")
        .map_err(|e| format!("failed to write bad replacement: {e}"))?;

    let second = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "second generate should succeed",
    )?;
    let second_bytes = read_qr_png(&second.qr_png_path)?;

    assert_eq!(first.qr_png_path, second.qr_png_path);
    assert_eq!(first_bytes, second_bytes);
    Ok(())
}

#[test]
fn wallet_qr_095_generated_file_name_has_no_spaces_newlines_or_path_separators() -> TestResult {
    let data_dir = temp_dir("safe-file-name")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "generate should succeed",
    )?;

    let file_name = receipt
        .qr_png_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "file name should be valid utf8".to_string())?;

    assert!(!file_name.contains(' '));
    assert!(!file_name.contains('\n'));
    assert!(!file_name.contains('\t'));
    assert!(!file_name.contains('/'));
    assert!(!file_name.contains('\\'));
    assert!(file_name.starts_with("wallet_"));
    assert!(file_name.ends_with("_qr.png"));
    Ok(())
}

#[test]
fn wallet_qr_096_qr_payload_exact_length_for_multiple_valid_vectors() -> TestResult {
    let vectors = vec![
        test_wallet().address.clone(),
        other_wallet().address.clone(),
        format!("r{}", "0".repeat(128)),
        format!("r{}", "f".repeat(128)),
        format!("r{}", "abcdef0123456789".repeat(8)),
    ];

    for vector in vectors {
        let payload = ok(
            QRWallet::qr_payload(&vector),
            "payload vector should succeed",
        )?;
        assert_eq!(payload.len(), REMZAR_WALLET_LEN);
        assert_eq!(payload.as_bytes().first(), Some(&b'r'));
    }

    Ok(())
}

#[test]
fn wallet_qr_097_build_qr_png_bytes_rejects_multiple_invalid_vectors() -> TestResult {
    let invalid_vectors = vec![
        "".to_string(),
        "r".to_string(),
        "x".repeat(129),
        format!("r{}", "z".repeat(128)),
        format!("r{}", "a".repeat(127)),
        format!("r{}", "a".repeat(129)),
        format!("r{}\n{}", "a".repeat(63), "b".repeat(64)),
    ];

    for vector in invalid_vectors {
        assert_validation_error(QRWallet::build_qr_png_bytes(&vector))?;
    }

    Ok(())
}

#[test]
fn wallet_qr_098_generate_for_owned_wallet_rejects_multiple_invalid_vectors_before_qr_dir()
-> TestResult {
    let data_dir = temp_dir("invalid-vectors-before-qr-dir")?;
    let opts = node_opts(&data_dir);

    let invalid_vectors = vec![
        "".to_string(),
        "not-a-wallet".to_string(),
        format!("x{}", "a".repeat(128)),
        format!("r{}", "g".repeat(128)),
        format!("r{}", "a".repeat(127)),
        format!("r{}", "a".repeat(129)),
    ];

    for vector in invalid_vectors {
        assert_validation_error(QRWallet::generate_for_owned_wallet(
            &opts,
            &vector,
            TEST_PASSPHRASE,
        ))?;
    }

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_099_generate_for_owned_wallet_with_wrong_wallet_file_passphrase_pair_fails()
-> TestResult {
    let data_dir = temp_dir("wrong-wallet-file-passphrase-pair")?;
    let opts = node_opts(&data_dir);
    let requested = test_wallet();
    let wrong_wallet = other_wallet();

    let requested_wallet_path = wallet_file_path(&opts, &requested.address)?;
    fs::create_dir_all(
        requested_wallet_path
            .parent()
            .ok_or("wallet path should have parent")?,
    )
    .map_err(|e| format!("failed to create wallet dir: {e}"))?;

    fs::write(&requested_wallet_path, &wrong_wallet.encrypted_secret)
        .map_err(|e| format!("failed to write wrong wallet file: {e}"))?;

    assert_cryptographic_error(QRWallet::generate_for_owned_wallet(
        &opts,
        &requested.address,
        TEST_PASSPHRASE,
    ))?;

    assert!(!data_dir.join("qr_code_wallet").exists());
    Ok(())
}

#[test]
fn wallet_qr_100_full_success_vector_generates_expected_receipt_path_payload_and_png() -> TestResult
{
    let data_dir = temp_dir("full-success-vector")?;
    let opts = node_opts(&data_dir);
    let wallet = test_wallet();

    write_wallet_file(&opts, wallet)?;

    let receipt = ok(
        QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE),
        "full success vector should generate",
    )?;

    let expected_dir = data_dir.join("qr_code_wallet");
    let expected_path = expected_dir.join(format!("wallet_{}_qr.png", wallet.address));

    assert_eq!(receipt.wallet_address, wallet.address);
    assert_eq!(receipt.qr_payload_bytes_len, REMZAR_WALLET_LEN);
    assert_eq!(receipt.qr_png_path, expected_path);
    assert!(receipt.qr_png_path.exists());

    let payload = ok(
        QRWallet::qr_payload(&receipt.wallet_address),
        "payload should rebuild",
    )?;
    assert_eq!(payload, wallet.address);

    let png = read_qr_png(&receipt.qr_png_path)?;
    let expected_png = ok(
        QRWallet::build_qr_png_bytes(&wallet.address),
        "expected png should build",
    )?;

    assert_png(&png);
    assert_eq!(png, expected_png);
    Ok(())
}
