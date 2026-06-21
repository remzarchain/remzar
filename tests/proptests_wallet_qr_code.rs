// tests/proptests_wallet_qr_code.rs

use proptest::prelude::*;
use proptest::string::string_regex;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::helper::REMZAR_WALLET_LEN;
use remzar::utility::wallet_qr_code::{QRWallet, QRWalletReceipt};

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_PASSPHRASE: &str = "remzar-wallet-qr-proptest-passphrase-2026!";

static TEST_WALLET: OnceLock<MLDSA65Wallet> = OnceLock::new();
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_wallet() -> &'static MLDSA65Wallet {
    TEST_WALLET.get_or_init(|| {
        MLDSA65Wallet::new(TEST_PASSPHRASE).expect("test wallet generation should succeed")
    })
}

fn temp_dir(label: &str) -> Result<PathBuf, String> {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e:?}"))?
        .as_nanos();

    let safe_label = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();

    let path = std::env::temp_dir().join(format!(
        "remzar_wallet_qr_prop_tests_{}_{}_{}_{}",
        std::process::id(),
        nanos,
        counter,
        safe_label
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

fn assert_png(bytes: &[u8]) -> Result<(), TestCaseError> {
    prop_assert!(bytes.len() > 8);
    prop_assert_eq!(
        &bytes[..8],
        &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n']
    );
    Ok(())
}

fn receipt_shape_is_valid(receipt: &QRWalletReceipt, expected_wallet: &str) -> bool {
    receipt.wallet_address == expected_wallet
        && receipt.wallet_address.len() == REMZAR_WALLET_LEN
        && receipt.qr_payload_bytes_len == REMZAR_WALLET_LEN
        && receipt.qr_png_path.exists()
        && receipt.qr_png_path.extension().and_then(|s| s.to_str()) == Some("png")
}

fn lower_hex_body_128() -> BoxedStrategy<String> {
    string_regex("[0-9a-f]{128}")
        .expect("valid lower hex regex")
        .boxed()
}

fn mixed_hex_body_128() -> BoxedStrategy<String> {
    string_regex("[0-9a-fA-F]{128}")
        .expect("valid mixed hex regex")
        .boxed()
}

fn valid_wallet_lower() -> BoxedStrategy<String> {
    lower_hex_body_128()
        .prop_map(|body| format!("r{body}"))
        .boxed()
}

fn valid_wallet_mixed_case() -> BoxedStrategy<String> {
    (prop_oneof![Just('r'), Just('R')], mixed_hex_body_128())
        .prop_map(|(prefix, body)| format!("{prefix}{body}"))
        .boxed()
}

fn whitespace_wrapper() -> BoxedStrategy<(String, String)> {
    (
        prop_oneof![
            Just("".to_string()),
            Just(" ".to_string()),
            Just("  ".to_string()),
            Just("\t".to_string()),
            Just("\n".to_string()),
            Just(" \t".to_string()),
        ],
        prop_oneof![
            Just("".to_string()),
            Just(" ".to_string()),
            Just("  ".to_string()),
            Just("\t".to_string()),
            Just("\n".to_string()),
            Just("\t ".to_string()),
        ],
    )
        .boxed()
}

fn safe_dir_leaf() -> BoxedStrategy<String> {
    string_regex("[a-zA-Z0-9_-]{1,32}")
        .expect("valid safe dir leaf regex")
        .boxed()
}

fn non_hex_char() -> BoxedStrategy<char> {
    prop_oneof![
        Just('g'),
        Just('G'),
        Just('z'),
        Just('Z'),
        Just('/'),
        Just('\\'),
        Just('_'),
        Just('-'),
        Just(':'),
        Just('{'),
        Just('}'),
        Just(' '),
        Just('\n'),
        Just('\t'),
        Just('\0'),
    ]
    .boxed()
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn wallet_qr_prop_001_valid_lowercase_wallet_payload_is_exact_address(
        wallet_address in valid_wallet_lower()
    ) {
        let payload = QRWallet::qr_payload(&wallet_address)
            .expect("valid lowercase wallet address must produce payload");

        prop_assert_eq!(&payload, &wallet_address);
        prop_assert_eq!(payload.len(), REMZAR_WALLET_LEN);
        prop_assert_eq!(payload.as_bytes().first(), Some(&b'r'));
        prop_assert_eq!(&payload, &payload.to_ascii_lowercase());
    }

    // 02/25
    #[test]
    fn wallet_qr_prop_002_mixed_case_wallet_payload_canonicalizes_to_lowercase(
        wallet_address in valid_wallet_mixed_case()
    ) {
        let payload = QRWallet::qr_payload(&wallet_address)
            .expect("valid mixed-case wallet address must canonicalize");

        let expected = wallet_address.trim().to_ascii_lowercase();

        prop_assert_eq!(payload.len(), REMZAR_WALLET_LEN);
        prop_assert_eq!(&payload, &expected);
        prop_assert_eq!(payload.as_bytes().first(), Some(&b'r'));
    }

    // 03/25
    #[test]
    fn wallet_qr_prop_003_wallet_payload_trims_boundary_whitespace_only(
        wallet_address in valid_wallet_lower(),
        (prefix, suffix) in whitespace_wrapper(),
    ) {
        let wrapped = format!("{prefix}{wallet_address}{suffix}");

        let payload = QRWallet::qr_payload(&wrapped)
            .expect("valid wallet address with surrounding whitespace must canonicalize");

        prop_assert_eq!(&payload, &wallet_address);
        prop_assert_eq!(payload.len(), REMZAR_WALLET_LEN);
    }

    // 04/25
    #[test]
    fn wallet_qr_prop_004_wrong_lengths_are_rejected(
        len in 0usize..260usize,
        fill in "[0-9a-f]{0,260}",
    ) {
        prop_assume!(len != REMZAR_WALLET_LEN);

        let body_len = len.saturating_sub(1);
        let body = fill
            .chars()
            .cycle()
            .take(body_len)
            .collect::<String>();

        let candidate = if len == 0 {
            String::new()
        } else {
            format!("r{body}")
        };

        prop_assert!(
            QRWallet::qr_payload(&candidate).is_err(),
            "wallet address with wrong length {len} must be rejected"
        );
    }

    // 05/25
    #[test]
    fn wallet_qr_prop_005_wrong_prefix_is_rejected_even_with_valid_hex_body(
        prefix in prop_oneof![Just('x'), Just('p'), Just('0'), Just('1'), Just('_'), Just('/')],
        body in lower_hex_body_128(),
    ) {
        let candidate = format!("{prefix}{body}");

        prop_assert!(
            QRWallet::qr_payload(&candidate).is_err(),
            "wrong prefix must be rejected"
        );
    }

    // 06/25
    #[test]
    fn wallet_qr_prop_006_any_non_hex_body_character_is_rejected(
        body in lower_hex_body_128(),
        index in 0usize..128usize,
        bad_char in non_hex_char(),
    ) {
        prop_assume!(!bad_char.is_ascii_hexdigit());

        let mut chars = body.chars().collect::<Vec<_>>();
        chars[index] = bad_char;

        let candidate = format!("r{}", chars.into_iter().collect::<String>());

        prop_assert!(
            QRWallet::qr_payload(&candidate).is_err(),
            "non-hex body character at index {index} must be rejected"
        );
    }

    // 07/25
    #[test]
    fn wallet_qr_prop_007_arbitrary_external_payload_input_never_panics(
        candidate in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let input = String::from_utf8_lossy(&candidate).to_string();

        let result = std::panic::catch_unwind(|| QRWallet::qr_payload(&input));

        prop_assert!(
            result.is_ok(),
            "qr_payload must never panic for arbitrary external input"
        );

        let parsed = result.expect("panic checked above");

        if let Ok(payload) = parsed {
            prop_assert_eq!(payload.len(), REMZAR_WALLET_LEN);
            prop_assert_eq!(payload.as_bytes().first(), Some(&b'r'));
            prop_assert_eq!(&payload, &payload.to_ascii_lowercase());
            prop_assert!(payload.as_bytes()[1..].iter().all(|b| b.is_ascii_hexdigit()));
        }
    }

    // 08/25
    #[test]
    fn wallet_qr_prop_008_valid_wallet_builds_png_under_declared_cap(
        wallet_address in valid_wallet_lower()
    ) {
        let bytes = QRWallet::build_qr_png_bytes(&wallet_address)
            .expect("valid wallet address must build QR PNG");

        assert_png(&bytes)?;
        prop_assert!(bytes.len() <= QRWallet::MAX_QR_PNG_BYTES);
    }

    // 09/25
    #[test]
    fn wallet_qr_prop_009_png_generation_is_deterministic_for_same_canonical_wallet(
        wallet_address in valid_wallet_lower()
    ) {
        let first = QRWallet::build_qr_png_bytes(&wallet_address)
            .expect("first QR PNG build must succeed");
        let second = QRWallet::build_qr_png_bytes(&wallet_address)
            .expect("second QR PNG build must succeed");

        prop_assert_eq!(&first, &second);
        assert_png(&first)?;
    }

    // 10/25
    #[test]
    fn wallet_qr_prop_010_png_generation_is_case_canonical(
        wallet_address in valid_wallet_mixed_case()
    ) {
        let canonical = QRWallet::qr_payload(&wallet_address)
            .expect("valid wallet must canonicalize");

        let mixed_png = QRWallet::build_qr_png_bytes(&wallet_address)
            .expect("mixed case QR PNG must build");
        let canonical_png = QRWallet::build_qr_png_bytes(&canonical)
            .expect("canonical QR PNG must build");

        prop_assert_eq!(&mixed_png, &canonical_png);
    }

    // 11/25
    #[test]
    fn wallet_qr_prop_011_distinct_wallet_payloads_produce_distinct_pngs(
        first in valid_wallet_lower(),
        second in valid_wallet_lower(),
    ) {
        prop_assume!(first != second);

        let first_png = QRWallet::build_qr_png_bytes(&first)
            .expect("first valid QR PNG must build");
        let second_png = QRWallet::build_qr_png_bytes(&second)
            .expect("second valid QR PNG must build");

        prop_assert_ne!(&first_png, &second_png);
    }

    // 12/25
    #[test]
    fn wallet_qr_prop_012_invalid_address_png_build_fails_without_panic(
        candidate in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let input = String::from_utf8_lossy(&candidate).to_string();
        let canonical_ok = QRWallet::qr_payload(&input).is_ok();

        prop_assume!(!canonical_ok);

        let result = std::panic::catch_unwind(|| QRWallet::build_qr_png_bytes(&input));

        prop_assert!(
            result.is_ok(),
            "build_qr_png_bytes must not panic on invalid address input"
        );
        prop_assert!(
            result.expect("panic checked above").is_err(),
            "invalid address input must fail QR PNG generation"
        );
    }

    // 13/25
    #[test]
    fn wallet_qr_prop_013_output_dir_is_exactly_data_dir_qr_code_wallet(
        leaf in safe_dir_leaf()
    ) {
        let root = temp_dir("prop-output-dir-root")
            .map_err(TestCaseError::fail)?;
        let data_dir = root.join(leaf);
        let opts = node_opts(&data_dir);

        let qr_dir = QRWallet::wallet_qr_output_dir(&opts)
            .map_err(|e| TestCaseError::fail(format!("wallet_qr_output_dir failed: {e:?}")))?;

        prop_assert!(qr_dir.exists());
        prop_assert!(qr_dir.is_dir());
        prop_assert_eq!(&qr_dir, &data_dir.join(QRWallet::WALLET_QR_DIR_NAME));
    }

    // 14/25
    #[test]
    fn wallet_qr_prop_014_output_dir_creation_is_idempotent(
        leaf in safe_dir_leaf()
    ) {
        let root = temp_dir("prop-output-dir-idempotent-root")
            .map_err(TestCaseError::fail)?;
        let data_dir = root.join(leaf);
        let opts = node_opts(&data_dir);

        let first = QRWallet::wallet_qr_output_dir(&opts)
            .map_err(|e| TestCaseError::fail(format!("first output dir call failed: {e:?}")))?;
        let second = QRWallet::wallet_qr_output_dir(&opts)
            .map_err(|e| TestCaseError::fail(format!("second output dir call failed: {e:?}")))?;

        prop_assert_eq!(&first, &second);
        prop_assert!(second.exists());
        prop_assert!(second.is_dir());
    }

    // 15/25
    #[test]
    fn wallet_qr_prop_015_output_dir_rejects_qr_dir_file_collision(
        leaf in safe_dir_leaf(),
        contents in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let root = temp_dir("prop-output-dir-file-collision-root")
            .map_err(TestCaseError::fail)?;
        let data_dir = root.join(leaf);

        fs::create_dir_all(&data_dir)
            .map_err(|e| TestCaseError::fail(format!("create data dir failed: {e}")))?;

        let qr_file = data_dir.join(QRWallet::WALLET_QR_DIR_NAME);

        fs::write(&qr_file, contents)
            .map_err(|e| TestCaseError::fail(format!("write qr dir collision file failed: {e}")))?;

        let opts = node_opts(&data_dir);

        prop_assert!(
            QRWallet::wallet_qr_output_dir(&opts).is_err(),
            "qr_code_wallet path that is a file must be rejected"
        );
    }

    // 16/25
    #[test]
    fn wallet_qr_prop_016_load_owned_wallet_accepts_canonicalized_user_input(
        (prefix_ws, suffix_ws) in whitespace_wrapper(),
        uppercase in any::<bool>(),
    ) {
        let data_dir = temp_dir("prop-load-owned-canonicalized")
            .map_err(TestCaseError::fail)?;
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        write_wallet_file(&opts, wallet)
            .map_err(TestCaseError::fail)?;

        let address_input = if uppercase {
            wallet.address.to_ascii_uppercase()
        } else {
            wallet.address.clone()
        };
        let wrapped = format!("{prefix_ws}{address_input}{suffix_ws}");

        let loaded = QRWallet::load_owned_wallet(&opts, &wrapped, TEST_PASSPHRASE)
            .map_err(|e| TestCaseError::fail(format!("load_owned_wallet failed: {e:?}")))?;

        prop_assert_eq!(&loaded.address, &wallet.address);
        prop_assert_eq!(&loaded.public, &wallet.public);
    }

    // 17/25
    #[test]
    fn wallet_qr_prop_017_load_owned_wallet_rejects_wrong_nonempty_passphrases(
        wrong_passphrase in ".{1,128}"
    ) {
        prop_assume!(wrong_passphrase != TEST_PASSPHRASE);

        let data_dir = temp_dir("prop-load-wrong-passphrase")
            .map_err(TestCaseError::fail)?;
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        write_wallet_file(&opts, wallet)
            .map_err(TestCaseError::fail)?;

        prop_assert!(
            QRWallet::load_owned_wallet(&opts, &wallet.address, &wrong_passphrase).is_err(),
            "wrong passphrase must not authenticate wallet ownership"
        );
    }

    // 18/25
    #[test]
    fn wallet_qr_prop_018_load_owned_wallet_rejects_arbitrary_corrupt_wallet_files_without_panic(
        corrupt in proptest::collection::vec(any::<u8>(), 1..4096)
    ) {
        let data_dir = temp_dir("prop-corrupt-wallet-file")
            .map_err(TestCaseError::fail)?;
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        let wallet_path = wallet_file_path(&opts, &wallet.address)
            .map_err(TestCaseError::fail)?;
        let parent = wallet_path
            .parent()
            .ok_or_else(|| TestCaseError::fail("wallet path must have parent"))?;

        fs::create_dir_all(parent)
            .map_err(|e| TestCaseError::fail(format!("create wallet dir failed: {e}")))?;
        fs::write(&wallet_path, corrupt)
            .map_err(|e| TestCaseError::fail(format!("write corrupt wallet failed: {e}")))?;

        let result = std::panic::catch_unwind(|| {
            QRWallet::load_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE)
        });

        prop_assert!(
            result.is_ok(),
            "corrupt wallet file must not panic load_owned_wallet"
        );

        let loaded = result.expect("panic checked above");

        prop_assert!(
            loaded.is_err(),
            "corrupt wallet file must not authenticate"
        );
    }

    // 19/25
    #[test]
    fn wallet_qr_prop_019_load_owned_wallet_rejects_oversized_wallet_files(
        extra in 1usize..2048usize,
        fill_byte in any::<u8>(),
    ) {
        let data_dir = temp_dir("prop-oversized-wallet-file")
            .map_err(TestCaseError::fail)?;
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        let wallet_path = wallet_file_path(&opts, &wallet.address)
            .map_err(TestCaseError::fail)?;
        let parent = wallet_path
            .parent()
            .ok_or_else(|| TestCaseError::fail("wallet path must have parent"))?;

        fs::create_dir_all(parent)
            .map_err(|e| TestCaseError::fail(format!("create wallet dir failed: {e}")))?;

        let len = QRWallet::MAX_WALLET_FILE_BYTES as usize + extra;

        fs::write(&wallet_path, vec![fill_byte; len])
            .map_err(|e| TestCaseError::fail(format!("write oversized wallet failed: {e}")))?;

        prop_assert!(
            QRWallet::load_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE).is_err(),
            "oversized wallet file must be rejected"
        );
    }

    // 20/25
    #[test]
    fn wallet_qr_prop_020_generate_for_owned_wallet_writes_receipt_and_png_with_expected_shape(
        leaf in safe_dir_leaf()
    ) {
        let root = temp_dir("prop-generate-success-root")
            .map_err(TestCaseError::fail)?;
        let data_dir = root.join(leaf);
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        write_wallet_file(&opts, wallet)
            .map_err(TestCaseError::fail)?;

        let receipt = QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE)
            .map_err(|e| TestCaseError::fail(format!("generate_for_owned_wallet failed: {e:?}")))?;

        let expected_path = data_dir
            .join("qr_code_wallet")
            .join(format!("wallet_{}_qr.png", wallet.address));

        prop_assert!(receipt_shape_is_valid(&receipt, &wallet.address));
        prop_assert_eq!(&receipt.qr_png_path, &expected_path);

        let bytes = fs::read(&receipt.qr_png_path)
            .map_err(|e| TestCaseError::fail(format!("read generated qr failed: {e}")))?;
        assert_png(&bytes)?;
    }

    // 21/25
    #[test]
    fn wallet_qr_prop_021_generate_invalid_addresses_fails_before_qr_output_dir(
        candidate in proptest::collection::vec(any::<u8>(), 0..256)
    ) {
        let input = String::from_utf8_lossy(&candidate).to_string();

        prop_assume!(QRWallet::qr_payload(&input).is_err());

        let data_dir = temp_dir("prop-generate-invalid-before-output")
            .map_err(TestCaseError::fail)?;
        let opts = node_opts(&data_dir);

        prop_assert!(
            QRWallet::generate_for_owned_wallet(&opts, &input, TEST_PASSPHRASE).is_err(),
            "invalid address must fail generation"
        );
        prop_assert!(
            !data_dir.join("qr_code_wallet").exists(),
            "invalid address must not create qr_code_wallet directory"
        );
    }

    // 22/25
    #[test]
    fn wallet_qr_prop_022_generate_wrong_passphrase_fails_before_qr_output_dir(
        wrong_passphrase in ".{1,128}"
    ) {
        prop_assume!(wrong_passphrase != TEST_PASSPHRASE);

        let data_dir = temp_dir("prop-generate-wrong-pass-before-output")
            .map_err(TestCaseError::fail)?;
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        write_wallet_file(&opts, wallet)
            .map_err(TestCaseError::fail)?;

        prop_assert!(
            QRWallet::generate_for_owned_wallet(&opts, &wallet.address, &wrong_passphrase).is_err(),
            "wrong passphrase must fail QR generation"
        );
        prop_assert!(
            !data_dir.join("qr_code_wallet").exists(),
            "wrong passphrase must not create qr_code_wallet directory"
        );
    }

    // 23/25
    #[test]
    fn wallet_qr_prop_023_write_verified_wallet_does_not_require_or_create_wallets_directory(
        leaf in safe_dir_leaf()
    ) {
        let root = temp_dir("prop-write-verified-no-wallets-root")
            .map_err(TestCaseError::fail)?;
        let data_dir = root.join(leaf);
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        let receipt = QRWallet::write_qr_png_for_verified_wallet(&opts, wallet)
            .map_err(|e| TestCaseError::fail(format!("write_qr_png_for_verified_wallet failed: {e:?}")))?;

        prop_assert!(receipt_shape_is_valid(&receipt, &wallet.address));
        prop_assert!(!data_dir.join("000.wallets").exists());
        prop_assert!(data_dir.join("qr_code_wallet").exists());
    }

    // 24/25
    #[test]
    fn wallet_qr_prop_024_receipt_serialization_contains_public_metadata_only(
        leaf in safe_dir_leaf()
    ) {
        let root = temp_dir("prop-receipt-privacy-root")
            .map_err(TestCaseError::fail)?;
        let data_dir = root.join(leaf);
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        write_wallet_file(&opts, wallet)
            .map_err(TestCaseError::fail)?;

        let receipt = QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE)
            .map_err(|e| TestCaseError::fail(format!("generate failed: {e:?}")))?;

        let json = serde_json::to_string_pretty(&receipt)
            .map_err(|e| TestCaseError::fail(format!("receipt json serialization failed: {e}")))?;
        let decoded: QRWalletReceipt = serde_json::from_str(&json)
            .map_err(|e| TestCaseError::fail(format!("receipt json deserialize failed: {e}")))?;

        prop_assert_eq!(&decoded, &receipt);
        prop_assert!(json.contains(&wallet.address));
        prop_assert!(!json.contains(TEST_PASSPHRASE));
        prop_assert!(!json.contains(&hex::encode(wallet.public)));
        prop_assert!(!json.contains(&hex::encode(&wallet.encrypted_secret)));
    }

    // 25/25
    #[test]
    fn wallet_qr_prop_025_stale_temp_file_is_removed_and_replaced_atomically(
        stale in proptest::collection::vec(any::<u8>(), 1..2048)
    ) {
        let data_dir = temp_dir("prop-stale-temp-atomic")
            .map_err(TestCaseError::fail)?;
        let opts = node_opts(&data_dir);
        let wallet = test_wallet();

        write_wallet_file(&opts, wallet)
            .map_err(TestCaseError::fail)?;

        let qr_dir = data_dir.join("qr_code_wallet");

        fs::create_dir_all(&qr_dir)
            .map_err(|e| TestCaseError::fail(format!("create qr dir failed: {e}")))?;

        let expected_png = qr_dir.join(format!("wallet_{}_qr.png", wallet.address));
        let tmp_path = expected_png.with_extension("png.tmp");

        fs::write(&tmp_path, stale)
            .map_err(|e| TestCaseError::fail(format!("write stale tmp failed: {e}")))?;

        let receipt = QRWallet::generate_for_owned_wallet(&opts, &wallet.address, TEST_PASSPHRASE)
            .map_err(|e| TestCaseError::fail(format!("generate failed: {e:?}")))?;

        prop_assert_eq!(&receipt.qr_png_path, &expected_png);
        prop_assert!(receipt.qr_png_path.exists());
        prop_assert!(!tmp_path.exists());

        let bytes = fs::read(&receipt.qr_png_path)
            .map_err(|e| TestCaseError::fail(format!("read final png failed: {e}")))?;
        assert_png(&bytes)?;
    }
}
