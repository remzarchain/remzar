use remzar::commandline::s_07_view_status::S07ViewStatus;
use remzar::consensus::por_000_ephemeral_registration::NodeEphemeral;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static ROOT_COUNTER: AtomicUsize = AtomicUsize::new(0);

const CHILD_ENV_KEY: &str = "REMZAR_S07_VIEW_STATUS_CHILD";
const CHILD_SCENARIO_KEY: &str = "REMZAR_S07_SCENARIO";
const CHILD_EXPECT_KEY: &str = "REMZAR_S07_EXPECT";
const CHILD_OK: &str = "S07_RESULT_OK";
const CHILD_ERR: &str = "S07_RESULT_ERR";
const CHILD_TEST_NAME: &str = "test_100_vector_edge_fuzz_adversarial_load_and_child_runner";

fn boxed_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn unique_root(label: &str) -> std::path::PathBuf {
    let counter = ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_s07_view_status_tests_{}_{}_{}",
        std::process::id(),
        label,
        counter
    ))
}

fn path_to_string(path: &std::path::Path) -> TestResult<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| boxed_error(format!("path is not valid UTF-8: {}", path.display())))
}

fn wallet_with_hex_digit(digit: char) -> String {
    format!("r{}", digit.to_string().repeat(128))
}

fn wallet_with_suffix_byte(byte: u8) -> String {
    let suffix = format!("{byte:02x}");
    let body = format!("{}{}", "0".repeat(126), suffix);
    format!("r{body}")
}

fn node_opts(root: &std::path::Path) -> TestResult<NodeOpts> {
    Ok(NodeOpts {
        identity_file: "identity.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: path_to_string(root)?,
        wallet_address: wallet_with_hex_digit('1'),
        founder: false,
    })
}

fn new_blockchain_manager(
    label: &str,
    tip: Option<u64>,
) -> TestResult<(Arc<RockDBManager>, std::path::PathBuf)> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(boxed_error)?;
    let db_path = path_to_string(&directory.blockchain_path)?;

    let manager = Arc::new(RockDBManager::new_blockchain(&opts, &db_path)?);

    if let Some(height) = tip {
        manager.set_latest_block_index(height)?;
    }

    Ok((manager, root))
}

fn cleanup_root(root: &std::path::Path) {
    if root.exists() {
        let _ignored = std::fs::remove_dir_all(root);
    }
}

fn run_status_once(
    label: &str,
    node_ephemeral: Option<&NodeEphemeral>,
    tip: Option<u64>,
    local_wallet: &str,
    identity_path: &std::path::Path,
) -> TestResult {
    let (manager, root) = new_blockchain_manager(label, tip)?;

    {
        let mut view_status = S07ViewStatus::new();
        view_status.view_status(
            node_ephemeral,
            Arc::clone(&manager),
            local_wallet,
            identity_path,
        )?;
    }

    drop(manager);
    cleanup_root(&root);

    Ok(())
}

fn create_identity_file(
    root: &std::path::Path,
    filename: &str,
) -> TestResult<(std::path::PathBuf, String)> {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(keypair.public()).to_string();
    let bytes = keypair.to_protobuf_encoding()?;

    let path = root.join(filename);
    std::fs::write(&path, bytes)?;

    Ok((path, peer_id))
}

fn create_invalid_identity_file(
    root: &std::path::Path,
    filename: &str,
) -> TestResult<std::path::PathBuf> {
    let path = root.join(filename);
    std::fs::write(&path, b"not-a-valid-libp2p-keypair")?;
    Ok(path)
}

fn sorted_wallets_model(mut wallets: Vec<String>) -> Vec<String> {
    wallets.sort_unstable_by(|a, b| {
        let al = a.to_ascii_lowercase();
        let bl = b.to_ascii_lowercase();
        match al.cmp(&bl) {
            std::cmp::Ordering::Equal => a.cmp(b),
            other => other,
        }
    });
    wallets
}

fn leader_for_height_model(wallets: &[String], height: u64) -> Option<String> {
    if wallets.is_empty() {
        return None;
    }

    let height_usize = usize::try_from(height).unwrap_or(usize::MAX);
    let index = height_usize.checked_rem(wallets.len()).unwrap_or(0);
    wallets.get(index).cloned()
}

fn display_wallet_model(local_wallet: &str) -> String {
    canon_wallet_id_checked(local_wallet).unwrap_or_else(|_| local_wallet.to_string())
}

fn populated_node_ephemeral(wallets: &[String]) -> TestResult<NodeEphemeral> {
    let node_ephemeral = NodeEphemeral::new();

    for (index, wallet) in wallets.iter().enumerate() {
        let join_height = u64::try_from(index)?;
        node_ephemeral.register_wallet_strict(wallet, join_height)?;
    }

    Ok(node_ephemeral)
}

fn run_status_child(scenario: &str, expected_marker: &str) -> TestResult<String> {
    let exe = std::env::current_exe()?;

    let output = Command::new(exe)
        .arg("--exact")
        .arg(CHILD_TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_ENV_KEY, "1")
        .env(CHILD_SCENARIO_KEY, scenario)
        .env(CHILD_EXPECT_KEY, expected_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(
        output.status.success(),
        "child process failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(expected_marker),
        "missing expected marker {expected_marker}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    Ok(stdout)
}

fn child_view_status_runner() -> TestResult {
    let scenario = std::env::var(CHILD_SCENARIO_KEY)?;
    let expected = std::env::var(CHILD_EXPECT_KEY)?;

    let result = run_child_scenario(&scenario);
    let marker = if result.is_ok() { CHILD_OK } else { CHILD_ERR };

    println!("{marker}");

    if let Err(error) = result {
        println!("S07_ERROR_TEXT={error}");
    }

    assert_eq!(marker, expected);

    Ok(())
}

fn run_child_scenario(scenario: &str) -> TestResult {
    match scenario {
        "none_registry_no_identity" => {
            let identity_root = unique_root("none_registry_no_identity_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");

            let result = run_status_once(
                "none_registry_no_identity_db",
                None,
                Some(0),
                "",
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "empty_registry_tip0" => {
            let identity_root = unique_root("empty_registry_tip0_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");
            let node_ephemeral = NodeEphemeral::new();

            let result = run_status_once(
                "empty_registry_tip0_db",
                Some(&node_ephemeral),
                Some(0),
                "",
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "one_wallet_tip0" => {
            let identity_root = unique_root("one_wallet_tip0_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");
            let wallet = wallet_with_hex_digit('1');
            let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

            let result = run_status_once(
                "one_wallet_tip0_db",
                Some(&node_ephemeral),
                Some(0),
                &wallet,
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "one_wallet_tip5" => {
            let identity_root = unique_root("one_wallet_tip5_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");
            let wallet = wallet_with_hex_digit('2');
            let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

            let result = run_status_once(
                "one_wallet_tip5_db",
                Some(&node_ephemeral),
                Some(5),
                &wallet,
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "three_wallets_tip1" => {
            let identity_root = unique_root("three_wallets_tip1_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");
            let wallets = vec![
                wallet_with_hex_digit('3'),
                wallet_with_hex_digit('1'),
                wallet_with_hex_digit('2'),
            ];
            let node_ephemeral = populated_node_ephemeral(&wallets)?;

            let result = run_status_once(
                "three_wallets_tip1_db",
                Some(&node_ephemeral),
                Some(1),
                "",
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "identity_exists" => {
            let identity_root = unique_root("identity_exists_identity");
            std::fs::create_dir_all(&identity_root)?;
            let (identity_path, _peer_id) = create_identity_file(&identity_root, "identity.key")?;
            let wallet = wallet_with_hex_digit('4');
            let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

            let result = run_status_once(
                "identity_exists_db",
                Some(&node_ephemeral),
                Some(2),
                &wallet,
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "invalid_identity_file" => {
            let identity_root = unique_root("invalid_identity_file_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = create_invalid_identity_file(&identity_root, "bad.identity")?;
            let wallet = wallet_with_hex_digit('5');
            let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

            let result = run_status_once(
                "invalid_identity_file_db",
                Some(&node_ephemeral),
                Some(3),
                &wallet,
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "invalid_local_wallet" => {
            let identity_root = unique_root("invalid_local_wallet_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");
            let wallet = wallet_with_hex_digit('6');
            let node_ephemeral = populated_node_ephemeral(&[wallet])?;

            let result = run_status_once(
                "invalid_local_wallet_db",
                Some(&node_ephemeral),
                Some(4),
                "not-a-wallet",
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "identity_mapping" => {
            let identity_root = unique_root("identity_mapping_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");
            let wallet = wallet_with_hex_digit('7');
            let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;
            node_ephemeral.map_peer_identity("peer-alpha", &wallet)?;

            let result = run_status_once(
                "identity_mapping_db",
                Some(&node_ephemeral),
                Some(5),
                &wallet,
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        "no_tip_metadata" => {
            let identity_root = unique_root("no_tip_metadata_identity");
            std::fs::create_dir_all(&identity_root)?;
            let identity_path = identity_root.join("missing.identity");
            let wallet = wallet_with_hex_digit('8');
            let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

            let result = run_status_once(
                "no_tip_metadata_db",
                Some(&node_ephemeral),
                None,
                &wallet,
                &identity_path,
            );

            cleanup_root(&identity_root);
            result
        }
        _ => Err(boxed_error(format!("unknown scenario: {scenario}"))),
    }
}

#[test]
fn test_01_new_is_zero_sized() {
    let view_status = S07ViewStatus::new();
    assert_eq!(std::mem::size_of_val(&view_status), 0);
}

#[test]
fn test_02_default_is_zero_sized() {
    let view_status = S07ViewStatus;
    assert_eq!(std::mem::size_of_val(&view_status), 0);
}

#[test]
fn test_03_new_and_default_have_same_size() {
    let new_view_status = S07ViewStatus::new();
    let default_view_status = S07ViewStatus;

    assert_eq!(
        std::mem::size_of_val(&new_view_status),
        std::mem::size_of_val(&default_view_status)
    );
}

#[test]
fn test_04_can_construct_many_new_instances() {
    for _round in 0_u16..1_024_u16 {
        let view_status = S07ViewStatus::new();
        assert_eq!(std::mem::size_of_val(&view_status), 0);
    }
}

#[test]
fn test_05_can_construct_many_default_instances() {
    for _round in 0_u16..1_024_u16 {
        let view_status = S07ViewStatus;
        assert_eq!(std::mem::size_of_val(&view_status), 0);
    }
}

#[test]
fn test_06_wallet_with_hex_digit_has_canonical_length() {
    let wallet = wallet_with_hex_digit('1');
    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
}

#[test]
fn test_07_wallet_with_hex_digit_starts_with_r() {
    let wallet = wallet_with_hex_digit('2');
    assert!(wallet.starts_with('r'));
}

#[test]
fn test_08_wallet_with_hex_digit_body_is_128_chars() {
    let wallet = wallet_with_hex_digit('3');
    let body = wallet.strip_prefix('r').unwrap_or_default();

    assert_eq!(body.len(), 128);
}

#[test]
fn test_09_wallet_with_hex_digit_is_canonical() -> TestResult {
    let wallet = wallet_with_hex_digit('4');
    let canonical = canon_wallet_id_checked(&wallet)?;

    assert_eq!(canonical, wallet);

    Ok(())
}

#[test]
fn test_10_wallet_suffix_byte_has_canonical_length() {
    let wallet = wallet_with_suffix_byte(15);
    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
}

#[test]
fn test_11_wallet_suffix_byte_00_is_canonical() -> TestResult {
    let wallet = wallet_with_suffix_byte(0);
    let canonical = canon_wallet_id_checked(&wallet)?;

    assert_eq!(canonical, wallet);

    Ok(())
}

#[test]
fn test_12_wallet_suffix_byte_ff_is_canonical() -> TestResult {
    let wallet = wallet_with_suffix_byte(255);
    let canonical = canon_wallet_id_checked(&wallet)?;

    assert_eq!(canonical, wallet);

    Ok(())
}

#[test]
fn test_13_display_wallet_canonical_preserves_lowercase() {
    let wallet = wallet_with_hex_digit('5');
    assert_eq!(display_wallet_model(&wallet), wallet);
}

#[test]
fn test_14_display_wallet_uppercase_canonicalizes() {
    let wallet = format!("r{}", "A".repeat(128));
    assert_eq!(
        display_wallet_model(&wallet),
        format!("r{}", "a".repeat(128))
    );
}

#[test]
fn test_15_display_wallet_invalid_preserves_original() {
    assert_eq!(display_wallet_model("not-a-wallet"), "not-a-wallet");
}

#[test]
fn test_16_display_wallet_empty_preserves_empty() {
    assert_eq!(display_wallet_model(""), "");
}

#[test]
fn test_17_sorted_wallets_empty_is_empty() {
    let sorted = sorted_wallets_model(Vec::new());
    assert!(sorted.is_empty());
}

#[test]
fn test_18_sorted_wallets_single_preserves_wallet() {
    let wallet = wallet_with_hex_digit('1');
    let sorted = sorted_wallets_model(vec![wallet.clone()]);

    assert_eq!(sorted, vec![wallet]);
}

#[test]
fn test_19_sorted_wallets_orders_numeric_hex() {
    let wallets = vec![
        wallet_with_hex_digit('3'),
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
    ];
    let sorted = sorted_wallets_model(wallets);

    assert_eq!(
        sorted,
        vec![
            wallet_with_hex_digit('1'),
            wallet_with_hex_digit('2'),
            wallet_with_hex_digit('3')
        ]
    );
}

#[test]
fn test_20_sorted_wallets_orders_zero_before_one() {
    let wallets = vec![wallet_with_hex_digit('1'), wallet_with_hex_digit('0')];
    let sorted = sorted_wallets_model(wallets);

    assert_eq!(
        sorted,
        vec![wallet_with_hex_digit('0'), wallet_with_hex_digit('1')]
    );
}

#[test]
fn test_21_sorted_wallets_orders_nine_before_a() {
    let wallets = vec![wallet_with_hex_digit('a'), wallet_with_hex_digit('9')];
    let sorted = sorted_wallets_model(wallets);

    assert_eq!(
        sorted,
        vec![wallet_with_hex_digit('9'), wallet_with_hex_digit('a')]
    );
}

#[test]
fn test_22_leader_empty_wallets_is_none() {
    assert_eq!(leader_for_height_model(&[], 0), None);
}

#[test]
fn test_23_leader_single_wallet_height_zero() {
    let wallet = wallet_with_hex_digit('1');
    let wallets = vec![wallet.clone()];

    assert_eq!(leader_for_height_model(&wallets, 0), Some(wallet));
}

#[test]
fn test_24_leader_single_wallet_large_height() {
    let wallet = wallet_with_hex_digit('1');
    let wallets = vec![wallet.clone()];

    assert_eq!(leader_for_height_model(&wallets, 1_000_000), Some(wallet));
}

#[test]
fn test_25_leader_two_wallet_height_zero() {
    let wallets = vec![wallet_with_hex_digit('1'), wallet_with_hex_digit('2')];

    assert_eq!(
        leader_for_height_model(&wallets, 0),
        Some(wallet_with_hex_digit('1'))
    );
}

#[test]
fn test_26_leader_two_wallet_height_one() {
    let wallets = vec![wallet_with_hex_digit('1'), wallet_with_hex_digit('2')];

    assert_eq!(
        leader_for_height_model(&wallets, 1),
        Some(wallet_with_hex_digit('2'))
    );
}

#[test]
fn test_27_leader_two_wallet_height_two_wraps() {
    let wallets = vec![wallet_with_hex_digit('1'), wallet_with_hex_digit('2')];

    assert_eq!(
        leader_for_height_model(&wallets, 2),
        Some(wallet_with_hex_digit('1'))
    );
}

#[test]
fn test_28_leader_three_wallet_height_four() {
    let wallets = vec![
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
        wallet_with_hex_digit('3'),
    ];

    assert_eq!(
        leader_for_height_model(&wallets, 4),
        Some(wallet_with_hex_digit('2'))
    );
}

#[test]
fn test_29_leader_three_wallet_height_five() {
    let wallets = vec![
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
        wallet_with_hex_digit('3'),
    ];

    assert_eq!(
        leader_for_height_model(&wallets, 5),
        Some(wallet_with_hex_digit('3'))
    );
}

#[test]
fn test_30_leader_three_wallet_height_six_wraps() {
    let wallets = vec![
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
        wallet_with_hex_digit('3'),
    ];

    assert_eq!(
        leader_for_height_model(&wallets, 6),
        Some(wallet_with_hex_digit('1'))
    );
}

#[test]
fn test_31_node_ephemeral_new_has_empty_registry() -> TestResult {
    let node_ephemeral = NodeEphemeral::new();
    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert!(guard.wallets.is_empty());
    assert!(guard.identity_map.is_empty());
    assert!(guard.join_heights.is_empty());

    Ok(())
}

#[test]
fn test_32_node_ephemeral_register_one_wallet() -> TestResult {
    let wallet = wallet_with_hex_digit('1');
    let node_ephemeral = NodeEphemeral::new();

    let registered = node_ephemeral.register_wallet_strict(&wallet, 7)?;

    assert_eq!(registered, wallet);

    Ok(())
}

#[test]
fn test_33_node_ephemeral_register_duplicate_wallet_errors() -> TestResult {
    let wallet = wallet_with_hex_digit('2');
    let node_ephemeral = NodeEphemeral::new();

    node_ephemeral.register_wallet_strict(&wallet, 0)?;
    let duplicate = node_ephemeral.register_wallet_strict(&wallet, 1);

    assert!(duplicate.is_err());

    Ok(())
}

#[test]
fn test_34_node_ephemeral_register_invalid_wallet_errors() {
    let node_ephemeral = NodeEphemeral::new();
    let result = node_ephemeral.register_wallet_strict("not-a-wallet", 0);

    assert!(result.is_err());
}

#[test]
fn test_35_node_ephemeral_identity_mapping_for_registered_wallet() -> TestResult {
    let wallet = wallet_with_hex_digit('3');
    let node_ephemeral = NodeEphemeral::new();

    node_ephemeral.register_wallet_strict(&wallet, 0)?;
    node_ephemeral.map_peer_identity("peer-alpha", &wallet)?;

    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert_eq!(guard.identity_map.get("peer-alpha"), Some(&wallet));

    Ok(())
}

#[test]
fn test_36_node_ephemeral_identity_mapping_for_unregistered_wallet_errors() {
    let wallet = wallet_with_hex_digit('4');
    let node_ephemeral = NodeEphemeral::new();

    let result = node_ephemeral.map_peer_identity("peer-alpha", &wallet);

    assert!(result.is_err());
}

#[test]
fn test_37_node_ephemeral_set_join_height_preserves_first_join_height() -> TestResult {
    let wallet = wallet_with_hex_digit('5');
    let node_ephemeral = NodeEphemeral::new();

    node_ephemeral.register_wallet_strict(&wallet, 3)?;
    node_ephemeral.set_join_height(&wallet, 9)?;

    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert_eq!(guard.join_heights.get(&wallet), Some(&3));

    Ok(())
}

#[test]
fn test_38_node_ephemeral_set_tip_snapshot() -> TestResult {
    let wallet = wallet_with_hex_digit('6');
    let node_ephemeral = NodeEphemeral::new();

    node_ephemeral.register_wallet_strict(&wallet, 0)?;
    node_ephemeral.set_tip_snapshot(&wallet, 42)?;

    assert_eq!(node_ephemeral.tip_snapshot(&wallet), Some(42));

    Ok(())
}

#[test]
fn test_39_node_ephemeral_boot_clear_empties_registry() -> TestResult {
    let wallet = wallet_with_hex_digit('7');
    let node_ephemeral = NodeEphemeral::new();

    node_ephemeral.register_wallet_strict(&wallet, 0)?;
    node_ephemeral.boot_clear();

    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert!(guard.wallets.is_empty());

    Ok(())
}

#[test]
fn test_40_populated_node_ephemeral_registers_all_wallets() -> TestResult {
    let wallets = vec![
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
        wallet_with_hex_digit('3'),
    ];
    let node_ephemeral = populated_node_ephemeral(&wallets)?;

    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert_eq!(guard.wallets.len(), 3);

    Ok(())
}

#[test]
fn test_41_real_none_registry_no_identity_returns_ok() -> TestResult {
    let stdout = run_status_child("none_registry_no_identity", CHILD_OK)?;

    assert!(stdout.contains("Viewing Wallet Registry Status"));
    assert!(stdout.contains("memory-only"));
    assert!(stdout.contains("wiped on restart"));
    assert!(stdout.contains("No registered wallets"));

    Ok(())
}

#[test]
fn test_42_real_empty_registry_tip0_returns_ok() -> TestResult {
    let stdout = run_status_child("empty_registry_tip0", CHILD_OK)?;

    assert!(stdout.contains("Participants"));
    assert!(stdout.contains("0/"));

    Ok(())
}

#[test]
fn test_43_real_one_wallet_tip0_returns_ok_and_lists_wallet() -> TestResult {
    let wallet = wallet_with_hex_digit('1');
    let stdout = run_status_child("one_wallet_tip0", CHILD_OK)?;

    assert!(stdout.contains(&wallet));
    assert!(stdout.contains("Current leader"));

    Ok(())
}

#[test]
fn test_44_real_one_wallet_tip5_returns_ok_and_lists_last_current_next() -> TestResult {
    let stdout = run_status_child("one_wallet_tip5", CHILD_OK)?;

    assert!(stdout.contains("Last leader"));
    assert!(stdout.contains("Current leader"));
    assert!(stdout.contains("Next leader"));

    Ok(())
}

#[test]
fn test_45_real_three_wallets_tip1_returns_ok() -> TestResult {
    let stdout = run_status_child("three_wallets_tip1", CHILD_OK)?;

    assert!(stdout.contains(&wallet_with_hex_digit('1')));
    assert!(stdout.contains(&wallet_with_hex_digit('2')));
    assert!(stdout.contains(&wallet_with_hex_digit('3')));

    Ok(())
}

#[test]
fn test_46_real_identity_exists_prints_non_unknown_peer_id() -> TestResult {
    let stdout = run_status_child("identity_exists", CHILD_OK)?;

    assert!(stdout.contains("This node PeerId"));
    assert!(!stdout.contains("This node PeerId: <unknown>"));

    Ok(())
}

#[test]
fn test_47_real_invalid_identity_file_prints_unknown_peer_id() -> TestResult {
    let stdout = run_status_child("invalid_identity_file", CHILD_OK)?;

    assert!(stdout.contains("This node PeerId: <unknown>"));

    Ok(())
}

#[test]
fn test_48_real_invalid_local_wallet_is_displayed_as_raw_input() -> TestResult {
    let stdout = run_status_child("invalid_local_wallet", CHILD_OK)?;

    assert!(stdout.contains("not-a-wallet"));

    Ok(())
}

#[test]
fn test_49_real_identity_mapping_prints_mapping_section() -> TestResult {
    let stdout = run_status_child("identity_mapping", CHILD_OK)?;

    assert!(stdout.contains("Node Identity Mappings"));
    assert!(stdout.contains("peer-alpha"));

    Ok(())
}

#[test]
fn test_50_real_no_tip_metadata_still_returns_ok() -> TestResult {
    let stdout = run_status_child("no_tip_metadata", CHILD_OK)?;

    assert!(stdout.contains("Current leader") || stdout.contains("unknown"));

    Ok(())
}

#[test]
fn test_51_real_direct_view_status_with_empty_registry_returns_ok() -> TestResult {
    let root = unique_root("direct_empty_identity");
    std::fs::create_dir_all(&root)?;
    let identity_path = root.join("missing.identity");
    let node_ephemeral = NodeEphemeral::new();

    run_status_once(
        "direct_empty_registry",
        Some(&node_ephemeral),
        Some(0),
        "",
        &identity_path,
    )?;

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_52_real_direct_view_status_with_one_wallet_returns_ok() -> TestResult {
    let root = unique_root("direct_one_wallet_identity");
    std::fs::create_dir_all(&root)?;
    let identity_path = root.join("missing.identity");
    let wallet = wallet_with_hex_digit('8');
    let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

    run_status_once(
        "direct_one_wallet",
        Some(&node_ephemeral),
        Some(1),
        &wallet,
        &identity_path,
    )?;

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_53_real_direct_view_status_with_identity_file_returns_ok() -> TestResult {
    let root = unique_root("direct_identity_file");
    std::fs::create_dir_all(&root)?;
    let (identity_path, peer_id) = create_identity_file(&root, "identity.key")?;
    let wallet = wallet_with_hex_digit('9');
    let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

    assert!(!peer_id.is_empty());

    run_status_once(
        "direct_identity_file_db",
        Some(&node_ephemeral),
        Some(2),
        &wallet,
        &identity_path,
    )?;

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_54_real_direct_view_status_with_invalid_identity_file_returns_ok() -> TestResult {
    let root = unique_root("direct_invalid_identity_file");
    std::fs::create_dir_all(&root)?;
    let identity_path = create_invalid_identity_file(&root, "bad.identity")?;
    let wallet = wallet_with_hex_digit('a');
    let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;

    run_status_once(
        "direct_invalid_identity_file_db",
        Some(&node_ephemeral),
        Some(3),
        &wallet,
        &identity_path,
    )?;

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_55_real_direct_view_status_with_three_wallets_returns_ok() -> TestResult {
    let root = unique_root("direct_three_wallets_identity");
    std::fs::create_dir_all(&root)?;
    let identity_path = root.join("missing.identity");
    let wallets = vec![
        wallet_with_hex_digit('c'),
        wallet_with_hex_digit('b'),
        wallet_with_hex_digit('d'),
    ];
    let node_ephemeral = populated_node_ephemeral(&wallets)?;

    run_status_once(
        "direct_three_wallets",
        Some(&node_ephemeral),
        Some(4),
        "",
        &identity_path,
    )?;

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_56_real_direct_view_status_none_node_ephemeral_returns_ok() -> TestResult {
    let root = unique_root("direct_none_ephemeral_identity");
    std::fs::create_dir_all(&root)?;
    let identity_path = root.join("missing.identity");

    run_status_once("direct_none_ephemeral", None, Some(0), "", &identity_path)?;

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_57_global_max_participants_is_nonzero() {
    assert!(GlobalConfiguration::MAX_ZAR_PARTICIPANTS > 0);
}

#[test]
fn test_58_global_max_participants_fits_usize_or_saturates_model() {
    let converted =
        usize::try_from(GlobalConfiguration::MAX_ZAR_PARTICIPANTS).unwrap_or(usize::MAX);

    assert!(converted > 0);
}

#[test]
fn test_59_global_reward_delay_blocks_is_nonzero_or_zero_safe() {
    let delay = GlobalConfiguration::REWARD_DELAY_BLOCKS;
    assert!(delay <= usize::MAX);
}

#[test]
fn test_60_model_last_leader_tip_zero_is_absent() {
    let tip = 0_u64;
    let last = if tip > 0 {
        Some(tip.saturating_sub(1))
    } else {
        None
    };

    assert_eq!(last, None);
}

#[test]
fn test_61_model_last_leader_tip_one_is_zero() {
    let tip = 1_u64;
    let last = if tip > 0 {
        Some(tip.saturating_sub(1))
    } else {
        None
    };

    assert_eq!(last, Some(0));
}

#[test]
fn test_62_model_next_leader_uses_saturating_add() {
    assert_eq!(u64::MAX.saturating_add(1), u64::MAX);
}

#[test]
fn test_63_model_tip_schedule_for_two_wallets_cycles() {
    let wallets = vec![wallet_with_hex_digit('1'), wallet_with_hex_digit('2')];

    for height in 0_u64..20_u64 {
        let expected = if height % 2 == 0 {
            wallet_with_hex_digit('1')
        } else {
            wallet_with_hex_digit('2')
        };
        assert_eq!(leader_for_height_model(&wallets, height), Some(expected));
    }
}

#[test]
fn test_64_model_tip_schedule_for_three_wallets_cycles() {
    let wallets = vec![
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
        wallet_with_hex_digit('3'),
    ];

    for height in 0_u64..30_u64 {
        let expected_index = usize::try_from(height % 3).unwrap_or(0);
        assert_eq!(
            leader_for_height_model(&wallets, height),
            wallets.get(expected_index).cloned()
        );
    }
}

#[test]
fn test_65_model_sorted_wallets_property_is_idempotent() {
    let wallets = vec![
        wallet_with_hex_digit('f'),
        wallet_with_hex_digit('0'),
        wallet_with_hex_digit('a'),
        wallet_with_hex_digit('1'),
    ];

    let once = sorted_wallets_model(wallets);
    let twice = sorted_wallets_model(once.clone());

    assert_eq!(once, twice);
}

#[test]
fn test_66_model_sorted_wallets_load_256_distinct_suffix_wallets() {
    let mut wallets = Vec::new();

    for byte in 0_u16..=255_u16 {
        let byte_u8 = u8::try_from(byte).unwrap_or(0);
        wallets.push(wallet_with_suffix_byte(byte_u8));
    }

    let sorted = sorted_wallets_model(wallets.clone());

    assert_eq!(sorted.len(), wallets.len());
    assert_eq!(sorted.first(), Some(&wallet_with_suffix_byte(0)));
    assert_eq!(sorted.last(), Some(&wallet_with_suffix_byte(255)));
}

#[test]
fn test_67_model_leader_load_256_wallets_first_height() {
    let wallets: Vec<String> = (0_u16..=255_u16)
        .map(|value| wallet_with_suffix_byte(u8::try_from(value).unwrap_or(0)))
        .collect();

    assert_eq!(
        leader_for_height_model(&wallets, 0),
        Some(wallet_with_suffix_byte(0))
    );
}

#[test]
fn test_68_model_leader_load_256_wallets_last_height() {
    let wallets: Vec<String> = (0_u16..=255_u16)
        .map(|value| wallet_with_suffix_byte(u8::try_from(value).unwrap_or(0)))
        .collect();

    assert_eq!(
        leader_for_height_model(&wallets, 255),
        Some(wallet_with_suffix_byte(255))
    );
}

#[test]
fn test_69_model_leader_load_256_wallets_wrap_height() {
    let wallets: Vec<String> = (0_u16..=255_u16)
        .map(|value| wallet_with_suffix_byte(u8::try_from(value).unwrap_or(0)))
        .collect();

    assert_eq!(
        leader_for_height_model(&wallets, 256),
        Some(wallet_with_suffix_byte(0))
    );
}

#[test]
fn test_70_model_leader_u64_max_does_not_panic() {
    let wallets = vec![wallet_with_hex_digit('1'), wallet_with_hex_digit('2')];
    let leader = leader_for_height_model(&wallets, u64::MAX);

    assert!(leader.is_some());
}

#[test]
fn test_71_model_display_wallet_accepts_uppercase_prefix() {
    let wallet = format!("R{}", "1".repeat(128));
    let expected = format!("r{}", "1".repeat(128));

    assert_eq!(display_wallet_model(&wallet), expected);
}

#[test]
fn test_72_model_display_wallet_rejects_wrong_prefix_and_preserves() {
    let wallet = format!("x{}", "1".repeat(128));

    assert_eq!(display_wallet_model(&wallet), wallet);
}

#[test]
fn test_73_model_display_wallet_rejects_short_and_preserves() {
    let wallet = format!("r{}", "1".repeat(127));

    assert_eq!(display_wallet_model(&wallet), wallet);
}

#[test]
fn test_74_model_display_wallet_rejects_long_and_preserves() {
    let wallet = format!("r{}", "1".repeat(129));

    assert_eq!(display_wallet_model(&wallet), wallet);
}

#[test]
fn test_75_identity_file_creation_returns_peer_id() -> TestResult {
    let root = unique_root("identity_file_creation");
    std::fs::create_dir_all(&root)?;

    let (identity_path, peer_id) = create_identity_file(&root, "identity.key")?;

    assert!(identity_path.exists());
    assert!(!peer_id.is_empty());

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_76_invalid_identity_file_creation_writes_file() -> TestResult {
    let root = unique_root("invalid_identity_file_creation");
    std::fs::create_dir_all(&root)?;

    let identity_path = create_invalid_identity_file(&root, "bad.identity")?;

    assert!(identity_path.exists());

    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_77_node_opts_uses_supplied_root() -> TestResult {
    let root = unique_root("node_opts_root");
    let opts = node_opts(&root)?;

    assert_eq!(opts.data_dir, path_to_string(&root)?);

    Ok(())
}

#[test]
fn test_78_directory_from_node_opts_maps_blockchain_path() -> TestResult {
    let root = unique_root("directory_from_node_opts");
    let opts = node_opts(&root)?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(boxed_error)?;

    assert_eq!(
        directory.blockchain_path,
        root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR)
    );

    Ok(())
}

#[test]
fn test_79_manager_creation_with_no_tip_returns_ok() -> TestResult {
    let (manager, root) = new_blockchain_manager("manager_no_tip", None)?;

    assert_eq!(
        manager.mode,
        remzar::storage::rocksdb_005_manager::Mode::Blockchain
    );

    drop(manager);
    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_80_manager_creation_with_tip_returns_ok() -> TestResult {
    let (manager, root) = new_blockchain_manager("manager_with_tip", Some(12))?;

    assert_eq!(manager.get_tip_height()?, 12);

    drop(manager);
    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_81_manager_tip_zero_round_trip() -> TestResult {
    let (manager, root) = new_blockchain_manager("manager_tip_zero", Some(0))?;

    assert_eq!(manager.get_tip_height()?, 0);

    drop(manager);
    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_82_manager_tip_large_round_trip() -> TestResult {
    let (manager, root) = new_blockchain_manager("manager_tip_large", Some(1_000_000))?;

    assert_eq!(manager.get_tip_height()?, 1_000_000);

    drop(manager);
    cleanup_root(&root);

    Ok(())
}

#[test]
fn test_83_registry_sorted_wallets_matches_model() -> TestResult {
    let wallets = vec![
        wallet_with_hex_digit('3'),
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
    ];
    let node_ephemeral = populated_node_ephemeral(&wallets)?;
    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert_eq!(guard.sorted_wallets(), sorted_wallets_model(wallets));

    Ok(())
}

#[test]
fn test_84_registry_identity_map_empty_by_default() -> TestResult {
    let node_ephemeral = NodeEphemeral::new();
    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert!(guard.identity_map.is_empty());

    Ok(())
}

#[test]
fn test_85_registry_join_heights_populated() -> TestResult {
    let wallets = vec![wallet_with_hex_digit('1'), wallet_with_hex_digit('2')];
    let node_ephemeral = populated_node_ephemeral(&wallets)?;
    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert_eq!(guard.join_heights.len(), 2);

    Ok(())
}

#[test]
fn test_86_registry_wallet_count_matches_registered_wallets() -> TestResult {
    let wallets = vec![
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
        wallet_with_hex_digit('3'),
        wallet_with_hex_digit('4'),
    ];
    let node_ephemeral = populated_node_ephemeral(&wallets)?;
    let registry = node_ephemeral.ephemeral();
    let guard = registry
        .lock()
        .map_err(|_| boxed_error("registry mutex poisoned"))?;

    assert_eq!(guard.wallets.len(), wallets.len());

    Ok(())
}

#[test]
fn test_87_registry_wallets_are_canonical_after_registration() -> TestResult {
    let wallet = format!("R{}", "A".repeat(128));
    let node_ephemeral = NodeEphemeral::new();
    let registered = node_ephemeral.register_wallet_strict(&wallet, 0)?;

    assert_eq!(registered, format!("r{}", "a".repeat(128)));

    Ok(())
}

#[test]
fn test_88_registry_map_peer_identity_empty_peer_rejected() -> TestResult {
    let wallet = wallet_with_hex_digit('1');
    let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;
    let result = node_ephemeral.map_peer_identity("", &wallet);

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_89_registry_map_peer_identity_non_ascii_peer_rejected() -> TestResult {
    let wallet = wallet_with_hex_digit('1');
    let node_ephemeral = populated_node_ephemeral(std::slice::from_ref(&wallet))?;
    let result = node_ephemeral.map_peer_identity("peer-🧪", &wallet);

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_90_registry_set_tip_snapshot_unregistered_wallet_rejected() {
    let wallet = wallet_with_hex_digit('1');
    let node_ephemeral = NodeEphemeral::new();
    let result = node_ephemeral.set_tip_snapshot(&wallet, 1);

    assert!(result.is_err());
}

#[test]
fn test_91_model_wallet_suffix_fuzz_all_256_are_canonical() -> TestResult {
    for value in 0_u16..=255_u16 {
        let byte = u8::try_from(value)?;
        let wallet = wallet_with_suffix_byte(byte);
        assert_eq!(canon_wallet_id_checked(&wallet)?, wallet);
    }

    Ok(())
}

#[test]
fn test_92_model_invalid_wallet_fuzz_ascii_single_chars() {
    for byte in 1_u8..=127_u8 {
        let ch = char::from(byte);
        let wallet = format!("r{}", ch.to_string().repeat(128));
        let valid = ch.is_ascii_hexdigit();

        assert_eq!(
            canon_wallet_id_checked(&wallet).is_ok(),
            valid,
            "unexpected canonical result for {ch:?}"
        );
    }
}

#[test]
fn test_93_model_sort_fuzz_reversed_suffix_wallets() {
    let mut wallets = Vec::new();

    for value in (0_u16..=255_u16).rev() {
        let byte = u8::try_from(value).unwrap_or(0);
        wallets.push(wallet_with_suffix_byte(byte));
    }

    let sorted = sorted_wallets_model(wallets);

    assert_eq!(sorted.first(), Some(&wallet_with_suffix_byte(0)));
    assert_eq!(sorted.last(), Some(&wallet_with_suffix_byte(255)));
}

#[test]
fn test_94_model_leader_fuzz_many_heights() {
    let wallets = vec![
        wallet_with_hex_digit('0'),
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
        wallet_with_hex_digit('3'),
    ];

    for height in 0_u64..1_000_u64 {
        let expected_index = usize::try_from(height % 4).unwrap_or(0);
        assert_eq!(
            leader_for_height_model(&wallets, height),
            wallets.get(expected_index).cloned()
        );
    }
}

#[test]
fn test_95_real_child_scenarios_all_expected_ok() -> TestResult {
    let scenarios = [
        "none_registry_no_identity",
        "empty_registry_tip0",
        "one_wallet_tip0",
        "one_wallet_tip5",
        "three_wallets_tip1",
        "identity_exists",
        "invalid_identity_file",
        "invalid_local_wallet",
        "identity_mapping",
        "no_tip_metadata",
    ];

    for scenario in scenarios {
        let stdout = run_status_child(scenario, CHILD_OK)?;
        assert!(stdout.contains(CHILD_OK));
    }

    Ok(())
}

#[test]
fn test_96_real_child_unknown_scenario_returns_err_marker() -> TestResult {
    let stdout = run_status_child("unknown_scenario", CHILD_ERR)?;

    assert!(stdout.contains(CHILD_ERR));
    assert!(stdout.contains("unknown scenario"));

    Ok(())
}

#[test]
fn test_97_child_helper_ok_marker_is_distinct_from_err_marker() {
    assert_ne!(CHILD_OK, CHILD_ERR);
}

#[test]
fn test_98_child_test_name_is_not_empty() {
    assert!(!CHILD_TEST_NAME.is_empty());
}

#[test]
fn test_99_real_repeated_empty_registry_load() -> TestResult {
    for _round in 0_u8..3_u8 {
        let stdout = run_status_child("empty_registry_tip0", CHILD_OK)?;
        assert!(stdout.contains(CHILD_OK));
    }

    Ok(())
}

#[test]
fn test_100_vector_edge_fuzz_adversarial_load_and_child_runner() -> TestResult {
    if std::env::var(CHILD_ENV_KEY).ok().as_deref() == Some("1") {
        return child_view_status_runner();
    }

    let wallets = vec![
        wallet_with_hex_digit('3'),
        wallet_with_hex_digit('1'),
        wallet_with_hex_digit('2'),
    ];
    let sorted = sorted_wallets_model(wallets);

    assert_eq!(
        sorted,
        vec![
            wallet_with_hex_digit('1'),
            wallet_with_hex_digit('2'),
            wallet_with_hex_digit('3'),
        ]
    );

    for height in 0_u64..300_u64 {
        let expected_index = usize::try_from(height % 3).unwrap_or(0);
        assert_eq!(
            leader_for_height_model(&sorted, height),
            sorted.get(expected_index).cloned()
        );
    }

    for value in 0_u16..=255_u16 {
        let byte = u8::try_from(value)?;
        let wallet = wallet_with_suffix_byte(byte);
        assert_eq!(canon_wallet_id_checked(&wallet)?, wallet);
    }

    let stdout = run_status_child("identity_mapping", CHILD_OK)?;
    assert!(stdout.contains("Node Identity Mappings"));
    assert!(stdout.contains("peer-alpha"));

    Ok(())
}
