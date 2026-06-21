use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::blockchain::genesis_002_file::GenesisFile;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::blockchain::validatorstate::ValidatorState;
use remzar::commandline::s_03_startnode::{S03StartNode, S03StartNodeArgs};
use remzar::commandline::s_04_view_blockchain_console::ConsoleBus;
use remzar::consensus::por_000_ephemeral_registration::{NodeEphemeral, RegistryData};
use remzar::network::p2p_010_netcmd::NetCmd;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::storage::rocksdb_006_manager_ext::ForkBlockStatus;
use remzar::storage::rocksdb_007_db_guard::{DbGuard, enforce_db_ownership};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::logging_data::JsonLogger;

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(case_name: &str) -> TestResult<Self> {
        let mut path = std::env::temp_dir();
        path.push(format!("remzar_s03_{case_name}_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self.path.exists() {
            match fs::remove_dir_all(&self.path) {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

fn boxed_error(message: &str) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message.to_owned()))
}

fn string_error(message: String) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::other(message))
}

fn path_to_string(path: &Path) -> TestResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn wallet_with_pair(pair: &str) -> String {
    let mut wallet = String::from("r");
    for _ in 0..64 {
        wallet.push_str(pair);
    }
    wallet
}

fn wallet_with_upper_hex_pair(pair: &str) -> String {
    let mut wallet = String::from("r");
    let upper_pair = pair.to_ascii_uppercase();
    for _ in 0..64 {
        wallet.push_str(&upper_pair);
    }
    wallet
}

fn node_opts(root: &Path) -> TestResult<NodeOpts> {
    Ok(NodeOpts {
        identity_file: path_to_string(&root.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "off".to_owned(),
        data_dir: path_to_string(root)?,
        wallet_address: String::new(),
        founder: false,
    })
}

fn run_start_node_guard_once(section: &mut S03StartNode<'_>, logger: &JsonLogger) -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        section.start_node(logger).await?;
        Ok(())
    })
}

fn valid_genesis_with_data(
    founder_wallet: &str,
    data: &str,
) -> Result<GenesisFile, ErrorDetection> {
    let genesis_block = GenesisBlock::new_with_timestamp_and_miner(
        data,
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        founder_wallet,
    )?;

    Ok(GenesisFile {
        chain_id: "remzar-testnet".to_owned(),
        description: Some("integration-test genesis".to_owned()),
        version: Some("1.0.0".to_owned()),
        genesis_block,
    })
}

fn valid_genesis_file(founder_wallet: &str) -> Result<GenesisFile, ErrorDetection> {
    let genesis_block = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar test genesis",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
        founder_wallet,
    )?;

    Ok(GenesisFile {
        chain_id: "remzar-testnet".to_owned(),
        description: Some("integration-test genesis".to_owned()),
        version: Some("1.0.0".to_owned()),
        genesis_block,
    })
}

fn write_genesis_file(root: &Path, name: &str, genesis: &GenesisFile) -> TestResult<String> {
    let path = root.join(name);
    let path_string = path_to_string(&path)?;
    genesis.to_json_file(&path_string)?;
    Ok(path_string)
}

fn write_raw_file(root: &Path, name: &str, bytes: &[u8]) -> TestResult<String> {
    let path = root.join(name);
    fs::write(&path, bytes)?;
    path_to_string(&path)
}

fn write_oversized_file(root: &Path, name: &str) -> TestResult<String> {
    let path = root.join(name);
    let file = fs::File::create(&path)?;
    file.set_len(GlobalConfiguration::MAX_GENESIS_JSON_BYTES.saturating_add(1))?;
    path_to_string(&path)
}

fn make_test_logger(root: &Path) -> TestResult<JsonLogger> {
    let directory = DirectoryDB::from_base_dir(root).map_err(string_error)?;
    directory.create_log_directory().map_err(string_error)?;
    JsonLogger::new(&directory).map_err(string_error)
}

fn with_section<F>(case_name: &str, p2p_running_initial: bool, test_body: F) -> TestResult
where
    F: FnOnce(&mut S03StartNode<'_>, &NodeOpts, &Path) -> TestResult,
{
    let temp = TempRoot::new(case_name)?;
    let opts = node_opts(temp.path())?;

    let mut node_registry: Option<RegistryData> = None;
    let mut node_ephemeral: Option<NodeEphemeral> = None;
    let mut db_manager = Arc::new(RockDBManager::new(&opts)?);
    let mut p2p_running = p2p_running_initial;
    let mut p2p_handle = None;
    let mut net_tx: Option<tokio::sync::mpsc::Sender<NetCmd>> = None;
    let console_bus = ConsoleBus::new();
    let mut chain: Option<AccountModelTree> = None;
    let mut local_wallet = String::new();
    let mut blockchain_db_guard: Option<DbGuard> = None;

    let mut section = S03StartNode::new(S03StartNodeArgs {
        node_registry: &mut node_registry,
        node_ephemeral: &mut node_ephemeral,
        db_manager: &mut db_manager,
        p2p_running: &mut p2p_running,
        p2p_handle: &mut p2p_handle,
        net_tx: &mut net_tx,
        console_bus,
        chain: &mut chain,
        local_wallet: &mut local_wallet,
        blockchain_db_guard: &mut blockchain_db_guard,
    });

    test_body(&mut section, &opts, temp.path())
}

fn expect_error<T>(result: Result<T, ErrorDetection>) -> TestResult<ErrorDetection> {
    match result {
        Ok(_) => Err(boxed_error("expected operation to fail")),
        Err(error) => Ok(error),
    }
}

fn assert_error_contains<T>(result: Result<T, ErrorDetection>, needle: &str) -> TestResult {
    let error = expect_error(result)?;
    let message = error.to_string();
    assert!(
        message.contains(needle),
        "error message did not contain '{needle}': {message}"
    );
    Ok(())
}

fn initialize_valid_chain(
    section: &mut S03StartNode<'_>,
    opts: &NodeOpts,
    root: &Path,
    founder_wallet: &str,
) -> TestResult<RockDBManager> {
    let genesis = valid_genesis_file(founder_wallet)?;
    let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
    let manager = section.initialize_blockchain(opts, false, &genesis_path, founder_wallet)?;
    Ok(manager)
}

#[test]
fn s03_01_new_wires_references_without_mutating_initial_state() -> TestResult {
    with_section("01_new_wires_state", false, |section, _opts, _root| {
        assert!(section.node_registry.is_none());
        assert!(section.node_ephemeral.is_none());
        assert!(!*section.p2p_running);
        assert!(section.p2p_handle.is_none());
        assert!(section.net_tx.is_none());
        assert!(section.chain.is_none());
        assert!(section.local_wallet.is_empty());
        assert!(section.blockchain_db_guard.is_none());
        Ok(())
    })
}

#[test]
fn s03_02_initialize_rejects_when_p2p_is_running() -> TestResult {
    with_section("02_rejects_running_node", true, |section, opts, root| {
        let founder = wallet_with_pair("01");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "P2P node is running",
        )
    })
}

#[test]
fn s03_03_initialize_rejects_missing_genesis_file() -> TestResult {
    with_section("03_missing_genesis", false, |section, opts, root| {
        let founder = wallet_with_pair("02");
        let missing = path_to_string(&root.join("missing-genesis.json"))?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &missing, &founder),
            "Failed to stat genesis file",
        )
    })
}

#[test]
fn s03_04_initialize_rejects_empty_genesis_file() -> TestResult {
    with_section("04_empty_genesis", false, |section, opts, root| {
        let founder = wallet_with_pair("03");
        let genesis_path = write_raw_file(root, "empty.json", b"")?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "Genesis file invalid size/type",
        )
    })
}

#[test]
fn s03_05_initialize_rejects_directory_as_genesis_path() -> TestResult {
    with_section("05_directory_genesis", false, |section, opts, root| {
        let founder = wallet_with_pair("04");
        let directory = root.join("genesis_dir");
        fs::create_dir_all(&directory)?;
        let directory_path = path_to_string(&directory)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &directory_path, &founder),
            "Genesis file invalid size/type",
        )
    })
}

#[test]
fn s03_06_initialize_rejects_oversized_genesis_file() -> TestResult {
    with_section("06_oversized_genesis", false, |section, opts, root| {
        let founder = wallet_with_pair("05");
        let genesis_path = write_oversized_file(root, "oversized.json")?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "Genesis file invalid size/type",
        )
    })
}

#[test]
fn s03_07_initialize_rejects_malformed_json_genesis() -> TestResult {
    with_section("07_malformed_json", false, |section, opts, root| {
        let founder = wallet_with_pair("06");
        let genesis_path = write_raw_file(root, "bad.json", br#"{"chain_id":"remzar","#)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "Serialization error",
        )
    })
}

#[test]
fn s03_08_initialize_rejects_empty_chain_id() -> TestResult {
    with_section("08_empty_chain_id", false, |section, opts, root| {
        let founder = wallet_with_pair("07");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.chain_id.clear();
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "chain_id is empty",
        )
    })
}

#[test]
fn s03_09_initialize_rejects_chain_id_over_128_bytes() -> TestResult {
    with_section("09_long_chain_id", false, |section, opts, root| {
        let founder = wallet_with_pair("08");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.chain_id = "x".repeat(129);
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "chain_id too long",
        )
    })
}

#[test]
fn s03_10_initialize_rejects_missing_version() -> TestResult {
    with_section("10_missing_version", false, |section, opts, root| {
        let founder = wallet_with_pair("09");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = None;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "version validation failed",
        )
    })
}

#[test]
fn s03_11_initialize_rejects_invalid_semver_version() -> TestResult {
    with_section("11_bad_version", false, |section, opts, root| {
        let founder = wallet_with_pair("0a");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some("1".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "invalid format",
        )
    })
}

#[test]
fn s03_12_initialize_rejects_empty_description() -> TestResult {
    with_section("12_empty_description", false, |section, opts, root| {
        let founder = wallet_with_pair("0b");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.description = Some("   ".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "description is empty",
        )
    })
}

#[test]
fn s03_13_initialize_rejects_description_over_500_chars() -> TestResult {
    with_section("13_long_description", false, |section, opts, root| {
        let founder = wallet_with_pair("0c");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.description = Some("d".repeat(501));
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "description is too long",
        )
    })
}

#[test]
fn s03_14_initialize_rejects_empty_genesis_block_data() -> TestResult {
    with_section("14_empty_block_data", false, |section, opts, root| {
        let founder = wallet_with_pair("0d");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.genesis_block.data.clear();
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "Genesis block data is empty",
        )
    })
}

#[test]
fn s03_15_initialize_rejects_oversized_genesis_block_data() -> TestResult {
    with_section("15_large_block_data", false, |section, opts, root| {
        let founder = wallet_with_pair("0e");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.genesis_block.data = "x".repeat(1025);
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "Genesis block data too large",
        )
    })
}

#[test]
fn s03_16_initialize_rejects_zero_merkle_root() -> TestResult {
    with_section("16_zero_merkle_root", false, |section, opts, root| {
        let founder = wallet_with_pair("0f");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.genesis_block.merkle_root = [0u8; 64];
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "Merkle root is all zeros",
        )
    })
}

#[test]
fn s03_17_initialize_rejects_zero_genesis_hash() -> TestResult {
    with_section("17_zero_genesis_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("10");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.genesis_block.genesis_hash = [0u8; 64];
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "Genesis hash is all zeros",
        )
    })
}

#[test]
fn s03_18_initialize_rejects_tampered_genesis_hash() -> TestResult {
    with_section("18_tampered_genesis_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("11");
        let mut genesis = valid_genesis_file(&founder)?;
        if let Some(first_byte) = genesis.genesis_block.genesis_hash.first_mut() {
            *first_byte = first_byte.wrapping_add(1);
        }
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "genesis_hash mismatch",
        )
    })
}

#[test]
fn s03_19_initialize_rejects_duplicate_hash_fields() -> TestResult {
    with_section("19_duplicate_hash_fields", false, |section, opts, root| {
        let founder = wallet_with_pair("12");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.genesis_block.prev_hash = genesis.genesis_block.merkle_root;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "hash fields must all be unique",
        )
    })
}

#[test]
fn s03_20_initialize_rejects_empty_founder_wallet_argument() -> TestResult {
    with_section("20_empty_founder_arg", false, |section, opts, root| {
        let founder = wallet_with_pair("13");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, ""),
            "Founder wallet address is invalid or incomplete",
        )
    })
}

#[test]
fn s03_21_initialize_rejects_short_founder_wallet_argument() -> TestResult {
    with_section("21_short_founder_arg", false, |section, opts, root| {
        let founder = wallet_with_pair("14");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, "r1234"),
            "Founder wallet address is invalid or incomplete",
        )
    })
}

#[test]
fn s03_22_initialize_rejects_bad_founder_wallet_prefix() -> TestResult {
    with_section("22_bad_founder_prefix", false, |section, opts, root| {
        let founder = wallet_with_pair("15");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let mut bad_founder = founder.clone();
        bad_founder.replace_range(..1, "x");
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &bad_founder),
            "Founder wallet address is invalid or incomplete",
        )
    })
}

#[test]
fn s03_23_initialize_rejects_non_hex_founder_wallet_argument() -> TestResult {
    with_section("23_non_hex_founder", false, |section, opts, root| {
        let founder = wallet_with_pair("16");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let mut bad_founder = String::from("r");
        for _ in 0..64 {
            bad_founder.push_str("gg");
        }
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &bad_founder),
            "Founder wallet address is invalid or incomplete",
        )
    })
}

#[test]
fn s03_24_initialize_fresh_chain_stores_latest_block() -> TestResult {
    with_section("24_store_latest_block", false, |section, opts, root| {
        let founder = wallet_with_pair("17");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let latest = manager
            .get_latest_block()?
            .ok_or_else(|| boxed_error("missing latest block after genesis initialization"))?;
        assert_eq!(latest.metadata.index, 0);
        Ok(())
    })
}

#[test]
fn s03_25_initialize_fresh_chain_stores_block_zero_by_index() -> TestResult {
    with_section("25_store_block_zero", false, |section, opts, root| {
        let founder = wallet_with_pair("18");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0 after genesis initialization"))?;
        assert_eq!(block0.metadata.index, 0);
        Ok(())
    })
}

#[test]
fn s03_26_initialize_fresh_chain_sets_local_wallet_to_founder() -> TestResult {
    with_section("26_local_wallet", false, |section, opts, root| {
        let founder = wallet_with_pair("19");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        drop(manager);
        assert_eq!(section.local_wallet.as_str(), founder.as_str());
        Ok(())
    })
}

#[test]
fn s03_27_initialize_fresh_chain_sets_tip_height_zero() -> TestResult {
    with_section("27_tip_height", false, |section, opts, root| {
        let founder = wallet_with_pair("1a");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        assert_eq!(manager.get_tip_height()?, 0);
        Ok(())
    })
}

#[test]
fn s03_28_initialize_fresh_chain_sets_latest_block_index_zero() -> TestResult {
    with_section("28_latest_index", false, |section, opts, root| {
        let founder = wallet_with_pair("1b");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        assert_eq!(manager.get_latest_block_index()?, 0);
        Ok(())
    })
}

#[test]
fn s03_29_initialize_fresh_chain_maps_canonical_height_zero_to_block_hash() -> TestResult {
    with_section("29_canonical_height_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("1c");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        let canonical_hash = manager
            .get_canonical_hash_at_height(0)?
            .ok_or_else(|| boxed_error("missing canonical height 0 hash"))?;
        assert_eq!(canonical_hash, block0.block_hash);
        Ok(())
    })
}

#[test]
fn s03_30_initialize_fresh_chain_sets_canonical_tip_to_block_zero() -> TestResult {
    with_section("30_canonical_tip", false, |section, opts, root| {
        let founder = wallet_with_pair("1d");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        let canonical_tip = manager
            .get_canonical_tip()?
            .ok_or_else(|| boxed_error("missing canonical tip"))?;
        assert_eq!(canonical_tip.tip_height, 0);
        assert_eq!(canonical_tip.tip_hash, block0.block_hash);
        Ok(())
    })
}

#[test]
fn s03_31_initialize_fresh_chain_persists_fork_graph_meta_for_genesis() -> TestResult {
    with_section("31_fork_graph_meta", false, |section, opts, root| {
        let founder = wallet_with_pair("1e");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        let meta = manager
            .get_block_meta_by_hash(&block0.block_hash)?
            .ok_or_else(|| boxed_error("missing fork meta for block 0"))?;
        assert_eq!(meta.height, 0);
        assert_eq!(meta.status, ForkBlockStatus::Canonical);
        assert_eq!(meta.parent_hash, block0.metadata.previous_hash);
        Ok(())
    })
}

#[test]
fn s03_32_initialize_fresh_chain_seeds_founder_validator_state() -> TestResult {
    with_section(
        "32_founder_validator_state",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("1f");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            let validator_state = ValidatorState::load_or_new(manager.clone())?;
            assert!(validator_state.is_canonically_known(&founder)?);
            let meta = validator_state
                .meta_for(&founder)
                .ok_or_else(|| boxed_error("founder meta missing from validator state"))?;
            assert_eq!(meta.join_height, 0);
            assert!(meta.exit_height.is_none());
            Ok(())
        },
    )
}

#[test]
fn s03_33_initialize_resume_existing_chain_preserves_block_zero_hash() -> TestResult {
    with_section("33_resume_preserves_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("20");
        let first_manager = initialize_valid_chain(section, opts, root, &founder)?;
        let first_block0 = first_manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing first block 0"))?;
        drop(first_manager);

        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "resume-genesis.json", &genesis)?;
        let second_manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        let second_block0 = second_manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing resumed block 0"))?;

        assert_eq!(second_block0.block_hash, first_block0.block_hash);
        Ok(())
    })
}

#[test]
fn s03_34_initialize_force_true_on_empty_db_creates_chain_without_prompt() -> TestResult {
    with_section("34_force_empty_db", false, |section, opts, root| {
        let founder = wallet_with_pair("21");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, true, &genesis_path, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0 after force-empty initialization"))?;
        assert_eq!(block0.miner_wallet(), founder.as_str());
        Ok(())
    })
}

#[test]
fn s03_35_property_multiple_valid_founders_initialize_with_matching_miners() -> TestResult {
    for pair in ["22", "23", "24", "25"] {
        let case_name = format!("35_valid_founder_{pair}");
        with_section(&case_name, false, |section, opts, root| {
            let founder = wallet_with_pair(pair);
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            let block0 = manager
                .get_block_by_index(0)?
                .ok_or_else(|| boxed_error("missing block 0"))?;
            assert_eq!(block0.miner_wallet(), founder.as_str());
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn s03_36_fuzz_invalid_founder_wallet_inputs_are_rejected() -> TestResult {
    with_section("36_fuzz_founders", false, |section, opts, root| {
        let founder = wallet_with_pair("26");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;

        let invalid_inputs = [
            "",
            "r",
            "r00",
            "x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "rzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "r111111111111111111111111111111111111111111111111111111111111111 1111111111111111111111111111111111111111111111111111111111111111",
            "r111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        ];

        for invalid in invalid_inputs {
            let result = section.initialize_blockchain(opts, false, &genesis_path, invalid);
            let error = expect_error(result)?;
            assert!(
                error
                    .to_string()
                    .contains("Founder wallet address is invalid or incomplete"),
                "unexpected error for invalid founder '{invalid}': {error}"
            );
        }

        Ok(())
    })
}

#[test]
fn s03_37_fuzz_malformed_json_payloads_are_rejected_before_db_genesis() -> TestResult {
    with_section("37_fuzz_json", false, |section, opts, root| {
        let founder = wallet_with_pair("27");
        let payloads: [&[u8]; 8] = [
            b"{",
            b"[]",
            b"null",
            b"true",
            b"123",
            br#"{"chain_id":""}"#,
            br#"{"chain_id":"x","version":"1.0.0"}"#,
            br#"{"chain_id":"x","version":"1.0.0","genesis_block":{}}"#,
        ];

        for (idx, payload) in payloads.iter().enumerate() {
            let file_name = format!("bad-{idx}.json");
            let genesis_path = write_raw_file(root, &file_name, payload)?;
            let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
            let error = expect_error(result)?;
            let message = error.to_string();
            assert!(
                message.contains("Serialization error") || message.contains("Validation error"),
                "unexpected malformed-json error: {message}"
            );
        }

        Ok(())
    })
}

#[test]
fn s03_38_adversarial_db_guard_rejects_concurrent_lock_holder() -> TestResult {
    let temp = TempRoot::new("38_db_guard_lock")?;
    let db_dir = temp.path().join("guarded-db");
    let first_guard = enforce_db_ownership(&db_dir, "node-a")?;
    let second_result = enforce_db_ownership(&db_dir, "node-a");

    let second_error = expect_error(second_result)?;
    assert!(
        second_error.to_string().contains("already in use"),
        "expected concurrent lock rejection, got: {second_error}"
    );

    drop(first_guard);
    Ok(())
}

#[test]
fn s03_39_adversarial_db_guard_rejects_different_owner_after_unlock() -> TestResult {
    let temp = TempRoot::new("39_db_guard_owner")?;
    let db_dir = temp.path().join("guarded-db");

    let first_guard = enforce_db_ownership(&db_dir, "node-a")?;
    drop(first_guard);

    let same_owner = enforce_db_ownership(&db_dir, "node-a")?;
    drop(same_owner);

    let different_owner = enforce_db_ownership(&db_dir, "node-b");
    let error = expect_error(different_owner)?;
    assert!(
        error.to_string().contains("DB ownership mismatch"),
        "expected owner mismatch rejection, got: {error}"
    );

    Ok(())
}

#[test]
fn s03_40_start_node_already_running_returns_ok_and_initializes_ephemeral() -> TestResult {
    with_section(
        "40_start_node_already_running",
        true,
        |section, _opts, root| {
            let logger = make_test_logger(root)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            runtime.block_on(async {
                section.start_node(&logger).await?;
                assert!(section.node_ephemeral.is_some());
                assert!(*section.p2p_running);
                Ok(())
            })
        },
    )
}

#[test]
fn s03_41_initialize_accepts_semver_prerelease_version() -> TestResult {
    with_section("41_semver_prerelease", false, |section, opts, root| {
        let founder = wallet_with_pair("28");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some("1.0.0-beta".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(block0.metadata.index, 0);
        Ok(())
    })
}

#[test]
fn s03_42_initialize_accepts_missing_description() -> TestResult {
    with_section("42_missing_description", false, |section, opts, root| {
        let founder = wallet_with_pair("29");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.description = None;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        assert!(manager.get_latest_block()?.is_some());
        Ok(())
    })
}

#[test]
fn s03_43_initialize_stores_block_zero_miner_as_founder() -> TestResult {
    with_section("43_block0_miner", false, |section, opts, root| {
        let founder = wallet_with_pair("2a");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(block0.miner_wallet(), founder.as_str());
        Ok(())
    })
}

#[test]
fn s03_44_initialize_stores_block_zero_reward_as_zero() -> TestResult {
    with_section("44_block0_reward", false, |section, opts, root| {
        let founder = wallet_with_pair("2b");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(block0.reward, 0);
        Ok(())
    })
}

#[test]
fn s03_45_initialize_stores_block_zero_without_batch_key() -> TestResult {
    with_section("45_block0_no_batch_key", false, |section, opts, root| {
        let founder = wallet_with_pair("2c");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert!(block0.batch_key.is_none());
        Ok(())
    })
}

#[test]
fn s03_46_initialize_stores_nonzero_block_hash() -> TestResult {
    with_section("46_nonzero_block_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("2d");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_ne!(block0.block_hash, [0u8; 64]);
        Ok(())
    })
}

#[test]
fn s03_47_initialize_stores_configured_genesis_previous_hash() -> TestResult {
    with_section("47_prev_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("2e");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(
            block0.metadata.previous_hash,
            GlobalConfiguration::GENESIS_PREV_HASH_BYTES
        );
        Ok(())
    })
}

#[test]
fn s03_48_initialize_preserves_genesis_merkle_root() -> TestResult {
    with_section("48_merkle_root", false, |section, opts, root| {
        let founder = wallet_with_pair("2f");
        let genesis = valid_genesis_file(&founder)?;
        let expected_merkle_root = genesis.genesis_block.merkle_root;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(block0.metadata.merkle_root, expected_merkle_root);
        Ok(())
    })
}

#[test]
fn s03_49_initialize_canonicalizes_uppercase_founder_hex_argument() -> TestResult {
    with_section("49_upper_founder_arg", false, |section, opts, root| {
        let canonical_founder = wallet_with_pair("aa");
        let uppercase_founder = wallet_with_upper_hex_pair("aa");
        let genesis = valid_genesis_file(&canonical_founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager =
            section.initialize_blockchain(opts, false, &genesis_path, &uppercase_founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(block0.miner_wallet(), canonical_founder.as_str());
        Ok(())
    })
}

#[test]
fn s03_50_initialize_rejects_too_long_founder_wallet_argument() -> TestResult {
    with_section("50_long_founder_arg", false, |section, opts, root| {
        let founder = wallet_with_pair("30");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let mut too_long = founder.clone();
        too_long.push('0');
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &too_long),
            "Founder wallet address is invalid or incomplete",
        )
    })
}

#[test]
fn s03_51_initialize_rejects_founder_wallet_with_internal_space() -> TestResult {
    with_section("51_founder_internal_space", false, |section, opts, root| {
        let founder = wallet_with_pair("31");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let invalid = "r3131313131313131313131313131313131313131313131313131313131313131 3131313131313131313131313131313131313131313131313131313131313131";
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, invalid),
            "Founder wallet address is invalid or incomplete",
        )
    })
}

#[test]
fn s03_52_initialize_rejects_founder_wallet_with_internal_newline() -> TestResult {
    with_section(
        "52_founder_internal_newline",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("32");
            let genesis = valid_genesis_file(&founder)?;
            let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
            let invalid = "r3232323232323232323232323232323232323232323232323232323232323232\n3232323232323232323232323232323232323232323232323232323232323232";
            assert_error_contains(
                section.initialize_blockchain(opts, false, &genesis_path, invalid),
                "Founder wallet address is invalid or incomplete",
            )
        },
    )
}

#[test]
fn s03_53_initialize_rejects_build_metadata_semver() -> TestResult {
    with_section("53_build_metadata_semver", false, |section, opts, root| {
        let founder = wallet_with_pair("33");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some("1.0.0+build".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "invalid format",
        )
    })
}

#[test]
fn s03_54_initialize_rejects_dotted_prerelease_semver() -> TestResult {
    with_section("54_dotted_prerelease", false, |section, opts, root| {
        let founder = wallet_with_pair("34");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some("1.0.0-beta.1".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        assert_error_contains(
            section.initialize_blockchain(opts, false, &genesis_path, &founder),
            "invalid format",
        )
    })
}

#[test]
fn s03_55_initialize_rejects_genesis_timestamp_below_minimum() -> TestResult {
    with_section("55_low_timestamp", false, |section, opts, root| {
        let founder = wallet_with_pair("35");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.genesis_block.timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1);
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;

        let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
        let error = expect_error(result)?;
        let message = error.to_string();

        assert!(
            message.contains("timestamp below UNIX_2000_SECS"),
            "unexpected low timestamp error: {message}"
        );

        Ok(())
    })
}

#[test]
fn s03_56_initialize_rejects_invalid_founder_wallet_inside_genesis_file() -> TestResult {
    with_section(
        "56_invalid_founder_in_genesis",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("36");
            let mut genesis = valid_genesis_file(&founder)?;
            genesis.genesis_block.founder_wallet = Some("not-a-wallet".to_owned());
            let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
            let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
            let error = expect_error(result)?;
            assert!(
                error.to_string().contains("Validation error"),
                "unexpected error: {error}"
            );
            Ok(())
        },
    )
}

#[test]
fn s03_57_initialize_accepts_uppercase_founder_wallet_inside_genesis_file() -> TestResult {
    with_section(
        "57_upper_founder_in_genesis",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("37");
            let mut genesis = valid_genesis_file(&founder)?;

            genesis.genesis_block.founder_wallet = Some(wallet_with_upper_hex_pair("37"));

            let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
            let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;

            let block0 = manager
                .get_block_by_index(0)?
                .ok_or_else(|| boxed_error("missing block 0"))?;

            assert_eq!(block0.miner_wallet(), founder.as_str());
            assert_eq!(section.local_wallet.as_str(), founder.as_str());

            Ok(())
        },
    )
}

#[test]
fn s03_58_initialize_success_overwrites_existing_local_wallet() -> TestResult {
    with_section(
        "58_overwrites_local_wallet",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("38");
            *section.local_wallet = wallet_with_pair("39");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            drop(manager);
            assert_eq!(section.local_wallet.as_str(), founder.as_str());
            Ok(())
        },
    )
}

#[test]
fn s03_59_initialize_failure_preserves_existing_local_wallet() -> TestResult {
    with_section(
        "59_failure_preserves_wallet",
        false,
        |section, opts, root| {
            let existing_wallet = wallet_with_pair("3a");
            *section.local_wallet = existing_wallet.clone();
            let founder = wallet_with_pair("3b");
            let genesis_path = write_raw_file(root, "bad.json", b"{")?;
            let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
            assert!(result.is_err());
            assert_eq!(section.local_wallet.as_str(), existing_wallet.as_str());
            Ok(())
        },
    )
}

#[test]
fn s03_60_initialize_writes_latest_block_index_metadata_as_zero() -> TestResult {
    with_section("60_latest_index_raw", false, |section, opts, root| {
        let founder = wallet_with_pair("3c");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let raw = manager
            .read(
                GlobalConfiguration::GLOBAL_COLUMN_NAME,
                b"latest_block_index",
            )?
            .ok_or_else(|| boxed_error("latest_block_index metadata missing"))?;
        assert_eq!(raw, 0u64.to_be_bytes());
        Ok(())
    })
}

#[test]
fn s03_61_initialize_writes_tip_height_metadata_as_zero() -> TestResult {
    with_section("61_tip_height_raw", false, |section, opts, root| {
        let founder = wallet_with_pair("3d");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let raw = manager
            .read(GlobalConfiguration::GLOBAL_COLUMN_NAME, b"tip_height")?
            .ok_or_else(|| boxed_error("tip_height metadata missing"))?;
        assert_eq!(raw, 0u64.to_be_bytes());
        Ok(())
    })
}

#[test]
fn s03_62_initialize_latest_block_hash_matches_block_zero_hash() -> TestResult {
    with_section("62_latest_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("3e");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        let latest_hash = manager.get_latest_block_hash()?;
        assert_eq!(latest_hash, block0.block_hash);
        Ok(())
    })
}

#[test]
fn s03_63_initialize_latest_block_iterator_returns_storage_bytes() -> TestResult {
    with_section("63_latest_iter_bytes", false, |section, opts, root| {
        let founder = wallet_with_pair("3f");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let bytes = manager
            .get_latest_block_by_iter()?
            .ok_or_else(|| boxed_error("latest block bytes missing"))?;
        assert!(!bytes.is_empty());
        let block = remzar::blockchain::block_002_blocks::Block::deserialize_from_storage(&bytes)?;
        assert_eq!(block.metadata.index, 0);
        Ok(())
    })
}

#[test]
fn s03_64_initialize_block_zero_storage_bytes_are_within_max_block_size() -> TestResult {
    with_section("64_block_storage_size", false, |section, opts, root| {
        let founder = wallet_with_pair("40");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let bytes = manager
            .get_latest_block_by_iter()?
            .ok_or_else(|| boxed_error("latest block bytes missing"))?;
        let max_block_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
            .map_err(|_| boxed_error("MAX_BLOCK_SIZE does not fit usize"))?;
        assert!(bytes.len() <= max_block_size);
        Ok(())
    })
}

#[test]
fn s03_65_initialize_canonical_tip_hash_matches_latest_block_hash() -> TestResult {
    with_section("65_tip_latest_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("41");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let latest_hash = manager.get_latest_block_hash()?;
        let canonical_tip = manager
            .get_canonical_tip()?
            .ok_or_else(|| boxed_error("canonical tip missing"))?;
        assert_eq!(canonical_tip.tip_hash, latest_hash);
        assert_eq!(canonical_tip.tip_height, 0);
        Ok(())
    })
}

#[test]
fn s03_66_initialize_has_no_canonical_hash_for_height_one() -> TestResult {
    with_section("66_no_height_one_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("42");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        assert!(manager.get_canonical_hash_at_height(1)?.is_none());
        Ok(())
    })
}

#[test]
fn s03_67_initialize_has_no_fork_meta_for_unknown_hash() -> TestResult {
    with_section("67_unknown_fork_meta", false, |section, opts, root| {
        let founder = wallet_with_pair("43");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let unknown_hash = [7u8; 64];
        assert!(manager.get_block_meta_by_hash(&unknown_hash)?.is_none());
        Ok(())
    })
}

#[test]
fn s03_68_initialize_fork_meta_has_nonzero_received_timestamp() -> TestResult {
    with_section("68_fork_meta_timestamp", false, |section, opts, root| {
        let founder = wallet_with_pair("44");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        let meta = manager
            .get_block_meta_by_hash(&block0.block_hash)?
            .ok_or_else(|| boxed_error("missing fork meta"))?;
        assert!(meta.received_at_unix_secs > 0);
        Ok(())
    })
}

#[test]
fn s03_69_validator_state_reload_preserves_genesis_founder() -> TestResult {
    with_section("69_validator_reload", false, |section, opts, root| {
        let founder = wallet_with_pair("45");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let first_state = ValidatorState::load_or_new(manager.clone())?;
        assert!(first_state.is_canonically_known(&founder)?);
        drop(first_state);

        let second_state = ValidatorState::load_or_new(manager.clone())?;
        assert!(second_state.is_canonically_known(&founder)?);
        Ok(())
    })
}

#[test]
fn s03_70_reopen_blockchain_manager_preserves_genesis_state() -> TestResult {
    with_section("70_reopen_manager", false, |section, opts, root| {
        let founder = wallet_with_pair("46");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        drop(manager);

        let directory = DirectoryDB::from_node_opts(opts).map_err(string_error)?;
        let reopened =
            RockDBManager::new_blockchain(opts, &directory.blockchain_path.to_string_lossy())?;
        let block0 = reopened
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0 after reopen"))?;
        assert_eq!(block0.miner_wallet(), founder.as_str());
        assert_eq!(reopened.get_tip_height()?, 0);
        Ok(())
    })
}

#[test]
fn s03_71_readonly_reopen_preserves_block_zero() -> TestResult {
    with_section("71_readonly_reopen", false, |section, opts, root| {
        let founder = wallet_with_pair("47");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        drop(manager);

        let directory = DirectoryDB::from_node_opts(opts).map_err(string_error)?;
        let readonly = RockDBManager::from_existing_readonly(opts, &directory.blockchain_path)?;
        let block0 = readonly
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing readonly block 0"))?;
        assert_eq!(block0.miner_wallet(), founder.as_str());
        Ok(())
    })
}

#[test]
fn s03_72_resume_missing_validator_state_recovers_from_block0_timestamp() -> TestResult {
    with_section(
        "72_resume_missing_validator_state_repair",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("48");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;

            let block0 = manager
                .get_block_by_index(0)?
                .ok_or_else(|| boxed_error("missing block 0 before validator-state delete"))?;
            let expected_join_timestamp = block0.metadata.timestamp;

            manager.delete(
                GlobalConfiguration::STATE_COLUMN_NAME,
                b"validator_state_v1",
            )?;
            drop(manager);

            let genesis = valid_genesis_file(&founder)?;
            let genesis_path = write_genesis_file(root, "resume.json", &genesis)?;

            let resumed = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
            let validator_state = ValidatorState::load_or_new(resumed.clone())?;

            assert!(validator_state.is_canonically_known(&founder)?);

            let meta = validator_state
                .meta_for(&founder)
                .ok_or_else(|| boxed_error("founder meta missing after resume repair"))?;

            assert_eq!(meta.join_height, 0);
            assert_eq!(meta.join_timestamp, expected_join_timestamp);
            assert!(meta.exit_height.is_none());

            Ok(())
        },
    )
}

#[test]
fn s03_73_resume_recovers_corrupted_validator_state_snapshot() -> TestResult {
    with_section(
        "73_resume_corrupt_validator",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("49");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            manager.write(
                GlobalConfiguration::STATE_COLUMN_NAME,
                b"validator_state_v1",
                b"not-valid-postcard",
            )?;
            drop(manager);

            let genesis = valid_genesis_file(&founder)?;
            let genesis_path = write_genesis_file(root, "resume.json", &genesis)?;
            let resumed = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
            let state = ValidatorState::load_or_new(resumed.clone())?;
            assert!(state.is_canonically_known(&founder)?);
            Ok(())
        },
    )
}

#[test]
fn s03_74_resume_existing_chain_does_not_replace_founder_from_new_valid_genesis() -> TestResult {
    with_section(
        "74_resume_different_genesis_founder",
        false,
        |section, opts, root| {
            let original_founder = wallet_with_pair("4a");
            let alternate_founder = wallet_with_pair("4b");

            let first_manager = initialize_valid_chain(section, opts, root, &original_founder)?;
            drop(first_manager);

            let alternate_genesis = valid_genesis_file(&alternate_founder)?;
            let alternate_path = write_genesis_file(root, "alternate.json", &alternate_genesis)?;
            let resumed =
                section.initialize_blockchain(opts, false, &alternate_path, &alternate_founder)?;

            let block0 = resumed
                .get_block_by_index(0)?
                .ok_or_else(|| boxed_error("missing block 0 after resume"))?;
            assert_eq!(block0.miner_wallet(), original_founder.as_str());
            Ok(())
        },
    )
}

#[test]
fn s03_75_load_initialize_many_isolated_fresh_chains() -> TestResult {
    for pair in ["4c", "4d", "4e", "4f", "50", "51", "52", "53"] {
        let case_name = format!("75_load_chain_{pair}");
        with_section(&case_name, false, |section, opts, root| {
            let founder = wallet_with_pair(pair);
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            let block0 = manager
                .get_block_by_index(0)?
                .ok_or_else(|| boxed_error("missing block 0"))?;
            assert_eq!(block0.miner_wallet(), founder.as_str());
            assert_eq!(manager.get_tip_height()?, 0);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn s03_76_vector_valid_founders_all_seed_validator_state() -> TestResult {
    for pair in ["54", "55", "56", "57"] {
        let case_name = format!("76_vector_founder_{pair}");
        with_section(&case_name, false, |section, opts, root| {
            let founder = wallet_with_pair(pair);
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            let state = ValidatorState::load_or_new(manager.clone())?;
            assert!(state.is_canonically_known(&founder)?);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn s03_77_vector_invalid_versions_are_rejected() -> TestResult {
    with_section("77_invalid_versions", false, |section, opts, root| {
        let founder = wallet_with_pair("58");
        let invalid_versions = ["", "1", "1.0", "v1.0.0", "1.0.0-", "1.0.0_beta"];

        for version in invalid_versions {
            let mut genesis = valid_genesis_file(&founder)?;
            genesis.version = Some(version.to_owned());
            let file_name = format!("bad-version-{}.json", uuid::Uuid::new_v4());
            let genesis_path = write_genesis_file(root, &file_name, &genesis)?;
            let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
            let error = expect_error(result)?;
            assert!(
                error.to_string().contains("version"),
                "unexpected invalid-version error for '{version}': {error}"
            );
        }

        Ok(())
    })
}

#[test]
fn s03_78_json_logger_accepts_start_node_error_event_shape() -> TestResult {
    let temp = TempRoot::new("78_logger_event")?;
    let logger = make_test_logger(temp.path())?;
    logger
        .log_error_event("p2p", "NoDialCandidatesAtStartup", "test event")
        .map_err(string_error)?;
    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;
    Ok(())
}

#[test]
fn s03_79_db_guard_writes_owner_file_for_new_database() -> TestResult {
    let temp = TempRoot::new("79_owner_file")?;
    let db_dir = temp.path().join("guarded-db");
    let guard = enforce_db_ownership(&db_dir, "node-owner")?;
    let owner_path = guard.db_dir.join("OWNER");
    let owner = fs::read_to_string(owner_path)?;
    assert_eq!(owner.trim(), "node-owner");
    Ok(())
}

#[test]
fn s03_80_start_node_already_running_preserves_wallet_and_runtime_slots() -> TestResult {
    with_section(
        "80_start_node_preserves_state",
        true,
        |section, _opts, root| {
            let wallet = wallet_with_pair("59");
            *section.local_wallet = wallet.clone();

            let logger = make_test_logger(root)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            runtime.block_on(async {
                section.start_node(&logger).await?;
                assert!(section.node_ephemeral.is_some());
                assert!(*section.p2p_running);
                assert_eq!(section.local_wallet.as_str(), wallet.as_str());
                assert!(section.p2p_handle.is_none());
                assert!(section.net_tx.is_none());
                Ok(())
            })
        },
    )
}

#[test]
fn s03_81_initialize_accepts_chain_id_exactly_128_bytes() -> TestResult {
    with_section("81_chain_id_128", false, |section, opts, root| {
        let founder = wallet_with_pair("5a");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.chain_id = "c".repeat(128);
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        assert!(manager.get_latest_block()?.is_some());
        Ok(())
    })
}

#[test]
fn s03_82_initialize_accepts_description_exactly_500_chars() -> TestResult {
    with_section("82_description_500", false, |section, opts, root| {
        let founder = wallet_with_pair("5b");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.description = Some("d".repeat(500));
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        assert!(manager.get_latest_block()?.is_some());
        Ok(())
    })
}

#[test]
fn s03_83_initialize_accepts_genesis_data_exactly_1024_chars() -> TestResult {
    with_section("83_data_1024", false, |section, opts, root| {
        let founder = wallet_with_pair("5c");
        let data = "x".repeat(1024);
        let genesis = valid_genesis_with_data(&founder, &data)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(block0.metadata.index, 0);
        Ok(())
    })
}

#[test]
fn s03_84_initialize_accepts_zero_semver_version() -> TestResult {
    with_section("84_zero_semver", false, |section, opts, root| {
        let founder = wallet_with_pair("5d");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some("0.0.0".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        assert!(manager.get_latest_block()?.is_some());
        Ok(())
    })
}

#[test]
fn s03_85_initialize_accepts_large_numeric_semver_version() -> TestResult {
    with_section("85_large_semver", false, |section, opts, root| {
        let founder = wallet_with_pair("5e");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some("999.999.999".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        assert!(manager.get_latest_block()?.is_some());
        Ok(())
    })
}

#[test]
fn s03_86_initialize_canonicalizes_founder_argument_with_outer_whitespace() -> TestResult {
    with_section("86_founder_whitespace", false, |section, opts, root| {
        let founder = wallet_with_pair("5f");
        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let input = format!("  {founder}\n");
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &input)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        assert_eq!(block0.miner_wallet(), founder.as_str());
        Ok(())
    })
}

#[test]
fn s03_87_initialize_canonicalizes_uppercase_founder_argument_with_outer_whitespace() -> TestResult
{
    with_section(
        "87_upper_founder_whitespace",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("aa");
            let upper = wallet_with_upper_hex_pair("aa");
            let genesis = valid_genesis_file(&founder)?;
            let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
            let input = format!("\t{upper}\r\n");
            let manager = section.initialize_blockchain(opts, false, &genesis_path, &input)?;
            let block0 = manager
                .get_block_by_index(0)?
                .ok_or_else(|| boxed_error("missing block 0"))?;
            assert_eq!(block0.miner_wallet(), founder.as_str());
            Ok(())
        },
    )
}

#[test]
fn s03_88_initialize_accepts_nested_genesis_path() -> TestResult {
    with_section("88_nested_genesis", false, |section, opts, root| {
        let founder = wallet_with_pair("60");
        let nested = root.join("nested").join("config");
        fs::create_dir_all(&nested)?;
        let genesis = valid_genesis_file(&founder)?;
        let path = nested.join("genesis.json");
        let path_string = path_to_string(&path)?;
        genesis.to_json_file(&path_string)?;
        let manager = section.initialize_blockchain(opts, false, &path_string, &founder)?;
        assert!(manager.get_latest_block()?.is_some());
        Ok(())
    })
}

#[test]
fn s03_89_initialize_accepts_unicode_description() -> TestResult {
    with_section("89_unicode_description", false, |section, opts, root| {
        let founder = wallet_with_pair("61");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.description = Some("Remzar genesis 測試 ✅".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let manager = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        assert!(manager.get_latest_block()?.is_some());
        Ok(())
    })
}

#[test]
fn s03_90_initialize_rejects_whitespace_only_chain_id() -> TestResult {
    with_section("90_whitespace_chain_id", false, |section, opts, root| {
        let founder = wallet_with_pair("62");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.chain_id = "   ".to_owned();
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
        let error = expect_error(result)?;
        assert!(
            error.to_string().contains("chain_id"),
            "unexpected error: {error}"
        );
        Ok(())
    })
}

#[test]
fn s03_91_initialize_rejects_version_with_outer_whitespace() -> TestResult {
    with_section("91_version_whitespace", false, |section, opts, root| {
        let founder = wallet_with_pair("63");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some(" 1.0.0 ".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
        let error = expect_error(result)?;
        assert!(
            error.to_string().contains("version"),
            "unexpected error: {error}"
        );
        Ok(())
    })
}

#[test]
fn s03_92_initialize_rejects_tab_in_version() -> TestResult {
    with_section("92_version_tab", false, |section, opts, root| {
        let founder = wallet_with_pair("64");
        let mut genesis = valid_genesis_file(&founder)?;
        genesis.version = Some("1.0\t.0".to_owned());
        let genesis_path = write_genesis_file(root, "genesis.json", &genesis)?;
        let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
        let error = expect_error(result)?;
        assert!(
            error.to_string().contains("version"),
            "unexpected error: {error}"
        );
        Ok(())
    })
}

#[test]
fn s03_93_initialize_rejects_genesis_file_with_only_whitespace_bytes() -> TestResult {
    with_section("93_whitespace_file", false, |section, opts, root| {
        let founder = wallet_with_pair("65");
        let genesis_path = write_raw_file(root, "blank.json", b"   \n\t  ")?;
        let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
        assert!(result.is_err());
        Ok(())
    })
}

#[test]
fn s03_94_initialize_returns_blockchain_mode_manager() -> TestResult {
    with_section("94_manager_mode", false, |section, opts, root| {
        let founder = wallet_with_pair("66");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        assert_eq!(
            manager.mode,
            remzar::storage::rocksdb_005_manager::Mode::Blockchain
        );
        Ok(())
    })
}

#[test]
fn s03_95_initialize_creates_blockchain_directory() -> TestResult {
    with_section("95_blockchain_dir_exists", false, |section, opts, root| {
        let founder = wallet_with_pair("67");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let directory = DirectoryDB::from_node_opts(opts).map_err(string_error)?;
        assert!(directory.blockchain_path.exists());
        assert!(directory.blockchain_path.is_dir());
        drop(manager);
        Ok(())
    })
}

#[test]
fn s03_96_block_zero_storage_round_trip_preserves_hash() -> TestResult {
    with_section("96_block_round_trip_hash", false, |section, opts, root| {
        let founder = wallet_with_pair("68");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let block0 = manager
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0"))?;
        let bytes = block0.serialize_for_storage()?;
        let round_trip =
            remzar::blockchain::block_002_blocks::Block::deserialize_from_storage(&bytes)?;
        assert_eq!(round_trip.block_hash, block0.block_hash);
        assert_eq!(round_trip.metadata.index, 0);
        Ok(())
    })
}

#[test]
fn s03_97_cloned_manager_reads_same_block_zero() -> TestResult {
    with_section("97_clone_manager", false, |section, opts, root| {
        let founder = wallet_with_pair("69");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let cloned = manager.clone();
        let block0 = cloned
            .get_block_by_index(0)?
            .ok_or_else(|| boxed_error("missing block 0 from cloned manager"))?;
        assert_eq!(block0.miner_wallet(), founder.as_str());
        Ok(())
    })
}

#[test]
fn s03_98_validator_state_does_not_mark_unrelated_wallet_known() -> TestResult {
    with_section("98_unrelated_validator", false, |section, opts, root| {
        let founder = wallet_with_pair("6a");
        let stranger = wallet_with_pair("6b");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let state = ValidatorState::load_or_new(manager.clone())?;
        assert!(state.is_canonically_known(&founder)?);
        assert!(!state.is_canonically_known(&stranger)?);
        assert!(state.meta_for(&stranger).is_none());
        Ok(())
    })
}

#[test]
fn s03_99_validator_state_meta_is_stable_across_multiple_loads() -> TestResult {
    with_section("99_validator_meta_stable", false, |section, opts, root| {
        let founder = wallet_with_pair("6c");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        let first = ValidatorState::load_or_new(manager.clone())?
            .meta_for(&founder)
            .ok_or_else(|| boxed_error("missing first founder meta"))?;
        let second = ValidatorState::load_or_new(manager.clone())?
            .meta_for(&founder)
            .ok_or_else(|| boxed_error("missing second founder meta"))?;
        assert_eq!(first.join_height, second.join_height);
        assert_eq!(first.exit_height, second.exit_height);
        Ok(())
    })
}

#[test]
fn s03_100_resume_existing_chain_still_requires_genesis_path_to_exist() -> TestResult {
    with_section(
        "100_resume_missing_genesis_path",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("6d");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            drop(manager);

            let missing_path = path_to_string(&root.join("missing-resume-genesis.json"))?;
            assert_error_contains(
                section.initialize_blockchain(opts, false, &missing_path, &founder),
                "Failed to stat genesis file",
            )
        },
    )
}

#[test]
fn s03_101_resume_existing_chain_rejects_malformed_supplied_genesis() -> TestResult {
    with_section("101_resume_bad_genesis", false, |section, opts, root| {
        let founder = wallet_with_pair("6e");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        drop(manager);

        let bad_path = write_raw_file(root, "bad-resume.json", b"{")?;
        let result = section.initialize_blockchain(opts, false, &bad_path, &founder);
        assert!(result.is_err());
        Ok(())
    })
}

#[test]
fn s03_102_resume_existing_chain_rejects_invalid_founder_argument_before_resume() -> TestResult {
    with_section(
        "102_resume_bad_founder_arg",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("6f");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            drop(manager);

            let genesis = valid_genesis_file(&founder)?;
            let genesis_path = write_genesis_file(root, "resume.json", &genesis)?;
            assert_error_contains(
                section.initialize_blockchain(opts, false, &genesis_path, "not-a-wallet"),
                "Founder wallet address is invalid or incomplete",
            )
        },
    )
}

#[test]
fn s03_103_resume_existing_chain_preserves_original_local_wallet() -> TestResult {
    with_section("103_resume_local_wallet", false, |section, opts, root| {
        let founder = wallet_with_pair("70");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        drop(manager);

        *section.local_wallet = String::new();

        let genesis = valid_genesis_file(&founder)?;
        let genesis_path = write_genesis_file(root, "resume.json", &genesis)?;
        let resumed = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
        drop(resumed);

        assert!(section.local_wallet.is_empty());
        Ok(())
    })
}

#[test]
fn s03_104_resume_existing_chain_preserves_original_block_hash_even_with_changed_description()
-> TestResult {
    with_section(
        "104_resume_changed_description",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("71");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            let original_hash = manager.get_latest_block_hash()?;
            drop(manager);

            let mut changed = valid_genesis_file(&founder)?;
            changed.description = Some("changed description for resume".to_owned());
            let changed_path = write_genesis_file(root, "changed.json", &changed)?;
            let resumed = section.initialize_blockchain(opts, false, &changed_path, &founder)?;
            assert_eq!(resumed.get_latest_block_hash()?, original_hash);
            Ok(())
        },
    )
}

#[test]
fn s03_105_existing_chain_resume_with_corrupted_validator_state_rebuilds_founder() -> TestResult {
    with_section(
        "105_resume_corrupt_validator_again",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("72");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            manager.write(
                GlobalConfiguration::STATE_COLUMN_NAME,
                b"validator_state_v1",
                &[0x80, 0x81, 0x82, 0x83],
            )?;
            drop(manager);

            let genesis = valid_genesis_file(&founder)?;
            let genesis_path = write_genesis_file(root, "resume.json", &genesis)?;
            let resumed = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
            let state = ValidatorState::load_or_new(resumed.clone())?;
            assert!(state.is_canonically_known(&founder)?);
            Ok(())
        },
    )
}

#[test]
fn s03_106_existing_chain_missing_validator_state_failure_preserves_local_wallet() -> TestResult {
    with_section(
        "106_missing_validator_preserve_wallet",
        false,
        |section, opts, root| {
            let founder = wallet_with_pair("73");
            let existing_wallet = wallet_with_pair("74");
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            manager.delete(
                GlobalConfiguration::STATE_COLUMN_NAME,
                b"validator_state_v1",
            )?;
            drop(manager);

            *section.local_wallet = existing_wallet.clone();

            let genesis = valid_genesis_file(&founder)?;
            let genesis_path = write_genesis_file(root, "resume.json", &genesis)?;
            let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);

            if result.is_err() {
                assert_eq!(section.local_wallet.as_str(), existing_wallet.as_str());
            }

            Ok(())
        },
    )
}

#[test]
fn s03_107_start_node_already_running_preserves_existing_ephemeral_wallet() -> TestResult {
    with_section("107_guard_ephemeral", true, |section, _opts, root| {
        let wallet = wallet_with_pair("75");
        let ephemeral = NodeEphemeral::new();
        ephemeral.register_wallet_strict(&wallet, 0)?;
        *section.node_ephemeral = Some(ephemeral);

        let logger = make_test_logger(root)?;
        run_start_node_guard_once(section, &logger)?;

        let stored = section
            .node_ephemeral
            .as_ref()
            .ok_or_else(|| boxed_error("missing node_ephemeral"))?;
        let handle = stored.ephemeral();
        let guard = handle
            .lock()
            .map_err(|_| boxed_error("ephemeral registry mutex poisoned"))?;
        assert!(guard.is_registered(&wallet));
        Ok(())
    })
}

#[test]
fn s03_108_start_node_already_running_preserves_node_registry_snapshot() -> TestResult {
    with_section("108_guard_registry", true, |section, _opts, root| {
        let wallet = wallet_with_pair("76");
        let mut registry = RegistryData::new();
        registry.wallets.insert(wallet.clone());
        *section.node_registry = Some(registry);

        let logger = make_test_logger(root)?;
        run_start_node_guard_once(section, &logger)?;

        let stored = section
            .node_registry
            .as_ref()
            .ok_or_else(|| boxed_error("missing node_registry"))?;
        assert!(stored.wallets.contains(&wallet));
        Ok(())
    })
}

#[test]
fn s03_109_start_node_already_running_preserves_net_tx_channel() -> TestResult {
    with_section("109_guard_net_tx", true, |section, _opts, root| {
        let (tx, _rx) = tokio::sync::mpsc::channel::<NetCmd>(4);
        *section.net_tx = Some(tx);

        let logger = make_test_logger(root)?;
        run_start_node_guard_once(section, &logger)?;

        assert!(section.net_tx.is_some());
        Ok(())
    })
}

#[test]
fn s03_110_start_node_already_running_preserves_chain_slot() -> TestResult {
    with_section("110_guard_chain", true, |section, _opts, root| {
        let chain = AccountModelTree::with_manager((**section.db_manager).clone());
        *section.chain = Some(chain);

        let logger = make_test_logger(root)?;
        run_start_node_guard_once(section, &logger)?;

        assert!(section.chain.is_some());
        Ok(())
    })
}

#[test]
fn s03_111_start_node_already_running_preserves_blockchain_db_guard() -> TestResult {
    with_section("111_guard_db_guard", true, |section, _opts, root| {
        let guard_dir = root.join("guarded-chain");
        let guard = enforce_db_ownership(&guard_dir, "node-111")?;
        *section.blockchain_db_guard = Some(guard);

        let logger = make_test_logger(root)?;
        run_start_node_guard_once(section, &logger)?;

        assert!(section.blockchain_db_guard.is_some());
        Ok(())
    })
}

#[test]
fn s03_112_start_node_already_running_accepts_invalid_local_wallet_without_touching_it()
-> TestResult {
    with_section(
        "112_guard_invalid_wallet_unchanged",
        true,
        |section, _opts, root| {
            *section.local_wallet = "not-a-wallet".to_owned();

            let logger = make_test_logger(root)?;
            run_start_node_guard_once(section, &logger)?;

            assert_eq!(section.local_wallet.as_str(), "not-a-wallet");
            Ok(())
        },
    )
}

#[test]
fn s03_113_start_node_already_running_can_be_called_twice() -> TestResult {
    with_section("113_guard_twice", true, |section, _opts, root| {
        let logger = make_test_logger(root)?;
        run_start_node_guard_once(section, &logger)?;
        run_start_node_guard_once(section, &logger)?;

        assert!(*section.p2p_running);
        assert!(section.node_ephemeral.is_some());
        Ok(())
    })
}

#[test]
fn s03_114_start_node_already_running_logger_remains_usable_after_guard_return() -> TestResult {
    with_section("114_guard_logger_usable", true, |section, _opts, root| {
        let logger = make_test_logger(root)?;
        run_start_node_guard_once(section, &logger)?;

        logger
            .log_error_event("p2p", "AlreadyRunningGuardTest", "logger still writable")
            .map_err(string_error)?;
        logger.flush().map_err(string_error)?;
        Ok(())
    })
}

#[test]
fn s03_115_db_guard_canonicalizes_created_database_directory() -> TestResult {
    let temp = TempRoot::new("115_guard_canonical")?;
    let db_dir = temp.path().join("a").join("..").join("guarded-db");
    let guard = enforce_db_ownership(&db_dir, "node-115")?;
    assert!(guard.db_dir.is_absolute());
    assert!(guard.db_dir.exists());
    Ok(())
}

#[test]
fn s03_116_db_guard_owner_file_is_newline_terminated() -> TestResult {
    let temp = TempRoot::new("116_owner_newline")?;
    let db_dir = temp.path().join("guarded-db");
    let guard = enforce_db_ownership(&db_dir, "node-116")?;
    let owner = fs::read_to_string(guard.db_dir.join("OWNER"))?;
    assert!(owner.ends_with('\n'));
    assert_eq!(owner.trim(), "node-116");
    Ok(())
}

#[test]
fn s03_117_db_guard_reopen_same_owner_after_drop_succeeds() -> TestResult {
    let temp = TempRoot::new("117_guard_reopen")?;
    let db_dir = temp.path().join("guarded-db");

    let first = enforce_db_ownership(&db_dir, "node-117")?;
    drop(first);

    let second = enforce_db_ownership(&db_dir, "node-117")?;
    assert_eq!(
        fs::read_to_string(second.db_dir.join("OWNER"))?.trim(),
        "node-117"
    );
    Ok(())
}

#[test]
fn s03_118_load_vector_multiple_resume_cycles_preserve_tip_height_zero() -> TestResult {
    with_section("118_many_resumes", false, |section, opts, root| {
        let founder = wallet_with_pair("77");
        let manager = initialize_valid_chain(section, opts, root, &founder)?;
        drop(manager);

        for idx in 0..5usize {
            let genesis = valid_genesis_file(&founder)?;
            let file_name = format!("resume-{idx}.json");
            let genesis_path = write_genesis_file(root, &file_name, &genesis)?;
            let resumed = section.initialize_blockchain(opts, false, &genesis_path, &founder)?;
            assert_eq!(resumed.get_tip_height()?, 0);
            drop(resumed);
        }

        Ok(())
    })
}

#[test]
fn s03_119_vector_genesis_hash_tamper_positions_are_rejected() -> TestResult {
    with_section("119_hash_tamper_positions", false, |section, opts, root| {
        let founder = wallet_with_pair("78");

        for idx in [0usize, 1, 31, 63] {
            let mut genesis = valid_genesis_file(&founder)?;
            if let Some(byte) = genesis.genesis_block.genesis_hash.get_mut(idx) {
                *byte = byte.wrapping_add(1);
            }

            let file_name = format!("tamper-{idx}.json");
            let genesis_path = write_genesis_file(root, &file_name, &genesis)?;
            let result = section.initialize_blockchain(opts, false, &genesis_path, &founder);
            let error = expect_error(result)?;
            assert!(
                error.to_string().contains("genesis_hash mismatch"),
                "unexpected hash tamper error at index {idx}: {error}"
            );
        }

        Ok(())
    })
}

#[test]
fn s03_120_load_vector_many_valid_genesis_files_initialize_isolated_chains() -> TestResult {
    for pair in ["79", "7a", "7b", "7c", "7d", "7e", "7f", "80"] {
        let case_name = format!("120_valid_chain_{pair}");
        with_section(&case_name, false, |section, opts, root| {
            let founder = wallet_with_pair(pair);
            let manager = initialize_valid_chain(section, opts, root, &founder)?;
            let block0 = manager
                .get_block_by_index(0)?
                .ok_or_else(|| boxed_error("missing block 0"))?;

            assert_eq!(block0.metadata.index, 0);
            assert_eq!(block0.miner_wallet(), founder.as_str());
            assert_eq!(manager.get_tip_height()?, 0);

            Ok(())
        })?;
    }

    Ok(())
}
