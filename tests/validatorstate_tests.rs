// tests/validatorstate_01_tests.rs

#![allow(clippy::too_many_lines)]

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::blockchain::validatorstate::ValidatorState;
use remzar::consensus::por_008_validator_lifecycle::ValidatorMeta;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn Error>>;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

const VALIDATOR_STATE_KEY_TEST: &[u8] = b"validator_state_v1";
const MULTI_VALIDATOR_EVER_SEEN_KEY_TEST: &[u8] = b"validator_multi_validator_ever_seen_v1";

struct TestDb {
    manager: Option<RockDBManager>,
    root: PathBuf,
}

impl TestDb {
    fn manager(&self) -> Result<&RockDBManager, Box<dyn Error>> {
        self.manager
            .as_ref()
            .ok_or_else(|| boxed_error("test database manager is not available"))
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        drop(self.manager.take());

        if std::fs::remove_dir_all(&self.root).is_err() {
            // Best-effort cleanup only. Drop must not fail tests.
        }
    }
}

struct TestState {
    state: ValidatorState,
    db: TestDb,
}

impl TestState {
    fn manager(&self) -> Result<&RockDBManager, Box<dyn Error>> {
        self.db.manager()
    }
}

fn test_block_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(1_700_000_000)
}

fn test_metadata(index: u64, previous_hash: Hash) -> BlockMetadata {
    let timestamp = test_block_timestamp();
    let merkle_root = fixed_hash(seed_from_index(index, 33));
    let signature_byte = if index == 0 {
        0u8
    } else {
        seed_from_index(index, 9)
    };
    let guardian_signature = [signature_byte; GlobalConfiguration::GUARDIAN_SIG_LEN];

    BlockMetadata::new(
        index,
        timestamp,
        previous_hash,
        merkle_root,
        guardian_signature,
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    )
}

fn boxed_error(message: &str) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message.to_owned()))
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("remzar_validator_state_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> Result<String, Box<dyn Error>> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn wallet_arr(seed: u64) -> Result<[u8; REMZAR_WALLET_LEN], Box<dyn Error>> {
    let value = wallet(seed);
    let bytes = value.as_bytes();

    if bytes.len() != REMZAR_WALLET_LEN {
        return Err(boxed_error("generated wallet has invalid length"));
    }

    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn node_opts(root: &Path) -> Result<NodeOpts, Box<dyn Error>> {
    Ok(NodeOpts {
        identity_file: path_to_string(&root.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "error".to_owned(),
        data_dir: path_to_string(root)?,
        wallet_address: wallet(1),
        founder: false,
    })
}

fn new_blockchain_db(label: &str) -> Result<TestDb, Box<dyn Error>> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path)?;
    let manager = RockDBManager::new_blockchain(&opts, &blockchain_path_string)?;

    Ok(TestDb {
        manager: Some(manager),
        root,
    })
}

fn new_test_state(label: &str) -> Result<TestState, Box<dyn Error>> {
    let db = new_blockchain_db(label)?;
    let state = ValidatorState::with_manager(db.manager()?.clone());
    Ok(TestState { state, db })
}

fn fixed_hash(seed: u8) -> Hash {
    [seed; 64]
}

fn seed_from_index(index: u64, offset: u8) -> u8 {
    let reduced: u8 = u8::try_from(index.rem_euclid(200)).unwrap_or_default();
    reduced.saturating_add(offset)
}

fn now_ts() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn test_block_with_miner(
    index: u64,
    previous_hash: Hash,
    miner: String,
) -> Result<Block, ErrorDetection> {
    let batch_key = if index == 0 {
        None
    } else {
        Some(format!("tx_batch_{index:010}"))
    };

    Block::new(test_metadata(index, previous_hash), batch_key, miner, 0)
}

fn test_block(index: u64, previous_hash: Hash) -> Result<Block, ErrorDetection> {
    let miner = if index == 0 {
        String::new()
    } else {
        wallet(index.saturating_add(10))
    };

    test_block_with_miner(index, previous_hash, miner)
}

fn genesis_block_with_founder(founder: &str) -> Result<Block, ErrorDetection> {
    test_block_with_miner(0, [0u8; 64], founder.to_owned())
}

fn reg_tx(seed: u64) -> Result<RegisterNodeTx, ErrorDetection> {
    RegisterNodeTx::new(wallet(seed))
}

fn reg_tx_for_wallet(wallet_value: &str) -> Result<RegisterNodeTx, ErrorDetection> {
    RegisterNodeTx::new(wallet_value.to_owned())
}

fn reg_tx_with_timestamp(seed: u64, timestamp: u64) -> Result<RegisterNodeTx, Box<dyn Error>> {
    Ok(RegisterNodeTx {
        wallet_address: wallet_arr(seed)?,
        timestamp,
    })
}

fn invalid_wallet_reg_tx(timestamp: u64) -> RegisterNodeTx {
    RegisterNodeTx {
        wallet_address: [b'!'; REMZAR_WALLET_LEN],
        timestamp,
    }
}

fn non_utf8_wallet_reg_tx(timestamp: u64) -> RegisterNodeTx {
    RegisterNodeTx {
        wallet_address: [0xFF; REMZAR_WALLET_LEN],
        timestamp,
    }
}

fn tx_batch(index: u64, transactions: Vec<TxKind>) -> Result<TransactionBatch, ErrorDetection> {
    TransactionBatch::new(index, 1_800_010_000u64.saturating_add(index), transactions)
}

fn block_ts_for_height(height: u64) -> u64 {
    1_800_010_000u64.saturating_add(height)
}

fn apply_register_for_test(
    test: &mut TestState,
    block_height: u64,
    tx: &RegisterNodeTx,
) -> Result<(), ErrorDetection> {
    test.state
        .apply_register_tx_at_block_time(block_height, block_ts_for_height(block_height), tx)
}

fn store_block_at_height(manager: &RockDBManager, index: u64) -> Result<Block, ErrorDetection> {
    let previous_hash = if index == 0 {
        [0u8; 64]
    } else {
        fixed_hash(seed_from_index(index.saturating_sub(1), 17))
    };
    let block = test_block(index, previous_hash)?;
    store_block(manager, &block)?;
    Ok(block)
}

fn store_block(manager: &RockDBManager, block: &Block) -> Result<(), ErrorDetection> {
    let bytes = block.serialize_for_storage()?;
    manager.store_latest_block(&bytes, block.metadata.index)?;
    manager.index_block_by_hash(&block.block_hash, &bytes)?;
    manager.set_latest_block_index(block.metadata.index)?;
    manager.set_tip_height(block.metadata.index)?;
    Ok(())
}

fn store_batch(manager: &RockDBManager, batch: &TransactionBatch) -> Result<(), ErrorDetection> {
    let bytes = batch.serialize_for_storage()?;
    manager.store_batch_bytes(batch.index, &bytes)
}

fn store_founder_genesis(manager: &RockDBManager, founder: &str) -> Result<Block, ErrorDetection> {
    let block = genesis_block_with_founder(founder)?;
    store_block(manager, &block)?;
    Ok(block)
}

fn assert_meta_core(
    meta: &ValidatorMeta,
    join_height: u64,
    last_renew_height: u64,
    exit_height: Option<u64>,
) {
    assert_eq!(meta.join_height, join_height);
    assert_eq!(meta.last_renew_height, last_renew_height);
    assert_eq!(meta.exit_height, exit_height);
}

fn assert_string_vec_sorted(values: &[String]) {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    assert_eq!(values, sorted.as_slice());
}

#[test]
fn test_001_with_manager_starts_empty() -> TestResult {
    let test = new_test_state("with_manager_empty")?;

    assert!(test.state.is_empty());
    assert_eq!(test.state.len(), 0);
    assert!(test.state.all().is_empty());
    assert!(!test.state.multi_validator_ever_seen()?);

    Ok(())
}

#[test]
fn test_002_load_state_missing_returns_not_found() -> TestResult {
    let test = new_test_state("load_missing")?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_003_load_or_new_missing_returns_empty_state() -> TestResult {
    let test = new_test_state("load_or_new_missing")?;

    let loaded = ValidatorState::load_or_new(test.manager()?.clone())?;

    assert!(loaded.is_empty());
    assert_eq!(loaded.len(), 0);
    Ok(())
}

#[test]
fn test_004_commit_empty_state_then_load_round_trips() -> TestResult {
    let test = new_test_state("commit_empty")?;

    test.state.commit()?;
    let loaded = ValidatorState::load_state(test.manager()?.clone())?;

    assert!(loaded.is_empty());
    assert_eq!(loaded.len(), 0);
    Ok(())
}

#[test]
fn test_005_apply_register_tx_at_block_time_inserts_validator() -> TestResult {
    let mut test = new_test_state("register_insert")?;
    let tx = reg_tx(5)?;
    let wallet_value = wallet(5);

    apply_register_for_test(&mut test, 5, &tx)?;

    assert_eq!(test.state.len(), 1);
    assert!(test.state.is_canonically_known(&wallet_value)?);
    assert_eq!(test.state.join_height(&wallet_value), Some(5));

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;
    assert_meta_core(&meta, 5, 5, None);

    Ok(())
}

#[test]
fn test_006_apply_register_tx_at_block_time_commits_to_db() -> TestResult {
    let mut test = new_test_state("register_commits")?;
    let tx = reg_tx(6)?;
    let wallet_value = wallet(6);

    apply_register_for_test(&mut test, 6, &tx)?;

    let loaded = ValidatorState::load_state(test.manager()?.clone())?;

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.join_height(&wallet_value), Some(6));
    assert!(loaded.is_active_at(&wallet_value, 6));
    Ok(())
}

#[test]
fn test_007_is_canonically_known_rejects_invalid_wallet() -> TestResult {
    let test = new_test_state("known_invalid_wallet")?;

    let result = test.state.is_canonically_known("not-a-wallet");

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_008_meta_for_invalid_wallet_returns_none() -> TestResult {
    let test = new_test_state("meta_invalid_wallet")?;

    assert_eq!(test.state.meta_for("not-a-wallet"), None);
    assert_eq!(test.state.join_height("not-a-wallet"), None);
    assert!(!test.state.is_active_at("not-a-wallet", 1));
    assert!(!test.state.reward_eligible_at("not-a-wallet", 1));

    Ok(())
}

#[test]
fn test_009_active_at_includes_joined_validator_at_join_height() -> TestResult {
    let mut test = new_test_state("active_at_join")?;
    let wallet_value = wallet(9);

    apply_register_for_test(&mut test, 9, &reg_tx(9)?)?;

    assert!(test.state.is_active_at(&wallet_value, 9));
    assert_eq!(test.state.active_at(9), vec![wallet_value]);
    Ok(())
}

#[test]
fn test_010_active_at_excludes_validator_before_join_height() -> TestResult {
    let mut test = new_test_state("active_before_join")?;
    let wallet_value = wallet(10);

    apply_register_for_test(&mut test, 10, &reg_tx(10)?)?;

    assert!(!test.state.is_active_at(&wallet_value, 9));
    assert!(test.state.active_at(9).is_empty());
    Ok(())
}

#[test]
fn test_011_proposable_at_with_zero_delay_is_immediate() -> TestResult {
    let mut test = new_test_state("proposable_zero_delay")?;
    let wallet_value = wallet(11);

    apply_register_for_test(&mut test, 11, &reg_tx(11)?)?;

    assert_eq!(test.state.proposable_at(11, 0), vec![wallet_value]);
    Ok(())
}

#[test]
fn test_012_proposable_at_respects_activation_delay() -> TestResult {
    let mut test = new_test_state("proposable_delay")?;
    let wallet_value = wallet(12);

    apply_register_for_test(&mut test, 12, &reg_tx(12)?)?;

    assert!(test.state.proposable_at(13, 2).is_empty());
    assert_eq!(test.state.proposable_at(14, 2), vec![wallet_value]);
    Ok(())
}

#[test]
fn test_013_reward_eligible_respects_reward_delay() -> TestResult {
    let mut test = new_test_state("reward_eligible_delay")?;
    let wallet_value = wallet(13);

    apply_register_for_test(&mut test, 13, &reg_tx(13)?)?;

    let delay = u64::try_from(GlobalConfiguration::REWARD_DELAY_BLOCKS)
        .map_err(|_| boxed_error("reward delay does not fit u64"))?;
    let before = 13u64.saturating_add(delay).saturating_sub(1);
    let eligible = 13u64.saturating_add(delay);

    if delay > 0 {
        assert!(!test.state.reward_eligible_at(&wallet_value, before));
    }
    assert!(test.state.reward_eligible_at(&wallet_value, eligible));
    Ok(())
}

#[test]
fn test_014_active_at_output_is_sorted() -> TestResult {
    let mut test = new_test_state("active_sorted")?;

    apply_register_for_test(&mut test, 3, &reg_tx(300)?)?;
    apply_register_for_test(&mut test, 1, &reg_tx(100)?)?;
    apply_register_for_test(&mut test, 2, &reg_tx(200)?)?;

    let active = test.state.active_at(3);

    assert_eq!(active.len(), 3);
    assert_string_vec_sorted(&active);
    Ok(())
}

#[test]
fn test_015_all_returns_clone_not_live_reference() -> TestResult {
    let mut test = new_test_state("all_clone")?;
    let wallet_value = wallet(15);

    apply_register_for_test(&mut test, 15, &reg_tx(15)?)?;

    let mut clone = test.state.all();
    clone.clear();

    assert!(clone.is_empty());
    assert_eq!(test.state.len(), 1);
    assert!(test.state.is_canonically_known(&wallet_value)?);
    Ok(())
}

#[test]
fn test_016_duplicate_register_same_height_is_no_change() -> TestResult {
    let mut test = new_test_state("duplicate_same_height")?;
    let tx = reg_tx(16)?;
    let wallet_value = wallet(16);

    apply_register_for_test(&mut test, 16, &tx)?;
    apply_register_for_test(&mut test, 16, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(test.state.len(), 1);
    assert_meta_core(&meta, 16, 16, None);
    Ok(())
}

#[test]
fn test_017_register_later_height_renews_validator() -> TestResult {
    let mut test = new_test_state("renew_later_height")?;
    let tx = reg_tx(17)?;
    let wallet_value = wallet(17);

    apply_register_for_test(&mut test, 17, &tx)?;
    apply_register_for_test(&mut test, 21, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_meta_core(&meta, 17, 21, None);
    Ok(())
}

#[test]
fn test_018_register_lower_height_after_renew_is_no_change() -> TestResult {
    let mut test = new_test_state("renew_lower_height_no_change")?;
    let tx = reg_tx(18)?;
    let wallet_value = wallet(18);

    apply_register_for_test(&mut test, 18, &tx)?;
    apply_register_for_test(&mut test, 25, &tx)?;
    apply_register_for_test(&mut test, 20, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_meta_core(&meta, 18, 25, None);
    Ok(())
}

#[test]
fn test_019_mark_exit_unknown_wallet_is_noop() -> TestResult {
    let mut test = new_test_state("exit_unknown")?;

    test.state.mark_exit(&wallet(19), 19)?;

    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_020_mark_exit_known_wallet_sets_exit_height() -> TestResult {
    let mut test = new_test_state("exit_known")?;
    let wallet_value = wallet(20);

    apply_register_for_test(&mut test, 20, &reg_tx(20)?)?;
    test.state.mark_exit(&wallet_value, 30)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_meta_core(&meta, 20, 20, Some(30));
    assert!(test.state.is_active_at(&wallet_value, 29));
    assert!(!test.state.is_active_at(&wallet_value, 30));
    Ok(())
}

#[test]
fn test_021_mark_exit_twice_keeps_earlier_exit_height() -> TestResult {
    let mut test = new_test_state("exit_earlier")?;
    let wallet_value = wallet(21);

    apply_register_for_test(&mut test, 21, &reg_tx(21)?)?;
    test.state.mark_exit(&wallet_value, 40)?;
    test.state.mark_exit(&wallet_value, 35)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.exit_height, Some(35));
    Ok(())
}

#[test]
fn test_022_reactivate_after_exit_resets_non_founder_join_height() -> TestResult {
    let mut test = new_test_state("reactivate_non_founder")?;
    let tx = reg_tx(22)?;
    let wallet_value = wallet(22);

    apply_register_for_test(&mut test, 22, &tx)?;
    test.state.mark_exit(&wallet_value, 30)?;
    apply_register_for_test(&mut test, 31, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_meta_core(&meta, 31, 31, None);
    Ok(())
}

#[test]
fn test_023_seed_genesis_founder_inserts_join_height_zero() -> TestResult {
    let mut test = new_test_state("seed_founder")?;
    let founder = wallet(23);

    test.state.seed_genesis_founder(&founder, now_ts()?)?;

    let meta = test
        .state
        .meta_for(&founder)
        .ok_or_else(|| boxed_error("missing founder meta"))?;

    assert_meta_core(&meta, 0, 0, None);
    assert!(test.state.is_active_at(&founder, 0));
    assert_eq!(test.state.proposable_at(0, 100), vec![founder]);
    Ok(())
}

#[test]
fn test_024_seed_genesis_founder_invalid_wallet_errors() -> TestResult {
    let mut test = new_test_state("seed_founder_invalid")?;

    let result = test.state.seed_genesis_founder("bad-wallet", now_ts()?);

    assert!(result.is_err());
    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_025_seed_genesis_founder_is_idempotent() -> TestResult {
    let mut test = new_test_state("seed_founder_idempotent")?;
    let founder = wallet(25);
    let timestamp = now_ts()?;

    test.state.seed_genesis_founder(&founder, timestamp)?;
    test.state.seed_genesis_founder(&founder, timestamp)?;

    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&founder), Some(0));
    Ok(())
}

#[test]
fn test_026_founder_late_register_preserves_join_height_zero() -> TestResult {
    let mut test = new_test_state("founder_late_register")?;
    let founder = wallet(26);
    let tx = reg_tx_for_wallet(&founder)?;

    test.state.seed_genesis_founder(&founder, now_ts()?)?;
    apply_register_for_test(&mut test, 50, &tx)?;

    let meta = test
        .state
        .meta_for(&founder)
        .ok_or_else(|| boxed_error("missing founder meta"))?;

    assert_eq!(meta.join_height, 0);
    assert_eq!(meta.last_renew_height, 50);
    assert_eq!(meta.exit_height, None);
    Ok(())
}

#[test]
fn test_027_founder_reactivation_preserves_join_height_zero() -> TestResult {
    let mut test = new_test_state("founder_reactivation")?;
    let founder = wallet(27);
    let tx = reg_tx_for_wallet(&founder)?;

    test.state.seed_genesis_founder(&founder, now_ts()?)?;
    test.state.mark_exit(&founder, 10)?;
    apply_register_for_test(&mut test, 12, &tx)?;

    let meta = test
        .state
        .meta_for(&founder)
        .ok_or_else(|| boxed_error("missing founder meta"))?;

    assert_meta_core(&meta, 0, 12, None);
    Ok(())
}

#[test]
fn test_028_multi_validator_latch_false_for_single_validator() -> TestResult {
    let mut test = new_test_state("latch_single")?;

    apply_register_for_test(&mut test, 28, &reg_tx(28)?)?;

    assert_eq!(test.state.len(), 1);
    assert!(!test.state.multi_validator_ever_seen()?);
    Ok(())
}

#[test]
fn test_029_multi_validator_latch_true_after_second_validator() -> TestResult {
    let mut test = new_test_state("latch_second")?;

    apply_register_for_test(&mut test, 29, &reg_tx(29)?)?;
    apply_register_for_test(&mut test, 30, &reg_tx(30)?)?;

    assert_eq!(test.state.len(), 2);
    assert!(test.state.multi_validator_ever_seen()?);
    Ok(())
}

#[test]
fn test_030_multi_validator_latch_persists_after_reload() -> TestResult {
    let mut test = new_test_state("latch_persists")?;

    apply_register_for_test(&mut test, 30, &reg_tx(3000)?)?;
    apply_register_for_test(&mut test, 31, &reg_tx(3001)?)?;

    let loaded = ValidatorState::load_state(test.manager()?.clone())?;

    assert!(loaded.multi_validator_ever_seen()?);
    assert_eq!(loaded.len(), 2);
    Ok(())
}

#[test]
fn test_031_multi_validator_latch_is_monotonic_after_exits() -> TestResult {
    let mut test = new_test_state("latch_monotonic_exit")?;
    let first = wallet(3100);
    let second = wallet(3101);

    apply_register_for_test(&mut test, 31, &reg_tx(3100)?)?;
    apply_register_for_test(&mut test, 32, &reg_tx(3101)?)?;
    test.state.mark_exit(&first, 40)?;
    test.state.mark_exit(&second, 41)?;

    assert!(test.state.multi_validator_ever_seen()?);
    assert!(!test.state.active_at(42).contains(&first));
    assert!(!test.state.active_at(42).contains(&second));
    Ok(())
}

#[test]
fn test_032_apply_block_with_no_register_txs_makes_no_snapshot() -> TestResult {
    let mut test = new_test_state("apply_block_no_register")?;
    let block = test_block(1, fixed_hash(1))?;
    let batch = tx_batch(1, Vec::new())?;

    test.state.apply_block(&block, &batch)?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_033_apply_block_with_register_tx_inserts_and_commits() -> TestResult {
    let mut test = new_test_state("apply_block_register")?;
    let block = test_block(33, fixed_hash(33))?;
    let wallet_value = wallet(33);
    let batch = tx_batch(33, vec![TxKind::RegisterNode(reg_tx(33)?)])?;

    test.state.apply_block(&block, &batch)?;

    let loaded = ValidatorState::load_state(test.manager()?.clone())?;

    assert_eq!(loaded.join_height(&wallet_value), Some(33));
    assert!(loaded.is_active_at(&wallet_value, 33));
    Ok(())
}

#[test]
fn test_034_apply_block_with_multiple_register_txs_inserts_all_sorted() -> TestResult {
    let mut test = new_test_state("apply_block_many_registers")?;
    let block = test_block(34, fixed_hash(34))?;
    let batch = tx_batch(
        34,
        vec![
            TxKind::RegisterNode(reg_tx(3403)?),
            TxKind::RegisterNode(reg_tx(3401)?),
            TxKind::RegisterNode(reg_tx(3402)?),
        ],
    )?;

    test.state.apply_block(&block, &batch)?;

    let active = test.state.active_at(34);

    assert_eq!(active.len(), 3);
    assert_string_vec_sorted(&active);
    Ok(())
}

#[test]
fn test_035_invalid_register_wallet_in_apply_register_tx_errors_without_mutation() -> TestResult {
    let mut test = new_test_state("invalid_wallet_register")?;
    let tx = invalid_wallet_reg_tx(now_ts()?);

    let result = apply_register_for_test(&mut test, 35, &tx);

    assert!(result.is_err());
    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_036_non_utf8_register_wallet_errors_without_mutation() -> TestResult {
    let mut test = new_test_state("non_utf8_wallet_register")?;
    let tx = non_utf8_wallet_reg_tx(now_ts()?);

    let result = apply_register_for_test(&mut test, 36, &tx);

    assert!(result.is_err());
    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_037_register_tx_self_reported_old_timestamp_uses_block_time_for_lifecycle() -> TestResult {
    let mut test = new_test_state("old_timestamp_register")?;
    let tx = reg_tx_with_timestamp(37, 1)?;
    let wallet_value = wallet(37);

    apply_register_for_test(&mut test, 37, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.join_height, 37);
    assert_eq!(meta.join_timestamp, block_ts_for_height(37));
    assert_eq!(meta.last_renew_timestamp, block_ts_for_height(37));
    Ok(())
}

#[test]
fn test_038_register_tx_self_reported_future_timestamp_uses_block_time_for_lifecycle() -> TestResult
{
    let mut test = new_test_state("future_timestamp_register")?;
    let tx = reg_tx_with_timestamp(38, u64::MAX)?;
    let wallet_value = wallet(38);

    apply_register_for_test(&mut test, 38, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.join_height, 38);
    assert_eq!(meta.join_timestamp, block_ts_for_height(38));
    assert_eq!(meta.last_renew_timestamp, block_ts_for_height(38));
    Ok(())
}

#[test]
fn test_039_rebuild_from_empty_chain_commits_empty_snapshot() -> TestResult {
    let mut test = new_test_state("rebuild_empty_chain")?;

    test.state.rebuild_from_chain(Some(0))?;

    let loaded = ValidatorState::load_state(test.manager()?.clone())?;
    assert!(loaded.is_empty());
    Ok(())
}

#[test]
fn test_040_rebuild_from_chain_seeds_founder_from_block_zero() -> TestResult {
    let mut test = new_test_state("rebuild_founder")?;
    let founder = wallet(40);

    store_founder_genesis(test.manager()?, &founder)?;

    test.state.rebuild_from_chain(Some(0))?;

    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&founder), Some(0));
    assert!(test.state.is_active_at(&founder, 0));
    Ok(())
}

#[test]
fn test_041_rebuild_from_chain_replays_register_batches() -> TestResult {
    let mut test = new_test_state("rebuild_register_batches")?;
    let founder = wallet(4100);
    let first = wallet(4101);
    let second = wallet(4102);

    let genesis = store_founder_genesis(test.manager()?, &founder)?;
    let block_one = test_block(1, genesis.block_hash)?;
    let block_two = test_block(2, block_one.block_hash)?;
    store_block(test.manager()?, &block_one)?;
    store_block(test.manager()?, &block_two)?;

    let batch_one = tx_batch(1, vec![TxKind::RegisterNode(reg_tx(4101)?)])?;
    let batch_two = tx_batch(2, vec![TxKind::RegisterNode(reg_tx(4102)?)])?;
    store_batch(test.manager()?, &batch_one)?;
    store_batch(test.manager()?, &batch_two)?;

    test.state.rebuild_from_chain(Some(2))?;

    assert_eq!(test.state.len(), 3);
    assert_eq!(test.state.join_height(&founder), Some(0));
    assert_eq!(test.state.join_height(&first), Some(1));
    assert_eq!(test.state.join_height(&second), Some(2));
    assert!(test.state.multi_validator_ever_seen()?);
    Ok(())
}

#[test]
fn test_042_rebuild_from_chain_up_to_height_excludes_later_register() -> TestResult {
    let mut test = new_test_state("rebuild_height_cutoff")?;
    let first = wallet(4201);
    let second = wallet(4202);

    store_block_at_height(test.manager()?, 1)?;
    store_block_at_height(test.manager()?, 2)?;

    let batch_one = tx_batch(1, vec![TxKind::RegisterNode(reg_tx(4201)?)])?;
    let batch_two = tx_batch(2, vec![TxKind::RegisterNode(reg_tx(4202)?)])?;
    store_batch(test.manager()?, &batch_one)?;
    store_batch(test.manager()?, &batch_two)?;

    test.state.rebuild_from_chain(Some(1))?;

    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&first), Some(1));
    assert_eq!(test.state.join_height(&second), None);
    Ok(())
}

#[test]
fn test_043_rebuild_from_chain_skips_missing_batch_heights() -> TestResult {
    let mut test = new_test_state("rebuild_missing_batches")?;
    let only = wallet(4302);

    store_block_at_height(test.manager()?, 2)?;

    let batch_two = tx_batch(2, vec![TxKind::RegisterNode(reg_tx(4302)?)])?;
    store_batch(test.manager()?, &batch_two)?;

    test.state.rebuild_from_chain(Some(2))?;

    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&only), Some(2));
    Ok(())
}

#[test]
fn test_044_load_state_rejects_corrupt_snapshot() -> TestResult {
    let test = new_test_state("corrupt_snapshot")?;

    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        b"not a validator state postcard map",
    )?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_045_load_or_new_corrupt_snapshot_rebuilds_from_chain() -> TestResult {
    let test = new_test_state("load_or_new_rebuilds")?;
    let founder = wallet(45);

    store_founder_genesis(test.manager()?, &founder)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        b"not a validator state postcard map",
    )?;

    let loaded = ValidatorState::load_or_new(test.manager()?.clone())?;

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.join_height(&founder), Some(0));
    Ok(())
}

#[test]
fn test_046_malformed_multi_validator_latch_values_are_false_unless_first_byte_is_one() -> TestResult
{
    let test = new_test_state("malformed_latch")?;

    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        MULTI_VALIDATOR_EVER_SEEN_KEY_TEST,
        b"0",
    )?;

    let state = ValidatorState::with_manager(test.manager()?.clone());
    assert!(!state.multi_validator_ever_seen()?);

    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        MULTI_VALIDATOR_EVER_SEEN_KEY_TEST,
        b"1-corrupt-trailing-data",
    )?;

    assert!(state.multi_validator_ever_seen()?);
    Ok(())
}

#[test]
fn test_047_property_many_validators_have_expected_join_heights_and_sorted_active_list()
-> TestResult {
    let mut test = new_test_state("property_many_validators")?;

    for offset in 0u64..50u64 {
        let seed = 4_700u64.saturating_add(offset);
        let height = 100u64.saturating_add(offset);
        apply_register_for_test(&mut test, height, &reg_tx(seed)?)?;
    }

    assert_eq!(test.state.len(), 50);

    for offset in 0u64..50u64 {
        let seed = 4_700u64.saturating_add(offset);
        let height = 100u64.saturating_add(offset);
        let wallet_value = wallet(seed);

        assert_eq!(test.state.join_height(&wallet_value), Some(height));
        assert!(test.state.is_active_at(&wallet_value, height));
    }

    let all_wallets: Vec<String> = test.state.all().keys().cloned().collect();
    assert_eq!(all_wallets.len(), 50);
    assert_string_vec_sorted(&all_wallets);

    Ok(())
}

#[test]
fn test_048_fuzz_invalid_wallet_strings_are_rejected_by_constructor_or_state_query() -> TestResult {
    let test = new_test_state("fuzz_invalid_wallets")?;
    let cases = [
        "",
        "r",
        "x0000000000000000000000000000000000000000000000000000000000000000",
        "rzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        " r00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 ",
    ];

    for case in cases {
        let constructor_result = RegisterNodeTx::new(case.to_owned());
        let query_result = test.state.is_canonically_known(case);

        assert!(
            constructor_result.is_err() || query_result.is_ok(),
            "unexpected constructor/query behavior for case {case:?}"
        );
    }

    Ok(())
}

#[test]
fn test_049_load_test_apply_block_with_100_registers_sets_latch_and_all_active() -> TestResult {
    let mut test = new_test_state("load_apply_block_100")?;
    let block = test_block(49, fixed_hash(49))?;
    let mut txs = Vec::with_capacity(100);

    for offset in 0u64..100u64 {
        txs.push(TxKind::RegisterNode(reg_tx(
            4_900u64.saturating_add(offset),
        )?));
    }

    let batch = tx_batch(49, txs)?;

    test.state.apply_block(&block, &batch)?;

    let active = test.state.active_at(49);

    assert_eq!(test.state.len(), 100);
    assert_eq!(active.len(), 100);
    assert!(test.state.multi_validator_ever_seen()?);
    assert_string_vec_sorted(&active);
    Ok(())
}

#[test]
fn test_050_load_test_rebuild_100_registers_from_chain_batches() -> TestResult {
    let mut test = new_test_state("load_rebuild_100")?;

    for height in 1u64..=100u64 {
        store_block_at_height(test.manager()?, height)?;

        let seed = 5_000u64.saturating_add(height);
        let batch = tx_batch(height, vec![TxKind::RegisterNode(reg_tx(seed)?)])?;
        store_batch(test.manager()?, &batch)?;
    }

    test.state.rebuild_from_chain(Some(100))?;

    assert_eq!(test.state.len(), 100);
    assert!(test.state.multi_validator_ever_seen()?);

    for height in 1u64..=100u64 {
        let seed = 5_000u64.saturating_add(height);
        let wallet_value = wallet(seed);

        assert_eq!(test.state.join_height(&wallet_value), Some(height));
        assert!(test.state.is_active_at(&wallet_value, height));
    }

    let all_wallets: Vec<String> = test.state.all().keys().cloned().collect();
    assert_eq!(all_wallets.len(), 100);
    assert_string_vec_sorted(&all_wallets);

    Ok(())
}

#[test]
fn test_051_commit_after_register_writes_validator_state_key() -> TestResult {
    let mut test = new_test_state("commit_writes_key")?;

    apply_register_for_test(&mut test, 51, &reg_tx(51)?)?;

    let bytes = test.manager()?.read(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
    )?;

    assert!(bytes.is_some());
    assert_eq!(test.state.len(), 1);
    Ok(())
}

#[test]
fn test_052_load_state_accepts_valid_handcrafted_snapshot() -> TestResult {
    let test = new_test_state("handcrafted_valid_snapshot")?;
    let wallet_value = wallet(52);
    let ts = now_ts()?;

    let mut map = BTreeMap::new();
    map.insert(
        wallet_value.clone(),
        ValidatorMeta {
            join_height: 52,
            join_timestamp: ts,
            last_renew_height: 52,
            last_renew_timestamp: ts,
            exit_height: None,
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let loaded = ValidatorState::load_state(test.manager()?.clone())?;

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.join_height(&wallet_value), Some(52));
    assert!(loaded.is_active_at(&wallet_value, 52));
    Ok(())
}

#[test]
fn test_053_load_state_rejects_snapshot_with_invalid_wallet_key() -> TestResult {
    let test = new_test_state("invalid_wallet_key_snapshot")?;
    let ts = now_ts()?;

    let mut map = BTreeMap::new();
    map.insert(
        "not-a-canonical-wallet".to_owned(),
        ValidatorMeta {
            join_height: 53,
            join_timestamp: ts,
            last_renew_height: 53,
            last_renew_timestamp: ts,
            exit_height: None,
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_054_load_state_rejects_last_renew_height_before_join_height() -> TestResult {
    let test = new_test_state("bad_renew_height_snapshot")?;
    let ts = now_ts()?;

    let mut map = BTreeMap::new();
    map.insert(
        wallet(54),
        ValidatorMeta {
            join_height: 54,
            join_timestamp: ts,
            last_renew_height: 53,
            last_renew_timestamp: ts,
            exit_height: None,
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_055_load_state_rejects_last_renew_timestamp_before_join_timestamp() -> TestResult {
    let test = new_test_state("bad_renew_timestamp_snapshot")?;
    let ts = now_ts()?.saturating_add(10);

    let mut map = BTreeMap::new();
    map.insert(
        wallet(55),
        ValidatorMeta {
            join_height: 55,
            join_timestamp: ts,
            last_renew_height: 55,
            last_renew_timestamp: ts.saturating_sub(1),
            exit_height: None,
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_056_load_state_rejects_exit_height_zero() -> TestResult {
    let test = new_test_state("exit_zero_snapshot")?;
    let ts = now_ts()?;

    let mut map = BTreeMap::new();
    map.insert(
        wallet(56),
        ValidatorMeta {
            join_height: 56,
            join_timestamp: ts,
            last_renew_height: 56,
            last_renew_timestamp: ts,
            exit_height: Some(0),
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_057_load_state_rejects_non_founder_exit_height_equal_to_join_height() -> TestResult {
    let test = new_test_state("exit_equal_join_snapshot")?;
    let ts = now_ts()?;

    let mut map = BTreeMap::new();
    map.insert(
        wallet(57),
        ValidatorMeta {
            join_height: 57,
            join_timestamp: ts,
            last_renew_height: 57,
            last_renew_timestamp: ts,
            exit_height: Some(57),
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_058_load_state_accepts_founder_exit_height_after_zero_join() -> TestResult {
    let test = new_test_state("founder_exit_after_zero")?;
    let founder = wallet(58);
    let ts = now_ts()?;

    let mut map = BTreeMap::new();
    map.insert(
        founder.clone(),
        ValidatorMeta {
            join_height: 0,
            join_timestamp: ts,
            last_renew_height: 0,
            last_renew_timestamp: ts,
            exit_height: Some(2),
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let loaded = ValidatorState::load_state(test.manager()?.clone())?;

    assert_eq!(loaded.len(), 1);
    assert!(loaded.is_active_at(&founder, 1));
    assert!(!loaded.is_active_at(&founder, 2));
    Ok(())
}

#[test]
fn test_059_mark_exit_invalid_wallet_errors() -> TestResult {
    let mut test = new_test_state("mark_exit_invalid_wallet")?;

    let result = test.state.mark_exit("not-a-wallet", 59);

    assert!(result.is_err());
    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_060_mark_exit_later_than_existing_exit_is_no_change() -> TestResult {
    let mut test = new_test_state("mark_exit_later_no_change")?;
    let wallet_value = wallet(60);

    apply_register_for_test(&mut test, 60, &reg_tx(60)?)?;
    test.state.mark_exit(&wallet_value, 70)?;
    test.state.mark_exit(&wallet_value, 80)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.exit_height, Some(70));
    Ok(())
}

#[test]
fn test_061_validator_is_active_through_lease_expiry_height() -> TestResult {
    let mut test = new_test_state("active_through_lease")?;
    let wallet_value = wallet(61);
    let lease =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config().lease_blocks;

    apply_register_for_test(&mut test, 61, &reg_tx(61)?)?;

    let expiry = 61u64.saturating_add(lease);
    assert!(test.state.is_active_at(&wallet_value, expiry));
    assert!(
        !test
            .state
            .is_active_at(&wallet_value, expiry.saturating_add(1))
    );
    Ok(())
}

#[test]
fn test_062_later_renewal_extends_lease_window() -> TestResult {
    let mut test = new_test_state("renew_extends_lease")?;
    let wallet_value = wallet(62);
    let tx = reg_tx(62)?;
    let lease =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config().lease_blocks;

    apply_register_for_test(&mut test, 62, &tx)?;
    apply_register_for_test(&mut test, 72, &tx)?;

    assert!(
        test.state
            .is_active_at(&wallet_value, 72u64.saturating_add(lease))
    );
    assert!(
        !test
            .state
            .is_active_at(&wallet_value, 72u64.saturating_add(lease).saturating_add(1))
    );

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.join_height, 62);
    assert_eq!(meta.last_renew_height, 72);
    Ok(())
}

#[test]
fn test_063_out_of_order_older_renewal_does_not_reduce_last_renew_height() -> TestResult {
    let mut test = new_test_state("older_renew_no_reduce")?;
    let wallet_value = wallet(63);
    let tx = reg_tx(63)?;

    apply_register_for_test(&mut test, 63, &tx)?;
    apply_register_for_test(&mut test, 90, &tx)?;
    apply_register_for_test(&mut test, 70, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.join_height, 63);
    assert_eq!(meta.last_renew_height, 90);
    Ok(())
}

#[test]
fn test_064_founder_is_reward_eligible_immediately() -> TestResult {
    let mut test = new_test_state("founder_reward_immediate")?;
    let founder = wallet(64);

    test.state.seed_genesis_founder(&founder, now_ts()?)?;

    assert!(test.state.reward_eligible_at(&founder, 0));
    assert!(test.state.reward_eligible_at(&founder, 1));
    Ok(())
}

#[test]
fn test_065_non_founder_is_not_reward_eligible_before_join_height() -> TestResult {
    let mut test = new_test_state("reward_before_join")?;
    let wallet_value = wallet(65);

    apply_register_for_test(&mut test, 65, &reg_tx(65)?)?;

    assert!(!test.state.reward_eligible_at(&wallet_value, 64));
    Ok(())
}

#[test]
fn test_066_founder_is_proposable_immediately_with_valid_activation_delay() -> TestResult {
    let mut test = new_test_state("founder_proposable_valid_delay")?;
    let founder = wallet(66);

    test.state.seed_genesis_founder(&founder, now_ts()?)?;

    let cfg = remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config();
    cfg.validate()?;

    assert_eq!(
        test.state.proposable_at(0, cfg.activation_delay_blocks),
        vec![founder]
    );

    Ok(())
}

#[test]
fn test_067_non_founder_proposable_boundary_with_lease_safe_delay() -> TestResult {
    let mut test = new_test_state("non_founder_proposable_boundary")?;
    let wallet_value = wallet(67);
    let lease =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config().lease_blocks;
    let delay = lease.clamp(1, 5);

    apply_register_for_test(&mut test, 67, &reg_tx(67)?)?;

    let before = 67u64.saturating_add(delay).saturating_sub(1);
    let at = 67u64.saturating_add(delay);

    assert!(test.state.proposable_at(before, delay).is_empty());
    assert_eq!(test.state.proposable_at(at, delay), vec![wallet_value]);
    Ok(())
}

#[test]
fn test_068_active_at_excludes_validator_at_exact_exit_height() -> TestResult {
    let mut test = new_test_state("active_exit_boundary")?;
    let wallet_value = wallet(68);

    apply_register_for_test(&mut test, 68, &reg_tx(68)?)?;
    test.state.mark_exit(&wallet_value, 75)?;

    assert!(test.state.active_at(74).contains(&wallet_value));
    assert!(!test.state.active_at(75).contains(&wallet_value));
    Ok(())
}

#[test]
fn test_069_active_at_retains_other_validators_after_one_exit() -> TestResult {
    let mut test = new_test_state("active_after_one_exit")?;
    let first = wallet(69);
    let second = wallet(70);

    apply_register_for_test(&mut test, 69, &reg_tx(69)?)?;
    apply_register_for_test(&mut test, 69, &reg_tx(70)?)?;
    test.state.mark_exit(&first, 70)?;

    let active = test.state.active_at(70);

    assert!(!active.contains(&first));
    assert!(active.contains(&second));
    Ok(())
}

#[test]
fn test_070_active_at_excludes_expired_lease() -> TestResult {
    let mut test = new_test_state("active_expired_lease")?;
    let wallet_value = wallet(70);
    let lease =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config().lease_blocks;

    apply_register_for_test(&mut test, 70, &reg_tx(70)?)?;

    assert!(
        !test
            .state
            .active_at(70u64.saturating_add(lease).saturating_add(1))
            .contains(&wallet_value)
    );
    Ok(())
}

#[test]
fn test_071_apply_block_empty_batch_does_not_modify_existing_validator_state() -> TestResult {
    let mut test = new_test_state("empty_block_existing_state")?;
    let wallet_value = wallet(71);

    apply_register_for_test(&mut test, 71, &reg_tx(71)?)?;

    let before = test.state.all();
    let block = test_block(72, fixed_hash(72))?;
    let batch = tx_batch(72, Vec::new())?;

    test.state.apply_block(&block, &batch)?;

    assert_eq!(test.state.all(), before);
    assert_eq!(test.state.join_height(&wallet_value), Some(71));
    Ok(())
}

#[test]
fn test_072_apply_block_duplicate_register_in_same_batch_inserts_once() -> TestResult {
    let mut test = new_test_state("duplicate_register_same_batch")?;
    let wallet_value = wallet(72);
    let tx = reg_tx(72)?;
    let block = test_block(72, fixed_hash(72))?;
    let batch = tx_batch(
        72,
        vec![TxKind::RegisterNode(tx.clone()), TxKind::RegisterNode(tx)],
    )?;

    test.state.apply_block(&block, &batch)?;

    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&wallet_value), Some(72));
    Ok(())
}

#[test]
fn test_073_apply_block_with_only_invalid_register_errors_without_mutation() -> TestResult {
    let mut test = new_test_state("invalid_register_only_block")?;
    let block = test_block(73, fixed_hash(73))?;
    let bad = invalid_wallet_reg_tx(now_ts()?);
    let batch = tx_batch(73, vec![TxKind::RegisterNode(bad)])?;

    let result = test.state.apply_block(&block, &batch);

    assert!(result.is_err());
    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_074_same_height_newer_block_timestamp_updates_last_renew_timestamp() -> TestResult {
    let mut test = new_test_state("same_height_newer_timestamp")?;
    let wallet_value = wallet(74);
    let tx = reg_tx(74)?;
    let old_ts = block_ts_for_height(74);
    let new_ts = old_ts.saturating_add(1);

    test.state
        .apply_register_tx_at_block_time(74, old_ts, &tx)?;
    test.state
        .apply_register_tx_at_block_time(74, new_ts, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.join_height, 74);
    assert_eq!(meta.last_renew_height, 74);
    assert_eq!(meta.last_renew_timestamp, new_ts);
    Ok(())
}

#[test]
fn test_075_same_height_older_block_timestamp_does_not_reduce_last_renew_timestamp() -> TestResult {
    let mut test = new_test_state("same_height_older_timestamp")?;
    let wallet_value = wallet(75);
    let tx = reg_tx(75)?;
    let older_ts = block_ts_for_height(75);
    let newer_ts = older_ts.saturating_add(10);

    test.state
        .apply_register_tx_at_block_time(75, newer_ts, &tx)?;
    test.state
        .apply_register_tx_at_block_time(75, older_ts, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.last_renew_timestamp, newer_ts);
    Ok(())
}

#[test]
fn test_076_load_or_new_invalid_snapshot_validation_error_does_not_rebuild() -> TestResult {
    let test = new_test_state("load_or_new_validation_error")?;
    let ts = now_ts()?;

    let mut map = BTreeMap::new();
    map.insert(
        "bad-wallet".to_owned(),
        ValidatorMeta {
            join_height: 76,
            join_timestamp: ts,
            last_renew_height: 76,
            last_renew_timestamp: ts,
            exit_height: None,
        },
    );

    let bytes = postcard::to_allocvec(&map)?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        &bytes,
    )?;

    let result = ValidatorState::load_or_new(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_077_rebuild_from_chain_none_uses_tip_height_metadata() -> TestResult {
    let mut test = new_test_state("rebuild_none_uses_tip")?;
    let wallet_value = wallet(77);

    test.manager()?.set_tip_height(2)?;
    store_block_at_height(test.manager()?, 2)?;

    let batch_two = tx_batch(2, vec![TxKind::RegisterNode(reg_tx(77)?)])?;
    store_batch(test.manager()?, &batch_two)?;

    test.state.rebuild_from_chain(None)?;

    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&wallet_value), Some(2));
    Ok(())
}

#[test]
fn test_078_rebuild_from_chain_corrupt_batch_errors_and_preserves_existing_state() -> TestResult {
    let mut test = new_test_state("rebuild_corrupt_batch_preserves")?;
    let existing = wallet(78);

    apply_register_for_test(&mut test, 78, &reg_tx(78)?)?;
    store_block_at_height(test.manager()?, 2)?;
    test.manager()?.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        b"tx_batch_0000000002",
        b"corrupt batch bytes",
    )?;

    let result = test.state.rebuild_from_chain(Some(2));

    assert!(result.is_err());
    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&existing), Some(78));
    Ok(())
}

#[test]
fn test_079_rebuild_from_chain_invalid_register_batch_errors_without_replacing_state() -> TestResult
{
    let mut test = new_test_state("rebuild_invalid_register_preserves")?;
    let existing = wallet(79);

    apply_register_for_test(&mut test, 79, &reg_tx(79)?)?;
    store_block_at_height(test.manager()?, 2)?;

    let bad = invalid_wallet_reg_tx(now_ts()?);
    let batch = tx_batch(2, vec![TxKind::RegisterNode(bad)])?;
    store_batch(test.manager()?, &batch)?;

    let result = test.state.rebuild_from_chain(Some(2));

    assert!(result.is_err());
    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&existing), Some(79));
    Ok(())
}

#[test]
fn test_080_rebuild_founder_late_register_preserves_founder_join_height_zero() -> TestResult {
    let mut test = new_test_state("rebuild_founder_late_register")?;
    let founder = wallet(80);

    let genesis = store_founder_genesis(test.manager()?, &founder)?;
    let block_one = test_block(1, genesis.block_hash)?;
    store_block(test.manager()?, &block_one)?;

    let batch = tx_batch(1, vec![TxKind::RegisterNode(reg_tx_for_wallet(&founder)?)])?;
    store_batch(test.manager()?, &batch)?;

    test.state.rebuild_from_chain(Some(1))?;

    let meta = test
        .state
        .meta_for(&founder)
        .ok_or_else(|| boxed_error("missing founder meta"))?;

    assert_eq!(meta.join_height, 0);
    assert_eq!(meta.last_renew_height, 1);
    Ok(())
}

#[test]
fn test_081_load_or_new_corrupt_snapshot_without_chain_rebuilds_empty() -> TestResult {
    let test = new_test_state("load_or_new_corrupt_empty_rebuild")?;

    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        b"corrupt validator snapshot",
    )?;

    let loaded = ValidatorState::load_or_new(test.manager()?.clone())?;

    assert!(loaded.is_empty());
    assert_eq!(loaded.len(), 0);
    Ok(())
}

#[test]
fn test_082_load_or_new_corrupt_snapshot_with_corrupt_chain_batch_returns_error() -> TestResult {
    let test = new_test_state("load_or_new_corrupt_chain_batch")?;

    test.manager()?.set_tip_height(1)?;
    store_block_at_height(test.manager()?, 1)?;
    test.manager()?.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        b"tx_batch_0000000001",
        b"bad batch bytes",
    )?;
    test.manager()?.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY_TEST,
        b"corrupt validator snapshot",
    )?;

    let result = ValidatorState::load_or_new(test.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_083_register_after_canonical_lease_expiry_renews_existing_era() -> TestResult {
    let mut test = new_test_state("renew_after_expiry_existing_era")?;
    let wallet_value = wallet(83);
    let tx = reg_tx(83)?;
    let lease =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config().lease_blocks;

    apply_register_for_test(&mut test, 83, &tx)?;

    let expired_height = 83u64.saturating_add(lease).saturating_add(1);
    assert!(!test.state.is_active_at(&wallet_value, expired_height));

    let renewed_height = expired_height.saturating_add(10);
    apply_register_for_test(&mut test, renewed_height, &tx)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.join_height, 83);
    assert_eq!(meta.last_renew_height, renewed_height);
    assert!(test.state.is_active_at(&wallet_value, renewed_height));
    Ok(())
}

#[test]
fn test_084_renewal_after_expiry_restores_active_membership() -> TestResult {
    let mut test = new_test_state("renew_restores_active")?;
    let wallet_value = wallet(84);
    let tx = reg_tx(84)?;
    let lease =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config().lease_blocks;

    apply_register_for_test(&mut test, 84, &tx)?;

    let inactive_at = 84u64.saturating_add(lease).saturating_add(1);
    assert!(!test.state.active_at(inactive_at).contains(&wallet_value));

    apply_register_for_test(&mut test, inactive_at, &tx)?;

    assert!(test.state.active_at(inactive_at).contains(&wallet_value));
    Ok(())
}

#[test]
fn test_085_mark_exit_after_lease_expiry_records_exit_height() -> TestResult {
    let mut test = new_test_state("exit_after_expiry")?;
    let wallet_value = wallet(85);
    let lease =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config().lease_blocks;

    apply_register_for_test(&mut test, 85, &reg_tx(85)?)?;

    let exit_height = 85u64.saturating_add(lease).saturating_add(5);
    test.state.mark_exit(&wallet_value, exit_height)?;

    let meta = test
        .state
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.exit_height, Some(exit_height));
    Ok(())
}

#[test]
fn test_086_proposable_at_returns_only_validators_past_activation_boundary() -> TestResult {
    let mut test = new_test_state("proposable_subset_sorted")?;
    let first = wallet(8601);
    let second = wallet(8602);
    let delay = 10u64;

    apply_register_for_test(&mut test, 100, &reg_tx(8601)?)?;
    apply_register_for_test(&mut test, 108, &reg_tx(8602)?)?;

    let proposable = test.state.proposable_at(110, delay);

    assert_eq!(proposable, vec![first]);
    assert!(!proposable.contains(&second));
    Ok(())
}

#[test]
fn test_087_active_at_after_exit_is_sorted_and_excludes_exited_validator() -> TestResult {
    let mut test = new_test_state("active_sorted_after_exit")?;
    let exited = wallet(8702);

    apply_register_for_test(&mut test, 87, &reg_tx(8703)?)?;
    apply_register_for_test(&mut test, 87, &reg_tx(8701)?)?;
    apply_register_for_test(&mut test, 87, &reg_tx(8702)?)?;
    test.state.mark_exit(&exited, 90)?;

    let active = test.state.active_at(90);

    assert_eq!(active.len(), 2);
    assert!(!active.contains(&exited));
    assert_string_vec_sorted(&active);
    Ok(())
}

#[test]
fn test_088_all_keeps_exited_validators_in_canonical_history() -> TestResult {
    let mut test = new_test_state("all_keeps_exited")?;
    let wallet_value = wallet(88);

    apply_register_for_test(&mut test, 88, &reg_tx(88)?)?;
    test.state.mark_exit(&wallet_value, 90)?;

    assert_eq!(test.state.len(), 1);
    assert!(test.state.all().contains_key(&wallet_value));
    assert!(!test.state.active_at(90).contains(&wallet_value));
    Ok(())
}

#[test]
fn test_089_is_empty_false_after_only_validator_exits() -> TestResult {
    let mut test = new_test_state("is_empty_false_after_exit")?;
    let wallet_value = wallet(89);

    apply_register_for_test(&mut test, 89, &reg_tx(89)?)?;
    test.state.mark_exit(&wallet_value, 90)?;

    assert!(!test.state.is_empty());
    assert_eq!(test.state.len(), 1);
    Ok(())
}

#[test]
fn test_090_mark_exit_persists_exit_height_to_db() -> TestResult {
    let mut test = new_test_state("exit_persists")?;
    let wallet_value = wallet(90);

    apply_register_for_test(&mut test, 90, &reg_tx(90)?)?;
    test.state.mark_exit(&wallet_value, 100)?;

    let loaded = ValidatorState::load_state(test.manager()?.clone())?;
    let meta = loaded
        .meta_for(&wallet_value)
        .ok_or_else(|| boxed_error("missing validator meta"))?;

    assert_eq!(meta.exit_height, Some(100));
    Ok(())
}

#[test]
fn test_091_mark_exit_unknown_wallet_does_not_create_snapshot() -> TestResult {
    let mut test = new_test_state("exit_unknown_no_snapshot")?;

    test.state.mark_exit(&wallet(91), 91)?;

    let result = ValidatorState::load_state(test.manager()?.clone());

    assert!(result.is_err());
    assert!(test.state.is_empty());
    Ok(())
}

#[test]
fn test_092_invalid_register_tx_after_existing_validator_keeps_existing_state() -> TestResult {
    let mut test = new_test_state("invalid_after_existing")?;
    let existing = wallet(92);

    apply_register_for_test(&mut test, 92, &reg_tx(92)?)?;

    let bad = invalid_wallet_reg_tx(now_ts()?);
    let result = apply_register_for_test(&mut test, 93, &bad);

    assert!(result.is_err());
    assert_eq!(test.state.len(), 1);
    assert_eq!(test.state.join_height(&existing), Some(92));
    Ok(())
}

#[test]
fn test_093_register_node_tx_serialize_deserialize_round_trip() -> TestResult {
    let tx = reg_tx(93)?;
    let bytes = tx.serialize()?;
    let decoded = RegisterNodeTx::deserialize(&bytes)?;

    assert_eq!(decoded, tx);
    assert_eq!(decoded.wallet_str()?, wallet(93));
    Ok(())
}

#[test]
fn test_094_register_node_tx_new_from_bytes_accepts_trailing_nul_padding() -> TestResult {
    let wallet_value = wallet(94);
    let mut padded = wallet_value.as_bytes().to_vec();
    padded.extend_from_slice(&[0u8; 16]);

    let tx = RegisterNodeTx::new_from_bytes(&padded)?;

    assert_eq!(tx.wallet_str()?, wallet_value);
    Ok(())
}

#[test]
fn test_095_register_node_tx_deserialize_rejects_invalid_serialized_wallet() -> TestResult {
    let bad = invalid_wallet_reg_tx(now_ts()?);
    let bytes = postcard::to_allocvec(&bad)?;

    let result = RegisterNodeTx::deserialize(&bytes);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_096_validator_lifecycle_default_config_is_valid() -> TestResult {
    let cfg = remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::config();

    cfg.validate()?;
    assert!(cfg.lease_blocks >= 1);
    Ok(())
}

#[test]
fn test_097_validator_meta_founder_rejects_old_timestamp() -> TestResult {
    let result = ValidatorMeta::founder(1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_098_validator_meta_joined_rejects_far_future_timestamp() -> TestResult {
    let result = ValidatorMeta::joined(98, u64::MAX);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_099_validator_lifecycle_active_wallets_returns_sorted_wallets() -> TestResult {
    let ts = now_ts()?;
    let mut map = BTreeMap::new();

    map.insert(wallet(9903), ValidatorMeta::joined(99, ts)?);
    map.insert(wallet(9901), ValidatorMeta::joined(99, ts)?);
    map.insert(wallet(9902), ValidatorMeta::joined(99, ts)?);

    let active =
        remzar::consensus::por_008_validator_lifecycle::ValidatorLifecycle::active_wallets_at(
            &map, 99,
        )?;

    assert_eq!(active.len(), 3);
    assert_string_vec_sorted(&active);
    Ok(())
}

#[test]
fn test_100_load_test_250_validators_same_height_all_active_and_latch_set() -> TestResult {
    let mut test = new_test_state("load_250_same_height")?;

    for offset in 0u64..250u64 {
        let seed = 10_000u64.saturating_add(offset);
        apply_register_for_test(&mut test, 100, &reg_tx(seed)?)?;
    }

    let active = test.state.active_at(100);

    assert_eq!(test.state.len(), 250);
    assert_eq!(active.len(), 250);
    assert!(test.state.multi_validator_ever_seen()?);
    assert_string_vec_sorted(&active);

    for offset in 0u64..250u64 {
        let seed = 10_000u64.saturating_add(offset);
        assert_eq!(test.state.join_height(&wallet(seed)), Some(100));
    }

    Ok(())
}
