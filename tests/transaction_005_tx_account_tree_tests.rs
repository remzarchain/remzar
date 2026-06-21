// tests/transaction_005_tx_01_account_tree.rs

#![allow(clippy::too_many_lines)]

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_account_tree::{
    AccountModelTree, ChainLogic, from_micro_units, to_micro_units,
};
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::tokens::nft_001::NftMintTx;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), Box<dyn Error>>;
type ColumnRow = (Vec<u8>, Vec<u8>);
type ColumnRows = Vec<ColumnRow>;
type ColumnRowsResult = Result<ColumnRows, ErrorDetection>;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

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
            // Best-effort cleanup only. Tests must not fail during Drop.
        }
    }
}

struct TestChain {
    tree: AccountModelTree,
    db: TestDb,
}

impl TestChain {
    fn manager(&self) -> Result<&RockDBManager, Box<dyn Error>> {
        self.db.manager()
    }
}

fn store_replay_block_41(manager: &RockDBManager, block: &Block) -> Result<(), ErrorDetection> {
    let bytes = block.serialize_for_storage()?;
    manager.store_latest_block(&bytes, block.metadata.index)?;
    manager.index_block_by_hash(&block.block_hash, &bytes)?;
    manager.set_latest_block_index(block.metadata.index)?;
    manager.set_tip_height(block.metadata.index)?;
    Ok(())
}

fn store_batch_by_index_41(
    manager: &RockDBManager,
    batch: &TransactionBatch,
) -> Result<(), ErrorDetection> {
    let bytes = batch.serialize_for_storage()?;
    manager.store_batch_bytes(batch.index, &bytes)
}

fn tamper_block_hash_81(block: &Block) -> Block {
    let mut out = block.clone();
    if let Some(byte) = out.block_hash.get_mut(0) {
        *byte ^= 0xA5;
    }
    out
}

fn sum_balances_81(tree: &AccountModelTree) -> Result<u64, Box<dyn Error>> {
    tree.get_balances()
        .values()
        .copied()
        .try_fold(0u64, |acc, value| acc.checked_add(value))
        .ok_or_else(|| boxed_error("balance sum overflow"))
}

fn store_linear_blocks_41(
    manager: &RockDBManager,
    count: usize,
) -> Result<Vec<Block>, ErrorDetection> {
    let mut previous_hash = [0u8; 64];
    let mut blocks = Vec::with_capacity(count);

    for index_usize in 0..count {
        let index = u64::try_from(index_usize).map_err(|_| ErrorDetection::ValidationError {
            message: "test block index cannot fit into u64".to_owned(),
            tx_id: None,
        })?;

        let block = test_block(index, previous_hash)?;
        previous_hash = block.block_hash;
        store_replay_block_41(manager, &block)?;
        blocks.push(block);
    }

    Ok(blocks)
}

fn apply_empty_genesis_block_41(chain: &mut TestChain) -> Result<Block, Box<dyn Error>> {
    let key = "tx_batch_0000000000";
    let block = test_block_with_key(0, [0u8; 64], Some(key.to_owned()))?;
    let batch = tx_batch(0, Vec::new())?;

    store_batch_by_index_41(chain.manager()?, &batch)?;
    chain
        .tree
        .apply_block(&block)
        .map_err(|err| boxed_error(&err))?;

    Ok(block)
}

fn boxed_error(message: &str) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message.to_owned()))
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_account_tree_{label}_{pid}_{id}"))
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

fn new_test_chain(label: &str) -> Result<TestChain, Box<dyn Error>> {
    let db = new_blockchain_db(label)?;
    let tree = AccountModelTree::with_manager(db.manager()?.clone());

    Ok(TestChain { tree, db })
}

fn fixed_hash(seed: u8) -> Hash {
    [seed; 64]
}

fn seed_from_index(index: u64, offset: u8) -> u8 {
    let reduced: u8 = u8::try_from(index.rem_euclid(200)).unwrap_or_default();
    reduced.saturating_add(offset)
}

fn test_metadata(index: u64, previous_hash: Hash) -> BlockMetadata {
    let timestamp = 1_800_000_000u64.saturating_add(index);
    let merkle_root = fixed_hash(seed_from_index(index, 31));
    let signature_byte = if index == 0 {
        0u8
    } else {
        seed_from_index(index, 7)
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

fn test_block_with_key(
    index: u64,
    previous_hash: Hash,
    batch_key: Option<String>,
) -> Result<Block, ErrorDetection> {
    let miner = if index == 0 {
        String::new()
    } else {
        wallet(index.saturating_add(10))
    };

    Block::new(test_metadata(index, previous_hash), batch_key, miner, index)
}

fn test_block(index: u64, previous_hash: Hash) -> Result<Block, ErrorDetection> {
    let batch_key = if index == 0 {
        None
    } else {
        Some(format!("tx_batch_{index:010}"))
    };

    test_block_with_key(index, previous_hash, batch_key)
}

fn add_linear_blocks(
    tree: &mut AccountModelTree,
    count: usize,
) -> Result<Vec<Block>, ErrorDetection> {
    let existing = tree.get_blocks();
    let mut previous_hash = existing
        .last()
        .map(|block| block.block_hash)
        .unwrap_or([0u8; 64]);
    let start_index = existing.len();

    let mut added = Vec::with_capacity(count);

    for offset in 0..count {
        let index_usize = start_index.saturating_add(offset);
        let index = u64::try_from(index_usize).map_err(|_| ErrorDetection::ValidationError {
            message: "test block index cannot fit into u64".to_owned(),
            tx_id: None,
        })?;

        let block = test_block(index, previous_hash)?;
        previous_hash = block.block_hash;
        tree.add_block(block.clone())?;
        added.push(block);
    }

    Ok(added)
}

fn add_blocks_until_tip(
    tree: &mut AccountModelTree,
    tip_height: u64,
) -> Result<(), ErrorDetection> {
    let wanted_len_u64 = tip_height.saturating_add(1);
    let wanted_len =
        usize::try_from(wanted_len_u64).map_err(|_| ErrorDetection::ValidationError {
            message: "wanted chain length cannot fit into usize".to_owned(),
            tx_id: None,
        })?;

    let current_len = tree.get_blocks().len();
    if current_len < wanted_len {
        let missing = wanted_len.saturating_sub(current_len);
        add_linear_blocks(tree, missing)?;
    }

    Ok(())
}

fn tx_batch(index: u64, transactions: Vec<TxKind>) -> Result<TransactionBatch, ErrorDetection> {
    TransactionBatch::new(index, 1_800_010_000u64.saturating_add(index), transactions)
}

fn transfer_tx(sender: u64, receiver: u64, amount: u64) -> Result<Transaction, ErrorDetection> {
    Transaction::new(wallet(sender), wallet(receiver), amount)
}

fn manual_tx(sender: u64, receiver: u64, amount: u64) -> Result<Transaction, Box<dyn Error>> {
    Ok(Transaction {
        sender: wallet_arr(sender)?,
        receiver: wallet_arr(receiver)?,
        amount,
        timestamp: 1_800_020_000,
    })
}

fn fund_with_reward(
    tree: &mut AccountModelTree,
    receiver: &str,
    amount: u64,
) -> Result<(), ErrorDetection> {
    add_blocks_until_tip(tree, 1)?;
    let reward = RewardTx::new(receiver.to_owned(), amount, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;
    tree.apply_batch(&batch)
}

fn store_batch_for_key(
    manager: &RockDBManager,
    key: &str,
    batch: &TransactionBatch,
) -> Result<(), ErrorDetection> {
    let bytes = batch.serialize_for_storage()?;
    manager.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        key.as_bytes(),
        &bytes,
    )
}

fn read_account_balance(
    manager: &RockDBManager,
    account: &str,
) -> Result<Option<u64>, Box<dyn Error>> {
    let maybe_bytes = manager.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, account.as_bytes())?;

    match maybe_bytes {
        Some(bytes) => {
            let value = postcard::from_bytes::<u64>(&bytes)
                .map_err(|err| boxed_error(&format!("failed to decode account balance: {err}")))?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

fn assert_string_error_contains(result: Result<(), String>, needle: &str) -> TestResult {
    match result {
        Ok(()) => Err(boxed_error("expected String error, got Ok(())")),
        Err(message) => {
            assert!(
                message.contains(needle),
                "error message did not contain '{needle}': {message}"
            );
            Ok(())
        }
    }
}

#[test]
fn test_001_new_tree_starts_empty() -> TestResult {
    let chain = new_test_chain("new_tree_empty")?;

    assert_eq!(chain.tree.latest_block_height(), 0);
    assert!(chain.tree.get_balances().is_empty());
    assert!(chain.tree.get_blocks().is_empty());
    assert_eq!(chain.tree.total_issued_micro(), 0);
    assert_eq!(chain.tree.rewards_issued_micro(), 0);
    assert_eq!(
        chain.tree.remaining_supply_micro(),
        GlobalConfiguration::MAX_SUPPLY
    );

    Ok(())
}

#[test]
fn test_002_missing_balance_returns_zero() -> TestResult {
    let chain = new_test_chain("missing_balance")?;
    assert_eq!(chain.tree.get_balance(&wallet(2)), 0);
    Ok(())
}

#[test]
fn test_003_set_balance_writes_memory_balance() -> TestResult {
    let mut chain = new_test_chain("set_balance")?;
    let account = wallet(3);

    chain.tree.set_balance(&account, 777);

    assert_eq!(chain.tree.get_balance(&account), 777);
    assert_eq!(chain.tree.get_balances().len(), 1);
    Ok(())
}

#[test]
fn test_004_increment_balance_new_and_existing_account() -> TestResult {
    let mut chain = new_test_chain("increment_balance")?;
    let account = wallet(4);

    chain.tree.increment_balance(&account, 10)?;
    chain.tree.increment_balance(&account, 15)?;

    assert_eq!(chain.tree.get_balance(&account), 25);
    Ok(())
}

#[test]
fn test_005_increment_balance_rejects_total_supply_overflow() -> TestResult {
    let mut chain = new_test_chain("increment_over_supply")?;
    let account = wallet(5);

    chain
        .tree
        .set_balance(&account, GlobalConfiguration::MAX_SUPPLY);

    let result = chain.tree.increment_balance(&account, 1);

    assert!(result.is_err());
    assert_eq!(
        chain.tree.get_balance(&account),
        GlobalConfiguration::MAX_SUPPLY
    );

    Ok(())
}

#[test]
fn test_006_decrement_balance_existing_account() -> TestResult {
    let mut chain = new_test_chain("decrement_existing")?;
    let account = wallet(6);

    chain.tree.set_balance(&account, 100);
    chain.tree.decrement_balance(&account, 40)?;

    assert_eq!(chain.tree.get_balance(&account), 60);
    Ok(())
}

#[test]
fn test_007_decrement_balance_missing_account_errors() -> TestResult {
    let mut chain = new_test_chain("decrement_missing")?;

    let result = chain.tree.decrement_balance(&wallet(7), 1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_008_decrement_balance_underflow_errors_without_mutation() -> TestResult {
    let mut chain = new_test_chain("decrement_underflow")?;
    let account = wallet(8);

    chain.tree.set_balance(&account, 5);

    let result = chain.tree.decrement_balance(&account, 6);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&account), 5);
    Ok(())
}

#[test]
fn test_009_update_balance_creates_and_accumulates() -> TestResult {
    let mut chain = new_test_chain("update_balance")?;
    let account = wallet(9);

    chain.tree.update_balance(&account, 12)?;
    chain.tree.update_balance(&account, 8)?;

    assert_eq!(chain.tree.get_balance(&account), 20);
    Ok(())
}

#[test]
fn test_010_update_balance_rejects_supply_limit_excess() -> TestResult {
    let mut chain = new_test_chain("update_over_supply")?;
    let account = wallet(10);

    chain
        .tree
        .set_balance(&account, GlobalConfiguration::MAX_SUPPLY);

    let result = chain.tree.update_balance(&account, 1);

    assert!(result.is_err());
    assert_eq!(
        chain.tree.get_balance(&account),
        GlobalConfiguration::MAX_SUPPLY
    );
    Ok(())
}

#[test]
fn test_011_decimal_conversion_helpers_are_available_from_account_tree_module() -> TestResult {
    let micro = to_micro_units(1.25);
    let remzar = from_micro_units(micro);

    assert_eq!(micro, 125_000_000);
    assert_eq!(format!("{remzar:.8}"), "1.25000000");

    Ok(())
}

#[test]
fn test_012_serialize_deserialize_empty_state_round_trip() -> TestResult {
    let chain = new_test_chain("serialize_empty")?;

    let bytes = chain.tree.serialize_state()?;
    let restored = AccountModelTree::deserialize_state(&bytes, chain.manager()?.clone())?;

    assert!(restored.get_balances().is_empty());
    assert!(restored.get_blocks().is_empty());
    assert_eq!(restored.total_issued_micro(), 0);
    Ok(())
}

#[test]
fn test_013_commit_and_load_state_round_trip() -> TestResult {
    let mut chain = new_test_chain("commit_load")?;
    let first = wallet(13);
    let second = wallet(14);

    chain.tree.set_balance(&first, 111);
    chain.tree.set_balance(&second, 222);
    add_linear_blocks(&mut chain.tree, 2)?;
    chain.tree.commit()?;

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    assert_eq!(loaded.get_balance(&first), 111);
    assert_eq!(loaded.get_balance(&second), 222);
    // Compact STATE_KEY intentionally does not persist block history.
    assert!(loaded.get_blocks().is_empty());
    assert_eq!(loaded.latest_block_height(), 1);
    Ok(())
}

#[test]
fn test_014_load_state_missing_returns_not_found_error() -> TestResult {
    let chain = new_test_chain("missing_state")?;

    let result = AccountModelTree::load_state(chain.manager()?.clone());

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_015_flush_balances_writes_account_column_family() -> TestResult {
    let mut chain = new_test_chain("flush_balances")?;
    let account = wallet(15);

    chain.tree.set_balance(&account, 515);
    chain.tree.flush_balances()?;

    assert_eq!(read_account_balance(chain.manager()?, &account)?, Some(515));
    Ok(())
}

#[test]
fn test_016_flush_addresses_only_writes_selected_accounts() -> TestResult {
    let mut chain = new_test_chain("flush_addresses_subset")?;
    let selected = wallet(16);
    let skipped = wallet(17);

    chain.tree.set_balance(&selected, 1600);
    chain.tree.set_balance(&skipped, 1700);

    chain
        .tree
        .flush_addresses(vec![selected.clone()])
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(
        read_account_balance(chain.manager()?, &selected)?,
        Some(1600)
    );
    assert_eq!(read_account_balance(chain.manager()?, &skipped)?, None);
    Ok(())
}

#[test]
fn test_017_flush_balances_for_batch_flushes_transfer_touched_accounts() -> TestResult {
    let mut chain = new_test_chain("flush_for_batch")?;
    let sender = wallet(18);
    let receiver = wallet(19);

    chain.tree.set_balance(&sender, 800);
    chain.tree.set_balance(&receiver, 200);

    let tx = transfer_tx(18, 19, 25)?;
    let batch = tx_batch(0, vec![TxKind::Transfer(tx)])?;

    chain
        .tree
        .flush_balances_for_batch(&batch)
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(read_account_balance(chain.manager()?, &sender)?, Some(800));
    assert_eq!(
        read_account_balance(chain.manager()?, &receiver)?,
        Some(200)
    );
    Ok(())
}

#[test]
fn test_018_apply_transaction_valid_moves_balance_and_commits_state() -> TestResult {
    let mut chain = new_test_chain("apply_transaction_valid")?;
    let sender = wallet(20);
    let receiver = wallet(21);

    chain.tree.set_balance(&sender, 100);
    let tx = transfer_tx(20, 21, 35)?;

    chain.tree.apply_transaction(&tx)?;

    assert_eq!(chain.tree.get_balance(&sender), 65);
    assert_eq!(chain.tree.get_balance(&receiver), 35);

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;
    assert_eq!(loaded.get_balance(&sender), 65);
    assert_eq!(loaded.get_balance(&receiver), 35);

    Ok(())
}

#[test]
fn test_019_apply_transaction_zero_amount_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_transaction_zero")?;
    let sender = wallet(22);
    let receiver = wallet(23);

    chain.tree.set_balance(&sender, 10);
    let tx = manual_tx(22, 23, 0)?;

    let result = chain.tree.apply_transaction(&tx);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&sender), 10);
    assert_eq!(chain.tree.get_balance(&receiver), 0);
    Ok(())
}

#[test]
fn test_020_apply_transaction_same_sender_receiver_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_transaction_same")?;
    let account = wallet(24);

    chain.tree.set_balance(&account, 10);
    let tx = manual_tx(24, 24, 1)?;

    let result = chain.tree.apply_transaction(&tx);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&account), 10);
    Ok(())
}

#[test]
fn test_021_apply_transaction_insufficient_balance_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_transaction_insufficient")?;
    let sender = wallet(25);
    let receiver = wallet(26);

    chain.tree.set_balance(&sender, 9);
    let tx = transfer_tx(25, 26, 10)?;

    let result = chain.tree.apply_transaction(&tx);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&sender), 9);
    assert_eq!(chain.tree.get_balance(&receiver), 0);
    Ok(())
}

#[test]
fn test_022_apply_transaction_over_max_amount_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_transaction_over_max")?;
    let sender = wallet(27);
    let receiver = wallet(28);
    let amount = GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(1);

    chain
        .tree
        .set_balance(&sender, GlobalConfiguration::MAX_SUPPLY);
    let tx = manual_tx(27, 28, amount)?;

    let result = chain.tree.apply_transaction(&tx);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&receiver), 0);
    Ok(())
}

#[test]
fn test_023_property_many_valid_transfers_conserve_total_balance() -> TestResult {
    let mut chain = new_test_chain("property_conserve_total")?;
    let sender = wallet(29);
    let receiver = wallet(30);

    chain.tree.set_balance(&sender, 1_000);
    chain.tree.set_balance(&receiver, 0);

    for step in 0usize..100usize {
        let amount = u64::try_from(step.rem_euclid(5).saturating_add(1))
            .map_err(|_| boxed_error("step amount conversion failed"))?;
        let tx = transfer_tx(29, 30, amount)?;
        chain.tree.apply_transaction(&tx)?;
    }

    let total = chain
        .tree
        .get_balance(&sender)
        .saturating_add(chain.tree.get_balance(&receiver));

    assert_eq!(total, 1_000);
    assert_eq!(chain.tree.get_balance(&sender), 700);
    assert_eq!(chain.tree.get_balance(&receiver), 300);
    Ok(())
}

#[test]
fn test_024_fuzz_invalid_manual_transactions_do_not_mutate_balances() -> TestResult {
    let mut chain = new_test_chain("fuzz_invalid_transactions")?;
    let sender = wallet(31);
    let receiver = wallet(32);

    chain.tree.set_balance(&sender, 500);

    let cases = [
        0,
        GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(1),
        u64::MAX,
    ];

    for amount in cases {
        let before_sender = chain.tree.get_balance(&sender);
        let before_receiver = chain.tree.get_balance(&receiver);
        let tx = manual_tx(31, 32, amount)?;

        let result = chain.tree.apply_transaction(&tx);

        assert!(result.is_err());
        assert_eq!(chain.tree.get_balance(&sender), before_sender);
        assert_eq!(chain.tree.get_balance(&receiver), before_receiver);
    }

    Ok(())
}

#[test]
fn test_025_add_block_accepts_genesis_block() -> TestResult {
    let mut chain = new_test_chain("add_genesis")?;

    let block = test_block(0, [0u8; 64])?;
    chain.tree.add_block(block.clone())?;

    assert_eq!(chain.tree.latest_block_height(), 0);
    assert_eq!(chain.tree.get_block_by_index(0)?, block);
    Ok(())
}

#[test]
fn test_026_add_block_accepts_valid_child_block() -> TestResult {
    let mut chain = new_test_chain("add_child")?;

    let blocks = add_linear_blocks(&mut chain.tree, 2)?;

    assert_eq!(chain.tree.latest_block_height(), 1);
    assert_eq!(chain.tree.get_blocks(), blocks);
    Ok(())
}

#[test]
fn test_027_adversarial_out_of_order_block_is_queued_then_processed() -> TestResult {
    let mut chain = new_test_chain("out_of_order_blocks")?;

    let genesis = test_block(0, [0u8; 64])?;
    let child = test_block(1, genesis.block_hash)?;
    let grandchild = test_block(2, child.block_hash)?;

    chain.tree.add_block(genesis.clone())?;
    chain.tree.add_block(grandchild.clone())?;

    assert_eq!(chain.tree.latest_block_height(), 0);

    chain.tree.add_block(child.clone())?;

    assert_eq!(chain.tree.latest_block_height(), 2);
    assert_eq!(chain.tree.get_block_by_index(0)?, genesis);
    assert_eq!(chain.tree.get_block_by_index(1)?, child);
    assert_eq!(chain.tree.get_block_by_index(2)?, grandchild);
    Ok(())
}

#[test]
fn test_028_add_block_rejects_invalid_previous_hash() -> TestResult {
    let mut chain = new_test_chain("bad_previous_hash")?;

    let genesis = test_block(0, [0u8; 64])?;
    let bad_child = test_block(1, fixed_hash(250))?;

    chain.tree.add_block(genesis)?;

    let result = chain.tree.add_block(bad_child);

    assert!(result.is_err());
    assert_eq!(chain.tree.latest_block_height(), 0);
    Ok(())
}

#[test]
fn test_029_add_block_duplicate_or_old_block_is_ignored_without_mutation() -> TestResult {
    let mut chain = new_test_chain("duplicate_block")?;

    let blocks = add_linear_blocks(&mut chain.tree, 2)?;
    let duplicate_genesis = blocks
        .first()
        .cloned()
        .ok_or_else(|| boxed_error("missing genesis block"))?;

    chain.tree.add_block(duplicate_genesis)?;

    assert_eq!(chain.tree.latest_block_height(), 1);
    assert_eq!(chain.tree.get_blocks().len(), 2);
    Ok(())
}

#[test]
fn test_030_apply_block_success_with_empty_genesis_batch() -> TestResult {
    let mut chain = new_test_chain("apply_block_success")?;
    let key = "tx_batch_0000000000";
    let block = test_block_with_key(0, [0u8; 64], Some(key.to_owned()))?;
    let batch = tx_batch(0, Vec::new())?;

    store_batch_for_key(chain.manager()?, key, &batch)?;

    chain
        .tree
        .apply_block(&block)
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(chain.tree.latest_block_height(), 0);
    assert_eq!(chain.tree.get_block_by_index(0)?, block);
    Ok(())
}

#[test]
fn test_031_apply_block_missing_batch_rolls_back_state() -> TestResult {
    let mut chain = new_test_chain("apply_block_missing_batch")?;
    let account = wallet(33);
    let key = "tx_batch_0000000000";
    let block = test_block_with_key(0, [0u8; 64], Some(key.to_owned()))?;

    chain.tree.set_balance(&account, 333);

    let result = chain.tree.apply_block(&block);

    assert_string_error_contains(result, "Batch bytes missing")?;
    assert!(chain.tree.get_blocks().is_empty());
    assert_eq!(chain.tree.get_balance(&account), 333);
    Ok(())
}

#[test]
fn test_032_apply_batch_reward_updates_balance_and_supply_counters() -> TestResult {
    let mut chain = new_test_chain("apply_batch_reward")?;
    let receiver = wallet(34);

    fund_with_reward(&mut chain.tree, &receiver, 500)?;

    assert_eq!(chain.tree.get_balance(&receiver), 500);
    assert_eq!(chain.tree.total_issued_micro(), 500);
    assert_eq!(chain.tree.rewards_issued_micro(), 500);
    assert_eq!(
        chain.tree.remaining_reward_supply_micro(),
        GlobalConfiguration::MAX_REWARD_SUPPLY.saturating_sub(500)
    );
    Ok(())
}

#[test]
fn test_033_apply_batch_transfer_after_reward_funding_updates_balances() -> TestResult {
    let mut chain = new_test_chain("apply_batch_transfer")?;
    let sender = wallet(35);
    let receiver = wallet(36);

    fund_with_reward(&mut chain.tree, &sender, 1_000)?;
    add_blocks_until_tip(&mut chain.tree, 2)?;

    let tx = transfer_tx(35, 36, 275)?;
    let batch = tx_batch(2, vec![TxKind::Transfer(tx)])?;

    chain.tree.apply_batch(&batch)?;

    assert_eq!(chain.tree.get_balance(&sender), 725);
    assert_eq!(chain.tree.get_balance(&receiver), 275);
    assert_eq!(chain.tree.total_issued_micro(), 1_000);
    Ok(())
}

#[test]
fn test_034_apply_batch_insufficient_aggregate_spend_is_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_batch_insufficient")?;
    let sender = wallet(37);
    let receiver = wallet(38);

    fund_with_reward(&mut chain.tree, &sender, 50)?;
    add_blocks_until_tip(&mut chain.tree, 2)?;

    let tx = transfer_tx(37, 38, 51)?;
    let batch = tx_batch(2, vec![TxKind::Transfer(tx)])?;

    let result = chain.tree.apply_batch(&batch);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&sender), 50);
    assert_eq!(chain.tree.get_balance(&receiver), 0);
    Ok(())
}

#[test]
fn test_035_apply_batch_duplicate_transfer_is_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_batch_duplicate_transfer")?;
    let sender = wallet(39);
    let receiver = wallet(40);

    fund_with_reward(&mut chain.tree, &sender, 500)?;
    add_blocks_until_tip(&mut chain.tree, 2)?;

    let tx = transfer_tx(39, 40, 10)?;
    let batch = tx_batch(2, vec![TxKind::Transfer(tx.clone()), TxKind::Transfer(tx)])?;

    let result = chain.tree.apply_batch(&batch);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&sender), 500);
    assert_eq!(chain.tree.get_balance(&receiver), 0);
    Ok(())
}

#[test]
fn test_036_apply_batch_zero_transfer_is_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_batch_zero_transfer")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let tx = manual_tx(41, 42, 0)?;
    let batch = tx_batch(1, vec![TxKind::Transfer(tx)])?;

    let result = chain.tree.apply_batch(&batch);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_037_apply_batch_same_sender_receiver_transfer_is_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_batch_same_sender")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let tx = manual_tx(43, 43, 1)?;
    let batch = tx_batch(1, vec![TxKind::Transfer(tx)])?;

    let result = chain.tree.apply_batch(&batch);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_038_apply_batch_multiple_rewards_is_rejected() -> TestResult {
    let mut chain = new_test_chain("apply_batch_multiple_rewards")?;
    let receiver_a = wallet(44);
    let receiver_b = wallet(45);

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let reward_a = RewardTx::new(receiver_a, 1, 1)?;
    let reward_b = RewardTx::new(receiver_b, 1, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward_a), TxKind::Reward(reward_b)])?;

    let result = chain.tree.apply_batch(&batch);

    assert!(result.is_err());
    assert_eq!(chain.tree.total_issued_micro(), 0);
    Ok(())
}

#[test]
fn test_039_apply_batch_nft_mint_does_not_mutate_balances_or_supply() -> TestResult {
    let mut chain = new_test_chain("apply_batch_nft_mint")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let nft = NftMintTx::from_content_bytes(
        fixed_hash(55),
        "test nft".to_owned(),
        "test description".to_owned(),
        b"deterministic nft content",
    );
    let batch = tx_batch(1, vec![TxKind::NftMint(nft)])?;

    chain.tree.apply_batch(&batch)?;

    assert!(chain.tree.get_balances().is_empty());
    assert_eq!(chain.tree.total_issued_micro(), 0);
    assert_eq!(chain.tree.rewards_issued_micro(), 0);
    Ok(())
}

#[test]
fn test_040_load_many_blocks_and_balances_stays_consistent() -> TestResult {
    let mut chain = new_test_chain("load_many_blocks_and_balances")?;

    add_linear_blocks(&mut chain.tree, 64)?;

    for seed in 1u64..=200u64 {
        let account = wallet(seed.saturating_add(1_000));
        chain.tree.update_balance(&account, seed)?;
    }

    chain.tree.commit()?;

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    // STATE_KEY is compact: balances and tip metadata persist, recent block cache does not.
    assert!(loaded.get_blocks().is_empty());
    assert_eq!(loaded.latest_block_height(), 63);
    assert_eq!(loaded.get_balances().len(), 200);

    for seed in 1u64..=200u64 {
        let account = wallet(seed.saturating_add(1_000));
        assert_eq!(loaded.get_balance(&account), seed);
    }

    Ok(())
}

#[test]
fn test_041_rocksdb_store_state_and_load_state_round_trip() -> TestResult {
    let mut chain = new_test_chain("db_store_state_round_trip")?;
    let account = wallet(41);

    chain.tree.set_balance(&account, 4_100);
    add_linear_blocks(&mut chain.tree, 3)?;
    chain.manager()?.store_state(&chain.tree)?;

    let loaded = chain.manager()?.load_state()?;

    assert_eq!(loaded.get_balance(&account), 4_100);
    assert!(loaded.get_blocks().is_empty());
    assert_eq!(loaded.latest_block_height(), 2);
    Ok(())
}

#[test]
fn test_042_rocksdb_set_account_balance_updates_state_and_account_cf() -> TestResult {
    let chain = new_test_chain("db_set_account_balance")?;
    let account = wallet(42);

    chain.manager()?.set_account_balance(&account, 4_200)?;

    let state_balance = chain.manager()?.get_account_balance(&account)?;
    let cf_balance = read_account_balance(chain.manager()?, &account)?;

    assert_eq!(state_balance, 4_200);
    assert_eq!(cf_balance, Some(4_200));
    Ok(())
}

#[test]
fn test_043_rocksdb_apply_transaction_batch_updates_persisted_state() -> TestResult {
    let mut chain = new_test_chain("db_apply_transaction_batch")?;
    let receiver = wallet(43);

    add_blocks_until_tip(&mut chain.tree, 1)?;
    chain.manager()?.store_state(&chain.tree)?;

    let reward = RewardTx::new(receiver.clone(), 430, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;

    chain.manager()?.apply_transaction_batch(&batch)?;

    let loaded = chain.manager()?.load_state()?;
    assert_eq!(loaded.get_balance(&receiver), 430);
    assert_eq!(loaded.total_issued_micro(), 430);
    Ok(())
}

#[test]
fn test_044_reload_from_db_to_height_genesis_without_batch_succeeds() -> TestResult {
    let mut chain = new_test_chain("reload_genesis_only")?;
    let blocks = store_linear_blocks_41(chain.manager()?, 1)?;

    chain.tree.reload_from_db_to_height(0)?;

    assert_eq!(chain.tree.get_blocks(), blocks);
    assert_eq!(chain.tree.latest_block_height(), 0);
    Ok(())
}

#[test]
fn test_045_reload_from_db_to_height_missing_non_genesis_batch_fails() -> TestResult {
    let mut chain = new_test_chain("reload_missing_batch")?;

    store_linear_blocks_41(chain.manager()?, 2)?;

    let result = chain.tree.reload_from_db_to_height(1);

    assert!(result.is_err());
    assert!(chain.tree.get_blocks().is_empty());
    Ok(())
}

#[test]
fn test_046_reload_from_db_to_height_reward_batch_rebuilds_balances() -> TestResult {
    let mut chain = new_test_chain("reload_reward_batch")?;
    let receiver = wallet(46);

    store_linear_blocks_41(chain.manager()?, 2)?;

    let reward = RewardTx::new(receiver.clone(), 460, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;
    store_batch_by_index_41(chain.manager()?, &batch)?;

    chain.tree.reload_from_db_to_height(1)?;

    assert_eq!(chain.tree.get_balance(&receiver), 460);
    assert_eq!(chain.tree.total_issued_micro(), 460);
    assert_eq!(chain.tree.rewards_issued_micro(), 460);
    Ok(())
}

#[test]
fn test_047_reload_from_db_uses_latest_block_index_metadata() -> TestResult {
    let mut chain = new_test_chain("reload_from_db_latest_index")?;
    let receiver = wallet(47);

    store_linear_blocks_41(chain.manager()?, 2)?;

    let reward = RewardTx::new(receiver.clone(), 470, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;
    store_batch_by_index_41(chain.manager()?, &batch)?;
    chain.manager()?.set_latest_block_index(1)?;

    chain.tree.reload_from_db();

    assert_eq!(chain.tree.latest_block_height(), 1);
    assert_eq!(chain.tree.get_balance(&receiver), 470);
    Ok(())
}

#[test]
fn test_048_reload_from_db_to_height_with_reward_then_transfer_replays_in_order() -> TestResult {
    let mut chain = new_test_chain("reload_reward_then_transfer")?;
    let sender = wallet(48);
    let receiver = wallet(49);

    store_linear_blocks_41(chain.manager()?, 3)?;

    let reward = RewardTx::new(sender.clone(), 1_000, 1)?;
    let batch_one = tx_batch(1, vec![TxKind::Reward(reward)])?;
    store_batch_by_index_41(chain.manager()?, &batch_one)?;

    let tx = transfer_tx(48, 49, 333)?;
    let batch_two = tx_batch(2, vec![TxKind::Transfer(tx)])?;
    store_batch_by_index_41(chain.manager()?, &batch_two)?;

    chain.tree.reload_from_db_to_height(2)?;

    assert_eq!(chain.tree.get_balance(&sender), 667);
    assert_eq!(chain.tree.get_balance(&receiver), 333);
    assert_eq!(chain.tree.total_issued_micro(), 1_000);
    Ok(())
}

#[test]
fn test_049_apply_block_without_batch_key_rolls_back() -> TestResult {
    let mut chain = new_test_chain("apply_no_batch_key")?;
    let account = wallet(50);

    chain.tree.set_balance(&account, 50);
    let block = test_block_with_key(0, [0u8; 64], None)?;

    let result = chain.tree.apply_block(&block);

    assert_string_error_contains(result, "Block missing batch_key")?;
    assert!(chain.tree.get_blocks().is_empty());
    assert_eq!(chain.tree.get_balance(&account), 50);
    Ok(())
}

#[test]
fn test_050_apply_block_with_corrupt_batch_bytes_rolls_back() -> TestResult {
    let mut chain = new_test_chain("apply_corrupt_batch")?;
    let key = "tx_batch_0000000000";
    let block = test_block_with_key(0, [0u8; 64], Some(key.to_owned()))?;

    chain.manager()?.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        key.as_bytes(),
        b"not a postcard batch",
    )?;

    let result = chain.tree.apply_block(&block);

    assert_string_error_contains(result, "Failed to deserialize batch")?;
    assert!(chain.tree.get_blocks().is_empty());
    Ok(())
}

#[test]
fn test_051_apply_block_with_batch_index_mismatch_rolls_back() -> TestResult {
    let mut chain = new_test_chain("apply_batch_index_mismatch")?;
    let key = "tx_batch_0000000000";
    let block = test_block_with_key(0, [0u8; 64], Some(key.to_owned()))?;
    let wrong_batch = tx_batch(1, Vec::new())?;

    store_batch_for_key(chain.manager()?, key, &wrong_batch)?;

    let result = chain.tree.apply_block(&block);

    assert_string_error_contains(result, "Batch index 1 does not match block height 0")?;
    assert!(chain.tree.get_blocks().is_empty());
    Ok(())
}

#[test]
fn test_052_apply_block_reward_child_batch_updates_state_and_account_cf() -> TestResult {
    let mut chain = new_test_chain("apply_child_reward")?;
    let receiver = wallet(52);

    let genesis = apply_empty_genesis_block_41(&mut chain)?;

    let key = "tx_batch_0000000001";
    let child = test_block_with_key(1, genesis.block_hash, Some(key.to_owned()))?;

    let reward = RewardTx::new(receiver.clone(), 520, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;

    store_batch_by_index_41(chain.manager()?, &batch)?;

    chain
        .tree
        .apply_block(&child)
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(chain.tree.latest_block_height(), 1);
    assert_eq!(chain.tree.get_balance(&receiver), 520);
    assert_eq!(chain.tree.total_issued_micro(), 520);
    assert_eq!(chain.tree.rewards_issued_micro(), 520);
    assert_eq!(
        read_account_balance(chain.manager()?, &receiver)?,
        Some(520)
    );

    Ok(())
}

#[test]
fn test_053_apply_block_same_canonical_block_is_idempotent() -> TestResult {
    let mut chain = new_test_chain("apply_block_idempotent")?;
    let block = apply_empty_genesis_block_41(&mut chain)?;

    chain
        .tree
        .apply_block(&block)
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(chain.tree.get_blocks().len(), 1);
    assert_eq!(chain.tree.get_block_by_index(0)?, block);
    Ok(())
}

#[test]
fn test_054_apply_block_wrong_next_index_fails_without_mutation() -> TestResult {
    let mut chain = new_test_chain("apply_wrong_next_index")?;
    let block = test_block_with_key(1, fixed_hash(54), Some("tx_batch_0000000001".to_owned()))?;

    let result = chain.tree.apply_block(&block);

    assert_string_error_contains(result, "Block linkage failed")?;
    assert!(chain.tree.get_blocks().is_empty());
    Ok(())
}

#[test]
fn test_055_apply_block_invalid_previous_hash_fails_without_db_batch_read() -> TestResult {
    let mut chain = new_test_chain("apply_invalid_previous_hash")?;
    let genesis = apply_empty_genesis_block_41(&mut chain)?;
    let bad_child =
        test_block_with_key(1, fixed_hash(200), Some("tx_batch_0000000001".to_owned()))?;

    let result = chain.tree.apply_block(&bad_child);

    assert_string_error_contains(result, "invalid previous_hash")?;
    assert_eq!(chain.tree.get_blocks().len(), 1);
    assert_eq!(chain.tree.get_block_by_index(0)?, genesis);
    Ok(())
}

#[test]
fn test_056_apply_block_valid_reward_child_updates_balance_and_flushes_account() -> TestResult {
    let mut chain = new_test_chain("apply_valid_reward_child")?;
    let genesis = apply_empty_genesis_block_41(&mut chain)?;
    let receiver = wallet(56);

    let child = test_block_with_key(
        1,
        genesis.block_hash,
        Some("tx_batch_0000000001".to_owned()),
    )?;
    let reward = RewardTx::new(receiver.clone(), 560, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;
    store_batch_by_index_41(chain.manager()?, &batch)?;

    chain
        .tree
        .apply_block(&child)
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(chain.tree.latest_block_height(), 1);
    assert_eq!(chain.tree.get_balance(&receiver), 560);
    assert_eq!(
        read_account_balance(chain.manager()?, &receiver)?,
        Some(560)
    );
    Ok(())
}

#[test]
fn test_057_apply_block_dry_run_failure_restores_snapshot() -> TestResult {
    let mut chain = new_test_chain("apply_dry_run_rollback")?;
    let genesis = apply_empty_genesis_block_41(&mut chain)?;
    let sender = wallet(57);
    let receiver = wallet(58);

    let child = test_block_with_key(
        1,
        genesis.block_hash,
        Some("tx_batch_0000000001".to_owned()),
    )?;
    let tx = transfer_tx(57, 58, 10)?;
    let batch = tx_batch(1, vec![TxKind::Transfer(tx)])?;
    store_batch_by_index_41(chain.manager()?, &batch)?;

    let result = chain.tree.apply_block(&child);

    assert_string_error_contains(result, "Dry-run block+batch failed")?;
    assert_eq!(chain.tree.get_blocks().len(), 1);
    assert_eq!(chain.tree.get_balance(&sender), 0);
    assert_eq!(chain.tree.get_balance(&receiver), 0);
    Ok(())
}

#[test]
fn test_058_rollback_to_missing_ancestor_errors() -> TestResult {
    let mut chain = new_test_chain("rollback_missing")?;

    add_linear_blocks(&mut chain.tree, 2)?;

    let result = chain.tree.rollback_to(fixed_hash(88));

    assert_string_error_contains(result, "not found for rollback")?;
    assert_eq!(chain.tree.get_blocks().len(), 2);
    Ok(())
}

#[test]
fn test_059_rollback_to_existing_ancestor_reloads_committed_state() -> TestResult {
    let mut chain = new_test_chain("rollback_existing")?;
    let account = wallet(59);

    let blocks = store_linear_blocks_41(chain.manager()?, 2)?;
    let reward = RewardTx::new(account.clone(), 590, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;
    store_batch_by_index_41(chain.manager()?, &batch)?;

    chain.tree.reload_from_db_to_height(1)?;
    assert_eq!(chain.tree.get_blocks().len(), 2);
    assert_eq!(chain.tree.get_balance(&account), 590);

    let ancestor_hash = blocks
        .first()
        .map(|block| block.block_hash)
        .ok_or_else(|| boxed_error("missing ancestor block"))?;

    chain
        .tree
        .rollback_to(ancestor_hash)
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(chain.tree.get_blocks().len(), 1);
    assert_eq!(chain.tree.latest_block_height(), 0);
    assert_eq!(chain.tree.get_balance(&account), 0);
    Ok(())
}

#[test]
fn test_060_remaining_supply_helpers_track_reward_issuance() -> TestResult {
    let mut chain = new_test_chain("remaining_supply_helpers")?;
    let receiver = wallet(60);

    fund_with_reward(&mut chain.tree, &receiver, 600)?;

    assert_eq!(chain.tree.total_issued_micro(), 600);
    assert_eq!(
        chain.tree.remaining_supply_micro(),
        GlobalConfiguration::MAX_SUPPLY.saturating_sub(600)
    );
    assert_eq!(
        chain.tree.remaining_reward_supply_micro(),
        GlobalConfiguration::MAX_REWARD_SUPPLY.saturating_sub(600)
    );
    Ok(())
}

#[test]
fn test_061_scheduled_reward_remaining_now_matches_tip_height_query() -> TestResult {
    let mut chain = new_test_chain("scheduled_now")?;

    add_blocks_until_tip(&mut chain.tree, 3)?;

    let now = chain.tree.remaining_reward_supply_micro_scheduled_now();
    let direct = chain
        .tree
        .remaining_reward_supply_micro_after_height_scheduled(3);

    assert_eq!(now, direct);
    Ok(())
}

#[test]
fn test_062_scheduled_reward_remaining_is_monotonic_non_increasing() -> TestResult {
    let chain = new_test_chain("scheduled_monotonic")?;
    let mut previous = u64::MAX;

    for height in 0u64..40u64 {
        let remaining = chain
            .tree
            .remaining_reward_supply_micro_after_height_scheduled(height);

        assert!(
            remaining <= previous,
            "remaining reward supply increased at height {height}"
        );

        previous = remaining;
    }

    Ok(())
}

#[test]
fn test_063_get_balance_decimal_reports_micro_units_as_remzar() -> TestResult {
    let mut chain = new_test_chain("balance_decimal")?;
    let account = wallet(63);

    chain.tree.set_balance(&account, 125_000_000);

    assert_eq!(
        format!("{:.8}", chain.tree.get_balance_decimal(&account)),
        "1.25000000"
    );
    Ok(())
}

#[test]
fn test_064_get_blocks_returns_clone_not_live_mutable_reference() -> TestResult {
    let mut chain = new_test_chain("blocks_clone")?;

    add_linear_blocks(&mut chain.tree, 2)?;

    let mut local_blocks = chain.tree.get_blocks();
    local_blocks.clear();

    assert_eq!(local_blocks.len(), 0);
    assert_eq!(chain.tree.get_blocks().len(), 2);
    Ok(())
}

#[test]
fn test_065_get_balances_returns_clone_not_live_mutable_reference() -> TestResult {
    let mut chain = new_test_chain("balances_clone")?;
    let account = wallet(65);

    chain.tree.set_balance(&account, 650);

    let mut local_balances = chain.tree.get_balances();
    local_balances.clear();

    assert!(local_balances.is_empty());
    assert_eq!(chain.tree.get_balance(&account), 650);
    Ok(())
}

#[test]
fn test_066_flush_addresses_empty_iterator_is_noop() -> TestResult {
    let mut chain = new_test_chain("flush_empty_addresses")?;
    let account = wallet(66);

    chain.tree.set_balance(&account, 660);
    chain
        .tree
        .flush_addresses(Vec::<String>::new())
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(read_account_balance(chain.manager()?, &account)?, None);
    assert_eq!(chain.tree.get_balance(&account), 660);
    Ok(())
}

#[test]
fn test_067_apply_batch_empty_future_index_is_noop_for_compatibility() -> TestResult {
    let mut chain = new_test_chain("apply_batch_future_empty_compat")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let before_balances = chain.tree.get_balances();
    let before_issued = chain.tree.total_issued_micro();
    let batch = tx_batch(3, Vec::new())?;

    chain.tree.apply_batch(&batch)?;

    assert_eq!(chain.tree.get_balances(), before_balances);
    assert_eq!(chain.tree.total_issued_micro(), before_issued);
    assert_eq!(chain.tree.latest_block_height(), 1);
    Ok(())
}

#[test]
fn test_068_reward_above_max_block_reward_is_rejected_by_constructor() -> TestResult {
    let mut chain = new_test_chain("reward_above_max")?;
    let receiver = wallet(68);

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let amount = GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(1);
    let result = RewardTx::new(receiver, amount, 1);

    assert!(result.is_err());
    assert_eq!(chain.tree.total_issued_micro(), 0);
    assert!(chain.tree.get_balances().is_empty());

    Ok(())
}

#[test]
fn test_069_apply_batch_transfer_above_max_tx_amount_is_rejected() -> TestResult {
    let mut chain = new_test_chain("transfer_above_max")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let tx = manual_tx(69, 70, GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(1))?;
    let batch = tx_batch(1, vec![TxKind::Transfer(tx)])?;

    let result = chain.tree.apply_batch(&batch);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_balance(&wallet(70)), 0);
    Ok(())
}

#[test]
fn test_070_property_batch_many_receivers_preserves_total_issued() -> TestResult {
    let mut chain = new_test_chain("batch_many_receivers")?;
    let sender = wallet(71);

    fund_with_reward(&mut chain.tree, &sender, 1_000)?;
    add_blocks_until_tip(&mut chain.tree, 2)?;

    let mut txs = Vec::with_capacity(10);
    for receiver_seed in 80u64..90u64 {
        txs.push(TxKind::Transfer(transfer_tx(71, receiver_seed, 10)?));
    }

    let batch = tx_batch(2, txs)?;
    chain.tree.apply_batch(&batch)?;

    let balances = chain.tree.get_balances();
    let total = balances
        .values()
        .copied()
        .try_fold(0u64, |acc, value| acc.checked_add(value))
        .ok_or_else(|| boxed_error("balance sum overflow"))?;

    assert_eq!(total, 1_000);
    assert_eq!(chain.tree.total_issued_micro(), 1_000);
    assert_eq!(chain.tree.get_balance(&sender), 900);
    Ok(())
}

#[test]
fn test_071_load_test_commit_and_load_many_balances() -> TestResult {
    let mut chain = new_test_chain("load_many_balances")?;

    for seed in 1u64..=1_000u64 {
        chain
            .tree
            .set_balance(&wallet(seed.saturating_add(2_000)), seed);
    }

    chain.tree.commit()?;

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    assert_eq!(loaded.get_balances().len(), 1_000);
    assert_eq!(loaded.get_balance(&wallet(2_001)), 1);
    assert_eq!(loaded.get_balance(&wallet(3_000)), 1_000);
    Ok(())
}

#[test]
fn test_072_load_test_many_apply_transaction_commits() -> TestResult {
    let mut chain = new_test_chain("load_many_apply_transaction")?;
    let sender = wallet(72);
    let receiver = wallet(73);

    chain.tree.set_balance(&sender, 1_000);

    for _ in 0usize..100usize {
        let tx = transfer_tx(72, 73, 1)?;
        chain.tree.apply_transaction(&tx)?;
    }

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    assert_eq!(loaded.get_balance(&sender), 900);
    assert_eq!(loaded.get_balance(&receiver), 100);
    Ok(())
}

#[test]
fn test_073_flush_balances_for_batch_after_apply_batch_persists_touched_accounts() -> TestResult {
    let mut chain = new_test_chain("flush_after_apply_batch")?;
    let sender = wallet(74);
    let receiver = wallet(75);

    fund_with_reward(&mut chain.tree, &sender, 900)?;
    add_blocks_until_tip(&mut chain.tree, 2)?;

    let tx = transfer_tx(74, 75, 250)?;
    let batch = tx_batch(2, vec![TxKind::Transfer(tx)])?;

    chain.tree.apply_batch(&batch)?;
    chain
        .tree
        .flush_balances_for_batch(&batch)
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(read_account_balance(chain.manager()?, &sender)?, Some(650));
    assert_eq!(
        read_account_balance(chain.manager()?, &receiver)?,
        Some(250)
    );
    Ok(())
}

#[test]
fn test_074_get_block_by_index_missing_returns_error() -> TestResult {
    let chain = new_test_chain("missing_block_by_index")?;

    let result = chain.tree.get_block_by_index(999);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_075_rocksdb_load_state_without_state_returns_empty_tree() -> TestResult {
    let chain = new_test_chain("db_load_state_empty")?;

    let loaded = chain.manager()?.load_state()?;

    assert!(loaded.get_balances().is_empty());
    assert!(loaded.get_blocks().is_empty());
    Ok(())
}

#[test]
fn test_076_rocksdb_store_state_round_trips_compact_tip_and_balances() -> TestResult {
    let mut chain = new_test_chain("db_store_state_compact")?;
    let account = wallet(76);

    chain.tree.set_balance(&account, 760);
    add_linear_blocks(&mut chain.tree, 4)?;
    chain.manager()?.store_state(&chain.tree)?;

    let loaded = chain.manager()?.load_state()?;

    assert_eq!(loaded.get_balance(&account), 760);
    assert!(loaded.get_blocks().is_empty());
    assert_eq!(loaded.latest_block_height(), 3);
    Ok(())
}

#[test]
fn test_077_tip_height_metadata_round_trip() -> TestResult {
    let chain = new_test_chain("tip_height_round_trip")?;

    chain.manager()?.set_latest_block_index(77)?;
    chain.manager()?.set_tip_height(78)?;

    assert_eq!(chain.manager()?.get_latest_block_index()?, 77);
    assert_eq!(chain.manager()?.get_tip_height()?, 78);
    Ok(())
}

#[test]
fn test_078_store_batch_bytes_and_get_tx_batch_bytes_round_trip() -> TestResult {
    let chain = new_test_chain("batch_bytes_round_trip_tx_getter")?;
    let batch = tx_batch(78, Vec::new())?;
    let bytes = batch.serialize_for_storage()?;

    chain.manager()?.store_batch_bytes(78, &bytes)?;

    assert_eq!(
        chain.manager()?.get_tx_batch_bytes_by_index(78)?,
        Some(bytes)
    );
    Ok(())
}

#[test]
fn test_079_store_batch_bytes_and_get_batch_bytes_round_trip() -> TestResult {
    let chain = new_test_chain("batch_bytes_round_trip_canonical_getter")?;
    let batch = tx_batch(79, Vec::new())?;
    let bytes = batch.serialize_for_storage()?;

    chain.manager()?.store_batch_bytes(79, &bytes)?;

    assert_eq!(chain.manager()?.get_batch_bytes_by_index(79)?, Some(bytes));
    Ok(())
}

#[test]
fn test_080_replay_db_reward_and_transfer_then_commit_loaded_state() -> TestResult {
    let mut chain = new_test_chain("replay_reward_transfer_commit")?;
    let sender = wallet(80);
    let receiver = wallet(81);

    store_linear_blocks_41(chain.manager()?, 3)?;

    let reward = RewardTx::new(sender.clone(), 2_000, 1)?;
    let reward_batch = tx_batch(1, vec![TxKind::Reward(reward)])?;
    store_batch_by_index_41(chain.manager()?, &reward_batch)?;

    let tx = transfer_tx(80, 81, 750)?;
    let transfer_batch = tx_batch(2, vec![TxKind::Transfer(tx)])?;
    store_batch_by_index_41(chain.manager()?, &transfer_batch)?;

    chain.tree.reload_from_db_to_height(2)?;
    chain.tree.commit()?;

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    assert_eq!(loaded.get_balance(&sender), 1_250);
    assert_eq!(loaded.get_balance(&receiver), 750);
    assert_eq!(loaded.total_issued_micro(), 2_000);
    assert_eq!(loaded.latest_block_height(), 2);
    Ok(())
}

#[test]
fn test_081_vector_latest_block_height_for_empty_and_small_chains() -> TestResult {
    for count in [0usize, 1, 2, 5, 10] {
        let mut chain = new_test_chain(&format!("height_vector_{count}"))?;

        if count > 0 {
            add_linear_blocks(&mut chain.tree, count)?;
        }

        let expected = if count == 0 {
            0
        } else {
            count.saturating_sub(1)
        };

        assert_eq!(chain.tree.latest_block_height(), expected);
        assert_eq!(chain.tree.get_blocks().len(), count);
    }

    Ok(())
}

#[test]
fn test_082_vector_get_block_by_index_returns_each_added_block() -> TestResult {
    let mut chain = new_test_chain("get_block_vector")?;
    let blocks = add_linear_blocks(&mut chain.tree, 8)?;

    for index in 0usize..blocks.len() {
        let expected = blocks
            .get(index)
            .cloned()
            .ok_or_else(|| boxed_error("missing expected block"))?;

        assert_eq!(chain.tree.get_block_by_index(index)?, expected);
    }

    Ok(())
}

#[test]
fn test_083_adversarial_multi_gap_block_queue_processes_after_parents_arrive() -> TestResult {
    let mut chain = new_test_chain("multi_gap_queue")?;

    let genesis = test_block(0, [0u8; 64])?;
    let block_one = test_block(1, genesis.block_hash)?;
    let block_two = test_block(2, block_one.block_hash)?;
    let block_three = test_block(3, block_two.block_hash)?;

    chain.tree.add_block(genesis.clone())?;
    chain.tree.add_block(block_three.clone())?;

    assert_eq!(chain.tree.latest_block_height(), 0);

    chain.tree.add_block(block_one.clone())?;
    assert_eq!(chain.tree.latest_block_height(), 1);

    chain.tree.add_block(block_two.clone())?;

    assert_eq!(chain.tree.latest_block_height(), 3);
    assert_eq!(chain.tree.get_block_by_index(0)?, genesis);
    assert_eq!(chain.tree.get_block_by_index(1)?, block_one);
    assert_eq!(chain.tree.get_block_by_index(2)?, block_two);
    assert_eq!(chain.tree.get_block_by_index(3)?, block_three);
    Ok(())
}

#[test]
fn test_084_adversarial_duplicate_queued_block_does_not_duplicate_chain() -> TestResult {
    let mut chain = new_test_chain("duplicate_queued_block")?;

    let genesis = test_block(0, [0u8; 64])?;
    let block_one = test_block(1, genesis.block_hash)?;
    let block_two = test_block(2, block_one.block_hash)?;

    chain.tree.add_block(genesis.clone())?;
    chain.tree.add_block(block_two.clone())?;
    chain.tree.add_block(block_two.clone())?;
    chain.tree.add_block(block_one.clone())?;

    assert_eq!(chain.tree.latest_block_height(), 2);
    assert_eq!(chain.tree.get_blocks().len(), 3);
    assert_eq!(chain.tree.get_block_by_index(2)?, block_two);
    Ok(())
}

#[test]
fn test_085_apply_empty_batch_at_matching_height_is_noop_success() -> TestResult {
    let mut chain = new_test_chain("empty_batch_matching_height")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let before_balances = chain.tree.get_balances();
    let before_issued = chain.tree.total_issued_micro();
    let batch = tx_batch(1, Vec::new())?;

    chain.tree.apply_batch(&batch)?;

    assert_eq!(chain.tree.get_balances(), before_balances);
    assert_eq!(chain.tree.total_issued_micro(), before_issued);
    assert_eq!(chain.tree.latest_block_height(), 1);
    Ok(())
}

#[test]
fn test_086_apply_multiple_empty_batches_is_idempotent_for_balances() -> TestResult {
    let mut chain = new_test_chain("empty_batch_repeat")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let batch = tx_batch(1, Vec::new())?;

    chain.tree.apply_batch(&batch)?;
    chain.tree.apply_batch(&batch)?;

    assert!(chain.tree.get_balances().is_empty());
    assert_eq!(chain.tree.total_issued_micro(), 0);
    assert_eq!(chain.tree.rewards_issued_micro(), 0);
    Ok(())
}

#[test]
fn test_087_apply_batch_multiple_nft_mints_do_not_change_supply_or_balances() -> TestResult {
    let mut chain = new_test_chain("multiple_nft_mints")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let mint_one = NftMintTx::from_content_bytes(
        fixed_hash(87),
        "nft one".to_owned(),
        "first nft".to_owned(),
        b"first deterministic nft payload",
    );
    let mint_two = NftMintTx::from_content_bytes(
        fixed_hash(88),
        "nft two".to_owned(),
        "second nft".to_owned(),
        b"second deterministic nft payload",
    );

    let batch = tx_batch(
        1,
        vec![TxKind::NftMint(mint_one), TxKind::NftMint(mint_two)],
    )?;

    chain.tree.apply_batch(&batch)?;

    assert!(chain.tree.get_balances().is_empty());
    assert_eq!(chain.tree.total_issued_micro(), 0);
    assert_eq!(chain.tree.rewards_issued_micro(), 0);
    Ok(())
}

#[test]
fn test_088_vector_reward_at_max_block_reward_is_accepted() -> TestResult {
    let mut chain = new_test_chain("max_block_reward")?;
    let receiver = wallet(88);

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let reward = RewardTx::new(receiver.clone(), GlobalConfiguration::MAX_BLOCK_REWARD, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;

    chain.tree.apply_batch(&batch)?;

    assert_eq!(
        chain.tree.get_balance(&receiver),
        GlobalConfiguration::MAX_BLOCK_REWARD
    );
    assert_eq!(
        chain.tree.total_issued_micro(),
        GlobalConfiguration::MAX_BLOCK_REWARD
    );
    Ok(())
}

#[test]
fn test_089_vector_reward_followed_by_empty_batch_keeps_supply_constant() -> TestResult {
    let mut chain = new_test_chain("reward_then_empty")?;
    let receiver = wallet(89);

    fund_with_reward(&mut chain.tree, &receiver, 890)?;
    add_blocks_until_tip(&mut chain.tree, 2)?;

    let before_supply = chain.tree.total_issued_micro();
    let before_reward_supply = chain.tree.rewards_issued_micro();
    let empty = tx_batch(2, Vec::new())?;

    chain.tree.apply_batch(&empty)?;

    assert_eq!(chain.tree.total_issued_micro(), before_supply);
    assert_eq!(chain.tree.rewards_issued_micro(), before_reward_supply);
    assert_eq!(chain.tree.get_balance(&receiver), 890);
    Ok(())
}

#[test]
fn test_090_vector_apply_transaction_at_exact_max_tx_amount_succeeds() -> TestResult {
    let mut chain = new_test_chain("exact_max_tx_amount")?;
    let sender = wallet(90);
    let receiver = wallet(91);

    chain
        .tree
        .set_balance(&sender, GlobalConfiguration::MAX_TX_AMOUNT);

    let tx = manual_tx(90, 91, GlobalConfiguration::MAX_TX_AMOUNT)?;
    chain.tree.apply_transaction(&tx)?;

    assert_eq!(chain.tree.get_balance(&sender), 0);
    assert_eq!(
        chain.tree.get_balance(&receiver),
        GlobalConfiguration::MAX_TX_AMOUNT
    );
    Ok(())
}

#[test]
fn test_091_vector_apply_transaction_u64_max_amount_is_rejected() -> TestResult {
    let mut chain = new_test_chain("u64_max_amount_tx")?;
    let sender = wallet(92);
    let receiver = wallet(93);

    chain
        .tree
        .set_balance(&sender, GlobalConfiguration::MAX_SUPPLY);

    let tx = manual_tx(92, 93, u64::MAX)?;
    let result = chain.tree.apply_transaction(&tx);

    assert!(result.is_err());
    assert_eq!(
        chain.tree.get_balance(&sender),
        GlobalConfiguration::MAX_SUPPLY
    );
    assert_eq!(chain.tree.get_balance(&receiver), 0);
    Ok(())
}

#[test]
fn test_092_increment_balance_exact_max_supply_on_empty_account_succeeds() -> TestResult {
    let mut chain = new_test_chain("increment_exact_max_supply")?;
    let account = wallet(94);

    chain
        .tree
        .increment_balance(&account, GlobalConfiguration::MAX_SUPPLY)?;

    assert_eq!(
        chain.tree.get_balance(&account),
        GlobalConfiguration::MAX_SUPPLY
    );
    Ok(())
}

#[test]
fn test_093_update_balance_exact_max_supply_on_empty_account_succeeds() -> TestResult {
    let mut chain = new_test_chain("update_exact_max_supply")?;
    let account = wallet(95);

    chain
        .tree
        .update_balance(&account, GlobalConfiguration::MAX_SUPPLY)?;

    assert_eq!(
        chain.tree.get_balance(&account),
        GlobalConfiguration::MAX_SUPPLY
    );
    Ok(())
}

#[test]
fn test_094_increment_zero_creates_zero_balance_account() -> TestResult {
    let mut chain = new_test_chain("increment_zero")?;
    let account = wallet(96);

    chain.tree.increment_balance(&account, 0)?;

    assert_eq!(chain.tree.get_balance(&account), 0);
    assert!(chain.tree.get_balances().contains_key(&account));
    Ok(())
}

#[test]
fn test_095_decrement_zero_on_existing_account_is_noop() -> TestResult {
    let mut chain = new_test_chain("decrement_zero")?;
    let account = wallet(97);

    chain.tree.set_balance(&account, 970);
    chain.tree.decrement_balance(&account, 0)?;

    assert_eq!(chain.tree.get_balance(&account), 970);
    Ok(())
}

#[test]
fn test_096_empty_account_name_can_be_set_and_flushed_as_public_api_behavior() -> TestResult {
    let mut chain = new_test_chain("empty_account_name")?;

    chain.tree.set_balance("", 960);
    chain
        .tree
        .flush_addresses(vec![String::new()])
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(chain.tree.get_balance(""), 960);
    assert_eq!(read_account_balance(chain.manager()?, "")?, Some(960));
    Ok(())
}

#[test]
fn test_097_commit_then_load_backfills_total_issued_from_legacy_like_balance_state() -> TestResult {
    let mut chain = new_test_chain("load_backfill_total_issued")?;
    let first = wallet(98);
    let second = wallet(99);

    chain.tree.set_balance(&first, 100);
    chain.tree.set_balance(&second, 200);
    chain.tree.commit()?;

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    assert_eq!(loaded.get_balance(&first), 100);
    assert_eq!(loaded.get_balance(&second), 200);
    assert_eq!(loaded.total_issued_micro(), 300);
    assert_eq!(loaded.rewards_issued_micro(), 300);
    Ok(())
}

#[test]
fn test_098_deserialize_state_backfills_total_issued_from_serialized_balances() -> TestResult {
    let mut chain = new_test_chain("deserialize_backfill")?;
    let account = wallet(100);

    chain.tree.set_balance(&account, 1_234);

    let bytes = chain.tree.serialize_state()?;
    let restored = AccountModelTree::deserialize_state(&bytes, chain.manager()?.clone())?;

    assert_eq!(restored.get_balance(&account), 1_234);
    assert_eq!(restored.total_issued_micro(), 1_234);
    assert_eq!(restored.rewards_issued_micro(), 1_234);
    Ok(())
}

#[test]
fn test_099_deserialize_state_rejects_corrupt_payload_vectors() -> TestResult {
    let chain = new_test_chain("corrupt_state_vectors")?;
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8],
        vec![1u8, 2, 3, 4],
        vec![255u8; 32],
        b"not postcard inner tree".to_vec(),
    ];

    for data in cases {
        let result = AccountModelTree::deserialize_state(&data, chain.manager()?.clone());
        assert!(result.is_err());
    }

    Ok(())
}

#[test]
fn test_100_serialize_state_rejects_balance_sum_overflow() -> TestResult {
    let mut chain = new_test_chain("backfill_sum_overflow")?;

    chain.tree.set_balance(&wallet(101), u64::MAX);
    chain.tree.set_balance(&wallet(102), 1);

    let result = chain.tree.serialize_state();

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_101_commit_rejects_balance_sum_above_max_supply() -> TestResult {
    let mut chain = new_test_chain("remaining_supply_saturates")?;
    let account = wallet(103);

    chain
        .tree
        .set_balance(&account, GlobalConfiguration::MAX_SUPPLY.saturating_add(1));

    let result = chain.tree.commit();

    assert!(result.is_err());
    assert_eq!(
        chain.tree.get_balance(&account),
        GlobalConfiguration::MAX_SUPPLY.saturating_add(1)
    );
    Ok(())
}

#[test]
fn test_102_apply_block_rejects_tampered_block_hash() -> TestResult {
    let mut chain = new_test_chain("apply_tampered_hash")?;
    let key = "tx_batch_0000000000";
    let valid_block = test_block_with_key(0, [0u8; 64], Some(key.to_owned()))?;
    let tampered = tamper_block_hash_81(&valid_block);
    let batch = tx_batch(0, Vec::new())?;

    store_batch_by_index_41(chain.manager()?, &batch)?;

    let result = chain.tree.apply_block(&tampered);

    assert_string_error_contains(result, "Block validation failed")?;
    assert!(chain.tree.get_blocks().is_empty());
    Ok(())
}

#[test]
fn test_103_apply_block_after_genesis_rejects_tampered_old_height_without_mutation() -> TestResult {
    let mut chain = new_test_chain("tampered_old_height")?;
    let genesis = apply_empty_genesis_block_41(&mut chain)?;
    let tampered_old = tamper_block_hash_81(&genesis);

    let result = chain.tree.apply_block(&tampered_old);

    assert!(result.is_err());
    assert_eq!(chain.tree.get_blocks().len(), 1);
    assert_eq!(chain.tree.get_block_by_index(0)?, genesis);
    Ok(())
}

#[test]
fn test_104_apply_block_rejects_child_with_missing_miner_via_block_validation() -> TestResult {
    let mut chain = new_test_chain("child_missing_miner")?;
    let genesis = apply_empty_genesis_block_41(&mut chain)?;
    let key = "tx_batch_0000000001";
    let metadata = test_metadata(1, genesis.block_hash);
    let mut child = Block {
        metadata,
        batch_key: Some(key.to_owned()),
        miner: String::new(),
        block_hash: [1u8; 64],
        reward: 0,
    };

    child.block_hash = fixed_hash(104);

    let result = chain.tree.apply_block(&child);

    assert_string_error_contains(result, "Block validation failed")?;
    assert_eq!(chain.tree.get_blocks().len(), 1);
    Ok(())
}

#[test]
fn test_105_apply_batch_rejects_too_many_transactions_vector() -> TestResult {
    let mut chain = new_test_chain("too_many_txs")?;

    add_blocks_until_tip(&mut chain.tree, 1)?;

    let count = usize::try_from(GlobalConfiguration::MAX_TXS_PER_BLOCK)
        .map_err(|_| boxed_error("MAX_TXS_PER_BLOCK does not fit usize"))?
        .saturating_add(1);

    let mut txs = Vec::with_capacity(count);
    for seed in 0usize..count {
        let receiver_seed = u64::try_from(seed.saturating_add(1_000))
            .map_err(|_| boxed_error("receiver seed does not fit u64"))?;
        txs.push(TxKind::NftMint(NftMintTx::from_content_bytes(
            fixed_hash(105),
            format!("nft {seed}"),
            "oversized batch structural test".to_owned(),
            wallet(receiver_seed).as_bytes(),
        )));
    }

    let batch = tx_batch(1, txs)?;
    let result = chain.tree.apply_batch(&batch);

    assert!(result.is_err());
    assert!(chain.tree.get_balances().is_empty());
    Ok(())
}

#[test]
fn test_106_rocksdb_list_column_families_contains_core_state_and_account_columns() -> TestResult {
    let chain = new_test_chain("list_column_families")?;
    let cfs = chain.manager()?.list_column_families()?;

    assert!(
        cfs.iter()
            .any(|name| name == GlobalConfiguration::STATE_COLUMN_NAME)
    );
    assert!(
        cfs.iter()
            .any(|name| name == GlobalConfiguration::ACCOUNT_COLUMN_NAME)
    );
    assert!(
        cfs.iter()
            .any(|name| name == GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
    );
    Ok(())
}

#[test]
fn test_107_rocksdb_latest_block_index_defaults_to_zero() -> TestResult {
    let chain = new_test_chain("latest_index_default")?;

    assert_eq!(chain.manager()?.get_latest_block_index()?, 0);
    Ok(())
}

#[test]
fn test_108_rocksdb_tip_height_falls_back_to_latest_block_index_metadata() -> TestResult {
    let chain = new_test_chain("tip_fallback_latest")?;
    let height = 108u64;

    chain
        .manager()?
        .store_metadata("latest_block_index", &height.to_be_bytes())?;

    assert_eq!(chain.manager()?.get_tip_height()?, height);
    Ok(())
}

#[test]
fn test_109_rocksdb_wallet_balance_missing_returns_none() -> TestResult {
    let chain = new_test_chain("wallet_balance_missing")?;

    assert_eq!(chain.manager()?.get_wallet_balance(&wallet(109))?, None);
    Ok(())
}

#[test]
fn test_110_rocksdb_register_get_remove_peer_round_trip() -> TestResult {
    let chain = new_test_chain("peer_round_trip")?;
    let peer_id = "peer_110";
    let peer_data = b"peer metadata";

    chain.manager()?.register_peer(peer_id, peer_data)?;

    assert_eq!(
        chain.manager()?.get_peer_info(peer_id)?,
        Some(peer_data.to_vec())
    );

    chain.manager()?.remove_peer(peer_id)?;

    assert_eq!(chain.manager()?.get_peer_info(peer_id)?, None);
    Ok(())
}

#[test]
fn test_111_rocksdb_generic_write_read_delete_round_trip() -> TestResult {
    let chain = new_test_chain("generic_write_read_delete")?;
    let key = b"generic-key-111";
    let value = b"generic-value-111";

    chain
        .manager()?
        .write(GlobalConfiguration::NETWORK_COLUMN_NAME, key, value)?;

    assert_eq!(
        chain
            .manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, key)?,
        Some(value.to_vec())
    );

    chain
        .manager()?
        .delete(GlobalConfiguration::NETWORK_COLUMN_NAME, key)?;

    assert_eq!(
        chain
            .manager()?
            .read(GlobalConfiguration::NETWORK_COLUMN_NAME, key)?,
        None
    );
    Ok(())
}

#[test]
fn test_112_rocksdb_iterate_column_finds_written_network_entry() -> TestResult {
    let chain = new_test_chain("iterate_column_network")?;
    let key = b"iterate-key-112";
    let value = b"iterate-value-112";

    chain
        .manager()?
        .write(GlobalConfiguration::NETWORK_COLUMN_NAME, key, value)?;

    let rows: ColumnRows = chain
        .manager()?
        .iterate_column(GlobalConfiguration::NETWORK_COLUMN_NAME)?
        .collect::<ColumnRowsResult>()?;

    assert!(rows.iter().any(|(row_key, row_value)| {
        row_key.as_slice() == key && row_value.as_slice() == value
    }));

    Ok(())
}

#[test]
fn test_113_rocksdb_store_latest_block_and_read_latest_block() -> TestResult {
    let chain = new_test_chain("store_latest_block")?;
    let block = test_block(0, [0u8; 64])?;
    let bytes = block.serialize_for_storage()?;

    chain.manager()?.store_latest_block(&bytes, 0)?;

    assert_eq!(chain.manager()?.get_latest_block()?, Some(block.clone()));
    assert_eq!(chain.manager()?.get_latest_block_hash()?, block.block_hash);
    Ok(())
}

#[test]
fn test_114_rocksdb_block_hash_index_round_trip() -> TestResult {
    let chain = new_test_chain("block_hash_index")?;
    let block = test_block(0, [0u8; 64])?;
    let bytes = block.serialize_for_storage()?;

    chain
        .manager()?
        .index_block_by_hash(&block.block_hash, &bytes)?;

    assert!(chain.manager()?.has_block_by_hash(&block.block_hash));
    assert_eq!(
        chain.manager()?.get_block_by_hash(&block.block_hash),
        Some(block)
    );
    Ok(())
}

#[test]
fn test_115_rocksdb_remove_block_by_index_removes_block_batch_and_hash_mapping() -> TestResult {
    let chain = new_test_chain("remove_block_by_index")?;
    let block = test_block(0, [0u8; 64])?;
    let block_bytes = block.serialize_for_storage()?;
    let batch = tx_batch(0, Vec::new())?;

    chain.manager()?.store_latest_block(&block_bytes, 0)?;
    chain
        .manager()?
        .index_block_by_hash(&block.block_hash, &block_bytes)?;
    store_batch_by_index_41(chain.manager()?, &batch)?;

    chain.manager()?.remove_block_by_index(0)?;

    assert_eq!(chain.manager()?.get_block_by_index(0)?, None);
    assert_eq!(chain.manager()?.get_batch_bytes_by_index(0)?, None);
    assert!(!chain.manager()?.has_block_by_hash(&block.block_hash));
    Ok(())
}

#[test]
fn test_116_blockstore_get_blocks_between_returns_child_path() -> TestResult {
    let chain = new_test_chain("blockstore_between")?;
    let blocks = store_linear_blocks_41(chain.manager()?, 4)?;

    let ancestor = blocks
        .first()
        .map(|block| block.block_hash)
        .ok_or_else(|| boxed_error("missing ancestor block"))?;
    let tip = blocks
        .get(3)
        .map(|block| block.block_hash)
        .ok_or_else(|| boxed_error("missing tip block"))?;

    let path =
        <RockDBManager as remzar::storage::rocksdb_005_manager::BlockStore>::get_blocks_between(
            chain.manager()?,
            ancestor,
            tip,
        )
        .map_err(|err| boxed_error(&err))?;

    assert_eq!(path.len(), 3);
    assert_eq!(
        path.first()
            .map(|block| block.metadata.index)
            .ok_or_else(|| boxed_error("missing first path block"))?,
        1
    );
    assert_eq!(
        path.last()
            .map(|block| block.metadata.index)
            .ok_or_else(|| boxed_error("missing last path block"))?,
        3
    );
    Ok(())
}

#[test]
fn test_117_blockstore_get_blocks_between_rejects_equal_ancestor_and_tip() -> TestResult {
    let chain = new_test_chain("blockstore_equal_hashes")?;
    let blocks = store_linear_blocks_41(chain.manager()?, 2)?;

    let hash = blocks
        .first()
        .map(|block| block.block_hash)
        .ok_or_else(|| boxed_error("missing block"))?;

    let result =
        <RockDBManager as remzar::storage::rocksdb_005_manager::BlockStore>::get_blocks_between(
            chain.manager()?,
            hash,
            hash,
        );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_118_blockstore_find_common_ancestor_returns_stored_hash() -> TestResult {
    let chain = new_test_chain("find_common_ancestor_found")?;
    let blocks = store_linear_blocks_41(chain.manager()?, 3)?;

    let hash = blocks
        .get(2)
        .map(|block| block.block_hash)
        .ok_or_else(|| boxed_error("missing stored block"))?;

    let found =
        <RockDBManager as remzar::storage::rocksdb_005_manager::BlockStore>::find_common_ancestor(
            chain.manager()?,
            hash,
        );

    assert_eq!(found, Some(hash));
    Ok(())
}

#[test]
fn test_119_blockstore_find_common_ancestor_returns_none_for_unknown_hash() -> TestResult {
    let chain = new_test_chain("find_common_ancestor_unknown")?;

    store_linear_blocks_41(chain.manager()?, 2)?;

    let found =
        <RockDBManager as remzar::storage::rocksdb_005_manager::BlockStore>::find_common_ancestor(
            chain.manager()?,
            fixed_hash(219),
        );

    assert_eq!(found, None);
    Ok(())
}

#[test]
fn test_120_load_test_large_reward_transfer_replay_and_balance_sum_property() -> TestResult {
    let mut chain = new_test_chain("large_replay_property")?;
    let sender = wallet(120);

    store_linear_blocks_41(chain.manager()?, 12)?;

    let reward = RewardTx::new(sender.clone(), 10_000, 1)?;
    let reward_batch = tx_batch(1, vec![TxKind::Reward(reward)])?;
    store_batch_by_index_41(chain.manager()?, &reward_batch)?;

    for height in 2u64..=11u64 {
        let receiver_seed = height.saturating_add(1_000);
        let tx = transfer_tx(120, receiver_seed, 100)?;
        let batch = tx_batch(height, vec![TxKind::Transfer(tx)])?;
        store_batch_by_index_41(chain.manager()?, &batch)?;
    }

    chain.tree.reload_from_db_to_height(11)?;

    assert_eq!(chain.tree.total_issued_micro(), 10_000);
    assert_eq!(chain.tree.get_balance(&sender), 9_000);
    assert_eq!(sum_balances_81(&chain.tree)?, 10_000);

    for height in 2u64..=11u64 {
        let receiver = wallet(height.saturating_add(1_000));
        assert_eq!(chain.tree.get_balance(&receiver), 100);
    }

    Ok(())
}

#[test]
fn test_121_compact_state_commit_does_not_persist_recent_block_cache() -> TestResult {
    let mut chain = new_test_chain("compact_state_no_blocks")?;
    let account = wallet(121);

    chain.tree.set_balance(&account, 1_210);
    add_linear_blocks(&mut chain.tree, 5)?;
    assert_eq!(chain.tree.get_blocks().len(), 5);

    chain.tree.commit()?;

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    assert_eq!(loaded.get_balance(&account), 1_210);
    assert!(loaded.get_blocks().is_empty());
    assert_eq!(loaded.latest_block_height(), 4);
    Ok(())
}

#[test]
fn test_122_get_block_by_index_falls_back_to_rocksdb_after_compact_load() -> TestResult {
    let mut chain = new_test_chain("compact_load_block_fallback")?;
    let blocks = add_linear_blocks(&mut chain.tree, 2)?;

    for block in &blocks {
        store_replay_block_41(chain.manager()?, block)?;
    }

    chain.tree.commit()?;

    let loaded = AccountModelTree::load_state(chain.manager()?.clone())?;

    assert!(loaded.get_blocks().is_empty());
    assert_eq!(loaded.latest_block_height(), 1);
    assert_eq!(loaded.get_block_by_index(0)?, blocks[0]);
    assert_eq!(loaded.get_block_by_index(1)?, blocks[1]);
    Ok(())
}

#[test]
fn test_123_recent_block_cache_is_bounded_after_long_in_memory_chain() -> TestResult {
    let mut chain = new_test_chain("recent_cache_bounded")?;

    add_linear_blocks(&mut chain.tree, 2_055)?;

    let recent = chain.tree.get_blocks();

    assert!(recent.len() <= 2_048);
    assert_eq!(chain.tree.latest_block_height(), 2_054);
    assert_eq!(
        recent
            .last()
            .map(|block| block.metadata.index)
            .ok_or_else(|| boxed_error("missing recent tip block"))?,
        2_054
    );
    assert!(
        recent
            .first()
            .map(|block| block.metadata.index)
            .unwrap_or_default()
            > 0
    );
    Ok(())
}

#[test]
fn test_124_accountmodel_manager_reuses_blockchain_handle_for_state_round_trip() -> TestResult {
    let mut chain = new_test_chain("accountmodel_reuse_handle")?;
    let account = wallet(124);

    chain.tree.set_balance(&account, 1_240);

    let account_manager = RockDBManager::from_blockchain_for_accountmodel(chain.manager()?)?;
    account_manager.store_state(&chain.tree)?;

    let loaded = account_manager.load_state()?;

    assert_eq!(loaded.get_balance(&account), 1_240);
    assert!(loaded.get_blocks().is_empty());
    Ok(())
}

#[test]
fn test_125_accountmodel_mode_rejects_generic_network_write() -> TestResult {
    let chain = new_test_chain("accountmodel_reject_network_write")?;
    let account_manager = RockDBManager::from_blockchain_for_accountmodel(chain.manager()?)?;

    let result = account_manager.write(
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        b"peer-in-accountmodel-mode",
        b"must not write network data from AccountModel mode",
    );

    assert!(result.is_err());
    Ok(())
}
