#![allow(clippy::too_many_lines)]

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::blockchain::transaction_006_tx_account_tree_guards::{
    AccountGuard, ApplyContext, ApplyMode, BatchApplyOutcome, GuardConfig, StateFingerprint,
};
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::tokens::nft_001::{NftMintTx, NftTransferTx};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), Box<dyn Error>>;

const UNIX_2000: u64 = 946_684_800;

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

        if let Err(_cleanup_error) = std::fs::remove_dir_all(&self.root) {
            // Best-effort cleanup only.
        }
    }
}

fn boxed_error(message: &str) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message.to_owned()))
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_tx_account_tree_guards_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> Result<String, Box<dyn Error>> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn wallet_array(address: &str) -> Result<[u8; REMZAR_WALLET_LEN], Box<dyn Error>> {
    if address.as_bytes().len() != REMZAR_WALLET_LEN {
        return Err(boxed_error("wallet address has invalid byte length"));
    }

    let mut out = [0_u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(address.as_bytes());
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

fn hash_from_seed(seed: u64) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed.to_le_bytes());

    let mut out = [0_u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out);
    out
}

fn nft_hash(seed: u64) -> [u8; 64] {
    hash_from_seed(seed)
}

fn test_metadata(index: u64, previous_hash: Hash) -> BlockMetadata {
    BlockMetadata::new(
        index,
        UNIX_2000.saturating_add(index),
        previous_hash,
        hash_from_seed(index.saturating_add(100)),
        [1_u8; GlobalConfiguration::GUARDIAN_SIG_LEN],
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    )
}

fn test_block(index: u64, previous_hash: Hash) -> Result<Block, ErrorDetection> {
    let miner = if index == 0 {
        String::new()
    } else {
        wallet(index.saturating_add(10))
    };

    let batch_key = if index == 0 {
        None
    } else {
        Some(format!("tx_batch_{index:010}"))
    };

    Block::new(test_metadata(index, previous_hash), batch_key, miner, index)
}

fn test_chain(count: usize) -> Result<Vec<Block>, ErrorDetection> {
    let mut blocks = Vec::with_capacity(count);
    let mut previous_hash = [0_u8; 64];

    for idx in 0..count {
        let index = u64::try_from(idx).map_err(|_| ErrorDetection::ValidationError {
            message: "test index does not fit into u64".to_owned(),
            tx_id: None,
        })?;

        let block = test_block(index, previous_hash)?;
        previous_hash = block.block_hash;
        blocks.push(block);
    }

    Ok(blocks)
}

fn store_block(manager: &RockDBManager, block: &Block) -> Result<(), ErrorDetection> {
    let bytes = block.serialize_for_storage()?;
    manager.store_latest_block(&bytes, block.metadata.index)?;
    manager.index_block_by_hash(&block.block_hash, &bytes)
}

fn store_chain(manager: &RockDBManager, count: usize) -> Result<Vec<Block>, ErrorDetection> {
    let blocks = test_chain(count)?;
    for block in &blocks {
        store_block(manager, block)?;
    }
    Ok(blocks)
}

fn transfer_kind(
    sender_seed: u64,
    receiver_seed: u64,
    amount: u64,
) -> Result<TxKind, Box<dyn Error>> {
    Ok(TxKind::Transfer(Transaction {
        sender: wallet_array(&wallet(sender_seed))?,
        receiver: wallet_array(&wallet(receiver_seed))?,
        amount,
        timestamp: UNIX_2000,
    }))
}

fn reward_kind(
    receiver_seed: u64,
    amount: u64,
    block_height: u64,
) -> Result<TxKind, Box<dyn Error>> {
    Ok(TxKind::Reward(RewardTx {
        receiver: wallet_array(&wallet(receiver_seed))?,
        amount,
        block_height,
        timestamp: UNIX_2000,
    }))
}

fn register_kind(seed: u64) -> Result<TxKind, Box<dyn Error>> {
    Ok(TxKind::RegisterNode(RegisterNodeTx {
        wallet_address: wallet_array(&wallet(seed))?,
        timestamp: UNIX_2000,
    }))
}

fn nft_mint_kind(seed: u64) -> TxKind {
    TxKind::NftMint(NftMintTx {
        nft_id: nft_hash(seed),
        content_hash: nft_hash(seed.saturating_add(10_000)),
        title: format!("NFT #{seed}"),
        description: format!("Description #{seed}"),
    })
}

fn nft_transfer_kind(seed: u64) -> TxKind {
    TxKind::NftTransfer(NftTransferTx {
        nft_id: nft_hash(seed.saturating_add(20_000)),
        new_owner_wallet: wallet(seed.saturating_add(30_000)),
    })
}

fn batch(index: u64, txs: Vec<TxKind>) -> Result<TransactionBatch, ErrorDetection> {
    TransactionBatch::new(index, UNIX_2000, txs)
}

fn store_batch(
    manager: &RockDBManager,
    index: u64,
    txs: Vec<TxKind>,
) -> Result<TransactionBatch, ErrorDetection> {
    let tx_batch = batch(index, txs)?;
    let bytes = tx_batch.serialize_for_storage()?;
    manager.store_batch_bytes(index, &bytes)?;
    Ok(tx_batch)
}

fn db_with_chain(label: &str, count: usize) -> Result<TestDb, Box<dyn Error>> {
    let db = new_blockchain_db(label)?;
    let blocks = store_chain(db.manager()?, count)?;

    if let Some(last) = blocks.last() {
        db.manager()?.set_latest_block_index(last.metadata.index)?;
    }

    Ok(db)
}

fn db_with_batches(
    label: &str,
    height: u64,
    batches: Vec<(u64, Vec<TxKind>)>,
) -> Result<TestDb, Box<dyn Error>> {
    let db = db_with_chain(
        label,
        usize::try_from(height.saturating_add(1))
            .map_err(|error| boxed_error(&format!("height conversion failed: {error}")))?,
    )?;

    for (index, txs) in batches {
        store_batch(db.manager()?, index, txs)?;
    }

    db.manager()?.set_latest_block_index(height)?;
    Ok(db)
}

fn load_tree(db: &TestDb) -> Result<AccountModelTree, Box<dyn Error>> {
    Ok(AccountModelTree::with_manager(db.manager()?.clone()))
}

fn assert_error_contains<T>(
    result: Result<T, ErrorDetection>,
    needle: &str,
    context: &str,
) -> TestResult {
    match result {
        Err(error) => {
            let rendered = format!("{error:?}");
            assert!(
                rendered.contains(needle),
                "{context}: expected {needle:?}, got {rendered:?}"
            );
            Ok(())
        }
        Ok(_) => Err(boxed_error(context)),
    }
}

#[test]
fn account_guard_001_new_constructs() -> TestResult {
    let guard = AccountGuard::new();
    let rendered = format!("{guard:?}");

    assert!(rendered.contains("AccountGuard"));
    Ok(())
}

#[test]
fn account_guard_002_with_config_false_constructs() -> TestResult {
    let guard = AccountGuard::with_config(GuardConfig {
        enforce_no_burn_supply_equality: false,
    });
    let rendered = format!("{guard:?}");

    assert!(rendered.contains("false"));
    Ok(())
}

#[test]
fn account_guard_003_clone_debug_is_stable() -> TestResult {
    let guard = AccountGuard::new();
    let cloned = guard.clone();

    assert_eq!(format!("{guard:?}"), format!("{cloned:?}"));
    Ok(())
}

#[test]
fn account_guard_004_new_and_custom_debug_differ() -> TestResult {
    let first = AccountGuard::new();
    let second = AccountGuard::with_config(GuardConfig {
        enforce_no_burn_supply_equality: false,
    });

    assert_ne!(format!("{first:?}"), format!("{second:?}"));
    Ok(())
}

#[test]
fn account_guard_005_guard_config_default_enforces_supply_equality() -> TestResult {
    let config = GuardConfig::default();

    assert!(config.enforce_no_burn_supply_equality);
    Ok(())
}

#[test]
fn account_guard_006_guard_config_false_field_is_stored() -> TestResult {
    let config = GuardConfig {
        enforce_no_burn_supply_equality: false,
    };

    assert!(!config.enforce_no_burn_supply_equality);
    Ok(())
}

#[test]
fn account_guard_007_apply_modes_are_distinct() -> TestResult {
    assert_ne!(ApplyMode::Live, ApplyMode::Replay);
    Ok(())
}

#[test]
fn account_guard_008_apply_mode_copy_clone_round_trip() -> TestResult {
    let live = ApplyMode::Live;
    let copied = live;
    let cloned = live.clone();

    assert_eq!(copied, live);
    assert_eq!(cloned, live);
    Ok(())
}

#[test]
fn account_guard_009_apply_mode_debug_labels() -> TestResult {
    assert_eq!(format!("{:?}", ApplyMode::Live), "Live");
    assert_eq!(format!("{:?}", ApplyMode::Replay), "Replay");
    Ok(())
}

#[test]
fn account_guard_010_apply_context_zero_fields() -> TestResult {
    let ctx = ApplyContext {
        mode: ApplyMode::Live,
        block_height: 0,
        block_hash: [0_u8; 64],
        previous_hash: [0_u8; 64],
        allow_duplicate_reward_in_batch: false,
    };

    assert_eq!(ctx.mode, ApplyMode::Live);
    assert_eq!(ctx.block_height, 0);
    assert_eq!(ctx.block_hash, [0_u8; 64]);
    assert_eq!(ctx.previous_hash, [0_u8; 64]);
    assert!(!ctx.allow_duplicate_reward_in_batch);
    Ok(())
}

#[test]
fn account_guard_011_apply_context_nonzero_fields() -> TestResult {
    let ctx = ApplyContext {
        mode: ApplyMode::Replay,
        block_height: 7,
        block_hash: hash_from_seed(1),
        previous_hash: hash_from_seed(2),
        allow_duplicate_reward_in_batch: true,
    };

    assert_eq!(ctx.mode, ApplyMode::Replay);
    assert_eq!(ctx.block_height, 7);
    assert_eq!(ctx.block_hash, hash_from_seed(1));
    assert_eq!(ctx.previous_hash, hash_from_seed(2));
    assert!(ctx.allow_duplicate_reward_in_batch);
    Ok(())
}

#[test]
fn account_guard_012_apply_context_clone_preserves_fields() -> TestResult {
    let ctx = ApplyContext {
        mode: ApplyMode::Replay,
        block_height: 9,
        block_hash: hash_from_seed(3),
        previous_hash: hash_from_seed(4),
        allow_duplicate_reward_in_batch: true,
    };
    let cloned = ctx.clone();

    assert_eq!(cloned.mode, ctx.mode);
    assert_eq!(cloned.block_height, ctx.block_height);
    assert_eq!(cloned.block_hash, ctx.block_hash);
    assert_eq!(cloned.previous_hash, ctx.previous_hash);
    assert_eq!(
        cloned.allow_duplicate_reward_in_batch,
        ctx.allow_duplicate_reward_in_batch
    );
    Ok(())
}

#[test]
fn account_guard_013_batch_apply_outcome_empty_constructs() -> TestResult {
    let outcome = BatchApplyOutcome {
        touched_accounts: BTreeSet::new(),
        total_supply_micro: 0,
        fingerprint_hex: String::new(),
    };

    assert!(outcome.touched_accounts.is_empty());
    assert_eq!(outcome.total_supply_micro, 0);
    assert!(outcome.fingerprint_hex.is_empty());
    Ok(())
}

#[test]
fn account_guard_014_batch_apply_outcome_touched_accounts_sorted() -> TestResult {
    let outcome = BatchApplyOutcome {
        touched_accounts: BTreeSet::from([wallet(2), wallet(1)]),
        total_supply_micro: 3,
        fingerprint_hex: "abc".to_owned(),
    };

    let touched: Vec<String> = outcome.touched_accounts.into_iter().collect();

    assert_eq!(touched, vec![wallet(1), wallet(2)]);
    Ok(())
}

#[test]
fn account_guard_015_batch_apply_outcome_clone_preserves_fields() -> TestResult {
    let outcome = BatchApplyOutcome {
        touched_accounts: BTreeSet::from([wallet(1)]),
        total_supply_micro: 10,
        fingerprint_hex: "abc123".to_owned(),
    };
    let cloned = outcome.clone();

    assert_eq!(cloned.touched_accounts, outcome.touched_accounts);
    assert_eq!(cloned.total_supply_micro, outcome.total_supply_micro);
    assert_eq!(cloned.fingerprint_hex, outcome.fingerprint_hex);
    Ok(())
}

#[test]
fn account_guard_016_state_fingerprint_constructs() -> TestResult {
    let fp = StateFingerprint {
        height: 1,
        total_issued_micro: 2,
        rewards_issued_micro: 3,
        total_supply_micro: 4,
        touched_accounts: vec![(wallet(1), 5)],
        hex: "0123456789abcdef0123456789abcdef".to_owned(),
    };

    assert_eq!(fp.height, 1);
    assert_eq!(fp.total_issued_micro, 2);
    assert_eq!(fp.rewards_issued_micro, 3);
    assert_eq!(fp.total_supply_micro, 4);
    assert_eq!(fp.touched_accounts, vec![(wallet(1), 5)]);
    assert_eq!(fp.hex.len(), 32);
    Ok(())
}

#[test]
fn account_guard_017_state_fingerprint_clone_preserves_fields() -> TestResult {
    let fp = StateFingerprint {
        height: 11,
        total_issued_micro: 12,
        rewards_issued_micro: 13,
        total_supply_micro: 14,
        touched_accounts: vec![(wallet(2), 99)],
        hex: "ffffffffffffffffffffffffffffffff".to_owned(),
    };
    let cloned = fp.clone();

    assert_eq!(cloned.height, fp.height);
    assert_eq!(cloned.total_issued_micro, fp.total_issued_micro);
    assert_eq!(cloned.rewards_issued_micro, fp.rewards_issued_micro);
    assert_eq!(cloned.total_supply_micro, fp.total_supply_micro);
    assert_eq!(cloned.touched_accounts, fp.touched_accounts);
    assert_eq!(cloned.hex, fp.hex);
    Ok(())
}

#[test]
fn account_guard_018_state_fingerprint_hex_vector_is_lowercase_hex() -> TestResult {
    let fp = StateFingerprint {
        height: 0,
        total_issued_micro: 0,
        rewards_issued_micro: 0,
        total_supply_micro: 0,
        touched_accounts: Vec::new(),
        hex: "0123456789abcdef0123456789abcdef".to_owned(),
    };

    assert_eq!(fp.hex.len(), 32);
    assert!(
        fp.hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    );
    Ok(())
}

#[test]
fn account_guard_019_txkind_transfer_validate_valid() -> TestResult {
    let kind = transfer_kind(1, 2, 1)?;

    kind.validate()?;
    Ok(())
}

#[test]
fn account_guard_020_txkind_transfer_validate_zero_amount_rejects() -> TestResult {
    let kind = transfer_kind(1, 2, 0)?;

    assert!(kind.validate().is_err());
    Ok(())
}

#[test]
fn account_guard_021_txkind_reward_validate_valid() -> TestResult {
    let kind = reward_kind(1, 1, 1)?;

    kind.validate()?;
    Ok(())
}

#[test]
fn account_guard_022_txkind_reward_validate_zero_amount_rejects() -> TestResult {
    let kind = reward_kind(1, 0, 1)?;

    assert!(kind.validate().is_err());
    Ok(())
}

#[test]
fn account_guard_023_txkind_register_validate_valid() -> TestResult {
    let kind = register_kind(1)?;

    kind.validate()?;
    Ok(())
}

#[test]
fn account_guard_024_txkind_nft_mint_validate_valid() -> TestResult {
    let kind = nft_mint_kind(1);

    kind.validate()?;
    Ok(())
}

#[test]
fn account_guard_025_txkind_nft_transfer_validate_valid() -> TestResult {
    let kind = nft_transfer_kind(1);

    kind.validate()?;
    Ok(())
}

#[test]
fn account_guard_026_transaction_batch_empty_roundtrip() -> TestResult {
    let tx_batch = batch(0, Vec::new())?;
    let bytes = tx_batch.serialize_for_storage()?;
    let decoded = TransactionBatch::deserialize(&bytes)?;

    assert_eq!(decoded, tx_batch);
    Ok(())
}

#[test]
fn account_guard_027_transaction_batch_reward_roundtrip() -> TestResult {
    let tx_batch = batch(1, vec![reward_kind(1, 7, 1)?])?;
    let bytes = tx_batch.serialize_for_storage()?;
    let decoded = TransactionBatch::deserialize(&bytes)?;

    assert_eq!(decoded, tx_batch);
    Ok(())
}

#[test]
fn account_guard_028_transaction_batch_transfer_roundtrip() -> TestResult {
    let tx_batch = batch(1, vec![transfer_kind(1, 2, 3)?])?;
    let bytes = tx_batch.serialize_for_storage()?;
    let decoded = TransactionBatch::deserialize(&bytes)?;

    assert_eq!(decoded, tx_batch);
    Ok(())
}

#[test]
fn account_guard_029_block_genesis_create() -> TestResult {
    let block = test_block(0, [0_u8; 64])?;

    assert_eq!(block.metadata.index, 0);
    assert_eq!(block.metadata.previous_hash, [0_u8; 64]);
    Ok(())
}

#[test]
fn account_guard_030_block_non_genesis_create() -> TestResult {
    let genesis = test_block(0, [0_u8; 64])?;
    let block = test_block(1, genesis.block_hash)?;

    assert_eq!(block.metadata.index, 1);
    assert_eq!(block.metadata.previous_hash, genesis.block_hash);
    Ok(())
}

#[test]
fn account_guard_031_tree_initial_height_zero() -> TestResult {
    let db = new_blockchain_db("tree_initial_height_zero")?;
    let tree = load_tree(&db)?;

    assert_eq!(tree.latest_block_height(), 0);
    Ok(())
}

#[test]
fn account_guard_032_tree_get_missing_block_errors() -> TestResult {
    let db = new_blockchain_db("tree_get_missing_block_errors")?;
    let tree = load_tree(&db)?;

    assert!(tree.get_block_by_index(0).is_err());
    Ok(())
}

#[test]
fn account_guard_033_tree_add_genesis_block() -> TestResult {
    let db = new_blockchain_db("tree_add_genesis_block")?;
    let mut tree = load_tree(&db)?;
    let genesis = test_block(0, [0_u8; 64])?;

    tree.add_block(genesis.clone())?;

    assert_eq!(tree.latest_block_height(), 0);
    assert_eq!(tree.get_block_by_index(0)?, genesis);
    Ok(())
}

#[test]
fn account_guard_034_tree_add_two_blocks() -> TestResult {
    let db = new_blockchain_db("tree_add_two_blocks")?;
    let mut tree = load_tree(&db)?;
    let genesis = test_block(0, [0_u8; 64])?;
    let next = test_block(1, genesis.block_hash)?;

    tree.add_block(genesis)?;
    tree.add_block(next.clone())?;

    assert_eq!(tree.latest_block_height(), 1);
    assert_eq!(tree.get_block_by_index(1)?, next);
    Ok(())
}

#[test]
fn account_guard_035_tree_rejects_bad_previous_hash() -> TestResult {
    let db = new_blockchain_db("tree_rejects_bad_previous_hash")?;
    let mut tree = load_tree(&db)?;
    let genesis = test_block(0, [0_u8; 64])?;
    let bad_next = test_block(1, hash_from_seed(99))?;

    tree.add_block(genesis)?;
    assert!(tree.add_block(bad_next).is_err());
    Ok(())
}

#[test]
fn account_guard_036_set_get_balance_zero_default() -> TestResult {
    let db = new_blockchain_db("set_get_balance_zero_default")?;
    let tree = load_tree(&db)?;

    assert_eq!(tree.get_balance(&wallet(1)), 0);
    Ok(())
}

#[test]
fn account_guard_037_set_get_balance_nonzero() -> TestResult {
    let db = new_blockchain_db("set_get_balance_nonzero")?;
    let mut tree = load_tree(&db)?;

    tree.set_balance(&wallet(1), 123);

    assert_eq!(tree.get_balance(&wallet(1)), 123);
    Ok(())
}

#[test]
fn account_guard_038_set_balance_overwrite_last_write_wins() -> TestResult {
    let db = new_blockchain_db("set_balance_overwrite_last_write_wins")?;
    let mut tree = load_tree(&db)?;

    tree.set_balance(&wallet(1), 123);
    tree.set_balance(&wallet(1), 456);

    assert_eq!(tree.get_balance(&wallet(1)), 456);
    Ok(())
}

#[test]
fn account_guard_039_multiple_balances_are_independent() -> TestResult {
    let db = new_blockchain_db("multiple_balances_are_independent")?;
    let mut tree = load_tree(&db)?;

    tree.set_balance(&wallet(1), 10);
    tree.set_balance(&wallet(2), 20);
    tree.set_balance(&wallet(3), 30);

    assert_eq!(tree.get_balance(&wallet(1)), 10);
    assert_eq!(tree.get_balance(&wallet(2)), 20);
    assert_eq!(tree.get_balance(&wallet(3)), 30);
    Ok(())
}

#[test]
fn account_guard_040_store_load_state_empty() -> TestResult {
    let db = new_blockchain_db("store_load_state_empty")?;
    let tree = load_tree(&db)?;

    db.manager()?.store_state(&tree)?;
    let loaded = db.manager()?.load_state()?;

    assert_eq!(loaded.latest_block_height(), 0);
    assert_eq!(loaded.get_balance(&wallet(1)), 0);
    Ok(())
}

#[test]
fn account_guard_041_store_load_state_one_balance() -> TestResult {
    let db = new_blockchain_db("store_load_state_one_balance")?;
    let mut tree = load_tree(&db)?;

    tree.set_balance(&wallet(1), 999);
    db.manager()?.store_state(&tree)?;

    let loaded = db.manager()?.load_state()?;

    assert_eq!(loaded.get_balance(&wallet(1)), 999);
    Ok(())
}

#[test]
fn account_guard_042_store_load_state_many_balances() -> TestResult {
    let db = new_blockchain_db("store_load_state_many_balances")?;
    let mut tree = load_tree(&db)?;

    for seed in 0_u64..32 {
        tree.set_balance(&wallet(seed), seed.saturating_mul(10));
    }

    db.manager()?.store_state(&tree)?;
    let loaded = db.manager()?.load_state()?;

    for seed in 0_u64..32 {
        assert_eq!(loaded.get_balance(&wallet(seed)), seed.saturating_mul(10));
    }

    Ok(())
}

#[test]
fn account_guard_043_load_state_missing_returns_empty_tree() -> TestResult {
    let db = new_blockchain_db("load_state_missing_returns_empty_tree")?;
    let loaded = db.manager()?.load_state()?;

    assert_eq!(loaded.get_balance(&wallet(1)), 0);
    assert_eq!(loaded.latest_block_height(), 0);
    Ok(())
}

#[test]
fn account_guard_044_reload_genesis_without_batch_succeeds() -> TestResult {
    let db = db_with_chain("reload_genesis_without_batch_succeeds", 1)?;
    let mut tree = load_tree(&db)?;

    tree.reload_from_db_to_height(0)?;

    assert_eq!(tree.latest_block_height(), 0);
    Ok(())
}

#[test]
fn account_guard_045_reload_reward_batch_updates_balance() -> TestResult {
    let db = db_with_batches(
        "reload_reward_batch_updates_balance",
        1,
        vec![(1, vec![reward_kind(1, 7, 1)?])],
    )?;
    let mut tree = load_tree(&db)?;

    tree.reload_from_db_to_height(1)?;

    assert_eq!(tree.get_balance(&wallet(1)), 7);
    assert_eq!(tree.latest_block_height(), 1);
    Ok(())
}

#[test]
fn account_guard_046_reload_reward_then_transfer_updates_balances() -> TestResult {
    let db = db_with_batches(
        "reload_reward_then_transfer_updates_balances",
        2,
        vec![
            (1, vec![reward_kind(1, 10, 1)?]),
            (2, vec![transfer_kind(1, 2, 4)?]),
        ],
    )?;
    let mut tree = load_tree(&db)?;

    tree.reload_from_db_to_height(2)?;

    assert_eq!(tree.get_balance(&wallet(1)), 6);
    assert_eq!(tree.get_balance(&wallet(2)), 4);
    Ok(())
}

#[test]
fn account_guard_047_reload_register_batch_does_not_create_balance() -> TestResult {
    let db = db_with_batches(
        "reload_register_batch_does_not_create_balance",
        1,
        vec![(1, vec![register_kind(9)?])],
    )?;
    let mut tree = load_tree(&db)?;

    tree.reload_from_db_to_height(1)?;

    assert_eq!(tree.get_balance(&wallet(9)), 0);
    Ok(())
}

#[test]
fn account_guard_048_reload_zero_reward_errors() -> TestResult {
    let db = db_with_batches(
        "reload_zero_reward_errors",
        1,
        vec![(1, vec![reward_kind(1, 0, 1)?])],
    )?;
    let mut tree = load_tree(&db)?;

    assert_error_contains(
        tree.reload_from_db_to_height(1),
        "Reward tx amount must be non-zero",
        "zero reward replay should fail",
    )
}

#[test]
fn account_guard_049_reload_zero_transfer_errors() -> TestResult {
    let db = db_with_batches(
        "reload_zero_transfer_errors",
        1,
        vec![(1, vec![transfer_kind(1, 2, 0)?])],
    )?;
    let mut tree = load_tree(&db)?;

    assert_error_contains(
        tree.reload_from_db_to_height(1),
        "Transfer tx amount must be non-zero",
        "zero transfer replay should fail",
    )
}

#[test]
fn account_guard_050_reload_missing_non_genesis_batch_errors() -> TestResult {
    let db = db_with_chain("reload_missing_non_genesis_batch_errors", 2)?;
    let mut tree = load_tree(&db)?;

    assert_error_contains(
        tree.reload_from_db_to_height(1),
        "missing batch bytes",
        "missing height-one batch should fail",
    )
}

macro_rules! reward_replay_test {
    ($name:ident, $seed:expr, $amount:expr) => {
        #[test]
        fn $name() -> TestResult {
            let label = concat!(stringify!($name), "_db");
            let db = db_with_batches(label, 1, vec![(1, vec![reward_kind($seed, $amount, 1)?])])?;
            let mut tree = load_tree(&db)?;

            tree.reload_from_db_to_height(1)?;

            assert_eq!(tree.get_balance(&wallet($seed)), $amount);
            Ok(())
        }
    };
}

reward_replay_test!(account_guard_051_reward_replay_vector_1, 51, 1);
reward_replay_test!(account_guard_052_reward_replay_vector_2, 52, 2);
reward_replay_test!(account_guard_053_reward_replay_vector_3, 53, 3);
reward_replay_test!(account_guard_054_reward_replay_vector_5, 54, 5);
reward_replay_test!(account_guard_055_reward_replay_vector_8, 55, 8);
reward_replay_test!(account_guard_056_reward_replay_vector_13, 56, 13);
reward_replay_test!(account_guard_057_reward_replay_vector_21, 57, 21);
reward_replay_test!(account_guard_058_reward_replay_vector_34, 58, 34);
reward_replay_test!(account_guard_059_reward_replay_vector_55, 59, 55);
reward_replay_test!(account_guard_060_reward_replay_vector_89, 60, 89);

macro_rules! transfer_replay_test {
    ($name:ident, $sender_seed:expr, $receiver_seed:expr, $reward:expr, $send:expr) => {
        #[test]
        fn $name() -> TestResult {
            let label = concat!(stringify!($name), "_db");
            let db = db_with_batches(
                label,
                2,
                vec![
                    (1, vec![reward_kind($sender_seed, $reward, 1)?]),
                    (2, vec![transfer_kind($sender_seed, $receiver_seed, $send)?]),
                ],
            )?;
            let mut tree = load_tree(&db)?;

            tree.reload_from_db_to_height(2)?;

            assert_eq!(tree.get_balance(&wallet($sender_seed)), $reward - $send);
            assert_eq!(tree.get_balance(&wallet($receiver_seed)), $send);
            Ok(())
        }
    };
}

transfer_replay_test!(account_guard_061_transfer_replay_vector_1, 101, 201, 10, 1);
transfer_replay_test!(account_guard_062_transfer_replay_vector_2, 102, 202, 10, 2);
transfer_replay_test!(account_guard_063_transfer_replay_vector_3, 103, 203, 10, 3);
transfer_replay_test!(account_guard_064_transfer_replay_vector_4, 104, 204, 10, 4);
transfer_replay_test!(account_guard_065_transfer_replay_vector_5, 105, 205, 10, 5);
transfer_replay_test!(account_guard_066_transfer_replay_vector_6, 106, 206, 10, 6);
transfer_replay_test!(account_guard_067_transfer_replay_vector_7, 107, 207, 10, 7);
transfer_replay_test!(account_guard_068_transfer_replay_vector_8, 108, 208, 10, 8);
transfer_replay_test!(account_guard_069_transfer_replay_vector_9, 109, 209, 10, 9);
transfer_replay_test!(
    account_guard_070_transfer_replay_vector_10,
    110,
    210,
    10,
    10
);

macro_rules! zero_reward_reject_test {
    ($name:ident, $seed:expr) => {
        #[test]
        fn $name() -> TestResult {
            let label = concat!(stringify!($name), "_db");
            let db = db_with_batches(label, 1, vec![(1, vec![reward_kind($seed, 0, 1)?])])?;
            let mut tree = load_tree(&db)?;

            assert_error_contains(
                tree.reload_from_db_to_height(1),
                "Reward tx amount must be non-zero",
                "zero reward vector should reject",
            )
        }
    };
}

zero_reward_reject_test!(account_guard_071_zero_reward_reject_vector_1, 301);
zero_reward_reject_test!(account_guard_072_zero_reward_reject_vector_2, 302);
zero_reward_reject_test!(account_guard_073_zero_reward_reject_vector_3, 303);
zero_reward_reject_test!(account_guard_074_zero_reward_reject_vector_4, 304);
zero_reward_reject_test!(account_guard_075_zero_reward_reject_vector_5, 305);
zero_reward_reject_test!(account_guard_076_zero_reward_reject_vector_6, 306);
zero_reward_reject_test!(account_guard_077_zero_reward_reject_vector_7, 307);
zero_reward_reject_test!(account_guard_078_zero_reward_reject_vector_8, 308);
zero_reward_reject_test!(account_guard_079_zero_reward_reject_vector_9, 309);
zero_reward_reject_test!(account_guard_080_zero_reward_reject_vector_10, 310);

macro_rules! insufficient_transfer_reject_test {
    ($name:ident, $sender_seed:expr, $receiver_seed:expr, $funded:expr, $spend:expr) => {
        #[test]
        fn $name() -> TestResult {
            let label = concat!(stringify!($name), "_db");
            let db = db_with_batches(
                label,
                2,
                vec![
                    (1, vec![reward_kind($sender_seed, $funded, 1)?]),
                    (
                        2,
                        vec![transfer_kind($sender_seed, $receiver_seed, $spend)?],
                    ),
                ],
            )?;
            let mut tree = load_tree(&db)?;

            assert_error_contains(
                tree.reload_from_db_to_height(2),
                "Insufficient balance",
                "insufficient transfer vector should reject",
            )
        }
    };
}

insufficient_transfer_reject_test!(
    account_guard_081_insufficient_transfer_vector_1,
    401,
    501,
    1,
    2
);
insufficient_transfer_reject_test!(
    account_guard_082_insufficient_transfer_vector_2,
    402,
    502,
    2,
    3
);
insufficient_transfer_reject_test!(
    account_guard_083_insufficient_transfer_vector_3,
    403,
    503,
    3,
    4
);
insufficient_transfer_reject_test!(
    account_guard_084_insufficient_transfer_vector_4,
    404,
    504,
    4,
    5
);
insufficient_transfer_reject_test!(
    account_guard_085_insufficient_transfer_vector_5,
    405,
    505,
    5,
    6
);
insufficient_transfer_reject_test!(
    account_guard_086_insufficient_transfer_vector_6,
    406,
    506,
    6,
    7
);
insufficient_transfer_reject_test!(
    account_guard_087_insufficient_transfer_vector_7,
    407,
    507,
    7,
    8
);
insufficient_transfer_reject_test!(
    account_guard_088_insufficient_transfer_vector_8,
    408,
    508,
    8,
    9
);
insufficient_transfer_reject_test!(
    account_guard_089_insufficient_transfer_vector_9,
    409,
    509,
    9,
    10
);
insufficient_transfer_reject_test!(
    account_guard_090_insufficient_transfer_vector_10,
    410,
    510,
    10,
    11
);

macro_rules! state_persistence_test {
    ($name:ident, $seed:expr, $balance:expr) => {
        #[test]
        fn $name() -> TestResult {
            let label = concat!(stringify!($name), "_db");
            let db = new_blockchain_db(label)?;
            let mut tree = load_tree(&db)?;

            tree.set_balance(&wallet($seed), $balance);
            db.manager()?.store_state(&tree)?;

            let loaded = db.manager()?.load_state()?;

            assert_eq!(loaded.get_balance(&wallet($seed)), $balance);
            Ok(())
        }
    };
}

state_persistence_test!(account_guard_091_state_persistence_vector_1, 601, 1);
state_persistence_test!(account_guard_092_state_persistence_vector_2, 602, 2);
state_persistence_test!(account_guard_093_state_persistence_vector_3, 603, 3);
state_persistence_test!(account_guard_094_state_persistence_vector_5, 604, 5);
state_persistence_test!(account_guard_095_state_persistence_vector_8, 605, 8);
state_persistence_test!(account_guard_096_state_persistence_vector_13, 606, 13);
state_persistence_test!(account_guard_097_state_persistence_vector_21, 607, 21);
state_persistence_test!(account_guard_098_state_persistence_vector_34, 608, 34);
state_persistence_test!(account_guard_099_state_persistence_vector_55, 609, 55);
state_persistence_test!(account_guard_100_state_persistence_vector_89, 610, 89);
