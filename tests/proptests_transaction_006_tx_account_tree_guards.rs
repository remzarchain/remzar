use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_account_tree::{AccountModelTree, ChainLogic};
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestDb {
    manager: Option<RockDBManager>,
    root: PathBuf,
}

impl TestDb {
    fn manager(&self) -> &RockDBManager {
        self.manager
            .as_ref()
            .expect("test database manager should be available")
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        drop(self.manager.take());

        if std::fs::remove_dir_all(&self.root).is_err() {
            // Best-effort cleanup only.
        }
    }
}

struct TestChain {
    tree: AccountModelTree,
    _db: TestDb,
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_proptest_account_guard_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> String {
    path.to_str()
        .expect("test path should be valid UTF-8")
        .to_owned()
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn wallet_arr(seed: u64) -> [u8; REMZAR_WALLET_LEN] {
    let value = wallet(seed);
    let bytes = value.as_bytes();

    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(bytes);
    out
}

fn node_opts(root: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: path_to_string(&root.join("identity.key")),
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "error".to_owned(),
        data_dir: path_to_string(root),
        wallet_address: wallet(1),
        founder: false,
    }
}

fn new_blockchain_db(label: &str) -> TestDb {
    let root = unique_root(label);

    std::fs::create_dir_all(&root).expect("test root directory should be created");

    let opts = node_opts(&root);
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path);

    let manager = RockDBManager::new_blockchain(&opts, &blockchain_path_string)
        .expect("test blockchain RocksDB manager should initialize");

    TestDb {
        manager: Some(manager),
        root,
    }
}

fn new_test_chain(label: &str) -> TestChain {
    let db = new_blockchain_db(label);
    let tree = AccountModelTree::with_manager(db.manager().clone());

    TestChain { tree, _db: db }
}

fn fixed_hash(seed: u8) -> Hash {
    [seed; 64]
}

fn seed_from_index(index: u64, offset: u8) -> u8 {
    let reduced = u8::try_from(index % 200).expect("index modulo 200 should fit into u8");

    reduced.saturating_add(offset)
}

fn test_metadata(index: u64, previous_hash: Hash) -> BlockMetadata {
    let timestamp = GlobalConfiguration::MIN_TIMESTAMP_SECS
        .saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS)
        .saturating_add(index);

    let merkle_root = fixed_hash(seed_from_index(index, 31));

    let guardian_signature = if index == 0 {
        [0u8; ml_dsa_65::SIG_LEN]
    } else {
        [seed_from_index(index, 7).max(1); ml_dsa_65::SIG_LEN]
    };

    BlockMetadata::new(
        index,
        timestamp,
        previous_hash,
        merkle_root,
        guardian_signature,
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    )
}

fn test_block(index: u64, previous_hash: Hash) -> Result<Block, ErrorDetection> {
    let miner = if index == 0 {
        String::new()
    } else {
        wallet(index.saturating_add(10_000))
    };

    let batch_key = if index == 0 {
        None
    } else {
        Some(format!("tx_batch_{index:010}"))
    };

    Block::new(test_metadata(index, previous_hash), batch_key, miner, index)
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

    if current_len >= wanted_len {
        return Ok(());
    }

    let mut previous_hash = tree
        .get_blocks()
        .last()
        .map(|block| block.block_hash)
        .unwrap_or([0u8; 64]);

    for next_index in current_len..wanted_len {
        let index = u64::try_from(next_index).map_err(|_| ErrorDetection::ValidationError {
            message: "test block index cannot fit into u64".to_owned(),
            tx_id: None,
        })?;

        let block = test_block(index, previous_hash)?;
        previous_hash = block.block_hash;

        tree.add_block(block)?;
    }

    Ok(())
}

fn tx_batch(index: u64, transactions: Vec<TxKind>) -> Result<TransactionBatch, ErrorDetection> {
    TransactionBatch::new(
        index,
        GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(index),
        transactions,
    )
}

fn manual_tx(sender_seed: u64, receiver_seed: u64, amount: u64) -> Transaction {
    Transaction {
        sender: wallet_arr(sender_seed),
        receiver: wallet_arr(receiver_seed),
        amount,
        timestamp: GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(1),
    }
}

fn valid_transfer(sender_seed: u64, receiver_seed: u64, amount: u64) -> Transaction {
    Transaction::new(wallet(sender_seed), wallet(receiver_seed), amount.max(1))
        .expect("generated valid transfer should construct")
}

fn valid_reward(receiver_seed: u64, amount: u64, block_height: u64) -> RewardTx {
    RewardTx::new(wallet(receiver_seed), amount.max(1), block_height.max(1))
        .expect("generated valid reward should construct")
}

fn valid_register(seed: u64) -> RegisterNodeTx {
    RegisterNodeTx::new(wallet(seed)).expect("generated valid register tx should construct")
}

fn sum_balances(tree: &AccountModelTree) -> u64 {
    tree.get_balances()
        .values()
        .copied()
        .try_fold(0u64, |acc, value| acc.checked_add(value))
        .expect("test balance sum should not overflow")
}

fn apply_reward_at_height(
    tree: &mut AccountModelTree,
    receiver_seed: u64,
    amount: u64,
    height: u64,
) -> Result<(), ErrorDetection> {
    add_blocks_until_tip(tree, height)?;

    let reward = valid_reward(receiver_seed, amount, height);
    let batch = tx_batch(height, vec![TxKind::Reward(reward)])?;

    tree.apply_batch(&batch)
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_guard_applies_valid_reward_and_updates_supply_counters(
        receiver_seed in 1u64..=1_000_000u64,
        amount in 1u64..=1_000_000u64,
    ) {
        prop_assume!(amount <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(amount <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(amount <= GlobalConfiguration::MAX_SUPPLY);

        let mut chain = new_test_chain("guard_reward_apply");

        apply_reward_at_height(&mut chain.tree, receiver_seed, amount, 1)
            .expect("valid reward batch should apply");

        let receiver = wallet(receiver_seed);

        prop_assert_eq!(
            chain.tree.get_balance(&receiver),
            amount,
            "reward must credit receiver balance"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            amount,
            "reward must increase total issued"
        );

        prop_assert_eq!(
            chain.tree.rewards_issued_micro(),
            amount,
            "reward must increase rewards issued"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            amount,
            "sum of balances must match issued supply after reward"
        );
    }

    // 02/25
    #[test]
    fn test_002_guard_accumulates_two_valid_rewards_at_different_heights(
        receiver_a_seed in 1u64..=1_000_000u64,
        receiver_b_delta in 1u64..=1_000_000u64,
        amount_a in 1u64..=1_000_000u64,
        amount_b in 1u64..=1_000_000u64,
    ) {
        let receiver_b_seed = receiver_a_seed.saturating_add(receiver_b_delta);

        prop_assume!(receiver_a_seed != receiver_b_seed);
        prop_assume!(amount_a <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(amount_b <= GlobalConfiguration::MAX_BLOCK_REWARD);

        let total = amount_a.saturating_add(amount_b);

        prop_assume!(total <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(total <= GlobalConfiguration::MAX_SUPPLY);

        let mut chain = new_test_chain("guard_two_rewards");

        apply_reward_at_height(&mut chain.tree, receiver_a_seed, amount_a, 1)
            .expect("first valid reward should apply");

        apply_reward_at_height(&mut chain.tree, receiver_b_seed, amount_b, 2)
            .expect("second valid reward should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_a_seed)),
            amount_a,
            "first reward receiver balance must be credited"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_b_seed)),
            amount_b,
            "second reward receiver balance must be credited"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            total,
            "two rewards must accumulate total issued"
        );

        prop_assert_eq!(
            chain.tree.rewards_issued_micro(),
            total,
            "two rewards must accumulate rewards issued"
        );
    }

    // 03/25
    #[test]
    fn test_003_guard_accepts_max_block_reward_boundary_when_supply_allows(
        receiver_seed in 1u64..=1_000_000u64,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD <= GlobalConfiguration::MAX_SUPPLY);

        let mut chain = new_test_chain("guard_max_reward_boundary");
        let amount = GlobalConfiguration::MAX_BLOCK_REWARD;

        apply_reward_at_height(&mut chain.tree, receiver_seed, amount, 1)
            .expect("MAX_BLOCK_REWARD boundary should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            amount,
            "MAX_BLOCK_REWARD must credit receiver exactly"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            amount,
            "MAX_BLOCK_REWARD must update issued supply exactly"
        );
    }

    // 04/25
    #[test]
    fn test_004_guard_rejects_zero_reward_without_mutating_state(
        receiver_seed in 1u64..=1_000_000u64,
    ) {
        let mut chain = new_test_chain("guard_zero_reward");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to reward height");

        let reward = RewardTx {
            receiver: wallet_arr(receiver_seed),
            amount: 0,
            block_height: 1,
            timestamp: GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(1),
        };

        let batch = tx_batch(1, vec![TxKind::Reward(reward)])
            .expect("zero reward batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "zero reward must be rejected by guard"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            0,
            "rejected zero reward must not credit receiver"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "rejected zero reward must not change issued supply"
        );
    }

    // 05/25
    #[test]
    fn test_005_guard_rejects_reward_above_max_block_reward_without_mutation(
        receiver_seed in 1u64..=1_000_000u64,
        extra in 1u64..=1_000_000u64,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD < u64::MAX);

        let amount = GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(extra);
        prop_assume!(amount > GlobalConfiguration::MAX_BLOCK_REWARD);

        let mut chain = new_test_chain("guard_above_max_reward");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to reward height");

        let reward = RewardTx {
            receiver: wallet_arr(receiver_seed),
            amount,
            block_height: 1,
            timestamp: GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(1),
        };

        let batch = tx_batch(1, vec![TxKind::Reward(reward)])
            .expect("above-max reward batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "reward above MAX_BLOCK_REWARD must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            0,
            "rejected above-max reward must not credit receiver"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "rejected above-max reward must not change issued supply"
        );
    }

    // 06/25
    #[test]
    fn test_006_guard_rejects_duplicate_rewards_without_partial_mutation(
        receiver_seed in 1u64..=1_000_000u64,
        amount in 1u64..=1_000_000u64,
    ) {
        prop_assume!(amount <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(amount <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let mut chain = new_test_chain("guard_duplicate_rewards");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to reward height");

        let reward_a = valid_reward(receiver_seed, amount, 1);
        let reward_b = valid_reward(receiver_seed.saturating_add(1), amount, 1);

        let batch = tx_batch(
            1,
            vec![TxKind::Reward(reward_a), TxKind::Reward(reward_b)],
        )
        .expect("duplicate reward batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "batch with multiple rewards must be rejected"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "duplicate reward batch must not change issued supply"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            0,
            "duplicate reward batch must not credit any balance"
        );
    }

    // 07/25
    #[test]
    fn test_007_guard_applies_funded_transfer_and_preserves_total_supply(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        amount_seed in any::<u64>(),
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let amount = amount_seed % funding.saturating_add(1);
        prop_assume!(amount > 0);
        prop_assume!(amount <= GlobalConfiguration::MAX_TX_AMOUNT);

        let mut chain = new_test_chain("guard_valid_transfer");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer height");

        let tx = valid_transfer(sender_seed, receiver_seed, amount);
        let batch = tx_batch(2, vec![TxKind::Transfer(tx)])
            .expect("transfer batch should construct");

        chain.tree
            .apply_batch(&batch)
            .expect("funded transfer should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            funding.saturating_sub(amount),
            "sender balance must decrease by amount"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            amount,
            "receiver balance must increase by amount"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            funding,
            "plain transfer must not change total issued"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            funding,
            "plain transfer must conserve total supply"
        );
    }

    // 08/25
    #[test]
    fn test_008_guard_rejects_aggregate_same_sender_spend_above_balance_before_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_a_delta in 1u64..=1_000_000u64,
        receiver_b_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        extra in 1u64..=1_000_000u64,
    ) {
        let receiver_a_seed = sender_seed.saturating_add(receiver_a_delta);
        let receiver_b_seed = sender_seed
            .saturating_add(receiver_b_delta)
            .saturating_add(10_000_000);

        prop_assume!(sender_seed != receiver_a_seed);
        prop_assume!(sender_seed != receiver_b_seed);
        prop_assume!(receiver_a_seed != receiver_b_seed);
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let mut chain = new_test_chain("guard_aggregate_spend");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer height");

        let before_sender = chain.tree.get_balance(&wallet(sender_seed));

        let tx_a = valid_transfer(sender_seed, receiver_a_seed, funding);
        let tx_b = valid_transfer(sender_seed, receiver_b_seed, extra);

        let batch = tx_batch(
            2,
            vec![TxKind::Transfer(tx_a), TxKind::Transfer(tx_b)],
        )
        .expect("aggregate overspend batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "aggregate same-sender spend above balance must be rejected before mutation"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            before_sender,
            "aggregate overspend failure must not debit sender"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_a_seed)),
            0,
            "aggregate overspend failure must not credit first receiver"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_b_seed)),
            0,
            "aggregate overspend failure must not credit second receiver"
        );
    }

    // 09/25
    #[test]
    fn test_009_guard_rejects_duplicate_transfer_transaction_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        amount_seed in any::<u64>(),
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let amount = amount_seed % funding.saturating_add(1);
        prop_assume!(amount > 0);

        let mut chain = new_test_chain("guard_duplicate_transfer");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer height");

        let tx = valid_transfer(sender_seed, receiver_seed, amount);

        let batch = tx_batch(
            2,
            vec![TxKind::Transfer(tx.clone()), TxKind::Transfer(tx)],
        )
        .expect("duplicate transfer batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "duplicate transfer transaction IDs must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            funding,
            "duplicate transfer rejection must not debit sender"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            0,
            "duplicate transfer rejection must not credit receiver"
        );
    }

    // 10/25
    #[test]
    fn test_010_guard_rejects_zero_amount_transfer_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let mut chain = new_test_chain("guard_zero_transfer");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer height");

        let tx = manual_tx(sender_seed, receiver_seed, 0);
        let batch = tx_batch(2, vec![TxKind::Transfer(tx)])
            .expect("zero transfer batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "zero transfer amount must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            funding,
            "zero transfer rejection must not debit sender"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            0,
            "zero transfer rejection must not credit receiver"
        );
    }

    // 11/25
    #[test]
    fn test_011_guard_rejects_same_sender_receiver_transfer_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        amount_seed in any::<u64>(),
    ) {
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let amount = amount_seed % funding.saturating_add(1);
        prop_assume!(amount > 0);

        let mut chain = new_test_chain("guard_same_sender_receiver");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer height");

        let tx = manual_tx(sender_seed, sender_seed, amount);
        let batch = tx_batch(2, vec![TxKind::Transfer(tx)])
            .expect("same sender/receiver batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "same sender/receiver transfer must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            funding,
            "same sender/receiver rejection must not mutate balance"
        );
    }

    // 12/25
    #[test]
    fn test_012_guard_rejects_transfer_above_max_tx_amount_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        extra in 1u64..=1_000_000u64,
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(GlobalConfiguration::MAX_TX_AMOUNT < u64::MAX);

        let amount = GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(extra);
        prop_assume!(amount > GlobalConfiguration::MAX_TX_AMOUNT);

        let mut chain = new_test_chain("guard_above_max_transfer");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer height");

        let tx = manual_tx(sender_seed, receiver_seed, amount);
        let batch = tx_batch(2, vec![TxKind::Transfer(tx)])
            .expect("above-max transfer batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "transfer above MAX_TX_AMOUNT must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            funding,
            "above-max transfer rejection must not debit sender"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            0,
            "above-max transfer rejection must not credit receiver"
        );
    }

    // 13/25
    #[test]
    fn test_013_guard_rejects_invalid_transfer_sender_bytes_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let mut chain = new_test_chain("guard_bad_transfer_wallet");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer height");

        let mut tx = manual_tx(sender_seed, receiver_seed, 1);
        tx.sender = [0u8; REMZAR_WALLET_LEN];

        let batch = tx_batch(2, vec![TxKind::Transfer(tx)])
            .expect("bad sender transfer batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "transfer with invalid sender bytes must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            funding,
            "invalid sender rejection must not debit real sender"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            0,
            "invalid sender rejection must not credit receiver"
        );
    }

    // 14/25
    #[test]
    fn test_014_guard_rejects_unfunded_transfer_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        amount in 1u64..=1_000_000u64,
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(amount <= GlobalConfiguration::MAX_TX_AMOUNT);

        let mut chain = new_test_chain("guard_unfunded_transfer");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to transfer height");

        let tx = valid_transfer(sender_seed, receiver_seed, amount);
        let batch = tx_batch(1, vec![TxKind::Transfer(tx)])
            .expect("unfunded transfer batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "unfunded transfer must be rejected"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            0,
            "unfunded transfer rejection must not mutate balances"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "unfunded transfer rejection must not mutate supply"
        );
    }

    // 15/25
    #[test]
    fn test_015_guard_applies_two_independent_funded_transfers_in_one_batch(
        sender_a_seed in 1u64..=1_000_000u64,
        sender_b_delta in 1u64..=1_000_000u64,
        receiver_a_delta in 1u64..=1_000_000u64,
        receiver_b_delta in 1u64..=1_000_000u64,
        funding_a in 1u64..=1_000_000u64,
        funding_b in 1u64..=1_000_000u64,
        amount_a_seed in any::<u64>(),
        amount_b_seed in any::<u64>(),
    ) {
        let sender_b_seed = sender_a_seed.saturating_add(sender_b_delta);
        let receiver_a_seed = sender_b_seed.saturating_add(receiver_a_delta);
        let receiver_b_seed = receiver_a_seed.saturating_add(receiver_b_delta);

        prop_assume!(sender_a_seed != sender_b_seed);
        prop_assume!(sender_a_seed != receiver_a_seed);
        prop_assume!(sender_a_seed != receiver_b_seed);
        prop_assume!(sender_b_seed != receiver_a_seed);
        prop_assume!(sender_b_seed != receiver_b_seed);
        prop_assume!(receiver_a_seed != receiver_b_seed);

        prop_assume!(funding_a <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding_b <= GlobalConfiguration::MAX_BLOCK_REWARD);

        let total_funding = funding_a.saturating_add(funding_b);

        prop_assume!(total_funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(total_funding <= GlobalConfiguration::MAX_SUPPLY);

        let amount_a = amount_a_seed % funding_a.saturating_add(1);
        let amount_b = amount_b_seed % funding_b.saturating_add(1);

        prop_assume!(amount_a > 0);
        prop_assume!(amount_b > 0);
        prop_assume!(amount_a <= GlobalConfiguration::MAX_TX_AMOUNT);
        prop_assume!(amount_b <= GlobalConfiguration::MAX_TX_AMOUNT);

        let mut chain = new_test_chain("guard_two_transfers");

        apply_reward_at_height(&mut chain.tree, sender_a_seed, funding_a, 1)
            .expect("first funding reward should apply");

        apply_reward_at_height(&mut chain.tree, sender_b_seed, funding_b, 2)
            .expect("second funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 3)
            .expect("chain should extend to transfer batch height");

        let tx_a = valid_transfer(sender_a_seed, receiver_a_seed, amount_a);
        let tx_b = valid_transfer(sender_b_seed, receiver_b_seed, amount_b);

        let batch = tx_batch(
            3,
            vec![TxKind::Transfer(tx_a), TxKind::Transfer(tx_b)],
        )
        .expect("two-transfer batch should construct");

        chain.tree
            .apply_batch(&batch)
            .expect("two independent funded transfers should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_a_seed)),
            funding_a.saturating_sub(amount_a),
            "sender A must be debited"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_b_seed)),
            funding_b.saturating_sub(amount_b),
            "sender B must be debited"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_a_seed)),
            amount_a,
            "receiver A must be credited"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_b_seed)),
            amount_b,
            "receiver B must be credited"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            total_funding,
            "two transfers must conserve total supply"
        );
    }

    // 16/25
    #[test]
    fn test_016_guard_accepts_valid_register_node_without_changing_balances_or_supply(
        register_seed in 1u64..=1_000_000u64,
    ) {
        let mut chain = new_test_chain("guard_valid_register");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to register height");

        let register = valid_register(register_seed);
        let batch = tx_batch(1, vec![TxKind::RegisterNode(register)])
            .expect("register batch should construct");

        chain.tree
            .apply_batch(&batch)
            .expect("valid register node batch should apply");

        prop_assert_eq!(
            sum_balances(&chain.tree),
            0,
            "register node batch must not change balances"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "register node batch must not issue supply"
        );

        prop_assert_eq!(
            chain.tree.rewards_issued_micro(),
            0,
            "register node batch must not issue rewards"
        );
    }

    // 17/25
    #[test]
    fn test_017_guard_rejects_invalid_register_wallet_without_mutating_state(
        probe in any::<u8>(),
    ) {
        let mut chain = new_test_chain("guard_invalid_register");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to register height");

        let register = RegisterNodeTx {
            wallet_address: [0u8; REMZAR_WALLET_LEN],
            timestamp: GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(1),
        };

        let batch = tx_batch(1, vec![TxKind::RegisterNode(register)])
            .expect("invalid register batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "invalid register wallet must be rejected"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            0,
            "invalid register rejection must not mutate balances"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "invalid register rejection must not mutate issued supply"
        );

        prop_assert!(
            probe <= u8::MAX,
            "probe keeps this as a real proptest case"
        );
    }

    // 18/25
    #[test]
    fn test_018_guard_accepts_empty_batch_at_matching_tip_without_mutation(
        height in 0u64..=8u64,
    ) {
        let mut chain = new_test_chain("guard_empty_batch_matching_tip");

        add_blocks_until_tip(&mut chain.tree, height)
            .expect("chain should extend to requested tip height");

        let batch = tx_batch(height, Vec::new())
            .expect("empty batch should construct");

        chain.tree
            .apply_batch(&batch)
            .expect("empty batch at matching tip should pass invariants");

        prop_assert_eq!(
            sum_balances(&chain.tree),
            0,
            "empty batch must not mutate balances"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "empty batch must not mutate total issued"
        );
    }

    // 19/25
    #[test]
    fn test_019_apply_block_rejects_batch_index_that_does_not_match_block_height(
        tip_height in 0u64..=8u64,
        delta in 1u64..=8u64,
    ) {
        let mut chain = new_test_chain("guard_batch_height_mismatch");

        add_blocks_until_tip(&mut chain.tree, tip_height)
            .expect("chain should extend to requested tip height");

        let next_height = tip_height.saturating_add(1);

        let previous_hash = chain
            .tree
            .get_blocks()
            .last()
            .map(|block| block.block_hash)
            .unwrap_or([0u8; 64]);

        // test_block() already creates Some("tx_batch_{height}") for non-genesis blocks.
        let block = test_block(next_height, previous_hash)
            .expect("next block should construct");

        let batch_key = block
            .batch_key
            .clone()
            .expect("non-genesis test block must have a batch key");

        let wrong_batch_height = next_height.saturating_add(delta);
        let wrong_batch = tx_batch(wrong_batch_height, Vec::new())
            .expect("wrong-height batch should construct");

        let bytes = wrong_batch
            .serialize_for_storage()
            .expect("wrong-height batch should serialize");

        chain
            ._db
            .manager()
            .write(
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                batch_key.as_bytes(),
                &bytes,
            )
            .expect("wrong-height batch should be stored under block batch key");

        let before_blocks = chain.tree.get_blocks();
        let before_sum = sum_balances(&chain.tree);

        let result = chain.tree.apply_block(&block);

        prop_assert!(
            result.is_err(),
            "apply_block must reject stored batch index that does not match block height"
        );

        prop_assert_eq!(
            chain.tree.get_blocks(),
            before_blocks,
            "batch-index mismatch must not mutate block cache"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            before_sum,
            "batch-index mismatch must not mutate balances"
        );
    }

    // 20/25
    #[test]
    fn test_020_guard_rejects_preexisting_supply_invariant_violation(
        account_seed in 1u64..=1_000_000u64,
        balance in 1u64..=1_000_000u64,
    ) {
        let mut chain = new_test_chain("guard_supply_invariant_violation");

        add_blocks_until_tip(&mut chain.tree, 0)
            .expect("chain should have genesis tip");

        chain.tree.set_balance(&wallet(account_seed), balance);

        let batch = tx_batch(0, Vec::new())
            .expect("empty batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "guard must reject state where sum balances != total_issued_micro"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(account_seed)),
            balance,
            "failed invariant check must leave existing balance unchanged"
        );
    }

    // 21/25
    #[test]
    fn test_021_guard_applies_mixed_funded_transfer_and_reward_batch(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        reward_receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        transfer_amount_seed in any::<u64>(),
        reward_amount in 1u64..=1_000_000u64,
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);
        let reward_receiver_seed = receiver_seed.saturating_add(reward_receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(sender_seed != reward_receiver_seed);
        prop_assume!(receiver_seed != reward_receiver_seed);

        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(reward_amount <= GlobalConfiguration::MAX_BLOCK_REWARD);

        let total_issued = funding.saturating_add(reward_amount);

        prop_assume!(total_issued <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(total_issued <= GlobalConfiguration::MAX_SUPPLY);

        let transfer_amount = transfer_amount_seed % funding.saturating_add(1);
        prop_assume!(transfer_amount > 0);
        prop_assume!(transfer_amount <= GlobalConfiguration::MAX_TX_AMOUNT);

        let mut chain = new_test_chain("guard_mixed_transfer_reward");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to mixed batch height");

        let transfer = valid_transfer(sender_seed, receiver_seed, transfer_amount);
        let reward = valid_reward(reward_receiver_seed, reward_amount, 2);

        let batch = tx_batch(
            2,
            vec![TxKind::Transfer(transfer), TxKind::Reward(reward)],
        )
        .expect("mixed transfer/reward batch should construct");

        chain.tree
            .apply_batch(&batch)
            .expect("funded mixed transfer/reward batch should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(sender_seed)),
            funding.saturating_sub(transfer_amount),
            "sender must be debited by transfer"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(receiver_seed)),
            transfer_amount,
            "transfer receiver must be credited"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&wallet(reward_receiver_seed)),
            reward_amount,
            "reward receiver must be credited"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            total_issued,
            "mixed batch must increase issued supply only by reward"
        );
    }

    // 22/25
    #[test]
    fn test_022_guard_rejects_transfer_that_relies_on_reward_in_same_batch_for_funds(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        reward_amount in 1u64..=1_000_000u64,
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(reward_amount <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(reward_amount <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(reward_amount <= GlobalConfiguration::MAX_TX_AMOUNT);

        let mut chain = new_test_chain("guard_same_batch_reward_spend");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to batch height");

        let reward = valid_reward(sender_seed, reward_amount, 1);
        let transfer = valid_transfer(sender_seed, receiver_seed, reward_amount);

        let batch = tx_batch(
            1,
            vec![TxKind::Reward(reward), TxKind::Transfer(transfer)],
        )
        .expect("same-batch reward/spend batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "guard must precheck transfer spend against pre-batch balance"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            0,
            "rejected same-batch reward/spend must not mutate balances"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "rejected same-batch reward/spend must not mint supply"
        );
    }

    // 23/25
    #[test]
    fn test_023_guard_reaches_same_balances_for_reordered_independent_transfers(
        sender_a_seed in 1u64..=1_000_000u64,
        sender_b_delta in 1u64..=1_000_000u64,
        receiver_a_delta in 1u64..=1_000_000u64,
        receiver_b_delta in 1u64..=1_000_000u64,
        funding_a in 1u64..=1_000_000u64,
        funding_b in 1u64..=1_000_000u64,
        amount_a_seed in any::<u64>(),
        amount_b_seed in any::<u64>(),
    ) {
        let sender_b_seed = sender_a_seed.saturating_add(sender_b_delta);
        let receiver_a_seed = sender_b_seed.saturating_add(receiver_a_delta);
        let receiver_b_seed = receiver_a_seed.saturating_add(receiver_b_delta);

        prop_assume!(sender_a_seed != sender_b_seed);
        prop_assume!(sender_a_seed != receiver_a_seed);
        prop_assume!(sender_a_seed != receiver_b_seed);
        prop_assume!(sender_b_seed != receiver_a_seed);
        prop_assume!(sender_b_seed != receiver_b_seed);
        prop_assume!(receiver_a_seed != receiver_b_seed);

        prop_assume!(funding_a <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding_b <= GlobalConfiguration::MAX_BLOCK_REWARD);

        let total_funding = funding_a.saturating_add(funding_b);

        prop_assume!(total_funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);
        prop_assume!(total_funding <= GlobalConfiguration::MAX_SUPPLY);

        let amount_a = amount_a_seed % funding_a.saturating_add(1);
        let amount_b = amount_b_seed % funding_b.saturating_add(1);

        prop_assume!(amount_a > 0);
        prop_assume!(amount_b > 0);
        prop_assume!(amount_a <= GlobalConfiguration::MAX_TX_AMOUNT);
        prop_assume!(amount_b <= GlobalConfiguration::MAX_TX_AMOUNT);

        let mut chain_a = new_test_chain("guard_reordered_a");
        let mut chain_b = new_test_chain("guard_reordered_b");

        for chain in [&mut chain_a, &mut chain_b] {
            apply_reward_at_height(&mut chain.tree, sender_a_seed, funding_a, 1)
                .expect("first funding reward should apply");

            apply_reward_at_height(&mut chain.tree, sender_b_seed, funding_b, 2)
                .expect("second funding reward should apply");

            add_blocks_until_tip(&mut chain.tree, 3)
                .expect("chain should extend to transfer height");
        }

        let tx_a = valid_transfer(sender_a_seed, receiver_a_seed, amount_a);
        let tx_b = valid_transfer(sender_b_seed, receiver_b_seed, amount_b);

        let batch_a = tx_batch(
            3,
            vec![TxKind::Transfer(tx_a.clone()), TxKind::Transfer(tx_b.clone())],
        )
        .expect("ordered batch should construct");

        let batch_b = tx_batch(
            3,
            vec![TxKind::Transfer(tx_b), TxKind::Transfer(tx_a)],
        )
        .expect("reordered batch should construct");

        chain_a.tree
            .apply_batch(&batch_a)
            .expect("ordered independent transfers should apply");

        chain_b.tree
            .apply_batch(&batch_b)
            .expect("reordered independent transfers should apply");

        prop_assert_eq!(
            chain_a.tree.get_balances(),
            chain_b.tree.get_balances(),
            "independent transfers should reach same final balances regardless of order"
        );

        prop_assert_eq!(
            chain_a.tree.total_issued_micro(),
            chain_b.tree.total_issued_micro(),
            "reordered independent transfers must preserve issued supply identically"
        );
    }

    // 24/25
    #[test]
    fn test_024_guard_apply_batch_never_panics_for_simple_external_batches(
        amount in any::<u64>(),
        case in 0usize..5usize,
    ) {
        let mut chain = new_test_chain("guard_panic_safety");

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to batch height");

        let txs = match case {
            0 => Vec::new(),
            1 => vec![TxKind::Transfer(manual_tx(1, 2, amount))],
            2 => vec![TxKind::Transfer(manual_tx(1, 1, amount))],
            3 => vec![TxKind::Reward(RewardTx {
                receiver: wallet_arr(1),
                amount,
                block_height: 1,
                timestamp: GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(1),
            })],
            _ => vec![TxKind::RegisterNode(RegisterNodeTx {
                wallet_address: [0u8; REMZAR_WALLET_LEN],
                timestamp: GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_add(1),
            })],
        };

        let batch = tx_batch(1, txs)
            .expect("simple external batch should construct");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            chain.tree.apply_batch(&batch)
        }));

        prop_assert!(
            result.is_ok(),
            "AccountGuard path through apply_batch must never panic for simple external batches"
        );
    }

    // 25/25
    #[test]
    fn test_025_failed_guard_batches_are_atomic_across_balances_and_supply(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        invalid_case in 0usize..4usize,
    ) {
        let receiver_seed = sender_seed.saturating_add(receiver_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(funding <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        let mut chain = new_test_chain("guard_failed_batch_atomicity");

        apply_reward_at_height(&mut chain.tree, sender_seed, funding, 1)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to invalid batch height");

        let before_balances = chain.tree.get_balances();
        let before_total_issued = chain.tree.total_issued_micro();
        let before_rewards_issued = chain.tree.rewards_issued_micro();

        let txs = match invalid_case {
            0 => vec![TxKind::Transfer(manual_tx(sender_seed, receiver_seed, 0))],
            1 => vec![TxKind::Transfer(manual_tx(sender_seed, sender_seed, 1))],
            2 => vec![TxKind::Transfer(manual_tx(
                sender_seed,
                receiver_seed,
                funding.saturating_add(1),
            ))],
            _ => {
                let tx = valid_transfer(sender_seed, receiver_seed, 1);
                vec![TxKind::Transfer(tx.clone()), TxKind::Transfer(tx)]
            }
        };

        let batch = tx_batch(2, txs)
            .expect("invalid atomicity batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "invalid guard batch must fail"
        );

        prop_assert_eq!(
            chain.tree.get_balances(),
            before_balances,
            "failed guard batch must not mutate balances"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            before_total_issued,
            "failed guard batch must not mutate total issued"
        );

        prop_assert_eq!(
            chain.tree.rewards_issued_micro(),
            before_rewards_issued,
            "failed guard batch must not mutate rewards issued"
        );
    }
}
