use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_account_tree::{
    AccountModelTree, from_micro_units, to_micro_units,
};
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
    db: TestDb,
}

impl TestChain {
    fn manager(&self) -> &RockDBManager {
        self.db.manager()
    }
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("remzar_proptest_account_tree_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> String {
    path.to_str()
        .expect("test path should be valid UTF-8")
        .to_owned()
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

    TestChain { tree, db }
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

fn fixed_hash(seed: u8) -> Hash {
    [seed; 64]
}

fn seed_from_index(index: u64, offset: u8) -> u8 {
    let reduced = u8::try_from(index.rem_euclid(200)).expect("index modulo 200 should fit into u8");

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

fn manual_tx(sender: u64, receiver: u64, amount: u64) -> Transaction {
    Transaction {
        sender: wallet_arr(sender),
        receiver: wallet_arr(receiver),
        amount,
        timestamp: 1_800_020_000,
    }
}

fn sum_balances(tree: &AccountModelTree) -> u64 {
    tree.get_balances()
        .values()
        .copied()
        .try_fold(0u64, |acc, value| acc.checked_add(value))
        .expect("test balance sum should not overflow")
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

fn read_account_balance(
    manager: &RockDBManager,
    account: &str,
) -> Result<Option<u64>, ErrorDetection> {
    let maybe_bytes = manager.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, account.as_bytes())?;

    match maybe_bytes {
        Some(bytes) => {
            let value = postcard::from_bytes::<u64>(&bytes).map_err(|err| {
                ErrorDetection::SerializationError {
                    details: format!("failed to decode account balance: {err}"),
                }
            })?;

            Ok(Some(value))
        }
        None => Ok(None),
    }
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_set_increment_update_and_decrement_balance_preserve_expected_value(
        account_seed in 1u64..=1_000_000u64,
        initial in 0u64..=1_000_000_000u64,
        inc in 0u64..=1_000_000_000u64,
        update in 0u64..=1_000_000_000u64,
        dec_seed in 0u64..=1_000_000_000u64,
    ) {
        let mut chain = new_test_chain("balance_ops");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, initial);

        let after_inc = initial.saturating_add(inc);
        prop_assume!(after_inc <= GlobalConfiguration::MAX_SUPPLY);

        chain.tree
            .increment_balance(&account, inc)
            .expect("increment within supply cap should succeed");

        prop_assert_eq!(
            chain.tree.get_balance(&account),
            after_inc,
            "increment_balance must add to existing balance"
        );

        let after_update = after_inc.saturating_add(update);
        prop_assume!(after_update <= GlobalConfiguration::MAX_SUPPLY);

        chain.tree
            .update_balance(&account, update)
            .expect("update within supply cap should succeed");

        prop_assert_eq!(
            chain.tree.get_balance(&account),
            after_update,
            "update_balance must create/add balance"
        );

        let dec = dec_seed % after_update.saturating_add(1);

        chain.tree
            .decrement_balance(&account, dec)
            .expect("decrement no larger than balance should succeed");

        prop_assert_eq!(
            chain.tree.get_balance(&account),
            after_update.saturating_sub(dec),
            "decrement_balance must subtract from existing balance"
        );
    }

    // 02/25
    #[test]
    fn test_002_decrement_missing_or_underflowing_account_does_not_mutate_state(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000u64,
        extra in 1u64..=1_000_000u64,
    ) {
        let mut chain = new_test_chain("decrement_errors");
        let account = wallet(account_seed);
        let missing = wallet(account_seed.saturating_add(10_000_000));

        prop_assert!(
            chain.tree.decrement_balance(&missing, 1).is_err(),
            "decrementing missing account must error"
        );

        chain.tree.set_balance(&account, balance);

        let before = chain.tree.get_balance(&account);
        let too_much = balance.saturating_add(extra);

        prop_assert!(
            chain.tree.decrement_balance(&account, too_much).is_err(),
            "decrementing more than available balance must error"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&account),
            before,
            "failed decrement must not mutate balance"
        );
    }

    // 03/25
    #[test]
    fn test_003_increment_and_update_reject_supply_cap_excess_without_mutation(
        account_seed in 1u64..=1_000_000u64,
        excess in 1u64..=1_000_000u64,
    ) {
        let mut chain = new_test_chain("supply_cap_excess");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, GlobalConfiguration::MAX_SUPPLY);

        prop_assert!(
            chain.tree.increment_balance(&account, excess).is_err(),
            "increment above MAX_SUPPLY must fail"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&account),
            GlobalConfiguration::MAX_SUPPLY,
            "failed increment must not mutate balance"
        );

        prop_assert!(
            chain.tree.update_balance(&account, excess).is_err(),
            "update above MAX_SUPPLY must fail"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&account),
            GlobalConfiguration::MAX_SUPPLY,
            "failed update must not mutate balance"
        );
    }

    // 04/25
    #[test]
    fn test_004_apply_transaction_moves_balance_and_conserves_total(
        sender_seed in 1u64..=1_000_000u64,
        receiver_seed_delta in 1u64..=1_000_000u64,
        starting_balance in 1u64..=1_000_000_000u64,
        amount_seed in any::<u64>(),
    ) {
        let mut chain = new_test_chain("apply_transaction_valid");

        let receiver_seed = sender_seed.saturating_add(receiver_seed_delta);

        prop_assume!(sender_seed != receiver_seed);

        let sender = wallet(sender_seed);
        let receiver = wallet(receiver_seed);

        let amount = amount_seed % starting_balance.saturating_add(1);
        prop_assume!(amount > 0);
        prop_assume!(amount <= GlobalConfiguration::MAX_TX_AMOUNT);

        chain.tree.set_balance(&sender, starting_balance);
        chain.tree.set_balance(&receiver, 0);

        let before_total = sum_balances(&chain.tree);

        let tx = Transaction::new(sender.clone(), receiver.clone(), amount)
            .expect("generated valid transfer should construct");

        chain.tree
            .apply_transaction(&tx)
            .expect("valid funded transaction should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&sender),
            starting_balance.saturating_sub(amount),
            "sender balance must decrease by amount"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&receiver),
            amount,
            "receiver balance must increase by amount"
        );

        prop_assert_eq!(
            sum_balances(&chain.tree),
            before_total,
            "plain transfers must conserve total balances"
        );
    }

    // 05/25
    #[test]
    fn test_005_apply_transaction_rejects_invalid_amounts_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_seed_delta in 1u64..=1_000_000u64,
        starting_balance in 1u64..=1_000_000u64,
        invalid_case in 0usize..3usize,
    ) {
        let mut chain = new_test_chain("apply_transaction_invalid");

        let receiver_seed = sender_seed.saturating_add(receiver_seed_delta);
        prop_assume!(sender_seed != receiver_seed);

        let sender = wallet(sender_seed);
        let receiver = wallet(receiver_seed);

        chain.tree.set_balance(&sender, starting_balance);
        chain.tree.set_balance(&receiver, 0);

        let amount = match invalid_case {
            0 => 0,
            1 => starting_balance.saturating_add(1),
            _ => GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(1),
        };

        let tx = manual_tx(sender_seed, receiver_seed, amount);

        let before_sender = chain.tree.get_balance(&sender);
        let before_receiver = chain.tree.get_balance(&receiver);

        prop_assert!(
            chain.tree.apply_transaction(&tx).is_err(),
            "invalid transaction amount or insufficient balance must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&sender),
            before_sender,
            "failed transaction must not mutate sender balance"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&receiver),
            before_receiver,
            "failed transaction must not mutate receiver balance"
        );
    }

    // 06/30
    #[test]
    fn test_006_serialize_deserialize_state_roundtrip_preserves_balances_and_compact_tip_not_blocks(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 0usize..8usize,
    ) {
        let mut chain = new_test_chain("state_roundtrip_compact");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);

        add_linear_blocks(&mut chain.tree, block_count)
            .expect("adding bounded linear blocks should succeed");

        let expected_tip_height = if block_count == 0 {
            0usize
        } else {
            block_count.saturating_sub(1)
        };

        let encoded = chain.tree
            .serialize_state()
            .expect("state serialization should succeed");

        let restored = AccountModelTree::deserialize_state(
            &encoded,
            chain.manager().clone(),
        )
        .expect("state deserialization should succeed");

        prop_assert_eq!(
            restored.get_balance(&account),
            balance,
            "restored compact state must preserve account balance"
        );

        prop_assert!(
            restored.get_blocks().is_empty(),
            "compact STATE_KEY must not deserialize recent block cache/full block history"
        );

        prop_assert_eq!(
            restored.latest_block_height(),
            expected_tip_height,
            "compact state must preserve tip height metadata even though blocks are not persisted"
        );

        prop_assert_eq!(
            restored.remaining_supply_micro(),
            GlobalConfiguration::MAX_SUPPLY.saturating_sub(restored.total_issued_micro()),
            "remaining supply view must be MAX_SUPPLY - total_issued"
        );

        prop_assert_eq!(
            restored.remaining_reward_supply_micro(),
            GlobalConfiguration::MAX_REWARD_SUPPLY.saturating_sub(restored.rewards_issued_micro()),
            "remaining reward supply view must be MAX_REWARD_SUPPLY - rewards_issued"
        );
    }

    // 07/30
    #[test]
    fn test_007_commit_then_load_state_roundtrip_preserves_balances_and_compact_tip_not_blocks(
        account_a_seed in 1u64..=1_000_000u64,
        account_b_delta in 1u64..=1_000_000u64,
        balance_a in 0u64..=1_000_000_000u64,
        balance_b in 0u64..=1_000_000_000u64,
        block_count in 0usize..8usize,
    ) {
        let mut chain = new_test_chain("commit_load_roundtrip_compact");

        let account_a = wallet(account_a_seed);
        let account_b_seed = account_a_seed.saturating_add(account_b_delta);
        let account_b = wallet(account_b_seed);

        prop_assume!(account_a != account_b);

        chain.tree.set_balance(&account_a, balance_a);
        chain.tree.set_balance(&account_b, balance_b);

        add_linear_blocks(&mut chain.tree, block_count)
            .expect("adding bounded linear blocks should succeed");

        let expected_tip_height = if block_count == 0 {
            0usize
        } else {
            block_count.saturating_sub(1)
        };

        chain.tree
            .commit()
            .expect("state commit should succeed");

        let loaded = AccountModelTree::load_state(chain.manager().clone())
            .expect("committed state should load");

        prop_assert_eq!(
            loaded.get_balance(&account_a),
            balance_a,
            "loaded compact state must preserve account A balance"
        );

        prop_assert_eq!(
            loaded.get_balance(&account_b),
            balance_b,
            "loaded compact state must preserve account B balance"
        );

        prop_assert!(
            loaded.get_blocks().is_empty(),
            "loaded compact state must not preserve recent block cache/full block history"
        );

        prop_assert_eq!(
            loaded.latest_block_height(),
            expected_tip_height,
            "loaded compact state must preserve tip height metadata"
        );
    }

    // 08/25
    #[test]
    fn test_008_flush_balances_and_flush_addresses_persist_selected_account_balances(
        account_a_seed in 1u64..=1_000_000u64,
        account_b_delta in 1u64..=1_000_000u64,
        balance_a in 0u64..=1_000_000_000u64,
        balance_b in 0u64..=1_000_000_000u64,
    ) {
        let mut chain = new_test_chain("flush_balances");

        let account_a = wallet(account_a_seed);
        let account_b = wallet(account_a_seed.saturating_add(account_b_delta));

        prop_assume!(account_a != account_b);

        chain.tree.set_balance(&account_a, balance_a);
        chain.tree.set_balance(&account_b, balance_b);

        chain.tree
            .flush_addresses(vec![account_a.clone()])
            .expect("flush selected address should succeed");

        prop_assert_eq!(
            read_account_balance(chain.manager(), &account_a)
                .expect("account A balance should read"),
            Some(balance_a),
            "flush_addresses must persist selected account"
        );

        prop_assert_eq!(
            read_account_balance(chain.manager(), &account_b)
                .expect("account B balance read should succeed"),
            None,
            "flush_addresses must not persist unselected account"
        );

        chain.tree
            .flush_balances()
            .expect("flush all balances should succeed");

        prop_assert_eq!(
            read_account_balance(chain.manager(), &account_b)
                .expect("account B balance should read"),
            Some(balance_b),
            "flush_balances must persist all accounts"
        );
    }

    // 09/25
    #[test]
    fn test_009_add_block_accepts_linear_blocks_and_queues_out_of_order_child_until_parent_arrives(
        extra_blocks in 0usize..5usize,
    ) {
        let mut chain = new_test_chain("block_ordering");

        let genesis = test_block(0, [0u8; 64])
            .expect("genesis block should construct");
        let child = test_block(1, genesis.block_hash)
            .expect("child block should construct");
        let grandchild = test_block(2, child.block_hash)
            .expect("grandchild block should construct");

        chain.tree
            .add_block(genesis.clone())
            .expect("genesis should be accepted");

        chain.tree
            .add_block(grandchild.clone())
            .expect("out-of-order grandchild should queue");

        prop_assert_eq!(
            chain.tree.latest_block_height(),
            0,
            "queued out-of-order block must not advance tip before parent"
        );

        chain.tree
            .add_block(child.clone())
            .expect("missing parent should be accepted and process queued child");

        prop_assert_eq!(
            chain.tree.latest_block_height(),
            2,
            "adding missing parent must process queued grandchild"
        );

        prop_assert_eq!(
            chain.tree.get_block_by_index(0).expect("genesis should exist"),
            genesis,
            "genesis must remain at index 0"
        );

        prop_assert_eq!(
            chain.tree.get_block_by_index(1).expect("child should exist"),
            child,
            "child must be inserted at index 1"
        );

        prop_assert_eq!(
            chain.tree.get_block_by_index(2).expect("grandchild should exist"),
            grandchild,
            "queued grandchild must be inserted at index 2"
        );

        add_linear_blocks(&mut chain.tree, extra_blocks)
            .expect("extra bounded linear blocks should apply");

        prop_assert_eq!(
            chain.tree.get_blocks().len(),
            3usize.saturating_add(extra_blocks),
            "extra linear blocks must extend chain length"
        );
    }

    // 10/25
    #[test]
    fn test_010_add_block_rejects_invalid_previous_hash_without_advancing_tip(
        bad_hash_seed in any::<u8>(),
    ) {
        let mut chain = new_test_chain("bad_previous_hash");

        let genesis = test_block(0, [0u8; 64])
            .expect("genesis block should construct");

        let genesis_hash = genesis.block_hash;

        chain.tree
            .add_block(genesis.clone())
            .expect("genesis should be accepted");

        prop_assert_eq!(
            chain.tree.latest_block_height(),
            0,
            "genesis should leave tip at height 0"
        );

        prop_assert_eq!(
            chain.tree.get_block_by_index(0).expect("genesis should exist"),
            genesis,
            "genesis must be stored before testing bad child"
        );

        let before_tip_height = chain.tree.latest_block_height();
        let before_genesis = chain
            .tree
            .get_block_by_index(0)
            .expect("genesis should exist before bad child");

        let zero_hash = [0u8; 64];

        let mut chosen_bad_child: Option<(Hash, Block)> = None;

        for offset in 0u16..=255u16 {
            let seed = bad_hash_seed.wrapping_add(offset as u8);
            let candidate_previous_hash = fixed_hash(seed);

            if candidate_previous_hash == zero_hash {
                continue;
            }

            if candidate_previous_hash == genesis_hash {
                continue;
            }

            match test_block(1, candidate_previous_hash) {
                Ok(block) => {
                    chosen_bad_child = Some((candidate_previous_hash, block));
                    break;
                }
                Err(_) => {
                    continue;
                }
            }
        }

        let (bad_previous_hash, bad_child) = chosen_bad_child
            .expect("test setup must find a structurally valid child with a wrong previous_hash");

        prop_assert_ne!(
            bad_previous_hash,
            zero_hash,
            "test setup must not use all-zero previous_hash for non-genesis block"
        );

        prop_assert_ne!(
            bad_previous_hash,
            genesis_hash,
            "test setup must generate a previous_hash different from the real parent"
        );

        prop_assert_eq!(
            bad_child.metadata.index,
            1,
            "bad child must target the next block height"
        );

        prop_assert_eq!(
            bad_child.metadata.previous_hash,
            bad_previous_hash,
            "bad child must contain the selected wrong previous_hash"
        );

        let result = chain.tree.add_block(bad_child);

        prop_assert!(
            result.is_err(),
            "child with structurally valid but wrong previous_hash must be rejected"
        );

        prop_assert_eq!(
            chain.tree.latest_block_height(),
            before_tip_height,
            "bad child must not advance chain tip"
        );

        prop_assert_eq!(
            chain.tree.latest_block_height(),
            0,
            "bad child must leave tip at genesis"
        );

        prop_assert_eq!(
            chain.tree.get_block_by_index(0).expect("genesis should still exist"),
            before_genesis,
            "bad child must not mutate existing canonical genesis block"
        );

        prop_assert!(
            chain.tree.get_block_by_index(1).is_err(),
            "bad child must not be stored as canonical block #1"
        );
    }

    // 11/25
    #[test]
    fn test_011_apply_batch_reward_updates_balance_and_supply_counters(
        receiver_seed in 1u64..=1_000_000u64,
        reward_amount in 1u64..=1_000_000_000u64,
    ) {
        let mut chain = new_test_chain("apply_batch_reward");
        let receiver = wallet(receiver_seed);

        prop_assume!(reward_amount <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        fund_with_reward(&mut chain.tree, &receiver, reward_amount)
            .expect("bounded reward batch should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&receiver),
            reward_amount,
            "reward batch must credit receiver"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            reward_amount,
            "reward batch must increment total issued"
        );

        prop_assert_eq!(
            chain.tree.rewards_issued_micro(),
            reward_amount,
            "reward batch must increment rewards issued"
        );

        prop_assert_eq!(
            chain.tree.remaining_reward_supply_micro(),
            GlobalConfiguration::MAX_REWARD_SUPPLY.saturating_sub(reward_amount),
            "remaining reward supply must decrease by reward amount"
        );
    }

    // 12/25
    #[test]
    fn test_012_apply_batch_transfer_after_reward_funding_conserves_total_issued_supply(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000_000u64,
        amount_seed in any::<u64>(),
    ) {
        let mut chain = new_test_chain("apply_batch_transfer_after_reward");

        let receiver_seed = sender_seed.saturating_add(receiver_delta);
        prop_assume!(sender_seed != receiver_seed);

        let sender = wallet(sender_seed);
        let receiver = wallet(receiver_seed);

        prop_assume!(funding <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        fund_with_reward(&mut chain.tree, &sender, funding)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to transfer batch height");

        let amount = amount_seed % funding.saturating_add(1);
        prop_assume!(amount > 0);
        prop_assume!(amount <= GlobalConfiguration::MAX_TX_AMOUNT);

        let tx = Transaction::new(sender.clone(), receiver.clone(), amount)
            .expect("generated transfer should construct");

        let batch = tx_batch(2, vec![TxKind::Transfer(tx)])
            .expect("transfer batch should construct");

        chain.tree
            .apply_batch(&batch)
            .expect("funded transfer batch should apply");

        prop_assert_eq!(
            chain.tree.get_balance(&sender),
            funding.saturating_sub(amount),
            "sender balance must decrease by transfer amount"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&receiver),
            amount,
            "receiver balance must increase by transfer amount"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            funding,
            "transfer batch must not change total issued supply"
        );
    }

    // 13/25
    #[test]
    fn test_013_apply_batch_rejects_insufficient_duplicate_zero_or_same_sender_without_mutation(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        funding in 1u64..=1_000_000u64,
        case in 0usize..4usize,
    ) {
        let mut chain = new_test_chain("apply_batch_invalid_transfer");

        let receiver_seed = sender_seed.saturating_add(receiver_delta);
        prop_assume!(sender_seed != receiver_seed);

        let sender = wallet(sender_seed);
        let receiver = wallet(receiver_seed);

        fund_with_reward(&mut chain.tree, &sender, funding)
            .expect("funding reward should apply");

        add_blocks_until_tip(&mut chain.tree, 2)
            .expect("chain should extend to batch height");

        let before_sender = chain.tree.get_balance(&sender);
        let before_receiver = chain.tree.get_balance(&receiver);
        let before_total_issued = chain.tree.total_issued_micro();

        let batch = match case {
            0 => {
                let tx = manual_tx(sender_seed, receiver_seed, funding.saturating_add(1));
                tx_batch(2, vec![TxKind::Transfer(tx)])
                    .expect("insufficient transfer batch should construct")
            }
            1 => {
                let tx = Transaction::new(sender.clone(), receiver.clone(), 1)
                    .expect("valid tx should construct");
                tx_batch(2, vec![TxKind::Transfer(tx.clone()), TxKind::Transfer(tx)])
                    .expect("duplicate transfer batch should construct")
            }
            2 => {
                let tx = manual_tx(sender_seed, receiver_seed, 0);
                tx_batch(2, vec![TxKind::Transfer(tx)])
                    .expect("zero transfer batch should construct")
            }
            _ => {
                let tx = manual_tx(sender_seed, sender_seed, 1);
                tx_batch(2, vec![TxKind::Transfer(tx)])
                    .expect("same-sender transfer batch should construct")
            }
        };

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "invalid transfer batch must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&sender),
            before_sender,
            "rejected batch must not mutate sender"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&receiver),
            before_receiver,
            "rejected batch must not mutate receiver"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            before_total_issued,
            "rejected batch must not mutate issued supply counter"
        );
    }

    // 14/25
    #[test]
    fn test_014_conversion_reexports_roundtrip_for_bounded_micro_amounts(
        amount in 1u64..=1_000_000_000u64,
    ) {
        let remzar = from_micro_units(amount);
        let micro = to_micro_units(remzar);

        prop_assert_eq!(
            micro,
            amount,
            "account tree conversion reexports must roundtrip bounded micro amounts"
        );
    }

    // 15/25
    #[test]
    fn test_015_get_balance_decimal_matches_micro_unit_conversion(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
    ) {
        let mut chain = new_test_chain("balance_decimal");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);

        prop_assert_eq!(
            chain.tree.get_balance_decimal(&account),
            from_micro_units(balance),
            "get_balance_decimal must match from_micro_units(get_balance)"
        );

        prop_assert_eq!(
            chain.tree.get_balance_decimal(&wallet(account_seed.saturating_add(999_999))),
            0.0,
            "missing account decimal balance must be zero"
        );
    }

    // 16/25
    #[test]
    fn test_016_get_block_by_index_reports_existing_blocks_and_rejects_missing_index(
        block_count in 1usize..8usize,
        missing_delta in 1usize..8usize,
    ) {
        let mut chain = new_test_chain("get_block_by_index");

        let blocks = add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        for (idx, expected) in blocks.iter().enumerate() {
            prop_assert_eq!(
                chain.tree.get_block_by_index(idx).expect("existing block should be found"),
                expected.clone(),
                "get_block_by_index must return the exact stored block"
            );
        }

        let missing_idx = block_count.saturating_add(missing_delta);

        prop_assert!(
            chain.tree.get_block_by_index(missing_idx).is_err(),
            "get_block_by_index must reject missing block index"
        );
    }

    // 17/25
    #[test]
    fn test_017_duplicate_or_old_block_is_ignored_without_changing_chain_length(
        extra_blocks in 0usize..5usize,
    ) {
        let mut chain = new_test_chain("duplicate_old_block");

        let blocks = add_linear_blocks(&mut chain.tree, 3usize.saturating_add(extra_blocks))
            .expect("bounded linear blocks should apply");

        let before = chain.tree.get_blocks();
        let old_block = blocks
            .first()
            .expect("at least one block should exist")
            .clone();

        chain.tree
            .add_block(old_block)
            .expect("old block should be ignored as duplicate/old");

        prop_assert_eq!(
            chain.tree.get_blocks(),
            before,
            "adding duplicate/old block must not mutate canonical chain"
        );
    }

    // 18/25
    #[test]
    fn test_018_serialize_state_is_deterministic_for_unchanged_state(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 0usize..8usize,
    ) {
        let mut chain = new_test_chain("state_deterministic");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);

        add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        let encoded_a = chain.tree
            .serialize_state()
            .expect("first state serialization should succeed");

        let encoded_b = chain.tree
            .serialize_state()
            .expect("second state serialization should succeed");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "serializing unchanged account state twice must produce identical bytes"
        );

        prop_assert!(
            !encoded_a.is_empty(),
            "serialized account state must not be empty"
        );
    }

    // 19/25
    #[test]
    fn test_019_deserialize_state_rejects_truncated_serialized_state(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 0usize..8usize,
        keep_seed in any::<usize>(),
    ) {
        let mut chain = new_test_chain("state_truncated");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);

        add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        let encoded = chain.tree
            .serialize_state()
            .expect("state serialization should succeed");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            AccountModelTree::deserialize_state(truncated, chain.manager().clone()).is_err(),
            "deserialize_state must reject truncated state bytes"
        );
    }

    // 20/25
    #[test]
    fn test_020_deserialize_state_rejects_trailing_bytes_after_valid_state(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        extra in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let mut chain = new_test_chain("state_trailing_bytes");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);

        let mut encoded = chain.tree
            .serialize_state()
            .expect("state serialization should succeed");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            AccountModelTree::deserialize_state(&encoded, chain.manager().clone()).is_err(),
            "deserialize_state must reject non-canonical state bytes with trailing data"
        );
    }

    // 21/25
    #[test]
    fn test_021_load_state_rejects_missing_committed_state(
        probe in any::<u8>(),
    ) {
        let db = new_blockchain_db("load_state_missing");

        prop_assert!(
            AccountModelTree::load_state(db.manager().clone()).is_err(),
            "load_state must reject a DB with no committed account state"
        );

        prop_assert!(
            probe <= u8::MAX,
            "generated probe keeps this as a real proptest case"
        );
    }

    // 22/25
    #[test]
    fn test_022_flush_balances_for_batch_persists_only_touched_transfer_accounts(
        sender_seed in 1u64..=1_000_000u64,
        receiver_delta in 1u64..=1_000_000u64,
        untouched_delta in 1u64..=1_000_000u64,
        sender_balance in 0u64..=1_000_000_000u64,
        receiver_balance in 0u64..=1_000_000_000u64,
        untouched_balance in 0u64..=1_000_000_000u64,
        amount_seed in any::<u64>(),
    ) {
        let mut chain = new_test_chain("flush_for_batch");

        let receiver_seed = sender_seed.saturating_add(receiver_delta);
        let untouched_seed = receiver_seed.saturating_add(untouched_delta);

        prop_assume!(sender_seed != receiver_seed);
        prop_assume!(sender_seed != untouched_seed);
        prop_assume!(receiver_seed != untouched_seed);

        let sender = wallet(sender_seed);
        let receiver = wallet(receiver_seed);
        let untouched = wallet(untouched_seed);

        chain.tree.set_balance(&sender, sender_balance);
        chain.tree.set_balance(&receiver, receiver_balance);
        chain.tree.set_balance(&untouched, untouched_balance);

        let amount = amount_seed % 1_000_000u64.saturating_add(1);
        let amount = amount.max(1);

        let tx = Transaction::new(sender.clone(), receiver.clone(), amount)
            .expect("valid transfer should construct");

        let batch = tx_batch(1, vec![TxKind::Transfer(tx)])
            .expect("transfer batch should construct");

        chain.tree
            .flush_balances_for_batch(&batch)
            .expect("flush_balances_for_batch should persist touched accounts");

        prop_assert_eq!(
            read_account_balance(chain.manager(), &sender)
                .expect("sender account read should succeed"),
            Some(sender_balance),
            "sender touched by batch must be flushed"
        );

        prop_assert_eq!(
            read_account_balance(chain.manager(), &receiver)
                .expect("receiver account read should succeed"),
            Some(receiver_balance),
            "receiver touched by batch must be flushed"
        );

        prop_assert_eq!(
            read_account_balance(chain.manager(), &untouched)
                .expect("untouched account read should succeed"),
            None,
            "untouched account must not be flushed by flush_balances_for_batch"
        );
    }

    // 23/25
    #[test]
    fn test_023_scheduled_reward_supply_views_are_bounded_and_decimal_consistent(
        block_count in 0usize..8usize,
        height in 0u64..=1_000_000u64,
    ) {
        let mut chain = new_test_chain("scheduled_reward_views");

        add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        let scheduled_remaining = chain
            .tree
            .remaining_reward_supply_micro_after_height_scheduled(height);

        prop_assert!(
            scheduled_remaining <= u64::MAX,
            "scheduled remaining reward supply must fit u64"
        );

        prop_assert_eq!(
            chain.tree.remaining_reward_supply_aos_after_height_scheduled(height),
            from_micro_units(scheduled_remaining),
            "scheduled reward AOS view must match micro-unit conversion"
        );

        prop_assert_eq!(
            chain.tree.remaining_reward_supply_aos_scheduled_now(),
            from_micro_units(chain.tree.remaining_reward_supply_micro_scheduled_now()),
            "scheduled-now AOS view must match scheduled-now micro view"
        );
    }

    // 24/25
    #[test]
    fn test_024_apply_batch_rejects_duplicate_rewards_without_mutating_supply_or_balances(
        receiver_seed in 1u64..=1_000_000u64,
        reward_amount in 1u64..=1_000_000u64,
    ) {
        let mut chain = new_test_chain("duplicate_rewards");

        let receiver = wallet(receiver_seed);

        prop_assume!(reward_amount <= GlobalConfiguration::MAX_BLOCK_REWARD);
        prop_assume!(reward_amount <= GlobalConfiguration::MAX_REWARD_SUPPLY);

        add_blocks_until_tip(&mut chain.tree, 1)
            .expect("chain should extend to reward batch height");

        let reward_a = RewardTx::new(receiver.clone(), reward_amount, 1)
            .expect("first reward should construct");

        let reward_b = RewardTx::new(receiver.clone(), reward_amount, 1)
            .expect("second reward should construct");

        let batch = tx_batch(
            1,
            vec![TxKind::Reward(reward_a), TxKind::Reward(reward_b)],
        )
        .expect("duplicate reward batch should construct");

        prop_assert!(
            chain.tree.apply_batch(&batch).is_err(),
            "duplicate reward batch must be rejected"
        );

        prop_assert_eq!(
            chain.tree.get_balance(&receiver),
            0,
            "rejected duplicate reward batch must not credit receiver"
        );

        prop_assert_eq!(
            chain.tree.total_issued_micro(),
            0,
            "rejected duplicate reward batch must not change total issued"
        );

        prop_assert_eq!(
            chain.tree.rewards_issued_micro(),
            0,
            "rejected duplicate reward batch must not change rewards issued"
        );
    }

    // 25/25
    #[test]
    fn test_025_deserialize_state_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let db = new_blockchain_db("state_panic_safety");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AccountModelTree::deserialize_state(&data, db.manager().clone())
        }));

        prop_assert!(
            result.is_ok(),
            "deserialize_state must never panic for arbitrary external bytes"
        );
    }

    // 26/30
    #[test]
    fn test_026_compact_state_serialization_does_not_persist_recent_blocks(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 1usize..16usize,
    ) {
        let mut chain = new_test_chain("compact_no_recent_blocks");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);

        add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        prop_assert_eq!(
            chain.tree.get_blocks().len(),
            block_count,
            "live tree should have recent block cache before serialization"
        );

        let encoded = chain.tree
            .serialize_state()
            .expect("compact state serialization should succeed");

        let restored = AccountModelTree::deserialize_state(
            &encoded,
            chain.manager().clone(),
        )
        .expect("compact state deserialization should succeed");

        prop_assert_eq!(restored.get_balance(&account), balance);
        prop_assert!(
            restored.get_blocks().is_empty(),
            "serialized compact state must drop the recent block cache"
        );
        prop_assert_eq!(
            restored.latest_block_height(),
            block_count.saturating_sub(1),
            "compact tip height must survive without serializing blocks"
        );
    }

    // 27/30
    #[test]
    fn test_027_compact_state_commit_load_does_not_reinflate_block_history(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 1usize..16usize,
    ) {
        let mut chain = new_test_chain("compact_commit_no_history");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);

        add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        chain.tree
            .commit()
            .expect("compact state commit should succeed");

        let loaded = AccountModelTree::load_state(chain.manager().clone())
            .expect("compact committed state should load");

        prop_assert_eq!(loaded.get_balance(&account), balance);
        prop_assert!(
            loaded.get_blocks().is_empty(),
            "load_state must not reinflate full block history from STATE_KEY"
        );
        prop_assert_eq!(
            loaded.latest_block_height(),
            block_count.saturating_sub(1),
            "load_state must preserve compact tip height"
        );
    }

    // 28/30
    #[test]
    fn test_028_compact_state_size_is_not_linear_in_recent_block_count(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 1usize..32usize,
    ) {
        let account = wallet(account_seed);

        let mut empty_chain = new_test_chain("compact_size_empty_blocks");
        empty_chain.tree.set_balance(&account, balance);
        let encoded_without_blocks = empty_chain.tree
            .serialize_state()
            .expect("empty compact state serialization should succeed");

        let mut block_chain = new_test_chain("compact_size_with_blocks");
        block_chain.tree.set_balance(&account, balance);
        add_linear_blocks(&mut block_chain.tree, block_count)
            .expect("bounded linear blocks should apply");
        let encoded_with_blocks = block_chain.tree
            .serialize_state()
            .expect("compact state with recent blocks should serialize");

        prop_assert_eq!(
            encoded_with_blocks.len(),
            encoded_without_blocks.len(),
            "STATE_KEY size must not grow with recent block cache length"
        );
    }

    // 29/30
    #[test]
    fn test_029_deserialize_then_reserialize_keeps_state_compact_blockless_and_canonicalizes_supply(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 1usize..16usize,
    ) {
        let mut chain = new_test_chain("compact_reserialize");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);
        add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        let encoded = chain.tree
            .serialize_state()
            .expect("state serialization should succeed");

        let restored = AccountModelTree::deserialize_state(
            &encoded,
            chain.manager().clone(),
        )
        .expect("state deserialization should succeed");

        prop_assert!(
            restored.get_blocks().is_empty(),
            "deserialized compact state must not restore recent block cache"
        );

        prop_assert_eq!(
            restored.get_balance(&account),
            balance,
            "deserialized compact state must preserve balance"
        );

        prop_assert_eq!(
            restored.latest_block_height(),
            if block_count == 0 {
                0
            } else {
                block_count.saturating_sub(1)
            },
            "deserialized compact state must preserve compact tip height"
        );

        let encoded_canonical = restored
            .serialize_state()
            .expect("reserializing compact state should succeed");

        let restored_again = AccountModelTree::deserialize_state(
            &encoded_canonical,
            chain.manager().clone(),
        )
        .expect("canonical compact state should deserialize again");

        prop_assert!(
            restored_again.get_blocks().is_empty(),
            "canonical compact state must remain blockless after second decode"
        );

        prop_assert_eq!(
            restored_again.get_balance(&account),
            balance,
            "canonical compact state must preserve balance after second decode"
        );

        let encoded_canonical_again = restored_again
            .serialize_state()
            .expect("second canonical reserialization should succeed");

        prop_assert_eq!(
            encoded_canonical_again,
            encoded_canonical,
            "canonical compact state must be stable after supply backfill"
        );
    }

    // 30/30
    #[test]
    fn test_030_recent_block_cache_is_runtime_only_after_compact_db_roundtrip(
        account_seed in 1u64..=1_000_000u64,
        balance in 0u64..=1_000_000_000u64,
        block_count in 1usize..16usize,
    ) {
        let mut chain = new_test_chain("compact_db_runtime_cache_only");
        let account = wallet(account_seed);

        chain.tree.set_balance(&account, balance);
        add_linear_blocks(&mut chain.tree, block_count)
            .expect("bounded linear blocks should apply");

        let live_blocks = chain.tree.get_blocks();
        prop_assert_eq!(live_blocks.len(), block_count);

        chain.manager()
            .store_state(&chain.tree)
            .expect("manager should store compact state");

        let loaded = chain.manager()
            .load_state()
            .expect("manager should load compact state");

        prop_assert_eq!(loaded.get_balance(&account), balance);
        prop_assert!(
            loaded.get_blocks().is_empty(),
            "RocksDB STATE_KEY roundtrip must not persist runtime recent block cache"
        );
        prop_assert_eq!(
            loaded.latest_block_height(),
            block_count.saturating_sub(1),
            "RocksDB STATE_KEY roundtrip must preserve compact tip height"
        );
    }

}
