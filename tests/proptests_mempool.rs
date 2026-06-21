#![allow(clippy::too_many_lines)]

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::mempool::MemPool;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::tokens::nft_001::NftMintTx;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::alpha_003_detection_system::DetectionSystem;
use remzar::utility::hash_system_remzarhash::RemzarHash;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

const MEMPOOL_BYTES_KEY_FOR_TEST: &[u8] = b"__mempool_bytes_used_v1";

struct TestMempool {
    mempool: Option<MemPool>,
    manager: Arc<RockDBManager>,
    root: PathBuf,
}

impl TestMempool {
    fn mempool(&self) -> &MemPool {
        self.mempool
            .as_ref()
            .expect("test mempool should still be available")
    }

    fn manager(&self) -> &RockDBManager {
        self.manager.as_ref()
    }

    fn second_mempool_handle(&self) -> MemPool {
        MemPool::new(Arc::clone(&self.manager), Arc::new(DetectionSystem::new()))
    }
}

impl Drop for TestMempool {
    fn drop(&mut self) {
        drop(self.mempool.take());

        if std::fs::remove_dir_all(&self.root).is_err() {
            // Best-effort cleanup only.
        }
    }
}

fn make_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_owned(),
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "info".to_owned(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder: false,
    }
}

fn make_test_mempool(label: &str) -> TestMempool {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);

    let root = std::env::temp_dir().join(format!(
        "remzar_proptest_mempool_{label}_{}_{}",
        std::process::id(),
        id
    ));

    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }

    std::fs::create_dir_all(&root).expect("test root directory should be created");

    let opts = make_node_opts(&root);
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_str = blockchain_path
        .to_str()
        .expect("test blockchain path should be valid UTF-8");

    let manager = Arc::new(
        RockDBManager::new_blockchain(&opts, blockchain_path_str)
            .expect("test blockchain RocksDB manager should initialize"),
    );

    let detection = Arc::new(DetectionSystem::new());
    let mempool = MemPool::new(Arc::clone(&manager), detection);

    TestMempool {
        mempool: Some(mempool),
        manager,
        root,
    }
}

fn wallet_from_seed(prefix: u8, tail: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(tail.len() + 1);
    preimage.push(prefix);
    preimage.extend_from_slice(tail);

    format!("r{}", RemzarHash::compute_bytes_hash_hex(&preimage))
}

fn make_transaction(
    sender_tail: &[u8],
    receiver_tail: &[u8],
    amount: u64,
) -> Result<Transaction, ErrorDetection> {
    let sender = wallet_from_seed(0x11, sender_tail);
    let receiver = wallet_from_seed(0xA7, receiver_tail);

    Transaction::new(sender, receiver, amount.max(1))
}

fn make_indexed_transaction(
    seed_tail: &[u8],
    index: usize,
    base_amount: u64,
) -> Result<Transaction, ErrorDetection> {
    let mut sender_tail = Vec::with_capacity(seed_tail.len() + 9);
    sender_tail.extend_from_slice(&(index as u64).to_le_bytes());
    sender_tail.push(0x31);
    sender_tail.extend_from_slice(seed_tail);

    let mut receiver_tail = Vec::with_capacity(seed_tail.len() + 9);
    receiver_tail.extend_from_slice(&(index as u64).to_be_bytes());
    receiver_tail.push(0xD4);
    receiver_tail.extend_from_slice(seed_tail);

    make_transaction(
        &sender_tail,
        &receiver_tail,
        base_amount.saturating_add(index as u64).max(1),
    )
}

fn register_kind_from_tail(tail: &[u8], tag: u8) -> TxKind {
    let wallet = wallet_from_seed(tag, tail);

    TxKind::RegisterNode(
        RegisterNodeTx::new(wallet).expect("generated register-node transaction should be valid"),
    )
}

fn hash_from_tail(tag: u8, tail: &[u8]) -> Hash {
    let mut preimage = Vec::with_capacity(tail.len() + 1);
    preimage.push(tag);
    preimage.extend_from_slice(tail);

    RemzarHash::compute_bytes_hash(&preimage)
}

fn nft_mint_kind_from_parts(seed_tail: &[u8], title: String, description: String) -> TxKind {
    TxKind::NftMint(NftMintTx {
        nft_id: hash_from_tail(0xC1, seed_tail),
        content_hash: hash_from_tail(0xC2, seed_tail),
        title,
        description,
    })
}

fn txkind_hash_for_mempool_lookup(kind: &TxKind) -> Hash {
    let bytes = postcard::to_allocvec(kind).expect("TxKind should serialize");
    RemzarHash::compute_bytes_hash(&bytes)
}

fn tx_hash_for_mempool_lookup(tx: &Transaction) -> Hash {
    txkind_hash_for_mempool_lookup(&TxKind::Transfer(tx.clone()))
}

fn raw_transaction_hash(tx: &Transaction) -> Hash {
    let bytes = tx.serialize().expect("Transaction should serialize");
    RemzarHash::compute_bytes_hash(&bytes)
}

fn batch_budget_bytes_usize() -> usize {
    usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .unwrap_or(usize::MAX)
        .saturating_sub(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE)
}

fn fetch_transfer_keys_for(fetched: &[(Vec<u8>, TxKind)], wanted: &Transaction) -> Vec<Vec<u8>> {
    fetched
        .iter()
        .filter_map(|(key, kind)| match kind {
            TxKind::Transfer(tx) if tx == wanted => Some(key.clone()),
            _ => None,
        })
        .collect()
}

fn fetched_contains_transfer(fetched: &[(Vec<u8>, TxKind)], wanted: &Transaction) -> bool {
    fetched.iter().any(|(_key, kind)| match kind {
        TxKind::Transfer(tx) => tx == wanted,
        _ => false,
    })
}

fn fetched_contains_kind(fetched: &[(Vec<u8>, TxKind)], wanted: &TxKind) -> bool {
    fetched.iter().any(|(_key, kind)| kind == wanted)
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 001/25
    #[test]
    fn test_001_add_transaction_increases_mempool_size_and_fetch_returns_transfer(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("add_fetch");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            0,
            "fresh mempool should start empty"
        );

        mempool
            .add_transaction(&tx)
            .expect("valid transaction should be added to mempool");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "mempool size should increase after adding one transaction"
        );

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetching pending transactions should succeed");

        prop_assert_eq!(
            fetched.len(),
            1,
            "fetch should return the one added transaction"
        );

        match &fetched[0].1 {
            TxKind::Transfer(fetched_tx) => {
                prop_assert_eq!(
                    fetched_tx,
                    &tx,
                    "fetched transfer must equal inserted transaction"
                );
            }
            other => {
                prop_assert!(
                    false,
                    "expected fetched TxKind::Transfer, got {:?}",
                    other.tag()
                );
            }
        }
    }

    // 002/25
    #[test]
    fn test_002_add_transaction_rejects_duplicate_canonical_transaction(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("duplicate");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        mempool
            .add_transaction(&tx)
            .expect("first insertion should succeed");

        prop_assert!(
            mempool.add_transaction(&tx).is_err(),
            "second insertion of the same canonical transaction must be rejected"
        );

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "duplicate rejection must not increase mempool size"
        );
    }

    // 003/25
    #[test]
    fn test_003_get_transaction_by_canonical_hash_returns_inserted_transfer(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("get_by_hash");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let hash = tx_hash_for_mempool_lookup(&tx);

        mempool
            .add_transaction(&tx)
            .expect("valid transaction should be added");

        let fetched = mempool
            .get_transaction(&hash)
            .expect("lookup by canonical mempool hash should not error");

        prop_assert_eq!(
            fetched.as_ref(),
            Some(&tx),
            "get_transaction must return the inserted transfer for its canonical TxKind hash"
        );
    }

    // 004/25
    #[test]
    fn test_004_get_transaction_returns_none_for_unknown_hash(
        hash in any::<[u8; 64]>(),
    ) {
        let test = make_test_mempool("unknown_hash");
        let mempool = test.mempool();

        let fetched = mempool
            .get_transaction(&hash)
            .expect("unknown hash lookup should not error");

        prop_assert!(
            fetched.is_none(),
            "unknown transaction hash should return None"
        );
    }

    // 005/25
    #[test]
    fn test_005_remove_transactions_deletes_fetched_transactions_and_resets_size(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("remove_keys");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let hash = tx_hash_for_mempool_lookup(&tx);

        mempool
            .add_transaction(&tx)
            .expect("valid transaction should be added");

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetch should succeed");

        let keys = fetched
            .iter()
            .map(|(key, _kind)| key.clone())
            .collect::<Vec<Vec<u8>>>();

        prop_assert_eq!(
            keys.len(),
            1,
            "one mempool key should be fetched"
        );

        mempool
            .remove_transactions(&keys)
            .expect("removing fetched transaction key should succeed");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            0,
            "mempool should be empty after removing the only transaction"
        );

        prop_assert!(
            mempool
                .get_transaction(&hash)
                .expect("lookup after removal should not error")
                .is_none(),
            "hash index should be removed when transaction is removed"
        );
    }

    // 006/25
    #[test]
    fn test_006_fetch_transactions_for_block_respects_inserted_count_for_small_batches(
        seed_tails in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..32),
            1..8
        ),
        base_amount in 1u64..=1_000_000u64,
    ) {
        let test = make_test_mempool("small_batch");
        let mempool = test.mempool();

        let mut inserted = Vec::with_capacity(seed_tails.len());

        for (index, tail) in seed_tails.iter().enumerate() {
            let tx = make_indexed_transaction(tail, index, base_amount)
                .expect("generated transaction should construct");

            mempool
                .add_transaction(&tx)
                .expect("unique generated transaction should be added");

            inserted.push(tx);
        }

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetching transactions for block should succeed");

        prop_assert_eq!(
            fetched.len(),
            inserted.len(),
            "small bounded batch should fetch every inserted transaction"
        );

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            inserted.len(),
            "fetching should not remove transactions"
        );

        for tx in &inserted {
            prop_assert!(
                fetched_contains_transfer(&fetched, tx),
                "fetch result must contain every inserted transfer"
            );
        }
    }

    // 007/25
    #[test]
    fn test_007_remove_unknown_keys_is_safe_and_does_not_remove_existing_transactions(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
        unknown_key in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let test = make_test_mempool("remove_unknown");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        mempool
            .add_transaction(&tx)
            .expect("valid transaction should be added");

        mempool
            .remove_transactions(&[unknown_key])
            .expect("removing unknown key should be safe");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "removing unknown key must not remove existing transactions"
        );
    }

    // 008/25
    #[test]
    fn test_008_mempool_hash_uses_canonical_txkind_bytes_not_raw_transaction_bytes(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("canonical_hash_not_raw_tx");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let canonical_hash = tx_hash_for_mempool_lookup(&tx);
        let raw_hash = raw_transaction_hash(&tx);

        mempool
            .add_transaction(&tx)
            .expect("valid transaction should be added");

        let canonical_lookup = mempool
            .get_transaction(&canonical_hash)
            .expect("canonical lookup should not error");

        prop_assert_eq!(
            canonical_lookup.as_ref(),
            Some(&tx),
            "canonical TxKind hash must retrieve the transfer"
        );

        if raw_hash != canonical_hash {
            let raw_lookup = mempool
                .get_transaction(&raw_hash)
                .expect("raw transaction hash lookup should not error");

            prop_assert!(
                raw_lookup.is_none(),
                "raw Transaction serialization hash must not be accepted as the mempool hash"
            );
        }
    }

    // 009/25
    #[test]
    fn test_009_two_distinct_transfers_are_both_accepted_and_independently_retrievable(
        seed_tail in proptest::collection::vec(any::<u8>(), 0..64),
        base_amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("two_distinct_transfers");
        let mempool = test.mempool();

        let tx_a = make_indexed_transaction(&seed_tail, 0, base_amount)
            .expect("first generated transaction should construct");

        let tx_b = make_indexed_transaction(&seed_tail, 1, base_amount)
            .expect("second generated transaction should construct");

        let hash_a = tx_hash_for_mempool_lookup(&tx_a);
        let hash_b = tx_hash_for_mempool_lookup(&tx_b);

        mempool.add_transaction(&tx_a).expect("first tx should add");
        mempool.add_transaction(&tx_b).expect("second distinct tx should add");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            2,
            "two distinct transfers must occupy two mempool entries"
        );

        let lookup_a = mempool
            .get_transaction(&hash_a)
            .expect("hash A lookup should not error");

        prop_assert_eq!(
            lookup_a.as_ref(),
            Some(&tx_a),
            "first transfer must remain retrievable by its hash"
        );

        let lookup_b = mempool
            .get_transaction(&hash_b)
            .expect("hash B lookup should not error");

        prop_assert_eq!(
            lookup_b.as_ref(),
            Some(&tx_b),
            "second transfer must remain retrievable by its hash"
        );
    }

    // 010/25
    #[test]
    fn test_010_fetch_is_read_only_and_duplicate_remains_rejected_after_fetch(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("fetch_read_only_duplicate");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        mempool.add_transaction(&tx).expect("first tx should add");

        let fetched_first = mempool
            .fetch_transactions_for_block()
            .expect("first fetch should succeed");

        let fetched_second = mempool
            .fetch_transactions_for_block()
            .expect("second fetch should succeed");

        prop_assert_eq!(
            fetched_first,
            fetched_second,
            "fetching must be read-only and deterministic for an unchanged mempool"
        );

        prop_assert!(
            mempool.add_transaction(&tx).is_err(),
            "fetched transaction must still be present and duplicate-protected"
        );

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "fetching must not remove the pending transaction"
        );
    }

    // 011/25
    #[test]
    fn test_011_remove_one_fetched_key_leaves_other_transactions_and_hash_indexes(
        seed_tail in proptest::collection::vec(any::<u8>(), 0..64),
        base_amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("remove_one_leave_other");
        let mempool = test.mempool();

        let tx_a = make_indexed_transaction(&seed_tail, 0, base_amount)
            .expect("first generated transaction should construct");

        let tx_b = make_indexed_transaction(&seed_tail, 1, base_amount)
            .expect("second generated transaction should construct");

        let hash_a = tx_hash_for_mempool_lookup(&tx_a);
        let hash_b = tx_hash_for_mempool_lookup(&tx_b);

        mempool.add_transaction(&tx_a).expect("first tx should add");
        mempool.add_transaction(&tx_b).expect("second tx should add");

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetch should succeed");

        let keys_for_a = fetch_transfer_keys_for(&fetched, &tx_a);

        prop_assert_eq!(
            keys_for_a.len(),
            1,
            "exactly one fetched key should correspond to tx_a"
        );

        mempool
            .remove_transactions(&keys_for_a)
            .expect("removing one fetched key should succeed");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "removing one of two transactions must leave one pending"
        );

        let lookup_a = mempool
            .get_transaction(&hash_a)
            .expect("removed hash lookup should not error");

        prop_assert!(
            lookup_a.is_none(),
            "removed transaction hash index must be deleted"
        );

        let lookup_b = mempool
            .get_transaction(&hash_b)
            .expect("remaining hash lookup should not error");

        prop_assert_eq!(
            lookup_b.as_ref(),
            Some(&tx_b),
            "remaining transaction hash index must still resolve"
        );
    }

    // 012/25
    #[test]
    fn test_012_remove_empty_key_list_is_noop_for_existing_mempool(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("remove_empty_noop");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let hash = tx_hash_for_mempool_lookup(&tx);

        mempool.add_transaction(&tx).expect("valid tx should add");

        mempool
            .remove_transactions(&[])
            .expect("removing an empty key list should succeed");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "empty removal must not change mempool size"
        );

        let lookup = mempool
            .get_transaction(&hash)
            .expect("hash lookup should not error");

        prop_assert_eq!(
            lookup.as_ref(),
            Some(&tx),
            "empty removal must not delete hash index"
        );
    }

    // 013/25
    #[test]
    fn test_013_remove_same_key_twice_deletes_transaction_without_panic(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("remove_same_key_twice");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let hash = tx_hash_for_mempool_lookup(&tx);

        mempool.add_transaction(&tx).expect("valid tx should add");

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetch should succeed");

        prop_assert_eq!(
            fetched.len(),
            1,
            "single inserted transaction should fetch one key"
        );

        let key = fetched[0].0.clone();

        mempool
            .remove_transactions(&[key.clone(), key])
            .expect("removing the same key twice should not panic or storage-error");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            0,
            "transaction must be gone after duplicated-key removal"
        );

        prop_assert!(
            mempool
                .get_transaction(&hash)
                .expect("lookup after removal should not error")
                .is_none(),
            "hash index must be gone after duplicated-key removal"
        );
    }

    // 014/25
    #[test]
    fn test_014_remove_transactions_in_empty_batch_is_noop(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
        batch_index in any::<u64>(),
        batch_timestamp in any::<u64>(),
    ) {
        let test = make_test_mempool("empty_batch_noop");
        let mempool = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let hash = tx_hash_for_mempool_lookup(&tx);

        mempool.add_transaction(&tx).expect("valid tx should add");

        let empty_batch = TransactionBatch::new(batch_index, batch_timestamp, Vec::new())
            .expect("empty batch should construct");

        mempool
            .remove_transactions_in_batch(&empty_batch)
            .expect("empty batch removal should succeed");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "empty batch removal must not remove pending transactions"
        );

        let lookup = mempool
            .get_transaction(&hash)
            .expect("hash lookup should not error");

        prop_assert_eq!(
            lookup.as_ref(),
            Some(&tx),
            "empty batch removal must not delete hash index"
        );
    }

    // 015/25
    #[test]
    fn test_015_remove_transactions_in_batch_prunes_matching_transfer_only(
        seed_tail in proptest::collection::vec(any::<u8>(), 0..64),
        base_amount in 1u64..=1_000_000_000_000u64,
        batch_index in any::<u64>(),
        batch_timestamp in any::<u64>(),
    ) {
        let test = make_test_mempool("batch_prune_transfer_only");
        let mempool = test.mempool();

        let tx_a = make_indexed_transaction(&seed_tail, 0, base_amount)
            .expect("first generated transaction should construct");

        let tx_b = make_indexed_transaction(&seed_tail, 1, base_amount)
            .expect("second generated transaction should construct");

        let hash_a = tx_hash_for_mempool_lookup(&tx_a);
        let hash_b = tx_hash_for_mempool_lookup(&tx_b);

        mempool.add_transaction(&tx_a).expect("first tx should add");
        mempool.add_transaction(&tx_b).expect("second tx should add");

        let batch = TransactionBatch::new(
            batch_index,
            batch_timestamp,
            vec![TxKind::Transfer(tx_a.clone())],
        )
        .expect("single-transfer batch should construct");

        mempool
            .remove_transactions_in_batch(&batch)
            .expect("batch pruning should succeed");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "batch pruning one of two transfers must leave one pending"
        );

        let lookup_a = mempool
            .get_transaction(&hash_a)
            .expect("removed hash lookup should not error");

        prop_assert!(
            lookup_a.is_none(),
            "batched transfer hash must be removed"
        );

        let lookup_b = mempool
            .get_transaction(&hash_b)
            .expect("remaining hash lookup should not error");

        prop_assert_eq!(
            lookup_b.as_ref(),
            Some(&tx_b),
            "non-batched transfer must remain retrievable"
        );
    }

    // 016/25
    #[test]
    fn test_016_remove_transactions_in_batch_prunes_matching_register_node_txkind(
        register_tail in proptest::collection::vec(any::<u8>(), 0..64),
        batch_index in any::<u64>(),
        batch_timestamp in any::<u64>(),
    ) {
        let test = make_test_mempool("batch_prune_register");
        let mempool = test.mempool();

        let register_kind = register_kind_from_tail(&register_tail, 0x44);

        mempool
            .add_tx_kind(&register_kind)
            .expect("register node TxKind should add");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "register TxKind should occupy one mempool entry"
        );

        let batch = TransactionBatch::new(
            batch_index,
            batch_timestamp,
            vec![register_kind.clone()],
        )
        .expect("register-node batch should construct");

        mempool
            .remove_transactions_in_batch(&batch)
            .expect("batch pruning register TxKind should succeed");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            0,
            "register TxKind included in a batch must be pruned from mempool"
        );

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetch after register prune should succeed");

        prop_assert!(
            fetched.is_empty(),
            "no TxKinds should remain after pruning the only register entry"
        );
    }

    // 017/25
    #[test]
    fn test_017_add_tx_kind_accepts_register_node_and_get_transaction_returns_none_for_non_transfer(
        register_tail in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let test = make_test_mempool("register_non_transfer_lookup");
        let mempool = test.mempool();

        let register_kind = register_kind_from_tail(&register_tail, 0x51);
        let hash = txkind_hash_for_mempool_lookup(&register_kind);

        mempool
            .add_tx_kind(&register_kind)
            .expect("register-node TxKind should be accepted");

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetch should succeed");

        prop_assert_eq!(
            fetched.len(),
            1,
            "register-node TxKind should be fetchable"
        );

        prop_assert_eq!(
            &fetched[0].1,
            &register_kind,
            "fetched non-transfer TxKind must equal inserted register-node TxKind"
        );

        let lookup = mempool
            .get_transaction(&hash)
            .expect("hash lookup for non-transfer should not error");

        prop_assert!(
            lookup.is_none(),
            "get_transaction intentionally returns None for non-Transfer TxKind hashes"
        );
    }

    // 018/25
    #[test]
    fn test_018_add_tx_kind_rejects_duplicate_non_transfer_by_canonical_hash(
        register_tail in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let test = make_test_mempool("duplicate_register_hash");
        let mempool = test.mempool();

        let register_kind = register_kind_from_tail(&register_tail, 0x62);

        mempool
            .add_tx_kind(&register_kind)
            .expect("first register-node TxKind should be accepted");

        prop_assert!(
            mempool.add_tx_kind(&register_kind).is_err(),
            "duplicate non-transfer TxKind must be rejected by canonical hash index"
        );

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            1,
            "duplicate non-transfer rejection must not increase mempool size"
        );
    }

    // 019/25
    #[test]
    fn test_019_mixed_transfer_and_register_fetch_returns_both_variants(
        seed_tail in proptest::collection::vec(any::<u8>(), 0..64),
        register_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("mixed_transfer_register");
        let mempool = test.mempool();

        let tx = make_transaction(&seed_tail, &[0xAA, 0xBB, 0xCC], amount)
            .expect("generated transfer should construct");

        let transfer_kind = TxKind::Transfer(tx.clone());
        let register_kind = register_kind_from_tail(&register_tail, 0x73);

        mempool.add_transaction(&tx).expect("transfer should add");
        mempool.add_tx_kind(&register_kind).expect("register should add");

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("mixed fetch should succeed");

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            2,
            "mixed mempool should contain two entries"
        );

        prop_assert_eq!(
            fetched.len(),
            2,
            "mixed fetch should return both inserted TxKinds"
        );

        prop_assert!(
            fetched_contains_kind(&fetched, &transfer_kind),
            "mixed fetch must include the inserted transfer"
        );

        prop_assert!(
            fetched_contains_kind(&fetched, &register_kind),
            "mixed fetch must include the inserted register-node TxKind"
        );
    }

    // 020/25
    #[test]
    fn test_020_mempool_state_is_visible_to_new_handle_using_same_manager(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("persistent_second_handle");
        let first = test.mempool();

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let hash = tx_hash_for_mempool_lookup(&tx);

        first.add_transaction(&tx).expect("valid tx should add");

        let second = test.second_mempool_handle();

        prop_assert_eq!(
            second.mempool_size().expect("second handle size should read"),
            1,
            "new MemPool handle over same RocksDB manager must see existing entry"
        );

        let lookup = second
            .get_transaction(&hash)
            .expect("second handle lookup should not error");

        prop_assert_eq!(
            lookup.as_ref(),
            Some(&tx),
            "new MemPool handle must resolve existing hash index"
        );

        let fetched = second
            .fetch_transactions_for_block()
            .expect("second handle fetch should succeed");

        prop_assert!(
            fetched_contains_transfer(&fetched, &tx),
            "new MemPool handle must fetch existing transfer"
        );
    }

    // 021/25
    #[test]
    fn test_021_fetch_skips_malformed_transaction_column_entries_without_panicking(
        bad_key_tail in proptest::collection::vec(any::<u8>(), 1..32),
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("malformed_tx_cf");
        let mempool = test.mempool();

        let mut bad_key = b"tx_bad_".to_vec();
        bad_key.extend_from_slice(&bad_key_tail);

        test.manager()
            .write(
                GlobalConfiguration::TRANSACTION_COLUMN_NAME,
                &bad_key,
                &[0xFFu8; 32],
            )
            .expect("test should write malformed transaction column entry");

        let empty_fetch = mempool
            .fetch_transactions_for_block()
            .expect("fetch should skip malformed TxKind entry, not error");

        prop_assert!(
            empty_fetch.is_empty(),
            "malformed transaction-column entry must not be returned as batchable TxKind"
        );

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        mempool
            .add_transaction(&tx)
            .expect("valid tx should still add despite malformed stale entry");

        let fetched = mempool
            .fetch_transactions_for_block()
            .expect("fetch with valid plus malformed entry should succeed");

        prop_assert!(
            fetched_contains_transfer(&fetched, &tx),
            "fetch must still return valid transactions when malformed stale entries exist"
        );
    }

    // 022/25
    #[test]
    fn test_022_get_transaction_rejects_malformed_hash_index_payload(
        hash_seed in any::<[u8; 64]>(),
        payload in proptest::collection::vec(0x80u8..=0xFFu8, 1..64),
    ) {
        let test = make_test_mempool("malformed_hash_index");
        let mempool = test.mempool();

        test.manager()
            .write(
                GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
                &hash_seed,
                &payload,
            )
            .expect("test should write malformed hash-index payload");

        prop_assert!(
            mempool.get_transaction(&hash_seed).is_err(),
            "get_transaction must reject malformed TxKind bytes stored under a hash index"
        );
    }

    // 023/25
    #[test]
    fn test_023_corrupt_mempool_bytes_counter_blocks_new_add_without_panic(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..64),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..64),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let test = make_test_mempool("corrupt_counter");
        let mempool = test.mempool();

        test.manager()
            .write(
                GlobalConfiguration::TRANSACTION_COLUMN_NAME,
                MEMPOOL_BYTES_KEY_FOR_TEST,
                &[0x80u8; 32],
            )
            .expect("test should write corrupt mempool bytes counter");

        let tx = make_transaction(&sender_tail, &receiver_tail, amount)
            .expect("generated valid transaction should construct");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mempool.add_transaction(&tx)
        }));

        prop_assert!(
            result.is_ok(),
            "corrupt counter must return an error, not panic"
        );

        prop_assert!(
            result.expect("panic result already checked").is_err(),
            "corrupt persisted mempool byte counter must block admission instead of using bogus capacity"
        );

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            0,
            "internal corrupt counter key must not count as a pending transaction"
        );
    }

    // 024/25
    #[test]
    fn test_024_add_tx_kind_rejects_oversized_nft_mint_that_cannot_fit_batch_budget(
        seed_tail in proptest::collection::vec(any::<u8>(), 0..64),
        extra_len in 1usize..4096usize,
    ) {
        let test = make_test_mempool("oversized_nft_mint");
        let mempool = test.mempool();

        let smallest_reject_limit = batch_budget_bytes_usize()
            .min(GlobalConfiguration::MAX_ITEM_BYTES);

        let oversized_description = "x".repeat(
            smallest_reject_limit
                .saturating_add(extra_len)
                .saturating_add(256)
        );

        let kind = nft_mint_kind_from_parts(
            &seed_tail,
            "oversized nft admission test".to_owned(),
            oversized_description,
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mempool.add_tx_kind(&kind)
        }));

        prop_assert!(
            result.is_ok(),
            "oversized TxKind admission must return Err, not panic"
        );

        prop_assert!(
            result.expect("panic result already checked").is_err(),
            "oversized NFT mint TxKind must be rejected before it can enter the mempool"
        );

        prop_assert_eq!(
            mempool.mempool_size().expect("mempool size should read"),
            0,
            "oversized rejected TxKind must not be persisted"
        );
    }

    // 025/25
    #[test]
    fn test_025_public_mempool_entrypoints_never_panic_for_arbitrary_external_inputs(
        sender_tail in proptest::collection::vec(any::<u8>(), 0..128),
        receiver_tail in proptest::collection::vec(any::<u8>(), 0..128),
        amount in any::<u64>(),
        lookup_hash in any::<[u8; 64]>(),
        arbitrary_key in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let test = make_test_mempool("public_no_panic");
        let mempool = test.mempool();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = mempool.mempool_size();
            let _ = mempool.get_transaction(&lookup_hash);
            let _ = mempool.remove_transactions(&[arbitrary_key]);
            let _ = mempool.fetch_transactions_for_block();

            if let Ok(tx) = make_transaction(&sender_tail, &receiver_tail, amount.max(1)) {
                let _ = mempool.add_transaction(&tx);
                let _ = mempool.fetch_transactions_for_block();
                let _ = mempool.get_transaction(&tx_hash_for_mempool_lookup(&tx));
            }
        }));

        prop_assert!(
            result.is_ok(),
            "public mempool entrypoints must return Ok/Err, not panic, for arbitrary external inputs"
        );
    }
}
