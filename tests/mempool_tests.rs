// tests/mempool_tests.rs

use remzar::blockchain::mempool::MemPool;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_003_detection_system::DetectionSystem;
use remzar::utility::hash_system_remzarhash::RemzarHash;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const TEST_MEMPOOL_BYTES_KEY: &[u8] = b"__mempool_bytes_used_v1";

struct MempoolCtx {
    db: Arc<RockDBManager>,
    mempool: MemPool,
}

fn write_raw_mempool_entry(ctx: &MempoolCtx, key: &[u8], value: &[u8]) {
    let db = match ctx.db.open_db_blockchain() {
        Ok(db) => db,
        Err(err) => panic!("open_db_blockchain failed: {err:?}"),
    };

    let cf = match db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME) {
        Some(cf) => cf,
        None => panic!("transaction column family missing"),
    };

    match db.put_cf(cf, key, value) {
        Ok(()) => {}
        Err(err) => panic!("raw mempool put_cf failed: {err:?}"),
    }
}

fn write_raw_hash_entry(ctx: &MempoolCtx, hash: &Hash, value: &[u8]) {
    let db = match ctx.db.open_db_blockchain() {
        Ok(db) => db,
        Err(err) => panic!("open_db_blockchain failed: {err:?}"),
    };

    let cf = match db.cf_handle(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME) {
        Some(cf) => cf,
        None => panic!("tx hash column family missing"),
    };

    match db.put_cf(cf, hash, value) {
        Ok(()) => {}
        Err(err) => panic!("raw hash-index put_cf failed: {err:?}"),
    }
}

fn read_raw_tx_entry(ctx: &MempoolCtx, key: &[u8]) -> Option<Vec<u8>> {
    match ctx
        .db
        .read(GlobalConfiguration::TRANSACTION_COLUMN_NAME, key)
    {
        Ok(value) => value,
        Err(err) => panic!("raw tx read failed: {err:?}"),
    }
}

fn read_raw_hash_entry(ctx: &MempoolCtx, hash: &Hash) -> Option<Vec<u8>> {
    match ctx
        .db
        .read(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME, hash)
    {
        Ok(value) => value,
        Err(err) => panic!("raw hash read failed: {err:?}"),
    }
}

fn batch_from_kinds(index: u64, kinds: Vec<TxKind>) -> TransactionBatch {
    match TransactionBatch::new(index, 1_700_000_000u64.saturating_add(index), kinds) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    }
}

fn err_to_string<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn wallet_u64(seed: u64) -> String {
    format!("r{:0128x}", seed.saturating_add(1))
}

fn unique_test_dir(name: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "remzar_mempool_tests_{name}_{}_{}",
        std::process::id(),
        id
    ));

    if fs::remove_dir_all(&dir).is_err() {
        // Nothing to clean.
    }

    dir
}

fn path_to_string(path: &Path) -> Result<String, String> {
    match path.to_str() {
        Some(s) => Ok(s.to_owned()),
        None => Err(format!("path is not valid UTF-8: {}", path.display())),
    }
}

fn new_db(name: &str) -> Result<Arc<RockDBManager>, String> {
    let base_dir = unique_test_dir(name);
    let blockchain_dir = base_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);

    let mut opts = NodeOpts::default();
    opts.data_dir = path_to_string(&base_dir)?;
    opts.identity_file = path_to_string(&base_dir.join("identity.key"))?;
    opts.wallet_address = wallet_u64(1);

    let blockchain_dir_str = path_to_string(&blockchain_dir)?;
    let db_inner =
        RockDBManager::new_blockchain(&opts, &blockchain_dir_str).map_err(err_to_string)?;

    db_inner.set_latest_block_index(0).map_err(err_to_string)?;
    db_inner.set_tip_height(0).map_err(err_to_string)?;

    Ok(Arc::new(db_inner))
}

fn new_ctx(name: &str) -> MempoolCtx {
    let db = match new_db(name) {
        Ok(db) => db,
        Err(err) => panic!("failed to create db: {err}"),
    };

    let detection = Arc::new(DetectionSystem::new());
    let mempool = MemPool::new(Arc::clone(&db), detection);

    MempoolCtx { db, mempool }
}

fn transfer(seed: u64, amount: u64) -> Transaction {
    match Transaction::new(
        wallet_u64(seed),
        wallet_u64(seed.saturating_add(10_000)),
        amount,
    ) {
        Ok(tx) => tx,
        Err(err) => panic!("Transaction::new failed for seed {seed}: {err:?}"),
    }
}

fn transfer_kind(seed: u64, amount: u64) -> TxKind {
    TxKind::Transfer(transfer(seed, amount))
}

fn register_kind(seed: u64) -> TxKind {
    let tx = match RegisterNodeTx::new(wallet_u64(seed)) {
        Ok(tx) => tx,
        Err(err) => panic!("RegisterNodeTx::new failed for seed {seed}: {err:?}"),
    };

    TxKind::RegisterNode(tx)
}

fn kind_hash(kind: &TxKind) -> Hash {
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind::serialize failed: {err:?}"),
    };

    RemzarHash::compute_bytes_hash(&bytes)
}

fn assert_result_err_contains<T, E: core::fmt::Debug>(result: Result<T, E>, needle: &str) {
    match result {
        Ok(_value) => panic!("expected error containing '{needle}', got Ok"),
        Err(err) => {
            let text = format!("{err:?}");
            let text_lower = text.to_ascii_lowercase();
            let needle_lower = needle.to_ascii_lowercase();

            assert!(
                text_lower.contains(&needle_lower),
                "expected error containing '{needle}', got: {text}"
            );
        }
    }
}

fn fetched_kinds(ctx: &MempoolCtx) -> Vec<TxKind> {
    match ctx.mempool.fetch_transactions_for_block() {
        Ok(entries) => entries.into_iter().map(|(_key, kind)| kind).collect(),
        Err(err) => panic!("fetch_transactions_for_block failed: {err:?}"),
    }
}

fn fetched_entries(ctx: &MempoolCtx) -> Vec<(Vec<u8>, TxKind)> {
    match ctx.mempool.fetch_transactions_for_block() {
        Ok(entries) => entries,
        Err(err) => panic!("fetch_transactions_for_block failed: {err:?}"),
    }
}

fn mempool_size(ctx: &MempoolCtx) -> usize {
    match ctx.mempool.mempool_size() {
        Ok(size) => size,
        Err(err) => panic!("mempool_size failed: {err:?}"),
    }
}

fn add_kind(ctx: &MempoolCtx, kind: &TxKind) {
    match ctx.mempool.add_tx_kind(kind) {
        Ok(()) => {}
        Err(err) => panic!("add_tx_kind failed: {err:?}"),
    }
}

fn add_transfer(ctx: &MempoolCtx, tx: &Transaction) {
    match ctx.mempool.add_transaction(tx) {
        Ok(()) => {}
        Err(err) => panic!("add_transaction failed: {err:?}"),
    }
}

#[test]
fn mempool_01_vector_new_starts_empty() {
    let ctx = new_ctx("vector_new_starts_empty");

    assert_eq!(mempool_size(&ctx), 0);
    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_02_vector_add_transfer_increments_size_to_one() {
    let ctx = new_ctx("vector_add_transfer_increments_size_to_one");
    let tx = transfer(2, 1);

    add_transfer(&ctx, &tx);

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_03_vector_add_tx_kind_transfer_is_fetchable() {
    let ctx = new_ctx("vector_add_tx_kind_transfer_is_fetchable");
    let kind = transfer_kind(3, 55);

    add_kind(&ctx, &kind);

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], kind);
}

#[test]
fn mempool_04_vector_add_register_node_txkind_is_fetchable() {
    let ctx = new_ctx("vector_add_register_node_txkind_is_fetchable");
    let kind = register_kind(4);

    add_kind(&ctx, &kind);

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], kind);
}

#[test]
fn mempool_05_vector_add_transfer_and_register_fetches_both() {
    let ctx = new_ctx("vector_add_transfer_and_register_fetches_both");
    let transfer = transfer_kind(5, 100);
    let register = register_kind(6);

    add_kind(&ctx, &transfer);
    add_kind(&ctx, &register);

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched.len(), 2);
    assert!(fetched.iter().any(|k| k == &transfer));
    assert!(fetched.iter().any(|k| k == &register));
}

#[test]
fn mempool_06_edge_duplicate_same_transfer_is_rejected() {
    let ctx = new_ctx("edge_duplicate_same_transfer_is_rejected");
    let tx = transfer(7, 100);

    add_transfer(&ctx, &tx);

    let result = ctx.mempool.add_transaction(&tx);

    assert_result_err_contains(result, "duplicate");
    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_07_edge_duplicate_same_register_hash_is_rejected() {
    let ctx = new_ctx("edge_duplicate_same_register_hash_is_rejected");
    let kind = register_kind(8);

    add_kind(&ctx, &kind);

    let result = ctx.mempool.add_tx_kind(&kind);

    assert_result_err_contains(result, "duplicate");
    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_08_vector_get_transaction_by_hash_returns_transfer() {
    let ctx = new_ctx("vector_get_transaction_by_hash_returns_transfer");
    let tx = transfer(9, 250);
    let kind = TxKind::Transfer(tx.clone());
    let hash = kind_hash(&kind);

    add_transfer(&ctx, &tx);

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(Some(tx)) => tx,
        Ok(None) => panic!("expected transfer by hash"),
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert_eq!(got, tx);
}

#[test]
fn mempool_09_vector_get_transaction_unknown_hash_returns_none() {
    let ctx = new_ctx("vector_get_transaction_unknown_hash_returns_none");

    let got = match ctx.mempool.get_transaction(&[9u8; 64]) {
        Ok(v) => v,
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert!(got.is_none());
}

#[test]
fn mempool_10_vector_get_transaction_for_register_hash_returns_none() {
    let ctx = new_ctx("vector_get_transaction_for_register_hash_returns_none");
    let kind = register_kind(10);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(v) => v,
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert!(got.is_none());
}

#[test]
fn mempool_11_vector_fetch_returns_mempool_keys() {
    let ctx = new_ctx("vector_fetch_returns_mempool_keys");
    let kind = transfer_kind(11, 111);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);

    assert_eq!(entries.len(), 1);
    assert!(!entries[0].0.is_empty());
    assert_eq!(entries[0].1, kind);
}

#[test]
fn mempool_12_vector_remove_fetched_key_empties_single_entry() {
    let ctx = new_ctx("vector_remove_fetched_key_empties_single_entry");
    let kind = transfer_kind(12, 100);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_13_vector_remove_one_of_two_keeps_other() {
    let ctx = new_ctx("vector_remove_one_of_two_keeps_other");
    let first = transfer_kind(13, 100);
    let second = transfer_kind(14, 200);

    add_kind(&ctx, &first);
    add_kind(&ctx, &second);

    let entries = fetched_entries(&ctx);
    assert_eq!(entries.len(), 2);

    let remove_key = vec![entries[0].0.clone()];
    let removed_kind = entries[0].1.clone();

    match ctx.mempool.remove_transactions(&remove_key) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    let remaining = fetched_kinds(&ctx);
    assert_eq!(remaining.len(), 1);
    assert_ne!(remaining[0], removed_kind);
}

#[test]
fn mempool_14_edge_remove_empty_key_list_is_noop() {
    let ctx = new_ctx("edge_remove_empty_key_list_is_noop");
    let kind = transfer_kind(15, 100);

    add_kind(&ctx, &kind);

    match ctx.mempool.remove_transactions(&[]) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions empty failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_15_edge_remove_nonexistent_key_is_noop() {
    let ctx = new_ctx("edge_remove_nonexistent_key_is_noop");
    let kind = transfer_kind(16, 100);

    add_kind(&ctx, &kind);

    match ctx.mempool.remove_transactions(&[b"not-present".to_vec()]) {
        Ok(()) => {}
        Err(err) => panic!("remove nonexistent failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_16_edge_remove_same_key_twice_is_idempotent() {
    let ctx = new_ctx("edge_remove_same_key_twice_is_idempotent");
    let kind = transfer_kind(17, 100);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);
    let key = entries[0].0.clone();

    match ctx.mempool.remove_transactions(&[key.clone()]) {
        Ok(()) => {}
        Err(err) => panic!("first remove failed: {err:?}"),
    }

    match ctx.mempool.remove_transactions(&[key]) {
        Ok(()) => {}
        Err(err) => panic!("second remove failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_17_vector_remove_transactions_in_empty_batch_is_noop() {
    let ctx = new_ctx("vector_remove_transactions_in_empty_batch_is_noop");
    let kind = transfer_kind(18, 100);

    add_kind(&ctx, &kind);

    let batch = match TransactionBatch::new(1, 1_700_000_000, Vec::new()) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_18_vector_remove_transactions_in_batch_removes_matching_transfer() {
    let ctx = new_ctx("vector_remove_transactions_in_batch_removes_matching_transfer");
    let kind = transfer_kind(19, 100);

    add_kind(&ctx, &kind);

    let batch = match TransactionBatch::new(1, 1_700_000_000, vec![kind]) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_19_vector_remove_transactions_in_batch_removes_matching_register() {
    let ctx = new_ctx("vector_remove_transactions_in_batch_removes_matching_register");
    let kind = register_kind(20);

    add_kind(&ctx, &kind);

    let batch = match TransactionBatch::new(1, 1_700_000_000, vec![kind]) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_20_vector_remove_transactions_in_batch_keeps_non_matching_tx() {
    let ctx = new_ctx("vector_remove_transactions_in_batch_keeps_non_matching_tx");
    let kept = transfer_kind(21, 100);
    let absent = transfer_kind(22, 200);

    add_kind(&ctx, &kept);

    let batch = match TransactionBatch::new(1, 1_700_000_000, vec![absent]) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 1);
    assert_eq!(fetched_kinds(&ctx), vec![kept]);
}

#[test]
fn mempool_21_property_hash_lookup_removed_after_remove_transactions() {
    let ctx = new_ctx("property_hash_lookup_removed_after_remove_transactions");
    let tx = transfer(23, 100);
    let kind = TxKind::Transfer(tx);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(v) => v,
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert!(got.is_none());
}

#[test]
fn mempool_22_property_hash_lookup_removed_after_batch_prune() {
    let ctx = new_ctx("property_hash_lookup_removed_after_batch_prune");
    let tx = transfer(24, 100);
    let kind = TxKind::Transfer(tx);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    let batch = match TransactionBatch::new(1, 1_700_000_000, vec![kind]) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(v) => v,
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert!(got.is_none());
}

#[test]
fn mempool_23_fuzz_malformed_entries_are_skipped_by_fetch() {
    let ctx = new_ctx("fuzz_malformed_entries_are_skipped_by_fetch");

    write_raw_mempool_entry(&ctx, b"bad_1", b"");
    write_raw_mempool_entry(&ctx, b"bad_2", &[0u8]);
    write_raw_mempool_entry(&ctx, b"bad_3", &[1u8, 2, 3, 4]);
    write_raw_mempool_entry(&ctx, b"bad_4", &[255u8; 32]);

    assert_eq!(mempool_size(&ctx), 4);
    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_24_fuzz_malformed_plus_valid_fetches_only_valid() {
    let ctx = new_ctx("fuzz_malformed_plus_valid_fetches_only_valid");
    let kind = register_kind(25);

    write_raw_mempool_entry(&ctx, b"bad_before", b"bad-payload");
    add_kind(&ctx, &kind);
    write_raw_mempool_entry(&ctx, b"bad_after", &[255u8; 64]);

    let fetched = fetched_kinds(&ctx);

    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], kind);
}

#[test]
fn mempool_25_vector_direct_valid_txkind_bytes_are_fetchable() {
    let ctx = new_ctx("vector_direct_valid_txkind_bytes_are_fetchable");
    let kind = register_kind(26);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_valid", &bytes);

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], kind);
}

#[test]
fn mempool_26_property_add_many_register_nodes_all_fetchable() {
    let ctx = new_ctx("property_add_many_register_nodes_all_fetchable");

    for seed in 30u64..40u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    assert_eq!(mempool_size(&ctx), 10);
    assert_eq!(fetched_entries(&ctx).len(), 10);
}

#[test]
fn mempool_27_property_add_many_transfers_all_fetchable() {
    let ctx = new_ctx("property_add_many_transfers_all_fetchable");

    for seed in 40u64..50u64 {
        add_kind(&ctx, &transfer_kind(seed, seed.saturating_add(1)));
    }

    assert_eq!(mempool_size(&ctx), 10);
    assert_eq!(fetched_entries(&ctx).len(), 10);
}

#[test]
fn mempool_28_property_mixed_many_kinds_all_fetchable() {
    let ctx = new_ctx("property_mixed_many_kinds_all_fetchable");

    for seed in 50u64..55u64 {
        add_kind(&ctx, &transfer_kind(seed, 100));
        add_kind(&ctx, &register_kind(seed.saturating_add(100)));
    }

    assert_eq!(mempool_size(&ctx), 10);
    assert_eq!(fetched_entries(&ctx).len(), 10);
}

#[test]
fn mempool_29_load_thirty_two_register_nodes_fetch_without_loss() {
    let ctx = new_ctx("load_thirty_two_register_nodes_fetch_without_loss");

    for seed in 100u64..132u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    let entries = fetched_entries(&ctx);

    assert_eq!(mempool_size(&ctx), 32);
    assert_eq!(entries.len(), 32);
}

#[test]
fn mempool_30_load_thirty_two_transfers_fetch_without_loss() {
    let ctx = new_ctx("load_thirty_two_transfers_fetch_without_loss");

    for seed in 200u64..232u64 {
        add_kind(&ctx, &transfer_kind(seed, 1));
    }

    let entries = fetched_entries(&ctx);

    assert_eq!(mempool_size(&ctx), 32);
    assert_eq!(entries.len(), 32);
}

#[test]
fn mempool_31_load_remove_half_of_thirty_two_entries() {
    let ctx = new_ctx("load_remove_half_of_thirty_two_entries");

    for seed in 300u64..332u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .take(16)
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 16);
    assert_eq!(fetched_entries(&ctx).len(), 16);
}

#[test]
fn mempool_32_load_remove_all_thirty_two_entries() {
    let ctx = new_ctx("load_remove_all_thirty_two_entries");

    for seed in 400u64..432u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_33_adversarial_duplicate_after_removal_is_accepted_again() {
    let ctx = new_ctx("adversarial_duplicate_after_removal_is_accepted_again");
    let kind = register_kind(500);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    add_kind(&ctx, &kind);

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_34_adversarial_duplicate_transfer_after_removal_is_accepted_again() {
    let ctx = new_ctx("adversarial_duplicate_transfer_after_removal_is_accepted_again");
    let tx = transfer(501, 100);

    add_transfer(&ctx, &tx);

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    add_transfer(&ctx, &tx);

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_35_adversarial_remove_batch_with_duplicate_kinds_removes_once_cleanly() {
    let ctx = new_ctx("adversarial_remove_batch_with_duplicate_kinds_removes_once_cleanly");
    let kind = register_kind(502);

    add_kind(&ctx, &kind);

    let batch = match TransactionBatch::new(1, 1_700_000_000, vec![kind.clone(), kind]) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_36_property_fetch_after_remove_then_add_new_contains_new_only() {
    let ctx = new_ctx("property_fetch_after_remove_then_add_new_contains_new_only");
    let old_kind = register_kind(503);
    let new_kind = register_kind(504);

    add_kind(&ctx, &old_kind);

    let entries = fetched_entries(&ctx);
    let old_keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&old_keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    add_kind(&ctx, &new_kind);

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], new_kind);
}

#[test]
fn mempool_37_property_txkind_hash_is_stable_for_same_serialized_kind() {
    let kind = register_kind(505);

    let first = kind_hash(&kind);
    let second = kind_hash(&kind);

    assert_eq!(first, second);
}

#[test]
fn mempool_38_property_different_txkinds_have_different_hashes() {
    let first = register_kind(506);
    let second = register_kind(507);

    assert_ne!(kind_hash(&first), kind_hash(&second));
}

#[test]
fn mempool_39_edge_invalid_transfer_constructor_not_admitted() {
    let result = Transaction::new(wallet_u64(600), wallet_u64(601), 0);

    assert_result_err_contains(result, "greater than zero");
}

#[test]
fn mempool_40_load_remove_transactions_in_large_batch_clears_all_matching_entries() {
    let ctx = new_ctx("load_remove_transactions_in_large_batch_clears_all_matching_entries");

    let kinds = (700u64..724u64).map(register_kind).collect::<Vec<_>>();

    for kind in &kinds {
        add_kind(&ctx, kind);
    }

    let batch = match TransactionBatch::new(9, 1_700_000_009, kinds) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_41_vector_raw_hash_index_transfer_is_gettable() {
    let ctx = new_ctx("vector_raw_hash_index_transfer_is_gettable");
    let tx = transfer(801, 100);
    let kind = TxKind::Transfer(tx.clone());
    let hash = kind_hash(&kind);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind::serialize failed: {err:?}"),
    };

    write_raw_hash_entry(&ctx, &hash, &bytes);

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(Some(tx)) => tx,
        Ok(None) => panic!("expected transaction from raw hash index"),
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert_eq!(got, tx);
}

#[test]
fn mempool_42_vector_raw_hash_index_register_returns_none() {
    let ctx = new_ctx("vector_raw_hash_index_register_returns_none");
    let kind = register_kind(802);
    let hash = kind_hash(&kind);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind::serialize failed: {err:?}"),
    };

    write_raw_hash_entry(&ctx, &hash, &bytes);

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(value) => value,
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert!(got.is_none());
}

#[test]
fn mempool_43_fuzz_raw_hash_index_malformed_payload_errors() {
    let ctx = new_ctx("fuzz_raw_hash_index_malformed_payload_errors");

    let cases = [
        ([1u8; 64], Vec::new()),
        ([2u8; 64], vec![0u8]),
        ([3u8; 64], vec![1u8, 2, 3, 4]),
        ([4u8; 64], vec![255u8; 16]),
    ];

    for (hash, payload) in cases {
        write_raw_hash_entry(&ctx, &hash, &payload);

        let result = ctx.mempool.get_transaction(&hash);
        assert!(result.is_err());
    }
}

#[test]
fn mempool_44_edge_counter_key_only_does_not_count_as_pending_tx() {
    let ctx = new_ctx("edge_counter_key_only_does_not_count_as_pending_tx");

    write_raw_mempool_entry(&ctx, TEST_MEMPOOL_BYTES_KEY, &[1u8, 2, 3]);

    assert_eq!(mempool_size(&ctx), 0);
    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_45_edge_malformed_counter_makes_add_fail_closed() {
    let ctx = new_ctx("edge_malformed_counter_makes_add_fail_closed");
    let kind = register_kind(805);

    // Invalid postcard varint for u64: continuation bit set, but buffer ends.
    write_raw_mempool_entry(&ctx, TEST_MEMPOOL_BYTES_KEY, &[0x80]);

    let result = ctx.mempool.add_tx_kind(&kind);

    assert_result_err_contains(result, "counter");
}

#[test]
fn mempool_46_edge_malformed_counter_makes_remove_fail_closed() {
    let ctx = new_ctx("edge_malformed_counter_makes_remove_fail_closed");

    // Invalid postcard varint for u64: continuation bit set, but buffer ends.
    write_raw_mempool_entry(&ctx, TEST_MEMPOOL_BYTES_KEY, &[0x80]);

    let result = ctx.mempool.remove_transactions(&[]);

    assert_result_err_contains(result, "counter");
}

#[test]
fn mempool_47_vector_valid_counter_missing_recomputed_on_remove() {
    let ctx = new_ctx("vector_valid_counter_missing_recomputed_on_remove");
    let kind = register_kind(807);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_48_vector_remove_transaction_deletes_timestamp_key_bytes() {
    let ctx = new_ctx("vector_remove_transaction_deletes_timestamp_key_bytes");
    let kind = register_kind(808);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);
    let key = entries[0].0.clone();

    assert!(read_raw_tx_entry(&ctx, &key).is_some());

    match ctx.mempool.remove_transactions(&[key.clone()]) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert!(read_raw_tx_entry(&ctx, &key).is_none());
}

#[test]
fn mempool_49_vector_remove_transaction_deletes_hash_index_for_register() {
    let ctx = new_ctx("vector_remove_transaction_deletes_hash_index_for_register");
    let kind = register_kind(809);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    assert!(read_raw_hash_entry(&ctx, &hash).is_some());

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert!(read_raw_hash_entry(&ctx, &hash).is_none());
}

#[test]
fn mempool_50_vector_remove_transaction_deletes_hash_index_for_transfer() {
    let ctx = new_ctx("vector_remove_transaction_deletes_hash_index_for_transfer");
    let kind = transfer_kind(810, 100);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    assert!(read_raw_hash_entry(&ctx, &hash).is_some());

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert!(read_raw_hash_entry(&ctx, &hash).is_none());
}

#[test]
fn mempool_51_property_remove_transactions_in_batch_deletes_hash_index_for_register() {
    let ctx = new_ctx("property_remove_transactions_in_batch_deletes_hash_index_for_register");
    let kind = register_kind(811);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    let batch = batch_from_kinds(1, vec![kind]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert!(read_raw_hash_entry(&ctx, &hash).is_none());
}

#[test]
fn mempool_52_property_remove_transactions_in_batch_deletes_hash_index_for_transfer() {
    let ctx = new_ctx("property_remove_transactions_in_batch_deletes_hash_index_for_transfer");
    let kind = transfer_kind(812, 200);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    let batch = batch_from_kinds(1, vec![kind]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert!(read_raw_hash_entry(&ctx, &hash).is_none());
}

#[test]
fn mempool_53_vector_batch_prune_removes_multiple_matching_entries() {
    let ctx = new_ctx("vector_batch_prune_removes_multiple_matching_entries");
    let first = register_kind(813);
    let second = transfer_kind(814, 300);
    let third = register_kind(815);

    add_kind(&ctx, &first);
    add_kind(&ctx, &second);
    add_kind(&ctx, &third);

    let batch = batch_from_kinds(2, vec![first.clone(), second.clone()]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    let remaining = fetched_kinds(&ctx);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0], third);
}

#[test]
fn mempool_54_vector_batch_prune_with_all_entries_clears_mempool() {
    let ctx = new_ctx("vector_batch_prune_with_all_entries_clears_mempool");
    let kinds = vec![
        register_kind(816),
        transfer_kind(817, 10),
        register_kind(818),
    ];

    for kind in &kinds {
        add_kind(&ctx, kind);
    }

    let batch = batch_from_kinds(3, kinds);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_55_edge_batch_prune_with_same_kind_twice_keeps_unmatched_entries() {
    let ctx = new_ctx("edge_batch_prune_with_same_kind_twice_keeps_unmatched_entries");
    let remove = register_kind(819);
    let keep = register_kind(820);

    add_kind(&ctx, &remove);
    add_kind(&ctx, &keep);

    let batch = batch_from_kinds(4, vec![remove.clone(), remove]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    let remaining = fetched_kinds(&ctx);
    assert_eq!(remaining, vec![keep]);
}

#[test]
fn mempool_56_fuzz_fetch_skips_invalid_entries_between_valid_entries() {
    let ctx = new_ctx("fuzz_fetch_skips_invalid_entries_between_valid_entries");
    let first = register_kind(821);
    let second = transfer_kind(822, 400);

    add_kind(&ctx, &first);
    write_raw_mempool_entry(&ctx, b"malformed_middle", &[255u8; 32]);
    add_kind(&ctx, &second);

    let fetched = fetched_kinds(&ctx);

    assert_eq!(fetched.len(), 2);
    assert!(fetched.iter().any(|kind| kind == &first));
    assert!(fetched.iter().any(|kind| kind == &second));
}

#[test]
fn mempool_57_fuzz_malformed_entries_count_but_do_not_fetch() {
    let ctx = new_ctx("fuzz_malformed_entries_count_but_do_not_fetch");

    for i in 0u8..10u8 {
        let key = format!("bad_{i}");
        write_raw_mempool_entry(&ctx, key.as_bytes(), &[i; 4]);
    }

    assert_eq!(mempool_size(&ctx), 10);
    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_58_vector_direct_raw_transfer_entry_fetches_as_transfer_kind() {
    let ctx = new_ctx("vector_direct_raw_transfer_entry_fetches_as_transfer_kind");
    let kind = transfer_kind(823, 500);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind::serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_transfer", &bytes);

    let fetched = fetched_kinds(&ctx);

    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], kind);
}

#[test]
fn mempool_59_vector_direct_raw_register_entry_fetches_as_register_kind() {
    let ctx = new_ctx("vector_direct_raw_register_entry_fetches_as_register_kind");
    let kind = register_kind(824);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind::serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_register", &bytes);

    let fetched = fetched_kinds(&ctx);

    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], kind);
}

#[test]
fn mempool_60_property_manual_valid_entries_can_be_removed_by_key() {
    let ctx = new_ctx("property_manual_valid_entries_can_be_removed_by_key");
    let kind = register_kind(825);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind::serialize failed: {err:?}"),
    };
    let key = b"manual_valid_remove".to_vec();

    write_raw_mempool_entry(&ctx, &key, &bytes);

    assert_eq!(fetched_kinds(&ctx), vec![kind]);

    match ctx.mempool.remove_transactions(&[key]) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions failed: {err:?}"),
    }

    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_61_property_manual_valid_entry_removed_by_batch_hash_match() {
    let ctx = new_ctx("property_manual_valid_entry_removed_by_batch_hash_match");
    let kind = register_kind(826);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind::serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_valid_batch_remove", &bytes);

    let batch = batch_from_kinds(5, vec![kind]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("remove_transactions_in_batch failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_62_edge_remove_missing_key_updates_counter_without_negative_effect() {
    let ctx = new_ctx("edge_remove_missing_key_updates_counter_without_negative_effect");

    match ctx.mempool.remove_transactions(&[b"missing_key".to_vec()]) {
        Ok(()) => {}
        Err(err) => panic!("remove missing key failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_63_edge_remove_missing_key_then_add_still_works() {
    let ctx = new_ctx("edge_remove_missing_key_then_add_still_works");
    let kind = register_kind(827);

    match ctx.mempool.remove_transactions(&[b"missing_key".to_vec()]) {
        Ok(()) => {}
        Err(err) => panic!("remove missing key failed: {err:?}"),
    }

    add_kind(&ctx, &kind);

    assert_eq!(mempool_size(&ctx), 1);
    assert_eq!(fetched_kinds(&ctx), vec![kind]);
}

#[test]
fn mempool_64_property_add_remove_add_different_hash_index_is_clean() {
    let ctx = new_ctx("property_add_remove_add_different_hash_index_is_clean");
    let first = register_kind(828);
    let second = register_kind(829);
    let first_hash = kind_hash(&first);
    let second_hash = kind_hash(&second);

    add_kind(&ctx, &first);

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove failed: {err:?}"),
    }

    add_kind(&ctx, &second);

    assert!(read_raw_hash_entry(&ctx, &first_hash).is_none());
    assert!(read_raw_hash_entry(&ctx, &second_hash).is_some());
}

#[test]
fn mempool_65_property_transfer_id_hash_lookup_matches_added_transfer() {
    let ctx = new_ctx("property_transfer_id_hash_lookup_matches_added_transfer");
    let tx = transfer(830, 123);
    let kind = TxKind::Transfer(tx.clone());
    let hash = kind_hash(&kind);
    let expected_id = match tx.id() {
        Ok(id) => id,
        Err(err) => panic!("tx id failed: {err:?}"),
    };

    add_kind(&ctx, &kind);

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(Some(tx)) => tx,
        Ok(None) => panic!("expected transfer"),
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    let got_id = match got.id() {
        Ok(id) => id,
        Err(err) => panic!("got tx id failed: {err:?}"),
    };

    assert_eq!(got_id, expected_id);
}

#[test]
fn mempool_66_property_register_node_not_returned_by_get_transaction_even_when_fetchable() {
    let ctx = new_ctx("property_register_node_not_returned_by_get_transaction_even_when_fetchable");
    let kind = register_kind(831);
    let hash = kind_hash(&kind);

    add_kind(&ctx, &kind);

    assert_eq!(fetched_kinds(&ctx), vec![kind]);

    let got = match ctx.mempool.get_transaction(&hash) {
        Ok(value) => value,
        Err(err) => panic!("get_transaction failed: {err:?}"),
    };

    assert!(got.is_none());
}

#[test]
fn mempool_67_vector_mempool_size_excludes_counter_after_add() {
    let ctx = new_ctx("vector_mempool_size_excludes_counter_after_add");

    add_kind(&ctx, &register_kind(832));

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_68_vector_mempool_size_excludes_counter_after_remove() {
    let ctx = new_ctx("vector_mempool_size_excludes_counter_after_remove");

    add_kind(&ctx, &register_kind(833));

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_69_edge_fetch_empty_after_only_counter_written() {
    let ctx = new_ctx("edge_fetch_empty_after_only_counter_written");

    write_raw_mempool_entry(&ctx, TEST_MEMPOOL_BYTES_KEY, &[0u8]);

    assert!(fetched_entries(&ctx).is_empty());
}

#[test]
fn mempool_70_edge_duplicate_raw_hash_index_blocks_add_of_same_kind() {
    let ctx = new_ctx("edge_duplicate_raw_hash_index_blocks_add_of_same_kind");
    let kind = register_kind(834);
    let hash = kind_hash(&kind);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind serialize failed: {err:?}"),
    };

    write_raw_hash_entry(&ctx, &hash, &bytes);

    let result = ctx.mempool.add_tx_kind(&kind);

    assert_result_err_contains(result, "duplicate");
}

#[test]
fn mempool_71_edge_duplicate_raw_hash_index_blocks_add_transaction() {
    let ctx = new_ctx("edge_duplicate_raw_hash_index_blocks_add_transaction");
    let tx = transfer(835, 100);
    let kind = TxKind::Transfer(tx.clone());
    let hash = kind_hash(&kind);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TxKind serialize failed: {err:?}"),
    };

    write_raw_hash_entry(&ctx, &hash, &bytes);

    let result = ctx.mempool.add_transaction(&tx);

    assert_result_err_contains(result, "duplicate");
}

#[test]
fn mempool_72_adversarial_hash_index_malformed_duplicate_still_blocks_by_hash() {
    let ctx = new_ctx("adversarial_hash_index_malformed_duplicate_still_blocks_by_hash");
    let kind = register_kind(836);
    let hash = kind_hash(&kind);

    write_raw_hash_entry(&ctx, &hash, b"corrupt-but-present");

    let result = ctx.mempool.add_tx_kind(&kind);

    assert_result_err_contains(result, "duplicate");
}

#[test]
fn mempool_73_property_fetch_after_duplicate_rejection_contains_original_only() {
    let ctx = new_ctx("property_fetch_after_duplicate_rejection_contains_original_only");
    let kind = register_kind(837);

    add_kind(&ctx, &kind);

    let result = ctx.mempool.add_tx_kind(&kind);
    assert!(result.is_err());

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], kind);
}

#[test]
fn mempool_74_load_add_forty_register_nodes_size_matches() {
    let ctx = new_ctx("load_add_forty_register_nodes_size_matches");

    for seed in 900u64..940u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    assert_eq!(mempool_size(&ctx), 40);
}

#[test]
fn mempool_75_load_fetch_forty_register_nodes_without_malformed_loss() {
    let ctx = new_ctx("load_fetch_forty_register_nodes_without_malformed_loss");

    for seed in 940u64..980u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    assert_eq!(fetched_entries(&ctx).len(), 40);
}

#[test]
fn mempool_76_load_add_forty_transfers_size_matches() {
    let ctx = new_ctx("load_add_forty_transfers_size_matches");

    for seed in 980u64..1_020u64 {
        add_kind(&ctx, &transfer_kind(seed, 1));
    }

    assert_eq!(mempool_size(&ctx), 40);
}

#[test]
fn mempool_77_load_fetch_forty_transfers_without_loss() {
    let ctx = new_ctx("load_fetch_forty_transfers_without_loss");

    for seed in 1_020u64..1_060u64 {
        add_kind(&ctx, &transfer_kind(seed, 2));
    }

    assert_eq!(fetched_entries(&ctx).len(), 40);
}

#[test]
fn mempool_78_load_remove_first_twenty_of_forty_by_key() {
    let ctx = new_ctx("load_remove_first_twenty_of_forty_by_key");

    for seed in 1_060u64..1_100u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    let entries = fetched_entries(&ctx);
    let keys = entries
        .iter()
        .take(20)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 20);
}

#[test]
fn mempool_79_load_remove_second_twenty_after_first_twenty() {
    let ctx = new_ctx("load_remove_second_twenty_after_first_twenty");

    for seed in 1_100u64..1_140u64 {
        add_kind(&ctx, &register_kind(seed));
    }

    let first_entries = fetched_entries(&ctx);
    let first_keys = first_entries
        .iter()
        .take(20)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&first_keys) {
        Ok(()) => {}
        Err(err) => panic!("first remove failed: {err:?}"),
    }

    let second_entries = fetched_entries(&ctx);
    let second_keys = second_entries
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&second_keys) {
        Ok(()) => {}
        Err(err) => panic!("second remove failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_80_load_batch_prune_thirty_matching_registers() {
    let ctx = new_ctx("load_batch_prune_thirty_matching_registers");

    let kinds = (1_140u64..1_170u64).map(register_kind).collect::<Vec<_>>();

    for kind in &kinds {
        add_kind(&ctx, kind);
    }

    let batch = batch_from_kinds(80, kinds);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("batch prune failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_81_load_batch_prune_thirty_matching_transfers() {
    let ctx = new_ctx("load_batch_prune_thirty_matching_transfers");

    let kinds = (1_170u64..1_200u64)
        .map(|seed| transfer_kind(seed, 3))
        .collect::<Vec<_>>();

    for kind in &kinds {
        add_kind(&ctx, kind);
    }

    let batch = batch_from_kinds(81, kinds);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("batch prune failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_82_load_batch_prune_half_of_mixed_forty() {
    let ctx = new_ctx("load_batch_prune_half_of_mixed_forty");

    let all = (0u64..20u64)
        .flat_map(|i| [register_kind(1_200u64 + i), transfer_kind(1_300u64 + i, 4)])
        .collect::<Vec<_>>();

    for kind in &all {
        add_kind(&ctx, kind);
    }

    let half = all.iter().take(20).cloned().collect::<Vec<_>>();
    let batch = batch_from_kinds(82, half);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("batch prune failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 20);
}

#[test]
fn mempool_83_property_removed_batch_entries_can_be_readded() {
    let ctx = new_ctx("property_removed_batch_entries_can_be_readded");
    let kind = register_kind(1_401);

    add_kind(&ctx, &kind);

    let batch = batch_from_kinds(83, vec![kind.clone()]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("batch prune failed: {err:?}"),
    }

    add_kind(&ctx, &kind);

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_84_property_removed_transfer_batch_entry_can_be_readded() {
    let ctx = new_ctx("property_removed_transfer_batch_entry_can_be_readded");
    let kind = transfer_kind(1_402, 10);

    add_kind(&ctx, &kind);

    let batch = batch_from_kinds(84, vec![kind.clone()]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("batch prune failed: {err:?}"),
    }

    add_kind(&ctx, &kind);

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_85_edge_batch_prune_absent_hashes_is_noop() {
    let ctx = new_ctx("edge_batch_prune_absent_hashes_is_noop");
    let present = register_kind(1_403);
    let absent_one = register_kind(1_404);
    let absent_two = transfer_kind(1_405, 5);

    add_kind(&ctx, &present);

    let batch = batch_from_kinds(85, vec![absent_one, absent_two]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("batch prune failed: {err:?}"),
    }

    assert_eq!(fetched_kinds(&ctx), vec![present]);
}

#[test]
fn mempool_86_property_empty_mempool_get_transaction_none_for_many_hashes() {
    let ctx = new_ctx("property_empty_mempool_get_transaction_none_for_many_hashes");

    for seed in 0u8..16u8 {
        let hash = [seed; 64];
        let got = match ctx.mempool.get_transaction(&hash) {
            Ok(value) => value,
            Err(err) => panic!("get_transaction failed: {err:?}"),
        };

        assert!(got.is_none());
    }
}

#[test]
fn mempool_87_property_many_added_transfers_are_gettable_by_hash() {
    let ctx = new_ctx("property_many_added_transfers_are_gettable_by_hash");

    let pairs = (1_500u64..1_510u64)
        .map(|seed| {
            let tx = transfer(seed, seed.saturating_add(1));
            let kind = TxKind::Transfer(tx.clone());
            let hash = kind_hash(&kind);
            (hash, tx)
        })
        .collect::<Vec<_>>();

    for (_hash, tx) in &pairs {
        add_transfer(&ctx, tx);
    }

    for (hash, expected) in pairs {
        let got = match ctx.mempool.get_transaction(&hash) {
            Ok(Some(tx)) => tx,
            Ok(None) => panic!("expected transaction for hash"),
            Err(err) => panic!("get_transaction failed: {err:?}"),
        };

        assert_eq!(got, expected);
    }
}

#[test]
fn mempool_88_property_many_registers_are_not_gettable_by_transaction_api() {
    let ctx = new_ctx("property_many_registers_are_not_gettable_by_transaction_api");

    let kinds = (1_510u64..1_520u64).map(register_kind).collect::<Vec<_>>();

    let hashes = kinds.iter().map(kind_hash).collect::<Vec<_>>();

    for kind in &kinds {
        add_kind(&ctx, kind);
    }

    for hash in hashes {
        let got = match ctx.mempool.get_transaction(&hash) {
            Ok(value) => value,
            Err(err) => panic!("get_transaction failed: {err:?}"),
        };

        assert!(got.is_none());
    }
}

#[test]
fn mempool_89_edge_remove_transactions_accepts_mixed_existing_and_missing_keys() {
    let ctx = new_ctx("edge_remove_transactions_accepts_mixed_existing_and_missing_keys");
    let first = register_kind(1_521);
    let second = register_kind(1_522);

    add_kind(&ctx, &first);
    add_kind(&ctx, &second);

    let entries = fetched_entries(&ctx);
    let keys = vec![
        entries[0].0.clone(),
        b"missing_a".to_vec(),
        entries[1].0.clone(),
        b"missing_b".to_vec(),
    ];

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("mixed remove failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_90_edge_remove_transactions_with_duplicate_key_and_missing_key() {
    let ctx = new_ctx("edge_remove_transactions_with_duplicate_key_and_missing_key");
    let kind = register_kind(1_523);

    add_kind(&ctx, &kind);

    let entries = fetched_entries(&ctx);
    let key = entries[0].0.clone();

    let keys = vec![key.clone(), b"missing".to_vec(), key];

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("duplicate key remove failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_91_fuzz_fetch_with_counter_and_malformed_and_valid_entry() {
    let ctx = new_ctx("fuzz_fetch_with_counter_and_malformed_and_valid_entry");
    let kind = register_kind(1_524);

    write_raw_mempool_entry(&ctx, TEST_MEMPOOL_BYTES_KEY, &[0u8]);
    write_raw_mempool_entry(&ctx, b"bad_payload", b"bad");
    add_kind(&ctx, &kind);

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched, vec![kind]);
    assert_eq!(mempool_size(&ctx), 2);
}

#[test]
fn mempool_92_adversarial_manual_valid_entry_without_hash_index_can_coexist_with_added_distinct_entry()
 {
    let ctx = new_ctx(
        "adversarial_manual_valid_entry_without_hash_index_can_coexist_with_added_distinct_entry",
    );
    let manual = register_kind(1_525);
    let added = register_kind(1_526);
    let bytes = match manual.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("manual serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_no_hash", &bytes);
    add_kind(&ctx, &added);

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched.len(), 2);
    assert!(fetched.iter().any(|kind| kind == &manual));
    assert!(fetched.iter().any(|kind| kind == &added));
}

#[test]
fn mempool_93_adversarial_manual_duplicate_without_hash_index_allows_duplicate_fetch_entries() {
    let ctx =
        new_ctx("adversarial_manual_duplicate_without_hash_index_allows_duplicate_fetch_entries");
    let kind = register_kind(1_527);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_dup_a", &bytes);
    write_raw_mempool_entry(&ctx, b"manual_dup_b", &bytes);

    let fetched = fetched_kinds(&ctx);

    assert_eq!(fetched.len(), 2);
    assert!(fetched.iter().all(|fetched_kind| fetched_kind == &kind));
}

#[test]
fn mempool_94_adversarial_batch_prune_removes_manual_duplicate_entries_by_hash() {
    let ctx = new_ctx("adversarial_batch_prune_removes_manual_duplicate_entries_by_hash");
    let kind = register_kind(1_528);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_dup_a", &bytes);
    write_raw_mempool_entry(&ctx, b"manual_dup_b", &bytes);

    let batch = batch_from_kinds(94, vec![kind]);

    match ctx.mempool.remove_transactions_in_batch(&batch) {
        Ok(()) => {}
        Err(err) => panic!("batch prune failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
}

#[test]
fn mempool_95_property_remove_by_key_removes_only_that_manual_duplicate_key() {
    let ctx = new_ctx("property_remove_by_key_removes_only_that_manual_duplicate_key");
    let kind = register_kind(1_529);
    let bytes = match kind.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize failed: {err:?}"),
    };

    write_raw_mempool_entry(&ctx, b"manual_dup_a", &bytes);
    write_raw_mempool_entry(&ctx, b"manual_dup_b", &bytes);

    match ctx.mempool.remove_transactions(&[b"manual_dup_a".to_vec()]) {
        Ok(()) => {}
        Err(err) => panic!("remove failed: {err:?}"),
    }

    let fetched = fetched_kinds(&ctx);
    assert_eq!(fetched, vec![kind]);
}

#[test]
fn mempool_96_vector_transaction_new_from_remzar_added_to_mempool() {
    let ctx = new_ctx("vector_transaction_new_from_remzar_added_to_mempool");

    let tx = match Transaction::new_from_remzar(wallet_u64(1_530), wallet_u64(1_531), 1.25) {
        Ok(tx) => tx,
        Err(err) => panic!("new_from_remzar failed: {err:?}"),
    };

    add_transfer(&ctx, &tx);

    assert_eq!(mempool_size(&ctx), 1);
}

#[test]
fn mempool_97_edge_transaction_new_from_remzar_zero_not_admitted() {
    let result = Transaction::new_from_remzar(wallet_u64(1_532), wallet_u64(1_533), 0.0);

    assert_result_err_contains(result, "greater than zero");
}

#[test]
fn mempool_98_edge_transaction_new_same_sender_receiver_not_admitted() {
    let wallet = wallet_u64(1_534);

    let result = Transaction::new(wallet.clone(), wallet, 1);

    assert_result_err_contains(result, "same");
}

#[test]
fn mempool_99_edge_transaction_new_invalid_wallet_not_admitted() {
    let result = Transaction::new("not-a-wallet".to_owned(), wallet_u64(1_535), 1);

    assert_result_err_contains(result, "address");
}

#[test]
fn mempool_100_load_final_mixed_add_fetch_remove_cycle_returns_to_empty() {
    let ctx = new_ctx("load_final_mixed_add_fetch_remove_cycle_returns_to_empty");

    for seed in 0u64..20u64 {
        add_kind(&ctx, &register_kind(1_600u64 + seed));
        add_kind(
            &ctx,
            &transfer_kind(1_700u64 + seed, seed.saturating_add(1)),
        );
    }

    assert_eq!(mempool_size(&ctx), 40);

    let entries = fetched_entries(&ctx);
    assert_eq!(entries.len(), 40);

    let keys = entries
        .iter()
        .map(|(key, _kind)| key.clone())
        .collect::<Vec<_>>();

    match ctx.mempool.remove_transactions(&keys) {
        Ok(()) => {}
        Err(err) => panic!("remove all failed: {err:?}"),
    }

    assert_eq!(mempool_size(&ctx), 0);
    assert!(fetched_entries(&ctx).is_empty());
}
