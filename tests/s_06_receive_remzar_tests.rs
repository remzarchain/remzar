use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::{TxKind, normalize_address_bytes};
use remzar::commandline::s_06_receive_remzar::S06ReceiveRemzar;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked, from_micro_units};
use rust_rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options};
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_06_receive_remzar_tests_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            make_writable_recursive(&root);
            if fs::remove_dir_all(&root).is_err() {}
        }

        match fs::create_dir_all(&root) {
            Ok(()) => Self { root },
            Err(err) => panic!("failed to create temp root '{}': {err}", root.display()),
        }
    }

    fn child(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        make_writable_recursive(&self.root);
        if fs::remove_dir_all(&self.root).is_err() {}
    }
}

fn make_writable_recursive(path: &Path) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(_) => return,
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = metadata.permissions();
        let mode = permissions.mode();
        permissions.set_mode(mode | 0o700);
        if fs::set_permissions(path, permissions).is_err() {}
    }

    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            if fs::set_permissions(path, permissions).is_err() {}
        }
    }

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let entries = match fs::read_dir(path) {
            Ok(value) => value,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            make_writable_recursive(&entry.path());
        }
    }
}

fn assert_ok<T, E>(result: Result<T, E>, label: &str) -> T
where
    E: Debug,
{
    match result {
        Ok(value) => value,
        Err(err) => panic!("{label} failed: {err:?}"),
    }
}

fn assert_err<T, E>(result: Result<T, E>, label: &str) -> E
where
    T: Debug,
    E: Debug,
{
    match result {
        Ok(value) => panic!("{label} unexpectedly succeeded: {value:?}"),
        Err(err) => err,
    }
}

fn assert_validation_error(err: ErrorDetection) {
    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("expected ValidationError, got {other:?}"),
    }
}

fn wallet_from_label(label: &str) -> String {
    format!("r{}", RemzarHash::compute_bytes_hash_hex(label.as_bytes()))
}

fn reward_txkind_bytes(receiver: &str, amount: u64, block_height: u64) -> Vec<u8> {
    let reward = assert_ok(
        RewardTx::new(receiver.to_owned(), amount, block_height),
        "RewardTx::new",
    );
    let kind = TxKind::Reward(reward);

    assert_ok(kind.serialize(), "serialize Reward TxKind")
}

fn put_tx_entry(db: &DB, key: &[u8], bytes: &[u8]) {
    let cf = match db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME) {
        Some(value) => value,
        None => panic!("transaction column family missing"),
    };

    assert_ok(db.put_cf(&cf, key, bytes), "put tx entry");
}

fn read_all_tx_entries(db: &DB) -> Vec<Vec<u8>> {
    let cf = match db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME) {
        Some(value) => value,
        None => panic!("transaction column family missing"),
    };

    let mut entries = Vec::new();

    for entry in db.iterator_cf(&cf, IteratorMode::Start) {
        let (_key, value) = assert_ok(entry, "iterator tx entry");
        entries.push(value.to_vec());
    }

    entries
}

fn make_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_owned(),
        listen: "/ip4/127.0.0.1/tcp/36213".to_owned(),
        bootstrap: Vec::new(),
        log: "info".to_owned(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder: false,
    }
}

fn valid_wallet_id(seed: u8) -> String {
    let mut address = String::with_capacity(REMZAR_WALLET_LEN);
    address.push('r');

    for index in 0usize..128usize {
        let value = usize::from(seed).wrapping_add(index).wrapping_rem(16);
        address.push_str(&format!("{value:x}"));
    }

    address
}

fn make_transfer_to(receiver: &str, amount: u64) -> Transaction {
    let sender = valid_wallet_id(11);
    assert_ne!(sender, receiver);

    assert_ok(
        Transaction::new(sender, receiver.to_owned(), amount),
        "Transaction::new transfer to receiver",
    )
}

fn make_transfer_between(sender: &str, receiver: &str, amount: u64) -> Transaction {
    assert_ok(
        Transaction::new(sender.to_owned(), receiver.to_owned(), amount),
        "Transaction::new transfer between wallets",
    )
}

fn txkind_transfer_bytes(tx: &Transaction) -> Vec<u8> {
    assert_ok(
        TxKind::Transfer(tx.clone()).serialize(),
        "TxKind::Transfer serialize",
    )
}

fn raw_transaction_bytes(tx: &Transaction) -> Vec<u8> {
    assert_ok(tx.serialize(), "Transaction::serialize")
}

fn scan_incoming_from_mempool_bytes(wallet: &str, entries: &[Vec<u8>]) -> Vec<(String, f64)> {
    let wallet_norm = assert_ok(
        canon_wallet_id_checked(wallet),
        "canon target wallet in scan helper",
    );
    let mut incoming = Vec::new();
    let mut seen = HashSet::<[u8; 64]>::new();

    for bytes in entries {
        let hash = RemzarHash::compute_bytes_hash(bytes);
        if !seen.insert(hash) {
            continue;
        }

        let maybe_tx = match postcard::from_bytes::<TxKind>(bytes) {
            Ok(TxKind::Transfer(tx)) => Some(tx),
            Ok(_) => None,
            Err(_) => match Transaction::deserialize(bytes) {
                Ok(tx) => Some(tx),
                Err(_) => None,
            },
        };

        let tx = match maybe_tx {
            Some(value) => value,
            None => continue,
        };

        let recipient = normalize_address_bytes(&tx.receiver);
        if recipient.is_empty() {
            continue;
        }

        let recipient = match canon_wallet_id_checked(&recipient) {
            Ok(value) => value,
            Err(_) => continue,
        };

        if recipient != wallet_norm {
            continue;
        }

        let sender = normalize_address_bytes(&tx.sender);
        if sender.is_empty() {
            continue;
        }

        let sender = match canon_wallet_id_checked(&sender) {
            Ok(value) => value,
            Err(_) => continue,
        };

        incoming.push((sender, from_micro_units(tx.amount)));
    }

    incoming
}

fn directory_from_opts(opts: &NodeOpts) -> DirectoryDB {
    assert_ok(
        DirectoryDB::from_node_opts(opts),
        "DirectoryDB::from_node_opts",
    )
}

fn open_blockchain_db_for_test(path: &Path) -> DB {
    assert_ok(fs::create_dir_all(path), "create blockchain directory");

    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);

    let descriptors: Vec<ColumnFamilyDescriptor> = CFDescriptors::get_cf_descriptors()
        .iter()
        .map(CFDescriptors::clone_column_family_descriptor)
        .collect();

    assert_ok(
        DB::open_cf_descriptors(&options, path, descriptors),
        "open blockchain DB for test",
    )
}

#[test]
fn test_01_new_constructor_creates_receive_section() {
    let _section = S06ReceiveRemzar::new();
}

#[test]
fn test_02_default_constructor_creates_receive_section() {
    let _section = S06ReceiveRemzar;
}

#[test]
fn test_03_default_trait_creates_receive_section() {
    let _section = S06ReceiveRemzar::default();
}

#[test]
fn test_04_valid_wallet_id_has_expected_length() {
    let wallet = valid_wallet_id(4);

    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
}

#[test]
fn test_05_valid_wallet_id_canonicalizes() {
    let wallet = valid_wallet_id(5);
    let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon valid wallet");

    assert_eq!(canonical, wallet);
}

#[test]
fn test_06_wallet_id_uppercase_canonicalizes_to_lowercase() {
    let wallet = valid_wallet_id(6);
    let uppercase = wallet.to_ascii_uppercase();
    let canonical = assert_ok(
        canon_wallet_id_checked(&uppercase),
        "canon uppercase wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_07_wallet_id_with_outer_whitespace_canonicalizes() {
    let wallet = valid_wallet_id(7);
    let padded = format!("  {wallet}  ");
    let canonical = assert_ok(canon_wallet_id_checked(&padded), "canon padded wallet");

    assert_eq!(canonical, wallet);
}

#[test]
fn test_08_wallet_id_wrong_prefix_is_rejected() {
    let wallet = valid_wallet_id(8);
    let bad = format!("x{}", &wallet[1..]);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong-prefix wallet");

    assert_validation_error(err);
}

#[test]
fn test_09_wallet_id_short_is_rejected() {
    let err = assert_err(canon_wallet_id_checked("r1234"), "canon short wallet");

    assert_validation_error(err);
}

#[test]
fn test_10_wallet_id_non_hex_body_is_rejected() {
    let mut wallet = valid_wallet_id(10);
    wallet.replace_range(1..2, "g");

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon non-hex wallet");

    assert_validation_error(err);
}

#[test]
fn test_11_normalize_address_bytes_accepts_canonical_sender_bytes() {
    let wallet = valid_wallet_id(11);
    let normalized = normalize_address_bytes(wallet.as_bytes());

    assert_eq!(normalized, wallet);
}

#[test]
fn test_12_normalize_address_bytes_rejects_embedded_nul() {
    let mut bytes = valid_wallet_id(12).into_bytes();
    match bytes.get_mut(5) {
        Some(slot) => {
            *slot = 0;
        }
        None => panic!("wallet bytes unexpectedly too short"),
    }

    let normalized = normalize_address_bytes(&bytes);

    assert!(normalized.is_empty());
}

#[test]
fn test_13_normalize_address_bytes_rejects_invalid_utf8() {
    let bytes = [0xFF_u8, 0xFE_u8, 0xFD_u8];

    let normalized = normalize_address_bytes(&bytes);

    assert!(normalized.is_empty());
}

#[test]
fn test_14_scan_accepts_txkind_transfer_to_wallet() {
    let receiver = valid_wallet_id(14);
    let tx = make_transfer_to(&receiver, 100_000_000);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 1.0);
}

#[test]
fn test_15_scan_accepts_raw_transaction_fallback_to_wallet() {
    let receiver = valid_wallet_id(15);
    let tx = make_transfer_to(&receiver, 250_000_000);
    let entries = vec![raw_transaction_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 2.5);
}

#[test]
fn test_16_scan_ignores_transfer_to_different_wallet() {
    let receiver = valid_wallet_id(16);
    let other = valid_wallet_id(17);
    let tx = make_transfer_to(&other, 100_000_000);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_17_scan_deduplicates_identical_txkind_bytes() {
    let receiver = valid_wallet_id(18);
    let tx = make_transfer_to(&receiver, 100_000_000);
    let bytes = txkind_transfer_bytes(&tx);
    let entries = vec![bytes.clone(), bytes];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_18_scan_deduplicates_identical_raw_transaction_bytes() {
    let receiver = valid_wallet_id(19);
    let tx = make_transfer_to(&receiver, 100_000_000);
    let bytes = raw_transaction_bytes(&tx);
    let entries = vec![bytes.clone(), bytes];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_19_scan_ignores_bad_mempool_bytes() {
    let receiver = valid_wallet_id(20);
    let entries = vec![b"not a valid transaction".to_vec()];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_20_scan_ignores_non_transfer_txkind_reward() {
    let receiver = valid_wallet_id(21);
    let reward = assert_ok(RewardTx::new(receiver.clone(), 100, 1), "RewardTx::new");
    let kind = TxKind::Reward(reward);
    let bytes = assert_ok(kind.serialize(), "serialize reward TxKind");
    let entries = vec![bytes];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_21_scan_multiple_matching_transfers() {
    let receiver = valid_wallet_id(22);
    let first = make_transfer_between(&valid_wallet_id(23), &receiver, 100_000_000);
    let second = make_transfer_between(&valid_wallet_id(24), &receiver, 200_000_000);
    let entries = vec![
        txkind_transfer_bytes(&first),
        txkind_transfer_bytes(&second),
    ];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 2);
    assert_eq!(incoming[0].1, 1.0);
    assert_eq!(incoming[1].1, 2.0);
}

#[test]
fn test_22_scan_mixed_matching_and_nonmatching_transfers() {
    let receiver = valid_wallet_id(25);
    let other = valid_wallet_id(26);
    let first = make_transfer_between(&valid_wallet_id(27), &receiver, 100_000_000);
    let second = make_transfer_between(&valid_wallet_id(28), &other, 200_000_000);
    let third = make_transfer_between(&valid_wallet_id(29), &receiver, 300_000_000);
    let entries = vec![
        txkind_transfer_bytes(&first),
        txkind_transfer_bytes(&second),
        txkind_transfer_bytes(&third),
    ];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 2);
    assert_eq!(incoming[0].1, 1.0);
    assert_eq!(incoming[1].1, 3.0);
}

#[test]
fn test_23_scan_preserves_sender_address_for_matching_transfer() {
    let sender = valid_wallet_id(30);
    let receiver = valid_wallet_id(31);
    let tx = make_transfer_between(&sender, &receiver, 123_000_000);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].0, sender);
}

#[test]
fn test_24_scan_amount_one_micro_unit_converts_to_fraction() {
    let receiver = valid_wallet_id(32);
    let tx = make_transfer_to(&receiver, 1);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 0.00000001);
}

#[test]
fn test_25_scan_amount_zero_raw_transfer_is_rejected_by_deserialize_validation() {
    let receiver = valid_wallet_id(33);
    let sender = valid_wallet_id(34);
    let tx_result = Transaction::new(sender, receiver.clone(), 0);

    let err = assert_err(tx_result, "zero transaction construction");

    assert_validation_error(err);
}

#[test]
fn test_26_txkind_transfer_hash_is_64_bytes_for_dedup_key() {
    let receiver = valid_wallet_id(35);
    let tx = make_transfer_to(&receiver, 100);
    let bytes = txkind_transfer_bytes(&tx);
    let hash = RemzarHash::compute_bytes_hash(&bytes);

    assert_eq!(hash.len(), 64);
}

#[test]
fn test_27_txkind_transfer_data_hash_is_128_hex_chars() {
    let receiver = valid_wallet_id(36);
    let tx = make_transfer_to(&receiver, 100);
    let kind = TxKind::Transfer(tx);
    let hash = assert_ok(RemzarHash::compute_data_hash(&kind), "compute data hash");

    assert_eq!(hash.len(), 128);
}

#[test]
fn test_28_from_micro_units_formats_one_remzar() {
    assert_eq!(from_micro_units(100_000_000), 1.0);
}

#[test]
fn test_29_from_micro_units_formats_half_remzar() {
    assert_eq!(from_micro_units(50_000_000), 0.5);
}

#[test]
fn test_30_from_micro_units_formats_one_micro_unit() {
    assert_eq!(from_micro_units(1), 0.00000001);
}

#[test]
fn test_31_blockchain_db_opens_with_cf_descriptors() {
    let temp = TempTree::new("test_31");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    assert!(
        db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
            .is_some()
    );
}

#[test]
fn test_32_blockchain_db_transaction_cf_accepts_txkind_transfer_bytes() {
    let temp = TempTree::new("test_32");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);
    let cf = match db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME) {
        Some(value) => value,
        None => panic!("transaction column family missing"),
    };

    let receiver = valid_wallet_id(37);
    let tx = make_transfer_to(&receiver, 111);
    let bytes = txkind_transfer_bytes(&tx);

    assert_ok(
        db.put_cf(&cf, b"tx_0000000001", &bytes),
        "put transaction bytes",
    );

    let stored = assert_ok(
        db.get_pinned_cf(&cf, b"tx_0000000001"),
        "get transaction bytes",
    );

    match stored {
        Some(value) => assert_eq!(value.as_ref(), bytes.as_slice()),
        None => panic!("stored transaction was missing"),
    }
}

#[test]
fn test_33_blockchain_db_iterator_reads_transaction_cf_entry() {
    let temp = TempTree::new("test_33");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);
    let cf = match db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME) {
        Some(value) => value,
        None => panic!("transaction column family missing"),
    };

    let receiver = valid_wallet_id(38);
    let tx = make_transfer_to(&receiver, 222);
    let bytes = txkind_transfer_bytes(&tx);

    assert_ok(db.put_cf(&cf, b"tx_0000000002", &bytes), "put tx");
    let mut count = 0usize;

    for entry in db.iterator_cf(&cf, IteratorMode::Start) {
        let (_key, value) = assert_ok(entry, "iterator entry");
        assert_eq!(value.as_ref(), bytes.as_slice());
        count = count.saturating_add(1);
    }

    assert_eq!(count, 1);
}

#[test]
fn test_34_scan_entries_loaded_from_db_transaction_cf() {
    let temp = TempTree::new("test_34");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);
    let cf = match db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME) {
        Some(value) => value,
        None => panic!("transaction column family missing"),
    };

    let receiver = valid_wallet_id(39);
    let tx = make_transfer_to(&receiver, 333_000_000);
    let bytes = txkind_transfer_bytes(&tx);

    assert_ok(db.put_cf(&cf, b"tx_0000000003", &bytes), "put tx");

    let mut entries = Vec::new();
    for entry in db.iterator_cf(&cf, IteratorMode::Start) {
        let (_key, value) = assert_ok(entry, "iterator entry");
        entries.push(value.to_vec());
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 3.33);
}

#[test]
fn test_35_vector_scan_five_matching_transfers() {
    let receiver = valid_wallet_id(40);
    let mut entries = Vec::new();

    for index in 0u64..5u64 {
        let sender = valid_wallet_id(41_u8.saturating_add(u8::try_from(index).unwrap_or(0)));
        let tx = make_transfer_between(&sender, &receiver, (index.saturating_add(1)) * 100);
        entries.push(txkind_transfer_bytes(&tx));
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 5);
}

#[test]
fn test_36_vector_scan_legacy_raw_and_txkind_mix() {
    let receiver = valid_wallet_id(50);
    let first = make_transfer_between(&valid_wallet_id(51), &receiver, 100);
    let second = make_transfer_between(&valid_wallet_id(52), &receiver, 200);
    let entries = vec![
        raw_transaction_bytes(&first),
        txkind_transfer_bytes(&second),
    ];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 2);
}

#[test]
fn test_37_adversarial_duplicate_bad_entries_do_not_create_incoming() {
    let receiver = valid_wallet_id(53);
    let bad = b"bad entry".to_vec();
    let entries = vec![bad.clone(), bad];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_38_adversarial_large_bad_entry_is_ignored() {
    let receiver = valid_wallet_id(54);
    let bad = vec![0xAB_u8; 4096];
    let entries = vec![bad];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_39_load_scan_twenty_entries_ten_matching() {
    let receiver = valid_wallet_id(55);
    let other = valid_wallet_id(56);
    let mut entries = Vec::new();

    for index in 0u64..20u64 {
        let target = if index % 2 == 0 { &receiver } else { &other };
        let sender_seed = if index % 2 == 0 {
            1_u8.saturating_add(u8::try_from(index).unwrap_or(0))
        } else {
            33_u8.saturating_add(u8::try_from(index).unwrap_or(0))
        };
        let mut sender = valid_wallet_id(sender_seed);

        if sender == *target {
            sender = valid_wallet_id(sender_seed.saturating_add(7));
        }

        let tx = make_transfer_between(&sender, target, index.saturating_add(1));
        entries.push(txkind_transfer_bytes(&tx));
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 10);
}

#[test]
fn test_40_final_receive_dependencies_db_scan_dedup_and_amount_conversion() {
    let temp = TempTree::new("test_40");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);
    let cf = match db.cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME) {
        Some(value) => value,
        None => panic!("transaction column family missing"),
    };

    let receiver = valid_wallet_id(90);
    let sender = valid_wallet_id(91);
    let other = valid_wallet_id(92);

    let matching = make_transfer_between(&sender, &receiver, 125_000_000);
    let nonmatching = make_transfer_between(&sender, &other, 250_000_000);
    let duplicate_bytes = txkind_transfer_bytes(&matching);

    assert_ok(db.put_cf(&cf, b"tx_1", &duplicate_bytes), "put matching tx");
    assert_ok(
        db.put_cf(&cf, b"tx_2", &duplicate_bytes),
        "put duplicate tx",
    );
    assert_ok(
        db.put_cf(&cf, b"tx_3", txkind_transfer_bytes(&nonmatching)),
        "put nonmatching tx",
    );
    assert_ok(db.put_cf(&cf, b"tx_bad", b"bad bytes"), "put bad tx");

    let mut entries = Vec::new();
    for entry in db.iterator_cf(&cf, IteratorMode::Start) {
        let (_key, value) = assert_ok(entry, "iterator entry");
        entries.push(value.to_vec());
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].0, sender);
    assert_eq!(incoming[0].1, 1.25);
}

#[test]
fn test_41_wallet_from_label_is_canonical() {
    let wallet = wallet_from_label("test_41");

    let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon wallet_from_label");

    assert_eq!(canonical, wallet);
    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
}

#[test]
fn test_42_wallet_from_label_produces_unique_wallets_for_different_labels() {
    let first = wallet_from_label("test_42_first");
    let second = wallet_from_label("test_42_second");

    assert_ne!(first, second);
}

#[test]
fn test_43_normalize_address_bytes_accepts_trailing_nul_padding() {
    let wallet = wallet_from_label("test_43");
    let mut bytes = wallet.as_bytes().to_vec();

    bytes.push(0);
    bytes.push(0);
    bytes.push(0);

    let normalized = normalize_address_bytes(&bytes);

    assert_eq!(normalized, wallet);
    assert_ok(
        canon_wallet_id_checked(&normalized),
        "canonicalize normalized trailing-NUL padded wallet",
    );
}

#[test]
fn test_44_normalize_address_bytes_rejects_all_nul_bytes() {
    let bytes = vec![0_u8; REMZAR_WALLET_LEN];

    let normalized = normalize_address_bytes(&bytes);

    assert!(normalized.is_empty());
}

#[test]
fn test_45_normalize_address_bytes_rejects_wrong_prefix() {
    let mut wallet = wallet_from_label("test_45").into_bytes();

    match wallet.get_mut(0) {
        Some(slot) => {
            *slot = b'x';
        }
        None => panic!("wallet bytes unexpectedly empty"),
    }

    let normalized = normalize_address_bytes(&wallet);

    assert!(normalized.is_empty());
}

#[test]
fn test_46_normalize_address_bytes_rejects_non_hex_body() {
    let mut wallet = wallet_from_label("test_46").into_bytes();

    match wallet.get_mut(1) {
        Some(slot) => {
            *slot = b'g';
        }
        None => panic!("wallet bytes unexpectedly too short"),
    }

    let normalized = normalize_address_bytes(&wallet);

    assert!(normalized.is_empty());
}

#[test]
fn test_47_scan_accepts_uppercase_target_wallet_input() {
    let receiver = wallet_from_label("test_47_receiver");
    let sender = wallet_from_label("test_47_sender");
    let tx = make_transfer_between(&sender, &receiver, 100_000_000);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver.to_ascii_uppercase(), &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 1.0);
}

#[test]
fn test_48_scan_accepts_whitespace_padded_target_wallet_input() {
    let receiver = wallet_from_label("test_48_receiver");
    let sender = wallet_from_label("test_48_sender");
    let tx = make_transfer_between(&sender, &receiver, 200_000_000);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&format!("  {receiver}  "), &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 2.0);
}

#[test]
fn test_49_scan_accepts_transaction_created_with_uppercase_receiver() {
    let receiver = wallet_from_label("test_49_receiver");
    let sender = wallet_from_label("test_49_sender");

    let tx = assert_ok(
        Transaction::new(sender, receiver.to_ascii_uppercase(), 300_000_000),
        "Transaction::new uppercase receiver",
    );
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 3.0);
}

#[test]
fn test_50_scan_accepts_transaction_created_with_uppercase_sender() {
    let receiver = wallet_from_label("test_50_receiver");
    let sender = wallet_from_label("test_50_sender");

    let tx = assert_ok(
        Transaction::new(sender.to_ascii_uppercase(), receiver.clone(), 400_000_000),
        "Transaction::new uppercase sender",
    );
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].0, sender);
    assert_eq!(incoming[0].1, 4.0);
}

#[test]
fn test_51_scan_counts_txkind_and_legacy_raw_encodings_separately() {
    let receiver = wallet_from_label("test_51_receiver");
    let sender = wallet_from_label("test_51_sender");
    let tx = make_transfer_between(&sender, &receiver, 100_000_000);
    let entries = vec![txkind_transfer_bytes(&tx), raw_transaction_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 2);
}

#[test]
fn test_52_scan_ignores_duplicate_reward_entries() {
    let receiver = wallet_from_label("test_52_receiver");
    let reward = reward_txkind_bytes(&receiver, 100, 1);
    let entries = vec![reward.clone(), reward];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_53_scan_mixed_reward_and_matching_transfer_returns_only_transfer() {
    let receiver = wallet_from_label("test_53_receiver");
    let sender = wallet_from_label("test_53_sender");
    let transfer = make_transfer_between(&sender, &receiver, 500_000_000);
    let reward = reward_txkind_bytes(&receiver, 999, 53);
    let entries = vec![reward, txkind_transfer_bytes(&transfer)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].0, sender);
    assert_eq!(incoming[0].1, 5.0);
}

#[test]
fn test_54_scan_empty_entries_returns_empty() {
    let receiver = wallet_from_label("test_54_receiver");
    let entries = Vec::<Vec<u8>>::new();

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_55_scan_preserves_entry_order_for_matching_transfers() {
    let receiver = wallet_from_label("test_55_receiver");
    let first_sender = wallet_from_label("test_55_first_sender");
    let second_sender = wallet_from_label("test_55_second_sender");
    let third_sender = wallet_from_label("test_55_third_sender");

    let first = make_transfer_between(&first_sender, &receiver, 100_000_000);
    let second = make_transfer_between(&second_sender, &receiver, 200_000_000);
    let third = make_transfer_between(&third_sender, &receiver, 300_000_000);
    let entries = vec![
        txkind_transfer_bytes(&first),
        txkind_transfer_bytes(&second),
        txkind_transfer_bytes(&third),
    ];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 3);
    assert_eq!(incoming[0].0, first_sender);
    assert_eq!(incoming[1].0, second_sender);
    assert_eq!(incoming[2].0, third_sender);
}

#[test]
fn test_56_scan_deduplicates_matching_transfer_before_bad_entry() {
    let receiver = wallet_from_label("test_56_receiver");
    let sender = wallet_from_label("test_56_sender");
    let tx = make_transfer_between(&sender, &receiver, 100_000_000);
    let bytes = txkind_transfer_bytes(&tx);
    let entries = vec![bytes.clone(), b"bad entry".to_vec(), bytes];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_57_scan_deduplicates_matching_transfer_after_bad_entry() {
    let receiver = wallet_from_label("test_57_receiver");
    let sender = wallet_from_label("test_57_sender");
    let tx = make_transfer_between(&sender, &receiver, 100_000_000);
    let bytes = txkind_transfer_bytes(&tx);
    let entries = vec![b"bad entry".to_vec(), bytes.clone(), bytes];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_58_scan_amount_vector_one_two_three_remzar() {
    let receiver = wallet_from_label("test_58_receiver");
    let sender = wallet_from_label("test_58_sender");
    let tx = make_transfer_between(&sender, &receiver, 123_000_000);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 1.23);
}

#[test]
fn test_59_scan_amount_vector_eight_decimal_places() {
    let receiver = wallet_from_label("test_59_receiver");
    let sender = wallet_from_label("test_59_sender");
    let tx = make_transfer_between(&sender, &receiver, 12_345_678);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 0.12345678);
}

#[test]
fn test_60_scan_amount_vector_large_whole_amount() {
    let receiver = wallet_from_label("test_60_receiver");
    let sender = wallet_from_label("test_60_sender");
    let tx = make_transfer_between(&sender, &receiver, 9_999_999_900_000_000);
    let entries = vec![txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].1, 99_999_999.0);
}

#[test]
fn test_61_db_transaction_cf_handles_two_entries() {
    let temp = TempTree::new("test_61");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_61_receiver");
    let first = make_transfer_between(&wallet_from_label("test_61_sender_a"), &receiver, 111);
    let second = make_transfer_between(&wallet_from_label("test_61_sender_b"), &receiver, 222);

    put_tx_entry(&db, b"tx_1", &txkind_transfer_bytes(&first));
    put_tx_entry(&db, b"tx_2", &txkind_transfer_bytes(&second));

    let entries = read_all_tx_entries(&db);

    assert_eq!(entries.len(), 2);
}

#[test]
fn test_62_db_transaction_cf_scan_two_matching_entries() {
    let temp = TempTree::new("test_62");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_62_receiver");
    let first = make_transfer_between(
        &wallet_from_label("test_62_sender_a"),
        &receiver,
        100_000_000,
    );
    let second = make_transfer_between(
        &wallet_from_label("test_62_sender_b"),
        &receiver,
        200_000_000,
    );

    put_tx_entry(&db, b"tx_1", &txkind_transfer_bytes(&first));
    put_tx_entry(&db, b"tx_2", &txkind_transfer_bytes(&second));

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 2);
}

#[test]
fn test_63_db_transaction_cf_scan_duplicate_bytes_once() {
    let temp = TempTree::new("test_63");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_63_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_63_sender"), &receiver, 100_000_000);
    let bytes = txkind_transfer_bytes(&tx);

    put_tx_entry(&db, b"tx_1", &bytes);
    put_tx_entry(&db, b"tx_2", &bytes);

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_64_db_transaction_cf_scan_good_and_bad_entries() {
    let temp = TempTree::new("test_64");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_64_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_64_sender"), &receiver, 100_000_000);

    put_tx_entry(&db, b"tx_good", &txkind_transfer_bytes(&tx));
    put_tx_entry(&db, b"tx_bad", b"bad bytes");

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_65_db_transaction_cf_scan_reward_and_transfer_entries() {
    let temp = TempTree::new("test_65");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_65_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_65_sender"), &receiver, 100_000_000);
    let reward = reward_txkind_bytes(&receiver, 100, 65);

    put_tx_entry(&db, b"tx_reward", &reward);
    put_tx_entry(&db, b"tx_transfer", &txkind_transfer_bytes(&tx));

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_66_db_transaction_cf_with_unicode_data_dir_scans_entry() {
    let temp = TempTree::new("test_66");
    let opts = make_node_opts(&temp.child("node_測試_receive"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_66_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_66_sender"), &receiver, 100_000_000);

    put_tx_entry(&db, b"tx_unicode", &txkind_transfer_bytes(&tx));

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_67_db_transaction_cf_with_space_data_dir_scans_entry() {
    let temp = TempTree::new("test_67");
    let opts = make_node_opts(&temp.child("node with spaces"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_67_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_67_sender"), &receiver, 100_000_000);

    put_tx_entry(&db, b"tx_space", &txkind_transfer_bytes(&tx));

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_68_vector_scan_ten_matching_unique_senders() {
    let receiver = wallet_from_label("test_68_receiver");
    let mut entries = Vec::new();

    for index in 0usize..10usize {
        let sender = wallet_from_label(&format!("test_68_sender_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &receiver, amount);
        entries.push(txkind_transfer_bytes(&tx));
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 10);
}

#[test]
fn test_69_vector_scan_ten_nonmatching_unique_receivers() {
    let receiver = wallet_from_label("test_69_receiver");
    let sender = wallet_from_label("test_69_sender");
    let mut entries = Vec::new();

    for index in 0usize..10usize {
        let other = wallet_from_label(&format!("test_69_other_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &other, amount);
        entries.push(txkind_transfer_bytes(&tx));
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_70_vector_scan_mixed_legacy_raw_matching_entries() {
    let receiver = wallet_from_label("test_70_receiver");
    let mut entries = Vec::new();

    for index in 0usize..6usize {
        let sender = wallet_from_label(&format!("test_70_sender_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &receiver, amount);

        if index % 2 == 0 {
            entries.push(raw_transaction_bytes(&tx));
        } else {
            entries.push(txkind_transfer_bytes(&tx));
        }
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 6);
}

#[test]
fn test_71_vector_scan_interleaved_bad_and_good_entries() {
    let receiver = wallet_from_label("test_71_receiver");
    let mut entries = Vec::new();

    for index in 0usize..5usize {
        entries.push(format!("bad-{index}").into_bytes());

        let sender = wallet_from_label(&format!("test_71_sender_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &receiver, amount);
        entries.push(txkind_transfer_bytes(&tx));
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 5);
}

#[test]
fn test_72_adversarial_duplicate_hash_set_rejects_identical_bytes() {
    let receiver = wallet_from_label("test_72_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_72_sender"), &receiver, 1);
    let bytes = txkind_transfer_bytes(&tx);
    let hash = RemzarHash::compute_bytes_hash(&bytes);
    let mut seen = HashSet::<[u8; 64]>::new();

    assert!(seen.insert(hash));
    assert!(!seen.insert(hash));
}

#[test]
fn test_73_adversarial_distinct_transaction_bytes_have_distinct_hashes() {
    let receiver = wallet_from_label("test_73_receiver");
    let first = make_transfer_between(&wallet_from_label("test_73_sender_a"), &receiver, 1);
    let second = make_transfer_between(&wallet_from_label("test_73_sender_b"), &receiver, 1);

    let first_hash = RemzarHash::compute_bytes_hash(&txkind_transfer_bytes(&first));
    let second_hash = RemzarHash::compute_bytes_hash(&txkind_transfer_bytes(&second));

    assert_ne!(first_hash, second_hash);
}

#[test]
fn test_74_adversarial_large_invalid_entry_followed_by_valid_entry() {
    let receiver = wallet_from_label("test_74_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_74_sender"), &receiver, 100);
    let entries = vec![vec![0xAB_u8; 7_500], txkind_transfer_bytes(&tx)];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_75_adversarial_valid_entry_followed_by_large_invalid_entry() {
    let receiver = wallet_from_label("test_75_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_75_sender"), &receiver, 100);
    let entries = vec![txkind_transfer_bytes(&tx), vec![0xAB_u8; 7_500]];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_76_adversarial_many_duplicate_bad_entries_do_not_count() {
    let receiver = wallet_from_label("test_76_receiver");
    let bad = b"same bad entry".to_vec();
    let mut entries = Vec::new();

    for _ in 0usize..20usize {
        entries.push(bad.clone());
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_77_adversarial_many_duplicate_good_entries_count_once() {
    let receiver = wallet_from_label("test_77_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_77_sender"), &receiver, 100);
    let bytes = txkind_transfer_bytes(&tx);
    let mut entries = Vec::new();

    for _ in 0usize..20usize {
        entries.push(bytes.clone());
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_78_load_scan_twenty_matching_entries_with_unique_senders() {
    let receiver = wallet_from_label("test_78_receiver");
    let mut entries = Vec::new();

    for index in 0usize..20usize {
        let sender = wallet_from_label(&format!("test_78_sender_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &receiver, amount);
        entries.push(txkind_transfer_bytes(&tx));
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 20);
}

#[test]
fn test_79_load_scan_fifty_bad_entries_returns_empty() {
    let receiver = wallet_from_label("test_79_receiver");
    let mut entries = Vec::new();

    for index in 0usize..50usize {
        entries.push(format!("bad-entry-{index}").into_bytes());
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_80_load_db_scan_twenty_matching_entries() {
    let temp = TempTree::new("test_80");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);
    let receiver = wallet_from_label("test_80_receiver");

    for index in 0usize..20usize {
        let sender = wallet_from_label(&format!("test_80_sender_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &receiver, amount);
        put_tx_entry(
            &db,
            format!("tx_{index:010}").as_bytes(),
            &txkind_transfer_bytes(&tx),
        );
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 20);
}

#[test]
fn test_81_load_db_scan_twenty_nonmatching_entries() {
    let temp = TempTree::new("test_81");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);
    let receiver = wallet_from_label("test_81_receiver");

    for index in 0usize..20usize {
        let sender = wallet_from_label(&format!("test_81_sender_{index}"));
        let other = wallet_from_label(&format!("test_81_other_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &other, amount);
        put_tx_entry(
            &db,
            format!("tx_{index:010}").as_bytes(),
            &txkind_transfer_bytes(&tx),
        );
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert!(incoming.is_empty());
}

#[test]
fn test_82_hash_vector_same_bytes_same_hash() {
    let receiver = wallet_from_label("test_82_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_82_sender"), &receiver, 82);
    let bytes = txkind_transfer_bytes(&tx);

    let first = RemzarHash::compute_bytes_hash(&bytes);
    let second = RemzarHash::compute_bytes_hash(&bytes);

    assert_eq!(first, second);
}

#[test]
fn test_83_hash_vector_different_bytes_different_hash() {
    let receiver = wallet_from_label("test_83_receiver");
    let first = make_transfer_between(&wallet_from_label("test_83_sender_a"), &receiver, 83);
    let second = make_transfer_between(&wallet_from_label("test_83_sender_b"), &receiver, 84);

    let first_hash = RemzarHash::compute_bytes_hash(&txkind_transfer_bytes(&first));
    let second_hash = RemzarHash::compute_bytes_hash(&txkind_transfer_bytes(&second));

    assert_ne!(first_hash, second_hash);
}

#[test]
fn test_84_txkind_transfer_validate_after_deserialize() {
    let receiver = wallet_from_label("test_84_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_84_sender"), &receiver, 84);
    let bytes = txkind_transfer_bytes(&tx);
    let decoded = assert_ok(TxKind::deserialize(&bytes), "TxKind::deserialize");

    assert_ok(decoded.validate(), "decoded TxKind validate");
}

#[test]
fn test_85_raw_transaction_validate_after_deserialize() {
    let receiver = wallet_from_label("test_85_receiver");
    let tx = make_transfer_between(&wallet_from_label("test_85_sender"), &receiver, 85);
    let bytes = raw_transaction_bytes(&tx);
    let decoded = assert_ok(Transaction::deserialize(&bytes), "Transaction::deserialize");

    assert_ok(decoded.validate(), "decoded Transaction validate");
}

#[test]
fn test_86_reward_txkind_validate_does_not_become_incoming() {
    let receiver = wallet_from_label("test_86_receiver");
    let reward = assert_ok(RewardTx::new(receiver.clone(), 86, 86), "RewardTx::new");
    let kind = TxKind::Reward(reward);

    assert_ok(kind.validate(), "Reward TxKind validate");

    let entries = vec![assert_ok(kind.serialize(), "serialize reward kind")];
    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_87_from_micro_units_large_value_is_stable() {
    assert_eq!(from_micro_units(1_000_000_000_000), 10_000.0);
}

#[test]
fn test_88_from_micro_units_zero_is_zero() {
    assert_eq!(from_micro_units(0), 0.0);
}

#[test]
fn test_89_canon_wallet_rejects_too_long_address() {
    let mut wallet = wallet_from_label("test_89");
    wallet.push('0');

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon too-long wallet");

    assert_validation_error(err);
}

#[test]
fn test_90_canon_wallet_rejects_empty_string() {
    let err = assert_err(canon_wallet_id_checked(""), "canon empty wallet");

    assert_validation_error(err);
}

#[test]
fn test_91_canon_wallet_rejects_whitespace_only() {
    let err = assert_err(canon_wallet_id_checked("     "), "canon whitespace wallet");

    assert_validation_error(err);
}

#[test]
fn test_92_db_cf_descriptors_include_transaction_column_name() {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let mut found = false;

    for descriptor in descriptors {
        if descriptor.name() == GlobalConfiguration::TRANSACTION_COLUMN_NAME {
            found = true;
        }
    }

    assert!(found, "transaction column family descriptor was missing");
}

#[test]
fn test_93_db_reopen_read_only_reads_transaction_entry() {
    let temp = TempTree::new("test_93");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    {
        let db = open_blockchain_db_for_test(&directory.blockchain_path);
        let receiver = wallet_from_label("test_93_receiver");
        let tx = make_transfer_between(&wallet_from_label("test_93_sender"), &receiver, 93);
        put_tx_entry(&db, b"tx_93", &txkind_transfer_bytes(&tx));
    }

    let mut options = Options::default();
    options.create_if_missing(false);
    options.create_missing_column_families(false);

    let descriptors: Vec<ColumnFamilyDescriptor> = CFDescriptors::get_cf_descriptors()
        .iter()
        .map(CFDescriptors::clone_column_family_descriptor)
        .collect();

    let db = assert_ok(
        DB::open_cf_descriptors_read_only(&options, &directory.blockchain_path, descriptors, false),
        "open read-only blockchain db",
    );

    assert_eq!(read_all_tx_entries(&db).len(), 1);
}

#[test]
fn test_94_db_reopen_read_only_scan_matching_entry() {
    let temp = TempTree::new("test_94");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let receiver = wallet_from_label("test_94_receiver");

    {
        let db = open_blockchain_db_for_test(&directory.blockchain_path);
        let tx = make_transfer_between(&wallet_from_label("test_94_sender"), &receiver, 94);
        put_tx_entry(&db, b"tx_94", &txkind_transfer_bytes(&tx));
    }

    let mut options = Options::default();
    options.create_if_missing(false);
    options.create_missing_column_families(false);

    let descriptors: Vec<ColumnFamilyDescriptor> = CFDescriptors::get_cf_descriptors()
        .iter()
        .map(CFDescriptors::clone_column_family_descriptor)
        .collect();

    let db = assert_ok(
        DB::open_cf_descriptors_read_only(&options, &directory.blockchain_path, descriptors, false),
        "open read-only blockchain db",
    );

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_95_property_scan_matches_only_requested_wallet() {
    let requested = wallet_from_label("test_95_requested");
    let other_a = wallet_from_label("test_95_other_a");
    let other_b = wallet_from_label("test_95_other_b");
    let sender = wallet_from_label("test_95_sender");

    let first = make_transfer_between(&sender, &requested, 1);
    let second = make_transfer_between(&sender, &other_a, 2);
    let third = make_transfer_between(&sender, &other_b, 3);
    let entries = vec![
        txkind_transfer_bytes(&first),
        txkind_transfer_bytes(&second),
        txkind_transfer_bytes(&third),
    ];

    let incoming = scan_incoming_from_mempool_bytes(&requested, &entries);

    assert_eq!(incoming.len(), 1);
}

#[test]
fn test_96_property_scan_sums_visible_amounts_externally() {
    let receiver = wallet_from_label("test_96_receiver");
    let first = make_transfer_between(
        &wallet_from_label("test_96_sender_a"),
        &receiver,
        100_000_000,
    );
    let second = make_transfer_between(
        &wallet_from_label("test_96_sender_b"),
        &receiver,
        250_000_000,
    );
    let entries = vec![
        txkind_transfer_bytes(&first),
        txkind_transfer_bytes(&second),
    ];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);
    let total: f64 = incoming.iter().map(|(_, amount)| *amount).sum();

    assert_eq!(total, 3.5);
}

#[test]
fn test_97_property_duplicate_and_nonduplicate_mix_counts_correctly() {
    let receiver = wallet_from_label("test_97_receiver");
    let first = make_transfer_between(&wallet_from_label("test_97_sender_a"), &receiver, 1);
    let second = make_transfer_between(&wallet_from_label("test_97_sender_b"), &receiver, 2);

    let first_bytes = txkind_transfer_bytes(&first);
    let second_bytes = txkind_transfer_bytes(&second);

    let entries = vec![
        first_bytes.clone(),
        first_bytes,
        second_bytes.clone(),
        second_bytes,
    ];

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 2);
}

#[test]
fn test_98_load_scan_one_hundred_bad_entries() {
    let receiver = wallet_from_label("test_98_receiver");
    let mut entries = Vec::new();

    for index in 0usize..100usize {
        entries.push(format!("invalid-load-entry-{index}").into_bytes());
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert!(incoming.is_empty());
}

#[test]
fn test_99_load_scan_thirty_matching_entries() {
    let receiver = wallet_from_label("test_99_receiver");
    let mut entries = Vec::new();

    for index in 0usize..30usize {
        let sender = wallet_from_label(&format!("test_99_sender_{index}"));
        let amount = u64::try_from(index.saturating_add(1)).unwrap_or(1);
        let tx = make_transfer_between(&sender, &receiver, amount);
        entries.push(txkind_transfer_bytes(&tx));
    }

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &entries);

    assert_eq!(incoming.len(), 30);
}

#[test]
fn test_100_final_receive_scan_db_duplicates_nonmatching_rewards_and_amounts() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let db = open_blockchain_db_for_test(&directory.blockchain_path);

    let receiver = wallet_from_label("test_100_receiver");
    let sender_a = wallet_from_label("test_100_sender_a");
    let sender_b = wallet_from_label("test_100_sender_b");
    let other = wallet_from_label("test_100_other");

    let matching_a = make_transfer_between(&sender_a, &receiver, 125_000_000);
    let matching_b = make_transfer_between(&sender_b, &receiver, 375_000_000);
    let nonmatching = make_transfer_between(&sender_a, &other, 999_000_000);
    let duplicate = txkind_transfer_bytes(&matching_a);
    let reward = reward_txkind_bytes(&receiver, 500, 100);

    put_tx_entry(&db, b"tx_a", &duplicate);
    put_tx_entry(&db, b"tx_a_dup", &duplicate);
    put_tx_entry(&db, b"tx_b", &txkind_transfer_bytes(&matching_b));
    put_tx_entry(&db, b"tx_other", &txkind_transfer_bytes(&nonmatching));
    put_tx_entry(&db, b"tx_reward", &reward);
    put_tx_entry(&db, b"tx_bad", b"bad mempool bytes");

    let incoming = scan_incoming_from_mempool_bytes(&receiver, &read_all_tx_entries(&db));

    assert_eq!(incoming.len(), 2);

    let total: f64 = incoming.iter().map(|(_, amount)| *amount).sum();
    assert_eq!(total, 5.0);
}
