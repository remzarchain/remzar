use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::network::p2p_010_netcmd::NetCmd;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::tokens::game_slot_machine::{
    SLOT_ENTRY_FEE_MICRO, SLOT_HOUSE_ADDRESS, SlotMachineContext, SlotMachineGame,
    SlotMachineGameConfig, SpinResult, enqueue_transfer_to_mempool,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{UNIT_DIVISOR, canon_wallet_id_checked};
use remzar::utility::logging_data::JsonLogger;

use rust_rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TestEnv {
    _root: PathBuf,
    opts: NodeOpts,
    db: Arc<DB>,
    logger: JsonLogger,
}

struct MinimalDbEnv {
    _root: PathBuf,
    db: DB,
    logger: JsonLogger,
}

fn boxed(message: String) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message))
}

fn boxed_static(message: &'static str) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message))
}

fn canonical_wallet(byte: u8) -> String {
    format!("r{}", hex::encode([byte; 64]))
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "remzar_game_001_slot_{}_{}",
        name,
        uuid::Uuid::new_v4()
    ))
}

fn new_test_env(name: &str) -> TestResult<TestEnv> {
    let root = temp_root(name);
    std::fs::create_dir_all(&root)?;

    let mut opts = NodeOpts::default();
    opts.data_dir = root.to_string_lossy().to_string();
    opts.wallet_address = canonical_wallet(201);

    let directory = DirectoryDB::from_base_dir(&root).map_err(boxed)?;
    directory.create_log_directory().map_err(boxed)?;

    let logger = JsonLogger::new(&directory).map_err(boxed)?;

    let blockchain_path = directory.blockchain_path.to_string_lossy().to_string();
    let manager = RockDBManager::new_blockchain(&opts, &blockchain_path)?;
    let db = manager.open_db_blockchain()?;

    Ok(TestEnv {
        _root: root,
        opts,
        db,
        logger,
    })
}

fn new_minimal_db_env(name: &str, cf_names: &[&str]) -> TestResult<MinimalDbEnv> {
    let root = temp_root(name);
    std::fs::create_dir_all(&root)?;

    let directory = DirectoryDB::from_base_dir(&root).map_err(boxed)?;
    directory.create_log_directory().map_err(boxed)?;
    let logger = JsonLogger::new(&directory).map_err(boxed)?;

    let db_path = root.join("minimal_db");

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    let mut descriptors = vec![ColumnFamilyDescriptor::new("default", Options::default())];
    for name in cf_names {
        descriptors.push(ColumnFamilyDescriptor::new(*name, Options::default()));
    }

    let db = DB::open_cf_descriptors(&db_opts, &db_path, descriptors)?;

    Ok(MinimalDbEnv {
        _root: root,
        db,
        logger,
    })
}

fn cf_values(db: &DB, cf_name: &str) -> TestResult<Vec<Vec<u8>>> {
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| boxed(format!("missing column family: {cf_name}")))?;

    let mut values = Vec::new();
    for item in db.iterator_cf(cf, IteratorMode::Start) {
        let (_, value) = item?;
        values.push(value.to_vec());
    }

    Ok(values)
}

fn cf_keys(db: &DB, cf_name: &str) -> TestResult<Vec<Vec<u8>>> {
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| boxed(format!("missing column family: {cf_name}")))?;

    let mut keys = Vec::new();
    for item in db.iterator_cf(cf, IteratorMode::Start) {
        let (key, _) = item?;
        keys.push(key.to_vec());
    }

    Ok(keys)
}

fn cf_count(db: &DB, cf_name: &str) -> TestResult<usize> {
    Ok(cf_values(db, cf_name)?.len())
}

fn single_stored_transfer(env: &TestEnv) -> TestResult<Transaction> {
    let values = cf_values(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;
    if values.len() != 1 {
        return Err(boxed(format!(
            "expected exactly one stored transfer, found {}",
            values.len()
        )));
    }

    let first = values
        .first()
        .ok_or_else(|| boxed_static("stored transfer value missing"))?;
    let kind = TxKind::deserialize(first)?;

    match kind {
        TxKind::Transfer(tx) => Ok(tx),
        other => Err(boxed(format!("expected transfer, got {}", other.tag()))),
    }
}

fn assert_err_contains(result: Result<(), ErrorDetection>, needle: &str) {
    let message = match result {
        Ok(()) => String::new(),
        Err(err) => err.to_string(),
    };

    assert!(
        message.contains(needle),
        "expected error containing `{needle}`, got `{message}`"
    );
}

#[test]
fn test_01_entry_fee_constant_is_one_remzar_micro_unit() {
    assert_eq!(SLOT_ENTRY_FEE_MICRO, UNIT_DIVISOR);
}

#[test]
fn test_02_default_game_max_payout_is_100_remzar() {
    let game = SlotMachineGame::default();

    assert_eq!(game.max_payout_micro(), 100u64.saturating_mul(UNIT_DIVISOR));
}

#[test]
fn test_03_zero_spin_result_is_loss() {
    let result = SpinResult { payout_micro: 0 };

    assert!(!result.is_win());
}

#[test]
fn test_04_one_micro_spin_result_is_win() {
    let result = SpinResult { payout_micro: 1 };

    assert!(result.is_win());
}

#[test]
fn test_05_large_spin_result_is_win() {
    let result = SpinResult {
        payout_micro: u64::MAX,
    };

    assert!(result.is_win());
}

#[test]
fn test_06_spin_result_copy_preserves_payout() {
    let first = SpinResult {
        payout_micro: SLOT_ENTRY_FEE_MICRO,
    };
    let second = first;

    assert_eq!(first.payout_micro, second.payout_micro);
    assert_eq!(first.is_win(), second.is_win());
}

#[test]
fn test_07_default_config_uses_slot_constants() {
    let cfg = SlotMachineGameConfig::default();

    assert_eq!(cfg.house_address, SLOT_HOUSE_ADDRESS);
    assert_eq!(cfg.entry_fee_micro, SLOT_ENTRY_FEE_MICRO);
}

#[test]
fn test_08_default_game_uses_default_config() {
    let game = SlotMachineGame::default();

    assert_eq!(game.cfg.house_address, SLOT_HOUSE_ADDRESS);
    assert_eq!(game.cfg.entry_fee_micro, SLOT_ENTRY_FEE_MICRO);
}

#[test]
fn test_09_config_clone_preserves_fields() {
    let cfg = SlotMachineGameConfig {
        house_address: SLOT_HOUSE_ADDRESS,
        entry_fee_micro: SLOT_ENTRY_FEE_MICRO,
    };
    let cloned = cfg.clone();

    assert_eq!(cloned.house_address, cfg.house_address);
    assert_eq!(cloned.entry_fee_micro, cfg.entry_fee_micro);
}

#[test]
fn test_10_game_clone_preserves_config() {
    let game = SlotMachineGame::default();
    let cloned = game.clone();

    assert_eq!(cloned.cfg.house_address, game.cfg.house_address);
    assert_eq!(cloned.cfg.entry_fee_micro, game.cfg.entry_fee_micro);
}

#[test]
fn test_11_house_address_constant_is_canonical_r_wallet() {
    assert_eq!(SLOT_HOUSE_ADDRESS.len(), 129);
    assert!(SLOT_HOUSE_ADDRESS.starts_with('r'));
}

#[test]
fn test_12_house_address_constant_passes_canonical_wallet_check() -> TestResult {
    let checked = canon_wallet_id_checked(SLOT_HOUSE_ADDRESS)?;

    assert_eq!(checked, SLOT_HOUSE_ADDRESS);
    Ok(())
}

#[test]
fn test_13_generated_test_wallet_is_canonical() -> TestResult {
    let wallet = canonical_wallet(13);
    let checked = canon_wallet_id_checked(&wallet)?;

    assert_eq!(checked, wallet);
    Ok(())
}

#[test]
fn test_14_different_generated_wallets_are_unique() {
    let first = canonical_wallet(14);
    let second = canonical_wallet(15);

    assert_ne!(first, second);
}

#[test]
fn test_15_remzar_hash_bytes_are_64_bytes() {
    let digest = RemzarHash::compute_bytes_hash(b"slot game hash vector");

    assert_eq!(digest.len(), 64);
}

#[test]
fn test_16_remzar_hash_is_deterministic_for_same_bytes() {
    let first = RemzarHash::compute_bytes_hash(b"same slot input");
    let second = RemzarHash::compute_bytes_hash(b"same slot input");

    assert_eq!(first, second);
}

#[test]
fn test_17_remzar_hash_changes_when_bytes_change() {
    let first = RemzarHash::compute_bytes_hash(b"slot input A");
    let second = RemzarHash::compute_bytes_hash(b"slot input B");

    assert_ne!(first, second);
}

#[test]
fn test_18_txkind_transfer_tag_is_transfer() -> TestResult {
    let sender = canonical_wallet(18);
    let receiver = canonical_wallet(19);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    assert_eq!(kind.tag(), "transfer");
    Ok(())
}

#[test]
fn test_19_txkind_transfer_validate_accepts_valid_transfer() -> TestResult {
    let sender = canonical_wallet(20);
    let receiver = canonical_wallet(21);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    kind.validate()?;
    Ok(())
}

#[test]
fn test_20_txkind_transfer_touched_addresses_contains_sender_and_receiver() -> TestResult {
    let sender = canonical_wallet(22);
    let receiver = canonical_wallet(23);
    let tx = Transaction::new(sender.clone(), receiver.clone(), SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    let touched: BTreeSet<String> = kind.touched_addresses().into_iter().collect();

    assert_eq!(touched.len(), 2);
    assert!(touched.contains(&sender));
    assert!(touched.contains(&receiver));
    Ok(())
}

#[test]
fn test_21_txkind_transfer_normalized_sender_and_receiver_are_present() -> TestResult {
    let sender = canonical_wallet(24);
    let receiver = canonical_wallet(25);
    let tx = Transaction::new(sender.clone(), receiver.clone(), SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    assert_eq!(kind.normalized_sender().as_deref(), Some(sender.as_str()));
    assert_eq!(
        kind.normalized_receiver().as_deref(),
        Some(receiver.as_str())
    );
    Ok(())
}

#[test]
fn test_22_enqueue_valid_transfer_writes_one_transaction_record() -> TestResult {
    let env = new_test_env("test_22")?;
    let sender = canonical_wallet(26);
    let receiver = canonical_wallet(27);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    assert_eq!(
        cf_count(
            env.db.as_ref(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
        )?,
        1
    );
    Ok(())
}

#[test]
fn test_23_enqueue_valid_transfer_writes_one_hash_record() -> TestResult {
    let env = new_test_env("test_23")?;
    let sender = canonical_wallet(28);
    let receiver = canonical_wallet(29);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        1
    );
    Ok(())
}

#[test]
fn test_24_enqueue_valid_transfer_decodes_as_txkind_transfer() -> TestResult {
    let env = new_test_env("test_24")?;
    let sender = canonical_wallet(30);
    let receiver = canonical_wallet(31);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let tx = single_stored_transfer(&env)?;

    assert_eq!(tx.amount, SLOT_ENTRY_FEE_MICRO);
    Ok(())
}

#[test]
fn test_25_enqueue_valid_transfer_preserves_sender_and_receiver() -> TestResult {
    let env = new_test_env("test_25")?;
    let sender = canonical_wallet(32);
    let receiver = canonical_wallet(33);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let tx = single_stored_transfer(&env)?;
    let stored_sender = std::str::from_utf8(&tx.sender)?;
    let stored_receiver = std::str::from_utf8(&tx.receiver)?;

    assert_eq!(stored_sender, sender);
    assert_eq!(stored_receiver, receiver);
    Ok(())
}

#[test]
fn test_26_enqueue_hash_index_key_matches_remzar_hash_of_stored_txkind() -> TestResult {
    let env = new_test_env("test_26")?;
    let sender = canonical_wallet(34);
    let receiver = canonical_wallet(35);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let tx_values = cf_values(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;
    let hash_keys = cf_keys(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?;

    if tx_values.len() != 1 || hash_keys.len() != 1 {
        return Err(boxed(format!(
            "expected one tx value and one hash key, got {} / {}",
            tx_values.len(),
            hash_keys.len()
        )));
    }

    let stored_tx_bytes = tx_values
        .first()
        .ok_or_else(|| boxed_static("missing stored tx bytes"))?;
    let stored_hash_key = hash_keys
        .first()
        .ok_or_else(|| boxed_static("missing stored hash key"))?;
    let expected_hash = RemzarHash::compute_bytes_hash(stored_tx_bytes);

    assert_eq!(stored_hash_key.as_slice(), expected_hash.as_slice());
    Ok(())
}

#[test]
fn test_27_enqueue_two_different_amounts_writes_two_hash_records() -> TestResult {
    let env = new_test_env("test_27")?;
    let sender = canonical_wallet(36);
    let receiver = canonical_wallet(37);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;
    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO.saturating_add(1),
        &env.logger,
    )?;

    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        2
    );
    Ok(())
}

#[test]
fn test_28_enqueue_two_different_receivers_writes_two_hash_records() -> TestResult {
    let env = new_test_env("test_28")?;
    let sender = canonical_wallet(38);
    let first_receiver = canonical_wallet(39);
    let second_receiver = canonical_wallet(40);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &first_receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;
    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &second_receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        2
    );
    Ok(())
}

#[test]
fn test_29_enqueue_zero_amount_is_rejected_and_writes_nothing() -> TestResult {
    let env = new_test_env("test_29")?;
    let sender = canonical_wallet(41);
    let receiver = canonical_wallet(42);

    let result = enqueue_transfer_to_mempool(env.db.as_ref(), &sender, &receiver, 0, &env.logger);

    assert_err_contains(result, "Amount must be > 0");
    assert_eq!(
        cf_count(
            env.db.as_ref(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
        )?,
        0
    );
    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        0
    );
    Ok(())
}

#[test]
fn test_30_enqueue_self_transfer_is_rejected_and_writes_nothing() -> TestResult {
    let env = new_test_env("test_30")?;
    let sender = canonical_wallet(43);

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &sender,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert_err_contains(result, "Refusing self-transfer");
    assert_eq!(
        cf_count(
            env.db.as_ref(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
        )?,
        0
    );
    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        0
    );
    Ok(())
}

#[test]
fn test_31_enqueue_invalid_sender_prefix_is_rejected() -> TestResult {
    let env = new_test_env("test_31")?;
    let sender = format!("p{}", hex::encode([44u8; 64]));
    let receiver = canonical_wallet(45);

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    assert_eq!(
        cf_count(
            env.db.as_ref(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
        )?,
        0
    );
    Ok(())
}

#[test]
fn test_32_enqueue_invalid_receiver_prefix_is_rejected() -> TestResult {
    let env = new_test_env("test_32")?;
    let sender = canonical_wallet(46);
    let receiver = format!("p{}", hex::encode([47u8; 64]));

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    assert_eq!(
        cf_count(
            env.db.as_ref(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
        )?,
        0
    );
    Ok(())
}

#[test]
fn test_33_enqueue_short_sender_is_rejected() -> TestResult {
    let env = new_test_env("test_33")?;
    let sender = "r1234".to_string();
    let receiver = canonical_wallet(48);

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_34_enqueue_receiver_with_non_hex_body_is_rejected() -> TestResult {
    let env = new_test_env("test_34")?;
    let sender = canonical_wallet(49);
    let receiver = format!("r{}", "g".repeat(128));

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_35_enqueue_u64_max_amount_is_stored_as_payload_amount() -> TestResult {
    let env = new_test_env("test_35")?;
    let sender = canonical_wallet(50);
    let receiver = canonical_wallet(51);

    enqueue_transfer_to_mempool(env.db.as_ref(), &sender, &receiver, u64::MAX, &env.logger)?;

    let tx = single_stored_transfer(&env)?;

    assert_eq!(tx.amount, u64::MAX);
    Ok(())
}

#[test]
fn test_36_enqueue_missing_transaction_cf_returns_database_error() -> TestResult {
    let env = new_minimal_db_env("test_36", &[GlobalConfiguration::TX_TO_HASH_COLUMN_NAME])?;
    let sender = canonical_wallet(52);
    let receiver = canonical_wallet(53);

    let result = enqueue_transfer_to_mempool(
        &env.db,
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(matches!(result, Err(ErrorDetection::DatabaseError { .. })));
    Ok(())
}

#[test]
fn test_37_enqueue_missing_tx_hash_cf_returns_database_error() -> TestResult {
    let env = new_minimal_db_env("test_37", &[GlobalConfiguration::TRANSACTION_COLUMN_NAME])?;
    let sender = canonical_wallet(54);
    let receiver = canonical_wallet(55);

    let result = enqueue_transfer_to_mempool(
        &env.db,
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(matches!(result, Err(ErrorDetection::DatabaseError { .. })));
    Ok(())
}

#[test]
fn test_38_load_enqueue_one_hundred_unique_amounts() -> TestResult {
    let env = new_test_env("test_38")?;
    let sender = canonical_wallet(56);
    let receiver = canonical_wallet(57);

    for offset in 0u64..100u64 {
        enqueue_transfer_to_mempool(
            env.db.as_ref(),
            &sender,
            &receiver,
            SLOT_ENTRY_FEE_MICRO.saturating_add(offset),
            &env.logger,
        )?;
    }

    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        100
    );
    Ok(())
}

#[test]
fn test_39_concurrent_enqueue_unique_transfers() -> TestResult {
    let env = new_test_env("test_39")?;
    let db = Arc::clone(&env.db);
    let logger = Arc::new(env.logger);

    let mut handles = Vec::new();

    for worker in 0u64..4u64 {
        let db_clone = Arc::clone(&db);
        let logger_clone = Arc::clone(&logger);

        let handle = std::thread::spawn(move || -> Result<(), ErrorDetection> {
            let sender_byte = u8::try_from(60u64.saturating_add(worker)).unwrap_or_default();
            let receiver_byte = u8::try_from(70u64.saturating_add(worker)).unwrap_or_default();

            let sender = canonical_wallet(sender_byte);
            let receiver = canonical_wallet(receiver_byte);

            for offset in 0u64..25u64 {
                let amount = SLOT_ENTRY_FEE_MICRO
                    .saturating_add(worker.saturating_mul(1_000))
                    .saturating_add(offset);

                enqueue_transfer_to_mempool(
                    db_clone.as_ref(),
                    &sender,
                    &receiver,
                    amount,
                    logger_clone.as_ref(),
                )?;
            }

            Ok(())
        });

        handles.push(handle);
    }

    for handle in handles {
        let joined = handle.join();
        match joined {
            Ok(result) => {
                assert!(result.is_ok());
            }
            Err(_) => {
                assert!(false, "worker thread panicked");
            }
        }
    }

    assert_eq!(
        cf_count(db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        100
    );
    Ok(())
}

#[test]
fn test_40_slot_machine_context_callbacks_are_callable_without_interactive_play() -> TestResult {
    let env = new_test_env("test_40")?;
    let sender = canonical_wallet(80);
    let receiver = canonical_wallet(81);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;

    let mut sent_count = 0u64;
    let mut send_net_cmd = |cmd: NetCmd| -> Result<(), ErrorDetection> {
        if let NetCmd::SendTx(_) = cmd {
            sent_count = sent_count.saturating_add(1);
        }
        Ok(())
    };

    let mut get_balance_micro = |_wallet: &str| -> u64 { 123u64 };

    {
        let ctx = SlotMachineContext {
            opts: &env.opts,
            db: env.db.as_ref(),
            json_logger: &env.logger,
            send_net_cmd: &mut send_net_cmd,
            get_balance_micro: &mut get_balance_micro,
        };

        assert_eq!((ctx.get_balance_micro)("any-wallet"), 123);
        (ctx.send_net_cmd)(NetCmd::SendTx(tx))?;
    }

    assert_eq!(sent_count, 1);
    Ok(())
}

#[test]
fn test_41_entry_fee_is_nonzero_and_not_above_max_payout() {
    let game = SlotMachineGame::default();

    assert!(SLOT_ENTRY_FEE_MICRO > 0);
    assert!(SLOT_ENTRY_FEE_MICRO <= game.max_payout_micro());
}

#[test]
fn test_42_max_payout_is_exactly_100_entry_fees() {
    let game = SlotMachineGame::default();

    assert_eq!(
        game.max_payout_micro().div_euclid(SLOT_ENTRY_FEE_MICRO),
        100
    );
}

#[test]
fn test_43_custom_zero_fee_config_does_not_change_public_max_payout() {
    let game = SlotMachineGame {
        cfg: SlotMachineGameConfig {
            house_address: SLOT_HOUSE_ADDRESS,
            entry_fee_micro: 0,
        },
    };

    assert_eq!(game.max_payout_micro(), 100u64.saturating_mul(UNIT_DIVISOR));
}

#[test]
fn test_44_custom_large_fee_config_does_not_change_public_max_payout() {
    let game = SlotMachineGame {
        cfg: SlotMachineGameConfig {
            house_address: SLOT_HOUSE_ADDRESS,
            entry_fee_micro: u64::MAX,
        },
    };

    assert_eq!(game.max_payout_micro(), 100u64.saturating_mul(UNIT_DIVISOR));
}

#[test]
fn test_45_house_address_canonical_check_returns_exact_constant() -> TestResult {
    let checked = canon_wallet_id_checked(SLOT_HOUSE_ADDRESS)?;

    assert_eq!(checked, SLOT_HOUSE_ADDRESS);
    Ok(())
}

#[test]
fn test_46_house_address_body_is_lowercase_hex() -> TestResult {
    let body = SLOT_HOUSE_ADDRESS
        .get(1..)
        .ok_or_else(|| boxed_static("house address missing body"))?;

    assert_eq!(body.len(), 128);
    assert!(
        body.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    Ok(())
}

#[test]
fn test_47_generated_wallet_vector_set_all_canonical() -> TestResult {
    for byte in 1u8..=40u8 {
        let wallet = canonical_wallet(byte);
        let checked = canon_wallet_id_checked(&wallet)?;

        assert_eq!(checked, wallet);
        assert_eq!(checked.len(), 129);
    }

    Ok(())
}

#[test]
fn test_48_generated_wallet_vector_set_all_unique() {
    let mut seen = BTreeSet::new();

    for byte in 41u8..=80u8 {
        let inserted = seen.insert(canonical_wallet(byte));
        assert!(inserted);
    }

    assert_eq!(seen.len(), 40);
}

#[test]
fn test_49_txkind_transfer_postcard_roundtrip_preserves_amount() -> TestResult {
    let sender = canonical_wallet(82);
    let receiver = canonical_wallet(83);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    let bytes = kind.serialize()?;
    let decoded = TxKind::deserialize(&bytes)?;

    match decoded {
        TxKind::Transfer(decoded_tx) => {
            assert_eq!(decoded_tx.amount, SLOT_ENTRY_FEE_MICRO);
        }
        other => {
            return Err(boxed(format!("expected transfer, got {}", other.tag())));
        }
    }

    Ok(())
}

#[test]
fn test_50_txkind_transfer_serialized_hash_is_deterministic() -> TestResult {
    let sender = canonical_wallet(84);
    let receiver = canonical_wallet(85);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    let bytes = kind.serialize()?;
    let first = RemzarHash::compute_bytes_hash(&bytes);
    let second = RemzarHash::compute_bytes_hash(&bytes);

    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    Ok(())
}

#[test]
fn test_51_remzar_hash_hex_for_transfer_is_128_chars() -> TestResult {
    let sender = canonical_wallet(86);
    let receiver = canonical_wallet(87);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);
    let bytes = kind.serialize()?;

    let hash_hex = RemzarHash::compute_bytes_hash_hex(&bytes);

    assert_eq!(hash_hex.len(), 128);
    assert!(
        hash_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    Ok(())
}

#[test]
fn test_52_truncated_hash_for_transfer_is_16_chars() -> TestResult {
    let sender = canonical_wallet(88);
    let receiver = canonical_wallet(89);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    let truncated = RemzarHash::compute_truncated_hash(&kind)?;

    assert_eq!(truncated.len(), 16);
    assert!(
        truncated
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    Ok(())
}

#[test]
fn test_53_verify_data_hash_accepts_matching_transfer_hash() -> TestResult {
    let sender = canonical_wallet(90);
    let receiver = canonical_wallet(91);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    let hash = RemzarHash::compute_data_hash(&kind)?;
    let verified = RemzarHash::verify_data_hash(&kind, &hash)?;

    assert!(verified);
    Ok(())
}

#[test]
fn test_54_verify_data_hash_rejects_different_valid_hash() -> TestResult {
    let sender = canonical_wallet(92);
    let receiver = canonical_wallet(93);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    let other_sender = canonical_wallet(94);
    let other_receiver = canonical_wallet(95);
    let other_tx = Transaction::new(other_sender, other_receiver, SLOT_ENTRY_FEE_MICRO)?;
    let other_kind = TxKind::Transfer(other_tx);

    let other_hash = RemzarHash::compute_data_hash(&other_kind)?;
    let verified = RemzarHash::verify_data_hash(&kind, &other_hash)?;

    assert!(!verified);
    Ok(())
}

#[test]
fn test_55_enqueue_valid_transfer_into_minimal_db_with_required_cfs() -> TestResult {
    let env = new_minimal_db_env(
        "test_55",
        &[
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        ],
    )?;
    let sender = canonical_wallet(96);
    let receiver = canonical_wallet(97);

    enqueue_transfer_to_mempool(
        &env.db,
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    assert_eq!(
        cf_count(&env.db, GlobalConfiguration::TRANSACTION_COLUMN_NAME)?,
        1
    );
    assert_eq!(
        cf_count(&env.db, GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        1
    );
    Ok(())
}

#[test]
fn test_56_minimal_db_stored_value_decodes_as_transfer() -> TestResult {
    let env = new_minimal_db_env(
        "test_56",
        &[
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        ],
    )?;
    let sender = canonical_wallet(98);
    let receiver = canonical_wallet(99);

    enqueue_transfer_to_mempool(
        &env.db,
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let values = cf_values(&env.db, GlobalConfiguration::TRANSACTION_COLUMN_NAME)?;
    let value = values
        .first()
        .ok_or_else(|| boxed_static("missing stored tx value"))?;
    let decoded = TxKind::deserialize(value)?;

    assert_eq!(decoded.tag(), "transfer");
    Ok(())
}

#[test]
fn test_57_minimal_db_hash_key_is_64_bytes() -> TestResult {
    let env = new_minimal_db_env(
        "test_57",
        &[
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        ],
    )?;
    let sender = canonical_wallet(100);
    let receiver = canonical_wallet(101);

    enqueue_transfer_to_mempool(
        &env.db,
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let keys = cf_keys(&env.db, GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?;
    let key = keys
        .first()
        .ok_or_else(|| boxed_static("missing hash key"))?;

    assert_eq!(key.len(), 64);
    Ok(())
}

#[test]
fn test_58_transaction_column_key_uses_tx_prefix() -> TestResult {
    let env = new_test_env("test_58")?;
    let sender = canonical_wallet(102);
    let receiver = canonical_wallet(103);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let keys = cf_keys(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;
    let key = keys
        .first()
        .ok_or_else(|| boxed_static("missing transaction key"))?;
    let key_string = std::str::from_utf8(key)?;

    assert!(key_string.starts_with("tx_"));
    Ok(())
}

#[test]
fn test_59_transaction_column_key_has_three_underscore_parts() -> TestResult {
    let env = new_test_env("test_59")?;
    let sender = canonical_wallet(104);
    let receiver = canonical_wallet(105);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let keys = cf_keys(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;
    let key = keys
        .first()
        .ok_or_else(|| boxed_static("missing transaction key"))?;
    let key_string = std::str::from_utf8(key)?;
    let parts: Vec<&str> = key_string.split('_').collect();

    assert_eq!(parts.len(), 3);
    assert_eq!(parts.first().copied(), Some("tx"));
    Ok(())
}

#[test]
fn test_60_hash_cf_value_equals_transaction_cf_value_for_single_enqueue() -> TestResult {
    let env = new_test_env("test_60")?;
    let sender = canonical_wallet(106);
    let receiver = canonical_wallet(107);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let tx_values = cf_values(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;
    let hash_values = cf_values(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?;

    assert_eq!(tx_values.len(), 1);
    assert_eq!(hash_values.len(), 1);
    assert_eq!(tx_values.first(), hash_values.first());
    Ok(())
}

#[test]
fn test_61_hash_cf_key_matches_value_hash_for_single_enqueue() -> TestResult {
    let env = new_test_env("test_61")?;
    let sender = canonical_wallet(108);
    let receiver = canonical_wallet(109);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let hash_keys = cf_keys(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?;
    let hash_values = cf_values(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?;

    let key = hash_keys
        .first()
        .ok_or_else(|| boxed_static("missing hash key"))?;
    let value = hash_values
        .first()
        .ok_or_else(|| boxed_static("missing hash value"))?;

    assert_eq!(
        key.as_slice(),
        RemzarHash::compute_bytes_hash(value).as_slice()
    );
    Ok(())
}

#[test]
fn test_62_stored_transfer_validate_passes_after_enqueue() -> TestResult {
    let env = new_test_env("test_62")?;
    let sender = canonical_wallet(110);
    let receiver = canonical_wallet(111);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let tx = single_stored_transfer(&env)?;
    tx.validate()?;

    Ok(())
}

#[test]
fn test_63_load_enqueue_fifty_unique_senders_same_receiver() -> TestResult {
    let env = new_test_env("test_63")?;
    let receiver = canonical_wallet(112);

    for byte in 113u8..=162u8 {
        let sender = canonical_wallet(byte);
        enqueue_transfer_to_mempool(
            env.db.as_ref(),
            &sender,
            &receiver,
            SLOT_ENTRY_FEE_MICRO,
            &env.logger,
        )?;
    }

    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        50
    );
    Ok(())
}

#[test]
fn test_64_load_enqueue_fifty_unique_receivers_same_sender() -> TestResult {
    let env = new_test_env("test_64")?;
    let sender = canonical_wallet(163);

    for byte in 164u8..=213u8 {
        let receiver = canonical_wallet(byte);
        enqueue_transfer_to_mempool(
            env.db.as_ref(),
            &sender,
            &receiver,
            SLOT_ENTRY_FEE_MICRO,
            &env.logger,
        )?;
    }

    assert_eq!(
        cf_count(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        50
    );
    Ok(())
}

#[test]
fn test_65_load_enqueue_twenty_five_unique_amounts_minimal_db() -> TestResult {
    let env = new_minimal_db_env(
        "test_65",
        &[
            GlobalConfiguration::TRANSACTION_COLUMN_NAME,
            GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        ],
    )?;
    let sender = canonical_wallet(214);
    let receiver = canonical_wallet(215);

    for offset in 0u64..25u64 {
        enqueue_transfer_to_mempool(
            &env.db,
            &sender,
            &receiver,
            SLOT_ENTRY_FEE_MICRO.saturating_add(offset),
            &env.logger,
        )?;
    }

    assert_eq!(
        cf_count(&env.db, GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?,
        25
    );
    Ok(())
}

#[test]
fn test_66_all_load_inserted_values_decode_as_transfer() -> TestResult {
    let env = new_test_env("test_66")?;
    let sender = canonical_wallet(216);

    for byte in 217u8..=226u8 {
        let receiver = canonical_wallet(byte);
        enqueue_transfer_to_mempool(
            env.db.as_ref(),
            &sender,
            &receiver,
            SLOT_ENTRY_FEE_MICRO,
            &env.logger,
        )?;
    }

    let values = cf_values(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;
    assert_eq!(values.len(), 10);

    for value in values {
        let decoded = TxKind::deserialize(&value)?;
        assert_eq!(decoded.tag(), "transfer");
    }

    Ok(())
}

#[test]
fn test_67_all_load_inserted_transfers_validate() -> TestResult {
    let env = new_test_env("test_67")?;
    let sender = canonical_wallet(227);

    for byte in 228u8..=237u8 {
        let receiver = canonical_wallet(byte);
        enqueue_transfer_to_mempool(
            env.db.as_ref(),
            &sender,
            &receiver,
            SLOT_ENTRY_FEE_MICRO.saturating_add(u64::from(byte)),
            &env.logger,
        )?;
    }

    let values = cf_values(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;

    for value in values {
        let decoded = TxKind::deserialize(&value)?;
        decoded.validate()?;
    }

    Ok(())
}

#[test]
fn test_68_stored_transaction_id_is_64_hex_chars() -> TestResult {
    let env = new_test_env("test_68")?;
    let sender = canonical_wallet(238);
    let receiver = canonical_wallet(239);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    let tx = single_stored_transfer(&env)?;
    let id = tx.id()?;

    assert_eq!(id.len(), 64);
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    Ok(())
}

#[test]
fn test_69_transaction_amount_as_remzar_for_entry_fee_is_one() -> TestResult {
    let tx = Transaction::new(
        canonical_wallet(240),
        canonical_wallet(241),
        SLOT_ENTRY_FEE_MICRO,
    )?;
    let formatted = remzar::utility::helper::format_remzar_trim(tx.amount);

    assert_eq!(formatted, "1");
    Ok(())
}

#[test]
fn test_70_enqueue_empty_sender_is_rejected() -> TestResult {
    let env = new_test_env("test_70")?;
    let receiver = canonical_wallet(242);

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        "",
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_71_enqueue_empty_receiver_is_rejected() -> TestResult {
    let env = new_test_env("test_71")?;
    let sender = canonical_wallet(243);

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        "",
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_72_enqueue_too_long_sender_is_rejected() -> TestResult {
    let env = new_test_env("test_72")?;
    let sender = format!("r{}00", hex::encode([244u8; 64]));
    let receiver = canonical_wallet(245);

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_73_enqueue_too_short_receiver_is_rejected() -> TestResult {
    let env = new_test_env("test_73")?;
    let sender = canonical_wallet(246);
    let receiver = format!("r{}", hex::encode([247u8; 63]));

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_74_enqueue_receiver_with_non_hex_z_body_is_rejected() -> TestResult {
    let env = new_test_env("test_74")?;
    let sender = canonical_wallet(248);
    let receiver = format!("r{}", "z".repeat(128));

    let result = enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_75_enqueue_db_with_only_default_cf_returns_database_error() -> TestResult {
    let env = new_minimal_db_env("test_75", &[])?;
    let sender = canonical_wallet(249);
    let receiver = canonical_wallet(250);

    let result = enqueue_transfer_to_mempool(
        &env.db,
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    );

    assert!(matches!(result, Err(ErrorDetection::DatabaseError { .. })));
    Ok(())
}

#[test]
fn test_76_json_logger_error_event_and_flush_succeed() -> TestResult {
    let env = new_test_env("test_76")?;

    env.logger
        .log_error_event("slot_test", "SyntheticError", "synthetic message")
        .map_err(boxed)?;
    env.logger.flush_logs_cf().map_err(boxed)?;

    Ok(())
}

#[test]
fn test_77_json_logger_general_flush_succeeds() -> TestResult {
    let env = new_test_env("test_77")?;

    env.logger
        .log_error_event("slot_test", "FlushEvent", "flush message")
        .map_err(boxed)?;
    env.logger.flush().map_err(boxed)?;

    Ok(())
}

#[test]
fn test_78_slot_machine_context_send_txkind_callback_is_callable() -> TestResult {
    let env = new_test_env("test_78")?;
    let sender = canonical_wallet(251);
    let receiver = canonical_wallet(252);
    let tx = Transaction::new(sender, receiver, SLOT_ENTRY_FEE_MICRO)?;
    let kind = TxKind::Transfer(tx);

    let mut send_txkind_count = 0u64;
    let mut send_net_cmd = |cmd: NetCmd| -> Result<(), ErrorDetection> {
        if let NetCmd::SendTxKind(_) = cmd {
            send_txkind_count = send_txkind_count.saturating_add(1);
        }
        Ok(())
    };

    let mut get_balance_micro = |_wallet: &str| -> u64 { SLOT_ENTRY_FEE_MICRO };

    {
        let ctx = SlotMachineContext {
            opts: &env.opts,
            db: env.db.as_ref(),
            json_logger: &env.logger,
            send_net_cmd: &mut send_net_cmd,
            get_balance_micro: &mut get_balance_micro,
        };

        (ctx.send_net_cmd)(NetCmd::SendTxKind(kind))?;
    }

    assert_eq!(send_txkind_count, 1);
    Ok(())
}

#[test]
fn test_79_slot_machine_context_balance_callback_can_branch_by_wallet() -> TestResult {
    let env = new_test_env("test_79")?;
    let rich_wallet = canonical_wallet(253);
    let poor_wallet = canonical_wallet(254);

    let mut send_net_cmd = |_cmd: NetCmd| -> Result<(), ErrorDetection> { Ok(()) };
    let mut get_balance_micro = |wallet: &str| -> u64 {
        if wallet == rich_wallet {
            500u64.saturating_mul(UNIT_DIVISOR)
        } else {
            0
        }
    };

    let ctx = SlotMachineContext {
        opts: &env.opts,
        db: env.db.as_ref(),
        json_logger: &env.logger,
        send_net_cmd: &mut send_net_cmd,
        get_balance_micro: &mut get_balance_micro,
    };

    assert_eq!(
        (ctx.get_balance_micro)(&rich_wallet),
        500u64.saturating_mul(UNIT_DIVISOR)
    );
    assert_eq!((ctx.get_balance_micro)(&poor_wallet), 0);
    Ok(())
}

#[test]
fn test_80_load_remzar_hash_unique_for_256_small_vectors() {
    let mut seen = BTreeSet::new();

    for byte in u8::MIN..=u8::MAX {
        let data = vec![byte; 32];
        let digest = RemzarHash::compute_bytes_hash(&data);
        let inserted = seen.insert(digest);

        assert!(inserted);
    }

    assert_eq!(seen.len(), 256);
}

#[test]
fn test_81_vector_empty_bytes_remzar_hash_first_32_match_blake3_default() {
    let digest = RemzarHash::compute_bytes_hash(b"");
    let reference = blake3::hash(b"");

    assert_eq!(digest.get(..32), Some(reference.as_bytes().as_slice()));
}

#[test]
fn test_82_vector_abc_remzar_hash_first_32_match_blake3_default() {
    let digest = RemzarHash::compute_bytes_hash(b"abc");
    let reference = blake3::hash(b"abc");

    assert_eq!(digest.get(..32), Some(reference.as_bytes().as_slice()));
}

#[test]
fn test_83_vector_slot_phrase_remzar_hash_first_32_match_blake3_default() {
    let input = b"remzar slot machine vector";
    let digest = RemzarHash::compute_bytes_hash(input);
    let reference = blake3::hash(input);

    assert_eq!(digest.get(..32), Some(reference.as_bytes().as_slice()));
}

#[test]
fn test_84_vector_empty_and_zero_byte_hashes_differ() {
    let empty = RemzarHash::compute_bytes_hash(b"");
    let zero = RemzarHash::compute_bytes_hash(&[0u8]);

    assert_ne!(empty, zero);
}

#[test]
fn test_85_vector_ascii_zero_and_binary_zero_hashes_differ() {
    let ascii_zero = RemzarHash::compute_bytes_hash(b"0");
    let binary_zero = RemzarHash::compute_bytes_hash(&[0u8]);

    assert_ne!(ascii_zero, binary_zero);
}

#[test]
fn test_86_edge_canonical_wallet_uppercase_prefix_is_canonicalized() -> TestResult {
    let wallet = format!("R{}", hex::encode([86u8; 64]));
    let expected = canonical_wallet(86);

    let checked = canon_wallet_id_checked(&wallet)?;

    assert_eq!(checked, expected);
    assert!(checked.starts_with('r'));
    Ok(())
}

#[test]
fn test_87_edge_canonical_wallet_uppercase_hex_body_is_canonicalized() -> TestResult {
    let wallet = format!("r{}", hex::encode([171u8; 64]).to_ascii_uppercase());
    let expected = canonical_wallet(171);

    let checked = canon_wallet_id_checked(&wallet)?;

    assert_eq!(checked, expected);
    assert!(
        checked
            .get(1..)
            .unwrap_or_default()
            .chars()
            .all(|c| { c.is_ascii_hexdigit() && !c.is_ascii_uppercase() })
    );
    Ok(())
}

#[test]
fn test_88_edge_canonical_wallet_rejects_embedded_space() {
    let mut wallet = canonical_wallet(88);
    wallet.insert(10, ' ');

    let checked = canon_wallet_id_checked(&wallet);

    assert!(checked.is_err());
}

#[test]
fn test_89_edge_canonical_wallet_trims_outer_whitespace_if_helper_allows_it() -> TestResult {
    let wallet = canonical_wallet(89);
    let padded = format!("  {wallet}\n");
    let checked = canon_wallet_id_checked(&padded)?;

    assert_eq!(checked, wallet);
    Ok(())
}

#[test]
fn test_90_edge_transaction_new_rejects_zero_amount() {
    let sender = canonical_wallet(90);
    let receiver = canonical_wallet(91);

    let result = Transaction::new(sender, receiver, 0);

    assert!(result.is_err());
}

#[test]
fn test_91_edge_transaction_new_rejects_same_sender_receiver() {
    let sender = canonical_wallet(92);

    let result = Transaction::new(sender.clone(), sender, SLOT_ENTRY_FEE_MICRO);

    assert!(result.is_err());
}

#[test]
fn test_92_edge_txkind_deserialize_rejects_empty_bytes() {
    let result = TxKind::deserialize(&[]);

    assert!(result.is_err());
}

#[test]
fn test_93_edge_txkind_deserialize_rejects_garbage_bytes() {
    let garbage = [255u8; 64];
    let result = TxKind::deserialize(&garbage);

    assert!(result.is_err());
}

#[test]
fn test_94_vector_txkind_transfer_roundtrip_for_boundary_amounts() -> TestResult {
    let amounts = [
        1u64,
        SLOT_ENTRY_FEE_MICRO,
        SLOT_ENTRY_FEE_MICRO.saturating_add(1),
        100u64.saturating_mul(UNIT_DIVISOR),
        u64::MAX,
    ];

    for amount in amounts {
        let tx = Transaction::new(canonical_wallet(94), canonical_wallet(95), amount)?;
        let kind = TxKind::Transfer(tx);
        let encoded = kind.serialize()?;
        let decoded = TxKind::deserialize(&encoded)?;

        match decoded {
            TxKind::Transfer(decoded_tx) => {
                assert_eq!(decoded_tx.amount, amount);
            }
            other => {
                return Err(boxed(format!("expected transfer, got {}", other.tag())));
            }
        }
    }

    Ok(())
}

#[test]
fn test_95_vector_enqueue_boundary_amounts_each_decode_correctly() -> TestResult {
    let env = new_test_env("test_95")?;
    let sender = canonical_wallet(96);
    let receiver = canonical_wallet(97);
    let amounts = [
        1u64,
        SLOT_ENTRY_FEE_MICRO,
        SLOT_ENTRY_FEE_MICRO.saturating_add(9),
        100u64.saturating_mul(UNIT_DIVISOR),
    ];

    for amount in amounts {
        enqueue_transfer_to_mempool(env.db.as_ref(), &sender, &receiver, amount, &env.logger)?;
    }

    let values = cf_values(
        env.db.as_ref(),
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
    )?;
    let mut decoded_amounts = BTreeSet::new();

    for value in values {
        let decoded = TxKind::deserialize(&value)?;
        match decoded {
            TxKind::Transfer(tx) => {
                decoded_amounts.insert(tx.amount);
            }
            other => {
                return Err(boxed(format!("expected transfer, got {}", other.tag())));
            }
        }
    }

    assert_eq!(decoded_amounts.len(), 4);
    assert!(decoded_amounts.contains(&1u64));
    assert!(decoded_amounts.contains(&SLOT_ENTRY_FEE_MICRO));
    assert!(decoded_amounts.contains(&SLOT_ENTRY_FEE_MICRO.saturating_add(9)));
    assert!(decoded_amounts.contains(&100u64.saturating_mul(UNIT_DIVISOR)));
    Ok(())
}

#[test]
fn test_96_edge_enqueue_sender_with_newline_is_trimmed_and_accepted() -> TestResult {
    let env = new_test_env("test_96")?;
    let sender = canonical_wallet(98);
    let sender_with_newline = format!("{sender}\n");
    let receiver = canonical_wallet(99);

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender_with_newline,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    assert_eq!(
        cf_count(
            env.db.as_ref(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
        )?,
        1
    );

    let tx = single_stored_transfer(&env)?;
    let stored_sender = std::str::from_utf8(&tx.sender)?;

    assert_eq!(stored_sender, sender);
    Ok(())
}

#[test]
fn test_97_edge_enqueue_receiver_with_tab_is_trimmed_and_accepted() -> TestResult {
    let env = new_test_env("test_97")?;
    let sender = canonical_wallet(100);
    let receiver = canonical_wallet(101);
    let receiver_with_tab = format!("{receiver}\t");

    enqueue_transfer_to_mempool(
        env.db.as_ref(),
        &sender,
        &receiver_with_tab,
        SLOT_ENTRY_FEE_MICRO,
        &env.logger,
    )?;

    assert_eq!(
        cf_count(
            env.db.as_ref(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
        )?,
        1
    );

    let tx = single_stored_transfer(&env)?;
    let stored_receiver = std::str::from_utf8(&tx.receiver)?;

    assert_eq!(stored_receiver, receiver);
    Ok(())
}

#[test]
fn test_98_vector_hash_cf_keys_are_unique_for_vector_amounts() -> TestResult {
    let env = new_test_env("test_98")?;
    let sender = canonical_wallet(102);
    let receiver = canonical_wallet(103);

    for amount in 1u64..=20u64 {
        enqueue_transfer_to_mempool(env.db.as_ref(), &sender, &receiver, amount, &env.logger)?;
    }

    let keys = cf_keys(env.db.as_ref(), GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?;
    let unique: BTreeSet<Vec<u8>> = keys.into_iter().collect();

    assert_eq!(unique.len(), 20);
    Ok(())
}

#[test]
fn test_99_edge_verify_data_hash_rejects_short_expected_hash() -> TestResult {
    let tx = Transaction::new(
        canonical_wallet(104),
        canonical_wallet(105),
        SLOT_ENTRY_FEE_MICRO,
    )?;
    let kind = TxKind::Transfer(tx);

    let result = RemzarHash::verify_data_hash(&kind, "abc");

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_100_edge_compute_data_hash_batch_rejects_empty_batch() {
    let empty: Vec<TxKind> = Vec::new();
    let result = RemzarHash::compute_data_hash_batch(&empty);

    assert!(result.is_err());
}
