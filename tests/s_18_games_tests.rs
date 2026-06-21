use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::network::p2p_010_netcmd::NetCmd;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::{Mode, RockDBManager};
use remzar::tokens::game_slot_machine::{
    SLOT_ENTRY_FEE_MICRO, SLOT_HOUSE_ADDRESS, SlotMachineContext, SlotMachineGame,
    SlotMachineGameConfig, SpinResult, enqueue_transfer_to_mempool,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::{UNIT_DIVISOR, from_micro_units};
use remzar::utility::logging_data::JsonLogger;
use rust_rocksdb::{DB, IteratorMode};

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
        path.push(format!(
            "remzar_game_slot_{case_name}_{}",
            uuid::Uuid::new_v4()
        ));
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

fn wallet_with_pair(pair: &str) -> String {
    let mut wallet = String::from("r");
    for _ in 0..64 {
        wallet.push_str(pair);
    }
    wallet
}

fn wallet_upper_with_pair(pair: &str) -> String {
    let mut wallet = String::from("r");
    let upper = pair.to_ascii_uppercase();
    for _ in 0..64 {
        wallet.push_str(&upper);
    }
    wallet
}

fn make_logger(root: &Path) -> TestResult<JsonLogger> {
    let directory = DirectoryDB::from_base_dir(root).map_err(string_error)?;
    directory.create_log_directory().map_err(string_error)?;
    JsonLogger::new(&directory).map_err(string_error)
}

fn make_blockchain_db(
    case_name: &str,
) -> TestResult<(TempRoot, NodeOpts, RockDBManager, Arc<DB>, JsonLogger)> {
    let temp = TempRoot::new(case_name)?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    let db_path = path_to_string(&directory.blockchain_path)?;
    let manager = RockDBManager::new_blockchain(&opts, &db_path)?;
    assert_eq!(manager.mode, Mode::Blockchain);
    let db = manager.open_db_blockchain()?;
    let logger = make_logger(temp.path())?;
    Ok((temp, opts, manager, db, logger))
}

fn cf_count(db: &DB, cf_name: &str) -> TestResult<usize> {
    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| boxed_error("missing column family"))?;
    Ok(db.iterator_cf(cf, IteratorMode::Start).flatten().count())
}

fn tx_count(db: &DB) -> TestResult<usize> {
    cf_count(db, GlobalConfiguration::TRANSACTION_COLUMN_NAME)
}

fn tx_hash_count(db: &DB) -> TestResult<usize> {
    cf_count(db, GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
}

fn tx_values(db: &DB) -> TestResult<Vec<Vec<u8>>> {
    let cf = db
        .cf_handle(GlobalConfiguration::TRANSACTION_COLUMN_NAME)
        .ok_or_else(|| boxed_error("missing transaction column family"))?;
    Ok(db
        .iterator_cf(cf, IteratorMode::Start)
        .flatten()
        .map(|(_key, value)| value.to_vec())
        .collect())
}

fn first_transfer_amount(db: &DB) -> TestResult<u64> {
    let values = tx_values(db)?;
    let first = values
        .first()
        .ok_or_else(|| boxed_error("missing stored transaction"))?;
    match TxKind::deserialize(first)? {
        TxKind::Transfer(tx) => Ok(tx.amount),
        _ => Err(boxed_error("stored tx was not transfer")),
    }
}

fn assert_error_contains<T, E: std::fmt::Display>(
    result: Result<T, E>,
    needle: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(boxed_error("expected operation to fail")),
        Err(error) => {
            let message = error.to_string();
            let message_lower = message.to_ascii_lowercase();
            let needle_lower = needle.to_ascii_lowercase();
            assert!(
                message_lower.contains(&needle_lower),
                "error message did not contain '{needle}': {message}"
            );
            Ok(())
        }
    }
}

fn write_wallet_blob(root: &Path, wallet: &str, bytes: &[u8]) -> TestResult<PathBuf> {
    let opts = node_opts(root)?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    directory.create_wallets_directory().map_err(string_error)?;
    let path = directory.wallets_path.join(format!("{wallet}.wallet"));
    fs::write(&path, bytes)?;
    Ok(path)
}

fn make_context<'a>(
    opts: &'a NodeOpts,
    db: &'a DB,
    logger: &'a JsonLogger,
    send_net_cmd: &'a mut dyn FnMut(NetCmd) -> Result<(), ErrorDetection>,
    get_balance_micro: &'a mut dyn FnMut(&str) -> u64,
) -> SlotMachineContext<'a> {
    SlotMachineContext {
        opts,
        db,
        json_logger: logger,
        send_net_cmd,
        get_balance_micro,
    }
}

#[test]
fn game_01_default_config_uses_fixed_house_wallet() -> TestResult {
    let cfg = SlotMachineGameConfig::default();
    assert_eq!(cfg.house_address, SLOT_HOUSE_ADDRESS);
    Ok(())
}

#[test]
fn game_02_default_config_uses_fixed_entry_fee() -> TestResult {
    let cfg = SlotMachineGameConfig::default();
    assert_eq!(cfg.entry_fee_micro, SLOT_ENTRY_FEE_MICRO);
    Ok(())
}

#[test]
fn game_03_entry_fee_is_one_remzar_micro_unit() -> TestResult {
    assert_eq!(SLOT_ENTRY_FEE_MICRO, UNIT_DIVISOR);
    Ok(())
}

#[test]
fn game_04_house_wallet_has_remzar_prefix() -> TestResult {
    assert!(SLOT_HOUSE_ADDRESS.starts_with('r'));
    Ok(())
}

#[test]
fn game_05_house_wallet_has_expected_length() -> TestResult {
    assert_eq!(SLOT_HOUSE_ADDRESS.len(), 129);
    Ok(())
}

#[test]
fn game_06_house_wallet_tail_is_ascii_hex() -> TestResult {
    assert!(
        SLOT_HOUSE_ADDRESS[1..]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
    Ok(())
}

#[test]
fn game_07_house_wallet_is_lowercase_canonical_text() -> TestResult {
    assert_eq!(SLOT_HOUSE_ADDRESS, SLOT_HOUSE_ADDRESS.to_ascii_lowercase());
    Ok(())
}

#[test]
fn game_08_default_game_max_payout_is_100_remzar() -> TestResult {
    let game = SlotMachineGame::default();
    assert_eq!(game.max_payout_micro(), 100u64.saturating_mul(UNIT_DIVISOR));
    Ok(())
}

#[test]
fn game_09_new_game_with_default_config_matches_default_game() -> TestResult {
    let direct = SlotMachineGame {
        cfg: SlotMachineGameConfig::default(),
    };
    let default = SlotMachineGame::default();
    assert_eq!(direct.max_payout_micro(), default.max_payout_micro());
    Ok(())
}

#[test]
fn game_10_custom_entry_fee_does_not_change_fixed_jackpot_cap() -> TestResult {
    let game = SlotMachineGame {
        cfg: SlotMachineGameConfig {
            house_address: SLOT_HOUSE_ADDRESS,
            entry_fee_micro: 7,
        },
    };
    assert_eq!(game.max_payout_micro(), 100u64.saturating_mul(UNIT_DIVISOR));
    Ok(())
}

#[test]
fn game_11_spin_result_zero_is_loss() -> TestResult {
    let spin = SpinResult { payout_micro: 0 };
    assert!(!spin.is_win());
    Ok(())
}

#[test]
fn game_12_spin_result_one_micro_is_win() -> TestResult {
    let spin = SpinResult { payout_micro: 1 };
    assert!(spin.is_win());
    Ok(())
}

#[test]
fn game_13_spin_result_entry_fee_amount_is_win() -> TestResult {
    let spin = SpinResult {
        payout_micro: SLOT_ENTRY_FEE_MICRO,
    };
    assert!(spin.is_win());
    Ok(())
}

#[test]
fn game_14_spin_result_max_u64_is_win() -> TestResult {
    let spin = SpinResult {
        payout_micro: u64::MAX,
    };
    assert!(spin.is_win());
    Ok(())
}

#[test]
fn game_15_spin_result_copy_preserves_amount() -> TestResult {
    let spin = SpinResult { payout_micro: 42 };
    let copied = spin;
    assert_eq!(copied.payout_micro, 42);
    Ok(())
}

#[test]
fn game_16_spin_result_debug_mentions_amount_field() -> TestResult {
    let spin = SpinResult { payout_micro: 42 };
    assert!(format!("{spin:?}").contains("payout_micro"));
    Ok(())
}

#[test]
fn game_17_config_clone_preserves_fields() -> TestResult {
    let cfg = SlotMachineGameConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cloned.house_address, SLOT_HOUSE_ADDRESS);
    assert_eq!(cloned.entry_fee_micro, SLOT_ENTRY_FEE_MICRO);
    Ok(())
}

#[test]
fn game_18_config_debug_mentions_house_address() -> TestResult {
    let cfg = SlotMachineGameConfig::default();
    assert!(format!("{cfg:?}").contains("house_address"));
    Ok(())
}

#[test]
fn game_19_game_clone_preserves_max_payout() -> TestResult {
    let game = SlotMachineGame::default();
    let cloned = game.clone();
    assert_eq!(cloned.max_payout_micro(), game.max_payout_micro());
    Ok(())
}

#[test]
fn game_20_game_debug_mentions_config() -> TestResult {
    let game = SlotMachineGame::default();
    assert!(format!("{game:?}").contains("cfg"));
    Ok(())
}

#[test]
fn game_21_from_micro_units_formats_entry_fee_as_positive_amount() -> TestResult {
    assert!(from_micro_units(SLOT_ENTRY_FEE_MICRO) > 0.0);
    Ok(())
}

#[test]
fn game_22_context_can_be_constructed_with_callbacks() -> TestResult {
    let (_temp, opts, _manager, db, logger) = make_blockchain_db("22_context")?;
    let mut send_cb = |_cmd: NetCmd| Ok(());
    let mut bal_cb = |_addr: &str| 0u64;
    let ctx = make_context(&opts, db.as_ref(), &logger, &mut send_cb, &mut bal_cb);
    assert_eq!(ctx.opts.listen, opts.listen);
    Ok(())
}

#[test]
fn game_23_enqueue_rejects_empty_sender() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("23_empty_sender")?;
    let receiver = wallet_with_pair("22");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), "", &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_24_enqueue_rejects_empty_receiver() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("24_empty_receiver")?;
    let sender = wallet_with_pair("23");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, "", 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_25_enqueue_rejects_short_sender() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("25_short_sender")?;
    let receiver = wallet_with_pair("24");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), "r1234", &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_26_enqueue_rejects_short_receiver() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("26_short_receiver")?;
    let sender = wallet_with_pair("25");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, "r1234", 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_27_enqueue_rejects_bad_sender_prefix() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("27_bad_sender_prefix")?;
    let mut sender = wallet_with_pair("26");
    sender.replace_range(..1, "x");
    let receiver = wallet_with_pair("27");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_28_enqueue_rejects_bad_receiver_prefix() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("28_bad_receiver_prefix")?;
    let sender = wallet_with_pair("28");
    let mut receiver = wallet_with_pair("29");
    receiver.replace_range(..1, "x");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_29_enqueue_rejects_non_hex_sender() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("29_non_hex_sender")?;
    let mut sender = String::from("r");
    for _ in 0..64 {
        sender.push_str("zz");
    }
    let receiver = wallet_with_pair("2a");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_30_enqueue_rejects_non_hex_receiver() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("30_non_hex_receiver")?;
    let sender = wallet_with_pair("2b");
    let mut receiver = String::from("r");
    for _ in 0..64 {
        receiver.push_str("zz");
    }
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_31_enqueue_rejects_too_long_sender() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("31_long_sender")?;
    let mut sender = wallet_with_pair("2c");
    sender.push('0');
    let receiver = wallet_with_pair("2d");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_32_enqueue_rejects_too_long_receiver() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("32_long_receiver")?;
    let sender = wallet_with_pair("2e");
    let mut receiver = wallet_with_pair("2f");
    receiver.push('0');
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_33_enqueue_rejects_self_transfer() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("33_self_transfer")?;
    let wallet = wallet_with_pair("30");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &wallet, &wallet, 1, &logger),
        "self-transfer",
    )
}

#[test]
fn game_34_enqueue_rejects_zero_amount() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("34_zero_amount")?;
    let sender = wallet_with_pair("31");
    let receiver = wallet_with_pair("32");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 0, &logger),
        "amount must be > 0",
    )
}

#[test]
fn game_35_enqueue_valid_transfer_writes_transaction_cf() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("35_valid_tx_cf")?;
    let sender = wallet_with_pair("33");
    let receiver = wallet_with_pair("34");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_36_enqueue_valid_transfer_writes_hash_cf() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("36_valid_hash_cf")?;
    let sender = wallet_with_pair("35");
    let receiver = wallet_with_pair("36");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_37_enqueue_valid_transfer_stores_requested_amount() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("37_amount")?;
    let sender = wallet_with_pair("37");
    let receiver = wallet_with_pair("38");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 42, &logger)?;
    assert_eq!(first_transfer_amount(db.as_ref())?, 42);
    Ok(())
}

#[test]
fn game_38_enqueue_entry_fee_amount_stores_entry_fee() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("38_entry_fee_amount")?;
    let sender = wallet_with_pair("39");
    let receiver = wallet_with_pair("3a");
    enqueue_transfer_to_mempool(
        db.as_ref(),
        &sender,
        &receiver,
        SLOT_ENTRY_FEE_MICRO,
        &logger,
    )?;
    assert_eq!(first_transfer_amount(db.as_ref())?, SLOT_ENTRY_FEE_MICRO);
    Ok(())
}

#[test]
fn game_39_enqueue_accepts_outer_whitespace_sender() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("39_whitespace_sender")?;
    let sender = format!("  {}\n", wallet_with_pair("3b"));
    let receiver = wallet_with_pair("3c");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_40_enqueue_accepts_outer_whitespace_receiver() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("40_whitespace_receiver")?;
    let sender = wallet_with_pair("3d");
    let receiver = format!("\t{}\r\n", wallet_with_pair("3e"));
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_41_enqueue_accepts_uppercase_sender_hex() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("41_upper_sender")?;
    let sender = wallet_upper_with_pair("aa");
    let receiver = wallet_with_pair("3f");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_42_enqueue_accepts_uppercase_receiver_hex() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("42_upper_receiver")?;
    let sender = wallet_with_pair("40");
    let receiver = wallet_upper_with_pair("bb");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_43_enqueue_same_transfer_twice_dedupes_transaction_cf() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("43_dedupe_tx")?;
    let sender = wallet_with_pair("41");
    let receiver = wallet_with_pair("42");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_44_enqueue_same_transfer_twice_dedupes_hash_cf() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("44_dedupe_hash")?;
    let sender = wallet_with_pair("43");
    let receiver = wallet_with_pair("44");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_45_enqueue_same_transfer_with_whitespace_dedupes() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("45_dedupe_whitespace")?;
    let sender = wallet_with_pair("45");
    let receiver = wallet_with_pair("46");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    enqueue_transfer_to_mempool(
        db.as_ref(),
        &format!("  {sender}\n"),
        &format!("\t{receiver}\r\n"),
        1,
        &logger,
    )?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_46_enqueue_same_transfer_with_uppercase_dedupes() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("46_dedupe_uppercase")?;
    let sender = wallet_with_pair("aa");
    let receiver = wallet_with_pair("bb");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    enqueue_transfer_to_mempool(
        db.as_ref(),
        &wallet_upper_with_pair("aa"),
        &wallet_upper_with_pair("bb"),
        1,
        &logger,
    )?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_47_enqueue_different_amounts_create_distinct_entries() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("47_different_amounts")?;
    let sender = wallet_with_pair("47");
    let receiver = wallet_with_pair("48");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 2, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 2);
    assert_eq!(tx_hash_count(db.as_ref())?, 2);
    Ok(())
}

#[test]
fn game_48_enqueue_different_receivers_create_distinct_entries() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("48_different_receivers")?;
    let sender = wallet_with_pair("49");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &wallet_with_pair("4a"), 1, &logger)?;
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &wallet_with_pair("4b"), 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 2);
    assert_eq!(tx_hash_count(db.as_ref())?, 2);
    Ok(())
}

#[test]
fn game_49_enqueue_different_senders_create_distinct_entries() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("49_different_senders")?;
    let receiver = wallet_with_pair("4c");
    enqueue_transfer_to_mempool(db.as_ref(), &wallet_with_pair("4d"), &receiver, 1, &logger)?;
    enqueue_transfer_to_mempool(db.as_ref(), &wallet_with_pair("4e"), &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 2);
    assert_eq!(tx_hash_count(db.as_ref())?, 2);
    Ok(())
}

#[test]
fn game_50_enqueue_player_to_house_entry_fee_succeeds() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("50_player_to_house")?;
    let player = wallet_with_pair("4f");
    enqueue_transfer_to_mempool(
        db.as_ref(),
        &player,
        SLOT_HOUSE_ADDRESS,
        SLOT_ENTRY_FEE_MICRO,
        &logger,
    )?;
    assert_eq!(first_transfer_amount(db.as_ref())?, SLOT_ENTRY_FEE_MICRO);
    Ok(())
}

#[test]
fn game_51_enqueue_house_to_player_jackpot_succeeds() -> TestResult {
    let game = SlotMachineGame::default();
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("51_house_to_player")?;
    let player = wallet_with_pair("50");
    enqueue_transfer_to_mempool(
        db.as_ref(),
        SLOT_HOUSE_ADDRESS,
        &player,
        game.max_payout_micro(),
        &logger,
    )?;
    assert_eq!(first_transfer_amount(db.as_ref())?, game.max_payout_micro());
    Ok(())
}

#[test]
fn game_52_enqueue_stored_bytes_deserialize_as_txkind_transfer() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("52_deserialize_transfer")?;
    let sender = wallet_with_pair("51");
    let receiver = wallet_with_pair("52");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 123, &logger)?;
    let values = tx_values(db.as_ref())?;
    let first = values.first().ok_or_else(|| boxed_error("missing tx"))?;
    assert!(matches!(TxKind::deserialize(first)?, TxKind::Transfer(_)));
    Ok(())
}

#[test]
fn game_53_enqueue_stored_transfer_normalized_sender_is_present() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("53_normalized_sender")?;
    let sender = wallet_with_pair("53");
    let receiver = wallet_with_pair("54");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 123, &logger)?;
    let values = tx_values(db.as_ref())?;
    let first = values.first().ok_or_else(|| boxed_error("missing tx"))?;
    let kind = TxKind::deserialize(first)?;
    assert_eq!(kind.normalized_sender().as_deref(), Some(sender.as_str()));
    Ok(())
}

#[test]
fn game_54_enqueue_stored_transfer_normalized_receiver_is_present() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("54_normalized_receiver")?;
    let sender = wallet_with_pair("55");
    let receiver = wallet_with_pair("56");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 123, &logger)?;
    let values = tx_values(db.as_ref())?;
    let first = values.first().ok_or_else(|| boxed_error("missing tx"))?;
    let kind = TxKind::deserialize(first)?;
    assert_eq!(
        kind.normalized_receiver().as_deref(),
        Some(receiver.as_str())
    );
    Ok(())
}

#[test]
fn game_55_enqueue_transfer_tag_is_transfer() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("55_tag_transfer")?;
    let sender = wallet_with_pair("57");
    let receiver = wallet_with_pair("58");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 123, &logger)?;
    let values = tx_values(db.as_ref())?;
    let first = values.first().ok_or_else(|| boxed_error("missing tx"))?;
    let kind = TxKind::deserialize(first)?;
    assert_eq!(kind.tag(), "transfer");
    Ok(())
}

#[test]
fn game_56_enqueue_transfer_touches_two_addresses() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("56_touched_addresses")?;
    let sender = wallet_with_pair("59");
    let receiver = wallet_with_pair("5a");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 123, &logger)?;
    let values = tx_values(db.as_ref())?;
    let first = values.first().ok_or_else(|| boxed_error("missing tx"))?;
    let mut touched = TxKind::deserialize(first)?.touched_addresses();
    touched.sort();
    let mut expected = vec![sender, receiver];
    expected.sort();
    assert_eq!(touched, expected);
    Ok(())
}

#[test]
fn game_57_enqueue_logs_dedupe_hit_without_error() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("57_dedupe_logging")?;
    let sender = wallet_with_pair("5b");
    let receiver = wallet_with_pair("5c");
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 777, &logger)?;
    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 777, &logger)?;
    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;
    Ok(())
}

#[test]
fn game_58_enqueue_many_small_distinct_amounts() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("58_many_amounts")?;
    let sender = wallet_with_pair("5d");
    let receiver = wallet_with_pair("5e");

    for amount in 1u64..=10u64 {
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, amount, &logger)?;
    }

    assert_eq!(tx_count(db.as_ref())?, 10);
    assert_eq!(tx_hash_count(db.as_ref())?, 10);
    Ok(())
}

#[test]
fn game_59_enqueue_vector_many_pairs() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("59_many_pairs")?;

    for pair in ["60", "61", "62", "63", "64"] {
        let sender = wallet_with_pair(pair);
        let receiver = wallet_with_pair("65");
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    }

    assert_eq!(tx_count(db.as_ref())?, 5);
    assert_eq!(tx_hash_count(db.as_ref())?, 5);
    Ok(())
}

#[test]
fn game_60_enqueue_vector_duplicate_pairs_do_not_grow() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("60_duplicate_pairs")?;

    for _ in 0..5usize {
        enqueue_transfer_to_mempool(
            db.as_ref(),
            &wallet_with_pair("66"),
            &wallet_with_pair("67"),
            1,
            &logger,
        )?;
    }

    assert_eq!(tx_count(db.as_ref())?, 1);
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_61_reopen_blockchain_db_preserves_enqueued_transfer() -> TestResult {
    let (_temp, opts, manager, db, logger) = make_blockchain_db("61_reopen_preserve")?;
    let sender = wallet_with_pair("68");
    let receiver = wallet_with_pair("69");
    let db_path = manager.directory.blockchain_path.clone();

    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    drop(db);
    drop(manager);

    let db_path_string = path_to_string(&db_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &db_path_string)?;
    let reopened_db = reopened.open_db_blockchain()?;
    assert_eq!(tx_count(reopened_db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_62_reopen_blockchain_db_preserves_hash_index() -> TestResult {
    let (_temp, opts, manager, db, logger) = make_blockchain_db("62_reopen_hash")?;
    let sender = wallet_with_pair("6a");
    let receiver = wallet_with_pair("6b");
    let db_path = manager.directory.blockchain_path.clone();

    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    drop(db);
    drop(manager);

    let db_path_string = path_to_string(&db_path)?;
    let reopened = RockDBManager::new_blockchain(&opts, &db_path_string)?;
    let reopened_db = reopened.open_db_blockchain()?;
    assert_eq!(tx_hash_count(reopened_db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_63_prove_wallet_ownership_rejects_invalid_wallet_before_io() -> TestResult {
    let temp = TempRoot::new("63_proof_invalid_wallet")?;
    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();

    assert_error_contains(
        game.prove_wallet_ownership(&opts, "not-a-wallet", "PLAYER", &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_64_prove_wallet_ownership_rejects_missing_wallet_file() -> TestResult {
    let temp = TempRoot::new("64_missing_wallet_file")?;
    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();
    let wallet = wallet_with_pair("6c");

    assert_error_contains(
        game.prove_wallet_ownership(&opts, &wallet, "PLAYER", &logger),
        "wallet file not found",
    )
}

#[test]
fn game_65_prove_wallet_ownership_rejects_wallet_path_that_is_directory() -> TestResult {
    let temp = TempRoot::new("65_wallet_path_directory")?;
    let opts = node_opts(temp.path())?;
    let directory = DirectoryDB::from_node_opts(&opts).map_err(string_error)?;
    directory.create_wallets_directory().map_err(string_error)?;
    let wallet = wallet_with_pair("6d");
    fs::create_dir_all(directory.wallets_path.join(format!("{wallet}.wallet")))?;

    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();

    assert_error_contains(
        game.prove_wallet_ownership(&opts, &wallet, "PLAYER", &logger),
        "not a file",
    )
}

#[test]
fn game_66_prove_wallet_ownership_rejects_empty_wallet_file() -> TestResult {
    let temp = TempRoot::new("66_empty_wallet_file")?;
    let wallet = wallet_with_pair("6e");
    write_wallet_blob(temp.path(), &wallet, b"")?;
    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();

    assert_error_contains(
        game.prove_wallet_ownership(&opts, &wallet, "PLAYER", &logger),
        "wallet file is empty",
    )
}

#[test]
fn game_67_prove_wallet_ownership_rejects_too_large_wallet_file() -> TestResult {
    let temp = TempRoot::new("67_large_wallet_file")?;
    let wallet = wallet_with_pair("6f");
    let path = write_wallet_blob(temp.path(), &wallet, b"x")?;
    let file = fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(512u64.saturating_mul(1024).saturating_add(1))?;

    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();

    assert_error_contains(
        game.prove_wallet_ownership(&opts, &wallet, "PLAYER", &logger),
        "wallet file too large",
    )
}

#[test]
fn game_68_prove_wallet_ownership_missing_wallet_logs_error() -> TestResult {
    let temp = TempRoot::new("68_missing_wallet_logs")?;
    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();
    let wallet = wallet_with_pair("70");

    let result = game.prove_wallet_ownership(&opts, &wallet, "PLAYER", &logger);
    assert!(result.is_err());
    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;
    Ok(())
}

#[test]
fn game_69_prove_wallet_ownership_empty_wallet_logs_error() -> TestResult {
    let temp = TempRoot::new("69_empty_wallet_logs")?;
    let wallet = wallet_with_pair("71");
    write_wallet_blob(temp.path(), &wallet, b"")?;
    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();

    let result = game.prove_wallet_ownership(&opts, &wallet, "PLAYER", &logger);
    assert!(result.is_err());
    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;
    Ok(())
}

#[test]
fn game_70_prove_wallet_ownership_accepts_uppercase_wallet_for_missing_file_check() -> TestResult {
    let temp = TempRoot::new("70_upper_wallet_missing")?;
    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();
    let wallet = wallet_upper_with_pair("aa");

    assert_error_contains(
        game.prove_wallet_ownership(&opts, &wallet, "PLAYER", &logger),
        "wallet file not found",
    )
}

#[test]
fn game_71_enqueue_rejects_sender_with_internal_space() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("71_sender_space")?;
    let sender = "r7171717171717171717171717171717171717171717171717171717171717171 7171717171717171717171717171717171717171717171717171717171717171";
    let receiver = wallet_with_pair("72");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_72_enqueue_rejects_receiver_with_internal_newline() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("72_receiver_newline")?;
    let sender = wallet_with_pair("73");
    let receiver = "r7272727272727272727272727272727272727272727272727272727272727272\n7272727272727272727272727272727272727272727272727272727272727272";
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_73_enqueue_rejects_sender_with_nul() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("73_sender_nul")?;
    let sender = format!("{}\0", wallet_with_pair("74"));
    let receiver = wallet_with_pair("75");
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_74_enqueue_rejects_receiver_with_nul() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("74_receiver_nul")?;
    let sender = wallet_with_pair("76");
    let receiver = format!("{}\0", wallet_with_pair("77"));
    assert_error_contains(
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger),
        "wallet address is invalid",
    )
}

#[test]
fn game_75_enqueue_after_invalid_attempt_still_accepts_valid_transfer() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("75_invalid_then_valid")?;
    let sender = wallet_with_pair("78");
    let receiver = wallet_with_pair("79");

    let invalid = enqueue_transfer_to_mempool(db.as_ref(), "bad", &receiver, 1, &logger);
    assert!(invalid.is_err());

    enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    assert_eq!(tx_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_76_failed_zero_amount_does_not_write_to_mempool() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("76_zero_no_write")?;
    let sender = wallet_with_pair("7a");
    let receiver = wallet_with_pair("7b");

    let result = enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 0, &logger);
    assert!(result.is_err());

    assert_eq!(tx_count(db.as_ref())?, 0);
    assert_eq!(tx_hash_count(db.as_ref())?, 0);
    Ok(())
}

#[test]
fn game_77_failed_self_transfer_does_not_write_to_mempool() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("77_self_no_write")?;
    let wallet = wallet_with_pair("7c");

    let result = enqueue_transfer_to_mempool(db.as_ref(), &wallet, &wallet, 1, &logger);
    assert!(result.is_err());

    assert_eq!(tx_count(db.as_ref())?, 0);
    assert_eq!(tx_hash_count(db.as_ref())?, 0);
    Ok(())
}

#[test]
fn game_78_vector_invalid_wallet_inputs_are_rejected() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("78_invalid_vector")?;
    let receiver = wallet_with_pair("7d");

    for invalid in ["", "r", "r00", "x1234", "not-a-wallet"] {
        let result = enqueue_transfer_to_mempool(db.as_ref(), invalid, &receiver, 1, &logger);
        assert!(
            result.is_err(),
            "invalid wallet unexpectedly accepted: {invalid}"
        );
    }

    assert_eq!(tx_count(db.as_ref())?, 0);
    Ok(())
}

#[test]
fn game_79_vector_valid_wallet_pairs_are_accepted() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("79_valid_vector")?;

    for (sender_pair, receiver_pair, amount) in [
        ("80", "81", 1u64),
        ("82", "83", 2u64),
        ("84", "85", 3u64),
        ("86", "87", 4u64),
    ] {
        enqueue_transfer_to_mempool(
            db.as_ref(),
            &wallet_with_pair(sender_pair),
            &wallet_with_pair(receiver_pair),
            amount,
            &logger,
        )?;
    }

    assert_eq!(tx_count(db.as_ref())?, 4);
    assert_eq!(tx_hash_count(db.as_ref())?, 4);
    Ok(())
}

#[test]
fn game_80_vector_amounts_are_preserved() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("80_amount_vector")?;
    let sender = wallet_with_pair("88");
    let receiver = wallet_with_pair("89");

    for amount in [
        1u64,
        10,
        SLOT_ENTRY_FEE_MICRO,
        SLOT_ENTRY_FEE_MICRO.saturating_add(1),
    ] {
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, amount, &logger)?;
    }

    assert_eq!(tx_count(db.as_ref())?, 4);
    Ok(())
}

#[test]
fn game_81_load_test_enqueue_50_distinct_transfers() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("81_load_50")?;
    let receiver = wallet_with_pair("8a");

    for amount in 1u64..=50u64 {
        let sender = wallet_with_pair("8b");
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, amount, &logger)?;
    }

    assert_eq!(tx_count(db.as_ref())?, 50);
    assert_eq!(tx_hash_count(db.as_ref())?, 50);
    Ok(())
}

#[test]
fn game_82_load_test_100_duplicate_transfers_remain_one() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("82_load_100_dupes")?;
    let sender = wallet_with_pair("8c");
    let receiver = wallet_with_pair("8d");

    for _ in 0..100usize {
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, 1, &logger)?;
    }

    assert_eq!(tx_count(db.as_ref())?, 1);
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_83_load_test_mixed_duplicates_and_unique_amounts() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("83_mixed_dupes_unique")?;
    let sender = wallet_with_pair("8e");
    let receiver = wallet_with_pair("8f");

    for amount in 1u64..=20u64 {
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, amount, &logger)?;
        enqueue_transfer_to_mempool(db.as_ref(), &sender, &receiver, amount, &logger)?;
    }

    assert_eq!(tx_count(db.as_ref())?, 20);
    assert_eq!(tx_hash_count(db.as_ref())?, 20);
    Ok(())
}

#[test]
fn game_84_logger_accepts_slot_error_event() -> TestResult {
    let temp = TempRoot::new("84_logger_event")?;
    let logger = make_logger(temp.path())?;
    logger
        .log_error_event("slot", "TestSlotEvent", "slot test event")
        .map_err(string_error)?;
    logger.flush().map_err(string_error)?;
    logger.flush_logs_cf().map_err(string_error)?;
    Ok(())
}

#[test]
fn game_85_context_send_callback_can_record_netcmd() -> TestResult {
    let (_temp, opts, _manager, db, logger) = make_blockchain_db("85_context_send")?;
    let mut sent = 0usize;
    let mut send_cb = |_cmd: NetCmd| {
        sent = sent.saturating_add(1);
        Ok(())
    };
    let mut bal_cb = |_addr: &str| 0u64;

    let ctx = make_context(&opts, db.as_ref(), &logger, &mut send_cb, &mut bal_cb);

    (ctx.send_net_cmd)(NetCmd::SendTx(
        remzar::blockchain::transaction_001_tx::Transaction::new(
            wallet_with_pair("90"),
            wallet_with_pair("91"),
            1,
        )?,
    ))?;

    drop(ctx);
    assert_eq!(sent, 1);
    Ok(())
}

#[test]
fn game_86_context_balance_callback_can_return_house_balance() -> TestResult {
    let (_temp, opts, _manager, db, logger) = make_blockchain_db("86_context_balance")?;
    let mut send_cb = |_cmd: NetCmd| Ok(());
    let mut bal_cb = |addr: &str| {
        if addr == SLOT_HOUSE_ADDRESS { 123 } else { 0 }
    };

    let ctx = make_context(&opts, db.as_ref(), &logger, &mut send_cb, &mut bal_cb);
    assert_eq!((ctx.get_balance_micro)(SLOT_HOUSE_ADDRESS), 123);
    Ok(())
}

#[test]
fn game_87_context_exposes_logger_reference() -> TestResult {
    let (_temp, opts, _manager, db, logger) = make_blockchain_db("87_context_logger")?;
    let mut send_cb = |_cmd: NetCmd| Ok(());
    let mut bal_cb = |_addr: &str| 0u64;
    let ctx = make_context(&opts, db.as_ref(), &logger, &mut send_cb, &mut bal_cb);
    ctx.json_logger
        .log_error_event("slot", "ContextLogger", "ok")
        .map_err(string_error)?;
    Ok(())
}

#[test]
fn game_88_custom_config_can_use_zero_entry_fee_structurally() -> TestResult {
    let cfg = SlotMachineGameConfig {
        house_address: SLOT_HOUSE_ADDRESS,
        entry_fee_micro: 0,
    };
    assert_eq!(cfg.entry_fee_micro, 0);
    Ok(())
}

#[test]
fn game_89_custom_config_can_use_alternate_static_house_structurally() -> TestResult {
    let cfg = SlotMachineGameConfig {
        house_address: "r00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        entry_fee_micro: 1,
    };
    assert_eq!(cfg.house_address.len(), 129);
    Ok(())
}

#[test]
fn game_90_max_payout_is_independent_of_custom_house_address() -> TestResult {
    let game = SlotMachineGame {
        cfg: SlotMachineGameConfig {
            house_address: "r00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            entry_fee_micro: 1,
        },
    };
    assert_eq!(game.max_payout_micro(), 100u64.saturating_mul(UNIT_DIVISOR));
    Ok(())
}

#[test]
fn game_91_default_game_cfg_matches_default_config() -> TestResult {
    let game = SlotMachineGame::default();
    let cfg = SlotMachineGameConfig::default();
    assert_eq!(game.cfg.house_address, cfg.house_address);
    assert_eq!(game.cfg.entry_fee_micro, cfg.entry_fee_micro);
    Ok(())
}

#[test]
fn game_92_enqueue_receiver_house_then_same_duplicate_dedupes() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("92_house_dedupe")?;
    let player = wallet_with_pair("92");

    enqueue_transfer_to_mempool(
        db.as_ref(),
        &player,
        SLOT_HOUSE_ADDRESS,
        SLOT_ENTRY_FEE_MICRO,
        &logger,
    )?;
    enqueue_transfer_to_mempool(
        db.as_ref(),
        &player,
        SLOT_HOUSE_ADDRESS,
        SLOT_ENTRY_FEE_MICRO,
        &logger,
    )?;

    assert_eq!(tx_count(db.as_ref())?, 1);
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_93_enqueue_house_payout_then_duplicate_dedupes() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("93_house_payout_dedupe")?;
    let player = wallet_with_pair("93");
    let game = SlotMachineGame::default();

    enqueue_transfer_to_mempool(
        db.as_ref(),
        SLOT_HOUSE_ADDRESS,
        &player,
        game.max_payout_micro(),
        &logger,
    )?;
    enqueue_transfer_to_mempool(
        db.as_ref(),
        SLOT_HOUSE_ADDRESS,
        &player,
        game.max_payout_micro(),
        &logger,
    )?;

    assert_eq!(tx_count(db.as_ref())?, 1);
    assert_eq!(tx_hash_count(db.as_ref())?, 1);
    Ok(())
}

#[test]
fn game_94_enqueue_multiple_house_payout_amounts_are_distinct() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("94_house_payout_amounts")?;
    let player = wallet_with_pair("94");

    for amount in [
        UNIT_DIVISOR,
        2u64.saturating_mul(UNIT_DIVISOR),
        5u64.saturating_mul(UNIT_DIVISOR),
        10u64.saturating_mul(UNIT_DIVISOR),
    ] {
        enqueue_transfer_to_mempool(db.as_ref(), SLOT_HOUSE_ADDRESS, &player, amount, &logger)?;
    }

    assert_eq!(tx_count(db.as_ref())?, 4);
    assert_eq!(tx_hash_count(db.as_ref())?, 4);
    Ok(())
}

#[test]
fn game_95_mempool_values_are_nonempty_after_enqueue() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("95_values_nonempty")?;
    enqueue_transfer_to_mempool(
        db.as_ref(),
        &wallet_with_pair("95"),
        &wallet_with_pair("96"),
        1,
        &logger,
    )?;

    for value in tx_values(db.as_ref())? {
        assert!(!value.is_empty());
    }

    Ok(())
}

#[test]
fn game_96_transaction_and_hash_cf_counts_match_after_unique_batch() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("96_cf_counts_match")?;

    for idx in 1u64..=12u64 {
        enqueue_transfer_to_mempool(
            db.as_ref(),
            &wallet_with_pair("97"),
            &wallet_with_pair("98"),
            idx,
            &logger,
        )?;
    }

    assert_eq!(tx_count(db.as_ref())?, tx_hash_count(db.as_ref())?);
    Ok(())
}

#[test]
fn game_97_transaction_and_hash_cf_counts_match_after_duplicate_batch() -> TestResult {
    let (_temp, _opts, _manager, db, logger) = make_blockchain_db("97_cf_counts_dupes")?;

    for _ in 0..12usize {
        enqueue_transfer_to_mempool(
            db.as_ref(),
            &wallet_with_pair("99"),
            &wallet_with_pair("9a"),
            1,
            &logger,
        )?;
    }

    assert_eq!(tx_count(db.as_ref())?, tx_hash_count(db.as_ref())?);
    Ok(())
}

#[test]
fn game_98_wallet_proof_too_large_file_uses_label_in_error() -> TestResult {
    let temp = TempRoot::new("98_label_large_wallet")?;
    let wallet = wallet_with_pair("9b");
    let path = write_wallet_blob(temp.path(), &wallet, b"x")?;
    let file = fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(512u64.saturating_mul(1024).saturating_add(1))?;

    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();

    assert_error_contains(
        game.prove_wallet_ownership(&opts, &wallet, "HOUSE", &logger),
        "HOUSE wallet file too large",
    )
}

#[test]
fn game_99_wallet_proof_missing_file_uses_label_in_error() -> TestResult {
    let temp = TempRoot::new("99_label_missing_wallet")?;
    let opts = node_opts(temp.path())?;
    let logger = make_logger(temp.path())?;
    let game = SlotMachineGame::default();
    let wallet = wallet_with_pair("9c");

    assert_error_contains(
        game.prove_wallet_ownership(&opts, &wallet, "HOUSE", &logger),
        "HOUSE wallet file not found",
    )
}

#[test]
fn game_100_full_noninteractive_slot_pipeline_smoke_test() -> TestResult {
    let (_temp, opts, _manager, db, logger) = make_blockchain_db("100_pipeline")?;
    let game = SlotMachineGame::default();
    let player = wallet_with_pair("9d");

    let mut sent = 0usize;
    let mut send_cb = |_cmd: NetCmd| {
        sent = sent.saturating_add(1);
        Ok(())
    };

    let mut bal_cb = |addr: &str| {
        if addr == SLOT_HOUSE_ADDRESS {
            game.max_payout_micro()
        } else if addr == player.as_str() {
            SLOT_ENTRY_FEE_MICRO
        } else {
            0
        }
    };

    let ctx = make_context(&opts, db.as_ref(), &logger, &mut send_cb, &mut bal_cb);

    assert_eq!(
        (ctx.get_balance_micro)(SLOT_HOUSE_ADDRESS),
        game.max_payout_micro()
    );
    assert_eq!((ctx.get_balance_micro)(&player), SLOT_ENTRY_FEE_MICRO);

    enqueue_transfer_to_mempool(
        ctx.db,
        &player,
        SLOT_HOUSE_ADDRESS,
        SLOT_ENTRY_FEE_MICRO,
        ctx.json_logger,
    )?;

    (ctx.send_net_cmd)(NetCmd::SendTx(
        remzar::blockchain::transaction_001_tx::Transaction::new(
            player.clone(),
            SLOT_HOUSE_ADDRESS.to_owned(),
            SLOT_ENTRY_FEE_MICRO,
        )?,
    ))?;

    drop(ctx);

    assert_eq!(sent, 1);
    assert_eq!(tx_count(db.as_ref())?, 1);
    assert_eq!(tx_hash_count(db.as_ref())?, 1);

    Ok(())
}
