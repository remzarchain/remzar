use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::commandline::s_05_send_remzar::S05SendRemzar;
use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::network::p2p_010_netcmd::NetCmd;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    from_micro_units, to_micro_units_str,
};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;
use zeroize::Zeroize;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_05_send_remzar_tests_{test_name}_{}_{}",
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

fn assert_tx_valid(tx: &Transaction) {
    assert_ok(tx.validate(), "transaction validate");
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

fn make_tx_from_wallets(
    sender: &MLDSA65Wallet,
    receiver: &MLDSA65Wallet,
    amount: u64,
) -> Transaction {
    assert_ok(
        Transaction::new(sender.address.clone(), receiver.address.clone(), amount),
        "Transaction::new from wallets",
    )
}

fn assert_decryption_like_error(err: ErrorDetection) {
    match err {
        ErrorDetection::DecryptionError { .. }
        | ErrorDetection::ValidationError { .. }
        | ErrorDetection::EncryptionError { .. }
        | ErrorDetection::CryptographicError { .. } => {}
        other => panic!("unexpected decryption-like error: {other:?}"),
    }
}

fn assert_hex_lowercase_ascii(value: &str) {
    assert!(
        value
            .as_bytes()
            .iter()
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

fn wallet_address_with_wrong_prefix(address: &str) -> String {
    let mut bytes = address.as_bytes().to_vec();

    match bytes.get_mut(0) {
        Some(slot) => {
            *slot = b'x';
        }
        None => panic!("wallet address was unexpectedly empty"),
    }

    match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(err) => panic!("wrong-prefix address was invalid UTF-8: {err}"),
    }
}

fn wallet_address_with_non_hex_body(address: &str) -> String {
    let mut bytes = address.as_bytes().to_vec();

    match bytes.get_mut(1) {
        Some(slot) => {
            *slot = b'g';
        }
        None => panic!("wallet address was unexpectedly too short"),
    }

    match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(err) => panic!("non-hex address was invalid UTF-8: {err}"),
    }
}

fn wallet_address_with_body_flip(address: &str) -> String {
    let mut bytes = address.as_bytes().to_vec();

    let replacement = match bytes.get(1).copied() {
        Some(b'0') => b'1',
        Some(_) => b'0',
        None => b'0',
    };

    match bytes.get_mut(1) {
        Some(slot) => {
            *slot = replacement;
        }
        None => panic!("wallet address was unexpectedly too short"),
    }

    match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(err) => panic!("body-flipped address was invalid UTF-8: {err}"),
    }
}

fn send_tx_command_round_trip(tx: Transaction) -> Transaction {
    let (net_tx, mut net_rx) = mpsc::channel::<NetCmd>(1);

    assert_ok(
        net_tx.try_send(NetCmd::SendTx(tx.clone())),
        "try_send NetCmd::SendTx",
    );

    match net_rx.try_recv() {
        Ok(NetCmd::SendTx(received)) => received,
        Ok(other) => panic!("unexpected NetCmd variant: {other:?}"),
        Err(err) => panic!("failed to receive NetCmd::SendTx: {err:?}"),
    }
}

fn directory_from_opts(opts: &NodeOpts) -> DirectoryDB {
    assert_ok(
        DirectoryDB::from_node_opts(opts),
        "DirectoryDB::from_node_opts",
    )
}

fn make_wallet(passphrase: &str) -> MLDSA65Wallet {
    assert_ok(MLDSA65Wallet::new(passphrase), "MLDSA65Wallet::new")
}

fn make_two_wallets() -> (MLDSA65Wallet, MLDSA65Wallet) {
    let sender = make_wallet("sender passphrase");
    let receiver = make_wallet("receiver passphrase");

    assert_ne!(sender.address, receiver.address);
    (sender, receiver)
}

fn wallet_file_path(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    directory
        .wallets_path
        .join(format!("{}.wallet", wallet.address))
}

fn write_wallet_file(directory: &DirectoryDB, wallet: &MLDSA65Wallet) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let path = wallet_file_path(directory, wallet);
    assert_ok(
        fs::write(&path, &wallet.encrypted_secret),
        "write wallet file",
    );
    path
}

fn decrypt_wallet_secret_bytes(encrypted_secret: &[u8], passphrase: &str) -> Vec<u8> {
    assert_ok(
        Cryption::decrypt_private_key_bytes(encrypted_secret, passphrase),
        "decrypt wallet secret bytes",
    )
}

fn derive_address_from_secret_bytes(secret_bytes: &[u8]) -> String {
    let sk_arr: [u8; ml_dsa_65::SK_LEN] = match secret_bytes.try_into() {
        Ok(value) => value,
        Err(_) => panic!("secret bytes did not fit ML-DSA-65 secret array"),
    };

    let sk = assert_ok(
        ml_dsa_65::PrivateKey::try_from_bytes(sk_arr),
        "PrivateKey::try_from_bytes",
    );
    let pk = sk.get_public_key();
    let pk_bytes = pk.into_bytes();

    derive_wallet_id_from_pubkey_bytes(&pk_bytes)
}

fn make_transaction(amount: u64) -> Transaction {
    let (sender, receiver) = make_two_wallets();

    assert_ok(
        Transaction::new(sender.address, receiver.address, amount),
        "Transaction::new",
    )
}

fn make_test_manager(opts: &NodeOpts) -> RockDBManager {
    assert_ok(RockDBManager::new(opts), "RockDBManager::new")
}

fn make_send_component<'a>(
    opts: &NodeOpts,
    chain: &'a mut Option<AccountModelTree>,
    net_tx: Option<mpsc::Sender<NetCmd>>,
) -> S05SendRemzar<'a> {
    let manager = make_test_manager(opts);
    S05SendRemzar::new(Arc::new(manager), chain, net_tx)
}

#[test]
fn test_01_constructor_without_network_builds_component() {
    let temp = TempTree::new("test_01");
    let opts = make_node_opts(&temp.child("node"));
    let mut chain = None;

    let _component = make_send_component(&opts, &mut chain, None);
}

#[test]
fn test_02_constructor_with_network_builds_component() {
    let temp = TempTree::new("test_02");
    let opts = make_node_opts(&temp.child("node"));
    let mut chain = None;
    let (tx, _rx) = mpsc::channel::<NetCmd>(8);

    let _component = make_send_component(&opts, &mut chain, Some(tx));
}

#[test]
fn test_03_constructor_with_account_tree_builds_component() {
    let temp = TempTree::new("test_03");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let tree = AccountModelTree::with_manager(manager.clone());
    let mut chain = Some(tree);

    let _component = S05SendRemzar::new(Arc::new(manager), &mut chain, None);
}

#[test]
fn test_04_wallet_file_path_uses_sender_address() {
    let temp = TempTree::new("test_04");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let sender = make_wallet("test_04_passphrase");

    let path = wallet_file_path(&directory, &sender);

    assert!(path.ends_with(format!("{}.wallet", sender.address)));
}

#[test]
fn test_05_wallet_file_write_and_read_round_trip() {
    let temp = TempTree::new("test_05");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let sender = make_wallet("test_05_passphrase");

    let path = write_wallet_file(&directory, &sender);
    let stored = assert_ok(fs::read(path), "read wallet file");

    assert_eq!(stored, sender.encrypted_secret);
}

#[test]
fn test_06_wallet_file_missing_path_is_detectable() {
    let temp = TempTree::new("test_06");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let sender = make_wallet("test_06_passphrase");
    let path = wallet_file_path(&directory, &sender);

    assert!(!path.exists());
}

#[test]
fn test_07_decrypt_wallet_secret_derives_sender_address() {
    let passphrase = "test_07_passphrase";
    let sender = make_wallet(passphrase);
    let mut secret = decrypt_wallet_secret_bytes(&sender.encrypted_secret, passphrase);

    let derived = derive_address_from_secret_bytes(&secret);

    secret.zeroize();
    assert_eq!(derived, sender.address);
}

#[test]
fn test_08_decrypt_wallet_secret_rejects_wrong_passphrase() {
    let sender = make_wallet("test_08_correct_passphrase");

    let err = assert_err(
        Cryption::decrypt_private_key_bytes(&sender.encrypted_secret, "test_08_wrong_passphrase"),
        "decrypt with wrong passphrase",
    );

    match err {
        ErrorDetection::DecryptionError { .. }
        | ErrorDetection::ValidationError { .. }
        | ErrorDetection::EncryptionError { .. } => {}
        other => panic!("unexpected decrypt error: {other:?}"),
    }
}

#[test]
fn test_09_tampered_wallet_secret_rejects_decrypt() {
    let sender = make_wallet("test_09_passphrase");
    let mut encrypted = sender.encrypted_secret.clone();

    match encrypted.first_mut() {
        Some(byte) => {
            *byte ^= 0xAA;
        }
        None => panic!("encrypted wallet secret was empty"),
    }

    let err = assert_err(
        Cryption::decrypt_private_key_bytes(&encrypted, "test_09_passphrase"),
        "decrypt tampered wallet secret",
    );

    match err {
        ErrorDetection::DecryptionError { .. }
        | ErrorDetection::ValidationError { .. }
        | ErrorDetection::EncryptionError { .. } => {}
        other => panic!("unexpected tampered decrypt error: {other:?}"),
    }
}

#[test]
fn test_10_canonical_wallet_address_accepts_generated_sender() {
    let sender = make_wallet("test_10_passphrase");
    let canonical = assert_ok(
        canon_wallet_id_checked(&sender.address),
        "canon_wallet_id_checked generated address",
    );

    assert_eq!(canonical, sender.address);
}

#[test]
fn test_11_canonical_wallet_address_rejects_empty_sender() {
    let err = assert_err(canon_wallet_id_checked(""), "canon empty wallet");

    assert_validation_error(err);
}

#[test]
fn test_12_canonical_wallet_address_rejects_short_sender() {
    let err = assert_err(canon_wallet_id_checked("r1234"), "canon short wallet");

    assert_validation_error(err);
}

#[test]
fn test_13_amount_one_micro_unit_parses() {
    assert_eq!(to_micro_units_str("0.00000001"), 1);
}

#[test]
fn test_14_amount_one_remzar_parses() {
    assert_eq!(to_micro_units_str("1"), 100_000_000);
}

#[test]
fn test_15_amount_eight_decimals_parses() {
    assert_eq!(to_micro_units_str("12.34567890"), 1_234_567_890);
}

#[test]
fn test_16_amount_zero_is_rejected_by_parser_contract() {
    assert_eq!(to_micro_units_str("0"), 0);
    assert_eq!(to_micro_units_str("0.00000000"), 0);
}

#[test]
fn test_17_amount_more_than_eight_decimals_is_rejected() {
    assert_eq!(to_micro_units_str("0.000000001"), 0);
}

#[test]
fn test_18_amount_with_comma_can_be_normalized_like_send_remzar() {
    let normalized = "1,25000000".replace(',', ".");

    assert_eq!(to_micro_units_str(&normalized), 125_000_000);
}

#[test]
fn test_19_from_micro_units_converts_one_remzar() {
    assert_eq!(from_micro_units(100_000_000), 1.0);
}

#[test]
fn test_20_transaction_new_accepts_valid_wallets_and_amount() {
    let tx = make_transaction(1);

    assert_tx_valid(&tx);
    assert_eq!(tx.amount, 1);
}

#[test]
fn test_21_transaction_new_rejects_zero_amount() {
    let (sender, receiver) = make_two_wallets();

    let err = assert_err(
        Transaction::new(sender.address, receiver.address, 0),
        "Transaction::new zero amount",
    );

    assert_validation_error(err);
}

#[test]
fn test_22_transaction_new_rejects_same_sender_receiver() {
    let sender = make_wallet("test_22_passphrase");

    let err = assert_err(
        Transaction::new(sender.address.clone(), sender.address, 1),
        "Transaction::new same sender receiver",
    );

    assert_validation_error(err);
}

#[test]
fn test_23_transaction_new_rejects_invalid_sender_address() {
    let (_sender, receiver) = make_two_wallets();

    let err = assert_err(
        Transaction::new("not-a-wallet".to_owned(), receiver.address, 1),
        "Transaction::new invalid sender",
    );

    assert_validation_error(err);
}

#[test]
fn test_24_transaction_new_rejects_invalid_receiver_address() {
    let (sender, _receiver) = make_two_wallets();

    let err = assert_err(
        Transaction::new(sender.address, "not-a-wallet".to_owned(), 1),
        "Transaction::new invalid receiver",
    );

    assert_validation_error(err);
}

#[test]
fn test_25_transaction_sender_receiver_arrays_have_wallet_length() {
    let tx = make_transaction(50);

    assert_eq!(tx.sender.len(), REMZAR_WALLET_LEN);
    assert_eq!(tx.receiver.len(), REMZAR_WALLET_LEN);
}

#[test]
fn test_26_transaction_serialize_deserialize_round_trip() {
    let tx = make_transaction(123_456);
    let bytes = assert_ok(tx.serialize(), "Transaction::serialize");
    let decoded = assert_ok(Transaction::deserialize(&bytes), "Transaction::deserialize");

    assert_eq!(decoded, tx);
}

#[test]
fn test_27_txkind_transfer_serializes_and_deserializes() {
    let tx = make_transaction(777);
    let kind = TxKind::Transfer(tx.clone());
    let bytes = assert_ok(kind.serialize(), "TxKind::serialize");
    let decoded = assert_ok(TxKind::deserialize(&bytes), "TxKind::deserialize");

    assert_eq!(decoded, TxKind::Transfer(tx));
}

#[test]
fn test_28_txkind_transfer_validate_accepts_valid_transfer() {
    let tx = make_transaction(888);
    let kind = TxKind::Transfer(tx);

    assert_ok(kind.validate(), "TxKind::validate transfer");
}

#[test]
fn test_29_txkind_transfer_normalized_sender_exists() {
    let tx = make_transaction(999);
    let kind = TxKind::Transfer(tx);

    let sender = match kind.normalized_sender() {
        Some(value) => value,
        None => panic!("normalized sender missing"),
    };

    assert_ok(canon_wallet_id_checked(&sender), "canon normalized sender");
}

#[test]
fn test_30_txkind_transfer_normalized_receiver_exists() {
    let tx = make_transaction(1_000);
    let kind = TxKind::Transfer(tx);

    let receiver = match kind.normalized_receiver() {
        Some(value) => value,
        None => panic!("normalized receiver missing"),
    };

    assert_ok(
        canon_wallet_id_checked(&receiver),
        "canon normalized receiver",
    );
}

#[test]
fn test_31_txkind_transfer_touched_addresses_has_two_unique_addresses() {
    let tx = make_transaction(1_001);
    let kind = TxKind::Transfer(tx);
    let touched = kind.touched_addresses();

    assert_eq!(touched.len(), 2);
}

#[test]
fn test_32_txkind_transfer_tag_is_transfer() {
    let tx = make_transaction(1_002);
    let kind = TxKind::Transfer(tx);

    assert_eq!(kind.tag(), "transfer");
}

#[test]
fn test_33_remzar_hash_txkind_transfer_is_128_hex_chars() {
    let tx = make_transaction(1_003);
    let kind = TxKind::Transfer(tx);
    let hash = assert_ok(
        RemzarHash::compute_data_hash(&kind),
        "compute_data_hash TxKind",
    );

    assert_eq!(hash.len(), 128);
    assert!(hash.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn test_34_remzar_truncated_hash_txkind_transfer_is_16_hex_chars() {
    let tx = make_transaction(1_004);
    let kind = TxKind::Transfer(tx);
    let hash = assert_ok(
        RemzarHash::compute_truncated_hash(&kind),
        "compute_truncated_hash TxKind",
    );

    assert_eq!(hash.len(), 16);
    assert!(hash.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn test_35_account_tree_set_and_get_sender_balance() {
    let temp = TempTree::new("test_35");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let sender = make_wallet("test_35_passphrase");

    tree.set_balance(&sender.address, 123_456);

    assert_eq!(tree.get_balance(&sender.address), 123_456);
}

#[test]
fn test_36_account_tree_increment_balance_succeeds() {
    let temp = TempTree::new("test_36");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let sender = make_wallet("test_36_passphrase");

    assert_ok(
        tree.increment_balance(&sender.address, 100),
        "increment balance first",
    );
    assert_ok(
        tree.increment_balance(&sender.address, 25),
        "increment balance second",
    );

    assert_eq!(tree.get_balance(&sender.address), 125);
}

#[test]
fn test_37_account_tree_decrement_balance_succeeds() {
    let temp = TempTree::new("test_37");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let sender = make_wallet("test_37_passphrase");

    tree.set_balance(&sender.address, 100);
    assert_ok(
        tree.decrement_balance(&sender.address, 40),
        "decrement balance",
    );

    assert_eq!(tree.get_balance(&sender.address), 60);
}

#[test]
fn test_38_account_tree_decrement_missing_account_fails() {
    let temp = TempTree::new("test_38");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let sender = make_wallet("test_38_passphrase");

    let err = assert_err(
        tree.decrement_balance(&sender.address, 1),
        "decrement missing account",
    );

    match err {
        ErrorDetection::NotFound { .. } => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn test_39_network_channel_try_send_accepts_sendtx_command() {
    let (sender_wallet, receiver_wallet) = make_two_wallets();
    let tx = assert_ok(
        Transaction::new(sender_wallet.address, receiver_wallet.address, 10),
        "Transaction::new",
    );

    let (net_tx, mut net_rx) = mpsc::channel::<NetCmd>(1);

    assert_ok(
        net_tx.try_send(NetCmd::SendTx(tx.clone())),
        "try_send SendTx",
    );

    match net_rx.try_recv() {
        Ok(NetCmd::SendTx(received)) => assert_eq!(received, tx),
        Ok(other) => panic!("unexpected net command: {other:?}"),
        Err(err) => panic!("failed to receive net command: {err:?}"),
    }
}

#[test]
fn test_40_final_wallet_file_transaction_txkind_hash_and_balance_flow() {
    let temp = TempTree::new("test_40");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let passphrase = "test_40_passphrase";
    let sender = make_wallet(passphrase);
    let receiver = make_wallet("test_40_receiver_passphrase");

    let wallet_file = write_wallet_file(&directory, &sender);
    assert!(wallet_file.exists());

    let mut encrypted_secret = assert_ok(fs::read(wallet_file), "read sender wallet file");
    let mut secret = decrypt_wallet_secret_bytes(&encrypted_secret, passphrase);
    let derived = derive_address_from_secret_bytes(&secret);

    secret.zeroize();
    encrypted_secret.zeroize();

    assert_eq!(derived, sender.address);

    let amount = to_micro_units_str("1.25000000");
    assert_eq!(amount, 125_000_000);

    let tx = assert_ok(
        Transaction::new(sender.address.clone(), receiver.address.clone(), amount),
        "Transaction::new final",
    );
    assert_tx_valid(&tx);

    let kind = TxKind::Transfer(tx);
    assert_ok(kind.validate(), "TxKind final validate");

    let hash = assert_ok(RemzarHash::compute_data_hash(&kind), "hash final kind");
    assert_eq!(hash.len(), 128);

    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    tree.set_balance(&sender.address, amount);
    assert_ok(
        tree.decrement_balance(&sender.address, amount),
        "final sender decrement",
    );
    assert_ok(
        tree.increment_balance(&receiver.address, amount),
        "final receiver increment",
    );

    assert_eq!(tree.get_balance(&sender.address), 0);
    assert_eq!(tree.get_balance(&receiver.address), amount);
}

#[test]
fn test_41_amount_vector_minimum_one_micro_unit() {
    assert_eq!(to_micro_units_str("0.00000001"), 1);
}

#[test]
fn test_42_amount_vector_ten_micro_units() {
    assert_eq!(to_micro_units_str("0.00000010"), 10);
}

#[test]
fn test_43_amount_vector_fractional_one_point_two_three() {
    assert_eq!(to_micro_units_str("1.23000000"), 123_000_000);
}

#[test]
fn test_44_amount_vector_trims_outer_whitespace() {
    assert_eq!(to_micro_units_str(" 2.50000000 "), 250_000_000);
}

#[test]
fn test_45_amount_vector_rejects_internal_whitespace() {
    assert_eq!(to_micro_units_str("2.5 0"), 0);
}

#[test]
fn test_46_amount_vector_rejects_negative() {
    assert_eq!(to_micro_units_str("-1"), 0);
}

#[test]
fn test_47_amount_vector_rejects_plus_sign() {
    assert_eq!(to_micro_units_str("+1"), 0);
}

#[test]
fn test_48_amount_vector_rejects_scientific_notation_lowercase() {
    assert_eq!(to_micro_units_str("1e8"), 0);
}

#[test]
fn test_49_amount_vector_rejects_scientific_notation_uppercase() {
    assert_eq!(to_micro_units_str("1E8"), 0);
}

#[test]
fn test_50_amount_vector_rejects_multiple_decimal_points() {
    assert_eq!(to_micro_units_str("1.2.3"), 0);
}

#[test]
fn test_51_amount_vector_rejects_letters() {
    assert_eq!(to_micro_units_str("abc"), 0);
}

#[test]
fn test_52_amount_vector_rejects_more_than_eight_fractional_digits() {
    assert_eq!(to_micro_units_str("1.123456789"), 0);
}

#[test]
fn test_53_amount_vector_accepts_empty_whole_part() {
    assert_eq!(to_micro_units_str(".00000001"), 1);
}

#[test]
fn test_54_amount_vector_rejects_empty_string() {
    assert_eq!(to_micro_units_str(""), 0);
}

#[test]
fn test_55_amount_vector_rejects_too_long_input() {
    let input = "1".repeat(65);

    assert_eq!(to_micro_units_str(&input), 0);
}

#[test]
fn test_56_amount_vector_normalized_comma_min_unit() {
    let normalized = "0,00000001".replace(',', ".");

    assert_eq!(to_micro_units_str(&normalized), 1);
}

#[test]
fn test_57_from_micro_units_zero_is_zero() {
    assert_eq!(from_micro_units(0), 0.0);
}

#[test]
fn test_58_from_micro_units_half_remzar() {
    assert_eq!(from_micro_units(50_000_000), 0.5);
}

#[test]
fn test_59_wallet_wrong_prefix_is_rejected_by_canonicalizer() {
    let wallet = make_wallet("test_59_passphrase");
    let bad = wallet_address_with_wrong_prefix(&wallet.address);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong-prefix address");

    assert_validation_error(err);
}

#[test]
fn test_60_wallet_non_hex_body_is_rejected_by_canonicalizer() {
    let wallet = make_wallet("test_60_passphrase");
    let bad = wallet_address_with_non_hex_body(&wallet.address);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon non-hex address");

    assert_validation_error(err);
}

#[test]
fn test_61_wallet_body_flip_still_has_valid_format_but_not_same_address() {
    let wallet = make_wallet("test_61_passphrase");
    let flipped = wallet_address_with_body_flip(&wallet.address);

    assert_ne!(flipped, wallet.address);

    let canonical = assert_ok(
        canon_wallet_id_checked(&flipped),
        "canon body-flipped address",
    );
    assert_eq!(canonical, flipped);
}

#[test]
fn test_62_wallet_address_uppercase_body_canonicalizes_to_lowercase() {
    let wallet = make_wallet("test_62_passphrase");
    let uppercase = wallet.address.to_ascii_uppercase();
    let canonical = assert_ok(
        canon_wallet_id_checked(&uppercase),
        "canon uppercase wallet address",
    );

    assert_eq!(canonical, wallet.address);
}

#[test]
fn test_63_wallet_address_with_outer_whitespace_canonicalizes() {
    let wallet = make_wallet("test_63_passphrase");
    let padded = format!("  {}  ", wallet.address);
    let canonical = assert_ok(
        canon_wallet_id_checked(&padded),
        "canon whitespace-padded wallet address",
    );

    assert_eq!(canonical, wallet.address);
}

#[test]
fn test_64_wallet_file_path_for_unicode_data_dir_round_trips() {
    let temp = TempTree::new("test_64");
    let opts = make_node_opts(&temp.child("node_測試_send"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_64_passphrase");

    let path = write_wallet_file(&directory, &wallet);
    let stored = assert_ok(fs::read(path), "read unicode-dir wallet file");

    assert_eq!(stored, wallet.encrypted_secret);
}

#[test]
fn test_65_wallet_file_path_for_space_data_dir_round_trips() {
    let temp = TempTree::new("test_65");
    let opts = make_node_opts(&temp.child("node with spaces"));
    let directory = directory_from_opts(&opts);
    let wallet = make_wallet("test_65_passphrase");

    let path = write_wallet_file(&directory, &wallet);
    let stored = assert_ok(fs::read(path), "read space-dir wallet file");

    assert_eq!(stored, wallet.encrypted_secret);
}

#[test]
fn test_66_wallet_secret_address_binding_detects_sender_mismatch() {
    let passphrase = "test_66_passphrase";
    let sender = make_wallet(passphrase);
    let other = make_wallet("test_66_other_passphrase");

    let mut secret = decrypt_wallet_secret_bytes(&sender.encrypted_secret, passphrase);
    let derived = derive_address_from_secret_bytes(&secret);

    secret.zeroize();

    assert_eq!(derived, sender.address);
    assert_ne!(derived, other.address);
}

#[test]
fn test_67_wallet_secret_hex_round_trip_matches_sender_address() {
    let passphrase = "test_67_passphrase";
    let sender = make_wallet(passphrase);
    let secret_hex = assert_ok(sender.secret_key_hex(passphrase), "secret_key_hex");
    let mut secret_bytes = assert_ok(hex::decode(secret_hex), "decode secret hex");

    let derived = derive_address_from_secret_bytes(&secret_bytes);

    secret_bytes.zeroize();
    assert_eq!(derived, sender.address);
}

#[test]
fn test_68_wallet_encrypted_secret_is_not_plain_secret_bytes() {
    let passphrase = "test_68_passphrase";
    let sender = make_wallet(passphrase);
    let mut secret = decrypt_wallet_secret_bytes(&sender.encrypted_secret, passphrase);

    assert_ne!(sender.encrypted_secret.as_slice(), secret.as_slice());

    secret.zeroize();
}

#[test]
fn test_69_decrypt_rejects_empty_encrypted_wallet_blob() {
    let err = assert_err(
        Cryption::decrypt_private_key_bytes(&[], "test_69_passphrase"),
        "decrypt empty encrypted blob",
    );

    assert_decryption_like_error(err);
}

#[test]
fn test_70_decrypt_rejects_short_encrypted_wallet_blob() {
    let short_blob = vec![7_u8; 12];

    let err = assert_err(
        Cryption::decrypt_private_key_bytes(&short_blob, "test_70_passphrase"),
        "decrypt short encrypted blob",
    );

    assert_decryption_like_error(err);
}

#[test]
fn test_71_transaction_rejects_body_flipped_sender_if_receiver_same_after_flip_not_used() {
    let (sender, receiver) = make_two_wallets();
    let flipped_sender = wallet_address_with_non_hex_body(&sender.address);

    let err = assert_err(
        Transaction::new(flipped_sender, receiver.address, 1),
        "Transaction::new non-hex sender",
    );

    assert_validation_error(err);
}

#[test]
fn test_72_transaction_rejects_wrong_prefix_receiver() {
    let (sender, receiver) = make_two_wallets();
    let bad_receiver = wallet_address_with_wrong_prefix(&receiver.address);

    let err = assert_err(
        Transaction::new(sender.address, bad_receiver, 1),
        "Transaction::new wrong-prefix receiver",
    );

    assert_validation_error(err);
}

#[test]
fn test_73_transaction_accepts_uppercase_addresses_by_canonicalizing() {
    let (sender, receiver) = make_two_wallets();

    let tx = assert_ok(
        Transaction::new(
            sender.address.to_ascii_uppercase(),
            receiver.address.to_ascii_uppercase(),
            123,
        ),
        "Transaction::new uppercase addresses",
    );

    assert_tx_valid(&tx);
}

#[test]
fn test_74_transaction_accepts_outer_whitespace_addresses_by_canonicalizing() {
    let (sender, receiver) = make_two_wallets();

    let tx = assert_ok(
        Transaction::new(
            format!(" {} ", sender.address),
            format!(" {} ", receiver.address),
            456,
        ),
        "Transaction::new whitespace addresses",
    );

    assert_tx_valid(&tx);
}

#[test]
fn test_75_transaction_new_from_remzar_one_remzar() {
    let (sender, receiver) = make_two_wallets();

    let tx = assert_ok(
        Transaction::new_from_remzar(sender.address, receiver.address, 1.0),
        "Transaction::new_from_remzar 1.0",
    );

    assert_eq!(tx.amount, 100_000_000);
}

#[test]
fn test_76_transaction_new_from_remzar_rejects_zero() {
    let (sender, receiver) = make_two_wallets();

    let err = assert_err(
        Transaction::new_from_remzar(sender.address, receiver.address, 0.0),
        "Transaction::new_from_remzar zero",
    );

    assert_validation_error(err);
}

#[test]
fn test_77_transaction_new_from_remzar_rejects_negative() {
    let (sender, receiver) = make_two_wallets();

    let err = assert_err(
        Transaction::new_from_remzar(sender.address, receiver.address, -1.0),
        "Transaction::new_from_remzar negative",
    );

    assert_validation_error(err);
}

#[test]
fn test_78_transaction_new_from_remzar_rejects_nan() {
    let (sender, receiver) = make_two_wallets();

    let err = assert_err(
        Transaction::new_from_remzar(sender.address, receiver.address, f64::NAN),
        "Transaction::new_from_remzar NaN",
    );

    assert_validation_error(err);
}

#[test]
fn test_79_transaction_new_from_remzar_rejects_infinity() {
    let (sender, receiver) = make_two_wallets();

    let err = assert_err(
        Transaction::new_from_remzar(sender.address, receiver.address, f64::INFINITY),
        "Transaction::new_from_remzar infinity",
    );

    assert_validation_error(err);
}

#[test]
fn test_80_transaction_new_from_aos_alias_matches_remzar_path() {
    let (sender, receiver) = make_two_wallets();

    let tx = assert_ok(
        Transaction::new_from_aos(sender.address, receiver.address, 2.0),
        "Transaction::new_from_aos",
    );

    assert_eq!(tx.amount, 200_000_000);
}

#[test]
fn test_81_transaction_amount_as_remzar_matches_micro_amount() {
    let tx = make_transaction(250_000_000);

    assert_eq!(tx.amount_as_remzar(), 2.5);
}

#[test]
fn test_82_transaction_amount_as_aos_alias_matches_remzar_amount() {
    let tx = make_transaction(375_000_000);

    assert_eq!(tx.amount_as_aos(), tx.amount_as_remzar());
}

#[test]
fn test_83_transaction_deserialize_rejects_garbage_bytes() {
    let err = assert_err(
        Transaction::deserialize(b"not a postcard transaction"),
        "Transaction::deserialize garbage",
    );

    match err {
        ErrorDetection::SerializationError { .. } | ErrorDetection::ValidationError { .. } => {}
        other => panic!("unexpected transaction deserialize error: {other:?}"),
    }
}

#[test]
fn test_84_txkind_deserialize_rejects_garbage_bytes() {
    let err = assert_err(
        TxKind::deserialize(b"not a postcard txkind"),
        "TxKind::deserialize garbage",
    );

    match err {
        ErrorDetection::SerializationError { .. } => {}
        other => panic!("unexpected TxKind deserialize error: {other:?}"),
    }
}

#[test]
fn test_85_txkind_transfer_hash_verification_succeeds() {
    let tx = make_transaction(85);
    let kind = TxKind::Transfer(tx);
    let hash = assert_ok(RemzarHash::compute_data_hash(&kind), "compute txkind hash");

    assert_ok(
        RemzarHash::verify_data_hash(&kind, &hash),
        "verify txkind hash",
    );
}

#[test]
fn test_86_txkind_transfer_hash_verification_rejects_wrong_hash_length() {
    let tx = make_transaction(86);
    let kind = TxKind::Transfer(tx);

    let err = assert_err(
        RemzarHash::verify_data_hash(&kind, "abcd"),
        "verify wrong hash length",
    );

    assert_validation_error(err);
}

#[test]
fn test_87_txkind_transfer_truncated_hash_verification_succeeds() {
    let tx = make_transaction(87);
    let kind = TxKind::Transfer(tx);
    let hash = assert_ok(
        RemzarHash::compute_truncated_hash(&kind),
        "compute truncated txkind hash",
    );

    let ok = assert_ok(
        RemzarHash::verify_truncated_hash(&kind, &hash),
        "verify truncated txkind hash",
    );

    assert!(ok);
}

#[test]
fn test_88_txkind_transfer_hash_batch_vector_succeeds() {
    let first = TxKind::Transfer(make_transaction(88));
    let second = TxKind::Transfer(make_transaction(89));
    let items = vec![first, second];

    let hashes = assert_ok(
        RemzarHash::compute_data_hash_batch(&items),
        "compute_data_hash_batch",
    );
    let checks = assert_ok(
        RemzarHash::verify_data_hash_batch(&items, &hashes),
        "verify_data_hash_batch",
    );

    assert_eq!(checks, vec![true, true]);
}

#[test]
fn test_89_txkind_transfer_hash_batch_rejects_length_mismatch() {
    let first = TxKind::Transfer(make_transaction(90));
    let items = vec![first];
    let expected = Vec::<String>::new();

    let err = assert_err(
        RemzarHash::verify_data_hash_batch(&items, &expected),
        "verify_data_hash_batch length mismatch",
    );

    assert_validation_error(err);
}

#[test]
fn test_90_account_tree_update_balance_succeeds() {
    let temp = TempTree::new("test_90");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = make_wallet("test_90_passphrase");

    assert_ok(
        tree.update_balance(&wallet.address, 100),
        "update balance first",
    );
    assert_ok(
        tree.update_balance(&wallet.address, 200),
        "update balance second",
    );

    assert_eq!(tree.get_balance(&wallet.address), 300);
}

#[test]
fn test_91_account_tree_get_balance_decimal_matches_micro_units() {
    let temp = TempTree::new("test_91");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = make_wallet("test_91_passphrase");

    tree.set_balance(&wallet.address, 150_000_000);

    assert_eq!(tree.get_balance_decimal(&wallet.address), 1.5);
}

#[test]
fn test_92_account_tree_get_balances_contains_set_balance() {
    let temp = TempTree::new("test_92");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = make_wallet("test_92_passphrase");

    tree.set_balance(&wallet.address, 777);

    let balances = tree.get_balances();
    let value = match balances.get(&wallet.address) {
        Some(v) => *v,
        None => panic!("wallet balance missing from get_balances"),
    };

    assert_eq!(value, 777);
}

#[test]
fn test_93_account_tree_decrement_underflow_fails() {
    let temp = TempTree::new("test_93");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = make_wallet("test_93_passphrase");

    tree.set_balance(&wallet.address, 10);

    let err = assert_err(
        tree.decrement_balance(&wallet.address, 11),
        "decrement underflow",
    );

    assert_validation_error(err);
}

#[test]
fn test_94_account_tree_increment_over_supply_fails() {
    let temp = TempTree::new("test_94");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let wallet = make_wallet("test_94_passphrase");

    tree.set_balance(&wallet.address, GlobalConfiguration::MAX_SUPPLY);

    let err = assert_err(
        tree.increment_balance(&wallet.address, 1),
        "increment over supply",
    );

    assert_validation_error(err);
}

#[test]
fn test_95_network_sendtx_channel_full_returns_error() {
    let tx = make_transaction(95);
    let (net_tx, _net_rx) = mpsc::channel::<NetCmd>(1);

    assert_ok(
        net_tx.try_send(NetCmd::SendTx(tx.clone())),
        "fill network channel",
    );

    let err = assert_err(
        net_tx.try_send(NetCmd::SendTx(tx)),
        "try_send second tx into full network channel",
    );

    match err {
        tokio::sync::mpsc::error::TrySendError::Full(NetCmd::SendTx(_)) => {}
        other => panic!("expected full SendTx error, got {other:?}"),
    }
}

#[test]
fn test_96_network_sendtx_channel_closed_returns_error() {
    let tx = make_transaction(96);
    let (net_tx, net_rx) = mpsc::channel::<NetCmd>(1);

    drop(net_rx);

    let err = assert_err(
        net_tx.try_send(NetCmd::SendTx(tx)),
        "try_send into closed network channel",
    );

    match err {
        tokio::sync::mpsc::error::TrySendError::Closed(NetCmd::SendTx(_)) => {}
        other => panic!("expected closed SendTx error, got {other:?}"),
    }
}

#[test]
fn test_97_network_sendtx_round_trip_preserves_transaction() {
    let tx = make_transaction(97);
    let received = send_tx_command_round_trip(tx.clone());

    assert_eq!(received, tx);
}

#[test]
fn test_98_load_create_six_transactions_unique_hashes() {
    let mut hashes = Vec::new();

    for amount in 1u64..=6u64 {
        let tx = make_transaction(amount);
        let kind = TxKind::Transfer(tx);
        let hash = assert_ok(RemzarHash::compute_data_hash(&kind), "hash transaction");
        hashes.push(hash);
    }

    for left_index in 0usize..hashes.len() {
        for right_index in left_index.saturating_add(1)..hashes.len() {
            let left = match hashes.get(left_index) {
                Some(value) => value,
                None => panic!("missing left hash"),
            };
            let right = match hashes.get(right_index) {
                Some(value) => value,
                None => panic!("missing right hash"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_99_load_create_ten_wallet_files_and_verify_binding() {
    let temp = TempTree::new("test_99");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    for index in 0usize..10usize {
        let passphrase = format!("test_99_passphrase_{index}");
        let wallet = make_wallet(&passphrase);
        let path = write_wallet_file(&directory, &wallet);

        let encrypted = assert_ok(fs::read(path), "read load wallet file");
        let mut secret = decrypt_wallet_secret_bytes(&encrypted, &passphrase);
        let derived = derive_address_from_secret_bytes(&secret);

        secret.zeroize();
        assert_eq!(derived, wallet.address);
    }
}

#[test]
fn test_100_final_send_dependencies_wallet_transaction_hash_balance_and_network_flow() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let manager = make_test_manager(&opts);
    let mut tree = AccountModelTree::with_manager(manager);
    let passphrase = "test_100_passphrase";
    let sender = make_wallet(passphrase);
    let receiver = make_wallet("test_100_receiver_passphrase");

    let wallet_file = write_wallet_file(&directory, &sender);
    let encrypted = assert_ok(fs::read(wallet_file), "read final wallet file");
    let mut secret = decrypt_wallet_secret_bytes(&encrypted, passphrase);
    let derived = derive_address_from_secret_bytes(&secret);

    secret.zeroize();
    assert_eq!(derived, sender.address);

    let amount = to_micro_units_str("3.21000000");
    assert_eq!(amount, 321_000_000);

    let tx = make_tx_from_wallets(&sender, &receiver, amount);
    assert_tx_valid(&tx);

    let kind = TxKind::Transfer(tx.clone());
    let serialized = assert_ok(kind.serialize(), "serialize final TxKind");
    let decoded = assert_ok(TxKind::deserialize(&serialized), "deserialize final TxKind");
    assert_eq!(decoded, kind);

    let hash = assert_ok(RemzarHash::compute_data_hash(&kind), "hash final TxKind");
    assert_eq!(hash.len(), 128);
    assert_hex_lowercase_ascii(&hash);

    tree.set_balance(&sender.address, amount);
    assert_ok(
        tree.decrement_balance(&sender.address, amount),
        "final sender debit",
    );
    assert_ok(
        tree.increment_balance(&receiver.address, amount),
        "final receiver credit",
    );

    assert_eq!(tree.get_balance(&sender.address), 0);
    assert_eq!(tree.get_balance(&receiver.address), amount);

    let received = send_tx_command_round_trip(tx.clone());
    assert_eq!(received, tx);
}
