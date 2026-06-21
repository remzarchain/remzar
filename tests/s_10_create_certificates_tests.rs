use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::commandline::s_10_create_certificates::S10CreateCertificates;
use remzar::network::p2p_010_netcmd::NetCmd;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::tokens::nft_001::{
    NftMintTx, NftRecord, NftTransferTx, apply_nft_mint, apply_nft_transfer, load_nft_record,
    store_nft_record,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::certificate_receipt::CertificateReceipt;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
use remzar::utility::logging_data::JsonLogger;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_10_create_certificates_tests_{test_name}_{}_{}",
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

fn assert_serialization_error(err: ErrorDetection) {
    match err {
        ErrorDetection::SerializationError { .. } => {}
        other => panic!("expected SerializationError, got {other:?}"),
    }
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

fn directory_from_opts(opts: &NodeOpts) -> DirectoryDB {
    assert_ok(
        DirectoryDB::from_node_opts(opts),
        "DirectoryDB::from_node_opts",
    )
}

fn make_manager(opts: &NodeOpts) -> Arc<RockDBManager> {
    Arc::new(assert_ok(RockDBManager::new(opts), "RockDBManager::new"))
}

fn make_logger(opts: &NodeOpts) -> JsonLogger {
    let directory = directory_from_opts(opts);
    assert_ok(directory.create_log_directory(), "create_log_directory");
    assert_ok(JsonLogger::new(&directory), "JsonLogger::new")
}

fn wallet_from_label(label: &str) -> String {
    format!("r{}", RemzarHash::compute_bytes_hash_hex(label.as_bytes()))
}

fn assert_wallet_shape(wallet: &str) {
    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
    assert!(wallet.starts_with('r'));
    assert!(
        wallet
            .as_bytes()
            .iter()
            .skip(1)
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

fn nft_id_from_label(label: &str) -> [u8; 64] {
    RemzarHash::compute_bytes_hash(label.as_bytes())
}

fn content_hash_from_bytes(bytes: &[u8]) -> [u8; 64] {
    RemzarHash::compute_bytes_hash(bytes)
}

fn sample_content(label: &str) -> Vec<u8> {
    format!("sample certificate content::{label}").into_bytes()
}

fn make_mint_tx(label: &str) -> NftMintTx {
    NftMintTx::from_content_bytes(
        nft_id_from_label(&format!("nft::{label}")),
        format!("Title {label}"),
        format!("Description {label}"),
        &sample_content(label),
    )
}

fn make_record(label: &str, owner: &str) -> NftRecord {
    let tx = make_mint_tx(label);
    NftRecord {
        nft_id: tx.nft_id,
        creator_wallet: owner.to_owned(),
        owner_wallet: owner.to_owned(),
        content_hash: tx.content_hash,
        title: tx.title,
        description: tx.description,
        minted_height: 7,
        minted_time: 1_700_000_000,
    }
}

fn make_receipt(label: &str) -> CertificateReceipt {
    let content = sample_content(label);
    CertificateReceipt {
        nft_id_hex: hex::encode(nft_id_from_label(&format!("receipt-nft::{label}"))),
        owner_wallet: wallet_from_label(&format!("owner::{label}")),
        file_name: format!("certificate_{label}.bin"),
        file_size_bytes: content.len(),
        content_hash_hex: RemzarHash::compute_bytes_hash_hex(&content),
        title: format!("Certificate {label}"),
        description: format!("Kind: Certificate | Schema: certificate-v1 | Label: {label}"),
        created_at_utc: "2026-05-02T00:00:00Z".to_owned(),
        edition: Some("01/01".to_owned()),
        kind: "Certificate".to_owned(),
        schema: "certificate-v1".to_owned(),
    }
}

fn assert_receipt_valid(receipt: &CertificateReceipt) {
    assert_ok(receipt.validate(), "CertificateReceipt::validate");
}

fn assert_hash_hex_128(value: &str) {
    assert_eq!(value.len(), 128);
    assert!(value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()));
}

fn send_txkind_round_trip(kind: TxKind) -> TxKind {
    let (tx, mut rx) = mpsc::channel::<NetCmd>(1);

    assert_ok(
        tx.try_send(NetCmd::SendTxKind(kind.clone())),
        "try_send NetCmd::SendTxKind",
    );

    match rx.try_recv() {
        Ok(NetCmd::SendTxKind(received)) => received,
        Ok(other) => panic!("unexpected NetCmd variant: {other:?}"),
        Err(err) => panic!("failed to receive NetCmd: {err:?}"),
    }
}

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S10CreateCertificates::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S10CreateCertificates;
}

#[test]
fn test_03_unit_struct_constructor_creates_section() {
    let _section = S10CreateCertificates;
}

#[test]
fn test_04_wallet_from_label_has_expected_shape() {
    let wallet = wallet_from_label("test_04");

    assert_wallet_shape(&wallet);
}

#[test]
fn test_05_wallet_canonicalization_accepts_wallet_from_label() {
    let wallet = wallet_from_label("test_05");
    let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon wallet");

    assert_eq!(canonical, wallet);
}

#[test]
fn test_06_wallet_canonicalization_accepts_uppercase() {
    let wallet = wallet_from_label("test_06");
    let canonical = assert_ok(
        canon_wallet_id_checked(&wallet.to_ascii_uppercase()),
        "canon uppercase wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_07_wallet_canonicalization_accepts_outer_whitespace() {
    let wallet = wallet_from_label("test_07");
    let canonical = assert_ok(
        canon_wallet_id_checked(&format!("  {wallet}  ")),
        "canon whitespace wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_08_wallet_canonicalization_rejects_empty() {
    let err = assert_err(canon_wallet_id_checked(""), "canon empty wallet");

    assert_validation_error(err);
}

#[test]
fn test_09_wallet_canonicalization_rejects_short() {
    let err = assert_err(canon_wallet_id_checked("r1234"), "canon short wallet");

    assert_validation_error(err);
}

#[test]
fn test_10_wallet_canonicalization_rejects_wrong_prefix() {
    let wallet = wallet_from_label("test_10");
    let bad = format!("x{}", &wallet[1..]);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong prefix");

    assert_validation_error(err);
}

#[test]
fn test_11_wallet_canonicalization_rejects_non_hex_body() {
    let mut wallet = wallet_from_label("test_11");
    wallet.replace_range(1..2, "g");

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon non-hex wallet");

    assert_validation_error(err);
}

#[test]
fn test_12_register_node_accepts_certificate_owner_wallet() {
    let wallet = wallet_from_label("test_12");

    assert_ok(RegisterNodeTx::new(wallet), "RegisterNodeTx::new");
}

#[test]
fn test_13_register_node_rejects_invalid_certificate_owner_wallet() {
    let err = assert_err(
        RegisterNodeTx::new("not-a-wallet".to_owned()),
        "RegisterNodeTx::new invalid",
    );

    assert_validation_error(err);
}

#[test]
fn test_14_nft_id_from_label_is_64_bytes() {
    let nft_id = nft_id_from_label("test_14");

    assert_eq!(nft_id.len(), 64);
}

#[test]
fn test_15_nft_id_hex_is_128_chars() {
    let nft_id_hex = hex::encode(nft_id_from_label("test_15"));

    assert_hash_hex_128(&nft_id_hex);
}

#[test]
fn test_16_content_hash_hex_is_128_chars() {
    let hash = RemzarHash::compute_bytes_hash_hex(&sample_content("test_16"));

    assert_hash_hex_128(&hash);
}

#[test]
fn test_17_nft_mint_from_content_bytes_sets_expected_hash() {
    let content = sample_content("test_17");
    let tx = NftMintTx::from_content_bytes(
        nft_id_from_label("test_17"),
        "Title".to_owned(),
        "Description".to_owned(),
        &content,
    );

    assert_eq!(tx.content_hash, content_hash_from_bytes(&content));
}

#[test]
fn test_18_nft_mint_preserves_title_and_description() {
    let tx = NftMintTx::from_content_bytes(
        nft_id_from_label("test_18"),
        "My Title".to_owned(),
        "My Description".to_owned(),
        b"content",
    );

    assert_eq!(tx.title, "My Title");
    assert_eq!(tx.description, "My Description");
}

#[test]
fn test_19_nft_mint_empty_content_hash_is_stable() {
    let first = NftMintTx::from_content_bytes(
        nft_id_from_label("test_19_a"),
        "Empty".to_owned(),
        "Empty content".to_owned(),
        b"",
    );
    let second = NftMintTx::from_content_bytes(
        nft_id_from_label("test_19_b"),
        "Empty".to_owned(),
        "Empty content".to_owned(),
        b"",
    );

    assert_eq!(first.content_hash, second.content_hash);
}

#[test]
fn test_20_nft_mint_different_content_changes_hash() {
    let first = NftMintTx::from_content_bytes(
        nft_id_from_label("test_20_a"),
        "Title".to_owned(),
        "Description".to_owned(),
        b"content one",
    );
    let second = NftMintTx::from_content_bytes(
        nft_id_from_label("test_20_b"),
        "Title".to_owned(),
        "Description".to_owned(),
        b"content two",
    );

    assert_ne!(first.content_hash, second.content_hash);
}

#[test]
fn test_21_txkind_nft_mint_serializes_and_deserializes() {
    let tx = make_mint_tx("test_21");
    let kind = TxKind::NftMint(tx.clone());
    let bytes = assert_ok(kind.serialize(), "TxKind::serialize");
    let decoded = assert_ok(TxKind::deserialize(&bytes), "TxKind::deserialize");

    assert_eq!(decoded, TxKind::NftMint(tx));
}

#[test]
fn test_22_txkind_nft_mint_validate_succeeds() {
    let kind = TxKind::NftMint(make_mint_tx("test_22"));

    assert_ok(kind.validate(), "TxKind::validate NftMint");
}

#[test]
fn test_23_txkind_nft_mint_tag_is_nft_mint() {
    let kind = TxKind::NftMint(make_mint_tx("test_23"));

    assert_eq!(kind.tag(), "nft_mint");
}

#[test]
fn test_24_txkind_nft_mint_touched_addresses_empty() {
    let kind = TxKind::NftMint(make_mint_tx("test_24"));

    assert!(kind.touched_addresses().is_empty());
}

#[test]
fn test_25_txkind_nft_mint_normalized_sender_none() {
    let kind = TxKind::NftMint(make_mint_tx("test_25"));

    assert!(kind.normalized_sender().is_none());
}

#[test]
fn test_26_txkind_nft_mint_normalized_receiver_none() {
    let kind = TxKind::NftMint(make_mint_tx("test_26"));

    assert!(kind.normalized_receiver().is_none());
}

#[test]
fn test_27_nft_transfer_validates_with_canonical_owner() {
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_27"),
        new_owner_wallet: wallet_from_label("test_27_owner"),
    };
    let kind = TxKind::NftTransfer(transfer);

    assert_ok(kind.validate(), "TxKind::validate NftTransfer");
}

#[test]
fn test_28_nft_transfer_rejects_empty_owner() {
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_28"),
        new_owner_wallet: String::new(),
    };
    let kind = TxKind::NftTransfer(transfer);

    let err = assert_err(kind.validate(), "validate empty owner transfer");

    assert_validation_error(err);
}

#[test]
fn test_29_nft_transfer_rejects_invalid_owner() {
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_29"),
        new_owner_wallet: "not-a-wallet".to_owned(),
    };
    let kind = TxKind::NftTransfer(transfer);

    let err = assert_err(kind.validate(), "validate invalid owner transfer");

    assert_validation_error(err);
}

#[test]
fn test_30_txkind_nft_transfer_serializes_and_deserializes() {
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_30"),
        new_owner_wallet: wallet_from_label("test_30_owner"),
    };
    let kind = TxKind::NftTransfer(transfer.clone());
    let bytes = assert_ok(kind.serialize(), "serialize transfer TxKind");
    let decoded = assert_ok(TxKind::deserialize(&bytes), "deserialize transfer TxKind");

    assert_eq!(decoded, TxKind::NftTransfer(transfer));
}

#[test]
fn test_31_txkind_nft_transfer_tag_is_nft_transfer() {
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_31"),
        new_owner_wallet: wallet_from_label("test_31_owner"),
    };
    let kind = TxKind::NftTransfer(transfer);

    assert_eq!(kind.tag(), "nft_transfer");
}

#[test]
fn test_32_txkind_deserialize_rejects_garbage() {
    let err = assert_err(
        TxKind::deserialize(b"not a txkind"),
        "deserialize garbage TxKind",
    );

    assert_serialization_error(err);
}

#[test]
fn test_33_send_txkind_channel_round_trips_nft_mint() {
    let kind = TxKind::NftMint(make_mint_tx("test_33"));
    let received = send_txkind_round_trip(kind.clone());

    assert_eq!(received, kind);
}

#[test]
fn test_34_send_txkind_channel_round_trips_nft_transfer() {
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_34"),
        new_owner_wallet: wallet_from_label("test_34_owner"),
    };
    let kind = TxKind::NftTransfer(transfer);
    let received = send_txkind_round_trip(kind.clone());

    assert_eq!(received, kind);
}

#[test]
fn test_35_send_txkind_channel_full_returns_error() {
    let (tx, _rx) = mpsc::channel::<NetCmd>(1);
    let first = TxKind::NftMint(make_mint_tx("test_35_first"));
    let second = TxKind::NftMint(make_mint_tx("test_35_second"));

    assert_ok(
        tx.try_send(NetCmd::SendTxKind(first)),
        "fill SendTxKind channel",
    );

    let err = assert_err(
        tx.try_send(NetCmd::SendTxKind(second)),
        "second SendTxKind should fail",
    );

    match err {
        tokio::sync::mpsc::error::TrySendError::Full(NetCmd::SendTxKind(_)) => {}
        other => panic!("expected full SendTxKind error, got {other:?}"),
    }
}

#[test]
fn test_36_send_txkind_channel_closed_returns_error() {
    let (tx, rx) = mpsc::channel::<NetCmd>(1);
    drop(rx);

    let err = assert_err(
        tx.try_send(NetCmd::SendTxKind(TxKind::NftMint(make_mint_tx("test_36")))),
        "closed SendTxKind channel",
    );

    match err {
        tokio::sync::mpsc::error::TrySendError::Closed(NetCmd::SendTxKind(_)) => {}
        other => panic!("expected closed SendTxKind error, got {other:?}"),
    }
}

#[test]
fn test_37_certificate_receipt_validate_accepts_valid_receipt() {
    let receipt = make_receipt("test_37");

    assert_receipt_valid(&receipt);
}

#[test]
fn test_38_certificate_receipt_json_round_trips() {
    let receipt = make_receipt("test_38");
    let bytes = assert_ok(serde_json::to_vec(&receipt), "serialize receipt json");
    let decoded: CertificateReceipt =
        assert_ok(serde_json::from_slice(&bytes), "deserialize receipt json");

    assert_eq!(decoded.nft_id_hex, receipt.nft_id_hex);
    assert_eq!(decoded.owner_wallet, receipt.owner_wallet);
    assert_eq!(decoded.content_hash_hex, receipt.content_hash_hex);
}

#[test]
fn test_39_certificate_receipt_pretty_json_contains_title() {
    let receipt = make_receipt("test_39");
    let bytes = assert_ok(
        serde_json::to_vec_pretty(&receipt),
        "pretty serialize receipt json",
    );
    let text = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(err) => panic!("receipt JSON was invalid UTF-8: {err}"),
    };

    assert!(text.contains("Certificate test_39"));
}

#[test]
fn test_40_certificate_receipt_rejects_empty_nft_id() {
    let mut receipt = make_receipt("test_40");
    receipt.nft_id_hex.clear();

    let err = assert_err(receipt.validate(), "validate empty nft id");

    assert_validation_error(err);
}

#[test]
fn test_41_certificate_receipt_rejects_short_nft_id() {
    let mut receipt = make_receipt("test_41");
    receipt.nft_id_hex = "abcd".to_owned();

    let err = assert_err(receipt.validate(), "validate short nft id");

    assert_validation_error(err);
}

#[test]
fn test_42_certificate_receipt_rejects_non_hex_nft_id() {
    let mut receipt = make_receipt("test_42");
    receipt.nft_id_hex.replace_range(0..1, "g");

    let err = assert_err(receipt.validate(), "validate non-hex nft id");

    assert_validation_error(err);
}

#[test]
fn test_43_certificate_receipt_rejects_empty_content_hash() {
    let mut receipt = make_receipt("test_43");
    receipt.content_hash_hex.clear();

    let err = assert_err(receipt.validate(), "validate empty content hash");

    assert_validation_error(err);
}

#[test]
fn test_44_certificate_receipt_rejects_short_content_hash() {
    let mut receipt = make_receipt("test_44");
    receipt.content_hash_hex = "abcd".to_owned();

    let err = assert_err(receipt.validate(), "validate short content hash");

    assert_validation_error(err);
}

#[test]
fn test_45_certificate_receipt_rejects_non_hex_content_hash() {
    let mut receipt = make_receipt("test_45");
    receipt.content_hash_hex.replace_range(0..1, "g");

    let err = assert_err(receipt.validate(), "validate non-hex content hash");

    assert_validation_error(err);
}

#[test]
fn test_46_certificate_receipt_rejects_invalid_owner() {
    let mut receipt = make_receipt("test_46");
    receipt.owner_wallet = "not-a-wallet".to_owned();

    let err = assert_err(receipt.validate(), "validate invalid owner");

    assert_validation_error(err);
}

#[test]
fn test_47_certificate_receipt_rejects_empty_file_name() {
    let mut receipt = make_receipt("test_47");
    receipt.file_name.clear();

    let err = assert_err(receipt.validate(), "validate empty file name");

    assert_validation_error(err);
}

#[test]
fn test_48_certificate_receipt_rejects_path_separator_file_name() {
    let mut receipt = make_receipt("test_48");
    receipt.file_name = "folder/file.txt".to_owned();

    let err = assert_err(receipt.validate(), "validate path separator file name");

    assert_validation_error(err);
}

#[test]
fn test_49_certificate_receipt_rejects_backslash_file_name() {
    let mut receipt = make_receipt("test_49");
    receipt.file_name = "folder\\file.txt".to_owned();

    let err = assert_err(receipt.validate(), "validate backslash file name");

    assert_validation_error(err);
}

#[test]
fn test_50_certificate_receipt_rejects_parent_dir_file_name() {
    let mut receipt = make_receipt("test_50");
    receipt.file_name = "../file.txt".to_owned();

    let err = assert_err(receipt.validate(), "validate parent dir file name");

    assert_validation_error(err);
}

#[test]
fn test_51_certificate_receipt_rejects_control_char_file_name() {
    let mut receipt = make_receipt("test_51");
    receipt.file_name = "bad\nfile.txt".to_owned();

    let err = assert_err(receipt.validate(), "validate control char file name");

    assert_validation_error(err);
}

#[test]
fn test_52_certificate_receipt_rejects_empty_title() {
    let mut receipt = make_receipt("test_52");
    receipt.title.clear();

    let err = assert_err(receipt.validate(), "validate empty title");

    assert_validation_error(err);
}

#[test]
fn test_53_certificate_receipt_rejects_empty_description() {
    let mut receipt = make_receipt("test_53");
    receipt.description.clear();

    let err = assert_err(receipt.validate(), "validate empty description");

    assert_validation_error(err);
}

#[test]
fn test_54_certificate_receipt_rejects_empty_created_at() {
    let mut receipt = make_receipt("test_54");
    receipt.created_at_utc.clear();

    let err = assert_err(receipt.validate(), "validate empty created at");

    assert_validation_error(err);
}

#[test]
fn test_55_certificate_receipt_rejects_empty_kind() {
    let mut receipt = make_receipt("test_55");
    receipt.kind.clear();

    let err = assert_err(receipt.validate(), "validate empty kind");

    assert_validation_error(err);
}

#[test]
fn test_56_certificate_receipt_rejects_empty_schema() {
    let mut receipt = make_receipt("test_56");
    receipt.schema.clear();

    let err = assert_err(receipt.validate(), "validate empty schema");

    assert_validation_error(err);
}

#[test]
fn test_57_certificate_receipt_accepts_none_edition() {
    let mut receipt = make_receipt("test_57");
    receipt.edition = None;

    assert_receipt_valid(&receipt);
}

#[test]
fn test_58_certificate_receipt_accepts_empty_some_edition() {
    let mut receipt = make_receipt("test_58");
    receipt.edition = Some(String::new());

    assert_receipt_valid(&receipt);
}

#[test]
fn test_59_certificate_receipt_rejects_too_long_title() {
    let mut receipt = make_receipt("test_59");
    receipt.title = "x".repeat(2_049);

    let err = assert_err(receipt.validate(), "validate too-long title");

    assert_validation_error(err);
}

#[test]
fn test_60_certificate_receipt_rejects_too_long_file_name() {
    let mut receipt = make_receipt("test_60");
    receipt.file_name = format!("{}.txt", "x".repeat(256));

    let err = assert_err(receipt.validate(), "validate too-long file name");

    assert_validation_error(err);
}

#[test]
fn test_61_store_and_load_nft_record_round_trips() {
    let temp = TempTree::new("test_61");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let owner = wallet_from_label("test_61_owner");
    let record = make_record("test_61", &owner);

    assert_ok(store_nft_record(&manager, &record), "store NFT record");

    let loaded = assert_ok(load_nft_record(&manager, &record.nft_id), "load NFT record");

    match loaded {
        Some(value) => {
            assert_eq!(value.nft_id, record.nft_id);
            assert_eq!(value.owner_wallet, record.owner_wallet);
            assert_eq!(value.content_hash, record.content_hash);
        }
        None => panic!("stored NFT record was missing"),
    }
}

#[test]
fn test_62_load_missing_nft_record_returns_none() {
    let temp = TempTree::new("test_62");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    let loaded = assert_ok(
        load_nft_record(&manager, &nft_id_from_label("missing")),
        "load missing NFT record",
    );

    assert!(loaded.is_none());
}

#[test]
fn test_63_apply_nft_mint_stores_record() {
    let temp = TempTree::new("test_63");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let signer = wallet_from_label("test_63_signer");
    let tx = make_mint_tx("test_63");

    assert_ok(
        apply_nft_mint(&manager, &tx, &signer, 63, 1_700_000_063),
        "apply NFT mint",
    );

    let loaded = assert_ok(load_nft_record(&manager, &tx.nft_id), "load minted record");

    match loaded {
        Some(record) => {
            assert_eq!(record.creator_wallet, signer);
            assert_eq!(record.owner_wallet, signer);
            assert_eq!(record.content_hash, tx.content_hash);
            assert_eq!(record.minted_height, 63);
        }
        None => panic!("minted record missing"),
    }
}

#[test]
fn test_64_apply_duplicate_nft_mint_fails() {
    let temp = TempTree::new("test_64");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let signer = wallet_from_label("test_64_signer");
    let tx = make_mint_tx("test_64");

    assert_ok(
        apply_nft_mint(&manager, &tx, &signer, 64, 1_700_000_064),
        "first NFT mint",
    );

    let err = assert_err(
        apply_nft_mint(&manager, &tx, &signer, 65, 1_700_000_065),
        "duplicate NFT mint",
    );

    assert_validation_error(err);
}

#[test]
fn test_65_apply_nft_transfer_changes_owner() {
    let temp = TempTree::new("test_65");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let owner = wallet_from_label("test_65_owner");
    let new_owner = wallet_from_label("test_65_new_owner");
    let tx = make_mint_tx("test_65");

    assert_ok(
        apply_nft_mint(&manager, &tx, &owner, 65, 1_700_000_065),
        "mint before transfer",
    );

    let transfer = NftTransferTx {
        nft_id: tx.nft_id,
        new_owner_wallet: new_owner.clone(),
    };

    assert_ok(
        apply_nft_transfer(&manager, &transfer, &owner, 66, 1_700_000_066),
        "apply NFT transfer",
    );

    let loaded = assert_ok(
        load_nft_record(&manager, &tx.nft_id),
        "load transferred NFT",
    );

    match loaded {
        Some(record) => assert_eq!(record.owner_wallet, new_owner),
        None => panic!("transferred record missing"),
    }
}

#[test]
fn test_66_apply_nft_transfer_missing_record_fails() {
    let temp = TempTree::new("test_66");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let owner = wallet_from_label("test_66_owner");
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_66_missing"),
        new_owner_wallet: wallet_from_label("test_66_new_owner"),
    };

    let err = assert_err(
        apply_nft_transfer(&manager, &transfer, &owner, 66, 1_700_000_066),
        "transfer missing NFT",
    );

    assert_validation_error(err);
}

#[test]
fn test_67_apply_nft_transfer_wrong_signer_fails() {
    let temp = TempTree::new("test_67");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let owner = wallet_from_label("test_67_owner");
    let wrong_signer = wallet_from_label("test_67_wrong_signer");
    let tx = make_mint_tx("test_67");

    assert_ok(
        apply_nft_mint(&manager, &tx, &owner, 67, 1_700_000_067),
        "mint before wrong signer transfer",
    );

    let transfer = NftTransferTx {
        nft_id: tx.nft_id,
        new_owner_wallet: wallet_from_label("test_67_new_owner"),
    };

    let err = assert_err(
        apply_nft_transfer(&manager, &transfer, &wrong_signer, 68, 1_700_000_068),
        "transfer with wrong signer",
    );

    assert_validation_error(err);
}

#[test]
fn test_68_apply_nft_transfer_same_owner_is_ok() {
    let temp = TempTree::new("test_68");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let owner = wallet_from_label("test_68_owner");
    let tx = make_mint_tx("test_68");

    assert_ok(
        apply_nft_mint(&manager, &tx, &owner, 68, 1_700_000_068),
        "mint before same-owner transfer",
    );

    let transfer = NftTransferTx {
        nft_id: tx.nft_id,
        new_owner_wallet: owner.clone(),
    };

    assert_ok(
        apply_nft_transfer(&manager, &transfer, &owner, 69, 1_700_000_069),
        "same owner transfer",
    );
}

#[test]
fn test_69_apply_nft_transfer_empty_new_owner_fails() {
    let temp = TempTree::new("test_69");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let owner = wallet_from_label("test_69_owner");
    let tx = make_mint_tx("test_69");

    assert_ok(
        apply_nft_mint(&manager, &tx, &owner, 69, 1_700_000_069),
        "mint before empty-owner transfer",
    );

    let transfer = NftTransferTx {
        nft_id: tx.nft_id,
        new_owner_wallet: String::new(),
    };

    let err = assert_err(
        apply_nft_transfer(&manager, &transfer, &owner, 70, 1_700_000_070),
        "empty new owner transfer",
    );

    assert_validation_error(err);
}

#[test]
fn test_70_txkind_nft_transfer_validate_accepts_uppercase_owner_by_canonicalizing() {
    let owner = wallet_from_label("test_70_owner");
    let transfer = NftTransferTx {
        nft_id: nft_id_from_label("test_70"),
        new_owner_wallet: owner.to_ascii_uppercase(),
    };
    let kind = TxKind::NftTransfer(transfer);

    assert_ok(kind.validate(), "validate uppercase NftTransfer owner");
}

#[test]
fn test_71_logger_accepts_certificate_event() {
    let temp = TempTree::new("test_71");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);

    assert_ok(
        logger.log_error_event("nft", "CertificateTestEvent", "certificate test event"),
        "log certificate event",
    );
    assert_ok(logger.flush_logs_cf(), "flush logs cf");
}

#[test]
fn test_72_logger_accepts_nft_id_message() {
    let temp = TempTree::new("test_72");
    let opts = make_node_opts(&temp.child("node"));
    let logger = make_logger(&opts);
    let nft_id_hex = hex::encode(nft_id_from_label("test_72"));

    assert_ok(
        logger.log_error_event("nft", "NftId", &nft_id_hex),
        "log NFT id",
    );
    assert_ok(logger.flush(), "flush logger");
}

#[test]
fn test_73_receipt_json_file_write_read_parse_validate() {
    let temp = TempTree::new("test_73");
    let receipt = make_receipt("test_73");
    let path = temp.child("certificate.json");
    let json = assert_ok(serde_json::to_vec_pretty(&receipt), "serialize receipt");

    assert_ok(fs::write(&path, &json), "write receipt json");

    let read = assert_ok(fs::read(&path), "read receipt json");
    let decoded: CertificateReceipt = assert_ok(serde_json::from_slice(&read), "decode receipt");

    assert_receipt_valid(&decoded);
    assert_eq!(decoded.nft_id_hex, receipt.nft_id_hex);
}

#[test]
fn test_74_receipt_json_rejects_garbage() {
    let err = assert_err(
        serde_json::from_slice::<CertificateReceipt>(b"not json"),
        "decode garbage receipt json",
    );

    let message = err.to_string();
    assert!(!message.is_empty());
}

#[test]
fn test_75_content_file_hash_matches_receipt_hash() {
    let temp = TempTree::new("test_75");
    let path = temp.child("content.bin");
    let content = sample_content("test_75");
    let receipt = CertificateReceipt {
        file_size_bytes: content.len(),
        content_hash_hex: RemzarHash::compute_bytes_hash_hex(&content),
        ..make_receipt("test_75")
    };

    assert_ok(fs::write(&path, &content), "write content file");
    let read = assert_ok(fs::read(&path), "read content file");

    assert_eq!(
        RemzarHash::compute_bytes_hash_hex(&read),
        receipt.content_hash_hex
    );
}

#[test]
fn test_76_empty_file_metadata_is_zero_len() {
    let temp = TempTree::new("test_76");
    let path = temp.child("empty.bin");

    assert_ok(fs::write(&path, b""), "write empty file");

    let meta = assert_ok(fs::metadata(path), "metadata empty file");
    assert_eq!(meta.len(), 0);
}

#[test]
fn test_77_nonempty_file_metadata_len_matches_content() {
    let temp = TempTree::new("test_77");
    let path = temp.child("content.bin");
    let content = sample_content("test_77");

    assert_ok(fs::write(&path, &content), "write content file");

    let meta = assert_ok(fs::metadata(path), "metadata content file");
    let len = match usize::try_from(meta.len()) {
        Ok(value) => value,
        Err(_) => panic!("metadata len did not fit usize"),
    };

    assert_eq!(len, content.len());
}

#[test]
fn test_78_directory_path_is_not_regular_file() {
    let temp = TempTree::new("test_78");
    let dir = temp.child("dir");

    assert_ok(fs::create_dir_all(&dir), "create directory");

    let meta = assert_ok(fs::metadata(dir), "metadata directory");
    assert!(!meta.is_file());
}

#[test]
fn test_79_vector_certificate_kinds_receipts_validate() {
    for (kind, schema) in [
        ("Art", "art-v1"),
        ("Badge", "badge-v1"),
        ("LegalDocument", "legal-v1"),
        ("Certificate", "certificate-v1"),
        ("SoftwareRelease", "release-v1"),
    ] {
        let mut receipt = make_receipt(kind);
        receipt.kind = kind.to_owned();
        receipt.schema = schema.to_owned();

        assert_receipt_valid(&receipt);
    }
}

#[test]
fn test_80_vector_nft_mint_content_hashes_are_distinct() {
    let mut hashes = Vec::new();

    for index in 0usize..5usize {
        let tx = make_mint_tx(&format!("test_80_{index}"));
        hashes.push(tx.content_hash);
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
fn test_81_vector_nft_ids_are_distinct() {
    let mut ids = Vec::new();

    for index in 0usize..5usize {
        ids.push(nft_id_from_label(&format!("test_81_{index}")));
    }

    for left_index in 0usize..ids.len() {
        for right_index in left_index.saturating_add(1)..ids.len() {
            let left = match ids.get(left_index) {
                Some(value) => value,
                None => panic!("missing left nft id"),
            };
            let right = match ids.get(right_index) {
                Some(value) => value,
                None => panic!("missing right nft id"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_82_vector_store_load_three_nft_records() {
    let temp = TempTree::new("test_82");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for index in 0usize..3usize {
        let owner = wallet_from_label(&format!("test_82_owner_{index}"));
        let record = make_record(&format!("test_82_{index}"), &owner);

        assert_ok(
            store_nft_record(&manager, &record),
            "store vector NFT record",
        );

        let loaded = assert_ok(load_nft_record(&manager, &record.nft_id), "load vector NFT");
        match loaded {
            Some(value) => assert_eq!(value.owner_wallet, owner),
            None => panic!("stored vector NFT missing"),
        }
    }
}

#[test]
fn test_83_vector_apply_three_nft_mints() {
    let temp = TempTree::new("test_83");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for index in 0usize..3usize {
        let signer = wallet_from_label(&format!("test_83_signer_{index}"));
        let tx = make_mint_tx(&format!("test_83_{index}"));

        assert_ok(
            apply_nft_mint(&manager, &tx, &signer, 83, 1_700_000_083),
            "apply vector NFT mint",
        );
    }
}

#[test]
fn test_84_vector_apply_transfer_chain_updates_owner() {
    let temp = TempTree::new("test_84");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let owner_a = wallet_from_label("test_84_owner_a");
    let owner_b = wallet_from_label("test_84_owner_b");
    let owner_c = wallet_from_label("test_84_owner_c");
    let tx = make_mint_tx("test_84");

    assert_ok(
        apply_nft_mint(&manager, &tx, &owner_a, 84, 1_700_000_084),
        "mint before transfer chain",
    );

    assert_ok(
        apply_nft_transfer(
            &manager,
            &NftTransferTx {
                nft_id: tx.nft_id,
                new_owner_wallet: owner_b.clone(),
            },
            &owner_a,
            85,
            1_700_000_085,
        ),
        "transfer owner a to b",
    );

    assert_ok(
        apply_nft_transfer(
            &manager,
            &NftTransferTx {
                nft_id: tx.nft_id,
                new_owner_wallet: owner_c.clone(),
            },
            &owner_b,
            86,
            1_700_000_086,
        ),
        "transfer owner b to c",
    );

    let loaded = assert_ok(
        load_nft_record(&manager, &tx.nft_id),
        "load transferred chain NFT",
    );
    match loaded {
        Some(record) => assert_eq!(record.owner_wallet, owner_c),
        None => panic!("transfer chain record missing"),
    }
}

#[test]
fn test_85_property_same_content_same_content_hash() {
    let first = NftMintTx::from_content_bytes(
        nft_id_from_label("test_85_first"),
        "Title".to_owned(),
        "Description".to_owned(),
        b"same content",
    );
    let second = NftMintTx::from_content_bytes(
        nft_id_from_label("test_85_second"),
        "Title".to_owned(),
        "Description".to_owned(),
        b"same content",
    );

    assert_eq!(first.content_hash, second.content_hash);
}

#[test]
fn test_86_property_same_nft_id_duplicate_mint_rejected_even_different_content() {
    let temp = TempTree::new("test_86");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let signer = wallet_from_label("test_86_signer");
    let nft_id = nft_id_from_label("test_86_same_id");

    let first = NftMintTx::from_content_bytes(
        nft_id,
        "First".to_owned(),
        "First description".to_owned(),
        b"first content",
    );
    let second = NftMintTx::from_content_bytes(
        nft_id,
        "Second".to_owned(),
        "Second description".to_owned(),
        b"second content",
    );

    assert_ok(
        apply_nft_mint(&manager, &first, &signer, 86, 1_700_000_086),
        "first mint same id",
    );

    let err = assert_err(
        apply_nft_mint(&manager, &second, &signer, 87, 1_700_000_087),
        "second mint same id",
    );

    assert_validation_error(err);
}

#[test]
fn test_87_property_receipt_hash_matches_mint_hash_for_same_content() {
    let content = sample_content("test_87");
    let tx = NftMintTx::from_content_bytes(
        nft_id_from_label("test_87"),
        "Title".to_owned(),
        "Description".to_owned(),
        &content,
    );
    let receipt_hash = RemzarHash::compute_bytes_hash_hex(&content);

    assert_eq!(hex::encode(tx.content_hash), receipt_hash);
}

#[test]
fn test_88_adversarial_receipt_rejects_long_description() {
    let mut receipt = make_receipt("test_88");
    receipt.description = "x".repeat(2_049);

    let err = assert_err(receipt.validate(), "validate long description");

    assert_validation_error(err);
}

#[test]
fn test_89_adversarial_receipt_rejects_long_kind() {
    let mut receipt = make_receipt("test_89");
    receipt.kind = "x".repeat(2_049);

    let err = assert_err(receipt.validate(), "validate long kind");

    assert_validation_error(err);
}

#[test]
fn test_90_adversarial_receipt_rejects_long_schema() {
    let mut receipt = make_receipt("test_90");
    receipt.schema = "x".repeat(2_049);

    let err = assert_err(receipt.validate(), "validate long schema");

    assert_validation_error(err);
}

#[test]
fn test_91_adversarial_receipt_rejects_long_edition() {
    let mut receipt = make_receipt("test_91");
    receipt.edition = Some("x".repeat(2_049));

    let err = assert_err(receipt.validate(), "validate long edition");

    assert_validation_error(err);
}

#[test]
fn test_92_adversarial_nft_record_corrupt_json_fails_load() {
    let temp = TempTree::new("test_92");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let nft_id = nft_id_from_label("test_92");
    let key = format!("nft::{}", hex::encode(nft_id));

    assert_ok(
        manager.store_metadata(&key, b"not json"),
        "store corrupt NFT json",
    );

    let err = assert_err(load_nft_record(&manager, &nft_id), "load corrupt NFT json");

    assert_serialization_error(err);
}

#[test]
fn test_93_load_apply_ten_mints() {
    let temp = TempTree::new("test_93");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for index in 0usize..10usize {
        let signer = wallet_from_label(&format!("test_93_signer_{index}"));
        let tx = make_mint_tx(&format!("test_93_{index}"));

        assert_ok(
            apply_nft_mint(&manager, &tx, &signer, 93, 1_700_000_093),
            "load apply mint",
        );
    }
}

#[test]
fn test_94_load_store_load_ten_records() {
    let temp = TempTree::new("test_94");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for index in 0usize..10usize {
        let owner = wallet_from_label(&format!("test_94_owner_{index}"));
        let record = make_record(&format!("test_94_{index}"), &owner);

        assert_ok(store_nft_record(&manager, &record), "load store record");
        let loaded = assert_ok(load_nft_record(&manager, &record.nft_id), "load record");

        match loaded {
            Some(value) => assert_eq!(value.owner_wallet, owner),
            None => panic!("load stored record missing"),
        }
    }
}

#[test]
fn test_95_load_receipt_validate_twenty_receipts() {
    for index in 0usize..20usize {
        let receipt = make_receipt(&format!("test_95_{index}"));
        assert_receipt_valid(&receipt);
    }
}

#[test]
fn test_96_load_txkind_serialize_twenty_mints() {
    for index in 0usize..20usize {
        let kind = TxKind::NftMint(make_mint_tx(&format!("test_96_{index}")));
        let bytes = assert_ok(kind.serialize(), "serialize load mint");
        let decoded = assert_ok(TxKind::deserialize(&bytes), "deserialize load mint");

        assert_eq!(decoded, kind);
    }
}

#[test]
fn test_97_load_txkind_hash_twenty_mints() {
    let mut hashes = Vec::new();

    for index in 0usize..20usize {
        let kind = TxKind::NftMint(make_mint_tx(&format!("test_97_{index}")));
        let hash = assert_ok(RemzarHash::compute_data_hash(&kind), "compute mint hash");
        assert_hash_hex_128(&hash);
        hashes.push(hash);
    }

    assert_eq!(hashes.len(), 20);
}

#[test]
fn test_98_load_send_txkind_twenty_mints() {
    let (tx, mut rx) = mpsc::channel::<NetCmd>(20);

    for index in 0usize..20usize {
        let kind = TxKind::NftMint(make_mint_tx(&format!("test_98_{index}")));
        assert_ok(
            tx.try_send(NetCmd::SendTxKind(kind)),
            "try_send load SendTxKind",
        );
    }

    let mut count = 0usize;
    for _ in 0usize..20usize {
        match rx.try_recv() {
            Ok(NetCmd::SendTxKind(TxKind::NftMint(_))) => {
                count = count.saturating_add(1);
            }
            Ok(other) => panic!("unexpected NetCmd in load receive: {other:?}"),
            Err(err) => panic!("failed to receive load SendTxKind: {err:?}"),
        }
    }

    assert_eq!(count, 20);
}

#[test]
fn test_99_load_apply_transfer_ten_times() {
    let temp = TempTree::new("test_99");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);

    for index in 0usize..10usize {
        let owner = wallet_from_label(&format!("test_99_owner_{index}"));
        let new_owner = wallet_from_label(&format!("test_99_new_owner_{index}"));
        let mint = make_mint_tx(&format!("test_99_{index}"));

        assert_ok(
            apply_nft_mint(&manager, &mint, &owner, 99, 1_700_000_099),
            "mint before load transfer",
        );

        let transfer = NftTransferTx {
            nft_id: mint.nft_id,
            new_owner_wallet: new_owner.clone(),
        };

        assert_ok(
            apply_nft_transfer(&manager, &transfer, &owner, 100, 1_700_000_100),
            "load transfer NFT",
        );

        let loaded = assert_ok(
            load_nft_record(&manager, &mint.nft_id),
            "load after transfer",
        );
        match loaded {
            Some(record) => assert_eq!(record.owner_wallet, new_owner),
            None => panic!("record missing after load transfer"),
        }
    }
}

#[test]
fn test_100_final_certificate_nft_receipt_network_and_db_flow() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let manager = make_manager(&opts);
    let logger = make_logger(&opts);
    let signer = wallet_from_label("test_100_signer");
    let new_owner = wallet_from_label("test_100_new_owner");
    let content = sample_content("test_100");

    let mint = NftMintTx::from_content_bytes(
        nft_id_from_label("test_100"),
        "Final Certificate".to_owned(),
        "Final certificate description".to_owned(),
        &content,
    );

    let content_hash_hex = hex::encode(mint.content_hash);
    assert_eq!(
        content_hash_hex,
        RemzarHash::compute_bytes_hash_hex(&content)
    );

    let receipt = CertificateReceipt {
        nft_id_hex: hex::encode(mint.nft_id),
        owner_wallet: signer.clone(),
        file_name: "final_certificate.bin".to_owned(),
        file_size_bytes: content.len(),
        content_hash_hex,
        title: mint.title.clone(),
        description: mint.description.clone(),
        created_at_utc: "2026-05-02T00:00:00Z".to_owned(),
        edition: Some("01/01".to_owned()),
        kind: "Certificate".to_owned(),
        schema: "certificate-v1".to_owned(),
    };

    assert_receipt_valid(&receipt);

    let received_mint = send_txkind_round_trip(TxKind::NftMint(mint.clone()));
    assert_eq!(received_mint, TxKind::NftMint(mint.clone()));

    assert_ok(
        apply_nft_mint(&manager, &mint, &signer, 100, 1_700_000_100),
        "final apply mint",
    );

    let transfer = NftTransferTx {
        nft_id: mint.nft_id,
        new_owner_wallet: new_owner.clone(),
    };

    let received_transfer = send_txkind_round_trip(TxKind::NftTransfer(transfer.clone()));
    assert_eq!(received_transfer, TxKind::NftTransfer(transfer.clone()));

    assert_ok(
        apply_nft_transfer(&manager, &transfer, &signer, 101, 1_700_000_101),
        "final apply transfer",
    );

    let loaded = assert_ok(load_nft_record(&manager, &mint.nft_id), "final load NFT");
    match loaded {
        Some(record) => {
            assert_eq!(record.owner_wallet, new_owner);
            assert_eq!(record.content_hash, mint.content_hash);
        }
        None => panic!("final NFT record missing"),
    }

    assert_ok(
        logger.log_error_event("nft", "FinalCertificateTest", &receipt.nft_id_hex),
        "final log certificate event",
    );
    assert_ok(logger.flush_logs_cf(), "final flush logs");
}
