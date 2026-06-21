// tests/proptests_privacy.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::privacy::privacy_001_private_receive_wallet::{
    PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_RECORD_EXT, PRIVATE_RECEIVE_VERSION, PrivateRW,
    PrivateReceiveCreateRequest, PrivateReceiveWalletReceipt, PrivateReceiveWalletRecord,
};
use remzar::privacy::privacy_002_private_receive_invoice::{
    MAX_PRIVATE_RECEIVE_CONTEXT_LEN, MAX_PRIVATE_RECEIVE_LABEL_LEN, PRIVATE_RECEIVE_INVOICE_KIND,
    PrivateRI, PrivateReceiveInvoiceBuildRequest, PrivateReceiveInvoiceSource,
};
use remzar::privacy::privacy_003_private_wallet_index::{
    PRIVATE_WALLET_INDEX_KIND, PrivateWI, PrivateWalletIndexAddRequest, PrivateWalletIndexEntry,
    PrivateWalletIndexFile,
};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const UNIX_2000_SECS: u64 = 946_684_800;
const PASSPHRASE_RE: &str = "[A-Za-z0-9_!@#%+=.,:-]{1,16}";
const LABEL_RE: &str = "[A-Za-z0-9_.-]{1,32}";
const CONTEXT_RE: &str = "[A-Za-z0-9_.-]{1,64}";

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDataDir {
    root: PathBuf,
}

impl TestDataDir {
    fn as_data_dir_string(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }
}

impl Drop for TestDataDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn test_data_dir(label: &str) -> TestDataDir {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after UNIX_EPOCH")
        .as_nanos();

    let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let root = std::env::temp_dir().join(format!(
        "remzar_privacy_prop_{label}_{}_{}_{}",
        std::process::id(),
        nanos,
        counter
    ));

    fs::create_dir_all(&root).expect("test temp dir should be created");

    TestDataDir { root }
}

fn node_opts_for(dir: &TestDataDir, wallet_address: &str) -> NodeOpts {
    NodeOpts {
        identity_file: dir.root.join("identity.key").to_string_lossy().into_owned(),
        data_dir: dir.as_data_dir_string(),
        wallet_address: wallet_address.to_string(),
        ..NodeOpts::default()
    }
}

fn wallet_from_tail(tail: &str) -> String {
    format!("r{tail}")
}

fn wallet_with_prefix(prefix: char, tail_127: &str) -> String {
    format!("r{prefix}{tail_127}")
}

fn invoice_for(wallet: &str) -> String {
    format!(
        "{}:v{}:{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, wallet
    )
}

fn valid_receipt(owner_wallet: &str, one_time_wallet: &str) -> PrivateReceiveWalletReceipt {
    PrivateReceiveWalletReceipt {
        version: PRIVATE_RECEIVE_VERSION,
        owner_wallet: owner_wallet.to_string(),
        one_time_wallet: one_time_wallet.to_string(),
        invoice: invoice_for(one_time_wallet),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_path: "/tmp/remzar/test.wallet".to_string(),
        metadata_file_path: "/tmp/remzar/private_receive/test.prw.json".to_string(),
    }
}

fn valid_record(owner_wallet: &str, one_time_wallet: &str) -> PrivateReceiveWalletRecord {
    PrivateReceiveWalletRecord {
        version: PRIVATE_RECEIVE_VERSION,
        kind: "remzar_private_receive_wallet".to_string(),
        owner_wallet: owner_wallet.to_string(),
        one_time_wallet: one_time_wallet.to_string(),
        invoice: invoice_for(one_time_wallet),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_name: PrivateRW::wallet_file_name(one_time_wallet),
    }
}

fn valid_entry(owner_wallet: &str, one_time_wallet: &str) -> PrivateWalletIndexEntry {
    PrivateWalletIndexEntry {
        version: PRIVATE_RECEIVE_VERSION,
        owner_wallet: owner_wallet.to_string(),
        one_time_wallet: one_time_wallet.to_string(),
        invoice: invoice_for(one_time_wallet),
        wallet_file_name: PrivateRW::wallet_file_name(one_time_wallet),
        created_unix_secs: UNIX_2000_SECS,
        indexed_unix_secs: UNIX_2000_SECS + 1,
        label: None,
        context: None,
    }
}

fn valid_index(entries: Vec<PrivateWalletIndexEntry>) -> PrivateWalletIndexFile {
    let mut entries_by_owner: BTreeMap<String, Vec<PrivateWalletIndexEntry>> = BTreeMap::new();

    for entry in entries {
        entries_by_owner
            .entry(entry.owner_wallet.clone())
            .or_default()
            .push(entry);
    }

    PrivateWalletIndexFile {
        kind: PRIVATE_WALLET_INDEX_KIND.to_string(),
        version: PRIVATE_RECEIVE_VERSION,
        created_unix_secs: UNIX_2000_SECS,
        updated_unix_secs: UNIX_2000_SECS + 1,
        entries_by_owner,
    }
}

fn directory_for(opts: &NodeOpts) -> DirectoryDB {
    DirectoryDB::from_node_opts(opts).expect("DirectoryDB should initialize")
}

fn create_wallets_dir(opts: &NodeOpts) -> DirectoryDB {
    let directory = directory_for(opts);
    directory
        .create_wallets_directory()
        .expect("wallets directory should be created");
    directory
}

fn create_one_time_wallet_placeholder(opts: &NodeOpts, one_time_wallet: &str) -> PathBuf {
    let directory = create_wallets_dir(opts);
    let path = PrivateRW::wallet_file_path(&directory.wallets_path, one_time_wallet);

    fs::write(&path, b"one-time-wallet-placeholder")
        .expect("one-time wallet placeholder should be written");

    path
}

fn write_private_receive_record(opts: &NodeOpts, record: &PrivateReceiveWalletRecord) -> PathBuf {
    let directory = create_wallets_dir(opts);
    let metadata_file =
        PrivateRW::metadata_file_path(&directory.wallets_path, &record.one_time_wallet);

    let parent = metadata_file
        .parent()
        .expect("metadata file should have parent");

    fs::create_dir_all(parent).expect("metadata dir should be created");

    let bytes = serde_json::to_vec_pretty(record).expect("record should serialize");
    fs::write(&metadata_file, bytes).expect("record should be written");

    metadata_file
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_private_rw_invoice_roundtrip_accepts_canonical_wallet(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let expected_invoice = invoice_for(&wallet);

        let invoice = PrivateRW::make_invoice(&wallet)
            .expect("PrivateRW should encode canonical wallet invoice");

        prop_assert_eq!(invoice.as_str(), expected_invoice.as_str());

        let parsed = PrivateRW::parse_invoice_or_address(&invoice)
            .expect("PrivateRW should parse its own invoice");

        prop_assert_eq!(parsed.as_str(), wallet.as_str());

        let parsed_raw = PrivateRW::parse_invoice_or_address(&wallet)
            .expect("PrivateRW should parse raw wallet convenience input");

        prop_assert_eq!(parsed_raw.as_str(), wallet.as_str());

        prop_assert!(
            PrivateRW::is_private_receive_invoice(&invoice),
            "PrivateRW should recognize canonical invoice prefix"
        );
    }

    // 02/25
    #[test]
    fn test_002_private_rw_and_ri_canonicalize_uppercase_wallet_inputs(
        upper_tail in "[0-9A-F]{128}",
    ) {
        let raw_wallet = format!(" \tR{upper_tail}\n");
        let expected_wallet = format!("r{}", upper_tail.to_ascii_lowercase());
        let expected_invoice = invoice_for(&expected_wallet);

        let rw_invoice = PrivateRW::make_invoice(&raw_wallet)
            .expect("PrivateRW should canonicalize uppercase wallet");

        prop_assert_eq!(rw_invoice.as_str(), expected_invoice.as_str());

        let rw_parsed = PrivateRW::parse_invoice_or_address(&rw_invoice)
            .expect("PrivateRW should parse canonicalized invoice");

        prop_assert_eq!(rw_parsed.as_str(), expected_wallet.as_str());

        let ri_encoded = PrivateRI::encode(&raw_wallet)
            .expect("PrivateRI should canonicalize uppercase wallet");

        prop_assert_eq!(ri_encoded.as_str(), expected_invoice.as_str());

        let ri_parsed = PrivateRI::parse_invoice_or_address(&ri_encoded)
            .expect("PrivateRI should parse canonicalized invoice");

        prop_assert_eq!(ri_parsed.one_time_wallet.as_str(), expected_wallet.as_str());
        prop_assert_eq!(ri_parsed.canonical_invoice.as_str(), expected_invoice.as_str());
    }

    // 03/25
    #[test]
    fn test_003_wallet_like_invalid_lengths_are_rejected_by_all_invoice_entry_points(
        short_tail in "[0-9a-f]{0,127}",
        long_tail in "[0-9a-f]{129,160}",
    ) {
        let short_wallet = wallet_from_tail(&short_tail);
        let long_wallet = wallet_from_tail(&long_tail);

        prop_assert!(
            PrivateRW::make_invoice(&short_wallet).is_err(),
            "PrivateRW must reject too-short wallet-like input"
        );

        prop_assert!(
            PrivateRW::make_invoice(&long_wallet).is_err(),
            "PrivateRW must reject too-long wallet-like input"
        );

        prop_assert!(
            PrivateRI::encode(&short_wallet).is_err(),
            "PrivateRI::encode must reject too-short wallet-like input"
        );

        prop_assert!(
            PrivateRI::encode(&long_wallet).is_err(),
            "PrivateRI::encode must reject too-long wallet-like input"
        );

        prop_assert!(
            PrivateRI::parse_invoice_or_address(&short_wallet).is_err(),
            "PrivateRI parser must reject too-short raw wallet input"
        );

        prop_assert!(
            PrivateRI::parse_invoice_or_address(&long_wallet).is_err(),
            "PrivateRI parser must reject too-long raw wallet input"
        );
    }

    // 04/25
    #[test]
    fn test_004_invoice_prefix_starts_with_r_but_parsers_treat_it_as_invoice(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let invoice = invoice_for(&wallet);

        prop_assert!(
            invoice.starts_with('r'),
            "regression guard: invoice prefix starts with r"
        );

        let rw_parsed = PrivateRW::parse_invoice_or_address(&invoice)
            .expect("PrivateRW must parse invoice before raw r-wallet path");

        prop_assert_eq!(rw_parsed.as_str(), wallet.as_str());

        let ri_parsed = PrivateRI::parse_invoice_or_address(&invoice)
            .expect("PrivateRI must parse invoice before raw r-wallet path");

        prop_assert_eq!(ri_parsed.source, PrivateReceiveInvoiceSource::Invoice);
        prop_assert_eq!(ri_parsed.one_time_wallet.as_str(), wallet.as_str());
        prop_assert_eq!(ri_parsed.canonical_invoice.as_str(), invoice.as_str());
    }

    // 05/25
    #[test]
    fn test_005_private_ri_build_trims_label_context_and_keeps_canonical_invoice(
        tail in "[0-9a-f]{128}",
        label in LABEL_RE,
        context in CONTEXT_RE,
    ) {
        let wallet = wallet_from_tail(&tail);
        let expected_invoice = invoice_for(&wallet);

        let built = PrivateRI::new()
            .build(PrivateReceiveInvoiceBuildRequest {
                one_time_wallet: &wallet,
                label: Some(&format!("   {label}   ")),
                context: Some(&format!("   {context}   ")),
            })
            .expect("PrivateRI build should accept generated label/context");

        prop_assert_eq!(built.kind.as_str(), PRIVATE_RECEIVE_INVOICE_KIND);
        prop_assert_eq!(built.version, PRIVATE_RECEIVE_VERSION);
        prop_assert_eq!(built.one_time_wallet.as_str(), wallet.as_str());
        prop_assert_eq!(built.invoice.as_str(), expected_invoice.as_str());
        prop_assert_eq!(built.label.as_deref(), Some(label.as_str()));
        prop_assert_eq!(built.context.as_deref(), Some(context.as_str()));
    }

    // 06/25
    #[test]
    fn test_006_private_ri_rejects_oversized_or_control_label_context(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);

        let long_label = "x".repeat(MAX_PRIVATE_RECEIVE_LABEL_LEN + 1);
        let long_context = "x".repeat(MAX_PRIVATE_RECEIVE_CONTEXT_LEN + 1);

        prop_assert!(
            PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
                one_time_wallet: &wallet,
                label: Some(&long_label),
                context: None,
            }).is_err(),
            "PrivateRI must reject oversized labels"
        );

        prop_assert!(
            PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
                one_time_wallet: &wallet,
                label: Some("bad\nlabel"),
                context: None,
            }).is_err(),
            "PrivateRI must reject label control characters"
        );

        prop_assert!(
            PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
                one_time_wallet: &wallet,
                label: None,
                context: Some(&long_context),
            }).is_err(),
            "PrivateRI must reject oversized context"
        );

        prop_assert!(
            PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
                one_time_wallet: &wallet,
                label: None,
                context: Some("bad\ncontext"),
            }).is_err(),
            "PrivateRI must reject context control characters"
        );
    }

    // 07/25
    #[test]
    fn test_007_private_ri_source_classification_matches_invoice_vs_raw_wallet(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let invoice = invoice_for(&wallet);

        let from_invoice = PrivateRI::parse_invoice_or_address(&invoice)
            .expect("full invoice should parse");

        prop_assert_eq!(from_invoice.source, PrivateReceiveInvoiceSource::Invoice);
        prop_assert_eq!(from_invoice.one_time_wallet.as_str(), wallet.as_str());
        prop_assert_eq!(from_invoice.canonical_invoice.as_str(), invoice.as_str());

        let from_raw = PrivateRI::parse_invoice_or_address(&wallet)
            .expect("raw one-time wallet should parse");

        prop_assert_eq!(from_raw.source, PrivateReceiveInvoiceSource::RawOneTimeWallet);
        prop_assert_eq!(from_raw.one_time_wallet.as_str(), wallet.as_str());
        prop_assert_eq!(from_raw.canonical_invoice.as_str(), invoice.as_str());
    }

    // 08/25
    #[test]
    fn test_008_parse_invoice_only_rejects_raw_wallet_but_sender_parser_accepts_it(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let expected_invoice = invoice_for(&wallet);

        prop_assert!(
            PrivateRI::parse_invoice_only(&wallet).is_err(),
            "strict invoice parser must reject raw wallets"
        );

        let parsed = PrivateRI::parse_invoice_or_address(&wallet)
            .expect("sender parser should accept raw wallet convenience input");

        prop_assert_eq!(parsed.source, PrivateReceiveInvoiceSource::RawOneTimeWallet);
        prop_assert_eq!(parsed.one_time_wallet.as_str(), wallet.as_str());
        prop_assert_eq!(parsed.canonical_invoice.as_str(), expected_invoice.as_str());
    }

    // 09/25
    #[test]
    fn test_009_private_ri_json_roundtrip_preserves_valid_invoice_object(
        tail in "[0-9a-f]{128}",
        label in LABEL_RE,
        context in CONTEXT_RE,
    ) {
        let wallet = wallet_from_tail(&tail);
        let expected_invoice = invoice_for(&wallet);

        let invoice = PrivateRI::new()
            .build(PrivateReceiveInvoiceBuildRequest {
                one_time_wallet: &wallet,
                label: Some(&label),
                context: Some(&context),
            })
            .expect("invoice should build");

        let json = PrivateRI::to_pretty_json(&invoice)
            .expect("invoice should serialize");

        let decoded = PrivateRI::from_json(&json)
            .expect("invoice should deserialize");

        prop_assert_eq!(&decoded, &invoice);
        prop_assert!(decoded.validate().is_ok());
        prop_assert_eq!(decoded.as_str(), expected_invoice.as_str());
        prop_assert_eq!(decoded.recipient_wallet(), wallet.as_str());
    }

    // 10/25
    #[test]
    fn test_010_private_ri_preview_and_qr_payload_are_canonical(
        tail in "[0-9a-f]{128}",
        label in LABEL_RE,
        context in CONTEXT_RE,
    ) {
        let wallet = wallet_from_tail(&tail);
        let expected_invoice = invoice_for(&wallet);

        let invoice = PrivateRI::new()
            .build(PrivateReceiveInvoiceBuildRequest {
                one_time_wallet: &wallet,
                label: Some(&label),
                context: Some(&context),
            })
            .expect("invoice should build");

        let short = PrivateRI::short_wallet(&wallet)
            .expect("short wallet should format");

        let expected_short = format!("{}...{}", &wallet[..9], &wallet[wallet.len() - 8..]);
        prop_assert_eq!(short.as_str(), expected_short.as_str());

        let preview = PrivateRI::display_preview(invoice.as_str())
            .expect("display preview should build");

        let expected_preview = format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX,
            PRIVATE_RECEIVE_VERSION,
            short
        );

        prop_assert_eq!(preview.as_str(), expected_preview.as_str());

        let qr = PrivateRI::qr_payload(&invoice)
            .expect("QR payload should validate");

        prop_assert_eq!(qr.as_str(), expected_invoice.as_str());
    }

    // 11/25
    #[test]
    fn test_011_private_rw_receipt_validation_accepts_match_and_rejects_invoice_mismatch(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let receipt = valid_receipt(&owner, &one_time);

        prop_assert!(
            PrivateRW::validate_receipt(&receipt).is_ok(),
            "matching receipt must validate"
        );

        let mut mismatched = receipt.clone();
        mismatched.invoice = invoice_for(&wallet_with_prefix('2', &one_tail));

        prop_assert!(
            PrivateRW::validate_receipt(&mismatched).is_err(),
            "receipt must reject invoice that points to another one-time wallet"
        );
    }

    // 12/25
    #[test]
    fn test_012_private_rw_record_validation_accepts_match_and_rejects_bad_wallet_file_name(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let record = valid_record(&owner, &one_time);

        prop_assert!(
            PrivateRW::validate_record(&record).is_ok(),
            "matching record must validate"
        );

        let mut bad_file = record.clone();
        bad_file.wallet_file_name = "wrong.wallet".to_string();

        prop_assert!(
            PrivateRW::validate_record(&bad_file).is_err(),
            "record must reject wallet_file_name mismatch"
        );
    }

    // 13/25
    #[test]
    fn test_013_private_ri_from_receipt_and_record_match_source_invoice(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let receipt = valid_receipt(&owner, &one_time);
        let record = valid_record(&owner, &one_time);

        let from_receipt = PrivateRI::new()
            .from_wallet_receipt(&receipt)
            .expect("invoice should build from valid receipt");

        prop_assert_eq!(from_receipt.one_time_wallet.as_str(), one_time.as_str());
        prop_assert_eq!(from_receipt.invoice.as_str(), receipt.invoice.as_str());
        prop_assert_eq!(
            from_receipt.context.as_deref(),
            Some("created_from_private_receive_wallet_receipt")
        );

        let from_record = PrivateRI::new()
            .from_wallet_record(&record)
            .expect("invoice should build from valid record");

        prop_assert_eq!(from_record.one_time_wallet.as_str(), one_time.as_str());
        prop_assert_eq!(from_record.invoice.as_str(), record.invoice.as_str());
        prop_assert_eq!(
            from_record.context.as_deref(),
            Some("created_from_private_receive_wallet_record")
        );
    }

    // 14/25
    #[test]
    fn test_014_private_wallet_index_entry_validation_accepts_valid_entry(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let entry = valid_entry(&owner, &one_time);

        prop_assert!(
            PrivateWI::validate_entry(&entry).is_ok(),
            "valid index entry must validate"
        );

        prop_assert!(
            entry.validate().is_ok(),
            "entry instance validate must delegate to PrivateWI"
        );

        let short = entry
            .short_one_time_wallet()
            .expect("short wallet should format");

        let expected_short = format!("{}...{}", &one_time[..9], &one_time[one_time.len() - 8..]);
        prop_assert_eq!(short.as_str(), expected_short.as_str());
    }

    // 15/25
    #[test]
    fn test_015_private_wallet_index_entry_rejects_mismatch_zero_time_and_bad_filename(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);
        let other = wallet_with_prefix('2', &one_tail);

        let mut invoice_mismatch = valid_entry(&owner, &one_time);
        invoice_mismatch.invoice = invoice_for(&other);

        prop_assert!(
            PrivateWI::validate_entry(&invoice_mismatch).is_err(),
            "index entry must reject invoice mismatch"
        );

        let mut zero_created = valid_entry(&owner, &one_time);
        zero_created.created_unix_secs = 0;

        prop_assert!(
            PrivateWI::validate_entry(&zero_created).is_err(),
            "index entry must reject zero created_unix_secs"
        );

        let mut bad_file = valid_entry(&owner, &one_time);
        bad_file.wallet_file_name = "wrong.wallet".to_string();

        prop_assert!(
            PrivateWI::validate_entry(&bad_file).is_err(),
            "index entry must reject wallet_file_name mismatch"
        );
    }

    // 16/25
    #[test]
    fn test_016_private_wallet_index_file_accepts_unique_entries_and_rejects_duplicate_one_time(
        shared_tail in "[0-9a-f]{127}",
    ) {
        let owner_a = wallet_with_prefix('0', &shared_tail);
        let owner_b = wallet_with_prefix('1', &shared_tail);
        let one_a = wallet_with_prefix('2', &shared_tail);
        let one_b = wallet_with_prefix('3', &shared_tail);

        let valid = valid_index(vec![
            valid_entry(&owner_a, &one_a),
            valid_entry(&owner_b, &one_b),
        ]);

        prop_assert!(
            PrivateWI::validate_index_file(&valid).is_ok(),
            "unique one-time wallets under unique owners must validate"
        );

        prop_assert_eq!(valid.total_entries(), 2);
        prop_assert_eq!(valid.owner_count(), 2);

        let duplicate = valid_index(vec![
            valid_entry(&owner_a, &one_a),
            valid_entry(&owner_b, &one_a),
        ]);

        prop_assert!(
            PrivateWI::validate_index_file(&duplicate).is_err(),
            "index must reject duplicate one-time wallets across owners"
        );
    }

    // 17/25
    #[test]
    fn test_017_private_wallet_index_add_persists_and_queries_entry(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
        label in LABEL_RE,
        context in CONTEXT_RE,
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let dir = test_data_dir("017_add_query");
        let opts = node_opts_for(&dir, &owner);
        let wi = PrivateWI::new();

        let entry = wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &owner,
                one_time_wallet: &one_time,
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some(&label),
                context: Some(&context),
                require_one_time_wallet_file: false,
            },
        ).expect("index entry should add");

        prop_assert_eq!(entry.owner_wallet.as_str(), owner.as_str());
        prop_assert_eq!(entry.one_time_wallet.as_str(), one_time.as_str());
        let expected_entry_invoice = invoice_for(&one_time);
        prop_assert_eq!(entry.invoice.as_str(), expected_entry_invoice.as_str());
        prop_assert_eq!(entry.label.as_deref(), Some(label.as_str()));
        prop_assert_eq!(entry.context.as_deref(), Some(context.as_str()));

        prop_assert_eq!(wi.count_for_owner(&opts, &owner).unwrap(), 1);
        prop_assert!(wi.contains_one_time_wallet(&opts, &one_time).unwrap());
        let owner_lookup = wi.lookup_owner(&opts, &one_time).unwrap();
        prop_assert_eq!(owner_lookup.as_deref(), Some(owner.as_str()));

        let lookup = wi.lookup_entry(&opts, &one_time)
            .expect("lookup should not fail")
            .expect("lookup should exist");

        prop_assert_eq!(lookup.owner_wallet.as_str(), owner.as_str());
        prop_assert_eq!(lookup.entry.one_time_wallet.as_str(), one_time.as_str());
    }

    // 18/25
    #[test]
    fn test_018_private_wallet_index_replaces_same_owner_same_one_time_wallet(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
        first_label in LABEL_RE,
        second_label in LABEL_RE,
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let dir = test_data_dir("018_replace");
        let opts = node_opts_for(&dir, &owner);
        let wi = PrivateWI::new();

        wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &owner,
                one_time_wallet: &one_time,
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: Some(&first_label),
                context: None,
                require_one_time_wallet_file: false,
            },
        ).expect("first entry should add");

        wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &owner,
                one_time_wallet: &one_time,
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS + 10),
                label: Some(&second_label),
                context: None,
                require_one_time_wallet_file: false,
            },
        ).expect("same owner/same one-time entry should replace");

        let entries = wi.list_for_owner(&opts, &owner)
            .expect("owner entries should list");

        prop_assert_eq!(entries.len(), 1);
        prop_assert_eq!(entries[0].one_time_wallet.as_str(), one_time.as_str());
        prop_assert_eq!(entries[0].created_unix_secs, UNIX_2000_SECS + 10);
        prop_assert_eq!(entries[0].label.as_deref(), Some(second_label.as_str()));
    }

    // 19/25
    #[test]
    fn test_019_private_wallet_index_rejects_same_one_time_under_different_owner(
        shared_tail in "[0-9a-f]{127}",
    ) {
        let owner_a = wallet_with_prefix('0', &shared_tail);
        let owner_b = wallet_with_prefix('1', &shared_tail);
        let one_time = wallet_with_prefix('2', &shared_tail);

        let dir = test_data_dir("019_conflict");
        let opts = node_opts_for(&dir, &owner_a);
        let wi = PrivateWI::new();

        wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &owner_a,
                one_time_wallet: &one_time,
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ).expect("first owner should add");

        prop_assert!(
            wi.add_entry(
                &opts,
                PrivateWalletIndexAddRequest {
                    owner_wallet: &owner_b,
                    one_time_wallet: &one_time,
                    invoice: None,
                    wallet_file_name: None,
                    created_unix_secs: Some(UNIX_2000_SECS + 1),
                    label: None,
                    context: None,
                    require_one_time_wallet_file: false,
                },
            ).is_err(),
            "same one-time wallet must not be indexable under a different owner"
        );
    }

    // 20/25
    #[test]
    fn test_020_private_wallet_index_canonicalizes_uppercase_inputs_and_raw_invoice(
        upper_owner_tail in "[0-9A-F]{127}",
        upper_one_tail in "[0-9A-F]{127}",
    ) {
        let raw_owner = format!("R0{upper_owner_tail}");
        let raw_one = format!("R1{upper_one_tail}");

        let owner = format!("r0{}", upper_owner_tail.to_ascii_lowercase());
        let one_time = format!("r1{}", upper_one_tail.to_ascii_lowercase());
        let expected_invoice = invoice_for(&one_time);

        let dir = test_data_dir("020_canonicalize");
        let opts = node_opts_for(&dir, &owner);
        let wi = PrivateWI::new();

        let entry = wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &raw_owner,
                one_time_wallet: &raw_one,
                invoice: Some(&raw_one),
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: false,
            },
        ).expect("uppercase index inputs should canonicalize");

        prop_assert_eq!(entry.owner_wallet.as_str(), owner.as_str());
        prop_assert_eq!(entry.one_time_wallet.as_str(), one_time.as_str());
        prop_assert_eq!(entry.invoice.as_str(), expected_invoice.as_str());
        let expected_wallet_file_name = PrivateRW::wallet_file_name(&one_time);

        prop_assert_eq!(
            entry.wallet_file_name.as_str(),
            expected_wallet_file_name.as_str()
        );
    }

    // 21/25
    #[test]
    fn test_021_private_wallet_index_wallet_file_requirement_matches_real_file_presence(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let dir = test_data_dir("021_require_file");
        let opts = node_opts_for(&dir, &owner);
        let wi = PrivateWI::new();

        prop_assert!(
            wi.add_entry(
                &opts,
                PrivateWalletIndexAddRequest {
                    owner_wallet: &owner,
                    one_time_wallet: &one_time,
                    invoice: None,
                    wallet_file_name: None,
                    created_unix_secs: Some(UNIX_2000_SECS),
                    label: None,
                    context: None,
                    require_one_time_wallet_file: true,
                },
            ).is_err(),
            "requiring a missing one-time wallet file must fail"
        );

        let wallet_file = create_one_time_wallet_placeholder(&opts, &one_time);
        prop_assert!(wallet_file.exists());

        let entry = wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &owner,
                one_time_wallet: &one_time,
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: true,
            },
        ).expect("requiring an existing one-time wallet file should succeed");

        prop_assert_eq!(entry.one_time_wallet.as_str(), one_time.as_str());
    }

    // 22/25
    #[test]
    fn test_022_private_wallet_index_remove_persists_absence_without_deleting_wallet_file(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let dir = test_data_dir("022_remove");
        let opts = node_opts_for(&dir, &owner);
        let wi = PrivateWI::new();

        let wallet_file = create_one_time_wallet_placeholder(&opts, &one_time);

        wi.add_entry(
            &opts,
            PrivateWalletIndexAddRequest {
                owner_wallet: &owner,
                one_time_wallet: &one_time,
                invoice: None,
                wallet_file_name: None,
                created_unix_secs: Some(UNIX_2000_SECS),
                label: None,
                context: None,
                require_one_time_wallet_file: true,
            },
        ).expect("entry should add");

        let removed = wi.remove_one_time_wallet(&opts, &one_time)
            .expect("remove should not fail")
            .expect("entry should be removed");

        prop_assert_eq!(removed.one_time_wallet.as_str(), one_time.as_str());
        prop_assert!(!wi.contains_one_time_wallet(&opts, &one_time).unwrap());
        prop_assert!(wallet_file.exists(), "remove must not delete encrypted wallet file");
    }

    // 23/25
    #[test]
    fn test_023_private_wallet_index_save_load_canonicalizes_uppercase_json_fields(
        upper_owner_tail in "[0-9A-F]{127}",
        upper_one_tail in "[0-9A-F]{127}",
    ) {
        let raw_owner = format!("R0{upper_owner_tail}");
        let raw_one = format!("R1{upper_one_tail}");

        let owner = format!("r0{}", upper_owner_tail.to_ascii_lowercase());
        let one_time = format!("r1{}", upper_one_tail.to_ascii_lowercase());
        let expected_invoice = invoice_for(&one_time);
        let expected_wallet_file_name = PrivateRW::wallet_file_name(&one_time);

        let dir = test_data_dir("023_save_load_canonicalize");
        let opts = node_opts_for(&dir, &owner);

        let mut entry = valid_entry(&raw_owner, &raw_one);
        entry.invoice = invoice_for(&raw_one);
        entry.wallet_file_name = PrivateRW::wallet_file_name(&raw_one);

        let mut map = BTreeMap::new();
        map.insert(raw_owner, vec![entry]);

        let index = PrivateWalletIndexFile {
            kind: PRIVATE_WALLET_INDEX_KIND.to_string(),
            version: PRIVATE_RECEIVE_VERSION,
            created_unix_secs: UNIX_2000_SECS,
            updated_unix_secs: UNIX_2000_SECS + 1,
            entries_by_owner: map,
        };

        PrivateWI::new()
            .save_index(&opts, &index)
            .expect("save_index should canonicalize before writing");

        let loaded = PrivateWI::new()
            .load_index(&opts)
            .expect("load_index should read canonicalized index");

        prop_assert!(loaded.entries_by_owner.contains_key(&owner));
        prop_assert_eq!(loaded.total_entries(), 1);

        let loaded_entry = loaded
            .entries_by_owner
            .get(&owner)
            .expect("canonical owner key should exist")
            .first()
            .expect("entry should exist");

        prop_assert_eq!(loaded_entry.owner_wallet.as_str(), owner.as_str());
        prop_assert_eq!(loaded_entry.one_time_wallet.as_str(), one_time.as_str());
        prop_assert_eq!(loaded_entry.invoice.as_str(), expected_invoice.as_str());
        prop_assert_eq!(loaded_entry.wallet_file_name.as_str(), expected_wallet_file_name.as_str());
    }

    // 24/25
    #[test]
    fn test_024_private_wallet_index_rebuild_imports_prw_records_and_ignores_other_files(
        owner_tail in "[0-9a-f]{127}",
        one_tail in "[0-9a-f]{127}",
    ) {
        let owner = wallet_with_prefix('0', &owner_tail);
        let one_time = wallet_with_prefix('1', &one_tail);

        let dir = test_data_dir("024_rebuild");
        let opts = node_opts_for(&dir, &owner);
        let wi = PrivateWI::new();

        let record = valid_record(&owner, &one_time);
        let record_path = write_private_receive_record(&opts, &record);

        prop_assert!(record_path.exists());
        prop_assert!(
            record_path
                .to_string_lossy()
                .ends_with(PRIVATE_RECEIVE_RECORD_EXT)
        );

        let directory = directory_for(&opts);
        let metadata_dir = PrivateRW::metadata_dir_path(&directory.wallets_path);
        fs::write(metadata_dir.join("ignored.txt"), b"not a private receive record")
            .expect("ignored file should be written");

        let rebuilt = wi
            .rebuild_from_private_receive_records(&opts, false)
            .expect("rebuild should import valid .prw.json records");

        prop_assert_eq!(rebuilt.kind.as_str(), PRIVATE_WALLET_INDEX_KIND);
        prop_assert_eq!(rebuilt.total_entries(), 1);
        prop_assert_eq!(rebuilt.owner_count(), 1);

        let entries = wi.list_for_owner(&opts, &owner)
            .expect("rebuilt owner entries should list");

        prop_assert_eq!(entries.len(), 1);
        prop_assert_eq!(entries[0].owner_wallet.as_str(), owner.as_str());
        prop_assert_eq!(entries[0].one_time_wallet.as_str(), one_time.as_str());
        prop_assert_eq!(
            entries[0].context.as_deref(),
            Some("rebuilt_from_private_receive_record")
        );
    }

    // 25/25
    #[test]
    fn test_025_end_to_end_real_private_receive_wallet_invoice_and_index_flow(
        owner_tail in "[0-9a-f]{128}",
        passphrase in PASSPHRASE_RE,
        label in LABEL_RE,
    ) {
        let owner = wallet_from_tail(&owner_tail);

        let dir = test_data_dir("025_real_e2e");
        let opts = node_opts_for(&dir, &owner);

        let receipt = PrivateRW::new()
            .create_receive_wallet(
                &opts,
                PrivateReceiveCreateRequest {
                    owner_wallet: &owner,
                    passphrase: &passphrase,
                    require_owner_wallet_file: false,
                },
            )
            .expect("real private receive wallet creation should succeed");

        prop_assert_eq!(receipt.owner_wallet.as_str(), owner.as_str());
        prop_assert_ne!(receipt.one_time_wallet.as_str(), receipt.owner_wallet.as_str());
        prop_assert!(receipt.created_unix_secs >= UNIX_2000_SECS);
        prop_assert!(std::path::Path::new(&receipt.wallet_file_path).exists());
        prop_assert!(std::path::Path::new(&receipt.metadata_file_path).exists());

        let record = PrivateRW::load_record_by_one_time_wallet(&opts, &receipt.one_time_wallet)
            .expect("record written by PrivateRW should load");

        prop_assert_eq!(record.owner_wallet.as_str(), receipt.owner_wallet.as_str());
        prop_assert_eq!(record.one_time_wallet.as_str(), receipt.one_time_wallet.as_str());
        prop_assert_eq!(record.invoice.as_str(), receipt.invoice.as_str());

        let invoice_obj = PrivateRI::new()
            .from_wallet_receipt(&receipt)
            .expect("PrivateRI should build from real PrivateRW receipt");

        prop_assert_eq!(invoice_obj.one_time_wallet.as_str(), receipt.one_time_wallet.as_str());
        prop_assert_eq!(invoice_obj.invoice.as_str(), receipt.invoice.as_str());

        let wi = PrivateWI::new();

        let entry = wi.add_from_receipt(
            &opts,
            &receipt,
            Some(&label),
            Some("created_by_privacy_proptest_e2e"),
            true,
        ).expect("PrivateWI should index real PrivateRW receipt when wallet file exists");

        prop_assert_eq!(entry.owner_wallet.as_str(), owner.as_str());
        prop_assert_eq!(entry.one_time_wallet.as_str(), receipt.one_time_wallet.as_str());
        prop_assert_eq!(entry.invoice.as_str(), receipt.invoice.as_str());
        prop_assert_eq!(entry.label.as_deref(), Some(label.as_str()));

        prop_assert!(wi.contains_one_time_wallet(&opts, &receipt.one_time_wallet).unwrap());
        let receipt_owner_lookup = wi
            .lookup_owner(&opts, &receipt.one_time_wallet)
            .unwrap();

        prop_assert_eq!(
            receipt_owner_lookup.as_deref(),
            Some(owner.as_str())
        );

        let parsed = PrivateRI::parse_invoice_or_address(&receipt.invoice)
            .expect("real receipt invoice should parse");

        prop_assert_eq!(parsed.source, PrivateReceiveInvoiceSource::Invoice);
        prop_assert_eq!(parsed.one_time_wallet.as_str(), receipt.one_time_wallet.as_str());
        prop_assert_eq!(parsed.canonical_invoice.as_str(), receipt.invoice.as_str());
    }
}
