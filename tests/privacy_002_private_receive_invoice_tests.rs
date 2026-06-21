use remzar::privacy::privacy_001_private_receive_wallet::{
    PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, PrivateRW,
    PrivateReceiveWalletReceipt, PrivateReceiveWalletRecord,
};
use remzar::privacy::privacy_002_private_receive_invoice::{
    MAX_PRIVATE_RECEIVE_CONTEXT_LEN, MAX_PRIVATE_RECEIVE_LABEL_LEN, PRIVATE_RECEIVE_INVOICE_KIND,
    PrivateRI, PrivateReceiveInvoice, PrivateReceiveInvoiceBuildOwnedRequest,
    PrivateReceiveInvoiceBuildRequest, PrivateReceiveInvoiceSource,
};

const UNIX_2000_SECS: u64 = 946_684_800;

fn wallet_with_body_char(ch: char) -> String {
    assert!(matches!(ch, '0'..='9' | 'a'..='f'));
    format!("r{}", ch.to_string().repeat(128))
}

fn wallet_a() -> String {
    wallet_with_body_char('a')
}

fn wallet_b() -> String {
    wallet_with_body_char('b')
}

fn wallet_c() -> String {
    wallet_with_body_char('c')
}

fn uppercase_wallet_a() -> String {
    format!("R{}", "A".repeat(128))
}

fn mixed_case_wallet() -> String {
    // 16 hex chars * 8 = 128 hex chars, plus "r" prefix = 129 total chars.
    format!("r{}", "AaBbCcDdEeFf0123".repeat(8))
}

fn invoice_for(wallet: &str) -> String {
    format!(
        "{}:v{}:{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, wallet
    )
}

fn assert_err_contains<T, E: std::fmt::Debug>(result: Result<T, E>, expected: &str) {
    match result {
        Ok(_) => panic!("expected error containing '{expected}', got Ok"),
        Err(error) => {
            let text = format!("{error:?}");
            assert!(
                text.contains(expected),
                "expected error containing '{expected}', got: {text}"
            );
        }
    }
}

fn valid_invoice_object() -> PrivateReceiveInvoice {
    let one_time_wallet = wallet_b();

    PrivateReceiveInvoice {
        kind: PRIVATE_RECEIVE_INVOICE_KIND.to_string(),
        version: PRIVATE_RECEIVE_VERSION,
        one_time_wallet: one_time_wallet.clone(),
        invoice: invoice_for(&one_time_wallet),
        label: Some("test label".to_string()),
        context: Some("test context".to_string()),
    }
}

fn valid_receipt() -> PrivateReceiveWalletReceipt {
    let owner = wallet_a();
    let one_time = wallet_b();

    PrivateReceiveWalletReceipt {
        version: PRIVATE_RECEIVE_VERSION,
        owner_wallet: owner,
        one_time_wallet: one_time.clone(),
        invoice: invoice_for(&one_time),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_path: "/tmp/remzar/test.wallet".to_string(),
        metadata_file_path: "/tmp/remzar/private_receive/test.prw.json".to_string(),
    }
}

fn valid_record() -> PrivateReceiveWalletRecord {
    let owner = wallet_a();
    let one_time = wallet_b();

    PrivateReceiveWalletRecord {
        version: PRIVATE_RECEIVE_VERSION,
        kind: "remzar_private_receive_wallet".to_string(),
        owner_wallet: owner,
        one_time_wallet: one_time.clone(),
        invoice: invoice_for(&one_time),
        created_unix_secs: UNIX_2000_SECS,
        wallet_file_name: PrivateRW::wallet_file_name(&one_time),
    }
}

#[test]
fn test_001_constants_are_expected_invoice_layer_values() {
    assert_eq!(
        PRIVATE_RECEIVE_INVOICE_KIND,
        "remzar_private_receive_invoice"
    );
    assert_eq!(MAX_PRIVATE_RECEIVE_LABEL_LEN, 96);
    assert_eq!(MAX_PRIVATE_RECEIVE_CONTEXT_LEN, 256);
    assert_eq!(PRIVATE_RECEIVE_INVOICE_PREFIX, "remzar-private-receive");
    assert_eq!(PRIVATE_RECEIVE_VERSION, 1);
}

#[test]
fn test_002_private_ri_is_stateless_default_constructible_and_zero_sized() {
    let via_new = PrivateRI::new();
    let via_default = PrivateRI::default();

    assert_eq!(format!("{via_new:?}"), format!("{via_default:?}"));
    assert_eq!(std::mem::size_of::<PrivateRI>(), 0);
}

#[test]
fn test_003_wallet_test_vectors_are_exact_canonical_length() {
    assert_eq!(wallet_a().len(), 129);
    assert_eq!(wallet_b().len(), 129);
    assert_eq!(wallet_c().len(), 129);
    assert!(wallet_a().starts_with('r'));
    assert!(wallet_b().starts_with('r'));
    assert!(wallet_c().starts_with('r'));
}

#[test]
fn test_004_encode_accepts_canonical_wallet_and_returns_canonical_invoice() {
    let wallet = wallet_a();

    let encoded = PrivateRI::encode(&wallet).expect("canonical wallet should encode");

    assert_eq!(encoded, invoice_for(&wallet));
}

#[test]
fn test_005_encode_trims_and_canonicalizes_uppercase_wallet() {
    let encoded = PrivateRI::encode(&format!(" \n{} \t", uppercase_wallet_a()))
        .expect("uppercase wallet should canonicalize");

    assert_eq!(encoded, invoice_for(&wallet_a()));
}

#[test]
fn test_006_encode_rejects_invalid_wallet() {
    assert_err_contains(
        PrivateRI::encode("not-a-wallet"),
        "Invalid Remzar wallet address for private receive invoice",
    );
}

#[test]
fn test_007_build_minimal_invoice_object_without_label_or_context() {
    let one_time_wallet = wallet_a();

    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &one_time_wallet,
            label: None,
            context: None,
        })
        .expect("minimal invoice should build");

    assert_eq!(built.kind, PRIVATE_RECEIVE_INVOICE_KIND);
    assert_eq!(built.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(built.one_time_wallet, one_time_wallet);
    assert_eq!(built.invoice, invoice_for(&wallet_a()));
    assert_eq!(built.label, None);
    assert_eq!(built.context, None);
}

#[test]
fn test_008_build_trims_label_and_context() {
    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("  Receive from Alice  "),
            context: Some("\tOne-time payment request\n"),
        })
        .expect("invoice with label/context should build");

    assert_eq!(built.label.as_deref(), Some("Receive from Alice"));
    assert_eq!(built.context.as_deref(), Some("One-time payment request"));
}

#[test]
fn test_009_build_owned_accepts_owned_request_values() {
    let built = PrivateRI::new()
        .build_owned(PrivateReceiveInvoiceBuildOwnedRequest {
            one_time_wallet: uppercase_wallet_a(),
            label: Some("  owned label  ".to_string()),
            context: Some("  owned context  ".to_string()),
        })
        .expect("owned request should build");

    assert_eq!(built.one_time_wallet, wallet_a());
    assert_eq!(built.invoice, invoice_for(&wallet_a()));
    assert_eq!(built.label.as_deref(), Some("owned label"));
    assert_eq!(built.context.as_deref(), Some("owned context"));
}

#[test]
fn test_010_build_accepts_max_length_label_and_context() {
    let label = "l".repeat(MAX_PRIVATE_RECEIVE_LABEL_LEN);
    let context = "c".repeat(MAX_PRIVATE_RECEIVE_CONTEXT_LEN);

    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some(&label),
            context: Some(&context),
        })
        .expect("max length label/context should be accepted");

    assert_eq!(built.label.as_deref(), Some(label.as_str()));
    assert_eq!(built.context.as_deref(), Some(context.as_str()));
}

#[test]
fn test_011_build_rejects_empty_label_when_provided() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some(" \n\t "),
            context: None,
        }),
        "label cannot be empty when provided",
    );
}

#[test]
fn test_012_build_rejects_too_long_label() {
    let label = "l".repeat(MAX_PRIVATE_RECEIVE_LABEL_LEN + 1);

    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some(&label),
            context: None,
        }),
        "label too long",
    );
}

#[test]
fn test_013_build_rejects_label_control_characters() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("bad\nlabel"),
            context: None,
        }),
        "label contains control characters",
    );
}

#[test]
fn test_014_build_rejects_empty_context_when_provided() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: Some(" \n\t "),
        }),
        "context cannot be empty when provided",
    );
}

#[test]
fn test_015_build_rejects_too_long_context() {
    let context = "c".repeat(MAX_PRIVATE_RECEIVE_CONTEXT_LEN + 1);

    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: Some(&context),
        }),
        "context too long",
    );
}

#[test]
fn test_016_build_rejects_context_control_characters() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: Some("bad\ncontext"),
        }),
        "context contains control characters",
    );
}

#[test]
fn test_017_parse_invoice_only_accepts_full_invoice() {
    let invoice = invoice_for(&wallet_a());

    let parsed = PrivateRI::parse_invoice_only(&invoice).expect("invoice should parse");

    assert_eq!(parsed.kind, PRIVATE_RECEIVE_INVOICE_KIND);
    assert_eq!(parsed.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(parsed.one_time_wallet, wallet_a());
    assert_eq!(parsed.invoice, invoice);
    assert_eq!(parsed.label, None);
    assert_eq!(parsed.context, None);
}

#[test]
fn test_018_parse_invoice_only_rejects_raw_wallet_address() {
    assert_err_contains(
        PrivateRI::parse_invoice_only(&wallet_a()),
        "Expected private receive invoice",
    );
}

#[test]
fn test_019_parse_invoice_only_rejects_empty_input() {
    assert_err_contains(PrivateRI::parse_invoice_only(" \n\t "), "cannot be empty");
}

#[test]
fn test_020_parse_invoice_only_rejects_wrong_prefix() {
    let input = format!("wrong-prefix:v{}:{}", PRIVATE_RECEIVE_VERSION, wallet_a());

    assert_err_contains(
        PrivateRI::parse_invoice_only(&input),
        "Expected private receive invoice",
    );
}

#[test]
fn test_021_parse_invoice_only_rejects_invoice_with_empty_wallet() {
    let input = format!(
        "{}:v{}:",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
    );

    assert_err_contains(
        PrivateRI::parse_invoice_only(&input),
        "Private receive invoice wallet address is empty",
    );
}

#[test]
fn test_022_parse_invoice_only_rejects_invoice_with_too_many_separators() {
    let input = format!(
        "{}:v{}:{}:extra",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        wallet_a()
    );

    assert_err_contains(
        PrivateRI::parse_invoice_only(&input),
        "too many ':' separators",
    );
}

#[test]
fn test_023_parse_invoice_only_accepts_uppercase_wallet_invoice_and_canonicalizes() {
    let input = invoice_for(&uppercase_wallet_a());

    let parsed = PrivateRI::parse_invoice_only(&input)
        .expect("uppercase wallet inside invoice should canonicalize");

    assert_eq!(parsed.kind, PRIVATE_RECEIVE_INVOICE_KIND);
    assert_eq!(parsed.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(parsed.one_time_wallet, wallet_a());
    assert_eq!(parsed.invoice, invoice_for(&wallet_a()));
    assert_eq!(parsed.label, None);
    assert_eq!(parsed.context, None);

    assert_ne!(parsed.invoice, input);
    assert_eq!(parsed.invoice, input.to_lowercase());
}

#[test]
fn test_024_parse_invoice_or_address_accepts_full_invoice_source() {
    let invoice = invoice_for(&wallet_a());

    let parsed = PrivateRI::parse_invoice_or_address(&invoice).expect("full invoice should parse");

    assert_eq!(parsed.source, PrivateReceiveInvoiceSource::Invoice);
    assert_eq!(parsed.one_time_wallet, wallet_a());
    assert_eq!(parsed.canonical_invoice, invoice);
}

#[test]
fn test_025_parse_invoice_or_address_accepts_raw_wallet_source() {
    let parsed = PrivateRI::parse_invoice_or_address(&wallet_b()).expect("raw wallet should parse");

    assert_eq!(parsed.source, PrivateReceiveInvoiceSource::RawOneTimeWallet);
    assert_eq!(parsed.one_time_wallet, wallet_b());
    assert_eq!(parsed.canonical_invoice, invoice_for(&wallet_b()));
}

#[test]
fn test_026_parse_invoice_or_address_canonicalizes_uppercase_raw_wallet() {
    let parsed = PrivateRI::parse_invoice_or_address(&uppercase_wallet_a())
        .expect("uppercase raw wallet should parse");

    assert_eq!(parsed.source, PrivateReceiveInvoiceSource::RawOneTimeWallet);
    assert_eq!(parsed.one_time_wallet, wallet_a());
    assert_eq!(parsed.canonical_invoice, invoice_for(&wallet_a()));
}

#[test]
fn test_027_parse_invoice_or_address_accepts_mixed_case_raw_wallet_and_returns_lowercase() {
    let input = mixed_case_wallet();

    assert_eq!(input.len(), 129);

    let parsed =
        PrivateRI::parse_invoice_or_address(&input).expect("mixed case wallet should parse");

    assert_eq!(parsed.source, PrivateReceiveInvoiceSource::RawOneTimeWallet);
    assert_eq!(parsed.one_time_wallet, input.to_lowercase());
    assert_eq!(parsed.canonical_invoice, invoice_for(&input.to_lowercase()));
}

#[test]
fn test_028_parse_invoice_or_address_rejects_unknown_colon_payload() {
    let input = format!("not-private:v1:{}", wallet_a());

    assert_err_contains(
        PrivateRI::parse_invoice_or_address(&input),
        "Invalid private receive target",
    );
}

#[test]
fn test_029_parse_invoice_or_address_rejects_internal_space() {
    let input = format!("r{} {}", "a".repeat(64), "a".repeat(63));

    assert_eq!(input.len(), 129);

    assert_err_contains(
        PrivateRI::parse_invoice_or_address(&input),
        "contains internal whitespace",
    );
}

#[test]
fn test_030_parse_invoice_or_address_rejects_control_characters() {
    let _input = format!(
        "{}:v{}:{}\n",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        wallet_a()
    );

    let input = format!(
        "{}:v{}:{}\nextra",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        wallet_a()
    );

    assert_err_contains(
        PrivateRI::parse_invoice_or_address(&input),
        "contains control characters",
    );
}

#[test]
fn test_031_parse_invoice_or_address_rejects_non_ascii_input() {
    let input = format!("{}é", wallet_a());

    assert_err_contains(PrivateRI::parse_invoice_or_address(&input), "must be ASCII");
}

#[test]
fn test_032_recipient_wallet_from_input_returns_wallet_for_invoice_and_raw_address() {
    let invoice = invoice_for(&wallet_a());

    let from_invoice =
        PrivateRI::recipient_wallet_from_input(&invoice).expect("invoice recipient should parse");
    let from_raw =
        PrivateRI::recipient_wallet_from_input(&wallet_b()).expect("raw recipient should parse");

    assert_eq!(from_invoice, wallet_a());
    assert_eq!(from_raw, wallet_b());
}

#[test]
fn test_033_looks_like_private_receive_invoice_is_prefix_shape_check_only() {
    let valid_invoice = invoice_for(&wallet_a());
    let malformed_invoice = format!(
        "{}:v{}:not-a-wallet",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
    );
    let v2_invoice = format!("{}:v2:{}", PRIVATE_RECEIVE_INVOICE_PREFIX, wallet_a());

    assert!(PrivateRI::looks_like_private_receive_invoice(
        &valid_invoice
    ));
    assert!(PrivateRI::looks_like_private_receive_invoice(
        &malformed_invoice
    ));
    assert!(!PrivateRI::looks_like_private_receive_invoice(&wallet_a()));
    assert!(!PrivateRI::looks_like_private_receive_invoice(&v2_invoice));
}

#[test]
fn test_034_short_wallet_returns_expected_preview() {
    let short = PrivateRI::short_wallet(&wallet_a()).expect("short wallet should format");

    assert_eq!(short, "raaaaaaaa...aaaaaaaa");
}

#[test]
fn test_035_display_preview_accepts_invoice_and_raw_wallet() {
    let invoice_preview =
        PrivateRI::display_preview(&invoice_for(&wallet_a())).expect("invoice preview");
    let raw_preview = PrivateRI::display_preview(&wallet_b()).expect("raw preview");

    assert_eq!(
        invoice_preview,
        format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, "raaaaaaaa...aaaaaaaa"
        )
    );

    assert_eq!(
        raw_preview,
        format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, "rbbbbbbbb...bbbbbbbb"
        )
    );
}

#[test]
fn test_036_qr_payload_returns_canonical_invoice_for_valid_object() {
    let invoice = valid_invoice_object();

    let payload = PrivateRI::qr_payload(&invoice).expect("QR payload should build");

    assert_eq!(payload, invoice.invoice);
}

#[test]
fn test_037_to_pretty_json_and_from_json_roundtrip_valid_invoice_object() {
    let invoice = valid_invoice_object();

    let json = PrivateRI::to_pretty_json(&invoice).expect("invoice should serialize");
    let decoded = PrivateRI::from_json(&json).expect("invoice should deserialize");

    assert_eq!(decoded, invoice);
    decoded.validate().expect("decoded invoice should validate");
}

#[test]
fn test_038_from_json_rejects_empty_invalid_and_oversized_json() {
    assert_err_contains(
        PrivateRI::from_json(" \n\t "),
        "Private receive invoice JSON cannot be empty",
    );

    assert_err_contains(
        PrivateRI::from_json("{ not valid json"),
        "Failed to parse private receive invoice JSON",
    );

    let oversized = "x".repeat(4097);
    assert_err_contains(
        PrivateRI::from_json(&oversized),
        "Private receive invoice JSON is too large",
    );
}

#[test]
fn test_039_from_wallet_receipt_and_from_wallet_record_build_matching_invoice_objects() {
    let receipt = valid_receipt();
    let record = valid_record();

    let from_receipt = PrivateRI::new()
        .from_wallet_receipt(&receipt)
        .expect("invoice should build from receipt");

    let from_record = PrivateRI::new()
        .from_wallet_record(&record)
        .expect("invoice should build from record");

    assert_eq!(from_receipt.kind, PRIVATE_RECEIVE_INVOICE_KIND);
    assert_eq!(from_receipt.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(from_receipt.one_time_wallet, receipt.one_time_wallet);
    assert_eq!(from_receipt.invoice, receipt.invoice);
    assert_eq!(from_receipt.label, None);
    assert_eq!(
        from_receipt.context.as_deref(),
        Some("created_from_private_receive_wallet_receipt")
    );

    assert_eq!(from_record.kind, PRIVATE_RECEIVE_INVOICE_KIND);
    assert_eq!(from_record.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(from_record.one_time_wallet, record.one_time_wallet);
    assert_eq!(from_record.invoice, record.invoice);
    assert_eq!(from_record.label, None);
    assert_eq!(
        from_record.context.as_deref(),
        Some("created_from_private_receive_wallet_record")
    );
}

#[test]
fn test_040_validate_invoice_object_and_instance_methods_cover_core_invariants() {
    let invoice = valid_invoice_object();

    PrivateRI::validate_invoice_object(&invoice).expect("valid invoice object should pass");
    invoice.validate().expect("instance validate should pass");

    assert_eq!(invoice.as_str(), invoice.invoice);
    assert_eq!(invoice.recipient_wallet(), invoice.one_time_wallet);
    assert_eq!(format!("{invoice}"), invoice.invoice);

    let mut wrong_kind = invoice.clone();
    wrong_kind.kind = "wrong_kind".to_string();
    assert_err_contains(
        PrivateRI::validate_invoice_object(&wrong_kind),
        "Invalid private receive invoice kind",
    );

    let mut wrong_version = invoice.clone();
    wrong_version.version = PRIVATE_RECEIVE_VERSION + 1;
    assert_err_contains(
        PrivateRI::validate_invoice_object(&wrong_version),
        "Invalid private receive invoice version",
    );

    let mut mismatched_wallet = invoice.clone();
    mismatched_wallet.one_time_wallet = wallet_c();
    assert_err_contains(
        PrivateRI::validate_invoice_object(&mismatched_wallet),
        "invoice wallet != one_time_wallet",
    );

    let mut noncanonical_invoice = invoice.clone();
    noncanonical_invoice.invoice = invoice_for(&uppercase_wallet_a());
    noncanonical_invoice.one_time_wallet = wallet_a();
    assert_err_contains(
        PrivateRI::validate_invoice_object(&noncanonical_invoice),
        "Private receive invoice object is not canonical",
    );
}

#[test]
fn test_041_encode_accepts_mixed_case_wallet_and_returns_lowercase_canonical_invoice() {
    let input = mixed_case_wallet();

    let encoded = PrivateRI::encode(&input).expect("mixed-case wallet should encode");

    assert_eq!(encoded, invoice_for(&input.to_lowercase()));
    assert_ne!(encoded, invoice_for(&input));
}

#[test]
fn test_042_encode_rejects_invoice_string_instead_of_wallet_address() {
    let invoice = invoice_for(&wallet_a());

    assert_err_contains(
        PrivateRI::encode(&invoice),
        "Invalid Remzar wallet address for private receive invoice",
    );
}

#[test]
fn test_043_build_rejects_malformed_one_time_wallet() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: "not-a-wallet",
            label: None,
            context: None,
        }),
        "Invalid Remzar wallet address for private receive invoice",
    );
}

#[test]
fn test_044_build_canonicalizes_mixed_case_one_time_wallet() {
    let input = mixed_case_wallet();

    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &input,
            label: None,
            context: None,
        })
        .expect("mixed-case wallet should build");

    assert_eq!(built.one_time_wallet, input.to_lowercase());
    assert_eq!(built.invoice, invoice_for(&input.to_lowercase()));
}

#[test]
fn test_045_build_accepts_label_and_context_after_trimming_to_valid_values() {
    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("     trimmed label     "),
            context: Some("     trimmed context     "),
        })
        .expect("trimmed label/context should be valid");

    assert_eq!(built.label.as_deref(), Some("trimmed label"));
    assert_eq!(built.context.as_deref(), Some("trimmed context"));
}

#[test]
fn test_046_build_rejects_label_with_tab_control_character() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("bad\tlabel"),
            context: None,
        }),
        "label contains control characters",
    );
}

#[test]
fn test_047_build_rejects_label_with_null_control_character() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("bad\0label"),
            context: None,
        }),
        "label contains control characters",
    );
}

#[test]
fn test_048_build_rejects_context_with_tab_control_character() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: Some("bad\tcontext"),
        }),
        "context contains control characters",
    );
}

#[test]
fn test_049_build_rejects_context_with_null_control_character() {
    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: Some("bad\0context"),
        }),
        "context contains control characters",
    );
}

#[test]
fn test_050_build_accepts_non_ascii_label_within_byte_limit() {
    let label = "é".repeat(48);

    assert_eq!(label.len(), MAX_PRIVATE_RECEIVE_LABEL_LEN);

    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some(&label),
            context: None,
        })
        .expect("non-ASCII label within byte limit should be accepted");

    assert_eq!(built.label.as_deref(), Some(label.as_str()));
}

#[test]
fn test_051_build_rejects_non_ascii_label_over_byte_limit() {
    let label = "é".repeat(49);

    assert!(label.len() > MAX_PRIVATE_RECEIVE_LABEL_LEN);

    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some(&label),
            context: None,
        }),
        "label too long",
    );
}

#[test]
fn test_052_build_accepts_non_ascii_context_within_byte_limit() {
    let context = "é".repeat(128);

    assert_eq!(context.len(), MAX_PRIVATE_RECEIVE_CONTEXT_LEN);

    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: Some(&context),
        })
        .expect("non-ASCII context within byte limit should be accepted");

    assert_eq!(built.context.as_deref(), Some(context.as_str()));
}

#[test]
fn test_053_build_rejects_non_ascii_context_over_byte_limit() {
    let context = "é".repeat(129);

    assert!(context.len() > MAX_PRIVATE_RECEIVE_CONTEXT_LEN);

    assert_err_contains(
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: Some(&context),
        }),
        "context too long",
    );
}

#[test]
fn test_054_parse_invoice_only_accepts_leading_and_trailing_whitespace() {
    let input = format!(" \n\t{} \r\n", invoice_for(&wallet_a()));

    let parsed = PrivateRI::parse_invoice_only(&input).expect("outer whitespace should be trimmed");

    assert_eq!(parsed.one_time_wallet, wallet_a());
    assert_eq!(parsed.invoice, invoice_for(&wallet_a()));
}

#[test]
fn test_055_parse_invoice_only_rejects_oversized_input_after_trim() {
    let oversized = "x".repeat(513);

    assert_err_contains(PrivateRI::parse_invoice_only(&oversized), "too long");
}

#[test]
fn test_056_parse_invoice_only_rejects_internal_space_inside_invoice() {
    let input = format!(
        "{}:v{}:{} {}",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        "a".repeat(64),
        "a".repeat(64)
    );

    assert_err_contains(
        PrivateRI::parse_invoice_only(&input),
        "contains internal whitespace",
    );
}

#[test]
fn test_057_parse_invoice_only_rejects_internal_newline_control_character() {
    let input = format!(
        "{}:v{}:{}\n{}",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        "a".repeat(64),
        "a".repeat(64)
    );

    assert_err_contains(
        PrivateRI::parse_invoice_only(&input),
        "contains control characters",
    );
}

#[test]
fn test_058_parse_invoice_only_rejects_non_ascii_invoice_input() {
    let input = format!("{}é", invoice_for(&wallet_a()));

    assert_err_contains(PrivateRI::parse_invoice_only(&input), "must be ASCII");
}

#[test]
fn test_059_parse_invoice_only_rejects_v0_shape_before_strict_version_parse() {
    let input = format!("{}:v0:{}", PRIVATE_RECEIVE_INVOICE_PREFIX, wallet_a());

    assert_err_contains(
        PrivateRI::parse_invoice_only(&input),
        "Expected private receive invoice",
    );
}

#[test]
fn test_060_validate_invoice_object_rejects_wrong_invoice_prefix() {
    let mut invoice = valid_invoice_object();
    invoice.invoice = format!("wrong-prefix:v{}:{}", PRIVATE_RECEIVE_VERSION, wallet_b());

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "Invalid private receive invoice prefix",
    );
}

#[test]
fn test_061_validate_invoice_object_rejects_wrong_version_inside_invoice_string() {
    let mut invoice = valid_invoice_object();
    invoice.invoice = format!("{}:v2:{}", PRIVATE_RECEIVE_INVOICE_PREFIX, wallet_b());

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "Unsupported private receive invoice version",
    );
}

#[test]
fn test_062_validate_invoice_object_rejects_too_many_colons_inside_invoice_string() {
    let mut invoice = valid_invoice_object();
    invoice.invoice = format!(
        "{}:v{}:{}:extra",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        wallet_b()
    );

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "too many ':' separators",
    );
}

#[test]
fn test_063_validate_invoice_object_rejects_empty_invoice_string() {
    let mut invoice = valid_invoice_object();
    invoice.invoice.clear();

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "cannot be empty",
    );
}

#[test]
fn test_064_validate_invoice_object_rejects_invalid_wallet_inside_invoice_string() {
    let mut invoice = valid_invoice_object();
    invoice.invoice = format!(
        "{}:v{}:not-a-wallet",
        PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
    );

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "Invalid Remzar wallet address for private receive invoice",
    );
}

#[test]
fn test_065_validate_invoice_object_rejects_uppercase_noncanonical_invoice_string() {
    let mut invoice = valid_invoice_object();
    invoice.one_time_wallet = wallet_a();
    invoice.invoice = invoice_for(&uppercase_wallet_a());

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "Private receive invoice object is not canonical",
    );
}

#[test]
fn test_066_validate_invoice_object_rejects_empty_label_on_existing_object() {
    let mut invoice = valid_invoice_object();
    invoice.label = Some("   ".to_string());

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "label cannot be empty when provided",
    );
}

#[test]
fn test_067_validate_invoice_object_rejects_too_long_label_on_existing_object() {
    let mut invoice = valid_invoice_object();
    invoice.label = Some("x".repeat(MAX_PRIVATE_RECEIVE_LABEL_LEN + 1));

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "label too long",
    );
}

#[test]
fn test_068_validate_invoice_object_rejects_empty_context_on_existing_object() {
    let mut invoice = valid_invoice_object();
    invoice.context = Some("   ".to_string());

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "context cannot be empty when provided",
    );
}

#[test]
fn test_069_validate_invoice_object_rejects_too_long_context_on_existing_object() {
    let mut invoice = valid_invoice_object();
    invoice.context = Some("x".repeat(MAX_PRIVATE_RECEIVE_CONTEXT_LEN + 1));

    assert_err_contains(
        PrivateRI::validate_invoice_object(&invoice),
        "context too long",
    );
}

#[test]
fn test_070_to_pretty_json_omits_none_label_and_context_fields() {
    let invoice = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: None,
        })
        .expect("invoice should build");

    let json = PrivateRI::to_pretty_json(&invoice).expect("JSON should serialize");

    assert!(json.contains(PRIVATE_RECEIVE_INVOICE_KIND));
    assert!(json.contains(&wallet_a()));
    assert!(!json.contains("\"label\""));
    assert!(!json.contains("\"context\""));
}

#[test]
fn test_071_to_pretty_json_rejects_invalid_invoice_object() {
    let mut invoice = valid_invoice_object();
    invoice.kind = "wrong_kind".to_string();

    assert_err_contains(
        PrivateRI::to_pretty_json(&invoice),
        "Invalid private receive invoice kind",
    );
}

#[test]
fn test_072_from_json_accepts_minimal_json_without_label_or_context() {
    let one_time_wallet = wallet_a();
    let canonical_invoice = invoice_for(&one_time_wallet);

    let json = format!(
        r#"{{
  "kind": "{}",
  "version": {},
  "one_time_wallet": "{}",
  "invoice": "{}"
}}"#,
        PRIVATE_RECEIVE_INVOICE_KIND, PRIVATE_RECEIVE_VERSION, one_time_wallet, canonical_invoice
    );

    let decoded = PrivateRI::from_json(&json).expect("minimal JSON should decode");

    assert_eq!(decoded.kind, PRIVATE_RECEIVE_INVOICE_KIND);
    assert_eq!(decoded.version, PRIVATE_RECEIVE_VERSION);
    assert_eq!(decoded.one_time_wallet, one_time_wallet);
    assert_eq!(decoded.invoice, canonical_invoice);
    assert_eq!(decoded.label, None);
    assert_eq!(decoded.context, None);
}

#[test]
fn test_073_from_json_rejects_wrong_kind() {
    let mut invoice = valid_invoice_object();
    invoice.kind = "wrong_kind".to_string();

    let json = serde_json::to_string_pretty(&invoice).expect("JSON should serialize");

    assert_err_contains(
        PrivateRI::from_json(&json),
        "Invalid private receive invoice kind",
    );
}

#[test]
fn test_074_from_json_rejects_wrong_version() {
    let mut invoice = valid_invoice_object();
    invoice.version = PRIVATE_RECEIVE_VERSION + 1;

    let json = serde_json::to_string_pretty(&invoice).expect("JSON should serialize");

    assert_err_contains(
        PrivateRI::from_json(&json),
        "Invalid private receive invoice version",
    );
}

#[test]
fn test_075_from_json_rejects_mismatched_one_time_wallet() {
    let mut invoice = valid_invoice_object();
    invoice.one_time_wallet = wallet_c();

    let json = serde_json::to_string_pretty(&invoice).expect("JSON should serialize");

    assert_err_contains(
        PrivateRI::from_json(&json),
        "invoice wallet != one_time_wallet",
    );
}

#[test]
fn test_076_from_json_rejects_noncanonical_uppercase_invoice_string() {
    let mut invoice = valid_invoice_object();
    invoice.one_time_wallet = wallet_a();
    invoice.invoice = invoice_for(&uppercase_wallet_a());

    let json = serde_json::to_string_pretty(&invoice).expect("JSON should serialize");

    assert_err_contains(
        PrivateRI::from_json(&json),
        "Private receive invoice object is not canonical",
    );
}

#[test]
fn test_077_from_json_accepts_outer_whitespace_around_json() {
    let invoice = valid_invoice_object();
    let json = serde_json::to_string_pretty(&invoice).expect("JSON should serialize");
    let wrapped = format!(" \n\t{json}\n ");

    let decoded = PrivateRI::from_json(&wrapped).expect("outer whitespace should be accepted");

    assert_eq!(decoded, invoice);
}

#[test]
fn test_078_from_json_rejects_json_array_instead_of_invoice_object() {
    assert_err_contains(
        PrivateRI::from_json("[]"),
        "Failed to parse private receive invoice JSON",
    );
}

#[test]
fn test_079_from_wallet_receipt_rejects_wrong_receipt_version() {
    let mut receipt = valid_receipt();
    receipt.version = PRIVATE_RECEIVE_VERSION + 1;

    assert_err_contains(
        PrivateRI::new().from_wallet_receipt(&receipt),
        "receipt version mismatch",
    );
}

#[test]
fn test_080_from_wallet_receipt_rejects_receipt_invoice_wallet_mismatch() {
    let mut receipt = valid_receipt();
    receipt.invoice = invoice_for(&wallet_c());

    assert_err_contains(
        PrivateRI::new().from_wallet_receipt(&receipt),
        "invoice does not match one-time wallet",
    );
}

#[test]
fn test_081_from_wallet_receipt_accepts_uppercase_wallet_field_and_returns_canonical_invoice() {
    let mut receipt = valid_receipt();
    receipt.one_time_wallet = format!("R{}", "B".repeat(128));
    receipt.invoice = invoice_for(&wallet_b());

    let built = PrivateRI::new()
        .from_wallet_receipt(&receipt)
        .expect("uppercase wallet field should canonicalize through builder");

    assert_eq!(built.one_time_wallet, wallet_b());
    assert_eq!(built.invoice, invoice_for(&wallet_b()));
    assert_eq!(
        built.context.as_deref(),
        Some("created_from_private_receive_wallet_receipt")
    );
}

#[test]
fn test_082_from_wallet_record_rejects_wrong_record_kind() {
    let mut record = valid_record();
    record.kind = "wrong_kind".to_string();

    assert_err_contains(
        PrivateRI::new().from_wallet_record(&record),
        "Invalid private receive record kind",
    );
}

#[test]
fn test_083_from_wallet_record_rejects_record_invoice_wallet_mismatch() {
    let mut record = valid_record();
    record.invoice = invoice_for(&wallet_c());

    assert_err_contains(
        PrivateRI::new().from_wallet_record(&record),
        "invoice does not match one-time wallet",
    );
}

#[test]
fn test_084_from_wallet_record_rejects_raw_wallet_invoice_even_though_record_validator_accepts_it()
{
    let mut record = valid_record();
    record.invoice = record.one_time_wallet.clone();

    PrivateRW::validate_record(&record)
        .expect("record validator accepts raw wallet through parse_invoice_or_address");

    assert_err_contains(
        PrivateRI::new().from_wallet_record(&record),
        "mismatch between record and invoice builder",
    );
}

#[test]
fn test_085_from_wallet_receipt_rejects_raw_wallet_invoice_even_though_receipt_validator_accepts_it()
 {
    let mut receipt = valid_receipt();
    receipt.invoice = receipt.one_time_wallet.clone();

    PrivateRW::validate_receipt(&receipt)
        .expect("receipt validator accepts raw wallet through parse_invoice_or_address");

    assert_err_contains(
        PrivateRI::new().from_wallet_receipt(&receipt),
        "mismatch between receipt and invoice builder",
    );
}

#[test]
fn test_086_parse_invoice_or_address_accepts_uppercase_wallet_inside_invoice_and_canonicalizes() {
    let input = invoice_for(&uppercase_wallet_a());

    let parsed =
        PrivateRI::parse_invoice_or_address(&input).expect("uppercase invoice wallet should parse");

    assert_eq!(parsed.source, PrivateReceiveInvoiceSource::Invoice);
    assert_eq!(parsed.one_time_wallet, wallet_a());
    assert_eq!(parsed.canonical_invoice, invoice_for(&wallet_a()));
}

#[test]
fn test_087_parse_invoice_or_address_rejects_v2_invoice_shape_as_invalid_target() {
    let input = format!("{}:v2:{}", PRIVATE_RECEIVE_INVOICE_PREFIX, wallet_a());

    assert_err_contains(
        PrivateRI::parse_invoice_or_address(&input),
        "Invalid private receive target",
    );
}

#[test]
fn test_088_parse_invoice_or_address_rejects_v1_invoice_with_too_many_separators() {
    let input = format!(
        "{}:v{}:{}:extra",
        PRIVATE_RECEIVE_INVOICE_PREFIX,
        PRIVATE_RECEIVE_VERSION,
        wallet_a()
    );

    assert_err_contains(
        PrivateRI::parse_invoice_or_address(&input),
        "too many ':' separators",
    );
}

#[test]
fn test_089_recipient_wallet_from_input_rejects_unknown_colon_target() {
    let input = format!("unknown:v1:{}", wallet_a());

    assert_err_contains(
        PrivateRI::recipient_wallet_from_input(&input),
        "Invalid private receive target",
    );
}

#[test]
fn test_090_short_wallet_canonicalizes_uppercase_wallet_before_display() {
    let short = PrivateRI::short_wallet(&uppercase_wallet_a())
        .expect("uppercase wallet should canonicalize before preview");

    assert_eq!(short, "raaaaaaaa...aaaaaaaa");
}

#[test]
fn test_091_short_wallet_rejects_invalid_wallet() {
    assert_err_contains(
        PrivateRI::short_wallet("not-a-wallet"),
        "Invalid Remzar wallet address for private receive invoice",
    );
}

#[test]
fn test_092_display_preview_canonicalizes_uppercase_raw_wallet() {
    let preview = PrivateRI::display_preview(&uppercase_wallet_a())
        .expect("uppercase raw wallet should preview");

    assert_eq!(
        preview,
        format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, "raaaaaaaa...aaaaaaaa"
        )
    );
}

#[test]
fn test_093_display_preview_rejects_invalid_target() {
    assert_err_contains(
        PrivateRI::display_preview("not-a-wallet"),
        "Invalid Remzar wallet address for private receive invoice",
    );
}

#[test]
fn test_094_qr_payload_rejects_invalid_invoice_object() {
    let mut invoice = valid_invoice_object();
    invoice.one_time_wallet = wallet_c();

    assert_err_contains(
        PrivateRI::qr_payload(&invoice),
        "invoice wallet != one_time_wallet",
    );
}

#[test]
fn test_095_display_and_accessors_match_built_invoice() {
    let invoice = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("accessor test"),
            context: Some("display test"),
        })
        .expect("invoice should build");

    assert_eq!(invoice.as_str(), invoice.invoice);
    assert_eq!(invoice.recipient_wallet(), invoice.one_time_wallet);
    assert_eq!(format!("{invoice}"), invoice.invoice);
}

#[test]
fn test_096_parse_result_json_roundtrip_preserves_source_wallet_and_canonical_invoice() {
    let parsed = PrivateRI::parse_invoice_or_address(&invoice_for(&wallet_a()))
        .expect("invoice parse result should build");

    let json = serde_json::to_string_pretty(&parsed).expect("parse result should serialize");

    let decoded: remzar::privacy::privacy_002_private_receive_invoice::PrivateReceiveInvoiceParseResult =
        serde_json::from_str(&json).expect("parse result should deserialize");

    assert_eq!(decoded, parsed);
    assert_eq!(decoded.source, PrivateReceiveInvoiceSource::Invoice);
    assert_eq!(decoded.one_time_wallet, wallet_a());
    assert_eq!(decoded.canonical_invoice, invoice_for(&wallet_a()));
}

#[test]
fn test_097_private_receive_invoice_source_json_roundtrip_for_both_variants() {
    let invoice_source = PrivateReceiveInvoiceSource::Invoice;
    let raw_source = PrivateReceiveInvoiceSource::RawOneTimeWallet;

    let invoice_json = serde_json::to_string(&invoice_source).expect("source should serialize");
    let raw_json = serde_json::to_string(&raw_source).expect("source should serialize");

    let invoice_decoded: PrivateReceiveInvoiceSource =
        serde_json::from_str(&invoice_json).expect("source should deserialize");
    let raw_decoded: PrivateReceiveInvoiceSource =
        serde_json::from_str(&raw_json).expect("source should deserialize");

    assert_eq!(invoice_decoded, invoice_source);
    assert_eq!(raw_decoded, raw_source);
}

#[test]
fn test_098_label_and_context_do_not_change_canonical_invoice_string() {
    let without_metadata = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: None,
            context: None,
        })
        .expect("invoice should build");

    let with_metadata = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("local label only"),
            context: Some("local context only"),
        })
        .expect("invoice should build");

    assert_eq!(without_metadata.invoice, with_metadata.invoice);
    assert_eq!(
        without_metadata.one_time_wallet,
        with_metadata.one_time_wallet
    );
    assert!(!with_metadata.invoice.contains("local label only"));
    assert!(!with_metadata.invoice.contains("local context only"));
}

#[test]
fn test_099_qr_payload_ignores_label_and_context_and_returns_only_canonical_invoice() {
    let invoice = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &wallet_a(),
            label: Some("QR Label"),
            context: Some("QR Context"),
        })
        .expect("invoice should build");

    let qr = PrivateRI::qr_payload(&invoice).expect("QR payload should validate");

    assert_eq!(qr, invoice_for(&wallet_a()));
    assert!(!qr.contains("QR Label"));
    assert!(!qr.contains("QR Context"));
}

#[test]
fn test_100_end_to_end_build_json_decode_parse_preview_and_qr_payload() {
    let built = PrivateRI::new()
        .build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &uppercase_wallet_a(),
            label: Some("  End To End Label  "),
            context: Some("  End To End Context  "),
        })
        .expect("invoice should build");

    assert_eq!(built.one_time_wallet, wallet_a());
    assert_eq!(built.invoice, invoice_for(&wallet_a()));
    assert_eq!(built.label.as_deref(), Some("End To End Label"));
    assert_eq!(built.context.as_deref(), Some("End To End Context"));

    let json = PrivateRI::to_pretty_json(&built).expect("JSON should serialize");
    let decoded = PrivateRI::from_json(&json).expect("JSON should decode");

    assert_eq!(decoded, built);

    let parsed = PrivateRI::parse_invoice_or_address(decoded.as_str())
        .expect("decoded invoice string should parse");

    assert_eq!(parsed.source, PrivateReceiveInvoiceSource::Invoice);
    assert_eq!(parsed.one_time_wallet, wallet_a());
    assert_eq!(parsed.canonical_invoice, invoice_for(&wallet_a()));

    let preview = PrivateRI::display_preview(decoded.as_str()).expect("preview should build");
    assert_eq!(
        preview,
        format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION, "raaaaaaaa...aaaaaaaa"
        )
    );

    let qr = PrivateRI::qr_payload(&decoded).expect("QR payload should build");
    assert_eq!(qr, invoice_for(&wallet_a()));
}
