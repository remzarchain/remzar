use proptest::prelude::*;
use proptest::string::string_regex;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::utility::certificate_receipt::CertificateReceipt;
use remzar::utility::helper::REMZAR_WALLET_LEN;

const HEX_128_LEN: usize = 128;
const MAX_TEXT_BYTES: usize = 2_048;
const MAX_FILE_NAME_BYTES: usize = 255;

fn hex128_strategy() -> impl Strategy<Value = String> {
    string_regex("[0-9a-fA-F]{128}").expect("valid hex regex")
}

fn lowercase_wallet_strategy() -> impl Strategy<Value = String> {
    string_regex("[0-9a-f]{128}")
        .expect("valid wallet tail regex")
        .prop_map(|tail| format!("r{tail}"))
}

fn safe_file_name_strategy() -> impl Strategy<Value = String> {
    (
        string_regex("[A-Za-z0-9_]{1,48}").expect("valid filename stem regex"),
        string_regex("[A-Za-z0-9]{1,8}").expect("valid filename extension regex"),
    )
        .prop_map(|(stem, ext)| format!("{stem}.{ext}"))
}

fn safe_text_strategy() -> impl Strategy<Value = String> {
    (
        string_regex("[A-Za-z0-9 _.,:;!?]{0,64}").expect("valid safe text prefix regex"),
        string_regex("[A-Za-z0-9_.,:;!?]{1}").expect("valid required non-whitespace text regex"),
        string_regex("[A-Za-z0-9 _.,:;!?]{0,63}").expect("valid safe text suffix regex"),
    )
        .prop_map(|(prefix, required, suffix)| format!("{prefix}{required}{suffix}"))
}

fn edition_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some(String::new())),
        Just(Some(" \t\r\n".to_string())),
        safe_text_strategy().prop_map(Some),
    ]
}

fn valid_receipt_strategy() -> impl Strategy<Value = CertificateReceipt> {
    (
        (
            hex128_strategy(),
            lowercase_wallet_strategy(),
            safe_file_name_strategy(),
            any::<usize>(),
            hex128_strategy(),
        ),
        (
            safe_text_strategy(),
            safe_text_strategy(),
            safe_text_strategy(),
            edition_strategy(),
            safe_text_strategy(),
            safe_text_strategy(),
        ),
    )
        .prop_map(
            |(
                (nft_id_hex, owner_wallet, file_name, file_size_bytes, content_hash_hex),
                (title, description, created_at_utc, edition, kind, schema),
            )| {
                CertificateReceipt {
                    nft_id_hex,
                    owner_wallet,
                    file_name,
                    file_size_bytes,
                    content_hash_hex,
                    title,
                    description,
                    created_at_utc,
                    edition,
                    kind,
                    schema,
                }
            },
        )
}

fn valid_receipt() -> CertificateReceipt {
    CertificateReceipt {
        nft_id_hex: "a".repeat(HEX_128_LEN),
        owner_wallet: format!("r{}", "1".repeat(128)),
        file_name: "certificate_receipt.png".to_string(),
        file_size_bytes: 1024,
        content_hash_hex: "b".repeat(HEX_128_LEN),
        title: "Certificate Title".to_string(),
        description: "Certificate Description".to_string(),
        created_at_utc: "2026-05-07T00:00:00Z".to_string(),
        edition: Some("1 of 1".to_string()),
        kind: "nft_certificate".to_string(),
        schema: "remzar.certificate.v1".to_string(),
    }
}

fn wrap_with_ascii_whitespace(value: &str, left_count: usize, right_count: usize) -> String {
    let left = " \t\r\n"
        .chars()
        .cycle()
        .take(left_count)
        .collect::<String>();

    let right = "\n\r\t "
        .chars()
        .cycle()
        .take(right_count)
        .collect::<String>();

    format!("{left}{value}{right}")
}

fn set_required_text_field(receipt: &mut CertificateReceipt, selector: u8, value: String) {
    match selector % 5 {
        0 => receipt.title = value,
        1 => receipt.description = value,
        2 => receipt.created_at_utc = value,
        3 => receipt.kind = value,
        _ => receipt.schema = value,
    }
}

fn replace_ascii_char(input: &str, index: usize, replacement: u8) -> String {
    let mut bytes = input.as_bytes().to_vec();
    let len = bytes.len();
    let replace_index = index % len;

    bytes[replace_index] = replacement;

    String::from_utf8(bytes).expect("test input should remain valid UTF-8")
}

fn assert_receipts_equal(left: &CertificateReceipt, right: &CertificateReceipt) {
    assert_eq!(&left.nft_id_hex, &right.nft_id_hex);
    assert_eq!(&left.owner_wallet, &right.owner_wallet);
    assert_eq!(&left.file_name, &right.file_name);
    assert_eq!(left.file_size_bytes, right.file_size_bytes);
    assert_eq!(&left.content_hash_hex, &right.content_hash_hex);
    assert_eq!(&left.title, &right.title);
    assert_eq!(&left.description, &right.description);
    assert_eq!(&left.created_at_utc, &right.created_at_utc);
    assert_eq!(&left.edition, &right.edition);
    assert_eq!(&left.kind, &right.kind);
    assert_eq!(&left.schema, &right.schema);
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 001/25
    #[test]
    fn valid_certificate_receipts_pass_validation(
        receipt in valid_receipt_strategy(),
    ) {
        prop_assert!(
            receipt.validate().is_ok(),
            "fully valid certificate receipt should pass validation"
        );
    }

    // 002/25
    #[test]
    fn validation_trims_outer_whitespace_on_all_boundary_fields(
        left_count in 0usize..4usize,
        right_count in 0usize..4usize,
    ) {
        let base = valid_receipt();

        let receipt = CertificateReceipt {
            nft_id_hex: wrap_with_ascii_whitespace(&base.nft_id_hex, left_count, right_count),
            owner_wallet: wrap_with_ascii_whitespace(&base.owner_wallet, left_count, right_count),
            file_name: wrap_with_ascii_whitespace(&base.file_name, left_count, right_count),
            file_size_bytes: base.file_size_bytes,
            content_hash_hex: wrap_with_ascii_whitespace(&base.content_hash_hex, left_count, right_count),
            title: wrap_with_ascii_whitespace(&base.title, left_count, right_count),
            description: wrap_with_ascii_whitespace(&base.description, left_count, right_count),
            created_at_utc: wrap_with_ascii_whitespace(&base.created_at_utc, left_count, right_count),
            edition: Some(wrap_with_ascii_whitespace("edition-1", left_count, right_count)),
            kind: wrap_with_ascii_whitespace(&base.kind, left_count, right_count),
            schema: wrap_with_ascii_whitespace(&base.schema, left_count, right_count),
        };

        prop_assert!(
            receipt.validate().is_ok(),
            "validator should trim outer ASCII whitespace before checking fields"
        );
    }

    // 003/25
    #[test]
    fn nft_id_hex_accepts_exact_128_ascii_hex_chars_including_uppercase(
        nft_id_hex in "[0-9A-F]{128}",
    ) {
        let mut receipt = valid_receipt();
        receipt.nft_id_hex = nft_id_hex;

        prop_assert!(
            receipt.validate().is_ok(),
            "nft_id_hex should accept exact-length uppercase ASCII hex"
        );
    }

    // 004/25
    #[test]
    fn content_hash_hex_accepts_exact_128_ascii_hex_chars_including_uppercase(
        content_hash_hex in "[0-9A-F]{128}",
    ) {
        let mut receipt = valid_receipt();
        receipt.content_hash_hex = content_hash_hex;

        prop_assert!(
            receipt.validate().is_ok(),
            "content_hash_hex should accept exact-length uppercase ASCII hex"
        );
    }

    // 005/25
    #[test]
    fn nft_id_hex_rejects_every_wrong_length_even_when_all_chars_are_hex(
        bad_len in 0usize..260usize,
    ) {
        prop_assume!(bad_len != HEX_128_LEN);

        let mut receipt = valid_receipt();
        receipt.nft_id_hex = "a".repeat(bad_len);

        prop_assert!(
            receipt.validate().is_err(),
            "nft_id_hex must be exactly 128 hex chars, got length {bad_len}"
        );
    }

    // 006/25
    #[test]
    fn content_hash_hex_rejects_every_wrong_length_even_when_all_chars_are_hex(
        bad_len in 0usize..260usize,
    ) {
        prop_assume!(bad_len != HEX_128_LEN);

        let mut receipt = valid_receipt();
        receipt.content_hash_hex = "b".repeat(bad_len);

        prop_assert!(
            receipt.validate().is_err(),
            "content_hash_hex must be exactly 128 hex chars, got length {bad_len}"
        );
    }

    // 007/25
    #[test]
    fn nft_id_hex_rejects_non_hex_at_any_position(
        index in 0usize..HEX_128_LEN,
        bad_char in "[g-zG-Z]{1}",
    ) {
        let mut receipt = valid_receipt();

        receipt.nft_id_hex = replace_ascii_char(
            &receipt.nft_id_hex,
            index,
            bad_char.as_bytes()[0],
        );

        prop_assert!(
            receipt.validate().is_err(),
            "nft_id_hex must reject non-hex character at index {index}"
        );
    }

    // 008/25
    #[test]
    fn content_hash_hex_rejects_non_hex_at_any_position(
        index in 0usize..HEX_128_LEN,
        bad_char in "[g-zG-Z]{1}",
    ) {
        let mut receipt = valid_receipt();

        receipt.content_hash_hex = replace_ascii_char(
            &receipt.content_hash_hex,
            index,
            bad_char.as_bytes()[0],
        );

        prop_assert!(
            receipt.validate().is_err(),
            "content_hash_hex must reject non-hex character at index {index}"
        );
    }

    // 009/25
    #[test]
    fn hex_fields_reject_unicode_length_spoofing(
        selector in 0u8..2u8,
        before_count in 0usize..=127usize,
    ) {
        let after_count = 127usize - before_count;
        let spoof = format!(
            "{}é{}",
            "a".repeat(before_count),
            "b".repeat(after_count),
        );

        prop_assert_eq!(
            spoof.chars().count(),
            HEX_128_LEN,
            "test input intentionally has 128 Unicode scalar values"
        );

        prop_assert!(
            spoof.len() > HEX_128_LEN,
            "test input intentionally exceeds 128 bytes because é is multibyte"
        );

        let mut receipt = valid_receipt();

        if selector == 0 {
            receipt.nft_id_hex = spoof;
        } else {
            receipt.content_hash_hex = spoof;
        }

        prop_assert!(
            receipt.validate().is_err(),
            "hex fields must be byte-length strict and reject Unicode spoofing"
        );
    }

    // 010/25
    #[test]
    fn owner_wallet_accepts_strict_lowercase_remzar_wallets(
        owner_wallet in lowercase_wallet_strategy(),
    ) {
        let mut receipt = valid_receipt();
        receipt.owner_wallet = owner_wallet;

        prop_assert!(
            receipt.validate().is_ok(),
            "owner_wallet should accept strict lowercase r + 128 lowercase hex"
        );
    }

    // 011/25
    #[test]
    fn owner_wallet_rejects_uppercase_prefix_or_uppercase_hex_body(
        upper_tail in "[0-9A-F]{128}",
    ) {
        let mut receipt_upper_prefix = valid_receipt();
        receipt_upper_prefix.owner_wallet = format!("R{}", upper_tail.to_ascii_lowercase());

        prop_assert!(
            receipt_upper_prefix.validate().is_err(),
            "owner_wallet must reject uppercase R prefix because parse_wallet_address is strict"
        );

        let mut receipt_upper_body = valid_receipt();
        receipt_upper_body.owner_wallet = format!("r{upper_tail}");

        prop_assert!(
            receipt_upper_body.validate().is_err(),
            "owner_wallet must reject uppercase hex body because wallet parsing is strict lowercase"
        );
    }

    // 012/25
    #[test]
    fn owner_wallet_rejects_wrong_prefix_even_with_valid_lowercase_hex_body(
        prefix in "[a-qs-z0-9]{1}",
        tail in "[0-9a-f]{128}",
    ) {
        let mut receipt = valid_receipt();
        receipt.owner_wallet = format!("{prefix}{tail}");

        prop_assert!(
            receipt.validate().is_err(),
            "owner_wallet must reject every prefix except lowercase r"
        );
    }

    // 013/25
    #[test]
    fn owner_wallet_rejects_wrong_length_before_wallet_parse(
        bad_tail_len in 0usize..260usize,
    ) {
        prop_assume!(bad_tail_len != 128);

        let mut receipt = valid_receipt();
        receipt.owner_wallet = format!("r{}", "a".repeat(bad_tail_len));

        prop_assert_ne!(
            receipt.owner_wallet.len(),
            REMZAR_WALLET_LEN,
            "test input must have wrong wallet length"
        );

        prop_assert!(
            receipt.validate().is_err(),
            "owner_wallet must reject anything not exactly 129 chars"
        );
    }

    // 014/25
    #[test]
    fn owner_wallet_rejects_non_hex_body_at_any_position(
        index in 0usize..128usize,
        bad_char in "[g-z]{1}",
    ) {
        let mut receipt = valid_receipt();

        receipt.owner_wallet = replace_ascii_char(
            &receipt.owner_wallet,
            1 + index,
            bad_char.as_bytes()[0],
        );

        prop_assert!(
            receipt.validate().is_err(),
            "owner_wallet must reject non-hex wallet body byte at index {index}"
        );
    }

    // 015/25
    #[test]
    fn safe_file_names_and_all_usize_file_sizes_validate(
        file_name in safe_file_name_strategy(),
        file_size_bytes in any::<usize>(),
    ) {
        let mut receipt = valid_receipt();
        receipt.file_name = file_name;
        receipt.file_size_bytes = file_size_bytes;

        prop_assert!(
            receipt.validate().is_ok(),
            "safe filename should validate and file_size_bytes should be metadata-only"
        );
    }

    // 016/25
    #[test]
    fn file_name_rejects_empty_or_whitespace_only_names(
        whitespace in "[ \\t\\r\\n]{0,32}",
    ) {
        let mut receipt = valid_receipt();
        receipt.file_name = whitespace;

        prop_assert!(
            receipt.validate().is_err(),
            "file_name must reject empty or whitespace-only names after trim"
        );
    }

    // 017/25
    #[test]
    fn file_name_rejects_names_longer_than_255_bytes(
        extra_len in 1usize..128usize,
    ) {
        let mut receipt = valid_receipt();
        receipt.file_name = "a".repeat(MAX_FILE_NAME_BYTES + extra_len);

        prop_assert!(
            receipt.validate().is_err(),
            "file_name must reject names longer than 255 bytes"
        );
    }

    // 018/25
    #[test]
    fn file_name_rejects_forward_slash_and_backslash_path_separators(
        stem in "[A-Za-z0-9_]{1,32}",
        tail in "[A-Za-z0-9_]{1,32}",
        separator_selector in 0u8..2u8,
    ) {
        let separator = if separator_selector == 0 { "/" } else { "\\" };

        let mut receipt = valid_receipt();
        receipt.file_name = format!("{stem}{separator}{tail}.png");

        prop_assert!(
            receipt.validate().is_err(),
            "file_name must reject path separator {separator:?}"
        );
    }

    // 019/25
    #[test]
    fn file_name_rejects_dot_dot_sequences_anywhere(
        prefix in "[A-Za-z0-9_]{0,32}",
        suffix in "[A-Za-z0-9_]{0,32}",
    ) {
        let mut receipt = valid_receipt();
        receipt.file_name = format!("{prefix}..{suffix}.png");

        prop_assert!(
            receipt.validate().is_err(),
            "file_name must reject '..' path traversal marker anywhere"
        );
    }

    // 020/25
    #[test]
    fn file_name_rejects_internal_control_characters_after_trim(
        prefix in "[A-Za-z0-9_]{1,32}",
        suffix in "[A-Za-z0-9_]{1,32}",
        control in 0u8..=31u8,
    ) {
        let mut receipt = valid_receipt();

        receipt.file_name = format!("{prefix}{}{suffix}.png", char::from(control));

        prop_assert!(
            receipt.validate().is_err(),
            "file_name must reject internal ASCII control character {control}"
        );
    }

    // 021/25
    #[test]
    fn required_text_fields_reject_empty_or_whitespace_only_values(
        field_selector in 0u8..5u8,
        whitespace in "[ \\t\\r\\n]{0,64}",
    ) {
        let mut receipt = valid_receipt();

        set_required_text_field(&mut receipt, field_selector, whitespace);

        prop_assert!(
            receipt.validate().is_err(),
            "title/description/created_at_utc/kind/schema must reject empty after trim"
        );
    }

    // 022/25
    #[test]
    fn required_text_fields_accept_2048_bytes_and_reject_2049_bytes(
        field_selector in 0u8..5u8,
    ) {
        let mut max_ok = valid_receipt();
        set_required_text_field(
            &mut max_ok,
            field_selector,
            "x".repeat(MAX_TEXT_BYTES),
        );

        prop_assert!(
            max_ok.validate().is_ok(),
            "required text fields should accept exactly 2048 bytes"
        );

        let mut too_long = valid_receipt();
        set_required_text_field(
            &mut too_long,
            field_selector,
            "x".repeat(MAX_TEXT_BYTES + 1),
        );

        prop_assert!(
            too_long.validate().is_err(),
            "required text fields must reject more than 2048 bytes"
        );
    }

    // 023/25
    #[test]
    fn optional_edition_accepts_none_empty_and_whitespace_but_rejects_overlong_nonempty(
        _case in any::<u8>(),
    ) {
        let mut none_receipt = valid_receipt();
        none_receipt.edition = None;

        prop_assert!(
            none_receipt.validate().is_ok(),
            "edition None should validate"
        );

        let mut empty_receipt = valid_receipt();
        empty_receipt.edition = Some(String::new());

        prop_assert!(
            empty_receipt.validate().is_ok(),
            "edition Some(empty) should be ignored and validate"
        );

        let mut whitespace_receipt = valid_receipt();
        whitespace_receipt.edition = Some(" \t\r\n ".to_string());

        prop_assert!(
            whitespace_receipt.validate().is_ok(),
            "edition Some(whitespace) should be ignored after trim and validate"
        );

        let mut max_receipt = valid_receipt();
        max_receipt.edition = Some("e".repeat(MAX_TEXT_BYTES));

        prop_assert!(
            max_receipt.validate().is_ok(),
            "edition should accept exactly 2048 non-empty bytes"
        );

        let mut too_long_receipt = valid_receipt();
        too_long_receipt.edition = Some("e".repeat(MAX_TEXT_BYTES + 1));

        prop_assert!(
            too_long_receipt.validate().is_err(),
            "edition must reject non-empty text longer than 2048 bytes"
        );
    }

    // 024/25
    #[test]
    fn serde_json_roundtrip_preserves_valid_receipt_and_still_validates(
        receipt in valid_receipt_strategy(),
    ) {
        let json = serde_json::to_string(&receipt)
            .expect("CertificateReceipt should serialize to JSON");

        let decoded: CertificateReceipt = serde_json::from_str(&json)
            .expect("CertificateReceipt should deserialize from JSON");

        assert_receipts_equal(&decoded, &receipt);

        prop_assert!(
            decoded.validate().is_ok(),
            "valid receipt should remain valid after JSON serde roundtrip"
        );
    }

    // 025/25
    #[test]
    fn serde_json_deserialization_does_not_bypass_validation_for_corrupted_receipts(
        mut receipt in valid_receipt_strategy(),
        corruption_selector in 0u8..8u8,
    ) {
        match corruption_selector {
            0 => receipt.nft_id_hex = "z".repeat(HEX_128_LEN),
            1 => receipt.content_hash_hex = "z".repeat(HEX_128_LEN),
            2 => receipt.owner_wallet = format!("R{}", "a".repeat(128)),
            3 => receipt.file_name = "../escape.png".to_string(),
            4 => receipt.title = " ".to_string(),
            5 => receipt.description = " ".to_string(),
            6 => receipt.kind = String::new(),
            _ => receipt.schema = "s".repeat(MAX_TEXT_BYTES + 1),
        }

        let json = serde_json::to_string(&receipt)
            .expect("corrupted receipt should still serialize structurally");

        let decoded: CertificateReceipt = serde_json::from_str(&json)
            .expect("corrupted receipt should still deserialize structurally");

        prop_assert!(
            decoded.validate().is_err(),
            "callers must not treat serde deserialization as validation"
        );
    }
}
