use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::utility::helper::{
    Hash64, PreHash, REMZAR_WALLET_BODY_LEN, REMZAR_WALLET_LEN, REMZAR_WALLET_PREFIX,
    SignatureWrapper, SimplePreHasher, canon_wallet_id, canon_wallet_id_checked, decode_hex_to_64,
    derive_wallet_id_from_pubkey_bytes, ellipsize_middle_ascii, format_remzar, format_remzar_trim,
    format_remzar_trim_one_decimal, from_micro_units, has_quorum, parse_wallet_address,
    parse_wallet_address_bytes, quorum_threshold, quorum_threshold_checked, to_micro_units,
    to_micro_units_str, wallet_id_matches_pubkey_bytes_checked,
};

fn valid_wallet_from_tail(tail: &str) -> String {
    format!("r{tail}")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 001/25
    #[test]
    fn to_micro_units_str_accepts_valid_fixed_point_amounts(
        whole in 0u64..=1_000_000u64,
        frac in 0u64..100_000_000u64,
    ) {
        let amount = format!("{whole}.{frac:08}");
        let expected = whole
            .checked_mul(100_000_000)
            .and_then(|v| v.checked_add(frac))
            .expect("bounded test amount should not overflow");

        prop_assert_eq!(
            to_micro_units_str(&amount),
            expected,
            "valid fixed-point REMZAR string must convert exactly to micro-units"
        );
    }

    // 002/25
    #[test]
    fn to_micro_units_str_rejects_invalid_amount_strings(
        digits in "[0-9]{1,20}",
        frac_too_long in "[0-9]{9,16}",
    ) {
        let negative = format!("-{digits}");
        let positive = format!("+{digits}");
        let scientific = format!("{digits}e1");
        let internal_space = format!("{digits} {digits}");
        let too_many_decimals = format!("{digits}.{frac_too_long}");
        let absurd = "99999999999999999999999999999999999999999999999999999999999999999";

        prop_assert_eq!(to_micro_units_str(&negative), 0);
        prop_assert_eq!(to_micro_units_str(&positive), 0);
        prop_assert_eq!(to_micro_units_str(&scientific), 0);
        prop_assert_eq!(to_micro_units_str(&internal_space), 0);
        prop_assert_eq!(to_micro_units_str(&too_many_decimals), 0);
        prop_assert_eq!(to_micro_units_str(absurd), 0);
    }

    // 003/25
    #[test]
    fn format_remzar_roundtrips_through_to_micro_units_str(
        amount in any::<u64>(),
    ) {
        let formatted = format_remzar(amount);

        prop_assert_eq!(
            to_micro_units_str(&formatted),
            amount,
            "format_remzar output must parse back to the same micro-unit amount"
        );

        prop_assert!(
            formatted.contains('.'),
            "format_remzar must always include decimal point"
        );

        let (_, frac) = formatted
            .split_once('.')
            .expect("format_remzar must contain decimal point");

        prop_assert_eq!(
            frac.len(),
            8,
            "format_remzar must always emit exactly 8 fractional digits"
        );
    }

    // 004/25
    #[test]
    fn trimmed_remzar_formats_parse_back_to_same_micro_units(
        amount in any::<u64>(),
    ) {
        let trimmed = format_remzar_trim(amount);
        let trimmed_one_decimal = format_remzar_trim_one_decimal(amount);

        prop_assert_eq!(
            to_micro_units_str(&trimmed),
            amount,
            "format_remzar_trim output must parse back to original amount"
        );

        prop_assert_eq!(
            to_micro_units_str(&trimmed_one_decimal),
            amount,
            "format_remzar_trim_one_decimal output must parse back to original amount"
        );

        prop_assert_eq!(
            trimmed,
            trimmed_one_decimal,
            "both trim helpers currently have identical behavior"
        );
    }

    // 005/25
    #[test]
    fn to_micro_units_ui_float_matches_bounded_micro_amounts(
        amount in 1u64..=1_000_000_000u64,
    ) {
        let remzar = amount as f64 / 100_000_000.0;

        prop_assert_eq!(
            to_micro_units(remzar),
            amount,
            "bounded UI float conversion should round back to the same micro amount"
        );

        prop_assert!(
            from_micro_units(amount) > 0.0,
            "positive micro amount should display as positive REMZAR float"
        );
    }

    // 006/25
    #[test]
    fn derive_wallet_id_from_pubkey_bytes_outputs_valid_canonical_wallet_id(
        pk_bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let wallet_id = derive_wallet_id_from_pubkey_bytes(&pk_bytes);

        prop_assert_eq!(
            wallet_id.len(),
            REMZAR_WALLET_LEN,
            "wallet id must be r + 128 hex chars"
        );

        prop_assert!(
            wallet_id.starts_with('r'),
            "wallet id must start with r"
        );

        prop_assert!(
            parse_wallet_address(&wallet_id).is_ok(),
            "derived wallet id must pass strict wallet parser"
        );

        let matched = wallet_id_matches_pubkey_bytes_checked(&wallet_id, &pk_bytes)
            .expect("derived wallet id must match the source pubkey bytes");

        prop_assert_eq!(
            matched,
            wallet_id,
            "wallet match helper must return canonical wallet id"
        );
    }

    // 007/25
    #[test]
    fn canon_wallet_id_checked_accepts_uppercase_and_whitespace_then_lowercases(
        upper_tail in "[0-9A-F]{128}",
    ) {
        let input = format!(" \tR{upper_tail}\n");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        let canonical = canon_wallet_id_checked(&input)
            .expect("canonicalizer should accept trimmed R-prefixed uppercase hex");

        prop_assert_eq!(
            &canonical,
            &expected,
            "canonicalizer must trim, lowercase prefix/body, and return canonical wallet id"
        );

        prop_assert_eq!(
            canon_wallet_id(&input),
            expected,
            "non-fallible canonicalizer must return same canonical value for valid input"
        );
    }

    // 008/25
    #[test]
    fn wallet_address_parsers_reject_short_wrong_prefix_non_hex_and_nul_bytes(
        short_tail in "[0-9a-f]{0,127}",
        valid_tail in "[0-9a-f]{128}",
        nul_index in 0usize..REMZAR_WALLET_LEN,
    ) {
        let short = valid_wallet_from_tail(&short_tail);
        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);
        let valid = valid_wallet_from_tail(&valid_tail);

        prop_assert!(
            parse_wallet_address(&short).is_err(),
            "strict parser must reject short wallet address"
        );

        prop_assert!(
            canon_wallet_id_checked(&short).is_err(),
            "canonical parser must reject short wallet address"
        );

        prop_assert!(
            parse_wallet_address(&wrong_prefix).is_err(),
            "strict parser must reject wrong prefix"
        );

        prop_assert!(
            canon_wallet_id_checked(&wrong_prefix).is_err(),
            "canonical parser must reject wrong prefix"
        );

        prop_assert!(
            parse_wallet_address(&non_hex).is_err(),
            "strict parser must reject non-hex wallet body"
        );

        prop_assert!(
            canon_wallet_id_checked(&non_hex).is_err(),
            "canonical parser must reject non-hex wallet body"
        );

        let mut bytes = valid.into_bytes();

        prop_assert!(
            parse_wallet_address_bytes(&bytes).is_ok(),
            "valid canonical wallet bytes must parse"
        );

        bytes[nul_index] = 0;

        prop_assert!(
            parse_wallet_address_bytes(&bytes).is_err(),
            "wallet byte parser must reject NUL byte at index {nul_index}"
        );
    }

    // 009/25
    #[test]
    fn wallet_constants_match_canonical_layout(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = valid_wallet_from_tail(&tail);

        prop_assert_eq!(
            REMZAR_WALLET_LEN,
            129,
            "wallet length must be 129"
        );

        prop_assert_eq!(
            REMZAR_WALLET_BODY_LEN,
            128,
            "wallet body length must be 128"
        );

        prop_assert_eq!(
            REMZAR_WALLET_PREFIX,
            b'r',
            "wallet prefix byte must be r"
        );

        prop_assert_eq!(
            wallet.len(),
            REMZAR_WALLET_LEN,
            "generated canonical wallet test string must match wallet length"
        );

        prop_assert!(
            parse_wallet_address(&wallet).is_ok(),
            "canonical r + 128 lowercase hex wallet must parse"
        );
    }

    // 010/25
    #[test]
    fn decode_hex_to_64_accepts_exact_128_hex_and_rejects_bad_inputs(
        bytes in any::<[u8; 64]>(),
    ) {
        let hex_value = hex::encode(bytes);

        let decoded = decode_hex_to_64(&hex_value)
            .expect("128 hex chars should decode into 64 bytes");

        prop_assert_eq!(
            decoded,
            bytes,
            "decode_hex_to_64 must preserve exact bytes"
        );

        let short = &hex_value[..127];
        let non_hex = format!("g{}", &hex_value[1..]);

        prop_assert!(
            decode_hex_to_64(short).is_err(),
            "decode_hex_to_64 must reject wrong hex length"
        );

        prop_assert!(
            decode_hex_to_64(&non_hex).is_err(),
            "decode_hex_to_64 must reject non-hex characters"
        );
    }

    // 011/25
    #[test]
    fn hash64_newtype_preserves_bytes_and_postcard_roundtrips(
        bytes in any::<[u8; 64]>(),
    ) {
        let hash = Hash64::from_bytes(bytes);

        prop_assert_eq!(
            hash.as_bytes(),
            &bytes,
            "Hash64 must preserve input bytes"
        );

        let encoded = postcard::to_allocvec(&hash)
            .expect("Hash64 should postcard-serialize");

        let decoded: Hash64 = postcard::from_bytes(&encoded)
            .expect("Hash64 should postcard-deserialize");

        prop_assert_eq!(
            decoded.as_bytes(),
            &bytes,
            "Hash64 postcard roundtrip must preserve bytes"
        );
    }

    // 012/25
    #[test]
    fn signature_wrapper_accepts_exact_signature_length_and_rejects_wrong_lengths(
        sig_bytes in proptest::collection::vec(any::<u8>(), ml_dsa_65::SIG_LEN..=ml_dsa_65::SIG_LEN),
        bad_len in 0usize..4000usize,
        fill in any::<u8>(),
    ) {
        prop_assume!(bad_len != ml_dsa_65::SIG_LEN);

        let wrapper = SignatureWrapper::from_bytes(&sig_bytes)
            .expect("exact ML-DSA-65 signature length must be accepted");

        prop_assert_eq!(
            wrapper.as_bytes(),
            sig_bytes.as_slice(),
            "SignatureWrapper must preserve raw signature bytes"
        );

        let signature = wrapper.to_signature()
            .expect("wrapper should convert back to fixed signature array");

        prop_assert_eq!(
            signature.as_slice(),
            sig_bytes.as_slice(),
            "fixed signature array must preserve wrapper bytes"
        );

        let bad = vec![fill; bad_len];

        prop_assert!(
            SignatureWrapper::from_bytes(&bad).is_err(),
            "SignatureWrapper must reject signature length {bad_len}"
        );
    }

    // 013/25
    #[test]
    fn simple_prehasher_fills_prefix_without_panicking(
        source in any::<[u8; 64]>(),
        out_len in 0usize..128usize,
        fill in any::<u8>(),
    ) {
        let mut hasher = SimplePreHasher { bytes: source };
        let mut out = vec![fill; out_len];

        hasher.fill_bytes(&mut out);

        let copied = out_len.min(64);

        prop_assert_eq!(
            &out[..copied],
            &source[..copied],
            "SimplePreHasher must copy source bytes into output prefix"
        );

        if out_len > 64 {
            prop_assert!(
                out[64..].iter().all(|b| *b == fill),
                "SimplePreHasher must not modify bytes after the 64-byte source"
            );
        }
    }

    // 014/25
    #[test]
    fn ellipsize_middle_ascii_shortens_only_when_it_actually_reduces_length(
        middle in "[A-Za-z0-9]{0,128}",
        head in 1usize..16usize,
        tail in 1usize..16usize,
    ) {
        let s = format!("HEAD{middle}TAIL");
        let out = ellipsize_middle_ascii(&s, head, tail);

        if s.len() <= head.saturating_add(tail).saturating_add(3) {
            prop_assert_eq!(
                out,
                s,
                "ellipsize should return original string when shortening would not reduce length"
            );
        } else {
            prop_assert_eq!(
                out.len(),
                head + tail + 3,
                "ellipsized output length must be head + tail + 3 dots"
            );

            prop_assert!(
                out.contains("..."),
                "ellipsized output must contain middle ellipsis"
            );

            prop_assert!(
                out.starts_with(&s[..head]),
                "ellipsized output must preserve head"
            );

            prop_assert!(
                out.ends_with(&s[s.len() - tail..]),
                "ellipsized output must preserve tail"
            );
        }
    }

    // 015/25
    #[test]
    fn quorum_threshold_checked_matches_threshold_and_has_quorum_rule(
        n in 0usize..10_000usize,
        have in 0usize..10_000usize,
    ) {
        let threshold = quorum_threshold(n);
        let checked = quorum_threshold_checked(n)
            .expect("quorum_threshold_checked should not fail for usize input");

        let expected = match n {
            0 | 1 => 1,
            2..=9 => 2,
            _ => n.div_ceil(5),
        };

        prop_assert_eq!(
            threshold,
            expected,
            "quorum_threshold must match policy"
        );

        prop_assert_eq!(
            checked,
            threshold,
            "checked quorum threshold must match non-checked helper"
        );

        prop_assert_eq!(
            has_quorum(have, n),
            have >= threshold,
            "has_quorum must be equivalent to have >= quorum_threshold(n)"
        );
    }

    // 016/25
    #[test]
    fn to_micro_units_str_accepts_fractional_amounts_with_implicit_zero_whole_part(
        frac_digits in "[0-9]{1,8}",
    ) {
        let amount = format!(".{frac_digits}");

        let frac_value = frac_digits
            .parse::<u64>()
            .expect("generated fractional digits should parse");

        let scale = 10u64.pow((8usize - frac_digits.len()) as u32);
        let expected = frac_value
            .checked_mul(scale)
            .expect("bounded fractional value should not overflow");

        prop_assert_eq!(
            to_micro_units_str(&amount),
            expected,
            "fraction-only amount must parse as zero whole REMZAR plus padded fractional micro-units"
        );

        prop_assert_eq!(
            to_micro_units_str(&format!("0.{frac_digits}")),
            expected,
            "explicit zero whole part and implicit zero whole part must parse the same"
        );
    }

    // 017/25
    #[test]
    fn to_micro_units_str_trims_outer_whitespace_but_rejects_internal_whitespace(
        amount in any::<u64>(),
        left_count in 0usize..4usize,
        right_count in 0usize..4usize,
    ) {
        let canonical = format_remzar(amount);

        let left = " \t\r\n".chars().cycle().take(left_count).collect::<String>();
        let right = "\n\r\t ".chars().cycle().take(right_count).collect::<String>();

        let with_outer_whitespace = format!("{left}{canonical}{right}");

        prop_assert_eq!(
            to_micro_units_str(&with_outer_whitespace),
            amount,
            "outer whitespace should be trimmed before deterministic amount parsing"
        );

        let with_internal_whitespace = canonical.replace('.', " .");

        prop_assert_eq!(
            to_micro_units_str(&with_internal_whitespace),
            0,
            "internal whitespace must be rejected"
        );
    }

    // 018/25
    #[test]
    fn format_remzar_splits_micro_units_into_exact_whole_and_fractional_parts(
        amount in any::<u64>(),
    ) {
        let formatted = format_remzar(amount);
        let (whole_str, frac_str) = formatted
            .split_once('.')
            .expect("format_remzar must include a decimal separator");

        let whole = whole_str
            .parse::<u64>()
            .expect("whole part emitted by formatter must parse");

        let frac = frac_str
            .parse::<u64>()
            .expect("fractional part emitted by formatter must parse");

        prop_assert_eq!(
            whole,
            amount / 100_000_000,
            "whole part must equal amount / 100_000_000"
        );

        prop_assert_eq!(
            frac,
            amount % 100_000_000,
            "fractional part must equal amount % 100_000_000"
        );

        prop_assert_eq!(
            frac_str.len(),
            8,
            "fractional part must always be zero-padded to 8 digits"
        );
    }

    // 019/25
    #[test]
    fn format_remzar_trim_removes_only_trailing_fractional_zeros_and_never_leaves_dot(
        amount in any::<u64>(),
    ) {
        let trimmed = format_remzar_trim(amount);

        prop_assert!(
            !trimmed.ends_with('.'),
            "trimmed REMZAR format must never leave a trailing decimal point"
        );

        if amount % 100_000_000 == 0 {
            prop_assert!(
                !trimmed.contains('.'),
                "whole REMZAR amounts should be emitted without fractional part"
            );
        } else {
            let (_whole, frac) = trimmed
                .split_once('.')
                .expect("non-whole micro-unit amount must keep a fractional part");

            prop_assert!(
                !frac.is_empty(),
                "non-whole trimmed amount must keep at least one fractional digit"
            );

            prop_assert!(
                !frac.ends_with('0'),
                "trimmed fractional part must remove trailing zeros"
            );

            prop_assert!(
                frac.len() <= 8,
                "trimmed fractional precision must never exceed 8 digits"
            );
        }
    }

    // 020/25
    #[test]
    fn to_micro_units_rejects_non_finite_zero_and_negative_ui_values(
        selector in 0u8..5u8,
        magnitude in 0u64..=1_000_000u64,
    ) {
        let amount = match selector {
            0 => f64::NAN,
            1 => f64::INFINITY,
            2 => f64::NEG_INFINITY,
            3 => 0.0,
            _ => -((magnitude as f64) + 1.0),
        };

        prop_assert_eq!(
            to_micro_units(amount),
            0,
            "UI float conversion must reject NaN, infinity, zero, and negative values"
        );
    }

    // 021/25
    #[test]
    fn canon_wallet_id_returns_trimmed_original_for_invalid_inputs(
        raw in ".{0,64}",
    ) {
        let input = format!(" \tbad_prefix_{raw}\n");
        let expected = input.trim().to_string();

        prop_assert!(
            canon_wallet_id_checked(&input).is_err(),
            "fallible canonicalizer must reject invalid wallet input"
        );

        prop_assert_eq!(
            canon_wallet_id(&input),
            expected,
            "non-fallible canonicalizer must return trimmed original text for invalid input"
        );
    }

    // 022/25
    #[test]
    fn parse_wallet_address_is_strict_lowercase_but_checked_canonicalizer_accepts_uppercase(
        upper_tail in "[0-9A-F]{128}",
    ) {
        let upper_wallet = format!("R{upper_tail}");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        prop_assert!(
            parse_wallet_address(&upper_wallet).is_err(),
            "strict wallet parser must reject uppercase prefix or body"
        );

        prop_assert_eq!(
            canon_wallet_id_checked(&upper_wallet).expect("checked canonicalizer should accept uppercase boundary input"),
            expected,
            "checked canonicalizer must normalize uppercase boundary input"
        );
    }

    // 023/25
    #[test]
    fn parse_wallet_address_bytes_rejects_wrong_length_and_invalid_utf8(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = valid_wallet_from_tail(&tail);
        let bytes = wallet.as_bytes();

        prop_assert!(
            parse_wallet_address_bytes(bytes).is_ok(),
            "valid exact canonical wallet bytes must parse"
        );

        prop_assert!(
            parse_wallet_address_bytes(&bytes[..REMZAR_WALLET_LEN - 1]).is_err(),
            "wallet byte parser must reject short byte slices"
        );

        let mut long = bytes.to_vec();
        long.push(b'0');

        prop_assert!(
            parse_wallet_address_bytes(&long).is_err(),
            "wallet byte parser must reject overlong byte slices"
        );

        let invalid_utf8 = vec![0xFFu8; REMZAR_WALLET_LEN];

        prop_assert!(
            parse_wallet_address_bytes(&invalid_utf8).is_err(),
            "wallet byte parser must reject invalid UTF-8 instead of lossy parsing"
        );
    }

    // 024/25
    #[test]
    fn wallet_id_matches_pubkey_bytes_checked_rejects_valid_shape_wrong_wallet(
        pk_bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let wallet = derive_wallet_id_from_pubkey_bytes(&pk_bytes);
        let mut tampered = wallet.into_bytes();

        tampered[1] = if tampered[1] == b'0' { b'1' } else { b'0' };

        let tampered_wallet = String::from_utf8(tampered)
            .expect("tampered wallet bytes should remain valid UTF-8");

        prop_assert!(
            parse_wallet_address(&tampered_wallet).is_ok(),
            "tampered wallet must still be syntactically canonical"
        );

        prop_assert!(
            wallet_id_matches_pubkey_bytes_checked(&tampered_wallet, &pk_bytes).is_err(),
            "wallet/pubkey match helper must reject a valid-shape wallet that does not match the pubkey commitment"
        );
    }

    // 025/25
    #[test]
    fn signature_wrapper_from_signature_and_postcard_roundtrip_preserve_exact_bytes(
        seed in any::<u8>(),
        fill in any::<u8>(),
    ) {
        let mut signature = [fill; ml_dsa_65::SIG_LEN];

        for (index, byte) in signature.iter_mut().enumerate() {
            *byte = seed
                .wrapping_add(fill)
                .wrapping_add((index % 251) as u8);
        }

        let wrapper = SignatureWrapper::from_signature(&signature);

        prop_assert_eq!(
            wrapper.as_bytes(),
            signature.as_slice(),
            "from_signature must preserve exact signature bytes"
        );

        let encoded = postcard::to_allocvec(&wrapper)
            .expect("SignatureWrapper should postcard-serialize");

        let decoded: SignatureWrapper = postcard::from_bytes(&encoded)
            .expect("SignatureWrapper should postcard-deserialize");

        prop_assert_eq!(
            decoded.as_bytes(),
            signature.as_slice(),
            "SignatureWrapper postcard roundtrip must preserve exact signature bytes"
        );

        let fixed = decoded
            .to_signature()
            .expect("decoded wrapper should convert back to fixed signature array");

        prop_assert_eq!(
            fixed.as_slice(),
            signature.as_slice(),
            "decoded wrapper fixed signature conversion must preserve exact bytes"
        );
    }
}
