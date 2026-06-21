// tests/proptests_s_05_send_remzar.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, from_micro_units, to_micro_units_str,
};

use std::collections::HashSet;

fn wallet_address(prefix: char, tail: &str) -> String {
    format!("r{prefix}{tail}")
}

fn cli_amount_to_micro_model(input: &str) -> Result<u64, &'static str> {
    let normalized = input.trim().replace(',', ".");
    let amount = to_micro_units_str(&normalized);

    if amount == 0 {
        Err("Invalid amount. Must be > 0 and have at most 8 decimals.")
    } else {
        Ok(amount)
    }
}

fn cli_wallet_model(input: &str) -> Result<String, String> {
    canon_wallet_id_checked(input).map_err(|e| format!("Invalid wallet address: {e}"))
}

fn total_amount_model(amount_each: u64, recipients_len: usize) -> Result<u64, &'static str> {
    let total = amount_each.saturating_mul(recipients_len as u64);

    if total == 0 {
        Err("Invalid total amount. Must be > 0.")
    } else {
        Ok(total)
    }
}

fn tx_hash_for_send_path(tx: &Transaction) -> [u8; 64] {
    let tx_kind = TxKind::Transfer(tx.clone());
    let tx_bytes = postcard::to_allocvec(&tx_kind)
        .expect("TxKind::Transfer should serialize in send-remzar path");

    RemzarHash::compute_bytes_hash(&tx_bytes)
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    #[test]
    fn amount_parser_accepts_valid_fixed_point_remzar_amounts(
        whole in 0u64..=1_000_000u64,
        frac in 0u64..100_000_000u64,
    ) {
        let amount = format!("{whole}.{frac:08}");
        let expected = whole
            .checked_mul(100_000_000)
            .and_then(|v| v.checked_add(frac))
            .expect("bounded test amount must not overflow");

        if expected == 0 {
            prop_assert!(
                cli_amount_to_micro_model(&amount).is_err(),
                "send-remzar CLI must reject zero amount"
            );
        } else {
            prop_assert_eq!(
                cli_amount_to_micro_model(&amount),
                Ok(expected),
                "send-remzar CLI amount parser must convert fixed-point REMZAR into micro-units"
            );
        }
    }

    #[test]
    fn amount_parser_treats_comma_as_decimal_separator(
        whole in 0u64..=1_000_000u64,
        frac in 1u64..100_000_000u64,
    ) {
        let dot_amount = format!("{whole}.{frac:08}");
        let comma_amount = format!("{whole},{frac:08}");

        prop_assert_eq!(
            cli_amount_to_micro_model(&comma_amount),
            cli_amount_to_micro_model(&dot_amount),
            "send-remzar CLI normalizes comma decimal separator to dot"
        );
    }

    #[test]
    fn amount_parser_rejects_zero_negative_scientific_plus_space_and_too_many_decimals(
        digits in "[0-9]{1,20}",
        frac_too_long in "[0-9]{9,16}",
    ) {
        let zero = "0";
        let zero_decimal = "0.00000000";
        let negative = format!("-{digits}");
        let positive = format!("+{digits}");
        let scientific = format!("{digits}e1");
        let internal_space = format!("{digits} {digits}");
        let too_many_decimals = format!("{digits}.{frac_too_long}");

        prop_assert!(
            cli_amount_to_micro_model(zero).is_err(),
            "zero amount must be rejected"
        );

        prop_assert!(
            cli_amount_to_micro_model(zero_decimal).is_err(),
            "zero decimal amount must be rejected"
        );

        prop_assert!(
            cli_amount_to_micro_model(&negative).is_err(),
            "negative amount must be rejected"
        );

        prop_assert!(
            cli_amount_to_micro_model(&positive).is_err(),
            "explicit plus amount must be rejected"
        );

        prop_assert!(
            cli_amount_to_micro_model(&scientific).is_err(),
            "scientific notation must be rejected"
        );

        prop_assert!(
            cli_amount_to_micro_model(&internal_space).is_err(),
            "amount with internal spaces must be rejected"
        );

        prop_assert!(
            cli_amount_to_micro_model(&too_many_decimals).is_err(),
            "amount with more than 8 decimals must be rejected"
        );
    }

    #[test]
    fn wallet_reader_model_canonicalizes_trimmed_uppercase_wallets(
        upper_tail in "[0-9A-F]{128}",
    ) {
        let raw = format!(" \tR{upper_tail}\n");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        let canonical = cli_wallet_model(&raw)
            .expect("send-remzar wallet reader should canonicalize trimmed uppercase wallet id");

        prop_assert_eq!(
            canonical.as_str(),
            expected.as_str(),
            "wallet input must be trimmed and canonicalized before send processing"
        );

        prop_assert_eq!(
            canonical.len(),
            REMZAR_WALLET_LEN,
            "canonical wallet must have fixed wallet length"
        );
    }

    #[test]
    fn wallet_reader_model_rejects_short_wrong_prefix_and_non_hex_wallets(
        short_tail in "[0-9a-f]{0,127}",
        valid_tail in "[0-9a-f]{128}",
    ) {
        let short = format!("r{short_tail}");
        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);

        prop_assert!(
            cli_wallet_model(&short).is_err(),
            "send-remzar wallet reader must reject short wallet ids"
        );

        prop_assert!(
            cli_wallet_model(&wrong_prefix).is_err(),
            "send-remzar wallet reader must reject wrong wallet prefix"
        );

        prop_assert!(
            cli_wallet_model(&non_hex).is_err(),
            "send-remzar wallet reader must reject non-hex wallet body"
        );
    }

    #[test]
    fn self_send_detection_must_happen_after_wallet_canonicalization(
        tail in "[0-9a-f]{128}",
    ) {
        let sender_raw = format!(" r{tail}\n");
        let recipient_raw = format!(" \tR{}\n", tail.to_ascii_uppercase());

        let sender = cli_wallet_model(&sender_raw)
            .expect("sender wallet should canonicalize");

        let recipient = cli_wallet_model(&recipient_raw)
            .expect("recipient wallet should canonicalize");

        prop_assert_eq!(
            sender.as_str(),
            recipient.as_str(),
            "same wallet written with different casing/whitespace must canonicalize to same id"
        );

        prop_assert!(
            sender == recipient,
            "send-remzar self-send guard must compare canonical wallet ids"
        );
    }

    #[test]
    fn total_amount_uses_saturating_multiplication_and_rejects_zero_total(
        amount_each in any::<u64>(),
        recipients_len in 1usize..=10usize,
    ) {
        let expected = amount_each.saturating_mul(recipients_len as u64);
        let actual = total_amount_model(amount_each, recipients_len);

        if expected == 0 {
            prop_assert!(
                actual.is_err(),
                "send-remzar must reject zero total amount"
            );
        } else {
            prop_assert_eq!(
                actual,
                Ok(expected),
                "send-remzar total amount must use saturating multiplication"
            );
        }
    }

    #[test]
    fn send_path_constructs_valid_transfer_txkind_for_single_recipient(
        sender_tail in "[0-9a-f]{127}",
        recipient_tail in "[0-9a-f]{127}",
        amount_each in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = wallet_address('0', &sender_tail);
        let recipient = wallet_address('1', &recipient_tail);

        let tx = Transaction::new(sender.clone(), recipient.clone(), amount_each)
            .expect("valid send-remzar sender, recipient, and amount should create tx");

        prop_assert!(
            tx.validate().is_ok(),
            "send-remzar-created transaction must validate"
        );

        let tx_kind = TxKind::Transfer(tx.clone());

        prop_assert!(
            tx_kind.validate().is_ok(),
            "send-remzar TxKind::Transfer must validate"
        );

        let encoded_a = postcard::to_allocvec(&tx_kind)
            .expect("TxKind::Transfer must serialize");

        let encoded_b = postcard::to_allocvec(&tx_kind)
            .expect("TxKind::Transfer must serialize deterministically");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "TxKind serialization must be deterministic for duplicate mempool/hash checks"
        );

        let hash_a = RemzarHash::compute_bytes_hash(&encoded_a);
        let hash_b = tx_hash_for_send_path(&tx);

        prop_assert_eq!(
            hash_a,
            hash_b,
            "send-remzar tx hash must be derived from canonical TxKind bytes"
        );

        prop_assert_eq!(
            hash_a.len(),
            64,
            "send-remzar tx hash must be 64 bytes"
        );
    }

    #[test]
    fn batch_send_model_constructs_one_valid_transaction_per_unique_recipient(
        shared_tail in "[0-9a-f]{127}",
        amount_each in 1u64..=1_000_000_000_000u64,
        recipient_count in 2usize..=10usize,
    ) {
        let sender = wallet_address('f', &shared_tail);
        let mut recipients = Vec::with_capacity(recipient_count);

        for i in 0..recipient_count {
            let prefix = match i {
                0 => '0',
                1 => '1',
                2 => '2',
                3 => '3',
                4 => '4',
                5 => '5',
                6 => '6',
                7 => '7',
                8 => '8',
                9 => '9',
                _ => unreachable!("recipient_count is capped at 10"),
            };

            recipients.push(wallet_address(prefix, &shared_tail));
        }

        prop_assert_eq!(
            recipients.len(),
            recipient_count,
            "test generator must create requested recipient count"
        );

        prop_assert!(
            recipients.iter().all(|r| r != &sender),
            "generated recipients must not include sender"
        );

        let unique_recipients = recipients.iter().collect::<HashSet<_>>();

        prop_assert_eq!(
            unique_recipients.len(),
            recipients.len(),
            "batch send recipients must be unique"
        );

        let total_amount = total_amount_model(amount_each, recipients.len())
            .expect("positive amount and non-empty recipients must produce positive total");

        prop_assert_eq!(
            total_amount,
            amount_each.saturating_mul(recipients.len() as u64),
            "batch total must equal amount_each saturating-mul recipient count"
        );

        let mut tx_hashes = HashSet::with_capacity(recipients.len());

        for recipient in recipients {
            let tx = Transaction::new(sender.clone(), recipient.clone(), amount_each)
                .expect("each generated batch transfer should construct");

            prop_assert!(
                tx.validate().is_ok(),
                "each generated batch transfer must validate"
            );

            let tx_kind = TxKind::Transfer(tx.clone());

            prop_assert!(
                tx_kind.validate().is_ok(),
                "each generated batch TxKind::Transfer must validate"
            );

            let tx_hash = tx_hash_for_send_path(&tx);

            prop_assert!(
                tx_hashes.insert(tx_hash),
                "unique batch recipients should produce unique transfer hashes"
            );
        }
    }

    #[test]
    fn displayed_amount_roundtrips_through_fixed_eight_decimal_format_for_bounded_values(
        amount_micro in 1u64..=1_000_000_000_000u64,
    ) {
        let displayed = format!("{:.8}", from_micro_units(amount_micro));

        prop_assert_eq!(
            cli_amount_to_micro_model(&displayed),
            Ok(amount_micro),
            "amount displayed with 8 decimals should parse back to the same micro-unit amount"
        );
    }
}
