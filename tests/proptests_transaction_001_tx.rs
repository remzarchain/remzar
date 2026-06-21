use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use postcard::to_allocvec;

use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::utility::helper::REMZAR_WALLET_LEN;

const UNIX_2000: u64 = 946_684_800;

fn wallet_address(prefix: char, tail: &str) -> String {
    format!("r{prefix}{tail}")
}

fn wallet_pair(left_tail: &str, right_tail: &str) -> (String, String) {
    let sender = wallet_address('0', left_tail);
    let receiver = wallet_address('1', right_tail);
    (sender, receiver)
}

fn tx_sender_string(tx: &Transaction) -> String {
    std::str::from_utf8(&tx.sender)
        .expect("transaction sender bytes should be valid UTF-8")
        .to_string()
}

fn tx_receiver_string(tx: &Transaction) -> String {
    std::str::from_utf8(&tx.receiver)
        .expect("transaction receiver bytes should be valid UTF-8")
        .to_string()
}

fn address_array(address: &str) -> [u8; REMZAR_WALLET_LEN] {
    let bytes = address.as_bytes();
    assert_eq!(bytes.len(), REMZAR_WALLET_LEN);

    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(bytes);
    out
}

fn raw_wire_bytes(tx: &Transaction) -> Vec<u8> {
    to_allocvec(tx).expect("raw postcard encoding should succeed for fixed transaction struct")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_accepts_valid_distinct_wallet_addresses_and_positive_micro_amount(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender.clone(), receiver.clone(), amount)
            .expect("valid distinct canonical wallet addresses and positive amount should create tx");

        prop_assert!(
            tx.validate().is_ok(),
            "new transaction must validate"
        );

        prop_assert_eq!(
            tx.amount,
            amount,
            "transaction must preserve micro-unit amount"
        );

        prop_assert_eq!(
            tx.sender.len(),
            REMZAR_WALLET_LEN,
            "sender byte array must have fixed wallet length"
        );

        prop_assert_eq!(
            tx.receiver.len(),
            REMZAR_WALLET_LEN,
            "receiver byte array must have fixed wallet length"
        );

        prop_assert_eq!(
            tx_sender_string(&tx),
            sender,
            "stored sender bytes must preserve canonical sender address"
        );

        prop_assert_eq!(
            tx_receiver_string(&tx),
            receiver,
            "stored receiver bytes must preserve canonical receiver address"
        );

        prop_assert!(
            tx.timestamp > 0,
            "transaction timestamp should be a positive Unix timestamp"
        );
    }

    // 02/25
    #[test]
    fn test_002_new_rejects_zero_amount(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        prop_assert!(
            Transaction::new(sender, receiver, 0).is_err(),
            "transaction constructor must reject zero amount"
        );
    }

    // 03/25
    #[test]
    fn test_003_new_rejects_same_sender_and_receiver(
        tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let address = wallet_address('0', &tail);

        prop_assert!(
            Transaction::new(address.clone(), address, amount).is_err(),
            "transaction constructor must reject same sender and receiver"
        );
    }

    // 04/25
    #[test]
    fn test_004_new_rejects_short_or_malformed_wallet_addresses(
        short_tail in "[0-9a-f]{0,126}",
        valid_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let short_sender = wallet_address('0', &short_tail);
        let valid_receiver = wallet_address('1', &valid_tail);

        prop_assert!(
            Transaction::new(short_sender, valid_receiver.clone(), amount).is_err(),
            "transaction constructor must reject short sender address"
        );

        let malformed_sender = format!("rz{valid_tail}");

        prop_assert_eq!(
            malformed_sender.len(),
            REMZAR_WALLET_LEN,
            "malformed address should still have canonical length so this tests hex validation"
        );

        prop_assert!(
            Transaction::new(malformed_sender, valid_receiver, amount).is_err(),
            "transaction constructor must reject malformed non-hex wallet address"
        );
    }

    // 05/25
    #[test]
    fn test_005_new_from_remzar_converts_to_micro_units_for_bounded_exact_amounts(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        micros in 1u64..=10_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);
        let amount_remzar = micros as f64 / 100_000_000.0;

        let tx = Transaction::new_from_remzar(sender, receiver, amount_remzar)
            .expect("bounded positive REMZAR amount should create tx");

        prop_assert_eq!(
            tx.amount,
            micros,
            "new_from_remzar must convert fixed 8-decimal REMZAR amount into exact micro-units"
        );

        prop_assert!(
            tx.validate().is_ok(),
            "transaction created from REMZAR amount must validate"
        );
    }

    // 06/25
    #[test]
    fn test_006_new_from_remzar_rejects_non_positive_or_non_finite_amounts(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        negative in -1_000_000.0f64..0.0f64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        prop_assert!(
            Transaction::new_from_remzar(sender.clone(), receiver.clone(), 0.0).is_err(),
            "new_from_remzar must reject zero"
        );

        prop_assert!(
            Transaction::new_from_remzar(sender.clone(), receiver.clone(), negative).is_err(),
            "new_from_remzar must reject negative amounts"
        );

        prop_assert!(
            Transaction::new_from_remzar(sender.clone(), receiver.clone(), f64::NAN).is_err(),
            "new_from_remzar must reject NaN"
        );

        prop_assert!(
            Transaction::new_from_remzar(sender, receiver, f64::INFINITY).is_err(),
            "new_from_remzar must reject infinity"
        );
    }

    // 07/25
    #[test]
    fn test_007_serialize_deserialize_roundtrip_preserves_valid_transaction(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        let encoded = tx.serialize()
            .expect("valid transaction should serialize");

        let decoded = Transaction::deserialize(&encoded)
            .expect("serialized valid transaction should deserialize");

        prop_assert_eq!(
            &decoded,
            &tx,
            "transaction serialization roundtrip must preserve all fields"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "deserialized transaction must validate"
        );
    }

    // 08/25
    #[test]
    fn test_008_deserialize_rejects_truncated_serialized_transaction(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
        keep_seed in any::<usize>(),
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        let encoded = tx.serialize()
            .expect("valid transaction should serialize");

        prop_assert!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            Transaction::deserialize(truncated).is_err(),
            "transaction deserializer must reject truncated serialized bytes"
        );
    }

    // 09/25
    #[test]
    fn test_009_deserialize_rejects_wire_transaction_with_zero_amount(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        tx.amount = 0;

        prop_assert!(
            tx.serialize().is_err(),
            "validated serializer must not emit malformed zero-amount transactions"
        );

        let encoded = raw_wire_bytes(&tx);

        prop_assert!(
            Transaction::deserialize(&encoded).is_err(),
            "transaction deserializer must reject raw wire tx with zero amount"
        );
    }

    // 10/25
    #[test]
    fn test_010_deserialize_rejects_wire_transaction_with_same_sender_and_receiver(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        tx.receiver = tx.sender;

        prop_assert!(
            tx.serialize().is_err(),
            "validated serializer must not emit malformed same-party transactions"
        );

        let encoded = raw_wire_bytes(&tx);

        prop_assert!(
            Transaction::deserialize(&encoded).is_err(),
            "transaction deserializer must reject raw wire tx with same sender and receiver"
        );
    }

    // 11/25
    #[test]
    fn test_011_transaction_id_is_deterministic_and_input_sensitive(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        let id_a = tx.id()
            .expect("transaction id should compute");

        let id_b = tx.id()
            .expect("transaction id should be deterministic");

        prop_assert_eq!(
            &id_a,
            &id_b,
            "transaction id must be deterministic for unchanged transaction"
        );

        prop_assert_eq!(
            id_a.len(),
            64,
            "transaction id uses default BLAKE3 hex length of 64 chars"
        );

        let mut changed = tx.clone();
        changed.amount = changed.amount.saturating_add(1);

        let changed_id = changed.id()
            .expect("changed transaction id should compute");

        prop_assert_ne!(
            &id_a,
            &changed_id,
            "transaction id should change when serialized transaction contents change"
        );
    }

    // 12/25
    #[test]
    fn test_012_new_canonicalizes_uppercase_and_whitespace_wallet_addresses(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let canonical_sender = wallet_address('0', &left_tail);
        let canonical_receiver = wallet_address('1', &right_tail);

        let messy_sender = format!(" \t{}\n", canonical_sender.to_ascii_uppercase());
        let messy_receiver = format!("\n{}\t ", canonical_receiver.to_ascii_uppercase());

        let tx = Transaction::new(messy_sender, messy_receiver, amount)
            .expect("constructor should canonicalize uppercase/whitespace wallet inputs");

        prop_assert_eq!(
            tx_sender_string(&tx),
            canonical_sender,
            "sender must be stored in canonical lowercase form"
        );

        prop_assert_eq!(
            tx_receiver_string(&tx),
            canonical_receiver,
            "receiver must be stored in canonical lowercase form"
        );

        prop_assert!(
            tx.validate().is_ok(),
            "canonicalized transaction must validate"
        );
    }

    // 13/25
    #[test]
    fn test_013_new_rejects_same_address_after_canonicalization(
        tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let canonical = wallet_address('0', &tail);
        let uppercase_same = canonical.to_ascii_uppercase();

        prop_assert!(
            Transaction::new(canonical, uppercase_same, amount).is_err(),
            "constructor must reject same sender/receiver even when one side needs canonicalization"
        );
    }

    // 14/25
    #[test]
    fn test_014_new_rejects_wrong_wallet_prefix(
        body in "[0-9a-f]{128}",
        valid_tail in "[0-9a-f]{127}",
        wrong_prefix in "[A-QS-Z0-9]",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = format!("{wrong_prefix}{body}");
        let receiver = wallet_address('1', &valid_tail);

        prop_assert_eq!(
            sender.len(),
            REMZAR_WALLET_LEN,
            "wrong-prefix sender should still have wallet length"
        );

        prop_assert!(
            Transaction::new(sender, receiver, amount).is_err(),
            "constructor must reject wallet address with wrong prefix"
        );
    }

    // 15/25
    #[test]
    fn test_015_new_rejects_too_long_wallet_address(
        valid_tail in "[0-9a-f]{127}",
        extra in "[0-9a-f]{1,32}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = format!("r0{valid_tail}{extra}");
        let receiver = wallet_address('1', &valid_tail);

        prop_assert!(
            sender.len() > REMZAR_WALLET_LEN,
            "test setup must create an overlong sender"
        );

        prop_assert!(
            Transaction::new(sender, receiver, amount).is_err(),
            "constructor must reject overlong wallet address"
        );
    }

    // 16/25
    #[test]
    fn test_016_new_from_aos_alias_matches_new_from_remzar_amount_conversion(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        micros in 1u64..=10_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);
        let amount_remzar = micros as f64 / 100_000_000.0;

        let from_remzar = Transaction::new_from_remzar(
            sender.clone(),
            receiver.clone(),
            amount_remzar,
        )
        .expect("new_from_remzar should accept bounded amount");

        let from_aos = Transaction::new_from_aos(sender, receiver, amount_remzar)
            .expect("new_from_aos alias should accept bounded amount");

        prop_assert_eq!(
            from_aos.amount,
            from_remzar.amount,
            "new_from_aos must preserve new_from_remzar micro-unit conversion"
        );

        prop_assert_eq!(
            from_aos.amount,
            micros,
            "new_from_aos must convert exact bounded amount into micro-units"
        );
    }

    // 17/25
    #[test]
    fn test_017_amount_aliases_are_consistent_for_bounded_micro_amounts(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        micros in 1u64..=10_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, micros)
            .expect("valid transaction should construct");

        prop_assert_eq!(
            tx.amount_as_remzar(),
            tx.amount_as_aos(),
            "amount_as_aos must remain an alias of amount_as_remzar"
        );

        prop_assert!(
            tx.amount_as_remzar() > 0.0,
            "positive micro-unit amount must convert to positive REMZAR display amount"
        );
    }

    // 18/25
    #[test]
    fn test_018_serialize_is_deterministic_for_unchanged_transaction(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        let encoded_a = tx.serialize()
            .expect("first serialization should succeed");

        let encoded_b = tx.serialize()
            .expect("second serialization should succeed");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "serializing the same transaction twice must produce identical bytes"
        );

        prop_assert!(
            !encoded_a.is_empty(),
            "serialized transaction must not be empty"
        );
    }

    // 19/25
    #[test]
    fn test_019_deserialize_rejects_serialized_transaction_with_trailing_bytes(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
        extra in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        let mut encoded = tx.serialize()
            .expect("valid transaction should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            Transaction::deserialize(&encoded).is_err(),
            "transaction deserializer must reject trailing bytes after a valid transaction payload"
        );
    }

    // 20/25
    #[test]
    fn test_020_deserialize_rejects_wire_transaction_with_noncanonical_uppercase_sender_bytes(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        tx.sender[0] = b'R';

        prop_assert!(
            tx.serialize().is_err(),
            "validated serializer must not emit noncanonical uppercase sender bytes"
        );

        let encoded = raw_wire_bytes(&tx);

        prop_assert!(
            Transaction::deserialize(&encoded).is_err(),
            "wire transaction with noncanonical uppercase sender prefix must be rejected"
        );
    }

    // 21/25
    #[test]
    fn test_021_deserialize_rejects_wire_transaction_with_nul_address_byte(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
        index in 0usize..REMZAR_WALLET_LEN,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        tx.receiver[index] = 0;

        prop_assert!(
            tx.serialize().is_err(),
            "validated serializer must not emit wallet bytes containing NUL"
        );

        let encoded = raw_wire_bytes(&tx);

        prop_assert!(
            Transaction::deserialize(&encoded).is_err(),
            "wire transaction with NUL byte inside wallet address must be rejected"
        );
    }

    // 22/25
    #[test]
    fn test_022_transaction_id_changes_when_timestamp_changes(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        let id_before = tx.id()
            .expect("transaction id should compute");

        let mut changed = tx.clone();
        changed.timestamp = changed.timestamp.saturating_add(1);

        let id_after = changed.id()
            .expect("changed timestamp transaction id should compute");

        prop_assert_ne!(
            &id_before,
            &id_after,
            "transaction id must change when timestamp changes"
        );
    }

    // 23/25
    #[test]
    fn test_023_transaction_id_changes_when_sender_changes_to_another_valid_wallet(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transaction should construct");

        let id_before = tx.id()
            .expect("transaction id should compute");

        let mut changed = tx.clone();
        let alternate_sender = wallet_address('2', &left_tail);
        changed.sender = address_array(&alternate_sender);

        prop_assert!(
            changed.validate().is_ok(),
            "sender-mutated transaction must remain structurally valid"
        );

        let id_after = changed.id()
            .expect("changed sender transaction id should compute");

        prop_assert_ne!(
            &id_before,
            &id_after,
            "transaction id must change when sender changes"
        );
    }

    // 24/25
    #[test]
    fn test_024_deserialize_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Transaction::deserialize(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "Transaction::deserialize must never panic for arbitrary external bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_validate_rejects_manual_zero_amount_and_accepts_manual_valid_arrays(
        left_tail in "[0-9a-f]{127}",
        right_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let (sender, receiver) = wallet_pair(&left_tail, &right_tail);

        let tx = Transaction {
            sender: address_array(&sender),
            receiver: address_array(&receiver),
            amount,
            timestamp: UNIX_2000,
        };

        prop_assert!(
            tx.validate().is_ok(),
            "manual transaction with valid canonical arrays, positive amount, and structural timestamp must validate"
        );

        let mut zero_amount = tx.clone();
        zero_amount.amount = 0;

        prop_assert!(
            zero_amount.validate().is_err(),
            "manual transaction with zero amount must fail validation"
        );
    }
}
