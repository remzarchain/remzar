// tests/proptests_transaction_002_tx_register.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use postcard::to_allocvec;

use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::utility::helper::REMZAR_WALLET_LEN;

const UNIX_2000: u64 = 946_684_800;
const TEN_YEARS_SECS: u64 = 3600 * 24 * 365 * 10;

fn wallet_from_tail(tail: &str) -> String {
    format!("r{tail}")
}

fn wallet_array(wallet: &str) -> [u8; REMZAR_WALLET_LEN] {
    let bytes = wallet.as_bytes();
    assert_eq!(bytes.len(), REMZAR_WALLET_LEN);

    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(bytes);
    out
}

fn valid_manual_register(wallet: &str, timestamp: u64) -> RegisterNodeTx {
    RegisterNodeTx {
        wallet_address: wallet_array(wallet),
        timestamp,
    }
}

fn raw_postcard_wire(tx: &RegisterNodeTx) -> Vec<u8> {
    to_allocvec(tx).expect("raw postcard serialization should encode the public test struct")
}

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp())
        .unwrap_or(UNIX_2000)
        .max(UNIX_2000)
}

fn far_future_timestamp() -> Option<u64> {
    now_secs()
        .checked_add(TEN_YEARS_SECS)
        .and_then(|v| v.checked_add(1))
}

fn register_wallet_string(tx: &RegisterNodeTx) -> String {
    std::str::from_utf8(&tx.wallet_address)
        .expect("register wallet bytes should be valid UTF-8")
        .to_string()
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_accepts_valid_wallet_and_stores_canonical_lowercase_address(
        upper_tail in "[0-9A-F]{128}",
    ) {
        let raw_wallet = format!(" \tR{upper_tail}\n");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        let tx = RegisterNodeTx::new(raw_wallet)
            .expect("RegisterNodeTx::new should accept canonicalizable wallet strings");

        prop_assert_eq!(
            register_wallet_string(&tx),
            expected,
            "RegisterNodeTx::new must store canonical lowercase wallet bytes"
        );

        prop_assert_eq!(
            tx.wallet_address.len(),
            REMZAR_WALLET_LEN,
            "RegisterNodeTx wallet address must have fixed wallet byte length"
        );

        prop_assert!(
            tx.validate().is_ok(),
            "fresh RegisterNodeTx::new output must validate"
        );

        prop_assert!(
            tx.timestamp >= UNIX_2000,
            "RegisterNodeTx::new timestamp must be structurally valid"
        );
    }

    // 02/25
    #[test]
    fn test_002_new_rejects_short_wrong_prefix_and_non_hex_wallets(
        short_tail in "[0-9a-f]{0,127}",
        valid_tail in "[0-9a-f]{128}",
    ) {
        let short = wallet_from_tail(&short_tail);
        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);

        prop_assert!(
            RegisterNodeTx::new(short).is_err(),
            "RegisterNodeTx::new must reject short wallet address"
        );

        prop_assert!(
            RegisterNodeTx::new(wrong_prefix).is_err(),
            "RegisterNodeTx::new must reject wrong wallet prefix"
        );

        prop_assert!(
            RegisterNodeTx::new(non_hex).is_err(),
            "RegisterNodeTx::new must reject non-hex wallet body"
        );
    }

    // 03/25
    #[test]
    fn test_003_new_from_bytes_accepts_canonical_wallet_and_trailing_nul_padding(
        tail in "[0-9a-f]{128}",
        pad_len in 0usize..32usize,
    ) {
        let wallet = wallet_from_tail(&tail);

        let tx = RegisterNodeTx::new_from_bytes(wallet.as_bytes())
            .expect("new_from_bytes should accept canonical wallet bytes");

        let tx_wallet = register_wallet_string(&tx);

        prop_assert_eq!(
            tx_wallet.as_str(),
            wallet.as_str(),
            "new_from_bytes must preserve canonical wallet bytes"
        );

        let mut padded = wallet.as_bytes().to_vec();
        padded.extend(std::iter::repeat_n(0u8, pad_len));

        let padded_tx = RegisterNodeTx::new_from_bytes(&padded)
            .expect("new_from_bytes should accept trailing NUL padding");

        let padded_wallet = register_wallet_string(&padded_tx);

        prop_assert_eq!(
            padded_wallet.as_str(),
            wallet.as_str(),
            "new_from_bytes must trim trailing NUL padding and preserve wallet"
        );
    }

    // 04/25
    #[test]
    fn test_004_new_from_bytes_rejects_embedded_nul_non_utf8_wrong_prefix_and_non_hex(
        valid_tail in "[0-9a-f]{128}",
        nul_index in 0usize..REMZAR_WALLET_LEN,
    ) {
        let wallet = wallet_from_tail(&valid_tail);

        let mut embedded_nul = wallet.clone().into_bytes();
        embedded_nul[nul_index] = 0;

        prop_assert!(
            RegisterNodeTx::new_from_bytes(&embedded_nul).is_err(),
            "new_from_bytes must reject embedded NUL bytes"
        );

        let mut non_utf8 = wallet.clone().into_bytes();
        non_utf8[nul_index] = 0xFF;

        prop_assert!(
            RegisterNodeTx::new_from_bytes(&non_utf8).is_err(),
            "new_from_bytes must reject non-UTF8 wallet bytes"
        );

        let wrong_prefix = format!("p{valid_tail}");

        prop_assert!(
            RegisterNodeTx::new_from_bytes(wrong_prefix.as_bytes()).is_err(),
            "new_from_bytes must reject wrong prefix"
        );

        let non_hex = format!("rz{}", &valid_tail[1..]);

        prop_assert!(
            RegisterNodeTx::new_from_bytes(non_hex.as_bytes()).is_err(),
            "new_from_bytes must reject non-hex wallet body"
        );
    }

    // 05/25
    #[test]
    fn test_005_validate_accepts_manual_valid_register_tx(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let tx = valid_manual_register(&wallet, UNIX_2000);

        prop_assert!(
            tx.validate().is_ok(),
            "manual RegisterNodeTx with canonical wallet and UNIX_2000 timestamp must validate"
        );

        prop_assert_eq!(
            tx.wallet_str().expect("wallet_str should return valid UTF-8"),
            wallet.as_str(),
            "wallet_str must expose canonical wallet"
        );
    }

    // 06/25
    #[test]
    fn test_006_validate_rejects_timestamp_before_2000_but_future_skew_is_mempool_only(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);

        let old = valid_manual_register(&wallet, UNIX_2000.saturating_sub(1));

        prop_assert!(
            old.validate().is_err(),
            "replay-safe validate must reject timestamps before 2000-01-01"
        );

        if let Some(future_ts) = far_future_timestamp() {
            let future = valid_manual_register(&wallet, future_ts);
            let now = now_secs();

            prop_assert!(
                future.validate().is_ok(),
                "replay-safe validate must not reject structurally valid timestamps based on local future skew"
            );

            prop_assert!(
                future.validate_for_mempool_at(now).is_err(),
                "runtime mempool validation must reject timestamps beyond allowed future skew"
            );
        }
    }

    // 07/25
    #[test]
    fn test_007_validate_rejects_noncanonical_or_corrupt_stored_wallet_bytes(
        tail in "[0-9a-f]{128}",
        index in 0usize..REMZAR_WALLET_LEN,
    ) {
        let wallet = wallet_from_tail(&tail);

        let mut uppercase_prefix = valid_manual_register(&wallet, UNIX_2000);
        uppercase_prefix.wallet_address[0] = b'R';

        prop_assert!(
            uppercase_prefix.validate().is_err(),
            "validate must reject noncanonical uppercase prefix in stored bytes"
        );

        let mut wrong_prefix = valid_manual_register(&wallet, UNIX_2000);
        wrong_prefix.wallet_address[0] = b'p';

        prop_assert!(
            wrong_prefix.validate().is_err(),
            "validate must reject wrong prefix in stored bytes"
        );

        let mut non_hex = valid_manual_register(&wallet, UNIX_2000);
        non_hex.wallet_address[1] = b'g';

        prop_assert!(
            non_hex.validate().is_err(),
            "validate must reject non-hex wallet body in stored bytes"
        );

        let mut nul_byte = valid_manual_register(&wallet, UNIX_2000);
        nul_byte.wallet_address[index] = 0;

        prop_assert!(
            nul_byte.validate().is_err(),
            "validate must reject embedded NUL in stored wallet bytes"
        );

        let mut non_utf8 = valid_manual_register(&wallet, UNIX_2000);
        non_utf8.wallet_address[index] = 0xFF;

        prop_assert!(
            non_utf8.validate().is_err(),
            "validate must reject non-UTF8 stored wallet bytes"
        );
    }

    // 08/25
    #[test]
    fn test_008_serialize_deserialize_roundtrip_preserves_valid_register_tx(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let tx = valid_manual_register(&wallet, UNIX_2000);

        let encoded = tx.serialize()
            .expect("valid RegisterNodeTx should serialize");

        let decoded = RegisterNodeTx::deserialize(&encoded)
            .expect("serialized valid RegisterNodeTx should deserialize");

        prop_assert_eq!(
            &decoded,
            &tx,
            "RegisterNodeTx serialization roundtrip must preserve all fields"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "deserialized valid RegisterNodeTx must validate"
        );
    }

    // 09/25
    #[test]
    fn test_009_deserialize_rejects_empty_and_truncated_wire(
        tail in "[0-9a-f]{128}",
        keep_seed in any::<usize>(),
    ) {
        prop_assert!(
            RegisterNodeTx::deserialize(&[]).is_err(),
            "deserialize must reject empty wire payload"
        );

        let wallet = wallet_from_tail(&tail);
        let tx = valid_manual_register(&wallet, UNIX_2000);

        let encoded = tx.serialize()
            .expect("valid RegisterNodeTx should serialize");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            RegisterNodeTx::deserialize(truncated).is_err(),
            "deserialize must reject truncated postcard bytes"
        );
    }

    // 10/25
    #[test]
    fn test_010_deserialize_rejects_wire_with_invalid_wallet_bytes(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);

        let mut wrong_prefix = valid_manual_register(&wallet, UNIX_2000);
        wrong_prefix.wallet_address[0] = b'p';

        let wrong_prefix_wire = raw_postcard_wire(&wrong_prefix);

        prop_assert!(
            RegisterNodeTx::deserialize(&wrong_prefix_wire).is_err(),
            "deserialize must reject wire tx with wrong wallet prefix"
        );

        let mut non_hex = valid_manual_register(&wallet, UNIX_2000);
        non_hex.wallet_address[1] = b'g';

        let non_hex_wire = raw_postcard_wire(&non_hex);

        prop_assert!(
            RegisterNodeTx::deserialize(&non_hex_wire).is_err(),
            "deserialize must reject wire tx with non-hex wallet body"
        );
    }

    // 11/25
    #[test]
    fn test_011_deserialize_rejects_structurally_invalid_timestamp_but_not_mempool_future_skew(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);

        let old = valid_manual_register(&wallet, UNIX_2000.saturating_sub(1));
        let old_wire = raw_postcard_wire(&old);

        prop_assert!(
            RegisterNodeTx::deserialize(&old_wire).is_err(),
            "deserialize must reject wire tx with timestamp before 2000"
        );

        if let Some(future_ts) = far_future_timestamp() {
            let future = valid_manual_register(&wallet, future_ts);
            let future_wire = raw_postcard_wire(&future);

            prop_assert!(
                RegisterNodeTx::deserialize(&future_wire).is_ok(),
                "replay-safe deserialize must accept structurally valid future timestamps"
            );

            prop_assert!(
                RegisterNodeTx::deserialize_for_mempool(&future_wire).is_err(),
                "mempool deserialize must reject timestamps beyond runtime future skew"
            );
        }
    }

    // 12/25
    #[test]
    fn test_012_deserialize_rejects_nonzero_trailing_bytes_after_valid_register_wire(
        tail in "[0-9a-f]{128}",
        extra in proptest::collection::vec(1u8..=255u8, 1..16),
    ) {
        let wallet = wallet_from_tail(&tail);
        let tx = valid_manual_register(&wallet, UNIX_2000);

        let mut encoded = tx.serialize()
            .expect("valid RegisterNodeTx should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            RegisterNodeTx::deserialize(&encoded).is_err(),
            "deserialize must reject nonzero trailing bytes after a valid RegisterNodeTx payload"
        );
    }

    // 13/25
    #[test]
    fn test_013_wallet_str_returns_error_for_non_utf8_wallet_bytes(
        tail in "[0-9a-f]{128}",
        index in 0usize..REMZAR_WALLET_LEN,
    ) {
        let wallet = wallet_from_tail(&tail);

        let mut tx = valid_manual_register(&wallet, UNIX_2000);
        tx.wallet_address[index] = 0xFF;

        prop_assert!(
            tx.wallet_str().is_err(),
            "wallet_str must reject non-UTF8 wallet bytes"
        );
    }

    // 14/25
    #[test]
    fn test_014_many_unique_wallets_produce_unique_register_wires(
        shared_tail in "[0-9a-f]{127}",
    ) {
        let mut wires = std::collections::BTreeSet::new();

        for i in 0u32..10u32 {
            let prefix = char::from_digit(i, 16)
                .expect("0..10 must be valid hex digit");

            let wallet = format!("r{prefix}{shared_tail}");
            let tx = valid_manual_register(&wallet, UNIX_2000.saturating_add(i as u64));

            prop_assert!(
                tx.validate().is_ok(),
                "generated register tx must validate"
            );

            let wire = tx.serialize()
                .expect("generated register tx should serialize");

            prop_assert!(
                wires.insert(wire),
                "unique wallet/timestamp register txs must produce unique wires"
            );
        }

        prop_assert_eq!(
            wires.len(),
            10,
            "test must produce ten unique serialized register txs"
        );
    }

    // 15/25
    #[test]
    fn test_015_deserialize_rejects_zero_trailing_bytes_after_valid_register_wire(
        tail in "[0-9a-f]{128}",
        extra_len in 1usize..16usize,
    ) {
        let wallet = wallet_from_tail(&tail);
        let tx = valid_manual_register(&wallet, UNIX_2000);

        let mut encoded = tx.serialize()
            .expect("valid RegisterNodeTx should serialize");

        encoded.extend(std::iter::repeat_n(0u8, extra_len));

        prop_assert!(
            RegisterNodeTx::deserialize(&encoded).is_err(),
            "deserialize must reject zero trailing bytes after a valid RegisterNodeTx payload"
        );
    }

    // 16/25
    #[test]
    fn test_016_serialize_is_deterministic_for_unchanged_register_tx(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let tx = valid_manual_register(&wallet, UNIX_2000);

        let encoded_a = tx.serialize()
            .expect("first RegisterNodeTx serialization should succeed");

        let encoded_b = tx.serialize()
            .expect("second RegisterNodeTx serialization should succeed");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "serializing the same RegisterNodeTx twice must produce identical bytes"
        );

        prop_assert!(
            !encoded_a.is_empty(),
            "serialized RegisterNodeTx must not be empty"
        );
    }

    // 17/25
    #[test]
    fn test_017_deserialize_canonicalizes_uppercase_wallet_bytes_from_wire(
        tail in "[0-9a-f]{128}",
    ) {
        let canonical_wallet = wallet_from_tail(&tail);
        let uppercase_wallet = canonical_wallet.to_ascii_uppercase();

        let mut tx = valid_manual_register(&canonical_wallet, UNIX_2000);
        tx.wallet_address = wallet_array(&uppercase_wallet);

        let encoded = raw_postcard_wire(&tx);

        let decoded = RegisterNodeTx::deserialize(&encoded)
            .expect("deserialize should canonicalize uppercase wallet bytes from wire");

        let decoded_wallet = register_wallet_string(&decoded);

        prop_assert_eq!(
            decoded_wallet.as_str(),
            canonical_wallet.as_str(),
            "deserialize must canonicalize uppercase wallet bytes into lowercase stored bytes"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "canonicalized decoded RegisterNodeTx must validate"
        );
    }

    // 18/25
    #[test]
    fn test_018_new_from_bytes_canonicalizes_uppercase_and_surrounding_whitespace(
        upper_tail in "[0-9A-F]{128}",
    ) {
        let raw = format!(" \tR{upper_tail}\n");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        let tx = RegisterNodeTx::new_from_bytes(raw.as_bytes())
            .expect("new_from_bytes should canonicalize uppercase/whitespace wallet bytes");

        let tx_wallet = register_wallet_string(&tx);

        prop_assert_eq!(
            tx_wallet.as_str(),
            expected.as_str(),
            "new_from_bytes must store canonical lowercase wallet bytes"
        );

        prop_assert!(
            tx.validate().is_ok(),
            "new_from_bytes canonicalized output must validate"
        );
    }

    // 19/25
    #[test]
    fn test_019_validate_rejects_uppercase_wallet_body_even_with_lowercase_prefix(
        tail in "[0-9a-f]{127}",
    ) {
        let canonical_wallet = format!("ra{tail}");
        let uppercase_body_wallet = format!("rA{}", tail.to_ascii_uppercase());

        let mut tx = valid_manual_register(&canonical_wallet, UNIX_2000);
        tx.wallet_address = wallet_array(&uppercase_body_wallet);

        prop_assert!(
            tx.validate().is_err(),
            "validate must reject uppercase hex body because stored bytes are not canonical lowercase"
        );
    }

    // 20/25
    #[test]
    fn test_020_new_from_bytes_rejects_all_nul_and_empty_after_padding_trim(
        pad_len in 0usize..64usize,
    ) {
        let bytes = vec![0u8; pad_len];

        prop_assert!(
            RegisterNodeTx::new_from_bytes(&bytes).is_err(),
            "new_from_bytes must reject empty wallet bytes after trimming trailing NUL padding"
        );
    }

    // 21/25
    #[test]
    fn test_021_deserialize_rejects_wire_with_embedded_nul_wallet_byte(
        tail in "[0-9a-f]{128}",
        index in 0usize..REMZAR_WALLET_LEN,
    ) {
        let wallet = wallet_from_tail(&tail);

        let mut tx = valid_manual_register(&wallet, UNIX_2000);
        tx.wallet_address[index] = 0;

        let encoded = raw_postcard_wire(&tx);

        prop_assert!(
            RegisterNodeTx::deserialize(&encoded).is_err(),
            "deserialize must reject wire tx with embedded NUL wallet byte"
        );
    }

    // 22/25
    #[test]
    fn test_022_validate_accepts_current_and_ten_year_boundary_timestamps(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let now = now_secs();

        let current = valid_manual_register(&wallet, now);

        prop_assert!(
            current.validate().is_ok(),
            "validate must accept current timestamp"
        );

        if let Some(boundary) = now.checked_add(TEN_YEARS_SECS) {
            let boundary_tx = valid_manual_register(&wallet, boundary);

            prop_assert!(
                boundary_tx.validate().is_ok(),
                "replay-safe validate must accept structurally valid future timestamps"
            );
        }
    }

    // 23/25
    #[test]
    fn test_023_same_wallet_different_valid_timestamps_produce_distinct_wires(
        tail in "[0-9a-f]{128}",
        offset in 1u64..1_000_000u64,
    ) {
        let wallet = wallet_from_tail(&tail);

        let tx_a = valid_manual_register(&wallet, UNIX_2000);
        let tx_b = valid_manual_register(&wallet, UNIX_2000.saturating_add(offset));

        prop_assert!(
            tx_a.validate().is_ok(),
            "first timestamped register tx must validate"
        );

        prop_assert!(
            tx_b.validate().is_ok(),
            "second timestamped register tx must validate"
        );

        let wire_a = tx_a.serialize()
            .expect("first register tx should serialize");

        let wire_b = tx_b.serialize()
            .expect("second register tx should serialize");

        prop_assert_ne!(
            &wire_a,
            &wire_b,
            "same wallet with different timestamps must produce distinct serialized wires"
        );
    }

    // 24/25
    #[test]
    fn test_024_deserialize_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RegisterNodeTx::deserialize(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "RegisterNodeTx::deserialize must never panic for arbitrary external bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_wallet_str_returns_exact_canonical_wallet_for_valid_manual_register(
        tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&tail);
        let tx = valid_manual_register(&wallet, UNIX_2000);

        prop_assert_eq!(
            tx.wallet_str()
                .expect("wallet_str should succeed for canonical wallet bytes"),
            wallet.as_str(),
            "wallet_str must return the exact canonical wallet string"
        );

        prop_assert!(
            tx.validate().is_ok(),
            "wallet_str success case should also validate"
        );
    }
}
