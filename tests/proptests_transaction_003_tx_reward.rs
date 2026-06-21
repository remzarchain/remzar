// tests/proptests_transaction_003_tx_reward.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::{REMZAR_WALLET_LEN, from_micro_units};

fn wallet_from_tail(tail: &str) -> String {
    format!("r{tail}")
}

fn wallet_with_prefix(prefix: char, tail_127: &str) -> String {
    format!("r{prefix}{tail_127}")
}

fn receiver_string(tx: &RewardTx) -> String {
    std::str::from_utf8(&tx.receiver)
        .expect("reward receiver bytes should be valid UTF-8")
        .to_string()
}

fn receiver_array(receiver: &str) -> [u8; REMZAR_WALLET_LEN] {
    let bytes = receiver.as_bytes();
    assert_eq!(bytes.len(), REMZAR_WALLET_LEN);

    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(bytes);
    out
}

fn raw_reward_wire(tx: &RewardTx) -> Vec<u8> {
    postcard::to_allocvec(tx).expect("raw RewardTx postcard encoding should serialize struct shape")
}

fn valid_reward_amount(seed: u64) -> u64 {
    let max_reward = GlobalConfiguration::MAX_BLOCK_REWARD;
    let amount = seed.checked_rem(max_reward).unwrap_or(0).saturating_add(1);

    amount.min(max_reward).max(1)
}

fn ten_years_secs() -> u64 {
    3600u64
        .saturating_mul(24)
        .saturating_mul(365)
        .saturating_mul(10)
}

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_new_accepts_valid_receiver_positive_reward_and_positive_block_height(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver.clone(), amount, block_height)
            .expect("valid reward receiver, amount, and block height should construct");

        prop_assert!(
            tx.validate().is_ok(),
            "freshly constructed reward transaction must validate"
        );

        prop_assert_eq!(
            receiver_string(&tx),
            receiver,
            "reward receiver bytes must preserve canonical receiver address"
        );

        prop_assert_eq!(
            tx.receiver.len(),
            REMZAR_WALLET_LEN,
            "reward receiver must be fixed wallet byte length"
        );

        prop_assert_eq!(
            tx.amount,
            amount,
            "reward constructor must preserve amount"
        );

        prop_assert_eq!(
            tx.block_height,
            block_height,
            "reward constructor must preserve block height"
        );

        prop_assert!(
            tx.timestamp >= 946_684_800,
            "reward timestamp must be at least year 2000"
        );
    }

    // 02/25
    #[test]
    fn test_002_new_canonicalizes_trimmed_uppercase_receiver_wallet(
        upper_tail in "[0-9A-F]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let raw_receiver = format!(" \tR{upper_tail}\n");
        let expected = format!("r{}", upper_tail.to_ascii_lowercase());

        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(raw_receiver, amount, block_height)
            .expect("constructor should canonicalize trimmed uppercase receiver wallet");

        prop_assert_eq!(
            receiver_string(&tx),
            expected,
            "RewardTx::new must store canonical lowercase receiver wallet"
        );

        prop_assert!(
            tx.validate().is_ok(),
            "canonicalized reward transaction must validate"
        );
    }

    // 03/25
    #[test]
    fn test_003_new_rejects_short_wrong_prefix_and_non_hex_receiver_wallets(
        short_tail in "[0-9a-f]{0,127}",
        valid_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let short = wallet_from_tail(&short_tail);
        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);

        prop_assert!(
            RewardTx::new(short, amount, block_height).is_err(),
            "RewardTx::new must reject short receiver wallet"
        );

        prop_assert!(
            RewardTx::new(wrong_prefix, amount, block_height).is_err(),
            "RewardTx::new must reject wrong receiver wallet prefix"
        );

        prop_assert!(
            RewardTx::new(non_hex, amount, block_height).is_err(),
            "RewardTx::new must reject non-hex receiver wallet body"
        );
    }

    // 04/25
    #[test]
    fn test_004_new_rejects_zero_reward_amount(
        wallet_tail in "[0-9a-f]{128}",
        block_height_seed in any::<u64>(),
    ) {
        let receiver = wallet_from_tail(&wallet_tail);
        let block_height = block_height_seed.saturating_add(1);

        prop_assert!(
            RewardTx::new(receiver, 0, block_height).is_err(),
            "RewardTx::new must reject zero reward amount"
        );
    }

    // 05/25
    #[test]
    fn test_005_new_rejects_reward_amount_above_max_block_reward(
        wallet_tail in "[0-9a-f]{128}",
        extra in 1u64..=1_000_000u64,
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD < u64::MAX);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(extra);
        let block_height = block_height_seed.saturating_add(1);

        prop_assume!(amount > GlobalConfiguration::MAX_BLOCK_REWARD);

        prop_assert!(
            RewardTx::new(receiver, amount, block_height).is_err(),
            "RewardTx::new must reject reward above MAX_BLOCK_REWARD"
        );
    }

    // 06/25
    #[test]
    fn test_006_new_rejects_zero_block_height(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);

        prop_assert!(
            RewardTx::new(receiver, amount, 0).is_err(),
            "RewardTx::new must reject block height zero"
        );
    }

    // 07/25
    #[test]
    fn test_007_validate_rejects_manual_mutation_to_zero_amount_above_max_or_zero_height(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
        extra in 1u64..=1_000_000u64,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let mut zero_amount = tx.clone();
        zero_amount.amount = 0;

        prop_assert!(
            zero_amount.validate().is_err(),
            "validate must reject manually mutated zero amount"
        );

        if GlobalConfiguration::MAX_BLOCK_REWARD < u64::MAX {
            let mut above_max = tx.clone();
            above_max.amount = GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(extra);

            prop_assume!(above_max.amount > GlobalConfiguration::MAX_BLOCK_REWARD);

            prop_assert!(
                above_max.validate().is_err(),
                "validate must reject manually mutated amount above MAX_BLOCK_REWARD"
            );
        }

        let mut zero_height = tx.clone();
        zero_height.block_height = 0;

        prop_assert!(
            zero_height.validate().is_err(),
            "validate must reject manually mutated zero block height"
        );
    }

    // 08/25
    #[test]
    fn test_008_validate_rejects_manual_receiver_mutations(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
        index in 0usize..REMZAR_WALLET_LEN,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let mut wrong_prefix = tx.clone();
        wrong_prefix.receiver[0] = b'p';

        prop_assert!(
            wrong_prefix.validate().is_err(),
            "validate must reject wrong receiver prefix"
        );

        let mut nul_byte = tx.clone();
        nul_byte.receiver[index] = 0;

        prop_assert!(
            nul_byte.validate().is_err(),
            "validate must reject receiver containing NUL byte"
        );

        let mut non_hex = tx.clone();
        non_hex.receiver[1] = b'g';

        prop_assert!(
            non_hex.validate().is_err(),
            "validate must reject non-hex receiver body"
        );
    }

    // 09/25
    #[test]
    fn test_009_validate_rejects_before_2000_and_runtime_validation_rejects_future_skew(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let mut too_old = tx.clone();
        too_old.timestamp = 946_684_799;

        prop_assert!(
            too_old.validate().is_err(),
            "validate must reject reward timestamp before year 2000"
        );

        let now = now_secs();

        prop_assume!(
            now <= u64::MAX
                .saturating_sub(ten_years_secs())
                .saturating_sub(1)
        );

        let mut too_future = tx.clone();
        too_future.timestamp = now
            .saturating_add(ten_years_secs())
            .saturating_add(1);

        prop_assert!(
            too_future.validate().is_ok(),
            "replay-safe validate is structural and must accept structurally valid future timestamps"
        );

        prop_assert!(
            too_future.validate_for_runtime_at(now).is_err(),
            "runtime validation must reject reward timestamp more than ten years in the future"
        );
    }

    // 10/25
    #[test]
    fn test_010_amount_as_remzar_matches_micro_unit_conversion(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        prop_assert_eq!(
            tx.amount_as_remzar(),
            from_micro_units(amount),
            "amount_as_remzar must delegate to canonical micro-unit conversion"
        );
    }

    // 11/25
    #[test]
    fn test_011_serialize_deserialize_roundtrip_preserves_valid_reward_tx(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let encoded = tx.serialize()
            .expect("valid reward transaction should serialize");

        let decoded = RewardTx::deserialize(&encoded)
            .expect("serialized valid reward transaction should deserialize");

        prop_assert_eq!(
            &decoded,
            &tx,
            "reward transaction serialization roundtrip must preserve all fields"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "deserialized valid reward transaction must validate"
        );
    }

    // 12/25
    #[test]
    fn test_012_deserialize_rejects_truncated_serialized_reward_tx(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
        keep_seed in any::<usize>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let encoded = tx.serialize()
            .expect("valid reward transaction should serialize");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            RewardTx::deserialize(truncated).is_err(),
            "RewardTx::deserialize must reject truncated postcard bytes"
        );
    }

    // 13/25
    #[test]
    fn test_013_deserialize_rejects_wire_reward_with_zero_amount(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        tx.amount = 0;

        let encoded = raw_reward_wire(&tx);

        prop_assert!(
            RewardTx::deserialize(&encoded).is_err(),
            "RewardTx::deserialize must reject wire reward with zero amount"
        );
    }

    // 14/25
    #[test]
    fn test_014_deserialize_rejects_wire_reward_with_zero_block_height(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        tx.block_height = 0;

        let encoded = raw_reward_wire(&tx);

        prop_assert!(
            RewardTx::deserialize(&encoded).is_err(),
            "RewardTx::deserialize must reject wire reward with zero block height"
        );
    }

    // 15/25
    #[test]
    fn test_015_deserialize_rejects_wire_reward_with_invalid_receiver_bytes(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        tx.receiver[0] = b'p';

        let encoded = raw_reward_wire(&tx);

        prop_assert!(
            RewardTx::deserialize(&encoded).is_err(),
            "RewardTx::deserialize must reject wire reward with invalid receiver bytes"
        );
    }

    // 16/25
    #[test]
    fn test_016_multiple_unique_receivers_create_distinct_valid_reward_txs(
        shared_tail in "[0-9a-f]{127}",
        amount_seed in any::<u64>(),
        base_height in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let amount = valid_reward_amount(amount_seed);
        let mut seen_receivers = std::collections::BTreeSet::new();

        for i in 0u32..10u32 {
            let prefix = char::from_digit(i, 16)
                .expect("0..10 must be valid hex digit");

            let receiver = wallet_with_prefix(prefix, &shared_tail);
            let block_height = base_height
                .saturating_add(i as u64)
                .saturating_add(1);

            let tx = RewardTx::new(receiver.clone(), amount, block_height)
                .expect("unique valid receiver should create reward tx");

            prop_assert!(
                tx.validate().is_ok(),
                "each generated reward tx must validate"
            );

            prop_assert!(
                seen_receivers.insert(receiver_string(&tx)),
                "each generated reward receiver must be unique"
            );
        }

        prop_assert_eq!(
            seen_receivers.len(),
            10,
            "test should generate ten unique reward receivers"
        );
    }

    // 17/25
    #[test]
    fn test_017_serialize_is_deterministic_for_unchanged_reward_tx(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let encoded_a = tx.serialize()
            .expect("first reward transaction serialization should succeed");

        let encoded_b = tx.serialize()
            .expect("second reward transaction serialization should succeed");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "serializing the same RewardTx twice must produce identical bytes"
        );

        prop_assert!(
            !encoded_a.is_empty(),
            "serialized RewardTx must not be empty"
        );
    }

    // 18/25
    #[test]
    fn test_018_deserialize_rejects_serialized_reward_tx_with_nonzero_trailing_bytes(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
        extra in proptest::collection::vec(1u8..=255u8, 1..32),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let mut encoded = tx.serialize()
            .expect("valid reward transaction should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            RewardTx::deserialize(&encoded).is_err(),
            "RewardTx::deserialize must reject nonzero trailing bytes after valid payload"
        );
    }

    // 19/25
    #[test]
    fn test_019_deserialize_rejects_serialized_reward_tx_with_zero_trailing_bytes(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
        extra_len in 1usize..32usize,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        let mut encoded = tx.serialize()
            .expect("valid reward transaction should serialize");

        encoded.extend(std::iter::repeat(0u8).take(extra_len));

        prop_assert!(
            RewardTx::deserialize(&encoded).is_err(),
            "RewardTx::deserialize must reject zero trailing bytes after valid payload"
        );
    }

    // 20/25
    #[test]
    fn test_020_validate_rejects_uppercase_receiver_body_after_manual_mutation(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        tx.receiver[1] = b'A';

        prop_assert!(
            tx.validate().is_err(),
            "validate must reject uppercase receiver body bytes because stored wallet must be canonical lowercase"
        );
    }

    // 21/25
    #[test]
    fn test_021_deserialize_rejects_non_utf8_receiver_byte_from_wire(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
        index in 0usize..REMZAR_WALLET_LEN,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut tx = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward transaction should construct");

        tx.receiver[index] = 0xFF;

        let encoded = raw_reward_wire(&tx);

        prop_assert!(
            RewardTx::deserialize(&encoded).is_err(),
            "RewardTx::deserialize must reject wire reward with non-UTF8 receiver bytes"
        );
    }

    // 22/25
    #[test]
    fn test_022_validate_accepts_current_and_ten_year_boundary_timestamps(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);
        let now = now_secs();

        let current = RewardTx {
            receiver: receiver_array(&receiver),
            amount,
            block_height,
            timestamp: now,
        };

        prop_assert!(
            current.validate().is_ok(),
            "validate must accept current timestamp"
        );

        if let Some(boundary) = now.checked_add(ten_years_secs()) {
            let boundary_tx = RewardTx {
                receiver: receiver_array(&receiver),
                amount,
                block_height,
                timestamp: boundary,
            };

            prop_assert!(
                boundary_tx.validate().is_ok(),
                "validate must accept timestamp exactly at now + ten years boundary"
            );
        }
    }

    // 23/25
    #[test]
    fn test_023_same_receiver_different_block_heights_produce_distinct_wires(
        wallet_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        base_height in 1u64..1_000_000u64,
        offset in 1u64..1_000_000u64,
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let amount = valid_reward_amount(amount_seed);

        let tx_a = RewardTx {
            receiver: receiver_array(&receiver),
            amount,
            block_height: base_height,
            timestamp: 946_684_800,
        };

        let tx_b = RewardTx {
            receiver: receiver_array(&receiver),
            amount,
            block_height: base_height.saturating_add(offset),
            timestamp: 946_684_800,
        };

        prop_assert!(
            tx_a.validate().is_ok(),
            "first reward tx must validate"
        );

        prop_assert!(
            tx_b.validate().is_ok(),
            "second reward tx must validate"
        );

        let wire_a = tx_a.serialize()
            .expect("first reward tx should serialize");

        let wire_b = tx_b.serialize()
            .expect("second reward tx should serialize");

        prop_assert_ne!(
            &wire_a,
            &wire_b,
            "same receiver and amount with different block heights must serialize differently"
        );
    }

    // 24/25
    #[test]
    fn test_024_deserialize_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RewardTx::deserialize(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "RewardTx::deserialize must never panic for arbitrary external bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_max_block_reward_boundary_is_accepted_when_positive(
        wallet_tail in "[0-9a-f]{128}",
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&wallet_tail);
        let block_height = block_height_seed.saturating_add(1);

        let tx = RewardTx::new(
            receiver,
            GlobalConfiguration::MAX_BLOCK_REWARD,
            block_height,
        )
        .expect("MAX_BLOCK_REWARD boundary should be accepted");

        prop_assert_eq!(
            tx.amount,
            GlobalConfiguration::MAX_BLOCK_REWARD,
            "RewardTx::new must preserve MAX_BLOCK_REWARD boundary amount"
        );

        prop_assert!(
            tx.validate().is_ok(),
            "MAX_BLOCK_REWARD boundary reward tx must validate"
        );
    }
}
