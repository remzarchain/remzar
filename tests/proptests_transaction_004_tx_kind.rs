// tests/proptests_transaction_004_tx_kind.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::{TxKind, normalize_address_bytes};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::collections::BTreeSet;

const UNIX_2000: u64 = 946_684_800;
const TEN_YEARS_SECS: u64 = 3600 * 24 * 365 * 10;

fn wallet_from_tail(tail: &str) -> String {
    format!("r{tail}")
}

fn wallet_with_prefix(prefix: char, tail_127: &str) -> String {
    format!("r{prefix}{tail_127}")
}

fn set_from_vec(v: Vec<String>) -> BTreeSet<String> {
    v.into_iter().collect()
}

fn valid_reward_amount(seed: u64) -> u64 {
    let max_reward = GlobalConfiguration::MAX_BLOCK_REWARD;
    let amount = seed.checked_rem(max_reward).unwrap_or(0).saturating_add(1);

    amount.min(max_reward).max(1)
}

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

fn far_future_timestamp() -> Option<u64> {
    now_secs()
        .checked_add(TEN_YEARS_SECS)
        .and_then(|v| v.checked_add(1))
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_transfer_txkind_roundtrip_validates_tags_and_touched_addresses(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let tx = Transaction::new(sender.clone(), receiver.clone(), amount)
            .expect("valid transfer should construct");

        let kind = TxKind::Transfer(tx);

        prop_assert!(
            kind.validate().is_ok(),
            "valid TxKind::Transfer must validate"
        );

        prop_assert_eq!(
            kind.tag(),
            "transfer",
            "TxKind::Transfer tag must be stable"
        );

        let normalized_sender = kind.normalized_sender();
        let normalized_receiver = kind.normalized_receiver();

        prop_assert_eq!(
            normalized_sender.as_deref(),
            Some(sender.as_str()),
            "TxKind::Transfer normalized_sender must expose canonical sender"
        );

        prop_assert_eq!(
            normalized_receiver.as_deref(),
            Some(receiver.as_str()),
            "TxKind::Transfer normalized_receiver must expose canonical receiver"
        );

        let touched = set_from_vec(kind.touched_addresses());
        let expected = BTreeSet::from([sender.clone(), receiver.clone()]);

        prop_assert_eq!(
            touched,
            expected,
            "TxKind::Transfer must touch sender and receiver exactly once"
        );

        let encoded_a = kind.serialize()
            .expect("valid TxKind::Transfer should serialize");

        let encoded_b = kind.serialize()
            .expect("valid TxKind::Transfer should serialize deterministically");

        prop_assert_eq!(
            &encoded_a,
            &encoded_b,
            "TxKind serialization must be deterministic"
        );

        let decoded = TxKind::deserialize(&encoded_a)
            .expect("serialized valid TxKind::Transfer should deserialize");

        prop_assert_eq!(
            &decoded,
            &kind,
            "TxKind::Transfer roundtrip must preserve the variant and inner tx"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "deserialized TxKind::Transfer must validate"
        );
    }

    // 02/25
    #[test]
    fn test_002_reward_txkind_roundtrip_validates_tag_receiver_and_touched_addresses(
        receiver_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&receiver_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let reward = RewardTx::new(receiver.clone(), amount, block_height)
            .expect("valid reward should construct");

        let kind = TxKind::Reward(reward);

        prop_assert!(
            kind.validate().is_ok(),
            "valid TxKind::Reward must validate"
        );

        prop_assert_eq!(
            kind.tag(),
            "reward",
            "TxKind::Reward tag must be stable"
        );

        prop_assert_eq!(
            kind.normalized_sender(),
            None,
            "TxKind::Reward must not expose a sender"
        );

        let normalized_receiver = kind.normalized_receiver();

        prop_assert_eq!(
            normalized_receiver.as_deref(),
            Some(receiver.as_str()),
            "TxKind::Reward normalized_receiver must expose canonical reward receiver"
        );

        let touched = set_from_vec(kind.touched_addresses());
        let expected = BTreeSet::from([receiver.clone()]);

        prop_assert_eq!(
            touched,
            expected,
            "TxKind::Reward must only touch the reward receiver"
        );

        let encoded = kind.serialize()
            .expect("valid TxKind::Reward should serialize");

        let decoded = TxKind::deserialize(&encoded)
            .expect("serialized valid TxKind::Reward should deserialize");

        prop_assert_eq!(
            &decoded,
            &kind,
            "TxKind::Reward roundtrip must preserve the variant and reward"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "deserialized TxKind::Reward must validate"
        );
    }

    // 03/25
    #[test]
    fn test_003_register_node_txkind_roundtrip_has_no_balance_touched_addresses(
        wallet_tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&wallet_tail);

        let register = RegisterNodeTx::new(wallet.clone())
            .expect("valid RegisterNodeTx should construct");

        let kind = TxKind::RegisterNode(register);

        prop_assert!(
            kind.validate().is_ok(),
            "valid TxKind::RegisterNode must validate"
        );

        prop_assert_eq!(
            kind.tag(),
            "register_node",
            "TxKind::RegisterNode tag must be stable"
        );

        prop_assert_eq!(
            kind.normalized_sender(),
            None,
            "TxKind::RegisterNode must not expose a sender"
        );

        prop_assert_eq!(
            kind.normalized_receiver(),
            None,
            "TxKind::RegisterNode must not expose a receiver"
        );

        prop_assert!(
            kind.touched_addresses().is_empty(),
            "TxKind::RegisterNode must not touch account balances"
        );

        let encoded = kind.serialize()
            .expect("valid TxKind::RegisterNode should serialize");

        let decoded = TxKind::deserialize(&encoded)
            .expect("serialized valid TxKind::RegisterNode should deserialize");

        prop_assert_eq!(
            &decoded,
            &kind,
            "TxKind::RegisterNode roundtrip must preserve variant and payload"
        );

        prop_assert!(
            decoded.validate().is_ok(),
            "deserialized TxKind::RegisterNode must validate"
        );
    }

    // 04/25
    #[test]
    fn test_004_normalize_address_bytes_accepts_canonical_wallet_and_trailing_nul_padding(
        wallet_tail in "[0-9a-f]{128}",
        pad_len in 0usize..32usize,
    ) {
        let wallet = wallet_from_tail(&wallet_tail);

        let normalized = normalize_address_bytes(wallet.as_bytes());

        prop_assert_eq!(
            normalized.as_str(),
            wallet.as_str(),
            "normalize_address_bytes must accept canonical wallet bytes"
        );

        let mut padded = wallet.as_bytes().to_vec();
        padded.extend(std::iter::repeat(0u8).take(pad_len));

        let normalized_padded = normalize_address_bytes(&padded);

        prop_assert_eq!(
            normalized_padded.as_str(),
            wallet.as_str(),
            "normalize_address_bytes must accept trailing NUL padding"
        );
    }

    // 05/25
    #[test]
    fn test_005_normalize_address_bytes_rejects_invalid_wallet_bytes(
        short_tail in "[0-9a-f]{0,127}",
        valid_tail in "[0-9a-f]{128}",
        nul_index in 0usize..REMZAR_WALLET_LEN,
    ) {
        let short = wallet_from_tail(&short_tail);
        let wrong_prefix = format!("p{valid_tail}");
        let non_hex = format!("rz{}", &valid_tail[1..]);

        prop_assert_eq!(
            normalize_address_bytes(short.as_bytes()),
            "",
            "short wallet bytes must normalize to empty string"
        );

        prop_assert_eq!(
            normalize_address_bytes(wrong_prefix.as_bytes()),
            "",
            "wrong-prefix wallet bytes must normalize to empty string"
        );

        prop_assert_eq!(
            normalize_address_bytes(non_hex.as_bytes()),
            "",
            "non-hex wallet bytes must normalize to empty string"
        );

        let mut embedded_nul = wallet_from_tail(&valid_tail).into_bytes();
        embedded_nul[nul_index] = 0;

        prop_assert_eq!(
            normalize_address_bytes(&embedded_nul),
            "",
            "embedded NUL must normalize to empty string"
        );

        let mut non_utf8 = wallet_from_tail(&valid_tail).into_bytes();
        non_utf8[nul_index] = 0xFF;

        prop_assert_eq!(
            normalize_address_bytes(&non_utf8),
            "",
            "non-UTF8 wallet bytes must normalize to empty string"
        );
    }

    // 06/25
    #[test]
    fn test_006_txkind_deserialize_rejects_truncated_valid_transfer_wire(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
        keep_seed in any::<usize>(),
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transfer should construct");

        let kind = TxKind::Transfer(tx);

        let encoded = kind.serialize()
            .expect("valid TxKind::Transfer should serialize");

        prop_assume!(!encoded.is_empty());

        let keep_len = keep_seed % encoded.len();
        let truncated = &encoded[..keep_len];

        prop_assert!(
            TxKind::deserialize(truncated).is_err(),
            "TxKind::deserialize must reject truncated transfer wire bytes"
        );
    }

    // 07/25
    #[test]
    fn test_007_txkind_validate_rejects_invalid_reward_variant_zero_amount_zero_height_and_bad_receiver(
        receiver_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&receiver_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let reward = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward should construct");

        let mut zero_amount = reward.clone();
        zero_amount.amount = 0;

        prop_assert!(
            TxKind::Reward(zero_amount).validate().is_err(),
            "TxKind::validate must reject Reward amount=0"
        );

        let mut zero_height = reward.clone();
        zero_height.block_height = 0;

        prop_assert!(
            TxKind::Reward(zero_height).validate().is_err(),
            "TxKind::validate must reject Reward block_height=0"
        );

        let mut bad_receiver = reward.clone();
        bad_receiver.receiver[0] = b'p';

        prop_assert!(
            TxKind::Reward(bad_receiver).validate().is_err(),
            "TxKind::validate must reject Reward with invalid receiver bytes"
        );
    }

    // 08/25
    #[test]
    fn test_008_txkind_deserialize_rejects_wire_reward_with_zero_amount(
        receiver_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&receiver_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut reward = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward should construct");

        reward.amount = 0;

        let kind = TxKind::Reward(reward);

        let encoded = kind.serialize()
            .expect("manually mutated TxKind::Reward should still serialize");

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject wire Reward amount=0"
        );
    }

    // 09/25
    #[test]
    fn test_009_txkind_deserialize_rejects_wire_reward_with_zero_block_height(
        receiver_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&receiver_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut reward = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward should construct");

        reward.block_height = 0;

        let kind = TxKind::Reward(reward);

        let encoded = kind.serialize()
            .expect("manually mutated TxKind::Reward should still serialize");

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject wire Reward block_height=0"
        );
    }

    // 10/25
    #[test]
    fn test_010_txkind_deserialize_rejects_wire_reward_with_invalid_receiver_bytes(
        receiver_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&receiver_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut reward = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward should construct");

        reward.receiver[0] = b'p';

        let kind = TxKind::Reward(reward);

        let encoded = kind.serialize()
            .expect("manually mutated TxKind::Reward should still serialize");

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject wire Reward with invalid receiver bytes"
        );
    }

    // 11/25
    #[test]
    fn test_011_txkind_deserialize_rejects_nonzero_trailing_bytes_after_valid_transfer_wire(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
        extra in proptest::collection::vec(1u8..=255u8, 1..16),
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transfer should construct");

        let kind = TxKind::Transfer(tx);

        let mut encoded = kind.serialize()
            .expect("valid TxKind::Transfer should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject nonzero trailing bytes after valid payload"
        );
    }

    // 12/25
    #[test]
    fn test_012_txkind_deserialize_rejects_zero_trailing_bytes_after_valid_transfer_wire(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
        extra_len in 1usize..16usize,
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let tx = Transaction::new(sender, receiver, amount)
            .expect("valid transfer should construct");

        let kind = TxKind::Transfer(tx);

        let mut encoded = kind.serialize()
            .expect("valid TxKind::Transfer should serialize");

        encoded.extend(std::iter::repeat(0u8).take(extra_len));

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject zero trailing bytes after valid payload"
        );
    }

    // 13/25
    #[test]
    fn test_013_txkind_deserialize_rejects_nonzero_trailing_bytes_after_valid_reward_wire(
        receiver_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
        extra in proptest::collection::vec(1u8..=255u8, 1..16),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&receiver_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let reward = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward should construct");

        let kind = TxKind::Reward(reward);

        let mut encoded = kind.serialize()
            .expect("valid TxKind::Reward should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject nonzero trailing bytes after valid Reward payload"
        );
    }

    // 14/25
    #[test]
    fn test_014_txkind_deserialize_rejects_nonzero_trailing_bytes_after_valid_register_wire(
        wallet_tail in "[0-9a-f]{128}",
        extra in proptest::collection::vec(1u8..=255u8, 1..16),
    ) {
        let wallet = wallet_from_tail(&wallet_tail);
        let register = RegisterNodeTx::new(wallet)
            .expect("valid RegisterNodeTx should construct");

        let kind = TxKind::RegisterNode(register);

        let mut encoded = kind.serialize()
            .expect("valid TxKind::RegisterNode should serialize");

        encoded.extend_from_slice(&extra);

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject nonzero trailing bytes after valid RegisterNode payload"
        );
    }

    // 15/25
    #[test]
    fn test_015_transfer_touched_addresses_deduplicates_same_sender_receiver_after_manual_mutation(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let mut tx = Transaction::new(sender.clone(), receiver, amount)
            .expect("valid transfer should construct");

        tx.receiver = tx.sender;

        let kind = TxKind::Transfer(tx);

        prop_assert!(
            kind.validate().is_err(),
            "manually mutated same-sender-receiver transfer must not validate"
        );

        let touched = set_from_vec(kind.touched_addresses());

        prop_assert_eq!(
            touched,
            BTreeSet::from([sender.clone()]),
            "touched_addresses must deduplicate identical sender/receiver wallet bytes"
        );

        let normalized_sender = kind.normalized_sender();
        let normalized_receiver = kind.normalized_receiver();

        prop_assert_eq!(
            normalized_sender.as_deref(),
            Some(sender.as_str()),
            "normalized_sender should still expose canonical sender"
        );

        prop_assert_eq!(
            normalized_receiver.as_deref(),
            Some(sender.as_str()),
            "normalized_receiver should expose same canonical wallet after manual mutation"
        );
    }

    // 16/25
    #[test]
    fn test_016_transfer_normalized_addresses_return_none_when_stored_bytes_are_corrupt(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("valid transfer should construct");

        tx.sender[0] = b'p';
        tx.receiver[1] = b'g';

        let kind = TxKind::Transfer(tx);

        prop_assert!(
            kind.validate().is_err(),
            "corrupt transfer must fail validation"
        );

        prop_assert_eq!(
            kind.normalized_sender(),
            None,
            "normalized_sender must hide invalid sender bytes"
        );

        prop_assert_eq!(
            kind.normalized_receiver(),
            None,
            "normalized_receiver must hide invalid receiver bytes"
        );

        prop_assert!(
            kind.touched_addresses().is_empty(),
            "corrupt transfer wallet bytes must not produce touched addresses"
        );
    }

    // 17/25
    #[test]
    fn test_017_reward_normalized_receiver_returns_none_when_receiver_bytes_are_corrupt(
        receiver_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
        block_height_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let receiver = wallet_from_tail(&receiver_tail);
        let amount = valid_reward_amount(amount_seed);
        let block_height = block_height_seed.saturating_add(1);

        let mut reward = RewardTx::new(receiver, amount, block_height)
            .expect("valid reward should construct");

        reward.receiver[0] = b'p';

        let kind = TxKind::Reward(reward);

        prop_assert!(
            kind.validate().is_err(),
            "corrupt reward must fail validation"
        );

        prop_assert_eq!(
            kind.normalized_receiver(),
            None,
            "normalized_receiver must hide invalid reward receiver bytes"
        );

        prop_assert!(
            kind.touched_addresses().is_empty(),
            "corrupt reward receiver bytes must not produce touched addresses"
        );
    }

    // 18/25
    #[test]
    fn test_018_txkind_deserialize_rejects_wire_transfer_with_zero_amount(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("valid transfer should construct");

        tx.amount = 0;

        let kind = TxKind::Transfer(tx);

        let encoded = kind.serialize()
            .expect("manually mutated TxKind::Transfer should still serialize");

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject wire Transfer amount=0"
        );
    }

    // 19/25
    #[test]
    fn test_019_txkind_deserialize_rejects_wire_transfer_with_same_sender_and_receiver(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let mut tx = Transaction::new(sender, receiver, amount)
            .expect("valid transfer should construct");

        tx.receiver = tx.sender;

        let kind = TxKind::Transfer(tx);

        let encoded = kind.serialize()
            .expect("manually mutated TxKind::Transfer should still serialize");

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject wire Transfer with same sender and receiver"
        );
    }

    // 20/25
    #[test]
    fn test_020_txkind_deserialize_rejects_wire_register_with_invalid_wallet_bytes(
        wallet_tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&wallet_tail);

        let mut register = RegisterNodeTx::new(wallet)
            .expect("valid RegisterNodeTx should construct");

        register.wallet_address[0] = b'p';

        let kind = TxKind::RegisterNode(register);

        let encoded = kind.serialize()
            .expect("manually mutated TxKind::RegisterNode should still serialize");

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject RegisterNode with invalid wallet bytes"
        );
    }

    // 21/25
    #[test]
    fn test_021_txkind_deserialize_rejects_wire_register_before_2000_but_accepts_structural_future_timestamp(
        wallet_tail in "[0-9a-f]{128}",
    ) {
        let wallet = wallet_from_tail(&wallet_tail);

        let mut register = RegisterNodeTx::new(wallet)
            .expect("valid RegisterNodeTx should construct");

        register.timestamp = UNIX_2000.saturating_sub(1);

        let kind = TxKind::RegisterNode(register);

        let encoded = kind.serialize()
            .expect("manually mutated TxKind::RegisterNode should still serialize");

        prop_assert!(
            TxKind::deserialize(&encoded).is_err(),
            "TxKind::deserialize must reject RegisterNode timestamp before year 2000"
        );

        if let Some(future_ts) = far_future_timestamp() {
            let wallet2 = wallet_from_tail(&"a".repeat(128));
            let mut future_register = RegisterNodeTx::new(wallet2)
                .expect("valid RegisterNodeTx should construct");

            future_register.timestamp = future_ts;

            let future_kind = TxKind::RegisterNode(future_register);
            let future_encoded = future_kind.serialize()
                .expect("future timestamp RegisterNodeTx should serialize structurally");

            prop_assert!(
                TxKind::deserialize(&future_encoded).is_ok(),
                "TxKind::deserialize is replay-safe structural validation and must accept structurally valid future RegisterNode timestamps"
            );
        }
    }

    // 22/25
    #[test]
    fn test_022_transfer_reward_and_register_tags_are_stable_and_distinct(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        reward_tail in "[0-9a-f]{128}",
        register_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let sender = wallet_with_prefix('0', &sender_tail);
        let receiver = wallet_with_prefix('1', &receiver_tail);

        let transfer = TxKind::Transfer(
            Transaction::new(sender, receiver, 1)
                .expect("valid transfer should construct")
        );

        let reward_amount = valid_reward_amount(amount_seed);
        let reward = TxKind::Reward(
            RewardTx::new(wallet_from_tail(&reward_tail), reward_amount, 1)
                .expect("valid reward should construct")
        );

        let register = TxKind::RegisterNode(
            RegisterNodeTx::new(wallet_from_tail(&register_tail))
                .expect("valid register tx should construct")
        );

        let tags = BTreeSet::from([
            transfer.tag(),
            reward.tag(),
            register.tag(),
        ]);

        prop_assert_eq!(
            tags,
            BTreeSet::from(["register_node", "reward", "transfer"]),
            "known balance/register TxKind tags must remain stable and distinct"
        );
    }

    // 23/25
    #[test]
    fn test_023_serialize_is_deterministic_for_transfer_reward_and_register_variants(
        sender_tail in "[0-9a-f]{127}",
        receiver_tail in "[0-9a-f]{127}",
        reward_tail in "[0-9a-f]{128}",
        register_tail in "[0-9a-f]{128}",
        amount_seed in any::<u64>(),
    ) {
        prop_assume!(GlobalConfiguration::MAX_BLOCK_REWARD > 0);

        let transfer = TxKind::Transfer(
            Transaction::new(
                wallet_with_prefix('0', &sender_tail),
                wallet_with_prefix('1', &receiver_tail),
                1,
            )
            .expect("valid transfer should construct")
        );

        let reward = TxKind::Reward(
            RewardTx::new(
                wallet_from_tail(&reward_tail),
                valid_reward_amount(amount_seed),
                1,
            )
            .expect("valid reward should construct")
        );

        let register = TxKind::RegisterNode(
            RegisterNodeTx::new(wallet_from_tail(&register_tail))
                .expect("valid register tx should construct")
        );

        for kind in [transfer, reward, register] {
            let encoded_a = kind.serialize()
                .expect("first TxKind serialization should succeed");

            let encoded_b = kind.serialize()
                .expect("second TxKind serialization should succeed");

            prop_assert_eq!(
                &encoded_a,
                &encoded_b,
                "TxKind serialization must be deterministic for unchanged variants"
            );

            prop_assert!(
                !encoded_a.is_empty(),
                "serialized TxKind variant must not be empty"
            );
        }
    }

    // 24/25
    #[test]
    fn test_024_txkind_deserialize_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            TxKind::deserialize(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "TxKind::deserialize must never panic for arbitrary external bytes"
        );
    }

    // 25/25
    #[test]
    fn test_025_normalize_address_bytes_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            normalize_address_bytes(&data)
        }));

        prop_assert!(
            result.is_ok(),
            "normalize_address_bytes must never panic for arbitrary external bytes"
        );
    }
}
