use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::{TxKind, normalize_address_bytes};
use remzar::tokens::nft_001::{NftMintTx, NftTransferTx};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::collections::BTreeSet;

type TestResult = Result<(), String>;

const UNIX_2000: u64 = 946_684_800;

fn require(condition: bool, context: &str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(context.to_owned())
    }
}

fn require_equal<T>(left: &T, right: &T, context: &str) -> TestResult
where
    T: PartialEq + core::fmt::Debug,
{
    if left == right {
        Ok(())
    } else {
        Err(format!("{context}: left={left:?}, right={right:?}"))
    }
}

fn require_not_equal<T>(left: &T, right: &T, context: &str) -> TestResult
where
    T: PartialEq + core::fmt::Debug,
{
    if left != right {
        Ok(())
    } else {
        Err(format!("{context}: both values were {left:?}"))
    }
}

fn map_err_debug<T>(result: Result<T, ErrorDetection>, context: &str) -> Result<T, String> {
    result.map_err(|error| format!("{context}: {error:?}"))
}

fn wallet_with_repeated_hex(ch: char) -> String {
    let body = ch.to_string().repeat(128);
    format!("r{body}")
}

fn uppercase_wallet_with_repeated_hex(ch: char) -> String {
    let body = ch.to_string().repeat(128).to_ascii_uppercase();
    format!("R{body}")
}

fn wallet_body_from_seed(seed: u64) -> String {
    let digest = blake3::hash(&seed.to_le_bytes()).to_hex().to_string();
    let mut body = String::with_capacity(128);
    body.push_str(&digest);
    body.push_str(&digest);
    body
}

fn wallet_from_seed(seed: u64) -> String {
    let body = wallet_body_from_seed(seed);
    format!("r{body}")
}

fn wallet_array(address: &str) -> Result<[u8; REMZAR_WALLET_LEN], String> {
    if address.len() != REMZAR_WALLET_LEN {
        return Err(format!(
            "wallet_array requires {REMZAR_WALLET_LEN} bytes, got {}",
            address.len()
        ));
    }

    let mut out = [0_u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(address.as_bytes());
    Ok(out)
}

fn btree_from_vec(values: Vec<String>) -> BTreeSet<String> {
    values.into_iter().collect()
}

fn hash_from_seed(seed: u64) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed.to_le_bytes());

    let mut out = [0_u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out);
    out
}

fn bytes_from_seed(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u64;

    while out.len() < len {
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&seed.to_le_bytes());
        input.extend_from_slice(&counter.to_le_bytes());

        let digest = blake3::hash(&input);
        for byte in digest.as_bytes() {
            if out.len() == len {
                break;
            }
            out.push(*byte);
        }

        counter = counter.wrapping_add(1);
    }

    out
}

fn valid_transfer() -> Result<Transaction, String> {
    Ok(Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: UNIX_2000,
    })
}

fn invalid_transfer_zero_amount() -> Result<Transaction, String> {
    Ok(Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 0,
        timestamp: UNIX_2000,
    })
}

fn valid_register() -> Result<RegisterNodeTx, String> {
    Ok(RegisterNodeTx {
        wallet_address: wallet_array(&wallet_with_repeated_hex('c'))?,
        timestamp: UNIX_2000,
    })
}

fn invalid_register_old_timestamp() -> Result<RegisterNodeTx, String> {
    Ok(RegisterNodeTx {
        wallet_address: wallet_array(&wallet_with_repeated_hex('c'))?,
        timestamp: UNIX_2000.saturating_sub(1),
    })
}

fn valid_reward() -> Result<RewardTx, String> {
    Ok(RewardTx {
        receiver: wallet_array(&wallet_with_repeated_hex('d'))?,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    })
}

fn invalid_reward_zero_height() -> Result<RewardTx, String> {
    Ok(RewardTx {
        receiver: wallet_array(&wallet_with_repeated_hex('d'))?,
        amount: 1,
        block_height: 0,
        timestamp: UNIX_2000,
    })
}

fn valid_nft_mint() -> NftMintTx {
    NftMintTx {
        nft_id: hash_from_seed(1),
        content_hash: hash_from_seed(2),
        title: "Genesis NFT".to_owned(),
        description: "test mint".to_owned(),
    }
}

fn valid_nft_transfer() -> NftTransferTx {
    NftTransferTx {
        nft_id: hash_from_seed(3),
        new_owner_wallet: wallet_with_repeated_hex('e'),
    }
}

fn require_validation_error_contains<T>(
    result: Result<T, ErrorDetection>,
    needle: &str,
    context: &str,
) -> TestResult
where
    T: core::fmt::Debug,
{
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => require(
            message.contains(needle),
            &format!("{context}: message was {message:?}"),
        ),
        Err(other) => Err(format!(
            "{context}: expected ValidationError, got {other:?}"
        )),
        Ok(value) => Err(format!("{context}: expected error, got {value:?}")),
    }
}

fn require_any_error<T>(result: Result<T, ErrorDetection>, context: &str) -> TestResult
where
    T: core::fmt::Debug,
{
    match result {
        Err(_) => Ok(()),
        Ok(value) => Err(format!("{context}: expected error, got {value:?}")),
    }
}

#[test]
fn tx_kind_01_tag_transfer() -> TestResult {
    let kind = TxKind::Transfer(valid_transfer()?);

    require_equal(&kind.tag(), &"transfer", "transfer tag should match")
}

#[test]
fn tx_kind_02_tag_register_node() -> TestResult {
    let kind = TxKind::RegisterNode(valid_register()?);

    require_equal(
        &kind.tag(),
        &"register_node",
        "register node tag should match",
    )
}

#[test]
fn tx_kind_03_tag_reward() -> TestResult {
    let kind = TxKind::Reward(valid_reward()?);

    require_equal(&kind.tag(), &"reward", "reward tag should match")
}

#[test]
fn tx_kind_04_tag_nft_mint() -> TestResult {
    let kind = TxKind::NftMint(valid_nft_mint());

    require_equal(&kind.tag(), &"nft_mint", "nft mint tag should match")
}

#[test]
fn tx_kind_05_tag_nft_transfer() -> TestResult {
    let kind = TxKind::NftTransfer(valid_nft_transfer());

    require_equal(
        &kind.tag(),
        &"nft_transfer",
        "nft transfer tag should match",
    )
}

#[test]
fn tx_kind_06_validate_valid_transfer() -> TestResult {
    let kind = TxKind::Transfer(valid_transfer()?);

    map_err_debug(kind.validate(), "valid transfer TxKind should validate")
}

#[test]
fn tx_kind_07_validate_valid_register_node() -> TestResult {
    let kind = TxKind::RegisterNode(valid_register()?);

    map_err_debug(
        kind.validate(),
        "valid register node TxKind should validate",
    )
}

#[test]
fn tx_kind_08_validate_valid_reward() -> TestResult {
    let kind = TxKind::Reward(valid_reward()?);

    map_err_debug(kind.validate(), "valid reward TxKind should validate")
}

#[test]
fn tx_kind_09_validate_valid_nft_mint() -> TestResult {
    let kind = TxKind::NftMint(valid_nft_mint());

    map_err_debug(kind.validate(), "NftMint TxKind should validate")
}

#[test]
fn tx_kind_10_validate_valid_nft_transfer() -> TestResult {
    let kind = TxKind::NftTransfer(valid_nft_transfer());

    map_err_debug(kind.validate(), "valid NftTransfer TxKind should validate")
}

#[test]
fn tx_kind_11_validate_invalid_transfer_wraps_error() -> TestResult {
    let kind = TxKind::Transfer(invalid_transfer_zero_amount()?);

    require_validation_error_contains(
        kind.validate(),
        "Invalid Transfer transaction",
        "invalid transfer should be wrapped by TxKind validation",
    )
}

#[test]
fn tx_kind_12_validate_invalid_register_node_wraps_error() -> TestResult {
    let kind = TxKind::RegisterNode(invalid_register_old_timestamp()?);

    require_validation_error_contains(
        kind.validate(),
        "Invalid RegisterNode transaction",
        "invalid register node should be wrapped by TxKind validation",
    )
}

#[test]
fn tx_kind_13_validate_invalid_reward_wraps_error() -> TestResult {
    let kind = TxKind::Reward(invalid_reward_zero_height()?);

    require_validation_error_contains(
        kind.validate(),
        "Invalid Reward transaction",
        "invalid reward should be wrapped by TxKind validation",
    )
}

#[test]
fn tx_kind_14_validate_nft_transfer_rejects_empty_owner() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(4),
        new_owner_wallet: String::new(),
    });

    require_validation_error_contains(
        kind.validate(),
        "new_owner_wallet is empty",
        "empty NFT transfer owner should fail",
    )
}

#[test]
fn tx_kind_15_validate_nft_transfer_rejects_whitespace_owner() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(5),
        new_owner_wallet: " \n\t ".to_owned(),
    });

    require_validation_error_contains(
        kind.validate(),
        "new_owner_wallet is empty",
        "whitespace NFT transfer owner should fail",
    )
}

#[test]
fn tx_kind_16_validate_nft_transfer_rejects_wrong_prefix_owner() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(6),
        new_owner_wallet: format!("x{}", "a".repeat(128)),
    });

    require_validation_error_contains(
        kind.validate(),
        "Invalid NftTransfer",
        "wrong-prefix NFT transfer owner should fail",
    )
}

#[test]
fn tx_kind_17_validate_nft_transfer_rejects_non_hex_owner() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(7),
        new_owner_wallet: format!("r{}z", "a".repeat(127)),
    });

    require_validation_error_contains(
        kind.validate(),
        "Invalid NftTransfer",
        "non-hex NFT transfer owner should fail",
    )
}

#[test]
fn tx_kind_18_validate_nft_transfer_accepts_uppercase_owner() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(8),
        new_owner_wallet: uppercase_wallet_with_repeated_hex('a'),
    });

    map_err_debug(
        kind.validate(),
        "uppercase NFT transfer owner should be accepted by canonical checker",
    )
}

#[test]
fn tx_kind_19_validate_nft_transfer_accepts_outer_whitespace_owner() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(9),
        new_owner_wallet: format!(" \n{}\t", uppercase_wallet_with_repeated_hex('b')),
    });

    map_err_debug(
        kind.validate(),
        "outer-whitespace NFT transfer owner should be accepted by canonical checker",
    )
}

#[test]
fn tx_kind_20_validate_nft_mint_allows_empty_title_and_description() -> TestResult {
    let kind = TxKind::NftMint(NftMintTx {
        nft_id: hash_from_seed(10),
        content_hash: hash_from_seed(11),
        title: String::new(),
        description: String::new(),
    });

    map_err_debug(
        kind.validate(),
        "NftMint validation should not reject empty metadata fields",
    )
}

#[test]
fn tx_kind_21_serialize_deserialize_transfer_roundtrip() -> TestResult {
    let kind = TxKind::Transfer(valid_transfer()?);
    let bytes = map_err_debug(kind.serialize(), "transfer TxKind should serialize")?;
    let decoded = map_err_debug(
        TxKind::deserialize(&bytes),
        "transfer TxKind should deserialize",
    )?;

    require_equal(&decoded, &kind, "transfer TxKind should roundtrip")
}

#[test]
fn tx_kind_22_serialize_deserialize_register_node_roundtrip() -> TestResult {
    let kind = TxKind::RegisterNode(valid_register()?);
    let bytes = map_err_debug(kind.serialize(), "register TxKind should serialize")?;
    let decoded = map_err_debug(
        TxKind::deserialize(&bytes),
        "register TxKind should deserialize",
    )?;

    require_equal(&decoded, &kind, "register TxKind should roundtrip")
}

#[test]
fn tx_kind_23_serialize_deserialize_reward_roundtrip() -> TestResult {
    let kind = TxKind::Reward(valid_reward()?);
    let bytes = map_err_debug(kind.serialize(), "reward TxKind should serialize")?;
    let decoded = map_err_debug(
        TxKind::deserialize(&bytes),
        "reward TxKind should deserialize",
    )?;

    require_equal(&decoded, &kind, "reward TxKind should roundtrip")
}

#[test]
fn tx_kind_24_serialize_deserialize_nft_mint_roundtrip() -> TestResult {
    let kind = TxKind::NftMint(valid_nft_mint());
    let bytes = map_err_debug(kind.serialize(), "NFT mint TxKind should serialize")?;
    let decoded = map_err_debug(
        TxKind::deserialize(&bytes),
        "NFT mint TxKind should deserialize",
    )?;

    require_equal(&decoded, &kind, "NFT mint TxKind should roundtrip")
}

#[test]
fn tx_kind_25_serialize_deserialize_nft_transfer_roundtrip() -> TestResult {
    let kind = TxKind::NftTransfer(valid_nft_transfer());
    let bytes = map_err_debug(kind.serialize(), "NFT transfer TxKind should serialize")?;
    let decoded = map_err_debug(
        TxKind::deserialize(&bytes),
        "NFT transfer TxKind should deserialize",
    )?;

    require_equal(&decoded, &kind, "NFT transfer TxKind should roundtrip")
}

#[test]
fn tx_kind_26_deserialize_rejects_empty_wire() -> TestResult {
    require_any_error(
        TxKind::deserialize(&[]),
        "empty TxKind wire payload should reject",
    )
}

#[test]
fn tx_kind_27_deserialize_rejects_truncated_wire() -> TestResult {
    let kind = TxKind::Transfer(valid_transfer()?);
    let mut bytes = map_err_debug(kind.serialize(), "TxKind should serialize")?;
    let half = bytes
        .len()
        .checked_div(2)
        .ok_or_else(|| "serialized length division failed".to_owned())?;
    bytes.truncate(half);

    require_any_error(
        TxKind::deserialize(&bytes),
        "truncated TxKind wire payload should reject",
    )
}

#[test]
fn tx_kind_28_deserialize_rejects_extra_trailing_bytes() -> TestResult {
    let kind = TxKind::Reward(valid_reward()?);
    let mut bytes = map_err_debug(kind.serialize(), "TxKind should serialize")?;
    bytes.extend_from_slice(&[0_u8, 1_u8, 2_u8, 3_u8]);

    require_any_error(
        TxKind::deserialize(&bytes),
        "TxKind wire payload with trailing bytes should reject",
    )
}

#[test]
fn tx_kind_29_normalized_sender_transfer_returns_sender() -> TestResult {
    let transfer = valid_transfer()?;
    let expected = wallet_with_repeated_hex('a');
    let kind = TxKind::Transfer(transfer);

    require_equal(
        &kind.normalized_sender(),
        &Some(expected),
        "transfer normalized_sender should return sender",
    )
}

#[test]
fn tx_kind_30_normalized_sender_non_transfer_returns_none() -> TestResult {
    let kinds = [
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    for kind in kinds {
        require_equal(
            &kind.normalized_sender(),
            &None,
            "non-transfer normalized_sender should return None",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_31_normalized_receiver_transfer_returns_receiver() -> TestResult {
    let kind = TxKind::Transfer(valid_transfer()?);

    require_equal(
        &kind.normalized_receiver(),
        &Some(wallet_with_repeated_hex('b')),
        "transfer normalized_receiver should return receiver",
    )
}

#[test]
fn tx_kind_32_normalized_receiver_reward_returns_receiver() -> TestResult {
    let kind = TxKind::Reward(valid_reward()?);

    require_equal(
        &kind.normalized_receiver(),
        &Some(wallet_with_repeated_hex('d')),
        "reward normalized_receiver should return receiver",
    )
}

#[test]
fn tx_kind_33_normalized_receiver_register_and_nft_return_none() -> TestResult {
    let kinds = [
        TxKind::RegisterNode(valid_register()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    for kind in kinds {
        require_equal(
            &kind.normalized_receiver(),
            &None,
            "register/NFT normalized_receiver should return None",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_34_touched_addresses_transfer_contains_sender_and_receiver() -> TestResult {
    let kind = TxKind::Transfer(valid_transfer()?);
    let actual = btree_from_vec(kind.touched_addresses());

    let expected = BTreeSet::from([wallet_with_repeated_hex('a'), wallet_with_repeated_hex('b')]);

    require_equal(
        &actual,
        &expected,
        "transfer should touch sender and receiver",
    )
}

#[test]
fn tx_kind_35_touched_addresses_reward_contains_receiver_only() -> TestResult {
    let kind = TxKind::Reward(valid_reward()?);
    let actual = btree_from_vec(kind.touched_addresses());
    let expected = BTreeSet::from([wallet_with_repeated_hex('d')]);

    require_equal(&actual, &expected, "reward should touch receiver only")
}

#[test]
fn tx_kind_36_touched_addresses_register_and_nft_are_empty() -> TestResult {
    let kinds = [
        TxKind::RegisterNode(valid_register()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    for kind in kinds {
        require(
            kind.touched_addresses().is_empty(),
            "register and NFT variants should not touch account balances",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_37_touched_addresses_deduplicates_same_transfer_wallets() -> TestResult {
    let wallet = wallet_array(&wallet_with_repeated_hex('a'))?;
    let kind = TxKind::Transfer(Transaction {
        sender: wallet,
        receiver: wallet,
        amount: 1,
        timestamp: UNIX_2000,
    });

    let actual = btree_from_vec(kind.touched_addresses());

    require_equal(
        &actual.len(),
        &1_usize,
        "touched_addresses should deduplicate identical sender and receiver",
    )?;
    require(
        actual.contains(&wallet_with_repeated_hex('a')),
        "deduplicated touched address should contain wallet",
    )?;

    Ok(())
}

#[test]
fn tx_kind_38_normalize_address_bytes_accepts_canonical_wallet() -> TestResult {
    let wallet = wallet_with_repeated_hex('a');
    let normalized = normalize_address_bytes(wallet.as_bytes());

    require_equal(
        &normalized,
        &wallet,
        "normalize_address_bytes should return canonical wallet",
    )
}

#[test]
fn tx_kind_39_normalize_address_bytes_rejects_uppercase_bytes() -> TestResult {
    let normalized = normalize_address_bytes(uppercase_wallet_with_repeated_hex('a').as_bytes());

    require_equal(
        &normalized,
        &String::new(),
        "normalize_address_bytes should reject uppercase stored bytes",
    )
}

#[test]
fn tx_kind_40_normalize_address_bytes_rejects_wrong_prefix() -> TestResult {
    let wrong_prefix = format!("x{}", "a".repeat(128));
    let normalized = normalize_address_bytes(wrong_prefix.as_bytes());

    require_equal(
        &normalized,
        &String::new(),
        "normalize_address_bytes should reject wrong-prefix wallet bytes",
    )
}

#[test]
fn tx_kind_41_normalize_address_bytes_rejects_non_hex() -> TestResult {
    let non_hex = format!("r{}z", "a".repeat(127));
    let normalized = normalize_address_bytes(non_hex.as_bytes());

    require_equal(
        &normalized,
        &String::new(),
        "normalize_address_bytes should reject non-hex wallet bytes",
    )
}

#[test]
fn tx_kind_42_normalize_address_bytes_rejects_nul_byte() -> TestResult {
    let mut bytes = wallet_with_repeated_hex('a').into_bytes();

    if let Some(byte) = bytes.get_mut(10) {
        *byte = 0;
    } else {
        return Err("failed to mutate wallet byte".to_owned());
    }

    let normalized = normalize_address_bytes(&bytes);

    require_equal(
        &normalized,
        &String::new(),
        "normalize_address_bytes should reject NUL-mutated wallet bytes",
    )
}

#[test]
fn tx_kind_43_normalize_address_bytes_rejects_non_utf8() -> TestResult {
    let mut bytes = wallet_with_repeated_hex('a').into_bytes();

    if let Some(byte) = bytes.get_mut(1) {
        *byte = 0xFF;
    } else {
        return Err("failed to mutate wallet byte".to_owned());
    }

    let normalized = normalize_address_bytes(&bytes);

    require_equal(
        &normalized,
        &String::new(),
        "normalize_address_bytes should reject non-UTF8 wallet bytes",
    )
}

#[test]
fn tx_kind_44_invalid_transfer_addresses_not_reported_as_touched() -> TestResult {
    let kind = TxKind::Transfer(Transaction {
        sender: wallet_array(&uppercase_wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&format!("x{}", "b".repeat(128)))?,
        amount: 1,
        timestamp: UNIX_2000,
    });

    require_equal(
        &kind.normalized_sender(),
        &None,
        "invalid sender bytes should normalize to None",
    )?;
    require_equal(
        &kind.normalized_receiver(),
        &None,
        "invalid receiver bytes should normalize to None",
    )?;
    require(
        kind.touched_addresses().is_empty(),
        "invalid transfer wallet bytes should not produce touched addresses",
    )?;

    Ok(())
}

#[test]
fn tx_kind_45_property_generated_transfer_addresses_roundtrip_and_touch() -> TestResult {
    for seed in 0_u64..64_u64 {
        let sender = wallet_from_seed(seed);
        let receiver = wallet_from_seed(seed.saturating_add(10_000));

        let kind = TxKind::Transfer(Transaction {
            sender: wallet_array(&sender)?,
            receiver: wallet_array(&receiver)?,
            amount: seed
                .checked_add(1)
                .ok_or_else(|| "amount seed overflowed".to_owned())?,
            timestamp: UNIX_2000,
        });

        let bytes = map_err_debug(
            kind.serialize(),
            "generated transfer TxKind should serialize",
        )?;
        let decoded = map_err_debug(
            TxKind::deserialize(&bytes),
            "generated transfer TxKind should deserialize",
        )?;

        require_equal(
            &decoded,
            &kind,
            "generated transfer TxKind should roundtrip",
        )?;

        let touched = btree_from_vec(decoded.touched_addresses());
        let expected = BTreeSet::from([sender, receiver]);

        require_equal(
            &touched,
            &expected,
            "generated transfer should touch generated sender and receiver",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_46_property_generated_rewards_roundtrip_and_touch_receiver() -> TestResult {
    for seed in 0_u64..64_u64 {
        let receiver = wallet_from_seed(seed);

        let kind = TxKind::Reward(RewardTx {
            receiver: wallet_array(&receiver)?,
            amount: 1,
            block_height: seed
                .checked_add(1)
                .ok_or_else(|| "block height seed overflowed".to_owned())?,
            timestamp: UNIX_2000,
        });

        let bytes = map_err_debug(kind.serialize(), "generated reward TxKind should serialize")?;
        let decoded = map_err_debug(
            TxKind::deserialize(&bytes),
            "generated reward TxKind should deserialize",
        )?;

        require_equal(&decoded, &kind, "generated reward TxKind should roundtrip")?;

        let touched = btree_from_vec(decoded.touched_addresses());
        let expected = BTreeSet::from([receiver]);

        require_equal(
            &touched,
            &expected,
            "generated reward should touch generated receiver only",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_47_property_nft_transfer_owner_vectors_validate() -> TestResult {
    for seed in 0_u64..64_u64 {
        let kind = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(seed),
            new_owner_wallet: wallet_from_seed(seed.saturating_add(20_000)),
        });

        map_err_debug(
            kind.validate(),
            "generated valid NFT transfer owner should validate",
        )?;
        require(
            kind.touched_addresses().is_empty(),
            "NFT transfer should not touch account-model balances",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_48_fuzz_arbitrary_payloads_do_not_validate_as_good_transactions() -> TestResult {
    for len in 0_usize..256_usize {
        let seed = u64::try_from(len).map_err(|error| format!("len conversion failed: {error}"))?;
        let bytes = bytes_from_seed(seed, len);

        if let Ok(kind) = TxKind::deserialize(&bytes) {
            require_any_error(
                kind.validate(),
                "arbitrary decoded TxKind should not pass validation",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_kind_49_adversarial_mixed_batch_counts_valid_and_invalid() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..40_u64 {
        let valid_transfer = TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_from_seed(seed))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(1_000)))?,
            amount: seed
                .checked_add(1)
                .ok_or_else(|| "valid transfer amount overflowed".to_owned())?,
            timestamp: UNIX_2000,
        });
        let valid_wire = map_err_debug(
            valid_transfer.serialize(),
            "valid mixed transfer should serialize",
        )?;
        wires.push(valid_wire.clone());

        if seed < 10 {
            wires.push(valid_wire.clone());
        }

        let invalid_transfer = TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_from_seed(seed.saturating_add(2_000)))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(3_000)))?,
            amount: 0,
            timestamp: UNIX_2000,
        });
        wires.push(map_err_debug(
            invalid_transfer.serialize(),
            "invalid mixed transfer should serialize",
        )?);

        let invalid_nft_transfer = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(seed),
            new_owner_wallet: format!("x{}", wallet_body_from_seed(seed)),
        });
        wires.push(map_err_debug(
            invalid_nft_transfer.serialize(),
            "invalid mixed NFT transfer should serialize",
        )?);

        let mut truncated = valid_wire;
        let half = truncated
            .len()
            .checked_div(2)
            .ok_or_else(|| "truncated length division failed".to_owned())?;
        truncated.truncate(half);
        wires.push(truncated);
    }

    let mut valid_unique = 0_usize;
    let mut valid_duplicates = 0_usize;
    let mut rejected = 0_usize;
    let mut seen = BTreeSet::new();

    for wire in wires {
        match TxKind::deserialize(&wire) {
            Ok(kind) => {
                if kind.validate().is_ok() {
                    let key = map_err_debug(kind.serialize(), "valid TxKind key should serialize")?;

                    if seen.insert(key) {
                        valid_unique = valid_unique
                            .checked_add(1)
                            .ok_or_else(|| "valid unique counter overflowed".to_owned())?;
                    } else {
                        valid_duplicates = valid_duplicates
                            .checked_add(1)
                            .ok_or_else(|| "valid duplicate counter overflowed".to_owned())?;
                    }
                } else {
                    rejected = rejected
                        .checked_add(1)
                        .ok_or_else(|| "rejected counter overflowed".to_owned())?;
                }
            }
            Err(_) => {
                rejected = rejected
                    .checked_add(1)
                    .ok_or_else(|| "rejected counter overflowed".to_owned())?;
            }
        }
    }

    require_equal(
        &valid_unique,
        &40_usize,
        "mixed batch should have 40 unique valid transfers",
    )?;
    require_equal(
        &valid_duplicates,
        &10_usize,
        "mixed batch should detect 10 duplicate transfers",
    )?;
    require_equal(
        &rejected,
        &120_usize,
        "mixed batch should reject invalid and truncated items",
    )?;

    Ok(())
}

#[test]
fn tx_kind_50_load_serializes_deserializes_and_validates_many_variants() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..128_u64 {
        let transfer = TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_from_seed(seed))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(50_000)))?,
            amount: seed
                .checked_add(1)
                .ok_or_else(|| "transfer amount overflowed".to_owned())?,
            timestamp: UNIX_2000,
        });
        wires.push(map_err_debug(
            transfer.serialize(),
            "load transfer should serialize",
        )?);

        let reward = TxKind::Reward(RewardTx {
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(100_000)))?,
            amount: 1,
            block_height: seed
                .checked_add(1)
                .ok_or_else(|| "reward block height overflowed".to_owned())?,
            timestamp: UNIX_2000,
        });
        wires.push(map_err_debug(
            reward.serialize(),
            "load reward should serialize",
        )?);

        let nft_transfer = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(seed),
            new_owner_wallet: wallet_from_seed(seed.saturating_add(150_000)),
        });
        wires.push(map_err_debug(
            nft_transfer.serialize(),
            "load NFT transfer should serialize",
        )?);
    }

    let mut accepted = 0_usize;

    for wire in wires {
        let kind = map_err_debug(TxKind::deserialize(&wire), "load TxKind should deserialize")?;
        map_err_debug(kind.validate(), "load TxKind should validate")?;

        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| "accepted counter overflowed".to_owned())?;
    }

    require_equal(
        &accepted,
        &384_usize,
        "load should validate 128 each of transfer, reward, and NFT transfer",
    )?;

    Ok(())
}

#[test]
fn tx_kind_51_transfer_with_same_sender_receiver_touches_one_address_but_validate_rejects()
-> TestResult {
    let wallet = wallet_array(&wallet_with_repeated_hex('a'))?;
    let kind = TxKind::Transfer(Transaction {
        sender: wallet,
        receiver: wallet,
        amount: 1,
        timestamp: UNIX_2000,
    });

    let touched = btree_from_vec(kind.touched_addresses());

    require_equal(
        &touched.len(),
        &1_usize,
        "same sender and receiver should deduplicate in touched_addresses",
    )?;
    require(
        touched.contains(&wallet_with_repeated_hex('a')),
        "deduplicated touched set should contain the shared wallet",
    )?;
    require_validation_error_contains(
        kind.validate(),
        "Invalid Transfer transaction",
        "same sender/receiver transfer should fail validation",
    )?;

    Ok(())
}

#[test]
fn tx_kind_52_transfer_with_zero_amount_still_reports_touched_addresses() -> TestResult {
    let kind = TxKind::Transfer(invalid_transfer_zero_amount()?);
    let touched = btree_from_vec(kind.touched_addresses());

    let expected = BTreeSet::from([wallet_with_repeated_hex('a'), wallet_with_repeated_hex('b')]);

    require_equal(
        &touched,
        &expected,
        "address helper should report valid addresses even when amount is invalid",
    )?;
    require_validation_error_contains(
        kind.validate(),
        "Invalid Transfer transaction",
        "zero amount transfer should fail validation",
    )?;

    Ok(())
}

#[test]
fn tx_kind_53_transfer_with_invalid_sender_only_reports_valid_receiver() -> TestResult {
    let kind = TxKind::Transfer(Transaction {
        sender: wallet_array(&uppercase_wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: UNIX_2000,
    });

    require_equal(
        &kind.normalized_sender(),
        &None,
        "uppercase stored sender bytes should not normalize",
    )?;
    require_equal(
        &kind.normalized_receiver(),
        &Some(wallet_with_repeated_hex('b')),
        "valid receiver should still normalize",
    )?;

    let touched = btree_from_vec(kind.touched_addresses());
    require_equal(
        &touched,
        &BTreeSet::from([wallet_with_repeated_hex('b')]),
        "only valid receiver should be reported as touched",
    )?;

    Ok(())
}

#[test]
fn tx_kind_54_transfer_with_invalid_receiver_only_reports_valid_sender() -> TestResult {
    let kind = TxKind::Transfer(Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&format!("x{}", "b".repeat(128)))?,
        amount: 1,
        timestamp: UNIX_2000,
    });

    require_equal(
        &kind.normalized_sender(),
        &Some(wallet_with_repeated_hex('a')),
        "valid sender should normalize",
    )?;
    require_equal(
        &kind.normalized_receiver(),
        &None,
        "wrong-prefix receiver should not normalize",
    )?;

    let touched = btree_from_vec(kind.touched_addresses());
    require_equal(
        &touched,
        &BTreeSet::from([wallet_with_repeated_hex('a')]),
        "only valid sender should be reported as touched",
    )?;

    Ok(())
}

#[test]
fn tx_kind_55_reward_with_invalid_receiver_has_no_normalized_receiver_or_touched_addresses()
-> TestResult {
    let kind = TxKind::Reward(RewardTx {
        receiver: wallet_array(&format!("x{}", "d".repeat(128)))?,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    });

    require_equal(
        &kind.normalized_receiver(),
        &None,
        "invalid reward receiver should not normalize",
    )?;
    require(
        kind.touched_addresses().is_empty(),
        "invalid reward receiver should not produce touched addresses",
    )?;
    require_validation_error_contains(
        kind.validate(),
        "Invalid Reward transaction",
        "invalid reward receiver should fail validation",
    )?;

    Ok(())
}

#[test]
fn tx_kind_56_register_node_never_reports_sender_receiver_or_touched_addresses() -> TestResult {
    let kind = TxKind::RegisterNode(valid_register()?);

    require_equal(
        &kind.normalized_sender(),
        &None,
        "register node should not have normalized sender",
    )?;
    require_equal(
        &kind.normalized_receiver(),
        &None,
        "register node should not have normalized receiver",
    )?;
    require(
        kind.touched_addresses().is_empty(),
        "register node should not touch account balances",
    )?;

    Ok(())
}

#[test]
fn tx_kind_57_nft_mint_never_reports_sender_receiver_or_touched_addresses() -> TestResult {
    let kind = TxKind::NftMint(valid_nft_mint());

    require_equal(
        &kind.normalized_sender(),
        &None,
        "NFT mint should not have normalized sender",
    )?;
    require_equal(
        &kind.normalized_receiver(),
        &None,
        "NFT mint should not have normalized receiver",
    )?;
    require(
        kind.touched_addresses().is_empty(),
        "NFT mint should not touch account balances",
    )?;

    Ok(())
}

#[test]
fn tx_kind_58_nft_transfer_never_reports_sender_receiver_or_touched_addresses() -> TestResult {
    let kind = TxKind::NftTransfer(valid_nft_transfer());

    require_equal(
        &kind.normalized_sender(),
        &None,
        "NFT transfer should not have normalized sender",
    )?;
    require_equal(
        &kind.normalized_receiver(),
        &None,
        "NFT transfer should not have normalized receiver",
    )?;
    require(
        kind.touched_addresses().is_empty(),
        "NFT transfer should not touch account balances",
    )?;

    Ok(())
}

#[test]
fn tx_kind_59_normalize_address_bytes_rejects_empty_and_short_inputs() -> TestResult {
    let cases: [&[u8]; 4] = [b"", b"r", b"ra", b"rabc"];

    for case in cases {
        let normalized = normalize_address_bytes(case);

        require_equal(
            &normalized,
            &String::new(),
            "empty or short wallet bytes should normalize to empty string",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_60_normalize_address_bytes_rejects_long_input() -> TestResult {
    let long_wallet = format!("r{}", "a".repeat(129));
    let normalized = normalize_address_bytes(long_wallet.as_bytes());

    require_equal(
        &normalized,
        &String::new(),
        "long wallet bytes should normalize to empty string",
    )
}

#[test]
fn tx_kind_61_normalize_address_bytes_accepts_trailing_nul_padding() -> TestResult {
    let wallet = wallet_with_repeated_hex('a');
    let mut bytes = wallet.clone().into_bytes();
    bytes.extend_from_slice(&[0_u8, 0_u8]);

    let normalized = normalize_address_bytes(&bytes);

    require_equal(
        &normalized,
        &wallet,
        "normalize_address_bytes should trim trailing NUL padding and return canonical wallet",
    )
}

#[test]
fn tx_kind_62_normalize_address_bytes_rejects_internal_space() -> TestResult {
    let wallet = format!("r{} {}", "a".repeat(63), "a".repeat(64));
    let normalized = normalize_address_bytes(wallet.as_bytes());

    require_equal(
        &normalized,
        &String::new(),
        "wallet bytes with internal space should normalize to empty string",
    )
}

#[test]
fn tx_kind_63_normalize_address_bytes_accepts_each_lowercase_hex_digit_repeated() -> TestResult {
    let chars = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    for ch in chars {
        let wallet = wallet_with_repeated_hex(ch);
        let normalized = normalize_address_bytes(wallet.as_bytes());

        require_equal(
            &normalized,
            &wallet,
            "canonical repeated lowercase hex wallet should normalize",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_64_normalize_address_bytes_rejects_invalid_ascii_body_chars() -> TestResult {
    let invalid_chars = ['g', 'G', 'z', 'Z', '-', '_', '/', ':', '@'];

    for ch in invalid_chars {
        let wallet = format!("r{}{}", "a".repeat(127), ch);
        let normalized = normalize_address_bytes(wallet.as_bytes());

        require_equal(
            &normalized,
            &String::new(),
            "invalid ASCII body char should normalize to empty string",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_65_nft_transfer_accepts_each_lowercase_hex_owner_vector() -> TestResult {
    let chars = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    for ch in chars {
        let kind = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(u64::from(ch as u32)),
            new_owner_wallet: wallet_with_repeated_hex(ch),
        });

        map_err_debug(
            kind.validate(),
            "NFT transfer owner repeated lowercase hex vector should validate",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_66_nft_transfer_rejects_length_boundaries() -> TestResult {
    let body_lengths = [0_usize, 1, 2, 126, 127, 129, 130, 255];

    for body_len in body_lengths {
        let kind = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(
                u64::try_from(body_len)
                    .map_err(|error| format!("body length conversion failed: {error}"))?,
            ),
            new_owner_wallet: format!("r{}", "a".repeat(body_len)),
        });

        require_validation_error_contains(
            kind.validate(),
            "Invalid NftTransfer",
            "NFT transfer owner length boundary should fail",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_67_nft_transfer_rejects_invalid_ascii_owner_body_chars() -> TestResult {
    let invalid_chars = ['g', 'G', 'z', 'Z', '-', '_', '/', ':', '@'];

    for ch in invalid_chars {
        let kind = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(u64::from(ch as u32)),
            new_owner_wallet: format!("r{}{}", "a".repeat(127), ch),
        });

        require_validation_error_contains(
            kind.validate(),
            "Invalid NftTransfer",
            "NFT transfer invalid ASCII owner body char should fail",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_68_nft_transfer_rejects_unicode_lookalike_prefix() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(68),
        new_owner_wallet: format!("ŕ{}", "a".repeat(127)),
    });

    require_validation_error_contains(
        kind.validate(),
        "Invalid NftTransfer",
        "NFT transfer unicode lookalike prefix should fail",
    )
}

#[test]
fn tx_kind_69_nft_transfer_rejects_unicode_body_character() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(69),
        new_owner_wallet: format!("r{}é", "a".repeat(126)),
    });

    require_validation_error_contains(
        kind.validate(),
        "Invalid NftTransfer",
        "NFT transfer unicode body char should fail",
    )
}

#[test]
fn tx_kind_70_nft_mint_accepts_large_metadata_fields() -> TestResult {
    let kind = TxKind::NftMint(NftMintTx {
        nft_id: hash_from_seed(70),
        content_hash: hash_from_seed(71),
        title: "T".repeat(1024),
        description: "D".repeat(4096),
    });

    map_err_debug(
        kind.validate(),
        "NFT mint validation should allow large metadata strings",
    )?;

    let bytes = map_err_debug(kind.serialize(), "large NFT mint should serialize")?;
    let decoded = map_err_debug(
        TxKind::deserialize(&bytes),
        "large NFT mint should deserialize",
    )?;

    require_equal(&decoded, &kind, "large NFT mint should roundtrip")?;

    Ok(())
}

#[test]
fn tx_kind_71_nft_mint_accepts_zero_hashes() -> TestResult {
    let kind = TxKind::NftMint(NftMintTx {
        nft_id: [0_u8; 64],
        content_hash: [0_u8; 64],
        title: String::new(),
        description: String::new(),
    });

    map_err_debug(
        kind.validate(),
        "NFT mint validation should allow zero hashes structurally",
    )?;

    Ok(())
}

#[test]
fn tx_kind_72_nft_transfer_accepts_zero_nft_id_with_valid_owner() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: [0_u8; 64],
        new_owner_wallet: wallet_with_repeated_hex('a'),
    });

    map_err_debug(
        kind.validate(),
        "NFT transfer validation should allow zero nft_id structurally",
    )
}

#[test]
fn tx_kind_73_deserialize_rejects_invalid_transfer() -> TestResult {
    let kind = TxKind::Transfer(invalid_transfer_zero_amount()?);
    let bytes = map_err_debug(kind.serialize(), "invalid transfer TxKind should serialize")?;

    require_validation_error_contains(
        TxKind::deserialize(&bytes),
        "Invalid Transfer transaction",
        "TxKind::deserialize should reject invalid transfer wire",
    )
}

#[test]
fn tx_kind_74_deserialize_rejects_invalid_register() -> TestResult {
    let kind = TxKind::RegisterNode(invalid_register_old_timestamp()?);
    let bytes = map_err_debug(kind.serialize(), "invalid register TxKind should serialize")?;

    require_validation_error_contains(
        TxKind::deserialize(&bytes),
        "Invalid RegisterNode transaction",
        "TxKind::deserialize should reject invalid register wire",
    )
}

#[test]
fn tx_kind_75_deserialize_rejects_invalid_reward() -> TestResult {
    let kind = TxKind::Reward(invalid_reward_zero_height()?);
    let bytes = map_err_debug(kind.serialize(), "invalid reward TxKind should serialize")?;

    require_validation_error_contains(
        TxKind::deserialize(&bytes),
        "Invalid Reward transaction",
        "TxKind::deserialize should reject invalid reward wire",
    )
}

#[test]
fn tx_kind_76_deserialize_rejects_invalid_nft_transfer() -> TestResult {
    let kind = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(76),
        new_owner_wallet: format!("x{}", "a".repeat(128)),
    });
    let bytes = map_err_debug(
        kind.serialize(),
        "invalid NFT transfer TxKind should serialize",
    )?;

    require_validation_error_contains(
        TxKind::deserialize(&bytes),
        "Invalid NftTransfer",
        "TxKind::deserialize should reject invalid NFT transfer wire",
    )
}

#[test]
fn tx_kind_77_all_variant_serialized_payloads_are_distinct_for_known_values() -> TestResult {
    let variants = [
        TxKind::Transfer(valid_transfer()?),
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    let mut serialized = BTreeSet::new();

    for kind in variants {
        let bytes = map_err_debug(kind.serialize(), "variant should serialize")?;
        require(
            serialized.insert(bytes),
            "each known TxKind variant should have distinct serialized bytes",
        )?;
    }

    require_equal(
        &serialized.len(),
        &5_usize,
        "all five variant payloads should be distinct",
    )?;

    Ok(())
}

#[test]
fn tx_kind_78_all_variant_tags_are_unique() -> TestResult {
    let variants = [
        TxKind::Transfer(valid_transfer()?),
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    let mut tags = BTreeSet::new();

    for kind in variants {
        require(tags.insert(kind.tag()), "variant tag should be unique")?;
    }

    require_equal(&tags.len(), &5_usize, "all TxKind tags should be unique")?;

    Ok(())
}

#[test]
fn tx_kind_79_repeated_serialization_is_stable_for_all_variants() -> TestResult {
    let variants = [
        TxKind::Transfer(valid_transfer()?),
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    for kind in variants {
        let first = map_err_debug(
            kind.serialize(),
            "first variant serialization should succeed",
        )?;
        let second = map_err_debug(
            kind.serialize(),
            "second variant serialization should succeed",
        )?;

        require_equal(
            &first,
            &second,
            "repeated TxKind serialization should be deterministic",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_80_repeated_roundtrip_is_stable_for_all_variants() -> TestResult {
    let variants = [
        TxKind::Transfer(valid_transfer()?),
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    for original in variants {
        let mut current = original.clone();

        for _ in 0_usize..5_usize {
            let bytes = map_err_debug(current.serialize(), "roundtrip serialize should succeed")?;
            current = map_err_debug(
                TxKind::deserialize(&bytes),
                "roundtrip deserialize should succeed",
            )?;
        }

        require_equal(
            &current,
            &original,
            "TxKind should remain stable after repeated roundtrips",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_81_clone_equality_and_tag_stability() -> TestResult {
    let original = TxKind::NftTransfer(valid_nft_transfer());
    let cloned = original.clone();

    require_equal(&cloned, &original, "cloned TxKind should equal original")?;
    require_equal(
        &cloned.tag(),
        &original.tag(),
        "cloned TxKind tag should match original",
    )?;

    Ok(())
}

#[test]
fn tx_kind_82_transfer_mutation_changes_equality() -> TestResult {
    let original = TxKind::Transfer(valid_transfer()?);
    let mut mutated = original.clone();

    if let TxKind::Transfer(tx) = &mut mutated {
        tx.amount = tx
            .amount
            .checked_add(1)
            .ok_or_else(|| "amount mutation overflowed".to_owned())?;
    } else {
        return Err("expected transfer variant".to_owned());
    }

    require_not_equal(
        &mutated,
        &original,
        "mutating transfer amount should change TxKind equality",
    )
}

#[test]
fn tx_kind_83_reward_mutation_changes_equality() -> TestResult {
    let original = TxKind::Reward(valid_reward()?);
    let mut mutated = original.clone();

    if let TxKind::Reward(tx) = &mut mutated {
        tx.block_height = tx
            .block_height
            .checked_add(1)
            .ok_or_else(|| "block height mutation overflowed".to_owned())?;
    } else {
        return Err("expected reward variant".to_owned());
    }

    require_not_equal(
        &mutated,
        &original,
        "mutating reward block height should change TxKind equality",
    )
}

#[test]
fn tx_kind_84_nft_mint_mutation_changes_equality() -> TestResult {
    let original = TxKind::NftMint(valid_nft_mint());
    let mut mutated = original.clone();

    if let TxKind::NftMint(tx) = &mut mutated {
        tx.title.push_str(" changed");
    } else {
        return Err("expected NFT mint variant".to_owned());
    }

    require_not_equal(
        &mutated,
        &original,
        "mutating NFT mint title should change TxKind equality",
    )
}

#[test]
fn tx_kind_85_nft_transfer_mutation_changes_equality() -> TestResult {
    let original = TxKind::NftTransfer(valid_nft_transfer());
    let mut mutated = original.clone();

    if let TxKind::NftTransfer(tx) = &mut mutated {
        tx.new_owner_wallet = wallet_with_repeated_hex('f');
    } else {
        return Err("expected NFT transfer variant".to_owned());
    }

    require_not_equal(
        &mutated,
        &original,
        "mutating NFT transfer owner should change TxKind equality",
    )
}

#[test]
fn tx_kind_86_deserialize_rejects_single_byte_invalid_variant_tags() -> TestResult {
    for tag in 5_u8..=32_u8 {
        let bytes = [tag];

        require_any_error(
            TxKind::deserialize(&bytes),
            "single-byte invalid variant tag should reject",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_87_fuzz_truncated_prefixes_reject_for_each_variant() -> TestResult {
    let variants = [
        TxKind::Transfer(valid_transfer()?),
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    for kind in variants {
        let bytes = map_err_debug(kind.serialize(), "variant should serialize")?;

        for cut in 0_usize..bytes.len() {
            let prefix = bytes
                .get(..cut)
                .ok_or_else(|| format!("failed to get prefix cut {cut}"))?;

            require_any_error(
                TxKind::deserialize(prefix),
                "truncated TxKind prefix should reject",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_kind_88_fuzz_bitflips_reject_or_decode_to_different_value() -> TestResult {
    let original = TxKind::Transfer(valid_transfer()?);
    let original_bytes = map_err_debug(original.serialize(), "original TxKind should serialize")?;

    for byte_index in 0_usize..original_bytes.len().min(64) {
        let mut mutated = original_bytes.clone();

        if let Some(byte) = mutated.get_mut(byte_index) {
            *byte ^= 0x01;
        } else {
            return Err(format!("failed to mutate byte index {byte_index}"));
        }

        if let Ok(decoded) = TxKind::deserialize(&mutated) {
            require_not_equal(
                &decoded,
                &original,
                "accepted bitflip mutation should not decode to original TxKind",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_kind_89_property_generated_register_nodes_roundtrip_and_validate() -> TestResult {
    for seed in 0_u64..64_u64 {
        let kind = TxKind::RegisterNode(RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "timestamp seed overflowed".to_owned())?,
        });

        let bytes = map_err_debug(
            kind.serialize(),
            "generated register TxKind should serialize",
        )?;
        let decoded = map_err_debug(
            TxKind::deserialize(&bytes),
            "generated register TxKind should deserialize",
        )?;

        require_equal(
            &decoded,
            &kind,
            "generated register TxKind should roundtrip",
        )?;
        map_err_debug(
            decoded.validate(),
            "generated register TxKind should validate",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_90_property_generated_nft_mints_roundtrip_and_validate() -> TestResult {
    for seed in 0_u64..64_u64 {
        let kind = TxKind::NftMint(NftMintTx {
            nft_id: hash_from_seed(seed),
            content_hash: hash_from_seed(seed.saturating_add(1_000)),
            title: format!("NFT #{seed}"),
            description: format!("description #{seed}"),
        });

        let bytes = map_err_debug(
            kind.serialize(),
            "generated NFT mint TxKind should serialize",
        )?;
        let decoded = map_err_debug(
            TxKind::deserialize(&bytes),
            "generated NFT mint TxKind should deserialize",
        )?;

        require_equal(
            &decoded,
            &kind,
            "generated NFT mint TxKind should roundtrip",
        )?;
        map_err_debug(
            decoded.validate(),
            "generated NFT mint TxKind should validate",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_91_property_generated_nft_transfers_roundtrip_and_validate() -> TestResult {
    for seed in 0_u64..64_u64 {
        let kind = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(seed),
            new_owner_wallet: wallet_from_seed(seed.saturating_add(2_000)),
        });

        let bytes = map_err_debug(
            kind.serialize(),
            "generated NFT transfer TxKind should serialize",
        )?;
        let decoded = map_err_debug(
            TxKind::deserialize(&bytes),
            "generated NFT transfer TxKind should deserialize",
        )?;

        require_equal(
            &decoded,
            &kind,
            "generated NFT transfer TxKind should roundtrip",
        )?;
        map_err_debug(
            decoded.validate(),
            "generated NFT transfer TxKind should validate",
        )?;
    }

    Ok(())
}

#[test]
fn tx_kind_92_load_many_normalized_addresses_are_unique() -> TestResult {
    let mut normalized = BTreeSet::new();

    for seed in 0_u64..512_u64 {
        let wallet = wallet_from_seed(seed);
        let value = normalize_address_bytes(wallet.as_bytes());

        require_equal(&value, &wallet, "generated wallet should normalize")?;
        require(
            normalized.insert(value),
            "normalized generated wallet should be unique",
        )?;
    }

    require_equal(
        &normalized.len(),
        &512_usize,
        "should collect 512 unique normalized addresses",
    )?;

    Ok(())
}

#[test]
fn tx_kind_93_load_invalid_nft_transfers_all_reject() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let kind = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(seed),
            new_owner_wallet: format!("x{}", wallet_body_from_seed(seed)),
        });

        if kind.validate().is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all wrong-prefix NFT transfer owners should reject",
    )?;

    Ok(())
}

#[test]
fn tx_kind_94_load_invalid_transfer_variants_deserialize_rejects() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let kind = TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_from_seed(seed))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(10_000)))?,
            amount: 0,
            timestamp: UNIX_2000,
        });

        let bytes = map_err_debug(kind.serialize(), "invalid transfer should serialize")?;

        if TxKind::deserialize(&bytes).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all zero-amount transfer TxKinds should reject during deserialization",
    )?;

    Ok(())
}

#[test]
fn tx_kind_95_load_invalid_reward_variants_deserialize_rejects() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let kind = TxKind::Reward(RewardTx {
            receiver: wallet_array(&wallet_from_seed(seed))?,
            amount: 1,
            block_height: 0,
            timestamp: UNIX_2000,
        });

        let bytes = map_err_debug(kind.serialize(), "invalid reward should serialize")?;

        if TxKind::deserialize(&bytes).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all zero-height reward TxKinds should reject during deserialization",
    )?;

    Ok(())
}

#[test]
fn tx_kind_96_load_invalid_register_variants_deserialize_rejects() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let kind = TxKind::RegisterNode(RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000.saturating_sub(1),
        });

        let bytes = map_err_debug(kind.serialize(), "invalid register should serialize")?;

        if TxKind::deserialize(&bytes).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all old-timestamp register TxKinds should reject during deserialization",
    )?;

    Ok(())
}

#[test]
fn tx_kind_97_mixed_variant_batch_counts_expected_touched_addresses() -> TestResult {
    let variants = [
        TxKind::Transfer(valid_transfer()?),
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    let mut total_touched = 0_usize;

    for kind in variants {
        total_touched = total_touched
            .checked_add(kind.touched_addresses().len())
            .ok_or_else(|| "total touched counter overflowed".to_owned())?;
    }

    require_equal(
        &total_touched,
        &3_usize,
        "transfer touches 2, reward touches 1, other variants touch 0",
    )?;

    Ok(())
}

#[test]
fn tx_kind_98_mixed_valid_variant_batch_all_validate() -> TestResult {
    let variants = [
        TxKind::Transfer(valid_transfer()?),
        TxKind::RegisterNode(valid_register()?),
        TxKind::Reward(valid_reward()?),
        TxKind::NftMint(valid_nft_mint()),
        TxKind::NftTransfer(valid_nft_transfer()),
    ];

    let mut accepted = 0_usize;

    for kind in variants {
        map_err_debug(kind.validate(), "valid mixed variant should validate")?;

        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| "accepted counter overflowed".to_owned())?;
    }

    require_equal(
        &accepted,
        &5_usize,
        "all five valid variants should validate",
    )?;

    Ok(())
}

#[test]
fn tx_kind_99_mixed_invalid_variant_batch_all_reject_except_nft_mint_not_included() -> TestResult {
    let variants = [
        TxKind::Transfer(invalid_transfer_zero_amount()?),
        TxKind::RegisterNode(invalid_register_old_timestamp()?),
        TxKind::Reward(invalid_reward_zero_height()?),
        TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(99),
            new_owner_wallet: format!("x{}", "a".repeat(128)),
        }),
    ];

    let mut rejected = 0_usize;

    for kind in variants {
        if kind.validate().is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &4_usize,
        "all invalid non-mint variants should reject",
    )?;

    Ok(())
}

#[test]
fn tx_kind_100_adversarial_large_mixed_load_counts_valid_duplicates_and_rejected() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..64_u64 {
        let valid_transfer = TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_from_seed(seed))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(1_000)))?,
            amount: seed
                .checked_add(1)
                .ok_or_else(|| "valid transfer amount overflowed".to_owned())?,
            timestamp: UNIX_2000,
        });
        let valid_transfer_wire = map_err_debug(
            valid_transfer.serialize(),
            "valid adversarial transfer should serialize",
        )?;
        wires.push(valid_transfer_wire.clone());

        if seed < 16 {
            wires.push(valid_transfer_wire.clone());
        }

        let valid_nft = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(seed),
            new_owner_wallet: wallet_from_seed(seed.saturating_add(5_000)),
        });
        wires.push(map_err_debug(
            valid_nft.serialize(),
            "valid adversarial NFT transfer should serialize",
        )?);

        let invalid_transfer = TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_from_seed(seed.saturating_add(10_000)))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(20_000)))?,
            amount: 0,
            timestamp: UNIX_2000,
        });
        wires.push(map_err_debug(
            invalid_transfer.serialize(),
            "invalid adversarial transfer should serialize",
        )?);

        let invalid_nft = TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(seed.saturating_add(30_000)),
            new_owner_wallet: format!("x{}", wallet_body_from_seed(seed)),
        });
        wires.push(map_err_debug(
            invalid_nft.serialize(),
            "invalid adversarial NFT transfer should serialize",
        )?);

        let mut truncated = valid_transfer_wire;
        let half = truncated
            .len()
            .checked_div(2)
            .ok_or_else(|| "truncated length division failed".to_owned())?;
        truncated.truncate(half);
        wires.push(truncated);
    }

    let mut seen = BTreeSet::new();
    let mut unique_valid = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut rejected = 0_usize;

    for wire in wires {
        match TxKind::deserialize(&wire) {
            Ok(kind) => {
                if kind.validate().is_ok() {
                    let key =
                        map_err_debug(kind.serialize(), "valid adversarial key should serialize")?;

                    if seen.insert(key) {
                        unique_valid = unique_valid
                            .checked_add(1)
                            .ok_or_else(|| "unique valid counter overflowed".to_owned())?;
                    } else {
                        duplicate_valid = duplicate_valid
                            .checked_add(1)
                            .ok_or_else(|| "duplicate valid counter overflowed".to_owned())?;
                    }
                } else {
                    rejected = rejected
                        .checked_add(1)
                        .ok_or_else(|| "rejected counter overflowed".to_owned())?;
                }
            }
            Err(_) => {
                rejected = rejected
                    .checked_add(1)
                    .ok_or_else(|| "rejected counter overflowed".to_owned())?;
            }
        }
    }

    require_equal(
        &unique_valid,
        &128_usize,
        "batch should accept 64 transfers plus 64 NFT transfers",
    )?;
    require_equal(
        &duplicate_valid,
        &16_usize,
        "batch should detect 16 duplicate transfer wires",
    )?;
    require_equal(
        &rejected,
        &192_usize,
        "batch should reject invalid transfers, invalid NFT transfers, and truncated wires",
    )?;

    Ok(())
}
