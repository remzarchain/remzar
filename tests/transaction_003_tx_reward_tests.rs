use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::{REMZAR_WALLET_LEN, UNIT_DIVISOR};

use chrono::Utc;
use postcard::to_allocvec;
use std::collections::BTreeSet;

type TestResult = Result<(), String>;

const UNIX_2000: u64 = 946_684_800;
const UNIX_9999: u64 = 253_402_300_799;
const TEN_YEARS_SECS: u64 = 3600 * 24 * 365 * 10;

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

fn raw_serialize(tx: &RewardTx, context: &str) -> Result<Vec<u8>, String> {
    to_allocvec(tx).map_err(|error| format!("{context}: {error}"))
}

fn now_secs() -> Result<u64, String> {
    u64::try_from(Utc::now().timestamp())
        .map_err(|error| format!("current timestamp conversion failed: {error}"))
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
    if address.as_bytes().len() != REMZAR_WALLET_LEN {
        return Err(format!(
            "wallet_array requires {REMZAR_WALLET_LEN} bytes, got {}",
            address.as_bytes().len()
        ));
    }

    let mut out = [0_u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(address.as_bytes());
    Ok(out)
}

fn array_as_str(arr: &[u8; REMZAR_WALLET_LEN], context: &str) -> Result<String, String> {
    std::str::from_utf8(arr)
        .map(str::to_owned)
        .map_err(|error| format!("{context}: {error}"))
}

fn valid_reward_with_values(
    receiver: String,
    amount: u64,
    block_height: u64,
    timestamp: u64,
) -> Result<RewardTx, String> {
    Ok(RewardTx {
        receiver: wallet_array(&receiver)?,
        amount,
        block_height,
        timestamp,
    })
}

fn valid_reward(amount: u64) -> Result<RewardTx, String> {
    valid_reward_with_values(wallet_with_repeated_hex('a'), amount, 1, now_secs()?)
}

fn max_reward() -> u64 {
    GlobalConfiguration::MAX_BLOCK_REWARD
}

fn amount_over_max() -> Option<u64> {
    GlobalConfiguration::MAX_BLOCK_REWARD.checked_add(1)
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

#[test]
fn reward_tx_01_new_accepts_valid_reward() -> TestResult {
    let tx = map_err_debug(
        RewardTx::new(wallet_with_repeated_hex('a'), 1, 1),
        "valid reward should create",
    )?;

    require_equal(&tx.amount, &1_u64, "amount should be stored")?;
    require_equal(&tx.block_height, &1_u64, "block height should be stored")?;
    require_equal(
        &tx.receiver.len(),
        &REMZAR_WALLET_LEN,
        "receiver should have canonical byte length",
    )?;
    map_err_debug(tx.validate(), "newly created reward should validate")?;

    Ok(())
}

#[test]
fn reward_tx_02_new_canonicalizes_uppercase_receiver() -> TestResult {
    let tx = map_err_debug(
        RewardTx::new(uppercase_wallet_with_repeated_hex('b'), 1, 1),
        "uppercase receiver should canonicalize",
    )?;

    require_equal(
        &array_as_str(&tx.receiver, "receiver utf8")?,
        &wallet_with_repeated_hex('b'),
        "receiver should be stored as lowercase canonical wallet",
    )?;

    Ok(())
}

#[test]
fn reward_tx_03_new_trims_outer_whitespace() -> TestResult {
    let input = format!("\n\t{}  \r\n", uppercase_wallet_with_repeated_hex('c'));

    let tx = map_err_debug(
        RewardTx::new(input, 1, 1),
        "receiver with outer whitespace should canonicalize",
    )?;

    require_equal(
        &array_as_str(&tx.receiver, "receiver utf8")?,
        &wallet_with_repeated_hex('c'),
        "trimmed receiver should be canonical lowercase",
    )?;

    Ok(())
}

#[test]
fn reward_tx_04_new_sets_recent_timestamp() -> TestResult {
    let before = now_secs()?;
    let tx = map_err_debug(
        RewardTx::new(wallet_with_repeated_hex('d'), 1, 1),
        "valid reward should create",
    )?;
    let after = now_secs()?;

    require(
        tx.timestamp >= before && tx.timestamp <= after.saturating_add(1),
        "new reward timestamp should be within test start/end window",
    )?;

    Ok(())
}

#[test]
fn reward_tx_05_new_accepts_max_block_reward() -> TestResult {
    let tx = map_err_debug(
        RewardTx::new(wallet_with_repeated_hex('e'), max_reward(), 1),
        "max block reward should create",
    )?;

    require_equal(
        &tx.amount,
        &max_reward(),
        "max block reward should be stored exactly",
    )?;
    map_err_debug(tx.validate(), "max block reward should validate")?;

    Ok(())
}

#[test]
fn reward_tx_06_new_rejects_zero_amount() -> TestResult {
    require_validation_error_contains(
        RewardTx::new(wallet_with_repeated_hex('a'), 0, 1),
        "Reward amount must be greater than zero",
        "zero reward amount should fail",
    )
}

#[test]
fn reward_tx_07_new_rejects_amount_over_max_when_representable() -> TestResult {
    match amount_over_max() {
        Some(over_max) => require_validation_error_contains(
            RewardTx::new(wallet_with_repeated_hex('a'), over_max, 1),
            "exceeds allowed maximum",
            "amount over max reward should fail",
        ),
        None => Ok(()),
    }
}

#[test]
fn reward_tx_08_new_rejects_zero_block_height() -> TestResult {
    require_validation_error_contains(
        RewardTx::new(wallet_with_repeated_hex('a'), 1, 0),
        "Block height cannot be zero",
        "zero block height should fail",
    )
}

#[test]
fn reward_tx_09_new_accepts_u64_max_block_height() -> TestResult {
    let tx = map_err_debug(
        RewardTx::new(wallet_with_repeated_hex('a'), 1, u64::MAX),
        "u64::MAX block height should create",
    )?;

    require_equal(
        &tx.block_height,
        &u64::MAX,
        "u64::MAX block height should be stored",
    )?;
    map_err_debug(tx.validate(), "u64::MAX block height should validate")?;

    Ok(())
}

#[test]
fn reward_tx_10_new_rejects_empty_receiver() -> TestResult {
    require_validation_error_contains(
        RewardTx::new(String::new(), 1, 1),
        "Invalid receiver address format",
        "empty receiver should fail",
    )
}

#[test]
fn reward_tx_11_new_rejects_short_receiver() -> TestResult {
    require_validation_error_contains(
        RewardTx::new("ra".to_owned(), 1, 1),
        "Invalid receiver address format",
        "short receiver should fail",
    )
}

#[test]
fn reward_tx_12_new_rejects_long_receiver() -> TestResult {
    let long_receiver = format!("r{}", "a".repeat(129));

    require_validation_error_contains(
        RewardTx::new(long_receiver, 1, 1),
        "Invalid receiver address format",
        "long receiver should fail",
    )
}

#[test]
fn reward_tx_13_new_rejects_wrong_prefix_receiver() -> TestResult {
    let wrong_prefix = format!("x{}", "a".repeat(128));

    require_validation_error_contains(
        RewardTx::new(wrong_prefix, 1, 1),
        "Invalid receiver address format",
        "wrong receiver prefix should fail",
    )
}

#[test]
fn reward_tx_14_new_rejects_non_hex_receiver_body() -> TestResult {
    let non_hex = format!("r{}z", "a".repeat(127));

    require_validation_error_contains(
        RewardTx::new(non_hex, 1, 1),
        "Invalid receiver address format",
        "non-hex receiver should fail",
    )
}

#[test]
fn reward_tx_15_new_accepts_full_lowercase_hex_alphabet_receiver() -> TestResult {
    let receiver = format!("r{}", "0123456789abcdef".repeat(8));

    let tx = map_err_debug(
        RewardTx::new(receiver.clone(), 1, 1),
        "full lowercase hex alphabet receiver should create",
    )?;

    require_equal(
        &array_as_str(&tx.receiver, "receiver utf8")?,
        &receiver,
        "full hex alphabet receiver should be stored exactly",
    )?;

    Ok(())
}

#[test]
fn reward_tx_16_validate_accepts_valid_manual_reward() -> TestResult {
    let tx = valid_reward(1)?;

    map_err_debug(tx.validate(), "valid manual reward should validate")?;

    Ok(())
}

#[test]
fn reward_tx_17_validate_rejects_zero_amount() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 0, 1, now_secs()?)?;

    require_validation_error_contains(
        tx.validate(),
        "Reward amount must be greater than zero",
        "validate should reject zero amount",
    )
}

#[test]
fn reward_tx_18_validate_rejects_amount_over_max_when_representable() -> TestResult {
    match amount_over_max() {
        Some(over_max) => {
            let tx =
                valid_reward_with_values(wallet_with_repeated_hex('a'), over_max, 1, now_secs()?)?;

            require_validation_error_contains(
                tx.validate(),
                "exceeds allowed maximum",
                "validate should reject amount over max reward",
            )
        }
        None => Ok(()),
    }
}

#[test]
fn reward_tx_19_validate_rejects_zero_block_height() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 0, now_secs()?)?;

    require_validation_error_contains(
        tx.validate(),
        "Block height cannot be zero",
        "validate should reject zero block height",
    )
}

#[test]
fn reward_tx_20_validate_rejects_uppercase_stored_receiver() -> TestResult {
    let tx = RewardTx {
        receiver: wallet_array(&uppercase_wallet_with_repeated_hex('a'))?,
        amount: 1,
        block_height: 1,
        timestamp: now_secs()?,
    };

    require_any_error(
        tx.validate(),
        "validate should reject uppercase stored receiver bytes",
    )
}

#[test]
fn reward_tx_21_validate_rejects_wrong_prefix_stored_receiver() -> TestResult {
    let tx = RewardTx {
        receiver: wallet_array(&format!("x{}", "a".repeat(128)))?,
        amount: 1,
        block_height: 1,
        timestamp: now_secs()?,
    };

    require_any_error(
        tx.validate(),
        "validate should reject wrong-prefix stored receiver bytes",
    )
}

#[test]
fn reward_tx_22_validate_rejects_non_hex_stored_receiver() -> TestResult {
    let tx = RewardTx {
        receiver: wallet_array(&format!("r{}z", "a".repeat(127)))?,
        amount: 1,
        block_height: 1,
        timestamp: now_secs()?,
    };

    require_any_error(
        tx.validate(),
        "validate should reject non-hex stored receiver bytes",
    )
}

#[test]
fn reward_tx_23_validate_rejects_nul_stored_receiver() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = receiver.get_mut(10) {
        *byte = 0;
    } else {
        return Err("failed to mutate receiver byte".to_owned());
    }

    let tx = RewardTx {
        receiver,
        amount: 1,
        block_height: 1,
        timestamp: now_secs()?,
    };

    require_any_error(
        tx.validate(),
        "validate should reject receiver with NUL byte",
    )
}

#[test]
fn reward_tx_24_validate_rejects_non_utf8_stored_receiver() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = receiver.get_mut(1) {
        *byte = 0xFF;
    } else {
        return Err("failed to mutate receiver byte".to_owned());
    }

    let tx = RewardTx {
        receiver,
        amount: 1,
        block_height: 1,
        timestamp: now_secs()?,
    };

    require_any_error(
        tx.validate(),
        "validate should reject non-UTF8 receiver bytes",
    )
}

#[test]
fn reward_tx_25_validate_rejects_timestamp_before_2000() -> TestResult {
    let tx = valid_reward_with_values(
        wallet_with_repeated_hex('a'),
        1,
        1,
        UNIX_2000.saturating_sub(1),
    )?;

    require_validation_error_contains(
        tx.validate(),
        "UNIX_2000_SECS",
        "timestamp before 2000 should fail",
    )
}

#[test]
fn reward_tx_26_validate_accepts_timestamp_at_2000_boundary() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;

    map_err_debug(
        tx.validate(),
        "timestamp exactly at UNIX_2000 should validate",
    )?;

    Ok(())
}

#[test]
fn reward_tx_27_validate_accepts_near_future_inside_window() -> TestResult {
    let timestamp = now_secs()?
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_sub(120))
        .ok_or_else(|| "inside-window timestamp arithmetic failed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

    map_err_debug(
        tx.validate(),
        "timestamp safely inside ten-year future window should validate",
    )?;

    Ok(())
}

#[test]
fn reward_tx_28_validate_for_runtime_rejects_far_future_timestamp() -> TestResult {
    let now = now_secs()?;
    let timestamp = now
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_add(120))
        .ok_or_else(|| "future timestamp arithmetic failed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

    map_err_debug(
        tx.validate(),
        "replay-safe validate should accept structurally valid future timestamp",
    )?;
    require_any_error(
        tx.validate_for_runtime_at(now),
        "runtime validation should reject timestamp beyond allowed future skew",
    )
}

#[test]
fn reward_tx_29_validate_rejects_u64_max_timestamp() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, u64::MAX)?;

    require_validation_error_contains(
        tx.validate(),
        "UNIX_9999_SECS",
        "u64::MAX timestamp should fail",
    )
}

#[test]
fn reward_tx_30_amount_as_remzar_formats_one_unit() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), UNIT_DIVISOR, 1, UNIX_2000)?;

    let displayed = format!("{:.8}", tx.amount_as_remzar());

    require_equal(
        &displayed,
        &"1.00000000".to_owned(),
        "UNIT_DIVISOR should display as 1 REMZAR",
    )?;

    Ok(())
}

#[test]
fn reward_tx_31_amount_as_remzar_formats_one_micro_unit() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;

    let displayed = format!("{:.8}", tx.amount_as_remzar());

    require_equal(
        &displayed,
        &"0.00000001".to_owned(),
        "one micro-unit should display as 0.00000001 REMZAR",
    )?;

    Ok(())
}

#[test]
fn reward_tx_32_serialize_deserialize_roundtrip() -> TestResult {
    let tx = valid_reward(1)?;
    let bytes = map_err_debug(tx.serialize(), "reward should serialize")?;
    let decoded = map_err_debug(RewardTx::deserialize(&bytes), "reward should deserialize")?;

    require_equal(&decoded, &tx, "reward should roundtrip exactly")?;
    map_err_debug(decoded.validate(), "decoded reward should validate")?;

    Ok(())
}

#[test]
fn reward_tx_33_serialize_is_deterministic_for_fixed_reward() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;

    let first = map_err_debug(tx.serialize(), "first serialize should succeed")?;
    let second = map_err_debug(tx.serialize(), "second serialize should succeed")?;

    require_equal(
        &first,
        &second,
        "fixed reward serialization should be deterministic",
    )?;

    Ok(())
}

#[test]
fn reward_tx_34_deserialize_rejects_empty_wire() -> TestResult {
    require_any_error(
        RewardTx::deserialize(&[]),
        "empty wire payload should be rejected",
    )
}

#[test]
fn reward_tx_35_deserialize_rejects_truncated_wire() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let mut bytes = map_err_debug(tx.serialize(), "reward should serialize")?;
    let half = bytes
        .len()
        .checked_div(2)
        .ok_or_else(|| "serialized length division failed".to_owned())?;
    bytes.truncate(half);

    require_any_error(
        RewardTx::deserialize(&bytes),
        "truncated wire payload should be rejected",
    )
}

#[test]
fn reward_tx_36_deserialize_rejects_zero_amount_wire() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 0, 1, UNIX_2000)?;
    let bytes = raw_serialize(&tx, "zero amount raw reward should raw-serialize")?;

    require_validation_error_contains(
        RewardTx::deserialize(&bytes),
        "Reward amount must be greater than zero",
        "deserialize must reject raw zero amount reward",
    )
}

#[test]
fn reward_tx_37_deserialize_rejects_zero_height_wire() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 0, UNIX_2000)?;
    let bytes = raw_serialize(&tx, "zero height raw reward should raw-serialize")?;

    require_validation_error_contains(
        RewardTx::deserialize(&bytes),
        "Block height cannot be zero",
        "deserialize must reject raw zero block height reward",
    )
}

#[test]
fn reward_tx_38_deserialize_rejects_invalid_receiver_wire() -> TestResult {
    let tx = RewardTx {
        receiver: wallet_array(&format!("x{}", "a".repeat(128)))?,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };
    let bytes = raw_serialize(&tx, "invalid receiver raw reward should raw-serialize")?;

    require_any_error(
        RewardTx::deserialize(&bytes),
        "deserialize must reject raw invalid receiver reward",
    )
}

#[test]
fn reward_tx_39_deserialize_rejects_old_timestamp_wire() -> TestResult {
    let tx = valid_reward_with_values(
        wallet_with_repeated_hex('a'),
        1,
        1,
        UNIX_2000.saturating_sub(1),
    )?;
    let bytes = raw_serialize(&tx, "old timestamp raw reward should raw-serialize")?;

    require_validation_error_contains(
        RewardTx::deserialize(&bytes),
        "UNIX_2000_SECS",
        "deserialize must reject raw old timestamp reward",
    )
}

#[test]
fn reward_tx_40_deserialize_rejects_extra_trailing_bytes() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let mut bytes = map_err_debug(tx.serialize(), "reward should serialize")?;
    bytes.extend_from_slice(&[0_u8, 1_u8, 2_u8, 3_u8]);

    require_any_error(
        RewardTx::deserialize(&bytes),
        "deserialize should reject non-canonical payloads with trailing bytes",
    )
}

#[test]
fn reward_tx_41_clone_equality_and_mutation() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let mut cloned = tx.clone();

    require_equal(&cloned, &tx, "clone should equal original")?;

    cloned.block_height = cloned
        .block_height
        .checked_add(1)
        .ok_or_else(|| "block height mutation overflowed".to_owned())?;

    require_not_equal(
        &cloned,
        &tx,
        "mutating clone block height should change equality",
    )?;

    Ok(())
}

#[test]
fn reward_tx_42_vector_accepts_repeated_lowercase_hex_receivers() -> TestResult {
    let valid_chars = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    for ch in valid_chars {
        let receiver = wallet_with_repeated_hex(ch);
        let tx = map_err_debug(
            RewardTx::new(receiver.clone(), 1, 1),
            "valid repeated hex receiver should create",
        )?;

        require_equal(
            &array_as_str(&tx.receiver, "receiver utf8")?,
            &receiver,
            "repeated lowercase hex receiver should be stored exactly",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_43_vector_rejects_invalid_ascii_receiver_body_chars() -> TestResult {
    let invalid_chars = ['g', 'G', 'z', 'Z', '-', '_', '/', ':', '@'];

    for ch in invalid_chars {
        let receiver = format!("r{}{}", "a".repeat(127), ch);

        require_equal(
            &receiver.len(),
            &REMZAR_WALLET_LEN,
            "invalid receiver should be length-correct for format validation",
        )?;

        require_any_error(
            RewardTx::new(receiver, 1, 1),
            "invalid receiver body character should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_44_vector_rejects_receiver_length_boundaries() -> TestResult {
    let body_lengths = [0_usize, 1, 2, 126, 127, 129, 130, 255];

    for body_len in body_lengths {
        let receiver = format!("r{}", "a".repeat(body_len));

        require(
            receiver.len() != REMZAR_WALLET_LEN,
            "length vector must intentionally avoid valid canonical length",
        )?;

        require_any_error(
            RewardTx::new(receiver, 1, 1),
            "receiver length boundary should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_45_property_generated_valid_rewards_roundtrip() -> TestResult {
    for seed in 0_u64..128_u64 {
        let amount = seed
            .checked_add(1)
            .ok_or_else(|| "amount seed overflowed".to_owned())?;
        let block_height = seed
            .checked_add(1)
            .ok_or_else(|| "block height seed overflowed".to_owned())?;
        let timestamp = UNIX_2000
            .checked_add(seed)
            .ok_or_else(|| "timestamp seed overflowed".to_owned())?;

        let tx = valid_reward_with_values(wallet_from_seed(seed), amount, block_height, timestamp)?;
        map_err_debug(tx.validate(), "generated reward should validate")?;

        let bytes = map_err_debug(tx.serialize(), "generated reward should serialize")?;
        let decoded = map_err_debug(
            RewardTx::deserialize(&bytes),
            "generated reward should deserialize",
        )?;

        require_equal(&decoded, &tx, "generated reward should roundtrip exactly")?;
    }

    Ok(())
}

#[test]
fn reward_tx_46_property_generated_uppercase_receivers_canonicalize() -> TestResult {
    for seed in 0_u64..64_u64 {
        let expected = wallet_from_seed(seed);
        let input = expected.to_ascii_uppercase();

        let tx = map_err_debug(
            RewardTx::new(input, 1, 1),
            "generated uppercase receiver should canonicalize",
        )?;

        require_equal(
            &array_as_str(&tx.receiver, "receiver utf8")?,
            &expected,
            "generated uppercase receiver should store lowercase canonical wallet",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_47_fuzz_arbitrary_wire_payloads_reject_or_fail_validation() -> TestResult {
    for len in 0_usize..256_usize {
        let seed = u64::try_from(len).map_err(|error| format!("len conversion failed: {error}"))?;
        let bytes = bytes_from_seed(seed, len);

        match RewardTx::deserialize(&bytes) {
            Ok(tx) => {
                require_any_error(
                    tx.validate(),
                    "arbitrary decoded reward should not validate",
                )?;
            }
            Err(_) => {}
        }
    }

    Ok(())
}

#[test]
fn reward_tx_48_adversarial_network_mix_counts_valid_duplicate_and_rejected() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..64_u64 {
        let valid = valid_reward_with_values(
            wallet_from_seed(seed),
            1,
            seed.checked_add(1)
                .ok_or_else(|| "valid block height overflowed".to_owned())?,
            UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "valid timestamp overflowed".to_owned())?,
        )?;
        let valid_wire = map_err_debug(valid.serialize(), "valid reward should serialize")?;
        wires.push(valid_wire.clone());

        if seed < 8 {
            wires.push(valid_wire.clone());
        }

        let zero_amount = valid_reward_with_values(
            wallet_from_seed(seed.saturating_add(10_000)),
            0,
            1,
            UNIX_2000,
        )?;
        wires.push(raw_serialize(
            &zero_amount,
            "zero amount adversarial reward should raw-serialize",
        )?);

        let bad_receiver = RewardTx {
            receiver: wallet_array(&format!("x{}", "a".repeat(128)))?,
            amount: 1,
            block_height: 1,
            timestamp: UNIX_2000,
        };
        wires.push(raw_serialize(
            &bad_receiver,
            "bad receiver adversarial reward should raw-serialize",
        )?);
    }

    let mut seen = BTreeSet::new();
    let mut unique_valid = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut rejected = 0_usize;

    for wire in wires {
        match RewardTx::deserialize(&wire) {
            Ok(tx) => {
                if tx.validate().is_ok() {
                    let key =
                        map_err_debug(tx.serialize(), "accepted reward should serialize for key")?;

                    if seen.insert(key) {
                        unique_valid = unique_valid
                            .checked_add(1)
                            .ok_or_else(|| "unique counter overflowed".to_owned())?;
                    } else {
                        duplicate_valid = duplicate_valid
                            .checked_add(1)
                            .ok_or_else(|| "duplicate counter overflowed".to_owned())?;
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
        &64_usize,
        "network sim should accept 64 unique valid rewards",
    )?;
    require_equal(
        &duplicate_valid,
        &8_usize,
        "network sim should detect 8 duplicate valid rewards",
    )?;
    require_equal(
        &rejected,
        &128_usize,
        "network sim should reject invalid rewards",
    )?;

    Ok(())
}

#[test]
fn reward_tx_49_load_serializes_and_deserializes_many_valid_rewards() -> TestResult {
    let mut wires = Vec::with_capacity(512);

    for seed in 0_u64..512_u64 {
        let tx = valid_reward_with_values(
            wallet_from_seed(seed),
            1,
            seed.checked_add(1)
                .ok_or_else(|| "load block height overflowed".to_owned())?,
            UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "load timestamp overflowed".to_owned())?,
        )?;

        wires.push(map_err_debug(
            tx.serialize(),
            "load reward should serialize",
        )?);
    }

    let mut accepted = 0_usize;

    for wire in wires {
        let tx = map_err_debug(
            RewardTx::deserialize(&wire),
            "load reward should deserialize",
        )?;
        map_err_debug(tx.validate(), "load decoded reward should validate")?;

        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| "accepted counter overflowed".to_owned())?;
    }

    require_equal(
        &accepted,
        &512_usize,
        "all load rewards should deserialize and validate",
    )?;

    Ok(())
}

#[test]
fn reward_tx_50_vector_serialized_size_depends_on_varint_width_not_receiver_contents() -> TestResult
{
    let first = valid_reward_with_values(wallet_from_seed(1), 1, 1, UNIX_2000)?;
    let second = valid_reward_with_values(wallet_from_seed(2), 1, 1, UNIX_2000)?;
    let third = valid_reward_with_values(wallet_from_seed(3), max_reward(), u64::MAX, UNIX_9999)?;

    let first_bytes = map_err_debug(first.serialize(), "first reward should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second reward should serialize")?;
    let third_bytes = map_err_debug(third.serialize(), "third reward should serialize")?;

    require_equal(
        &first_bytes.len(),
        &second_bytes.len(),
        "same numeric varint widths and fixed receiver length should produce same serialized size",
    )?;
    require(
        third_bytes.len() >= first_bytes.len(),
        "larger numeric varint widths should not serialize smaller than small numeric widths",
    )?;
    require(
        first_bytes.len() > 0,
        "serialized reward should be non-empty",
    )?;

    Ok(())
}

#[test]
fn reward_tx_51_validate_accepts_max_reward_boundary() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), max_reward(), 1, UNIX_2000)?;

    map_err_debug(tx.validate(), "max reward boundary should validate")?;
    require_equal(
        &tx.amount,
        &max_reward(),
        "max reward boundary should be stored exactly",
    )?;

    Ok(())
}

#[test]
fn reward_tx_52_deserialize_rejects_over_max_when_representable() -> TestResult {
    match amount_over_max() {
        Some(over_max) => {
            let tx =
                valid_reward_with_values(wallet_with_repeated_hex('a'), over_max, 1, UNIX_2000)?;
            let bytes = raw_serialize(&tx, "over-max raw reward should raw-serialize")?;

            require_validation_error_contains(
                RewardTx::deserialize(&bytes),
                "exceeds allowed maximum",
                "deserialize must reject over-max raw reward",
            )
        }
        None => Ok(()),
    }
}

#[test]
fn reward_tx_53_validate_accepts_block_height_one_boundary() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;

    map_err_debug(tx.validate(), "block height one should validate")?;
    require_equal(
        &tx.block_height,
        &1_u64,
        "block height one should be preserved",
    )?;

    Ok(())
}

#[test]
fn reward_tx_54_validate_accepts_u64_max_block_height() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, u64::MAX, UNIX_2000)?;

    map_err_debug(tx.validate(), "u64::MAX block height should validate")?;
    require_equal(
        &tx.block_height,
        &u64::MAX,
        "u64::MAX block height should be preserved",
    )?;

    Ok(())
}

#[test]
fn reward_tx_55_validate_accepts_current_timestamp() -> TestResult {
    let timestamp = now_secs()?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

    map_err_debug(tx.validate(), "current timestamp should validate")?;

    Ok(())
}

#[test]
fn reward_tx_56_validate_accepts_one_second_future_timestamp() -> TestResult {
    let timestamp = now_secs()?
        .checked_add(1)
        .ok_or_else(|| "timestamp + 1 overflowed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

    map_err_debug(
        tx.validate(),
        "timestamp one second in the future should validate",
    )?;

    Ok(())
}

#[test]
fn reward_tx_57_validate_accepts_timestamp_safely_inside_ten_year_window() -> TestResult {
    let timestamp = now_secs()?
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_sub(3_600))
        .ok_or_else(|| "inside-window timestamp arithmetic failed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

    map_err_debug(
        tx.validate(),
        "timestamp safely inside ten-year window should validate",
    )?;

    Ok(())
}

#[test]
fn reward_tx_58_validate_accepts_unix_2000_plus_one() -> TestResult {
    let timestamp = UNIX_2000
        .checked_add(1)
        .ok_or_else(|| "UNIX_2000 + 1 overflowed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

    map_err_debug(
        tx.validate(),
        "timestamp immediately after UNIX_2000 should validate",
    )?;

    Ok(())
}

#[test]
fn reward_tx_59_amount_as_remzar_formats_two_units() -> TestResult {
    let amount = 2_u64
        .checked_mul(UNIT_DIVISOR)
        .ok_or_else(|| "2 * UNIT_DIVISOR overflowed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), amount, 1, UNIX_2000)?;

    let displayed = format!("{:.8}", tx.amount_as_remzar());

    require_equal(
        &displayed,
        &"2.00000000".to_owned(),
        "two full units should display as 2.00000000",
    )?;

    Ok(())
}

#[test]
fn reward_tx_60_amount_as_remzar_formats_half_unit() -> TestResult {
    let amount = UNIT_DIVISOR
        .checked_div(2)
        .ok_or_else(|| "UNIT_DIVISOR / 2 failed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), amount, 1, UNIX_2000)?;

    let displayed = format!("{:.8}", tx.amount_as_remzar());

    require_equal(
        &displayed,
        &"0.50000000".to_owned(),
        "half unit should display as 0.50000000",
    )?;

    Ok(())
}

#[test]
fn reward_tx_61_new_rejects_internal_space_in_receiver() -> TestResult {
    let receiver = format!("r{} {}", "a".repeat(63), "a".repeat(64));

    require_equal(
        &receiver.len(),
        &REMZAR_WALLET_LEN,
        "internal-space receiver should be length-correct",
    )?;

    require_validation_error_contains(
        RewardTx::new(receiver, 1, 1),
        "Invalid receiver address format",
        "internal space should be rejected",
    )
}

#[test]
fn reward_tx_62_new_rejects_internal_newline_in_receiver() -> TestResult {
    let receiver = format!("r{}\n{}", "a".repeat(63), "a".repeat(64));

    require_equal(
        &receiver.len(),
        &REMZAR_WALLET_LEN,
        "internal-newline receiver should be length-correct",
    )?;

    require_validation_error_contains(
        RewardTx::new(receiver, 1, 1),
        "Invalid receiver address format",
        "internal newline should be rejected",
    )
}

#[test]
fn reward_tx_63_new_rejects_unicode_lookalike_prefix() -> TestResult {
    let receiver = format!("ŕ{}", "a".repeat(127));

    require_equal(
        &receiver.len(),
        &REMZAR_WALLET_LEN,
        "unicode-prefix receiver should be byte-length-correct",
    )?;

    require_validation_error_contains(
        RewardTx::new(receiver, 1, 1),
        "Invalid receiver address format",
        "unicode lookalike prefix should be rejected",
    )
}

#[test]
fn reward_tx_64_new_rejects_unicode_body_character() -> TestResult {
    let receiver = format!("r{}é", "a".repeat(126));

    require_equal(
        &receiver.len(),
        &REMZAR_WALLET_LEN,
        "unicode-body receiver should be byte-length-correct",
    )?;

    require_validation_error_contains(
        RewardTx::new(receiver, 1, 1),
        "Invalid receiver address format",
        "unicode body character should be rejected",
    )
}

#[test]
fn reward_tx_65_validate_rejects_final_nul_receiver_byte() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = receiver.get_mut(128) {
        *byte = 0;
    } else {
        return Err("failed to mutate final receiver byte".to_owned());
    }

    let tx = RewardTx {
        receiver,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };

    require_any_error(
        tx.validate(),
        "validate should reject receiver ending with NUL byte",
    )
}

#[test]
fn reward_tx_66_validate_rejects_first_nul_receiver_byte() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = receiver.get_mut(0) {
        *byte = 0;
    } else {
        return Err("failed to mutate first receiver byte".to_owned());
    }

    let tx = RewardTx {
        receiver,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };

    require_any_error(
        tx.validate(),
        "validate should reject receiver beginning with NUL byte",
    )
}

#[test]
fn reward_tx_67_validate_rejects_middle_nul_receiver_byte() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = receiver.get_mut(64) {
        *byte = 0;
    } else {
        return Err("failed to mutate middle receiver byte".to_owned());
    }

    let tx = RewardTx {
        receiver,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };

    require_any_error(
        tx.validate(),
        "validate should reject receiver containing middle NUL byte",
    )
}

#[test]
fn reward_tx_68_validate_rejects_non_utf8_final_receiver_byte() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = receiver.get_mut(128) {
        *byte = 0xFF;
    } else {
        return Err("failed to mutate final receiver byte".to_owned());
    }

    let tx = RewardTx {
        receiver,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };

    require_any_error(
        tx.validate(),
        "validate should reject non-UTF8 final receiver byte",
    )
}

#[test]
fn reward_tx_69_deserialize_accepts_u64_max_block_height_then_validate_accepts() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, u64::MAX, UNIX_2000)?;
    let bytes = map_err_debug(tx.serialize(), "max block height reward should serialize")?;
    let decoded = map_err_debug(
        RewardTx::deserialize(&bytes),
        "max block height reward should deserialize",
    )?;

    require_equal(
        &decoded.block_height,
        &u64::MAX,
        "decoded block height should remain u64::MAX",
    )?;
    map_err_debug(
        decoded.validate(),
        "decoded max block height reward should validate",
    )?;

    Ok(())
}

#[test]
fn reward_tx_70_deserialize_rejects_zero_timestamp_wire() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, 0)?;
    let bytes = raw_serialize(&tx, "zero timestamp reward should raw-serialize")?;

    require_validation_error_contains(
        RewardTx::deserialize(&bytes),
        "UNIX_2000_SECS",
        "deserialize must reject zero timestamp reward",
    )
}

#[test]
fn reward_tx_71_deserialize_accepts_replay_safe_far_future_timestamp_wire() -> TestResult {
    let now = now_secs()?;
    let timestamp = now
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_add(3_600))
        .ok_or_else(|| "future timestamp arithmetic failed".to_owned())?;
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;
    let bytes = map_err_debug(tx.serialize(), "future timestamp reward should serialize")?;

    let decoded = map_err_debug(
        RewardTx::deserialize(&bytes),
        "replay-safe deserialize should accept structurally valid future timestamp",
    )?;

    require_equal(
        &decoded.timestamp,
        &timestamp,
        "decoded far-future timestamp should be preserved",
    )?;
    require_any_error(
        decoded.validate_for_runtime_at(now),
        "runtime validation should reject far-future timestamp",
    )
}

#[test]
fn reward_tx_72_deserialize_rejects_u64_max_timestamp_wire() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, u64::MAX)?;
    let bytes = raw_serialize(&tx, "u64::MAX timestamp reward should raw-serialize")?;

    require_validation_error_contains(
        RewardTx::deserialize(&bytes),
        "UNIX_9999_SECS",
        "deserialize must reject u64::MAX timestamp reward",
    )
}

#[test]
fn reward_tx_73_deserialize_rejects_multiple_trailing_byte_vectors() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let original_bytes = map_err_debug(tx.serialize(), "reward should serialize")?;

    for tail_len in [1_usize, 2_usize, 4_usize, 8_usize, 16_usize] {
        let mut bytes = original_bytes.clone();
        let tail_seed = u64::try_from(tail_len)
            .map_err(|error| format!("tail len conversion failed: {error}"))?;
        bytes.extend_from_slice(&bytes_from_seed(tail_seed, tail_len));

        require_any_error(
            RewardTx::deserialize(&bytes),
            "deserialize should reject trailing bytes for every tail vector",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_74_fuzz_all_truncated_serialized_prefixes_reject() -> TestResult {
    let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let bytes = map_err_debug(tx.serialize(), "valid reward should serialize")?;

    for cut in 0_usize..bytes.len() {
        let prefix = bytes
            .get(..cut)
            .ok_or_else(|| format!("failed to get prefix at cut {cut}"))?;

        require_any_error(
            RewardTx::deserialize(prefix),
            "truncated serialized prefix should reject",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_75_fuzz_bitflips_reject_or_decode_to_different_reward() -> TestResult {
    let original = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let original_bytes = map_err_debug(original.serialize(), "original reward should serialize")?;

    for byte_index in 0_usize..original_bytes.len().min(64) {
        let mut mutated = original_bytes.clone();

        if let Some(byte) = mutated.get_mut(byte_index) {
            *byte ^= 0x01;
        } else {
            return Err(format!("failed to mutate byte index {byte_index}"));
        }

        match RewardTx::deserialize(&mutated) {
            Ok(decoded) => {
                require_not_equal(
                    &decoded,
                    &original,
                    "accepted bitflip mutation should not decode to original reward",
                )?;
            }
            Err(_) => {}
        }
    }

    Ok(())
}

#[test]
fn reward_tx_76_property_repeated_roundtrip_is_stable() -> TestResult {
    let original = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let mut current = original.clone();

    for _ in 0_usize..10_usize {
        let bytes = map_err_debug(current.serialize(), "repeated serialize should succeed")?;
        current = map_err_debug(
            RewardTx::deserialize(&bytes),
            "repeated deserialize should succeed",
        )?;
    }

    require_equal(
        &current,
        &original,
        "reward should remain stable after repeated roundtrips",
    )?;

    Ok(())
}

#[test]
fn reward_tx_77_clone_receiver_mutation_changes_equality() -> TestResult {
    let original = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let mut cloned = original.clone();

    cloned.receiver = wallet_array(&wallet_with_repeated_hex('b'))?;

    require_not_equal(
        &cloned,
        &original,
        "changing receiver should change reward equality",
    )?;

    Ok(())
}

#[test]
fn reward_tx_78_property_generated_receivers_are_unique() -> TestResult {
    let mut receivers = BTreeSet::new();

    for seed in 0_u64..256_u64 {
        let receiver = wallet_from_seed(seed);

        require(
            receivers.insert(receiver),
            "generated receiver should be unique for each seed",
        )?;
    }

    require_equal(
        &receivers.len(),
        &256_usize,
        "should collect 256 unique generated receivers",
    )?;

    Ok(())
}

#[test]
fn reward_tx_79_property_generated_valid_new_rewards_create_and_validate() -> TestResult {
    for seed in 0_u64..128_u64 {
        let amount = seed
            .checked_add(1)
            .ok_or_else(|| "amount seed overflowed".to_owned())?;
        let block_height = seed
            .checked_add(1)
            .ok_or_else(|| "block height seed overflowed".to_owned())?;

        let tx = map_err_debug(
            RewardTx::new(wallet_from_seed(seed), amount, block_height),
            "generated RewardTx::new should create",
        )?;

        map_err_debug(tx.validate(), "generated RewardTx::new should validate")?;
    }

    Ok(())
}

#[test]
fn reward_tx_80_property_generated_outer_whitespace_receivers_canonicalize() -> TestResult {
    for seed in 0_u64..64_u64 {
        let expected = wallet_from_seed(seed);
        let input = format!(" \n{}\t", expected.to_ascii_uppercase());

        let tx = map_err_debug(
            RewardTx::new(input, 1, 1),
            "generated whitespace uppercase receiver should canonicalize",
        )?;

        require_equal(
            &array_as_str(&tx.receiver, "receiver utf8")?,
            &expected,
            "generated receiver should canonicalize after trimming whitespace",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_81_vector_wrong_prefix_receivers_reject() -> TestResult {
    let prefixes = ['x', 'q', '1', '-', '_', '0'];

    for prefix in prefixes {
        let receiver = format!("{prefix}{}", "a".repeat(128));

        require_equal(
            &receiver.len(),
            &REMZAR_WALLET_LEN,
            "wrong-prefix receiver should be length-correct",
        )?;

        require_any_error(
            RewardTx::new(receiver, 1, 1),
            "wrong-prefix receiver should reject",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_82_vector_whitespace_only_receivers_reject() -> TestResult {
    let cases = [" ", "\n", "\t", "\r\n", " \n\t "];

    for receiver in cases {
        require_any_error(
            RewardTx::new(receiver.to_owned(), 1, 1),
            "whitespace-only receiver should reject",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_83_vector_valid_block_heights_accept() -> TestResult {
    let heights = [1_u64, 2_u64, 10_u64, 1_000_u64, 1_000_000_u64, u64::MAX];

    for block_height in heights {
        let tx =
            valid_reward_with_values(wallet_with_repeated_hex('a'), 1, block_height, UNIX_2000)?;

        map_err_debug(tx.validate(), "valid positive block height should validate")?;
    }

    Ok(())
}

#[test]
fn reward_tx_84_vector_valid_amounts_accept_when_not_over_max() -> TestResult {
    let half_max = max_reward()
        .checked_div(2)
        .ok_or_else(|| "max reward / 2 failed".to_owned())?;
    let candidates = [1_u64, 2_u64, half_max, max_reward()];

    for amount in candidates {
        if amount == 0 {
            continue;
        }

        let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), amount, 1, UNIX_2000)?;

        map_err_debug(
            tx.validate(),
            "valid reward amount candidate should validate",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_85_vector_invalid_zero_amount_validate_rejects() -> TestResult {
    for block_height in [1_u64, 2_u64, 100_u64, u64::MAX] {
        let tx =
            valid_reward_with_values(wallet_with_repeated_hex('a'), 0, block_height, UNIX_2000)?;

        require_validation_error_contains(
            tx.validate(),
            "Reward amount must be greater than zero",
            "zero amount should reject for every block height vector",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_86_vector_old_timestamps_reject() -> TestResult {
    let timestamps = [
        0_u64,
        1_u64,
        60_u64,
        86_400_u64,
        315_360_000_u64,
        UNIX_2000.saturating_sub(1),
    ];

    for timestamp in timestamps {
        let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

        require_validation_error_contains(
            tx.validate(),
            "UNIX_2000_SECS",
            "old timestamp vector should reject",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_87_vector_far_future_timestamps_reject_for_runtime() -> TestResult {
    let now = now_secs()?;
    let base = now
        .checked_add(TEN_YEARS_SECS)
        .ok_or_else(|| "future base timestamp overflowed".to_owned())?;
    let timestamps = [
        base.checked_add(3_600)
            .ok_or_else(|| "future +1h overflowed".to_owned())?,
        base.checked_add(86_400)
            .ok_or_else(|| "future +1d overflowed".to_owned())?,
        u64::MAX,
    ];

    for timestamp in timestamps {
        let tx = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, timestamp)?;

        require_any_error(
            tx.validate_for_runtime_at(now),
            "far-future timestamp vector should reject for runtime validation",
        )?;
    }

    Ok(())
}

#[test]
fn reward_tx_88_deserialize_rejects_raw_uppercase_receiver() -> TestResult {
    let tx = RewardTx {
        receiver: wallet_array(&uppercase_wallet_with_repeated_hex('a'))?,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };
    let bytes = raw_serialize(&tx, "uppercase raw receiver reward should raw-serialize")?;

    require_any_error(
        RewardTx::deserialize(&bytes),
        "deserialize must reject uppercase raw receiver reward",
    )
}

#[test]
fn reward_tx_89_deserialize_rejects_raw_nul_receiver() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = receiver.get_mut(5) {
        *byte = 0;
    } else {
        return Err("failed to mutate receiver byte".to_owned());
    }

    let tx = RewardTx {
        receiver,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };
    let bytes = raw_serialize(&tx, "NUL receiver reward should raw-serialize")?;

    require_any_error(
        RewardTx::deserialize(&bytes),
        "deserialize must reject NUL receiver reward",
    )
}

#[test]
fn reward_tx_90_adversarial_over_max_batch_rejects_when_representable() -> TestResult {
    match amount_over_max() {
        Some(over_max) => {
            let mut rejected = 0_usize;

            for seed in 0_u64..64_u64 {
                let tx = valid_reward_with_values(wallet_from_seed(seed), over_max, 1, UNIX_2000)?;
                let wire = raw_serialize(&tx, "over-max batch reward should raw-serialize")?;

                if RewardTx::deserialize(&wire).is_err() {
                    rejected = rejected
                        .checked_add(1)
                        .ok_or_else(|| "rejected counter overflowed".to_owned())?;
                }
            }

            require_equal(
                &rejected,
                &64_usize,
                "all over-max batch rewards should reject during deserialize",
            )
        }
        None => Ok(()),
    }
}

#[test]
fn reward_tx_91_load_many_valid_rewards_have_unique_serialized_keys() -> TestResult {
    let mut keys = BTreeSet::new();

    for seed in 0_u64..512_u64 {
        let tx = valid_reward_with_values(
            wallet_from_seed(seed),
            1,
            seed.checked_add(1)
                .ok_or_else(|| "block height overflowed".to_owned())?,
            UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "timestamp overflowed".to_owned())?,
        )?;

        map_err_debug(tx.validate(), "load valid reward should validate")?;
        let key = map_err_debug(tx.serialize(), "load valid reward should serialize")?;

        require(keys.insert(key), "serialized reward key should be unique")?;
    }

    require_equal(
        &keys.len(),
        &512_usize,
        "load should produce 512 unique serialized reward keys",
    )?;

    Ok(())
}

#[test]
fn reward_tx_92_load_zero_amount_rewards_deserialize_rejects() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let tx = valid_reward_with_values(
            wallet_from_seed(seed),
            0,
            seed.checked_add(1)
                .ok_or_else(|| "block height overflowed".to_owned())?,
            UNIX_2000,
        )?;
        let wire = raw_serialize(&tx, "zero amount load reward should raw-serialize")?;

        if RewardTx::deserialize(&wire).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all zero amount load rewards should reject during deserialize",
    )?;

    Ok(())
}

#[test]
fn reward_tx_93_load_wrong_prefix_receivers_deserialize_rejects() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let receiver = format!("x{}", wallet_body_from_seed(seed));
        let tx = RewardTx {
            receiver: wallet_array(&receiver)?,
            amount: 1,
            block_height: 1,
            timestamp: UNIX_2000,
        };
        let wire = raw_serialize(&tx, "wrong-prefix load reward should raw-serialize")?;

        if RewardTx::deserialize(&wire).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all wrong-prefix receiver load rewards should reject during deserialize",
    )?;

    Ok(())
}

#[test]
fn reward_tx_94_load_future_timestamps_deserialize_but_runtime_rejects() -> TestResult {
    let now = now_secs()?;
    let future = now
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_add(3_600))
        .ok_or_else(|| "future timestamp arithmetic failed".to_owned())?;
    let mut decoded_count = 0_usize;
    let mut runtime_rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let tx = valid_reward_with_values(
            wallet_from_seed(seed),
            1,
            seed.checked_add(1)
                .ok_or_else(|| "block height overflowed".to_owned())?,
            future,
        )?;
        let wire = map_err_debug(
            tx.serialize(),
            "future timestamp load reward should serialize",
        )?;

        let decoded = map_err_debug(
            RewardTx::deserialize(&wire),
            "replay-safe deserialize should accept structurally valid future timestamp",
        )?;
        decoded_count = decoded_count
            .checked_add(1)
            .ok_or_else(|| "decoded counter overflowed".to_owned())?;

        if decoded.validate_for_runtime_at(now).is_err() {
            runtime_rejected = runtime_rejected
                .checked_add(1)
                .ok_or_else(|| "runtime rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &decoded_count,
        &128_usize,
        "all future timestamp load rewards should deserialize replay-safely",
    )?;
    require_equal(
        &runtime_rejected,
        &128_usize,
        "all future timestamp load rewards should reject during runtime validation",
    )?;

    Ok(())
}

#[test]
fn reward_tx_95_load_old_timestamps_deserialize_rejects() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let tx = valid_reward_with_values(
            wallet_from_seed(seed),
            1,
            seed.checked_add(1)
                .ok_or_else(|| "block height overflowed".to_owned())?,
            UNIX_2000.saturating_sub(1),
        )?;
        let wire = raw_serialize(&tx, "old timestamp load reward should raw-serialize")?;

        if RewardTx::deserialize(&wire).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all old timestamp load rewards should reject during deserialize",
    )?;

    Ok(())
}

#[test]
fn reward_tx_96_mixed_batch_counts_valid_duplicates_and_invalid_rewards() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..40_u64 {
        let valid = valid_reward_with_values(
            wallet_from_seed(seed),
            1,
            seed.checked_add(1)
                .ok_or_else(|| "valid block height overflowed".to_owned())?,
            UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "valid timestamp overflowed".to_owned())?,
        )?;
        let valid_wire = map_err_debug(valid.serialize(), "valid mixed reward should serialize")?;
        wires.push(valid_wire.clone());

        if seed < 10 {
            wires.push(valid_wire.clone());
        }

        let zero_amount = valid_reward_with_values(
            wallet_from_seed(seed.saturating_add(10_000)),
            0,
            1,
            UNIX_2000,
        )?;
        wires.push(raw_serialize(
            &zero_amount,
            "zero amount mixed reward should raw-serialize",
        )?);

        let wrong_prefix = RewardTx {
            receiver: wallet_array(&format!("x{}", wallet_body_from_seed(seed)))?,
            amount: 1,
            block_height: 1,
            timestamp: UNIX_2000,
        };
        wires.push(raw_serialize(
            &wrong_prefix,
            "wrong-prefix mixed reward should raw-serialize",
        )?);

        let mut truncated = valid_wire;
        let half = truncated
            .len()
            .checked_div(2)
            .ok_or_else(|| "truncated len division failed".to_owned())?;
        truncated.truncate(half);
        wires.push(truncated);
    }

    let mut seen = BTreeSet::new();
    let mut unique_valid = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut rejected = 0_usize;

    for wire in wires {
        match RewardTx::deserialize(&wire) {
            Ok(tx) => {
                if tx.validate().is_ok() {
                    let key =
                        map_err_debug(tx.serialize(), "valid mixed reward key should serialize")?;

                    if seen.insert(key) {
                        unique_valid = unique_valid
                            .checked_add(1)
                            .ok_or_else(|| "unique counter overflowed".to_owned())?;
                    } else {
                        duplicate_valid = duplicate_valid
                            .checked_add(1)
                            .ok_or_else(|| "duplicate counter overflowed".to_owned())?;
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
        &40_usize,
        "mixed batch should accept 40 unique valid rewards",
    )?;
    require_equal(
        &duplicate_valid,
        &10_usize,
        "mixed batch should detect 10 duplicate valid rewards",
    )?;
    require_equal(
        &rejected,
        &120_usize,
        "mixed batch should reject zero amount, wrong-prefix, and truncated rewards",
    )?;

    Ok(())
}

#[test]
fn reward_tx_97_vector_serialized_size_same_for_same_numeric_widths_different_receivers()
-> TestResult {
    let first = valid_reward_with_values(wallet_from_seed(1), 1, 1, UNIX_2000)?;
    let second = valid_reward_with_values(wallet_from_seed(2), 1, 1, UNIX_2000)?;

    let first_bytes = map_err_debug(first.serialize(), "first reward should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second reward should serialize")?;

    require_equal(
        &first_bytes.len(),
        &second_bytes.len(),
        "receiver contents should not change serialized size when numeric varint widths match",
    )?;

    Ok(())
}

#[test]
fn reward_tx_98_vector_serialized_size_non_decreasing_for_larger_numeric_varints() -> TestResult {
    let small = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let medium = valid_reward_with_values(
        wallet_with_repeated_hex('a'),
        127,
        127,
        UNIX_2000
            .checked_add(127)
            .ok_or_else(|| "medium timestamp overflowed".to_owned())?,
    )?;
    let large = valid_reward_with_values(
        wallet_with_repeated_hex('a'),
        max_reward(),
        u64::MAX,
        UNIX_9999,
    )?;

    let small_len = map_err_debug(small.serialize(), "small reward should serialize")?.len();
    let medium_len = map_err_debug(medium.serialize(), "medium reward should serialize")?.len();
    let large_len = map_err_debug(large.serialize(), "large reward should serialize")?.len();

    require(
        medium_len >= small_len,
        "medium numeric varints should not serialize smaller than small numeric varints",
    )?;
    require(
        large_len >= medium_len,
        "large numeric varints should not serialize smaller than medium numeric varints",
    )?;

    Ok(())
}

#[test]
fn reward_tx_99_changing_block_height_changes_serialized_bytes() -> TestResult {
    let first = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 1, UNIX_2000)?;
    let second = valid_reward_with_values(wallet_with_repeated_hex('a'), 1, 2, UNIX_2000)?;

    let first_bytes = map_err_debug(first.serialize(), "first reward should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second reward should serialize")?;

    require_not_equal(
        &first_bytes,
        &second_bytes,
        "changing block height should change serialized bytes",
    )?;

    Ok(())
}

#[test]
fn reward_tx_100_fuzz_arbitrary_payloads_never_validate_without_full_invariants() -> TestResult {
    let mut valid_count = 0_usize;
    let mut invalid_or_decode_error = 0_usize;

    for len in 0_usize..384_usize {
        let seed = u64::try_from(len).map_err(|error| format!("len conversion failed: {error}"))?;
        let bytes = bytes_from_seed(seed, len);

        match RewardTx::deserialize(&bytes) {
            Ok(tx) => {
                if tx.validate().is_ok() {
                    valid_count = valid_count
                        .checked_add(1)
                        .ok_or_else(|| "valid counter overflowed".to_owned())?;
                } else {
                    invalid_or_decode_error = invalid_or_decode_error
                        .checked_add(1)
                        .ok_or_else(|| "invalid counter overflowed".to_owned())?;
                }
            }
            Err(_) => {
                invalid_or_decode_error = invalid_or_decode_error
                    .checked_add(1)
                    .ok_or_else(|| "decode error counter overflowed".to_owned())?;
            }
        }
    }

    require_equal(
        &valid_count,
        &0_usize,
        "deterministic arbitrary fuzz payloads should not satisfy full reward invariants",
    )?;
    require_equal(
        &invalid_or_decode_error,
        &384_usize,
        "all arbitrary fuzz payloads should fail decode or validation",
    )?;

    Ok(())
}
