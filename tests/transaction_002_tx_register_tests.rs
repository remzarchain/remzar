use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use chrono::Utc;
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

fn raw_postcard_bytes(tx: &RegisterNodeTx, context: &str) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(tx).map_err(|error| format!("{context}: {error}"))
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

fn valid_tx_with_timestamp(timestamp: u64) -> Result<RegisterNodeTx, String> {
    Ok(RegisterNodeTx {
        wallet_address: wallet_array(&wallet_with_repeated_hex('a'))?,
        timestamp,
    })
}

fn valid_tx() -> Result<RegisterNodeTx, String> {
    valid_tx_with_timestamp(now_secs()?)
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
fn register_node_01_new_accepts_valid_wallet() -> TestResult {
    let tx = map_err_debug(
        RegisterNodeTx::new(wallet_with_repeated_hex('a')),
        "valid wallet registration should create",
    )?;

    require_equal(
        &tx.wallet_address.len(),
        &REMZAR_WALLET_LEN,
        "wallet byte array length should be canonical",
    )?;
    map_err_debug(tx.validate(), "newly created registration should validate")?;

    Ok(())
}

#[test]
fn register_node_02_new_canonicalizes_uppercase_wallet() -> TestResult {
    let tx = map_err_debug(
        RegisterNodeTx::new(uppercase_wallet_with_repeated_hex('a')),
        "uppercase wallet should canonicalize",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &wallet_with_repeated_hex('a'),
        "wallet should be stored as lowercase canonical string",
    )?;

    Ok(())
}

#[test]
fn register_node_03_new_trims_outer_whitespace() -> TestResult {
    let input = format!("\n\t{}  \r\n", uppercase_wallet_with_repeated_hex('b'));

    let tx = map_err_debug(
        RegisterNodeTx::new(input),
        "wallet with outer whitespace should canonicalize",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &wallet_with_repeated_hex('b'),
        "trimmed wallet should be lowercase canonical",
    )?;

    Ok(())
}

#[test]
fn register_node_04_new_sets_recent_timestamp() -> TestResult {
    let before = now_secs()?;
    let tx = map_err_debug(
        RegisterNodeTx::new(wallet_with_repeated_hex('c')),
        "valid wallet registration should create",
    )?;
    let after = now_secs()?;

    require(
        tx.timestamp >= before && tx.timestamp <= after.saturating_add(1),
        "new timestamp should be within test start/end window",
    )?;

    Ok(())
}

#[test]
fn register_node_05_wallet_str_returns_canonical_wallet() -> TestResult {
    let tx = map_err_debug(
        RegisterNodeTx::new(uppercase_wallet_with_repeated_hex('d')),
        "valid uppercase wallet registration should create",
    )?;

    let wallet = map_err_debug(tx.wallet_str(), "wallet_str should succeed")?;

    require_equal(
        &wallet.to_owned(),
        &wallet_with_repeated_hex('d'),
        "wallet_str should return canonical lowercase wallet",
    )?;

    Ok(())
}

#[test]
fn register_node_06_new_rejects_empty_wallet() -> TestResult {
    require_validation_error_contains(
        RegisterNodeTx::new(String::new()),
        "Wallet address is invalid or incomplete",
        "empty wallet should fail",
    )
}

#[test]
fn register_node_07_new_rejects_short_wallet() -> TestResult {
    require_validation_error_contains(
        RegisterNodeTx::new("ra".to_owned()),
        "Wallet address is invalid or incomplete",
        "short wallet should fail",
    )
}

#[test]
fn register_node_08_new_rejects_long_wallet() -> TestResult {
    let long_wallet = format!("r{}", "a".repeat(129));

    require_validation_error_contains(
        RegisterNodeTx::new(long_wallet),
        "Wallet address is invalid or incomplete",
        "long wallet should fail",
    )
}

#[test]
fn register_node_09_new_rejects_wrong_prefix() -> TestResult {
    let wrong_prefix = format!("x{}", "a".repeat(128));

    require_validation_error_contains(
        RegisterNodeTx::new(wrong_prefix),
        "Wallet address is invalid or incomplete",
        "wrong prefix should fail",
    )
}

#[test]
fn register_node_10_new_rejects_non_hex_wallet_body() -> TestResult {
    let non_hex = format!("r{}z", "a".repeat(127));

    require_validation_error_contains(
        RegisterNodeTx::new(non_hex),
        "Wallet address is invalid or incomplete",
        "non-hex wallet body should fail",
    )
}

#[test]
fn register_node_11_new_accepts_full_lowercase_hex_alphabet() -> TestResult {
    let wallet = format!("r{}", "0123456789abcdef".repeat(8));

    let tx = map_err_debug(
        RegisterNodeTx::new(wallet.clone()),
        "full lowercase hex alphabet wallet should create",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &wallet,
        "full hex alphabet wallet should be preserved",
    )?;

    Ok(())
}

#[test]
fn register_node_12_new_from_bytes_accepts_canonical_bytes() -> TestResult {
    let wallet = wallet_with_repeated_hex('e');

    let tx = map_err_debug(
        RegisterNodeTx::new_from_bytes(wallet.as_bytes()),
        "canonical wallet bytes should create registration",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &wallet,
        "new_from_bytes should store canonical wallet bytes",
    )?;

    Ok(())
}

#[test]
fn register_node_13_new_from_bytes_accepts_trailing_nul_padding() -> TestResult {
    let wallet = wallet_with_repeated_hex('f');
    let mut bytes = wallet.as_bytes().to_vec();
    bytes.extend_from_slice(&[0_u8, 0_u8, 0_u8, 0_u8]);

    let tx = map_err_debug(
        RegisterNodeTx::new_from_bytes(&bytes),
        "trailing NUL-padded wallet bytes should canonicalize",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &wallet,
        "new_from_bytes should trim trailing NUL padding and store canonical wallet",
    )
}

#[test]
fn register_node_14_new_from_bytes_rejects_embedded_nul() -> TestResult {
    let mut bytes = wallet_with_repeated_hex('a').into_bytes();
    if let Some(byte) = bytes.get_mut(10) {
        *byte = 0;
    } else {
        return Err("failed to mutate wallet byte".to_owned());
    }

    require_validation_error_contains(
        RegisterNodeTx::new_from_bytes(&bytes),
        "embedded NUL",
        "embedded NUL wallet bytes should fail",
    )
}

#[test]
fn register_node_15_new_from_bytes_rejects_non_utf8() -> TestResult {
    let mut bytes = wallet_with_repeated_hex('a').into_bytes();
    if let Some(byte) = bytes.get_mut(1) {
        *byte = 0xFF;
    } else {
        return Err("failed to mutate wallet byte".to_owned());
    }

    require_validation_error_contains(
        RegisterNodeTx::new_from_bytes(&bytes),
        "Wallet address bytes are invalid",
        "non-UTF8 wallet bytes should fail",
    )
}

#[test]
fn register_node_16_new_from_bytes_canonicalizes_uppercase_bytes() -> TestResult {
    let wallet = uppercase_wallet_with_repeated_hex('a');

    let tx = map_err_debug(
        RegisterNodeTx::new_from_bytes(wallet.as_bytes()),
        "new_from_bytes should canonicalize uppercase wallet bytes",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &wallet_with_repeated_hex('a'),
        "uppercase byte wallet should be stored as lowercase canonical wallet",
    )
}

#[test]
fn register_node_17_validate_accepts_valid_existing_instance() -> TestResult {
    let tx = valid_tx()?;

    map_err_debug(tx.validate(), "valid existing instance should validate")?;

    Ok(())
}

#[test]
fn register_node_18_validate_rejects_uppercase_stored_wallet() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&uppercase_wallet_with_repeated_hex('a'))?,
        timestamp: now_secs()?,
    };

    require_validation_error_contains(
        tx.validate(),
        "not in canonical form",
        "validate should reject uppercase stored wallet",
    )
}

#[test]
fn register_node_19_validate_rejects_wrong_prefix_stored_wallet() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&format!("x{}", "a".repeat(128)))?,
        timestamp: now_secs()?,
    };

    require_validation_error_contains(
        tx.validate(),
        "Wallet address is invalid or incomplete",
        "validate should reject wrong-prefix stored wallet",
    )
}

#[test]
fn register_node_20_validate_rejects_non_hex_stored_wallet() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&format!("r{}z", "a".repeat(127)))?,
        timestamp: now_secs()?,
    };

    require_validation_error_contains(
        tx.validate(),
        "Wallet address is invalid or incomplete",
        "validate should reject non-hex stored wallet",
    )
}

#[test]
fn register_node_21_validate_rejects_timestamp_before_2000() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000.saturating_sub(1))?;

    require_validation_error_contains(
        tx.validate(),
        "timestamp below UNIX_2000_SECS",
        "timestamp before 2000 should fail",
    )
}

#[test]
fn register_node_22_validate_accepts_timestamp_at_2000_boundary() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000)?;

    map_err_debug(
        tx.validate(),
        "timestamp at UNIX_2000 boundary should validate",
    )?;

    Ok(())
}

#[test]
fn register_node_23_validate_for_mempool_rejects_timestamp_too_far_future() -> TestResult {
    let now = now_secs()?;
    let too_far_future = now
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_add(1_000))
        .ok_or_else(|| "future timestamp overflowed".to_owned())?;

    let tx = valid_tx_with_timestamp(too_far_future)?;

    require_any_error(
        tx.validate_for_mempool_at(now),
        "mempool validation should reject timestamp beyond runtime future-skew window",
    )
}

#[test]
fn register_node_24_validate_accepts_near_future_timestamp_inside_window() -> TestResult {
    let inside_future = now_secs()?
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_sub(2))
        .ok_or_else(|| "inside future timestamp overflowed".to_owned())?;

    let tx = valid_tx_with_timestamp(inside_future)?;

    map_err_debug(
        tx.validate(),
        "timestamp just inside future plausibility window should validate",
    )?;

    Ok(())
}

#[test]
fn register_node_25_serialize_deserialize_roundtrip() -> TestResult {
    let tx = valid_tx()?;
    let bytes = map_err_debug(tx.serialize(), "registration should serialize")?;
    let decoded = map_err_debug(
        RegisterNodeTx::deserialize(&bytes),
        "registration should deserialize",
    )?;

    require_equal(&decoded, &tx, "registration should roundtrip exactly")?;

    Ok(())
}

#[test]
fn register_node_26_serialize_is_deterministic_for_fixed_instance() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000)?;

    let first = map_err_debug(tx.serialize(), "first serialize should succeed")?;
    let second = map_err_debug(tx.serialize(), "second serialize should succeed")?;

    require_equal(
        &first,
        &second,
        "fixed registration serialization should be deterministic",
    )?;

    Ok(())
}

#[test]
fn register_node_27_deserialize_rejects_empty_wire() -> TestResult {
    require_any_error(
        RegisterNodeTx::deserialize(&[]),
        "empty wire payload should be rejected",
    )
}

#[test]
fn register_node_28_deserialize_rejects_truncated_wire() -> TestResult {
    let tx = valid_tx()?;
    let mut bytes = map_err_debug(tx.serialize(), "registration should serialize")?;
    let half = bytes.len().checked_div(2).unwrap_or(0);
    bytes.truncate(half);

    require_any_error(
        RegisterNodeTx::deserialize(&bytes),
        "truncated wire payload should be rejected",
    )
}

#[test]
fn register_node_29_deserialize_rejects_old_timestamp_wire() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000.saturating_sub(1))?;
    let bytes = raw_postcard_bytes(&tx, "old timestamp wire should encode as raw postcard")?;

    require_validation_error_contains(
        RegisterNodeTx::deserialize(&bytes),
        "timestamp below UNIX_2000_SECS",
        "old timestamp wire should fail deserialize validation",
    )
}

#[test]
fn register_node_30_deserialize_for_mempool_rejects_future_timestamp_wire() -> TestResult {
    let now = now_secs()?;
    let future = now
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_add(10_000))
        .ok_or_else(|| "future timestamp overflowed".to_owned())?;
    let tx = valid_tx_with_timestamp(future)?;
    let bytes = map_err_debug(
        tx.serialize(),
        "future timestamp wire should serialize structurally",
    )?;

    require_any_error(
        RegisterNodeTx::deserialize_for_mempool(&bytes),
        "mempool deserialization should reject timestamp beyond runtime future-skew window",
    )
}

#[test]
fn register_node_31_deserialize_rejects_wrong_prefix_wire() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&format!("x{}", "a".repeat(128)))?,
        timestamp: now_secs()?,
    };
    let bytes = raw_postcard_bytes(&tx, "wrong-prefix wire should encode as raw postcard")?;

    require_validation_error_contains(
        RegisterNodeTx::deserialize(&bytes),
        "Wallet address is invalid or incomplete",
        "wrong-prefix wallet wire should fail deserialize validation",
    )
}

#[test]
fn register_node_32_deserialize_accepts_valid_boundary_timestamp_wire() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000)?;
    let bytes = map_err_debug(tx.serialize(), "boundary timestamp wire should serialize")?;
    let decoded = map_err_debug(
        RegisterNodeTx::deserialize(&bytes),
        "boundary timestamp wire should deserialize",
    )?;

    require_equal(
        &decoded,
        &tx,
        "boundary timestamp registration should roundtrip",
    )?;

    Ok(())
}

#[test]
fn register_node_33_wallet_str_rejects_non_utf8_wallet_bytes() -> TestResult {
    let mut wallet = wallet_array(&wallet_with_repeated_hex('a'))?;
    if let Some(byte) = wallet.get_mut(1) {
        *byte = 0xFF;
    } else {
        return Err("failed to mutate wallet byte".to_owned());
    }

    let tx = RegisterNodeTx {
        wallet_address: wallet,
        timestamp: now_secs()?,
    };

    require_validation_error_contains(
        tx.wallet_str(),
        "Wallet address is not valid UTF-8",
        "wallet_str should reject non-UTF8 wallet bytes",
    )
}

#[test]
fn register_node_34_clone_equality_and_mutation() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000)?;
    let mut cloned = tx.clone();

    require_equal(&cloned, &tx, "clone should equal original")?;

    cloned.timestamp = cloned
        .timestamp
        .checked_add(1)
        .ok_or_else(|| "timestamp mutation overflowed".to_owned())?;

    require_not_equal(
        &cloned,
        &tx,
        "mutating clone timestamp should change equality",
    )?;

    Ok(())
}

#[test]
fn register_node_35_vector_accepts_repeated_lowercase_hex_chars() -> TestResult {
    let valid_chars = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    for ch in valid_chars {
        let wallet = wallet_with_repeated_hex(ch);
        let tx = map_err_debug(
            RegisterNodeTx::new(wallet.clone()),
            "valid repeated hex char wallet should create",
        )?;

        require_equal(
            &array_as_str(&tx.wallet_address, "wallet utf8")?,
            &wallet,
            "repeated lowercase hex wallet should be stored exactly",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_36_vector_rejects_invalid_ascii_body_chars() -> TestResult {
    let invalid_chars = ['g', 'G', 'z', 'Z', '-', '_', '/', ':', '@'];

    for ch in invalid_chars {
        let invalid_wallet = format!("r{}{}", "a".repeat(127), ch);

        require_equal(
            &invalid_wallet.len(),
            &REMZAR_WALLET_LEN,
            "invalid wallet should be length-correct for format validation",
        )?;

        require_any_error(
            RegisterNodeTx::new(invalid_wallet),
            "invalid ASCII body character should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_37_vector_rejects_wallet_length_boundaries() -> TestResult {
    let body_lengths = [0_usize, 1, 2, 126, 127, 129, 130, 255];

    for body_len in body_lengths {
        let wallet = format!("r{}", "a".repeat(body_len));

        require(
            wallet.len() != REMZAR_WALLET_LEN,
            "length vector must intentionally avoid valid canonical length",
        )?;

        require_any_error(
            RegisterNodeTx::new(wallet),
            "wallet length boundary should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_38_vector_timestamp_boundaries() -> TestResult {
    let valid_boundary = valid_tx_with_timestamp(UNIX_2000)?;
    let invalid_before = valid_tx_with_timestamp(UNIX_2000.saturating_sub(1))?;
    let invalid_zero = valid_tx_with_timestamp(0)?;

    map_err_debug(
        valid_boundary.validate(),
        "timestamp exactly at UNIX_2000 should validate",
    )?;
    require_any_error(
        invalid_before.validate(),
        "timestamp immediately before UNIX_2000 should fail",
    )?;
    require_any_error(invalid_zero.validate(), "timestamp zero should fail")?;

    Ok(())
}

#[test]
fn register_node_39_property_generated_valid_wallets_create() -> TestResult {
    for seed in 0_u64..128_u64 {
        let wallet = wallet_from_seed(seed);
        let tx = map_err_debug(
            RegisterNodeTx::new(wallet.clone()),
            "generated valid wallet should create",
        )?;

        require_equal(
            &array_as_str(&tx.wallet_address, "wallet utf8")?,
            &wallet,
            "generated wallet should be stored exactly",
        )?;
        map_err_debug(tx.validate(), "generated registration should validate")?;
    }

    Ok(())
}

#[test]
fn register_node_40_property_generated_roundtrip_is_stable() -> TestResult {
    for seed in 0_u64..128_u64 {
        let timestamp = UNIX_2000
            .checked_add(seed)
            .ok_or_else(|| "timestamp seed overflowed".to_owned())?;

        let tx = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp,
        };

        let bytes = map_err_debug(tx.serialize(), "generated registration should serialize")?;
        let decoded = map_err_debug(
            RegisterNodeTx::deserialize(&bytes),
            "generated registration should deserialize",
        )?;

        require_equal(
            &decoded,
            &tx,
            "generated registration should roundtrip exactly",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_41_property_new_from_bytes_wallet_str_matches_input() -> TestResult {
    for seed in 0_u64..64_u64 {
        let wallet = wallet_from_seed(seed);
        let tx = map_err_debug(
            RegisterNodeTx::new_from_bytes(wallet.as_bytes()),
            "generated wallet bytes should create",
        )?;
        let wallet_str = map_err_debug(tx.wallet_str(), "wallet_str should succeed")?;

        require_equal(
            &wallet_str.to_owned(),
            &wallet,
            "wallet_str should match generated canonical input",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_42_fuzz_arbitrary_byte_payloads_do_not_deserialize_as_valid() -> TestResult {
    for len in 0_usize..256_usize {
        let seed = u64::try_from(len).map_err(|error| format!("len conversion failed: {error}"))?;
        let mut bytes = bytes_from_seed(seed, len);

        if let Some(first) = bytes.get_mut(0) {
            *first = b'x';
        }

        require_any_error(
            RegisterNodeTx::deserialize(&bytes),
            "arbitrary fuzz bytes should not deserialize as valid registration",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_43_fuzz_malformed_wallet_strings_are_rejected() -> TestResult {
    for seed in 0_u64..64_u64 {
        let body = wallet_body_from_seed(seed);

        let mut body_127 = String::with_capacity(127);
        for ch in body.chars().take(127) {
            body_127.push(ch);
        }

        let wrong_prefix = format!("x{body}");
        let non_hex = format!("r{body_127}z");
        let short = format!("r{body_127}");

        require_any_error(
            RegisterNodeTx::new(wrong_prefix),
            "fuzz wrong-prefix wallet should fail",
        )?;
        require_any_error(
            RegisterNodeTx::new(non_hex),
            "fuzz non-hex wallet should fail",
        )?;
        require_any_error(RegisterNodeTx::new(short), "fuzz short wallet should fail")?;
    }

    Ok(())
}

#[test]
fn register_node_44_adversarial_network_mix_counts_valid_duplicate_and_rejected() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..64_u64 {
        let valid = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "valid timestamp overflowed".to_owned())?,
        };
        let valid_wire = map_err_debug(
            valid.serialize(),
            "valid network registration should serialize",
        )?;
        wires.push(valid_wire.clone());

        if seed < 8 {
            wires.push(valid_wire.clone());
        }

        let invalid_old = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed.saturating_add(10_000)))?,
            timestamp: UNIX_2000.saturating_sub(1),
        };
        wires.push(raw_postcard_bytes(
            &invalid_old,
            "old timestamp adversarial registration should encode as raw postcard",
        )?);

        let invalid_wallet = RegisterNodeTx {
            wallet_address: wallet_array(&format!("x{}", "a".repeat(128)))?,
            timestamp: UNIX_2000,
        };
        wires.push(raw_postcard_bytes(
            &invalid_wallet,
            "wrong-prefix adversarial registration should encode as raw postcard",
        )?);
    }

    let mut seen_wallets = BTreeSet::new();
    let mut unique_valid = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut rejected = 0_usize;

    for wire in wires {
        match RegisterNodeTx::deserialize(&wire) {
            Ok(tx) => {
                let wallet = map_err_debug(tx.wallet_str(), "accepted wallet_str should succeed")?
                    .to_owned();

                if seen_wallets.insert(wallet) {
                    unique_valid = unique_valid
                        .checked_add(1)
                        .ok_or_else(|| "unique counter overflowed".to_owned())?;
                } else {
                    duplicate_valid = duplicate_valid
                        .checked_add(1)
                        .ok_or_else(|| "duplicate counter overflowed".to_owned())?;
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
        "network sim should accept 64 unique registrations",
    )?;
    require_equal(
        &duplicate_valid,
        &8_usize,
        "network sim should detect 8 duplicate registrations",
    )?;
    require_equal(
        &rejected,
        &128_usize,
        "network sim should reject all adversarial registrations",
    )?;

    Ok(())
}

#[test]
fn register_node_45_load_creates_many_valid_registrations() -> TestResult {
    let mut wallets = BTreeSet::new();

    for seed in 0_u64..512_u64 {
        let wallet = wallet_from_seed(seed);
        let tx = map_err_debug(
            RegisterNodeTx::new(wallet.clone()),
            "load valid registration should create",
        )?;

        require(wallets.insert(wallet), "load wallet should be unique")?;
        map_err_debug(tx.validate(), "load registration should validate")?;
    }

    require_equal(
        &wallets.len(),
        &512_usize,
        "load should create 512 unique wallet registrations",
    )?;

    Ok(())
}

#[test]
fn register_node_46_load_serializes_and_deserializes_many_valid_wires() -> TestResult {
    let mut wires = Vec::with_capacity(512);

    for seed in 0_u64..512_u64 {
        let tx = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "load timestamp overflowed".to_owned())?,
        };

        wires.push(map_err_debug(
            tx.serialize(),
            "load registration should serialize",
        )?);
    }

    let mut accepted = 0_usize;

    for wire in wires {
        let tx = map_err_debug(
            RegisterNodeTx::deserialize(&wire),
            "load registration wire should deserialize",
        )?;
        map_err_debug(tx.validate(), "load decoded registration should validate")?;

        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| "accepted counter overflowed".to_owned())?;
    }

    require_equal(&accepted, &512_usize, "all load wires should deserialize")?;

    Ok(())
}

#[test]
fn register_node_47_deserialize_rejects_extra_trailing_bytes() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000)?;
    let mut bytes = map_err_debug(tx.serialize(), "valid registration should serialize")?;
    bytes.extend_from_slice(&[0_u8, 1_u8, 2_u8, 3_u8]);

    require_any_error(
        RegisterNodeTx::deserialize(&bytes),
        "deserialize should reject trailing bytes after valid payload",
    )
}

#[test]
fn register_node_48_validate_rejects_u64_max_timestamp() -> TestResult {
    let tx = valid_tx_with_timestamp(u64::MAX)?;

    require_validation_error_contains(
        tx.validate(),
        "timestamp above UNIX_9999_SECS",
        "u64::MAX timestamp should fail structural timestamp validation",
    )
}

#[test]
fn register_node_49_new_from_bytes_accepts_boundary_whitespace_bytes() -> TestResult {
    let expected = wallet_with_repeated_hex('a');
    let wallet = format!(" {} ", expected);

    let tx = map_err_debug(
        RegisterNodeTx::new_from_bytes(wallet.as_bytes()),
        "byte constructor should canonicalize ASCII whitespace wrappers through wallet parser",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &expected,
        "byte constructor should store canonical wallet after trimming whitespace wrappers",
    )
}

#[test]
fn register_node_50_vector_serialized_size_depends_on_timestamp_varint_not_wallet_contents()
-> TestResult {
    let first = RegisterNodeTx {
        wallet_address: wallet_array(&wallet_from_seed(1))?,
        timestamp: UNIX_2000,
    };
    let second = RegisterNodeTx {
        wallet_address: wallet_array(&wallet_from_seed(2))?,
        timestamp: UNIX_2000,
    };
    let third = RegisterNodeTx {
        wallet_address: wallet_array(&wallet_from_seed(3))?,
        timestamp: UNIX_9999.saturating_sub(1),
    };

    let first_bytes = map_err_debug(first.serialize(), "first registration should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second registration should serialize")?;
    let third_bytes = map_err_debug(
        third.serialize(),
        "largest structural timestamp registration should serialize",
    )?;

    require_equal(
        &first_bytes.len(),
        &second_bytes.len(),
        "same timestamp varint width and fixed wallet length should produce same serialized size",
    )?;
    require(
        third_bytes.len() >= first_bytes.len(),
        "larger valid timestamp varint should not serialize smaller than boundary timestamp",
    )?;
    require(
        first_bytes.len() > 0,
        "serialized registration should be non-empty",
    )?;

    Ok(())
}

#[test]
fn register_node_51_vector_mixed_lowercase_hex_wallet_is_accepted() -> TestResult {
    let wallet = format!("r{}", "00112233445566778899aabbccddeeff".repeat(4));

    let tx = map_err_debug(
        RegisterNodeTx::new(wallet.clone()),
        "mixed lowercase hex wallet should create",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &wallet,
        "mixed lowercase hex wallet should be stored exactly",
    )?;

    Ok(())
}

#[test]
fn register_node_52_vector_mixed_uppercase_hex_wallet_canonicalizes() -> TestResult {
    let expected = format!("r{}", "00112233445566778899aabbccddeeff".repeat(4));
    let input = expected.to_ascii_uppercase();

    let tx = map_err_debug(
        RegisterNodeTx::new(input),
        "mixed uppercase hex wallet should canonicalize",
    )?;

    require_equal(
        &array_as_str(&tx.wallet_address, "wallet utf8")?,
        &expected,
        "mixed uppercase hex wallet should canonicalize to lowercase",
    )?;

    Ok(())
}

#[test]
fn register_node_53_vector_outer_whitespace_variants_canonicalize() -> TestResult {
    let cases = [
        format!(" {}", uppercase_wallet_with_repeated_hex('a')),
        format!("{} ", uppercase_wallet_with_repeated_hex('b')),
        format!("\n{}", uppercase_wallet_with_repeated_hex('c')),
        format!("{}\n", uppercase_wallet_with_repeated_hex('d')),
        format!("\t{}\r\n", uppercase_wallet_with_repeated_hex('e')),
    ];
    let expected = [
        wallet_with_repeated_hex('a'),
        wallet_with_repeated_hex('b'),
        wallet_with_repeated_hex('c'),
        wallet_with_repeated_hex('d'),
        wallet_with_repeated_hex('e'),
    ];

    for (input, expected_wallet) in cases.iter().zip(expected.iter()) {
        let tx = map_err_debug(
            RegisterNodeTx::new(input.clone()),
            "outer whitespace wallet should canonicalize",
        )?;

        require_equal(
            &array_as_str(&tx.wallet_address, "wallet utf8")?,
            expected_wallet,
            "outer whitespace case should store expected canonical wallet",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_54_vector_rejects_whitespace_only_wallets() -> TestResult {
    let cases = [" ", "\n", "\t", "\r\n", " \n\t "];

    for case in cases {
        require_any_error(
            RegisterNodeTx::new(case.to_owned()),
            "whitespace-only wallet should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_55_vector_rejects_wrong_prefix_chars() -> TestResult {
    let prefixes = ['x', 'q', '1', '-', '_', '0'];

    for prefix in prefixes {
        let wallet = format!("{prefix}{}", "a".repeat(128));

        require_equal(
            &wallet.len(),
            &REMZAR_WALLET_LEN,
            "wrong-prefix vector wallet should be length-correct",
        )?;

        require_any_error(
            RegisterNodeTx::new(wallet),
            "wrong wallet prefix should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_56_vector_rejects_non_hex_body_symbols() -> TestResult {
    let suffixes = ['g', 'h', 'z', 'G', 'Z', '.', ',', '*', '+', '='];

    for suffix in suffixes {
        let wallet = format!("r{}{}", "a".repeat(127), suffix);

        require_equal(
            &wallet.len(),
            &REMZAR_WALLET_LEN,
            "non-hex vector wallet should be length-correct",
        )?;

        require_any_error(
            RegisterNodeTx::new(wallet),
            "non-hex wallet body symbol should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_57_edge_rejects_unicode_lookalike_prefix() -> TestResult {
    let wallet = format!("ŕ{}", "a".repeat(127));

    require_equal(
        &wallet.len(),
        &REMZAR_WALLET_LEN,
        "unicode-prefix wallet should be byte-length-correct",
    )?;

    require_any_error(
        RegisterNodeTx::new(wallet),
        "unicode lookalike prefix must not pass as ASCII r",
    )
}

#[test]
fn register_node_58_edge_rejects_unicode_body_character() -> TestResult {
    let wallet = format!("r{}é", "a".repeat(126));

    require_equal(
        &wallet.len(),
        &REMZAR_WALLET_LEN,
        "unicode-body wallet should be byte-length-correct",
    )?;

    require_any_error(
        RegisterNodeTx::new(wallet),
        "unicode body character must not pass as lowercase ASCII hex",
    )
}

#[test]
fn register_node_59_vector_new_from_bytes_accepts_multiple_trailing_nul_counts() -> TestResult {
    let wallet = wallet_with_repeated_hex('a');

    for nul_count in [1_usize, 2_usize, 4_usize, 8_usize, 16_usize] {
        let mut bytes = wallet.as_bytes().to_vec();
        bytes.extend(std::iter::repeat(0_u8).take(nul_count));

        let tx = map_err_debug(
            RegisterNodeTx::new_from_bytes(&bytes),
            "new_from_bytes should accept trailing NUL padding",
        )?;

        require_equal(
            &array_as_str(&tx.wallet_address, "wallet utf8")?,
            &wallet,
            "trailing NUL padding should be trimmed before canonical storage",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_60_edge_new_from_bytes_rejects_leading_nul() -> TestResult {
    let mut bytes = Vec::with_capacity(REMZAR_WALLET_LEN + 1);
    bytes.push(0_u8);
    bytes.extend_from_slice(wallet_with_repeated_hex('a').as_bytes());

    require_any_error(
        RegisterNodeTx::new_from_bytes(&bytes),
        "leading NUL should be rejected as embedded invalid byte",
    )
}

#[test]
fn register_node_61_vector_new_from_bytes_accepts_ascii_whitespace_wrapping() -> TestResult {
    let expected = wallet_with_repeated_hex('a');
    let cases = [
        format!(" {}", expected),
        format!("{} ", expected),
        format!("\n{}", expected),
        format!("{}\n", expected),
        format!("\t{}\t", expected),
    ];

    for case in cases {
        let tx = map_err_debug(
            RegisterNodeTx::new_from_bytes(case.as_bytes()),
            "byte constructor should canonicalize ASCII whitespace wrappers",
        )?;

        require_equal(
            &array_as_str(&tx.wallet_address, "wallet utf8")?,
            &expected,
            "byte constructor should store canonical wallet after trimming whitespace wrappers",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_62_vector_validate_rejects_nul_at_multiple_positions() -> TestResult {
    for position in [0_usize, 1_usize, 64_usize, 128_usize] {
        let mut wallet = wallet_array(&wallet_with_repeated_hex('a'))?;

        if let Some(byte) = wallet.get_mut(position) {
            *byte = 0;
        } else {
            return Err(format!(
                "failed to mutate wallet byte at position {position}"
            ));
        }

        let tx = RegisterNodeTx {
            wallet_address: wallet,
            timestamp: now_secs()?,
        };

        require_any_error(
            tx.validate(),
            "validate should reject stored wallet with NUL byte",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_63_edge_wallet_str_rejects_wrong_prefix_wallet() -> TestResult {
    let wallet = format!("x{}", "a".repeat(128));
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&wallet)?,
        timestamp: now_secs()?,
    };

    require_validation_error_contains(
        tx.wallet_str(),
        "RegisterNodeTx wallet_str invalid wallet",
        "wallet_str should reject wrong-prefix wallet bytes",
    )
}

#[test]
fn register_node_64_edge_wallet_str_rejects_uppercase_wallet() -> TestResult {
    let wallet = uppercase_wallet_with_repeated_hex('a');
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&wallet)?,
        timestamp: now_secs()?,
    };

    require_validation_error_contains(
        tx.wallet_str(),
        "RegisterNodeTx wallet_str wallet is not canonical",
        "wallet_str should reject uppercase non-canonical wallet bytes",
    )
}

#[test]
fn register_node_65_edge_validate_and_wallet_str_reject_uppercase_wallet() -> TestResult {
    let wallet = uppercase_wallet_with_repeated_hex('b');
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&wallet)?,
        timestamp: now_secs()?,
    };

    require_validation_error_contains(
        tx.wallet_str(),
        "RegisterNodeTx wallet_str wallet is not canonical",
        "wallet_str should reject uppercase raw wallet",
    )?;
    require_any_error(
        tx.validate(),
        "validate should reject uppercase raw wallet after wallet_str rejects it",
    )
}

#[test]
fn register_node_66_edge_validate_accepts_timestamp_one_second_in_future() -> TestResult {
    let timestamp = now_secs()?
        .checked_add(1)
        .ok_or_else(|| "timestamp addition overflowed".to_owned())?;
    let tx = valid_tx_with_timestamp(timestamp)?;

    map_err_debug(
        tx.validate(),
        "timestamp one second in future should remain inside plausible window",
    )?;

    Ok(())
}

#[test]
fn register_node_67_edge_validate_accepts_timestamp_safely_inside_ten_year_window() -> TestResult {
    let timestamp = now_secs()?
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_sub(60))
        .ok_or_else(|| "inside-window timestamp arithmetic failed".to_owned())?;
    let tx = valid_tx_with_timestamp(timestamp)?;

    map_err_debug(
        tx.validate(),
        "timestamp safely inside ten-year future window should validate",
    )?;

    Ok(())
}

#[test]
fn register_node_68_edge_validate_for_mempool_rejects_timestamp_safely_beyond_window() -> TestResult
{
    let now = now_secs()?;
    let timestamp = now
        .checked_add(TEN_YEARS_SECS)
        .and_then(|value| value.checked_add(60))
        .ok_or_else(|| "beyond-window timestamp arithmetic failed".to_owned())?;
    let tx = valid_tx_with_timestamp(timestamp)?;

    require_any_error(
        tx.validate_for_mempool_at(now),
        "runtime mempool validation should reject timestamp safely beyond future-skew window",
    )
}

#[test]
fn register_node_69_edge_validate_rejects_timestamp_one() -> TestResult {
    let tx = valid_tx_with_timestamp(1)?;

    require_any_error(
        tx.validate(),
        "timestamp 1 should be rejected because it is before year 2000",
    )
}

#[test]
fn register_node_70_edge_validate_accepts_unix_2000_plus_one() -> TestResult {
    let timestamp = UNIX_2000
        .checked_add(1)
        .ok_or_else(|| "UNIX_2000 + 1 overflowed".to_owned())?;
    let tx = valid_tx_with_timestamp(timestamp)?;

    map_err_debug(
        tx.validate(),
        "timestamp immediately after UNIX_2000 should validate",
    )?;

    Ok(())
}

#[test]
fn register_node_71_edge_deserialize_canonicalizes_uppercase_wallet_wire() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&uppercase_wallet_with_repeated_hex('a'))?,
        timestamp: UNIX_2000,
    };
    let bytes = raw_postcard_bytes(&tx, "uppercase wallet wire should encode as raw postcard")?;

    let decoded = map_err_debug(
        RegisterNodeTx::deserialize(&bytes),
        "deserialize should canonicalize uppercase wallet wire",
    )?;

    require_equal(
        &array_as_str(&decoded.wallet_address, "wallet utf8")?,
        &wallet_with_repeated_hex('a'),
        "deserialize should store uppercase wire wallet as lowercase canonical wallet",
    )
}

#[test]
fn register_node_72_edge_deserialize_rejects_wrong_prefix_wallet_wire() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&format!("x{}", "a".repeat(128)))?,
        timestamp: UNIX_2000,
    };
    let bytes = raw_postcard_bytes(
        &tx,
        "wrong-prefix wallet wire should encode as raw postcard",
    )?;

    require_any_error(
        RegisterNodeTx::deserialize(&bytes),
        "deserialize should reject wrong-prefix wallet wire",
    )
}

#[test]
fn register_node_73_edge_deserialize_rejects_trailing_nul_inside_fixed_wallet() -> TestResult {
    let mut wallet = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = wallet.get_mut(128) {
        *byte = 0;
    } else {
        return Err("failed to mutate final wallet byte".to_owned());
    }

    let tx = RegisterNodeTx {
        wallet_address: wallet,
        timestamp: UNIX_2000,
    };
    let bytes = raw_postcard_bytes(&tx, "final-NUL wallet wire should encode as raw postcard")?;

    require_any_error(
        RegisterNodeTx::deserialize(&bytes),
        "deserialize should reject fixed wallet that becomes too short after trailing NUL trim",
    )
}

#[test]
fn register_node_74_edge_deserialize_rejects_non_utf8_wallet_wire() -> TestResult {
    let mut wallet = wallet_array(&wallet_with_repeated_hex('a'))?;

    if let Some(byte) = wallet.get_mut(2) {
        *byte = 0xFF;
    } else {
        return Err("failed to mutate wallet byte".to_owned());
    }

    let tx = RegisterNodeTx {
        wallet_address: wallet,
        timestamp: UNIX_2000,
    };
    let bytes = raw_postcard_bytes(&tx, "non-UTF8 wallet wire should encode as raw postcard")?;

    require_any_error(
        RegisterNodeTx::deserialize(&bytes),
        "deserialize should reject non-UTF8 wallet wire",
    )
}

#[test]
fn register_node_75_edge_deserialize_rejects_non_hex_wallet_wire() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&format!("r{}z", "a".repeat(127)))?,
        timestamp: UNIX_2000,
    };
    let bytes = raw_postcard_bytes(&tx, "non-hex wallet wire should encode as raw postcard")?;

    require_any_error(
        RegisterNodeTx::deserialize(&bytes),
        "deserialize should reject non-hex wallet wire",
    )
}

#[test]
fn register_node_76_property_repeated_roundtrip_is_stable() -> TestResult {
    let original = valid_tx_with_timestamp(UNIX_2000)?;
    let mut current = original.clone();

    for _ in 0_usize..10_usize {
        let bytes = map_err_debug(
            current.serialize(),
            "repeated roundtrip serialize should succeed",
        )?;
        current = map_err_debug(
            RegisterNodeTx::deserialize(&bytes),
            "repeated roundtrip deserialize should succeed",
        )?;
    }

    require_equal(
        &current,
        &original,
        "registration should remain stable after repeated roundtrips",
    )?;

    Ok(())
}

#[test]
fn register_node_77_vector_serialized_size_same_for_same_timestamp_different_wallets() -> TestResult
{
    let first = RegisterNodeTx {
        wallet_address: wallet_array(&wallet_from_seed(1))?,
        timestamp: UNIX_2000,
    };
    let second = RegisterNodeTx {
        wallet_address: wallet_array(&wallet_from_seed(2))?,
        timestamp: UNIX_2000,
    };

    let first_bytes = map_err_debug(first.serialize(), "first registration should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second registration should serialize")?;

    require_equal(
        &first_bytes.len(),
        &second_bytes.len(),
        "same fixed wallet length and same timestamp should produce same serialized size",
    )?;

    Ok(())
}

#[test]
fn register_node_78_vector_serialized_size_is_non_decreasing_for_timestamp_varints() -> TestResult {
    let small = valid_tx_with_timestamp(UNIX_2000)?;
    let medium = valid_tx_with_timestamp(
        UNIX_2000
            .checked_add(1_000_000)
            .ok_or_else(|| "medium timestamp overflowed".to_owned())?,
    )?;
    let large = RegisterNodeTx {
        wallet_address: wallet_array(&wallet_with_repeated_hex('a'))?,
        timestamp: UNIX_9999.saturating_sub(1),
    };

    let small_len = map_err_debug(small.serialize(), "small timestamp should serialize")?.len();
    let medium_len = map_err_debug(medium.serialize(), "medium timestamp should serialize")?.len();
    let large_len = map_err_debug(
        large.serialize(),
        "largest structural timestamp should serialize",
    )?
    .len();

    require(
        medium_len >= small_len,
        "larger timestamp varint should not serialize smaller than smaller timestamp",
    )?;
    require(
        large_len >= medium_len,
        "largest structural timestamp varint should not serialize smaller than medium timestamp",
    )?;

    Ok(())
}

#[test]
fn register_node_79_vector_generated_wallet_strings_are_unique() -> TestResult {
    let mut wallets = BTreeSet::new();

    for seed in 0_u64..256_u64 {
        let wallet = wallet_from_seed(seed);

        require(
            wallets.insert(wallet),
            "generated wallet string should be unique for each seed",
        )?;
    }

    require_equal(
        &wallets.len(),
        &256_usize,
        "should collect 256 unique generated wallets",
    )?;

    Ok(())
}

#[test]
fn register_node_80_property_generated_uppercase_wallets_canonicalize() -> TestResult {
    for seed in 0_u64..64_u64 {
        let expected = wallet_from_seed(seed);
        let input = expected.to_ascii_uppercase();

        let tx = map_err_debug(
            RegisterNodeTx::new(input),
            "generated uppercase wallet should canonicalize",
        )?;

        require_equal(
            &array_as_str(&tx.wallet_address, "wallet utf8")?,
            &expected,
            "generated uppercase wallet should store lowercase canonical wallet",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_81_property_generated_bytes_with_nul_padding_accept() -> TestResult {
    for seed in 0_u64..64_u64 {
        let wallet = wallet_from_seed(seed);
        let mut bytes = wallet.as_bytes().to_vec();
        bytes.extend_from_slice(&[0_u8, 0_u8, 0_u8]);

        let tx = map_err_debug(
            RegisterNodeTx::new_from_bytes(&bytes),
            "generated NUL-padded wallet bytes should canonicalize",
        )?;

        require_equal(
            &array_as_str(&tx.wallet_address, "wallet utf8")?,
            &wallet,
            "generated NUL-padded wallet bytes should store original canonical wallet",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_82_property_generated_bytes_with_embedded_nul_reject() -> TestResult {
    for seed in 0_u64..64_u64 {
        let mut bytes = wallet_from_seed(seed).into_bytes();

        if let Some(byte) = bytes.get_mut(10) {
            *byte = 0;
        } else {
            return Err("failed to mutate generated wallet byte".to_owned());
        }

        require_any_error(
            RegisterNodeTx::new_from_bytes(&bytes),
            "generated bytes with embedded NUL should reject",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_83_vector_old_timestamps_reject() -> TestResult {
    let timestamps = [
        0_u64,
        1_u64,
        60_u64,
        86_400_u64,
        315_360_000_u64,
        UNIX_2000.saturating_sub(1),
    ];

    for timestamp in timestamps {
        let tx = valid_tx_with_timestamp(timestamp)?;

        require_any_error(tx.validate(), "old timestamp vector should fail validation")?;
    }

    Ok(())
}

#[test]
fn register_node_84_vector_far_future_timestamps_reject() -> TestResult {
    let now = now_secs()?;
    let base = now
        .checked_add(TEN_YEARS_SECS)
        .ok_or_else(|| "future base timestamp overflowed".to_owned())?;
    let runtime_rejected_timestamps = [
        base.checked_add(1)
            .ok_or_else(|| "future +1 overflowed".to_owned())?,
        base.checked_add(60)
            .ok_or_else(|| "future +60 overflowed".to_owned())?,
        base.checked_add(86_400)
            .ok_or_else(|| "future +1d overflowed".to_owned())?,
    ];

    for timestamp in runtime_rejected_timestamps {
        let tx = valid_tx_with_timestamp(timestamp)?;

        require_any_error(
            tx.validate_for_mempool_at(now),
            "far-future timestamp vector should fail runtime mempool validation",
        )?;
    }

    let structurally_invalid = valid_tx_with_timestamp(u64::MAX)?;
    require_any_error(
        structurally_invalid.validate(),
        "u64::MAX timestamp should fail structural validation",
    )?;

    Ok(())
}

#[test]
fn register_node_85_vector_valid_timestamps_accept() -> TestResult {
    let now = now_secs()?;
    let plus_day = now
        .checked_add(86_400)
        .ok_or_else(|| "now + one day overflowed".to_owned())?;
    let plus_year = now
        .checked_add(31_536_000)
        .ok_or_else(|| "now + one year overflowed".to_owned())?;

    let timestamps = [UNIX_2000, UNIX_2000 + 1, now, plus_day, plus_year];

    for timestamp in timestamps {
        let tx = valid_tx_with_timestamp(timestamp)?;

        map_err_debug(
            tx.validate(),
            "valid timestamp vector should pass validation",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_86_fuzz_random_byte_wallet_inputs_reject() -> TestResult {
    for len in 0_usize..192_usize {
        let seed = u64::try_from(len).map_err(|error| format!("len conversion failed: {error}"))?;
        let bytes = bytes_from_seed(seed, len);

        require_any_error(
            RegisterNodeTx::new_from_bytes(&bytes),
            "random wallet byte input should reject",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_87_fuzz_all_truncated_serialized_prefixes_reject() -> TestResult {
    let tx = valid_tx_with_timestamp(UNIX_2000)?;
    let bytes = map_err_debug(tx.serialize(), "valid registration should serialize")?;

    for cut in 0_usize..bytes.len() {
        let prefix = bytes
            .get(..cut)
            .ok_or_else(|| format!("failed to get serialized prefix at cut {cut}"))?;

        require_any_error(
            RegisterNodeTx::deserialize(prefix),
            "truncated serialized prefix should reject",
        )?;
    }

    Ok(())
}

#[test]
fn register_node_88_fuzz_bitflips_reject_or_change_decoded_registration() -> TestResult {
    let original = valid_tx_with_timestamp(UNIX_2000)?;
    let original_bytes = map_err_debug(
        original.serialize(),
        "original registration should serialize",
    )?;

    for byte_index in 0_usize..original_bytes.len().min(48) {
        let mut mutated = original_bytes.clone();

        if let Some(byte) = mutated.get_mut(byte_index) {
            *byte ^= 0x01;
        } else {
            return Err(format!("failed to mutate byte index {byte_index}"));
        }

        match RegisterNodeTx::deserialize(&mutated) {
            Ok(decoded) => {
                require_not_equal(
                    &decoded,
                    &original,
                    "accepted bitflip mutation should not decode to original registration",
                )?;
            }
            Err(_) => {}
        }
    }

    Ok(())
}

#[test]
fn register_node_89_adversarial_duplicate_wallet_flood_detected_by_set() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..32_u64 {
        let tx = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000,
        };
        let wire = map_err_debug(
            tx.serialize(),
            "duplicate-flood registration should serialize",
        )?;

        wires.push(wire.clone());
        wires.push(wire.clone());
        wires.push(wire);
    }

    let mut seen = BTreeSet::new();
    let mut unique = 0_usize;
    let mut duplicates = 0_usize;

    for wire in wires {
        let tx = map_err_debug(
            RegisterNodeTx::deserialize(&wire),
            "duplicate-flood registration should deserialize",
        )?;
        let wallet =
            map_err_debug(tx.wallet_str(), "duplicate-flood wallet_str should succeed")?.to_owned();

        if seen.insert(wallet) {
            unique = unique
                .checked_add(1)
                .ok_or_else(|| "unique counter overflowed".to_owned())?;
        } else {
            duplicates = duplicates
                .checked_add(1)
                .ok_or_else(|| "duplicate counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &unique,
        &32_usize,
        "duplicate flood should have 32 unique wallets",
    )?;
    require_equal(
        &duplicates,
        &64_usize,
        "duplicate flood should detect 64 duplicates",
    )?;

    Ok(())
}

#[test]
fn register_node_90_load_new_from_bytes_many_valid_wallets() -> TestResult {
    let mut accepted = 0_usize;

    for seed in 0_u64..256_u64 {
        let wallet = wallet_from_seed(seed);
        let tx = map_err_debug(
            RegisterNodeTx::new_from_bytes(wallet.as_bytes()),
            "load byte wallet registration should create",
        )?;

        map_err_debug(
            tx.validate(),
            "load byte wallet registration should validate",
        )?;

        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| "accepted counter overflowed".to_owned())?;
    }

    require_equal(
        &accepted,
        &256_usize,
        "load byte constructor should accept 256 valid wallets",
    )?;

    Ok(())
}

#[test]
fn register_node_91_load_old_timestamp_wires_reject() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let tx = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000.saturating_sub(1),
        };
        let wire =
            raw_postcard_bytes(&tx, "old timestamp load wire should encode as raw postcard")?;

        if RegisterNodeTx::deserialize(&wire).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all old timestamp load wires should reject",
    )?;

    Ok(())
}

#[test]
fn register_node_92_load_wrong_prefix_wires_reject() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let wallet = format!("x{}", wallet_body_from_seed(seed));
        let tx = RegisterNodeTx {
            wallet_address: wallet_array(&wallet)?,
            timestamp: UNIX_2000,
        };
        let wire = raw_postcard_bytes(&tx, "wrong-prefix load wire should encode as raw postcard")?;

        if RegisterNodeTx::deserialize(&wire).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all wrong-prefix load wires should reject",
    )?;

    Ok(())
}

#[test]
fn register_node_93_vector_wallet_str_has_expected_prefix_length_and_lower_hex_body() -> TestResult
{
    for seed in 0_u64..64_u64 {
        let tx = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000,
        };
        let wallet = map_err_debug(tx.wallet_str(), "wallet_str should succeed")?;
        let bytes = wallet.as_bytes();

        require_equal(
            &bytes.len(),
            &REMZAR_WALLET_LEN,
            "wallet_str should expose canonical wallet length",
        )?;

        match bytes.first() {
            Some(first) => require_equal(first, &b'r', "wallet_str should begin with lowercase r")?,
            None => return Err("wallet_str returned empty bytes".to_owned()),
        }

        let body_is_lower_hex = bytes
            .iter()
            .skip(1)
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));

        require(body_is_lower_hex, "wallet_str body should be lowercase hex")?;
    }

    Ok(())
}

#[test]
fn register_node_94_vector_all_constructors_store_exact_wallet_length() -> TestResult {
    let wallet = wallet_with_repeated_hex('c');

    let from_string = map_err_debug(
        RegisterNodeTx::new(wallet.clone()),
        "string constructor should create",
    )?;
    let from_bytes = map_err_debug(
        RegisterNodeTx::new_from_bytes(wallet.as_bytes()),
        "byte constructor should create",
    )?;
    let manual = RegisterNodeTx {
        wallet_address: wallet_array(&wallet)?,
        timestamp: UNIX_2000,
    };

    require_equal(
        &from_string.wallet_address.len(),
        &REMZAR_WALLET_LEN,
        "string constructor wallet length should be exact",
    )?;
    require_equal(
        &from_bytes.wallet_address.len(),
        &REMZAR_WALLET_LEN,
        "byte constructor wallet length should be exact",
    )?;
    require_equal(
        &manual.wallet_address.len(),
        &REMZAR_WALLET_LEN,
        "manual wallet length should be exact",
    )?;

    Ok(())
}

#[test]
fn register_node_95_edge_clone_equality_changes_when_wallet_changes() -> TestResult {
    let original = valid_tx_with_timestamp(UNIX_2000)?;
    let mut cloned = original.clone();

    cloned.wallet_address = wallet_array(&wallet_with_repeated_hex('b'))?;

    require_not_equal(
        &cloned,
        &original,
        "changing cloned wallet should change equality",
    )?;

    Ok(())
}

#[test]
fn register_node_96_edge_roundtrip_preserves_wallet_str() -> TestResult {
    let tx = RegisterNodeTx {
        wallet_address: wallet_array(&wallet_with_repeated_hex('d'))?,
        timestamp: UNIX_2000,
    };

    let before = map_err_debug(tx.wallet_str(), "before wallet_str should succeed")?.to_owned();
    let bytes = map_err_debug(tx.serialize(), "registration should serialize")?;
    let decoded = map_err_debug(
        RegisterNodeTx::deserialize(&bytes),
        "registration should deserialize",
    )?;
    let after = map_err_debug(decoded.wallet_str(), "after wallet_str should succeed")?.to_owned();

    require_equal(
        &after,
        &before,
        "wallet_str should be preserved through serialization roundtrip",
    )?;

    Ok(())
}

#[test]
fn register_node_97_edge_rejects_internal_tab_in_wallet_string() -> TestResult {
    let wallet = format!("r{}\t{}", "a".repeat(63), "a".repeat(64));

    require_equal(
        &wallet.len(),
        &REMZAR_WALLET_LEN,
        "internal-tab wallet should be length-correct",
    )?;

    require_any_error(
        RegisterNodeTx::new(wallet),
        "internal tab should be rejected in wallet string",
    )
}

#[test]
fn register_node_98_edge_rejects_internal_carriage_return_in_wallet_string() -> TestResult {
    let wallet = format!("r{}\r{}", "a".repeat(63), "a".repeat(64));

    require_equal(
        &wallet.len(),
        &REMZAR_WALLET_LEN,
        "internal-carriage-return wallet should be length-correct",
    )?;

    require_any_error(
        RegisterNodeTx::new(wallet),
        "internal carriage return should be rejected in wallet string",
    )
}

#[test]
fn register_node_99_edge_deserialize_accepts_current_timestamp_wire() -> TestResult {
    let timestamp = now_secs()?;
    let tx = valid_tx_with_timestamp(timestamp)?;
    let bytes = map_err_debug(tx.serialize(), "current timestamp wire should serialize")?;
    let decoded = map_err_debug(
        RegisterNodeTx::deserialize(&bytes),
        "current timestamp wire should deserialize",
    )?;

    require_equal(
        &decoded,
        &tx,
        "current timestamp registration should roundtrip",
    )?;

    Ok(())
}

#[test]
fn register_node_100_mixed_vector_batch_counts_valid_duplicate_and_rejected() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..40_u64 {
        let valid = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed))?,
            timestamp: UNIX_2000
                .checked_add(seed)
                .ok_or_else(|| "valid timestamp overflowed".to_owned())?,
        };
        let valid_wire = map_err_debug(valid.serialize(), "valid mixed wire should serialize")?;
        wires.push(valid_wire.clone());

        if seed < 10 {
            wires.push(valid_wire.clone());
        }

        let wrong_prefix = RegisterNodeTx {
            wallet_address: wallet_array(&format!("x{}", wallet_body_from_seed(seed)))?,
            timestamp: UNIX_2000,
        };
        wires.push(raw_postcard_bytes(
            &wrong_prefix,
            "wrong-prefix mixed wire should encode as raw postcard",
        )?);

        let old_timestamp = RegisterNodeTx {
            wallet_address: wallet_array(&wallet_from_seed(seed.saturating_add(10_000)))?,
            timestamp: UNIX_2000.saturating_sub(1),
        };
        wires.push(raw_postcard_bytes(
            &old_timestamp,
            "old timestamp mixed wire should encode as raw postcard",
        )?);

        let mut truncated = valid_wire;
        let half = truncated.len().checked_div(2).unwrap_or(0);
        truncated.truncate(half);
        wires.push(truncated);
    }

    let mut seen_wallets = BTreeSet::new();
    let mut unique_valid = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut rejected = 0_usize;

    for wire in wires {
        match RegisterNodeTx::deserialize(&wire) {
            Ok(tx) => {
                let wallet =
                    map_err_debug(tx.wallet_str(), "mixed accepted wallet_str should succeed")?
                        .to_owned();

                if seen_wallets.insert(wallet) {
                    unique_valid = unique_valid
                        .checked_add(1)
                        .ok_or_else(|| "unique valid counter overflowed".to_owned())?;
                } else {
                    duplicate_valid = duplicate_valid
                        .checked_add(1)
                        .ok_or_else(|| "duplicate valid counter overflowed".to_owned())?;
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
        "mixed batch should accept 40 unique valid registrations",
    )?;
    require_equal(
        &duplicate_valid,
        &10_usize,
        "mixed batch should detect 10 duplicate valid registrations",
    )?;
    require_equal(
        &rejected,
        &120_usize,
        "mixed batch should reject wrong-prefix, old timestamp, and truncated registrations",
    )?;

    Ok(())
}
