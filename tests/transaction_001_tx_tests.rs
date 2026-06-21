use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::{REMZAR_WALLET_LEN, UNIT_DIVISOR};

use chrono::Utc;
use postcard::to_allocvec;
use std::collections::BTreeSet;

type TestResult = Result<(), String>;

const VALID_STRUCTURAL_TIMESTAMP: u64 = 1_700_000_000;

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

fn valid_tx(amount: u64) -> Result<Transaction, String> {
    map_err_debug(
        Transaction::new(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            amount,
        ),
        "valid transaction creation failed",
    )
}

fn fixed_tx(amount: u64, timestamp: u64) -> Result<Transaction, String> {
    Ok(Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount,
        timestamp,
    })
}

fn require_tx_validation_error_contains(
    result: Result<Transaction, ErrorDetection>,
    needle: &str,
    context: &str,
) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => require(
            message.contains(needle),
            &format!("{context}: message was {message:?}"),
        ),
        Err(other) => Err(format!(
            "{context}: expected ValidationError, got {other:?}"
        )),
        Ok(tx) => Err(format!("{context}: expected error, got transaction {tx:?}")),
    }
}

fn require_unit_validation_error_contains(
    result: Result<(), ErrorDetection>,
    needle: &str,
    context: &str,
) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => require(
            message.contains(needle),
            &format!("{context}: message was {message:?}"),
        ),
        Err(other) => Err(format!(
            "{context}: expected ValidationError, got {other:?}"
        )),
        Ok(()) => Err(format!("{context}: expected validation error")),
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

fn raw_wire(tx: &Transaction, context: &str) -> Result<Vec<u8>, String> {
    to_allocvec(tx).map_err(|error| format!("{context}: {error}"))
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

fn lower_hex_string(s: &str) -> bool {
    s.bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[test]
fn transaction_01_new_accepts_valid_micro_units() -> TestResult {
    let tx = valid_tx(1)?;

    require_equal(&tx.amount, &1_u64, "amount should be stored in micro-units")?;
    require_equal(
        &tx.sender.len(),
        &REMZAR_WALLET_LEN,
        "sender byte array length should match wallet length",
    )?;
    require_equal(
        &tx.receiver.len(),
        &REMZAR_WALLET_LEN,
        "receiver byte array length should match wallet length",
    )?;
    map_err_debug(tx.validate(), "valid tx should validate")?;

    Ok(())
}

#[test]
fn transaction_02_new_canonicalizes_uppercase_and_spaces() -> TestResult {
    let sender = format!("  {}  ", uppercase_wallet_with_repeated_hex('a'));
    let receiver = format!("  {}  ", uppercase_wallet_with_repeated_hex('b'));

    let tx = map_err_debug(
        Transaction::new(sender, receiver, 77),
        "new should canonicalize",
    )?;

    let sender_str = array_as_str(&tx.sender, "sender utf8")?;
    let receiver_str = array_as_str(&tx.receiver, "receiver utf8")?;

    require_equal(
        &sender_str,
        &wallet_with_repeated_hex('a'),
        "sender should be canonical lowercase",
    )?;
    require_equal(
        &receiver_str,
        &wallet_with_repeated_hex('b'),
        "receiver should be canonical lowercase",
    )?;

    Ok(())
}

#[test]
fn transaction_03_new_preserves_sender_receiver_arrays() -> TestResult {
    let sender = wallet_with_repeated_hex('c');
    let receiver = wallet_with_repeated_hex('d');

    let tx = map_err_debug(
        Transaction::new(sender.clone(), receiver.clone(), 999),
        "new should succeed",
    )?;

    require_equal(
        &array_as_str(&tx.sender, "sender utf8")?,
        &sender,
        "sender array should match canonical sender",
    )?;
    require_equal(
        &array_as_str(&tx.receiver, "receiver utf8")?,
        &receiver,
        "receiver array should match canonical receiver",
    )?;

    Ok(())
}

#[test]
fn transaction_04_new_sets_recent_timestamp() -> TestResult {
    let before = u64::try_from(Utc::now().timestamp())
        .map_err(|error| format!("before timestamp conversion failed: {error}"))?;

    let tx = valid_tx(123)?;

    let after = u64::try_from(Utc::now().timestamp())
        .map_err(|error| format!("after timestamp conversion failed: {error}"))?;

    require(
        tx.timestamp >= before && tx.timestamp <= after.saturating_add(1),
        "timestamp should be between test start and test end",
    )?;

    Ok(())
}

#[test]
fn transaction_05_rejects_empty_sender() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new(String::new(), wallet_with_repeated_hex('b'), 1),
        "empty",
        "empty sender should fail",
    )
}

#[test]
fn transaction_06_rejects_empty_receiver() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new(wallet_with_repeated_hex('a'), String::new(), 1),
        "empty",
        "empty receiver should fail",
    )
}

#[test]
fn transaction_07_rejects_short_sender() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new("ra".to_owned(), wallet_with_repeated_hex('b'), 1),
        "Invalid address length",
        "short sender should fail length check",
    )
}

#[test]
fn transaction_08_rejects_long_receiver() -> TestResult {
    let long_receiver = format!("r{}", "b".repeat(129));

    require_tx_validation_error_contains(
        Transaction::new(wallet_with_repeated_hex('a'), long_receiver, 1),
        "Invalid address length",
        "long receiver should fail length check",
    )
}

#[test]
fn transaction_09_rejects_wrong_prefix() -> TestResult {
    let wrong_prefix = format!("x{}", "a".repeat(128));

    require_tx_validation_error_contains(
        Transaction::new(wrong_prefix, wallet_with_repeated_hex('b'), 1),
        "Wallet address is invalid or incomplete",
        "wrong wallet prefix should fail",
    )
}

#[test]
fn transaction_10_rejects_non_hex_body() -> TestResult {
    let non_hex = format!("r{}g", "a".repeat(127));

    require_tx_validation_error_contains(
        Transaction::new(non_hex, wallet_with_repeated_hex('b'), 1),
        "Wallet address is invalid or incomplete",
        "non-hex wallet body should fail",
    )
}

#[test]
fn transaction_11_rejects_same_wallet_after_canonicalization() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new(
            uppercase_wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('a'),
            1,
        ),
        "Sender and receiver cannot be the same",
        "same canonical sender and receiver should fail",
    )
}

#[test]
fn transaction_12_rejects_zero_amount() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            0,
        ),
        "greater than zero",
        "zero amount should fail",
    )
}

#[test]
fn transaction_13_accepts_max_u64_micro_amount() -> TestResult {
    let tx = valid_tx(u64::MAX)?;

    require_equal(
        &tx.amount,
        &u64::MAX,
        "u64::MAX micro amount should be stored",
    )?;
    map_err_debug(tx.validate(), "u64::MAX amount tx should validate")?;

    Ok(())
}

#[test]
fn transaction_14_new_from_remzar_one_remzar() -> TestResult {
    let tx = map_err_debug(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            1.0,
        ),
        "new_from_remzar should create one REMZAR",
    )?;

    require_equal(
        &tx.amount,
        &UNIT_DIVISOR,
        "1 REMZAR should equal UNIT_DIVISOR micro-units",
    )?;

    Ok(())
}

#[test]
fn transaction_15_new_from_remzar_fractional_one_micro() -> TestResult {
    let tx = map_err_debug(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            0.00000001,
        ),
        "new_from_remzar should create one micro-unit",
    )?;

    require_equal(
        &tx.amount,
        &1_u64,
        "0.00000001 REMZAR should be 1 micro-unit",
    )?;

    Ok(())
}

#[test]
fn transaction_16_new_from_remzar_exact_eight_decimals() -> TestResult {
    let tx = map_err_debug(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            12.34567891,
        ),
        "new_from_remzar should accept 8 displayed decimals",
    )?;

    require_equal(
        &tx.amount,
        &1_234_567_891_u64,
        "12.34567891 REMZAR should convert exactly to micro-units",
    )?;

    Ok(())
}

#[test]
fn transaction_17_new_from_aos_alias_matches_remzar_constructor() -> TestResult {
    let tx = map_err_debug(
        Transaction::new_from_aos(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            3.5,
        ),
        "new_from_aos alias should succeed",
    )?;

    require_equal(
        &tx.amount,
        &350_000_000_u64,
        "3.5 alias amount should match REMZAR",
    )?;

    Ok(())
}

#[test]
fn transaction_18_new_from_remzar_rejects_nan() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            f64::NAN,
        ),
        "greater than zero",
        "NaN amount should fail",
    )
}

#[test]
fn transaction_19_new_from_remzar_rejects_infinity() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            f64::INFINITY,
        ),
        "too large",
        "infinite amount should fail",
    )
}

#[test]
fn transaction_20_new_from_remzar_rejects_overflow() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            184_467_440_738.0,
        ),
        "too large",
        "finite overflow amount should fail",
    )
}

#[test]
fn transaction_21_new_from_remzar_rejects_zero_negative_and_tiny() -> TestResult {
    let zero = Transaction::new_from_remzar(
        wallet_with_repeated_hex('a'),
        wallet_with_repeated_hex('b'),
        0.0,
    );
    let negative = Transaction::new_from_remzar(
        wallet_with_repeated_hex('a'),
        wallet_with_repeated_hex('b'),
        -1.0,
    );
    let tiny = Transaction::new_from_remzar(
        wallet_with_repeated_hex('a'),
        wallet_with_repeated_hex('b'),
        0.000000004,
    );

    require_tx_validation_error_contains(zero, "greater than zero", "zero REMZAR should fail")?;
    require_tx_validation_error_contains(
        negative,
        "greater than zero",
        "negative REMZAR should fail",
    )?;
    require_tx_validation_error_contains(
        tiny,
        "greater than zero",
        "rounded-to-zero REMZAR should fail",
    )?;

    Ok(())
}

#[test]
fn transaction_22_amount_display_aliases_match() -> TestResult {
    let tx = valid_tx(300_000_000)?;

    let remzar = format!("{:.8}", tx.amount_as_remzar());
    let aos = format!("{:.8}", tx.amount_as_aos());

    require_equal(
        &remzar,
        &"3.00000000".to_owned(),
        "amount_as_remzar display value",
    )?;
    require_equal(
        &aos,
        &remzar,
        "amount_as_aos should be alias of amount_as_remzar",
    )?;

    Ok(())
}

#[test]
fn transaction_23_serialize_deserialize_roundtrip() -> TestResult {
    let tx = valid_tx(987_654_321)?;
    let bytes = map_err_debug(tx.serialize(), "serialize should succeed")?;
    let decoded = map_err_debug(
        Transaction::deserialize(&bytes),
        "deserialize should succeed",
    )?;

    require_equal(&decoded, &tx, "roundtrip transaction should be equal")?;

    Ok(())
}

#[test]
fn transaction_24_serialize_is_deterministic_for_fixed_transaction() -> TestResult {
    let tx = fixed_tx(42, 1_700_000_000)?;

    let first = map_err_debug(tx.serialize(), "first serialize should succeed")?;
    let second = map_err_debug(tx.serialize(), "second serialize should succeed")?;

    require_equal(
        &first,
        &second,
        "fixed transaction serialization should be deterministic",
    )?;

    Ok(())
}

#[test]
fn transaction_25_deserialize_rejects_empty_wire() -> TestResult {
    require_any_error(
        Transaction::deserialize(&[]),
        "empty wire payload should be rejected",
    )
}

#[test]
fn transaction_26_deserialize_rejects_truncated_wire() -> TestResult {
    let tx = valid_tx(100)?;
    let mut bytes = map_err_debug(tx.serialize(), "serialize should succeed")?;
    let half = bytes.len().checked_div(2).unwrap_or(0);
    bytes.truncate(half);

    require_any_error(
        Transaction::deserialize(&bytes),
        "truncated wire payload should be rejected",
    )
}

#[test]
fn transaction_27_deserialize_rejects_zero_amount_wire() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 0,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(
        &tx,
        "malformed zero amount raw postcard encoding should succeed",
    )?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "greater than zero",
        "deserializer should reject zero amount wire transaction",
    )
}

#[test]
fn transaction_28_deserialize_rejects_same_wallet_wire() -> TestResult {
    let sender = wallet_array(&wallet_with_repeated_hex('a'))?;
    let tx = Transaction {
        sender,
        receiver: sender,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(
        &tx,
        "malformed same-wallet raw postcard encoding should succeed",
    )?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "Sender and receiver cannot be the same",
        "deserializer should reject same-wallet wire transaction",
    )
}

#[test]
fn transaction_29_validate_rejects_uppercase_stored_bytes() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&uppercase_wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    require_unit_validation_error_contains(
        tx.validate(),
        "Wallet address is invalid or incomplete",
        "validate should reject uppercase bytes already stored in struct",
    )
}

#[test]
fn transaction_30_validate_rejects_nul_stored_bytes() -> TestResult {
    let mut sender = wallet_array(&wallet_with_repeated_hex('a'))?;
    if let Some(byte) = sender.get_mut(10) {
        *byte = 0;
    } else {
        return Err("failed to mutate sender byte".to_owned());
    }

    let tx = Transaction {
        sender,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    require_unit_validation_error_contains(
        tx.validate(),
        "Wallet address bytes are invalid",
        "validate should reject NUL-padded or NUL-mutated wallet bytes",
    )
}

#[test]
fn transaction_31_validate_rejects_non_utf8_stored_bytes() -> TestResult {
    let mut sender = wallet_array(&wallet_with_repeated_hex('a'))?;
    if let Some(byte) = sender.get_mut(1) {
        *byte = 0xFF;
    } else {
        return Err("failed to mutate sender byte".to_owned());
    }

    let tx = Transaction {
        sender,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    require_unit_validation_error_contains(
        tx.validate(),
        "Wallet address bytes are invalid",
        "validate should reject non-UTF8 wallet bytes",
    )
}

#[test]
fn transaction_32_id_is_64_lower_hex() -> TestResult {
    let tx = valid_tx(44)?;
    let id = map_err_debug(tx.id(), "id should compute")?;

    require_equal(
        &id.len(),
        &64_usize,
        "Transaction::id should be 32-byte Blake3 hex",
    )?;
    require(
        lower_hex_string(&id),
        "Transaction::id should be lowercase hex",
    )?;

    Ok(())
}

#[test]
fn transaction_33_id_matches_blake3_of_serialized_bytes() -> TestResult {
    let tx = fixed_tx(55, VALID_STRUCTURAL_TIMESTAMP)?;
    let bytes = map_err_debug(tx.serialize(), "serialize should succeed")?;
    let expected = blake3::hash(&bytes).to_hex().to_string();
    let actual = map_err_debug(tx.id(), "id should compute")?;

    require_equal(
        &actual,
        &expected,
        "id should equal Blake3 hash of serialized bytes",
    )?;

    Ok(())
}

#[test]
fn transaction_34_id_changes_when_amount_changes() -> TestResult {
    let tx_one = fixed_tx(1, VALID_STRUCTURAL_TIMESTAMP)?;
    let tx_two = fixed_tx(2, VALID_STRUCTURAL_TIMESTAMP)?;

    let id_one = map_err_debug(tx_one.id(), "first id should compute")?;
    let id_two = map_err_debug(tx_two.id(), "second id should compute")?;

    require_not_equal(
        &id_one,
        &id_two,
        "different amounts should produce different ids",
    )?;

    Ok(())
}

#[test]
fn transaction_35_clone_equality_and_mutation() -> TestResult {
    let tx = fixed_tx(7, 77)?;
    let mut cloned = tx.clone();

    require_equal(&cloned, &tx, "clone should initially equal original")?;

    cloned.amount = 8;

    require_not_equal(&cloned, &tx, "mutating clone amount should change equality")?;

    Ok(())
}

#[test]
fn transaction_36_vector_micro_amount_table() -> TestResult {
    let cases = [
        (1_u64, 1_u64),
        (42_u64, 42_u64),
        (100_000_000_u64, 100_000_000_u64),
        (9_999_999_999_u64, 9_999_999_999_u64),
        (10_000_000_000_000_000_u64, 10_000_000_000_000_000_u64),
        (u64::MAX, u64::MAX),
    ];

    for (amount, expected) in cases {
        let tx = valid_tx(amount)?;
        require_equal(&tx.amount, &expected, "micro amount vector mismatch")?;
        map_err_debug(tx.validate(), "vector transaction should validate")?;
    }

    Ok(())
}

#[test]
fn transaction_37_vector_remzar_amount_table() -> TestResult {
    let cases = [
        (0.00000001_f64, 1_u64),
        (0.1_f64, 10_000_000_u64),
        (1.0_f64, 100_000_000_u64),
        (2.5_f64, 250_000_000_u64),
        (12.34567891_f64, 1_234_567_891_u64),
        (99.99999999_f64, 9_999_999_999_u64),
    ];

    for (amount_remzar, expected_micro) in cases {
        let tx = map_err_debug(
            Transaction::new_from_remzar(
                wallet_with_repeated_hex('a'),
                wallet_with_repeated_hex('b'),
                amount_remzar,
            ),
            "remzar vector transaction should create",
        )?;

        require_equal(
            &tx.amount,
            &expected_micro,
            "REMZAR amount vector should convert to expected micro-units",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_38_property_generated_valid_transactions_roundtrip() -> TestResult {
    for seed in 0_u64..128_u64 {
        let amount = seed
            .checked_add(1)
            .ok_or_else(|| "amount seed overflow".to_owned())?;

        let tx = map_err_debug(
            Transaction::new(
                wallet_from_seed(seed),
                wallet_from_seed(seed.saturating_add(10_000)),
                amount,
            ),
            "generated valid transaction should create",
        )?;

        map_err_debug(tx.validate(), "generated transaction should validate")?;

        let bytes = map_err_debug(tx.serialize(), "generated transaction should serialize")?;
        let decoded = map_err_debug(
            Transaction::deserialize(&bytes),
            "generated transaction should deserialize",
        )?;

        require_equal(
            &decoded,
            &tx,
            "generated roundtrip transaction should match",
        )?;

        let original_id = map_err_debug(tx.id(), "original id should compute")?;
        let decoded_id = map_err_debug(decoded.id(), "decoded id should compute")?;

        require_equal(
            &decoded_id,
            &original_id,
            "roundtrip id should remain stable",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_39_fuzz_invalid_wallet_and_wire_inputs() -> TestResult {
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
            Transaction::new(wrong_prefix, wallet_with_repeated_hex('b'), 1),
            "fuzz wrong-prefix wallet should fail",
        )?;
        require_any_error(
            Transaction::new(non_hex, wallet_with_repeated_hex('b'), 1),
            "fuzz non-hex wallet should fail",
        )?;
        require_any_error(
            Transaction::new(short, wallet_with_repeated_hex('b'), 1),
            "fuzz short wallet should fail",
        )?;
    }

    for len in 0_usize..384_usize {
        let seed = u64::try_from(len).map_err(|error| format!("len conversion failed: {error}"))?;
        let mut bytes = bytes_from_seed(seed, len);

        if let Some(first) = bytes.get_mut(0) {
            *first = b'x';
        }

        require_any_error(
            Transaction::deserialize(&bytes),
            "fuzz arbitrary wire payload should not become a valid transaction",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_40_adversarial_network_sim_and_load() -> TestResult {
    let mut incoming_wires: Vec<Vec<u8>> = Vec::new();

    for seed in 0_u64..64_u64 {
        let amount = seed
            .checked_add(1)
            .ok_or_else(|| "load amount overflow".to_owned())?;

        let tx = map_err_debug(
            Transaction::new(
                wallet_from_seed(seed),
                wallet_from_seed(seed.saturating_add(50_000)),
                amount,
            ),
            "load valid tx should create",
        )?;

        let valid_wire = map_err_debug(tx.serialize(), "load valid tx should serialize")?;
        incoming_wires.push(valid_wire.clone());

        if seed < 8 {
            incoming_wires.push(valid_wire.clone());
        }

        let zero_amount = Transaction {
            sender: wallet_array(&wallet_from_seed(seed.saturating_add(100_000)))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(150_000)))?,
            amount: 0,
            timestamp: VALID_STRUCTURAL_TIMESTAMP,
        };
        incoming_wires.push(raw_wire(
            &zero_amount,
            "zero amount adversarial raw postcard encoding should succeed",
        )?);

        let same_wallet = wallet_array(&wallet_from_seed(seed.saturating_add(200_000)))?;
        let same_wallet_tx = Transaction {
            sender: same_wallet,
            receiver: same_wallet,
            amount: 1,
            timestamp: VALID_STRUCTURAL_TIMESTAMP,
        };
        incoming_wires.push(raw_wire(
            &same_wallet_tx,
            "same wallet adversarial raw postcard encoding should succeed",
        )?);

        let mut nul_sender = wallet_array(&wallet_from_seed(seed.saturating_add(300_000)))?;
        if let Some(byte) = nul_sender.get_mut(20) {
            *byte = 0;
        } else {
            return Err("failed to mutate NUL sender byte".to_owned());
        }

        let nul_sender_tx = Transaction {
            sender: nul_sender,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(350_000)))?,
            amount: 1,
            timestamp: VALID_STRUCTURAL_TIMESTAMP,
        };
        incoming_wires.push(raw_wire(
            &nul_sender_tx,
            "NUL sender adversarial raw postcard encoding should succeed",
        )?);

        let mut truncated = valid_wire;
        let half = truncated.len().checked_div(2).unwrap_or(0);
        truncated.truncate(half);
        incoming_wires.push(truncated);
    }

    let mut seen_ids = BTreeSet::new();
    let mut accepted_unique = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut rejected = 0_usize;

    for wire in incoming_wires {
        match Transaction::deserialize(&wire) {
            Ok(tx) => {
                let id = map_err_debug(tx.id(), "accepted network tx id should compute")?;
                if seen_ids.insert(id) {
                    accepted_unique = accepted_unique
                        .checked_add(1)
                        .ok_or_else(|| "accepted count overflow".to_owned())?;
                } else {
                    duplicate_valid = duplicate_valid
                        .checked_add(1)
                        .ok_or_else(|| "duplicate count overflow".to_owned())?;
                }
            }
            Err(_) => {
                rejected = rejected
                    .checked_add(1)
                    .ok_or_else(|| "rejected count overflow".to_owned())?;
            }
        }
    }

    require_equal(
        &accepted_unique,
        &64_usize,
        "network sim should accept 64 unique valid txs",
    )?;
    require_equal(
        &duplicate_valid,
        &8_usize,
        "network sim should detect 8 duplicate valid txs",
    )?;
    require_equal(
        &rejected,
        &256_usize,
        "network sim should reject all adversarial wires",
    )?;

    Ok(())
}

#[test]
fn transaction_41_accepts_full_hex_alphabet_wallets() -> TestResult {
    let sender = format!("r{}", "0123456789abcdef".repeat(8));
    let receiver = format!("r{}", "fedcba9876543210".repeat(8));

    let tx = map_err_debug(
        Transaction::new(sender.clone(), receiver.clone(), 101),
        "full hex alphabet wallets should be accepted",
    )?;

    require_equal(
        &array_as_str(&tx.sender, "sender utf8")?,
        &sender,
        "sender should preserve full lowercase hex alphabet body",
    )?;
    require_equal(
        &array_as_str(&tx.receiver, "receiver utf8")?,
        &receiver,
        "receiver should preserve full lowercase hex alphabet body",
    )?;

    Ok(())
}

#[test]
fn transaction_42_rejects_missing_r_prefix_even_with_valid_length() -> TestResult {
    let missing_prefix = "a".repeat(REMZAR_WALLET_LEN);

    require_tx_validation_error_contains(
        Transaction::new(missing_prefix, wallet_with_repeated_hex('b'), 1),
        "Wallet address is invalid or incomplete",
        "missing r prefix should fail canonical wallet validation",
    )
}

#[test]
fn transaction_43_rejects_internal_space_in_wallet_body() -> TestResult {
    let invalid_sender = format!("r{} {}", "a".repeat(63), "a".repeat(64));

    require_equal(
        &invalid_sender.len(),
        &REMZAR_WALLET_LEN,
        "test wallet should be length-correct but format-invalid",
    )?;

    require_tx_validation_error_contains(
        Transaction::new(invalid_sender, wallet_with_repeated_hex('b'), 1),
        "Wallet address is invalid or incomplete",
        "internal wallet body space should fail",
    )
}

#[test]
fn transaction_44_rejects_internal_newline_in_wallet_body() -> TestResult {
    let invalid_sender = format!("r{}\n{}", "a".repeat(63), "a".repeat(64));

    require_equal(
        &invalid_sender.len(),
        &REMZAR_WALLET_LEN,
        "test wallet should be length-correct but contain newline",
    )?;

    require_tx_validation_error_contains(
        Transaction::new(invalid_sender, wallet_with_repeated_hex('b'), 1),
        "Wallet address is invalid or incomplete",
        "internal newline should fail",
    )
}

#[test]
fn transaction_45_accepts_boundary_whitespace_after_trim() -> TestResult {
    let sender = format!("\n{}\r\n", uppercase_wallet_with_repeated_hex('c'));
    let receiver = format!("\t{}\n", uppercase_wallet_with_repeated_hex('d'));

    let tx = map_err_debug(
        Transaction::new(sender, receiver, 22),
        "boundary whitespace should be trimmed and canonicalized",
    )?;

    require_equal(
        &array_as_str(&tx.sender, "sender utf8")?,
        &wallet_with_repeated_hex('c'),
        "trimmed sender should canonicalize to lowercase",
    )?;
    require_equal(
        &array_as_str(&tx.receiver, "receiver utf8")?,
        &wallet_with_repeated_hex('d'),
        "trimmed receiver should canonicalize to lowercase",
    )?;

    Ok(())
}

#[test]
fn transaction_46_rejects_unicode_lookalike_prefix() -> TestResult {
    let invalid_sender = format!("ŕ{}", "a".repeat(127));

    require_equal(
        &invalid_sender.len(),
        &REMZAR_WALLET_LEN,
        "unicode-prefix wallet should be byte-length-correct for this adversarial test",
    )?;

    require_tx_validation_error_contains(
        Transaction::new(invalid_sender, wallet_with_repeated_hex('b'), 1),
        "Wallet address is invalid or incomplete",
        "unicode lookalike prefix must not pass as ASCII r",
    )
}

#[test]
fn transaction_47_validate_rejects_zero_timestamp() -> TestResult {
    let tx = fixed_tx(5, 0)?;

    require_unit_validation_error_contains(
        tx.validate(),
        "timestamp below UNIX_2000_SECS",
        "timestamp zero should fail structural timestamp validation",
    )
}

#[test]
fn transaction_48_validate_rejects_u64_max_timestamp() -> TestResult {
    let tx = fixed_tx(6, u64::MAX)?;

    require_unit_validation_error_contains(
        tx.validate(),
        "timestamp above UNIX_9999_SECS",
        "u64::MAX timestamp should fail structural timestamp validation",
    )
}

#[test]
fn transaction_49_deserialize_rejects_zero_timestamp_wire() -> TestResult {
    let tx = fixed_tx(7, 0)?;
    let bytes = raw_wire(&tx, "zero timestamp raw postcard encoding should succeed")?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "timestamp below UNIX_2000_SECS",
        "zero timestamp wire transaction should be rejected",
    )
}

#[test]
fn transaction_50_id_changes_when_timestamp_changes() -> TestResult {
    let first = fixed_tx(9, VALID_STRUCTURAL_TIMESTAMP)?;
    let second = fixed_tx(9, VALID_STRUCTURAL_TIMESTAMP + 1)?;

    let first_id = map_err_debug(first.id(), "first id should compute")?;
    let second_id = map_err_debug(second.id(), "second id should compute")?;

    require_not_equal(
        &first_id,
        &second_id,
        "changing timestamp should change transaction id",
    )?;

    Ok(())
}

#[test]
fn transaction_51_id_changes_when_sender_changes() -> TestResult {
    let first = Transaction {
        sender: wallet_array(&wallet_from_seed(1))?,
        receiver: wallet_array(&wallet_from_seed(2))?,
        amount: 8,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };
    let second = Transaction {
        sender: wallet_array(&wallet_from_seed(3))?,
        receiver: wallet_array(&wallet_from_seed(2))?,
        amount: 8,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let first_id = map_err_debug(first.id(), "first sender id should compute")?;
    let second_id = map_err_debug(second.id(), "second sender id should compute")?;

    require_not_equal(&first_id, &second_id, "changing sender should change id")?;

    Ok(())
}

#[test]
fn transaction_52_id_changes_when_receiver_changes() -> TestResult {
    let first = Transaction {
        sender: wallet_array(&wallet_from_seed(4))?,
        receiver: wallet_array(&wallet_from_seed(5))?,
        amount: 8,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };
    let second = Transaction {
        sender: wallet_array(&wallet_from_seed(4))?,
        receiver: wallet_array(&wallet_from_seed(6))?,
        amount: 8,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let first_id = map_err_debug(first.id(), "first receiver id should compute")?;
    let second_id = map_err_debug(second.id(), "second receiver id should compute")?;

    require_not_equal(&first_id, &second_id, "changing receiver should change id")?;

    Ok(())
}

#[test]
fn transaction_53_roundtrips_max_amount_fixed_transaction() -> TestResult {
    let tx = fixed_tx(u64::MAX, VALID_STRUCTURAL_TIMESTAMP)?;
    let bytes = map_err_debug(tx.serialize(), "max amount tx should serialize")?;
    let decoded = map_err_debug(
        Transaction::deserialize(&bytes),
        "max amount tx should deserialize",
    )?;

    require_equal(
        &decoded.amount,
        &u64::MAX,
        "max amount should survive roundtrip",
    )?;
    require_equal(
        &decoded,
        &tx,
        "max amount transaction should roundtrip exactly",
    )?;

    Ok(())
}

#[test]
fn transaction_54_new_from_remzar_converts_sub_one_remzar_vector() -> TestResult {
    let tx = map_err_debug(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            0.99999999,
        ),
        "0.99999999 REMZAR should create transaction",
    )?;

    require_equal(
        &tx.amount,
        &99_999_999_u64,
        "0.99999999 should convert to 99,999,999 micro",
    )?;

    Ok(())
}

#[test]
fn transaction_55_new_from_remzar_converts_large_decimal_vector() -> TestResult {
    let tx = map_err_debug(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            123_456.78901234,
        ),
        "large decimal REMZAR amount should create transaction",
    )?;

    require_equal(
        &tx.amount,
        &12_345_678_901_234_u64,
        "123456.78901234 should convert to exact micro-units",
    )?;

    Ok(())
}

#[test]
fn transaction_56_new_from_remzar_accepts_largest_whole_precheck_boundary() -> TestResult {
    let expected = 184_467_440_737_u64
        .checked_mul(UNIT_DIVISOR)
        .ok_or_else(|| "expected amount multiplication overflowed".to_owned())?;

    let tx = map_err_debug(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            184_467_440_737.0,
        ),
        "largest whole precheck boundary should create transaction",
    )?;

    require_equal(
        &tx.amount,
        &expected,
        "largest accepted whole REMZAR boundary should convert correctly",
    )?;

    Ok(())
}

#[test]
fn transaction_57_new_from_remzar_rejects_negative_infinity() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            f64::NEG_INFINITY,
        ),
        "too large",
        "negative infinity follows explicit infinite-amount rejection branch",
    )
}

#[test]
fn transaction_58_new_from_remzar_rejects_huge_finite_whole_part() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new_from_remzar(
            wallet_with_repeated_hex('a'),
            wallet_with_repeated_hex('b'),
            1_000_000_000_000.0,
        ),
        "too large",
        "huge finite whole-part amount should be rejected",
    )
}

#[test]
fn transaction_59_amount_as_remzar_formats_one_micro_unit() -> TestResult {
    let tx = fixed_tx(1, VALID_STRUCTURAL_TIMESTAMP)?;

    let displayed = format!("{:.8}", tx.amount_as_remzar());

    require_equal(
        &displayed,
        &"0.00000001".to_owned(),
        "one micro-unit should display as 0.00000001 REMZAR",
    )?;

    Ok(())
}

#[test]
fn transaction_60_amount_as_remzar_formats_whole_remzar() -> TestResult {
    let amount = 2_u64
        .checked_mul(UNIT_DIVISOR)
        .ok_or_else(|| "whole REMZAR multiplication overflowed".to_owned())?;
    let tx = fixed_tx(amount, VALID_STRUCTURAL_TIMESTAMP)?;

    let displayed = format!("{:.8}", tx.amount_as_remzar());

    require_equal(
        &displayed,
        &"2.00000000".to_owned(),
        "two REMZAR should display with eight decimal places",
    )?;

    Ok(())
}

#[test]
fn transaction_61_deserialize_rejects_wrong_sender_prefix_wire() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&format!("x{}", "a".repeat(128)))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(
        &tx,
        "wrong-prefix sender raw postcard encoding should succeed",
    )?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "Wallet address is invalid or incomplete",
        "wrong sender prefix should be rejected on deserialize",
    )
}

#[test]
fn transaction_62_deserialize_rejects_wrong_receiver_prefix_wire() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&format!("x{}", "b".repeat(128)))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(
        &tx,
        "wrong-prefix receiver raw postcard encoding should succeed",
    )?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "Wallet address is invalid or incomplete",
        "wrong receiver prefix should be rejected on deserialize",
    )
}

#[test]
fn transaction_63_deserialize_rejects_sender_non_hex_wire() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&format!("r{}z", "a".repeat(127)))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(&tx, "non-hex sender raw postcard encoding should succeed")?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "Wallet address is invalid or incomplete",
        "non-hex sender should be rejected on deserialize",
    )
}

#[test]
fn transaction_64_deserialize_rejects_receiver_uppercase_wire() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&uppercase_wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(
        &tx,
        "uppercase receiver raw postcard encoding should succeed",
    )?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "Wallet address is invalid or incomplete",
        "uppercase stored receiver should be rejected on deserialize",
    )
}

#[test]
fn transaction_65_deserialize_rejects_receiver_nul_wire() -> TestResult {
    let mut receiver = wallet_array(&wallet_with_repeated_hex('b'))?;
    if let Some(byte) = receiver.get_mut(50) {
        *byte = 0;
    } else {
        return Err("failed to mutate receiver byte".to_owned());
    }

    let tx = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(&tx, "NUL receiver raw postcard encoding should succeed")?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "Wallet address bytes are invalid",
        "NUL receiver should be rejected on deserialize",
    )
}

#[test]
fn transaction_66_validate_rejects_wrong_prefix_in_stored_receiver() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&format!("x{}", "b".repeat(128)))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    require_unit_validation_error_contains(
        tx.validate(),
        "Wallet address is invalid or incomplete",
        "validate should reject stored receiver with wrong prefix",
    )
}

#[test]
fn transaction_67_property_generated_fixed_transactions_have_unique_ids() -> TestResult {
    let mut ids = BTreeSet::new();

    for seed in 0_u64..100_u64 {
        let amount = seed
            .checked_add(1)
            .ok_or_else(|| "seed amount overflowed".to_owned())?;
        let timestamp = VALID_STRUCTURAL_TIMESTAMP
            .checked_add(seed)
            .ok_or_else(|| "seed timestamp overflowed".to_owned())?;

        let tx = Transaction {
            sender: wallet_array(&wallet_from_seed(seed))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(100)))?,
            amount,
            timestamp,
        };

        let id = map_err_debug(tx.id(), "generated fixed tx id should compute")?;
        require(
            ids.insert(id),
            "generated fixed transaction id should be unique",
        )?;
    }

    require_equal(
        &ids.len(),
        &100_usize,
        "should collect 100 unique generated ids",
    )?;

    Ok(())
}

#[test]
fn transaction_68_property_uppercase_boundary_inputs_canonicalize() -> TestResult {
    for seed in 0_u64..32_u64 {
        let sender_lower = wallet_from_seed(seed);
        let receiver_lower = wallet_from_seed(seed.saturating_add(1_000));
        let sender_upper = sender_lower.to_ascii_uppercase();
        let receiver_upper = receiver_lower.to_ascii_uppercase();

        let tx = map_err_debug(
            Transaction::new(sender_upper, receiver_upper, 1),
            "uppercase generated wallets should canonicalize",
        )?;

        require_equal(
            &array_as_str(&tx.sender, "sender utf8")?,
            &sender_lower,
            "generated uppercase sender should canonicalize to lowercase",
        )?;
        require_equal(
            &array_as_str(&tx.receiver, "receiver utf8")?,
            &receiver_lower,
            "generated uppercase receiver should canonicalize to lowercase",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_69_property_constructor_preserves_generated_micro_amounts() -> TestResult {
    let amounts = [
        1_u64, 2_u64, 3_u64, 5_u64, 8_u64, 13_u64, 21_u64, 34_u64, 55_u64, 89_u64, 144_u64,
        233_u64, 377_u64, 610_u64, 987_u64, 1_597_u64,
    ];

    for amount in amounts {
        let tx = map_err_debug(
            Transaction::new(
                wallet_with_repeated_hex('a'),
                wallet_with_repeated_hex('b'),
                amount,
            ),
            "amount preservation constructor should succeed",
        )?;

        require_equal(
            &tx.amount,
            &amount,
            "constructor should preserve exact micro amount",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_70_property_whole_remzar_conversion_range() -> TestResult {
    for whole in 1_u64..32_u64 {
        let whole_string = whole.to_string();
        let amount_remzar = whole_string
            .parse::<f64>()
            .map_err(|error| format!("failed to parse whole amount {whole_string}: {error}"))?;
        let expected = whole
            .checked_mul(UNIT_DIVISOR)
            .ok_or_else(|| "whole amount multiplication overflowed".to_owned())?;

        let tx = map_err_debug(
            Transaction::new_from_remzar(
                wallet_with_repeated_hex('a'),
                wallet_with_repeated_hex('b'),
                amount_remzar,
            ),
            "whole REMZAR conversion should succeed",
        )?;

        require_equal(
            &tx.amount,
            &expected,
            "whole REMZAR amount should convert exactly",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_71_property_repeated_roundtrip_is_stable() -> TestResult {
    let original = fixed_tx(123, VALID_STRUCTURAL_TIMESTAMP)?;
    let mut current = original.clone();

    for _ in 0_usize..10_usize {
        let bytes = map_err_debug(
            current.serialize(),
            "repeated roundtrip serialize should succeed",
        )?;
        current = map_err_debug(
            Transaction::deserialize(&bytes),
            "repeated roundtrip deserialize should succeed",
        )?;
    }

    require_equal(
        &current,
        &original,
        "transaction should remain stable after repeated roundtrips",
    )?;

    Ok(())
}

#[test]
fn transaction_72_property_repeated_id_calls_are_stable() -> TestResult {
    let tx = fixed_tx(321, VALID_STRUCTURAL_TIMESTAMP)?;
    let expected = map_err_debug(tx.id(), "initial id should compute")?;

    for _ in 0_usize..20_usize {
        let actual = map_err_debug(tx.id(), "repeated id should compute")?;
        require_equal(
            &actual,
            &expected,
            "repeated id call should remain deterministic",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_73_fuzz_all_truncated_prefixes_rejected() -> TestResult {
    let tx = fixed_tx(777, VALID_STRUCTURAL_TIMESTAMP)?;
    let bytes = map_err_debug(tx.serialize(), "valid transaction should serialize")?;

    for cut in 0_usize..bytes.len() {
        let prefix = bytes
            .get(..cut)
            .ok_or_else(|| format!("failed to get prefix cut {cut}"))?;

        require_any_error(
            Transaction::deserialize(prefix),
            "every truncated serialized prefix should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_74_fuzz_bitflips_reject_or_change_id() -> TestResult {
    let original = fixed_tx(999, VALID_STRUCTURAL_TIMESTAMP)?;
    let original_bytes = map_err_debug(original.serialize(), "original tx should serialize")?;
    let original_id = map_err_debug(original.id(), "original id should compute")?;

    for byte_index in 0_usize..original_bytes.len().min(48) {
        let mut mutated = original_bytes.clone();
        if let Some(byte) = mutated.get_mut(byte_index) {
            *byte ^= 0x01;
        } else {
            return Err(format!("failed to mutate byte index {byte_index}"));
        }

        match Transaction::deserialize(&mutated) {
            Ok(tx) => {
                let mutated_id = map_err_debug(tx.id(), "mutated accepted tx id should compute")?;
                require_not_equal(
                    &mutated_id,
                    &original_id,
                    "accepted bitflip mutation should not preserve original id",
                )?;
            }
            Err(_) => {}
        }
    }

    Ok(())
}

#[test]
fn transaction_75_adversarial_duplicate_flood_detected_by_id_set() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..32_u64 {
        let tx = map_err_debug(
            Transaction::new(
                wallet_from_seed(seed),
                wallet_from_seed(seed.saturating_add(500)),
                seed.checked_add(1)
                    .ok_or_else(|| "amount overflowed".to_owned())?,
            ),
            "duplicate flood valid tx should create",
        )?;
        let wire = map_err_debug(tx.serialize(), "duplicate flood valid tx should serialize")?;

        wires.push(wire.clone());
        wires.push(wire.clone());
        wires.push(wire);
    }

    let mut seen = BTreeSet::new();
    let mut unique = 0_usize;
    let mut duplicate = 0_usize;

    for wire in wires {
        let tx = map_err_debug(
            Transaction::deserialize(&wire),
            "duplicate flood wire should deserialize",
        )?;
        let id = map_err_debug(tx.id(), "duplicate flood id should compute")?;

        if seen.insert(id) {
            unique = unique
                .checked_add(1)
                .ok_or_else(|| "unique counter overflowed".to_owned())?;
        } else {
            duplicate = duplicate
                .checked_add(1)
                .ok_or_else(|| "duplicate counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &unique,
        &32_usize,
        "duplicate flood should have 32 unique transactions",
    )?;
    require_equal(
        &duplicate,
        &64_usize,
        "duplicate flood should detect 64 duplicates",
    )?;

    Ok(())
}

#[test]
fn transaction_76_adversarial_malformed_wallet_wire_flood_rejected() -> TestResult {
    let mut rejected = 0_usize;

    for seed in 0_u64..128_u64 {
        let mut invalid_body = String::with_capacity(127);
        for ch in wallet_body_from_seed(seed).chars().take(127) {
            invalid_body.push(ch);
        }

        let invalid_sender = format!("r{invalid_body}z");
        let tx = Transaction {
            sender: wallet_array(&invalid_sender)?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(10_000)))?,
            amount: 1,
            timestamp: VALID_STRUCTURAL_TIMESTAMP
                .checked_add(seed)
                .ok_or_else(|| "malformed wallet timestamp overflowed".to_owned())?,
        };

        let wire = raw_wire(&tx, "malformed wallet raw postcard encoding should succeed")?;

        if Transaction::deserialize(&wire).is_err() {
            rejected = rejected
                .checked_add(1)
                .ok_or_else(|| "rejected counter overflowed".to_owned())?;
        }
    }

    require_equal(
        &rejected,
        &128_usize,
        "all malformed wallet wires should be rejected",
    )?;

    Ok(())
}

#[test]
fn transaction_77_load_serializes_many_valid_transactions_with_unique_ids() -> TestResult {
    let mut total_bytes = 0_usize;
    let mut ids = BTreeSet::new();

    for seed in 0_u64..512_u64 {
        let tx = map_err_debug(
            Transaction::new(
                wallet_from_seed(seed),
                wallet_from_seed(seed.saturating_add(100_000)),
                seed.checked_add(1)
                    .ok_or_else(|| "amount overflowed".to_owned())?,
            ),
            "load transaction should create",
        )?;

        let wire = map_err_debug(tx.serialize(), "load transaction should serialize")?;
        total_bytes = total_bytes
            .checked_add(wire.len())
            .ok_or_else(|| "total serialized byte counter overflowed".to_owned())?;

        let id = map_err_debug(tx.id(), "load transaction id should compute")?;
        require(ids.insert(id), "load transaction id should be unique")?;
    }

    require_equal(&ids.len(), &512_usize, "load should produce 512 unique ids")?;
    require(total_bytes > 0, "load serialization should produce bytes")?;

    Ok(())
}

#[test]
fn transaction_78_load_deserializes_many_valid_wires() -> TestResult {
    let mut wires = Vec::with_capacity(512);

    for seed in 0_u64..512_u64 {
        let tx = map_err_debug(
            Transaction::new(
                wallet_from_seed(seed),
                wallet_from_seed(seed.saturating_add(200_000)),
                seed.checked_add(1)
                    .ok_or_else(|| "amount overflowed".to_owned())?,
            ),
            "load deserialize tx should create",
        )?;
        wires.push(map_err_debug(
            tx.serialize(),
            "load deserialize tx should serialize",
        )?);
    }

    let mut accepted = 0_usize;

    for wire in wires {
        let tx = map_err_debug(
            Transaction::deserialize(&wire),
            "load wire should deserialize",
        )?;
        map_err_debug(tx.validate(), "load decoded transaction should validate")?;

        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| "accepted counter overflowed".to_owned())?;
    }

    require_equal(
        &accepted,
        &512_usize,
        "all valid load wires should deserialize",
    )?;

    Ok(())
}

#[test]
fn transaction_79_adversarial_reversed_order_network_batch_counts_valid_and_invalid() -> TestResult
{
    let mut wires = Vec::new();

    for seed in 0_u64..40_u64 {
        let valid = map_err_debug(
            Transaction::new(
                wallet_from_seed(seed),
                wallet_from_seed(seed.saturating_add(300_000)),
                seed.checked_add(1)
                    .ok_or_else(|| "valid amount overflowed".to_owned())?,
            ),
            "valid network tx should create",
        )?;
        wires.push(map_err_debug(
            valid.serialize(),
            "valid network tx should serialize",
        )?);

        let invalid_zero = Transaction {
            sender: wallet_array(&wallet_from_seed(seed.saturating_add(400_000)))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(500_000)))?,
            amount: 0,
            timestamp: VALID_STRUCTURAL_TIMESTAMP
                .checked_add(seed)
                .ok_or_else(|| "invalid zero timestamp overflowed".to_owned())?,
        };
        wires.push(raw_wire(
            &invalid_zero,
            "invalid zero network raw postcard encoding should succeed",
        )?);
    }

    wires.reverse();

    let mut accepted = 0_usize;
    let mut rejected = 0_usize;

    for wire in wires {
        match Transaction::deserialize(&wire) {
            Ok(_) => {
                accepted = accepted
                    .checked_add(1)
                    .ok_or_else(|| "accepted counter overflowed".to_owned())?;
            }
            Err(_) => {
                rejected = rejected
                    .checked_add(1)
                    .ok_or_else(|| "rejected counter overflowed".to_owned())?;
            }
        }
    }

    require_equal(
        &accepted,
        &40_usize,
        "reversed batch should accept all valid txs",
    )?;
    require_equal(
        &rejected,
        &40_usize,
        "reversed batch should reject all zero amount txs",
    )?;

    Ok(())
}

#[test]
fn transaction_80_mixed_adversarial_load_accepts_only_valid_unique_transactions() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..96_u64 {
        let valid = map_err_debug(
            Transaction::new(
                wallet_from_seed(seed),
                wallet_from_seed(seed.saturating_add(600_000)),
                seed.checked_add(1)
                    .ok_or_else(|| "valid amount overflowed".to_owned())?,
            ),
            "mixed load valid tx should create",
        )?;
        let valid_wire = map_err_debug(valid.serialize(), "mixed load valid tx should serialize")?;
        wires.push(valid_wire.clone());

        if seed < 16 {
            wires.push(valid_wire.clone());
        }

        let same_wallet = wallet_array(&wallet_from_seed(seed.saturating_add(700_000)))?;
        let invalid_same = Transaction {
            sender: same_wallet,
            receiver: same_wallet,
            amount: 1,
            timestamp: VALID_STRUCTURAL_TIMESTAMP
                .checked_add(seed)
                .ok_or_else(|| "invalid same-wallet timestamp overflowed".to_owned())?,
        };
        wires.push(raw_wire(
            &invalid_same,
            "mixed load same-wallet raw postcard encoding should succeed",
        )?);

        let mut truncated = valid_wire;
        let half = truncated.len().checked_div(2).unwrap_or(0);
        truncated.truncate(half);
        wires.push(truncated);
    }

    let mut seen = BTreeSet::new();
    let mut unique_valid = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut rejected = 0_usize;

    for wire in wires {
        match Transaction::deserialize(&wire) {
            Ok(tx) => {
                let id = map_err_debug(tx.id(), "mixed accepted tx id should compute")?;
                if seen.insert(id) {
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
        &96_usize,
        "mixed load should accept 96 unique valid txs",
    )?;
    require_equal(
        &duplicate_valid,
        &16_usize,
        "mixed load should detect 16 duplicate valids",
    )?;
    require_equal(
        &rejected,
        &192_usize,
        "mixed load should reject malformed and truncated txs",
    )?;

    Ok(())
}

#[test]
fn transaction_81_vector_accepts_all_lowercase_hex_digits_in_wallet_body() -> TestResult {
    let sender = format!("r{}", "0123456789abcdef".repeat(8));
    let receiver = format!("r{}", "fedcba9876543210".repeat(8));

    require_equal(
        &sender.len(),
        &REMZAR_WALLET_LEN,
        "sender vector wallet should have canonical length",
    )?;
    require_equal(
        &receiver.len(),
        &REMZAR_WALLET_LEN,
        "receiver vector wallet should have canonical length",
    )?;

    let tx = map_err_debug(
        Transaction::new(sender.clone(), receiver.clone(), 1),
        "all lowercase hex digits should be accepted",
    )?;

    require_equal(
        &array_as_str(&tx.sender, "sender utf8")?,
        &sender,
        "sender should preserve lowercase hex vector",
    )?;
    require_equal(
        &array_as_str(&tx.receiver, "receiver utf8")?,
        &receiver,
        "receiver should preserve lowercase hex vector",
    )?;

    Ok(())
}

#[test]
fn transaction_82_vector_rejects_invalid_ascii_wallet_body_chars() -> TestResult {
    let invalid_suffixes = ["g", "G", "z", "Z", "-", "_", "/", ":"];

    for suffix in invalid_suffixes {
        let invalid_sender = format!("r{}{}", "a".repeat(127), suffix);

        require_equal(
            &invalid_sender.len(),
            &REMZAR_WALLET_LEN,
            "invalid wallet should be length-correct for format validation",
        )?;

        require_any_error(
            Transaction::new(invalid_sender, wallet_with_repeated_hex('b'), 1),
            "invalid ASCII wallet body char should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_83_vector_rejects_sender_length_boundaries() -> TestResult {
    let body_lengths = [0_usize, 1, 2, 126, 127, 129, 130, 255];

    for body_len in body_lengths {
        let sender = format!("r{}", "a".repeat(body_len));

        require(
            sender.len() != REMZAR_WALLET_LEN,
            "sender length vector must intentionally avoid valid canonical length",
        )?;

        require_tx_validation_error_contains(
            Transaction::new(sender, wallet_with_repeated_hex('b'), 1),
            "Invalid address length",
            "sender length boundary should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_84_vector_rejects_receiver_length_boundaries() -> TestResult {
    let body_lengths = [0_usize, 1, 2, 126, 127, 129, 130, 255];

    for body_len in body_lengths {
        let receiver = format!("r{}", "b".repeat(body_len));

        require(
            receiver.len() != REMZAR_WALLET_LEN,
            "receiver length vector must intentionally avoid valid canonical length",
        )?;

        require_tx_validation_error_contains(
            Transaction::new(wallet_with_repeated_hex('a'), receiver, 1),
            "Invalid address length",
            "receiver length boundary should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_85_vector_micro_amount_boundaries_roundtrip() -> TestResult {
    let unit_minus_one = UNIT_DIVISOR
        .checked_sub(1)
        .ok_or_else(|| "UNIT_DIVISOR - 1 underflowed".to_owned())?;
    let unit_plus_one = UNIT_DIVISOR
        .checked_add(1)
        .ok_or_else(|| "UNIT_DIVISOR + 1 overflowed".to_owned())?;

    let amounts = [
        1_u64,
        unit_minus_one,
        UNIT_DIVISOR,
        unit_plus_one,
        10_000_000_000_000_000_u64,
        u64::MAX,
    ];

    for amount in amounts {
        let tx = fixed_tx(amount, VALID_STRUCTURAL_TIMESTAMP)?;
        map_err_debug(tx.validate(), "micro amount boundary tx should validate")?;

        let bytes = map_err_debug(tx.serialize(), "micro amount boundary tx should serialize")?;
        let decoded = map_err_debug(
            Transaction::deserialize(&bytes),
            "micro amount boundary tx should deserialize",
        )?;

        require_equal(
            &decoded.amount,
            &amount,
            "micro amount boundary should survive roundtrip",
        )?;
        require_equal(
            &decoded,
            &tx,
            "micro amount boundary transaction should roundtrip exactly",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_86_vector_remzar_fraction_boundaries() -> TestResult {
    let cases = [
        (0.00000001_f64, 1_u64),
        (0.00000002_f64, 2_u64),
        (0.00000009_f64, 9_u64),
        (0.00000010_f64, 10_u64),
        (0.00000100_f64, 100_u64),
        (0.00001000_f64, 1_000_u64),
        (0.00010000_f64, 10_000_u64),
        (0.00100000_f64, 100_000_u64),
    ];

    for (amount_remzar, expected_micro) in cases {
        let tx = map_err_debug(
            Transaction::new_from_remzar(
                wallet_with_repeated_hex('a'),
                wallet_with_repeated_hex('b'),
                amount_remzar,
            ),
            "fraction boundary REMZAR amount should create",
        )?;

        require_equal(
            &tx.amount,
            &expected_micro,
            "fraction boundary should convert to expected micro-units",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_87_vector_remzar_decimal_rounding_boundaries() -> TestResult {
    let cases = [
        (0.000000014_f64, 1_u64),
        (0.000000016_f64, 2_u64),
        (1.234567894_f64, 123_456_789_u64),
        (1.234567896_f64, 123_456_790_u64),
        (9.999999994_f64, 999_999_999_u64),
        (9.999999996_f64, 1_000_000_000_u64),
    ];

    for (amount_remzar, expected_micro) in cases {
        let tx = map_err_debug(
            Transaction::new_from_remzar(
                wallet_with_repeated_hex('a'),
                wallet_with_repeated_hex('b'),
                amount_remzar,
            ),
            "rounded REMZAR boundary amount should create",
        )?;

        require_equal(
            &tx.amount,
            &expected_micro,
            "rounded REMZAR boundary should convert through fixed 8 decimal display",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_88_vector_rejects_non_positive_remzar_values() -> TestResult {
    let invalid_amounts = [
        -100.0_f64,
        -1.0_f64,
        -0.00000001_f64,
        -0.0_f64,
        0.0_f64,
        0.000000001_f64,
        0.000000004_f64,
    ];

    for amount in invalid_amounts {
        require_tx_validation_error_contains(
            Transaction::new_from_remzar(
                wallet_with_repeated_hex('a'),
                wallet_with_repeated_hex('b'),
                amount,
            ),
            "greater than zero",
            "non-positive or rounded-zero REMZAR value should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_89_vector_rejects_non_finite_remzar_values() -> TestResult {
    let nan_result = Transaction::new_from_remzar(
        wallet_with_repeated_hex('a'),
        wallet_with_repeated_hex('b'),
        f64::NAN,
    );
    let inf_result = Transaction::new_from_remzar(
        wallet_with_repeated_hex('a'),
        wallet_with_repeated_hex('b'),
        f64::INFINITY,
    );
    let neg_inf_result = Transaction::new_from_remzar(
        wallet_with_repeated_hex('a'),
        wallet_with_repeated_hex('b'),
        f64::NEG_INFINITY,
    );

    require_tx_validation_error_contains(
        nan_result,
        "greater than zero",
        "NaN should be rejected",
    )?;
    require_tx_validation_error_contains(
        inf_result,
        "too large",
        "positive infinity should be rejected",
    )?;
    require_tx_validation_error_contains(
        neg_inf_result,
        "too large",
        "negative infinity should be rejected by explicit infinity branch",
    )?;

    Ok(())
}

#[test]
fn transaction_90_edge_constructor_rejects_same_wallet_with_different_outer_whitespace()
-> TestResult {
    let sender = format!("  {}  ", wallet_with_repeated_hex('a'));
    let receiver = format!("\n{}\t", wallet_with_repeated_hex('a'));

    require_tx_validation_error_contains(
        Transaction::new(sender, receiver, 1),
        "Sender and receiver cannot be the same",
        "same wallet after trimming should be rejected",
    )
}

#[test]
fn transaction_91_edge_constructor_rejects_same_wallet_with_different_case() -> TestResult {
    require_tx_validation_error_contains(
        Transaction::new(
            uppercase_wallet_with_repeated_hex('c'),
            wallet_with_repeated_hex('c'),
            1,
        ),
        "Sender and receiver cannot be the same",
        "same wallet after case canonicalization should be rejected",
    )
}

#[test]
fn transaction_92_edge_validate_rejects_same_wallet_arrays_with_max_amount() -> TestResult {
    let wallet = wallet_array(&wallet_with_repeated_hex('d'))?;
    let tx = Transaction {
        sender: wallet,
        receiver: wallet,
        amount: u64::MAX,
        timestamp: u64::MAX,
    };

    require_unit_validation_error_contains(
        tx.validate(),
        "Sender and receiver cannot be the same",
        "same stored wallet arrays should be rejected even with max amount and timestamp",
    )
}

#[test]
fn transaction_93_edge_deserialize_rejects_zero_amount_wire() -> TestResult {
    let tx = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 0,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let bytes = raw_wire(&tx, "zero amount raw postcard encoding should succeed")?;

    require_tx_validation_error_contains(
        Transaction::deserialize(&bytes),
        "greater than zero",
        "deserialize should reject zero amount wire transaction",
    )
}

#[test]
fn transaction_94_edge_deserialize_rejects_extra_trailing_bytes() -> TestResult {
    let tx = fixed_tx(44, VALID_STRUCTURAL_TIMESTAMP)?;
    let mut bytes = map_err_debug(tx.serialize(), "valid tx should serialize")?;
    bytes.extend_from_slice(&[0_u8, 1_u8, 2_u8, 3_u8]);

    require_any_error(
        Transaction::deserialize(&bytes),
        "deserialize should reject non-canonical transaction bytes with trailing data",
    )
}

#[test]
fn transaction_95_edge_deserialize_rejects_single_byte_payloads() -> TestResult {
    for byte in 0_u8..=32_u8 {
        let payload = [byte];

        require_any_error(
            Transaction::deserialize(&payload),
            "single-byte payload should be rejected",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_96_edge_id_stable_after_serialization_roundtrip() -> TestResult {
    let tx = fixed_tx(123_456_789, 987_654_321)?;
    let original_id = map_err_debug(tx.id(), "original id should compute")?;

    let bytes = map_err_debug(tx.serialize(), "transaction should serialize")?;
    let decoded = map_err_debug(
        Transaction::deserialize(&bytes),
        "transaction should deserialize",
    )?;
    let decoded_id = map_err_debug(decoded.id(), "decoded id should compute")?;

    require_equal(
        &decoded_id,
        &original_id,
        "transaction id should remain stable after serialization roundtrip",
    )?;

    Ok(())
}

#[test]
fn transaction_97_edge_id_changes_for_reversed_sender_receiver() -> TestResult {
    let forward = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };
    let reversed = Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('b'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('a'))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let forward_id = map_err_debug(forward.id(), "forward id should compute")?;
    let reversed_id = map_err_debug(reversed.id(), "reversed id should compute")?;

    require_not_equal(
        &forward_id,
        &reversed_id,
        "reversing sender and receiver should change transaction id",
    )?;

    Ok(())
}

#[test]
fn transaction_98_vector_generated_wallet_pairs_do_not_alias() -> TestResult {
    for seed in 0_u64..64_u64 {
        let sender = wallet_from_seed(seed);
        let receiver = wallet_from_seed(seed.saturating_add(1));

        require_not_equal(
            &sender,
            &receiver,
            "generated adjacent wallet seeds should produce different wallets",
        )?;

        let tx = map_err_debug(
            Transaction::new(sender.clone(), receiver.clone(), 1),
            "generated adjacent wallet pair should create transaction",
        )?;

        require_equal(
            &array_as_str(&tx.sender, "sender utf8")?,
            &sender,
            "generated sender should be stored exactly",
        )?;
        require_equal(
            &array_as_str(&tx.receiver, "receiver utf8")?,
            &receiver,
            "generated receiver should be stored exactly",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_99_vector_id_length_and_charset_for_many_fixed_txs() -> TestResult {
    for seed in 0_u64..128_u64 {
        let amount = seed
            .checked_add(1)
            .ok_or_else(|| "amount seed overflowed".to_owned())?;
        let timestamp = VALID_STRUCTURAL_TIMESTAMP
            .checked_add(seed)
            .ok_or_else(|| "timestamp seed overflowed".to_owned())?;

        let tx = Transaction {
            sender: wallet_array(&wallet_from_seed(seed))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(999)))?,
            amount,
            timestamp,
        };

        let id = map_err_debug(tx.id(), "generated fixed tx id should compute")?;

        require_equal(&id.len(), &64_usize, "generated id should be 64 hex chars")?;
        require(
            lower_hex_string(&id),
            "generated id should use lowercase hex chars only",
        )?;
    }

    Ok(())
}

#[test]
fn transaction_100_vector_serialized_size_reflects_postcard_varint_encoding() -> TestResult {
    let small = fixed_tx(1, VALID_STRUCTURAL_TIMESTAMP)?;
    let large = fixed_tx(u64::MAX, VALID_STRUCTURAL_TIMESTAMP)?;
    let same_width_different_wallets = Transaction {
        sender: wallet_array(&wallet_from_seed(1))?,
        receiver: wallet_array(&wallet_from_seed(2))?,
        amount: 1,
        timestamp: VALID_STRUCTURAL_TIMESTAMP,
    };

    let small_bytes = map_err_debug(small.serialize(), "small tx should serialize")?;
    let large_bytes = map_err_debug(large.serialize(), "large tx should serialize")?;
    let different_wallet_bytes = map_err_debug(
        same_width_different_wallets.serialize(),
        "same numeric width different-wallet tx should serialize",
    )?;

    require(
        large_bytes.len() > small_bytes.len(),
        "postcard varint encoding should make u64::MAX transaction larger than small u64 transaction",
    )?;
    require_equal(
        &small_bytes.len(),
        &different_wallet_bytes.len(),
        "wallet contents should not change serialized size when wallet byte lengths and numeric widths match",
    )?;

    let decoded_small = map_err_debug(
        Transaction::deserialize(&small_bytes),
        "small tx should deserialize",
    )?;
    let decoded_large = map_err_debug(
        Transaction::deserialize(&large_bytes),
        "large tx should deserialize",
    )?;

    require_equal(&decoded_small, &small, "small tx should roundtrip")?;
    require_equal(&decoded_large, &large, "large tx should roundtrip")?;

    Ok(())
}
