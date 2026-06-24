// tests/genesis_001_block_tests.rs

use fips204::ml_dsa_65;
use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::decode_hex_to_64;
use std::error::Error as StdError;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn StdError>>;

fn fail(message: impl Into<String>) -> Box<dyn StdError> {
    std::io::Error::other(message.into()).into()
}

fn set_json_string(value: &mut serde_json::Value, field: &str, replacement: String) -> TestResult {
    json_object_mut(value)?.insert(String::from(field), serde_json::Value::String(replacement));
    Ok(())
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(fail(message))
    }
}

fn ensure_eq<T>(left: &T, right: &T, message: &str) -> TestResult
where
    T: PartialEq + std::fmt::Debug,
{
    if left == right {
        Ok(())
    } else {
        Err(fail(format!("{message}: left={left:?}, right={right:?}")))
    }
}

fn ensure_ne<T>(left: &T, right: &T, message: &str) -> TestResult
where
    T: PartialEq + std::fmt::Debug,
{
    if left != right {
        Ok(())
    } else {
        Err(fail(format!("{message}: both={left:?}")))
    }
}

fn require_validation_error<T>(result: Result<T, ErrorDetection>, needle: &str) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => ensure(
            message.contains(needle),
            format!("ValidationError did not contain `{needle}`: {message}"),
        ),
        Err(other) => Err(fail(format!(
            "expected ValidationError containing `{needle}`, got {other:?}"
        ))),
        Ok(_) => Err(fail(format!(
            "expected ValidationError containing `{needle}`, got Ok"
        ))),
    }
}

fn require_validation_error_any<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { .. }) => Ok(()),
        Err(other) => Err(fail(format!("expected ValidationError, got {other:?}"))),
        Ok(_) => Err(fail("expected ValidationError, got Ok")),
    }
}

fn require_serialization_error<T>(result: Result<T, ErrorDetection>, needle: &str) -> TestResult {
    match result {
        Err(ErrorDetection::SerializationError { details }) => ensure(
            details.contains(needle),
            format!("SerializationError did not contain `{needle}`: {details}"),
        ),
        Err(other) => Err(fail(format!(
            "expected SerializationError containing `{needle}`, got {other:?}"
        ))),
        Ok(_) => Err(fail(format!(
            "expected SerializationError containing `{needle}`, got Ok"
        ))),
    }
}

fn canonical_wallet() -> String {
    let mut wallet = String::from("r");
    for _ in 0..128 {
        wallet.push('1');
    }
    wallet
}

fn alternate_wallet() -> String {
    let mut wallet = String::from("r");
    for _ in 0..128 {
        wallet.push('2');
    }
    wallet
}

fn uppercase_wallet() -> String {
    let mut wallet = String::from("R");
    for _ in 0..128 {
        wallet.push('A');
    }
    wallet
}

fn genesis_at(timestamp: u64) -> Result<GenesisBlock, ErrorDetection> {
    GenesisBlock::new_with_timestamp("Remzar genesis test vector", timestamp)
}

fn min_timestamp() -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS
}

fn is_lowercase_hex(s: &str) -> bool {
    s.chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'))
}

fn json_object_mut(
    value: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, Box<dyn StdError>> {
    match value.as_object_mut() {
        Some(object) => Ok(object),
        None => Err(fail("expected JSON object")),
    }
}

fn json_string_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, Box<dyn StdError>> {
    match value.get(field).and_then(serde_json::Value::as_str) {
        Some(s) => Ok(s),
        None => Err(fail(format!("missing JSON string field `{field}`"))),
    }
}

fn temp_json_path(suffix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "remzar_genesis_001_block_tests_{}_{}.json",
        std::process::id(),
        suffix
    ));
    path
}

fn remove_file_if_exists(path: &Path) -> TestResult {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn manual_genesis_hash() -> Result<[u8; 64], Box<dyn StdError>> {
    let prev_hash = decode_hex_to_64(GlobalConfiguration::GENESIS_PREV_HASH_HEX)?;
    let merkle_root = decode_hex_to_64(GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX)?;
    let guardian_signature = [0_u8; ml_dsa_65::SIG_LEN];
    let reward = 0_u64;
    let dummy_hex = RemzarHash::compute_dummy_hash();

    let mut dummy_bytes = [0_u8; 64];
    hex::decode_to_slice(dummy_hex, &mut dummy_bytes)?;

    let mut preimage = Vec::with_capacity(64 + 64 + ml_dsa_65::SIG_LEN + 8 + 64);
    preimage.extend_from_slice(&prev_hash);
    preimage.extend_from_slice(&merkle_root);
    preimage.extend_from_slice(&guardian_signature);
    preimage.extend_from_slice(&reward.to_be_bytes());
    preimage.extend_from_slice(&dummy_bytes);

    Ok(RemzarHash::compute_bytes_hash(&preimage))
}

#[test]
fn genesis_001_block_01_new_with_timestamp_preserves_data_and_timestamp() -> TestResult {
    let data = "Remzar genesis test vector";
    let timestamp = min_timestamp();

    let genesis = GenesisBlock::new_with_timestamp(data, timestamp)?;

    ensure_eq(&genesis.data, &data.to_string(), "data should be preserved")?;
    ensure_eq(
        &genesis.timestamp,
        &timestamp,
        "timestamp should be preserved",
    )?;
    ensure(
        genesis.founder_wallet().is_none(),
        "new_with_timestamp should not set founder_wallet",
    )?;
    genesis.validate()?;
    Ok(())
}

#[test]
fn genesis_001_block_02_new_uses_current_utc_timestamp_and_validates() -> TestResult {
    let genesis = GenesisBlock::new("Remzar live genesis constructor")?;

    ensure(
        genesis.timestamp >= GlobalConfiguration::MIN_TIMESTAMP_SECS,
        "GenesisBlock::new timestamp should be above configured minimum",
    )?;
    genesis.validate()?;
    Ok(())
}

#[test]
fn genesis_001_block_03_new_with_timestamp_rejects_empty_data() -> TestResult {
    require_validation_error(
        GenesisBlock::new_with_timestamp("", min_timestamp()),
        "Genesis block data cannot be empty",
    )
}

#[test]
fn genesis_001_block_04_new_with_timestamp_rejects_whitespace_only_data() -> TestResult {
    require_validation_error(
        GenesisBlock::new_with_timestamp(" \n\t ", min_timestamp()),
        "Genesis block data cannot be empty",
    )
}

#[test]
fn genesis_001_block_05_new_with_timestamp_accepts_exactly_1024_bytes_data() -> TestResult {
    let data = "x".repeat(1024);

    let genesis = GenesisBlock::new_with_timestamp(&data, min_timestamp())?;

    ensure_eq(
        &genesis.data.len(),
        &1024_usize,
        "1024-byte data should pass",
    )?;
    genesis.validate()?;
    Ok(())
}

#[test]
fn genesis_001_block_06_new_with_timestamp_rejects_1025_bytes_data() -> TestResult {
    let data = "x".repeat(1025);

    require_validation_error(
        GenesisBlock::new_with_timestamp(&data, min_timestamp()),
        "Genesis block data too large",
    )
}

#[test]
fn genesis_001_block_07_new_with_timestamp_rejects_timestamp_below_minimum() -> TestResult {
    let ts = GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1);

    let result = GenesisBlock::new_with_timestamp("remzar genesis", ts);

    require_validation_error(result, "timestamp below UNIX_2000_SECS")
}

#[test]
fn genesis_001_block_08_new_with_timestamp_accepts_minimum_timestamp() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp(
        "Remzar exact minimum timestamp",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
    )?;

    ensure_eq(
        &genesis.timestamp,
        &GlobalConfiguration::MIN_TIMESTAMP_SECS,
        "minimum timestamp should be accepted",
    )?;
    genesis.validate()?;
    Ok(())
}

#[test]
fn genesis_001_block_09_new_with_timestamp_and_miner_stores_founder_wallet() -> TestResult {
    let wallet = canonical_wallet();

    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder wallet vector",
        min_timestamp(),
        &wallet,
    )?;

    ensure_eq(
        &genesis.founder_wallet(),
        &Some(wallet.as_str()),
        "founder_wallet accessor should return configured wallet",
    )?;
    ensure_eq(
        &genesis.miner_for_genesis_block(),
        &wallet,
        "miner_for_genesis_block should return founder wallet",
    )
}

#[test]
fn genesis_001_block_10_empty_miner_keeps_founder_wallet_none_and_miner_empty() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar no founder wallet",
        min_timestamp(),
        "",
    )?;

    ensure(
        genesis.founder_wallet().is_none(),
        "empty miner should leave founder_wallet None",
    )?;
    ensure_eq(
        &genesis.miner_for_genesis_block(),
        &String::new(),
        "miner_for_genesis_block should be empty without founder wallet",
    )
}

#[test]
fn genesis_001_block_11_whitespace_miner_keeps_founder_wallet_none() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar whitespace founder wallet",
        min_timestamp(),
        "   \n\t  ",
    )?;

    ensure(
        genesis.founder_wallet().is_none(),
        "whitespace miner should be treated as no founder wallet",
    )
}

#[test]
fn genesis_001_block_12_padded_lowercase_miner_is_trimmed_and_stored_canonical() -> TestResult {
    let wallet = canonical_wallet();
    let padded = format!("  {wallet}\n");

    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar padded founder wallet",
        min_timestamp(),
        &padded,
    )?;

    ensure_eq(
        &genesis.founder_wallet(),
        &Some(wallet.as_str()),
        "padded canonical wallet should be trimmed and stored",
    )
}

#[test]
fn genesis_001_block_13_uppercase_miner_is_rejected_by_strict_parse_wallet_address() -> TestResult {
    require_validation_error_any(GenesisBlock::new_with_timestamp_and_miner(
        "Remzar uppercase founder wallet rejection",
        min_timestamp(),
        &uppercase_wallet(),
    ))
}

#[test]
fn genesis_001_block_14_invalid_miner_is_rejected() -> TestResult {
    require_validation_error_any(GenesisBlock::new_with_timestamp_and_miner(
        "Remzar invalid founder wallet rejection",
        min_timestamp(),
        "not-a-remzar-wallet",
    ))
}

#[test]
fn genesis_001_block_15_genesis_hash_hex_is_128_lowercase_hex() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let hash_hex = genesis.genesis_hash_hex();

    ensure_eq(&hash_hex.len(), &128_usize, "genesis hash hex length")?;
    ensure(
        is_lowercase_hex(&hash_hex),
        "genesis hash must be lowercase hex",
    )
}

#[test]
fn genesis_001_block_16_constructed_hash_matches_manual_preimage_vector() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let expected = manual_genesis_hash()?;

    ensure_eq(
        &genesis.genesis_hash,
        &expected,
        "genesis_hash should match documented deterministic preimage",
    )
}

#[test]
fn genesis_001_block_17_genesis_hash_is_independent_of_timestamp() -> TestResult {
    let first = GenesisBlock::new_with_timestamp("Remzar timestamp A", min_timestamp())?;
    let second = GenesisBlock::new_with_timestamp(
        "Remzar timestamp A",
        min_timestamp().saturating_add(10_000),
    )?;

    ensure_eq(
        &first.genesis_hash,
        &second.genesis_hash,
        "timestamp is not part of genesis hash preimage",
    )
}

#[test]
fn genesis_001_block_18_genesis_hash_is_independent_of_data() -> TestResult {
    let first = GenesisBlock::new_with_timestamp("Remzar data A", min_timestamp())?;
    let second = GenesisBlock::new_with_timestamp("Remzar data B", min_timestamp())?;

    ensure_eq(
        &first.genesis_hash,
        &second.genesis_hash,
        "data is not part of genesis hash preimage",
    )
}

#[test]
fn genesis_001_block_19_genesis_hash_is_independent_of_founder_wallet() -> TestResult {
    let without_founder = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder independence",
        min_timestamp(),
        "",
    )?;
    let with_founder = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder independence",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    ensure_eq(
        &without_founder.genesis_hash,
        &with_founder.genesis_hash,
        "founder_wallet is config only and not part of genesis hash",
    )?;
    ensure_ne(
        &without_founder.founder_wallet(),
        &with_founder.founder_wallet(),
        "test setup should have different founder_wallet state",
    )
}

#[test]
fn genesis_001_block_20_prev_hash_matches_global_configuration() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let expected = decode_hex_to_64(GlobalConfiguration::GENESIS_PREV_HASH_HEX)?;

    ensure_eq(
        &genesis.prev_hash,
        &expected,
        "prev_hash should decode from GENESIS_PREV_HASH_HEX",
    )
}

#[test]
fn genesis_001_block_21_merkle_root_matches_global_configuration() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let expected = decode_hex_to_64(GlobalConfiguration::GENESIS_MERKLE_ROOT_HEX)?;

    ensure_eq(
        &genesis.merkle_root,
        &expected,
        "merkle_root should decode from GENESIS_MERKLE_ROOT_HEX",
    )
}

#[test]
fn genesis_001_block_22_validate_accepts_fresh_genesis() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;

    genesis.validate()?;
    Ok(())
}

#[test]
fn genesis_001_block_23_validate_rejects_zero_genesis_hash() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.genesis_hash = [0_u8; 64];

    require_validation_error(genesis.validate(), "Genesis hash is all zeros")
}

#[test]
fn genesis_001_block_24_validate_rejects_zero_merkle_root() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.merkle_root = [0_u8; 64];

    require_validation_error(genesis.validate(), "Merkle root is all zeros")
}

#[test]
fn genesis_001_block_25_validate_rejects_empty_data_after_manual_mutation() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.data.clear();

    require_validation_error(genesis.validate(), "Genesis block data is empty")
}

#[test]
fn genesis_001_block_26_validate_rejects_whitespace_data_after_manual_mutation() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.data = String::from("   \n\t  ");

    require_validation_error(genesis.validate(), "Genesis block data is empty")
}

#[test]
fn genesis_001_block_27_validate_rejects_oversized_data_after_manual_mutation() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.data = "x".repeat(1025);

    require_validation_error(genesis.validate(), "Genesis block data too large")
}

#[test]
fn genesis_001_block_28_validate_rejects_invalid_founder_wallet_after_manual_mutation() -> TestResult
{
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.founder_wallet = Some(String::from("bad-wallet"));

    require_validation_error_any(genesis.validate())
}

#[test]
fn genesis_001_block_29_validate_rejects_uppercase_founder_wallet_after_manual_mutation()
-> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.founder_wallet = Some(uppercase_wallet());

    require_validation_error_any(genesis.validate())
}

#[test]
fn genesis_001_block_30_validate_rejects_equal_hash_fields() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.prev_hash = genesis.merkle_root;

    require_validation_error(genesis.validate(), "Genesis hash fields must all be unique")
}

#[test]
fn genesis_001_block_31_validate_rejects_recomputed_hash_mismatch() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    for byte in genesis.genesis_hash.iter_mut().take(1) {
        *byte = byte.wrapping_add(1);
    }

    require_validation_error(genesis.validate(), "genesis_hash mismatch")
}

#[test]
fn genesis_001_block_32_validate_against_now_accepts_boundary_future_drift() -> TestResult {
    let now = min_timestamp();
    let timestamp = now.saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS);
    let genesis = GenesisBlock::new_with_timestamp("Remzar future boundary", timestamp)?;

    genesis.validate_against_now(now)?;
    Ok(())
}

#[test]
fn genesis_001_block_33_validate_against_now_rejects_too_far_future() -> TestResult {
    let now = min_timestamp();
    let timestamp = now
        .saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS)
        .saturating_add(1);
    let genesis = GenesisBlock::new_with_timestamp("Remzar future rejection", timestamp)?;

    require_validation_error(
        genesis.validate_against_now(now),
        "timestamp too far in future",
    )
}

#[test]
fn genesis_001_block_34_serialize_deserialize_roundtrip() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar postcard roundtrip",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let bytes = genesis.serialize()?;
    let decoded = GenesisBlock::deserialize(&bytes)?;

    ensure_eq(
        &decoded,
        &genesis,
        "postcard serialize/deserialize should preserve genesis block",
    )
}

#[test]
fn genesis_001_block_35_deserialize_rejects_nonzero_trailing_bytes_that_decode_as_invalid_data()
-> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut bytes = genesis.serialize()?;
    bytes.extend_from_slice(&[1_u8, 2_u8, 3_u8, 4_u8]);

    require_serialization_error(GenesisBlock::deserialize(&bytes), "trailing non-zero bytes")
}

#[test]
fn genesis_001_block_36_deserialize_rejects_empty_payload() -> TestResult {
    require_serialization_error(GenesisBlock::deserialize(&[]), "")
}

#[test]
fn genesis_001_block_37_pad_to_max_size_returns_exact_max_block_size() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let padded = genesis.pad_to_max_size()?;
    let max_block_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|_| fail("MAX_BLOCK_SIZE should fit usize"))?;

    ensure_eq(
        &padded.len(),
        &max_block_size,
        "pad_to_max_size should return exactly MAX_BLOCK_SIZE bytes",
    )
}

#[test]
fn genesis_001_block_38_serialize_for_storage_matches_unpadded_serialize() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;

    let serialized = genesis.serialize()?;
    let storage = genesis.serialize_for_storage()?;

    ensure_eq(
        &storage,
        &serialized,
        "serialize_for_storage should return unpadded postcard bytes",
    )
}

#[test]
fn genesis_001_block_39_to_json_uses_128_char_hash_strings_and_omits_none_founder() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let json = genesis.to_json()?;
    let value: serde_json::Value = serde_json::from_str(&json)?;

    let genesis_hash = json_string_field(&value, "genesis_hash")?;
    let merkle_root = json_string_field(&value, "merkle_root")?;
    let prev_hash = json_string_field(&value, "prev_hash")?;

    ensure_eq(&genesis_hash.len(), &128_usize, "genesis_hash JSON length")?;
    ensure_eq(&merkle_root.len(), &128_usize, "merkle_root JSON length")?;
    ensure_eq(&prev_hash.len(), &128_usize, "prev_hash JSON length")?;
    ensure(
        is_lowercase_hex(genesis_hash),
        "genesis_hash JSON should be lowercase hex",
    )?;
    ensure(
        is_lowercase_hex(merkle_root),
        "merkle_root JSON should be lowercase hex",
    )?;
    ensure(
        is_lowercase_hex(prev_hash),
        "prev_hash JSON should be lowercase hex",
    )?;
    ensure(
        value.get("founder_wallet").is_none(),
        "founder_wallet should be omitted when None",
    )
}

#[test]
fn genesis_001_block_40_json_and_file_roundtrip_with_founder_wallet() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar JSON file roundtrip",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let json = genesis.to_json()?;
    let decoded = GenesisBlock::from_json(&json)?;
    ensure_eq(
        &decoded,
        &genesis,
        "from_json should preserve genesis block",
    )?;

    let path = temp_json_path("roundtrip");
    remove_file_if_exists(&path)?;
    let path_string = path.to_string_lossy().into_owned();

    genesis.to_json_file(&path_string)?;
    let file_decoded = GenesisBlock::from_json_file(&path_string)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &file_decoded,
        &genesis,
        "from_json_file should preserve genesis block",
    )
}

#[test]
fn genesis_001_block_41_to_json_includes_founder_wallet_when_present() -> TestResult {
    let wallet = canonical_wallet();
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder JSON inclusion",
        min_timestamp(),
        &wallet,
    )?;

    let json = genesis.to_json()?;
    let value: serde_json::Value = serde_json::from_str(&json)?;

    let founder_wallet = json_string_field(&value, "founder_wallet")?;

    ensure_eq(
        &founder_wallet,
        &wallet.as_str(),
        "to_json should include founder_wallet when present",
    )
}

#[test]
fn genesis_001_block_42_from_json_accepts_unknown_fields_current_behavior() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let json = genesis.to_json()?;
    let mut value: serde_json::Value = serde_json::from_str(&json)?;

    json_object_mut(&mut value)?.insert(
        String::from("extra_ignored_field"),
        serde_json::Value::String(String::from("ignored by serde")),
    );

    let raw = serde_json::to_string(&value)?;
    let decoded = GenesisBlock::from_json(&raw)?;

    ensure_eq(
        &decoded,
        &genesis,
        "GenesisBlock has no deny_unknown_fields, so unknown JSON fields are ignored",
    )
}

#[test]
fn genesis_001_block_43_from_json_rejects_short_genesis_hash_hex() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "genesis_hash", String::from("abcd"))?;

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "expected 128 hex chars",
    )
}

#[test]
fn genesis_001_block_44_from_json_rejects_invalid_genesis_hash_hex() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "genesis_hash", "z".repeat(128))?;

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "invalid hex",
    )
}

#[test]
fn genesis_001_block_45_from_json_rejects_short_merkle_root_hex() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "merkle_root", String::from("abcd"))?;

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "expected 128 hex chars",
    )
}

#[test]
fn genesis_001_block_46_from_json_rejects_invalid_prev_hash_hex() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "prev_hash", "g".repeat(128))?;

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "invalid hex",
    )
}

#[test]
fn genesis_001_block_47_from_json_rejects_zero_genesis_hash_after_decode() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "genesis_hash", "00".repeat(64))?;

    require_validation_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "Genesis hash is all zeros",
    )
}

#[test]
fn genesis_001_block_48_from_json_rejects_zero_merkle_root_after_decode() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "merkle_root", "00".repeat(64))?;

    require_validation_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "Merkle root is all zeros",
    )
}

#[test]
fn genesis_001_block_49_from_json_rejects_equal_prev_hash_and_merkle_root() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;
    let merkle_root = json_string_field(&value, "merkle_root")?.to_string();

    set_json_string(&mut value, "prev_hash", merkle_root)?;

    require_validation_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "Genesis hash fields must all be unique",
    )
}

#[test]
fn genesis_001_block_50_from_json_rejects_recomputed_genesis_hash_mismatch() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "genesis_hash", "01".repeat(64))?;

    require_validation_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "genesis_hash mismatch",
    )
}

#[test]
fn genesis_001_block_51_from_json_rejects_timestamp_below_minimum() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp(
        "remzar genesis",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
    )?;

    let json = genesis.to_json()?;
    let mut value: serde_json::Value = serde_json::from_str(&json)?;

    value["timestamp"] = serde_json::Value::Number(serde_json::Number::from(
        GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1),
    ));

    let mutated_json = serde_json::to_string(&value)?;
    let result = GenesisBlock::from_json(&mutated_json);

    require_validation_error(result, "timestamp below UNIX_2000_SECS")
}

#[test]
fn genesis_001_block_52_from_json_rejects_empty_data() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "data", String::new())?;

    require_validation_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "Genesis block data is empty",
    )
}

#[test]
fn genesis_001_block_53_from_json_rejects_invalid_founder_wallet() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(
        &mut value,
        "founder_wallet",
        String::from("not-a-valid-wallet"),
    )?;

    require_validation_error_any(GenesisBlock::from_json(&serde_json::to_string(&value)?))
}

#[test]
fn genesis_001_block_54_from_json_defaults_missing_founder_wallet_to_none() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar missing founder default",
        min_timestamp(),
        &canonical_wallet(),
    )?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    json_object_mut(&mut value)?.remove("founder_wallet");

    let decoded = GenesisBlock::from_json(&serde_json::to_string(&value)?)?;

    ensure(
        decoded.founder_wallet().is_none(),
        "missing founder_wallet should default to None",
    )
}

#[test]
fn genesis_001_block_55_from_json_rejects_missing_genesis_hash() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    json_object_mut(&mut value)?.remove("genesis_hash");

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "missing field",
    )
}

#[test]
fn genesis_001_block_56_from_json_rejects_missing_merkle_root() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    json_object_mut(&mut value)?.remove("merkle_root");

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "missing field",
    )
}

#[test]
fn genesis_001_block_57_from_json_rejects_missing_prev_hash() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    json_object_mut(&mut value)?.remove("prev_hash");

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "missing field",
    )
}

#[test]
fn genesis_001_block_58_from_json_rejects_missing_timestamp() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    json_object_mut(&mut value)?.remove("timestamp");

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "missing field",
    )
}

#[test]
fn genesis_001_block_59_from_json_rejects_missing_data() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    json_object_mut(&mut value)?.remove("data");

    require_serialization_error(
        GenesisBlock::from_json(&serde_json::to_string(&value)?),
        "missing field",
    )
}

#[test]
fn genesis_001_block_60_serialize_for_storage_roundtrips_with_founder_wallet() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder storage roundtrip",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let bytes = genesis.serialize_for_storage()?;
    let decoded = GenesisBlock::deserialize(&bytes)?;

    ensure_eq(
        &decoded,
        &genesis,
        "serialize_for_storage bytes should deserialize back to same genesis block",
    )
}

#[test]
fn genesis_001_block_61_padded_max_size_payload_deserializes_to_original() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;

    let padded = genesis.pad_to_max_size()?;
    let decoded = GenesisBlock::deserialize(&padded)?;

    ensure_eq(
        &decoded,
        &genesis,
        "pad_to_max_size payload should deserialize back to original genesis block",
    )
}

#[test]
fn genesis_001_block_62_padded_payload_starts_with_unpadded_serialized_bytes() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;

    let serialized = genesis.serialize()?;
    let padded = genesis.pad_to_max_size()?;
    let prefix = padded
        .get(..serialized.len())
        .ok_or_else(|| fail("padded payload should contain serialized prefix"))?;

    ensure(
        prefix == serialized.as_slice(),
        "padded payload should begin with canonical serialized bytes",
    )
}

#[test]
fn genesis_001_block_63_from_json_file_rejects_missing_file() -> TestResult {
    let path = temp_json_path("missing_file");
    remove_file_if_exists(&path)?;
    let path_string = path.to_string_lossy().into_owned();

    require_serialization_error(GenesisBlock::from_json_file(&path_string), "")
}

#[test]
fn genesis_001_block_64_from_json_file_rejects_oversized_file_before_json_parse() -> TestResult {
    let path = temp_json_path("oversized_file");
    remove_file_if_exists(&path)?;

    let max_len = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|_| fail("MAX_BLOCK_SIZE should fit usize"))?;
    fs::write(&path, vec![b'x'; max_len.saturating_add(1)])?;

    let path_string = path.to_string_lossy().into_owned();
    let result = GenesisBlock::from_json_file(&path_string);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "Genesis JSON file too large")
}

#[test]
fn genesis_001_block_65_from_json_file_rejects_invalid_json_contents() -> TestResult {
    let path = temp_json_path("invalid_json");
    remove_file_if_exists(&path)?;
    fs::write(&path, b"{ not valid json")?;

    let path_string = path.to_string_lossy().into_owned();
    let result = GenesisBlock::from_json_file(&path_string);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_001_block_66_to_json_file_overwrites_existing_file_with_valid_json() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let path = temp_json_path("overwrite");
    remove_file_if_exists(&path)?;
    fs::write(&path, b"old contents")?;
    let path_string = path.to_string_lossy().into_owned();

    genesis.to_json_file(&path_string)?;
    let decoded = GenesisBlock::from_json_file(&path_string)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &decoded,
        &genesis,
        "to_json_file should overwrite existing path with valid genesis JSON",
    )
}

#[test]
fn genesis_001_block_67_validate_against_now_accepts_equal_now() -> TestResult {
    let now = min_timestamp();
    let genesis = GenesisBlock::new_with_timestamp("Remzar now equality", now)?;

    genesis.validate_against_now(now)?;
    Ok(())
}

#[test]
fn genesis_001_block_68_validate_against_now_rejects_u64_max_structural_timestamp() -> TestResult {
    let mut genesis = GenesisBlock::new_with_timestamp(
        "remzar genesis",
        GlobalConfiguration::MIN_TIMESTAMP_SECS,
    )?;

    genesis.timestamp = u64::MAX;

    let result = genesis.validate_against_now(u64::MAX);

    require_validation_error(result, "timestamp above UNIX_9999_SECS")
}

#[test]
fn genesis_001_block_69_validate_against_now_accepts_past_timestamp() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let now = min_timestamp()
        .saturating_add(GlobalConfiguration::MAX_FUTURE_DRIFT_SECS)
        .saturating_add(1_000);

    genesis.validate_against_now(now)?;
    Ok(())
}

#[test]
fn genesis_001_block_70_clone_preserves_equality_and_hash_hex() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let cloned = genesis.clone();

    ensure_eq(
        &cloned,
        &genesis,
        "clone should preserve full genesis block",
    )?;
    ensure_eq(
        &cloned.genesis_hash_hex(),
        &genesis.genesis_hash_hex(),
        "clone should preserve genesis_hash_hex",
    )
}

#[test]
fn genesis_001_block_71_partial_eq_detects_data_difference_even_when_hash_same() -> TestResult {
    let first = GenesisBlock::new_with_timestamp("Remzar data one", min_timestamp())?;
    let second = GenesisBlock::new_with_timestamp("Remzar data two", min_timestamp())?;

    ensure_eq(
        &first.genesis_hash,
        &second.genesis_hash,
        "test setup should keep same consensus hash",
    )?;
    ensure_ne(
        &first,
        &second,
        "PartialEq should still detect data field difference",
    )
}

#[test]
fn genesis_001_block_72_partial_eq_detects_founder_wallet_difference_even_when_hash_same()
-> TestResult {
    let first = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder eq test",
        min_timestamp(),
        &canonical_wallet(),
    )?;
    let second = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder eq test",
        min_timestamp(),
        &alternate_wallet(),
    )?;

    ensure_eq(
        &first.genesis_hash,
        &second.genesis_hash,
        "founder wallet should not affect consensus hash",
    )?;
    ensure_ne(
        &first,
        &second,
        "PartialEq should detect founder_wallet field difference",
    )
}

#[test]
fn genesis_001_block_73_debug_output_mentions_struct_and_data() -> TestResult {
    let data = "Remzar debug vector";
    let genesis = GenesisBlock::new_with_timestamp(data, min_timestamp())?;
    let debug = format!("{genesis:?}");

    ensure(
        debug.contains("GenesisBlock"),
        "Debug output should contain struct name",
    )?;
    ensure(
        debug.contains(data),
        "Debug output should contain data field",
    )
}

#[test]
fn genesis_001_block_74_genesis_hash_matches_global_configuration_hex() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;

    ensure_eq(
        &genesis.genesis_hash_hex(),
        &GlobalConfiguration::GENESIS_HASH_HEX.to_string(),
        "computed genesis hash should match configured GENESIS_HASH_HEX",
    )
}

#[test]
fn genesis_001_block_75_serialize_is_deterministic() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar deterministic serialize",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let first = genesis.serialize()?;
    let second = genesis.serialize()?;

    ensure_eq(
        &first,
        &second,
        "serialize should be deterministic for the same genesis block",
    )
}

#[test]
fn genesis_001_block_76_to_json_is_deterministic() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar deterministic JSON",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let first = genesis.to_json()?;
    let second = genesis.to_json()?;

    ensure_eq(
        &first,
        &second,
        "to_json should be deterministic for the same genesis block",
    )
}

#[test]
fn genesis_001_block_77_many_timestamps_keep_same_consensus_hash() -> TestResult {
    let baseline = genesis_at(min_timestamp())?.genesis_hash;

    for offset in 0_u64..128_u64 {
        let genesis = GenesisBlock::new_with_timestamp(
            "Remzar timestamp property",
            min_timestamp().saturating_add(offset),
        )?;

        ensure_eq(
            &genesis.genesis_hash,
            &baseline,
            "timestamp variants should keep same genesis consensus hash",
        )?;
        genesis.validate()?;
    }

    Ok(())
}

#[test]
fn genesis_001_block_78_many_data_values_keep_same_hash_but_unique_json() -> TestResult {
    let baseline = genesis_at(min_timestamp())?.genesis_hash;
    let mut json_values = std::collections::BTreeSet::new();

    for index in 0_u64..128_u64 {
        let data = format!("Remzar data vector {index}");
        let genesis = GenesisBlock::new_with_timestamp(&data, min_timestamp())?;

        ensure_eq(
            &genesis.genesis_hash,
            &baseline,
            "data variants should keep same genesis consensus hash",
        )?;
        ensure(
            json_values.insert(genesis.to_json()?),
            "different data values should produce unique JSON payloads",
        )?;
    }

    ensure_eq(
        &json_values.len(),
        &128_usize,
        "should collect 128 unique JSON payloads",
    )
}

#[test]
fn genesis_001_block_79_many_valid_founder_wallet_states_validate() -> TestResult {
    let wallets = vec![canonical_wallet(), alternate_wallet()];

    for wallet in wallets {
        let genesis = GenesisBlock::new_with_timestamp_and_miner(
            "Remzar founder wallet vector set",
            min_timestamp(),
            &wallet,
        )?;

        ensure_eq(
            &genesis.founder_wallet(),
            &Some(wallet.as_str()),
            "founder wallet should be stored exactly for valid lowercase wallets",
        )?;
        genesis.validate()?;
    }

    let no_wallet = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder wallet vector set",
        min_timestamp(),
        "",
    )?;

    ensure(
        no_wallet.founder_wallet().is_none(),
        "empty founder wallet state should validate as None",
    )?;
    no_wallet.validate()?;
    Ok(())
}

#[test]
fn genesis_001_block_80_adversarial_load_valid_roundtrip_and_invalid_mutations() -> TestResult {
    let founder_wallet = canonical_wallet();
    let baseline = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar adversarial genesis baseline",
        min_timestamp(),
        &founder_wallet,
    )?
    .genesis_hash;

    let mut serialized_values = std::collections::BTreeSet::new();

    for index in 0_u64..64_u64 {
        let data = format!("Remzar adversarial genesis vector {index}");
        let genesis = GenesisBlock::new_with_timestamp_and_miner(
            &data,
            min_timestamp().saturating_add(index),
            &founder_wallet,
        )?;

        ensure_eq(
            &genesis.genesis_hash,
            &baseline,
            "valid adversarial-load variants should share the same consensus hash",
        )?;

        let bytes = genesis.serialize()?;
        ensure(
            serialized_values.insert(bytes.clone()),
            "different data/timestamp variants should produce unique serialized payloads",
        )?;

        let decoded = GenesisBlock::deserialize(&bytes)?;
        ensure_eq(
            &decoded,
            &genesis,
            "valid adversarial-load payload with founder_wallet should deserialize exactly",
        )?;

        let mut zero_hash = genesis.clone();
        zero_hash.genesis_hash = [0_u8; 64];
        require_validation_error(zero_hash.validate(), "Genesis hash is all zeros")?;

        let mut empty_data = genesis.clone();
        empty_data.data.clear();
        require_validation_error(empty_data.validate(), "Genesis block data is empty")?;
    }

    ensure_eq(
        &serialized_values.len(),
        &64_usize,
        "adversarial load should collect 64 unique serialized genesis payloads",
    )
}

#[test]
fn genesis_001_block_81_from_json_accepts_uppercase_hash_hex_strings() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    let genesis_hash = json_string_field(&value, "genesis_hash")?.to_ascii_uppercase();
    let merkle_root = json_string_field(&value, "merkle_root")?.to_ascii_uppercase();
    let prev_hash = json_string_field(&value, "prev_hash")?.to_ascii_uppercase();

    set_json_string(&mut value, "genesis_hash", genesis_hash)?;
    set_json_string(&mut value, "merkle_root", merkle_root)?;
    set_json_string(&mut value, "prev_hash", prev_hash)?;

    let decoded = GenesisBlock::from_json(&serde_json::to_string(&value)?)?;

    ensure_eq(
        &decoded,
        &genesis,
        "hash hex deserializer should accept uppercase hex strings that decode to the same bytes",
    )
}

#[test]
fn genesis_001_block_82_from_json_trims_hash_hex_strings() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    let genesis_hash = format!("  {}\n", json_string_field(&value, "genesis_hash")?);
    let merkle_root = format!("\t{}  ", json_string_field(&value, "merkle_root")?);
    let prev_hash = format!("\n{}\t", json_string_field(&value, "prev_hash")?);

    set_json_string(&mut value, "genesis_hash", genesis_hash)?;
    set_json_string(&mut value, "merkle_root", merkle_root)?;
    set_json_string(&mut value, "prev_hash", prev_hash)?;

    let decoded = GenesisBlock::from_json(&serde_json::to_string(&value)?)?;

    ensure_eq(
        &decoded,
        &genesis,
        "hash hex deserializer should trim surrounding whitespace",
    )
}

#[test]
fn genesis_001_block_83_from_json_null_founder_wallet_decodes_as_none() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar null founder wallet JSON",
        min_timestamp(),
        &canonical_wallet(),
    )?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    json_object_mut(&mut value)?.insert(String::from("founder_wallet"), serde_json::Value::Null);

    let decoded = GenesisBlock::from_json(&serde_json::to_string(&value)?)?;

    ensure(
        decoded.founder_wallet().is_none(),
        "JSON null founder_wallet should decode as None",
    )
}

#[test]
fn genesis_001_block_84_from_json_rejects_empty_founder_wallet_string() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    set_json_string(&mut value, "founder_wallet", String::new())?;

    require_validation_error_any(GenesisBlock::from_json(&serde_json::to_string(&value)?))
}

#[test]
fn genesis_001_block_85_to_json_hash_strings_have_no_0x_prefix() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

    for field in ["genesis_hash", "merkle_root", "prev_hash"] {
        let s = json_string_field(&value, field)?;
        ensure(
            !s.starts_with("0x"),
            format!("{field} should be plain hex without 0x prefix"),
        )?;
        ensure_eq(&s.len(), &128_usize, "hash JSON field should be 128 chars")?;
    }

    Ok(())
}

#[test]
fn genesis_001_block_86_serialize_length_is_below_max_block_size() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar serialize length bound",
        min_timestamp(),
        &canonical_wallet(),
    )?;
    let bytes = genesis.serialize()?;
    let max_block_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|_| fail("MAX_BLOCK_SIZE should fit usize"))?;

    ensure(
        bytes.len() < max_block_size,
        "serialized GenesisBlock should be below MAX_BLOCK_SIZE",
    )
}

#[test]
fn genesis_001_block_87_pad_to_max_size_zero_fills_after_serialized_prefix() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar padding zero-fill",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let serialized = genesis.serialize()?;
    let padded = genesis.pad_to_max_size()?;
    let tail = padded
        .get(serialized.len()..)
        .ok_or_else(|| fail("padded payload should have a tail"))?;

    ensure(
        tail.iter().all(|byte| *byte == 0),
        "pad_to_max_size should zero-fill bytes after the serialized prefix",
    )
}

#[test]
fn genesis_001_block_88_padded_payload_with_founder_wallet_deserializes_to_original() -> TestResult
{
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar padded founder deserialize",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let padded = genesis.pad_to_max_size()?;
    let decoded = GenesisBlock::deserialize(&padded)?;

    ensure_eq(
        &decoded,
        &genesis,
        "padded payload with founder_wallet should deserialize to original",
    )
}

#[test]
fn genesis_001_block_89_from_json_file_valid_no_founder_roundtrip() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let path = temp_json_path("valid_no_founder");
    remove_file_if_exists(&path)?;
    let path_string = path.to_string_lossy().into_owned();

    genesis.to_json_file(&path_string)?;
    let decoded = GenesisBlock::from_json_file(&path_string)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &decoded,
        &genesis,
        "valid JSON file without founder_wallet should roundtrip",
    )
}

#[test]
fn genesis_001_block_90_from_json_file_rejects_zero_merkle_root() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let mut value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;
    set_json_string(&mut value, "merkle_root", "00".repeat(64))?;

    let path = temp_json_path("zero_merkle");
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string(&value)?)?;

    let path_string = path.to_string_lossy().into_owned();
    let result = GenesisBlock::from_json_file(&path_string);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "Merkle root is all zeros")
}

#[test]
fn genesis_001_block_91_validate_rejects_genesis_hash_equal_to_prev_hash_zero_config() -> TestResult
{
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.genesis_hash = genesis.prev_hash;

    require_validation_error(genesis.validate(), "Genesis hash is all zeros")
}

#[test]
fn genesis_001_block_92_validate_rejects_genesis_hash_equal_to_merkle_root() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;
    genesis.genesis_hash = genesis.merkle_root;

    require_validation_error(genesis.validate(), "Genesis hash fields must all be unique")
}

#[test]
fn genesis_001_block_93_validate_rejects_prev_hash_mutation_by_hash_mismatch() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;

    for byte in genesis.prev_hash.iter_mut().take(1) {
        *byte = byte.wrapping_add(1);
    }

    require_validation_error(genesis.validate(), "genesis_hash mismatch")
}

#[test]
fn genesis_001_block_94_validate_rejects_merkle_root_mutation_by_hash_mismatch() -> TestResult {
    let mut genesis = genesis_at(min_timestamp())?;

    for byte in genesis.merkle_root.iter_mut().take(1) {
        *byte = byte.wrapping_add(1);
    }

    require_validation_error(genesis.validate(), "genesis_hash mismatch")
}

#[test]
fn genesis_001_block_95_genesis_hash_hex_matches_hex_encode_of_raw_hash() -> TestResult {
    let genesis = genesis_at(min_timestamp())?;
    let expected = hex::encode(genesis.genesis_hash);

    ensure_eq(
        &genesis.genesis_hash_hex(),
        &expected,
        "genesis_hash_hex should be hex::encode(genesis_hash)",
    )
}

#[test]
fn genesis_001_block_96_storage_serialization_with_founder_is_deterministic() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar storage deterministic founder",
        min_timestamp(),
        &canonical_wallet(),
    )?;

    let first = genesis.serialize_for_storage()?;
    let second = genesis.serialize_for_storage()?;

    ensure_eq(
        &first,
        &second,
        "serialize_for_storage should be deterministic",
    )
}

#[test]
fn genesis_001_block_97_json_founder_wallet_does_not_change_consensus_hash_across_wallets()
-> TestResult {
    let first = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder hash invariant",
        min_timestamp(),
        &canonical_wallet(),
    )?;
    let second = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar founder hash invariant",
        min_timestamp(),
        &alternate_wallet(),
    )?;

    ensure_eq(
        &first.genesis_hash,
        &second.genesis_hash,
        "different founder wallets should not affect genesis consensus hash",
    )?;

    let first_json = first.to_json()?;
    let second_json = second.to_json()?;

    ensure_ne(
        &first_json,
        &second_json,
        "different founder wallets should still produce different JSON config payloads",
    )
}

#[test]
fn genesis_001_block_98_many_json_hash_fields_are_128_lowercase_hex() -> TestResult {
    for index in 0_u64..64_u64 {
        let genesis = GenesisBlock::new_with_timestamp(
            &format!("Remzar JSON hash vector {index}"),
            min_timestamp().saturating_add(index),
        )?;
        let value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;

        for field in ["genesis_hash", "merkle_root", "prev_hash"] {
            let s = json_string_field(&value, field)?;
            ensure_eq(&s.len(), &128_usize, "hash field should be 128 chars")?;
            ensure(is_lowercase_hex(s), "hash field should be lowercase hex")?;
        }
    }

    Ok(())
}

#[test]
fn genesis_001_block_99_many_founder_wallet_json_roundtrips_preserve_miner_string() -> TestResult {
    let wallets = vec![canonical_wallet(), alternate_wallet()];

    for wallet in wallets {
        let genesis = GenesisBlock::new_with_timestamp_and_miner(
            "Remzar founder JSON roundtrip vector",
            min_timestamp(),
            &wallet,
        )?;

        let json = genesis.to_json()?;
        let decoded = GenesisBlock::from_json(&json)?;

        ensure_eq(
            &decoded.miner_for_genesis_block(),
            &wallet,
            "founder wallet should survive JSON roundtrip and return as miner string",
        )?;
        ensure_eq(
            &decoded,
            &genesis,
            "founder wallet JSON roundtrip should preserve full genesis block",
        )?;
    }

    Ok(())
}

#[test]
fn genesis_001_block_100_adversarial_file_json_valid_and_invalid_vectors() -> TestResult {
    let valid_path = temp_json_path("adv_valid");
    let invalid_path = temp_json_path("adv_invalid");
    remove_file_if_exists(&valid_path)?;
    remove_file_if_exists(&invalid_path)?;

    let genesis = GenesisBlock::new_with_timestamp_and_miner(
        "Remzar adversarial file vector",
        min_timestamp(),
        &canonical_wallet(),
    )?;
    let valid_path_string = valid_path.to_string_lossy().into_owned();

    genesis.to_json_file(&valid_path_string)?;
    let decoded = GenesisBlock::from_json_file(&valid_path_string)?;
    ensure_eq(
        &decoded,
        &genesis,
        "valid adversarial file vector should roundtrip",
    )?;

    let mut invalid_value: serde_json::Value = serde_json::from_str(&genesis.to_json()?)?;
    set_json_string(
        &mut invalid_value,
        "founder_wallet",
        String::from("bad-wallet"),
    )?;

    let invalid_path_string = invalid_path.to_string_lossy().into_owned();
    fs::write(&invalid_path, serde_json::to_string(&invalid_value)?)?;
    let invalid_result = GenesisBlock::from_json_file(&invalid_path_string);

    remove_file_if_exists(&valid_path)?;
    remove_file_if_exists(&invalid_path)?;

    require_validation_error_any(invalid_result)
}

#[test]
#[ignore = "manual genesis vector printer; run only when checking/updating genesis constants"]
fn genesis_001_block_101_print_mainnet_genesis_hash_vector() -> TestResult {
    // Remzar launch date:
    // 2026-06-26 00:00:00 UTC
    let launch_ts: u64 = 1_782_432_000;

    let genesis = GenesisBlock::new_with_timestamp(
        "genesis for remzar blockchain - a single executable pq l1 base layer for verified data.",
        launch_ts,
    )?;

    let generated_hash = genesis.genesis_hash_hex();

    println!();
    println!("========== REMZAR GENESIS HASH VECTOR ==========");
    println!("launch_date_utc        = 2026-06-26 00:00:00 UTC");
    println!("launch_timestamp       = {}", launch_ts);
    println!("genesis_hash           = {}", generated_hash);
    println!(
        "current_GENESIS_HASH   = {}",
        GlobalConfiguration::GENESIS_HASH_HEX
    );
    println!(
        "matches_current_const  = {}",
        generated_hash == GlobalConfiguration::GENESIS_HASH_HEX
    );
    println!();
    println!("Paste/update these constants if desired:");
    println!(
        "pub const DEFAULT_USER_CHAIN_GENESIS_TIMESTAMP: u64 = {}; // 2026-06-26 00:00:00 UTC",
        launch_ts
    );
    println!(
        "pub const GENESIS_HASH_HEX: &'static str = \"{}\";",
        generated_hash
    );
    println!("================================================");
    println!();

    ensure_eq(
        &genesis.timestamp,
        &launch_ts,
        "genesis timestamp should be the June 26, 2026 launch timestamp",
    )?;

    ensure_eq(
        &generated_hash.len(),
        &128_usize,
        "genesis hash should be 128 lowercase hex chars",
    )?;

    ensure(
        is_lowercase_hex(&generated_hash),
        "genesis hash should be lowercase hex",
    )?;

    genesis.validate()?;
    Ok(())
}
