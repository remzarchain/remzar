// tests/genesis_file_tests.rs

use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::blockchain::genesis_002_file::GenesisFile;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::error::Error as StdError;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn StdError>>;

fn fail(message: impl Into<String>) -> Box<dyn StdError> {
    std::io::Error::other(message.into()).into()
}

fn genesis_file_json_object_mut(
    value: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, Box<dyn StdError>> {
    match value.as_object_mut() {
        Some(object) => Ok(object),
        None => Err(fail("GenesisFile should serialize to JSON object")),
    }
}

fn write_value_to_temp_file(
    value: &serde_json::Value,
    suffix: &str,
) -> Result<PathBuf, Box<dyn StdError>> {
    let path = temp_json_path(suffix);
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string_pretty(value)?)?;
    Ok(path)
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

fn min_timestamp() -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS
}

fn valid_genesis_block() -> Result<GenesisBlock, ErrorDetection> {
    GenesisBlock::new_with_timestamp_and_miner(
        "Remzar GenesisFile test genesis block",
        min_timestamp(),
        &canonical_wallet(),
    )
}

fn valid_genesis_file() -> Result<GenesisFile, ErrorDetection> {
    Ok(GenesisFile {
        chain_id: String::from("remzar-mainnet"),
        description: Some(String::from("Remzar blockchain genesis file")),
        version: Some(String::from("1.0.0")),
        genesis_block: valid_genesis_block()?,
    })
}

fn temp_json_path(suffix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "remzar_genesis_file_tests_{}_{}.json",
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

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn genesis_file_01_validate_accepts_valid_file() -> TestResult {
    let file = valid_genesis_file()?;

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_02_validate_accepts_description_none() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = None;

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_03_validate_accepts_semver_with_beta_suffix() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("2.1.3-beta"));

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_04_validate_accepts_chain_id_exactly_128_bytes() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id = "a".repeat(128);

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_05_validate_accepts_description_exactly_500_bytes() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = Some("d".repeat(500));

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_06_validate_rejects_empty_chain_id() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id.clear();

    require_validation_error(file.validate(), "chain_id is empty")
}

#[test]
fn genesis_file_07_validate_rejects_whitespace_chain_id() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id = String::from("   \n\t   ");

    require_validation_error(file.validate(), "chain_id is empty")
}

#[test]
fn genesis_file_08_validate_rejects_chain_id_over_128_bytes() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id = "a".repeat(129);

    require_validation_error(file.validate(), "chain_id too long")
}

#[test]
fn genesis_file_09_validate_rejects_missing_version() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = None;

    require_validation_error(file.validate(), "version validation failed")
}

#[test]
fn genesis_file_10_validate_rejects_empty_version_string() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::new());

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_11_validate_rejects_short_semver() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("1.0"));

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_12_validate_rejects_version_with_v_prefix() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("v1.0.0"));

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_13_validate_rejects_semver_with_dotted_prerelease() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("1.0.0-beta.1"));

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_14_validate_rejects_semver_with_plus_build_metadata() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("1.0.0+build"));

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_15_validate_rejects_empty_description() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = Some(String::new());

    require_validation_error(file.validate(), "description is empty")
}

#[test]
fn genesis_file_16_validate_rejects_whitespace_description() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = Some(String::from("   \n\t   "));

    require_validation_error(file.validate(), "description is empty")
}

#[test]
fn genesis_file_17_validate_rejects_description_over_500_bytes() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = Some("d".repeat(501));

    require_validation_error(file.validate(), "description is too long")
}

#[test]
fn genesis_file_18_validate_rejects_invalid_nested_genesis_block() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.genesis_block.data.clear();

    require_validation_error(file.validate(), "Genesis block data is empty")
}

#[test]
fn genesis_file_19_validate_rejects_nested_zero_genesis_hash() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.genesis_block.genesis_hash = [0_u8; 64];

    require_validation_error(file.validate(), "Genesis hash is all zeros")
}

#[test]
fn genesis_file_20_validate_rejects_nested_zero_merkle_root() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.genesis_block.merkle_root = [0_u8; 64];

    require_validation_error(file.validate(), "Merkle root is all zeros")
}

#[test]
fn genesis_file_21_json_roundtrip_preserves_fields() -> TestResult {
    let file = valid_genesis_file()?;

    let json = serde_json::to_string_pretty(&file)?;
    let decoded: GenesisFile = serde_json::from_str(&json)?;

    ensure_eq(
        &decoded.chain_id,
        &file.chain_id,
        "chain_id should roundtrip",
    )?;
    ensure_eq(
        &decoded.description,
        &file.description,
        "description should roundtrip",
    )?;
    ensure_eq(&decoded.version, &file.version, "version should roundtrip")?;
    ensure_eq(
        &decoded.genesis_block,
        &file.genesis_block,
        "genesis_block should roundtrip",
    )
}

#[test]
fn genesis_file_22_json_unknown_fields_are_ignored_by_current_serde_behavior() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(
                String::from("unknown_field_currently_ignored"),
                serde_json::Value::String(String::from("ignored")),
            );
        }
        None => return Err(fail("GenesisFile should serialize to JSON object")),
    }

    let decoded: GenesisFile = serde_json::from_value(value)?;

    ensure_eq(&decoded.chain_id, &file.chain_id, "chain_id should decode")?;
    decoded.validate()?;
    Ok(())
}

#[test]
fn genesis_file_23_json_missing_description_defaults_to_none() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("description");
        }
        None => return Err(fail("GenesisFile should serialize to JSON object")),
    }

    let decoded: GenesisFile = serde_json::from_value(value)?;

    ensure(
        decoded.description.is_none(),
        "missing Option description should deserialize as None",
    )
}

#[test]
fn genesis_file_24_json_missing_version_deserializes_none_then_validation_rejects() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("version");
        }
        None => return Err(fail("GenesisFile should serialize to JSON object")),
    }

    let decoded: GenesisFile = serde_json::from_value(value)?;

    require_validation_error(decoded.validate(), "version validation failed")
}

#[test]
fn genesis_file_25_json_missing_chain_id_is_serde_error() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("chain_id");
        }
        None => return Err(fail("GenesisFile should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<GenesisFile>(value);

    ensure(decoded.is_err(), "missing chain_id should be a serde error")
}

#[test]
fn genesis_file_26_json_missing_genesis_block_is_serde_error() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    match value.as_object_mut() {
        Some(object) => {
            object.remove("genesis_block");
        }
        None => return Err(fail("GenesisFile should serialize to JSON object")),
    }

    let decoded = serde_json::from_value::<GenesisFile>(value);

    ensure(
        decoded.is_err(),
        "missing genesis_block should be a serde error",
    )
}

#[test]
fn genesis_file_27_json_null_description_is_none() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(String::from("description"), serde_json::Value::Null);
        }
        None => return Err(fail("GenesisFile should serialize to JSON object")),
    }

    let decoded: GenesisFile = serde_json::from_value(value)?;

    ensure(
        decoded.description.is_none(),
        "null description should decode as None",
    )
}

#[test]
fn genesis_file_28_json_null_version_is_rejected_by_validation() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    match value.as_object_mut() {
        Some(object) => {
            object.insert(String::from("version"), serde_json::Value::Null);
        }
        None => return Err(fail("GenesisFile should serialize to JSON object")),
    }

    let decoded: GenesisFile = serde_json::from_value(value)?;

    require_validation_error(decoded.validate(), "version validation failed")
}

#[test]
fn genesis_file_29_to_json_file_and_from_json_file_roundtrip() -> TestResult {
    let file = valid_genesis_file()?;
    let path = temp_json_path("roundtrip");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    file.to_json_file(&path_str)?;
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &decoded.chain_id,
        &file.chain_id,
        "chain_id should roundtrip",
    )?;
    ensure_eq(
        &decoded.genesis_block,
        &file.genesis_block,
        "genesis_block should roundtrip",
    )
}

#[test]
fn genesis_file_30_to_json_file_overwrites_existing_file() -> TestResult {
    let file = valid_genesis_file()?;
    let path = temp_json_path("overwrite");
    remove_file_if_exists(&path)?;
    fs::write(&path, b"old invalid data")?;

    let path_str = path_string(&path);
    file.to_json_file(&path_str)?;
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &decoded.chain_id,
        &file.chain_id,
        "to_json_file should overwrite existing file with valid JSON",
    )
}

#[test]
fn genesis_file_31_from_json_file_rejects_missing_file() -> TestResult {
    let path = temp_json_path("missing");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    require_serialization_error(GenesisFile::from_json_file(&path_str), "")
}

#[test]
fn genesis_file_32_from_json_file_rejects_invalid_json() -> TestResult {
    let path = temp_json_path("invalid_json");
    remove_file_if_exists(&path)?;
    fs::write(&path, b"{ not valid json")?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_33_from_json_file_rejects_oversized_file_before_parse() -> TestResult {
    let path = temp_json_path("oversized");
    remove_file_if_exists(&path)?;

    let cap = GlobalConfiguration::MAX_GENESIS_JSON_BYTES;
    let file = fs::File::create(&path)?;
    file.set_len(cap.saturating_add(1))?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "Genesis JSON file too large")
}

#[test]
fn genesis_file_34_from_json_file_rejects_empty_file() -> TestResult {
    let path = temp_json_path("empty_file");
    remove_file_if_exists(&path)?;
    fs::write(&path, b"")?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_35_load_genesis_block_from_json_returns_nested_block() -> TestResult {
    let file = valid_genesis_file()?;
    let path = temp_json_path("load_block");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    file.to_json_file(&path_str)?;
    let block = GenesisFile::load_genesis_block_from_json(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &block,
        &file.genesis_block,
        "load_genesis_block_from_json should return nested genesis_block",
    )
}

#[test]
fn genesis_file_36_load_genesis_block_from_json_rejects_invalid_file() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id.clear();

    let path = temp_json_path("load_invalid");
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string_pretty(&file)?)?;

    let path_str = path_string(&path);
    let result = GenesisFile::load_genesis_block_from_json(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "chain_id is empty")
}

#[test]
fn genesis_file_37_to_json_file_refuses_json_over_cap() -> TestResult {
    let mut file = valid_genesis_file()?;
    let cap = usize::try_from(GlobalConfiguration::MAX_GENESIS_JSON_BYTES)
        .map_err(|_| fail("MAX_GENESIS_JSON_BYTES should fit usize"))?;

    file.genesis_block.data = "x".repeat(cap.saturating_add(1));

    let path = temp_json_path("refuse_write");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    let result = file.to_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "Refusing to write genesis JSON")
}

#[test]
fn genesis_file_38_from_json_file_rejects_invalid_chain_id() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id = String::from("   ");

    let path = temp_json_path("invalid_chain");
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string_pretty(&file)?)?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "chain_id is empty")
}

#[test]
fn genesis_file_39_from_json_file_rejects_invalid_version() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("bad-version"));

    let path = temp_json_path("invalid_version");
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string_pretty(&file)?)?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "version has invalid format")
}

#[test]
fn genesis_file_40_from_json_file_rejects_invalid_description() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = Some(String::from("   "));

    let path = temp_json_path("invalid_description");
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string_pretty(&file)?)?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "description is empty")
}

#[test]
fn genesis_file_41_from_json_file_rejects_invalid_nested_genesis_block() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.genesis_block.data.clear();

    let path = temp_json_path("invalid_nested_block");
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string_pretty(&file)?)?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "Genesis block data is empty")
}

#[test]
fn genesis_file_42_clone_preserves_fields() -> TestResult {
    let file = valid_genesis_file()?;
    let cloned = file.clone();

    ensure_eq(&cloned.chain_id, &file.chain_id, "chain_id should clone")?;
    ensure_eq(
        &cloned.description,
        &file.description,
        "description should clone",
    )?;
    ensure_eq(&cloned.version, &file.version, "version should clone")?;
    ensure_eq(
        &cloned.genesis_block,
        &file.genesis_block,
        "genesis_block should clone",
    )
}

#[test]
fn genesis_file_43_debug_output_mentions_struct_name_and_chain_id() -> TestResult {
    let file = valid_genesis_file()?;
    let debug = format!("{file:?}");

    ensure(
        debug.contains("GenesisFile"),
        "Debug output should contain struct name",
    )?;
    ensure(
        debug.contains(&file.chain_id),
        "Debug output should contain chain_id",
    )
}

#[test]
fn genesis_file_44_different_chain_ids_keep_same_genesis_block() -> TestResult {
    let first = valid_genesis_file()?;
    let mut second = valid_genesis_file()?;
    second.chain_id = String::from("remzar-testnet");

    ensure_ne(
        &first.chain_id,
        &second.chain_id,
        "test setup should have different chain ids",
    )?;
    ensure_eq(
        &first.genesis_block,
        &second.genesis_block,
        "chain_id is GenesisFile metadata and should not alter nested genesis block",
    )?;

    first.validate()?;
    second.validate()?;
    Ok(())
}

#[test]
fn genesis_file_45_many_valid_semver_vectors_validate() -> TestResult {
    let versions = [
        "0.0.1",
        "1.0.0",
        "10.20.30",
        "2.1.3-beta",
        "999.999.999-rc1",
    ];

    for version in versions {
        let mut file = valid_genesis_file()?;
        file.version = Some(version.to_string());
        file.validate()?;
    }

    Ok(())
}

#[test]
fn genesis_file_46_many_invalid_semver_vectors_reject() -> TestResult {
    let versions = [
        "",
        "1",
        "1.2",
        "1.2.3.4",
        "v1.2.3",
        "1.2.3-beta.1",
        "1.2.3+build",
        "one.two.three",
    ];

    for version in versions {
        let mut file = valid_genesis_file()?;
        file.version = Some(version.to_string());
        require_validation_error(file.validate(), "version has invalid format")?;
    }

    Ok(())
}

#[test]
fn genesis_file_47_many_chain_id_boundaries_validate_or_reject() -> TestResult {
    let mut valid_short = valid_genesis_file()?;
    valid_short.chain_id = String::from("a");
    valid_short.validate()?;

    let mut valid_max = valid_genesis_file()?;
    valid_max.chain_id = "a".repeat(128);
    valid_max.validate()?;

    let mut invalid_empty = valid_genesis_file()?;
    invalid_empty.chain_id = String::new();
    require_validation_error(invalid_empty.validate(), "chain_id is empty")?;

    let mut invalid_long = valid_genesis_file()?;
    invalid_long.chain_id = "a".repeat(129);
    require_validation_error(invalid_long.validate(), "chain_id too long")
}

#[test]
fn genesis_file_48_many_description_boundaries_validate_or_reject() -> TestResult {
    let mut none_desc = valid_genesis_file()?;
    none_desc.description = None;
    none_desc.validate()?;

    let mut one_char = valid_genesis_file()?;
    one_char.description = Some(String::from("d"));
    one_char.validate()?;

    let mut max_desc = valid_genesis_file()?;
    max_desc.description = Some("d".repeat(500));
    max_desc.validate()?;

    let mut empty_desc = valid_genesis_file()?;
    empty_desc.description = Some(String::new());
    require_validation_error(empty_desc.validate(), "description is empty")?;

    let mut long_desc = valid_genesis_file()?;
    long_desc.description = Some("d".repeat(501));
    require_validation_error(long_desc.validate(), "description is too long")
}

#[test]
fn genesis_file_49_load_property_many_valid_files_roundtrip() -> TestResult {
    for index in 0_u64..32_u64 {
        let mut file = valid_genesis_file()?;
        file.chain_id = format!("remzar-chain-{index}");
        file.description = Some(format!("Remzar load vector {index}"));
        file.version = Some(format!("1.0.{index}"));

        let path = temp_json_path(&format!("load_property_{index}"));
        remove_file_if_exists(&path)?;
        let path_str = path_string(&path);

        file.to_json_file(&path_str)?;
        let decoded = GenesisFile::from_json_file(&path_str)?;
        let block = GenesisFile::load_genesis_block_from_json(&path_str)?;
        remove_file_if_exists(&path)?;

        ensure_eq(
            &decoded.chain_id,
            &file.chain_id,
            "chain_id should roundtrip",
        )?;
        ensure_eq(
            &decoded.description,
            &file.description,
            "description should roundtrip",
        )?;
        ensure_eq(&decoded.version, &file.version, "version should roundtrip")?;
        ensure_eq(
            &block,
            &file.genesis_block,
            "loaded genesis block should match nested block",
        )?;
    }

    Ok(())
}

#[test]
fn genesis_file_50_adversarial_valid_and_invalid_json_file_vectors() -> TestResult {
    let valid_path = temp_json_path("adv_valid");
    let invalid_path = temp_json_path("adv_invalid");
    remove_file_if_exists(&valid_path)?;
    remove_file_if_exists(&invalid_path)?;

    let valid = valid_genesis_file()?;
    let valid_path_str = path_string(&valid_path);
    valid.to_json_file(&valid_path_str)?;

    let decoded = GenesisFile::from_json_file(&valid_path_str)?;
    ensure_eq(
        &decoded.chain_id,
        &valid.chain_id,
        "valid adversarial vector should load",
    )?;

    let mut invalid = valid.clone();
    invalid.version = Some(String::from("invalid-version"));
    fs::write(&invalid_path, serde_json::to_string_pretty(&invalid)?)?;

    let invalid_path_str = path_string(&invalid_path);
    let result = GenesisFile::from_json_file(&invalid_path_str);

    remove_file_if_exists(&valid_path)?;
    remove_file_if_exists(&invalid_path)?;

    require_validation_error(result, "version has invalid format")
}

#[test]
fn genesis_file_51_validate_accepts_chain_id_with_surrounding_spaces_if_nonempty() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id = String::from("  remzar-mainnet  ");

    file.validate()?;
    ensure_eq(
        &file.chain_id,
        &String::from("  remzar-mainnet  "),
        "validate should not mutate chain_id",
    )
}

#[test]
fn genesis_file_52_validate_accepts_chain_id_128_bytes_including_spaces() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id = format!("{}{}", " ".repeat(2), "a".repeat(126));

    ensure_eq(
        &file.chain_id.len(),
        &128_usize,
        "test setup should use exactly 128 bytes",
    )?;
    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_53_validate_rejects_chain_id_129_bytes_even_if_trimmed_part_is_shorter()
-> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id = format!("{}{}", "a".repeat(128), " ");

    ensure_eq(
        &file.chain_id.len(),
        &129_usize,
        "test setup should use 129 bytes",
    )?;
    require_validation_error(file.validate(), "chain_id too long")
}

#[test]
fn genesis_file_54_validate_accepts_semver_with_leading_zero_numeric_parts() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("01.002.0003"));

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_55_validate_accepts_semver_prerelease_with_uppercase_alnum() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("1.2.3-BETA123"));

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_56_validate_rejects_semver_prerelease_with_underscore() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("1.2.3-beta_1"));

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_57_validate_rejects_semver_empty_prerelease_suffix() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from("1.2.3-"));

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_58_validate_rejects_semver_with_surrounding_whitespace() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.version = Some(String::from(" 1.2.3 "));

    require_validation_error(file.validate(), "version has invalid format")
}

#[test]
fn genesis_file_59_validate_accepts_description_with_surrounding_whitespace_and_content()
-> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = Some(String::from("   Remzar genesis description   "));

    file.validate()?;
    Ok(())
}

#[test]
fn genesis_file_60_validate_rejects_unicode_description_over_500_bytes() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = Some("界".repeat(167));

    ensure(
        file.description
            .as_ref()
            .is_some_and(|desc| desc.len() > 500),
        "test setup should exceed 500 bytes",
    )?;
    require_validation_error(file.validate(), "description is too long")
}

#[test]
fn genesis_file_61_to_json_file_writes_pretty_json_object() -> TestResult {
    let file = valid_genesis_file()?;
    let path = temp_json_path("pretty_json");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    file.to_json_file(&path_str)?;
    let contents = fs::read_to_string(&path)?;
    remove_file_if_exists(&path)?;

    ensure(
        contents.contains('\n'),
        "to_json_file should write pretty JSON with newlines",
    )?;
    ensure(
        contents.trim_start().starts_with('{'),
        "to_json_file should write a JSON object",
    )
}

#[test]
fn genesis_file_62_from_json_file_accepts_unknown_top_level_fields_current_behavior() -> TestResult
{
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?.insert(
        String::from("unknown_top_level"),
        serde_json::Value::String(String::from("ignored")),
    );

    let path = write_value_to_temp_file(&value, "unknown_top_level")?;
    let path_str = path_string(&path);
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &decoded.chain_id,
        &file.chain_id,
        "unknown top-level fields should be ignored by current serde behavior",
    )
}

#[test]
fn genesis_file_63_from_json_file_missing_version_deserializes_then_validation_rejects()
-> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?.remove("version");

    let path = write_value_to_temp_file(&value, "missing_version")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "version validation failed")
}

#[test]
fn genesis_file_64_from_json_file_null_version_deserializes_then_validation_rejects() -> TestResult
{
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?
        .insert(String::from("version"), serde_json::Value::Null);

    let path = write_value_to_temp_file(&value, "null_version")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "version validation failed")
}

#[test]
fn genesis_file_65_from_json_file_missing_description_defaults_to_none() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?.remove("description");

    let path = write_value_to_temp_file(&value, "missing_description")?;
    let path_str = path_string(&path);
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure(
        decoded.description.is_none(),
        "missing optional description should decode as None",
    )
}

#[test]
fn genesis_file_66_from_json_file_null_description_decodes_as_none() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?
        .insert(String::from("description"), serde_json::Value::Null);

    let path = write_value_to_temp_file(&value, "null_description")?;
    let path_str = path_string(&path);
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure(
        decoded.description.is_none(),
        "null optional description should decode as None",
    )
}

#[test]
fn genesis_file_67_from_json_file_rejects_chain_id_as_number() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?
        .insert(String::from("chain_id"), serde_json::Value::from(123_u64));

    let path = write_value_to_temp_file(&value, "chain_id_number")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_68_from_json_file_rejects_description_as_number() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?.insert(
        String::from("description"),
        serde_json::Value::from(123_u64),
    );

    let path = write_value_to_temp_file(&value, "description_number")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_69_from_json_file_rejects_version_as_number() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?
        .insert(String::from("version"), serde_json::Value::from(1_u64));

    let path = write_value_to_temp_file(&value, "version_number")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_70_from_json_file_rejects_genesis_block_null() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?
        .insert(String::from("genesis_block"), serde_json::Value::Null);

    let path = write_value_to_temp_file(&value, "genesis_block_null")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_71_from_json_file_accepts_unknown_nested_genesis_block_field_current_behavior()
-> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    genesis_block.insert(
        String::from("unknown_nested_field"),
        serde_json::Value::String(String::from("ignored")),
    );

    let path = write_value_to_temp_file(&value, "unknown_nested")?;
    let path_str = path_string(&path);
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &decoded.genesis_block,
        &file.genesis_block,
        "GenesisBlock currently ignores unknown nested JSON fields",
    )
}

#[test]
fn genesis_file_72_from_json_file_accepts_uppercase_nested_hash_hex() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    for field in ["genesis_hash", "merkle_root", "prev_hash"] {
        let uppercase = genesis_block
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| fail(format!("missing nested hash field {field}")))?
            .to_ascii_uppercase();

        genesis_block.insert(String::from(field), serde_json::Value::String(uppercase));
    }

    let path = write_value_to_temp_file(&value, "uppercase_nested_hashes")?;
    let path_str = path_string(&path);
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure_eq(
        &decoded.genesis_block,
        &file.genesis_block,
        "nested GenesisBlock hash deserializer should accept uppercase hex",
    )
}

#[test]
fn genesis_file_73_from_json_file_null_nested_founder_wallet_decodes_as_none() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    genesis_block.insert(String::from("founder_wallet"), serde_json::Value::Null);

    let path = write_value_to_temp_file(&value, "null_nested_founder")?;
    let path_str = path_string(&path);
    let decoded = GenesisFile::from_json_file(&path_str)?;
    remove_file_if_exists(&path)?;

    ensure(
        decoded.genesis_block.founder_wallet().is_none(),
        "nested null founder_wallet should decode as None",
    )
}

#[test]
fn genesis_file_74_from_json_file_empty_nested_founder_wallet_rejects_validation() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    genesis_block.insert(
        String::from("founder_wallet"),
        serde_json::Value::String(String::new()),
    );

    let path = write_value_to_temp_file(&value, "empty_nested_founder")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error_any(result)
}

#[test]
fn genesis_file_75_from_json_file_uppercase_nested_founder_wallet_rejects_validation() -> TestResult
{
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    let mut wallet = String::from("R");
    for _ in 0..128 {
        wallet.push('A');
    }

    genesis_block.insert(
        String::from("founder_wallet"),
        serde_json::Value::String(wallet),
    );

    let path = write_value_to_temp_file(&value, "uppercase_nested_founder")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error_any(result)
}

#[test]
fn genesis_file_76_to_json_file_output_can_be_parsed_as_json_value() -> TestResult {
    let file = valid_genesis_file()?;
    let path = temp_json_path("parse_value");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    file.to_json_file(&path_str)?;
    let contents = fs::read_to_string(&path)?;
    remove_file_if_exists(&path)?;

    let value: serde_json::Value = serde_json::from_str(&contents)?;

    ensure(
        value.get("chain_id").is_some(),
        "written JSON should contain chain_id",
    )?;
    ensure(
        value.get("genesis_block").is_some(),
        "written JSON should contain genesis_block",
    )
}

#[test]
fn genesis_file_77_to_json_file_rejects_directory_path() -> TestResult {
    let file = valid_genesis_file()?;
    let dir = temp_json_path("write_directory");
    remove_file_if_exists(&dir)?;
    fs::create_dir_all(&dir)?;

    let dir_str = path_string(&dir);
    let result = file.to_json_file(&dir_str);
    fs::remove_dir_all(&dir)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_78_from_json_file_rejects_directory_path() -> TestResult {
    let dir = temp_json_path("read_directory");
    remove_file_if_exists(&dir)?;
    fs::create_dir_all(&dir)?;

    let dir_str = path_string(&dir);
    let result = GenesisFile::from_json_file(&dir_str);
    fs::remove_dir_all(&dir)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_79_from_json_file_large_but_under_cap_invalid_json_rejects_parse() -> TestResult {
    let path = temp_json_path("large_invalid_under_cap");
    remove_file_if_exists(&path)?;

    let cap = usize::try_from(GlobalConfiguration::MAX_GENESIS_JSON_BYTES)
        .map_err(|_| fail("MAX_GENESIS_JSON_BYTES should fit usize"))?;
    let len = cap.min(4096).saturating_sub(1).max(1);
    fs::write(&path, vec![b'x'; len])?;

    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "")
}

#[test]
fn genesis_file_80_from_json_file_rejects_missing_chain_id() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?.remove("chain_id");

    let path = write_value_to_temp_file(&value, "missing_chain_id_file")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "missing field")
}

#[test]
fn genesis_file_81_from_json_file_rejects_missing_genesis_block() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?.remove("genesis_block");

    let path = write_value_to_temp_file(&value, "missing_genesis_block_file")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "missing field")
}

#[test]
fn genesis_file_82_from_json_file_rejects_nested_timestamp_below_minimum() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    genesis_block.insert(
        String::from("timestamp"),
        serde_json::Value::from(GlobalConfiguration::MIN_TIMESTAMP_SECS.saturating_sub(1)),
    );

    let path = write_value_to_temp_file(&value, "nested_timestamp_low")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "timestamp below UNIX_2000_SECS")
}

#[test]
fn genesis_file_83_from_json_file_rejects_nested_data_too_large() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    genesis_block.insert(
        String::from("data"),
        serde_json::Value::String("x".repeat(1025)),
    );

    let path = write_value_to_temp_file(&value, "nested_data_large")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "Genesis block data too large")
}

#[test]
fn genesis_file_84_from_json_file_rejects_nested_prev_hash_equal_merkle_root() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    let merkle_root = genesis_block
        .get("merkle_root")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| fail("nested merkle_root should be string"))?
        .to_string();

    genesis_block.insert(
        String::from("prev_hash"),
        serde_json::Value::String(merkle_root),
    );

    let path = write_value_to_temp_file(&value, "nested_prev_eq_merkle")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "Genesis hash fields must all be unique")
}

#[test]
fn genesis_file_85_from_json_file_rejects_nested_genesis_hash_equal_merkle_root() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    let merkle_root = genesis_block
        .get("merkle_root")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| fail("nested merkle_root should be string"))?
        .to_string();

    genesis_block.insert(
        String::from("genesis_hash"),
        serde_json::Value::String(merkle_root),
    );

    let path = write_value_to_temp_file(&value, "nested_genesis_eq_merkle")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "Genesis hash fields must all be unique")
}

#[test]
fn genesis_file_86_from_json_file_rejects_nested_genesis_hash_mismatch() -> TestResult {
    let file = valid_genesis_file()?;
    let mut value = serde_json::to_value(&file)?;

    let genesis_block = value
        .get_mut("genesis_block")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| fail("genesis_block should be a JSON object"))?;

    genesis_block.insert(
        String::from("genesis_hash"),
        serde_json::Value::String("01".repeat(64)),
    );

    let path = write_value_to_temp_file(&value, "nested_hash_mismatch")?;
    let path_str = path_string(&path);
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "genesis_hash mismatch")
}

#[test]
fn genesis_file_87_to_json_file_writes_invalid_file_if_struct_invalid_current_behavior()
-> TestResult {
    let mut file = valid_genesis_file()?;
    file.chain_id.clear();

    let path = temp_json_path("write_invalid_current_behavior");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    file.to_json_file(&path_str)?;
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "chain_id is empty")
}

#[test]
fn genesis_file_88_to_json_file_writes_invalid_nested_block_current_behavior() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.genesis_block.data.clear();

    let path = temp_json_path("write_invalid_nested_current_behavior");
    remove_file_if_exists(&path)?;
    let path_str = path_string(&path);

    file.to_json_file(&path_str)?;
    let result = GenesisFile::from_json_file(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "Genesis block data is empty")
}

#[test]
fn genesis_file_89_description_none_and_missing_description_json_are_equivalent_after_load()
-> TestResult {
    let mut file = valid_genesis_file()?;
    file.description = None;

    let mut value = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut value)?.remove("description");

    let decoded: GenesisFile = serde_json::from_value(value)?;

    ensure(
        decoded.description.is_none(),
        "description None and missing description should both decode to None",
    )?;
    decoded.validate()?;
    Ok(())
}

#[test]
fn genesis_file_90_version_null_and_missing_version_both_reject_validation() -> TestResult {
    let file = valid_genesis_file()?;

    let mut missing = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut missing)?.remove("version");
    let missing_decoded: GenesisFile = serde_json::from_value(missing)?;
    require_validation_error(missing_decoded.validate(), "version validation failed")?;

    let mut null_version = serde_json::to_value(&file)?;
    genesis_file_json_object_mut(&mut null_version)?
        .insert(String::from("version"), serde_json::Value::Null);
    let null_decoded: GenesisFile = serde_json::from_value(null_version)?;
    require_validation_error(null_decoded.validate(), "version validation failed")
}

#[test]
fn genesis_file_91_vector_json_contains_expected_top_level_fields() -> TestResult {
    let file = valid_genesis_file()?;
    let value = serde_json::to_value(&file)?;

    for field in ["chain_id", "description", "version", "genesis_block"] {
        ensure(
            value.get(field).is_some(),
            format!("GenesisFile JSON should contain top-level field {field}"),
        )?;
    }

    Ok(())
}

#[test]
fn genesis_file_92_vector_nested_genesis_block_contains_expected_fields() -> TestResult {
    let file = valid_genesis_file()?;
    let value = serde_json::to_value(&file)?;
    let genesis_block = value
        .get("genesis_block")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| fail("genesis_block should be JSON object"))?;

    for field in [
        "genesis_hash",
        "merkle_root",
        "prev_hash",
        "timestamp",
        "data",
        "founder_wallet",
    ] {
        ensure(
            genesis_block.get(field).is_some(),
            format!("nested genesis_block should contain field {field}"),
        )?;
    }

    Ok(())
}

#[test]
fn genesis_file_93_load_genesis_block_from_json_rejects_oversized_file() -> TestResult {
    let path = temp_json_path("load_block_oversized");
    remove_file_if_exists(&path)?;

    let cap = GlobalConfiguration::MAX_GENESIS_JSON_BYTES;
    let file = fs::File::create(&path)?;
    file.set_len(cap.saturating_add(1))?;

    let path_str = path_string(&path);
    let result = GenesisFile::load_genesis_block_from_json(&path_str);
    remove_file_if_exists(&path)?;

    require_serialization_error(result, "Genesis JSON file too large")
}

#[test]
fn genesis_file_94_load_genesis_block_from_json_rejects_invalid_nested_block() -> TestResult {
    let mut file = valid_genesis_file()?;
    file.genesis_block.merkle_root = [0_u8; 64];

    let path = temp_json_path("load_block_invalid_nested");
    remove_file_if_exists(&path)?;
    fs::write(&path, serde_json::to_string_pretty(&file)?)?;

    let path_str = path_string(&path);
    let result = GenesisFile::load_genesis_block_from_json(&path_str);
    remove_file_if_exists(&path)?;

    require_validation_error(result, "Merkle root is all zeros")
}

#[test]
fn genesis_file_95_property_many_chain_ids_validate_and_roundtrip() -> TestResult {
    for index in 0_u64..64_u64 {
        let mut file = valid_genesis_file()?;
        file.chain_id = format!("remzar-property-chain-{index}");
        file.description = Some(format!("Remzar property description {index}"));
        file.version = Some(format!("1.2.{index}"));

        file.validate()?;

        let json = serde_json::to_string_pretty(&file)?;
        let decoded: GenesisFile = serde_json::from_str(&json)?;
        decoded.validate()?;

        ensure_eq(
            &decoded.chain_id,
            &file.chain_id,
            "chain_id should roundtrip",
        )?;
        ensure_eq(&decoded.version, &file.version, "version should roundtrip")?;
    }

    Ok(())
}

#[test]
fn genesis_file_96_property_many_invalid_chain_ids_reject() -> TestResult {
    let chain_ids = vec![
        String::new(),
        String::from("   "),
        "\n\t".to_string(),
        "a".repeat(129),
        "界".repeat(43),
    ];

    for chain_id in chain_ids {
        let mut file = valid_genesis_file()?;
        file.chain_id = chain_id;
        require_validation_error_any(file.validate())?;
    }

    Ok(())
}

#[test]
fn genesis_file_97_property_many_invalid_descriptions_reject() -> TestResult {
    let descriptions = vec![
        String::new(),
        String::from("   "),
        "\n\t".to_string(),
        "d".repeat(501),
        "界".repeat(167),
    ];

    for description in descriptions {
        let mut file = valid_genesis_file()?;
        file.description = Some(description);
        require_validation_error_any(file.validate())?;
    }

    Ok(())
}

#[test]
fn genesis_file_98_property_many_file_roundtrips_preserve_nested_block_hash() -> TestResult {
    for index in 0_u64..32_u64 {
        let mut file = valid_genesis_file()?;
        file.chain_id = format!("remzar-file-roundtrip-{index}");
        file.version = Some(format!("2.0.{index}"));

        let path = temp_json_path(&format!("roundtrip_hash_{index}"));
        remove_file_if_exists(&path)?;
        let path_str = path_string(&path);

        file.to_json_file(&path_str)?;
        let decoded = GenesisFile::from_json_file(&path_str)?;
        remove_file_if_exists(&path)?;

        ensure_eq(
            &decoded.genesis_block.genesis_hash,
            &file.genesis_block.genesis_hash,
            "nested genesis hash should survive file roundtrip",
        )?;
    }

    Ok(())
}

#[test]
fn genesis_file_99_adversarial_json_mutation_matrix_rejects_invalid_vectors() -> TestResult {
    let base = valid_genesis_file()?;

    let mut empty_chain = serde_json::to_value(&base)?;
    genesis_file_json_object_mut(&mut empty_chain)?.insert(
        String::from("chain_id"),
        serde_json::Value::String(String::new()),
    );
    let empty_chain_decoded: GenesisFile = serde_json::from_value(empty_chain)?;
    require_validation_error(empty_chain_decoded.validate(), "chain_id is empty")?;

    let mut bad_version = serde_json::to_value(&base)?;
    genesis_file_json_object_mut(&mut bad_version)?.insert(
        String::from("version"),
        serde_json::Value::String(String::from("bad")),
    );
    let bad_version_decoded: GenesisFile = serde_json::from_value(bad_version)?;
    require_validation_error(bad_version_decoded.validate(), "version has invalid format")?;

    let mut bad_desc = serde_json::to_value(&base)?;
    genesis_file_json_object_mut(&mut bad_desc)?.insert(
        String::from("description"),
        serde_json::Value::String(String::from("   ")),
    );
    let bad_desc_decoded: GenesisFile = serde_json::from_value(bad_desc)?;
    require_validation_error(bad_desc_decoded.validate(), "description is empty")
}

#[test]
fn genesis_file_100_adversarial_file_matrix_valid_then_invalid_then_missing() -> TestResult {
    let valid_path = temp_json_path("matrix_valid");
    let invalid_path = temp_json_path("matrix_invalid");
    let missing_path = temp_json_path("matrix_missing");

    remove_file_if_exists(&valid_path)?;
    remove_file_if_exists(&invalid_path)?;
    remove_file_if_exists(&missing_path)?;

    let valid = valid_genesis_file()?;
    let valid_path_str = path_string(&valid_path);
    valid.to_json_file(&valid_path_str)?;

    let loaded = GenesisFile::from_json_file(&valid_path_str)?;
    ensure_eq(
        &loaded.chain_id,
        &valid.chain_id,
        "valid matrix file should load",
    )?;

    let mut invalid = valid.clone();
    invalid.chain_id.clear();
    fs::write(&invalid_path, serde_json::to_string_pretty(&invalid)?)?;

    let invalid_path_str = path_string(&invalid_path);
    let invalid_result = GenesisFile::from_json_file(&invalid_path_str);
    require_validation_error(invalid_result, "chain_id is empty")?;

    let missing_path_str = path_string(&missing_path);
    let missing_result = GenesisFile::from_json_file(&missing_path_str);

    remove_file_if_exists(&valid_path)?;
    remove_file_if_exists(&invalid_path)?;

    require_serialization_error(missing_result, "")
}
