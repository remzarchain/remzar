#![forbid(unsafe_code)]

use anyhow::{Result, anyhow};
use fips204::ml_dsa_65;
use remzar::network::p2p_014_chat::{ChatJson, ChatMessage, MAX_CHAT_JSON_BYTES};
use remzar::network::p2p_015_chat_store::{save_incoming_chat, save_outgoing_chat};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn wallet(seed: u128) -> String {
    format!("r{seed:0128x}")
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0_u64)
}

fn fresh_dir(label: &str) -> Result<PathBuf> {
    let id = TEST_DIR_COUNTER.fetch_add(1_u64, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "remzar_chat_store_tests_{}_{}_{}",
        std::process::id(),
        label,
        id
    ));

    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }

    Ok(dir)
}

fn opts_for_dir(dir: &Path) -> NodeOpts {
    NodeOpts {
        data_dir: dir.to_string_lossy().to_string(),
        ..NodeOpts::default()
    }
}

fn chat_dir(dir: &Path) -> PathBuf {
    dir.join("json.chat")
}

fn incoming_path(dir: &Path) -> PathBuf {
    chat_dir(dir).join("received_chat.jsonl")
}

fn outgoing_path(dir: &Path) -> PathBuf {
    chat_dir(dir).join("sent_chat.jsonl")
}

fn chat_json(plaintext: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&ChatJson {
        m: plaintext.to_owned(),
    })?)
}

fn manual_message(
    from_wallet: String,
    to_wallet: String,
    timestamp_ms: u64,
    plaintext: &str,
    signature_len: usize,
) -> Result<ChatMessage> {
    Ok(ChatMessage {
        from_wallet,
        to_wallet,
        timestamp_ms,
        json: chat_json(plaintext)?,
        signature: vec![0_u8; signature_len],
    })
}

fn valid_shape_message(seed: u128, plaintext: &str) -> Result<ChatMessage> {
    manual_message(
        wallet(seed),
        wallet(seed.saturating_add(1_u128)),
        now_ms(),
        plaintext,
        ml_dsa_65::SIG_LEN,
    )
}

fn message_with_json_len(seed: u128, json_len: usize, signature_len: usize) -> ChatMessage {
    ChatMessage {
        from_wallet: wallet(seed),
        to_wallet: wallet(seed.saturating_add(1_u128)),
        timestamp_ms: now_ms(),
        json: vec![b'a'; json_len],
        signature: vec![0_u8; signature_len],
    }
}

fn assert_io_error_contains<T>(
    result: std::result::Result<T, io::Error>,
    kind: io::ErrorKind,
    needle: &str,
) -> Result<()> {
    match result {
        Err(err) => {
            assert_eq!(err.kind(), kind);
            let rendered = err.to_string();
            assert!(
                rendered.contains(needle),
                "expected error containing `{needle}`, got `{rendered}`"
            );
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected io error containing `{needle}`")),
    }
}

fn assert_path_missing(path: &Path) {
    assert!(
        !path.exists(),
        "path should not exist after rejected save: {}",
        path.display()
    );
}

/* ───────────────────────── path and preflight behavior ─────────────────── */

#[test]
fn test_001_valid_shape_incoming_rejects_jsonl_line_too_large() -> Result<()> {
    let dir = fresh_dir("incoming_line_too_large")?;
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(1_u128, "hello incoming")?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    assert_path_missing(&incoming_path(&dir));
    Ok(())
}

#[test]
fn test_002_valid_shape_outgoing_rejects_jsonl_line_too_large() -> Result<()> {
    let dir = fresh_dir("outgoing_line_too_large")?;
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(2_u128, "hello outgoing")?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    assert_path_missing(&outgoing_path(&dir));
    Ok(())
}

#[test]
fn test_003_rejected_incoming_does_not_create_json_chat_directory() -> Result<()> {
    let dir = fresh_dir("incoming_no_dir")?;
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(3_u128, "no dir")?;

    let result = save_incoming_chat(&opts, &msg);

    assert!(result.is_err());
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_004_rejected_outgoing_does_not_create_json_chat_directory() -> Result<()> {
    let dir = fresh_dir("outgoing_no_dir")?;
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(4_u128, "no dir")?;

    let result = save_outgoing_chat(&opts, &msg);

    assert!(result.is_err());
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_005_incoming_and_outgoing_use_separate_target_paths_when_rejected() -> Result<()> {
    let dir = fresh_dir("separate_paths")?;
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(5_u128, "separate paths")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert!(save_outgoing_chat(&opts, &msg).is_err());

    assert_path_missing(&incoming_path(&dir));
    assert_path_missing(&outgoing_path(&dir));
    Ok(())
}

/* ───────────────────────── signature length validation ────────────────── */

#[test]
fn test_006_incoming_rejects_empty_signature_before_filesystem_write() -> Result<()> {
    let dir = fresh_dir("incoming_empty_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(wallet(6_u128), wallet(7_u128), now_ms(), "bad sig", 0_usize)?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_007_outgoing_rejects_empty_signature_before_filesystem_write() -> Result<()> {
    let dir = fresh_dir("outgoing_empty_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(wallet(7_u128), wallet(8_u128), now_ms(), "bad sig", 0_usize)?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_008_incoming_rejects_short_signature() -> Result<()> {
    let dir = fresh_dir("incoming_short_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(
        wallet(8_u128),
        wallet(9_u128),
        now_ms(),
        "short sig",
        ml_dsa_65::SIG_LEN.saturating_sub(1_usize),
    )?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    Ok(())
}

#[test]
fn test_009_outgoing_rejects_short_signature() -> Result<()> {
    let dir = fresh_dir("outgoing_short_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(
        wallet(9_u128),
        wallet(10_u128),
        now_ms(),
        "short sig",
        ml_dsa_65::SIG_LEN.saturating_sub(1_usize),
    )?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    Ok(())
}

#[test]
fn test_010_incoming_rejects_long_signature() -> Result<()> {
    let dir = fresh_dir("incoming_long_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(
        wallet(10_u128),
        wallet(11_u128),
        now_ms(),
        "long sig",
        ml_dsa_65::SIG_LEN.saturating_add(1_usize),
    )?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    Ok(())
}

#[test]
fn test_011_outgoing_rejects_long_signature() -> Result<()> {
    let dir = fresh_dir("outgoing_long_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(
        wallet(11_u128),
        wallet(12_u128),
        now_ms(),
        "long sig",
        ml_dsa_65::SIG_LEN.saturating_add(1_usize),
    )?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    Ok(())
}

#[test]
fn test_012_signature_error_reports_actual_and_expected_lengths() -> Result<()> {
    let dir = fresh_dir("signature_error_lengths")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(wallet(12_u128), wallet(13_u128), now_ms(), "bad", 1_usize)?;

    match save_incoming_chat(&opts, &msg) {
        Err(err) => {
            let rendered = err.to_string();
            assert!(rendered.contains("1 bytes"));
            assert!(rendered.contains(&ml_dsa_65::SIG_LEN.to_string()));
        }
        Ok(_) => return Err(anyhow!("expected signature length error")),
    }

    Ok(())
}

/* ───────────────────────── json size validation ───────────────────────── */

#[test]
fn test_013_incoming_rejects_json_over_chat_json_cap_before_signature_check() -> Result<()> {
    let dir = fresh_dir("incoming_json_over_cap")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(
        13_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        0_usize,
    );

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_014_outgoing_rejects_json_over_chat_json_cap_before_signature_check() -> Result<()> {
    let dir = fresh_dir("outgoing_json_over_cap")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(
        14_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        0_usize,
    );

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_015_json_exactly_at_chat_json_cap_reaches_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("json_exact_cap")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(15_u128, MAX_CHAT_JSON_BYTES, ml_dsa_65::SIG_LEN);

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_016_json_empty_with_valid_signature_still_reaches_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("empty_json_line_cap")?;
    let opts = opts_for_dir(&dir);

    let mut msg = valid_shape_message(16_u128, "will clear json")?;
    msg.json.clear();

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_017_invalid_json_bytes_are_not_parsed_by_store_before_line_cap() -> Result<()> {
    let dir = fresh_dir("invalid_json_not_parsed")?;
    let opts = opts_for_dir(&dir);

    let mut msg = valid_shape_message(17_u128, "valid first")?;
    msg.json = b"{not valid json".to_vec();

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

/* ───────────────────────── wallet/timestamp are not store validators ───── */

#[test]
fn test_018_invalid_from_wallet_is_not_checked_before_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("invalid_from_wallet")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(18_u128, "invalid wallet")?;
    msg.from_wallet = "not-a-wallet".to_owned();

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_019_same_wallet_is_not_checked_before_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("same_wallet")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(19_u128, "same wallet")?;
    msg.to_wallet = msg.from_wallet.clone();

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_020_zero_timestamp_is_not_checked_before_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("zero_timestamp")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(20_u128, "zero timestamp")?;
    msg.timestamp_ms = 0_u64;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_021_u64_max_timestamp_is_not_checked_before_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("u64_max_timestamp")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(21_u128, "max timestamp")?;
    msg.timestamp_ms = u64::MAX;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

/* ───────────────────────── no partial writes / existing files ─────────── */

#[test]
fn test_022_rejected_incoming_does_not_modify_existing_received_log() -> Result<()> {
    let dir = fresh_dir("incoming_existing_unchanged")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"before\n")?;

    let msg = valid_shape_message(22_u128, "do not append")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(incoming_path(&dir))?, "before\n");
    Ok(())
}

#[test]
fn test_023_rejected_outgoing_does_not_modify_existing_sent_log() -> Result<()> {
    let dir = fresh_dir("outgoing_existing_unchanged")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(outgoing_path(&dir), b"before\n")?;

    let msg = valid_shape_message(23_u128, "do not append")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "before\n");
    Ok(())
}

#[test]
fn test_024_rejected_incoming_does_not_create_sent_log() -> Result<()> {
    let dir = fresh_dir("incoming_no_sent")?;
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(24_u128, "incoming only")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());

    assert_path_missing(&outgoing_path(&dir));
    Ok(())
}

#[test]
fn test_025_rejected_outgoing_does_not_create_received_log() -> Result<()> {
    let dir = fresh_dir("outgoing_no_received")?;
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(25_u128, "outgoing only")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());

    assert_path_missing(&incoming_path(&dir));
    Ok(())
}

/* ───────────────────────── data_dir path vectors ──────────────────────── */

#[test]
fn test_026_data_dir_with_spaces_is_safe_on_rejected_save() -> Result<()> {
    let root = fresh_dir("space_root")?;
    let dir = root.join("dir with spaces");
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(26_u128, "spaces")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_027_data_dir_with_unicode_is_safe_on_rejected_save() -> Result<()> {
    let root = fresh_dir("unicode_root")?;
    let dir = root.join("聊天");
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(27_u128, "unicode path")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_028_existing_json_chat_directory_is_left_empty_after_rejected_save() -> Result<()> {
    let dir = fresh_dir("existing_chat_dir_empty")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let msg = valid_shape_message(28_u128, "existing dir")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert!(fs::read_dir(chat_dir(&dir))?.next().is_none());
    Ok(())
}

#[test]
fn test_029_existing_unrelated_file_in_json_chat_dir_is_preserved() -> Result<()> {
    let dir = fresh_dir("unrelated_file")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    let unrelated = chat_dir(&dir).join("keep.txt");
    fs::write(&unrelated, b"keep me")?;

    let msg = valid_shape_message(29_u128, "preserve unrelated")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(unrelated)?, "keep me");
    Ok(())
}

/* ───────────────────────── vector / fuzz-style error checks ───────────── */

#[test]
fn test_030_vector_incoming_short_signature_lengths_are_rejected() -> Result<()> {
    let dir = fresh_dir("vector_incoming_short_sigs")?;
    let opts = opts_for_dir(&dir);

    for signature_len in [1_usize, 2_usize, 8_usize, 32_usize, 64_usize, 128_usize] {
        let msg = manual_message(
            wallet(30_u128 + u128::try_from(signature_len)?),
            wallet(300_u128 + u128::try_from(signature_len)?),
            now_ms(),
            "short signature vector",
            signature_len,
        )?;

        assert_io_error_contains(
            save_incoming_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat.signature invalid length",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_031_vector_outgoing_short_signature_lengths_are_rejected() -> Result<()> {
    let dir = fresh_dir("vector_outgoing_short_sigs")?;
    let opts = opts_for_dir(&dir);

    for signature_len in [1_usize, 3_usize, 9_usize, 33_usize, 65_usize, 129_usize] {
        let msg = manual_message(
            wallet(31_u128 + u128::try_from(signature_len)?),
            wallet(310_u128 + u128::try_from(signature_len)?),
            now_ms(),
            "short signature vector",
            signature_len,
        )?;

        assert_io_error_contains(
            save_outgoing_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat.signature invalid length",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_032_vector_json_lengths_over_cap_are_rejected() -> Result<()> {
    let dir = fresh_dir("vector_json_over_cap")?;
    let opts = opts_for_dir(&dir);

    for extra in 1_usize..=5_usize {
        let msg = message_with_json_len(
            32_u128 + u128::try_from(extra)?,
            MAX_CHAT_JSON_BYTES.saturating_add(extra),
            ml_dsa_65::SIG_LEN,
        );

        assert_io_error_contains(
            save_incoming_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat.json too large for logging",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_033_vector_valid_signature_messages_all_hit_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("vector_valid_shape_line_cap")?;
    let opts = opts_for_dir(&dir);

    for seed in 33_u128..38_u128 {
        let msg = valid_shape_message(seed, "valid shape line cap")?;

        assert_io_error_contains(
            save_incoming_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat JSONL line too large",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_034_vector_outgoing_valid_signature_messages_all_hit_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("vector_outgoing_valid_shape_line_cap")?;
    let opts = opts_for_dir(&dir);

    for seed in 34_u128..39_u128 {
        let msg = valid_shape_message(seed, "valid shape line cap")?;

        assert_io_error_contains(
            save_outgoing_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat JSONL line too large",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

/* ───────────────────────── adversarial filesystem preflight ───────────── */

#[test]
fn test_035_data_dir_that_is_existing_file_is_not_touched_when_encode_fails() -> Result<()> {
    let root = fresh_dir("data_dir_file_root")?;
    fs::create_dir_all(&root)?;
    let data_dir_file = root.join("data_as_file");
    fs::write(&data_dir_file, b"file data")?;

    let opts = opts_for_dir(&data_dir_file);
    let msg = valid_shape_message(35_u128, "data dir is file")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(data_dir_file)?, "file data");
    Ok(())
}

#[test]
fn test_036_existing_received_log_large_file_is_not_rotated_when_encode_fails() -> Result<()> {
    let dir = fresh_dir("large_received_not_rotated")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let path = incoming_path(&dir);
    fs::write(&path, b"large placeholder")?;
    let rotated = chat_dir(&dir).join("received_chat.jsonl.1");

    let msg = valid_shape_message(36_u128, "no rotation")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert!(path.exists());
    assert_path_missing(&rotated);
    Ok(())
}

#[test]
fn test_037_existing_sent_log_large_file_is_not_rotated_when_encode_fails() -> Result<()> {
    let dir = fresh_dir("large_sent_not_rotated")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let path = outgoing_path(&dir);
    fs::write(&path, b"large placeholder")?;
    let rotated = chat_dir(&dir).join("sent_chat.jsonl.1");

    let msg = valid_shape_message(37_u128, "no rotation")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert!(path.exists());
    assert_path_missing(&rotated);
    Ok(())
}

/* ───────────────────────── final combined paths ───────────────────────── */

#[test]
fn test_038_combined_incoming_then_outgoing_rejections_have_no_cross_side_effects() -> Result<()> {
    let dir = fresh_dir("combined_no_cross_side_effects")?;
    let opts = opts_for_dir(&dir);

    let incoming = valid_shape_message(38_u128, "incoming")?;
    let outgoing = valid_shape_message(39_u128, "outgoing")?;

    assert!(save_incoming_chat(&opts, &incoming).is_err());
    assert!(save_outgoing_chat(&opts, &outgoing).is_err());

    assert_path_missing(&incoming_path(&dir));
    assert_path_missing(&outgoing_path(&dir));
    Ok(())
}

#[test]
fn test_039_combined_error_precedence_json_before_signature_before_line_cap() -> Result<()> {
    let dir = fresh_dir("combined_error_precedence")?;
    let opts = opts_for_dir(&dir);

    let json_too_large_and_bad_sig = message_with_json_len(
        39_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        0_usize,
    );
    assert_io_error_contains(
        save_incoming_chat(&opts, &json_too_large_and_bad_sig),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;

    let good_json_bad_sig = message_with_json_len(40_u128, 1_usize, 0_usize);
    assert_io_error_contains(
        save_incoming_chat(&opts, &good_json_bad_sig),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;

    let good_json_good_sig = message_with_json_len(41_u128, 1_usize, ml_dsa_65::SIG_LEN);
    assert_io_error_contains(
        save_incoming_chat(&opts, &good_json_good_sig),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;

    Ok(())
}

#[test]
fn test_040_combined_adversarial_chat_store_path_is_safe() -> Result<()> {
    let dir = fresh_dir("combined_adversarial")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"old incoming\n")?;
    fs::write(outgoing_path(&dir), b"old outgoing\n")?;

    let mut msg = valid_shape_message(40_u128, "combined adversarial")?;
    msg.from_wallet = "not-a-wallet".to_owned();
    msg.to_wallet = msg.from_wallet.clone();
    msg.timestamp_ms = u64::MAX;
    msg.json = b"{bad json".to_vec();

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;

    assert_eq!(fs::read_to_string(incoming_path(&dir))?, "old incoming\n");
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "old outgoing\n");
    Ok(())
}

/* ───────────────────────── serialized line-cap vectors ────────────────── */

#[test]
fn test_041_valid_shape_serialized_json_line_exceeds_private_4096_cap() -> Result<()> {
    let msg = valid_shape_message(41_u128, "line size check")?;

    let line = serde_json::to_string(&msg)?;

    assert!(line.len() > 4096_usize);
    Ok(())
}

#[test]
fn test_042_valid_shape_with_empty_json_still_exceeds_private_4096_cap() -> Result<()> {
    let mut msg = valid_shape_message(42_u128, "clear json")?;
    msg.json.clear();

    let line = serde_json::to_string(&msg)?;

    assert!(line.len() > 4096_usize);
    Ok(())
}

#[test]
fn test_043_valid_shape_with_one_byte_json_still_exceeds_private_4096_cap() -> Result<()> {
    let msg = message_with_json_len(43_u128, 1_usize, ml_dsa_65::SIG_LEN);

    let line = serde_json::to_string(&msg)?;

    assert!(line.len() > 4096_usize);
    Ok(())
}

#[test]
fn test_044_valid_shape_with_max_json_cap_exceeds_private_4096_cap() -> Result<()> {
    let msg = message_with_json_len(44_u128, MAX_CHAT_JSON_BYTES, ml_dsa_65::SIG_LEN);

    let line = serde_json::to_string(&msg)?;

    assert!(line.len() > 4096_usize);
    Ok(())
}

#[test]
fn test_045_line_cap_error_prevents_incoming_file_creation_even_with_empty_json() -> Result<()> {
    let dir = fresh_dir("incoming_empty_json_line_cap_2")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(45_u128, "empty json")?;
    msg.json.clear();

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;

    assert_path_missing(&incoming_path(&dir));
    Ok(())
}

#[test]
fn test_046_line_cap_error_prevents_outgoing_file_creation_even_with_empty_json() -> Result<()> {
    let dir = fresh_dir("outgoing_empty_json_line_cap_2")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(46_u128, "empty json")?;
    msg.json.clear();

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;

    assert_path_missing(&outgoing_path(&dir));
    Ok(())
}

/* ───────────────────────── existing-file no-mutation vectors ───────────── */

#[test]
fn test_047_json_over_cap_incoming_does_not_modify_existing_received_log() -> Result<()> {
    let dir = fresh_dir("json_over_cap_incoming_existing")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"old received\n")?;

    let msg = message_with_json_len(
        47_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        ml_dsa_65::SIG_LEN,
    );

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;
    assert_eq!(fs::read_to_string(incoming_path(&dir))?, "old received\n");
    Ok(())
}

#[test]
fn test_048_json_over_cap_outgoing_does_not_modify_existing_sent_log() -> Result<()> {
    let dir = fresh_dir("json_over_cap_outgoing_existing")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(outgoing_path(&dir), b"old sent\n")?;

    let msg = message_with_json_len(
        48_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        ml_dsa_65::SIG_LEN,
    );

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "old sent\n");
    Ok(())
}

#[test]
fn test_049_bad_signature_incoming_does_not_modify_existing_received_log() -> Result<()> {
    let dir = fresh_dir("bad_sig_incoming_existing")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"old received\n")?;

    let msg = manual_message(
        wallet(49_u128),
        wallet(50_u128),
        now_ms(),
        "bad signature",
        ml_dsa_65::SIG_LEN.saturating_sub(1_usize),
    )?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    assert_eq!(fs::read_to_string(incoming_path(&dir))?, "old received\n");
    Ok(())
}

#[test]
fn test_050_bad_signature_outgoing_does_not_modify_existing_sent_log() -> Result<()> {
    let dir = fresh_dir("bad_sig_outgoing_existing")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(outgoing_path(&dir), b"old sent\n")?;

    let msg = manual_message(
        wallet(50_u128),
        wallet(51_u128),
        now_ms(),
        "bad signature",
        ml_dsa_65::SIG_LEN.saturating_add(1_usize),
    )?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "old sent\n");
    Ok(())
}

#[test]
fn test_051_line_cap_incoming_does_not_modify_existing_received_log() -> Result<()> {
    let dir = fresh_dir("line_cap_incoming_existing")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"old received\n")?;

    let msg = valid_shape_message(51_u128, "line cap")?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    assert_eq!(fs::read_to_string(incoming_path(&dir))?, "old received\n");
    Ok(())
}

#[test]
fn test_052_line_cap_outgoing_does_not_modify_existing_sent_log() -> Result<()> {
    let dir = fresh_dir("line_cap_outgoing_existing")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(outgoing_path(&dir), b"old sent\n")?;

    let msg = valid_shape_message(52_u128, "line cap")?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "old sent\n");
    Ok(())
}

/* ───────────────────────── error precedence boundaries ────────────────── */

#[test]
fn test_053_json_over_cap_takes_precedence_over_short_signature() -> Result<()> {
    let dir = fresh_dir("json_before_short_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(
        53_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        ml_dsa_65::SIG_LEN.saturating_sub(1_usize),
    );

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;
    Ok(())
}

#[test]
fn test_054_json_over_cap_takes_precedence_over_long_signature() -> Result<()> {
    let dir = fresh_dir("json_before_long_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(
        54_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        ml_dsa_65::SIG_LEN.saturating_add(1_usize),
    );

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;
    Ok(())
}

#[test]
fn test_055_signature_length_takes_precedence_over_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("sig_before_line_cap")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(55_u128, MAX_CHAT_JSON_BYTES, 0_usize);

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    Ok(())
}

#[test]
fn test_056_valid_signature_and_max_json_reaches_jsonl_line_cap() -> Result<()> {
    let dir = fresh_dir("valid_sig_max_json_line_cap")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(56_u128, MAX_CHAT_JSON_BYTES, ml_dsa_65::SIG_LEN);

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_057_zero_json_short_signature_reports_signature_not_json() -> Result<()> {
    let dir = fresh_dir("zero_json_short_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(57_u128, 0_usize, 1_usize);

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    Ok(())
}

#[test]
fn test_058_zero_json_valid_signature_reports_line_cap() -> Result<()> {
    let dir = fresh_dir("zero_json_valid_sig")?;
    let opts = opts_for_dir(&dir);
    let msg = message_with_json_len(58_u128, 0_usize, ml_dsa_65::SIG_LEN);

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

/* ───────────────────────── path safety before append is reached ────────── */

#[test]
fn test_059_nested_data_dir_is_not_created_when_encode_fails() -> Result<()> {
    let root = fresh_dir("nested_root")?;
    let dir = root.join("a").join("b").join("c");
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(59_u128, "nested")?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;

    assert_path_missing(&dir);
    Ok(())
}

#[test]
fn test_060_nested_data_dir_is_not_created_when_signature_fails() -> Result<()> {
    let root = fresh_dir("nested_sig_root")?;
    let dir = root.join("a").join("b").join("c");
    let opts = opts_for_dir(&dir);
    let msg = manual_message(wallet(60_u128), wallet(61_u128), now_ms(), "bad", 0_usize)?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;

    assert_path_missing(&dir);
    Ok(())
}

#[test]
fn test_061_existing_data_dir_file_is_preserved_when_signature_fails() -> Result<()> {
    let root = fresh_dir("data_file_sig_root")?;
    fs::create_dir_all(&root)?;
    let data_file = root.join("data-file");
    fs::write(&data_file, b"original")?;

    let opts = opts_for_dir(&data_file);
    let msg = manual_message(wallet(61_u128), wallet(62_u128), now_ms(), "bad", 0_usize)?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;

    assert_eq!(fs::read_to_string(&data_file)?, "original");
    Ok(())
}

#[test]
fn test_062_existing_data_dir_file_is_preserved_when_json_fails() -> Result<()> {
    let root = fresh_dir("data_file_json_root")?;
    fs::create_dir_all(&root)?;
    let data_file = root.join("data-file");
    fs::write(&data_file, b"original")?;

    let opts = opts_for_dir(&data_file);
    let msg = message_with_json_len(
        62_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        ml_dsa_65::SIG_LEN,
    );

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.json too large for logging",
    )?;

    assert_eq!(fs::read_to_string(&data_file)?, "original");
    Ok(())
}

#[test]
fn test_063_json_chat_existing_file_is_preserved_when_encode_fails() -> Result<()> {
    let dir = fresh_dir("json_chat_existing_file")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(&dir)?;
    fs::write(chat_dir(&dir), b"json.chat as file")?;

    let msg = valid_shape_message(63_u128, "line cap")?;

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;

    assert_eq!(fs::read_to_string(chat_dir(&dir))?, "json.chat as file");
    Ok(())
}

#[test]
fn test_064_json_chat_existing_file_is_preserved_when_signature_fails() -> Result<()> {
    let dir = fresh_dir("json_chat_existing_file_sig")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(&dir)?;
    fs::write(chat_dir(&dir), b"json.chat as file")?;

    let msg = manual_message(wallet(64_u128), wallet(65_u128), now_ms(), "bad", 0_usize)?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;

    assert_eq!(fs::read_to_string(chat_dir(&dir))?, "json.chat as file");
    Ok(())
}

/* ───────────────────────── rotation is not reached on encode failure ───── */

#[test]
fn test_065_large_received_log_is_not_rotated_when_line_cap_fails() -> Result<()> {
    let dir = fresh_dir("large_received_real_not_rotated")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let path = incoming_path(&dir);
    let file = fs::File::create(&path)?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    let rotated = chat_dir(&dir).join("received_chat.jsonl.1");
    let msg = valid_shape_message(65_u128, "line cap before rotate")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert!(path.exists());
    assert_path_missing(&rotated);
    assert_eq!(fs::metadata(path)?.len(), 8_u64 * 1024_u64 * 1024_u64);
    Ok(())
}

#[test]
fn test_066_large_sent_log_is_not_rotated_when_line_cap_fails() -> Result<()> {
    let dir = fresh_dir("large_sent_real_not_rotated")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let path = outgoing_path(&dir);
    let file = fs::File::create(&path)?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    let rotated = chat_dir(&dir).join("sent_chat.jsonl.1");
    let msg = valid_shape_message(66_u128, "line cap before rotate")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert!(path.exists());
    assert_path_missing(&rotated);
    assert_eq!(fs::metadata(path)?.len(), 8_u64 * 1024_u64 * 1024_u64);
    Ok(())
}

#[test]
fn test_067_existing_rotated_received_log_is_preserved_when_encode_fails() -> Result<()> {
    let dir = fresh_dir("rotated_received_preserved")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let rotated = chat_dir(&dir).join("received_chat.jsonl.1");
    fs::write(&rotated, b"old rotated")?;

    let msg = valid_shape_message(67_u128, "line cap")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(rotated)?, "old rotated");
    Ok(())
}

#[test]
fn test_068_existing_rotated_sent_log_is_preserved_when_encode_fails() -> Result<()> {
    let dir = fresh_dir("rotated_sent_preserved")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let rotated = chat_dir(&dir).join("sent_chat.jsonl.1");
    fs::write(&rotated, b"old rotated")?;

    let msg = valid_shape_message(68_u128, "line cap")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(rotated)?, "old rotated");
    Ok(())
}

/* ───────────────────────── message mutation vectors ───────────────────── */

#[test]
fn test_069_store_does_not_verify_signature_contents_before_line_cap() -> Result<()> {
    let dir = fresh_dir("does_not_verify_signature")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(69_u128, "all ff signature")?;
    msg.signature = vec![0xff_u8; ml_dsa_65::SIG_LEN];

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_070_store_does_not_validate_plaintext_empty_before_line_cap() -> Result<()> {
    let dir = fresh_dir("does_not_validate_empty_plaintext")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(70_u128, "will become empty")?;
    msg.json = chat_json("")?;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_071_store_does_not_validate_unknown_json_fields_before_line_cap() -> Result<()> {
    let dir = fresh_dir("does_not_validate_unknown_fields")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(71_u128, "unknown fields")?;
    msg.json = br#"{"m":"hello","extra":true}"#.to_vec();

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_072_store_does_not_validate_non_json_payload_before_line_cap() -> Result<()> {
    let dir = fresh_dir("does_not_validate_non_json_payload")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(72_u128, "non json payload")?;
    msg.json = vec![0_u8, 1_u8, 2_u8, 3_u8];

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_073_store_accepts_any_wallet_shape_until_line_cap() -> Result<()> {
    let dir = fresh_dir("any_wallet_shape_until_line_cap")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(73_u128, "bad wallet shape")?;
    msg.from_wallet = String::new();
    msg.to_wallet = "not-a-wallet".to_owned();

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_074_store_accepts_any_timestamp_until_line_cap() -> Result<()> {
    let dir = fresh_dir("any_timestamp_until_line_cap")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(74_u128, "timestamp shape")?;
    msg.timestamp_ms = u64::MAX;

    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

/* ───────────────────────── fuzz/load rejection vectors ────────────────── */

#[test]
fn test_075_load_16_incoming_valid_shape_messages_reject_without_writes() -> Result<()> {
    let dir = fresh_dir("load_16_incoming_valid_shape")?;
    let opts = opts_for_dir(&dir);

    for seed in 75_u128..91_u128 {
        let msg = valid_shape_message(seed, "load incoming line cap")?;
        assert_io_error_contains(
            save_incoming_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat JSONL line too large",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_076_load_16_outgoing_valid_shape_messages_reject_without_writes() -> Result<()> {
    let dir = fresh_dir("load_16_outgoing_valid_shape")?;
    let opts = opts_for_dir(&dir);

    for seed in 76_u128..92_u128 {
        let msg = valid_shape_message(seed, "load outgoing line cap")?;
        assert_io_error_contains(
            save_outgoing_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat JSONL line too large",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_077_load_16_bad_signature_incoming_messages_reject_without_writes() -> Result<()> {
    let dir = fresh_dir("load_16_bad_sig_incoming")?;
    let opts = opts_for_dir(&dir);

    for sig_len in 0_usize..16_usize {
        let msg = manual_message(
            wallet(77_u128 + u128::try_from(sig_len)?),
            wallet(177_u128 + u128::try_from(sig_len)?),
            now_ms(),
            "bad sig load",
            sig_len,
        )?;
        assert_io_error_contains(
            save_incoming_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat.signature invalid length",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_078_load_16_bad_signature_outgoing_messages_reject_without_writes() -> Result<()> {
    let dir = fresh_dir("load_16_bad_sig_outgoing")?;
    let opts = opts_for_dir(&dir);

    for offset in 0_usize..16_usize {
        let sig_len = ml_dsa_65::SIG_LEN
            .saturating_add(1_usize)
            .saturating_add(offset);
        let msg = manual_message(
            wallet(78_u128 + u128::try_from(offset)?),
            wallet(178_u128 + u128::try_from(offset)?),
            now_ms(),
            "bad sig load",
            sig_len,
        )?;
        assert_io_error_contains(
            save_outgoing_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat.signature invalid length",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_079_load_json_over_cap_messages_reject_without_writes() -> Result<()> {
    let dir = fresh_dir("load_json_over_cap")?;
    let opts = opts_for_dir(&dir);

    for extra in 1_usize..=16_usize {
        let msg = message_with_json_len(
            79_u128 + u128::try_from(extra)?,
            MAX_CHAT_JSON_BYTES.saturating_add(extra),
            ml_dsa_65::SIG_LEN,
        );
        assert_io_error_contains(
            save_incoming_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat.json too large for logging",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_080_fuzz_plaintext_lengths_all_hit_line_cap_with_valid_signature() -> Result<()> {
    let dir = fresh_dir("fuzz_plaintext_lengths_line_cap")?;
    let opts = opts_for_dir(&dir);

    for len in 1_usize..=16_usize {
        let msg = valid_shape_message(80_u128 + u128::try_from(len)?, &"a".repeat(len))?;
        assert_io_error_contains(
            save_outgoing_chat(&opts, &msg),
            io::ErrorKind::InvalidData,
            "chat JSONL line too large",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

/* ───────────────────────── JSON serialization shape vectors ───────────── */

#[test]
fn test_081_serialized_message_line_contains_expected_field_names() -> Result<()> {
    let msg = valid_shape_message(81_u128, "field names")?;
    let line = serde_json::to_string(&msg)?;

    assert!(line.contains("from_wallet"));
    assert!(line.contains("to_wallet"));
    assert!(line.contains("timestamp_ms"));
    assert!(line.contains("json"));
    assert!(line.contains("signature"));
    Ok(())
}

#[test]
fn test_082_serialized_message_line_does_not_contain_newline() -> Result<()> {
    let msg = valid_shape_message(82_u128, "single line")?;
    let line = serde_json::to_string(&msg)?;

    assert!(!line.contains('\n'));
    Ok(())
}

#[test]
fn test_083_serialized_message_line_keeps_wallet_values() -> Result<()> {
    let msg = valid_shape_message(83_u128, "wallet values")?;
    let line = serde_json::to_string(&msg)?;

    assert!(line.contains(&wallet(83_u128)));
    assert!(line.contains(&wallet(84_u128)));
    Ok(())
}

#[test]
fn test_084_serialized_message_line_size_increases_with_larger_json_payload() -> Result<()> {
    let small = message_with_json_len(84_u128, 1_usize, ml_dsa_65::SIG_LEN);
    let large = message_with_json_len(85_u128, 128_usize, ml_dsa_65::SIG_LEN);

    let small_line = serde_json::to_string(&small)?;
    let large_line = serde_json::to_string(&large)?;

    assert!(large_line.len() > small_line.len());
    Ok(())
}

#[test]
fn test_085_short_signature_serialized_line_can_be_small_but_store_rejects_signature() -> Result<()>
{
    let dir = fresh_dir("short_sig_line_small")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(wallet(85_u128), wallet(86_u128), now_ms(), "small", 1_usize)?;

    let line = serde_json::to_string(&msg)?;
    assert!(line.len() < 4096_usize);

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat.signature invalid length",
    )?;
    Ok(())
}

/* ───────────────────────── side-effect isolation vectors ──────────────── */

#[test]
fn test_086_incoming_rejection_preserves_existing_sent_log() -> Result<()> {
    let dir = fresh_dir("incoming_preserves_sent")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(outgoing_path(&dir), b"sent remains\n")?;

    let msg = valid_shape_message(86_u128, "incoming reject")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "sent remains\n");
    Ok(())
}

#[test]
fn test_087_outgoing_rejection_preserves_existing_received_log() -> Result<()> {
    let dir = fresh_dir("outgoing_preserves_received")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"received remains\n")?;

    let msg = valid_shape_message(87_u128, "outgoing reject")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert_eq!(
        fs::read_to_string(incoming_path(&dir))?,
        "received remains\n"
    );
    Ok(())
}

#[test]
fn test_088_bad_incoming_signature_preserves_existing_sent_log() -> Result<()> {
    let dir = fresh_dir("bad_incoming_sig_preserves_sent")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(outgoing_path(&dir), b"sent remains\n")?;

    let msg = manual_message(wallet(88_u128), wallet(89_u128), now_ms(), "bad", 0_usize)?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "sent remains\n");
    Ok(())
}

#[test]
fn test_089_bad_outgoing_signature_preserves_existing_received_log() -> Result<()> {
    let dir = fresh_dir("bad_outgoing_sig_preserves_received")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"received remains\n")?;

    let msg = manual_message(wallet(89_u128), wallet(90_u128), now_ms(), "bad", 0_usize)?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert_eq!(
        fs::read_to_string(incoming_path(&dir))?,
        "received remains\n"
    );
    Ok(())
}

/* ───────────────────────── adversarial path/content cases ─────────────── */

#[test]
fn test_090_existing_binary_received_log_is_preserved_after_rejection() -> Result<()> {
    let dir = fresh_dir("binary_received_preserved")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), [0_u8, 1_u8, 2_u8, 255_u8])?;

    let msg = valid_shape_message(90_u128, "line cap")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_eq!(
        fs::read(incoming_path(&dir))?,
        vec![0_u8, 1_u8, 2_u8, 255_u8]
    );
    Ok(())
}

#[test]
fn test_091_existing_binary_sent_log_is_preserved_after_rejection() -> Result<()> {
    let dir = fresh_dir("binary_sent_preserved")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(outgoing_path(&dir), [0_u8, 1_u8, 2_u8, 255_u8])?;

    let msg = valid_shape_message(91_u128, "line cap")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert_eq!(
        fs::read(outgoing_path(&dir))?,
        vec![0_u8, 1_u8, 2_u8, 255_u8]
    );
    Ok(())
}

#[test]
fn test_092_received_directory_named_as_file_path_is_preserved_when_encode_fails() -> Result<()> {
    let dir = fresh_dir("received_path_is_dir")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(incoming_path(&dir))?;

    let msg = valid_shape_message(92_u128, "line cap before open")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert!(incoming_path(&dir).is_dir());
    Ok(())
}

#[test]
fn test_093_sent_directory_named_as_file_path_is_preserved_when_encode_fails() -> Result<()> {
    let dir = fresh_dir("sent_path_is_dir")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(outgoing_path(&dir))?;

    let msg = valid_shape_message(93_u128, "line cap before open")?;

    assert!(save_outgoing_chat(&opts, &msg).is_err());
    assert!(outgoing_path(&dir).is_dir());
    Ok(())
}

/* ───────────────────────── final combined scenarios ───────────────────── */

#[test]
fn test_094_combined_repeated_error_precedence_stays_stable() -> Result<()> {
    let dir = fresh_dir("combined_repeated_precedence")?;
    let opts = opts_for_dir(&dir);

    for round in 0_usize..8_usize {
        let json_too_large = message_with_json_len(
            94_u128 + u128::try_from(round)?,
            MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
            0_usize,
        );
        assert_io_error_contains(
            save_incoming_chat(&opts, &json_too_large),
            io::ErrorKind::InvalidData,
            "chat.json too large for logging",
        )?;

        let bad_sig = message_with_json_len(194_u128 + u128::try_from(round)?, 1_usize, 0_usize);
        assert_io_error_contains(
            save_outgoing_chat(&opts, &bad_sig),
            io::ErrorKind::InvalidData,
            "chat.signature invalid length",
        )?;

        let line_cap = message_with_json_len(
            294_u128 + u128::try_from(round)?,
            1_usize,
            ml_dsa_65::SIG_LEN,
        );
        assert_io_error_contains(
            save_incoming_chat(&opts, &line_cap),
            io::ErrorKind::InvalidData,
            "chat JSONL line too large",
        )?;
    }

    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_095_combined_existing_logs_survive_mixed_rejection_sequence() -> Result<()> {
    let dir = fresh_dir("combined_existing_logs_survive")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"in\n")?;
    fs::write(outgoing_path(&dir), b"out\n")?;

    let json_too_large = message_with_json_len(
        95_u128,
        MAX_CHAT_JSON_BYTES.saturating_add(1_usize),
        ml_dsa_65::SIG_LEN,
    );
    let bad_sig = manual_message(wallet(96_u128), wallet(97_u128), now_ms(), "bad", 0_usize)?;
    let line_cap = valid_shape_message(98_u128, "line cap")?;

    assert!(save_incoming_chat(&opts, &json_too_large).is_err());
    assert!(save_outgoing_chat(&opts, &bad_sig).is_err());
    assert!(save_incoming_chat(&opts, &line_cap).is_err());
    assert!(save_outgoing_chat(&opts, &line_cap).is_err());

    assert_eq!(fs::read_to_string(incoming_path(&dir))?, "in\n");
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "out\n");
    Ok(())
}

#[test]
fn test_096_combined_data_dir_with_newline_name_is_safe_on_rejected_save() -> Result<()> {
    let root = fresh_dir("newline_dir_root")?;
    let dir = root.join("line\nbreak");
    let opts = opts_for_dir(&dir);
    let msg = valid_shape_message(96_u128, "newline path")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert_path_missing(&chat_dir(&dir));
    Ok(())
}

#[test]
fn test_097_combined_json_chat_dir_preserves_multiple_unrelated_files() -> Result<()> {
    let dir = fresh_dir("multiple_unrelated_files")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(chat_dir(&dir))?;

    let first = chat_dir(&dir).join("a.txt");
    let second = chat_dir(&dir).join("b.txt");
    fs::write(&first, b"a")?;
    fs::write(&second, b"b")?;

    let msg = valid_shape_message(97_u128, "line cap")?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert!(save_outgoing_chat(&opts, &msg).is_err());

    assert_eq!(fs::read_to_string(first)?, "a");
    assert_eq!(fs::read_to_string(second)?, "b");
    Ok(())
}

#[test]
fn test_098_combined_mutated_valid_shape_message_reaches_line_cap_for_both_directions() -> Result<()>
{
    let dir = fresh_dir("mutated_valid_shape_both")?;
    let opts = opts_for_dir(&dir);
    let mut msg = valid_shape_message(98_u128, "mutated")?;

    msg.from_wallet = "not-a-wallet".to_owned();
    msg.to_wallet = "also-not-a-wallet".to_owned();
    msg.timestamp_ms = 0_u64;
    msg.json = vec![0_u8; 16_usize];
    msg.signature = vec![0xaa_u8; ml_dsa_65::SIG_LEN];

    assert_io_error_contains(
        save_incoming_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    assert_io_error_contains(
        save_outgoing_chat(&opts, &msg),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    Ok(())
}

#[test]
fn test_099_combined_short_signature_message_has_no_filesystem_side_effects_anywhere() -> Result<()>
{
    let dir = fresh_dir("short_sig_no_side_effects")?;
    let opts = opts_for_dir(&dir);
    let msg = manual_message(wallet(99_u128), wallet(100_u128), now_ms(), "bad", 1_usize)?;

    assert!(save_incoming_chat(&opts, &msg).is_err());
    assert!(save_outgoing_chat(&opts, &msg).is_err());

    assert_path_missing(&chat_dir(&dir));
    assert_path_missing(&incoming_path(&dir));
    assert_path_missing(&outgoing_path(&dir));
    Ok(())
}

#[test]
fn test_100_combined_adversarial_chat_store_rejection_path_is_safe() -> Result<()> {
    let dir = fresh_dir("combined_final_rejection_path")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(chat_dir(&dir))?;
    fs::write(incoming_path(&dir), b"old incoming\n")?;
    fs::write(outgoing_path(&dir), b"old outgoing\n")?;
    fs::write(chat_dir(&dir).join("notes.txt"), b"keep")?;

    let mut valid_shape = valid_shape_message(100_u128, "final path")?;
    valid_shape.from_wallet = String::new();
    valid_shape.to_wallet = String::new();
    valid_shape.timestamp_ms = u64::MAX;
    valid_shape.json = b"{not json".to_vec();
    valid_shape.signature = vec![0xff_u8; ml_dsa_65::SIG_LEN];

    assert_io_error_contains(
        save_incoming_chat(&opts, &valid_shape),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;
    assert_io_error_contains(
        save_outgoing_chat(&opts, &valid_shape),
        io::ErrorKind::InvalidData,
        "chat JSONL line too large",
    )?;

    assert_eq!(fs::read_to_string(incoming_path(&dir))?, "old incoming\n");
    assert_eq!(fs::read_to_string(outgoing_path(&dir))?, "old outgoing\n");
    assert_eq!(
        fs::read_to_string(chat_dir(&dir).join("notes.txt"))?,
        "keep"
    );
    Ok(())
}
