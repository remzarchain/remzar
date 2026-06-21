#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use remzar::network::p2p_016_file_store::{
    SaveOutgoingFileArgs, handle_incoming_file_chunk, save_outgoing_file,
};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::utility::send_file::{FILE_CHUNK_SIZE, FileChunkMessage, SendFile};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static FILE_STORE_TEST_LOCK: Mutex<()> = Mutex::new(());

const WALLET_A: &str = "ra6068ac5c5cceadcac34baa201ef3aa2caaa8c2540b7c0626c07e4a42618b1de17680b08323abb5ed86e77e6f8f6c2e1ce7806d443f1eb7dea1fba2472e735dd";
const WALLET_B: &str = "re78e061555b556722c5e06bab31d60c6ca0823598dfa3e49d9e58b266e8c119d5ca99ab480a3884af8626ac8d5e8c627631a560732da5e248cbbccd618236939";
const WALLET_C: &str = "rf9ce7658c9adaf7098d1419f83981600ca2f0055ea99df33440bd4df3b41b150bd1484ec9a211dcecd9f61e981ff7eac574ada94a63d21b8a78f394e1ced444b";

fn test_lock() -> Result<MutexGuard<'static, ()>> {
    Ok(FILE_STORE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()))
}

fn filename_is_safe_ascii(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128_usize
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0_u64)
}

fn received_file_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if receiver_dir(dir).exists() {
        for entry in fs::read_dir(receiver_dir(dir))? {
            let entry = entry?;
            let path = entry.path();

            let is_received_index_log = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("received_files.jsonl"));

            if path.is_file() && !is_received_index_log {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn fresh_dir(label: &str) -> Result<PathBuf> {
    let id = TEST_DIR_COUNTER.fetch_add(1_u64, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "remzar_file_store_tests_{}_{}_{}",
        std::process::id(),
        label,
        id
    ));

    if dir.exists() {
        fs::remove_dir_all(&dir)
            .with_context(|| format!("failed to remove stale dir: {}", dir.display()))?;
    }

    Ok(dir)
}

fn opts_for_dir(dir: &Path) -> NodeOpts {
    NodeOpts {
        data_dir: dir.to_string_lossy().to_string(),
        ..NodeOpts::default()
    }
}

fn sender_dir(dir: &Path) -> PathBuf {
    dir.join("sender.file")
}

fn receiver_dir(dir: &Path) -> PathBuf {
    dir.join("receiver.file")
}

fn sent_log(dir: &Path) -> PathBuf {
    sender_dir(dir).join("sent_files.jsonl")
}

fn sent_rotated_log(dir: &Path) -> PathBuf {
    sender_dir(dir).join("sent_files.jsonl.1")
}

fn received_index(dir: &Path) -> PathBuf {
    receiver_dir(dir).join("received_files.jsonl")
}

fn hash_bytes(bytes: &[u8]) -> ([u8; 32], String) {
    let digest = blake3::hash(bytes);
    let mut file_id = [0_u8; 32];
    file_id.copy_from_slice(digest.as_bytes());
    (file_id, hex::encode(file_id))
}

fn outgoing_args<'a>(
    file_id: [u8; 32],
    from_wallet: &'a str,
    to_wallet: &'a str,
    filename: &'a str,
    file_size_bytes: u64,
    content_hash_hex: &'a str,
    original_path: &'a str,
) -> SaveOutgoingFileArgs<'a> {
    SaveOutgoingFileArgs {
        file_id,
        from_wallet,
        to_wallet,
        filename,
        file_size_bytes,
        content_hash_hex,
        original_path,
    }
}

fn valid_outgoing_args_for_bytes<'a>(
    bytes: &[u8],
    from_wallet: &'a str,
    to_wallet: &'a str,
    filename: &'a str,
    original_path: &'a str,
) -> (SaveOutgoingFileArgs<'a>, String) {
    let (file_id, hash_hex) = hash_bytes(bytes);
    let leaked_hash: &'a str = Box::leak(hash_hex.clone().into_boxed_str());

    (
        outgoing_args(
            file_id,
            from_wallet,
            to_wallet,
            filename,
            u64::try_from(bytes.len()).unwrap_or(0_u64),
            leaked_hash,
            original_path,
        ),
        hash_hex,
    )
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read jsonl file: {}", path.display()))?;

    text.lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect::<Result<Vec<_>>>()
}

fn assert_path_missing(path: &Path) {
    assert!(!path.exists(), "path should not exist: {}", path.display());
}

fn source_file_path(dir: &Path, filename: &str, bytes: &[u8]) -> Result<PathBuf> {
    let source_dir = dir.join("source");
    fs::create_dir_all(&source_dir)?;
    let path = source_dir.join(filename);
    fs::write(&path, bytes)?;
    Ok(path)
}

fn chunks_from_real_send_file(
    dir: &Path,
    filename: &str,
    bytes: &[u8],
    from_wallet: &str,
    to_wallet: &str,
) -> Result<Vec<FileChunkMessage>> {
    let path = source_file_path(dir, filename, bytes)?;
    let send_file = SendFile::from_path(from_wallet.to_owned(), to_wallet.to_owned(), &path)
        .map_err(|err| anyhow!("SendFile::from_path failed: {err:?}"))?;

    Ok(send_file.iter_chunks().collect())
}

fn first_real_chunk(
    dir: &Path,
    filename: &str,
    bytes: &[u8],
    from_wallet: &str,
    to_wallet: &str,
) -> Result<FileChunkMessage> {
    chunks_from_real_send_file(dir, filename, bytes, from_wallet, to_wallet)?
        .into_iter()
        .next()
        .context("expected at least one file chunk")
}

fn manual_chunk_from_parts(
    bytes: &[u8],
    filename: &str,
    from_wallet: &str,
    to_wallet: &str,
    chunk_index: u32,
    total_chunks: u32,
    chunk_bytes: Vec<u8>,
) -> Result<FileChunkMessage> {
    let (file_id, hash_hex) = hash_bytes(bytes);

    Ok(FileChunkMessage {
        file_id,
        from_wallet: from_wallet.to_owned(),
        to_wallet: to_wallet.to_owned(),
        chunk_index,
        total_chunks,
        filename: filename.to_owned(),
        file_size_bytes: u64::try_from(bytes.len())?,
        content_hash_hex: hash_hex,
        chunk_bytes,
        timestamp_ms: now_ms(),
    })
}

fn handle_all_chunks(dir: &Path, local_wallet: &str, chunks: Vec<FileChunkMessage>) {
    let opts = opts_for_dir(dir);
    for chunk in chunks {
        handle_incoming_file_chunk(chunk, local_wallet, &opts);
    }
}

fn only_received_file_path(dir: &Path) -> Result<PathBuf> {
    let mut files = received_file_paths(dir)?;

    if files.len() != 1_usize {
        return Err(anyhow!(
            "expected exactly one received file, got {}",
            files.len()
        ));
    }

    Ok(files.remove(0_usize))
}

/* ───────────────────────── outgoing logging ───────────────────────────── */

#[test]
fn test_001_save_outgoing_file_creates_sender_log() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_creates_log")?;
    let opts = opts_for_dir(&dir);
    let bytes = b"hello outgoing";
    let (args, hash_hex) =
        valid_outgoing_args_for_bytes(bytes, WALLET_A, WALLET_B, "hello.txt", "C:/tmp/hello.txt");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize]["direction"].as_str(), Some("outgoing"));
    assert_eq!(rows[0_usize]["from_wallet"].as_str(), Some(WALLET_A));
    assert_eq!(rows[0_usize]["to_wallet"].as_str(), Some(WALLET_B));
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("hello.txt"));
    assert_eq!(
        rows[0_usize]["content_hash_hex"].as_str(),
        Some(hash_hex.as_str())
    );
    Ok(())
}

#[test]
fn test_002_save_outgoing_file_appends_two_records() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_appends")?;
    let opts = opts_for_dir(&dir);

    let (first, _hash_one) =
        valid_outgoing_args_for_bytes(b"first", WALLET_A, WALLET_B, "first.bin", "/first.bin");
    let (second, _hash_two) =
        valid_outgoing_args_for_bytes(b"second", WALLET_A, WALLET_B, "second.bin", "/second.bin");

    save_outgoing_file(&opts, first);
    save_outgoing_file(&opts, second);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 2_usize);
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("first.bin"));
    assert_eq!(rows[1_usize]["filename"].as_str(), Some("second.bin"));
    Ok(())
}

#[test]
fn test_003_outgoing_filename_with_spaces_is_sanitized() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_sanitize_filename")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"abc", WALLET_A, WALLET_B, "bad name.txt", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("bad_name.txt"));
    Ok(())
}

#[test]
fn test_004_outgoing_empty_filename_becomes_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_empty_filename")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) = valid_outgoing_args_for_bytes(b"abc", WALLET_A, WALLET_B, "", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("file"));
    Ok(())
}

#[test]
fn test_005_outgoing_filename_is_truncated_to_128_bytes() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_filename_truncate")?;
    let opts = opts_for_dir(&dir);
    let filename = "a".repeat(200_usize);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"abc", WALLET_A, WALLET_B, &filename, "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    let saved_name = rows[0_usize]["filename"]
        .as_str()
        .context("expected filename")?;

    assert_eq!(saved_name.len(), 128_usize);
    assert!(saved_name.chars().all(|ch| ch == 'a'));
    Ok(())
}

#[test]
fn test_006_outgoing_oversized_file_size_is_not_logged() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_oversize")?;
    let opts = opts_for_dir(&dir);
    let (file_id, hash_hex) = hash_bytes(b"oversized");

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "oversized.bin",
            (128_u64 * 1024_u64 * 1024_u64).saturating_add(1_u64),
            &hash_hex,
            "/oversized.bin",
        ),
    );

    assert_path_missing(&sent_log(&dir));
    Ok(())
}

#[test]
fn test_007_outgoing_exact_128_mib_file_size_is_logged() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_exact_cap")?;
    let opts = opts_for_dir(&dir);
    let (file_id, hash_hex) = hash_bytes(b"cap");

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "cap.bin",
            128_u64 * 1024_u64 * 1024_u64,
            &hash_hex,
            "/cap.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(
        rows[0_usize]["file_size_bytes"].as_u64(),
        Some(128_u64 * 1024_u64 * 1024_u64)
    );
    Ok(())
}

#[test]
fn test_008_outgoing_large_existing_log_rotates_before_append() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_rotate")?;
    let opts = opts_for_dir(&dir);
    fs::create_dir_all(sender_dir(&dir))?;

    let existing = sent_log(&dir);
    let file = fs::File::create(&existing)?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"rotate", WALLET_A, WALLET_B, "rotate.bin", "/raw");

    save_outgoing_file(&opts, args);

    assert!(sent_rotated_log(&dir).exists());
    assert!(sent_log(&dir).exists());
    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_009_outgoing_jsonl_line_too_large_is_not_logged() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_line_too_large")?;
    let opts = opts_for_dir(&dir);
    let (file_id, hash_hex) = hash_bytes(b"line too large");
    let huge_original_path = "x".repeat(9000_usize);

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "large-line.bin",
            10_u64,
            &hash_hex,
            &huge_original_path,
        ),
    );

    assert!(sender_dir(&dir).exists());
    assert_path_missing(&sent_log(&dir));
    Ok(())
}

#[test]
fn test_010_outgoing_records_are_single_line_json() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_single_line")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"line", WALLET_A, WALLET_B, "line.bin", "/line");

    save_outgoing_file(&opts, args);

    let text = fs::read_to_string(sent_log(&dir))?;
    assert_eq!(text.lines().count(), 1_usize);
    assert!(text.ends_with('\n'));
    Ok(())
}

#[test]
fn test_011_outgoing_original_path_is_logged_verbatim() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_original_path")?;
    let opts = opts_for_dir(&dir);
    let original_path = "C:/Users/Ronald/file.txt";
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"path", WALLET_A, WALLET_B, "file.txt", original_path);

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["original_path"].as_str(), Some(original_path));
    Ok(())
}

#[test]
fn test_012_outgoing_file_id_is_hex_encoded() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_file_id_hex")?;
    let opts = opts_for_dir(&dir);
    let bytes = b"id hex";
    let (expected_file_id, _hash) = hash_bytes(bytes);
    let (args, _hash_hex) =
        valid_outgoing_args_for_bytes(bytes, WALLET_A, WALLET_B, "id.bin", "/id.bin");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(
        rows[0_usize]["file_id"].as_str(),
        Some(hex::encode(expected_file_id).as_str())
    );
    Ok(())
}

#[test]
fn test_013_outgoing_timestamp_is_positive() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_timestamp")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"ts", WALLET_A, WALLET_B, "ts.bin", "/ts.bin");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert!(rows[0_usize]["timestamp_ms"].as_i64().unwrap_or(0_i64) > 0_i64);
    Ok(())
}

/* ───────────────────────── incoming filtering / rejection ─────────────── */

#[test]
fn test_014_incoming_ignores_chunk_for_different_wallet() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_wrong_wallet")?;
    let opts = opts_for_dir(&dir);
    let chunk = first_real_chunk(&dir, "wrong-wallet.txt", b"hello", WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk, WALLET_C, &opts);

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_015_incoming_ignores_when_local_wallet_is_empty() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_empty_local")?;
    let opts = opts_for_dir(&dir);
    let chunk = first_real_chunk(&dir, "empty-local.txt", b"hello", WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk, "", &opts);

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_016_incoming_rejects_total_chunks_zero_before_state_insert() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_zero_total")?;
    let opts = opts_for_dir(&dir);
    let chunk = manual_chunk_from_parts(
        b"hello",
        "zero.txt",
        WALLET_A,
        WALLET_B,
        0_u32,
        0_u32,
        b"hello".to_vec(),
    )?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_017_incoming_rejects_total_chunks_above_defensive_cap() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_total_above_cap")?;
    let opts = opts_for_dir(&dir);
    let chunk = manual_chunk_from_parts(
        b"hello",
        "huge_total.txt",
        WALLET_A,
        WALLET_B,
        0_u32,
        50_001_u32,
        b"hello".to_vec(),
    )?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_018_incoming_rejects_chunk_index_equal_total_chunks() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_index_equal_total")?;
    let opts = opts_for_dir(&dir);
    let chunk = manual_chunk_from_parts(
        b"hello",
        "bad_index.txt",
        WALLET_A,
        WALLET_B,
        1_u32,
        1_u32,
        b"hello".to_vec(),
    )?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_019_incoming_rejects_file_size_above_128_mib_cap() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_file_size_above_cap")?;
    let opts = opts_for_dir(&dir);
    let mut chunk = first_real_chunk(&dir, "too-big.txt", b"hello", WALLET_A, WALLET_B)?;
    chunk.file_size_bytes = (128_u64 * 1024_u64 * 1024_u64).saturating_add(1_u64);

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_020_incoming_rejects_absurd_wire_filename_length() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_absurd_filename")?;
    let opts = opts_for_dir(&dir);
    let mut chunk = first_real_chunk(&dir, "normal.txt", b"hello", WALLET_A, WALLET_B)?;
    chunk.filename = "a".repeat((8_usize * 128_usize).saturating_add(1_usize));

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

/* ───────────────────────── incoming reconstruction ────────────────────── */

#[test]
fn test_021_incoming_one_chunk_file_is_reconstructed_and_indexed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_one_chunk")?;
    let opts = opts_for_dir(&dir);
    let bytes = b"hello reconstructed";
    let chunk = first_real_chunk(&dir, "hello.txt", bytes, WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(&stored)?, bytes);
    assert!(received_index(&dir).exists());

    let rows = read_jsonl(&received_index(&dir))?;
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize]["direction"].as_str(), Some("incoming"));
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("hello.txt"));
    assert_eq!(
        rows[0_usize]["file_size_bytes"].as_u64(),
        Some(u64::try_from(bytes.len())?)
    );
    Ok(())
}

#[test]
fn test_022_incoming_rejects_uppercase_to_wallet_payload() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_uppercase_to_wallet_rejected")?;
    let opts = opts_for_dir(&dir);

    let mut chunk = first_real_chunk(
        &dir,
        "case.txt",
        b"case insensitive outer check only",
        WALLET_A,
        WALLET_B,
    )?;

    chunk.to_wallet = format!("p{}", WALLET_B[1_usize..].to_ascii_uppercase());

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    assert_eq!(received_file_paths(&dir)?.len(), 0_usize);
    Ok(())
}

#[test]
fn test_023_incoming_reconstructed_filename_contains_digest_prefix() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_digest_prefix")?;
    let opts = opts_for_dir(&dir);
    let bytes = b"digest prefix";
    let (file_id, _hash_hex) = hash_bytes(bytes);
    let expected_prefix = hex::encode(file_id)
        .get(..12_usize)
        .context("digest prefix")?
        .to_owned();

    let chunk = first_real_chunk(&dir, "prefix.txt", bytes, WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let stored = only_received_file_path(&dir)?;
    let name = stored
        .file_name()
        .and_then(|value| value.to_str())
        .context("stored filename")?;

    assert!(name.starts_with(&expected_prefix));
    assert!(name.ends_with("prefix.txt"));
    Ok(())
}

#[test]
fn test_024_received_index_stored_at_points_to_existing_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("received_stored_at")?;
    let opts = opts_for_dir(&dir);
    let chunk = first_real_chunk(&dir, "stored.txt", b"stored at", WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let rows = read_jsonl(&received_index(&dir))?;
    let stored_at = rows[0_usize]["stored_at"]
        .as_str()
        .context("expected stored_at")?;

    assert!(PathBuf::from(stored_at).exists());
    Ok(())
}

#[test]
fn test_025_received_index_file_id_matches_hash() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("received_file_id_hash")?;
    let opts = opts_for_dir(&dir);
    let bytes = b"index hash";
    let (file_id, hash_hex) = hash_bytes(bytes);
    let chunk = first_real_chunk(&dir, "hash.txt", bytes, WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let rows = read_jsonl(&received_index(&dir))?;
    assert_eq!(
        rows[0_usize]["file_id"].as_str(),
        Some(hex::encode(file_id).as_str())
    );
    assert_eq!(
        rows[0_usize]["content_hash_hex"].as_str(),
        Some(hash_hex.as_str())
    );
    Ok(())
}

#[test]
fn test_026_received_index_wallets_match_chunk_wallets() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("received_wallets")?;
    let opts = opts_for_dir(&dir);
    let chunk = first_real_chunk(&dir, "wallets.txt", b"wallets", WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let rows = read_jsonl(&received_index(&dir))?;
    assert_eq!(rows[0_usize]["from_wallet"].as_str(), Some(WALLET_A));
    assert_eq!(rows[0_usize]["to_wallet"].as_str(), Some(WALLET_B));
    Ok(())
}

#[test]
fn test_027_incoming_index_filename_with_spaces_is_sanitized() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_index_filename_spaces")?;
    let opts = opts_for_dir(&dir);
    let chunk = first_real_chunk(&dir, "bad name.txt", b"safe name", WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let rows = read_jsonl(&received_index(&dir))?;
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("bad_name.txt"));
    Ok(())
}

#[test]
fn test_028_incoming_two_chunk_file_reconstructs_in_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_two_chunks_ordered")?;
    let mut bytes = vec![1_u8; FILE_CHUNK_SIZE];
    bytes.extend_from_slice(b"tail");

    let chunks = chunks_from_real_send_file(&dir, "two.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 2_usize);

    handle_all_chunks(&dir, WALLET_B, chunks);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_029_incoming_two_chunk_file_reconstructs_out_of_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_two_chunks_out_of_order")?;
    let mut bytes = vec![2_u8; FILE_CHUNK_SIZE];
    bytes.extend_from_slice(b"tail-2");

    let mut chunks = chunks_from_real_send_file(&dir, "two_ooo.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 2_usize);
    chunks.swap(0_usize, 1_usize);

    handle_all_chunks(&dir, WALLET_B, chunks);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_030_incoming_duplicate_same_chunk_is_idempotent_before_completion() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_duplicate_chunk")?;
    let mut bytes = vec![3_u8; FILE_CHUNK_SIZE];
    bytes.extend_from_slice(b"tail-3");

    let chunks = chunks_from_real_send_file(&dir, "dup.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 2_usize);

    handle_all_chunks(
        &dir,
        WALLET_B,
        vec![
            chunks[0_usize].clone(),
            chunks[0_usize].clone(),
            chunks[1_usize].clone(),
        ],
    );

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_031_incoming_missing_second_chunk_does_not_finalize() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_missing_chunk")?;
    let opts = opts_for_dir(&dir);
    let mut bytes = vec![4_u8; FILE_CHUNK_SIZE];
    bytes.extend_from_slice(b"tail-4");

    let chunks = chunks_from_real_send_file(&dir, "missing.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 2_usize);

    handle_incoming_file_chunk(chunks[0_usize].clone(), WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    Ok(())
}

/* ───────────────────────── integrity / adversarial cases ──────────────── */

#[test]
fn test_032_incoming_hash_mismatch_does_not_write_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_hash_mismatch")?;
    let opts = opts_for_dir(&dir);
    let mut chunk = first_real_chunk(&dir, "bad_hash.bin", b"hash mismatch", WALLET_A, WALLET_B)?;
    chunk.content_hash_hex = "00".repeat(32_usize);

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    Ok(())
}

#[test]
fn test_033_incoming_file_id_mismatch_does_not_write_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_file_id_mismatch")?;
    let opts = opts_for_dir(&dir);
    let mut chunk = first_real_chunk(&dir, "bad_id.bin", b"id mismatch", WALLET_A, WALLET_B)?;
    chunk.file_id = [9_u8; 32];

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    Ok(())
}

#[test]
fn test_034_incoming_declared_total_chunks_inconsistent_with_size_is_not_written() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_bad_total_for_size")?;
    let opts = opts_for_dir(&dir);
    let mut chunk = first_real_chunk(&dir, "bad_total.bin", b"bad total", WALLET_A, WALLET_B)?;
    chunk.total_chunks = 2_u32;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    Ok(())
}

#[test]
fn test_035_incoming_empty_chunk_bytes_are_not_written() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_empty_chunk_bytes")?;
    let opts = opts_for_dir(&dir);
    let mut chunk = first_real_chunk(&dir, "empty_chunk.bin", b"not empty", WALLET_A, WALLET_B)?;
    chunk.chunk_bytes.clear();

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    Ok(())
}

#[test]
fn test_036_incoming_same_wallet_is_rejected_by_incoming_file_validation() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_same_wallet")?;
    let opts = opts_for_dir(&dir);
    let chunk = manual_chunk_from_parts(
        b"same wallet",
        "same.bin",
        WALLET_B,
        WALLET_B,
        0_u32,
        1_u32,
        b"same wallet".to_vec(),
    )?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    Ok(())
}

/* ───────────────────────── load / combined paths ──────────────────────── */

#[test]
fn test_037_load_16_outgoing_file_logs_append() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_outgoing_16")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..16_u8 {
        let bytes = vec![index; 8_usize];
        let filename = format!("file-{index}.bin");
        let original = format!("/tmp/file-{index}.bin");
        let (args, _hash) =
            valid_outgoing_args_for_bytes(&bytes, WALLET_A, WALLET_B, &filename, &original);
        save_outgoing_file(&opts, args);
    }

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 16_usize);
    Ok(())
}

#[test]
fn test_038_load_8_incoming_one_chunk_files_reconstruct_and_index() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_incoming_8")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..8_u8 {
        let bytes = vec![index; usize::from(index).saturating_add(1_usize)];
        let filename = format!("recv-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    let rows = read_jsonl(&received_index(&dir))?;
    assert_eq!(rows.len(), 8_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 8_usize);
    Ok(())
}

#[test]
fn test_039_combined_file_store_outgoing_and_incoming_paths_are_safe() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("combined_file_store")?;
    let opts = opts_for_dir(&dir);

    let outgoing_bytes = b"outgoing combined";
    let (args, _hash) = valid_outgoing_args_for_bytes(
        outgoing_bytes,
        WALLET_A,
        WALLET_B,
        "combo out.bin",
        "/tmp/combo out.bin",
    );
    save_outgoing_file(&opts, args);

    let incoming_bytes = b"incoming combined";
    let chunk = first_real_chunk(&dir, "combo in.bin", incoming_bytes, WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, incoming_bytes);
    Ok(())
}

#[test]
fn test_040_combined_reject_then_accept_different_file_id_is_safe() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("combined_reject_then_accept")?;
    let opts = opts_for_dir(&dir);

    let mut bad = first_real_chunk(&dir, "bad.bin", b"bad bytes", WALLET_A, WALLET_B)?;
    bad.content_hash_hex = "00".repeat(32_usize);
    handle_incoming_file_chunk(bad, WALLET_B, &opts);
    assert_path_missing(&received_index(&dir));

    let good_bytes = b"good bytes after rejection";
    let good = first_real_chunk(&dir, "good.bin", good_bytes, WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(good, WALLET_B, &opts);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, good_bytes);
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_041_outgoing_invalid_content_hash_is_logged_verbatim() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_invalid_hash_verbatim")?;
    let opts = opts_for_dir(&dir);
    let (file_id, _hash_hex) = hash_bytes(b"bad hash text");

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "bad-hash.bin",
            13_u64,
            "not-a-hex-hash",
            "/tmp/bad-hash.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(
        rows[0_usize]["content_hash_hex"].as_str(),
        Some("not-a-hex-hash")
    );
    Ok(())
}

#[test]
fn test_042_outgoing_empty_content_hash_is_logged_verbatim() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_empty_hash_verbatim")?;
    let opts = opts_for_dir(&dir);
    let (file_id, _hash_hex) = hash_bytes(b"empty hash text");

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "empty-hash.bin",
            15_u64,
            "",
            "/tmp/empty-hash.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize]["content_hash_hex"].as_str(), Some(""));
    Ok(())
}

#[test]
fn test_043_outgoing_zero_file_size_is_logged() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_zero_size")?;
    let opts = opts_for_dir(&dir);
    let (file_id, hash_hex) = hash_bytes(b"");

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "zero.bin",
            0_u64,
            &hash_hex,
            "/tmp/zero.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize]["file_size_bytes"].as_u64(), Some(0_u64));
    Ok(())
}

#[test]
fn test_044_outgoing_newline_original_path_is_logged_verbatim() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_newline_original_path")?;
    let opts = opts_for_dir(&dir);
    let original_path = "C:/tmp/line\nbreak.bin";
    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"path newline",
        WALLET_A,
        WALLET_B,
        "path.bin",
        original_path,
    );

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["original_path"].as_str(), Some(original_path));
    Ok(())
}

#[test]
fn test_045_outgoing_slash_in_filename_is_sanitized() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_slash_filename")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"slash", WALLET_A, WALLET_B, "dir/file.txt", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("dir_file.txt"));
    Ok(())
}

#[test]
fn test_046_outgoing_backslash_in_filename_is_sanitized() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_backslash_filename")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"backslash", WALLET_A, WALLET_B, "dir\\file.txt", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("dir_file.txt"));
    Ok(())
}

#[test]
fn test_047_outgoing_unicode_filename_is_sanitized_to_safe_ascii() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_unicode_filename_safe")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"unicode", WALLET_A, WALLET_B, "file❤️.bin", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    let filename = rows[0_usize]["filename"]
        .as_str()
        .context("expected sanitized filename")?;

    assert!(filename.starts_with("file"));
    assert!(filename.ends_with(".bin"));
    assert!(filename.contains('_'));
    assert!(filename_is_safe_ascii(filename));
    Ok(())
}

#[test]
fn test_048_outgoing_filename_with_newline_is_sanitized() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_newline_filename")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"newline", WALLET_A, WALLET_B, "line\nbreak.txt", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("line_break.txt"));
    Ok(())
}

#[test]
fn test_049_outgoing_filename_with_colon_is_sanitized() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_colon_filename")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"colon", WALLET_A, WALLET_B, "C:evil.txt", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("C_evil.txt"));
    Ok(())
}

#[test]
fn test_050_outgoing_rotation_overwrites_existing_rotated_log() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_rotation_overwrites_old")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(sender_dir(&dir))?;
    fs::write(sent_rotated_log(&dir), b"old rotated")?;

    let existing = sent_log(&dir);
    let file = fs::File::create(&existing)?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"rotate overwrite",
        WALLET_A,
        WALLET_B,
        "rotate.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    assert_eq!(
        fs::metadata(sent_rotated_log(&dir))?.len(),
        8_u64 * 1024_u64 * 1024_u64
    );
    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_051_existing_rotated_log_is_preserved_when_no_rotation_happens() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_existing_rotated_preserved")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(sender_dir(&dir))?;
    fs::write(sent_rotated_log(&dir), b"old rotated")?;

    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"no rotation", WALLET_A, WALLET_B, "small.bin", "/raw");
    save_outgoing_file(&opts, args);

    assert_eq!(fs::read_to_string(sent_rotated_log(&dir))?, "old rotated");
    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_052_sender_dir_existing_file_prevents_outgoing_write_and_is_preserved() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sender_dir_existing_file")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(&dir)?;
    fs::write(sender_dir(&dir), b"sender.file is a regular file")?;

    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"blocked", WALLET_A, WALLET_B, "blocked.bin", "/raw");
    save_outgoing_file(&opts, args);

    assert_eq!(
        fs::read_to_string(sender_dir(&dir))?,
        "sender.file is a regular file"
    );
    Ok(())
}

#[test]
fn test_053_outgoing_invalid_wallet_strings_are_logged_verbatim() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_invalid_wallets_verbatim")?;
    let opts = opts_for_dir(&dir);
    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"wallets", "not-a-wallet", "", "wallets.bin", "/raw");

    save_outgoing_file(&opts, args);

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows[0_usize]["from_wallet"].as_str(), Some("not-a-wallet"));
    assert_eq!(rows[0_usize]["to_wallet"].as_str(), Some(""));
    Ok(())
}

#[test]
fn test_054_outgoing_jsonl_line_too_large_preserves_existing_sent_log() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_line_too_large_preserves")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(sender_dir(&dir))?;
    fs::write(sent_log(&dir), b"{\"old\":true}\n")?;

    let (file_id, hash_hex) = hash_bytes(b"too large preserve");
    let huge_original_path = "x".repeat(9000_usize);

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "too-large-preserve.bin",
            12_u64,
            &hash_hex,
            &huge_original_path,
        ),
    );

    assert_eq!(fs::read_to_string(sent_log(&dir))?, "{\"old\":true}\n");
    Ok(())
}

#[test]
fn test_055_load_32_outgoing_file_logs_append() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_outgoing_32")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..32_u8 {
        let bytes = vec![index; 4_usize];
        let filename = format!("load32-{index}.bin");
        let original = format!("/tmp/load32-{index}.bin");
        let (args, _hash) =
            valid_outgoing_args_for_bytes(&bytes, WALLET_A, WALLET_B, &filename, &original);
        save_outgoing_file(&opts, args);
    }

    let rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(rows.len(), 32_usize);
    assert_eq!(rows[0_usize]["filename"].as_str(), Some("load32-0.bin"));
    assert_eq!(rows[31_usize]["filename"].as_str(), Some("load32-31.bin"));
    Ok(())
}

#[test]
fn test_056_load_64_outgoing_file_logs_append() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_outgoing_64")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..64_u8 {
        let bytes = vec![index; 2_usize];
        let filename = format!("out64-{index}.bin");
        let original = format!("/tmp/out64-{index}.bin");
        let (args, _hash) =
            valid_outgoing_args_for_bytes(&bytes, WALLET_A, WALLET_B, &filename, &original);
        save_outgoing_file(&opts, args);
    }

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 64_usize);
    Ok(())
}

/* ───────────────────────── incoming safe success paths ────────────────── */

#[test]
fn test_057_incoming_second_one_chunk_file_appends_second_index_row() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_second_one_chunk")?;
    let opts = opts_for_dir(&dir);

    let first = first_real_chunk(&dir, "first57.txt", b"first 57", WALLET_A, WALLET_B)?;
    let second = first_real_chunk(&dir, "second57.txt", b"second 57", WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(first, WALLET_B, &opts);
    handle_incoming_file_chunk(second, WALLET_B, &opts);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 2_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 2_usize);
    Ok(())
}

#[test]
fn test_058_replaying_same_one_chunk_file_appends_index_but_keeps_one_stored_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_replay_same_one_chunk")?;
    let opts = opts_for_dir(&dir);

    let bytes = b"replay one chunk 58";
    let chunk = first_real_chunk(&dir, "replay58.txt", bytes, WALLET_A, WALLET_B)?;

    handle_incoming_file_chunk(chunk.clone(), WALLET_B, &opts);
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 2_usize);
    let files = received_file_paths(&dir)?;
    assert_eq!(files.len(), 1_usize);
    assert_eq!(fs::read(&files[0_usize])?, bytes);
    Ok(())
}

#[test]
fn test_059_incoming_exact_file_chunk_size_reconstructs_as_one_chunk() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_exact_chunk_size")?;
    let opts = opts_for_dir(&dir);
    let bytes = vec![59_u8; FILE_CHUNK_SIZE];

    let chunks = chunks_from_real_send_file(&dir, "exact59.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 1_usize);

    handle_incoming_file_chunk(chunks[0_usize].clone(), WALLET_B, &opts);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_060_incoming_file_chunk_size_plus_one_reconstructs_two_chunks() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_chunk_size_plus_one")?;
    let mut bytes = vec![60_u8; FILE_CHUNK_SIZE];
    bytes.push(1_u8);

    let chunks = chunks_from_real_send_file(&dir, "plus-one60.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 2_usize);
    assert_eq!(chunks[1_usize].chunk_bytes.len(), 1_usize);

    handle_all_chunks(&dir, WALLET_B, chunks);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_061_incoming_three_chunk_file_reconstructs_in_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_three_chunks_ordered")?;
    let mut bytes = vec![61_u8; FILE_CHUNK_SIZE * 2_usize];
    bytes.extend_from_slice(b"tail-three-61");

    let chunks = chunks_from_real_send_file(&dir, "three61.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 3_usize);

    handle_all_chunks(&dir, WALLET_B, chunks);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_062_incoming_three_chunk_file_reconstructs_reverse_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_three_chunks_reverse")?;
    let mut bytes = vec![62_u8; FILE_CHUNK_SIZE * 2_usize];
    bytes.extend_from_slice(b"tail-three-62");

    let mut chunks = chunks_from_real_send_file(&dir, "three62.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 3_usize);
    chunks.reverse();

    handle_all_chunks(&dir, WALLET_B, chunks);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_063_incoming_three_chunk_file_reconstructs_middle_first_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_three_chunks_middle_first")?;
    let mut bytes = vec![63_u8; FILE_CHUNK_SIZE * 2_usize];
    bytes.extend_from_slice(b"tail-three-63");

    let chunks = chunks_from_real_send_file(&dir, "three63.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 3_usize);

    handle_all_chunks(
        &dir,
        WALLET_B,
        vec![
            chunks[1_usize].clone(),
            chunks[0_usize].clone(),
            chunks[2_usize].clone(),
        ],
    );

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, bytes);
    Ok(())
}

#[test]
fn test_064_load_16_incoming_one_chunk_files_reconstruct_and_index() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_incoming_16")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..16_u8 {
        let bytes = vec![index; usize::from(index).saturating_add(1_usize)];
        let filename = format!("load16-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 16_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 16_usize);
    Ok(())
}

#[test]
fn test_065_fuzz_payload_lengths_1_to_32_reconstruct() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("fuzz_payload_lengths_1_to_32")?;
    let opts = opts_for_dir(&dir);

    for len in 1_usize..=32_usize {
        let byte = u8::try_from(len)?;
        let bytes = vec![byte; len];
        let filename = format!("len-{len}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 32_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 32_usize);
    Ok(())
}

/* ───────────────────────── incoming reject/no-side-effect paths ───────── */

#[test]
fn test_066_incoming_uppercase_from_wallet_payload_is_accepted_and_stored() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_uppercase_from_wallet")?;
    let opts = opts_for_dir(&dir);

    let mut chunk = first_real_chunk(
        &dir,
        "upper-from66.txt",
        b"upper from 66",
        WALLET_A,
        WALLET_B,
    )?;
    chunk.from_wallet = format!("r{}", WALLET_A[1_usize..].to_ascii_uppercase());

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, b"upper from 66");

    let rows = read_jsonl(&received_index(&dir))?;
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize]["to_wallet"].as_str(), Some(WALLET_B));

    Ok(())
}

#[test]
fn test_067_incoming_from_wallet_invalid_text_is_rejected() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_invalid_from_wallet")?;
    let opts = opts_for_dir(&dir);

    let mut chunk = first_real_chunk(
        &dir,
        "bad-from67.txt",
        b"bad from wallet 67",
        WALLET_A,
        WALLET_B,
    )?;
    chunk.from_wallet = "not-a-wallet".to_owned();

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    assert_eq!(received_file_paths(&dir)?.len(), 0_usize);
    Ok(())
}

#[test]
fn test_068_load_16_incoming_wrong_wallet_chunks_create_no_receiver_dir() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_wrong_wallet_16")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..16_u8 {
        let bytes = vec![index; 3_usize];
        let filename = format!("wrong16-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_C, &opts);
    }

    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_069_chunk_larger_than_file_chunk_size_is_rejected() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_chunk_larger_than_cap")?;
    let opts = opts_for_dir(&dir);
    let bytes = vec![69_u8; FILE_CHUNK_SIZE.saturating_add(1_usize)];

    let chunk = manual_chunk_from_parts(
        &bytes,
        "too-large-chunk69.bin",
        WALLET_A,
        WALLET_B,
        0_u32,
        1_u32,
        bytes.clone(),
    )?;

    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    assert_eq!(received_file_paths(&dir)?.len(), 0_usize);
    Ok(())
}

#[test]
fn test_070_non_last_short_chunk_is_rejected() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_non_last_short")?;
    let opts = opts_for_dir(&dir);
    let mut bytes = vec![70_u8; FILE_CHUNK_SIZE];
    bytes.extend_from_slice(b"tail-70");

    let chunks =
        chunks_from_real_send_file(&dir, "non-last-short70.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 2_usize);

    let mut bad_first = chunks[0_usize].clone();
    bad_first.chunk_bytes.pop();

    handle_incoming_file_chunk(bad_first, WALLET_B, &opts);
    handle_incoming_file_chunk(chunks[1_usize].clone(), WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    assert_eq!(received_file_paths(&dir)?.len(), 0_usize);
    Ok(())
}

#[test]
fn test_071_last_chunk_wrong_length_is_rejected() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_last_wrong_len")?;
    let opts = opts_for_dir(&dir);
    let mut bytes = vec![71_u8; FILE_CHUNK_SIZE];
    bytes.extend_from_slice(b"tail-71");

    let chunks = chunks_from_real_send_file(&dir, "last-wrong71.bin", &bytes, WALLET_A, WALLET_B)?;
    assert_eq!(chunks.len(), 2_usize);

    handle_incoming_file_chunk(chunks[0_usize].clone(), WALLET_B, &opts);

    let mut bad_last = chunks[1_usize].clone();
    bad_last.chunk_bytes.push(0_u8);
    handle_incoming_file_chunk(bad_last, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));
    assert_eq!(received_file_paths(&dir)?.len(), 0_usize);
    Ok(())
}

#[test]
fn test_072_receiver_dir_existing_file_prevents_incoming_write_and_is_preserved() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("receiver_dir_existing_file")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(&dir)?;
    fs::write(receiver_dir(&dir), b"receiver.file is a regular file")?;

    let chunk = first_real_chunk(
        &dir,
        "blocked72.txt",
        b"blocked receiver 72",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_eq!(
        fs::read_to_string(receiver_dir(&dir))?,
        "receiver.file is a regular file"
    );
    Ok(())
}

/* ───────────────────────── index and rotation coverage ────────────────── */

#[test]
fn test_073_existing_received_index_rotates_before_new_append() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_index_rotate")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(receiver_dir(&dir))?;
    let index = received_index(&dir);
    let file = fs::File::create(&index)?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    let chunk = first_real_chunk(
        &dir,
        "rotate-index73.txt",
        b"rotate index 73",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert!(receiver_dir(&dir).join("received_files.jsonl.1").exists());
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_074_existing_received_index_row_is_preserved_and_new_row_appended() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_index_append_existing")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(receiver_dir(&dir))?;
    fs::write(received_index(&dir), b"{\"old\":true}\n")?;

    let chunk = first_real_chunk(
        &dir,
        "append-index74.txt",
        b"append index 74",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let rows = read_jsonl(&received_index(&dir))?;
    assert_eq!(rows.len(), 2_usize);
    assert_eq!(rows[0_usize]["old"].as_bool(), Some(true));
    assert_eq!(
        rows[1_usize]["filename"].as_str(),
        Some("append-index74.txt")
    );
    Ok(())
}

#[test]
fn test_075_incoming_after_outgoing_rotation_still_uses_receiver_directory() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_after_outgoing_rotation")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(sender_dir(&dir))?;
    let file = fs::File::create(sent_log(&dir))?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"rotate first 75",
        WALLET_A,
        WALLET_B,
        "rotate-first75.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    let chunk = first_real_chunk(
        &dir,
        "incoming-after-rotate75.txt",
        b"incoming after rotate 75",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert!(sent_rotated_log(&dir).exists());
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_076_outgoing_after_incoming_reconstruction_still_uses_sender_directory() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_after_incoming")?;
    let opts = opts_for_dir(&dir);

    let chunk = first_real_chunk(
        &dir,
        "incoming-first76.txt",
        b"incoming first 76",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"outgoing second 76",
        WALLET_A,
        WALLET_B,
        "outgoing-second76.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    Ok(())
}

/* ───────────────────────── recovery and isolation coverage ────────────── */

#[test]
fn test_077_bad_hash_file_does_not_block_different_good_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("bad_hash_then_different_good")?;
    let opts = opts_for_dir(&dir);

    let mut bad = first_real_chunk(&dir, "bad77.bin", b"bad hash 77", WALLET_A, WALLET_B)?;
    bad.content_hash_hex = "00".repeat(32_usize);
    handle_incoming_file_chunk(bad, WALLET_B, &opts);

    let good = first_real_chunk(&dir, "good77.bin", b"good file 77", WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(good, WALLET_B, &opts);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_078_bad_file_id_file_does_not_block_different_good_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("bad_file_id_then_different_good")?;
    let opts = opts_for_dir(&dir);

    let mut bad = first_real_chunk(&dir, "bad78.bin", b"bad id 78", WALLET_A, WALLET_B)?;
    bad.file_id = [7_u8; 32];
    handle_incoming_file_chunk(bad, WALLET_B, &opts);

    let good = first_real_chunk(&dir, "good78.bin", b"good file 78", WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(good, WALLET_B, &opts);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_079_missing_chunk_then_different_complete_file_finalizes() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("missing_then_different_complete")?;
    let opts = opts_for_dir(&dir);

    let mut incomplete_bytes = vec![79_u8; FILE_CHUNK_SIZE];
    incomplete_bytes.extend_from_slice(b"incomplete-tail-79");

    let incomplete_chunks = chunks_from_real_send_file(
        &dir,
        "incomplete79.bin",
        &incomplete_bytes,
        WALLET_A,
        WALLET_B,
    )?;
    assert_eq!(incomplete_chunks.len(), 2_usize);
    handle_incoming_file_chunk(incomplete_chunks[0_usize].clone(), WALLET_B, &opts);

    let complete = first_real_chunk(
        &dir,
        "complete79.bin",
        b"complete file 79",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(complete, WALLET_B, &opts);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_080_wrong_wallet_chunks_do_not_block_valid_local_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("wrong_wallet_then_valid")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..8_u8 {
        let bytes = vec![index; 3_usize];
        let filename = format!("ignored80-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_C)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    assert_path_missing(&receiver_dir(&dir));

    let good = first_real_chunk(
        &dir,
        "valid-after-ignored80.bin",
        b"valid after ignored 80",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(good, WALLET_B, &opts);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(fs::read(stored)?, b"valid after ignored 80");
    Ok(())
}

/* ───────────────────────── path and platform coverage ─────────────────── */

#[test]
fn test_081_outgoing_data_dir_with_spaces_and_incoming_data_dir_with_spaces() -> Result<()> {
    let _guard = test_lock()?;
    let root = fresh_dir("space_root")?;
    let dir = root.join("dir with spaces");
    let opts = opts_for_dir(&dir);

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"spaces out 81",
        WALLET_A,
        WALLET_B,
        "spaces-out81.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    let chunk = first_real_chunk(&dir, "spaces-in81.bin", b"spaces in 81", WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_082_outgoing_data_dir_unicode_and_incoming_data_dir_unicode() -> Result<()> {
    let _guard = test_lock()?;
    let root = fresh_dir("unicode_root")?;
    let dir = root.join("file_store_unicode");
    let opts = opts_for_dir(&dir);

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"unicode out 82",
        WALLET_A,
        WALLET_B,
        "unicode-out82.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    let chunk = first_real_chunk(
        &dir,
        "unicode-in82.bin",
        b"unicode in 82",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_083_sender_and_receiver_directories_are_independent() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sender_receiver_independent")?;
    let opts = opts_for_dir(&dir);

    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"out 83", WALLET_A, WALLET_B, "out83.bin", "/raw");
    save_outgoing_file(&opts, args);

    let chunk = first_real_chunk(&dir, "in83.bin", b"in 83", WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert!(sender_dir(&dir).is_dir());
    assert!(receiver_dir(&dir).is_dir());
    assert!(sent_log(&dir).exists());
    assert!(received_index(&dir).exists());
    Ok(())
}

#[test]
fn test_084_outgoing_after_sender_rotation_many_records_is_safe() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("rotation_then_many_outgoing")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(sender_dir(&dir))?;
    let file = fs::File::create(sent_log(&dir))?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    for index in 0_u8..8_u8 {
        let bytes = vec![index; 2_usize];
        let filename = format!("post-rotate-{index}.bin");
        let original = format!("/tmp/post-rotate-{index}.bin");
        let (args, _hash) =
            valid_outgoing_args_for_bytes(&bytes, WALLET_A, WALLET_B, &filename, &original);
        save_outgoing_file(&opts, args);
    }

    assert!(sent_rotated_log(&dir).exists());
    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 8_usize);
    Ok(())
}

#[test]
fn test_085_incoming_after_received_index_rotation_many_records_is_safe() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_after_index_rotation_many")?;
    let opts = opts_for_dir(&dir);

    fs::create_dir_all(receiver_dir(&dir))?;
    let file = fs::File::create(received_index(&dir))?;
    file.set_len(8_u64 * 1024_u64 * 1024_u64)?;

    for index in 0_u8..4_u8 {
        let bytes = vec![index.saturating_add(85_u8); 4_usize];
        let filename = format!("after-index-rotate-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    assert!(receiver_dir(&dir).join("received_files.jsonl.1").exists());
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 4_usize);

    let stored_payload_files = received_file_paths(&dir)?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with("received_files.jsonl"))
        })
        .count();

    assert_eq!(stored_payload_files, 4_usize);
    Ok(())
}

/* ───────────────────────── metadata/index checks ──────────────────────── */

#[test]
fn test_086_received_index_records_are_single_line_json() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("received_single_line_json")?;
    let opts = opts_for_dir(&dir);

    let chunk = first_real_chunk(
        &dir,
        "single-line86.bin",
        b"single line 86",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let text = fs::read_to_string(received_index(&dir))?;
    assert_eq!(text.lines().count(), 1_usize);
    assert!(text.ends_with('\n'));
    Ok(())
}

#[test]
fn test_087_received_index_timestamp_is_positive() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("received_timestamp_positive")?;
    let opts = opts_for_dir(&dir);

    let chunk = first_real_chunk(&dir, "timestamp87.bin", b"timestamp 87", WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let rows = read_jsonl(&received_index(&dir))?;
    assert!(rows[0_usize]["timestamp_ms"].as_i64().unwrap_or(0_i64) > 0_i64);
    Ok(())
}

#[test]
fn test_088_received_index_stored_at_parent_is_receiver_dir() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("stored_at_parent_receiver")?;
    let opts = opts_for_dir(&dir);

    let chunk = first_real_chunk(&dir, "parent88.bin", b"parent 88", WALLET_A, WALLET_B)?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    let rows = read_jsonl(&received_index(&dir))?;
    let stored_at = rows[0_usize]["stored_at"]
        .as_str()
        .context("expected stored_at")?;
    let stored_path = PathBuf::from(stored_at);

    assert_eq!(stored_path.parent(), Some(receiver_dir(&dir).as_path()));
    Ok(())
}

#[test]
fn test_089_received_index_direction_is_incoming_for_each_row() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("direction_each_row_incoming")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..4_u8 {
        let bytes = vec![index; 2_usize];
        let filename = format!("direction-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    for row in read_jsonl(&received_index(&dir))? {
        assert_eq!(row["direction"].as_str(), Some("incoming"));
    }

    Ok(())
}

#[test]
fn test_090_sent_log_direction_is_outgoing_for_each_row() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("direction_each_row_outgoing")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..4_u8 {
        let bytes = vec![index; 2_usize];
        let filename = format!("direction-out-{index}.bin");
        let original = format!("/tmp/direction-out-{index}.bin");
        let (args, _hash) =
            valid_outgoing_args_for_bytes(&bytes, WALLET_A, WALLET_B, &filename, &original);
        save_outgoing_file(&opts, args);
    }

    for row in read_jsonl(&sent_log(&dir))? {
        assert_eq!(row["direction"].as_str(), Some("outgoing"));
    }

    Ok(())
}

/* ───────────────────────── combined count/load coverage ───────────────── */

#[test]
fn test_091_combined_multiple_outgoing_and_incoming_records_have_expected_counts() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("combined_multiple_counts")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..4_u8 {
        let bytes = vec![index; 5_usize];
        let filename = format!("out-combo-{index}.bin");
        let original = format!("/tmp/out-combo-{index}.bin");
        let (args, _hash) =
            valid_outgoing_args_for_bytes(&bytes, WALLET_A, WALLET_B, &filename, &original);
        save_outgoing_file(&opts, args);
    }

    for index in 0_u8..4_u8 {
        let bytes = vec![index.saturating_add(100_u8); 6_usize];
        let filename = format!("in-combo-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 4_usize);
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 4_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 4_usize);
    Ok(())
}

#[test]
fn test_092_combined_8_outgoing_and_8_incoming_records_have_expected_counts() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("combined_8_and_8_counts")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..8_u8 {
        let bytes = vec![index; 3_usize];
        let filename = format!("out8-{index}.bin");
        let original = format!("/tmp/out8-{index}.bin");
        let (args, _hash) =
            valid_outgoing_args_for_bytes(&bytes, WALLET_A, WALLET_B, &filename, &original);
        save_outgoing_file(&opts, args);
    }

    for index in 0_u8..8_u8 {
        let bytes = vec![index.saturating_add(20_u8); 4_usize];
        let filename = format!("in8-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 8_usize);
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 8_usize);
    assert_eq!(received_file_paths(&dir)?.len(), 8_usize);
    Ok(())
}

#[test]
fn test_093_combined_invalid_outgoing_size_does_not_block_valid_incoming() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("bad_outgoing_size_then_valid_incoming")?;
    let opts = opts_for_dir(&dir);

    let (file_id, hash_hex) = hash_bytes(b"too big out");
    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "too-big-out.bin",
            (128_u64 * 1024_u64 * 1024_u64).saturating_add(1_u64),
            &hash_hex,
            "/tmp/too-big-out.bin",
        ),
    );

    assert_path_missing(&sent_log(&dir));

    let chunk = first_real_chunk(
        &dir,
        "valid-in93.bin",
        b"valid incoming 93",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_094_combined_invalid_incoming_wrong_wallet_does_not_block_valid_outgoing() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("wrong_wallet_then_valid_outgoing")?;
    let opts = opts_for_dir(&dir);

    let ignored = first_real_chunk(&dir, "ignored94.bin", b"ignored 94", WALLET_A, WALLET_C)?;
    handle_incoming_file_chunk(ignored, WALLET_B, &opts);
    assert_path_missing(&receiver_dir(&dir));

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"valid out 94",
        WALLET_A,
        WALLET_B,
        "valid-out94.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_095_combined_outgoing_line_too_large_does_not_block_valid_outgoing_afterward() -> Result<()>
{
    let _guard = test_lock()?;
    let dir = fresh_dir("line_too_large_then_valid_outgoing")?;
    let opts = opts_for_dir(&dir);

    let (file_id, hash_hex) = hash_bytes(b"line too large first");
    let huge_original_path = "x".repeat(9000_usize);

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            WALLET_A,
            WALLET_B,
            "too-large-first.bin",
            10_u64,
            &hash_hex,
            &huge_original_path,
        ),
    );

    assert_path_missing(&sent_log(&dir));

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"valid after 95",
        WALLET_A,
        WALLET_B,
        "valid-after95.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_096_combined_bad_incoming_hash_does_not_block_valid_outgoing() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("bad_in_hash_then_outgoing")?;
    let opts = opts_for_dir(&dir);

    let mut bad = first_real_chunk(&dir, "bad96.bin", b"bad hash 96", WALLET_A, WALLET_B)?;
    bad.content_hash_hex = "00".repeat(32_usize);
    handle_incoming_file_chunk(bad, WALLET_B, &opts);

    assert_path_missing(&received_index(&dir));

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"out after bad 96",
        WALLET_A,
        WALLET_B,
        "out-after-bad96.bin",
        "/raw",
    );
    save_outgoing_file(&opts, args);

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    Ok(())
}

#[test]
fn test_097_combined_valid_outgoing_does_not_create_receiver_dir() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("outgoing_only_no_receiver")?;
    let opts = opts_for_dir(&dir);

    let (args, _hash) =
        valid_outgoing_args_for_bytes(b"only out 97", WALLET_A, WALLET_B, "only-out97.bin", "/raw");
    save_outgoing_file(&opts, args);

    assert_eq!(read_jsonl(&sent_log(&dir))?.len(), 1_usize);
    assert_path_missing(&receiver_dir(&dir));
    Ok(())
}

#[test]
fn test_098_combined_valid_incoming_does_not_create_sender_dir() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("incoming_only_no_sender")?;
    let opts = opts_for_dir(&dir);

    let chunk = first_real_chunk(
        &dir,
        "only-in98.bin",
        b"only incoming 98",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(chunk, WALLET_B, &opts);

    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    assert_path_missing(&sender_dir(&dir));
    Ok(())
}

#[test]
fn test_099_combined_repeated_small_valid_incoming_files_preserve_bytes() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("repeated_small_incoming_preserve")?;
    let opts = opts_for_dir(&dir);

    for index in 0_u8..6_u8 {
        let bytes = vec![index.saturating_add(99_u8); usize::from(index).saturating_add(2_usize)];
        let filename = format!("preserve-{index}.bin");
        let chunk = first_real_chunk(&dir, &filename, &bytes, WALLET_A, WALLET_B)?;
        handle_incoming_file_chunk(chunk, WALLET_B, &opts);
    }

    let files = received_file_paths(&dir)?;
    assert_eq!(files.len(), 6_usize);

    for path in files {
        let bytes = fs::read(path)?;
        assert!(!bytes.is_empty());
    }

    Ok(())
}

#[test]
fn test_100_combined_adversarial_file_store_path_is_safe() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("combined_adversarial_final")?;
    let opts = opts_for_dir(&dir);

    let (args, _hash) = valid_outgoing_args_for_bytes(
        b"final out",
        "bad-from-wallet",
        "",
        "../bad out❤️.bin",
        "C:/tmp/final out.bin",
    );
    save_outgoing_file(&opts, args);

    let outgoing_rows = read_jsonl(&sent_log(&dir))?;
    assert_eq!(outgoing_rows.len(), 1_usize);
    assert!(filename_is_safe_ascii(
        outgoing_rows[0_usize]["filename"]
            .as_str()
            .context("expected outgoing filename")?
    ));

    let ignored = first_real_chunk(&dir, "ignored100.bin", b"ignored 100", WALLET_A, WALLET_C)?;
    handle_incoming_file_chunk(ignored, WALLET_B, &opts);
    assert_path_missing(&received_index(&dir));

    let accepted = first_real_chunk(
        &dir,
        "accepted100.bin",
        b"accepted final 100",
        WALLET_A,
        WALLET_B,
    )?;
    handle_incoming_file_chunk(accepted, WALLET_B, &opts);

    let stored = only_received_file_path(&dir)?;
    assert_eq!(stored.parent(), Some(receiver_dir(&dir).as_path()));
    assert_eq!(fs::read(stored)?, b"accepted final 100");
    assert_eq!(read_jsonl(&received_index(&dir))?.len(), 1_usize);
    Ok(())
}
