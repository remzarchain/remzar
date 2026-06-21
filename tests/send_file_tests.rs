use chrono::Utc;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::send_file::{
    FILE_CHUNK_SIZE, FileChunkMessage, IncomingFile, MAX_P2P_FILE_BYTES, MAX_TOTAL_CHUNKS, SendFile,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), String>;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_test_path(label: &str) -> PathBuf {
    let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_file_transfer_test_{}_{}_{}",
        label,
        std::process::id(),
        n
    ))
}

fn remove_path_if_exists(path: &Path) -> TestResult {
    if path.exists() {
        if path.is_dir() {
            std::fs::remove_dir_all(path).map_err(|e| e.to_string())?;
        } else {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn wallet_a() -> String {
    format!("r{}", "a".repeat(128))
}

fn wallet_b() -> String {
    format!("r{}", "b".repeat(128))
}

fn wallet_c() -> String {
    format!("r{}", "c".repeat(128))
}

fn now_ms() -> Result<u64, String> {
    u64::try_from(Utc::now().timestamp_millis()).map_err(|e| e.to_string())
}

fn future_ms(minutes: i64) -> Result<u64, String> {
    let ts = Utc::now()
        .timestamp_millis()
        .saturating_add(minutes.saturating_mul(60_000));
    u64::try_from(ts).map_err(|e| e.to_string())
}

fn file_digest(bytes: &[u8]) -> ([u8; 32], String) {
    let digest = blake3::hash(bytes);
    let mut file_id = [0_u8; 32];
    file_id.copy_from_slice(digest.as_bytes());
    (file_id, hex::encode(digest.as_bytes()))
}

fn write_file(path: &Path, bytes: &[u8]) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

fn send_file_from_bytes(bytes: &[u8], filename: &str) -> Result<(SendFile, PathBuf), String> {
    let path = next_test_path(filename);
    remove_path_if_exists(&path)?;
    write_file(&path, bytes)?;

    let send = SendFile::from_path(wallet_a(), wallet_b(), &path)
        .map_err(|e| format!("SendFile::from_path failed: {e:?}"))?;

    Ok((send, path))
}

fn manual_chunks(bytes: &[u8], filename: &str) -> Result<Vec<FileChunkMessage>, String> {
    let (file_id, content_hash_hex) = file_digest(bytes);
    let total_chunks_usize = bytes.len().div_ceil(FILE_CHUNK_SIZE);
    let total_chunks = u32::try_from(total_chunks_usize).map_err(|e| e.to_string())?;
    let timestamp_ms = now_ms()?;

    Ok(bytes
        .chunks(FILE_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| FileChunkMessage {
            file_id,
            from_wallet: wallet_a(),
            to_wallet: wallet_b(),
            chunk_index: u32::try_from(index).unwrap_or(u32::MAX),
            total_chunks,
            filename: filename.to_string(),
            file_size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            content_hash_hex: content_hash_hex.clone(),
            chunk_bytes: chunk.to_vec(),
            timestamp_ms,
        })
        .collect())
}

fn valid_message(bytes: &[u8]) -> Result<FileChunkMessage, String> {
    manual_chunks(bytes, "valid.bin")?
        .into_iter()
        .next()
        .ok_or_else(|| "manual_chunks returned no chunks".to_string())
}

fn assert_validation_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected ValidationError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected ValidationError, got Err({error:?})")),
    }
}

fn assert_io_error<T>(result: Result<T, ErrorDetection>) -> TestResult {
    match result {
        Err(ErrorDetection::IoError { message, .. }) => {
            assert!(!message.is_empty());
            Ok(())
        }
        Ok(_) => Err("expected IoError, got Ok(_)".to_string()),
        Err(error) => Err(format!("expected IoError, got Err({error:?})")),
    }
}

#[test]
fn file_transfer_001_constants_are_expected_vectors() -> TestResult {
    assert_eq!(MAX_P2P_FILE_BYTES, 5 * 1024 * 1024);
    assert_eq!(FILE_CHUNK_SIZE, 32 * 1024);
    assert_eq!(MAX_TOTAL_CHUNKS, 160);
    Ok(())
}

#[test]
fn file_transfer_002_max_total_chunks_matches_ceil_div_formula() -> TestResult {
    let expected = MAX_P2P_FILE_BYTES.div_ceil(FILE_CHUNK_SIZE);
    let expected_u32 = u32::try_from(expected).map_err(|e| e.to_string())?;

    assert_eq!(MAX_TOTAL_CHUNKS, expected_u32);
    Ok(())
}

#[test]
fn file_transfer_003_from_path_accepts_one_byte_file() -> TestResult {
    let (send, path) = send_file_from_bytes(&[42], "one_byte.bin")?;

    assert_eq!(send.file_size_bytes, 1);
    assert_eq!(send.total_chunks, 1);
    assert_eq!(send.from_wallet, wallet_a());
    assert_eq!(send.to_wallet, wallet_b());
    assert_eq!(
        send.filename,
        path.file_name().and_then(|s| s.to_str()).unwrap_or("")
    );
    assert_eq!(send.content_hash_hex.len(), 64);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_004_from_path_trims_wallet_inputs() -> TestResult {
    let path = next_test_path("trim_wallets.bin");
    remove_path_if_exists(&path)?;
    write_file(&path, b"wallet trim")?;

    let send = SendFile::from_path(
        format!("  {}  ", wallet_a()),
        format!("\n{}\t", wallet_b()),
        &path,
    )
    .map_err(|e| format!("trimmed wallet from_path failed: {e:?}"))?;

    assert_eq!(send.from_wallet, wallet_a());
    assert_eq!(send.to_wallet, wallet_b());

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_005_from_path_rejects_same_wallet() -> TestResult {
    let path = next_test_path("same_wallet.bin");
    remove_path_if_exists(&path)?;
    write_file(&path, b"same wallet")?;

    assert_validation_error(SendFile::from_path(wallet_a(), wallet_a(), &path))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_006_from_path_rejects_empty_file() -> TestResult {
    let path = next_test_path("empty_file.bin");
    remove_path_if_exists(&path)?;
    write_file(&path, b"")?;

    assert_validation_error(SendFile::from_path(wallet_a(), wallet_b(), &path))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_007_from_path_missing_file_returns_io_error() -> TestResult {
    let path = next_test_path("missing_file.bin");
    remove_path_if_exists(&path)?;

    assert_io_error(SendFile::from_path(wallet_a(), wallet_b(), &path))?;
    Ok(())
}

#[test]
fn file_transfer_008_from_path_directory_returns_validation_error() -> TestResult {
    let path = next_test_path("directory_input");
    remove_path_if_exists(&path)?;
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;

    assert_validation_error(SendFile::from_path(wallet_a(), wallet_b(), &path))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_009_from_path_rejects_file_above_hard_cap() -> TestResult {
    let path = next_test_path("too_large_file.bin");
    remove_path_if_exists(&path)?;

    let bytes = vec![7_u8; MAX_P2P_FILE_BYTES.saturating_add(1)];
    write_file(&path, &bytes)?;

    assert_validation_error(SendFile::from_path(wallet_a(), wallet_b(), &path))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_010_from_path_accepts_file_exactly_at_hard_cap() -> TestResult {
    let path = next_test_path("max_file.bin");
    remove_path_if_exists(&path)?;

    let bytes = vec![9_u8; MAX_P2P_FILE_BYTES];
    write_file(&path, &bytes)?;

    let send = SendFile::from_path(wallet_a(), wallet_b(), &path)
        .map_err(|e| format!("max size from_path failed: {e:?}"))?;

    assert_eq!(
        send.file_size_bytes,
        u64::try_from(MAX_P2P_FILE_BYTES).unwrap_or(u64::MAX)
    );
    assert_eq!(send.total_chunks, MAX_TOTAL_CHUNKS);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_011_iter_chunks_one_byte_file_has_one_valid_chunk() -> TestResult {
    let (send, path) = send_file_from_bytes(&[1], "one_chunk.bin")?;
    let chunks = send.iter_chunks().collect::<Vec<_>>();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].chunk_index, 0);
    assert_eq!(chunks[0].total_chunks, 1);
    assert_eq!(chunks[0].chunk_bytes, vec![1]);
    chunks[0]
        .validate()
        .map_err(|e| format!("chunk validate failed: {e:?}"))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_012_iter_chunks_exact_chunk_size_has_one_full_chunk() -> TestResult {
    let bytes = vec![3_u8; FILE_CHUNK_SIZE];
    let (send, path) = send_file_from_bytes(&bytes, "exact_chunk.bin")?;
    let chunks = send.iter_chunks().collect::<Vec<_>>();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].chunk_bytes.len(), FILE_CHUNK_SIZE);
    assert_eq!(chunks[0].total_chunks, 1);
    chunks[0]
        .validate()
        .map_err(|e| format!("chunk validate failed: {e:?}"))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_013_iter_chunks_chunk_size_plus_one_has_two_chunks() -> TestResult {
    let bytes = vec![4_u8; FILE_CHUNK_SIZE.saturating_add(1)];
    let (send, path) = send_file_from_bytes(&bytes, "two_chunks.bin")?;
    let chunks = send.iter_chunks().collect::<Vec<_>>();

    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].chunk_bytes.len(), FILE_CHUNK_SIZE);
    assert_eq!(chunks[1].chunk_bytes.len(), 1);
    assert_eq!(chunks[0].total_chunks, 2);
    assert_eq!(chunks[1].total_chunks, 2);

    for chunk in &chunks {
        chunk
            .validate()
            .map_err(|e| format!("chunk validate failed: {e:?}"))?;
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_014_iter_chunks_max_size_file_has_max_total_chunks() -> TestResult {
    let path = next_test_path("max_chunks_file.bin");
    remove_path_if_exists(&path)?;

    let bytes = vec![5_u8; MAX_P2P_FILE_BYTES];
    write_file(&path, &bytes)?;

    let send = SendFile::from_path(wallet_a(), wallet_b(), &path)
        .map_err(|e| format!("max size from_path failed: {e:?}"))?;

    let chunks = send.iter_chunks().collect::<Vec<_>>();

    assert_eq!(
        chunks.len(),
        usize::try_from(MAX_TOTAL_CHUNKS).map_err(|e| e.to_string())?
    );
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.chunk_bytes.len() == FILE_CHUNK_SIZE)
    );

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_015_all_iterated_chunks_validate_for_multichunk_file() -> TestResult {
    let bytes = vec![6_u8; FILE_CHUNK_SIZE.saturating_mul(3).saturating_add(17)];
    let (send, path) = send_file_from_bytes(&bytes, "multi_validate.bin")?;

    for chunk in send.iter_chunks() {
        chunk
            .validate()
            .map_err(|e| format!("iterated chunk validate failed: {e:?}"))?;
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_016_file_id_matches_content_hash_hex() -> TestResult {
    let bytes = b"hash identity vector";
    let (send, path) = send_file_from_bytes(bytes, "hash_identity.bin")?;

    assert_eq!(hex::encode(send.file_id), send.content_hash_hex);
    assert_eq!(
        send.content_hash_hex,
        blake3::hash(bytes).to_hex().to_string()
    );

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_017_valid_file_chunk_message_validate_passes() -> TestResult {
    let chunk = valid_message(b"valid message")?;

    chunk
        .validate()
        .map_err(|e| format!("valid chunk validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_018_content_hash_hex_uppercase_is_canonicalized_for_validation() -> TestResult {
    let mut chunk = valid_message(b"uppercase hash")?;
    chunk.content_hash_hex = chunk.content_hash_hex.to_ascii_uppercase();

    chunk
        .validate()
        .map_err(|e| format!("uppercase content hash validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_019_content_hash_hex_with_boundary_spaces_validates() -> TestResult {
    let mut chunk = valid_message(b"trimmed hash")?;
    chunk.content_hash_hex = format!("  {}  ", chunk.content_hash_hex);

    chunk
        .validate()
        .map_err(|e| format!("trimmed content hash validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_020_content_hash_hex_bad_length_rejected() -> TestResult {
    let mut chunk = valid_message(b"bad hash len")?;
    chunk.content_hash_hex = "a".repeat(63);

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_021_content_hash_hex_bad_character_rejected() -> TestResult {
    let mut chunk = valid_message(b"bad hash char")?;
    chunk.content_hash_hex = "g".repeat(64);

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_022_file_id_content_hash_mismatch_rejected() -> TestResult {
    let mut chunk = valid_message(b"mismatch")?;
    chunk.file_id[0] ^= 0xFF;

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_023_empty_from_wallet_rejected() -> TestResult {
    let mut chunk = valid_message(b"empty from wallet")?;
    chunk.from_wallet = "   ".to_string();

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_024_invalid_wallet_length_rejected() -> TestResult {
    let mut chunk = valid_message(b"invalid wallet length")?;
    chunk.to_wallet = "rabc".to_string();

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_025_same_wallet_chunk_metadata_rejected() -> TestResult {
    let mut chunk = valid_message(b"same wallet chunk")?;
    chunk.to_wallet = chunk.from_wallet.clone();

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_026_future_timestamp_too_far_rejected() -> TestResult {
    let mut chunk = valid_message(b"future timestamp")?;
    chunk.timestamp_ms = future_ms(20)?;

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_027_total_chunks_zero_rejected() -> TestResult {
    let mut chunk = valid_message(b"zero total chunks")?;
    chunk.total_chunks = 0;

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_028_total_chunks_inconsistent_with_file_size_rejected() -> TestResult {
    let mut chunk = valid_message(b"inconsistent chunks")?;
    chunk.total_chunks = chunk.total_chunks.saturating_add(1);

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_029_chunk_index_out_of_range_rejected() -> TestResult {
    let mut chunk = valid_message(b"out of range")?;
    chunk.chunk_index = chunk.total_chunks;

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_030_empty_chunk_bytes_rejected() -> TestResult {
    let mut chunk = valid_message(b"empty chunk bytes")?;
    chunk.chunk_bytes.clear();

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_031_oversized_chunk_bytes_rejected() -> TestResult {
    let mut chunk = valid_message(&vec![1_u8; FILE_CHUNK_SIZE])?;
    chunk.chunk_bytes = vec![1_u8; FILE_CHUNK_SIZE.saturating_add(1)];

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_032_non_last_chunk_wrong_length_rejected() -> TestResult {
    let bytes = vec![2_u8; FILE_CHUNK_SIZE.saturating_add(1)];
    let mut chunks = manual_chunks(&bytes, "wrong_non_last.bin")?;
    let mut first = chunks
        .drain(..)
        .next()
        .ok_or_else(|| "missing first chunk".to_string())?;

    first.chunk_bytes.pop();

    assert_validation_error(first.validate())?;
    Ok(())
}

#[test]
fn file_transfer_033_last_chunk_wrong_length_rejected() -> TestResult {
    let bytes = vec![2_u8; FILE_CHUNK_SIZE.saturating_add(1)];
    let chunks = manual_chunks(&bytes, "wrong_last.bin")?;
    let mut last = chunks
        .into_iter()
        .last()
        .ok_or_else(|| "missing last chunk".to_string())?;

    last.chunk_bytes.push(9);

    assert_validation_error(last.validate())?;
    Ok(())
}

#[test]
fn file_transfer_034_incoming_from_first_chunk_checked_initializes_metadata() -> TestResult {
    let chunk = valid_message(b"incoming init")?;
    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    assert_eq!(incoming.file_id, chunk.file_id);
    assert_eq!(incoming.from_wallet, wallet_a());
    assert_eq!(incoming.to_wallet, wallet_b());
    assert_eq!(incoming.filename, "valid.bin");
    assert_eq!(incoming.file_size_bytes, chunk.file_size_bytes);
    assert_eq!(incoming.total_chunks, chunk.total_chunks);
    assert!(!incoming.is_complete());
    Ok(())
}

#[test]
fn file_transfer_035_incoming_single_chunk_roundtrip_verifies_bytes() -> TestResult {
    let bytes = b"single chunk roundtrip".to_vec();
    let chunk = valid_message(&bytes)?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming
        .apply_chunk(chunk)
        .map_err(|e| format!("apply_chunk failed: {e:?}"))?;

    assert!(incoming.is_complete());

    let verified = incoming
        .into_verified_bytes()
        .map_err(|e| format!("into_verified_bytes failed: {e:?}"))?;

    assert_eq!(verified, bytes);
    Ok(())
}

#[test]
fn file_transfer_036_incoming_multichunk_out_of_order_roundtrip_verifies_bytes() -> TestResult {
    let bytes = (0_u32..70_000_u32)
        .map(|n| u8::try_from(n % 251).unwrap_or(0))
        .collect::<Vec<_>>();
    let mut chunks = manual_chunks(&bytes, "out_of_order.bin")?;
    let first_chunk = chunks
        .first()
        .cloned()
        .ok_or_else(|| "missing first chunk".to_string())?;

    let mut incoming = IncomingFile::from_first_chunk_checked(&first_chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    chunks.reverse();

    for chunk in chunks {
        incoming
            .apply_chunk(chunk)
            .map_err(|e| format!("apply reversed chunk failed: {e:?}"))?;
    }

    assert!(incoming.is_complete());

    let verified = incoming
        .into_verified_bytes()
        .map_err(|e| format!("verify reversed chunks failed: {e:?}"))?;

    assert_eq!(verified, bytes);
    Ok(())
}

#[test]
fn file_transfer_037_duplicate_same_chunk_is_idempotent() -> TestResult {
    let chunk = valid_message(b"duplicate same chunk")?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming
        .apply_chunk(chunk.clone())
        .map_err(|e| format!("first apply failed: {e:?}"))?;
    incoming
        .apply_chunk(chunk)
        .map_err(|e| format!("duplicate same apply failed: {e:?}"))?;

    assert!(incoming.is_complete());
    Ok(())
}

#[test]
fn file_transfer_038_duplicate_conflicting_chunk_rejected() -> TestResult {
    let chunk = valid_message(b"duplicate conflict")?;
    let mut conflicting = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming
        .apply_chunk(chunk)
        .map_err(|e| format!("first apply failed: {e:?}"))?;

    if let Some(first) = conflicting.chunk_bytes.first_mut() {
        *first ^= 0xFF;
    }

    assert_validation_error(incoming.apply_chunk(conflicting))?;
    Ok(())
}

#[test]
fn file_transfer_039_into_verified_bytes_rejects_incomplete_file() -> TestResult {
    let bytes = vec![8_u8; FILE_CHUNK_SIZE.saturating_add(1)];
    let chunks = manual_chunks(&bytes, "incomplete.bin")?;
    let first = chunks
        .first()
        .cloned()
        .ok_or_else(|| "missing first chunk".to_string())?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&first)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming
        .apply_chunk(first)
        .map_err(|e| format!("apply first chunk failed: {e:?}"))?;

    assert!(!incoming.is_complete());
    assert_validation_error(incoming.into_verified_bytes())?;
    Ok(())
}

#[test]
fn file_transfer_040_suggested_output_path_uses_digest_prefix_and_sanitized_filename() -> TestResult
{
    let mut chunk = valid_message(b"suggested path")?;
    chunk.filename = "nested/path/final.txt".to_string();

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    let base = next_test_path("output_base");
    let suggested = incoming.suggested_output_path(&base);
    let filename = suggested
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "suggested path missing filename".to_string())?;

    let file_id_hex = hex::encode(chunk.file_id);
    let prefix = file_id_hex
        .get(..16)
        .ok_or_else(|| "file id hex missing prefix".to_string())?;

    assert!(filename.starts_with(prefix));
    assert!(filename.ends_with("_final.txt"));
    assert_eq!(suggested.parent(), Some(base.as_path()));
    Ok(())
}

#[test]
fn file_transfer_041_from_path_uses_only_file_name_component() -> TestResult {
    let dir = next_test_path("nested_filename_dir");
    remove_path_if_exists(&dir)?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let file = dir.join("actual_name.bin");
    write_file(&file, b"nested filename")?;

    let send = SendFile::from_path(wallet_a(), wallet_b(), &file)
        .map_err(|e| format!("from_path nested filename failed: {e:?}"))?;

    assert_eq!(send.filename, "actual_name.bin");

    remove_path_if_exists(&dir)?;
    Ok(())
}

#[test]
fn file_transfer_042_from_path_accepts_unicode_filename() -> TestResult {
    let path = next_test_path("unicode_filename_dir").with_file_name("remzar_鎖_данные.bin");
    remove_path_if_exists(&path)?;
    write_file(&path, b"unicode filename")?;

    let send = SendFile::from_path(wallet_a(), wallet_b(), &path)
        .map_err(|e| format!("from_path unicode filename failed: {e:?}"))?;

    assert_eq!(send.filename, "remzar_鎖_данные.bin");

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_043_from_path_rejects_invalid_from_wallet_prefix() -> TestResult {
    let path = next_test_path("bad_from_wallet_prefix.bin");
    remove_path_if_exists(&path)?;
    write_file(&path, b"bad wallet prefix")?;

    let bad_wallet = format!("p{}", "a".repeat(128));

    assert_validation_error(SendFile::from_path(bad_wallet, wallet_b(), &path))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_044_from_path_rejects_invalid_to_wallet_prefix() -> TestResult {
    let path = next_test_path("bad_to_wallet_prefix.bin");
    remove_path_if_exists(&path)?;
    write_file(&path, b"bad wallet prefix")?;

    let bad_wallet = format!("p{}", "b".repeat(128));

    assert_validation_error(SendFile::from_path(wallet_a(), bad_wallet, &path))?;

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_045_chunk_filename_with_path_segments_validates_as_basename() -> TestResult {
    let mut chunk = valid_message(b"path filename")?;
    chunk.filename = "nested/path/final.bin".to_string();

    chunk
        .validate()
        .map_err(|e| format!("path filename chunk validate failed: {e:?}"))?;

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    assert_eq!(incoming.filename, "final.bin");
    Ok(())
}

#[test]
fn file_transfer_046_chunk_empty_filename_falls_back_to_unnamed_file() -> TestResult {
    let mut chunk = valid_message(b"empty filename")?;
    chunk.filename = String::new();

    chunk
        .validate()
        .map_err(|e| format!("empty filename chunk validate failed: {e:?}"))?;

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    assert_eq!(incoming.filename, "unnamed_file");
    Ok(())
}

#[test]
fn file_transfer_047_chunk_whitespace_filename_falls_back_to_unnamed_file() -> TestResult {
    let mut chunk = valid_message(b"whitespace filename")?;
    chunk.filename = " \t\n ".to_string();

    chunk
        .validate()
        .map_err(|e| format!("whitespace filename chunk validate failed: {e:?}"))?;

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    assert_eq!(incoming.filename, "unnamed_file");
    Ok(())
}

#[test]
fn file_transfer_048_chunk_filename_with_control_character_rejected() -> TestResult {
    let mut chunk = valid_message(b"bad filename control")?;
    chunk.filename = "bad\nname.bin".to_string();

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_049_chunk_filename_with_nul_character_rejected() -> TestResult {
    let mut chunk = valid_message(b"bad filename nul")?;
    chunk.filename = "bad\0name.bin".to_string();

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_050_chunk_filename_over_255_bytes_rejected() -> TestResult {
    let mut chunk = valid_message(b"long filename")?;
    chunk.filename = format!("{}.bin", "a".repeat(256));

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_051_chunk_filename_exactly_255_bytes_validates() -> TestResult {
    let mut chunk = valid_message(b"exact filename")?;
    chunk.filename = "a".repeat(255);

    chunk
        .validate()
        .map_err(|e| format!("exact 255-byte filename validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_052_validate_rejects_declared_zero_file_size() -> TestResult {
    let mut chunk = valid_message(b"zero size declared")?;
    chunk.file_size_bytes = 0;
    chunk.total_chunks = 0;

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_053_validate_rejects_declared_file_size_over_cap() -> TestResult {
    let mut chunk = valid_message(b"declared too large")?;
    chunk.file_size_bytes =
        u64::try_from(MAX_P2P_FILE_BYTES.saturating_add(1)).map_err(|e| e.to_string())?;
    chunk.total_chunks = MAX_TOTAL_CHUNKS.saturating_add(1);

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_054_validate_rejects_total_chunks_above_max() -> TestResult {
    let mut chunk = valid_message(b"total chunks too high")?;
    chunk.total_chunks = MAX_TOTAL_CHUNKS.saturating_add(1);

    assert_validation_error(chunk.validate())?;
    Ok(())
}

#[test]
fn file_transfer_055_validate_accepts_exact_chunk_size_last_chunk_when_file_size_matches()
-> TestResult {
    let bytes = vec![11_u8; FILE_CHUNK_SIZE];
    let chunks = manual_chunks(&bytes, "exact_last.bin")?;
    let chunk = chunks
        .first()
        .ok_or_else(|| "missing exact chunk".to_string())?;

    chunk
        .validate()
        .map_err(|e| format!("exact chunk validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_056_validate_accepts_max_file_last_chunk_full_size() -> TestResult {
    let bytes = vec![12_u8; MAX_P2P_FILE_BYTES];
    let chunks = manual_chunks(&bytes, "max_file_chunks.bin")?;
    let last = chunks
        .last()
        .ok_or_else(|| "missing max file last chunk".to_string())?;

    assert_eq!(last.chunk_index, MAX_TOTAL_CHUNKS.saturating_sub(1));
    assert_eq!(last.chunk_bytes.len(), FILE_CHUNK_SIZE);

    last.validate()
        .map_err(|e| format!("max file last chunk validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_057_validate_accepts_file_chunk_size_minus_one_single_chunk() -> TestResult {
    let bytes = vec![13_u8; FILE_CHUNK_SIZE.saturating_sub(1)];
    let chunks = manual_chunks(&bytes, "chunk_minus_one.bin")?;

    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].chunk_bytes.len(),
        FILE_CHUNK_SIZE.saturating_sub(1)
    );

    chunks[0]
        .validate()
        .map_err(|e| format!("chunk size minus one validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_058_validate_accepts_file_two_full_chunks() -> TestResult {
    let bytes = vec![14_u8; FILE_CHUNK_SIZE.saturating_mul(2)];
    let chunks = manual_chunks(&bytes, "two_full_chunks.bin")?;

    assert_eq!(chunks.len(), 2);

    for chunk in &chunks {
        assert_eq!(chunk.chunk_bytes.len(), FILE_CHUNK_SIZE);
        chunk
            .validate()
            .map_err(|e| format!("two full chunks validate failed: {e:?}"))?;
    }

    Ok(())
}

#[test]
fn file_transfer_059_file_chunk_message_serde_roundtrip_preserves_fields() -> TestResult {
    let chunk = valid_message(b"serde roundtrip")?;
    let encoded = serde_json::to_string(&chunk).map_err(|e| e.to_string())?;
    let decoded = serde_json::from_str::<FileChunkMessage>(&encoded).map_err(|e| e.to_string())?;

    assert_eq!(decoded.file_id, chunk.file_id);
    assert_eq!(decoded.from_wallet, chunk.from_wallet);
    assert_eq!(decoded.to_wallet, chunk.to_wallet);
    assert_eq!(decoded.chunk_index, chunk.chunk_index);
    assert_eq!(decoded.total_chunks, chunk.total_chunks);
    assert_eq!(decoded.filename, chunk.filename);
    assert_eq!(decoded.file_size_bytes, chunk.file_size_bytes);
    assert_eq!(decoded.content_hash_hex, chunk.content_hash_hex);
    assert_eq!(decoded.chunk_bytes, chunk.chunk_bytes);
    assert_eq!(decoded.timestamp_ms, chunk.timestamp_ms);

    decoded
        .validate()
        .map_err(|e| format!("decoded chunk validate failed: {e:?}"))?;

    Ok(())
}

#[test]
fn file_transfer_060_file_chunk_message_json_has_expected_snake_case_fields() -> TestResult {
    let chunk = valid_message(b"json field names")?;
    let value = serde_json::to_value(&chunk).map_err(|e| e.to_string())?;

    for field in [
        "file_id",
        "from_wallet",
        "to_wallet",
        "chunk_index",
        "total_chunks",
        "filename",
        "file_size_bytes",
        "content_hash_hex",
        "chunk_bytes",
        "timestamp_ms",
    ] {
        assert!(value.get(field).is_some(), "missing field {field}");
    }

    assert!(value.get("fileId").is_none());
    assert!(value.get("fromWallet").is_none());
    Ok(())
}

#[test]
fn file_transfer_061_from_first_chunk_backward_compatible_constructor_handles_invalid_metadata()
-> TestResult {
    let mut chunk = valid_message(b"fallback constructor")?;
    chunk.from_wallet = "bad".to_string();
    chunk.to_wallet = "also_bad".to_string();
    chunk.filename = "bad\nname.bin".to_string();
    chunk.content_hash_hex = "nothex".to_string();
    chunk.total_chunks = MAX_TOTAL_CHUNKS.saturating_add(50);

    let incoming = IncomingFile::from_first_chunk(&chunk);

    assert_eq!(incoming.from_wallet, "bad");
    assert_eq!(incoming.to_wallet, "also_bad");
    assert_eq!(incoming.filename, "unnamed_file");
    assert_eq!(incoming.content_hash_hex, "");
    assert_eq!(incoming.total_chunks, MAX_TOTAL_CHUNKS);
    assert!(!incoming.is_complete());
    Ok(())
}

#[test]
fn file_transfer_062_from_first_chunk_checked_rejects_invalid_metadata() -> TestResult {
    let mut chunk = valid_message(b"checked invalid metadata")?;
    chunk.from_wallet = "bad".to_string();

    assert_validation_error(IncomingFile::from_first_chunk_checked(&chunk))?;
    Ok(())
}

#[test]
fn file_transfer_063_apply_chunk_rejects_file_id_mismatch() -> TestResult {
    let chunk = valid_message(b"file id mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.file_id[0] ^= 0xAA;
    bad.content_hash_hex = hex::encode(bad.file_id);

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_064_apply_chunk_rejects_from_wallet_mismatch() -> TestResult {
    let chunk = valid_message(b"from wallet mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.from_wallet = wallet_c();

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_065_apply_chunk_rejects_to_wallet_mismatch() -> TestResult {
    let chunk = valid_message(b"to wallet mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.to_wallet = wallet_c();

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_066_apply_chunk_rejects_filename_mismatch() -> TestResult {
    let chunk = valid_message(b"filename mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.filename = "other.bin".to_string();

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_067_apply_chunk_rejects_total_chunks_mismatch() -> TestResult {
    let chunk = valid_message(b"total chunks mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.total_chunks = bad.total_chunks.saturating_add(1);

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_068_apply_chunk_rejects_file_size_mismatch() -> TestResult {
    let chunk = valid_message(b"file size mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.file_size_bytes = bad.file_size_bytes.saturating_add(1);

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_069_apply_chunk_rejects_content_hash_mismatch() -> TestResult {
    let chunk = valid_message(b"content hash mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.content_hash_hex = "f".repeat(64);

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_070_apply_chunk_rejects_out_of_range_chunk_index() -> TestResult {
    let chunk = valid_message(b"chunk index mismatch")?;
    let mut bad = chunk.clone();
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    bad.chunk_index = bad.total_chunks;

    assert_validation_error(incoming.apply_chunk(bad))?;
    Ok(())
}

#[test]
fn file_transfer_071_incoming_content_hash_uppercase_is_canonicalized() -> TestResult {
    let mut chunk = valid_message(b"incoming uppercase hash")?;
    chunk.content_hash_hex = chunk.content_hash_hex.to_ascii_uppercase();

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("uppercase incoming constructor failed: {e:?}"))?;

    assert_eq!(
        incoming.content_hash_hex,
        chunk.content_hash_hex.to_ascii_lowercase()
    );
    Ok(())
}

#[test]
fn file_transfer_072_incoming_wallets_are_canonicalized_after_trimming() -> TestResult {
    let mut chunk = valid_message(b"incoming wallet trim")?;
    chunk.from_wallet = format!("  {}  ", wallet_a());
    chunk.to_wallet = format!("\n{}\t", wallet_b());

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("trimmed incoming constructor failed: {e:?}"))?;

    assert_eq!(incoming.from_wallet, wallet_a());
    assert_eq!(incoming.to_wallet, wallet_b());
    Ok(())
}

#[test]
fn file_transfer_073_incoming_suggested_output_path_empty_filename_uses_unnamed_file() -> TestResult
{
    let mut chunk = valid_message(b"unnamed suggested path")?;
    chunk.filename = String::new();

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("incoming constructor failed: {e:?}"))?;

    let base = next_test_path("suggested_empty_filename_base");
    let suggested = incoming.suggested_output_path(&base);
    let name = suggested
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "suggested path missing filename".to_string())?;

    assert!(name.ends_with("_unnamed_file"));
    assert_eq!(suggested.parent(), Some(base.as_path()));
    Ok(())
}

#[test]
fn file_transfer_074_incoming_suggested_output_path_bad_filename_falls_back_to_unnamed_file()
-> TestResult {
    let chunk = valid_message(b"bad suggested path")?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("incoming constructor failed: {e:?}"))?;

    incoming.filename = "bad\nname.bin".to_string();

    let base = next_test_path("suggested_bad_filename_base");
    let suggested = incoming.suggested_output_path(&base);
    let name = suggested
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "suggested path missing filename".to_string())?;

    assert!(name.ends_with("_unnamed_file"));
    assert_eq!(suggested.parent(), Some(base.as_path()));
    Ok(())
}

#[test]
fn file_transfer_075_into_verified_bytes_detects_tampered_content_hash_after_receipt() -> TestResult
{
    let bytes = b"tamper after receipt".to_vec();
    let chunk = valid_message(&bytes)?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("incoming constructor failed: {e:?}"))?;

    incoming
        .apply_chunk(chunk)
        .map_err(|e| format!("apply chunk failed: {e:?}"))?;

    incoming.content_hash_hex = "f".repeat(64);

    assert_validation_error(incoming.into_verified_bytes())?;
    Ok(())
}

#[test]
fn file_transfer_076_into_verified_bytes_detects_tampered_file_id_after_receipt() -> TestResult {
    let bytes = b"tamper file id after receipt".to_vec();
    let chunk = valid_message(&bytes)?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("incoming constructor failed: {e:?}"))?;

    incoming
        .apply_chunk(chunk)
        .map_err(|e| format!("apply chunk failed: {e:?}"))?;

    incoming.file_id[0] ^= 0xFF;

    assert_validation_error(incoming.into_verified_bytes())?;
    Ok(())
}

#[test]
fn file_transfer_077_send_file_debug_contains_public_metadata() -> TestResult {
    let (send, path) = send_file_from_bytes(b"debug metadata", "debug_metadata.bin")?;
    let rendered = format!("{send:?}");

    assert!(rendered.contains("file_id"));
    assert!(rendered.contains("from_wallet"));
    assert!(rendered.contains("to_wallet"));
    assert!(rendered.contains("filename"));
    assert!(rendered.contains("file_size_bytes"));
    assert!(rendered.contains("total_chunks"));

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_078_file_chunk_debug_contains_chunk_metadata() -> TestResult {
    let chunk = valid_message(b"chunk debug")?;
    let rendered = format!("{chunk:?}");

    assert!(rendered.contains("file_id"));
    assert!(rendered.contains("chunk_index"));
    assert!(rendered.contains("total_chunks"));
    assert!(rendered.contains("filename"));
    assert!(rendered.contains("timestamp_ms"));
    Ok(())
}

#[test]
fn file_transfer_079_load_many_small_files_from_path_and_validate_chunks() -> TestResult {
    for index in 0_u64..100_u64 {
        let byte = u8::try_from(index % 251).unwrap_or(0);
        let bytes =
            vec![byte; usize::try_from(index.saturating_add(1)).map_err(|e| e.to_string())?];
        let (send, path) = send_file_from_bytes(&bytes, &format!("load_small_{index}.bin"))?;

        assert_eq!(send.file_size_bytes, index.saturating_add(1));

        for chunk in send.iter_chunks() {
            chunk
                .validate()
                .map_err(|e| format!("load small chunk validate failed at {index}: {e:?}"))?;
        }

        remove_path_if_exists(&path)?;
    }

    Ok(())
}

#[test]
fn file_transfer_080_load_many_chunk_sizes_roundtrip_verify() -> TestResult {
    for size in [
        1_usize,
        2,
        FILE_CHUNK_SIZE.saturating_sub(1),
        FILE_CHUNK_SIZE,
        FILE_CHUNK_SIZE.saturating_add(1),
        FILE_CHUNK_SIZE.saturating_mul(2),
        FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(7),
    ] {
        let bytes = (0..size)
            .map(|index| u8::try_from(index % 251).unwrap_or(0))
            .collect::<Vec<_>>();

        let chunks = manual_chunks(&bytes, "load_roundtrip.bin")?;
        let first = chunks
            .first()
            .cloned()
            .ok_or_else(|| "missing first chunk".to_string())?;

        let mut incoming = IncomingFile::from_first_chunk_checked(&first)
            .map_err(|e| format!("incoming constructor failed for size {size}: {e:?}"))?;

        for chunk in chunks {
            incoming
                .apply_chunk(chunk)
                .map_err(|e| format!("apply chunk failed for size {size}: {e:?}"))?;
        }

        let verified = incoming
            .into_verified_bytes()
            .map_err(|e| format!("verify failed for size {size}: {e:?}"))?;

        assert_eq!(verified, bytes);
    }

    Ok(())
}

#[test]
fn file_transfer_081_iter_chunks_two_chunks_plus_one_byte_has_three_chunks() -> TestResult {
    let size = FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(1);
    let bytes = vec![21_u8; size];
    let (send, path) = send_file_from_bytes(&bytes, "two_plus_one.bin")?;
    let chunks = send.iter_chunks().collect::<Vec<_>>();

    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].chunk_index, 0);
    assert_eq!(chunks[1].chunk_index, 1);
    assert_eq!(chunks[2].chunk_index, 2);
    assert_eq!(chunks[0].chunk_bytes.len(), FILE_CHUNK_SIZE);
    assert_eq!(chunks[1].chunk_bytes.len(), FILE_CHUNK_SIZE);
    assert_eq!(chunks[2].chunk_bytes.len(), 1);

    for chunk in &chunks {
        chunk
            .validate()
            .map_err(|e| format!("chunk validation failed: {e:?}"))?;
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_082_iterated_chunks_share_stable_file_metadata() -> TestResult {
    let bytes = vec![22_u8; FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(9)];
    let (send, path) = send_file_from_bytes(&bytes, "stable_metadata.bin")?;
    let chunks = send.iter_chunks().collect::<Vec<_>>();

    assert!(chunks.len() > 1);

    for chunk in &chunks {
        assert_eq!(chunk.file_id, send.file_id);
        assert_eq!(chunk.from_wallet, send.from_wallet);
        assert_eq!(chunk.to_wallet, send.to_wallet);
        assert_eq!(chunk.filename, send.filename);
        assert_eq!(chunk.file_size_bytes, send.file_size_bytes);
        assert_eq!(chunk.content_hash_hex, send.content_hash_hex);
        assert_eq!(chunk.total_chunks, send.total_chunks);
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_083_iterated_chunk_indexes_are_contiguous_vectors() -> TestResult {
    let bytes = vec![23_u8; FILE_CHUNK_SIZE.saturating_mul(4).saturating_add(3)];
    let (send, path) = send_file_from_bytes(&bytes, "contiguous_indexes.bin")?;

    for (expected, chunk) in send.iter_chunks().enumerate() {
        let expected_u32 = u32::try_from(expected).map_err(|e| e.to_string())?;
        assert_eq!(chunk.chunk_index, expected_u32);
    }

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_084_send_file_clone_preserves_public_metadata_and_chunks() -> TestResult {
    let bytes = vec![24_u8; FILE_CHUNK_SIZE.saturating_add(5)];
    let (send, path) = send_file_from_bytes(&bytes, "clone_send_file.bin")?;
    let cloned = send.clone();

    assert_eq!(cloned.file_id, send.file_id);
    assert_eq!(cloned.from_wallet, send.from_wallet);
    assert_eq!(cloned.to_wallet, send.to_wallet);
    assert_eq!(cloned.filename, send.filename);
    assert_eq!(cloned.file_size_bytes, send.file_size_bytes);
    assert_eq!(cloned.content_hash_hex, send.content_hash_hex);
    assert_eq!(cloned.total_chunks, send.total_chunks);

    let original_chunks = send.iter_chunks().collect::<Vec<_>>();
    let cloned_chunks = cloned.iter_chunks().collect::<Vec<_>>();

    assert_eq!(original_chunks.len(), cloned_chunks.len());
    assert_eq!(original_chunks[0].chunk_bytes, cloned_chunks[0].chunk_bytes);

    remove_path_if_exists(&path)?;
    Ok(())
}

#[test]
fn file_transfer_085_file_chunk_clone_preserves_full_payload() -> TestResult {
    let chunk = valid_message(b"clone chunk payload")?;
    let cloned = chunk.clone();

    assert_eq!(cloned.file_id, chunk.file_id);
    assert_eq!(cloned.from_wallet, chunk.from_wallet);
    assert_eq!(cloned.to_wallet, chunk.to_wallet);
    assert_eq!(cloned.chunk_index, chunk.chunk_index);
    assert_eq!(cloned.total_chunks, chunk.total_chunks);
    assert_eq!(cloned.filename, chunk.filename);
    assert_eq!(cloned.file_size_bytes, chunk.file_size_bytes);
    assert_eq!(cloned.content_hash_hex, chunk.content_hash_hex);
    assert_eq!(cloned.chunk_bytes, chunk.chunk_bytes);
    assert_eq!(cloned.timestamp_ms, chunk.timestamp_ms);
    Ok(())
}

#[test]
fn file_transfer_086_serde_rejects_missing_required_file_id() -> TestResult {
    let chunk = valid_message(b"missing file id json")?;
    let mut value = serde_json::to_value(&chunk).map_err(|e| e.to_string())?;

    value
        .as_object_mut()
        .ok_or_else(|| "chunk json was not object".to_string())?
        .remove("file_id");

    let decoded = serde_json::from_value::<FileChunkMessage>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn file_transfer_087_serde_rejects_file_id_array_with_wrong_length() -> TestResult {
    let chunk = valid_message(b"wrong file id array length")?;
    let mut value = serde_json::to_value(&chunk).map_err(|e| e.to_string())?;

    value["file_id"] = serde_json::json!([1, 2, 3]);

    let decoded = serde_json::from_value::<FileChunkMessage>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn file_transfer_088_serde_rejects_string_chunk_index() -> TestResult {
    let chunk = valid_message(b"string chunk index")?;
    let mut value = serde_json::to_value(&chunk).map_err(|e| e.to_string())?;

    value["chunk_index"] = serde_json::json!("0");

    let decoded = serde_json::from_value::<FileChunkMessage>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn file_transfer_089_serde_rejects_negative_file_size() -> TestResult {
    let chunk = valid_message(b"negative file size")?;
    let mut value = serde_json::to_value(&chunk).map_err(|e| e.to_string())?;

    value["file_size_bytes"] = serde_json::json!(-1);

    let decoded = serde_json::from_value::<FileChunkMessage>(value);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn file_transfer_090_duplicate_same_chunk_does_not_mark_multichunk_file_complete() -> TestResult {
    let bytes = vec![30_u8; FILE_CHUNK_SIZE.saturating_add(1)];
    let chunks = manual_chunks(&bytes, "duplicate_not_complete.bin")?;
    let first = chunks
        .first()
        .cloned()
        .ok_or_else(|| "missing first chunk".to_string())?;

    let mut incoming = IncomingFile::from_first_chunk_checked(&first)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming
        .apply_chunk(first.clone())
        .map_err(|e| format!("first apply failed: {e:?}"))?;
    incoming
        .apply_chunk(first)
        .map_err(|e| format!("duplicate apply failed: {e:?}"))?;

    assert!(!incoming.is_complete());
    Ok(())
}

#[test]
fn file_transfer_091_apply_chunk_rejects_when_receiver_state_wallets_are_tampered_same()
-> TestResult {
    let chunk = valid_message(b"state same wallet tamper")?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming.to_wallet = incoming.from_wallet.clone();

    assert_validation_error(incoming.apply_chunk(chunk))?;
    Ok(())
}

#[test]
fn file_transfer_092_apply_chunk_rejects_when_receiver_state_hash_is_invalid() -> TestResult {
    let chunk = valid_message(b"state bad hash tamper")?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming.content_hash_hex = "not-hex".to_string();

    assert_validation_error(incoming.apply_chunk(chunk))?;
    Ok(())
}

#[test]
fn file_transfer_093_apply_chunk_rejects_when_receiver_state_file_size_is_zero() -> TestResult {
    let chunk = valid_message(b"state zero size tamper")?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming.file_size_bytes = 0;

    assert_validation_error(incoming.apply_chunk(chunk))?;
    Ok(())
}

#[test]
fn file_transfer_094_apply_chunk_rejects_when_receiver_state_total_chunks_is_zero() -> TestResult {
    let chunk = valid_message(b"state zero chunks tamper")?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming.total_chunks = 0;

    assert_validation_error(incoming.apply_chunk(chunk))?;
    Ok(())
}

#[test]
fn file_transfer_095_into_verified_bytes_rejects_when_receiver_state_filename_is_invalid()
-> TestResult {
    let bytes = b"bad state filename after complete".to_vec();
    let chunk = valid_message(&bytes)?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming
        .apply_chunk(chunk)
        .map_err(|e| format!("apply chunk failed: {e:?}"))?;

    incoming.filename = "bad\nname.bin".to_string();

    assert_validation_error(incoming.into_verified_bytes())?;
    Ok(())
}

#[test]
fn file_transfer_096_into_verified_bytes_rejects_when_receiver_state_size_tampered_larger()
-> TestResult {
    let bytes = b"tampered larger file size".to_vec();
    let chunk = valid_message(&bytes)?;
    let mut incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    incoming
        .apply_chunk(chunk)
        .map_err(|e| format!("apply chunk failed: {e:?}"))?;

    incoming.file_size_bytes = incoming.file_size_bytes.saturating_add(1);

    assert_validation_error(incoming.into_verified_bytes())?;
    Ok(())
}

#[test]
fn file_transfer_097_from_first_chunk_checked_rejects_timestamp_at_u64_max() -> TestResult {
    let mut chunk = valid_message(b"max timestamp")?;
    chunk.timestamp_ms = u64::MAX;

    assert_validation_error(IncomingFile::from_first_chunk_checked(&chunk))?;
    Ok(())
}

#[test]
fn file_transfer_098_suggested_output_path_preserves_unicode_safe_filename() -> TestResult {
    let mut chunk = valid_message(b"unicode suggested filename")?;
    chunk.filename = "報告_鎖.bin".to_string();

    let incoming = IncomingFile::from_first_chunk_checked(&chunk)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    let base = next_test_path("unicode_suggested_base");
    let suggested = incoming.suggested_output_path(&base);
    let name = suggested
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "suggested filename was not utf8".to_string())?;

    assert!(name.ends_with("_報告_鎖.bin"));
    assert_eq!(suggested.parent(), Some(base.as_path()));
    Ok(())
}

#[test]
fn file_transfer_099_load_max_size_manual_chunks_roundtrip_verify() -> TestResult {
    let bytes = (0..MAX_P2P_FILE_BYTES)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect::<Vec<_>>();

    let chunks = manual_chunks(&bytes, "manual_max_roundtrip.bin")?;
    assert_eq!(
        chunks.len(),
        usize::try_from(MAX_TOTAL_CHUNKS).map_err(|e| e.to_string())?
    );

    let first = chunks
        .first()
        .cloned()
        .ok_or_else(|| "missing first chunk".to_string())?;

    let mut incoming = IncomingFile::from_first_chunk_checked(&first)
        .map_err(|e| format!("from_first_chunk_checked failed: {e:?}"))?;

    for chunk in chunks {
        incoming
            .apply_chunk(chunk)
            .map_err(|e| format!("apply max-size chunk failed: {e:?}"))?;
    }

    assert!(incoming.is_complete());

    let verified = incoming
        .into_verified_bytes()
        .map_err(|e| format!("max-size verify failed: {e:?}"))?;

    assert_eq!(verified.len(), MAX_P2P_FILE_BYTES);
    assert_eq!(verified, bytes);
    Ok(())
}

#[test]
fn file_transfer_100_load_repeated_sendfile_roundtrips_are_stable() -> TestResult {
    for index in 0_usize..50_usize {
        let size = index
            .saturating_mul(257)
            .saturating_add(1)
            .min(FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(13));
        let bytes = (0..size)
            .map(|n| u8::try_from((n + index) % 251).unwrap_or(0))
            .collect::<Vec<_>>();

        let (send, path) = send_file_from_bytes(&bytes, &format!("stable_roundtrip_{index}.bin"))?;
        let chunks = send.iter_chunks().collect::<Vec<_>>();
        let first = chunks
            .first()
            .cloned()
            .ok_or_else(|| format!("missing first chunk for index {index}"))?;

        let mut incoming = IncomingFile::from_first_chunk_checked(&first)
            .map_err(|e| format!("constructor failed for index {index}: {e:?}"))?;

        for chunk in chunks {
            incoming
                .apply_chunk(chunk)
                .map_err(|e| format!("apply failed for index {index}: {e:?}"))?;
        }

        let verified = incoming
            .into_verified_bytes()
            .map_err(|e| format!("verify failed for index {index}: {e:?}"))?;

        assert_eq!(verified, bytes);

        remove_path_if_exists(&path)?;
    }

    Ok(())
}
