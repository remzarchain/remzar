use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use remzar::commandline::s_12_send_file::S12SendFile;
use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::network::p2p_010_netcmd::NetCmd;
use remzar::network::p2p_016_file_store::{SaveOutgoingFileArgs, save_outgoing_file};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    wallet_id_matches_pubkey_bytes_checked,
};
use remzar::utility::send_file::{
    FILE_CHUNK_SIZE, FileChunkMessage, IncomingFile, MAX_P2P_FILE_BYTES, MAX_TOTAL_CHUNKS, SendFile,
};
use serde_json::Value;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PRIMARY_WALLET: OnceLock<WalletFixture> = OnceLock::new();
static SECONDARY_WALLET: OnceLock<WalletFixture> = OnceLock::new();

#[derive(Clone)]
struct WalletFixture {
    address: String,
    encrypted_secret: Vec<u8>,
    secret: Vec<u8>,
    passphrase: &'static str,
}

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_12_send_file_tests_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            make_writable_recursive(&root);
            if fs::remove_dir_all(&root).is_err() {}
        }

        match fs::create_dir_all(&root) {
            Ok(()) => Self { root },
            Err(err) => panic!("failed to create temp root '{}': {err}", root.display()),
        }
    }

    fn child(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        make_writable_recursive(&self.root);
        if fs::remove_dir_all(&self.root).is_err() {}
    }
}

fn make_writable_recursive(path: &Path) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(_) => return,
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = metadata.permissions();
        let mode = permissions.mode();
        permissions.set_mode(mode | 0o700);
        if fs::set_permissions(path, permissions).is_err() {}
    }

    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            if fs::set_permissions(path, permissions).is_err() {}
        }
    }

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let entries = match fs::read_dir(path) {
            Ok(value) => value,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            make_writable_recursive(&entry.path());
        }
    }
}

fn assert_ok<T, E>(result: Result<T, E>, label: &str) -> T
where
    E: Debug,
{
    match result {
        Ok(value) => value,
        Err(err) => panic!("{label} failed: {err:?}"),
    }
}

fn assert_err<T, E>(result: Result<T, E>, label: &str) -> E
where
    T: Debug,
    E: Debug,
{
    match result {
        Ok(value) => panic!("{label} unexpectedly succeeded: {value:?}"),
        Err(err) => err,
    }
}

fn assert_validation_error(err: ErrorDetection) {
    match err {
        ErrorDetection::ValidationError { .. } => {}
        other => panic!("expected ValidationError, got {other:?}"),
    }
}

fn assert_decrypt_like_error(err: ErrorDetection) {
    match err {
        ErrorDetection::DecryptionError { .. }
        | ErrorDetection::ValidationError { .. }
        | ErrorDetection::EncryptionError { .. }
        | ErrorDetection::CryptographicError { .. } => {}
        other => panic!("unexpected decrypt-like error: {other:?}"),
    }
}

fn make_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_owned(),
        listen: "/ip4/127.0.0.1/tcp/36213".to_owned(),
        bootstrap: Vec::new(),
        log: "info".to_owned(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder: false,
    }
}

fn directory_from_opts(opts: &NodeOpts) -> DirectoryDB {
    assert_ok(
        DirectoryDB::from_node_opts(opts),
        "DirectoryDB::from_node_opts",
    )
}

fn build_wallet_fixture(passphrase: &'static str) -> WalletFixture {
    let wallet = assert_ok(MLDSA65Wallet::new(passphrase), "MLDSA65Wallet::new");
    let secret = assert_ok(
        Cryption::decrypt_private_key_bytes(&wallet.encrypted_secret, passphrase),
        "decrypt wallet secret",
    );

    WalletFixture {
        address: wallet.address,
        encrypted_secret: wallet.encrypted_secret,
        secret,
        passphrase,
    }
}

fn primary_fixture() -> WalletFixture {
    PRIMARY_WALLET
        .get_or_init(|| build_wallet_fixture("s12_primary_passphrase"))
        .clone()
}

fn secondary_fixture() -> WalletFixture {
    SECONDARY_WALLET
        .get_or_init(|| build_wallet_fixture("s12_secondary_passphrase"))
        .clone()
}

fn private_key_from_secret(secret: &[u8]) -> ml_dsa_65::PrivateKey {
    let sk_arr: [u8; ml_dsa_65::SK_LEN] = match secret.try_into() {
        Ok(value) => value,
        Err(_) => panic!("secret bytes did not fit ML-DSA-65 secret key array"),
    };

    assert_ok(
        ml_dsa_65::PrivateKey::try_from_bytes(sk_arr),
        "PrivateKey::try_from_bytes",
    )
}

fn primary_key() -> ml_dsa_65::PrivateKey {
    private_key_from_secret(&primary_fixture().secret)
}

fn secondary_key() -> ml_dsa_65::PrivateKey {
    private_key_from_secret(&secondary_fixture().secret)
}

fn derived_wallet_from_key(key: &ml_dsa_65::PrivateKey) -> String {
    let public_key = key.get_public_key();
    let public_bytes = public_key.into_bytes();

    derive_wallet_id_from_pubkey_bytes(&public_bytes)
}

fn wallet_from_label(label: &str) -> String {
    format!("r{}", RemzarHash::compute_bytes_hash_hex(label.as_bytes()))
}

fn assert_wallet_shape(wallet: &str) {
    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
    assert!(wallet.starts_with('r'));
    assert!(
        wallet
            .as_bytes()
            .iter()
            .skip(1)
            .all(|byte| { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() })
    );
}

fn source_file_path(dir: &Path, filename: &str, bytes: &[u8]) -> PathBuf {
    let source_dir = dir.join("source");
    assert_ok(fs::create_dir_all(&source_dir), "create source dir");

    let path = source_dir.join(filename);
    assert_ok(fs::write(&path, bytes), "write source file");
    path
}

fn make_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for index in 0usize..len {
        let byte = seed.wrapping_add(u8::try_from(index % 251usize).unwrap_or(0));
        out.push(byte);
    }

    out
}

fn hash_bytes(bytes: &[u8]) -> ([u8; 32], String) {
    let digest = blake3::hash(bytes);
    let mut file_id = [0_u8; 32];
    file_id.copy_from_slice(digest.as_bytes());
    (file_id, hex::encode(file_id))
}

fn make_send_file(dir: &Path, filename: &str, bytes: &[u8]) -> SendFile {
    let path = source_file_path(dir, filename, bytes);

    assert_ok(
        SendFile::from_path(
            primary_fixture().address,
            secondary_fixture().address,
            &path,
        ),
        "SendFile::from_path",
    )
}

fn make_send_file_with_wallets(
    dir: &Path,
    filename: &str,
    bytes: &[u8],
    from_wallet: String,
    to_wallet: String,
) -> SendFile {
    let path = source_file_path(dir, filename, bytes);

    assert_ok(
        SendFile::from_path(from_wallet, to_wallet, &path),
        "SendFile::from_path custom wallets",
    )
}

fn first_chunk(send_file: &SendFile) -> FileChunkMessage {
    match send_file.iter_chunks().next() {
        Some(value) => value,
        None => panic!("expected at least one chunk"),
    }
}

fn collect_chunks(send_file: &SendFile) -> Vec<FileChunkMessage> {
    send_file.iter_chunks().collect()
}

fn reconstruct_with_incoming(chunks: Vec<FileChunkMessage>) -> Vec<u8> {
    let first = match chunks.first() {
        Some(value) => value.clone(),
        None => panic!("expected at least one chunk"),
    };

    let mut incoming = IncomingFile::from_first_chunk(&first);

    for chunk in chunks {
        assert_ok(incoming.apply_chunk(chunk), "IncomingFile::apply_chunk");
    }

    assert!(incoming.is_complete());

    assert_ok(
        incoming.into_verified_bytes(),
        "IncomingFile::into_verified_bytes",
    )
}

fn manual_chunk_from_parts(
    full_bytes: &[u8],
    filename: &str,
    from_wallet: &str,
    to_wallet: &str,
    chunk_index: u32,
    total_chunks: u32,
    chunk_bytes: Vec<u8>,
) -> FileChunkMessage {
    let (file_id, content_hash_hex) = hash_bytes(full_bytes);

    FileChunkMessage {
        file_id,
        from_wallet: from_wallet.to_owned(),
        to_wallet: to_wallet.to_owned(),
        chunk_index,
        total_chunks,
        filename: filename.to_owned(),
        file_size_bytes: u64::try_from(full_bytes.len()).unwrap_or(0),
        content_hash_hex,
        chunk_bytes,
        timestamp_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0),
    }
}

fn wallet_file_path(directory: &DirectoryDB, address: &str) -> PathBuf {
    directory.wallets_path.join(format!("{address}.wallet"))
}

fn write_wallet_file(directory: &DirectoryDB, fixture: &WalletFixture) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let path = wallet_file_path(directory, &fixture.address);
    assert_ok(
        fs::write(&path, &fixture.encrypted_secret),
        "write wallet file",
    );
    path
}

fn load_signing_key_from_wallet_file_like_s12(
    wallet_file: &Path,
    passphrase: &str,
) -> Result<ml_dsa_65::PrivateKey, ErrorDetection> {
    let encrypted = fs::read(wallet_file).map_err(|e| ErrorDetection::IoError {
        message: format!("Failed to read wallet file: {e}"),
        code: e.raw_os_error(),
        source: Some(Box::new(e)),
    })?;

    let plaintext = Cryption::decrypt_private_key_bytes(&encrypted, passphrase)?;

    if plaintext.len() == ml_dsa_65::SK_LEN {
        return Ok(private_key_from_secret(&plaintext));
    }

    let maybe_utf8 =
        std::str::from_utf8(&plaintext).map_err(|_| ErrorDetection::ValidationError {
            message: format!(
                "Decrypted secret is not {} raw bytes and is not valid UTF-8",
                ml_dsa_65::SK_LEN
            ),
            tx_id: None,
        })?;

    let secret_hex = maybe_utf8.trim();

    if secret_hex.len() != ml_dsa_65::SK_LEN.saturating_mul(2)
        || !secret_hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(ErrorDetection::ValidationError {
            message: "Decrypted secret has unexpected length/format".to_owned(),
            tx_id: None,
        });
    }

    let secret_bytes = hex::decode(secret_hex).map_err(|e| ErrorDetection::ValidationError {
        message: format!("Cannot decode decrypted secret hex: {e:?}"),
        tx_id: None,
    })?;

    Ok(private_key_from_secret(&secret_bytes))
}

fn sender_dir(dir: &Path) -> PathBuf {
    dir.join("sender.file")
}

fn sent_log(dir: &Path) -> PathBuf {
    sender_dir(dir).join("sent_files.jsonl")
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    let text = assert_ok(fs::read_to_string(path), "read jsonl");
    let mut values = Vec::new();

    for line in text.lines() {
        values.push(assert_ok(
            serde_json::from_str::<Value>(line),
            "parse jsonl line",
        ));
    }

    values
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

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S12SendFile::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S12SendFile;
}

#[test]
fn test_03_unit_struct_constructor_creates_section() {
    let _section = S12SendFile;
}

#[test]
fn test_04_wallet_from_label_has_canonical_shape() {
    let wallet = wallet_from_label("test_04");

    assert_wallet_shape(&wallet);
}

#[test]
fn test_05_primary_wallet_has_canonical_shape() {
    assert_wallet_shape(&primary_fixture().address);
}

#[test]
fn test_06_secondary_wallet_has_canonical_shape() {
    assert_wallet_shape(&secondary_fixture().address);
}

#[test]
fn test_07_primary_wallet_canonicalizes() {
    let wallet = primary_fixture().address;
    let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon primary wallet");

    assert_eq!(canonical, wallet);
}

#[test]
fn test_08_canon_wallet_accepts_uppercase() {
    let wallet = wallet_from_label("test_08");
    let canonical = assert_ok(
        canon_wallet_id_checked(&wallet.to_ascii_uppercase()),
        "canon uppercase wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_09_canon_wallet_accepts_outer_whitespace() {
    let wallet = wallet_from_label("test_09");
    let canonical = assert_ok(
        canon_wallet_id_checked(&format!("  {wallet}  ")),
        "canon whitespace wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_10_canon_wallet_rejects_empty() {
    let err = assert_err(canon_wallet_id_checked(""), "canon empty wallet");

    assert_validation_error(err);
}

#[test]
fn test_11_canon_wallet_rejects_short() {
    let err = assert_err(canon_wallet_id_checked("r1234"), "canon short wallet");

    assert_validation_error(err);
}

#[test]
fn test_12_canon_wallet_rejects_wrong_prefix() {
    let wallet = wallet_from_label("test_12");
    let bad = format!("x{}", &wallet[1..]);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong prefix wallet");

    assert_validation_error(err);
}

#[test]
fn test_13_canon_wallet_rejects_non_hex_body() {
    let mut wallet = wallet_from_label("test_13");
    wallet.replace_range(1..2, "g");

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon non-hex wallet");

    assert_validation_error(err);
}

#[test]
fn test_14_primary_wallet_matches_primary_public_key() {
    let key = primary_key();
    let public_key = key.get_public_key();
    let public_bytes = public_key.into_bytes();

    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&primary_fixture().address, &public_bytes),
        "primary wallet matches public key",
    );
}

#[test]
fn test_15_primary_wallet_rejects_secondary_public_key() {
    let key = secondary_key();
    let public_key = key.get_public_key();
    let public_bytes = public_key.into_bytes();

    let err = assert_err(
        wallet_id_matches_pubkey_bytes_checked(&primary_fixture().address, &public_bytes),
        "primary wallet should reject secondary public key",
    );

    assert_validation_error(err);
}

#[test]
fn test_16_sendfile_one_byte_file_has_one_chunk() {
    let temp = TempTree::new("test_16");
    let send_file = make_send_file(&temp.root, "one.bin", &[7_u8]);

    assert_eq!(send_file.file_size_bytes, 1);
    assert_eq!(send_file.total_chunks, 1);
}

#[test]
fn test_17_sendfile_file_id_matches_blake3_hash() {
    let temp = TempTree::new("test_17");
    let bytes = b"hash me";
    let send_file = make_send_file(&temp.root, "hash.txt", bytes);
    let (file_id, hash_hex) = hash_bytes(bytes);

    assert_eq!(send_file.file_id, file_id);
    assert_eq!(send_file.content_hash_hex, hash_hex);
}

#[test]
fn test_18_sendfile_filename_keeps_safe_leaf_name() {
    let temp = TempTree::new("test_18");
    let send_file = make_send_file(&temp.root, "safe_name.txt", b"abc");

    assert_eq!(send_file.filename, "safe_name.txt");
}

#[test]
fn test_19_sendfile_records_from_and_to_wallets() {
    let temp = TempTree::new("test_19");
    let send_file = make_send_file(&temp.root, "wallets.bin", b"abc");

    assert_eq!(send_file.from_wallet, primary_fixture().address);
    assert_eq!(send_file.to_wallet, secondary_fixture().address);
}

#[test]
fn test_20_sendfile_rejects_empty_file() {
    let temp = TempTree::new("test_20");
    let path = source_file_path(&temp.root, "empty.bin", b"");

    let err = assert_err(
        SendFile::from_path(
            primary_fixture().address,
            secondary_fixture().address,
            &path,
        ),
        "SendFile::from_path empty file",
    );

    assert_validation_error(err);
}

#[test]
fn test_21_sendfile_rejects_missing_file() {
    let temp = TempTree::new("test_21");
    let path = temp.child("missing.bin");

    let err = assert_err(
        SendFile::from_path(
            primary_fixture().address,
            secondary_fixture().address,
            &path,
        ),
        "SendFile::from_path missing file",
    );

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_22_sendfile_rejects_invalid_from_wallet() {
    let temp = TempTree::new("test_22");
    let path = source_file_path(&temp.root, "file.bin", b"abc");

    let err = assert_err(
        SendFile::from_path(
            "not-a-wallet".to_owned(),
            secondary_fixture().address,
            &path,
        ),
        "SendFile::from_path invalid from wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_23_sendfile_rejects_invalid_to_wallet() {
    let temp = TempTree::new("test_23");
    let path = source_file_path(&temp.root, "file.bin", b"abc");

    let err = assert_err(
        SendFile::from_path(primary_fixture().address, "not-a-wallet".to_owned(), &path),
        "SendFile::from_path invalid to wallet",
    );

    assert_validation_error(err);
}

#[test]
fn test_24_sendfile_accepts_uppercase_wallet_inputs_by_canonicalizing_or_storing_valid() {
    let temp = TempTree::new("test_24");
    let path = source_file_path(&temp.root, "file.bin", b"abc");

    let result = SendFile::from_path(
        primary_fixture().address.to_ascii_uppercase(),
        secondary_fixture().address.to_ascii_uppercase(),
        &path,
    );

    match result {
        Ok(send_file) => {
            assert_ok(
                canon_wallet_id_checked(&send_file.from_wallet),
                "canon stored from",
            );
            assert_ok(
                canon_wallet_id_checked(&send_file.to_wallet),
                "canon stored to",
            );
        }
        Err(err) => assert_validation_error(err),
    }
}

#[test]
fn test_25_sendfile_chunk_for_small_file_has_expected_payload() {
    let temp = TempTree::new("test_25");
    let bytes = b"small payload";
    let send_file = make_send_file(&temp.root, "small.bin", bytes);
    let chunk = first_chunk(&send_file);

    assert_eq!(chunk.chunk_index, 0);
    assert_eq!(chunk.total_chunks, 1);
    assert_eq!(chunk.chunk_bytes, bytes);
}

#[test]
fn test_26_sendfile_chunk_metadata_matches_sendfile() {
    let temp = TempTree::new("test_26");
    let send_file = make_send_file(&temp.root, "meta.bin", b"metadata");
    let chunk = first_chunk(&send_file);

    assert_eq!(chunk.file_id, send_file.file_id);
    assert_eq!(chunk.from_wallet, send_file.from_wallet);
    assert_eq!(chunk.to_wallet, send_file.to_wallet);
    assert_eq!(chunk.filename, send_file.filename);
    assert_eq!(chunk.file_size_bytes, send_file.file_size_bytes);
    assert_eq!(chunk.content_hash_hex, send_file.content_hash_hex);
}

#[test]
fn test_27_sendfile_exact_chunk_size_has_one_full_chunk() {
    let temp = TempTree::new("test_27");
    let bytes = make_bytes(FILE_CHUNK_SIZE, 27);
    let send_file = make_send_file(&temp.root, "exact.bin", &bytes);
    let chunks = collect_chunks(&send_file);

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].chunk_bytes.len(), FILE_CHUNK_SIZE);
    assert_eq!(chunks[0].total_chunks, 1);
}

#[test]
fn test_28_sendfile_chunk_size_plus_one_has_two_chunks() {
    let temp = TempTree::new("test_28");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_add(1), 28);
    let send_file = make_send_file(&temp.root, "two.bin", &bytes);
    let chunks = collect_chunks(&send_file);

    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].chunk_bytes.len(), FILE_CHUNK_SIZE);
    assert_eq!(chunks[1].chunk_bytes.len(), 1);
}

#[test]
fn test_29_sendfile_two_full_chunks() {
    let temp = TempTree::new("test_29");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(2), 29);
    let send_file = make_send_file(&temp.root, "two_full.bin", &bytes);
    let chunks = collect_chunks(&send_file);

    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].chunk_bytes.len(), FILE_CHUNK_SIZE);
    assert_eq!(chunks[1].chunk_bytes.len(), FILE_CHUNK_SIZE);
}

#[test]
fn test_30_sendfile_total_chunks_matches_div_ceil() {
    let temp = TempTree::new("test_30");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(3).saturating_add(7), 30);
    let send_file = make_send_file(&temp.root, "three_plus.bin", &bytes);
    let expected = bytes.len().div_ceil(FILE_CHUNK_SIZE);

    assert_eq!(
        usize::try_from(send_file.total_chunks).unwrap_or(0),
        expected
    );
}

#[test]
fn test_31_reconstruct_small_file_with_incoming_file() {
    let temp = TempTree::new("test_31");
    let bytes = b"reconstruct me".to_vec();
    let send_file = make_send_file(&temp.root, "reconstruct.bin", &bytes);
    let reconstructed = reconstruct_with_incoming(collect_chunks(&send_file));

    assert_eq!(reconstructed, bytes);
}

#[test]
fn test_32_reconstruct_multi_chunk_file_with_incoming_file() {
    let temp = TempTree::new("test_32");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_add(99), 32);
    let send_file = make_send_file(&temp.root, "multi.bin", &bytes);
    let reconstructed = reconstruct_with_incoming(collect_chunks(&send_file));

    assert_eq!(reconstructed, bytes);
}

#[test]
fn test_33_incoming_file_is_not_complete_before_apply() {
    let temp = TempTree::new("test_33");
    let send_file = make_send_file(&temp.root, "incomplete.bin", b"abc");
    let chunk = first_chunk(&send_file);
    let incoming = IncomingFile::from_first_chunk(&chunk);

    assert!(!incoming.is_complete());
}

#[test]
fn test_34_incoming_file_is_complete_after_single_chunk_apply() {
    let temp = TempTree::new("test_34");
    let send_file = make_send_file(&temp.root, "complete.bin", b"abc");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    assert_ok(incoming.apply_chunk(chunk), "apply single chunk");

    assert!(incoming.is_complete());
}

#[test]
fn test_35_incoming_duplicate_chunk_is_idempotent() {
    let temp = TempTree::new("test_35");
    let send_file = make_send_file(&temp.root, "dup.bin", b"abc");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    assert_ok(
        incoming.apply_chunk(chunk.clone()),
        "apply first duplicate chunk",
    );
    assert_ok(incoming.apply_chunk(chunk), "apply second duplicate chunk");

    assert!(incoming.is_complete());
}

#[test]
fn test_36_incoming_rejects_wrong_file_id() {
    let temp = TempTree::new("test_36");
    let send_file = make_send_file(&temp.root, "wrong_id.bin", b"abcdef");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let mut bad = chunk.clone();

    bad.file_id[0] ^= 0x01;

    let err = assert_err(incoming.apply_chunk(bad), "apply wrong file id");

    assert_validation_error(err);
}

#[test]
fn test_37_incoming_rejects_wrong_content_hash() {
    let temp = TempTree::new("test_37");
    let send_file = make_send_file(&temp.root, "wrong_hash.bin", b"abcdef");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let mut bad = chunk.clone();

    bad.content_hash_hex.replace_range(0..1, "f");

    let err = assert_err(incoming.apply_chunk(bad), "apply wrong content hash");

    assert_validation_error(err);
}

#[test]
fn test_38_incoming_rejects_wrong_total_chunks() {
    let temp = TempTree::new("test_38");
    let send_file = make_send_file(&temp.root, "wrong_total.bin", b"abcdef");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let mut bad = chunk.clone();

    bad.total_chunks = bad.total_chunks.saturating_add(1);

    let err = assert_err(incoming.apply_chunk(bad), "apply wrong total chunks");

    assert_validation_error(err);
}

#[test]
fn test_39_incoming_rejects_wrong_file_size() {
    let temp = TempTree::new("test_39");
    let send_file = make_send_file(&temp.root, "wrong_size.bin", b"abcdef");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let mut bad = chunk.clone();

    bad.file_size_bytes = bad.file_size_bytes.saturating_add(1);

    let err = assert_err(incoming.apply_chunk(bad), "apply wrong file size");

    assert_validation_error(err);
}

#[test]
fn test_40_incoming_rejects_out_of_range_index() {
    let bytes = b"abc";
    let mut chunk = manual_chunk_from_parts(
        bytes,
        "bad_index.bin",
        &primary_fixture().address,
        &secondary_fixture().address,
        0,
        1,
        bytes.to_vec(),
    );
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    chunk.chunk_index = 1;

    let err = assert_err(incoming.apply_chunk(chunk), "apply out-of-range index");

    assert_validation_error(err);
}

#[test]
fn test_41_incoming_rejects_empty_chunk_bytes() {
    let bytes = b"abc";
    let chunk = manual_chunk_from_parts(
        bytes,
        "empty_chunk.bin",
        &primary_fixture().address,
        &secondary_fixture().address,
        0,
        1,
        Vec::new(),
    );
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    let err = assert_err(incoming.apply_chunk(chunk), "apply empty chunk");

    assert_validation_error(err);
}

#[test]
fn test_42_incoming_rejects_nonlast_short_chunk() {
    let full = make_bytes(FILE_CHUNK_SIZE.saturating_add(1), 42);
    let chunk = manual_chunk_from_parts(
        &full,
        "short_nonlast.bin",
        &primary_fixture().address,
        &secondary_fixture().address,
        0,
        2,
        vec![1_u8; FILE_CHUNK_SIZE.saturating_sub(1)],
    );
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    let err = assert_err(incoming.apply_chunk(chunk), "apply short nonlast chunk");

    assert_validation_error(err);
}

#[test]
fn test_43_incoming_rejects_last_chunk_wrong_size() {
    let full = make_bytes(FILE_CHUNK_SIZE.saturating_add(1), 43);
    let chunk = manual_chunk_from_parts(
        &full,
        "wrong_last.bin",
        &primary_fixture().address,
        &secondary_fixture().address,
        1,
        2,
        vec![1_u8; 2],
    );
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    let err = assert_err(incoming.apply_chunk(chunk), "apply wrong last chunk size");

    assert_validation_error(err);
}

#[test]
fn test_44_incoming_into_verified_bytes_rejects_incomplete() {
    let temp = TempTree::new("test_44");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_add(1), 44);
    let send_file = make_send_file(&temp.root, "incomplete_verify.bin", &bytes);
    let chunks = collect_chunks(&send_file);
    let first = match chunks.first() {
        Some(value) => value.clone(),
        None => panic!("missing first chunk"),
    };
    let incoming = IncomingFile::from_first_chunk(&first);

    let err = assert_err(
        incoming.into_verified_bytes(),
        "into_verified_bytes incomplete",
    );

    assert_validation_error(err);
}

#[test]
fn test_45_filechunk_postcard_round_trip() {
    let temp = TempTree::new("test_45");
    let send_file = make_send_file(&temp.root, "postcard.bin", b"postcard");
    let chunk = first_chunk(&send_file);
    let bytes = assert_ok(postcard::to_allocvec(&chunk), "serialize chunk postcard");
    let decoded: FileChunkMessage = assert_ok(postcard::from_bytes(&bytes), "deserialize chunk");

    assert_eq!(decoded.file_id, chunk.file_id);
    assert_eq!(decoded.chunk_index, chunk.chunk_index);
    assert_eq!(decoded.chunk_bytes, chunk.chunk_bytes);
}

#[test]
fn test_46_filechunk_json_round_trip() {
    let temp = TempTree::new("test_46");
    let send_file = make_send_file(&temp.root, "json.bin", b"json");
    let chunk = first_chunk(&send_file);
    let bytes = assert_ok(serde_json::to_vec(&chunk), "serialize chunk json");
    let decoded: FileChunkMessage =
        assert_ok(serde_json::from_slice(&bytes), "deserialize chunk json");

    assert_eq!(decoded.file_id, chunk.file_id);
    assert_eq!(decoded.filename, chunk.filename);
}

#[test]
fn test_47_netcmd_send_file_chunk_round_trips() {
    let temp = TempTree::new("test_47");
    let send_file = make_send_file(&temp.root, "netcmd.bin", b"netcmd");
    let chunk = first_chunk(&send_file);
    let (tx, mut rx) = mpsc::channel::<NetCmd>(1);

    assert_ok(
        tx.try_send(NetCmd::SendFileChunk(chunk.clone())),
        "try_send NetCmd::SendFileChunk",
    );

    match rx.try_recv() {
        Ok(NetCmd::SendFileChunk(received)) => assert_eq!(received.chunk_bytes, chunk.chunk_bytes),
        Ok(other) => panic!("unexpected NetCmd variant: {other:?}"),
        Err(err) => panic!("failed to receive NetCmd: {err:?}"),
    }
}

#[test]
fn test_48_netcmd_send_file_chunk_channel_full_returns_error() {
    let temp = TempTree::new("test_48");
    let send_file = make_send_file(&temp.root, "full.bin", b"full");
    let chunk = first_chunk(&send_file);
    let (tx, _rx) = mpsc::channel::<NetCmd>(1);

    assert_ok(
        tx.try_send(NetCmd::SendFileChunk(chunk.clone())),
        "fill channel",
    );

    let err = assert_err(
        tx.try_send(NetCmd::SendFileChunk(chunk)),
        "second send should be full",
    );

    match err {
        tokio::sync::mpsc::error::TrySendError::Full(NetCmd::SendFileChunk(_)) => {}
        other => panic!("expected full SendFileChunk error, got {other:?}"),
    }
}

#[test]
fn test_49_netcmd_send_file_chunk_channel_closed_returns_error() {
    let temp = TempTree::new("test_49");
    let send_file = make_send_file(&temp.root, "closed.bin", b"closed");
    let chunk = first_chunk(&send_file);
    let (tx, rx) = mpsc::channel::<NetCmd>(1);

    drop(rx);

    let err = assert_err(
        tx.try_send(NetCmd::SendFileChunk(chunk)),
        "send into closed channel",
    );

    match err {
        tokio::sync::mpsc::error::TrySendError::Closed(NetCmd::SendFileChunk(_)) => {}
        other => panic!("expected closed SendFileChunk error, got {other:?}"),
    }
}

#[test]
fn test_50_wallet_file_path_uses_sender_wallet() {
    let temp = TempTree::new("test_50");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = wallet_file_path(&directory, &fixture.address);

    assert!(path.ends_with(format!("{}.wallet", fixture.address)));
}

#[test]
fn test_51_wallet_file_write_round_trips_encrypted_secret() {
    let temp = TempTree::new("test_51");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();

    let path = write_wallet_file(&directory, &fixture);
    let stored = assert_ok(fs::read(path), "read wallet file");

    assert_eq!(stored, fixture.encrypted_secret);
}

#[test]
fn test_52_wallet_file_load_signing_key_derives_wallet() {
    let temp = TempTree::new("test_52");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);

    let key = assert_ok(
        load_signing_key_from_wallet_file_like_s12(&path, fixture.passphrase),
        "load signing key",
    );

    assert_eq!(derived_wallet_from_key(&key), fixture.address);
}

#[test]
fn test_53_wallet_file_load_rejects_wrong_passphrase() {
    let temp = TempTree::new("test_53");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);

    let err = match load_signing_key_from_wallet_file_like_s12(&path, "wrong passphrase") {
        Ok(_) => panic!("load wrong passphrase unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_decrypt_like_error(err);
}

#[test]
fn test_54_wallet_file_load_rejects_missing_file() {
    let temp = TempTree::new("test_54");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = wallet_file_path(&directory, &fixture.address);

    let err = match load_signing_key_from_wallet_file_like_s12(&path, fixture.passphrase) {
        Ok(_) => panic!("load missing wallet file unexpectedly succeeded"),
        Err(err) => err,
    };

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_55_wallet_file_load_rejects_tampered_file() {
    let temp = TempTree::new("test_55");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);
    let mut bytes = assert_ok(fs::read(&path), "read wallet file");

    match bytes.first_mut() {
        Some(byte) => {
            *byte ^= 0xAA;
        }
        None => panic!("wallet bytes unexpectedly empty"),
    }

    assert_ok(fs::write(&path, &bytes), "write tampered wallet file");

    let err = match load_signing_key_from_wallet_file_like_s12(&path, fixture.passphrase) {
        Ok(_) => panic!("load tampered wallet file unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_decrypt_like_error(err);
}

#[test]
fn test_56_wallet_file_metadata_is_regular_file() {
    let temp = TempTree::new("test_56");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let path = write_wallet_file(&directory, &primary_fixture());
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(metadata.is_file());
}

#[test]
fn test_57_wallet_file_metadata_is_nonempty() {
    let temp = TempTree::new("test_57");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let path = write_wallet_file(&directory, &primary_fixture());
    let metadata = assert_ok(fs::metadata(path), "wallet metadata");

    assert!(metadata.len() > 0);
}

#[test]
fn test_58_sendfile_content_hash_hex_is_64_hex_chars() {
    let temp = TempTree::new("test_58");
    let send_file = make_send_file(&temp.root, "hash_len.bin", b"hash length");

    assert_eq!(send_file.content_hash_hex.len(), 64);
    assert!(
        send_file
            .content_hash_hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    );
}

#[test]
fn test_59_sendfile_file_id_hex_matches_content_hash_hex() {
    let temp = TempTree::new("test_59");
    let send_file = make_send_file(&temp.root, "hash_eq.bin", b"hash equality");

    assert_eq!(hex::encode(send_file.file_id), send_file.content_hash_hex);
}

#[test]
fn test_60_sendfile_created_at_is_nonzero() {
    let temp = TempTree::new("test_60");
    let send_file = make_send_file(&temp.root, "created.bin", b"created time");

    assert!(send_file.created_at_ms > 0);
}

#[test]
fn test_61_chunk_timestamp_is_nonzero() {
    let temp = TempTree::new("test_61");
    let send_file = make_send_file(&temp.root, "timestamp.bin", b"timestamp");
    let chunk = first_chunk(&send_file);

    assert!(chunk.timestamp_ms > 0);
}

#[test]
fn test_62_chunk_indices_are_sequential() {
    let temp = TempTree::new("test_62");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(3).saturating_add(1), 62);
    let send_file = make_send_file(&temp.root, "sequential.bin", &bytes);
    let chunks = collect_chunks(&send_file);

    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.chunk_index, u32::try_from(index).unwrap_or(u32::MAX));
    }
}

#[test]
fn test_63_chunk_total_chunks_same_for_all_chunks() {
    let temp = TempTree::new("test_63");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(5), 63);
    let send_file = make_send_file(&temp.root, "totals.bin", &bytes);

    for chunk in collect_chunks(&send_file) {
        assert_eq!(chunk.total_chunks, send_file.total_chunks);
    }
}

#[test]
fn test_64_chunk_file_id_same_for_all_chunks() {
    let temp = TempTree::new("test_64");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(5), 64);
    let send_file = make_send_file(&temp.root, "ids.bin", &bytes);

    for chunk in collect_chunks(&send_file) {
        assert_eq!(chunk.file_id, send_file.file_id);
    }
}

#[test]
fn test_65_chunk_content_hash_same_for_all_chunks() {
    let temp = TempTree::new("test_65");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(5), 65);
    let send_file = make_send_file(&temp.root, "hashes.bin", &bytes);

    for chunk in collect_chunks(&send_file) {
        assert_eq!(chunk.content_hash_hex, send_file.content_hash_hex);
    }
}

#[test]
fn test_66_reconstruct_accepts_chunks_out_of_order() {
    let temp = TempTree::new("test_66");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(2).saturating_add(9), 66);
    let send_file = make_send_file(&temp.root, "out_of_order.bin", &bytes);
    let mut chunks = collect_chunks(&send_file);

    chunks.reverse();

    let reconstructed = reconstruct_with_incoming(chunks);

    assert_eq!(reconstructed, bytes);
}

#[test]
fn test_67_reconstruct_accepts_duplicate_then_remaining_chunks() {
    let temp = TempTree::new("test_67");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_add(9), 67);
    let send_file = make_send_file(&temp.root, "dup_remaining.bin", &bytes);
    let chunks = collect_chunks(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunks[0]);

    assert_ok(incoming.apply_chunk(chunks[0].clone()), "apply first");
    assert_ok(incoming.apply_chunk(chunks[0].clone()), "apply duplicate");
    assert_ok(incoming.apply_chunk(chunks[1].clone()), "apply second");

    assert_eq!(
        assert_ok(incoming.into_verified_bytes(), "verify after duplicate"),
        bytes
    );
}

#[test]
fn test_68_incoming_rejects_filename_mismatch() {
    let temp = TempTree::new("test_68");
    let send_file = make_send_file(&temp.root, "filename_a.bin", b"abcdef");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let mut bad = chunk.clone();

    bad.filename = "filename_b.bin".to_owned();

    let err = assert_err(incoming.apply_chunk(bad), "apply filename mismatch");

    assert_validation_error(err);
}

#[test]
fn test_69_incoming_rejects_future_timestamp() {
    let temp = TempTree::new("test_69");
    let send_file = make_send_file(&temp.root, "future.bin", b"abcdef");
    let chunk = first_chunk(&send_file);
    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let mut bad = chunk.clone();

    bad.timestamp_ms = u64::MAX;

    let err = assert_err(incoming.apply_chunk(bad), "apply future timestamp");

    assert_validation_error(err);
}

#[test]
fn test_70_incoming_rejects_same_wallet_sender_receiver() {
    let bytes = b"same wallet";
    let wallet = primary_fixture().address;
    let chunk = manual_chunk_from_parts(
        bytes,
        "same_wallet.bin",
        &wallet,
        &wallet,
        0,
        1,
        bytes.to_vec(),
    );
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    let err = assert_err(incoming.apply_chunk(chunk), "apply same wallet chunk");

    assert_validation_error(err);
}

#[test]
fn test_71_outgoing_log_creates_sender_file() {
    let temp = TempTree::new("test_71");
    let opts = make_node_opts(&temp.root);
    let bytes = b"outgoing log";
    let (file_id, hash_hex) = hash_bytes(bytes);

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            &primary_fixture().address,
            &secondary_fixture().address,
            "outgoing.bin",
            u64::try_from(bytes.len()).unwrap_or(0),
            &hash_hex,
            "/tmp/outgoing.bin",
        ),
    );

    assert!(sent_log(&temp.root).exists());
}

#[test]
fn test_72_outgoing_log_contains_filename() {
    let temp = TempTree::new("test_72");
    let opts = make_node_opts(&temp.root);
    let bytes = b"outgoing filename";
    let (file_id, hash_hex) = hash_bytes(bytes);

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            &primary_fixture().address,
            &secondary_fixture().address,
            "logged.bin",
            u64::try_from(bytes.len()).unwrap_or(0),
            &hash_hex,
            "/tmp/logged.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&temp.root));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["filename"].as_str(), Some("logged.bin"));
}

#[test]
fn test_73_outgoing_log_contains_wallets() {
    let temp = TempTree::new("test_73");
    let opts = make_node_opts(&temp.root);
    let bytes = b"outgoing wallets";
    let (file_id, hash_hex) = hash_bytes(bytes);

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            &primary_fixture().address,
            &secondary_fixture().address,
            "wallets.bin",
            u64::try_from(bytes.len()).unwrap_or(0),
            &hash_hex,
            "/tmp/wallets.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&temp.root));
    assert_eq!(
        rows[0]["from_wallet"].as_str(),
        Some(primary_fixture().address.as_str())
    );
    assert_eq!(
        rows[0]["to_wallet"].as_str(),
        Some(secondary_fixture().address.as_str())
    );
}

#[test]
fn test_74_outgoing_log_contains_content_hash() {
    let temp = TempTree::new("test_74");
    let opts = make_node_opts(&temp.root);
    let bytes = b"outgoing hash";
    let (file_id, hash_hex) = hash_bytes(bytes);

    save_outgoing_file(
        &opts,
        outgoing_args(
            file_id,
            &primary_fixture().address,
            &secondary_fixture().address,
            "hash.bin",
            u64::try_from(bytes.len()).unwrap_or(0),
            &hash_hex,
            "/tmp/hash.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&temp.root));
    assert_eq!(
        rows[0]["content_hash_hex"].as_str(),
        Some(hash_hex.as_str())
    );
}

#[test]
fn test_75_outgoing_log_appends_two_rows() {
    let temp = TempTree::new("test_75");
    let opts = make_node_opts(&temp.root);

    for index in 0usize..2usize {
        let bytes = format!("row-{index}").into_bytes();
        let (file_id, hash_hex) = hash_bytes(&bytes);
        save_outgoing_file(
            &opts,
            outgoing_args(
                file_id,
                &primary_fixture().address,
                &secondary_fixture().address,
                &format!("row_{index}.bin"),
                u64::try_from(bytes.len()).unwrap_or(0),
                &hash_hex,
                "/tmp/row.bin",
            ),
        );
    }

    let rows = read_jsonl(&sent_log(&temp.root));
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_76_vector_small_files_round_trip() {
    let temp = TempTree::new("test_76");

    for size in [1usize, 2, 16, 255, 1024] {
        let bytes = make_bytes(size, 76);
        let send_file = make_send_file(&temp.root, &format!("small_{size}.bin"), &bytes);
        let reconstructed = reconstruct_with_incoming(collect_chunks(&send_file));

        assert_eq!(reconstructed, bytes);
    }
}

#[test]
fn test_77_vector_boundary_files_round_trip() {
    let temp = TempTree::new("test_77");

    for size in [
        FILE_CHUNK_SIZE.saturating_sub(1),
        FILE_CHUNK_SIZE,
        FILE_CHUNK_SIZE.saturating_add(1),
    ] {
        let bytes = make_bytes(size, 77);
        let send_file = make_send_file(&temp.root, &format!("boundary_{size}.bin"), &bytes);
        let reconstructed = reconstruct_with_incoming(collect_chunks(&send_file));

        assert_eq!(reconstructed, bytes);
    }
}

#[test]
fn test_78_vector_filenames_are_sanitized_to_leaf_name() {
    let temp = TempTree::new("test_78");
    let nested = temp.child("nested").join("folder");
    assert_ok(fs::create_dir_all(&nested), "create nested folder");
    let path = nested.join("leaf.txt");
    assert_ok(fs::write(&path, b"leaf"), "write nested leaf");

    let send_file = assert_ok(
        SendFile::from_path(
            primary_fixture().address,
            secondary_fixture().address,
            &path,
        ),
        "SendFile::from_path nested leaf",
    );

    assert_eq!(send_file.filename, "leaf.txt");
}
#[test]
fn test_79_vector_rejects_directory_path_as_send_file_input() {
    let temp = TempTree::new("test_79");
    let directory_path = temp.child("not_a_file_directory");

    assert_ok(
        fs::create_dir_all(&directory_path),
        "create directory used as invalid file input",
    );

    let err = assert_err(
        SendFile::from_path(
            primary_fixture().address,
            secondary_fixture().address,
            &directory_path,
        ),
        "SendFile::from_path directory path",
    );

    match err {
        ErrorDetection::ValidationError { .. } | ErrorDetection::IoError { .. } => {}
        other => panic!("expected ValidationError or IoError for directory path, got {other:?}"),
    }
}

#[test]
fn test_80_vector_multiple_wallet_recipients_create_distinct_metadata() {
    let temp = TempTree::new("test_80");
    let bytes = b"wallet recipient vector";
    let first_to = wallet_from_label("test_80_first_to");
    let second_to = wallet_from_label("test_80_second_to");

    let first = make_send_file_with_wallets(
        &temp.root,
        "first.bin",
        bytes,
        primary_fixture().address,
        first_to,
    );
    let second = make_send_file_with_wallets(
        &temp.root,
        "second.bin",
        bytes,
        primary_fixture().address,
        second_to,
    );

    assert_ne!(first.to_wallet, second.to_wallet);
    assert_eq!(first.file_id, second.file_id);
}

#[test]
fn test_81_property_same_bytes_same_file_id() {
    let temp = TempTree::new("test_81");
    let bytes = b"same bytes same id";

    let first = make_send_file(&temp.root, "first.bin", bytes);
    let second = make_send_file(&temp.root, "second.bin", bytes);

    assert_eq!(first.file_id, second.file_id);
    assert_eq!(first.content_hash_hex, second.content_hash_hex);
}

#[test]
fn test_82_property_different_bytes_different_file_id() {
    let temp = TempTree::new("test_82");

    let first = make_send_file(&temp.root, "first.bin", b"first content");
    let second = make_send_file(&temp.root, "second.bin", b"second content");

    assert_ne!(first.file_id, second.file_id);
    assert_ne!(first.content_hash_hex, second.content_hash_hex);
}

#[test]
fn test_83_property_iter_chunks_count_matches_total_chunks() {
    let temp = TempTree::new("test_83");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(4).saturating_add(3), 83);
    let send_file = make_send_file(&temp.root, "count.bin", &bytes);
    let chunks = collect_chunks(&send_file);

    assert_eq!(
        u32::try_from(chunks.len()).unwrap_or(u32::MAX),
        send_file.total_chunks
    );
}

#[test]
fn test_84_property_total_chunks_never_zero_for_valid_file() {
    let temp = TempTree::new("test_84");
    let send_file = make_send_file(&temp.root, "nonzero.bin", b"x");

    assert!(send_file.total_chunks > 0);
}

#[test]
fn test_85_property_total_chunks_not_above_max_total_chunks_for_valid_file() {
    let temp = TempTree::new("test_85");
    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_mul(2), 85);
    let send_file = make_send_file(&temp.root, "max_total_ok.bin", &bytes);

    assert!(send_file.total_chunks <= MAX_TOTAL_CHUNKS);
}

#[test]
fn test_86_adversarial_chunk_with_invalid_from_wallet_rejected() {
    let bytes = b"invalid from";
    let chunk = manual_chunk_from_parts(
        bytes,
        "invalid_from.bin",
        "not-a-wallet",
        &secondary_fixture().address,
        0,
        1,
        bytes.to_vec(),
    );
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    let err = assert_err(incoming.apply_chunk(chunk), "apply invalid from wallet");

    assert_validation_error(err);
}

#[test]
fn test_87_adversarial_chunk_with_invalid_to_wallet_rejected() {
    let bytes = b"invalid to";
    let chunk = manual_chunk_from_parts(
        bytes,
        "invalid_to.bin",
        &primary_fixture().address,
        "not-a-wallet",
        0,
        1,
        bytes.to_vec(),
    );
    let mut incoming = IncomingFile::from_first_chunk(&chunk);

    let err = assert_err(incoming.apply_chunk(chunk), "apply invalid to wallet");

    assert_validation_error(err);
}

#[test]
fn test_88_adversarial_chunk_with_non_hex_hash_rejected() {
    let bytes = b"invalid hash";
    let mut chunk = manual_chunk_from_parts(
        bytes,
        "invalid_hash.bin",
        &primary_fixture().address,
        &secondary_fixture().address,
        0,
        1,
        bytes.to_vec(),
    );
    chunk.content_hash_hex.replace_range(0..1, "g");

    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let err = assert_err(incoming.apply_chunk(chunk), "apply invalid hash hex");

    assert_validation_error(err);
}

#[test]
fn test_89_adversarial_chunk_with_wrong_hash_length_rejected() {
    let bytes = b"short hash";
    let mut chunk = manual_chunk_from_parts(
        bytes,
        "short_hash.bin",
        &primary_fixture().address,
        &secondary_fixture().address,
        0,
        1,
        bytes.to_vec(),
    );
    chunk.content_hash_hex = "abcd".to_owned();

    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let err = assert_err(incoming.apply_chunk(chunk), "apply short hash hex");

    assert_validation_error(err);
}

#[test]
fn test_90_adversarial_chunk_with_wrong_file_id_hash_rejected() {
    let bytes = b"wrong id hash";
    let mut chunk = manual_chunk_from_parts(
        bytes,
        "wrong_id_hash.bin",
        &primary_fixture().address,
        &secondary_fixture().address,
        0,
        1,
        bytes.to_vec(),
    );
    chunk.file_id[0] ^= 0xFF;

    let mut incoming = IncomingFile::from_first_chunk(&chunk);
    let err = assert_err(incoming.apply_chunk(chunk), "apply wrong file id hash");

    assert_validation_error(err);
}

#[test]
fn test_91_load_generate_ten_send_files() {
    let temp = TempTree::new("test_91");

    for index in 0usize..10usize {
        let bytes = make_bytes(index.saturating_add(1), 91);
        let send_file = make_send_file(&temp.root, &format!("load_{index}.bin"), &bytes);

        assert_eq!(
            send_file.file_size_bytes,
            u64::try_from(bytes.len()).unwrap_or(0)
        );
    }
}

#[test]
fn test_92_load_reconstruct_ten_files() {
    let temp = TempTree::new("test_92");

    for index in 0usize..10usize {
        let bytes = make_bytes(index.saturating_mul(17).saturating_add(1), 92);
        let send_file = make_send_file(&temp.root, &format!("reconstruct_{index}.bin"), &bytes);
        let reconstructed = reconstruct_with_incoming(collect_chunks(&send_file));

        assert_eq!(reconstructed, bytes);
    }
}

#[test]
fn test_93_load_queue_ten_chunks_through_channel() {
    let temp = TempTree::new("test_93");
    let mut chunks = Vec::new();

    for index in 0usize..10usize {
        let bytes = make_bytes(index.saturating_add(1), 93);
        let send_file = make_send_file(&temp.root, &format!("queue_{index}.bin"), &bytes);
        chunks.push(first_chunk(&send_file));
    }

    let (tx, mut rx) = mpsc::channel::<NetCmd>(10);

    for chunk in chunks {
        assert_ok(
            tx.try_send(NetCmd::SendFileChunk(chunk)),
            "queue load chunk",
        );
    }

    let mut count = 0usize;
    for _ in 0usize..10usize {
        match rx.try_recv() {
            Ok(NetCmd::SendFileChunk(_)) => count = count.saturating_add(1),
            Ok(other) => panic!("unexpected NetCmd variant: {other:?}"),
            Err(err) => panic!("failed to receive queued chunk: {err:?}"),
        }
    }

    assert_eq!(count, 10);
}

#[test]
fn test_94_load_hash_twenty_files_distinct() {
    let temp = TempTree::new("test_94");
    let mut hashes = Vec::new();

    for index in 0usize..20usize {
        let bytes = make_bytes(index.saturating_add(1), u8::try_from(index).unwrap_or(0));
        let send_file = make_send_file(&temp.root, &format!("hash_{index}.bin"), &bytes);
        hashes.push(send_file.content_hash_hex);
    }

    for left_index in 0usize..hashes.len() {
        for right_index in left_index.saturating_add(1)..hashes.len() {
            let left = match hashes.get(left_index) {
                Some(value) => value,
                None => panic!("missing left hash"),
            };
            let right = match hashes.get(right_index) {
                Some(value) => value,
                None => panic!("missing right hash"),
            };
            assert_ne!(left, right);
        }
    }
}

#[test]
fn test_95_load_wallet_file_unlock_three_times() {
    let temp = TempTree::new("test_95");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);

    for _ in 0usize..3usize {
        let key = assert_ok(
            load_signing_key_from_wallet_file_like_s12(&path, fixture.passphrase),
            "load wallet key repeatedly",
        );

        assert_eq!(derived_wallet_from_key(&key), fixture.address);
    }
}

#[test]
fn test_96_load_outgoing_log_five_rows() {
    let temp = TempTree::new("test_96");
    let opts = make_node_opts(&temp.root);

    for index in 0usize..5usize {
        let bytes = format!("log-{index}").into_bytes();
        let (file_id, hash_hex) = hash_bytes(&bytes);
        save_outgoing_file(
            &opts,
            outgoing_args(
                file_id,
                &primary_fixture().address,
                &secondary_fixture().address,
                &format!("log_{index}.bin"),
                u64::try_from(bytes.len()).unwrap_or(0),
                &hash_hex,
                "/tmp/log.bin",
            ),
        );
    }

    let rows = read_jsonl(&sent_log(&temp.root));
    assert_eq!(rows.len(), 5);
}

#[test]
fn test_97_constant_file_chunk_size_is_nonzero() {
    const {
        assert!(FILE_CHUNK_SIZE > 0);
    }
}

#[test]
fn test_98_constant_max_p2p_file_bytes_is_above_chunk_size() {
    const {
        assert!(MAX_P2P_FILE_BYTES >= FILE_CHUNK_SIZE);
    }
}

#[test]
fn test_99_constant_max_total_chunks_matches_max_size_ceiling() {
    let expected = MAX_P2P_FILE_BYTES.div_ceil(FILE_CHUNK_SIZE);

    assert_eq!(usize::try_from(MAX_TOTAL_CHUNKS).unwrap_or(0), expected);
}

#[test]
fn test_100_final_send_file_dependencies_wallet_file_chunk_reconstruct_netcmd_and_log() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();

    let wallet_path = write_wallet_file(&directory, &fixture);
    let key = assert_ok(
        load_signing_key_from_wallet_file_like_s12(&wallet_path, fixture.passphrase),
        "final load signing key",
    );
    assert_eq!(derived_wallet_from_key(&key), fixture.address);

    let bytes = make_bytes(FILE_CHUNK_SIZE.saturating_add(123), 100);
    let send_file = make_send_file(&temp.root, "final.bin", &bytes);
    let chunks = collect_chunks(&send_file);

    let reconstructed = reconstruct_with_incoming(chunks.clone());
    assert_eq!(reconstructed, bytes);

    let (tx, mut rx) =
        mpsc::channel::<NetCmd>(usize::try_from(send_file.total_chunks).unwrap_or(1));
    for chunk in chunks {
        assert_ok(
            tx.try_send(NetCmd::SendFileChunk(chunk)),
            "final queue chunk",
        );
    }

    let mut queued = 0usize;
    for _ in 0u32..send_file.total_chunks {
        match rx.try_recv() {
            Ok(NetCmd::SendFileChunk(_)) => queued = queued.saturating_add(1),
            Ok(other) => panic!("unexpected final NetCmd variant: {other:?}"),
            Err(err) => panic!("failed to receive final queued chunk: {err:?}"),
        }
    }

    assert_eq!(queued, usize::try_from(send_file.total_chunks).unwrap_or(0));

    save_outgoing_file(
        &opts,
        outgoing_args(
            send_file.file_id,
            &send_file.from_wallet,
            &send_file.to_wallet,
            &send_file.filename,
            send_file.file_size_bytes,
            &send_file.content_hash_hex,
            "final.bin",
        ),
    );

    let rows = read_jsonl(&sent_log(&temp.child("node")));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["filename"].as_str(), Some("final.bin"));
    assert_eq!(
        rows[0]["content_hash_hex"].as_str(),
        Some(send_file.content_hash_hex.as_str())
    );
}
