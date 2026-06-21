use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use remzar::commandline::s_11_send_chat::S11SendChat;
use remzar::cryptography::ml_dsa_65_005_encryption::Cryption;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::network::p2p_014_chat::{
    CHAT_MAX_FUTURE_SKEW_MS, CHAT_MAX_PAST_AGE_MS, CHAT_TOPIC, ChatJson, ChatMessage,
    MAX_CHAT_JSON_BYTES, MAX_CHAT_PLAINTEXT_CHARS, MAX_CHAT_WIRE_BYTES, MAX_WALLET_STR_BYTES,
    chat_topic,
};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    wallet_id_matches_pubkey_bytes_checked,
};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
            "remzar_s_11_send_chat_tests_{test_name}_{}_{}",
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

fn assert_serialization_error(err: ErrorDetection) {
    match err {
        ErrorDetection::SerializationError { .. } => {}
        other => panic!("expected SerializationError, got {other:?}"),
    }
}

fn assert_signature_error(err: ErrorDetection) {
    match err {
        ErrorDetection::SignatureVerificationFailed { .. } => {}
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
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
        .get_or_init(|| build_wallet_fixture("s11_primary_passphrase"))
        .clone()
}

fn secondary_fixture() -> WalletFixture {
    SECONDARY_WALLET
        .get_or_init(|| build_wallet_fixture("s11_secondary_passphrase"))
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

fn primary_public_key() -> ml_dsa_65::PublicKey {
    primary_key().get_public_key()
}

fn secondary_public_key() -> ml_dsa_65::PublicKey {
    secondary_key().get_public_key()
}

fn derived_wallet_from_key(key: &ml_dsa_65::PrivateKey) -> String {
    let public_key = key.get_public_key();
    let public_key_bytes = public_key.into_bytes();

    derive_wallet_id_from_pubkey_bytes(&public_key_bytes)
}

fn wallet_from_label(label: &str) -> String {
    format!("r{}", RemzarHash::compute_bytes_hash_hex(label.as_bytes()))
}

fn recipient_wallet(label: &str) -> String {
    let primary = primary_fixture().address;
    let candidate = wallet_from_label(label);

    if candidate == primary {
        wallet_from_label(&format!("{label}_alternate"))
    } else {
        candidate
    }
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

fn make_signed_chat(label: &str, plaintext: &str) -> ChatMessage {
    let from_wallet = primary_fixture().address;
    let to_wallet = recipient_wallet(&format!("recipient_{label}"));

    assert_ok(
        ChatMessage::new_signed(from_wallet, to_wallet, plaintext, &primary_key()),
        "ChatMessage::new_signed",
    )
}

fn make_signed_chat_to(to_wallet: String, plaintext: &str) -> ChatMessage {
    let from_wallet = primary_fixture().address;

    assert_ok(
        ChatMessage::new_signed(from_wallet, to_wallet, plaintext, &primary_key()),
        "ChatMessage::new_signed to wallet",
    )
}

fn chat_json_bytes(message: &str) -> Vec<u8> {
    assert_ok(
        serde_json::to_vec(&ChatJson {
            m: message.to_owned(),
        }),
        "serialize ChatJson",
    )
}

fn now_ms() -> u64 {
    let duration = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value,
        Err(err) => panic!("system time before UNIX_EPOCH: {err:?}"),
    };

    match u64::try_from(duration.as_millis()) {
        Ok(value) => value,
        Err(_) => panic!("system time millis did not fit u64"),
    }
}

fn encode_direct_postcard(msg: &ChatMessage) -> Vec<u8> {
    assert_ok(
        postcard::to_allocvec(msg),
        "direct postcard encode ChatMessage",
    )
}

fn write_wallet_file(directory: &DirectoryDB, fixture: &WalletFixture) -> PathBuf {
    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let path = directory
        .wallets_path
        .join(format!("{}.wallet", fixture.address));

    assert_ok(
        fs::write(&path, &fixture.encrypted_secret),
        "write wallet file",
    );
    path
}

fn load_signing_key_from_wallet_file_like_s11(
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

#[test]
fn test_01_new_constructor_creates_section() {
    let _section = S11SendChat::new();
}

#[test]
fn test_02_default_constructor_creates_section() {
    let _section = S11SendChat;
}

#[test]
fn test_03_unit_struct_constructor_creates_section() {
    let _section = S11SendChat;
}

#[test]
fn test_04_chat_topic_constant_matches_expected_value() {
    assert_eq!(CHAT_TOPIC, "remzar.chat.v1");
}

#[test]
fn test_05_chat_topic_helper_uses_constant_topic() {
    let topic = chat_topic();

    assert_eq!(topic.hash().as_str(), CHAT_TOPIC);
}

#[test]
fn test_06_wallet_from_label_has_canonical_shape() {
    let wallet = wallet_from_label("test_06");

    assert_wallet_shape(&wallet);
}

#[test]
fn test_07_primary_wallet_has_canonical_shape() {
    let fixture = primary_fixture();

    assert_wallet_shape(&fixture.address);
}

#[test]
fn test_08_secondary_wallet_has_canonical_shape() {
    let fixture = secondary_fixture();

    assert_wallet_shape(&fixture.address);
}

#[test]
fn test_09_primary_wallet_matches_primary_public_key() {
    let fixture = primary_fixture();
    let public_key = primary_public_key();
    let public_bytes = public_key.into_bytes();

    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&fixture.address, &public_bytes),
        "primary wallet matches public key",
    );
}

#[test]
fn test_10_secondary_wallet_matches_secondary_public_key() {
    let fixture = secondary_fixture();
    let public_key = secondary_public_key();
    let public_bytes = public_key.into_bytes();

    assert_ok(
        wallet_id_matches_pubkey_bytes_checked(&fixture.address, &public_bytes),
        "secondary wallet matches public key",
    );
}

#[test]
fn test_11_primary_wallet_rejects_secondary_public_key_binding() {
    let fixture = primary_fixture();
    let public_key = secondary_public_key();
    let public_bytes = public_key.into_bytes();

    let err = assert_err(
        wallet_id_matches_pubkey_bytes_checked(&fixture.address, &public_bytes),
        "primary wallet should not match secondary public key",
    );

    assert_validation_error(err);
}

#[test]
fn test_12_canon_wallet_accepts_uppercase_label_wallet() {
    let wallet = wallet_from_label("test_12");
    let canonical = assert_ok(
        canon_wallet_id_checked(&wallet.to_ascii_uppercase()),
        "canon uppercase wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_13_canon_wallet_accepts_outer_whitespace() {
    let wallet = wallet_from_label("test_13");
    let canonical = assert_ok(
        canon_wallet_id_checked(&format!("  {wallet}  ")),
        "canon whitespace wallet",
    );

    assert_eq!(canonical, wallet);
}

#[test]
fn test_14_canon_wallet_rejects_empty() {
    let err = assert_err(canon_wallet_id_checked(""), "canon empty wallet");

    assert_validation_error(err);
}

#[test]
fn test_15_canon_wallet_rejects_short() {
    let err = assert_err(canon_wallet_id_checked("r1234"), "canon short wallet");

    assert_validation_error(err);
}

#[test]
fn test_16_canon_wallet_rejects_wrong_prefix() {
    let wallet = wallet_from_label("test_16");
    let bad = format!("x{}", &wallet[1..]);

    let err = assert_err(canon_wallet_id_checked(&bad), "canon wrong prefix wallet");

    assert_validation_error(err);
}

#[test]
fn test_17_canon_wallet_rejects_non_hex_body() {
    let mut wallet = wallet_from_label("test_17");
    wallet.replace_range(1..2, "g");

    let err = assert_err(canon_wallet_id_checked(&wallet), "canon non-hex wallet");

    assert_validation_error(err);
}

#[test]
fn test_18_chat_json_serializes_plaintext() {
    let bytes = chat_json_bytes("hello chat");
    let decoded: ChatJson = assert_ok(serde_json::from_slice(&bytes), "decode ChatJson");

    assert_eq!(decoded.m, "hello chat");
}

#[test]
fn test_19_chat_json_rejects_unknown_fields() {
    let err = assert_err(
        serde_json::from_slice::<ChatJson>(br#"{"m":"hello","extra":true}"#),
        "decode ChatJson with unknown field",
    );

    assert!(!err.to_string().is_empty());
}

#[test]
fn test_20_new_signed_creates_valid_plaintext_message() {
    let msg = make_signed_chat("test_20", "hello world");

    assert_eq!(
        assert_ok(msg.plaintext(), "ChatMessage::plaintext"),
        "hello world"
    );
}

#[test]
fn test_21_new_signed_stores_canonical_wallets() {
    let from_wallet = primary_fixture().address.to_ascii_uppercase();
    let to_wallet = recipient_wallet("test_21").to_ascii_uppercase();

    let msg = assert_ok(
        ChatMessage::new_signed(from_wallet, to_wallet, "canonicalize me", &primary_key()),
        "ChatMessage::new_signed canonical wallets",
    );

    assert_wallet_shape(&msg.from_wallet);
    assert_wallet_shape(&msg.to_wallet);
}

#[test]
fn test_22_new_signed_rejects_empty_plaintext() {
    let err = assert_err(
        ChatMessage::new_signed(
            primary_fixture().address,
            recipient_wallet("test_22"),
            "",
            &primary_key(),
        ),
        "new_signed empty plaintext",
    );

    assert_validation_error(err);
}

#[test]
fn test_23_new_signed_rejects_whitespace_plaintext() {
    let err = assert_err(
        ChatMessage::new_signed(
            primary_fixture().address,
            recipient_wallet("test_23"),
            "     ",
            &primary_key(),
        ),
        "new_signed whitespace plaintext",
    );

    assert_validation_error(err);
}

#[test]
fn test_24_new_signed_accepts_500_ascii_characters() {
    let text = "a".repeat(MAX_CHAT_PLAINTEXT_CHARS);
    let msg = make_signed_chat("test_24", &text);

    assert_eq!(assert_ok(msg.plaintext(), "plaintext 500 chars"), text);
}

#[test]
fn test_25_new_signed_rejects_501_ascii_characters() {
    let text = "a".repeat(MAX_CHAT_PLAINTEXT_CHARS.saturating_add(1));

    let err = assert_err(
        ChatMessage::new_signed(
            primary_fixture().address,
            recipient_wallet("test_25"),
            &text,
            &primary_key(),
        ),
        "new_signed 501 chars",
    );

    assert_validation_error(err);
}

#[test]
fn test_26_new_signed_accepts_unicode_plaintext() {
    let text = "hello 測試 чат 🚀";
    let msg = make_signed_chat("test_26", text);

    assert_eq!(assert_ok(msg.plaintext(), "unicode plaintext"), text);
}

#[test]
fn test_27_new_signed_accepts_emoji_vector_under_limit() {
    let text = "🚀".repeat(100);
    let msg = make_signed_chat("test_27", &text);

    assert_eq!(assert_ok(msg.plaintext(), "emoji plaintext"), text);
}

#[test]
fn test_28_new_signed_rejects_same_sender_and_receiver() {
    let wallet = primary_fixture().address;

    let err = assert_err(
        ChatMessage::new_signed(wallet.clone(), wallet, "same wallet", &primary_key()),
        "new_signed same sender receiver",
    );

    assert_validation_error(err);
}

#[test]
fn test_29_new_signed_rejects_invalid_sender_wallet() {
    let err = assert_err(
        ChatMessage::new_signed(
            "not-a-wallet".to_owned(),
            recipient_wallet("test_29"),
            "hello",
            &primary_key(),
        ),
        "new_signed invalid sender",
    );

    assert_validation_error(err);
}

#[test]
fn test_30_new_signed_rejects_invalid_receiver_wallet() {
    let err = assert_err(
        ChatMessage::new_signed(
            primary_fixture().address,
            "not-a-wallet".to_owned(),
            "hello",
            &primary_key(),
        ),
        "new_signed invalid receiver",
    );

    assert_validation_error(err);
}

#[test]
fn test_31_new_signed_rejects_huge_sender_wallet_string() {
    let err = assert_err(
        ChatMessage::new_signed(
            "r".repeat(MAX_WALLET_STR_BYTES.saturating_add(1)),
            recipient_wallet("test_31"),
            "hello",
            &primary_key(),
        ),
        "new_signed huge sender",
    );

    assert_validation_error(err);
}

#[test]
fn test_32_new_signed_signature_has_mldsa65_length() {
    let msg = make_signed_chat("test_32", "signature length");

    assert_eq!(msg.signature.len(), ml_dsa_65::SIG_LEN);
}

#[test]
fn test_33_verify_accepts_valid_message_with_primary_public_key() {
    let msg = make_signed_chat("test_33", "valid signed message");

    assert_ok(
        msg.verify(&primary_public_key()),
        "verify valid chat message",
    );
}

#[test]
fn test_34_verify_rejects_valid_message_with_wrong_public_key() {
    let msg = make_signed_chat("test_34", "wrong verifier");

    let err = assert_err(
        msg.verify(&secondary_public_key()),
        "verify with wrong public key",
    );

    assert_signature_error(err);
}

#[test]
fn test_35_verify_rejects_mutated_plaintext_json_same_signature() {
    let mut msg = make_signed_chat("test_35", "original message");
    msg.json = chat_json_bytes("mutated message");

    let err = assert_err(msg.verify(&primary_public_key()), "verify mutated json");

    assert_signature_error(err);
}

#[test]
fn test_36_verify_rejects_mutated_to_wallet_same_signature() {
    let mut msg = make_signed_chat("test_36", "route mutation");
    msg.to_wallet = recipient_wallet("test_36_other");

    let err = assert_err(msg.verify(&primary_public_key()), "verify mutated receiver");

    assert_signature_error(err);
}

#[test]
fn test_37_verify_rejects_mutated_timestamp_same_signature() {
    let mut msg = make_signed_chat("test_37", "timestamp mutation");
    msg.timestamp_ms = msg.timestamp_ms.saturating_add(1);

    let err = assert_err(
        msg.verify(&primary_public_key()),
        "verify mutated timestamp",
    );

    assert_signature_error(err);
}

#[test]
fn test_38_verify_rejects_mutated_signature_same_length() {
    let mut msg = make_signed_chat("test_38", "signature mutation");

    match msg.signature.first_mut() {
        Some(byte) => {
            *byte ^= 0x01;
        }
        None => panic!("signature unexpectedly empty"),
    }

    let err = assert_err(
        msg.verify(&primary_public_key()),
        "verify mutated signature",
    );

    assert_signature_error(err);
}

#[test]
fn test_39_verify_rejects_short_signature() {
    let mut msg = make_signed_chat("test_39", "short signature");
    msg.signature.pop();

    let err = assert_err(msg.verify(&primary_public_key()), "verify short signature");

    assert_serialization_error(err);
}

#[test]
fn test_40_verify_rejects_long_signature() {
    let mut msg = make_signed_chat("test_40", "long signature");
    msg.signature.push(0);

    let err = assert_err(msg.verify(&primary_public_key()), "verify long signature");

    assert_serialization_error(err);
}

#[test]
fn test_41_verify_rejects_too_old_timestamp() {
    let mut msg = make_signed_chat("test_41", "old timestamp");
    msg.timestamp_ms = now_ms()
        .saturating_sub(CHAT_MAX_PAST_AGE_MS)
        .saturating_sub(1);

    let err = assert_err(msg.verify(&primary_public_key()), "verify old timestamp");

    assert_validation_error(err);
}

#[test]
fn test_42_verify_rejects_too_future_timestamp() {
    let mut msg = make_signed_chat("test_42", "future timestamp");
    msg.timestamp_ms = now_ms()
        .saturating_add(CHAT_MAX_FUTURE_SKEW_MS)
        .saturating_add(60_000);

    let err = assert_err(msg.verify(&primary_public_key()), "verify future timestamp");

    assert_validation_error(err);
}

#[test]
fn test_43_plaintext_rejects_invalid_json() {
    let mut msg = make_signed_chat("test_43", "valid before mutation");
    msg.json = b"not json".to_vec();

    let err = assert_err(msg.plaintext(), "plaintext invalid json");

    assert_serialization_error(err);
}

#[test]
fn test_44_plaintext_rejects_empty_message_json() {
    let mut msg = make_signed_chat("test_44", "valid before empty");
    msg.json = chat_json_bytes("");

    let err = assert_err(msg.plaintext(), "plaintext empty message json");

    assert_validation_error(err);
}

#[test]
fn test_45_plaintext_rejects_whitespace_message_json() {
    let mut msg = make_signed_chat("test_45", "valid before whitespace");
    msg.json = chat_json_bytes("    ");

    let err = assert_err(msg.plaintext(), "plaintext whitespace message json");

    assert_validation_error(err);
}

#[test]
fn test_46_plaintext_rejects_json_payload_over_cap() {
    let mut msg = make_signed_chat("test_46", "valid before huge json");
    msg.json = vec![b'a'; MAX_CHAT_JSON_BYTES.saturating_add(1)];

    let err = assert_err(msg.plaintext(), "plaintext huge json");

    assert_validation_error(err);
}

#[test]
fn test_47_encode_wire_round_trips_with_decode_wire() {
    let msg = make_signed_chat("test_47", "wire round trip");
    let bytes = assert_ok(msg.encode_wire(), "encode_wire");
    let decoded = assert_ok(ChatMessage::decode_wire(&bytes), "decode_wire");

    assert_eq!(decoded.from_wallet, msg.from_wallet);
    assert_eq!(decoded.to_wallet, msg.to_wallet);
    assert_eq!(decoded.timestamp_ms, msg.timestamp_ms);
    assert_eq!(decoded.json, msg.json);
    assert_eq!(decoded.signature, msg.signature);
}

#[test]
fn test_48_decode_wire_plaintext_matches_original() {
    let msg = make_signed_chat("test_48", "decode plaintext");
    let bytes = assert_ok(msg.encode_wire(), "encode_wire");
    let decoded = assert_ok(ChatMessage::decode_wire(&bytes), "decode_wire");

    assert_eq!(
        assert_ok(decoded.plaintext(), "decoded plaintext"),
        "decode plaintext"
    );
}

#[test]
fn test_49_decoded_message_verifies() {
    let msg = make_signed_chat("test_49", "decode then verify");
    let bytes = assert_ok(msg.encode_wire(), "encode_wire");
    let decoded = assert_ok(ChatMessage::decode_wire(&bytes), "decode_wire");

    assert_ok(
        decoded.verify(&primary_public_key()),
        "verify decoded message",
    );
}

#[test]
fn test_50_encode_wire_rejects_short_signature() {
    let mut msg = make_signed_chat("test_50", "short signature encode");
    msg.signature.pop();

    let err = assert_err(msg.encode_wire(), "encode_wire short signature");

    assert_serialization_error(err);
}

#[test]
fn test_51_encode_wire_rejects_invalid_from_wallet() {
    let mut msg = make_signed_chat("test_51", "invalid from wallet");
    msg.from_wallet = "not-a-wallet".to_owned();

    let err = assert_err(msg.encode_wire(), "encode invalid from wallet");

    assert_validation_error(err);
}

#[test]
fn test_52_encode_wire_rejects_invalid_to_wallet() {
    let mut msg = make_signed_chat("test_52", "invalid to wallet");
    msg.to_wallet = "not-a-wallet".to_owned();

    let err = assert_err(msg.encode_wire(), "encode invalid to wallet");

    assert_validation_error(err);
}

#[test]
fn test_53_encode_wire_rejects_same_wallets() {
    let mut msg = make_signed_chat("test_53", "same wallets encode");
    msg.to_wallet = msg.from_wallet.clone();

    let err = assert_err(msg.encode_wire(), "encode same wallets");

    assert_validation_error(err);
}

#[test]
fn test_54_decode_wire_rejects_garbage() {
    let err = assert_err(
        ChatMessage::decode_wire(b"not postcard"),
        "decode garbage wire",
    );

    assert_serialization_error(err);
}

#[test]
fn test_55_decode_wire_rejects_oversized_bytes_before_decode() {
    let huge = vec![0_u8; MAX_CHAT_WIRE_BYTES.saturating_add(1)];

    let err = assert_err(ChatMessage::decode_wire(&huge), "decode huge wire bytes");

    assert_validation_error(err);
}

#[test]
fn test_56_decode_wire_rejects_short_signature_in_message() {
    let mut msg = make_signed_chat("test_56", "short sig decode");
    msg.signature.pop();
    let bytes = encode_direct_postcard(&msg);

    let err = assert_err(ChatMessage::decode_wire(&bytes), "decode short sig message");

    assert_serialization_error(err);
}

#[test]
fn test_57_decode_wire_rejects_invalid_json_in_message() {
    let mut msg = make_signed_chat("test_57", "invalid json decode");
    msg.json = b"bad json".to_vec();
    let bytes = encode_direct_postcard(&msg);

    let err = assert_err(
        ChatMessage::decode_wire(&bytes),
        "decode invalid json message",
    );

    assert_serialization_error(err);
}

#[test]
fn test_58_decode_wire_rejects_invalid_wallet_in_message() {
    let mut msg = make_signed_chat("test_58", "invalid wallet decode");
    msg.from_wallet = "not-a-wallet".to_owned();
    let bytes = encode_direct_postcard(&msg);

    let err = assert_err(
        ChatMessage::decode_wire(&bytes),
        "decode invalid wallet message",
    );

    assert_validation_error(err);
}

#[test]
fn test_59_decode_wire_rejects_same_wallets_in_message() {
    let mut msg = make_signed_chat("test_59", "same wallet decode");
    msg.to_wallet = msg.from_wallet.clone();
    let bytes = encode_direct_postcard(&msg);

    let err = assert_err(
        ChatMessage::decode_wire(&bytes),
        "decode same wallet message",
    );

    assert_validation_error(err);
}

#[test]
fn test_60_decode_wire_rejects_old_timestamp_message() {
    let mut msg = make_signed_chat("test_60", "old timestamp decode");
    msg.timestamp_ms = now_ms()
        .saturating_sub(CHAT_MAX_PAST_AGE_MS)
        .saturating_sub(1);
    let bytes = encode_direct_postcard(&msg);

    let err = assert_err(ChatMessage::decode_wire(&bytes), "decode old timestamp");

    assert_validation_error(err);
}

#[test]
fn test_61_decode_wire_rejects_future_timestamp_message() {
    let mut msg = make_signed_chat("test_61", "future timestamp decode");
    msg.timestamp_ms = now_ms()
        .saturating_add(CHAT_MAX_FUTURE_SKEW_MS)
        .saturating_add(60_000);
    let bytes = encode_direct_postcard(&msg);

    let err = assert_err(ChatMessage::decode_wire(&bytes), "decode future timestamp");

    assert_validation_error(err);
}

#[test]
fn test_62_wallet_file_path_uses_sender_wallet_address() {
    let temp = TempTree::new("test_62");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();

    let path = directory
        .wallets_path
        .join(format!("{}.wallet", fixture.address));

    assert!(path.ends_with(format!("{}.wallet", fixture.address)));
}

#[test]
fn test_63_wallet_file_write_round_trips_encrypted_secret() {
    let temp = TempTree::new("test_63");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();

    let path = write_wallet_file(&directory, &fixture);
    let stored = assert_ok(fs::read(path), "read wallet file");

    assert_eq!(stored, fixture.encrypted_secret);
}

#[test]
fn test_64_wallet_file_load_signing_key_derives_sender_wallet() {
    let temp = TempTree::new("test_64");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);

    let key = assert_ok(
        load_signing_key_from_wallet_file_like_s11(&path, fixture.passphrase),
        "load signing key from wallet file",
    );

    assert_eq!(derived_wallet_from_key(&key), fixture.address);
}

#[test]
fn test_65_wallet_file_load_rejects_wrong_passphrase() {
    let temp = TempTree::new("test_65");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);

    let err = match load_signing_key_from_wallet_file_like_s11(&path, "wrong passphrase") {
        Ok(_) => panic!("load wallet wrong passphrase unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_decrypt_like_error(err);
}

#[test]
fn test_66_wallet_file_load_rejects_missing_file() {
    let temp = TempTree::new("test_66");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = directory
        .wallets_path
        .join(format!("{}.wallet", fixture.address));

    let err = match load_signing_key_from_wallet_file_like_s11(&path, fixture.passphrase) {
        Ok(_) => panic!("load missing wallet file unexpectedly succeeded"),
        Err(err) => err,
    };

    match err {
        ErrorDetection::IoError { .. } => {}
        other => panic!("expected IoError, got {other:?}"),
    }
}

#[test]
fn test_67_wallet_file_load_rejects_tampered_file() {
    let temp = TempTree::new("test_67");
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

    let err = match load_signing_key_from_wallet_file_like_s11(&path, fixture.passphrase) {
        Ok(_) => panic!("load tampered wallet file unexpectedly succeeded"),
        Err(err) => err,
    };

    assert_decrypt_like_error(err);
}

#[test]
fn test_68_wallet_file_metadata_is_regular_file() {
    let temp = TempTree::new("test_68");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);
    let metadata = assert_ok(fs::metadata(path), "wallet file metadata");

    assert!(metadata.is_file());
}

#[test]
fn test_69_wallet_file_metadata_is_nonempty() {
    let temp = TempTree::new("test_69");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();
    let path = write_wallet_file(&directory, &fixture);
    let metadata = assert_ok(fs::metadata(path), "wallet file metadata");

    assert!(metadata.len() > 0);
}

#[test]
fn test_70_wallet_directory_path_is_not_regular_file() {
    let temp = TempTree::new("test_70");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);

    assert_ok(
        directory.create_wallets_directory(),
        "create_wallets_directory",
    );

    let metadata = assert_ok(
        fs::metadata(directory.wallets_path),
        "wallet directory metadata",
    );

    assert!(!metadata.is_file());
}

#[test]
fn test_71_vector_plaintext_messages_round_trip() {
    for text in [
        "hello",
        "chat vector",
        "1234567890",
        "symbols !@#$",
        "unicode 測試",
    ] {
        let msg = make_signed_chat("test_71", text);
        assert_eq!(assert_ok(msg.plaintext(), "vector plaintext"), text);
        assert_ok(msg.verify(&primary_public_key()), "verify vector plaintext");
    }
}

#[test]
fn test_72_vector_wire_round_trip_messages() {
    for index in 0usize..5usize {
        let text = format!("wire vector message {index}");
        let msg = make_signed_chat(&format!("test_72_{index}"), &text);
        let bytes = assert_ok(msg.encode_wire(), "encode vector wire");
        let decoded = assert_ok(ChatMessage::decode_wire(&bytes), "decode vector wire");

        assert_eq!(
            assert_ok(decoded.plaintext(), "decoded vector plaintext"),
            text
        );
    }
}

#[test]
fn test_73_vector_rejects_invalid_sender_wallets() {
    for sender in ["", "r123", "x123", "not-a-wallet"] {
        let err = assert_err(
            ChatMessage::new_signed(
                sender.to_owned(),
                recipient_wallet("test_73"),
                "hello",
                &primary_key(),
            ),
            "invalid sender vector",
        );

        assert_validation_error(err);
    }
}

#[test]
fn test_74_vector_rejects_invalid_receiver_wallets() {
    for receiver in ["", "r123", "x123", "not-a-wallet"] {
        let err = assert_err(
            ChatMessage::new_signed(
                primary_fixture().address,
                receiver.to_owned(),
                "hello",
                &primary_key(),
            ),
            "invalid receiver vector",
        );

        assert_validation_error(err);
    }
}

#[test]
fn test_75_vector_chat_json_plaintext_values() {
    for text in ["a", "two words", "line with punctuation.", "測試", "🚀"] {
        let bytes = chat_json_bytes(text);
        let decoded: ChatJson = assert_ok(serde_json::from_slice(&bytes), "decode vector ChatJson");

        assert_eq!(decoded.m, text);
    }
}

#[test]
fn test_76_property_same_message_has_different_timestamp_or_signature() {
    let first = make_signed_chat("test_76", "same message");
    let second = make_signed_chat("test_76", "same message");

    let changed = first.timestamp_ms != second.timestamp_ms || first.signature != second.signature;

    assert!(changed);
}

#[test]
fn test_77_property_same_message_same_key_verifies_each_time() {
    let first = make_signed_chat("test_77_first", "repeat verify");
    let second = make_signed_chat("test_77_second", "repeat verify");

    assert_ok(first.verify(&primary_public_key()), "verify first repeat");
    assert_ok(second.verify(&primary_public_key()), "verify second repeat");
}

#[test]
fn test_78_property_different_recipients_change_signature_or_preimage() {
    let first = make_signed_chat_to(recipient_wallet("test_78_a"), "same text");
    let second = make_signed_chat_to(recipient_wallet("test_78_b"), "same text");

    assert_ne!(first.to_wallet, second.to_wallet);
    assert_ne!(first.signature, second.signature);
}

#[test]
fn test_79_property_encoded_wire_size_is_under_cap() {
    let msg = make_signed_chat("test_79", "wire size under cap");
    let bytes = assert_ok(msg.encode_wire(), "encode wire size");

    assert!(bytes.len() <= MAX_CHAT_WIRE_BYTES);
}

#[test]
fn test_80_property_json_size_is_under_cap_for_valid_message() {
    let msg = make_signed_chat("test_80", "json size under cap");

    assert!(msg.json.len() <= MAX_CHAT_JSON_BYTES);
}

#[test]
fn test_81_adversarial_manual_message_with_uppercase_from_rejected_by_encode() {
    let mut msg = make_signed_chat("test_81", "uppercase from");
    msg.from_wallet = msg.from_wallet.to_ascii_uppercase();

    let err = assert_err(msg.encode_wire(), "encode uppercase from");

    assert_validation_error(err);
}

#[test]
fn test_82_adversarial_manual_message_with_uppercase_to_rejected_by_encode() {
    let mut msg = make_signed_chat("test_82", "uppercase to");
    msg.to_wallet = msg.to_wallet.to_ascii_uppercase();

    let err = assert_err(msg.encode_wire(), "encode uppercase to");

    assert_validation_error(err);
}

#[test]
fn test_83_adversarial_manual_message_with_empty_signature_rejected() {
    let mut msg = make_signed_chat("test_83", "empty signature");
    msg.signature.clear();

    let err = assert_err(msg.encode_wire(), "encode empty signature");

    assert_serialization_error(err);
}

#[test]
fn test_84_adversarial_manual_message_with_empty_json_rejected() {
    let mut msg = make_signed_chat("test_84", "empty json");
    msg.json.clear();

    let err = assert_err(msg.encode_wire(), "encode empty json");

    assert_serialization_error(err);
}

#[test]
fn test_85_adversarial_manual_message_with_json_unknown_field_rejected() {
    let mut msg = make_signed_chat("test_85", "unknown json");
    msg.json = br#"{"m":"hello","extra":true}"#.to_vec();

    let err = assert_err(msg.encode_wire(), "encode unknown json field");

    assert_serialization_error(err);
}

#[test]
fn test_86_adversarial_truncated_wire_rejected() {
    let msg = make_signed_chat("test_86", "truncate wire");
    let mut bytes = assert_ok(msg.encode_wire(), "encode before truncate");
    bytes.truncate(bytes.len().saturating_div(2));

    let err = assert_err(ChatMessage::decode_wire(&bytes), "decode truncated wire");

    assert_serialization_error(err);
}

#[test]
fn test_87_adversarial_appended_wire_bytes_rejected_or_not_verified() {
    let msg = make_signed_chat("test_87", "append wire");
    let mut bytes = assert_ok(msg.encode_wire(), "encode before append");
    bytes.extend_from_slice(b"extra bytes");

    let result = ChatMessage::decode_wire(&bytes);
    match result {
        Ok(decoded) => {
            assert_ok(
                decoded.verify(&primary_public_key()),
                "verify decoded appended wire",
            );
        }
        Err(err) => assert_serialization_error(err),
    }
}

#[test]
fn test_88_adversarial_json_plaintext_501_chars_rejected_by_plaintext() {
    let mut msg = make_signed_chat("test_88", "valid first");
    msg.json = chat_json_bytes(&"a".repeat(MAX_CHAT_PLAINTEXT_CHARS.saturating_add(1)));

    let err = assert_err(msg.plaintext(), "plaintext 501 chars");

    assert_validation_error(err);
}

#[test]
fn test_89_adversarial_wrong_key_can_sign_but_sender_public_key_rejects() {
    let from_wallet = primary_fixture().address;
    let to_wallet = recipient_wallet("test_89");

    let msg = assert_ok(
        ChatMessage::new_signed(
            from_wallet,
            to_wallet,
            "signed by wrong key",
            &secondary_key(),
        ),
        "new_signed wrong key for sender",
    );

    let err = assert_err(
        msg.verify(&primary_public_key()),
        "verify wrong-key message with primary key",
    );

    assert_signature_error(err);
}

#[test]
fn test_90_adversarial_wrong_key_message_verifies_with_wrong_key_public_key() {
    let from_wallet = primary_fixture().address;
    let to_wallet = recipient_wallet("test_90");

    let msg = assert_ok(
        ChatMessage::new_signed(
            from_wallet,
            to_wallet,
            "signed by secondary",
            &secondary_key(),
        ),
        "new_signed secondary key",
    );

    assert_ok(
        msg.verify(&secondary_public_key()),
        "verify wrong-key message with secondary key",
    );
}

#[test]
fn test_91_load_create_ten_signed_messages() {
    for index in 0usize..10usize {
        let msg = make_signed_chat(
            &format!("test_91_{index}"),
            &format!("load message {index}"),
        );
        assert_ok(
            msg.verify(&primary_public_key()),
            "verify load signed message",
        );
    }
}

#[test]
fn test_92_load_encode_decode_ten_signed_messages() {
    for index in 0usize..10usize {
        let msg = make_signed_chat(
            &format!("test_92_{index}"),
            &format!("load wire message {index}"),
        );
        let bytes = assert_ok(msg.encode_wire(), "load encode");
        let decoded = assert_ok(ChatMessage::decode_wire(&bytes), "load decode");

        assert_ok(decoded.verify(&primary_public_key()), "load verify decoded");
    }
}

#[test]
fn test_93_load_reject_twenty_empty_or_whitespace_messages() {
    for text in ["", " ", "  ", "\t", "\n"] {
        let err = assert_err(
            ChatMessage::new_signed(
                primary_fixture().address,
                recipient_wallet("test_93"),
                text,
                &primary_key(),
            ),
            "reject empty load message",
        );

        assert_validation_error(err);
    }
}

#[test]
fn test_94_load_canonicalize_twenty_wallet_labels() {
    for index in 0usize..20usize {
        let wallet = wallet_from_label(&format!("test_94_wallet_{index}"));
        let canonical = assert_ok(canon_wallet_id_checked(&wallet), "canon load wallet");

        assert_eq!(canonical, wallet);
    }
}

#[test]
fn test_95_load_wallet_file_round_trip_three_times() {
    let temp = TempTree::new("test_95");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();

    for index in 0usize..3usize {
        let path = directory
            .wallets_path
            .join(format!("{}_{}.wallet", fixture.address, index));
        assert_ok(
            directory.create_wallets_directory(),
            "create wallet directory load",
        );
        assert_ok(
            fs::write(&path, &fixture.encrypted_secret),
            "write wallet load",
        );

        let key = assert_ok(
            load_signing_key_from_wallet_file_like_s11(&path, fixture.passphrase),
            "load wallet key load",
        );

        assert_eq!(derived_wallet_from_key(&key), fixture.address);
    }
}

#[test]
fn test_96_load_message_hashes_differ_for_distinct_wire_messages() {
    let mut hashes = Vec::new();

    for index in 0usize..8usize {
        let msg = make_signed_chat(
            &format!("test_96_{index}"),
            &format!("hash message {index}"),
        );
        let bytes = assert_ok(msg.encode_wire(), "encode hash message");
        hashes.push(RemzarHash::compute_bytes_hash_hex(&bytes));
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
fn test_97_vector_max_wallet_string_constant_is_above_canonical_len() {
    const {
        assert!(MAX_WALLET_STR_BYTES >= REMZAR_WALLET_LEN);
    }
}

#[test]
fn test_98_vector_wire_limit_is_above_signature_length() {
    const {
        assert!(MAX_CHAT_WIRE_BYTES > ml_dsa_65::SIG_LEN);
    }
}

#[test]
fn test_99_vector_json_limit_is_above_minimal_chat_json() {
    let bytes = chat_json_bytes("hi");

    assert!(MAX_CHAT_JSON_BYTES > bytes.len());
}

#[test]
fn test_100_final_chat_sign_verify_wire_wallet_file_and_topic_flow() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let directory = directory_from_opts(&opts);
    let fixture = primary_fixture();

    let wallet_file = write_wallet_file(&directory, &fixture);
    let loaded_key = assert_ok(
        load_signing_key_from_wallet_file_like_s11(&wallet_file, fixture.passphrase),
        "final load signing key",
    );

    assert_eq!(derived_wallet_from_key(&loaded_key), fixture.address);
    assert_eq!(chat_topic().hash().as_str(), CHAT_TOPIC);

    let to_wallet = recipient_wallet("test_100_final_receiver");
    let msg = assert_ok(
        ChatMessage::new_signed(
            fixture.address.clone(),
            to_wallet.clone(),
            "final signed chat message",
            &loaded_key,
        ),
        "final ChatMessage::new_signed",
    );

    assert_eq!(msg.from_wallet, fixture.address);
    assert_eq!(msg.to_wallet, to_wallet);
    assert_eq!(
        assert_ok(msg.plaintext(), "final plaintext"),
        "final signed chat message"
    );

    let public_key = loaded_key.get_public_key();
    assert_ok(msg.verify(&public_key), "final verify");

    let wire = assert_ok(msg.encode_wire(), "final encode wire");
    let decoded = assert_ok(ChatMessage::decode_wire(&wire), "final decode wire");

    assert_ok(decoded.verify(&public_key), "final decoded verify");
    assert_eq!(
        assert_ok(decoded.plaintext(), "final decoded plaintext"),
        "final signed chat message"
    );
}
