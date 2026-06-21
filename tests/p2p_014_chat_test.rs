#![forbid(unsafe_code)]

use anyhow::{Result, anyhow};
use fips204::{ml_dsa_65, traits::KeyGen};
use libp2p::gossipsub::{self, Message};
use remzar::network::p2p_014_chat::{
    CHAT_MAX_FUTURE_SKEW_MS, CHAT_MAX_PAST_AGE_MS, CHAT_TOPIC, ChatJson, ChatMessage,
    MAX_CHAT_JSON_BYTES, MAX_CHAT_PLAINTEXT_BYTES, MAX_CHAT_PLAINTEXT_CHARS, MAX_CHAT_WIRE_BYTES,
    MAX_WALLET_STR_BYTES, chat_topic, publish_chat, try_decode_incoming,
};
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;

fn wallet(seed: u128) -> String {
    format!("r{seed:0128x}")
}

fn uppercase_wallet(seed: u128) -> String {
    format!("r{seed:0128X}")
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0_u64)
}

fn keypair() -> Result<(ml_dsa_65::PublicKey, ml_dsa_65::PrivateKey)> {
    ml_dsa_65::KG::try_keygen().map_err(|err| anyhow!("ML-DSA-65 keygen failed: {err}"))
}

fn signed_chat(seed: u128, plaintext: &str) -> Result<(ChatMessage, ml_dsa_65::PublicKey)> {
    let (vk, sk) = keypair()?;
    let msg = ChatMessage::new_signed(
        wallet(seed),
        wallet(seed.saturating_add(1_u128)),
        plaintext,
        &sk,
    )?;
    Ok((msg, vk))
}

fn manual_message(
    from_wallet: String,
    to_wallet: String,
    timestamp_ms: u64,
    plaintext: &str,
    signature_len: usize,
) -> Result<ChatMessage> {
    let json = serde_json::to_vec(&ChatJson {
        m: plaintext.to_owned(),
    })?;

    Ok(ChatMessage {
        from_wallet,
        to_wallet,
        timestamp_ms,
        json,
        signature: vec![0_u8; signature_len],
    })
}

fn gossipsub_message(data: Vec<u8>) -> Message {
    Message {
        source: None,
        data,
        sequence_number: None,
        topic: chat_topic().hash(),
    }
}

fn assert_message_same(left: &ChatMessage, right: &ChatMessage) {
    assert_eq!(left.from_wallet, right.from_wallet);
    assert_eq!(left.to_wallet, right.to_wallet);
    assert_eq!(left.timestamp_ms, right.timestamp_ms);
    assert_eq!(left.json, right.json);
    assert_eq!(left.signature, right.signature);
}

fn assert_error_contains<T>(
    result: std::result::Result<T, ErrorDetection>,
    needle: &str,
) -> Result<()> {
    match result {
        Err(err) => {
            let rendered = format!("{err} {err:?}");
            assert!(
                rendered.contains(needle),
                "expected error containing `{needle}`, got `{rendered}`"
            );
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected error containing `{needle}`")),
    }
}

/* ───────────────────────── constants / topic helpers ───────────────────── */

#[test]
fn test_001_chat_constants_match_contract() -> Result<()> {
    assert_eq!(CHAT_TOPIC, "remzar.chat.v1");
    assert_eq!(MAX_CHAT_PLAINTEXT_CHARS, 500_usize);
    assert_eq!(MAX_CHAT_PLAINTEXT_BYTES, 2_usize * 1024_usize);
    assert_eq!(MAX_CHAT_JSON_BYTES, 4_usize * 1024_usize);
    assert_eq!(MAX_CHAT_WIRE_BYTES, 8_usize * 1024_usize);
    assert_eq!(MAX_WALLET_STR_BYTES, 192_usize);
    assert_eq!(CHAT_MAX_FUTURE_SKEW_MS, 5_u64 * 60_u64 * 1000_u64);
    assert_eq!(
        CHAT_MAX_PAST_AGE_MS,
        30_u64 * 24_u64 * 60_u64 * 60_u64 * 1000_u64
    );
    Ok(())
}

#[test]
fn test_002_chat_topic_hash_is_stable() -> Result<()> {
    let first = chat_topic();
    let second = chat_topic();

    assert_eq!(first.hash(), second.hash());
    assert_eq!(CHAT_TOPIC, "remzar.chat.v1");
    Ok(())
}

/* ───────────────────────── signed happy paths ─────────────────────────── */

#[test]
fn test_003_new_signed_plaintext_and_verify_succeeds() -> Result<()> {
    let (msg, vk) = signed_chat(3_u128, "hello remzar")?;

    assert_eq!(msg.plaintext()?, "hello remzar");
    assert_eq!(msg.signature.len(), ml_dsa_65::SIG_LEN);
    assert!(msg.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_004_new_signed_canonicalizes_uppercase_hex_wallets() -> Result<()> {
    let (_vk, sk) = keypair()?;

    let msg = ChatMessage::new_signed(
        uppercase_wallet(4_u128),
        uppercase_wallet(5_u128),
        "uppercase wallet input",
        &sk,
    )?;

    assert_eq!(msg.from_wallet, wallet(4_u128));
    assert_eq!(msg.to_wallet, wallet(5_u128));
    assert_eq!(msg.plaintext()?, "uppercase wallet input");
    Ok(())
}

#[test]
fn test_005_new_signed_accepts_exactly_500_ascii_chars() -> Result<()> {
    let (vk, sk) = keypair()?;
    let plaintext = "a".repeat(MAX_CHAT_PLAINTEXT_CHARS);

    let msg = ChatMessage::new_signed(wallet(5_u128), wallet(6_u128), &plaintext, &sk)?;

    assert_eq!(msg.plaintext()?, plaintext);
    assert!(msg.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_006_new_signed_accepts_multibyte_plaintext_within_limits() -> Result<()> {
    let (vk, sk) = keypair()?;
    let plaintext = "🚀".repeat(100_usize);

    let msg = ChatMessage::new_signed(wallet(6_u128), wallet(7_u128), &plaintext, &sk)?;

    assert_eq!(msg.plaintext()?, plaintext);
    assert!(msg.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_007_encode_decode_wire_round_trip_preserves_fields_and_verifies() -> Result<()> {
    let (msg, vk) = signed_chat(7_u128, "wire round trip")?;

    let wire = msg.encode_wire()?;
    let decoded = ChatMessage::decode_wire(&wire)?;

    assert_message_same(&decoded, &msg);
    assert_eq!(decoded.plaintext()?, "wire round trip");
    assert!(decoded.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_008_encode_wire_output_is_within_cap_for_valid_signed_message() -> Result<()> {
    let (msg, _vk) = signed_chat(8_u128, "small message")?;

    let wire = msg.encode_wire()?;

    assert!(wire.len() <= MAX_CHAT_WIRE_BYTES);
    Ok(())
}

#[test]
fn test_009_json_serde_round_trip_preserves_chat_message() -> Result<()> {
    let (msg, vk) = signed_chat(9_u128, "json serde")?;

    let encoded = serde_json::to_string(&msg)?;
    let decoded = serde_json::from_str::<ChatMessage>(&encoded)?;

    assert_message_same(&decoded, &msg);
    assert!(decoded.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_010_postcard_direct_round_trip_then_decode_wire_verifies() -> Result<()> {
    let (msg, vk) = signed_chat(10_u128, "postcard direct")?;

    let wire = postcard::to_allocvec(&msg)?;
    let decoded = ChatMessage::decode_wire(&wire)?;

    assert_message_same(&decoded, &msg);
    assert!(decoded.verify(&vk).is_ok());
    Ok(())
}

/* ───────────────────────── plaintext / payload validation ─────────────── */

#[test]
fn test_011_plaintext_rejects_malformed_json_bytes() -> Result<()> {
    let mut msg = manual_message(
        wallet(11_u128),
        wallet(12_u128),
        now_ms(),
        "valid",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = b"{not valid json".to_vec();

    assert_error_contains(msg.plaintext(), "Chat JSON deserialization failed")?;
    Ok(())
}

#[test]
fn test_012_plaintext_rejects_unknown_json_field() -> Result<()> {
    let mut msg = manual_message(
        wallet(12_u128),
        wallet(13_u128),
        now_ms(),
        "valid",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = br#"{"m":"hello","extra":true}"#.to_vec();

    assert_error_contains(msg.plaintext(), "Chat JSON deserialization failed")?;
    Ok(())
}

#[test]
fn test_013_plaintext_rejects_empty_payload_text() -> Result<()> {
    let msg = manual_message(
        wallet(13_u128),
        wallet(14_u128),
        now_ms(),
        "",
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(msg.plaintext(), "chat plaintext cannot be empty")?;
    Ok(())
}

#[test]
fn test_014_plaintext_rejects_whitespace_payload_text() -> Result<()> {
    let msg = manual_message(
        wallet(14_u128),
        wallet(15_u128),
        now_ms(),
        " \t\n ",
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(msg.plaintext(), "chat plaintext cannot be empty")?;
    Ok(())
}

#[test]
fn test_015_plaintext_rejects_501_ascii_chars() -> Result<()> {
    let msg = manual_message(
        wallet(15_u128),
        wallet(16_u128),
        now_ms(),
        &"a".repeat(MAX_CHAT_PLAINTEXT_CHARS.saturating_add(1_usize)),
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(msg.plaintext(), "chat plaintext too long")?;
    Ok(())
}

#[test]
fn test_016_plaintext_rejects_json_payload_over_4k() -> Result<()> {
    let mut msg = manual_message(
        wallet(16_u128),
        wallet(17_u128),
        now_ms(),
        "valid",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = vec![b'a'; MAX_CHAT_JSON_BYTES.saturating_add(1_usize)];

    assert_error_contains(msg.plaintext(), "chat payload too large")?;
    Ok(())
}

/* ───────────────────────── new_signed rejection vectors ────────────────── */

#[test]
fn test_017_new_signed_rejects_same_wallet() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed(wallet(17_u128), wallet(17_u128), "same wallet", &sk),
        "from_wallet and to_wallet cannot be the same",
    )?;
    Ok(())
}

#[test]
fn test_018_new_signed_rejects_empty_plaintext() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed(wallet(18_u128), wallet(19_u128), "", &sk),
        "chat plaintext cannot be empty",
    )?;
    Ok(())
}

#[test]
fn test_019_new_signed_rejects_whitespace_plaintext() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed(wallet(19_u128), wallet(20_u128), "   \n\t", &sk),
        "chat plaintext cannot be empty",
    )?;
    Ok(())
}

#[test]
fn test_020_new_signed_rejects_501_chars_before_signing() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed(
            wallet(20_u128),
            wallet(21_u128),
            &"a".repeat(MAX_CHAT_PLAINTEXT_CHARS.saturating_add(1_usize)),
            &sk,
        ),
        "chat plaintext too long",
    )?;
    Ok(())
}

#[test]
fn test_021_new_signed_rejects_oversized_wallet_string_before_canonicalization() -> Result<()> {
    let (_vk, sk) = keypair()?;
    let huge_wallet = "r".repeat(MAX_WALLET_STR_BYTES.saturating_add(1_usize));

    assert_error_contains(
        ChatMessage::new_signed(huge_wallet, wallet(22_u128), "bad wallet", &sk),
        "wallet string too large",
    )?;
    Ok(())
}

#[test]
fn test_022_new_signed_rejects_invalid_wallet_text() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed(
            "not-a-wallet".to_owned(),
            wallet(23_u128),
            "bad wallet",
            &sk,
        ),
        "Wallet",
    )?;
    Ok(())
}

/* ───────────────────────── verification adversarial cases ─────────────── */

#[test]
fn test_023_verify_rejects_wrong_public_key() -> Result<()> {
    let (msg, _good_vk) = signed_chat(23_u128, "wrong key")?;
    let (wrong_vk, _wrong_sk) = keypair()?;

    assert_error_contains(msg.verify(&wrong_vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_024_verify_rejects_tampered_json_same_valid_shape() -> Result<()> {
    let (mut msg, vk) = signed_chat(24_u128, "original")?;
    msg.json = serde_json::to_vec(&ChatJson {
        m: "tampered".to_owned(),
    })?;

    assert_error_contains(msg.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_025_verify_rejects_tampered_recipient_wallet() -> Result<()> {
    let (mut msg, vk) = signed_chat(25_u128, "recipient tamper")?;
    msg.to_wallet = wallet(2500_u128);

    assert_error_contains(msg.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_026_verify_rejects_tampered_timestamp_within_skew_window() -> Result<()> {
    let (mut msg, vk) = signed_chat(26_u128, "timestamp tamper")?;
    msg.timestamp_ms = msg.timestamp_ms.saturating_add(1_u64);

    assert_error_contains(msg.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_027_verify_rejects_tampered_signature_byte() -> Result<()> {
    let (mut msg, vk) = signed_chat(27_u128, "signature tamper")?;
    if let Some(first) = msg.signature.first_mut() {
        *first = first.wrapping_add(1_u8);
    }

    assert_error_contains(msg.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_028_verify_rejects_short_signature() -> Result<()> {
    let (mut msg, vk) = signed_chat(28_u128, "short signature")?;
    assert!(msg.signature.pop().is_some());

    assert_error_contains(msg.verify(&vk), "chat signature length")?;
    Ok(())
}

#[test]
fn test_029_verify_rejects_long_signature() -> Result<()> {
    let (mut msg, vk) = signed_chat(29_u128, "long signature")?;
    msg.signature.push(0_u8);

    assert_error_contains(msg.verify(&vk), "chat signature length")?;
    Ok(())
}

/* ───────────────────────── wire decode boundary cases ─────────────────── */

#[test]
fn test_030_encode_wire_rejects_short_signature() -> Result<()> {
    let (mut msg, _vk) = signed_chat(30_u128, "bad encode signature")?;
    assert!(msg.signature.pop().is_some());

    assert_error_contains(msg.encode_wire(), "chat signature length")?;
    Ok(())
}

#[test]
fn test_031_encode_wire_rejects_noncanonical_wallet_field() -> Result<()> {
    let (mut msg, _vk) = signed_chat(31_u128, "bad wallet boundary")?;
    msg.from_wallet = uppercase_wallet(31_u128);

    assert_error_contains(msg.encode_wire(), "not canonical")?;
    Ok(())
}

#[test]
fn test_032_decode_wire_rejects_oversized_wire_before_postcard() -> Result<()> {
    let wire = vec![0_u8; MAX_CHAT_WIRE_BYTES.saturating_add(1_usize)];

    assert_error_contains(ChatMessage::decode_wire(&wire), "chat wire bytes too large")?;
    Ok(())
}

#[test]
fn test_033_decode_wire_rejects_malformed_postcard() -> Result<()> {
    let wire = vec![1_u8, 2_u8, 3_u8, 4_u8];

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "ChatMessage postcard deserialization failed",
    )?;
    Ok(())
}

#[test]
fn test_034_decode_wire_rejects_short_signature_after_decode() -> Result<()> {
    let msg = manual_message(
        wallet(34_u128),
        wallet(35_u128),
        now_ms(),
        "short sig after decode",
        ml_dsa_65::SIG_LEN.saturating_sub(1_usize),
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "chat signature length")?;
    Ok(())
}

#[test]
fn test_035_decode_wire_rejects_same_wallet_after_decode() -> Result<()> {
    let msg = manual_message(
        wallet(35_u128),
        wallet(35_u128),
        now_ms(),
        "same wallet after decode",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "from_wallet and to_wallet cannot be the same",
    )?;
    Ok(())
}

#[test]
fn test_036_decode_wire_rejects_future_timestamp_beyond_skew() -> Result<()> {
    let msg = manual_message(
        wallet(36_u128),
        wallet(37_u128),
        now_ms()
            .saturating_add(CHAT_MAX_FUTURE_SKEW_MS)
            .saturating_add(60_000_u64),
        "future timestamp",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "chat timestamp too far in the future",
    )?;
    Ok(())
}

#[test]
fn test_037_decode_wire_rejects_past_timestamp_beyond_age() -> Result<()> {
    let msg = manual_message(
        wallet(37_u128),
        wallet(38_u128),
        now_ms()
            .saturating_sub(CHAT_MAX_PAST_AGE_MS)
            .saturating_sub(60_000_u64),
        "old timestamp",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "chat timestamp too old")?;
    Ok(())
}

/* ───────────────────────── incoming gossipsub helper coverage ─────────── */

#[test]
fn test_038_try_decode_incoming_decodes_valid_message() -> Result<()> {
    let (msg, vk) = signed_chat(38_u128, "incoming decode")?;
    let wire = msg.encode_wire()?;
    let incoming = gossipsub_message(wire);

    let decoded = try_decode_incoming(&incoming)?;

    assert_message_same(&decoded, &msg);
    assert!(decoded.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_039_try_decode_incoming_rejects_oversized_frame_before_decode() -> Result<()> {
    let incoming = gossipsub_message(vec![0_u8; MAX_CHAT_WIRE_BYTES.saturating_add(1_usize)]);

    assert_error_contains(
        try_decode_incoming(&incoming),
        "incoming chat frame too large",
    )?;
    Ok(())
}

#[test]
fn test_040_publish_chat_rejects_invalid_message_before_network_publish() -> Result<()> {
    let libp2p_key = libp2p::identity::Keypair::generate_ed25519();

    let mut behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(libp2p_key),
        gossipsub::Config::default(),
    )
    .map_err(|err| anyhow!("failed to build gossipsub behaviour: {err}"))?;

    let msg = manual_message(
        wallet(40_u128),
        wallet(41_u128),
        now_ms(),
        "invalid publish signature",
        0_usize,
    )?;

    assert_error_contains(publish_chat(&mut behaviour, &msg), "chat signature length")?;
    Ok(())
}

/* ───────────────────────── extra plaintext / signing boundaries ────────── */

#[test]
fn test_041_new_signed_accepts_exactly_500_emoji_chars() -> Result<()> {
    let (vk, sk) = keypair()?;
    let plaintext = "🚀".repeat(MAX_CHAT_PLAINTEXT_CHARS);

    let msg = ChatMessage::new_signed(wallet(41_u128), wallet(42_u128), &plaintext, &sk)?;

    assert_eq!(msg.plaintext()?, plaintext);
    assert!(msg.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_042_new_signed_preserves_nonempty_outer_whitespace() -> Result<()> {
    let (vk, sk) = keypair()?;
    let plaintext = "  hello with padding  ";

    let msg = ChatMessage::new_signed(wallet(42_u128), wallet(43_u128), plaintext, &sk)?;

    assert_eq!(msg.plaintext()?, plaintext);
    assert!(msg.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_043_new_signed_accepts_newlines_inside_nonempty_message() -> Result<()> {
    let (vk, sk) = keypair()?;
    let plaintext = "line one\nline two\nline three";

    let msg = ChatMessage::new_signed(wallet(43_u128), wallet(44_u128), plaintext, &sk)?;

    assert_eq!(msg.plaintext()?, plaintext);
    assert!(msg.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_044_plaintext_accepts_exactly_500_ascii_chars_from_manual_message() -> Result<()> {
    let plaintext = "a".repeat(MAX_CHAT_PLAINTEXT_CHARS);
    let msg = manual_message(
        wallet(44_u128),
        wallet(45_u128),
        now_ms(),
        &plaintext,
        ml_dsa_65::SIG_LEN,
    )?;

    assert_eq!(msg.plaintext()?, plaintext);
    Ok(())
}

#[test]
fn test_045_plaintext_accepts_exactly_500_emoji_chars_from_manual_message() -> Result<()> {
    let plaintext = "🚀".repeat(MAX_CHAT_PLAINTEXT_CHARS);
    let msg = manual_message(
        wallet(45_u128),
        wallet(46_u128),
        now_ms(),
        &plaintext,
        ml_dsa_65::SIG_LEN,
    )?;

    assert_eq!(msg.plaintext()?, plaintext);
    Ok(())
}

#[test]
fn test_046_plaintext_rejects_501_emoji_chars() -> Result<()> {
    let plaintext = "🚀".repeat(MAX_CHAT_PLAINTEXT_CHARS.saturating_add(1_usize));
    let msg = manual_message(
        wallet(46_u128),
        wallet(47_u128),
        now_ms(),
        &plaintext,
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(msg.plaintext(), "chat plaintext too long")?;
    Ok(())
}

#[test]
fn test_047_plaintext_rejects_json_string_missing_m_field() -> Result<()> {
    let mut msg = manual_message(
        wallet(47_u128),
        wallet(48_u128),
        now_ms(),
        "valid",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = br#"{"x":"missing message"}"#.to_vec();

    assert_error_contains(msg.plaintext(), "Chat JSON deserialization failed")?;
    Ok(())
}

#[test]
fn test_048_plaintext_rejects_json_m_field_wrong_type() -> Result<()> {
    let mut msg = manual_message(
        wallet(48_u128),
        wallet(49_u128),
        now_ms(),
        "valid",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = br#"{"m":123}"#.to_vec();

    assert_error_contains(msg.plaintext(), "Chat JSON deserialization failed")?;
    Ok(())
}

/* ───────────────────────── wallet validation vectors ──────────────────── */

#[test]
fn test_049_new_signed_rejects_empty_from_wallet() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed(String::new(), wallet(50_u128), "empty wallet", &sk),
        "Wallet",
    )?;
    Ok(())
}

#[test]
fn test_050_new_signed_rejects_whitespace_from_wallet() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed("   ".to_owned(), wallet(51_u128), "wallet spaces", &sk),
        "Wallet",
    )?;
    Ok(())
}

#[test]
fn test_051_new_signed_rejects_short_wallet() -> Result<()> {
    let (_vk, sk) = keypair()?;

    assert_error_contains(
        ChatMessage::new_signed("r1234".to_owned(), wallet(52_u128), "short wallet", &sk),
        "Wallet",
    )?;
    Ok(())
}

#[test]
fn test_052_new_signed_rejects_non_hex_wallet_body() -> Result<()> {
    let (_vk, sk) = keypair()?;
    let bad_wallet = format!("r{}", "g".repeat(128_usize));

    assert_error_contains(
        ChatMessage::new_signed(bad_wallet, wallet(53_u128), "non hex wallet", &sk),
        "Wallet",
    )?;
    Ok(())
}

#[test]
fn test_053_decode_wire_rejects_uppercase_from_wallet_as_noncanonical() -> Result<()> {
    let upper_from = uppercase_wallet(0xabcdef_u128);
    assert_ne!(upper_from, wallet(0xabcdef_u128));

    let msg = manual_message(
        upper_from,
        wallet(54_u128),
        now_ms(),
        "uppercase sender",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "not canonical")?;
    Ok(())
}

#[test]
fn test_054_decode_wire_rejects_uppercase_to_wallet_as_noncanonical() -> Result<()> {
    let upper_to = uppercase_wallet(0xabcdee_u128);
    assert_ne!(upper_to, wallet(0xabcdee_u128));

    let msg = manual_message(
        wallet(54_u128),
        upper_to,
        now_ms(),
        "uppercase recipient",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "not canonical")?;
    Ok(())
}

#[test]
fn test_055_decode_wire_rejects_oversized_to_wallet() -> Result<()> {
    let msg = manual_message(
        wallet(55_u128),
        "r".repeat(MAX_WALLET_STR_BYTES.saturating_add(1_usize)),
        now_ms(),
        "oversized recipient wallet",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "wallet string invalid size",
    )?;
    Ok(())
}

#[test]
fn test_056_decode_wire_rejects_invalid_from_wallet_text() -> Result<()> {
    let msg = manual_message(
        "not-a-wallet".to_owned(),
        wallet(57_u128),
        now_ms(),
        "invalid sender wallet",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "Wallet")?;
    Ok(())
}

/* ───────────────────────── timestamp validation vectors ───────────────── */

#[test]
fn test_057_decode_wire_accepts_future_timestamp_within_skew() -> Result<()> {
    let msg = manual_message(
        wallet(57_u128),
        wallet(58_u128),
        now_ms().saturating_add(CHAT_MAX_FUTURE_SKEW_MS / 2_u64),
        "future but valid",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    let decoded = ChatMessage::decode_wire(&wire)?;

    assert_eq!(decoded.plaintext()?, "future but valid");
    Ok(())
}

#[test]
fn test_058_decode_wire_accepts_recent_past_timestamp() -> Result<()> {
    let msg = manual_message(
        wallet(58_u128),
        wallet(59_u128),
        now_ms().saturating_sub(60_000_u64),
        "recent past",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    let decoded = ChatMessage::decode_wire(&wire)?;

    assert_eq!(decoded.plaintext()?, "recent past");
    Ok(())
}

#[test]
fn test_059_decode_wire_rejects_zero_timestamp_as_too_old() -> Result<()> {
    let msg = manual_message(
        wallet(59_u128),
        wallet(60_u128),
        0_u64,
        "zero timestamp",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "chat timestamp too old")?;
    Ok(())
}

#[test]
fn test_060_decode_wire_rejects_u64_max_timestamp_as_future() -> Result<()> {
    let msg = manual_message(
        wallet(60_u128),
        wallet(61_u128),
        u64::MAX,
        "max timestamp",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "chat timestamp too far in the future",
    )?;
    Ok(())
}

/* ───────────────────────── decode / encode validation vectors ─────────── */

#[test]
fn test_061_decode_wire_accepts_valid_zero_signature_bytes_but_verify_rejects() -> Result<()> {
    let (vk, _sk) = keypair()?;
    let msg = manual_message(
        wallet(61_u128),
        wallet(62_u128),
        now_ms(),
        "zero signature body",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    let decoded = ChatMessage::decode_wire(&wire)?;

    assert_eq!(decoded.signature, vec![0_u8; ml_dsa_65::SIG_LEN]);
    assert_error_contains(decoded.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_062_decode_wire_rejects_long_signature_after_decode() -> Result<()> {
    let msg = manual_message(
        wallet(62_u128),
        wallet(63_u128),
        now_ms(),
        "long sig after decode",
        ml_dsa_65::SIG_LEN.saturating_add(1_usize),
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "chat signature length")?;
    Ok(())
}

#[test]
fn test_063_decode_wire_rejects_json_payload_too_large_after_decode() -> Result<()> {
    let mut msg = manual_message(
        wallet(63_u128),
        wallet(64_u128),
        now_ms(),
        "valid",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = vec![b'a'; MAX_CHAT_JSON_BYTES.saturating_add(1_usize)];

    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "chat payload too large")?;
    Ok(())
}

#[test]
fn test_064_decode_wire_rejects_empty_plaintext_after_decode() -> Result<()> {
    let msg = manual_message(
        wallet(64_u128),
        wallet(65_u128),
        now_ms(),
        "",
        ml_dsa_65::SIG_LEN,
    )?;
    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "chat plaintext cannot be empty",
    )?;
    Ok(())
}

#[test]
fn test_065_encode_wire_rejects_json_payload_too_large() -> Result<()> {
    let mut msg = manual_message(
        wallet(65_u128),
        wallet(66_u128),
        now_ms(),
        "valid",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = vec![b'a'; MAX_CHAT_JSON_BYTES.saturating_add(1_usize)];

    assert_error_contains(msg.encode_wire(), "chat payload too large")?;
    Ok(())
}

#[test]
fn test_066_encode_wire_rejects_same_wallet() -> Result<()> {
    let msg = manual_message(
        wallet(66_u128),
        wallet(66_u128),
        now_ms(),
        "same wallet encode",
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(
        msg.encode_wire(),
        "from_wallet and to_wallet cannot be the same",
    )?;
    Ok(())
}

#[test]
fn test_067_encode_wire_allows_future_timestamp_but_decode_rejects_it() -> Result<()> {
    let msg = manual_message(
        wallet(67_u128),
        wallet(68_u128),
        now_ms()
            .saturating_add(CHAT_MAX_FUTURE_SKEW_MS)
            .saturating_add(60_000_u64),
        "future encode",
        ml_dsa_65::SIG_LEN,
    )?;

    let wire = msg.encode_wire()?;

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "chat timestamp too far in the future",
    )?;
    Ok(())
}

#[test]
fn test_068_encode_wire_allows_past_timestamp_but_decode_rejects_it() -> Result<()> {
    let msg = manual_message(
        wallet(68_u128),
        wallet(69_u128),
        now_ms()
            .saturating_sub(CHAT_MAX_PAST_AGE_MS)
            .saturating_sub(60_000_u64),
        "past encode",
        ml_dsa_65::SIG_LEN,
    )?;

    let wire = msg.encode_wire()?;

    assert_error_contains(ChatMessage::decode_wire(&wire), "chat timestamp too old")?;
    Ok(())
}

#[test]
fn test_069_decode_wire_rejects_empty_wire() -> Result<()> {
    assert_error_contains(
        ChatMessage::decode_wire(&[]),
        "ChatMessage postcard deserialization failed",
    )?;
    Ok(())
}

#[test]
fn test_070_decode_wire_rejects_exactly_max_sized_zero_wire_after_postcard_decode() -> Result<()> {
    let wire = vec![0_u8; MAX_CHAT_WIRE_BYTES];

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "Chat JSON deserialization failed",
    )?;
    Ok(())
}

/* ───────────────────────── verification mutation vectors ──────────────── */

#[test]
fn test_071_verify_rejects_tampered_sender_wallet() -> Result<()> {
    let (mut msg, vk) = signed_chat(71_u128, "sender tamper")?;
    msg.from_wallet = wallet(7100_u128);

    assert_error_contains(msg.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_072_verify_rejects_uppercase_sender_before_signature_check() -> Result<()> {
    let seed = 0xabcdef_u128;
    let (mut msg, vk) = signed_chat(seed, "uppercase sender verify")?;

    let upper_from = uppercase_wallet(seed);
    assert_ne!(upper_from, wallet(seed));

    msg.from_wallet = upper_from;

    assert_error_contains(msg.verify(&vk), "not canonical")?;
    Ok(())
}

#[test]
fn test_073_verify_rejects_uppercase_recipient_before_signature_check() -> Result<()> {
    let (mut msg, vk) = signed_chat(73_u128, "uppercase recipient verify")?;
    msg.to_wallet = uppercase_wallet(74_u128);

    assert_error_contains(msg.verify(&vk), "not canonical")?;
    Ok(())
}

#[test]
fn test_074_verify_rejects_same_wallet_before_signature_check() -> Result<()> {
    let (mut msg, vk) = signed_chat(74_u128, "same wallet verify")?;
    msg.to_wallet = msg.from_wallet.clone();

    assert_error_contains(
        msg.verify(&vk),
        "from_wallet and to_wallet cannot be the same",
    )?;
    Ok(())
}

#[test]
fn test_075_verify_rejects_future_timestamp_before_signature_check() -> Result<()> {
    let (mut msg, vk) = signed_chat(75_u128, "future verify")?;
    msg.timestamp_ms = now_ms()
        .saturating_add(CHAT_MAX_FUTURE_SKEW_MS)
        .saturating_add(60_000_u64);

    assert_error_contains(msg.verify(&vk), "chat timestamp too far in the future")?;
    Ok(())
}

#[test]
fn test_076_verify_rejects_old_timestamp_before_signature_check() -> Result<()> {
    let (mut msg, vk) = signed_chat(76_u128, "old verify")?;
    msg.timestamp_ms = now_ms()
        .saturating_sub(CHAT_MAX_PAST_AGE_MS)
        .saturating_sub(60_000_u64);

    assert_error_contains(msg.verify(&vk), "chat timestamp too old")?;
    Ok(())
}

#[test]
fn test_077_verify_rejects_malformed_json_before_signature_check() -> Result<()> {
    let (mut msg, vk) = signed_chat(77_u128, "malformed json verify")?;
    msg.json = b"{bad json".to_vec();

    assert_error_contains(msg.verify(&vk), "Chat JSON deserialization failed")?;
    Ok(())
}

#[test]
fn test_078_verify_rejects_empty_plaintext_before_signature_check() -> Result<()> {
    let (mut msg, vk) = signed_chat(78_u128, "empty json verify")?;
    msg.json = serde_json::to_vec(&ChatJson { m: String::new() })?;

    assert_error_contains(msg.verify(&vk), "chat plaintext cannot be empty")?;
    Ok(())
}

#[test]
fn test_079_verify_rejects_one_byte_signature_even_if_other_fields_valid() -> Result<()> {
    let (mut msg, vk) = signed_chat(79_u128, "one byte sig")?;
    msg.signature = vec![0_u8];

    assert_error_contains(msg.verify(&vk), "chat signature length")?;
    Ok(())
}

#[test]
fn test_080_verify_rejects_all_ff_signature() -> Result<()> {
    let (mut msg, vk) = signed_chat(80_u128, "all ff sig")?;
    msg.signature = vec![0xff_u8; ml_dsa_65::SIG_LEN];

    assert_error_contains(msg.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

/* ───────────────────────── incoming gossipsub helper vectors ───────────── */

#[test]
fn test_081_try_decode_incoming_rejects_empty_frame() -> Result<()> {
    let incoming = gossipsub_message(Vec::new());

    assert_error_contains(
        try_decode_incoming(&incoming),
        "ChatMessage postcard deserialization failed",
    )?;
    Ok(())
}

#[test]
fn test_082_try_decode_incoming_rejects_malformed_frame() -> Result<()> {
    let incoming = gossipsub_message(vec![1_u8, 2_u8, 3_u8, 4_u8]);

    assert_error_contains(
        try_decode_incoming(&incoming),
        "ChatMessage postcard deserialization failed",
    )?;
    Ok(())
}

#[test]
fn test_083_try_decode_incoming_rejects_short_signature_after_decode() -> Result<()> {
    let msg = manual_message(
        wallet(83_u128),
        wallet(84_u128),
        now_ms(),
        "incoming short sig",
        ml_dsa_65::SIG_LEN.saturating_sub(1_usize),
    )?;
    let incoming = gossipsub_message(postcard::to_allocvec(&msg)?);

    assert_error_contains(try_decode_incoming(&incoming), "chat signature length")?;
    Ok(())
}

#[test]
fn test_084_try_decode_incoming_accepts_valid_decodable_zero_signature_message() -> Result<()> {
    let msg = manual_message(
        wallet(84_u128),
        wallet(85_u128),
        now_ms(),
        "incoming valid decode",
        ml_dsa_65::SIG_LEN,
    )?;
    let incoming = gossipsub_message(postcard::to_allocvec(&msg)?);

    let decoded = try_decode_incoming(&incoming)?;

    assert_message_same(&decoded, &msg);
    Ok(())
}

#[test]
fn test_085_try_decode_incoming_rejects_same_wallet_after_decode() -> Result<()> {
    let msg = manual_message(
        wallet(85_u128),
        wallet(85_u128),
        now_ms(),
        "incoming same wallet",
        ml_dsa_65::SIG_LEN,
    )?;
    let incoming = gossipsub_message(postcard::to_allocvec(&msg)?);

    assert_error_contains(
        try_decode_incoming(&incoming),
        "from_wallet and to_wallet cannot be the same",
    )?;
    Ok(())
}

#[test]
fn test_086_try_decode_incoming_rejects_old_timestamp_after_decode() -> Result<()> {
    let msg = manual_message(
        wallet(86_u128),
        wallet(87_u128),
        now_ms()
            .saturating_sub(CHAT_MAX_PAST_AGE_MS)
            .saturating_sub(60_000_u64),
        "incoming old timestamp",
        ml_dsa_65::SIG_LEN,
    )?;
    let incoming = gossipsub_message(postcard::to_allocvec(&msg)?);

    assert_error_contains(try_decode_incoming(&incoming), "chat timestamp too old")?;
    Ok(())
}

/* ───────────────────────── publish_chat preflight vectors ──────────────── */

#[test]
fn test_087_publish_chat_rejects_noncanonical_wallet_before_network_publish() -> Result<()> {
    let libp2p_key = libp2p::identity::Keypair::generate_ed25519();

    let mut behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(libp2p_key),
        gossipsub::Config::default(),
    )
    .map_err(|err| anyhow!("failed to build gossipsub behaviour: {err}"))?;

    let upper_from = uppercase_wallet(0xabcdef_u128);
    assert_ne!(upper_from, wallet(0xabcdef_u128));

    let msg = manual_message(
        upper_from,
        wallet(88_u128),
        now_ms(),
        "bad publish wallet",
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(publish_chat(&mut behaviour, &msg), "not canonical")?;
    Ok(())
}

#[test]
fn test_088_publish_chat_rejects_oversized_payload_before_network_publish() -> Result<()> {
    let libp2p_key = libp2p::identity::Keypair::generate_ed25519();
    let mut behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(libp2p_key),
        gossipsub::Config::default(),
    )
    .map_err(|err| anyhow!("failed to build gossipsub behaviour: {err}"))?;

    let mut msg = manual_message(
        wallet(88_u128),
        wallet(89_u128),
        now_ms(),
        "bad publish payload",
        ml_dsa_65::SIG_LEN,
    )?;
    msg.json = vec![b'a'; MAX_CHAT_JSON_BYTES.saturating_add(1_usize)];

    assert_error_contains(publish_chat(&mut behaviour, &msg), "chat payload too large")?;
    Ok(())
}

#[test]
fn test_089_publish_chat_with_future_timestamp_reaches_gossipsub_publish() -> Result<()> {
    let libp2p_key = libp2p::identity::Keypair::generate_ed25519();

    let mut behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(libp2p_key),
        gossipsub::Config::default(),
    )
    .map_err(|err| anyhow!("failed to build gossipsub behaviour: {err}"))?;

    let msg = manual_message(
        wallet(89_u128),
        wallet(90_u128),
        now_ms()
            .saturating_add(CHAT_MAX_FUTURE_SKEW_MS)
            .saturating_add(60_000_u64),
        "future publish",
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(
        publish_chat(&mut behaviour, &msg),
        "NoPeersSubscribedToTopic",
    )?;
    Ok(())
}

#[test]
fn test_090_publish_chat_rejects_same_wallet_before_network_publish() -> Result<()> {
    let libp2p_key = libp2p::identity::Keypair::generate_ed25519();
    let mut behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(libp2p_key),
        gossipsub::Config::default(),
    )
    .map_err(|err| anyhow!("failed to build gossipsub behaviour: {err}"))?;

    let msg = manual_message(
        wallet(90_u128),
        wallet(90_u128),
        now_ms(),
        "same wallet publish",
        ml_dsa_65::SIG_LEN,
    )?;

    assert_error_contains(
        publish_chat(&mut behaviour, &msg),
        "from_wallet and to_wallet cannot be the same",
    )?;
    Ok(())
}

/* ───────────────────────── load / fuzz-style signed vectors ────────────── */

#[test]
fn test_091_load_8_signed_messages_verify_and_round_trip() -> Result<()> {
    for seed in 91_u128..99_u128 {
        let (msg, vk) = signed_chat(seed, "load signed round trip")?;
        let wire = msg.encode_wire()?;
        let decoded = ChatMessage::decode_wire(&wire)?;

        assert_message_same(&decoded, &msg);
        assert!(decoded.verify(&vk).is_ok());
    }

    Ok(())
}

#[test]
fn test_092_load_8_distinct_plaintexts_verify() -> Result<()> {
    for seed in 92_u128..100_u128 {
        let plaintext = format!("load plaintext number {seed}");
        let (msg, vk) = signed_chat(seed, &plaintext)?;

        assert_eq!(msg.plaintext()?, plaintext);
        assert!(msg.verify(&vk).is_ok());
    }

    Ok(())
}

#[test]
fn test_093_fuzz_message_lengths_from_1_to_32_verify() -> Result<()> {
    let (vk, sk) = keypair()?;

    for len in 1_usize..=32_usize {
        let plaintext = "a".repeat(len);
        let msg = ChatMessage::new_signed(
            wallet(93_u128.saturating_add(u128::try_from(len)?)),
            wallet(193_u128.saturating_add(u128::try_from(len)?)),
            &plaintext,
            &sk,
        )?;

        assert_eq!(msg.plaintext()?, plaintext);
        assert!(msg.verify(&vk).is_ok());
    }

    Ok(())
}

#[test]
fn test_094_fuzz_unicode_message_lengths_verify() -> Result<()> {
    let (vk, sk) = keypair()?;

    for len in 1_usize..=16_usize {
        let plaintext = "🦀".repeat(len);
        let msg = ChatMessage::new_signed(
            wallet(94_u128.saturating_add(u128::try_from(len)?)),
            wallet(194_u128.saturating_add(u128::try_from(len)?)),
            &plaintext,
            &sk,
        )?;

        assert_eq!(msg.plaintext()?, plaintext);
        assert!(msg.verify(&vk).is_ok());
    }

    Ok(())
}

#[test]
fn test_095_fuzz_tampered_messages_all_fail_verification() -> Result<()> {
    for seed in 95_u128..103_u128 {
        let (mut msg, vk) = signed_chat(seed, "tamper fuzz")?;
        msg.json = serde_json::to_vec(&ChatJson {
            m: format!("tampered {seed}"),
        })?;

        assert_error_contains(msg.verify(&vk), "chat signature verification failed")?;
    }

    Ok(())
}

/* ───────────────────────── final combined paths ───────────────────────── */

#[test]
fn test_096_combined_signed_to_wire_to_incoming_to_verify_path() -> Result<()> {
    let (msg, vk) = signed_chat(96_u128, "combined incoming verify")?;

    let wire = msg.encode_wire()?;
    let incoming = gossipsub_message(wire);
    let decoded = try_decode_incoming(&incoming)?;

    assert_message_same(&decoded, &msg);
    assert!(decoded.verify(&vk).is_ok());
    Ok(())
}

#[test]
fn test_097_combined_json_mutation_then_decode_rejects_plaintext_empty() -> Result<()> {
    let (mut msg, _vk) = signed_chat(97_u128, "will become empty")?;
    msg.json = serde_json::to_vec(&ChatJson { m: String::new() })?;

    let wire = postcard::to_allocvec(&msg)?;

    assert_error_contains(
        ChatMessage::decode_wire(&wire),
        "chat plaintext cannot be empty",
    )?;
    Ok(())
}

#[test]
fn test_098_combined_wire_roundtrip_then_tamper_signature_fails_verify() -> Result<()> {
    let (msg, vk) = signed_chat(98_u128, "roundtrip then tamper signature")?;

    let wire = msg.encode_wire()?;
    let mut decoded = ChatMessage::decode_wire(&wire)?;

    if let Some(last) = decoded.signature.last_mut() {
        *last = last.wrapping_add(1_u8);
    }

    assert_error_contains(decoded.verify(&vk), "chat signature verification failed")?;
    Ok(())
}

#[test]
fn test_099_combined_valid_decode_but_wrong_public_key_fails_verify() -> Result<()> {
    let (msg, _vk) = signed_chat(99_u128, "wrong key after decode")?;
    let (wrong_vk, _wrong_sk) = keypair()?;

    let wire = msg.encode_wire()?;
    let decoded = ChatMessage::decode_wire(&wire)?;

    assert_error_contains(
        decoded.verify(&wrong_vk),
        "chat signature verification failed",
    )?;
    Ok(())
}

#[test]
fn test_100_combined_adversarial_chat_validation_path_is_safe() -> Result<()> {
    let (msg, vk) = signed_chat(100_u128, "final combined chat path")?;

    let wire = msg.encode_wire()?;
    assert!(wire.len() <= MAX_CHAT_WIRE_BYTES);

    let incoming = gossipsub_message(wire);
    let decoded = try_decode_incoming(&incoming)?;

    assert_message_same(&decoded, &msg);
    assert!(decoded.verify(&vk).is_ok());

    let mut tampered = decoded.clone();
    tampered.to_wallet = wallet(10_000_u128);
    assert_error_contains(tampered.verify(&vk), "chat signature verification failed")?;

    Ok(())
}
