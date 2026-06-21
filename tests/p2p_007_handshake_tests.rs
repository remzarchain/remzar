#![forbid(unsafe_code)]

use anyhow::{Result as AnyResult, anyhow};
use futures::executor::block_on;
use futures::io::Cursor;
use libp2p::{PeerId, identity::Keypair, request_response::Codec};
use remzar::network::p2p_005_pq_fips203kem::{
    DEFAULT_MAX_MESSAGE_AGE_SECS, MIN_REPLAY_FILTER_CAPACITY, PQ_KEM_SUITE_ID, PQ_MAX_WIRE_BYTES,
    PQ_NONCE_LEN, PqKemError, PqKemPolicy, PqResponder, ct_len,
};
use remzar::network::p2p_007_handshake::{
    PqCodec, PqHandshakeRequest, PqHandshakeResponse, PqProto, Services, VersionCodec, VersionInfo,
    VersionProto, build_default_pq_manager, build_outbound_pq_offer, build_pq_exchange,
    build_pq_manager, build_version_exchange, finalize_inbound_pq_response,
    handle_inbound_pq_request,
};
use std::time::Duration;

const TEST_VERSION_MAX_WIRE_BYTES: usize = 16 * 1024;

/// Defensive cap on user_agent bytes surfaced in logs.
const MAX_USER_AGENT_LOG_BYTES: usize = 128;

fn version_frame_for(info: &VersionInfo) -> AnyResult<Vec<u8>> {
    let encoded = postcard::to_stdvec(info)?;
    framed_bytes(&encoded)
}

fn pq_request_frame_for(request: &PqHandshakeRequest) -> AnyResult<Vec<u8>> {
    let encoded = postcard::to_stdvec(request)?;
    framed_bytes(&encoded)
}

fn pq_response_frame_for(response: &PqHandshakeResponse) -> AnyResult<Vec<u8>> {
    let encoded = postcard::to_stdvec(response)?;
    framed_bytes(&encoded)
}

fn assert_pq_invalid_message<T>(result: Result<T, PqKemError>, needle: &str) -> AnyResult<()> {
    match result {
        Err(PqKemError::InvalidMessage(message)) => {
            assert!(message.contains(needle));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected PQ error: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidMessage containing {needle}")),
    }
}

fn assert_pq_invalid_length<T>(
    result: Result<T, PqKemError>,
    field: &'static str,
    expected: usize,
    actual: usize,
) -> AnyResult<()> {
    match result {
        Err(PqKemError::InvalidLength {
            field: got_field,
            expected: got_expected,
            actual: got_actual,
        }) => {
            assert_eq!(got_field, field);
            assert_eq!(got_expected, expected);
            assert_eq!(got_actual, actual);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected PQ error: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidLength")),
    }
}

fn generated_peer_id() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

fn lcg_next(state: &mut u64) -> u64 {
    let next = state
        .wrapping_mul(6_364_136_223_846_793_005_u64)
        .wrapping_add(1_442_695_040_888_963_407_u64);
    *state = next;
    next
}

fn nonce_from_seed(seed: u64) -> [u8; PQ_NONCE_LEN] {
    let mut out = [0_u8; PQ_NONCE_LEN];
    let mut state = seed;

    for slot in &mut out {
        let next = lcg_next(&mut state);
        let bytes = next.to_le_bytes();
        if let Some(first) = bytes.first() {
            *slot = *first;
        }
    }

    out
}

fn hash64_from_seed(seed: u64) -> [u8; 64] {
    let mut out = [0_u8; 64];
    let mut state = seed;

    for slot in &mut out {
        let next = lcg_next(&mut state);
        let bytes = next.to_le_bytes();
        if let Some(first) = bytes.first() {
            *slot = *first;
        }
    }

    out
}

fn version_info(
    protocol_version: u32,
    chain_height: u64,
    services: Services,
    user_agent: &str,
    genesis_hash: Option<[u8; 64]>,
) -> VersionInfo {
    VersionInfo {
        protocol_version,
        chain_height,
        services,
        user_agent: user_agent.to_owned(),
        genesis_hash,
    }
}

fn assert_version_eq(left: &VersionInfo, right: &VersionInfo) {
    assert_eq!(left.protocol_version, right.protocol_version);
    assert_eq!(left.chain_height, right.chain_height);
    assert_eq!(left.services, right.services);
    assert_eq!(left.user_agent, right.user_agent);
    assert_eq!(left.genesis_hash, right.genesis_hash);
}

fn encode_varint_u32(mut value: u32) -> AnyResult<Vec<u8>> {
    let mut out = Vec::new();

    loop {
        let low = value & 0x7f_u32;
        let mut byte = u8::try_from(low)?;
        value >>= 7_u32;

        if value == 0_u32 {
            out.push(byte);
            return Ok(out);
        }

        byte |= 0x80_u8;
        out.push(byte);
    }
}

fn framed_bytes(data: &[u8]) -> AnyResult<Vec<u8>> {
    let len = u32::try_from(data.len())?;
    let mut out = encode_varint_u32(len)?;
    out.extend_from_slice(data);
    Ok(out)
}

fn assert_invalid_data<T>(result: std::io::Result<T>, needle: &str) -> AnyResult<()> {
    match result {
        Err(err) => {
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(err.to_string().contains(needle));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected InvalidData error containing {needle}")),
    }
}

fn assert_pq_replay<T>(result: Result<T, PqKemError>) -> AnyResult<()> {
    match result {
        Err(PqKemError::ReplayDetected { nonce_hex }) => {
            assert_eq!(nonce_hex.len(), PQ_NONCE_LEN.saturating_mul(2_usize));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected PQ error: {other:?}")),
        Ok(_) => Err(anyhow!("expected replay error")),
    }
}

/* ───────────────────────── services / version validation ───────────────── */

#[test]
fn test_001_services_bits_are_expected() -> AnyResult<()> {
    assert_eq!(Services::NONE.bits(), 0_u32);
    assert_eq!(Services::NODE.bits(), 1_u32);
    assert_eq!(Services::MINER.bits(), 2_u32);
    assert_eq!(Services::VALIDATOR.bits(), 4_u32);

    let combined = Services::NODE | Services::MINER | Services::VALIDATOR;
    assert_eq!(combined.bits(), 7_u32);
    Ok(())
}

#[test]
fn test_002_version_info_valid_minimal_node() -> AnyResult<()> {
    let info = version_info(1_u32, 0_u64, Services::NODE, "remzar/test", None);

    assert!(info.validate_untrusted().is_ok());
    Ok(())
}

#[test]
fn test_003_version_info_valid_all_services() -> AnyResult<()> {
    let services = Services::NODE | Services::MINER | Services::VALIDATOR;
    let info = version_info(1_000_000_u32, u64::MAX, services, "remzar/all", None);

    assert!(info.validate_untrusted().is_ok());
    Ok(())
}

#[test]
fn test_004_version_info_rejects_protocol_zero() -> AnyResult<()> {
    let info = version_info(0_u32, 0_u64, Services::NODE, "remzar/bad", None);

    assert_invalid_data(info.validate_untrusted(), "protocol_version")?;
    Ok(())
}

#[test]
fn test_005_version_info_rejects_protocol_above_cap() -> AnyResult<()> {
    let info = version_info(1_000_001_u32, 0_u64, Services::NODE, "remzar/bad", None);

    assert_invalid_data(info.validate_untrusted(), "protocol_version")?;
    Ok(())
}

#[test]
fn test_006_version_info_accepts_exactly_256_byte_user_agent() -> AnyResult<()> {
    let user_agent = "a".repeat(256_usize);
    let info = version_info(1_u32, 0_u64, Services::NODE, &user_agent, None);

    assert!(info.validate_untrusted().is_ok());
    Ok(())
}

#[test]
fn test_007_version_info_rejects_257_byte_user_agent() -> AnyResult<()> {
    let user_agent = "a".repeat(257_usize);
    let info = version_info(1_u32, 0_u64, Services::NODE, &user_agent, None);

    assert_invalid_data(info.validate_untrusted(), "user_agent too large")?;
    Ok(())
}

#[test]
fn test_008_version_info_rejects_unknown_service_bits() -> AnyResult<()> {
    let unknown_services = Services::from_bits_retain(1_u32 << 12_u32);
    let info = version_info(1_u32, 0_u64, unknown_services, "remzar/bad-services", None);

    assert_invalid_data(info.validate_untrusted(), "unknown bits")?;
    Ok(())
}

#[test]
fn test_009_version_info_expectations_accept_matching_protocol_and_genesis() -> AnyResult<()> {
    let genesis = hash64_from_seed(9_u64);
    let info = version_info(
        7_u32,
        90_u64,
        Services::NODE,
        "remzar/expected",
        Some(genesis),
    );

    assert!(
        info.validate_untrusted_with_expectations(7_u32, Some(genesis))
            .is_ok()
    );
    Ok(())
}

#[test]
fn test_010_version_info_expectations_allow_protocol_zero_as_no_protocol_check() -> AnyResult<()> {
    let genesis = hash64_from_seed(10_u64);
    let info = version_info(
        11_u32,
        100_u64,
        Services::NODE,
        "remzar/no-proto-check",
        Some(genesis),
    );

    assert!(
        info.validate_untrusted_with_expectations(0_u32, Some(genesis))
            .is_ok()
    );
    Ok(())
}

#[test]
fn test_011_version_info_expectations_reject_protocol_mismatch() -> AnyResult<()> {
    let info = version_info(3_u32, 0_u64, Services::NODE, "remzar/mismatch", None);

    assert_invalid_data(
        info.validate_untrusted_with_expectations(4_u32, None),
        "protocol_version mismatch",
    )?;
    Ok(())
}

#[test]
fn test_012_version_info_expectations_reject_genesis_mismatch() -> AnyResult<()> {
    let got = hash64_from_seed(12_u64);
    let expected = hash64_from_seed(12_001_u64);
    let info = version_info(
        1_u32,
        0_u64,
        Services::NODE,
        "remzar/genesis-mismatch",
        Some(got),
    );

    assert_invalid_data(
        info.validate_untrusted_with_expectations(1_u32, Some(expected)),
        "genesis_hash mismatch",
    )?;
    Ok(())
}

#[test]
fn test_013_version_info_expectations_reject_missing_genesis() -> AnyResult<()> {
    let expected = hash64_from_seed(13_u64);
    let info = version_info(1_u32, 0_u64, Services::NODE, "remzar/missing-genesis", None);

    assert_invalid_data(
        info.validate_untrusted_with_expectations(1_u32, Some(expected)),
        "missing genesis_hash",
    )?;
    Ok(())
}

#[test]
fn test_014_user_agent_for_log_keeps_short_agent() -> AnyResult<()> {
    let info = version_info(1_u32, 0_u64, Services::NODE, "remzar/short", None);

    assert_eq!(info.user_agent_for_log(), "remzar/short");
    Ok(())
}

#[test]
fn test_015_user_agent_for_log_truncates_long_agent_to_ellipsis() -> AnyResult<()> {
    let user_agent = "a".repeat(200_usize);
    let info = version_info(1_u32, 0_u64, Services::NODE, &user_agent, None);

    let logged = info.user_agent_for_log();

    assert_eq!(logged.len(), MAX_USER_AGENT_LOG_BYTES);
    assert!(logged.ends_with('…'));
    assert_eq!(logged.chars().count(), 126_usize);
    Ok(())
}

/* ───────────────────────── serde / protocol / builders ─────────────────── */

#[test]
fn test_016_version_info_json_round_trip_with_genesis_hash() -> AnyResult<()> {
    let info = version_info(
        1_u32,
        16_u64,
        Services::NODE | Services::VALIDATOR,
        "remzar/json",
        Some(hash64_from_seed(16_u64)),
    );

    let encoded = serde_json::to_string(&info)?;
    let decoded = serde_json::from_str::<VersionInfo>(&encoded)?;

    assert_version_eq(&decoded, &info);
    Ok(())
}

#[test]
fn test_017_version_info_postcard_round_trip_without_genesis_hash() -> AnyResult<()> {
    let info = version_info(
        2_u32,
        17_u64,
        Services::NODE | Services::MINER,
        "remzar/postcard",
        None,
    );

    let encoded = postcard::to_stdvec(&info)?;
    let decoded = postcard::from_bytes::<VersionInfo>(&encoded)?;

    assert_version_eq(&decoded, &info);
    Ok(())
}

#[test]
fn test_018_version_and_pq_protocol_names_match_wire_contract() -> AnyResult<()> {
    let version_proto = VersionProto;
    let pq_proto = PqProto;

    assert_eq!(version_proto.as_ref(), "/remzar/version/1.0.0");
    assert_eq!(pq_proto.as_ref(), "/remzar/pq/ml-kem-768/1.0.0");
    Ok(())
}

#[test]
fn test_019_build_version_exchange_can_send_request_id() -> AnyResult<()> {
    let mut exchange = build_version_exchange();
    let peer = generated_peer_id();
    let info = version_info(1_u32, 19_u64, Services::NODE, "remzar/version-send", None);

    let request_id = exchange.send_request(&peer, info);
    let rendered = format!("{request_id:?}");

    assert!(!rendered.is_empty());
    Ok(())
}

#[test]
fn test_020_build_pq_exchange_can_send_request_id() -> AnyResult<()> {
    let mut exchange = build_pq_exchange();
    let peer = generated_peer_id();
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(20_u64))?;

    let request_id = exchange.send_request(&peer, request);
    let rendered = format!("{request_id:?}");

    assert!(!rendered.is_empty());
    Ok(())
}

/* ───────────────────────── VersionCodec framing ────────────────────────── */

#[test]
fn test_021_version_codec_write_then_read_request_round_trip() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let info = version_info(1_u32, 21_u64, Services::NODE, "remzar/codec-req", None);

    let mut writer = Cursor::new(Vec::<u8>::new());
    block_on(codec.write_request(&proto, &mut writer, info.clone()))?;

    let bytes = writer.into_inner();
    let mut reader = Cursor::new(bytes);
    let decoded = block_on(codec.read_request(&proto, &mut reader))?;

    assert_version_eq(&decoded, &info);
    Ok(())
}

#[test]
fn test_022_version_codec_write_then_read_response_round_trip() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let info = version_info(
        2_u32,
        22_u64,
        Services::NODE | Services::MINER,
        "remzar/codec-rsp",
        Some(hash64_from_seed(22_u64)),
    );

    let mut writer = Cursor::new(Vec::<u8>::new());
    block_on(codec.write_response(&proto, &mut writer, info.clone()))?;

    let bytes = writer.into_inner();
    let mut reader = Cursor::new(bytes);
    let decoded = block_on(codec.read_response(&proto, &mut reader))?;

    assert_version_eq(&decoded, &info);
    Ok(())
}

#[test]
fn test_023_version_codec_read_request_rejects_invalid_version_payload() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let bad_info = version_info(0_u32, 23_u64, Services::NODE, "remzar/bad-codec", None);

    let encoded = postcard::to_stdvec(&bad_info)?;
    let frame = framed_bytes(&encoded)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "protocol_version",
    )?;
    Ok(())
}

#[test]
fn test_024_version_codec_write_rejects_oversized_payload() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let huge_user_agent = "a".repeat(TEST_VERSION_MAX_WIRE_BYTES);
    let info = version_info(
        1_u32,
        24_u64,
        Services::NODE,
        &huge_user_agent,
        Some(hash64_from_seed(24_u64)),
    );

    let mut writer = Cursor::new(Vec::<u8>::new());
    assert_invalid_data(
        block_on(codec.write_request(&proto, &mut writer, info)),
        "too large",
    )?;
    Ok(())
}

#[test]
fn test_025_version_codec_read_rejects_oversized_length_prefix_before_body() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let too_large = u32::try_from(TEST_VERSION_MAX_WIRE_BYTES.saturating_add(1_usize))?;
    let frame = encode_varint_u32(too_large)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "payload too large",
    )?;
    Ok(())
}

#[test]
fn test_026_version_codec_read_rejects_malformed_varint() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;

    let frame = vec![0x80_u8, 0x80_u8, 0x80_u8, 0x80_u8, 0x80_u8, 0x00_u8];
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "varint length exceeds u32 prefix cap",
    )?;
    Ok(())
}

#[test]
fn test_027_version_codec_read_rejects_truncated_body() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let mut frame = encode_varint_u32(8_u32)?;
    frame.extend_from_slice(&[1_u8, 2_u8]);
    let mut reader = Cursor::new(frame);

    match block_on(codec.read_request(&proto, &mut reader)) {
        Err(err) => {
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected UnexpectedEof")),
    }
}

/* ───────────────────────── PQ orchestration helpers ────────────────────── */

#[test]
fn test_028_build_default_pq_manager_has_default_policy() -> AnyResult<()> {
    let manager = build_default_pq_manager();

    assert_eq!(
        manager.policy().max_message_age,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)
    );
    assert!(manager.policy().require_single_use_local_keypair);
    Ok(())
}

#[test]
fn test_029_build_pq_manager_preserves_custom_policy() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(9_u64),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 7_usize,
    };

    let manager = build_pq_manager(policy);

    assert_eq!(manager.policy().max_message_age, Duration::from_secs(9_u64));
    assert_eq!(manager.policy().replay_filter_capacity, 7_usize);
    Ok(())
}

#[test]
fn test_030_build_outbound_pq_offer_returns_state_and_offer_with_nonce() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let nonce = nonce_from_seed(30_u64);

    let (state, request) = build_outbound_pq_offer(&mut manager, nonce)?;

    assert_eq!(state.offer_nonce, nonce);
    match request {
        PqHandshakeRequest::Offer(offer) => {
            assert_eq!(offer.suite_id, PQ_KEM_SUITE_ID);
            assert_eq!(offer.nonce, nonce.to_vec());
            assert!(offer.created_at_unix_secs > 0_u64);
        }
    }

    Ok(())
}

#[test]
fn test_031_handle_inbound_pq_request_returns_accept_and_session() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(31_u64);
    let (_state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;

    let (response, session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    match response {
        PqHandshakeResponse::Accept(accept) => {
            assert_eq!(accept.suite_id, PQ_KEM_SUITE_ID);
            assert_eq!(accept.offer_nonce, nonce.to_vec());
            assert_eq!(accept.ct.len(), ct_len());
        }
    }
    assert_eq!(session.as_bytes().len(), 32_usize);
    Ok(())
}

#[test]
fn test_032_finalize_inbound_pq_response_matches_responder_session() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(32_u64);

    let (mut state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;
    let (response, responder_session) = handle_inbound_pq_request(&mut responder_manager, request)?;
    let initiator_session =
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, response)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    Ok(())
}

#[test]
fn test_033_handle_inbound_pq_request_rejects_replay() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(33_u64);

    let (_state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;
    let first = handle_inbound_pq_request(&mut responder_manager, request.clone());
    assert!(first.is_ok());

    assert_pq_replay(handle_inbound_pq_request(&mut responder_manager, request))?;
    Ok(())
}

#[test]
fn test_034_finalize_inbound_pq_response_rejects_second_finalize() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(34_u64);

    let (mut state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;
    let (response, _responder_session) =
        handle_inbound_pq_request(&mut responder_manager, request)?;

    let first = finalize_inbound_pq_response(&mut initiator_manager, &mut state, response.clone());
    assert!(first.is_ok());

    match finalize_inbound_pq_response(&mut initiator_manager, &mut state, response) {
        Err(PqKemError::InvalidState(message)) => {
            assert!(message.contains("consumed"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected PQ error: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidState error")),
    }
}

/* ───────────────────────── PqCodec framing ─────────────────────────────── */

#[test]
fn test_035_pq_codec_write_then_read_request_round_trip_offer() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(35_u64))?;

    let mut codec = PqCodec;
    let proto = PqProto;
    let mut writer = Cursor::new(Vec::<u8>::new());

    block_on(codec.write_request(&proto, &mut writer, request.clone()))?;

    let bytes = writer.into_inner();
    let mut reader = Cursor::new(bytes);
    let decoded = block_on(codec.read_request(&proto, &mut reader))?;

    match (request, decoded) {
        (PqHandshakeRequest::Offer(left), PqHandshakeRequest::Offer(right)) => {
            assert_eq!(left, right);
        }
    }

    Ok(())
}

#[test]
fn test_036_pq_codec_write_then_read_response_round_trip_accept() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(36_u64))?;
    let (response, _session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    let mut codec = PqCodec;
    let proto = PqProto;
    let mut writer = Cursor::new(Vec::<u8>::new());

    block_on(codec.write_response(&proto, &mut writer, response.clone()))?;

    let bytes = writer.into_inner();
    let mut reader = Cursor::new(bytes);
    let decoded = block_on(codec.read_response(&proto, &mut reader))?;

    match (response, decoded) {
        (PqHandshakeResponse::Accept(left), PqHandshakeResponse::Accept(right)) => {
            assert_eq!(left, right);
        }
    }

    Ok(())
}

#[test]
fn test_037_pq_codec_read_request_rejects_bad_offer_nonce_length() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(37_u64))?;

    let bad_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            assert!(offer.nonce.pop().is_some());
            PqHandshakeRequest::Offer(offer)
        }
    };

    let encoded = postcard::to_stdvec(&bad_request)?;
    let frame = framed_bytes(&encoded)?;
    let mut reader = Cursor::new(frame);

    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(block_on(codec.read_request(&proto, &mut reader)), "nonce")?;
    Ok(())
}

#[test]
fn test_038_pq_codec_read_response_rejects_bad_accept_nonce_length() -> AnyResult<()> {
    let bad_accept = remzar::network::p2p_005_pq_fips203kem::PqKemAccept {
        suite_id: PQ_KEM_SUITE_ID,
        offer_nonce: vec![0_u8; PQ_NONCE_LEN.saturating_sub(1_usize)],
        created_at_unix_secs: 1_u64,
        ct: vec![0_u8; ct_len()],
    };
    let response = PqHandshakeResponse::Accept(bad_accept);

    let encoded = postcard::to_stdvec(&response)?;
    let frame = framed_bytes(&encoded)?;
    let mut reader = Cursor::new(frame);

    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(
        block_on(codec.read_response(&proto, &mut reader)),
        "invalid PQ accept nonce length",
    )?;
    Ok(())
}

#[test]
fn test_039_pq_codec_read_rejects_oversized_length_prefix_before_body() -> AnyResult<()> {
    let too_large = u32::try_from(PQ_MAX_WIRE_BYTES.saturating_add(1_usize))?;
    let frame = encode_varint_u32(too_large)?;
    let mut reader = Cursor::new(frame);

    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "payload too large",
    )?;
    Ok(())
}

#[test]
fn test_040_combined_version_and_pq_handshake_path_is_safe() -> AnyResult<()> {
    let version = version_info(
        1_u32,
        40_u64,
        Services::NODE | Services::VALIDATOR,
        "remzar/combined",
        Some(hash64_from_seed(40_u64)),
    );
    assert!(
        version
            .validate_untrusted_with_expectations(1_u32, Some(hash64_from_seed(40_u64)))
            .is_ok()
    );

    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(40_u64);

    let (mut state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;
    let (response, responder_session) = handle_inbound_pq_request(&mut responder_manager, request)?;
    let initiator_session =
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, response)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());

    let peer = generated_peer_id();
    let mut version_exchange = build_version_exchange();
    let mut pq_exchange = build_pq_exchange();

    let version_request_id = version_exchange.send_request(&peer, version);
    let (_state_two, pq_request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(40_001_u64))?;
    let pq_request_id = pq_exchange.send_request(&peer, pq_request);

    assert!(!format!("{version_request_id:?}").is_empty());
    assert!(!format!("{pq_request_id:?}").is_empty());
    Ok(())
}

#[test]
fn test_041_version_info_empty_user_agent_is_valid() -> AnyResult<()> {
    let info = version_info(1_u32, 41_u64, Services::NODE, "", None);

    assert!(info.validate_untrusted().is_ok());
    Ok(())
}

#[test]
fn test_042_version_info_none_services_is_valid() -> AnyResult<()> {
    let info = version_info(1_u32, 42_u64, Services::NONE, "remzar/none", None);

    assert!(info.validate_untrusted().is_ok());
    Ok(())
}

#[test]
fn test_043_version_info_service_combinations_are_valid() -> AnyResult<()> {
    for services in [
        Services::NODE,
        Services::MINER,
        Services::VALIDATOR,
        Services::NODE | Services::MINER,
        Services::NODE | Services::VALIDATOR,
        Services::MINER | Services::VALIDATOR,
        Services::NODE | Services::MINER | Services::VALIDATOR,
    ] {
        let info = version_info(1_u32, 43_u64, services, "remzar/services", None);
        assert!(info.validate_untrusted().is_ok());
    }

    Ok(())
}

#[test]
fn test_044_version_info_chain_height_edges_are_valid() -> AnyResult<()> {
    for height in [0_u64, 1_u64, 2_u64, u64::MAX] {
        let info = version_info(1_u32, height, Services::NODE, "remzar/heights", None);
        assert!(info.validate_untrusted().is_ok());
    }

    Ok(())
}

#[test]
fn test_045_version_expectations_accept_all_zero_genesis() -> AnyResult<()> {
    let genesis = [0_u8; 64];
    let info = version_info(
        1_u32,
        45_u64,
        Services::NODE,
        "remzar/zero-genesis",
        Some(genesis),
    );

    assert!(
        info.validate_untrusted_with_expectations(1_u32, Some(genesis))
            .is_ok()
    );
    Ok(())
}

#[test]
fn test_046_version_expectations_none_does_not_require_genesis_even_if_present() -> AnyResult<()> {
    let info = version_info(
        1_u32,
        46_u64,
        Services::NODE,
        "remzar/no-genesis-check",
        Some(hash64_from_seed(46_u64)),
    );

    assert!(
        info.validate_untrusted_with_expectations(1_u32, None)
            .is_ok()
    );
    Ok(())
}

#[test]
fn test_047_version_info_rejects_valid_and_unknown_service_bits_together() -> AnyResult<()> {
    let services = Services::from_bits_retain(Services::NODE.bits() | (1_u32 << 20_u32));
    let info = version_info(1_u32, 47_u64, services, "remzar/unknown-service", None);

    assert_invalid_data(info.validate_untrusted(), "unknown bits")?;
    Ok(())
}

#[test]
fn test_048_user_agent_for_log_keeps_exactly_128_ascii_bytes() -> AnyResult<()> {
    let user_agent = "a".repeat(128_usize);
    let info = version_info(1_u32, 48_u64, Services::NODE, &user_agent, None);

    let logged = info.user_agent_for_log();

    assert_eq!(logged, user_agent);
    assert_eq!(logged.len(), 128_usize);
    Ok(())
}

#[test]
fn test_049_user_agent_for_log_truncates_129_ascii_bytes() -> AnyResult<()> {
    let user_agent = "a".repeat(129_usize);
    let info = version_info(1_u32, 49_u64, Services::NODE, &user_agent, None);

    let logged = info.user_agent_for_log();

    assert_eq!(logged.len(), MAX_USER_AGENT_LOG_BYTES);
    assert!(logged.ends_with('…'));
    assert_eq!(logged.chars().count(), 126_usize);
    Ok(())
}

#[test]
fn test_050_version_json_legacy_32_byte_genesis_expands_to_64_bytes() -> AnyResult<()> {
    let info = version_info(1_u32, 50_u64, Services::NODE, "remzar/legacy32", None);
    let legacy32 = [7_u8; 32];
    let mut value = serde_json::to_value(&info)?;

    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "genesis_hash".to_owned(),
            serde_json::Value::String(hex::encode(legacy32)),
        );
    } else {
        return Err(anyhow!("expected JSON object"));
    }

    let decoded = serde_json::from_value::<VersionInfo>(value)?;

    let mut expected = [0_u8; 64];
    expected[32_usize..].copy_from_slice(&legacy32);
    assert_eq!(decoded.genesis_hash, Some(expected));
    Ok(())
}

#[test]
fn test_051_version_json_rejects_invalid_genesis_hash_length() -> AnyResult<()> {
    let info = version_info(
        1_u32,
        51_u64,
        Services::NODE,
        "remzar/bad-genesis-len",
        None,
    );
    let mut value = serde_json::to_value(&info)?;

    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "genesis_hash".to_owned(),
            serde_json::Value::String("abcd".to_owned()),
        );
    } else {
        return Err(anyhow!("expected JSON object"));
    }

    let decoded = serde_json::from_value::<VersionInfo>(value);
    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn test_052_version_json_rejects_invalid_genesis_hash_hex() -> AnyResult<()> {
    let info = version_info(
        1_u32,
        52_u64,
        Services::NODE,
        "remzar/bad-genesis-hex",
        None,
    );
    let mut value = serde_json::to_value(&info)?;

    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "genesis_hash".to_owned(),
            serde_json::Value::String("zz".repeat(64_usize)),
        );
    } else {
        return Err(anyhow!("expected JSON object"));
    }

    let decoded = serde_json::from_value::<VersionInfo>(value);
    assert!(decoded.is_err());
    Ok(())
}

/* ───────────────────────── VersionCodec extra wire tests ──────────────── */

#[test]
fn test_053_version_codec_read_response_rejects_257_byte_user_agent() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let info = version_info(1_u32, 53_u64, Services::NODE, &"a".repeat(257_usize), None);

    let frame = version_frame_for(&info)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_response(&proto, &mut reader)),
        "user_agent too large",
    )?;
    Ok(())
}

#[test]
fn test_054_version_codec_read_request_rejects_zero_length_postcard_body() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let frame = encode_varint_u32(0_u32)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(block_on(codec.read_request(&proto, &mut reader)), "")?;
    Ok(())
}

#[test]
fn test_055_version_codec_read_request_rejects_random_body() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let body = vec![1_u8, 2_u8, 3_u8, 4_u8, 5_u8];
    let frame = framed_bytes(&body)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(block_on(codec.read_request(&proto, &mut reader)), "")?;
    Ok(())
}

#[test]
fn test_056_version_codec_read_response_rejects_oversized_length_prefix() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let too_large = u32::try_from(TEST_VERSION_MAX_WIRE_BYTES.saturating_add(1_usize))?;
    let frame = encode_varint_u32(too_large)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_response(&proto, &mut reader)),
        "payload too large",
    )?;
    Ok(())
}

#[test]
fn test_057_version_codec_write_and_read_exact_256_user_agent() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let user_agent = "b".repeat(256_usize);
    let info = version_info(1_u32, 57_u64, Services::NODE, &user_agent, None);

    let mut writer = Cursor::new(Vec::<u8>::new());
    block_on(codec.write_request(&proto, &mut writer, info.clone()))?;

    let bytes = writer.into_inner();
    let mut reader = Cursor::new(bytes);
    let decoded = block_on(codec.read_request(&proto, &mut reader))?;

    assert_version_eq(&decoded, &info);
    Ok(())
}

#[test]
fn test_058_version_codec_vector_round_trips_multiple_service_sets() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;

    for services in [
        Services::NONE,
        Services::NODE,
        Services::MINER,
        Services::VALIDATOR,
        Services::NODE | Services::MINER | Services::VALIDATOR,
    ] {
        let info = version_info(1_u32, 58_u64, services, "remzar/vector-codec", None);

        let mut writer = Cursor::new(Vec::<u8>::new());
        block_on(codec.write_request(&proto, &mut writer, info.clone()))?;

        let bytes = writer.into_inner();
        let mut reader = Cursor::new(bytes);
        let decoded = block_on(codec.read_request(&proto, &mut reader))?;

        assert_version_eq(&decoded, &info);
    }

    Ok(())
}

/* ───────────────────────── PQ protocol / codec edge cases ──────────────── */

#[test]
fn test_059_protocol_debug_and_clone_are_nonempty() -> AnyResult<()> {
    let version_proto = VersionProto;
    let pq_proto = PqProto;

    let version_clone = version_proto.clone();
    let pq_clone = pq_proto.clone();

    assert!(!format!("{version_clone:?}").is_empty());
    assert!(!format!("{pq_clone:?}").is_empty());
    Ok(())
}

#[test]
fn test_060_pq_codec_read_request_rejects_wrong_suite_id_offer() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(60_u64))?;

    let bad_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            offer.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);
            PqHandshakeRequest::Offer(offer)
        }
    };

    let frame = pq_request_frame_for(&bad_request)?;
    let mut reader = Cursor::new(frame);
    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(block_on(codec.read_request(&proto, &mut reader)), "suite")?;
    Ok(())
}

#[test]
fn test_061_pq_codec_read_request_rejects_zero_created_at_offer() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(61_u64))?;

    let bad_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            offer.created_at_unix_secs = 0_u64;
            PqHandshakeRequest::Offer(offer)
        }
    };

    let frame = pq_request_frame_for(&bad_request)?;
    let mut reader = Cursor::new(frame);
    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "created_at_unix_secs",
    )?;
    Ok(())
}

#[test]
fn test_062_pq_codec_read_request_rejects_bad_ek_length_offer() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(62_u64))?;

    let bad_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            assert!(offer.ek.pop().is_some());
            PqHandshakeRequest::Offer(offer)
        }
    };

    let frame = pq_request_frame_for(&bad_request)?;
    let mut reader = Cursor::new(frame);
    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(block_on(codec.read_request(&proto, &mut reader)), "ek")?;
    Ok(())
}

#[test]
fn test_063_pq_codec_read_request_rejects_expired_offer() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(63_u64))?;

    let bad_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            offer.created_at_unix_secs = 1_u64;
            PqHandshakeRequest::Offer(offer)
        }
    };

    let frame = pq_request_frame_for(&bad_request)?;
    let mut reader = Cursor::new(frame);
    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(block_on(codec.read_request(&proto, &mut reader)), "expired")?;
    Ok(())
}

#[test]
fn test_064_pq_codec_read_response_accepts_structural_accept_without_full_nonce_validation()
-> AnyResult<()> {
    let accept = remzar::network::p2p_005_pq_fips203kem::PqKemAccept {
        // The response codec intentionally does not fully validate suite id;
        suite_id: PQ_KEM_SUITE_ID.saturating_add(1_u16),
        offer_nonce: vec![9_u8; PQ_NONCE_LEN],
        created_at_unix_secs: 1_u64,

        // Current codec rejects empty ciphertext early, so keep it non-empty.
        ct: vec![1_u8],
    };
    let response = PqHandshakeResponse::Accept(accept.clone());

    let frame = pq_response_frame_for(&response)?;
    let mut reader = Cursor::new(frame);
    let mut codec = PqCodec;
    let proto = PqProto;

    let decoded = block_on(codec.read_response(&proto, &mut reader))?;

    match decoded {
        PqHandshakeResponse::Accept(decoded_accept) => {
            assert_eq!(decoded_accept.offer_nonce.len(), PQ_NONCE_LEN);
            assert_eq!(decoded_accept.suite_id, accept.suite_id);
            assert_eq!(decoded_accept.ct, vec![1_u8]);
        }
    }

    Ok(())
}

#[test]
fn test_065_pq_codec_read_response_rejects_random_body() -> AnyResult<()> {
    let body = vec![1_u8, 2_u8, 3_u8, 4_u8, 5_u8];
    let frame = framed_bytes(&body)?;
    let mut reader = Cursor::new(frame);
    let mut codec = PqCodec;
    let proto = PqProto;

    assert_invalid_data(block_on(codec.read_response(&proto, &mut reader)), "")?;
    Ok(())
}

#[test]
fn test_066_pq_codec_read_response_rejects_truncated_body() -> AnyResult<()> {
    let mut frame = encode_varint_u32(64_u32)?;
    frame.extend_from_slice(&[1_u8, 2_u8, 3_u8]);
    let mut reader = Cursor::new(frame);
    let mut codec = PqCodec;
    let proto = PqProto;

    match block_on(codec.read_response(&proto, &mut reader)) {
        Err(err) => {
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected UnexpectedEof")),
    }
}

#[test]
fn test_067_pq_codec_write_request_rejects_oversized_serialized_offer() -> AnyResult<()> {
    let huge_offer = remzar::network::p2p_005_pq_fips203kem::PqKemOffer {
        suite_id: PQ_KEM_SUITE_ID,
        created_at_unix_secs: 1_u64,
        nonce: vec![1_u8; PQ_NONCE_LEN],
        ek: vec![2_u8; PQ_MAX_WIRE_BYTES.saturating_add(512_usize)],
    };
    let request = PqHandshakeRequest::Offer(huge_offer);

    let mut codec = PqCodec;
    let proto = PqProto;
    let mut writer = Cursor::new(Vec::<u8>::new());

    assert_invalid_data(
        block_on(codec.write_request(&proto, &mut writer, request)),
        "too large",
    )?;
    Ok(())
}

#[test]
fn test_068_pq_codec_write_response_rejects_oversized_serialized_accept() -> AnyResult<()> {
    let huge_accept = remzar::network::p2p_005_pq_fips203kem::PqKemAccept {
        suite_id: PQ_KEM_SUITE_ID,
        offer_nonce: vec![1_u8; PQ_NONCE_LEN],
        created_at_unix_secs: 1_u64,
        ct: vec![2_u8; PQ_MAX_WIRE_BYTES.saturating_add(512_usize)],
    };
    let response = PqHandshakeResponse::Accept(huge_accept);

    let mut codec = PqCodec;
    let proto = PqProto;
    let mut writer = Cursor::new(Vec::<u8>::new());

    assert_invalid_data(
        block_on(codec.write_response(&proto, &mut writer, response)),
        "too large",
    )?;
    Ok(())
}

/* ───────────────────────── PQ orchestration edge cases ─────────────────── */

#[test]
fn test_069_pq_responder_directly_accepts_outbound_offer() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let nonce = nonce_from_seed(69_u64);
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce)?;

    match request {
        PqHandshakeRequest::Offer(offer) => {
            let (accept, session) = PqResponder::respond_to_offer(
                &offer,
                Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
            )?;

            assert_eq!(accept.offer_nonce, nonce.to_vec());
            assert_eq!(session.as_bytes().len(), 32_usize);
        }
    }

    Ok(())
}

#[test]
fn test_070_build_outbound_pq_offer_rejects_all_zero_nonce() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let nonce = [0_u8; PQ_NONCE_LEN];

    match build_outbound_pq_offer(&mut manager, nonce) {
        Err(PqKemError::InvalidRange { field, details }) => {
            assert_eq!(field, "offer_nonce");
            assert!(details.contains("all zero"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected PQ error: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidRange for all-zero offer_nonce")),
    }
}

#[test]
fn test_071_build_outbound_pq_offer_all_ff_nonce() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let nonce = [0xff_u8; PQ_NONCE_LEN];

    let (state, request) = build_outbound_pq_offer(&mut manager, nonce)?;

    assert_eq!(state.offer_nonce, nonce);
    match request {
        PqHandshakeRequest::Offer(offer) => {
            assert_eq!(offer.nonce, nonce.to_vec());
        }
    }

    Ok(())
}

#[test]
fn test_072_handle_inbound_pq_request_rejects_wrong_suite_offer() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(72_u64))?;

    let bad_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            offer.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);
            PqHandshakeRequest::Offer(offer)
        }
    };

    assert_pq_invalid_message(
        handle_inbound_pq_request(&mut responder_manager, bad_request),
        "inbound PQ offer failed validation",
    )?;
    Ok(())
}

#[test]
fn test_073_handle_inbound_pq_request_rejects_zero_created_at_offer() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(73_u64))?;

    let bad_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            offer.created_at_unix_secs = 0_u64;
            PqHandshakeRequest::Offer(offer)
        }
    };

    assert_pq_invalid_message(
        handle_inbound_pq_request(&mut responder_manager, bad_request),
        "inbound PQ offer failed validation",
    )?;
    Ok(())
}

#[test]
fn test_074_handle_inbound_replay_after_clear_cache_is_allowed() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(74_u64))?;

    let first = handle_inbound_pq_request(&mut responder_manager, request.clone());
    assert!(first.is_ok());

    assert_pq_replay(handle_inbound_pq_request(
        &mut responder_manager,
        request.clone(),
    ))?;

    responder_manager.clear_replay_cache();

    let second_after_clear = handle_inbound_pq_request(&mut responder_manager, request);
    assert!(second_after_clear.is_ok());
    Ok(())
}

#[test]
fn test_075_finalize_rejects_response_for_different_offer_nonce() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (mut state_one, _request_one) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(75_u64))?;
    let (_state_two, request_two) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(75_002_u64))?;

    let (response_two, _session_two) =
        handle_inbound_pq_request(&mut responder_manager, request_two)?;

    assert_pq_invalid_message(
        finalize_inbound_pq_response(&mut initiator_manager, &mut state_one, response_two),
        "mismatch",
    )?;
    Ok(())
}

#[test]
fn test_076_finalize_rejects_bad_accept_nonce_length() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(76_u64);

    let (mut state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;
    let (response, _session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    let bad_response = match response {
        PqHandshakeResponse::Accept(mut accept) => {
            assert!(accept.offer_nonce.pop().is_some());
            PqHandshakeResponse::Accept(accept)
        }
    };

    assert_pq_invalid_message(
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, bad_response),
        "inbound PQ accept failed validation",
    )?;

    Ok(())
}

#[test]
fn test_077_finalize_rejects_wrong_suite_accept() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(77_u64);

    let (mut state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;
    let (response, _session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    let bad_response = match response {
        PqHandshakeResponse::Accept(mut accept) => {
            accept.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);
            PqHandshakeResponse::Accept(accept)
        }
    };

    assert_pq_invalid_message(
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, bad_response),
        "suite",
    )?;
    Ok(())
}

#[test]
fn test_078_finalize_rejects_short_ciphertext_accept() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();
    let nonce = nonce_from_seed(78_u64);

    let (mut state, request) = build_outbound_pq_offer(&mut initiator_manager, nonce)?;
    let (response, _session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    let bad_response = match response {
        PqHandshakeResponse::Accept(mut accept) => {
            assert!(accept.ct.pop().is_some());
            PqHandshakeResponse::Accept(accept)
        }
    };

    assert_pq_invalid_length(
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, bad_response),
        "ct",
        ct_len(),
        ct_len().saturating_sub(1_usize),
    )?;
    Ok(())
}

#[test]
fn test_079_custom_policy_min_replay_capacity_allows_old_nonce_after_eviction() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: true,
        replay_filter_capacity: MIN_REPLAY_FILTER_CAPACITY,
    };

    let mut initiator_manager = build_pq_manager(policy.clone());
    let mut responder_manager = build_pq_manager(policy);

    let (_state_one, request_one) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(79_u64))?;

    assert!(handle_inbound_pq_request(&mut responder_manager, request_one.clone()).is_ok());

    for offset in 0_usize..MIN_REPLAY_FILTER_CAPACITY {
        let offset_u64 = u64::try_from(offset)?;
        let (_state, request) = build_outbound_pq_offer(
            &mut initiator_manager,
            nonce_from_seed(79_002_u64.saturating_add(offset_u64)),
        )?;
        assert!(handle_inbound_pq_request(&mut responder_manager, request).is_ok());
    }

    assert!(handle_inbound_pq_request(&mut responder_manager, request_one).is_ok());
    Ok(())
}

#[test]
fn test_080_custom_policy_expired_offer_rejected_by_inbound_handler() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(1_u64),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 16_usize,
    };

    let mut initiator_manager = build_pq_manager(policy.clone());
    let mut responder_manager = build_pq_manager(policy);

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(80_u64))?;

    let expired_request = match request {
        PqHandshakeRequest::Offer(mut offer) => {
            offer.created_at_unix_secs = 1_u64;
            PqHandshakeRequest::Offer(offer)
        }
    };

    assert_pq_invalid_message(
        handle_inbound_pq_request(&mut responder_manager, expired_request),
        "inbound PQ offer failed validation",
    )?;

    Ok(())
}

/* ───────────────────────── combined codec/orchestration vectors ────────── */

#[test]
fn test_081_pq_request_postcard_codec_then_inbound_handler() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(81_u64))?;

    let encoded = postcard::to_stdvec(&request)?;
    let decoded = postcard::from_bytes::<PqHandshakeRequest>(&encoded)?;

    let (response, session) = handle_inbound_pq_request(&mut responder_manager, decoded)?;

    match response {
        PqHandshakeResponse::Accept(accept) => {
            assert_eq!(accept.ct.len(), ct_len());
        }
    }
    assert_eq!(session.as_bytes().len(), 32_usize);
    Ok(())
}

#[test]
fn test_082_pq_response_postcard_codec_then_finalize_matches() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (mut state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(82_u64))?;
    let (response, responder_session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    let encoded = postcard::to_stdvec(&response)?;
    let decoded = postcard::from_bytes::<PqHandshakeResponse>(&encoded)?;

    let initiator_session =
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, decoded)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    Ok(())
}

#[test]
fn test_083_version_and_pq_codecs_can_be_used_back_to_back() -> AnyResult<()> {
    let mut version_codec = VersionCodec;
    let version_proto = VersionProto;
    let version = version_info(1_u32, 83_u64, Services::NODE, "remzar/back-to-back", None);

    let mut version_writer = Cursor::new(Vec::<u8>::new());
    block_on(version_codec.write_request(&version_proto, &mut version_writer, version.clone()))?;

    let mut version_reader = Cursor::new(version_writer.into_inner());
    let decoded_version =
        block_on(version_codec.read_request(&version_proto, &mut version_reader))?;
    assert_version_eq(&decoded_version, &version);

    let mut pq_manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut pq_manager, nonce_from_seed(83_u64))?;
    let mut pq_codec = PqCodec;
    let pq_proto = PqProto;

    let mut pq_writer = Cursor::new(Vec::<u8>::new());
    block_on(pq_codec.write_request(&pq_proto, &mut pq_writer, request.clone()))?;

    let mut pq_reader = Cursor::new(pq_writer.into_inner());
    let decoded_request = block_on(pq_codec.read_request(&pq_proto, &mut pq_reader))?;

    match (request, decoded_request) {
        (PqHandshakeRequest::Offer(left), PqHandshakeRequest::Offer(right)) => {
            assert_eq!(left, right);
        }
    }

    Ok(())
}

#[test]
fn test_084_version_exchange_load_32_send_request_ids() -> AnyResult<()> {
    let mut exchange = build_version_exchange();

    for height in 0_u64..32_u64 {
        let peer = generated_peer_id();
        let info = version_info(1_u32, height, Services::NODE, "remzar/load-version", None);
        let request_id = exchange.send_request(&peer, info);
        assert!(!format!("{request_id:?}").is_empty());
    }

    Ok(())
}

#[test]
fn test_085_pq_exchange_load_16_send_request_ids() -> AnyResult<()> {
    let mut exchange = build_pq_exchange();
    let mut manager = build_default_pq_manager();

    for seed in 0_u64..16_u64 {
        let peer = generated_peer_id();
        let (_state, request) =
            build_outbound_pq_offer(&mut manager, nonce_from_seed(85_000_u64 + seed))?;
        let request_id = exchange.send_request(&peer, request);
        assert!(!format!("{request_id:?}").is_empty());
    }

    Ok(())
}

#[test]
fn test_086_version_codec_fuzz_20_round_trips() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;

    for seed in 86_u64..106_u64 {
        let info = version_info(
            1_u32,
            seed,
            Services::NODE | Services::VALIDATOR,
            "remzar/fuzz-version",
            Some(hash64_from_seed(seed)),
        );

        let mut writer = Cursor::new(Vec::<u8>::new());
        block_on(codec.write_request(&proto, &mut writer, info.clone()))?;

        let mut reader = Cursor::new(writer.into_inner());
        let decoded = block_on(codec.read_request(&proto, &mut reader))?;

        assert_version_eq(&decoded, &info);
    }

    Ok(())
}

#[test]
fn test_087_pq_codec_fuzz_8_request_round_trips() -> AnyResult<()> {
    let mut codec = PqCodec;
    let proto = PqProto;
    let mut manager = build_default_pq_manager();

    for seed in 87_u64..95_u64 {
        let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(seed))?;

        let mut writer = Cursor::new(Vec::<u8>::new());
        block_on(codec.write_request(&proto, &mut writer, request.clone()))?;

        let mut reader = Cursor::new(writer.into_inner());
        let decoded = block_on(codec.read_request(&proto, &mut reader))?;

        match (request, decoded) {
            (PqHandshakeRequest::Offer(left), PqHandshakeRequest::Offer(right)) => {
                assert_eq!(left, right);
            }
        }
    }

    Ok(())
}

#[test]
fn test_088_pq_orchestration_fuzz_8_full_handshakes_match() -> AnyResult<()> {
    for seed in 88_u64..96_u64 {
        let mut initiator_manager = build_default_pq_manager();
        let mut responder_manager = build_default_pq_manager();

        let (mut state, request) =
            build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(seed))?;
        let (response, responder_session) =
            handle_inbound_pq_request(&mut responder_manager, request)?;
        let initiator_session =
            finalize_inbound_pq_response(&mut initiator_manager, &mut state, response)?;

        assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    }

    Ok(())
}

#[test]
fn test_089_adversarial_replay_then_clear_then_full_handshake() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(89_u64))?;

    assert!(handle_inbound_pq_request(&mut responder_manager, request.clone()).is_ok());
    assert_pq_replay(handle_inbound_pq_request(
        &mut responder_manager,
        request.clone(),
    ))?;

    responder_manager.clear_replay_cache();

    let (mut state_two, request_two) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(89_002_u64))?;
    let (response_two, responder_session_two) =
        handle_inbound_pq_request(&mut responder_manager, request_two)?;
    let initiator_session_two =
        finalize_inbound_pq_response(&mut initiator_manager, &mut state_two, response_two)?;

    assert_eq!(
        initiator_session_two.as_bytes(),
        responder_session_two.as_bytes()
    );
    Ok(())
}

#[test]
fn test_090_adversarial_bad_finalize_after_good_finalize_is_safe() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (mut state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(90_u64))?;
    let (response, responder_session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    let initiator_session =
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, response.clone())?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());

    match finalize_inbound_pq_response(&mut initiator_manager, &mut state, response) {
        Err(PqKemError::InvalidState(message)) => {
            assert!(message.contains("consumed"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected PQ error: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidState")),
    }
}

#[test]
fn test_091_version_info_debug_clone_is_nonempty() -> AnyResult<()> {
    let info = version_info(
        1_u32,
        91_u64,
        Services::NODE | Services::MINER,
        "remzar/debug-clone",
        Some(hash64_from_seed(91_u64)),
    );
    let cloned = info.clone();
    let rendered = format!("{cloned:?}");

    assert!(!rendered.is_empty());
    assert_version_eq(&info, &cloned);
    Ok(())
}

#[test]
fn test_092_pq_initiator_state_debug_is_nonempty_and_redacted_by_keypair_debug() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (state, _request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(92_u64))?;

    let rendered = format!("{state:?}");

    assert!(rendered.contains("PqInitiatorState"));
    assert!(rendered.contains("<redacted>"));
    Ok(())
}

#[test]
fn test_093_pq_handshake_request_json_round_trip_offer() -> AnyResult<()> {
    let mut manager = build_default_pq_manager();
    let (_state, request) = build_outbound_pq_offer(&mut manager, nonce_from_seed(93_u64))?;

    let encoded = serde_json::to_string(&request)?;
    let decoded = serde_json::from_str::<PqHandshakeRequest>(&encoded)?;

    match (request, decoded) {
        (PqHandshakeRequest::Offer(left), PqHandshakeRequest::Offer(right)) => {
            assert_eq!(left, right);
        }
    }

    Ok(())
}

#[test]
fn test_094_pq_handshake_response_json_round_trip_accept() -> AnyResult<()> {
    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (_state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(94_u64))?;
    let (response, _session) = handle_inbound_pq_request(&mut responder_manager, request)?;

    let encoded = serde_json::to_string(&response)?;
    let decoded = serde_json::from_str::<PqHandshakeResponse>(&encoded)?;

    match (response, decoded) {
        (PqHandshakeResponse::Accept(left), PqHandshakeResponse::Accept(right)) => {
            assert_eq!(left, right);
        }
    }

    Ok(())
}

#[test]
fn test_095_version_codec_adversarial_unknown_services_wire_rejected() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;

    let info = version_info(
        1_u32,
        95_u64,
        Services::from_bits_retain(1_u32 << 29_u32),
        "remzar/wire-unknown-services",
        None,
    );

    let frame = version_frame_for(&info)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "unknown bits",
    )?;
    Ok(())
}

#[test]
fn test_096_version_codec_adversarial_protocol_zero_wire_rejected() -> AnyResult<()> {
    let mut codec = VersionCodec;
    let proto = VersionProto;

    let info = version_info(0_u32, 96_u64, Services::NODE, "remzar/wire-zero", None);
    let frame = version_frame_for(&info)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "protocol_version",
    )?;
    Ok(())
}

#[test]
fn test_097_pq_codec_adversarial_zero_length_request_body_rejected() -> AnyResult<()> {
    let mut codec = PqCodec;
    let proto = PqProto;
    let frame = encode_varint_u32(0_u32)?;
    let mut reader = Cursor::new(frame);

    assert_invalid_data(block_on(codec.read_request(&proto, &mut reader)), "")?;
    Ok(())
}

#[test]
fn test_098_pq_codec_adversarial_malformed_varint_rejected() -> AnyResult<()> {
    let mut codec = PqCodec;
    let proto = PqProto;

    // Six-byte continuation varint forces InvalidData instead of UnexpectedEof.
    let frame = vec![0x80_u8, 0x80_u8, 0x80_u8, 0x80_u8, 0x80_u8, 0x00_u8];
    let mut reader = Cursor::new(frame);

    assert_invalid_data(
        block_on(codec.read_request(&proto, &mut reader)),
        "varint length exceeds u32 prefix cap",
    )?;
    Ok(())
}

#[test]
fn test_099_load_16_combined_version_and_pq_paths_are_safe() -> AnyResult<()> {
    for seed in 99_u64..115_u64 {
        let version = version_info(
            1_u32,
            seed,
            Services::NODE | Services::VALIDATOR,
            "remzar/load-combined",
            Some(hash64_from_seed(seed)),
        );
        assert!(
            version
                .validate_untrusted_with_expectations(1_u32, Some(hash64_from_seed(seed)))
                .is_ok()
        );

        let mut initiator_manager = build_default_pq_manager();
        let mut responder_manager = build_default_pq_manager();

        let (mut state, request) =
            build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(seed))?;
        let (response, responder_session) =
            handle_inbound_pq_request(&mut responder_manager, request)?;
        let initiator_session =
            finalize_inbound_pq_response(&mut initiator_manager, &mut state, response)?;

        assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    }

    Ok(())
}

#[test]
fn test_100_combined_adversarial_codec_exchange_and_pq_path_is_safe() -> AnyResult<()> {
    let peer = generated_peer_id();

    let mut version_exchange = build_version_exchange();
    let version = version_info(
        1_u32,
        100_u64,
        Services::NODE | Services::MINER | Services::VALIDATOR,
        "remzar/final-combined",
        Some(hash64_from_seed(100_u64)),
    );
    let version_request_id = version_exchange.send_request(&peer, version.clone());
    assert!(!format!("{version_request_id:?}").is_empty());

    let mut version_codec = VersionCodec;
    let version_proto = VersionProto;
    let mut version_writer = Cursor::new(Vec::<u8>::new());
    block_on(version_codec.write_request(&version_proto, &mut version_writer, version.clone()))?;
    let mut version_reader = Cursor::new(version_writer.into_inner());
    let decoded_version =
        block_on(version_codec.read_request(&version_proto, &mut version_reader))?;
    assert_version_eq(&decoded_version, &version);

    let mut initiator_manager = build_default_pq_manager();
    let mut responder_manager = build_default_pq_manager();

    let (mut state, request) =
        build_outbound_pq_offer(&mut initiator_manager, nonce_from_seed(100_u64))?;

    let mut pq_exchange = build_pq_exchange();
    let pq_request_id = pq_exchange.send_request(&peer, request.clone());
    assert!(!format!("{pq_request_id:?}").is_empty());

    let mut pq_codec = PqCodec;
    let pq_proto = PqProto;
    let mut pq_writer = Cursor::new(Vec::<u8>::new());
    block_on(pq_codec.write_request(&pq_proto, &mut pq_writer, request.clone()))?;
    let mut pq_reader = Cursor::new(pq_writer.into_inner());
    let decoded_request = block_on(pq_codec.read_request(&pq_proto, &mut pq_reader))?;

    let (response, responder_session) =
        handle_inbound_pq_request(&mut responder_manager, decoded_request)?;
    let initiator_session =
        finalize_inbound_pq_response(&mut initiator_manager, &mut state, response)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    Ok(())
}

#[test]
fn user_agent_for_log_does_not_panic_on_utf8_boundary() {
    let info = VersionInfo {
        protocol_version: 1,
        chain_height: 0,
        services: Services::NODE,
        user_agent: "🚀".repeat(100),
        genesis_hash: None,
    };

    let logged = info.user_agent_for_log();

    assert!(logged.ends_with('…'));
    assert!(logged.len() <= MAX_USER_AGENT_LOG_BYTES);
    assert!(logged.is_char_boundary(logged.len()));
}

#[test]
fn user_agent_for_log_keeps_short_value_unchanged() {
    let info = VersionInfo {
        protocol_version: 1,
        chain_height: 0,
        services: Services::NODE,
        user_agent: "remzar/1.0.0".to_string(),
        genesis_hash: None,
    };

    assert_eq!(info.user_agent_for_log(), "remzar/1.0.0");
}
