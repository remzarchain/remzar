#![cfg(test)]
#![deny(unsafe_code)]

use futures::io::Cursor;
use libp2p::request_response::Codec;
use remzar::network::{
    p2p_005_pq_fips203kem::{
        PQ_KEM_SUITE_ID, PQ_MAX_WIRE_BYTES, PQ_NONCE_LEN, PqKemManager, PqKemOffer,
    },
    p2p_007_handshake::{
        PqCodec, PqHandshakeRequest, PqHandshakeResponse, PqInitiatorState, PqProto, Services,
        VersionCodec, VersionInfo, VersionProto, build_default_pq_manager, build_outbound_pq_offer,
        build_pq_exchange, build_pq_manager, build_version_exchange, finalize_inbound_pq_response,
        handle_inbound_pq_request,
    },
};
use std::{io::ErrorKind, time::Duration};
use tokio::time::timeout;

type TestResult<T = ()> = Result<T, String>;

const VERSION_MAX_WIRE_BYTES_FOR_TEST: usize = 16 * 1024;
const MAX_USER_AGENT_BYTES_FOR_TEST: usize = 256;
const MAX_PROTOCOL_VERSION_FOR_TEST: u32 = 1_000_000;

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn hash64(seed: u8) -> [u8; 64] {
    let mut out = [0u8; 64];

    for (idx, byte) in out.iter_mut().enumerate() {
        let i = u8::try_from(idx).unwrap_or(0);
        *byte = seed
            .wrapping_add(i.wrapping_mul(31))
            .wrapping_add(7)
            .rotate_left(u32::from(i % 7));
    }

    out
}

fn nonce(seed: u8) -> [u8; PQ_NONCE_LEN] {
    let mut out = [0u8; PQ_NONCE_LEN];

    for (idx, byte) in out.iter_mut().enumerate() {
        let i = u8::try_from(idx).unwrap_or(0);
        *byte = seed
            .wrapping_add(i.wrapping_mul(17))
            .wrapping_add(3)
            .rotate_left(u32::from(i % 5));
    }

    out
}

fn version_info(seed: u8) -> VersionInfo {
    VersionInfo {
        protocol_version: 1,
        chain_height: u64::from(seed) * 10,
        services: Services::NODE,
        user_agent: format!("remzar-e2e/{seed}"),
        genesis_hash: Some(hash64(seed)),
    }
}

fn version_info_no_genesis(seed: u8) -> VersionInfo {
    VersionInfo {
        protocol_version: 1,
        chain_height: u64::from(seed) * 10,
        services: Services::NODE,
        user_agent: format!("remzar-e2e/{seed}"),
        genesis_hash: None,
    }
}

fn encode_varint_u32_for_test(mut val: u32) -> Vec<u8> {
    let mut out = Vec::new();

    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;

        if val == 0 {
            out.push(byte);
            break;
        }

        byte |= 0x80;
        out.push(byte);
    }

    out
}

fn invalid_varint_too_long_for_test() -> Vec<u8> {
    vec![0x80, 0x80, 0x80, 0x80, 0x80]
}

fn wire_with_declared_payload(mut payload: Vec<u8>) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = encode_varint_u32_for_test(len);
    out.append(&mut payload);
    out
}

fn oversized_declared_wire(max: usize) -> TestResult<Vec<u8>> {
    let oversized = u32::try_from(max + 1).map_err(fmt_err)?;
    Ok(encode_varint_u32_for_test(oversized))
}

async fn write_version_request_wire(info: VersionInfo) -> std::io::Result<Vec<u8>> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let mut io = Cursor::new(Vec::<u8>::new());

    codec.write_request(&proto, &mut io, info).await?;

    Ok(io.into_inner())
}

async fn read_version_request_wire(bytes: Vec<u8>) -> std::io::Result<VersionInfo> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let mut io = Cursor::new(bytes);

    codec.read_request(&proto, &mut io).await
}

async fn write_version_response_wire(info: VersionInfo) -> std::io::Result<Vec<u8>> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let mut io = Cursor::new(Vec::<u8>::new());

    codec.write_response(&proto, &mut io, info).await?;

    Ok(io.into_inner())
}

async fn read_version_response_wire(bytes: Vec<u8>) -> std::io::Result<VersionInfo> {
    let mut codec = VersionCodec;
    let proto = VersionProto;
    let mut io = Cursor::new(bytes);

    codec.read_response(&proto, &mut io).await
}

async fn write_pq_request_wire(req: PqHandshakeRequest) -> std::io::Result<Vec<u8>> {
    let mut codec = PqCodec;
    let proto = PqProto;
    let mut io = Cursor::new(Vec::<u8>::new());

    codec.write_request(&proto, &mut io, req).await?;

    Ok(io.into_inner())
}

async fn read_pq_request_wire(bytes: Vec<u8>) -> std::io::Result<PqHandshakeRequest> {
    let mut codec = PqCodec;
    let proto = PqProto;
    let mut io = Cursor::new(bytes);

    codec.read_request(&proto, &mut io).await
}

async fn write_pq_response_wire(rsp: PqHandshakeResponse) -> std::io::Result<Vec<u8>> {
    let mut codec = PqCodec;
    let proto = PqProto;
    let mut io = Cursor::new(Vec::<u8>::new());

    codec.write_response(&proto, &mut io, rsp).await?;

    Ok(io.into_inner())
}

async fn read_pq_response_wire(bytes: Vec<u8>) -> std::io::Result<PqHandshakeResponse> {
    let mut codec = PqCodec;
    let proto = PqProto;
    let mut io = Cursor::new(bytes);

    codec.read_response(&proto, &mut io).await
}

fn assert_version_same(actual: &VersionInfo, expected: &VersionInfo) {
    assert_eq!(actual.protocol_version, expected.protocol_version);
    assert_eq!(actual.chain_height, expected.chain_height);
    assert_eq!(actual.services, expected.services);
    assert_eq!(actual.user_agent, expected.user_agent);
    assert_eq!(actual.genesis_hash, expected.genesis_hash);
}

#[test]
fn e2e_01_version_protocol_name_is_stable() -> TestResult {
    let proto = VersionProto;

    assert_eq!(proto.as_ref(), "/remzar/version/1.0.0");

    Ok(())
}

#[test]
fn e2e_02_pq_protocol_name_is_stable() -> TestResult {
    let proto = PqProto;

    assert_eq!(proto.as_ref(), "/remzar/pq/ml-kem-768/1.0.0");

    Ok(())
}

#[test]
fn e2e_03_services_flags_have_expected_bits() -> TestResult {
    assert_eq!(Services::NONE.bits(), 0);
    assert_eq!(Services::NODE.bits(), 1);
    assert_eq!(Services::MINER.bits(), 2);
    assert_eq!(Services::VALIDATOR.bits(), 4);

    Ok(())
}

#[test]
fn e2e_04_services_flags_can_be_combined() -> TestResult {
    let services = Services::NODE | Services::VALIDATOR;

    assert!(services.contains(Services::NODE));
    assert!(services.contains(Services::VALIDATOR));
    assert!(!services.contains(Services::MINER));
    assert_eq!(services.bits(), 5);

    Ok(())
}

#[test]
fn e2e_05_build_version_exchange_constructs_public_behaviour() -> TestResult {
    let _exchange = build_version_exchange();

    Ok(())
}

#[test]
fn e2e_06_build_pq_exchange_constructs_public_behaviour() -> TestResult {
    let _exchange = build_pq_exchange();

    Ok(())
}

#[test]
fn e2e_07_build_exchanges_repeatedly_without_panic() -> TestResult {
    for _ in 0usize..16usize {
        let _version = build_version_exchange();
        let _pq = build_pq_exchange();
    }

    Ok(())
}

#[test]
fn e2e_08_version_validate_accepts_valid_info() -> TestResult {
    let info = version_info(8);

    info.validate_untrusted().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_09_version_validate_accepts_combined_known_services() -> TestResult {
    let mut info = version_info(9);
    info.services = Services::NODE | Services::MINER | Services::VALIDATOR;

    info.validate_untrusted().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_10_version_validate_rejects_protocol_zero() -> TestResult {
    let mut info = version_info(10);
    info.protocol_version = 0;

    let err = info
        .validate_untrusted()
        .expect_err("protocol version zero must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("protocol_version out of range"));

    Ok(())
}

#[test]
fn e2e_11_version_validate_rejects_protocol_above_cap() -> TestResult {
    let mut info = version_info(11);
    info.protocol_version = MAX_PROTOCOL_VERSION_FOR_TEST + 1;

    let err = info
        .validate_untrusted()
        .expect_err("protocol version above cap must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("protocol_version out of range"));

    Ok(())
}

#[test]
fn e2e_12_version_validate_accepts_max_protocol_version() -> TestResult {
    let mut info = version_info(12);
    info.protocol_version = MAX_PROTOCOL_VERSION_FOR_TEST;

    info.validate_untrusted().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_13_version_validate_rejects_oversized_user_agent() -> TestResult {
    let mut info = version_info(13);
    info.user_agent = "a".repeat(MAX_USER_AGENT_BYTES_FOR_TEST + 1);

    let err = info
        .validate_untrusted()
        .expect_err("oversized user agent must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("user_agent too large"));

    Ok(())
}

#[test]
fn e2e_14_version_validate_accepts_max_user_agent() -> TestResult {
    let mut info = version_info(14);
    info.user_agent = "a".repeat(MAX_USER_AGENT_BYTES_FOR_TEST);

    info.validate_untrusted().map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_15_version_validate_rejects_unknown_service_bits() -> TestResult {
    let mut info = version_info(15);
    info.services = Services::from_bits_retain(1 << 31);

    let err = info
        .validate_untrusted()
        .expect_err("unknown service bits must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("services contains unknown bits"));

    Ok(())
}

#[test]
fn e2e_16_version_expectations_accept_matching_protocol_and_genesis() -> TestResult {
    let info = version_info(16);

    info.validate_untrusted_with_expectations(1, info.genesis_hash)
        .map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_17_version_expectations_protocol_zero_means_no_expected_version() -> TestResult {
    let info = version_info(17);

    info.validate_untrusted_with_expectations(0, info.genesis_hash)
        .map_err(fmt_err)?;

    Ok(())
}

#[test]
fn e2e_18_version_expectations_reject_protocol_mismatch() -> TestResult {
    let info = version_info(18);

    let err = info
        .validate_untrusted_with_expectations(999, info.genesis_hash)
        .expect_err("protocol mismatch must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("protocol_version mismatch"));

    Ok(())
}

#[test]
fn e2e_19_version_expectations_reject_missing_genesis() -> TestResult {
    let info = version_info_no_genesis(19);

    let err = info
        .validate_untrusted_with_expectations(1, Some(hash64(19)))
        .expect_err("missing genesis must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("missing genesis_hash"));

    Ok(())
}

#[test]
fn e2e_20_version_expectations_reject_genesis_mismatch() -> TestResult {
    let info = version_info(20);

    let err = info
        .validate_untrusted_with_expectations(1, Some(hash64(21)))
        .expect_err("genesis mismatch must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("genesis_hash mismatch"));

    Ok(())
}

#[test]
fn e2e_21_user_agent_for_log_leaves_short_agent_unchanged() -> TestResult {
    let info = version_info(21);

    assert_eq!(info.user_agent_for_log(), info.user_agent);

    Ok(())
}

#[test]
fn e2e_22_user_agent_for_log_truncates_long_ascii_agent() {
    let info = VersionInfo {
        protocol_version: 1,
        chain_height: 0,
        services: Services::NODE,
        user_agent: "a".repeat(512),
        genesis_hash: None,
    };

    let logged = info.user_agent_for_log();

    assert_eq!(logged.len(), 128);
    assert!(logged.ends_with('…'));
    assert_eq!(logged.chars().count(), 126);
}

#[tokio::test]
async fn e2e_23_version_codec_roundtrips_request() -> TestResult {
    let info = version_info(23);

    let wire = write_version_request_wire(info.clone())
        .await
        .map_err(fmt_err)?;
    let decoded = read_version_request_wire(wire).await.map_err(fmt_err)?;

    assert_version_same(&decoded, &info);

    Ok(())
}

#[tokio::test]
async fn e2e_24_version_codec_roundtrips_response() -> TestResult {
    let info = version_info(24);

    let wire = write_version_response_wire(info.clone())
        .await
        .map_err(fmt_err)?;
    let decoded = read_version_response_wire(wire).await.map_err(fmt_err)?;

    assert_version_same(&decoded, &info);

    Ok(())
}

#[tokio::test]
async fn e2e_25_version_codec_roundtrips_no_genesis() -> TestResult {
    let info = version_info_no_genesis(25);

    let wire = write_version_request_wire(info.clone())
        .await
        .map_err(fmt_err)?;
    let decoded = read_version_request_wire(wire).await.map_err(fmt_err)?;

    assert_version_same(&decoded, &info);

    Ok(())
}

#[tokio::test]
async fn e2e_26_version_codec_rejects_empty_wire() -> TestResult {
    let err = read_version_request_wire(Vec::new())
        .await
        .expect_err("empty wire must fail");

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

    Ok(())
}

#[tokio::test]
async fn e2e_27_version_codec_rejects_invalid_varint() -> TestResult {
    let err = read_version_request_wire(invalid_varint_too_long_for_test())
        .await
        .expect_err("invalid varint must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(
        err.to_string()
            .contains("varint length exceeds u32 prefix cap")
    );

    Ok(())
}

#[tokio::test]
async fn e2e_28_version_codec_rejects_oversized_declared_length() -> TestResult {
    let wire = oversized_declared_wire(VERSION_MAX_WIRE_BYTES_FOR_TEST)?;

    let err = read_version_request_wire(wire)
        .await
        .expect_err("oversized version wire must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("handshake payload too large"));

    Ok(())
}

#[tokio::test]
async fn e2e_29_version_codec_rejects_truncated_payload() -> TestResult {
    let mut wire = encode_varint_u32_for_test(20);
    wire.extend_from_slice(&[1, 2, 3]);

    let err = read_version_request_wire(wire)
        .await
        .expect_err("truncated version payload must fail");

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

    Ok(())
}

#[tokio::test]
async fn e2e_30_version_codec_rejects_malformed_postcard_payload() -> TestResult {
    let wire = wire_with_declared_payload(vec![0xff, 0xee, 0xdd, 0xcc]);

    let err = read_version_request_wire(wire)
        .await
        .expect_err("malformed version postcard must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_31_version_codec_rejects_invalid_decoded_user_agent() -> TestResult {
    let mut info = version_info(31);
    info.user_agent = "a".repeat(MAX_USER_AGENT_BYTES_FOR_TEST + 1);

    let payload = postcard::to_allocvec(&info).map_err(fmt_err)?;
    let wire = wire_with_declared_payload(payload);

    let err = read_version_request_wire(wire)
        .await
        .expect_err("oversized decoded user agent must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("user_agent too large"));

    Ok(())
}

#[tokio::test]
async fn e2e_32_version_codec_write_rejects_payload_over_wire_cap() -> TestResult {
    let mut info = version_info(32);
    info.user_agent = "a".repeat(VERSION_MAX_WIRE_BYTES_FOR_TEST + 1);

    let err = write_version_request_wire(info)
        .await
        .expect_err("oversized version write must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(
        err.to_string()
            .contains("handshake payload too large to send")
    );

    Ok(())
}

#[test]
fn e2e_33_default_pq_manager_builder_uses_default_policy() -> TestResult {
    let mgr = build_default_pq_manager();

    // The hardened FIPS203/PQ default message age is 120 seconds.
    assert_eq!(mgr.policy().max_message_age, Duration::from_secs(120));
    assert!(mgr.policy().require_single_use_local_keypair);

    Ok(())
}

#[test]
fn e2e_34_custom_pq_manager_builder_preserves_policy() -> TestResult {
    let policy = remzar::network::p2p_005_pq_fips203kem::PqKemPolicy {
        max_message_age: Duration::from_secs(9),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 7,
    };

    let mgr = build_pq_manager(policy.clone());

    assert_eq!(mgr.policy().max_message_age, policy.max_message_age);
    assert_eq!(
        mgr.policy().require_single_use_local_keypair,
        policy.require_single_use_local_keypair
    );
    assert_eq!(
        mgr.policy().replay_filter_capacity,
        policy.replay_filter_capacity
    );

    Ok(())
}

#[test]
fn e2e_35_build_outbound_pq_offer_returns_state_and_offer() -> TestResult {
    let mut mgr = PqKemManager::default();
    let n = nonce(35);

    let (state, req) = build_outbound_pq_offer(&mut mgr, n).map_err(fmt_err)?;

    assert_eq!(state.offer_nonce, n);
    assert!(!state.local_keypair.is_consumed());

    match req {
        PqHandshakeRequest::Offer(offer) => {
            assert_eq!(offer.suite_id, PQ_KEM_SUITE_ID);
            assert_eq!(offer.nonce, n.to_vec());
        }
    }

    Ok(())
}

#[test]
fn e2e_36_pq_initiator_state_new_preserves_keypair_and_nonce() -> TestResult {
    let keypair =
        remzar::network::p2p_005_pq_fips203kem::LocalPqKeypair::generate().map_err(fmt_err)?;
    let n = nonce(36);

    let state = PqInitiatorState::new(keypair, n);

    assert_eq!(state.offer_nonce, n);
    assert!(!state.local_keypair.is_consumed());

    Ok(())
}

#[test]
fn e2e_37_handle_inbound_pq_request_accepts_valid_offer() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let (_state, req) = build_outbound_pq_offer(&mut initiator, nonce(37)).map_err(fmt_err)?;
    let (rsp, session) = handle_inbound_pq_request(&mut responder, req).map_err(fmt_err)?;

    assert_eq!(session.as_bytes().len(), 32);

    match rsp {
        PqHandshakeResponse::Accept(accept) => {
            assert_eq!(accept.suite_id, PQ_KEM_SUITE_ID);
            assert_eq!(accept.offer_nonce.len(), PQ_NONCE_LEN);
        }
    }

    Ok(())
}

#[test]
fn e2e_38_full_pq_orchestration_establishes_matching_session_keys() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let (mut state, req) = build_outbound_pq_offer(&mut initiator, nonce(38)).map_err(fmt_err)?;

    let (rsp, responder_session) =
        handle_inbound_pq_request(&mut responder, req).map_err(fmt_err)?;

    let initiator_session =
        finalize_inbound_pq_response(&mut initiator, &mut state, rsp).map_err(fmt_err)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert!(state.local_keypair.is_consumed());

    Ok(())
}

#[test]
fn e2e_39_finalize_pq_response_fails_on_tampered_nonce_without_consuming_state() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let (mut state, req) = build_outbound_pq_offer(&mut initiator, nonce(39)).map_err(fmt_err)?;

    let (mut rsp, _responder_session) =
        handle_inbound_pq_request(&mut responder, req).map_err(fmt_err)?;

    match &mut rsp {
        PqHandshakeResponse::Accept(accept) => {
            accept.offer_nonce[0] ^= 0xff;
        }
    }

    let err = finalize_inbound_pq_response(&mut initiator, &mut state, rsp)
        .expect_err("tampered nonce must fail");

    assert!(format!("{err:?}").contains("offer_nonce mismatch"));
    assert!(!state.local_keypair.is_consumed());

    Ok(())
}

#[test]
fn e2e_40_finalize_pq_response_fails_on_short_nonce_without_consuming_state() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let (mut state, req) = build_outbound_pq_offer(&mut initiator, nonce(40)).map_err(fmt_err)?;

    let (mut rsp, _responder_session) =
        handle_inbound_pq_request(&mut responder, req).map_err(fmt_err)?;

    match &mut rsp {
        PqHandshakeResponse::Accept(accept) => {
            accept.offer_nonce.pop();
        }
    }

    let err = finalize_inbound_pq_response(&mut initiator, &mut state, rsp)
        .expect_err("short nonce must fail");

    assert!(format!("{err:?}").contains("inbound PQ accept failed validation"));
    assert!(!state.local_keypair.is_consumed());

    Ok(())
}

#[test]
fn e2e_41_handle_inbound_pq_request_rejects_replayed_offer() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let (_state, req) = build_outbound_pq_offer(&mut initiator, nonce(41)).map_err(fmt_err)?;

    let _first = handle_inbound_pq_request(&mut responder, req.clone()).map_err(fmt_err)?;

    let err = handle_inbound_pq_request(&mut responder, req).expect_err("replayed offer must fail");

    assert!(format!("{err:?}").contains("ReplayDetected"));

    Ok(())
}

#[tokio::test]
async fn e2e_42_pq_codec_roundtrips_offer_request() -> TestResult {
    let mut mgr = PqKemManager::default();
    let (_state, req) = build_outbound_pq_offer(&mut mgr, nonce(42)).map_err(fmt_err)?;

    let wire = write_pq_request_wire(req.clone()).await.map_err(fmt_err)?;
    let decoded = read_pq_request_wire(wire).await.map_err(fmt_err)?;

    match (req, decoded) {
        (PqHandshakeRequest::Offer(a), PqHandshakeRequest::Offer(b)) => {
            assert_eq!(a.suite_id, b.suite_id);
            assert_eq!(a.nonce, b.nonce);
            assert_eq!(a.ek, b.ek);
        }
    }

    Ok(())
}

#[tokio::test]
async fn e2e_43_pq_codec_roundtrips_accept_response() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let (_state, req) = build_outbound_pq_offer(&mut initiator, nonce(43)).map_err(fmt_err)?;
    let (rsp, _session) = handle_inbound_pq_request(&mut responder, req).map_err(fmt_err)?;

    let wire = write_pq_response_wire(rsp.clone()).await.map_err(fmt_err)?;
    let decoded = read_pq_response_wire(wire).await.map_err(fmt_err)?;

    match (rsp, decoded) {
        (PqHandshakeResponse::Accept(a), PqHandshakeResponse::Accept(b)) => {
            assert_eq!(a.suite_id, b.suite_id);
            assert_eq!(a.offer_nonce, b.offer_nonce);
            assert_eq!(a.ct, b.ct);
        }
    }

    Ok(())
}

#[tokio::test]
async fn e2e_44_pq_codec_rejects_empty_request_wire() -> TestResult {
    let err = read_pq_request_wire(Vec::new())
        .await
        .expect_err("empty PQ request wire must fail");

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);

    Ok(())
}

#[tokio::test]
async fn e2e_45_pq_codec_rejects_invalid_request_varint() -> TestResult {
    let err = read_pq_request_wire(invalid_varint_too_long_for_test())
        .await
        .expect_err("invalid varint must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(
        err.to_string()
            .contains("varint length exceeds u32 prefix cap")
    );

    Ok(())
}

#[tokio::test]
async fn e2e_46_pq_codec_rejects_oversized_declared_request_length() -> TestResult {
    let wire = oversized_declared_wire(PQ_MAX_WIRE_BYTES)?;

    let err = read_pq_request_wire(wire)
        .await
        .expect_err("oversized PQ request must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("handshake payload too large"));

    Ok(())
}

#[tokio::test]
async fn e2e_47_pq_codec_rejects_malformed_request_payload() -> TestResult {
    let wire = wire_with_declared_payload(vec![0xff, 0xee, 0xdd, 0xcc]);

    let err = read_pq_request_wire(wire)
        .await
        .expect_err("malformed PQ request must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    Ok(())
}

#[tokio::test]
async fn e2e_48_pq_codec_rejects_accept_response_with_short_nonce() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let (_state, req) = build_outbound_pq_offer(&mut initiator, nonce(48)).map_err(fmt_err)?;
    let (mut rsp, _session) = handle_inbound_pq_request(&mut responder, req).map_err(fmt_err)?;

    match &mut rsp {
        PqHandshakeResponse::Accept(accept) => {
            accept.offer_nonce.pop();
        }
    }

    let payload = postcard::to_allocvec(&rsp).map_err(fmt_err)?;
    let wire = wire_with_declared_payload(payload);

    let err = read_pq_response_wire(wire)
        .await
        .expect_err("short PQ accept nonce must fail");

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid PQ accept nonce length"));

    Ok(())
}

#[tokio::test]
async fn e2e_49_full_version_and_pq_codec_lifecycle_completes_before_timeout() -> TestResult {
    timeout(Duration::from_secs(2), async {
        let version = version_info(49);

        let version_wire = write_version_request_wire(version.clone())
            .await
            .map_err(fmt_err)?;
        let version_decoded = read_version_request_wire(version_wire)
            .await
            .map_err(fmt_err)?;

        assert_version_same(&version_decoded, &version);

        let mut initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let (mut state, pq_req) =
            build_outbound_pq_offer(&mut initiator, nonce(49)).map_err(fmt_err)?;

        let pq_req_wire = write_pq_request_wire(pq_req.clone())
            .await
            .map_err(fmt_err)?;
        let pq_req_decoded = read_pq_request_wire(pq_req_wire).await.map_err(fmt_err)?;

        let (pq_rsp, responder_session) =
            handle_inbound_pq_request(&mut responder, pq_req_decoded).map_err(fmt_err)?;

        let pq_rsp_wire = write_pq_response_wire(pq_rsp.clone())
            .await
            .map_err(fmt_err)?;
        let pq_rsp_decoded = read_pq_response_wire(pq_rsp_wire).await.map_err(fmt_err)?;

        let initiator_session =
            finalize_inbound_pq_response(&mut initiator, &mut state, pq_rsp_decoded)
                .map_err(fmt_err)?;

        assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());

        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "version + PQ handshake lifecycle timed out".to_string())??;

    Ok(())
}

#[tokio::test]
async fn e2e_50_full_handshake_edge_lifecycle_validation_wire_caps_and_pq_replay() -> TestResult {
    let valid_version = version_info(50);
    valid_version
        .validate_untrusted_with_expectations(1, valid_version.genesis_hash)
        .map_err(fmt_err)?;

    let version_wire = write_version_response_wire(valid_version.clone())
        .await
        .map_err(fmt_err)?;
    let version_decoded = read_version_response_wire(version_wire)
        .await
        .map_err(fmt_err)?;

    assert_version_same(&version_decoded, &valid_version);

    let mut bad_version = valid_version.clone();
    bad_version.user_agent = "a".repeat(MAX_USER_AGENT_BYTES_FOR_TEST + 1);

    let bad_payload = postcard::to_allocvec(&bad_version).map_err(fmt_err)?;
    let bad_wire = wire_with_declared_payload(bad_payload);

    let err = read_version_request_wire(bad_wire)
        .await
        .expect_err("bad version must fail validation");

    assert_eq!(err.kind(), ErrorKind::InvalidData);

    let mut initiator = build_default_pq_manager();
    let mut responder = build_default_pq_manager();

    let (mut state, pq_req) =
        build_outbound_pq_offer(&mut initiator, nonce(50)).map_err(fmt_err)?;

    let pq_req_wire = write_pq_request_wire(pq_req.clone())
        .await
        .map_err(fmt_err)?;
    let decoded_req = read_pq_request_wire(pq_req_wire).await.map_err(fmt_err)?;

    let (pq_rsp, responder_session) =
        handle_inbound_pq_request(&mut responder, decoded_req).map_err(fmt_err)?;

    let replay_err = handle_inbound_pq_request(&mut responder, pq_req)
        .expect_err("same PQ offer must replay-fail");

    assert!(format!("{replay_err:?}").contains("ReplayDetected"));

    let pq_rsp_wire = write_pq_response_wire(pq_rsp).await.map_err(fmt_err)?;
    let decoded_rsp = read_pq_response_wire(pq_rsp_wire).await.map_err(fmt_err)?;

    let initiator_session =
        finalize_inbound_pq_response(&mut initiator, &mut state, decoded_rsp).map_err(fmt_err)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert!(state.local_keypair.is_consumed());

    let mut oversized_offer = PqKemOffer {
        suite_id: PQ_KEM_SUITE_ID,
        nonce: nonce(100).to_vec(),
        ek: vec![0u8; PQ_MAX_WIRE_BYTES + 1],
        created_at_unix_secs: 1,
    };

    let oversized_req = PqHandshakeRequest::Offer(oversized_offer.clone());
    let write_err = write_pq_request_wire(oversized_req)
        .await
        .expect_err("oversized PQ request must fail write cap");

    assert_eq!(write_err.kind(), ErrorKind::InvalidData);

    oversized_offer.ek = vec![0u8; 1];
    let invalid_req = PqHandshakeRequest::Offer(oversized_offer);
    let payload = postcard::to_allocvec(&invalid_req).map_err(fmt_err)?;
    let wire = wire_with_declared_payload(payload);

    let read_err = read_pq_request_wire(wire)
        .await
        .expect_err("invalid PQ offer ek must fail read validation");

    assert_eq!(read_err.kind(), ErrorKind::InvalidData);

    Ok(())
}
