#![no_main]

use futures::executor::block_on;
use futures::io::Cursor;
use libfuzzer_sys::fuzz_target;
use libp2p::request_response::Codec;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod utility {
    pub mod time_policy {
        use std::time::{SystemTime, UNIX_EPOCH};

        pub struct TimePolicy;

        impl TimePolicy {
            #[inline]
            pub fn now_unix_secs_runtime() -> Result<u64, &'static str> {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock before UNIX_EPOCH")
                    .map(|d| d.as_secs())
            }
        }
    }
}

mod storage {
    pub mod rocksdb_005_manager {
        #[derive(Debug, Clone, Default)]
        pub struct RockDBManager;

        impl RockDBManager {
            #[inline]
            pub fn get_latest_block_index(&self) -> Result<u64, std::io::Error> {
                Ok(0)
            }
        }
    }
}

#[path = "../../src/network/p2p_005_pq_fips203kem.rs"]
pub mod p2p_005_pq_fips203kem;

mod network {
    pub use crate::p2p_005_pq_fips203kem;
}

/* ─────────────────────────────────────────────────────────────
   Pull in the real handshake module using #[path], not include!().
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/network/p2p_007_handshake.rs"]
pub mod p2p_007_handshake;

/* ─────────────────────────────────────────────────────────────
   Imports from local modules, NOT remzar::...
   ───────────────────────────────────────────────────────────── */

use crate::p2p_005_pq_fips203kem::{
    MAX_ALLOWED_MESSAGE_AGE_SECS, PQ_NONCE_LEN, PqKemError, PqKemPolicy,
};

use crate::p2p_007_handshake::{
    build_default_pq_manager, build_outbound_pq_offer, build_pq_manager,
    finalize_inbound_pq_response, handle_inbound_pq_request, PqCodec, PqProto,
    Services, VersionCodec, VersionInfo, VersionProto,
};

const MAX_SYNTH_USER_AGENT_CHARS: usize = 384;

/* ─────────────────────────────────────────────────────────────
   Main fuzz entry
   ───────────────────────────────────────────────────────────── */

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] % 9;
    let body = &data[1..];

    match mode {
        0 => fuzz_version_codec_read_request(body),
        1 => fuzz_version_codec_read_response(body),
        2 => fuzz_version_valid_roundtrip(body),
        3 => fuzz_version_validation_and_log(body),
        4 => fuzz_pq_codec_read_request(body),
        5 => fuzz_pq_codec_read_response(body),
        6 => fuzz_pq_valid_memory_handshake(body),
        7 => fuzz_pq_policy_and_nonce_guards(body),
        _ => fuzz_mixed_sequence(body),
    }
});

/* ─────────────────────────────────────────────────────────────
   Error touching helpers
   ───────────────────────────────────────────────────────────── */

fn touch_pq_error(err: &PqKemError) {
    let _ = err.to_string();

    let io_err: std::io::Error = err.clone().into();
    let _ = io_err.kind();
    let _ = io_err.to_string();
}

fn touch_pq_result<T>(result: Result<T, PqKemError>) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            touch_pq_error(&e);
            None
        }
    }
}

fn now_unix_secs_fuzz() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(946_684_800)
}

/* ─────────────────────────────────────────────────────────────
   Version codec fuzzing
   ───────────────────────────────────────────────────────────── */

fn fuzz_version_codec_read_request(data: &[u8]) {
    let mut codec = VersionCodec::default();
    let proto = VersionProto::default();
    let mut io = Cursor::new(data.to_vec());

    let _ = block_on(codec.read_request(&proto, &mut io));
}

fn fuzz_version_codec_read_response(data: &[u8]) {
    let mut codec = VersionCodec::default();
    let proto = VersionProto::default();
    let mut io = Cursor::new(data.to_vec());

    let _ = block_on(codec.read_response(&proto, &mut io));
}

fn fuzz_version_valid_roundtrip(data: &[u8]) {
    let info = make_valid_version_info(data);

    let mut codec = VersionCodec::default();
    let proto = VersionProto::default();

    let mut out = Cursor::new(Vec::<u8>::new());

    let write_result = block_on(codec.write_request(&proto, &mut out, info.clone()));
    if write_result.is_err() {
        return;
    }

    let wire = out.into_inner();
    let mut input = Cursor::new(wire);

    let decoded = match block_on(codec.read_request(&proto, &mut input)) {
        Ok(v) => v,
        Err(_) => return,
    };

    assert_eq!(decoded.protocol_version, info.protocol_version);
    assert_eq!(decoded.chain_height, info.chain_height);
    assert_eq!(decoded.services.bits(), info.services.bits());
    assert_eq!(decoded.user_agent, info.user_agent);
    assert_eq!(decoded.genesis_hash, info.genesis_hash);

    assert!(decoded.validate_untrusted().is_ok());
}

fn fuzz_version_validation_and_log(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let protocol_version = r.next_u32();
    let chain_height = r.next_u64();
    let service_bits = r.next_u32();
    let user_agent = make_fuzzy_user_agent(&mut r);
    let genesis_hash = make_optional_genesis_hash(&mut r);

    let info = VersionInfo {
        protocol_version,
        chain_height,
        services: Services::from_bits_retain(service_bits),
        user_agent,
        genesis_hash,
    };

    let validation = info.validate_untrusted();

    let expected_protocol = match r.next_u8() % 4 {
        0 => 0,
        1 => protocol_version,
        2 => protocol_version.wrapping_add(1),
        _ => 1,
    };

    let expected_genesis = match r.next_u8() % 4 {
        0 => None,
        1 => info.genesis_hash,
        2 => Some(make_hash64_from_reader(&mut r)),
        _ => Some([0x42u8; 64]),
    };

    let _ = info.validate_untrusted_with_expectations(
        expected_protocol,
        expected_genesis,
    );

    if validation.is_ok() {
        /*
            This is intentionally included.

            If user_agent_for_log() truncates a Rust String at a non-UTF-8
            char boundary, it can panic. That is a real network-input crash.
        */
        let logged = info.user_agent_for_log();

        assert!(!logged.is_empty() || info.user_agent.is_empty());
        assert!(logged.len() <= info.user_agent.len().saturating_add("…".len()));
    }
}

/* ─────────────────────────────────────────────────────────────
   PQ codec fuzzing
   ───────────────────────────────────────────────────────────── */

fn fuzz_pq_codec_read_request(data: &[u8]) {
    let mut codec = PqCodec::default();
    let proto = PqProto::default();
    let mut io = Cursor::new(data.to_vec());

    let _ = block_on(codec.read_request(&proto, &mut io));
}

fn fuzz_pq_codec_read_response(data: &[u8]) {
    let mut codec = PqCodec::default();
    let proto = PqProto::default();
    let mut io = Cursor::new(data.to_vec());

    let _ = block_on(codec.read_response(&proto, &mut io));
}

/* ─────────────────────────────────────────────────────────────
   Full valid memory-only PQ handshake path
   ───────────────────────────────────────────────────────────── */

fn fuzz_pq_valid_memory_handshake(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let mut nonce = make_nonce(&mut r);
    force_nonce_nonzero(&mut nonce);

    let mut initiator_mgr = build_default_pq_manager();
    let mut responder_mgr = build_default_pq_manager();

    let Some((mut initiator_state, outbound_req)) =
        touch_pq_result(build_outbound_pq_offer(&mut initiator_mgr, nonce))
    else {
        return;
    };

    let mut pq_codec = PqCodec::default();
    let pq_proto = PqProto::default();

    /*
        Encode/decode the PQ offer through memory only.
        No socket, no swarm, no RocksDB.
    */
    let mut req_wire_out = Cursor::new(Vec::<u8>::new());

    if block_on(pq_codec.write_request(
        &pq_proto,
        &mut req_wire_out,
        outbound_req.clone(),
    ))
    .is_err()
    {
        return;
    }

    let mut req_wire_in = Cursor::new(req_wire_out.into_inner());

    let decoded_req = match block_on(pq_codec.read_request(&pq_proto, &mut req_wire_in)) {
        Ok(v) => v,
        Err(_) => return,
    };

    let Some((outbound_rsp, responder_session)) =
        touch_pq_result(handle_inbound_pq_request(&mut responder_mgr, decoded_req.clone()))
    else {
        return;
    };

    /*
        Replay invariant:
        The same offer nonce must not be accepted twice by the same responder manager.
    */
    let replay_result = handle_inbound_pq_request(&mut responder_mgr, decoded_req);

    assert!(
        replay_result.is_err(),
        "BUG: PQ responder accepted the same offer nonce twice"
    );

    /*
        Encode/decode the PQ accept through memory only.
    */
    let mut rsp_wire_out = Cursor::new(Vec::<u8>::new());

    if block_on(pq_codec.write_response(
        &pq_proto,
        &mut rsp_wire_out,
        outbound_rsp.clone(),
    ))
    .is_err()
    {
        return;
    }

    let mut rsp_wire_in = Cursor::new(rsp_wire_out.into_inner());

    let decoded_rsp = match block_on(pq_codec.read_response(&pq_proto, &mut rsp_wire_in)) {
        Ok(v) => v,
        Err(_) => return,
    };

    let Some(initiator_session) = touch_pq_result(finalize_inbound_pq_response(
        &mut initiator_mgr,
        &mut initiator_state,
        decoded_rsp.clone(),
    )) else {
        return;
    };

    /*
        Main KEM invariant:
        Initiator and responder derive the same shared secret.
    */
    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert_eq!(initiator_session.suite_id(), responder_session.suite_id());

    /*
        Single-use invariant:
        Initiator must not finalize the same accept twice.
    */
    let second_finalize = finalize_inbound_pq_response(
        &mut initiator_mgr,
        &mut initiator_state,
        decoded_rsp,
    );

    assert!(
        second_finalize.is_err(),
        "BUG: PQ initiator finalized the same accept twice"
    );
}

/* ─────────────────────────────────────────────────────────────
   PQ policy and nonce guard fuzzing
   ───────────────────────────────────────────────────────────── */

fn fuzz_pq_policy_and_nonce_guards(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let max_age_secs = match r.next_u8() % 7 {
        0 => 0,
        1 => 1,
        2 => 120,
        3 => MAX_ALLOWED_MESSAGE_AGE_SECS,
        4 => MAX_ALLOWED_MESSAGE_AGE_SECS.saturating_add(1),
        5 => r.next_u64() % MAX_ALLOWED_MESSAGE_AGE_SECS.max(1),
        _ => 1 + (r.next_u64() % MAX_ALLOWED_MESSAGE_AGE_SECS.max(1)),
    };

    let replay_filter_capacity = match r.next_u8() % 6 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 8,
        4 => 4096,
        _ => (r.next_u64() as usize % 128).saturating_add(1),
    };

    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(max_age_secs),
        require_single_use_local_keypair: r.next_bool(),
        replay_filter_capacity,
    };

    let mut pq_mgr = build_pq_manager(policy);

    let nonce = make_nonce(&mut r);
    let all_zero_nonce = nonce.iter().all(|b| *b == 0);

    let result = build_outbound_pq_offer(&mut pq_mgr, nonce);

    let invalid_age =
        max_age_secs == 0 || max_age_secs > MAX_ALLOWED_MESSAGE_AGE_SECS;

    let invalid_replay_capacity = replay_filter_capacity == 0;

    if all_zero_nonce || invalid_age || invalid_replay_capacity {
        assert!(
            result.is_err(),
            "BUG: invalid PQ policy or all-zero nonce unexpectedly succeeded"
        );
    }
}

/* ─────────────────────────────────────────────────────────────
   Mixed sequence fuzzing
   ───────────────────────────────────────────────────────────── */

fn fuzz_mixed_sequence(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let steps = 1 + r.next_usize(16);

    for _ in 0..steps {
        match r.next_u8() % 8 {
            0 => fuzz_version_codec_read_request(r.remaining_window(256)),
            1 => fuzz_version_codec_read_response(r.remaining_window(256)),
            2 => fuzz_version_valid_roundtrip(r.remaining_window(256)),
            3 => fuzz_version_validation_and_log(r.remaining_window(256)),
            4 => fuzz_pq_codec_read_request(r.remaining_window(512)),
            5 => fuzz_pq_codec_read_response(r.remaining_window(512)),
            6 => fuzz_pq_policy_and_nonce_guards(r.remaining_window(256)),
            _ => {
                let _ = now_unix_secs_fuzz();
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   VersionInfo constructors
   ───────────────────────────────────────────────────────────── */

fn make_valid_version_info(data: &[u8]) -> VersionInfo {
    let mut r = FuzzBytes::new(data);

    let protocol_version = 1 + (r.next_u32() % 1_000_000);
    let chain_height = r.next_u64();

    let known_service_bits =
        Services::NODE.bits() | Services::MINER.bits() | Services::VALIDATOR.bits();

    let service_bits = r.next_u32() & known_service_bits;

    let mut user_agent = String::from("remzar-fuzz/");

    let suffix_len = r.next_usize(64);
    for _ in 0..suffix_len {
        let b = r.next_u8();

        let c = match b % 36 {
            n @ 0..=9 => char::from(b'0' + n),
            n => char::from(b'a' + (n - 10)),
        };

        user_agent.push(c);
    }

    VersionInfo {
        protocol_version,
        chain_height,
        services: Services::from_bits_truncate(service_bits),
        user_agent,
        genesis_hash: make_optional_genesis_hash(&mut r),
    }
}

fn make_fuzzy_user_agent(r: &mut FuzzBytes<'_>) -> String {
    let char_count = r.next_usize(MAX_SYNTH_USER_AGENT_CHARS);

    let mut s = String::new();

    for _ in 0..char_count {
        let b = r.next_u8();

        match b % 8 {
            0 => s.push(char::from(b'a' + (b % 26))),
            1 => s.push(char::from(b'0' + (b % 10))),
            2 => s.push('/'),
            3 => s.push('-'),
            4 => s.push('_'),
            5 => s.push('é'),
            6 => s.push('雪'),
            _ => s.push('🚀'),
        }
    }

    s
}

fn make_optional_genesis_hash(r: &mut FuzzBytes<'_>) -> Option<[u8; 64]> {
    match r.next_u8() % 3 {
        0 => None,
        _ => Some(make_hash64_from_reader(r)),
    }
}

fn make_hash64_from_reader(r: &mut FuzzBytes<'_>) -> [u8; 64] {
    let mut out = [0u8; 64];

    for b in &mut out {
        *b = r.next_u8();
    }

    out
}

/* ─────────────────────────────────────────────────────────────
   PQ helpers
   ───────────────────────────────────────────────────────────── */

fn make_nonce(r: &mut FuzzBytes<'_>) -> [u8; PQ_NONCE_LEN] {
    let mut nonce = [0u8; PQ_NONCE_LEN];

    for b in &mut nonce {
        *b = r.next_u8();
    }

    nonce
}

fn force_nonce_nonzero(nonce: &mut [u8; PQ_NONCE_LEN]) {
    if nonce.iter().all(|b| *b == 0) {
        nonce[0] = 1;
    }
}

/* ─────────────────────────────────────────────────────────────
   Deterministic byte reader
   ───────────────────────────────────────────────────────────── */

struct FuzzBytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FuzzBytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }

        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];

        for b in &mut out {
            *b = self.next_u8();
        }

        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];

        for b in &mut out {
            *b = self.next_u8();
        }

        u64::from_le_bytes(out)
    }

    fn next_usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }

        (self.next_u64() as usize) % max_exclusive
    }

    fn remaining_window(&mut self, max_len: usize) -> &'a [u8] {
        if self.data.is_empty() || max_len == 0 {
            return &[];
        }

        let start = self.pos % self.data.len();
        let available = self.data.len().saturating_sub(start);
        let len = available.min(max_len);

        self.pos = self.pos.wrapping_add(len.max(1));

        &self.data[start..start + len]
    }
}