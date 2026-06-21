use bitflags::bitflags;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    PeerId,
    request_response::{Behaviour, Codec, Config, Event, ProtocolSupport, ResponseChannel},
};
use postcard::{from_bytes, to_stdvec};
use std::{
    convert::TryFrom,
    future::Future,
    iter,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    time::Duration,
};

use crate::network::p2p_005_pq_fips203kem::{
    DEFAULT_MAX_MESSAGE_AGE_SECS, LocalPqKeypair, PQ_MAX_WIRE_BYTES, PQ_NONCE_LEN, PqKemAccept,
    PqKemManager, PqKemOffer, PqKemPolicy, PqResult, PqSessionKey,
};
use crate::storage::rocksdb_005_manager::RockDBManager;

/* ─────────────────────────────────────────────────────────────
Defensive wire caps / timing
───────────────────────────────────────────────────────────── */

/// Maximum allowed VERSION handshake payload size (bytes).
const VERSION_MAX_WIRE_BYTES: usize = 16 * 1024;

/// Maximum allowed PQ handshake payload size (bytes).
const PQ_HANDSHAKE_MAX_WIRE_BYTES: usize = PQ_MAX_WIRE_BYTES;

/// Version request timeout.
const VERSION_REQUEST_TIMEOUT_SECS: u64 = 5;

/// PQ request timeout.
const PQ_REQUEST_TIMEOUT_SECS: u64 = 10;

/// Maximum varint bytes accepted for a u32 length prefix.
const MAX_HANDSHAKE_VARINT_BYTES: usize = 5;

/// Maximum user_agent string length (bytes) we accept from peers.
const MAX_USER_AGENT_BYTES: usize = 256;

/// Defensive cap on protocol_version.
const MAX_PROTOCOL_VERSION: u32 = 1_000_000;

/// Defensive cap on user_agent bytes surfaced in logs.
const MAX_USER_AGENT_LOG_BYTES: usize = 128;

#[inline(always)]
fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

#[inline(always)]
fn invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

#[inline(always)]
fn is_safe_user_agent(s: &str) -> bool {
    !s.chars().any(|ch| ch.is_control())
}

/* ─────────────────────────────────────────────────────────────
Advertised service flags
───────────────────────────────────────────────────────────── */

bitflags! {
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Services: u32 {
        const NONE      = 0;
        const NODE      = 1 << 0;
        const MINER     = 1 << 1;
        const VALIDATOR = 1 << 2;
    }
}

/* ─────────────────────────────────────────────────────────────
Ser / de helper for Option<[u8;64]> ⇄ hex string
───────────────────────────────────────────────────────────── */

mod opt_hex64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match v {
            Some(arr) => s.serialize_some(&hex::encode(arr)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(d)?;

        match opt {
            Some(hexstr) => {
                match hexstr.len() {
                    64 | 128 => {}
                    _ => {
                        return Err(serde::de::Error::custom(
                            "expected 64-byte hex (128 chars) or legacy 32-byte hex (64 chars)",
                        ));
                    }
                }

                let bytes = hex::decode(&hexstr).map_err(serde::de::Error::custom)?;

                match bytes.len() {
                    64 => {
                        let mut arr = [0u8; 64];
                        arr.copy_from_slice(&bytes);
                        Ok(Some(arr))
                    }
                    32 => {
                        let mut arr = [0u8; 64];
                        arr[32..].copy_from_slice(&bytes);
                        Ok(Some(arr))
                    }
                    _ => Err(serde::de::Error::custom(
                        "expected 64-byte hex (or legacy 32-byte hex)",
                    )),
                }
            }
            None => Ok(None),
        }
    }
}

/* ─────────────────────────────────────────────────────────────
Version handshake payload
───────────────────────────────────────────────────────────── */

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionInfo {
    pub protocol_version: u32,
    pub chain_height: u64,
    pub services: Services,
    pub user_agent: String,
    #[serde(with = "opt_hex64")]
    pub genesis_hash: Option<[u8; 64]>,
}

impl VersionInfo {
    pub fn local_tip(
        protocol_version: u32,
        db: &RockDBManager,
        genesis_hash: Option<[u8; 64]>,
    ) -> Self {
        Self {
            protocol_version,
            chain_height: db.get_latest_block_index().unwrap_or(0),
            services: Services::NODE,
            user_agent: format!("remzar/{}", env!("CARGO_PKG_VERSION")),
            genesis_hash,
        }
    }

    pub fn validate_untrusted(&self) -> std::io::Result<()> {
        if self.user_agent.len() > MAX_USER_AGENT_BYTES {
            return Err(invalid_data(format!(
                "user_agent too large: {} bytes (max {})",
                self.user_agent.len(),
                MAX_USER_AGENT_BYTES
            )));
        }

        if !is_safe_user_agent(&self.user_agent) {
            return Err(invalid_data("user_agent contains control characters"));
        }

        if self.protocol_version == 0 || self.protocol_version > MAX_PROTOCOL_VERSION {
            return Err(invalid_data(format!(
                "protocol_version out of range: {} (allowed 1..={})",
                self.protocol_version, MAX_PROTOCOL_VERSION
            )));
        }

        let raw = self.services.bits();
        let known = Services::all().bits();

        if raw & !known != 0 {
            return Err(invalid_data(format!(
                "services contains unknown bits: 0x{:08x}",
                raw & !known
            )));
        }

        Ok(())
    }

    pub fn validate_untrusted_with_expectations(
        &self,
        expected_protocol_version: u32,
        expected_genesis_hash: Option<[u8; 64]>,
    ) -> std::io::Result<()> {
        self.validate_untrusted()?;

        if expected_protocol_version != 0 && self.protocol_version != expected_protocol_version {
            return Err(invalid_data(format!(
                "protocol_version mismatch: got {}, expected {}",
                self.protocol_version, expected_protocol_version
            )));
        }

        if let Some(expected) = expected_genesis_hash {
            match self.genesis_hash {
                Some(got) if got == expected => {}
                Some(_) => {
                    return Err(invalid_data("genesis_hash mismatch"));
                }
                None => {
                    return Err(invalid_data("missing genesis_hash"));
                }
            }
        }

        Ok(())
    }

    pub fn user_agent_for_log(&self) -> String {
        if self.user_agent.len() <= MAX_USER_AGENT_LOG_BYTES {
            return self.user_agent.clone();
        }

        let ellipsis = '…';
        let ellipsis_len = ellipsis.len_utf8();

        let max_body_bytes = MAX_USER_AGENT_LOG_BYTES.saturating_sub(ellipsis_len);

        let mut out = String::new();

        for ch in self.user_agent.chars() {
            let next_len = out.len().saturating_add(ch.len_utf8());

            if next_len > max_body_bytes {
                break;
            }

            out.push(ch);
        }

        out.push(ellipsis);
        out
    }
}

/* ─────────────────────────────────────────────────────────────
PQ handshake payloads
───────────────────────────────────────────────────────────── */

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PqHandshakeRequest {
    Offer(PqKemOffer),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PqHandshakeResponse {
    Accept(PqKemAccept),
}

#[inline]
fn validate_pq_handshake_request(req: &PqHandshakeRequest) -> std::io::Result<()> {
    match req {
        PqHandshakeRequest::Offer(offer) => offer
            .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
            .map_err(std::io::Error::from),
    }
}

#[inline]
fn validate_pq_handshake_response(rsp: &PqHandshakeResponse) -> std::io::Result<()> {
    match rsp {
        PqHandshakeResponse::Accept(accept) => {
            // Full Accept validation requires the expected offer nonce.
            if accept.offer_nonce.len() != PQ_NONCE_LEN {
                return Err(invalid_data(format!(
                    "invalid PQ accept nonce length: {} (expected {})",
                    accept.offer_nonce.len(),
                    PQ_NONCE_LEN
                )));
            }

            if accept.created_at_unix_secs == 0 {
                return Err(invalid_data(
                    "invalid PQ accept timestamp: created_at_unix_secs must be nonzero",
                ));
            }

            if accept.ct.is_empty() {
                return Err(invalid_data("invalid PQ accept ciphertext: empty ct"));
            }

            if accept.ct.len() > PQ_HANDSHAKE_MAX_WIRE_BYTES {
                return Err(invalid_data(format!(
                    "invalid PQ accept ciphertext: {} bytes exceeds cap {}",
                    accept.ct.len(),
                    PQ_HANDSHAKE_MAX_WIRE_BYTES
                )));
            }
        }
    }

    Ok(())
}

/* ─────────────────────────────────────────────────────────────
Version protocol + codec
───────────────────────────────────────────────────────────── */

#[derive(Clone, Debug, Default)]
pub struct VersionProto;

impl AsRef<str> for VersionProto {
    fn as_ref(&self) -> &str {
        "/remzar/version/1.0.0"
    }
}

#[derive(Clone, Default)]
pub struct VersionCodec;

impl Codec for VersionCodec {
    type Protocol = VersionProto;
    type Request = VersionInfo;
    type Response = VersionInfo;

    fn read_request<'a, 'b, 'c, 'd, R>(
        &'a mut self,
        _: &'b Self::Protocol,
        io: &'c mut R,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Request>> + Send + 'd>>
    where
        R: AsyncRead + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        Box::pin(async move {
            let v: VersionInfo = boxed_read_with_cap(io, VERSION_MAX_WIRE_BYTES).await?;
            v.validate_untrusted()?;
            Ok(v)
        })
    }

    fn read_response<'a, 'b, 'c, 'd, R>(
        &'a mut self,
        p: &'b Self::Protocol,
        io: &'c mut R,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send + 'd>>
    where
        R: AsyncRead + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        self.read_request(p, io)
    }

    fn write_request<'a, 'b, 'c, 'd, W>(
        &'a mut self,
        _: &'b Self::Protocol,
        io: &'c mut W,
        req: Self::Request,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'd>>
    where
        W: AsyncWrite + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        boxed_write_with_cap(io, req, VERSION_MAX_WIRE_BYTES)
    }

    fn write_response<'a, 'b, 'c, 'd, W>(
        &'a mut self,
        p: &'b Self::Protocol,
        io: &'c mut W,
        rsp: Self::Response,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'd>>
    where
        W: AsyncWrite + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        self.write_request(p, io, rsp)
    }
}

/* ─────────────────────────────────────────────────────────────
PQ protocol + codec
───────────────────────────────────────────────────────────── */

#[derive(Clone, Debug, Default)]
pub struct PqProto;

impl AsRef<str> for PqProto {
    fn as_ref(&self) -> &str {
        "/remzar/pq/ml-kem-768/1.0.0"
    }
}

#[derive(Clone, Default)]
pub struct PqCodec;

impl Codec for PqCodec {
    type Protocol = PqProto;
    type Request = PqHandshakeRequest;
    type Response = PqHandshakeResponse;

    fn read_request<'a, 'b, 'c, 'd, R>(
        &'a mut self,
        _: &'b Self::Protocol,
        io: &'c mut R,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Request>> + Send + 'd>>
    where
        R: AsyncRead + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        Box::pin(async move {
            let req: PqHandshakeRequest =
                boxed_read_with_cap(io, PQ_HANDSHAKE_MAX_WIRE_BYTES).await?;
            validate_pq_handshake_request(&req)?;
            Ok(req)
        })
    }

    fn read_response<'a, 'b, 'c, 'd, R>(
        &'a mut self,
        _: &'b Self::Protocol,
        io: &'c mut R,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send + 'd>>
    where
        R: AsyncRead + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        Box::pin(async move {
            let rsp: PqHandshakeResponse =
                boxed_read_with_cap(io, PQ_HANDSHAKE_MAX_WIRE_BYTES).await?;
            validate_pq_handshake_response(&rsp)?;
            Ok(rsp)
        })
    }

    fn write_request<'a, 'b, 'c, 'd, W>(
        &'a mut self,
        _: &'b Self::Protocol,
        io: &'c mut W,
        req: Self::Request,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'd>>
    where
        W: AsyncWrite + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        boxed_write_with_cap(io, req, PQ_HANDSHAKE_MAX_WIRE_BYTES)
    }

    fn write_response<'a, 'b, 'c, 'd, W>(
        &'a mut self,
        _: &'b Self::Protocol,
        io: &'c mut W,
        rsp: Self::Response,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'd>>
    where
        W: AsyncWrite + Unpin + Send + 'd,
        'a: 'd,
        'b: 'd,
        'c: 'd,
    {
        boxed_write_with_cap(io, rsp, PQ_HANDSHAKE_MAX_WIRE_BYTES)
    }
}

/* ─────────────────────────────────────────────────────────────
Behaviour constructors
───────────────────────────────────────────────────────────── */

pub type VersionExchange = Behaviour<VersionCodec>;
pub type PqExchange = Behaviour<PqCodec>;

pub fn build_version_exchange() -> VersionExchange {
    let cfg =
        Config::default().with_request_timeout(Duration::from_secs(VERSION_REQUEST_TIMEOUT_SECS));

    Behaviour::with_codec(
        VersionCodec,
        iter::once((VersionProto, ProtocolSupport::Full)),
        cfg,
    )
}

pub fn build_pq_exchange() -> PqExchange {
    let cfg = Config::default().with_request_timeout(Duration::from_secs(PQ_REQUEST_TIMEOUT_SECS));

    Behaviour::with_codec(PqCodec, iter::once((PqProto, ProtocolSupport::Full)), cfg)
}

/* ─────────────────────────────────────────────────────────────
Slim helper enums – easier RR event matching
───────────────────────────────────────────────────────────── */

#[derive(Debug)]
pub enum VEvent {
    InboundReq {
        peer: PeerId,
        info: VersionInfo,
        ch: ResponseChannel<VersionInfo>,
    },
    InboundResp {
        peer: PeerId,
        info: VersionInfo,
    },
}

pub fn match_version_event(ev: Event<VersionInfo, VersionInfo>) -> Option<VEvent> {
    use libp2p::request_response::Message::*;

    match ev {
        Event::Message { peer, message, .. } => match message {
            Request {
                request, channel, ..
            } => Some(VEvent::InboundReq {
                peer,
                info: request,
                ch: channel,
            }),
            Response { response, .. } => Some(VEvent::InboundResp {
                peer,
                info: response,
            }),
        },
        _ => None,
    }
}

#[derive(Debug)]
pub enum PqEvent {
    InboundReq {
        peer: PeerId,
        msg: PqHandshakeRequest,
        ch: ResponseChannel<PqHandshakeResponse>,
    },
    InboundResp {
        peer: PeerId,
        msg: PqHandshakeResponse,
    },
}

pub fn match_pq_event(ev: Event<PqHandshakeRequest, PqHandshakeResponse>) -> Option<PqEvent> {
    use libp2p::request_response::Message::*;

    match ev {
        Event::Message { peer, message, .. } => match message {
            Request {
                request, channel, ..
            } => Some(PqEvent::InboundReq {
                peer,
                msg: request,
                ch: channel,
            }),
            Response { response, .. } => Some(PqEvent::InboundResp {
                peer,
                msg: response,
            }),
        },
        _ => None,
    }
}

/* ─────────────────────────────────────────────────────────────
PQ orchestration helpers
───────────────────────────────────────────────────────────── */

/// Stateful initiator context.
/// Store this per peer while waiting for a PQ response.
#[derive(Debug)]
pub struct PqInitiatorState {
    pub local_keypair: LocalPqKeypair,
    pub offer_nonce: [u8; PQ_NONCE_LEN],
}

impl PqInitiatorState {
    pub fn new(local_keypair: LocalPqKeypair, offer_nonce: [u8; PQ_NONCE_LEN]) -> Self {
        Self {
            local_keypair,
            offer_nonce,
        }
    }
}

#[inline]
fn validate_offer_nonce_for_new_handshake(offer_nonce: &[u8; PQ_NONCE_LEN]) -> PqResult<()> {
    if offer_nonce.iter().all(|b| *b == 0) {
        return Err(
            crate::network::p2p_005_pq_fips203kem::PqKemError::InvalidRange {
                field: "offer_nonce",
                details: "must not be all zero",
            },
        );
    }

    Ok(())
}

/// Build a fresh initiator state and outbound PQ offer.
pub fn build_outbound_pq_offer(
    pq_mgr: &mut PqKemManager,
    offer_nonce: [u8; PQ_NONCE_LEN],
) -> PqResult<(PqInitiatorState, PqHandshakeRequest)> {
    validate_offer_nonce_for_new_handshake(&offer_nonce)?;

    let local_keypair = pq_mgr.build_local_keypair()?;
    let offer = pq_mgr.build_offer(&local_keypair, offer_nonce)?;
    let request = PqHandshakeRequest::Offer(offer);

    validate_pq_handshake_request(&request).map_err(|_| {
        crate::network::p2p_005_pq_fips203kem::PqKemError::InvalidMessage(
            "outbound PQ offer failed local validation",
        )
    })?;

    let state = PqInitiatorState::new(local_keypair, offer_nonce);

    Ok((state, request))
}

/// Responder helper for an inbound PQ offer.
pub fn handle_inbound_pq_request(
    pq_mgr: &mut PqKemManager,
    req: PqHandshakeRequest,
) -> PqResult<(PqHandshakeResponse, PqSessionKey)> {
    validate_pq_handshake_request(&req).map_err(|_| {
        crate::network::p2p_005_pq_fips203kem::PqKemError::InvalidMessage(
            "inbound PQ offer failed validation",
        )
    })?;

    match req {
        PqHandshakeRequest::Offer(offer) => {
            let (accept, session_key) = pq_mgr.accept_offer(&offer)?;
            let response = PqHandshakeResponse::Accept(accept);

            validate_pq_handshake_response(&response).map_err(|_| {
                crate::network::p2p_005_pq_fips203kem::PqKemError::InvalidMessage(
                    "outbound PQ accept failed local validation",
                )
            })?;

            Ok((response, session_key))
        }
    }
}

/// Initiator finalization helper.
pub fn finalize_inbound_pq_response(
    pq_mgr: &mut PqKemManager,
    state: &mut PqInitiatorState,
    rsp: PqHandshakeResponse,
) -> PqResult<PqSessionKey> {
    validate_pq_handshake_response(&rsp).map_err(|_| {
        crate::network::p2p_005_pq_fips203kem::PqKemError::InvalidMessage(
            "inbound PQ accept failed validation",
        )
    })?;

    match rsp {
        PqHandshakeResponse::Accept(accept) => {
            pq_mgr.finalize_accept(&mut state.local_keypair, &accept, state.offer_nonce)
        }
    }
}

/// Convenience constructor for callers that want a default policy.
pub fn build_default_pq_manager() -> PqKemManager {
    PqKemManager::default()
}

/// Convenience constructor for callers that want a custom PQ policy.
pub fn build_pq_manager(policy: PqKemPolicy) -> PqKemManager {
    PqKemManager::new(policy)
}

/* ─────────────────────────────────────────────────────────────
Framing helpers – little-endian varint + postcard
───────────────────────────────────────────────────────────── */

fn boxed_read_with_cap<'d, M, T>(
    io: &'d mut T,
    max_wire_bytes: usize,
) -> Pin<Box<dyn Future<Output = std::io::Result<M>> + Send + 'd>>
where
    M: serde::de::DeserializeOwned + Send + 'd,
    T: AsyncRead + Unpin + Send + 'd,
{
    Box::pin(async move {
        if max_wire_bytes == 0 {
            return Err(invalid_input("max_wire_bytes must be nonzero"));
        }

        let len_u32 = read_varint_u32(io).await?;

        let len =
            usize::try_from(len_u32).map_err(|_| invalid_data("length conversion overflow"))?;

        if len == 0 {
            return Err(invalid_data("handshake payload is empty"));
        }

        if len > max_wire_bytes {
            return Err(invalid_data(format!(
                "handshake payload too large: {} bytes (max {})",
                len, max_wire_bytes
            )));
        }

        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;

        match catch_unwind(AssertUnwindSafe(|| from_bytes(&buf))) {
            Ok(Ok(msg)) => Ok(msg),
            Ok(Err(e)) => Err(invalid_data(e.to_string())),
            Err(_) => Err(invalid_data("handshake postcard decode panicked")),
        }
    })
}

fn boxed_write_with_cap<'d, M, T>(
    io: &'d mut T,
    msg: M,
    max_wire_bytes: usize,
) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'd>>
where
    M: serde::Serialize + Send + 'd,
    T: AsyncWrite + Unpin + Send + 'd,
{
    Box::pin(async move {
        if max_wire_bytes == 0 {
            return Err(invalid_input("max_wire_bytes must be nonzero"));
        }

        let data = match catch_unwind(AssertUnwindSafe(|| to_stdvec(&msg))) {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(invalid_data(e.to_string())),
            Err(_) => return Err(invalid_data("handshake postcard encode panicked")),
        };

        if data.is_empty() {
            return Err(invalid_data("handshake payload serialized to empty buffer"));
        }

        if data.len() > max_wire_bytes {
            return Err(invalid_data(format!(
                "handshake payload too large to send: {} bytes (max {})",
                data.len(),
                max_wire_bytes
            )));
        }

        let len_u32 =
            u32::try_from(data.len()).map_err(|_| invalid_data("length conversion overflow"))?;

        write_varint_u32(io, len_u32).await?;
        io.write_all(&data).await?;
        io.flush().await
    })
}

async fn read_varint_u32<R>(r: &mut R) -> std::io::Result<u32>
where
    R: AsyncRead + Unpin,
{
    let mut v = 0u32;
    let mut shift = 0u32;
    let mut b = [0u8; 1];

    for byte_index in 0..MAX_HANDSHAKE_VARINT_BYTES {
        r.read_exact(&mut b).await?;
        let byte = b[0];
        let low = byte & 0x7F;

        if shift == 28 && (low & 0x70) != 0 {
            return Err(invalid_data("varint value overflow"));
        }

        v |= u32::from(low) << shift;

        if byte & 0x80 == 0 {
            return Ok(v);
        }

        if byte_index == MAX_HANDSHAKE_VARINT_BYTES.saturating_sub(1) {
            return Err(invalid_data("varint length exceeds u32 prefix cap"));
        }

        shift = shift.saturating_add(7);
    }

    Err(invalid_data("varint length exceeds u32 prefix cap"))
}

async fn write_varint_u32<W>(w: &mut W, mut val: u32) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut b = [0u8; 1];

    loop {
        b[0] = (val & 0x7F) as u8;
        val >>= 7;

        if val == 0 {
            w.write_all(&b).await?;
            return Ok(());
        }

        b[0] |= 0x80;
        w.write_all(&b).await?;
    }
}
