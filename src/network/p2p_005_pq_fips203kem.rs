//! src/network/p2p_005_pq_fips203kem.rs

use core::fmt;
use std::collections::{HashSet, VecDeque};
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use crate::utility::time_policy::TimePolicy;
use fips203::ml_kem_768::{CT_LEN, CipherText, DK_LEN, DecapsKey, EK_LEN, EncapsKey, KG};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use serde::{Deserialize, Serialize};

pub const PQ_SHARED_SECRET_LEN: usize = 32;
pub const PQ_MAX_WIRE_BYTES: usize = 16 * 1024;

/// Replay filter defaults and hard caps. These are local resource limits only.
pub const DEFAULT_REPLAY_FILTER_CAPACITY: usize = 4096;
pub const MIN_REPLAY_FILTER_CAPACITY: usize = 16;
pub const MAX_REPLAY_FILTER_CAPACITY: usize = 65_536;

/// Default validity window for PQ offer/accept messages.
pub const DEFAULT_MAX_MESSAGE_AGE_SECS: u64 = 120;

/// Maximum allowed future skew for PQ messages.
pub const MAX_FUTURE_SKEW_SECS: u64 = 10;

/// Hard upper bound for configured PQ message age.
pub const MAX_ALLOWED_MESSAGE_AGE_SECS: u64 = 10 * 60;

pub const PQ_NONCE_LEN: usize = 32;

pub const PQ_KEM_SUITE_ID: u16 = 0x0301;
pub const PQ_KEM_SUITE_NAME: &str = "ML-KEM-768/FIPS203-0.4.3";

pub type PqResult<T> = Result<T, PqKemError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqKemError {
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidRange {
        field: &'static str,
        details: &'static str,
    },
    InvalidState(&'static str),
    InvalidMessage(&'static str),
    Expired {
        field: &'static str,
        age_secs: u64,
        max_age_secs: u64,
    },
    ClockSkew {
        field: &'static str,
        now_unix_secs: u64,
        created_at_unix_secs: u64,
        skew_secs: u64,
        max_future_skew_secs: u64,
    },
    ReplayDetected {
        nonce_hex: String,
    },
    Crypto(&'static str),
    Io(String),
}

impl fmt::Display for PqKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "invalid length for {}: expected {} bytes, got {} bytes",
                field, expected, actual
            ),
            Self::InvalidRange { field, details } => {
                write!(f, "invalid range for {}: {}", field, details)
            }
            Self::InvalidState(msg) => write!(f, "invalid state: {}", msg),
            Self::InvalidMessage(msg) => write!(f, "invalid message: {}", msg),
            Self::Expired {
                field,
                age_secs,
                max_age_secs,
            } => write!(
                f,
                "{} expired: age={}s exceeds max={}s",
                field, age_secs, max_age_secs
            ),
            Self::ClockSkew {
                field,
                now_unix_secs,
                created_at_unix_secs,
                skew_secs,
                max_future_skew_secs,
            } => write!(
                f,
                "{} timestamp is too far in the future: created_at={} now={} skew={}s exceeds max_future_skew={}s",
                field, created_at_unix_secs, now_unix_secs, skew_secs, max_future_skew_secs
            ),
            Self::ReplayDetected { nonce_hex } => {
                write!(f, "replay detected for nonce {}", nonce_hex)
            }
            Self::Crypto(msg) => write!(f, "crypto error: {}", msg),
            Self::Io(msg) => write!(f, "io error: {}", msg),
        }
    }
}

impl std::error::Error for PqKemError {}

impl From<PqKemError> for io::Error {
    fn from(value: PqKemError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, value.to_string())
    }
}

#[inline]
fn now_unix_secs() -> PqResult<u64> {
    TimePolicy::now_unix_secs_runtime().map_err(|_| {
        PqKemError::InvalidState("failed to derive runtime unix timestamp from TimePolicy")
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes.len().saturating_mul(2);
    let mut out = String::with_capacity(capacity);

    for b in bytes {
        let hi = usize::from(*b >> 4);
        let lo = usize::from(*b & 0x0f);

        out.push(char::from(*LUT.get(hi).unwrap_or(&b'0')));
        out.push(char::from(*LUT.get(lo).unwrap_or(&b'0')));
    }

    out
}

#[inline]
fn validate_exact_len(field: &'static str, got: usize, expected: usize) -> PqResult<()> {
    if got != expected {
        return Err(PqKemError::InvalidLength {
            field,
            expected,
            actual: got,
        });
    }

    Ok(())
}

#[inline]
fn validate_nonzero_u64(field: &'static str, value: u64) -> PqResult<()> {
    if value == 0 {
        return Err(PqKemError::InvalidRange {
            field,
            details: "must be nonzero",
        });
    }

    Ok(())
}

#[inline]
fn validate_not_all_zero(field: &'static str, bytes: &[u8]) -> PqResult<()> {
    if bytes.iter().all(|b| *b == 0) {
        return Err(PqKemError::InvalidRange {
            field,
            details: "must not be all zero",
        });
    }

    Ok(())
}

#[inline]
fn validate_nonce_bytes(field: &'static str, nonce: &[u8]) -> PqResult<()> {
    validate_exact_len(field, nonce.len(), PQ_NONCE_LEN)?;
    validate_not_all_zero(field, nonce)
}

#[inline]
fn validate_suite_id(suite_id: u16) -> PqResult<()> {
    if suite_id != PQ_KEM_SUITE_ID {
        return Err(PqKemError::InvalidMessage("unexpected PQ suite id"));
    }

    Ok(())
}

#[inline]
fn clamp_replay_capacity(cap: usize) -> usize {
    cap.clamp(MIN_REPLAY_FILTER_CAPACITY, MAX_REPLAY_FILTER_CAPACITY)
}

fn catch_crypto<T, F>(op: &'static str, f: F) -> PqResult<T>
where
    F: FnOnce() -> PqResult<T>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => Err(PqKemError::Crypto(op)),
    }
}

#[inline]
fn validate_max_age(max_age: Duration) -> PqResult<()> {
    let max_age_secs = max_age.as_secs();

    if max_age_secs == 0 {
        return Err(PqKemError::InvalidRange {
            field: "max_message_age",
            details: "must be nonzero",
        });
    }

    if max_age_secs > MAX_ALLOWED_MESSAGE_AGE_SECS {
        return Err(PqKemError::InvalidRange {
            field: "max_message_age",
            details: "exceeds MAX_ALLOWED_MESSAGE_AGE_SECS",
        });
    }

    Ok(())
}

/// Validate freshness of a PQ wire message.
fn validate_message_age(
    field: &'static str,
    created_at_unix_secs: u64,
    max_age: Duration,
) -> PqResult<()> {
    validate_nonzero_u64("created_at_unix_secs", created_at_unix_secs)?;
    validate_max_age(max_age)?;

    let now = now_unix_secs()?;

    if created_at_unix_secs > now {
        let skew_secs = created_at_unix_secs.abs_diff(now);

        if skew_secs > MAX_FUTURE_SKEW_SECS {
            return Err(PqKemError::ClockSkew {
                field,
                now_unix_secs: now,
                created_at_unix_secs,
                skew_secs,
                max_future_skew_secs: MAX_FUTURE_SKEW_SECS,
            });
        }

        // Small future skew is tolerated.
        return Ok(());
    }

    let age_secs = now.abs_diff(created_at_unix_secs);

    if age_secs > max_age.as_secs() {
        return Err(PqKemError::Expired {
            field,
            age_secs,
            max_age_secs: max_age.as_secs(),
        });
    }

    Ok(())
}

fn copy_into_array<const N: usize>(field: &'static str, src: &[u8]) -> PqResult<[u8; N]> {
    validate_exact_len(field, src.len(), N)?;

    let mut out = [0u8; N];
    out.copy_from_slice(src);

    Ok(out)
}

#[derive(Debug, Clone)]
pub struct ReplayFilter {
    seen: HashSet<[u8; PQ_NONCE_LEN]>,
    order: VecDeque<[u8; PQ_NONCE_LEN]>,
    cap: usize,
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_FILTER_CAPACITY)
    }
}

impl ReplayFilter {
    pub fn new(cap: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            cap: clamp_replay_capacity(cap),
        }
    }

    pub fn contains(&self, nonce: &[u8; PQ_NONCE_LEN]) -> bool {
        self.seen.contains(nonce)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn insert(&mut self, nonce: [u8; PQ_NONCE_LEN]) -> bool {
        if self.seen.contains(&nonce) {
            return false;
        }

        while self.seen.len() >= self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            } else {
                self.seen.clear();
                break;
            }
        }

        self.order.push_back(nonce);
        self.seen.insert(nonce)
    }

    pub fn check_and_insert(&mut self, nonce: [u8; PQ_NONCE_LEN]) -> PqResult<()> {
        validate_not_all_zero("nonce", &nonce)?;

        if self.contains(&nonce) {
            return Err(PqKemError::ReplayDetected {
                nonce_hex: hex_encode(&nonce),
            });
        }

        let _ = self.insert(nonce);
        Ok(())
    }

    pub fn clear(&mut self) {
        self.seen.clear();
        self.order.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqKemOffer {
    pub suite_id: u16,
    pub created_at_unix_secs: u64,
    pub nonce: Vec<u8>,
    pub ek: Vec<u8>,
}

impl PqKemOffer {
    pub fn validate_untrusted(&self, max_age: Duration) -> PqResult<()> {
        validate_suite_id(self.suite_id)?;
        validate_message_age("PqKemOffer", self.created_at_unix_secs, max_age)?;
        validate_nonce_bytes("nonce", &self.nonce)?;
        validate_exact_len("ek", self.ek.len(), EK_LEN)?;
        validate_not_all_zero("ek", &self.ek)?;

        let ek_arr = copy_into_array::<EK_LEN>("ek", &self.ek)?;
        let _parsed = catch_crypto("EncapsKey::try_from_bytes panicked", || {
            EncapsKey::try_from_bytes(ek_arr).map_err(PqKemError::Crypto)
        })?;

        Ok(())
    }

    pub fn nonce_array(&self) -> PqResult<[u8; PQ_NONCE_LEN]> {
        validate_nonce_bytes("nonce", &self.nonce)?;
        copy_into_array::<PQ_NONCE_LEN>("nonce", &self.nonce)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqKemAccept {
    pub suite_id: u16,
    pub offer_nonce: Vec<u8>,
    pub created_at_unix_secs: u64,
    pub ct: Vec<u8>,
}

impl PqKemAccept {
    pub fn validate_untrusted(
        &self,
        expected_offer_nonce: &[u8; PQ_NONCE_LEN],
        max_age: Duration,
    ) -> PqResult<()> {
        validate_suite_id(self.suite_id)?;
        validate_message_age("PqKemAccept", self.created_at_unix_secs, max_age)?;
        validate_nonce_bytes("offer_nonce", &self.offer_nonce)?;
        validate_not_all_zero("expected_offer_nonce", expected_offer_nonce)?;
        validate_exact_len("ct", self.ct.len(), CT_LEN)?;
        validate_not_all_zero("ct", &self.ct)?;

        if self.offer_nonce.as_slice() != expected_offer_nonce {
            return Err(PqKemError::InvalidMessage("offer_nonce mismatch"));
        }

        let ct_arr = copy_into_array::<CT_LEN>("ct", &self.ct)?;
        let _parsed = catch_crypto("CipherText::try_from_bytes panicked", || {
            CipherText::try_from_bytes(ct_arr).map_err(PqKemError::Crypto)
        })?;

        Ok(())
    }
}

pub struct LocalPqKeypair {
    ek_bytes: [u8; EK_LEN],
    dk: DecapsKey,
    consumed: bool,
}

impl fmt::Debug for LocalPqKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPqKeypair")
            .field("ek_len", &self.ek_bytes.len())
            .field("dk", &"<redacted>")
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl LocalPqKeypair {
    pub fn generate() -> PqResult<Self> {
        let (ek, dk) = catch_crypto("ML-KEM keygen panicked", || {
            KG::try_keygen().map_err(PqKemError::Crypto)
        })?;
        let ek_bytes = ek.into_bytes();
        validate_not_all_zero("generated ek", &ek_bytes)?;

        Ok(Self {
            ek_bytes,
            dk,
            consumed: false,
        })
    }

    pub fn build_offer(&self, nonce: [u8; PQ_NONCE_LEN]) -> PqResult<PqKemOffer> {
        validate_not_all_zero("nonce", &nonce)?;
        validate_not_all_zero("ek", &self.ek_bytes)?;

        Ok(PqKemOffer {
            suite_id: PQ_KEM_SUITE_ID,
            created_at_unix_secs: now_unix_secs()?,
            nonce: nonce.to_vec(),
            ek: self.ek_bytes.to_vec(),
        })
    }

    pub fn ek_bytes(&self) -> &[u8; EK_LEN] {
        &self.ek_bytes
    }

    pub fn decapsulate_accept(
        &mut self,
        accept: &PqKemAccept,
        expected_offer_nonce: &[u8; PQ_NONCE_LEN],
        max_age: Duration,
    ) -> PqResult<PqSessionKey> {
        if self.consumed {
            return Err(PqKemError::InvalidState(
                "local PQ keypair already consumed; generate a fresh keypair",
            ));
        }

        accept.validate_untrusted(expected_offer_nonce, max_age)?;

        let ct_arr = copy_into_array::<CT_LEN>("ct", &accept.ct)?;
        let ct = catch_crypto("CipherText::try_from_bytes panicked", || {
            CipherText::try_from_bytes(ct_arr).map_err(PqKemError::Crypto)
        })?;

        // Mark consumed before decapsulation so an invalid or panicking accept cannot
        // leave this single-use local keypair reusable. The caller should clear state
        // and start a fresh PQ offer on failure.
        self.consumed = true;

        let ss = catch_crypto("ML-KEM decapsulation panicked", || {
            self.dk.try_decaps(&ct).map_err(PqKemError::Crypto)
        })?;
        let ss_bytes = ss.into_bytes();
        validate_not_all_zero("shared_secret", &ss_bytes)?;

        Ok(PqSessionKey {
            secret: ss_bytes,
            suite_id: PQ_KEM_SUITE_ID,
            suite_name: PQ_KEM_SUITE_NAME,
            established_at_unix_secs: now_unix_secs()?,
        })
    }

    pub fn set_consumed(&mut self, consumed: bool) {
        self.consumed = consumed;
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PqResponder;

impl PqResponder {
    pub fn respond_to_offer(
        offer: &PqKemOffer,
        max_age: Duration,
    ) -> PqResult<(PqKemAccept, PqSessionKey)> {
        offer.validate_untrusted(max_age)?;

        let ek_arr = copy_into_array::<EK_LEN>("ek", &offer.ek)?;
        let ek = catch_crypto("EncapsKey::try_from_bytes panicked", || {
            EncapsKey::try_from_bytes(ek_arr).map_err(PqKemError::Crypto)
        })?;

        let (ss, ct) = catch_crypto("ML-KEM encapsulation panicked", || {
            ek.try_encaps().map_err(PqKemError::Crypto)
        })?;
        let ct_bytes = ct.into_bytes();
        let ss_bytes = ss.into_bytes();
        validate_not_all_zero("ct", &ct_bytes)?;
        validate_not_all_zero("shared_secret", &ss_bytes)?;

        let now = now_unix_secs()?;

        let accept = PqKemAccept {
            suite_id: PQ_KEM_SUITE_ID,
            offer_nonce: offer.nonce.clone(),
            created_at_unix_secs: now,
            ct: ct_bytes.to_vec(),
        };

        accept.validate_untrusted(&offer.nonce_array()?, max_age)?;

        let session = PqSessionKey {
            secret: ss_bytes,
            suite_id: PQ_KEM_SUITE_ID,
            suite_name: PQ_KEM_SUITE_NAME,
            established_at_unix_secs: now,
        };

        Ok((accept, session))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSessionKey {
    secret: [u8; PQ_SHARED_SECRET_LEN],
    suite_id: u16,
    suite_name: &'static str,
    established_at_unix_secs: u64,
}

impl PqSessionKey {
    pub fn as_bytes(&self) -> &[u8; PQ_SHARED_SECRET_LEN] {
        &self.secret
    }

    pub fn into_bytes(self) -> [u8; PQ_SHARED_SECRET_LEN] {
        self.secret
    }

    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    pub fn suite_name(&self) -> &'static str {
        self.suite_name
    }

    pub fn established_at_unix_secs(&self) -> u64 {
        self.established_at_unix_secs
    }

    pub fn zeroize(&mut self) {
        for b in &mut self.secret {
            *b = 0;
        }
    }

    pub fn is_zeroized(&self) -> bool {
        self.secret.iter().all(|b| *b == 0)
    }
}

#[derive(Debug, Clone)]
pub struct PqKemPolicy {
    pub max_message_age: Duration,
    pub require_single_use_local_keypair: bool,
    pub replay_filter_capacity: usize,
}

impl PqKemPolicy {
    pub fn validate(&self) -> PqResult<()> {
        validate_max_age(self.max_message_age)?;

        if self.replay_filter_capacity == 0 {
            return Err(PqKemError::InvalidRange {
                field: "replay_filter_capacity",
                details: "must be nonzero",
            });
        }

        if self.replay_filter_capacity > MAX_REPLAY_FILTER_CAPACITY {
            return Err(PqKemError::InvalidRange {
                field: "replay_filter_capacity",
                details: "exceeds MAX_REPLAY_FILTER_CAPACITY",
            });
        }

        Ok(())
    }
}

impl Default for PqKemPolicy {
    fn default() -> Self {
        Self {
            max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
            require_single_use_local_keypair: true,
            replay_filter_capacity: DEFAULT_REPLAY_FILTER_CAPACITY,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PqKemManager {
    policy: PqKemPolicy,
    replay_filter: ReplayFilter,
}

impl Default for PqKemManager {
    fn default() -> Self {
        let policy = PqKemPolicy::default();

        Self {
            replay_filter: ReplayFilter::new(policy.replay_filter_capacity),
            policy,
        }
    }
}

impl PqKemManager {
    pub fn new(policy: PqKemPolicy) -> Self {
        // Keep constructor infallible for existing call sites.
        // Invalid policy is rejected before use through PqKemPolicy::validate().
        Self {
            replay_filter: ReplayFilter::new(policy.replay_filter_capacity),
            policy,
        }
    }

    pub fn policy(&self) -> &PqKemPolicy {
        &self.policy
    }

    pub fn build_local_keypair(&self) -> PqResult<LocalPqKeypair> {
        self.policy.validate()?;
        LocalPqKeypair::generate()
    }

    /// Initiator path.
    pub fn build_offer(
        &mut self,
        local: &LocalPqKeypair,
        nonce: [u8; PQ_NONCE_LEN],
    ) -> PqResult<PqKemOffer> {
        self.policy.validate()?;
        validate_not_all_zero("nonce", &nonce)?;
        local.build_offer(nonce)
    }

    /// Responder path.
    pub fn accept_offer(&mut self, offer: &PqKemOffer) -> PqResult<(PqKemAccept, PqSessionKey)> {
        self.policy.validate()?;
        offer.validate_untrusted(self.policy.max_message_age)?;

        let nonce = offer.nonce_array()?;
        self.replay_filter.check_and_insert(nonce)?;

        PqResponder::respond_to_offer(offer, self.policy.max_message_age)
    }

    /// Initiator finalization path.
    pub fn finalize_accept(
        &mut self,
        local: &mut LocalPqKeypair,
        accept: &PqKemAccept,
        expected_offer_nonce: [u8; PQ_NONCE_LEN],
    ) -> PqResult<PqSessionKey> {
        self.policy.validate()?;

        if self.policy.require_single_use_local_keypair && local.is_consumed() {
            return Err(PqKemError::InvalidState(
                "single-use local keypair already consumed",
            ));
        }

        local.decapsulate_accept(accept, &expected_offer_nonce, self.policy.max_message_age)
    }

    pub fn replay_cache_len(&self) -> usize {
        self.replay_filter.len()
    }

    pub fn replay_cache_capacity(&self) -> usize {
        self.replay_filter.capacity()
    }

    pub fn clear_replay_cache(&mut self) {
        self.replay_filter.clear();
    }
}

pub fn validate_ek_bytes(ek: &[u8]) -> PqResult<()> {
    validate_exact_len("ek", ek.len(), EK_LEN)?;
    validate_not_all_zero("ek", ek)?;

    let ek_arr = copy_into_array::<EK_LEN>("ek", ek)?;
    let _ = catch_crypto("EncapsKey::try_from_bytes panicked", || {
        EncapsKey::try_from_bytes(ek_arr).map_err(PqKemError::Crypto)
    })?;

    Ok(())
}

pub fn validate_ct_bytes(ct: &[u8]) -> PqResult<()> {
    validate_exact_len("ct", ct.len(), CT_LEN)?;
    validate_not_all_zero("ct", ct)?;

    let ct_arr = copy_into_array::<CT_LEN>("ct", ct)?;
    let _ = catch_crypto("CipherText::try_from_bytes panicked", || {
        CipherText::try_from_bytes(ct_arr).map_err(PqKemError::Crypto)
    })?;

    Ok(())
}

#[inline]
pub const fn ek_len() -> usize {
    EK_LEN
}

#[inline]
pub const fn dk_len() -> usize {
    DK_LEN
}

#[inline]
pub const fn ct_len() -> usize {
    CT_LEN
}

#[inline]
pub const fn shared_secret_len() -> usize {
    PQ_SHARED_SECRET_LEN
}
