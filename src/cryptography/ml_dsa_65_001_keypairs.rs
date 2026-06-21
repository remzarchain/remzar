use crate::utility::alpha_002_error_detection_system::ErrorDetection;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct MlDsa65Keypair {
    secret_bytes: [u8; ml_dsa_65::SK_LEN],
    public_bytes: [u8; ml_dsa_65::PK_LEN],
}

impl core::fmt::Debug for MlDsa65Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65Keypair")
            .field("secret_bytes", &"[REDACTED; ML-DSA-65 secret key bytes]")
            .field("public_bytes", &"[REDACTED; ML-DSA-65 public key bytes]")
            .finish()
    }
}

impl Drop for MlDsa65Keypair {
    fn drop(&mut self) {
        self.secret_bytes.zeroize();
        self.public_bytes.zeroize();
    }
}

impl MlDsa65Keypair {
    pub const SECRET_LEN: usize = ml_dsa_65::SK_LEN;
    pub const PUBLIC_LEN: usize = ml_dsa_65::PK_LEN;
    pub const RAW_SERIALIZED_LEN: usize = Self::SECRET_LEN + Self::PUBLIC_LEN;

    pub const CANONICAL_MAGIC: [u8; 4] = *b"M65K";
    pub const CANONICAL_VERSION: u8 = 1;
    pub const CANONICAL_FLAGS: u8 = 0;
    pub const CANONICAL_RESERVED: [u8; 2] = [0u8; 2];
    pub const CANONICAL_HEADER_LEN: usize = 8;
    pub const CANONICAL_SERIALIZED_LEN: usize =
        Self::CANONICAL_HEADER_LEN + Self::RAW_SERIALIZED_LEN;

    pub const SERIALIZED_LEN: usize = Self::RAW_SERIALIZED_LEN;
    pub const VALIDATE_INVARIANTS_BUDGET_MILLIS: u64 = 750;
    #[inline]
    fn validate_invariants_budget() -> Duration {
        Duration::from_millis(Self::VALIDATE_INVARIANTS_BUDGET_MILLIS)
    }

    #[inline]
    fn reject_if_validation_budget_exceeded(
        started_at: Instant,
        stage: &'static str,
    ) -> Result<(), ErrorDetection> {
        if started_at.elapsed() > Self::validate_invariants_budget() {
            tracing::debug!(
                target: "remzar::cryptography::ml_dsa_65_001_keypairs",
                event = "MlDsa65ValidateInvariantsBudgetExceeded",
                stage = stage,
                budget_ms = Self::VALIDATE_INVARIANTS_BUDGET_MILLIS,
                "ML-DSA-65 keypair validation exceeded hard budget; rejecting key material"
            );

            return Err(Self::invalid_signature_format(format!(
                "Invalid ML-DSA-65 keypair: validation exceeded {} ms at {stage}",
                Self::VALIDATE_INVARIANTS_BUDGET_MILLIS
            )));
        }

        Ok(())
    }

    #[inline]
    fn maybe_fault(op: &'static str) -> Result<(), ErrorDetection> {
        if std::env::var_os(format!("REMZAR_FAIL_{}", op)).is_some() {
            return Err(ErrorDetection::CryptographicError {
                message: format!("Fault injection triggered at operation: {op}"),
            });
        }

        Ok(())
    }

    #[inline]
    fn serialization_error(details: impl Into<String>) -> ErrorDetection {
        ErrorDetection::SerializationError {
            details: details.into(),
        }
    }

    #[inline]
    fn invalid_signature_format(format: impl Into<String>) -> ErrorDetection {
        ErrorDetection::InvalidSignatureFormat {
            format: format.into(),
        }
    }

    #[inline]
    fn panic_hook_lock() -> &'static Mutex<()> {
        static PANIC_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        PANIC_HOOK_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[inline]
    fn derive_public_bytes_with_suppressed_panic_hook(
        sk: ml_dsa_65::PrivateKey,
    ) -> Result<[u8; ml_dsa_65::PK_LEN], ErrorDetection> {
        let _hook_guard =
            Self::panic_hook_lock()
                .lock()
                .map_err(|_| ErrorDetection::CryptographicError {
                    message: "Panic hook lock poisoned during ML-DSA-65 public key derivation"
                        .to_string(),
                })?;

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sk.get_public_key().into_bytes()
        }));

        std::panic::set_hook(previous_hook);

        match result {
            Ok(public_bytes) => Ok(public_bytes),
            Err(_) => {
                tracing::debug!(
                    target: "remzar::cryptography::ml_dsa_65_001_keypairs",
                    event = "MlDsa65PublicKeyDerivationPanic",
                    "ML-DSA-65 public key derivation panicked from secret bytes; rejecting key material"
                );

                Err(Self::invalid_signature_format(
                    "Invalid ML-DSA-65 secret key: public key derivation panicked",
                ))
            }
        }
    }

    #[inline]
    fn parse_secret_key_bytes_with_suppressed_panic_hook(
        mut secret_bytes: Box<[u8; ml_dsa_65::SK_LEN]>,
        context: &'static str,
    ) -> Result<ml_dsa_65::PrivateKey, ErrorDetection> {
        let _hook_guard =
            Self::panic_hook_lock()
                .lock()
                .map_err(|_| ErrorDetection::CryptographicError {
                    message: "Panic hook lock poisoned during ML-DSA-65 secret key parsing"
                        .to_string(),
                })?;

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ml_dsa_65::PrivateKey::try_from_bytes(*secret_bytes)
        }));

        std::panic::set_hook(previous_hook);
        secret_bytes.zeroize();

        match result {
            Ok(Ok(sk)) => Ok(sk),

            Ok(Err(e)) => {
                tracing::debug!("{context}: invalid ML-DSA-65 secret key format: {e}");
                Err(Self::invalid_signature_format(format!(
                    "Invalid ML-DSA-65 secret key format: {e}"
                )))
            }

            Err(_) => {
                tracing::debug!(
                    target: "remzar::cryptography::ml_dsa_65_001_keypairs",
                    event = "MlDsa65SecretKeyParsePanic",
                    "ML-DSA-65 secret key parsing panicked; rejecting key material"
                );

                Err(Self::invalid_signature_format(
                    "Invalid ML-DSA-65 secret key: secret key parsing panicked",
                ))
            }
        }
    }

    #[inline]
    fn parse_public_key_bytes_checked(
        public_bytes: &[u8; ml_dsa_65::PK_LEN],
        context: &'static str,
    ) -> Result<ml_dsa_65::PublicKey, ErrorDetection> {
        ml_dsa_65::PublicKey::try_from_bytes(*public_bytes).map_err(|e| {
            tracing::debug!("{context}: invalid ML-DSA-65 public key format: {e}");
            Self::invalid_signature_format(format!("Invalid ML-DSA-65 public key format: {e}"))
        })
    }

    #[inline]
    fn parse_secret_key_bytes_checked(
        secret_bytes: &[u8; ml_dsa_65::SK_LEN],
        context: &'static str,
    ) -> Result<ml_dsa_65::PrivateKey, ErrorDetection> {
        Self::parse_secret_key_bytes_with_suppressed_panic_hook(Box::new(*secret_bytes), context)
    }

    #[inline]
    fn derive_public_bytes_from_secret_checked(
        sk: ml_dsa_65::PrivateKey,
    ) -> Result<[u8; ml_dsa_65::PK_LEN], ErrorDetection> {
        Self::derive_public_bytes_with_suppressed_panic_hook(sk)
    }

    fn validate_invariants(&self) -> Result<(), ErrorDetection> {
        let started_at = Instant::now();

        Self::maybe_fault("VALIDATE_INVARIANTS_PRE")?;

        let parsed_pk = Self::parse_public_key_bytes_checked(
            &self.public_bytes,
            "MlDsa65Keypair invariant failure",
        )?;

        Self::reject_if_validation_budget_exceeded(started_at, "public-key-parse")?;

        let sk = Self::parse_secret_key_bytes_checked(
            &self.secret_bytes,
            "MlDsa65Keypair invariant failure",
        )?;

        Self::reject_if_validation_budget_exceeded(started_at, "secret-key-parse")?;

        let derived_pk_bytes = Self::derive_public_bytes_from_secret_checked(sk)?;

        Self::reject_if_validation_budget_exceeded(started_at, "public-key-derivation")?;

        if self.public_bytes != derived_pk_bytes {
            tracing::debug!(
                "MlDsa65Keypair invariant failure: stored public key does not match secret-derived public key"
            );
            return Err(Self::invalid_signature_format(
                "Stored public key does not match secret-derived public key",
            ));
        }

        if parsed_pk.into_bytes() != derived_pk_bytes {
            tracing::debug!(
                "MlDsa65Keypair invariant failure: parsed public key does not serialize canonically"
            );
            return Err(Self::invalid_signature_format(
                "Stored public key mismatch after parsing",
            ));
        }

        Self::reject_if_validation_budget_exceeded(started_at, "final")?;

        Self::maybe_fault("VALIDATE_INVARIANTS_POST")?;
        Ok(())
    }

    #[inline]
    fn from_parts_validated(
        secret_bytes: &[u8; ml_dsa_65::SK_LEN],
        public_bytes: &[u8; ml_dsa_65::PK_LEN],
    ) -> Result<Self, ErrorDetection> {
        let kp = Self {
            secret_bytes: *secret_bytes,
            public_bytes: *public_bytes,
        };
        kp.validate_invariants()?;
        Ok(kp)
    }

    pub fn generate() -> Result<Self, ErrorDetection> {
        Self::maybe_fault("GENERATE_PRE")?;

        let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| {
            tracing::debug!("ML-DSA-65 key generation failed: {e}");
            ErrorDetection::CryptographicError {
                message: format!("ML-DSA-65 key generation failed: {e}"),
            }
        })?;

        let kp = Self {
            secret_bytes: sk.into_bytes(),
            public_bytes: pk.into_bytes(),
        };

        kp.validate_invariants()?;
        Self::maybe_fault("GENERATE_POST")?;
        Ok(kp)
    }

    pub fn from_secret(mut secret_bytes: [u8; ml_dsa_65::SK_LEN]) -> Result<Self, ErrorDetection> {
        let started_at = Instant::now();

        Self::maybe_fault("FROM_SECRET_PRE")?;

        let sk = match Self::parse_secret_key_bytes_checked(
            &secret_bytes,
            "Invalid ML-DSA-65 secret key format in from_secret",
        ) {
            Ok(sk) => sk,
            Err(e) => {
                secret_bytes.zeroize();
                return Err(e);
            }
        };

        Self::reject_if_validation_budget_exceeded(started_at, "from-secret-parse")?;

        let public_bytes = match Self::derive_public_bytes_from_secret_checked(sk) {
            Ok(public_bytes) => public_bytes,
            Err(e) => {
                secret_bytes.zeroize();
                return Err(e);
            }
        };

        Self::reject_if_validation_budget_exceeded(started_at, "from-secret-derive-public")?;

        let parsed_pk = match Self::parse_public_key_bytes_checked(
            &public_bytes,
            "Invalid ML-DSA-65 derived public key in from_secret",
        ) {
            Ok(parsed_pk) => parsed_pk,
            Err(e) => {
                secret_bytes.zeroize();
                return Err(e);
            }
        };

        Self::reject_if_validation_budget_exceeded(started_at, "from-secret-parse-public")?;

        if parsed_pk.into_bytes() != public_bytes {
            tracing::debug!(
                "Invalid ML-DSA-65 derived public key in from_secret: parsed public key mismatch"
            );
            secret_bytes.zeroize();
            return Err(Self::invalid_signature_format(
                "Derived ML-DSA-65 public key mismatch after parsing",
            ));
        }

        let kp = Self {
            secret_bytes,
            public_bytes,
        };

        Self::maybe_fault("FROM_SECRET_POST")?;
        Ok(kp)
    }

    pub fn get_signing_key(&self) -> Result<ml_dsa_65::PrivateKey, ErrorDetection> {
        Self::maybe_fault("GET_SIGNING_KEY_PRE")?;

        Self::parse_secret_key_bytes_checked(
            &self.secret_bytes,
            "Invalid ML-DSA-65 secret key bytes in get_signing_key",
        )
    }

    pub fn get_verifying_key(&self) -> Result<ml_dsa_65::PublicKey, ErrorDetection> {
        Self::maybe_fault("GET_VERIFYING_KEY_PRE")?;

        Self::parse_public_key_bytes_checked(
            &self.public_bytes,
            "Invalid ML-DSA-65 public key format in get_verifying_key",
        )
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
        Self::maybe_fault("SERIALIZE_RAW_PRE")?;

        tracing::debug!("MlDsa65Keypair::serialize() exporting raw secret||public format");

        let mut out = Vec::with_capacity(Self::RAW_SERIALIZED_LEN);
        out.extend_from_slice(&self.secret_bytes);
        out.extend_from_slice(&self.public_bytes);

        debug_assert_eq!(out.len(), Self::RAW_SERIALIZED_LEN);

        if let Err(e) = Self::maybe_fault("SERIALIZE_RAW_POST") {
            out.zeroize();
            return Err(e);
        }

        Ok(out)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ErrorDetection> {
        Self::maybe_fault("DESERIALIZE_RAW_PRE")?;

        if data.len() != Self::RAW_SERIALIZED_LEN {
            tracing::debug!(
                "Raw keypair deserialize failed: expected {} bytes, got {}",
                Self::RAW_SERIALIZED_LEN,
                data.len()
            );
            return Err(Self::serialization_error(format!(
                "Data length mismatch: expected {} bytes, got {}",
                Self::RAW_SERIALIZED_LEN,
                data.len()
            )));
        }

        let secret_slice = data
            .get(0..Self::SECRET_LEN)
            .ok_or_else(|| Self::serialization_error("Data slice out of bounds for secret key"))?;

        let public_slice = data
            .get(Self::SECRET_LEN..Self::RAW_SERIALIZED_LEN)
            .ok_or_else(|| Self::serialization_error("Data slice out of bounds for public key"))?;

        let mut secret_bytes = [0u8; ml_dsa_65::SK_LEN];
        secret_bytes.copy_from_slice(secret_slice);

        let mut public_bytes = [0u8; ml_dsa_65::PK_LEN];
        public_bytes.copy_from_slice(public_slice);

        match Self::from_parts_validated(&secret_bytes, &public_bytes) {
            Ok(kp) => {
                secret_bytes.zeroize();
                public_bytes.zeroize();

                Self::maybe_fault("DESERIALIZE_RAW_POST")?;
                Ok(kp)
            }
            Err(e) => {
                secret_bytes.zeroize();
                public_bytes.zeroize();
                Err(e)
            }
        }
    }

    pub fn serialize_canonical(&self) -> Result<Vec<u8>, ErrorDetection> {
        Self::maybe_fault("SERIALIZE_CANONICAL_PRE")?;

        let mut out = Vec::with_capacity(Self::CANONICAL_SERIALIZED_LEN);
        out.extend_from_slice(&Self::CANONICAL_MAGIC);
        out.push(Self::CANONICAL_VERSION);
        out.push(Self::CANONICAL_FLAGS);
        out.extend_from_slice(&Self::CANONICAL_RESERVED);
        out.extend_from_slice(&self.secret_bytes);
        out.extend_from_slice(&self.public_bytes);

        debug_assert_eq!(out.len(), Self::CANONICAL_SERIALIZED_LEN);

        if let Err(e) = Self::maybe_fault("SERIALIZE_CANONICAL_POST") {
            out.zeroize();
            return Err(e);
        }

        Ok(out)
    }

    pub fn deserialize_canonical(data: &[u8]) -> Result<Self, ErrorDetection> {
        Self::maybe_fault("DESERIALIZE_CANONICAL_PRE")?;

        if data.len() != Self::CANONICAL_SERIALIZED_LEN {
            tracing::debug!(
                "Canonical keypair deserialize failed: expected {} bytes, got {}",
                Self::CANONICAL_SERIALIZED_LEN,
                data.len()
            );
            return Err(Self::serialization_error(format!(
                "Canonical data length mismatch: expected {} bytes, got {}",
                Self::CANONICAL_SERIALIZED_LEN,
                data.len()
            )));
        }

        let magic = data
            .get(0..4)
            .ok_or_else(|| Self::serialization_error("Canonical header missing magic"))?;
        if magic != Self::CANONICAL_MAGIC {
            tracing::debug!("Canonical keypair deserialize failed: invalid magic");
            return Err(Self::serialization_error(
                "Canonical keypair magic mismatch",
            ));
        }

        let version = *data
            .get(4)
            .ok_or_else(|| Self::serialization_error("Canonical header missing version"))?;
        if version != Self::CANONICAL_VERSION {
            tracing::debug!(
                "Canonical keypair deserialize failed: unsupported version {}",
                version
            );
            return Err(Self::serialization_error(format!(
                "Unsupported canonical keypair version: {}",
                version
            )));
        }

        let flags = *data
            .get(5)
            .ok_or_else(|| Self::serialization_error("Canonical header missing flags"))?;
        if flags != Self::CANONICAL_FLAGS {
            tracing::debug!(
                "Canonical keypair deserialize failed: unexpected flags {}",
                flags
            );
            return Err(Self::serialization_error(format!(
                "Unsupported canonical keypair flags: {}",
                flags
            )));
        }

        let reserved = data
            .get(6..8)
            .ok_or_else(|| Self::serialization_error("Canonical header missing reserved bytes"))?;
        if reserved != Self::CANONICAL_RESERVED {
            tracing::debug!("Canonical keypair deserialize failed: reserved bytes must be zero");
            return Err(Self::serialization_error(
                "Canonical keypair reserved bytes must be zero",
            ));
        }

        let body = data
            .get(Self::CANONICAL_HEADER_LEN..)
            .ok_or_else(|| Self::serialization_error("Canonical body missing"))?;

        let kp = Self::deserialize(body)?;
        Self::maybe_fault("DESERIALIZE_CANONICAL_POST")?;
        Ok(kp)
    }

    pub fn validate_self(&self) -> Result<(), ErrorDetection> {
        self.validate_invariants()
    }

    pub fn secret_bytes_ref(&self) -> &[u8; ml_dsa_65::SK_LEN] {
        &self.secret_bytes
    }

    pub fn public_bytes_ref(&self) -> &[u8; ml_dsa_65::PK_LEN] {
        &self.public_bytes
    }

    pub fn secret_bytes_slice(&self) -> &[u8] {
        &self.secret_bytes
    }

    pub fn public_bytes_slice(&self) -> &[u8] {
        &self.public_bytes
    }

    pub fn to_bytes(&self) -> [u8; ml_dsa_65::SK_LEN] {
        self.secret_bytes
    }

    pub fn public_key_bytes(&self) -> [u8; ml_dsa_65::PK_LEN] {
        self.public_bytes
    }
}
