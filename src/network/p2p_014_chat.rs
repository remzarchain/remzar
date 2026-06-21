use chrono::Utc;
use fips204::ml_dsa_65;
use fips204::traits::{Signer, Verifier};
use libp2p::gossipsub::{self, IdentTopic, Message, MessageId};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};

const CONSENSUS_CTX: &[u8] = b"";

/// Local aliases to keep the file structure intact.
type SigningKey = ml_dsa_65::PrivateKey;
type VerifyingKey = ml_dsa_65::PublicKey;

const ML_DSA_65_SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

/// Maximum user-visible plaintext length in characters.
pub const MAX_CHAT_PLAINTEXT_CHARS: usize = 500;

/// Maximum plaintext length in UTF-8 bytes.
pub const MAX_CHAT_PLAINTEXT_BYTES: usize = 2 * 1024;

/// Maximum size of the serialized JSON payload in bytes.
pub const MAX_CHAT_JSON_BYTES: usize = 4 * 1024;

/// Defensive cap: maximum allowed *wire* size for a postcard-encoded ChatMessage.
pub const MAX_CHAT_WIRE_BYTES: usize = 8 * 1024;

/// Defensive cap: wallet address string size.
pub const MAX_WALLET_STR_BYTES: usize = 192;

/// Defensive timestamp sanity window:
pub const CHAT_MAX_FUTURE_SKEW_MS: u64 = 5 * 60 * 1000;
pub const CHAT_MAX_PAST_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Global libp2p topic for Remzar chat messages.
pub const CHAT_TOPIC: &str = "remzar.chat.v1";

/// Minimal JSON payload stored inside the chat envelope.
/// Serialized as e.g. `{"m":"hi"}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatJson {
    /// User-visible message text.
    pub m: String,
}

/// Full chat envelope that is passed over gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub from_wallet: String,
    pub to_wallet: String,
    pub timestamp_ms: u64,

    /// Raw UTF-8 bytes of `ChatJson` (e.g. `{"m":"hello"}`).
    #[serde(with = "serde_bytes")]
    pub json: Vec<u8>,

    /// ML-DSA-65 signature bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl ChatMessage {
    /* ────────────────────────────────────────────────
    Defensive validators (pure wiring, no crypto changes)
    ──────────────────────────────────────────────── */

    /// Guardrail:
    /// - This is the ONLY wall-clock helper in this file.
    #[inline]
    fn now_unix_millis() -> Result<u64, ErrorDetection> {
        u64::try_from(Utc::now().timestamp_millis()).map_err(|_| ErrorDetection::ValidationError {
            message: "system clock ms overflow/underflow (i64 -> u64)".to_string(),
            tx_id: None,
        })
    }

    /// Wallet sanity check: canonical `"r" + 128 lowercase hex` (129 chars total).
    fn validate_wallet_str_canonical(s: &str, field: &'static str) -> Result<(), ErrorDetection> {
        let trimmed = s.trim();

        if trimmed.is_empty() || trimmed.len() > MAX_WALLET_STR_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{field} wallet string invalid size: {} bytes (max {MAX_WALLET_STR_BYTES})",
                    trimmed.len()
                ),
                tx_id: None,
            });
        }

        // Enforce canonical Remzar wallet form exactly:
        let canon = canon_wallet_id_checked(trimmed)?;
        if canon != trimmed {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{field} wallet is not canonical (expected lowercase 'r' + 128 lowercase hex)"
                ),
                tx_id: None,
            });
        }

        // Explicit length guard (keeps error messages sane if helpers change).
        if trimmed.len() != REMZAR_WALLET_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{field} wallet length invalid (expected {}): {}",
                    REMZAR_WALLET_LEN,
                    trimmed.len()
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Timestamp sanity (off-chain policy only).
    fn validate_timestamp_ms(ts: u64) -> Result<(), ErrorDetection> {
        let now_ms = Self::now_unix_millis()?;

        // Future skew check
        if ts > now_ms {
            let skew = ts.saturating_sub(now_ms);
            if skew > CHAT_MAX_FUTURE_SKEW_MS {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "chat timestamp too far in the future: skew {} ms (max {} ms)",
                        skew, CHAT_MAX_FUTURE_SKEW_MS
                    ),
                    tx_id: None,
                });
            }
        } else {
            // Past age check
            let age = now_ms.saturating_sub(ts);
            if age > CHAT_MAX_PAST_AGE_MS {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "chat timestamp too old: age {} ms (max {} ms)",
                        age, CHAT_MAX_PAST_AGE_MS
                    ),
                    tx_id: None,
                });
            }
        }

        Ok(())
    }

    /// Parse and validate the embedded JSON payload.
    fn parse_and_validate_payload_json(json_bytes: &[u8]) -> Result<ChatJson, ErrorDetection> {
        if json_bytes.len() > MAX_CHAT_JSON_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat payload too large: {} bytes (max {MAX_CHAT_JSON_BYTES})",
                    json_bytes.len()
                ),
                tx_id: None,
            });
        }

        let payload: ChatJson =
            serde_json::from_slice(json_bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Chat JSON deserialization failed: {e}"),
            })?;

        if payload.m.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "chat plaintext cannot be empty".to_string(),
                tx_id: None,
            });
        }

        let chars = payload.m.chars().count();
        if chars > MAX_CHAT_PLAINTEXT_CHARS {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat plaintext too long: {} chars (max {MAX_CHAT_PLAINTEXT_CHARS})",
                    chars
                ),
                tx_id: None,
            });
        }

        let bytes = payload.m.len();
        if bytes > MAX_CHAT_PLAINTEXT_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat plaintext too large: {} bytes (max {MAX_CHAT_PLAINTEXT_BYTES})",
                    bytes
                ),
                tx_id: None,
            });
        }

        Ok(payload)
    }

    /// Conservative pre-sign wire-size screen.
    fn ensure_pre_sign_wire_budget(
        from_wallet: &str,
        to_wallet: &str,
        json_len: usize,
    ) -> Result<(), ErrorDetection> {
        let approx_wire_len = from_wallet
            .len()
            .saturating_add(to_wallet.len())
            .saturating_add(json_len)
            .saturating_add(ML_DSA_65_SIGNATURE_LEN)
            .saturating_add(256); // postcard/string/vector framing + timestamp slack

        if approx_wire_len > MAX_CHAT_WIRE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat would exceed wire budget before signing: approx {} bytes (max {})",
                    approx_wire_len, MAX_CHAT_WIRE_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    /* ──────────────────────────────────────────────── */

    /// BLAKE3-XOF(64) helper for constant-size prehashing.
    #[inline]
    fn blake3_hash64(data: &[u8]) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);
        out
    }

    /// Internal helper: build the preimage that we prehash & sign.
    fn build_preimage(
        from_wallet: &str,
        to_wallet: &str,
        timestamp_ms: u64,
        json_bytes: &[u8],
    ) -> Vec<u8> {
        // Separator '|' is just to make the structure unambiguous.
        let capacity = from_wallet
            .len()
            .checked_add(to_wallet.len())
            .and_then(|v| v.checked_add(json_bytes.len()))
            .and_then(|v| v.checked_add(16))
            .unwrap_or(usize::MAX);

        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(from_wallet.as_bytes());
        buf.extend_from_slice(b"|");
        buf.extend_from_slice(to_wallet.as_bytes());
        buf.extend_from_slice(b"|");
        buf.extend_from_slice(&timestamp_ms.to_be_bytes());
        buf.extend_from_slice(b"|");
        buf.extend_from_slice(json_bytes);
        buf
    }

    /// Create a new signed chat message.
    pub fn new_signed(
        from_wallet: String,
        to_wallet: String,
        plaintext: &str,
        signing_key: &SigningKey,
    ) -> Result<Self, ErrorDetection> {
        // Defensive: cap before any heavier processing.
        if from_wallet.len() > MAX_WALLET_STR_BYTES || to_wallet.len() > MAX_WALLET_STR_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!("wallet string too large (max {MAX_WALLET_STR_BYTES} bytes)"),
                tx_id: None,
            });
        }

        // Canonicalize (accepts 'r' / uppercase hex, returns canonical lowercase).
        // We then *require* canonical in the stored message fields to avoid signature ambiguity.
        let from_wallet = canon_wallet_id_checked(&from_wallet)?;
        let to_wallet = canon_wallet_id_checked(&to_wallet)?;

        // Defensive: validate wallet strings early (avoids huge preimage work).
        Self::validate_wallet_str_canonical(&from_wallet, "from_wallet")?;
        Self::validate_wallet_str_canonical(&to_wallet, "to_wallet")?;

        if from_wallet == to_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "from_wallet and to_wallet cannot be the same for chat".to_string(),
                tx_id: None,
            });
        }

        // Defensive: fast fail on obviously-too-large plaintext (before JSON allocs).
        let plaintext_chars = plaintext.chars().count();
        if plaintext_chars > MAX_CHAT_PLAINTEXT_CHARS {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat plaintext too long: {} chars (max {MAX_CHAT_PLAINTEXT_CHARS})",
                    plaintext_chars
                ),
                tx_id: None,
            });
        }

        let plaintext_bytes = plaintext.len();
        if plaintext_bytes > MAX_CHAT_PLAINTEXT_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat plaintext too large pre-JSON: {} bytes (max {MAX_CHAT_PLAINTEXT_BYTES})",
                    plaintext_bytes
                ),
                tx_id: None,
            });
        }

        if plaintext.trim().is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "chat plaintext cannot be empty".to_string(),
                tx_id: None,
            });
        }

        // 1) JSON payload construction.
        let payload = ChatJson {
            m: plaintext.to_owned(),
        };

        let json_bytes =
            serde_json::to_vec(&payload).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Chat JSON serialization failed: {e}"),
            })?;

        // Validate the final JSON payload as the receiver will see it.
        let _ = Self::parse_and_validate_payload_json(&json_bytes)?;

        // Early budget screen before signing.
        Self::ensure_pre_sign_wire_budget(&from_wallet, &to_wallet, json_bytes.len())?;

        // 2) Timestamp in ms since UNIX epoch.
        let timestamp_ms = Self::now_unix_millis()?;

        // 3) Build preimage and prehash it via BLAKE3-XOF(64) → 64 bytes.
        let preimage = Self::build_preimage(&from_wallet, &to_wallet, timestamp_ms, &json_bytes);
        let prehashed = Self::blake3_hash64(&preimage);

        // 4) ML-DSA-65 signature over the 64-byte prehash.
        let signature: [u8; ml_dsa_65::SIG_LEN] =
            signing_key
                .try_sign(&prehashed, CONSENSUS_CTX)
                .map_err(|e| ErrorDetection::CryptographicError {
                    message: format!("chat message signing failed: {e}"),
                })?;

        let signature_bytes = signature.to_vec();

        Ok(ChatMessage {
            from_wallet,
            to_wallet,
            timestamp_ms,
            json: json_bytes,
            signature: signature_bytes,
        })
    }

    /// Return the user-visible plaintext message (`ChatJson.m`).
    pub fn plaintext(&self) -> Result<String, ErrorDetection> {
        let payload = Self::parse_and_validate_payload_json(&self.json)?;
        Ok(payload.m)
    }

    /// Verify this message against the sender's ML-DSA-65 verifying key.
    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), ErrorDetection> {
        // Defensive: wallet + timestamp sanity before doing any crypto verification.
        Self::validate_wallet_str_canonical(&self.from_wallet, "from_wallet")?;
        Self::validate_wallet_str_canonical(&self.to_wallet, "to_wallet")?;
        Self::validate_timestamp_ms(self.timestamp_ms)?;

        if self.from_wallet == self.to_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "from_wallet and to_wallet cannot be the same for chat".to_string(),
                tx_id: None,
            });
        }

        let _ = Self::parse_and_validate_payload_json(&self.json)?;

        if self.signature.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "chat signature length {} != expected {}",
                    self.signature.len(),
                    ML_DSA_65_SIGNATURE_LEN
                ),
            });
        }

        let sig_array: &[u8; ml_dsa_65::SIG_LEN] =
            self.signature.as_slice().try_into().map_err(|_| {
                ErrorDetection::SerializationError {
                    details: "failed to convert chat signature to fixed array".into(),
                }
            })?;

        let preimage = Self::build_preimage(
            &self.from_wallet,
            &self.to_wallet,
            self.timestamp_ms,
            &self.json,
        );
        let prehashed = Self::blake3_hash64(&preimage);

        if !vk.verify(&prehashed, sig_array, CONSENSUS_CTX) {
            return Err(ErrorDetection::SignatureVerificationFailed {
                message: "chat signature verification failed".to_string(),
            });
        }

        Ok(())
    }

    /// Encode the full `ChatMessage` as postcard bytes for libp2p.
    pub fn encode_wire(&self) -> Result<Vec<u8>, ErrorDetection> {
        // Defensive: ensure internal caps still hold before encoding.
        let _ = Self::parse_and_validate_payload_json(&self.json)?;

        if self.signature.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "chat signature length {} != expected {}",
                    self.signature.len(),
                    ML_DSA_65_SIGNATURE_LEN
                ),
            });
        }

        // Defensive: ensure wallet fields are canonical at the boundary.
        Self::validate_wallet_str_canonical(&self.from_wallet, "from_wallet")?;
        Self::validate_wallet_str_canonical(&self.to_wallet, "to_wallet")?;

        if self.from_wallet == self.to_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "from_wallet and to_wallet cannot be the same for chat".to_string(),
                tx_id: None,
            });
        }

        let out = postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
            details: format!("ChatMessage postcard serialization failed: {e}"),
        })?;

        // Defensive: cap final wire size.
        if out.len() > MAX_CHAT_WIRE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat wire message too large: {} bytes (max {MAX_CHAT_WIRE_BYTES})",
                    out.len()
                ),
                tx_id: None,
            });
        }

        Ok(out)
    }

    /// Decode a `ChatMessage` from postcard bytes.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        // Defensive: top-level wire cap BEFORE postcard allocates.
        if bytes.len() > MAX_CHAT_WIRE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "chat wire bytes too large: {} bytes (max {MAX_CHAT_WIRE_BYTES})",
                    bytes.len()
                ),
                tx_id: None,
            });
        }

        let msg: ChatMessage =
            postcard::from_bytes(bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!("ChatMessage postcard deserialization failed: {e}"),
            })?;

        // Defensive re-checks (never trust decoded content).
        let _ = Self::parse_and_validate_payload_json(&msg.json)?;

        if msg.signature.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "chat signature length {} != expected {}",
                    msg.signature.len(),
                    ML_DSA_65_SIGNATURE_LEN
                ),
            });
        }

        // Defensive: sanity check wallet format + timestamp window at decode-time.
        // (verification still requires `verify()` with vk; this is just fast-fail hygiene)
        Self::validate_wallet_str_canonical(&msg.from_wallet, "from_wallet")?;
        Self::validate_wallet_str_canonical(&msg.to_wallet, "to_wallet")?;
        Self::validate_timestamp_ms(msg.timestamp_ms)?;

        if msg.from_wallet == msg.to_wallet {
            return Err(ErrorDetection::ValidationError {
                message: "from_wallet and to_wallet cannot be the same for chat".to_string(),
                tx_id: None,
            });
        }

        Ok(msg)
    }
}

// ─────────────────────────────────────────────────────────────
// Libp2p gossipsub helpers
// ─────────────────────────────────────────────────────────────

/// The libp2p topic used for Remzar chat messages.
pub fn chat_topic() -> IdentTopic {
    IdentTopic::new(CHAT_TOPIC)
}

/// Publish a `ChatMessage` over gossipsub.
pub fn publish_chat(
    behaviour: &mut gossipsub::Behaviour,
    msg: &ChatMessage,
) -> Result<MessageId, ErrorDetection> {
    let bytes = msg.encode_wire()?;
    let topic = chat_topic();
    behaviour
        .publish(topic.hash(), bytes)
        .map_err(|e| ErrorDetection::StorageError {
            // "StorageError" is closest existing variant for generic network failures.
            message: format!("gossipsub publish failed for chat message: {e}"),
        })
}

pub fn try_decode_incoming(message: &Message) -> Result<ChatMessage, ErrorDetection> {
    // Defensive: fast-fail huge gossipsub frames before postcard decode.
    if message.data.len() > MAX_CHAT_WIRE_BYTES {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "incoming chat frame too large: {} bytes (max {MAX_CHAT_WIRE_BYTES})",
                message.data.len()
            ),
            tx_id: None,
        });
    }
    ChatMessage::decode_wire(&message.data)
}
