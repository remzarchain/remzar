#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

mod utility {
    pub mod alpha_001_global_configuration {
        use fips204::ml_dsa_65;

        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const DOMAIN_SEPARATION_ON: bool = false;
            pub const DOMAIN_TAG: &'static [u8] = b"remzar_guardian_signature_domain";

            // Fuzz-safe caps.
            // Keep these small so fuzzing guardian signatures does not waste time
            // constructing huge transaction batches or huge Merkle trees.
            pub const MAX_BATCH_ITEMS: usize = 64;
            pub const MAX_ITEM_BYTES: usize = 4096;
            pub const MAX_TOTAL_BATCH_BYTES: usize =
                Self::MAX_BATCH_ITEMS * Self::MAX_ITEM_BYTES;

            // Must match the ML-DSA-65 signature length because GuardianSignature
            // validates this against fips204::ml_dsa_65::SIG_LEN.
            pub const GUARDIAN_SIG_LEN: usize = ml_dsa_65::SIG_LEN;
        }
    }

    pub mod alpha_002_error_detection_system {
        #[derive(Debug, Clone)]
        pub enum ErrorDetection {
            CryptographicError { message: String },
            SerializationError { details: String },
            InvalidSignatureFormat { format: String },
            MerkleProofGenerationError { reason: String },
            ValidationError { message: String, tx_id: Option<String> },
            SignatureVerificationFailed { message: String },
        }
    }

    pub mod helper {
        use serde::de::{Error as DeError, SeqAccess, Visitor};
        use serde::ser::SerializeTuple;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use std::fmt;

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct Hash64([u8; 64]);

        impl Hash64 {
            #[inline]
            pub fn from_bytes(bytes: [u8; 64]) -> Self {
                Self(bytes)
            }

            #[inline]
            pub fn as_bytes(&self) -> &[u8; 64] {
                &self.0
            }
        }

        impl Serialize for Hash64 {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut tuple = serializer.serialize_tuple(64)?;

                for byte in self.0 {
                    tuple.serialize_element(&byte)?;
                }

                tuple.end()
            }
        }

        struct Hash64Visitor;

        impl<'de> Visitor<'de> for Hash64Visitor {
            type Value = Hash64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 64 bytes for Hash64")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0u8; 64];

                for (i, slot) in bytes.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| DeError::invalid_length(i, &self))?;
                }

                Ok(Hash64(bytes))
            }
        }

        impl<'de> Deserialize<'de> for Hash64 {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_tuple(64, Hash64Visitor)
            }
        }
    }
}

#[path = "../../src/cryptography/ml_dsa_65_001_keypairs.rs"]
mod ml_dsa_65_001_keypairs;

#[path = "../../src/cryptography/ml_dsa_65_002_merkleproof.rs"]
pub mod ml_dsa_65_002_merkleproof;

#[path = "../../src/cryptography/ml_dsa_65_004_guardian_signature.rs"]
pub mod ml_dsa_65_004_guardian_signature;

pub mod cryptography {
    pub use crate::ml_dsa_65_002_merkleproof;
    pub use crate::ml_dsa_65_004_guardian_signature;
}

use cryptography::ml_dsa_65_004_guardian_signature::GuardianSignature;
use fips204::ml_dsa_65;
use ml_dsa_65_001_keypairs::MlDsa65Keypair;
use utility::alpha_002_error_detection_system::ErrorDetection;

const MAX_FUZZ_TXS: usize = 32;
const MAX_FUZZ_TX_LEN: usize = 512;

struct GuardianKeyMaterial {
    signing: ml_dsa_65::PrivateKey,
    verifying: ml_dsa_65::PublicKey,
    wrong_verifying: ml_dsa_65::PublicKey,
}

fn guardian_keys() -> Option<&'static GuardianKeyMaterial> {
    static KEYS: OnceLock<Option<GuardianKeyMaterial>> = OnceLock::new();

    KEYS.get_or_init(|| {
        let guardian = MlDsa65Keypair::generate().ok()?;
        let wrong_guardian = MlDsa65Keypair::generate().ok()?;

        Some(GuardianKeyMaterial {
            signing: guardian.get_signing_key().ok()?,
            verifying: guardian.get_verifying_key().ok()?,
            wrong_verifying: wrong_guardian.get_verifying_key().ok()?,
        })
    })
    .as_ref()
}

fn touch_error(error: &ErrorDetection) {
    match error {
        ErrorDetection::CryptographicError { message } => {
            let _ = message.len();
        }
        ErrorDetection::SerializationError { details } => {
            let _ = details.len();
        }
        ErrorDetection::InvalidSignatureFormat { format } => {
            let _ = format.len();
        }
        ErrorDetection::MerkleProofGenerationError { reason } => {
            let _ = reason.len();
        }
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            let _ = tx_id.as_ref().map(|value| value.len());
        }
        ErrorDetection::SignatureVerificationFailed { message } => {
            let _ = message.len();
        }
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            touch_error(&error);
            None
        }
    }
}

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn fill_from_fuzz<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];

    if data.is_empty() {
        return out;
    }

    for i in 0..N {
        out[i] = data[i % data.len()];
    }

    out
}

fn mutate_bytes(buf: &mut [u8], data: &[u8], salt: usize) {
    if buf.is_empty() {
        return;
    }

    if data.is_empty() {
        buf[salt % buf.len()] ^= 0xA5;
        return;
    }

    let stride = ((data[0] as usize) % 31) + 1;

    for (i, byte) in data.iter().enumerate() {
        let idx = i
            .wrapping_mul(stride)
            .wrapping_add(salt)
            .wrapping_rem(buf.len());

        buf[idx] ^= *byte;
    }
}

fn mutate_length(mut buf: Vec<u8>, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        if !buf.is_empty() {
            buf.pop();
        }
        return buf;
    }

    match data[0] % 8 {
        0 => buf.clear(),
        1 => {
            let new_len = byte_at(data, 1, 0) as usize % buf.len().saturating_add(1);
            buf.truncate(new_len);
        }
        2 => {
            buf.push(byte_at(data, 1, 0));
        }
        3 => {
            buf.extend_from_slice(data);
        }
        4 => {
            if !buf.is_empty() {
                let idx = byte_at(data, 1, 0) as usize % buf.len();
                buf.remove(idx);
            }
        }
        5 => {
            let remove = ((byte_at(data, 1, 0) as usize) % 32) + 1;
            let new_len = buf.len().saturating_sub(remove);
            buf.truncate(new_len);
        }
        6 => {
            let exact_ish = ml_dsa_65::SIG_LEN.saturating_sub(1);
            buf.resize(exact_ish, byte_at(data, 2, 0x55));
        }
        _ => {
            let over = ml_dsa_65::SIG_LEN.saturating_add(1);
            buf.resize(over, byte_at(data, 2, 0xAA));
        }
    }

    buf
}

fn make_txs(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return Vec::new();
    }

    let count = data[0] as usize % (MAX_FUZZ_TXS + 1);
    let mut cursor = 1usize;
    let mut txs = Vec::with_capacity(count);

    for tx_index in 0..count {
        let len = byte_at(data, cursor, tx_index as u8) as usize % (MAX_FUZZ_TX_LEN + 1);
        cursor = cursor.wrapping_add(1);

        let mut tx = Vec::with_capacity(len);
        for j in 0..len {
            tx.push(byte_at(data, cursor + j, j as u8) ^ tx_index as u8);
        }

        cursor = cursor.wrapping_add(len);
        txs.push(tx);
    }

    txs
}

fn make_refs(txs: &[Vec<u8>]) -> Vec<&[u8]> {
    txs.iter().map(|tx| tx.as_slice()).collect()
}

fn mutate_batch(mut txs: Vec<Vec<u8>>, data: &[u8]) -> Vec<Vec<u8>> {
    if txs.is_empty() {
        txs.push(Vec::new());
        return txs;
    }

    match byte_at(data, 2, 0) % 8 {
        0 => {
            let idx = byte_at(data, 3, 0) as usize % txs.len();
            mutate_bytes(&mut txs[idx], data, 101);
        }
        1 => {
            let idx = byte_at(data, 3, 0) as usize % txs.len();
            txs[idx].push(byte_at(data, 4, 0x42));
        }
        2 => {
            let idx = byte_at(data, 3, 0) as usize % txs.len();
            if !txs[idx].is_empty() {
                txs[idx].pop();
            }
        }
        3 => {
            txs.push(data.iter().copied().take(MAX_FUZZ_TX_LEN).collect());
        }
        4 => {
            let idx = byte_at(data, 3, 0) as usize % txs.len();
            txs.remove(idx);
        }
        5 => {
            txs.reverse();
        }
        6 => {
            let idx = byte_at(data, 3, 0) as usize % txs.len();
            let cloned = txs[idx].clone();
            txs.push(cloned);
        }
        _ => {
            txs.push(Vec::new());
        }
    }

    txs
}

fn exercise_guardian_batch(
    keys: &GuardianKeyMaterial,
    txs: Vec<Vec<u8>>,
    data: &[u8],
) -> Option<Vec<u8>> {
    let refs = make_refs(&txs);

    // 1. Valid guardian signing path.
    let signature = touch_result(GuardianSignature::sign_batch(&keys.signing, &refs))?;

    assert_eq!(
        signature.len(),
        ml_dsa_65::SIG_LEN,
        "GuardianSignature::sign_batch must return exact ML-DSA-65 signature length"
    );

    // 2. Valid guardian verification path.
    if let Err(error) = GuardianSignature::verify_batch(&keys.verifying, &refs, &signature) {
        panic!("valid guardian signature failed to verify: {error:?}");
    }

    // 3. Wrong guardian public key should reject cleanly.
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.wrong_verifying,
        &refs,
        &signature,
    ));

    // 4. Raw fuzzer input as a signature. Usually rejected by length validation.
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &refs,
        data,
    ));

    // 5. Exact-length fuzzer-generated signature. Usually rejected cryptographically.
    let fuzz_signature = fill_from_fuzz::<{ ml_dsa_65::SIG_LEN }>(data);
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &refs,
        &fuzz_signature,
    ));

    // 6. All-zero exact-length signature.
    let zero_signature = [0u8; ml_dsa_65::SIG_LEN];
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &refs,
        &zero_signature,
    ));

    // 7. Byte-mutated valid signature.
    let mut mutated_signature = signature.clone();
    mutate_bytes(&mut mutated_signature, data, 17);
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &refs,
        &mutated_signature,
    ));

    // 8. Length-mutated valid signature:
    // empty, short, long, exact-minus-one, exact-plus-one, etc.
    let resized_signature = mutate_length(signature.clone(), data);
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &refs,
        &resized_signature,
    ));

    // 9. Valid signature against mutated batch should usually fail because
    // the Merkle root changes.
    let mutated_txs = mutate_batch(txs, data);
    let mutated_refs = make_refs(&mutated_txs);
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &mutated_refs,
        &signature,
    ));

    Some(signature)
}

fn exercise_guardian_rejections(
    keys: &GuardianKeyMaterial,
    valid_signature: &[u8],
    data: &[u8],
) {
    // Over item count should reject cleanly before expensive hashing/signing.
    let over_cap_item = b"tiny";
    let over_cap_batch: Vec<&[u8]> = vec![
        over_cap_item.as_slice();
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_BATCH_ITEMS + 1
    ];

    let _ = touch_result(GuardianSignature::sign_batch(
        &keys.signing,
        &over_cap_batch,
    ));
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &over_cap_batch,
        valid_signature,
    ));

    // Oversized individual item should reject cleanly.
    let oversized_item = vec![
        byte_at(data, 5, 0xCD);
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_ITEM_BYTES + 1
    ];
    let oversized_batch: Vec<&[u8]> = vec![oversized_item.as_slice()];

    let _ = touch_result(GuardianSignature::sign_batch(
        &keys.signing,
        &oversized_batch,
    ));
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &oversized_batch,
        valid_signature,
    ));

    // Oversized total bytes should reject cleanly. Each item is under MAX_ITEM_BYTES,
    // but the total crosses MAX_TOTAL_BATCH_BYTES.
    let item_len =
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_ITEM_BYTES;
    let item_a = vec![byte_at(data, 6, 0xA1); item_len];
    let item_b = vec![byte_at(data, 7, 0xB2); item_len];
    let item_c = vec![byte_at(data, 8, 0xC3); item_len];

    let repeated: Vec<&[u8]> = vec![
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
        item_a.as_slice(),
        item_b.as_slice(),
        item_c.as_slice(),
    ];

    let _ = touch_result(GuardianSignature::sign_batch(&keys.signing, &repeated));
    let _ = touch_result(GuardianSignature::verify_batch(
        &keys.verifying,
        &repeated,
        valid_signature,
    ));
}

fn edge_batch(data: &[u8]) -> Vec<Vec<u8>> {
    match byte_at(data, 0, 0) % 10 {
        0 => Vec::new(),
        1 => vec![Vec::new()],
        2 => vec![b"only_tx".to_vec()],
        3 => vec![b"left_tx".to_vec(), b"right_tx".to_vec()],
        4 => vec![
            b"tx0".to_vec(),
            b"tx1".to_vec(),
            b"tx2".to_vec(),
            b"tx3".to_vec(),
            b"tx4".to_vec(),
        ],
        5 => vec![b"dup".to_vec(), b"dup".to_vec(), b"unique".to_vec()],
        6 => vec![b"".to_vec(), b"a".to_vec(), b"b".to_vec()],
        7 => vec![
            vec![byte_at(data, 1, 0x11); 1],
            vec![byte_at(data, 2, 0x22); 31],
            vec![byte_at(data, 3, 0x33); 257],
        ],
        8 => vec![
            b"guardian".to_vec(),
            b"block".to_vec(),
            b"batch".to_vec(),
            b"signature".to_vec(),
            data.iter().copied().take(128).collect(),
        ],
        _ => vec![
            vec![0u8; 32],
            vec![0xFFu8; 64],
            vec![byte_at(data, 4, 0x5A); 128],
        ],
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(keys) = guardian_keys() else {
        return;
    };

    // Main fuzzer-generated batch.
    let txs = make_txs(data);
    if let Some(signature) = exercise_guardian_batch(keys, txs, data) {
        exercise_guardian_rejections(keys, &signature, data);
    }

    // Deterministic edge-case batch chosen from the fuzz bytes.
    // This improves coverage without doing too many expensive ML-DSA signs per input.
    let edge = edge_batch(data);
    let _ = exercise_guardian_batch(keys, edge, data);
});