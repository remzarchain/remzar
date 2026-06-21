#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const DOMAIN_SEPARATION_ON: bool = false;
            pub const DOMAIN_TAG: &'static [u8] = b"remzar_merkle_domain";

            // Smaller fuzz-safe caps so the fuzzer does not waste time building massive trees.
            pub const MAX_BATCH_ITEMS: usize = 64;
            pub const MAX_ITEM_BYTES: usize = 4096;
            pub const MAX_TOTAL_BATCH_BYTES: usize =
                Self::MAX_BATCH_ITEMS * Self::MAX_ITEM_BYTES;
        }
    }

    pub mod alpha_002_error_detection_system {
        #[derive(Debug, Clone)]
        pub enum ErrorDetection {
            MerkleProofGenerationError { reason: String },
            SerializationError { details: String },
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

#[path = "../../src/cryptography/ml_dsa_65_002_merkleproof.rs"]
mod ml_dsa_65_002_merkleproof;

use ml_dsa_65_002_merkleproof::{
    compute_merkle_root, deserialize_merkle_proof, generate_merkle_proof,
    serialize_merkle_proof, verify_merkle_proof, MerkleProof,
};
use utility::alpha_002_error_detection_system::ErrorDetection;
use utility::helper::Hash64;

const MAX_TXS: usize = 64;
const MAX_TX_LEN: usize = 256;
const MAX_HASHES: usize = 96;

fn touch_error(error: &ErrorDetection) {
    match error {
        ErrorDetection::MerkleProofGenerationError { reason } => {
            let _ = reason.len();
        }
        ErrorDetection::SerializationError { details } => {
            let _ = details.len();
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

fn fuzz_hash(data: &[u8], salt: usize) -> [u8; 64] {
    let mut out = [0u8; 64];

    if data.is_empty() {
        out[0] = salt as u8;
        return out;
    }

    for i in 0..64 {
        let a = data[(i + salt) % data.len()];
        let b = data[(i * 7 + salt) % data.len()];
        out[i] = a ^ b ^ (i as u8).wrapping_add(salt as u8);
    }

    out
}

fn fuzz_hash64(data: &[u8], salt: usize) -> Hash64 {
    Hash64::from_bytes(fuzz_hash(data, salt))
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

    match data[0] % 6 {
        0 => buf.clear(),
        1 => {
            let new_len = byte_at(data, 1, 0) as usize % buf.len().saturating_add(1);
            buf.truncate(new_len);
        }
        2 => buf.push(byte_at(data, 1, 0)),
        3 => buf.extend_from_slice(data),
        4 => {
            if !buf.is_empty() {
                let idx = byte_at(data, 1, 0) as usize % buf.len();
                buf.remove(idx);
            }
        }
        _ => {}
    }

    buf
}

fn make_hashes(data: &[u8]) -> Vec<[u8; 64]> {
    if data.is_empty() {
        return Vec::new();
    }

    let count = data[0] as usize % (MAX_HASHES + 1);
    let mut hashes = Vec::with_capacity(count);

    for i in 0..count {
        hashes.push(fuzz_hash(data, i * 17));
    }

    hashes
}

fn make_txs(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return Vec::new();
    }

    let count = (data[0] as usize % MAX_TXS) + 1;
    let mut cursor = 1usize;
    let mut txs = Vec::with_capacity(count);

    for tx_index in 0..count {
        let len = byte_at(data, cursor, tx_index as u8) as usize % (MAX_TX_LEN + 1);
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

fn make_manual_proof(data: &[u8]) -> MerkleProof {
    let sibling_count = byte_at(data, 0, 0) as usize % 16;

    let path_count = match byte_at(data, 1, 0) % 3 {
        0 => sibling_count,
        1 => sibling_count.saturating_add(1),
        _ => sibling_count.saturating_sub(1),
    };

    let mut sibling_hashes = Vec::with_capacity(sibling_count);
    for i in 0..sibling_count {
        sibling_hashes.push(fuzz_hash64(data, i * 29));
    }

    let mut path = Vec::with_capacity(path_count);
    for i in 0..path_count {
        path.push((byte_at(data, i + 2, 0) & 1) == 1);
    }

    MerkleProof {
        transaction_hash: fuzz_hash64(data, 1001),
        sibling_hashes,
        path,
        merkle_root: fuzz_hash64(data, 2002),
    }
}

fn exercise_proof(proof: MerkleProof, data: &[u8]) {
    let embedded_root = *proof.merkle_root.as_bytes();

    let _ = verify_merkle_proof(&proof, &embedded_root);

    let mut wrong_root = embedded_root;
    mutate_bytes(&mut wrong_root, data, 7);
    let _ = verify_merkle_proof(&proof, &wrong_root);

    if let Some(encoded) = touch_result(serialize_merkle_proof(&proof)) {
        if let Some(decoded) = touch_result(deserialize_merkle_proof(&encoded)) {
            let decoded_root = *decoded.merkle_root.as_bytes();
            let _ = verify_merkle_proof(&decoded, &decoded_root);
        }

        let mut mutated = encoded.clone();
        mutate_bytes(&mut mutated, data, 11);
        let _ = touch_result(deserialize_merkle_proof(&mutated));

        let resized = mutate_length(encoded, data);
        let _ = touch_result(deserialize_merkle_proof(&resized));
    }

    let mut bad_path = proof.clone();
    bad_path.path.push(true);
    let _ = verify_merkle_proof(&bad_path, &embedded_root);
    let _ = touch_result(serialize_merkle_proof(&bad_path));

    let mut bad_siblings = proof.clone();
    if bad_siblings.sibling_hashes.is_empty() {
        bad_siblings.sibling_hashes.push(fuzz_hash64(data, 3030));
    } else {
        bad_siblings.sibling_hashes.pop();
    }
    let _ = verify_merkle_proof(&bad_siblings, &embedded_root);
    let _ = touch_result(serialize_merkle_proof(&bad_siblings));
}

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz raw postcard decode.
    if let Some(proof) = touch_result(deserialize_merkle_proof(data)) {
        exercise_proof(proof, data);
    }

    // 2. Fuzz compute_merkle_root with empty input and arbitrary hash lists.
    let _ = touch_result(compute_merkle_root(&[]));

    let hashes = make_hashes(data);
    if let Some((root, levels)) = touch_result(compute_merkle_root(&hashes)) {
        assert_eq!(root.len(), 64);
        assert!(!levels.is_empty());
        assert_eq!(levels.last().map(|level| level.len()), Some(1));
    }

    // 3. Over-cap hash list should reject cleanly.
    let over_cap_hashes = vec![
        fuzz_hash(data, 999);
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_BATCH_ITEMS + 1
    ];
    let _ = touch_result(compute_merkle_root(&over_cap_hashes));

    // 4. Empty batch proof generation should reject cleanly.
    let empty_batch: [&[u8]; 0] = [];
    let _ = touch_result(generate_merkle_proof(&empty_batch, data));

    // 5. Fuzz generated transaction batches.
    let txs = make_txs(data);
    let refs = make_refs(&txs);

    if !refs.is_empty() {
        let target_index = byte_at(data, 3, 0) as usize % refs.len();
        let target = refs[target_index];

        if let Some(proof) = touch_result(generate_merkle_proof(&refs, target)) {
            assert!(
                verify_merkle_proof(&proof, proof.merkle_root.as_bytes()),
                "generated Merkle proof must verify"
            );
            exercise_proof(proof, data);
        }

        let missing_target = b"definitely_missing_target_transaction";
        let _ = touch_result(generate_merkle_proof(&refs, missing_target));
    }

    // 6. Deterministic edge-case batches.
    let single: Vec<&[u8]> = vec![b"only_tx"];
    if let Some(proof) = touch_result(generate_merkle_proof(&single, b"only_tx")) {
        exercise_proof(proof, data);
    }

    let two: Vec<&[u8]> = vec![b"left_tx", b"right_tx"];
    if let Some(proof) = touch_result(generate_merkle_proof(&two, b"right_tx")) {
        exercise_proof(proof, data);
    }

    let odd: Vec<&[u8]> = vec![b"tx0", b"tx1", b"tx2", b"tx3", b"tx4"];
    if let Some(proof) = touch_result(generate_merkle_proof(&odd, b"tx4")) {
        exercise_proof(proof, data);
    }

    let dup: Vec<&[u8]> = vec![b"dup", b"dup", b"unique"];
    if let Some(proof) = touch_result(generate_merkle_proof(&dup, b"dup")) {
        exercise_proof(proof, data);
    }

    let empty_tx: Vec<&[u8]> = vec![b"", b"a", b"b"];
    if let Some(proof) = touch_result(generate_merkle_proof(&empty_tx, b"")) {
        exercise_proof(proof, data);
    }

    // 7. Oversized target and oversized item should reject cleanly.
    let oversized_target = vec![
        0xAB;
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_ITEM_BYTES + 1
    ];
    let small_batch: Vec<&[u8]> = vec![b"small"];
    let _ = touch_result(generate_merkle_proof(&small_batch, &oversized_target));

    let oversized_item = vec![
        0xCD;
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_ITEM_BYTES + 1
    ];
    let oversized_batch: Vec<&[u8]> = vec![oversized_item.as_slice()];
    let _ = touch_result(generate_merkle_proof(&oversized_batch, oversized_item.as_slice()));

    // 8. Manually malformed proof.
    let manual = make_manual_proof(data);
    exercise_proof(manual, data);
});