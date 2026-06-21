#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Serialize;

mod utility {
    pub mod alpha_002_error_detection_system {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
        }
    }

    pub mod hash_system_remzarhash {
        pub use crate::real_hash_system_remzarhash::*;
    }
}

#[path = "../../src/utility/hash_system_remzarhash.rs"]
mod real_hash_system_remzarhash;

use utility::hash_system_remzarhash::RemzarHash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SamplePayload {
    tag: u8,
    counter: u64,
    flag: bool,
    bytes: Vec<u8>,
    nested: Vec<Vec<u8>>,
}

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for i in 0..8 {
        out[i] = byte_at(data, offset + i, i as u8);
    }

    u64::from_le_bytes(out)
}

fn array64_from_data(data: &[u8], salt: usize) -> [u8; 64] {
    let mut out = [0u8; 64];

    for i in 0..64 {
        let a = byte_at(data, salt.wrapping_add(i), i as u8);
        let b = byte_at(
            data,
            salt.wrapping_add(i.wrapping_mul(17)),
            i.wrapping_mul(3) as u8,
        );

        out[i] = a ^ b ^ (salt as u8).wrapping_add(i as u8);
    }

    out
}

fn make_payload(data: &[u8], salt: usize) -> SamplePayload {
    let byte_len = byte_at(data, salt, 0) as usize % 256;
    let mut bytes = Vec::with_capacity(byte_len);

    for i in 0..byte_len {
        bytes.push(byte_at(data, salt + 1 + i, i as u8) ^ (salt as u8));
    }

    let nested_count = byte_at(data, salt + 300, 0) as usize % 8;
    let mut nested = Vec::with_capacity(nested_count);
    let mut cursor = salt + 301;

    for outer in 0..nested_count {
        let len = byte_at(data, cursor, outer as u8) as usize % 128;
        cursor = cursor.wrapping_add(1);

        let mut item = Vec::with_capacity(len);
        for inner in 0..len {
            item.push(
                byte_at(data, cursor + inner, inner as u8)
                    .wrapping_add(outer as u8)
                    ^ (salt as u8),
            );
        }

        cursor = cursor.wrapping_add(len);
        nested.push(item);
    }

    SamplePayload {
        tag: byte_at(data, salt + 500, 0),
        counter: read_u64(data, salt + 501),
        flag: byte_at(data, salt + 509, 0) & 1 == 1,
        bytes,
        nested,
    }
}

fn make_payloads(data: &[u8]) -> Vec<SamplePayload> {
    let count = (byte_at(data, 700, 1) as usize % 8) + 1;

    (0..count)
        .map(|i| make_payload(data, 800 + i * 997))
        .collect()
}

fn make_transactions(data: &[u8]) -> Vec<Vec<u8>> {
    let count = byte_at(data, 10_000, 0) as usize % 12;
    let mut txs = Vec::with_capacity(count);
    let mut cursor = 10_001usize;

    for tx_index in 0..count {
        let len = byte_at(data, cursor, tx_index as u8) as usize % 256;
        cursor = cursor.wrapping_add(1);

        let mut tx = Vec::with_capacity(len);
        for j in 0..len {
            tx.push(
                byte_at(data, cursor + j, j as u8)
                    .wrapping_add(tx_index as u8)
                    ^ 0xA5,
            );
        }

        cursor = cursor.wrapping_add(len);
        txs.push(tx);
    }

    txs
}

fn reference_xof64_bytes(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn reference_xof64_hex(bytes: &[u8]) -> String {
    hex::encode(reference_xof64_bytes(bytes))
}

fn reference_merkle_root_hex(txs: &[Vec<u8>]) -> String {
    let mut hasher = blake3::Hasher::new();

    if txs.is_empty() {
        hasher.update(b"EMPTY_MERKLE_ROOT");
    } else {
        for tx in txs {
            let encoded = postcard::to_allocvec(tx).expect("Vec<u8> serialization must not fail");
            hasher.update(&encoded);
        }
    }

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);
    hex::encode(out)
}

fn assert_lower_hex_len(value: &str, expected_len: usize) {
    assert_eq!(
        value.len(),
        expected_len,
        "unexpected hex length for value {value:?}"
    );

    assert!(
        value
            .as_bytes()
            .iter()
            .all(|b| matches!(*b, b'0'..=b'9' | b'a'..=b'f')),
        "value is not lowercase hex: {value:?}"
    );
}

fn mutate_valid_hex(value: &str, data: &[u8], salt: usize) -> String {
    let mut bytes = value.as_bytes().to_vec();

    if !bytes.is_empty() {
        let index = byte_at(data, salt, 0) as usize % bytes.len();

        bytes[index] = match bytes[index] {
            b'0' => b'1',
            b'1' => b'2',
            b'2' => b'3',
            b'3' => b'4',
            b'4' => b'5',
            b'5' => b'6',
            b'6' => b'7',
            b'7' => b'8',
            b'8' => b'9',
            b'9' => b'a',
            b'a' => b'b',
            b'b' => b'c',
            b'c' => b'd',
            b'd' => b'e',
            b'e' => b'f',
            b'f' => b'0',
            _ => b'0',
        };
    }

    String::from_utf8(bytes).expect("hex mutation must remain valid utf8")
}

fn expect_ok<T, E: core::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context} returned unexpected error: {error:?}"),
    }
}

fn exercise_raw_hashing(data: &[u8]) {
    let raw = RemzarHash::compute_bytes_hash(data);
    let hexed = RemzarHash::compute_bytes_hash_hex(data);

    assert_eq!(raw.len(), 64);
    assert_eq!(raw, reference_xof64_bytes(data));
    assert_eq!(hexed, hex::encode(raw));
    assert_eq!(hexed, reference_xof64_hex(data));
    assert_lower_hex_len(&hexed, 128);
}

fn exercise_data_hashing(data: &[u8]) {
    let payload = make_payload(data, 0);

    let hash = expect_ok(
        RemzarHash::compute_data_hash(&payload),
        "compute_data_hash",
    );

    let encoded = postcard::to_allocvec(&payload).expect("SamplePayload serialization must not fail");
    let reference = reference_xof64_hex(&encoded);

    assert_eq!(hash, reference);
    assert_lower_hex_len(&hash, 128);

    let verified = expect_ok(
        RemzarHash::verify_data_hash(&payload, &hash),
        "verify_data_hash exact",
    );
    assert!(verified, "payload must verify against its own hash");

    let wrong_valid_hash = mutate_valid_hex(&hash, data, 31);
    let wrong_verified = expect_ok(
        RemzarHash::verify_data_hash(&payload, &wrong_valid_hash),
        "verify_data_hash wrong-valid",
    );
    assert!(
        !wrong_verified,
        "payload must not verify against a different valid hash"
    );

    assert!(RemzarHash::verify_data_hash(&payload, &"0".repeat(127)).is_err());
    assert!(RemzarHash::verify_data_hash(&payload, &"0".repeat(129)).is_err());
    assert!(RemzarHash::verify_data_hash(&payload, &"g".repeat(128)).is_err());

    let fuzz_expected = String::from_utf8_lossy(data).to_string();
    let _ = RemzarHash::verify_data_hash(&payload, &fuzz_expected);
}

fn exercise_data_hash_batches(data: &[u8]) {
    let items = make_payloads(data);

    let batch = expect_ok(
        RemzarHash::compute_data_hash_batch(&items),
        "compute_data_hash_batch",
    );

    assert_eq!(batch.len(), items.len());

    for (item, hash) in items.iter().zip(batch.iter()) {
        assert_lower_hex_len(hash, 128);

        let individual = expect_ok(
            RemzarHash::compute_data_hash(item),
            "compute_data_hash individual",
        );

        assert_eq!(*hash, individual);
    }

    let verified = expect_ok(
        RemzarHash::verify_data_hash_batch(&items, &batch),
        "verify_data_hash_batch exact",
    );

    assert_eq!(verified.len(), items.len());
    assert!(verified.iter().all(|ok| *ok));

    let mut wrong = batch.clone();
    wrong[0] = mutate_valid_hex(&wrong[0], data, 71);

    let wrong_verified = expect_ok(
        RemzarHash::verify_data_hash_batch(&items, &wrong),
        "verify_data_hash_batch wrong-valid",
    );

    assert_eq!(wrong_verified.len(), items.len());
    assert!(!wrong_verified[0]);

    let mut bad_hex = batch.clone();
    bad_hex[0] = "z".repeat(128);
    assert!(RemzarHash::verify_data_hash_batch(&items, &bad_hex).is_err());

    let mut wrong_len = batch.clone();
    wrong_len.pop();
    assert!(RemzarHash::verify_data_hash_batch(&items, &wrong_len).is_err());

    let empty: Vec<SamplePayload> = Vec::new();
    assert!(RemzarHash::compute_data_hash_batch(&empty).is_err());
}

fn exercise_truncated_hashing(data: &[u8]) {
    let payload = make_payload(data, 2_000);

    let truncated = expect_ok(
        RemzarHash::compute_truncated_hash(&payload),
        "compute_truncated_hash",
    );

    assert_lower_hex_len(&truncated, 16);

    let encoded = postcard::to_allocvec(&payload).expect("SamplePayload serialization must not fail");
    let full_reference = reference_xof64_bytes(&encoded);
    let truncated_reference = hex::encode(&full_reference[..8]);

    assert_eq!(truncated, truncated_reference);

    let verified = expect_ok(
        RemzarHash::verify_truncated_hash(&payload, &truncated),
        "verify_truncated_hash exact",
    );
    assert!(verified);

    let wrong_valid = mutate_valid_hex(&truncated, data, 101);
    let wrong_verified = expect_ok(
        RemzarHash::verify_truncated_hash(&payload, &wrong_valid),
        "verify_truncated_hash wrong-valid",
    );
    assert!(!wrong_verified);

    assert!(RemzarHash::verify_truncated_hash(&payload, &"0".repeat(15)).is_err());
    assert!(RemzarHash::verify_truncated_hash(&payload, &"0".repeat(17)).is_err());
    assert!(RemzarHash::verify_truncated_hash(&payload, &"g".repeat(16)).is_err());

    let items = make_payloads(data);

    let batch = expect_ok(
        RemzarHash::compute_truncated_hash_batch(&items),
        "compute_truncated_hash_batch",
    );

    assert_eq!(batch.len(), items.len());

    for hash in &batch {
        assert_lower_hex_len(hash, 16);
    }

    let verified_batch = expect_ok(
        RemzarHash::verify_truncated_hash_batch(&items, &batch),
        "verify_truncated_hash_batch exact",
    );

    assert_eq!(verified_batch.len(), items.len());
    assert!(verified_batch.iter().all(|ok| *ok));

    let empty: Vec<SamplePayload> = Vec::new();
    assert!(RemzarHash::compute_truncated_hash_batch(&empty).is_err());
}

fn exercise_merkle_root(data: &[u8]) {
    let txs = make_transactions(data);

    let merkle = expect_ok(
        RemzarHash::compute_merkle_root(&txs),
        "compute_merkle_root",
    );

    assert_lower_hex_len(&merkle, 128);
    assert_eq!(merkle, reference_merkle_root_hex(&txs));

    if txs.len() == 1 {
        let single_data_hash = expect_ok(
            RemzarHash::compute_data_hash(&txs[0]),
            "compute_data_hash single tx",
        );

        assert_eq!(merkle, single_data_hash);
    }

    let empty: Vec<Vec<u8>> = Vec::new();
    let empty_merkle = expect_ok(
        RemzarHash::compute_merkle_root(&empty),
        "compute_merkle_root empty",
    );

    assert_lower_hex_len(&empty_merkle, 128);
    assert_eq!(empty_merkle, reference_merkle_root_hex(&empty));
}

fn exercise_header_hashing(data: &[u8]) {
    let prev = array64_from_data(data, 3_000);
    let merkle = array64_from_data(data, 4_000);
    let nonce = read_u64(data, 5_000);

    let bytes = RemzarHash::compute_header_hash_bytes(&prev, &merkle, nonce);
    let hexed = RemzarHash::compute_header_hash_hex(&prev, &merkle, nonce);

    assert_eq!(bytes.len(), 64);
    assert_eq!(hexed, hex::encode(bytes));
    assert_lower_hex_len(&hexed, 128);

    assert!(RemzarHash::verify_header_hash(
        &prev, &merkle, nonce, &hexed
    ));

    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce.wrapping_add(1),
        &hexed
    ));

    let mut wrong_prev = prev;
    wrong_prev[0] ^= 0x01;

    assert!(!RemzarHash::verify_header_hash(
        &wrong_prev,
        &merkle,
        nonce,
        &hexed
    ));

    let mut wrong_merkle = merkle;
    wrong_merkle[0] ^= 0x01;

    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &wrong_merkle,
        nonce,
        &hexed
    ));

    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce,
        &"0".repeat(127)
    ));

    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce,
        &"0".repeat(129)
    ));

    assert!(!RemzarHash::verify_header_hash(
        &prev,
        &merkle,
        nonce,
        &"z".repeat(128)
    ));
}

fn exercise_header_struct_hashing(data: &[u8]) {
    let payload = make_payload(data, 6_000);
    let nonce = byte_at(data, 7_000, 0);

    let got = expect_ok(
        RemzarHash::compute_header_struct_hash_hex(&payload, nonce),
        "compute_header_struct_hash_hex",
    );

    assert_lower_hex_len(&got, 128);

    let encoded = postcard::to_allocvec(&payload).expect("SamplePayload serialization must not fail");

    let mut hasher = blake3::Hasher::new();
    hasher.update(&encoded);
    hasher.update(&[nonce]);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    assert_eq!(got, hex::encode(out));
}

fn exercise_dummy_and_genesis(data: &[u8]) {
    let dummy = RemzarHash::compute_dummy_hash();

    assert_lower_hex_len(&dummy, 128);
    assert_eq!(
        dummy,
        RemzarHash::compute_bytes_hash_hex(b"remzar_empty_block_mint")
    );

    let genesis = RemzarHash::compute_genesis_hash();
    let expected_genesis = RemzarHash::compute_bytes_hash(&[0u8; 64]);

    assert_eq!(genesis.len(), 64);
    assert_eq!(genesis, expected_genesis);

    let ts = read_u64(data, 8_000);
    let with_ts = RemzarHash::compute_genesis_hash_with_ts(ts);

    let mut preimage = Vec::with_capacity(72);
    preimage.extend_from_slice(&[0u8; 64]);
    preimage.extend_from_slice(&ts.to_be_bytes());

    assert_eq!(with_ts.len(), 64);
    assert_eq!(with_ts, RemzarHash::compute_bytes_hash(&preimage));
}

fuzz_target!(|data: &[u8]| {
    exercise_raw_hashing(data);
    exercise_data_hashing(data);
    exercise_data_hash_batches(data);
    exercise_truncated_hashing(data);
    exercise_merkle_root(data);
    exercise_header_hashing(data);
    exercise_header_struct_hashing(data);
    exercise_dummy_and_genesis(data);
});