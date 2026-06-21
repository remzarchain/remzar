#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            // Must match Cryption constants.
            pub const SALT_SIZE: usize = 16;
            pub const NONCE_SIZE: usize = 12;

            // Fuzz-safe but still large enough for:
            // - raw ML-DSA-65 secret bytes: 4032
            // - hex ML-DSA-65 secret string: 8064
            pub const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;

            // Large enough for salt + nonce + ciphertext/tag + fuzz-generated payloads.
            pub const MAX_ENCRYPTED_BLOB_BYTES: usize = 64 * 1024;

            // Fuzz-safe Argon2 settings.
            // These still exercise real Argon2id key derivation without making fuzzing crawl.
            pub const ARGON2_MEMORY_KIB: u32 = 32;
            pub const ARGON2_TIME_COST: u32 = 1;
            pub const ARGON2_LANES: u32 = 1;
        }
    }

    pub mod alpha_002_error_detection_system {
        #[derive(Debug, Clone)]
        pub enum ErrorDetection {
            EncryptionError {
                message: String,
            },
            DecryptionError {
                message: String,
            },
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
        }
    }
}

#[path = "../../src/cryptography/ml_dsa_65_005_encryption.rs"]
mod ml_dsa_65_005_encryption;

use ml_dsa_65_005_encryption::Cryption;
use utility::alpha_002_error_detection_system::ErrorDetection;

const MAX_SMALL_PLAINTEXT: usize = 512;
const MAX_LARGE_PLAINTEXT: usize = Cryption::ML_DSA_65_SECRET_BYTES;
const HEX_SECRET_LEN: usize = Cryption::ML_DSA_65_SECRET_HEX_CHARS;

fn touch_error(error: &ErrorDetection) {
    match error {
        ErrorDetection::EncryptionError { message } => {
            let _ = message.len();
        }
        ErrorDetection::DecryptionError { message } => {
            let _ = message.len();
        }
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            if let Some(id) = tx_id {
                let _ = id.len();
            }
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

fn fill_repeated(data: &[u8], len: usize, salt: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    if data.is_empty() {
        out.resize(len, salt);
        return out;
    }

    for i in 0..len {
        let a = byte_at(data, i, salt);
        let b = byte_at(data, i.wrapping_mul(7).wrapping_add(3), salt.rotate_left(1));
        out.push(a ^ b ^ salt ^ (i as u8));
    }

    out
}

fn make_private_key_bytes(data: &[u8]) -> Vec<u8> {
    match byte_at(data, 0, 0) % 8 {
        // Invalid: empty plaintext.
        0 => Vec::new(),

        // Tiny valid payload.
        1 => fill_repeated(data, 1, 0x11),

        // Small bounded arbitrary payload.
        2 => {
            let len = (byte_at(data, 1, 0) as usize % MAX_SMALL_PLAINTEXT) + 1;
            fill_repeated(data, len, 0x22)
        }

        // Real roadmap size: raw ML-DSA-65 secret bytes.
        3 => fill_repeated(data, Cryption::ML_DSA_65_SECRET_BYTES, 0x33),

        // Near the real raw secret size.
        4 => {
            let delta = byte_at(data, 1, 0) as usize % 64;
            let len = Cryption::ML_DSA_65_SECRET_BYTES.saturating_sub(delta).max(1);
            fill_repeated(data, len, 0x44)
        }

        // Larger but still below fuzz config cap.
        5 => {
            let len = MAX_LARGE_PLAINTEXT;
            fill_repeated(data, len, 0x55)
        }

        // Mostly UTF-8-like bytes to also feed decrypt_private_key string path.
        6 => make_private_key_string(data).into_bytes(),

        // Direct data slice, bounded and never empty unless input is empty.
        _ => {
            let len = data.len().min(MAX_SMALL_PLAINTEXT);
            if len == 0 {
                Vec::new()
            } else {
                data[..len].to_vec()
            }
        }
    }
}

fn make_passphrase(data: &[u8]) -> String {
    match byte_at(data, 2, 0) % 8 {
        // Invalid cases.
        0 => String::new(),
        1 => "     ".to_string(),

        // Stable valid passphrases.
        2 => "remzar-fuzz-passphrase".to_string(),
        3 => "correct horse battery staple remzar".to_string(),

        // Fuzz-derived printable ASCII passphrase.
        _ => {
            let len = (byte_at(data, 3, 0) as usize % 96) + 1;
            let mut s = String::with_capacity(len);

            for i in 0..len {
                let raw = byte_at(data, i.wrapping_add(4), 0x41);
                let printable = 33u8.wrapping_add(raw % 94);
                s.push(char::from(printable));
            }

            s
        }
    }
}

fn make_wrong_passphrase(passphrase: &str, data: &[u8]) -> String {
    let mut wrong = String::from("wrong-remzar-fuzz-passphrase-");

    for i in 0usize..8usize {
        let b = byte_at(data, i.wrapping_add(9), i as u8);
        let c = char::from(33u8.wrapping_add(b % 94));
        wrong.push(c);
    }

    if wrong == passphrase {
        wrong.push('x');
    }

    wrong
}

fn make_private_key_string(data: &[u8]) -> String {
    match byte_at(data, 4, 0) % 7 {
        // Invalid string plaintexts.
        0 => String::new(),
        1 => "   ".to_string(),

        // Normal valid strings.
        2 => "remzar-private-key-fuzz-string".to_string(),
        3 => "0123456789abcdef".repeat(16),

        // Real roadmap size: hex-encoded ML-DSA-65 secret string length = 8064.
        4 => {
            let mut s = String::with_capacity(HEX_SECRET_LEN);
            for i in 0..HEX_SECRET_LEN {
                let b = byte_at(data, i.wrapping_add(13), i as u8);
                let nibble = b % 16;
                let c = match nibble {
                    0..=9 => char::from(b'0' + nibble),
                    _ => char::from(b'a' + (nibble - 10)),
                };
                s.push(c);
            }
            s
        }

        // Bounded printable ASCII string.
        _ => {
            let len = (byte_at(data, 5, 0) as usize % MAX_SMALL_PLAINTEXT) + 1;
            let mut s = String::with_capacity(len);

            for i in 0..len {
                let b = byte_at(data, i.wrapping_add(17), 0x52);
                let printable = 32u8.wrapping_add(b % 95);
                s.push(char::from(printable));
            }

            s
        }
    }
}

fn mutate_bytes(buf: &mut [u8], data: &[u8], salt: usize) {
    if buf.is_empty() {
        return;
    }

    if data.is_empty() {
        let idx = salt % buf.len();
        buf[idx] ^= 0xA5;
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
    match byte_at(data, 6, 0) % 7 {
        0 => {
            buf.clear();
        }
        1 => {
            let new_len = byte_at(data, 7, 0) as usize % buf.len().saturating_add(1);
            buf.truncate(new_len);
        }
        2 => {
            buf.push(byte_at(data, 8, 0));
        }
        3 => {
            buf.extend_from_slice(data);
        }
        4 => {
            if !buf.is_empty() {
                let idx = byte_at(data, 9, 0) as usize % buf.len();
                buf.remove(idx);
            }
        }
        5 => {
            let extra = byte_at(data, 10, 0) as usize % 64;
            for i in 0..extra {
                buf.push(byte_at(data, i.wrapping_add(11), i as u8));
            }
        }
        _ => {}
    }

    buf
}

fn make_blob_with_layout(data: &[u8]) -> Vec<u8> {
    let ciphertext_len = byte_at(data, 12, 0) as usize % 128;
    let total_len = Cryption::SALT_BYTES + Cryption::NONCE_BYTES + ciphertext_len;

    fill_repeated(data, total_len, 0xC7)
}

fn exercise_hashing(data: &[u8]) {
    let h1 = Cryption::compute_core_hash(data);
    let h2 = Cryption::compute_core_hash(data);

    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);

    let derived = fill_repeated(data, byte_at(data, 13, 0) as usize % 1024, 0x64);
    let h3 = Cryption::compute_core_hash(&derived);
    let h4 = Cryption::compute_core_hash(&derived);

    assert_eq!(h3, h4);
    assert_eq!(h3.len(), 64);
}

fn exercise_bytes_api(data: &[u8]) {
    let private_key_bytes = make_private_key_bytes(data);
    let passphrase = make_passphrase(data);
    let wrong_passphrase = make_wrong_passphrase(&passphrase, data);

    if let Some(encrypted) =
        touch_result(Cryption::encrypt_private_key_bytes(&private_key_bytes, &passphrase))
    {
        let min_expected = Cryption::SALT_BYTES
            .saturating_add(Cryption::NONCE_BYTES)
            .saturating_add(Cryption::GCM_TAG_BYTES)
            .saturating_add(private_key_bytes.len());

        assert!(encrypted.len() >= min_expected);

        if let Some(decrypted) =
            touch_result(Cryption::decrypt_private_key_bytes(&encrypted, &passphrase))
        {
            assert_eq!(decrypted, private_key_bytes);
        }

        // Wrong passphrase should be handled cleanly.
        let _ = touch_result(Cryption::decrypt_private_key_bytes(
            &encrypted,
            &wrong_passphrase,
        ));

        // Mutated salt/nonce/ciphertext/tag should never panic.
        let mut mutated = encrypted.clone();
        mutate_bytes(&mut mutated, data, 19);
        let _ = touch_result(Cryption::decrypt_private_key_bytes(&mutated, &passphrase));

        // Truncated/extended/cleared encrypted blobs should reject cleanly.
        let resized = mutate_length(encrypted.clone(), data);
        let _ = touch_result(Cryption::decrypt_private_key_bytes(&resized, &passphrase));

        // Legacy string decrypt over arbitrary byte plaintext should either:
        // - return the original UTF-8 string if plaintext was valid UTF-8, or
        // - return a clean validation/decryption error.
        if let Some(as_string) = touch_result(Cryption::decrypt_private_key(&encrypted, &passphrase))
        {
            if let Ok(expected) = String::from_utf8(private_key_bytes.clone()) {
                assert_eq!(as_string, expected);
            }
        }
    }

    // Raw fuzz bytes as encrypted blob.
    let _ = touch_result(Cryption::decrypt_private_key_bytes(data, &passphrase));

    // Layout-shaped but unauthenticated blob.
    let layout_blob = make_blob_with_layout(data);
    let _ = touch_result(Cryption::decrypt_private_key_bytes(
        &layout_blob,
        &passphrase,
    ));

    // Length-mutated layout blob.
    let resized_layout_blob = mutate_length(layout_blob, data);
    let _ = touch_result(Cryption::decrypt_private_key_bytes(
        &resized_layout_blob,
        &passphrase,
    ));
}

fn exercise_string_api(data: &[u8]) {
    let private_key = make_private_key_string(data);
    let passphrase = make_passphrase(data);
    let wrong_passphrase = make_wrong_passphrase(&passphrase, data);

    if let Some(encrypted) = touch_result(Cryption::encrypt_private_key(&private_key, &passphrase)) {
        let min_expected = Cryption::SALT_BYTES
            .saturating_add(Cryption::NONCE_BYTES)
            .saturating_add(Cryption::GCM_TAG_BYTES)
            .saturating_add(private_key.as_bytes().len());

        assert!(encrypted.len() >= min_expected);

        if let Some(decrypted) = touch_result(Cryption::decrypt_private_key(&encrypted, &passphrase))
        {
            assert_eq!(decrypted, private_key);
        }

        if let Some(decrypted_bytes) =
            touch_result(Cryption::decrypt_private_key_bytes(&encrypted, &passphrase))
        {
            assert_eq!(decrypted_bytes, private_key.as_bytes());
        }

        // Wrong passphrase should reject cleanly.
        let _ = touch_result(Cryption::decrypt_private_key(
            &encrypted,
            &wrong_passphrase,
        ));

        // Mutated encrypted string blob should never panic.
        let mut mutated = encrypted.clone();
        mutate_bytes(&mut mutated, data, 29);
        let _ = touch_result(Cryption::decrypt_private_key(&mutated, &passphrase));

        // Truncated/extended encrypted string blob should reject cleanly.
        let resized = mutate_length(encrypted, data);
        let _ = touch_result(Cryption::decrypt_private_key(&resized, &passphrase));
    }

    // Raw fuzz bytes into legacy string decrypt.
    let _ = touch_result(Cryption::decrypt_private_key(data, &passphrase));
}

fuzz_target!(|data: &[u8]| {
    exercise_hashing(data);
    exercise_bytes_api(data);
    exercise_string_api(data);
});