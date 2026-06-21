#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

mod utility {
    pub mod alpha_002_error_detection_system {
        #[derive(Debug, Clone)]
        pub enum ErrorDetection {
            CryptographicError { message: String },
            SerializationError { details: String },
            InvalidSignatureFormat { format: String },
        }
    }
}

#[path = "../../src/cryptography/ml_dsa_65_001_keypairs.rs"]
mod ml_dsa_65_001_keypairs;

use ml_dsa_65_001_keypairs::MlDsa65Keypair;
use utility::alpha_002_error_detection_system::ErrorDetection;

const DEBUG_PREFIX_CHECK_LEN: usize = 16;
const SHORT_REGRESSION_ARTIFACT: [u8; 5] = [226, 99, 255, 59, 208];

const MALFORMED_SECRET_SEED_A: &[u8] = &[
    0xe2, 0xb0, 0xfa, 0xff, 0xff, 0xa0, 0x01, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0x1b, 0x08,
    0x00, 0x00, 0xfe, 0xf6, 0xff, 0xff, 0x8c, 0x03, 0x00, 0x00, 0x52, 0x04, 0x00, 0x00, 0x9d,
    0xfc, 0xff, 0xff, 0xd6, 0xfc, 0xff, 0xff, 0xbf, 0x02, 0x00, 0x00, 0x60, 0xfe, 0xff, 0xff,
    0x40, 0x0f, 0x00, 0x00, 0xef, 0x0e, 0x00, 0x00, 0x66, 0x06, 0x00, 0x00, 0x94, 0x05, 0x00,
    0x94, 0x05, 0x00, 0x00, 0x64, 0xfe, 0xff, 0xff, 0x00, 0x64, 0xfe, 0xff, 0xff, 0x00, 0x26,
    0xee,
];

const MALFORMED_SECRET_SEED_B: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfb,
];

struct ValidMaterial {
    raw: Vec<u8>,
    canonical: Vec<u8>,
    secret: [u8; MlDsa65Keypair::SECRET_LEN],
    public: [u8; MlDsa65Keypair::PUBLIC_LEN],
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

fn repeat_seed_to_array<const N: usize>(seed: &[u8], shift: usize) -> [u8; N] {
    let mut out = [0u8; N];

    if seed.is_empty() {
        return out;
    }

    for i in 0..N {
        out[i] = seed[(i + shift) % seed.len()];
    }

    out
}

fn mutate_bytes(buf: &mut [u8], data: &[u8], salt: usize) {
    if buf.is_empty() || data.is_empty() {
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
        return buf;
    }

    match data[0] % 12 {
        0 => {
            let new_len =
                data.get(1).copied().unwrap_or(0) as usize % buf.len().saturating_add(1);
            buf.truncate(new_len);
        }
        1 => {
            buf.push(data.get(1).copied().unwrap_or(0));
        }
        2 => {
            let extension_len = data.len().min(64);
            buf.extend_from_slice(&data[..extension_len]);
        }
        3 => {
            if !buf.is_empty() {
                let idx = data.get(1).copied().unwrap_or(0) as usize % buf.len();
                buf.remove(idx);
            }
        }
        4 => {
            let remove = ((data.get(1).copied().unwrap_or(0) as usize) % 16) + 1;
            let new_len = buf.len().saturating_sub(remove);
            buf.truncate(new_len);
        }
        5 => {
            buf.truncate(MlDsa65Keypair::SECRET_LEN.saturating_sub(1));
        }
        6 => {
            buf.truncate(MlDsa65Keypair::SECRET_LEN);
        }
        7 => {
            buf.truncate(MlDsa65Keypair::SECRET_LEN.saturating_add(1));
        }
        8 => {
            buf.truncate(MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_sub(1));
        }
        9 => {
            buf.resize(
                MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_add(1),
                data.get(1).copied().unwrap_or(0),
            );
        }
        10 => {
            buf.truncate(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_sub(1));
        }
        _ => {
            buf.resize(
                MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(1),
                data.get(1).copied().unwrap_or(0),
            );
        }
    }

    buf
}

fn with_valid_canonical_header(
    mut buf: [u8; MlDsa65Keypair::CANONICAL_SERIALIZED_LEN],
) -> [u8; MlDsa65Keypair::CANONICAL_SERIALIZED_LEN] {
    buf[0..4].copy_from_slice(&MlDsa65Keypair::CANONICAL_MAGIC);
    buf[4] = MlDsa65Keypair::CANONICAL_VERSION;
    buf[5] = MlDsa65Keypair::CANONICAL_FLAGS;
    buf[6..8].copy_from_slice(&MlDsa65Keypair::CANONICAL_RESERVED);
    buf
}

fn valid_material() -> Option<&'static ValidMaterial> {
    static VALID: OnceLock<Option<ValidMaterial>> = OnceLock::new();

    VALID
        .get_or_init(|| {
            let kp = MlDsa65Keypair::generate().ok()?;

            let secret = kp.to_bytes();
            let public = kp.public_key_bytes();
            let raw = kp.serialize().ok()?;
            let canonical = kp.serialize_canonical().ok()?;

            Some(ValidMaterial {
                raw,
                canonical,
                secret,
                public,
            })
        })
        .as_ref()
}

fn assert_static_contracts() {
    assert_eq!(
        MlDsa65Keypair::SERIALIZED_LEN,
        MlDsa65Keypair::RAW_SERIALIZED_LEN
    );
    assert_eq!(
        MlDsa65Keypair::RAW_SERIALIZED_LEN,
        MlDsa65Keypair::SECRET_LEN + MlDsa65Keypair::PUBLIC_LEN
    );
    assert_eq!(MlDsa65Keypair::CANONICAL_HEADER_LEN, 8);
    assert_eq!(
        MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
        MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::RAW_SERIALIZED_LEN
    );
    assert_eq!(MlDsa65Keypair::CANONICAL_MAGIC, *b"M65K");
    assert_eq!(MlDsa65Keypair::CANONICAL_VERSION, 1);
    assert_eq!(MlDsa65Keypair::CANONICAL_FLAGS, 0);
    assert_eq!(MlDsa65Keypair::CANONICAL_RESERVED, [0, 0]);
    assert!(MlDsa65Keypair::VALIDATE_INVARIANTS_BUDGET_MILLIS <= 2_000);
}

fn assert_debug_is_redacted(kp: &MlDsa65Keypair) {
    let debug = format!("{:?}", kp);
    assert!(debug.contains("MlDsa65Keypair"));
    assert!(debug.contains("REDACTED"));

    let mut secret = kp.to_bytes();
    let public = kp.public_key_bytes();

    let prefix_len = DEBUG_PREFIX_CHECK_LEN.min(secret.len()).min(public.len());

    let secret_prefix = format!("{:?}", &secret[..prefix_len]);
    let public_prefix = format!("{:?}", &public[..prefix_len]);

    assert!(
        !debug.contains(&secret_prefix),
        "Debug output leaked an ML-DSA-65 secret-key prefix"
    );
    assert!(
        !debug.contains(&public_prefix),
        "Debug output leaked an ML-DSA-65 public-key prefix"
    );

    secret.fill(0);
}

fn exercise_keypair_light(kp: MlDsa65Keypair) {
    assert_static_contracts();
    assert_debug_is_redacted(&kp);

    assert_eq!(kp.secret_bytes_ref().len(), MlDsa65Keypair::SECRET_LEN);
    assert_eq!(kp.public_bytes_ref().len(), MlDsa65Keypair::PUBLIC_LEN);
    assert_eq!(kp.secret_bytes_slice().len(), MlDsa65Keypair::SECRET_LEN);
    assert_eq!(kp.public_bytes_slice().len(), MlDsa65Keypair::PUBLIC_LEN);

    let mut secret_copy = kp.to_bytes();
    let public_copy = kp.public_key_bytes();

    assert_eq!(secret_copy.len(), MlDsa65Keypair::SECRET_LEN);
    assert_eq!(public_copy.len(), MlDsa65Keypair::PUBLIC_LEN);

    secret_copy.fill(0);

    if let Some(raw) = touch_result(kp.serialize()) {
        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);
    }

    if let Some(canonical) = touch_result(kp.serialize_canonical()) {
        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        assert_eq!(&canonical[0..4], &MlDsa65Keypair::CANONICAL_MAGIC);
        assert_eq!(canonical[4], MlDsa65Keypair::CANONICAL_VERSION);
        assert_eq!(canonical[5], MlDsa65Keypair::CANONICAL_FLAGS);
        assert_eq!(&canonical[6..8], &MlDsa65Keypair::CANONICAL_RESERVED);
    }
}

fn exercise_keypair_deep(kp: MlDsa65Keypair, data: &[u8]) {
    assert_static_contracts();
    assert_debug_is_redacted(&kp);

    let cloned = kp.clone();
    assert_debug_is_redacted(&cloned);
    let _ = touch_result(cloned.validate_self());
    drop(cloned);

    let _ = touch_result(kp.validate_self());
    let _ = touch_result(kp.get_signing_key());
    let _ = touch_result(kp.get_verifying_key());

    let mut secret_copy = kp.to_bytes();

    if let Some(from_secret_kp) = touch_result(MlDsa65Keypair::from_secret(secret_copy)) {
        let _ = touch_result(from_secret_kp.validate_self());
        assert_debug_is_redacted(&from_secret_kp);
    }

    secret_copy.fill(0);

    if let Some(raw) = touch_result(kp.serialize()) {
        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        if let Some(roundtrip) = touch_result(MlDsa65Keypair::deserialize(&raw)) {
            let _ = touch_result(roundtrip.validate_self());
            assert_debug_is_redacted(&roundtrip);
        }

        let mut mutated_raw = raw.clone();
        mutate_bytes(&mut mutated_raw, data, 11);
        if let Some(mutated_kp) = touch_result(MlDsa65Keypair::deserialize(&mutated_raw)) {
            let _ = touch_result(mutated_kp.validate_self());
            assert_debug_is_redacted(&mutated_kp);
        }

        let resized_raw = mutate_length(raw, data);
        let _ = touch_result(MlDsa65Keypair::deserialize(&resized_raw));
    }

    if let Some(canonical) = touch_result(kp.serialize_canonical()) {
        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        if let Some(roundtrip) = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical)) {
            let _ = touch_result(roundtrip.validate_self());
            assert_debug_is_redacted(&roundtrip);
        }

        let mut mutated_canonical = canonical.clone();
        mutate_bytes(&mut mutated_canonical, data, 23);
        if let Some(mutated_kp) =
            touch_result(MlDsa65Keypair::deserialize_canonical(&mutated_canonical))
        {
            let _ = touch_result(mutated_kp.validate_self());
            assert_debug_is_redacted(&mutated_kp);
        }

        let resized_canonical = mutate_length(canonical, data);
        let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&resized_canonical));
    }
}

fn exercise_generate_path() {
    if let Some(kp) = touch_result(MlDsa65Keypair::generate()) {
        exercise_keypair_light(kp);
    }
}

fn exercise_direct_inputs(data: &[u8]) {
    let _ = touch_result(MlDsa65Keypair::deserialize(data)).map(exercise_keypair_light);
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(data)).map(exercise_keypair_light);
}

fn exercise_exact_raw_from_fuzz(data: &[u8]) {
    if data.len() != MlDsa65Keypair::RAW_SERIALIZED_LEN {
        return;
    }

    let _ = touch_result(MlDsa65Keypair::deserialize(data)).map(exercise_keypair_light);

    let mut raw_short = data.to_vec();
    raw_short.pop();
    let _ = touch_result(MlDsa65Keypair::deserialize(&raw_short));

    let mut raw_long = data.to_vec();
    raw_long.push(data.first().copied().unwrap_or(0));
    let _ = touch_result(MlDsa65Keypair::deserialize(&raw_long));
}

fn exercise_exact_canonical_from_fuzz(data: &[u8]) {
    if data.len() != MlDsa65Keypair::CANONICAL_SERIALIZED_LEN {
        return;
    }

    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(data)).map(exercise_keypair_light);

    let mut canonical_with_valid_header = data.to_vec();
    canonical_with_valid_header[0..4].copy_from_slice(&MlDsa65Keypair::CANONICAL_MAGIC);
    canonical_with_valid_header[4] = MlDsa65Keypair::CANONICAL_VERSION;
    canonical_with_valid_header[5] = MlDsa65Keypair::CANONICAL_FLAGS;
    canonical_with_valid_header[6..8].copy_from_slice(&MlDsa65Keypair::CANONICAL_RESERVED);

    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(
        &canonical_with_valid_header,
    ))
    .map(exercise_keypair_light);
}

fn exercise_from_secret(data: &[u8]) {
    if data.len() != MlDsa65Keypair::SECRET_LEN {
        return;
    }

    let mut secret = [0u8; MlDsa65Keypair::SECRET_LEN];
    secret.copy_from_slice(data);

    let _ = touch_result(MlDsa65Keypair::from_secret(secret)).map(exercise_keypair_light);
}

fn exercise_canonical_header_rejections(data: &[u8]) {
    let canonical_base = with_valid_canonical_header(fill_from_fuzz::<{
        MlDsa65Keypair::CANONICAL_SERIALIZED_LEN
    }>(data));

    let mut canonical_bad_magic = canonical_base;
    canonical_bad_magic[0] ^= data.first().copied().unwrap_or(0xFF).wrapping_add(1);
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical_bad_magic));

    let mut canonical_bad_version = canonical_base;
    canonical_bad_version[4] = MlDsa65Keypair::CANONICAL_VERSION.wrapping_add(1);
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical_bad_version));

    let mut canonical_bad_flags = canonical_base;
    canonical_bad_flags[5] = MlDsa65Keypair::CANONICAL_FLAGS.wrapping_add(1);
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical_bad_flags));

    let mut canonical_bad_reserved = canonical_base;
    canonical_bad_reserved[6] = data.first().copied().unwrap_or(1).wrapping_add(1);
    canonical_bad_reserved[7] = data.get(1).copied().unwrap_or(1).wrapping_add(1);
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical_bad_reserved));
}

fn exercise_valid_material_light(data: &[u8]) {
    let Some(valid) = valid_material() else {
        return;
    };

    match data.first().copied().unwrap_or(0) % 3 {
        0 => {
            let _ = touch_result(MlDsa65Keypair::from_secret(valid.secret))
                .map(exercise_keypair_light);
        }
        1 => {
            let _ = touch_result(MlDsa65Keypair::deserialize(&valid.raw))
                .map(exercise_keypair_light);
        }
        _ => {
            let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&valid.canonical))
                .map(exercise_keypair_light);
        }
    }
}

fn exercise_valid_material_deep(data: &[u8]) {
    let Some(valid) = valid_material() else {
        return;
    };

    let Some(kp) = touch_result(MlDsa65Keypair::deserialize(&valid.raw)) else {
        return;
    };

    exercise_keypair_deep(kp, data);
}

fn exercise_valid_material_one_mutation(data: &[u8]) {
    let Some(valid) = valid_material() else {
        return;
    };

    if data.is_empty() {
        return;
    }

    match data[0] % 6 {
        0 => {
            let mut raw = valid.raw.clone();
            mutate_bytes(&mut raw, data, 37);
            let _ = touch_result(MlDsa65Keypair::deserialize(&raw)).map(exercise_keypair_light);
        }
        1 => {
            let mut raw = valid.raw.clone();
            mutate_bytes(&mut raw[..MlDsa65Keypair::SECRET_LEN], data, 41);
            let _ = touch_result(MlDsa65Keypair::deserialize(&raw));
        }
        2 => {
            let mut raw = valid.raw.clone();
            mutate_bytes(&mut raw[MlDsa65Keypair::SECRET_LEN..], data, 43);
            let _ = touch_result(MlDsa65Keypair::deserialize(&raw));
        }
        3 => {
            let mut canonical = valid.canonical.clone();
            mutate_bytes(&mut canonical, data, 47);
            let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical))
                .map(exercise_keypair_light);
        }
        4 => {
            let mut canonical = valid.canonical.clone();
            let header_len = MlDsa65Keypair::CANONICAL_HEADER_LEN;
            mutate_bytes(&mut canonical[..header_len], data, 53);
            let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical));
        }
        _ => {
            let mut canonical = valid.canonical.clone();
            mutate_bytes(
                &mut canonical[MlDsa65Keypair::CANONICAL_HEADER_LEN..],
                data,
                59,
            );
            let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical));
        }
    }
}

fn exercise_one_length_boundary(data: &[u8]) {
    let boundary_lengths = [
        0usize,
        1,
        2,
        3,
        4,
        5,
        7,
        8,
        16,
        25,
        32,
        63,
        MlDsa65Keypair::SECRET_LEN.saturating_sub(1),
        MlDsa65Keypair::SECRET_LEN,
        MlDsa65Keypair::SECRET_LEN.saturating_add(1),
        MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_sub(1),
        MlDsa65Keypair::RAW_SERIALIZED_LEN,
        MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_add(1),
        MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_sub(1),
        MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
        MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(1),
    ];

    let idx = data.first().copied().unwrap_or(0) as usize % boundary_lengths.len();
    let len = boundary_lengths[idx];
    let filler = data.get(1).copied().unwrap_or(0);

    let mut candidate = vec![filler; len];
    mutate_bytes(&mut candidate, data, len);

    let _ = touch_result(MlDsa65Keypair::deserialize(&candidate)).map(exercise_keypair_light);
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&candidate))
        .map(exercise_keypair_light);
}

fn exercise_tiny_inputs(data: &[u8]) {
    let tiny_lengths = [0usize, 1, 2, 3, 4, 5, 7, 8, 16, 25, 32, 63];

    let idx = data.first().copied().unwrap_or(0) as usize % tiny_lengths.len();
    let len = tiny_lengths[idx];

    let mut candidate = vec![0u8; len];
    mutate_bytes(&mut candidate, data, len.wrapping_add(101));

    let _ = touch_result(MlDsa65Keypair::deserialize(&candidate));
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&candidate));

    let _ = touch_result(MlDsa65Keypair::deserialize(&SHORT_REGRESSION_ARTIFACT));
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(
        &SHORT_REGRESSION_ARTIFACT,
    ));
}

fn exercise_short_regression_artifact() {
    let _ = touch_result(MlDsa65Keypair::deserialize(&SHORT_REGRESSION_ARTIFACT));
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(
        &SHORT_REGRESSION_ARTIFACT,
    ));
}

fn exercise_malformed_full_size_imports(data: &[u8]) {
    let Some(valid) = valid_material() else {
        return;
    };

    let shift_a = data.first().copied().unwrap_or(0) as usize % MALFORMED_SECRET_SEED_A.len();
    let shift_b = data.get(1).copied().unwrap_or(0) as usize % MALFORMED_SECRET_SEED_B.len();

    let malformed_secret_a =
        repeat_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(MALFORMED_SECRET_SEED_A, shift_a);
    let malformed_secret_b =
        repeat_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(MALFORMED_SECRET_SEED_B, shift_b);

    for malformed_secret in [malformed_secret_a, malformed_secret_b] {
        let _ = touch_result(MlDsa65Keypair::from_secret(malformed_secret));

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(malformed_secret.as_ref());
        raw.extend_from_slice(valid.public.as_ref());
        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);
        let _ = touch_result(MlDsa65Keypair::deserialize(&raw));

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(malformed_secret.as_ref());
        canonical.extend_from_slice(valid.public.as_ref());
        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&canonical));
    }

    let _ = touch_result(MlDsa65Keypair::deserialize(&valid.raw)).map(exercise_keypair_light);
}

fn exercise_serialization_pressure(data: &[u8]) {
    let Some(valid) = valid_material() else {
        return;
    };

    let Some(kp) = touch_result(MlDsa65Keypair::deserialize(&valid.raw)) else {
        return;
    };

    let rounds = ((data.first().copied().unwrap_or(0) as usize) % 4) + 1;

    for _ in 0..rounds {
        let _ = touch_result(kp.serialize());
        let _ = touch_result(kp.serialize_canonical());
    }
}

fn exercise_all_public_api_once(data: &[u8]) {
    let Some(valid) = valid_material() else {
        return;
    };

    exercise_short_regression_artifact();
    exercise_valid_material_light(data);
    exercise_valid_material_one_mutation(data);
    exercise_canonical_header_rejections(data);

    if let Some(kp) = touch_result(MlDsa65Keypair::deserialize(&valid.raw)) {
        assert_debug_is_redacted(&kp);
        let _ = touch_result(kp.validate_self());
        let _ = touch_result(kp.get_signing_key());
        let _ = touch_result(kp.get_verifying_key());
        let _ = touch_result(kp.serialize());
        let _ = touch_result(kp.serialize_canonical());
        let mut secret = kp.to_bytes();
        let public = kp.public_key_bytes();
        assert_eq!(secret.len(), MlDsa65Keypair::SECRET_LEN);
        assert_eq!(public.len(), MlDsa65Keypair::PUBLIC_LEN);
        secret.fill(0);
    }

    let _ = touch_result(MlDsa65Keypair::from_secret(valid.secret)).map(exercise_keypair_light);
    let _ = touch_result(MlDsa65Keypair::deserialize_canonical(&valid.canonical))
        .map(exercise_keypair_light);
}

fuzz_target!(|data: &[u8]| {
    assert_static_contracts();

    let selector = data.first().copied().unwrap_or(0);
    let payload = data.get(1..).unwrap_or(data);

    exercise_tiny_inputs(payload);

    if data == SHORT_REGRESSION_ARTIFACT {
        exercise_short_regression_artifact();
        exercise_malformed_full_size_imports(payload);
        return;
    }

    match selector % 16 {
        0 => exercise_direct_inputs(payload),
        1 => exercise_exact_raw_from_fuzz(payload),
        2 => exercise_exact_canonical_from_fuzz(payload),
        3 => exercise_canonical_header_rejections(payload),
        4 => exercise_from_secret(payload),
        5 => exercise_valid_material_light(payload),
        6 => exercise_valid_material_one_mutation(payload),
        7 => exercise_one_length_boundary(payload),
        8 => exercise_short_regression_artifact(),
        9 => exercise_serialization_pressure(payload),
        10 => exercise_malformed_full_size_imports(payload),
        11 => exercise_valid_material_deep(payload),
        12 => exercise_generate_path(),
        13 => {
            exercise_direct_inputs(payload);
            exercise_canonical_header_rejections(payload);
        }
        14 => exercise_all_public_api_once(payload),
        _ => {
            exercise_valid_material_one_mutation(payload);
            exercise_one_length_boundary(payload);
            exercise_short_regression_artifact();
        }
    }
});
