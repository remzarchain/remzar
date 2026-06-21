use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

fn ml_dsa_65_prop_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn enter_ml_dsa_65_prop_test_lock() -> MutexGuard<'static, ()> {
    match ml_dsa_65_prop_test_lock().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn fresh_keypair() -> MlDsa65Keypair {
    MlDsa65Keypair::generate().expect("ML-DSA-65 keypair generation should succeed")
}

fn assert_finishes_quickly<T>(
    label: &'static str,
    max_elapsed: Duration,
    f: impl FnOnce() -> T,
) -> T {
    let started = Instant::now();
    let output = f();
    let elapsed = started.elapsed();

    assert!(
        elapsed <= max_elapsed,
        "{label} took too long: elapsed {:?}, max {:?}",
        elapsed,
        max_elapsed
    );

    output
}

fn assert_debug_redacts_key_material(kp: &MlDsa65Keypair) {
    let debug_output = format!("{kp:?}");
    let full_secret_debug = format!("{:?}", kp.secret_bytes_slice());
    let full_public_debug = format!("{:?}", kp.public_bytes_slice());

    assert!(
        debug_output.contains("MlDsa65Keypair"),
        "Debug output should still identify the wrapper type"
    );

    assert!(
        debug_output.contains("[REDACTED; ML-DSA-65 secret key bytes]"),
        "Debug output must explicitly redact secret key bytes"
    );

    assert!(
        debug_output.contains("[REDACTED; ML-DSA-65 public key bytes]"),
        "Debug output must explicitly redact public key bytes"
    );

    assert!(
        !debug_output.contains(&full_secret_debug),
        "Debug output must not contain the full secret byte array"
    );

    assert!(
        !debug_output.contains(&full_public_debug),
        "Debug output must not contain the full public byte array"
    );

    assert!(
        !debug_output.contains("secret_bytes: ["),
        "Debug output must not expose raw secret byte-array formatting"
    );

    assert!(
        !debug_output.contains("public_bytes: ["),
        "Debug output must not expose raw public byte-array formatting"
    );
}

fn malformed_secret_artifact_seed_bytes() -> &'static [u8] {
    &[
        0xe2, 0xb0, 0xfa, 0xff, 0xff, 0xa0, 0x01, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0x1b, 0x08,
        0x00, 0x00, 0xfe, 0xf6, 0xff, 0xff, 0x8c, 0x03, 0x00, 0x00, 0x52, 0x04, 0x00, 0x00, 0x9d,
        0xfc, 0xff, 0xff, 0xd6, 0xfc, 0xff, 0xff, 0xbf, 0x02, 0x00, 0x00, 0x60, 0xfe, 0xff, 0xff,
        0x40, 0x0f, 0x00, 0x00, 0xef, 0x0e, 0x00, 0x00, 0x66, 0x06, 0x00, 0x00, 0x94, 0x05, 0x00,
        0x94, 0x05, 0x00, 0x00, 0x64, 0xfe, 0xff, 0xff, 0x00, 0x64, 0xfe, 0xff, 0xff, 0x00, 0x26,
        0xee,
    ]
}

fn repeat_bytes_to_array<const N: usize>(seed: &[u8]) -> [u8; N] {
    assert!(!seed.is_empty(), "seed must not be empty");

    let mut out = [0_u8; N];

    for i in 0..N {
        out[i] = seed[i % seed.len()];
    }

    out
}

fn rotated_repeat_bytes_to_array<const N: usize>(seed: &[u8], shift: usize) -> [u8; N] {
    assert!(!seed.is_empty(), "seed must not be empty");

    let mut out = [0_u8; N];

    for i in 0..N {
        out[i] = seed[(i + shift) % seed.len()];
    }

    out
}

fn v3_malformed_secret_artifact_seed_bytes() -> &'static [u8] {
    &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfb,
    ]
}

fn v3_repeat_malformed_seed_to_array<const N: usize>(seed: &[u8]) -> [u8; N] {
    assert!(!seed.is_empty(), "seed must not be empty");

    let mut out = [0_u8; N];

    for i in 0..N {
        out[i] = seed[i % seed.len()];
    }

    out
}

fn v3_rotate_malformed_seed_to_array<const N: usize>(seed: &[u8], shift: usize) -> [u8; N] {
    assert!(!seed.is_empty(), "seed must not be empty");

    let mut out = [0_u8; N];

    for i in 0..N {
        out[i] = seed[(i + shift) % seed.len()];
    }

    out
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/30
    #[test]
    fn test_001_raw_deserialize_rejects_all_wrong_lengths(len in 0usize..7000usize) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        prop_assume!(len != MlDsa65Keypair::RAW_SERIALIZED_LEN);

        let data = vec![0u8; len];

        prop_assert!(
            MlDsa65Keypair::deserialize(&data).is_err(),
            "raw deserializer must reject wrong length: {len}"
        );
    }

    // 02/30
    #[test]
    fn test_002_canonical_deserialize_rejects_all_wrong_lengths(len in 0usize..7000usize) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        prop_assume!(len != MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        let data = vec![0u8; len];

        prop_assert!(
            MlDsa65Keypair::deserialize_canonical(&data).is_err(),
            "canonical deserializer must reject wrong length: {len}"
        );
    }

    // 03/30
    #[test]
    fn test_003_canonical_deserialize_rejects_header_corruption(
        header_index in 0usize..MlDsa65Keypair::CANONICAL_HEADER_LEN,
        replacement in any::<u8>(),
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let mut canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        let original = canonical[header_index];

        prop_assume!(replacement != original);

        canonical[header_index] = replacement;

        prop_assert!(
            MlDsa65Keypair::deserialize_canonical(&canonical).is_err(),
            "canonical decoder must reject corrupted header byte at index {header_index}"
        );
    }

    // 04/30
    #[test]
    fn test_004_canonical_deserialize_rejects_trailing_bytes(
        extra in proptest::collection::vec(any::<u8>(), 1..128)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let mut canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        canonical.extend_from_slice(&extra);

        prop_assert!(
            MlDsa65Keypair::deserialize_canonical(&canonical).is_err(),
            "canonical decoder must reject trailing bytes"
        );
    }

    // 05/30
    #[test]
    fn test_005_canonical_deserialize_rejects_truncated_valid_prefix(
        keep_len in 0usize..MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        let truncated = &canonical[..keep_len];

        prop_assert!(
            MlDsa65Keypair::deserialize_canonical(truncated).is_err(),
            "canonical decoder must reject truncated prefix of length {keep_len}"
        );
    }

    // 06/30
    #[test]
    fn test_006_raw_deserialize_handles_corrupted_secret_bytes_without_panic_and_rejects_public_corruption(
        index in 0usize..MlDsa65Keypair::RAW_SERIALIZED_LEN,
        delta in 1u8..=255u8,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let mut raw = kp
            .serialize()
            .expect("raw serialization should succeed");

        raw[index] = raw[index].wrapping_add(delta);

        let result = std::panic::catch_unwind(|| MlDsa65Keypair::deserialize(&raw));

        prop_assert!(
            result.is_ok(),
            "raw deserializer must never panic on corrupted key material at index {index}"
        );

        let decoded = result.expect("panic was already checked above");

        if index >= MlDsa65Keypair::SECRET_LEN {
            prop_assert!(
                decoded.is_err(),
                "raw deserializer must reject corrupted public key material at index {index}"
            );
        } else if let Ok(kp) = decoded {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if corrupted secret bytes are accepted, the resulting keypair must still validate"
            );
        }
    }

    // 07/30
    #[test]
    fn test_007_canonical_deserialize_handles_corrupted_secret_body_without_panic_and_rejects_public_corruption(
        body_index in 0usize..MlDsa65Keypair::RAW_SERIALIZED_LEN,
        delta in 1u8..=255u8,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let mut canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        let index = MlDsa65Keypair::CANONICAL_HEADER_LEN + body_index;
        canonical[index] = canonical[index].wrapping_add(delta);

        let result = std::panic::catch_unwind(|| {
            MlDsa65Keypair::deserialize_canonical(&canonical)
        });

        prop_assert!(
            result.is_ok(),
            "canonical deserializer must never panic on corrupted body byte at canonical index {index}"
        );

        let decoded = result.expect("panic was already checked above");

        if body_index >= MlDsa65Keypair::SECRET_LEN {
            prop_assert!(
                decoded.is_err(),
                "canonical deserializer must reject corrupted public key material at body index {body_index}"
            );
        } else if let Ok(kp) = decoded {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if corrupted secret bytes are accepted, the resulting keypair must still validate"
            );
        }
    }

    // 08/30
    #[test]
    fn test_008_generated_keypair_validate_self_and_key_getters_succeed(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        prop_assert!(
            kp.validate_self().is_ok(),
            "freshly generated keypair must satisfy all internal invariants"
        );

        prop_assert!(
            kp.get_signing_key().is_ok(),
            "freshly generated secret key bytes must parse back into a signing key"
        );

        prop_assert!(
            kp.get_verifying_key().is_ok(),
            "freshly generated public key bytes must parse back into a verifying key"
        );
    }

    // 09/30
    #[test]
    fn test_009_raw_serialize_has_exact_length_and_secret_public_layout(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let raw = kp
            .serialize()
            .expect("raw serialization should succeed");

        prop_assert_eq!(
            raw.len(),
            MlDsa65Keypair::RAW_SERIALIZED_LEN,
            "raw serialization must have exact fixed length"
        );

        prop_assert_eq!(
            &raw[..MlDsa65Keypair::SECRET_LEN],
            kp.secret_bytes_slice(),
            "raw serialization must start with secret bytes"
        );

        prop_assert_eq!(
            &raw[MlDsa65Keypair::SECRET_LEN..],
            kp.public_bytes_slice(),
            "raw serialization must end with public bytes"
        );
    }

    // 10/30
    #[test]
    fn test_010_canonical_serialize_has_exact_length_header_and_body_layout(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        prop_assert_eq!(
            canonical.len(),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            "canonical serialization must have exact fixed length"
        );

        prop_assert_eq!(
            &canonical[0..4],
            MlDsa65Keypair::CANONICAL_MAGIC.as_ref(),
            "canonical magic must be exact"
        );

        prop_assert_eq!(
            canonical[4],
            MlDsa65Keypair::CANONICAL_VERSION,
            "canonical version must be exact"
        );

        prop_assert_eq!(
            canonical[5],
            MlDsa65Keypair::CANONICAL_FLAGS,
            "canonical flags must be exact"
        );

        prop_assert_eq!(
            &canonical[6..8],
            MlDsa65Keypair::CANONICAL_RESERVED.as_ref(),
            "canonical reserved bytes must be exact"
        );

        prop_assert_eq!(
            &canonical[MlDsa65Keypair::CANONICAL_HEADER_LEN
                ..MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::SECRET_LEN],
            kp.secret_bytes_slice(),
            "canonical body must place secret bytes immediately after header"
        );

        prop_assert_eq!(
            &canonical[MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::SECRET_LEN..],
            kp.public_bytes_slice(),
            "canonical body must place public bytes after secret bytes"
        );
    }

    // 11/30
    #[test]
    fn test_011_raw_roundtrip_preserves_exact_bytes_and_revalidates(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let raw = kp
            .serialize()
            .expect("raw serialization should succeed");

        let decoded = MlDsa65Keypair::deserialize(&raw)
            .expect("valid raw serialization must deserialize");

        prop_assert!(
            decoded.validate_self().is_ok(),
            "raw roundtripped keypair must validate"
        );

        let encoded_again = decoded
            .serialize()
            .expect("raw reserialization should succeed");

        prop_assert_eq!(
            encoded_again,
            raw,
            "raw serialize -> deserialize -> serialize must be byte-stable"
        );
    }

    // 12/30
    #[test]
    fn test_012_canonical_roundtrip_preserves_exact_bytes_and_revalidates(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        let decoded = MlDsa65Keypair::deserialize_canonical(&canonical)
            .expect("valid canonical serialization must deserialize");

        prop_assert!(
            decoded.validate_self().is_ok(),
            "canonical roundtripped keypair must validate"
        );

        let encoded_again = decoded
            .serialize_canonical()
            .expect("canonical reserialization should succeed");

        prop_assert_eq!(
            encoded_again,
            canonical,
            "canonical serialize -> deserialize -> serialize must be byte-stable"
        );
    }

    // 13/30
    #[test]
    fn test_013_canonical_body_is_exactly_legacy_raw_encoding(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let raw = kp
            .serialize()
            .expect("raw serialization should succeed");

        let canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        prop_assert_eq!(
            &canonical[MlDsa65Keypair::CANONICAL_HEADER_LEN..],
            raw.as_slice(),
            "canonical body must be exactly the legacy raw secret||public encoding"
        );
    }

    // 14/30
    #[test]
    fn test_014_from_secret_reconstructs_same_secret_and_public(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let original = fresh_keypair();

        let secret = original.to_bytes();

        let rebuilt = MlDsa65Keypair::from_secret(secret)
            .expect("valid generated secret must rebuild a valid keypair");

        prop_assert!(
            rebuilt.validate_self().is_ok(),
            "keypair rebuilt from valid secret must validate"
        );

        prop_assert_eq!(
            rebuilt.secret_bytes_slice(),
            original.secret_bytes_slice(),
            "from_secret must preserve exact secret bytes"
        );

        prop_assert_eq!(
            rebuilt.public_bytes_slice(),
            original.public_bytes_slice(),
            "from_secret must derive the exact matching public key"
        );
    }

    // 15/30
    #[test]
    fn test_015_from_secret_handles_single_byte_secret_corruption_without_panic_and_never_returns_invalid_keypair(
        index in 0usize..MlDsa65Keypair::SECRET_LEN,
        delta in 1u8..=255u8,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let original = fresh_keypair();

        let mut secret = original.to_bytes();
        secret[index] = secret[index].wrapping_add(delta);

        let result = std::panic::catch_unwind(|| MlDsa65Keypair::from_secret(secret));

        prop_assert!(
            result.is_ok(),
            "from_secret must never panic on corrupted secret byte at index {index}"
        );

        if let Ok(rebuilt) = result.expect("panic was already checked above") {
            prop_assert!(
                rebuilt.validate_self().is_ok(),
                "if corrupted secret bytes are accepted, rebuilt keypair must still validate"
            );

            prop_assert_eq!(
                rebuilt.secret_bytes_slice(),
                &secret,
                "accepted corrupted secret must be stored exactly as provided"
            );
        }
    }

    // 16/30
    #[test]
    fn test_016_secret_accessors_are_consistent_and_exact_length(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let secret_ref = kp.secret_bytes_ref();
        let secret_slice = kp.secret_bytes_slice();
        let secret_copy = kp.to_bytes();

        prop_assert_eq!(
            secret_ref.len(),
            MlDsa65Keypair::SECRET_LEN,
            "secret_bytes_ref must expose exact ML-DSA-65 secret length"
        );

        prop_assert_eq!(
            secret_slice.len(),
            MlDsa65Keypair::SECRET_LEN,
            "secret_bytes_slice must expose exact ML-DSA-65 secret length"
        );

        prop_assert_eq!(
            secret_copy.len(),
            MlDsa65Keypair::SECRET_LEN,
            "to_bytes must return exact ML-DSA-65 secret length"
        );

        prop_assert_eq!(
            secret_ref.as_slice(),
            secret_slice,
            "secret ref and secret slice must expose identical bytes"
        );

        prop_assert_eq!(
            secret_copy.as_slice(),
            secret_slice,
            "secret copy and secret slice must expose identical bytes"
        );
    }

    // 17/30
    #[test]
    fn test_017_public_accessors_are_consistent_and_exact_length(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let public_ref = kp.public_bytes_ref();
        let public_slice = kp.public_bytes_slice();
        let public_copy = kp.public_key_bytes();

        prop_assert_eq!(
            public_ref.len(),
            MlDsa65Keypair::PUBLIC_LEN,
            "public_bytes_ref must expose exact ML-DSA-65 public length"
        );

        prop_assert_eq!(
            public_slice.len(),
            MlDsa65Keypair::PUBLIC_LEN,
            "public_bytes_slice must expose exact ML-DSA-65 public length"
        );

        prop_assert_eq!(
            public_copy.len(),
            MlDsa65Keypair::PUBLIC_LEN,
            "public_key_bytes must return exact ML-DSA-65 public length"
        );

        prop_assert_eq!(
            public_ref.as_slice(),
            public_slice,
            "public ref and public slice must expose identical bytes"
        );

        prop_assert_eq!(
            public_copy.as_slice(),
            public_slice,
            "public copy and public slice must expose identical bytes"
        );
    }

    // 18/45
    #[test]
    fn test_018_debug_output_redacts_secret_and_public_material(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_debug_redacts_key_material(&kp);
        }));

        prop_assert!(
            result.is_ok(),
            "Debug output must redact both secret and public ML-DSA-65 key material"
        );
    }

    // 19/30
    #[test]
    fn test_019_canonical_decoder_rejects_valid_raw_encoding_as_format_confusion(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let raw = kp
            .serialize()
            .expect("raw serialization should succeed");

        prop_assert!(
            MlDsa65Keypair::deserialize(&raw).is_ok(),
            "test setup must produce valid raw encoding"
        );

        prop_assert!(
            MlDsa65Keypair::deserialize_canonical(&raw).is_err(),
            "canonical decoder must reject valid raw encoding to prevent format confusion"
        );
    }

    // 20/30
    #[test]
    fn test_020_raw_decoder_rejects_valid_canonical_encoding_as_format_confusion(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        prop_assert!(
            MlDsa65Keypair::deserialize_canonical(&canonical).is_ok(),
            "test setup must produce valid canonical encoding"
        );

        prop_assert!(
            MlDsa65Keypair::deserialize(&canonical).is_err(),
            "raw decoder must reject canonical encoding to prevent format confusion"
        );
    }

    // 21/30
    #[test]
    fn test_021_raw_decoder_rejects_mixed_secret_and_public_from_different_keypairs(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let secret_owner = fresh_keypair();
        let public_owner = fresh_keypair();

        prop_assume!(
            secret_owner.public_bytes_slice() != public_owner.public_bytes_slice()
        );

        let mut mixed = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        mixed.extend_from_slice(secret_owner.secret_bytes_slice());
        mixed.extend_from_slice(public_owner.public_bytes_slice());

        prop_assert_eq!(
            mixed.len(),
            MlDsa65Keypair::RAW_SERIALIZED_LEN,
            "mixed raw payload must have exact raw length"
        );

        let result = std::panic::catch_unwind(|| MlDsa65Keypair::deserialize(&mixed));

        prop_assert!(
            result.is_ok(),
            "raw decoder must not panic on secret/public mismatch"
        );

        prop_assert!(
            result.expect("panic was already checked above").is_err(),
            "raw decoder must reject a valid secret paired with a different valid public key"
        );
    }

    // 22/30
    #[test]
    fn test_022_canonical_decoder_rejects_mixed_secret_and_public_from_different_keypairs(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let secret_owner = fresh_keypair();
        let public_owner = fresh_keypair();

        prop_assume!(
            secret_owner.public_bytes_slice() != public_owner.public_bytes_slice()
        );

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(secret_owner.secret_bytes_slice());
        canonical.extend_from_slice(public_owner.public_bytes_slice());

        prop_assert_eq!(
            canonical.len(),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            "mixed canonical payload must have exact canonical length"
        );

        let result = std::panic::catch_unwind(|| {
            MlDsa65Keypair::deserialize_canonical(&canonical)
        });

        prop_assert!(
            result.is_ok(),
            "canonical decoder must not panic on secret/public mismatch"
        );

        prop_assert!(
            result.expect("panic was already checked above").is_err(),
            "canonical decoder must reject a valid secret paired with a different valid public key"
        );
    }

    // 23/30
    #[test]
    fn test_023_constants_partition_lengths_without_drift(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        prop_assert_eq!(
            MlDsa65Keypair::SECRET_LEN + MlDsa65Keypair::PUBLIC_LEN,
            MlDsa65Keypair::RAW_SERIALIZED_LEN,
            "raw length must always equal secret length plus public length"
        );

        prop_assert_eq!(
            MlDsa65Keypair::RAW_SERIALIZED_LEN,
            MlDsa65Keypair::SERIALIZED_LEN,
            "legacy SERIALIZED_LEN alias must remain equal to raw serialized length"
        );

        prop_assert_eq!(
            MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::RAW_SERIALIZED_LEN,
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            "canonical length must always equal header length plus raw body length"
        );

        prop_assert_eq!(
            MlDsa65Keypair::CANONICAL_HEADER_LEN,
            8,
            "canonical header length must remain fixed at 8 bytes"
        );

        prop_assert_eq!(
            MlDsa65Keypair::CANONICAL_RESERVED,
            [0u8; 2],
            "canonical reserved bytes must remain zero-filled"
        );
    }

    // 24/30
    #[test]
    fn test_024_raw_deserialize_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..7000)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let result = std::panic::catch_unwind(|| MlDsa65Keypair::deserialize(&data));

        prop_assert!(
            result.is_ok(),
            "raw deserializer must never panic for arbitrary external byte input of length {}",
            data.len()
        );

        let decoded = result.expect("panic was already checked above");

        if data.len() != MlDsa65Keypair::RAW_SERIALIZED_LEN {
            prop_assert!(
                decoded.is_err(),
                "raw deserializer must reject arbitrary input with wrong length {}",
                data.len()
            );
        } else if let Ok(kp) = decoded {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if arbitrary exact-length raw bytes are accepted, keypair must validate"
            );
        }
    }

    // 25/30
    #[test]
    fn test_025_canonical_deserialize_never_panics_for_arbitrary_external_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..7000)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let result = std::panic::catch_unwind(|| MlDsa65Keypair::deserialize_canonical(&data));

        prop_assert!(
            result.is_ok(),
            "canonical deserializer must never panic for arbitrary external byte input of length {}",
            data.len()
        );

        let decoded = result.expect("panic was already checked above");

        if data.len() != MlDsa65Keypair::CANONICAL_SERIALIZED_LEN {
            prop_assert!(
                decoded.is_err(),
                "canonical deserializer must reject arbitrary input with wrong length {}",
                data.len()
            );
        } else if let Ok(kp) = decoded {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if arbitrary exact-length canonical bytes are accepted, keypair must validate"
            );
        }
    }

    // 26/30
    #[test]
    fn test_026_malformed_artifact_from_secret_fails_closed_without_panic(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let secret =
            repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(malformed_secret_artifact_seed_bytes());

        let result = assert_finishes_quickly(
            "from_secret malformed secret artifact regression",
            Duration::from_secs(10),
            || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                MlDsa65Keypair::from_secret(secret)
            })),
        );

        prop_assert!(
            result.is_ok(),
            "from_secret must not panic on malformed secret artifact"
        );

        prop_assert!(
            result.expect("panic was already checked above").is_err(),
            "from_secret must reject malformed secret artifact secret material"
        );
    }

    // 27/30
    #[test]
    fn test_027_malformed_artifact_raw_deserialize_fails_closed_without_panic(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let valid_public_owner = fresh_keypair();
        let malformed_secret =
            repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(malformed_secret_artifact_seed_bytes());

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(malformed_secret.as_ref());
        raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        prop_assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        let result = assert_finishes_quickly(
            "raw deserialize malformed secret artifact regression",
            Duration::from_secs(10),
            || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                MlDsa65Keypair::deserialize(&raw)
            })),
        );

        prop_assert!(
            result.is_ok(),
            "raw deserialize must not panic on malformed secret artifact"
        );

        prop_assert!(
            result.expect("panic was already checked above").is_err(),
            "raw deserialize must reject malformed malformed artifact secret material"
        );
    }

    // 28/30
    #[test]
    fn test_028_malformed_artifact_canonical_deserialize_fails_closed_without_panic(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let valid_public_owner = fresh_keypair();
        let malformed_secret =
            repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(malformed_secret_artifact_seed_bytes());

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(malformed_secret.as_ref());
        canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        prop_assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        let result = assert_finishes_quickly(
            "canonical deserialize malformed secret artifact regression",
            Duration::from_secs(10),
            || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                MlDsa65Keypair::deserialize_canonical(&canonical)
            })),
        );

        prop_assert!(
            result.is_ok(),
            "canonical deserialize must not panic on malformed secret artifact"
        );

        prop_assert!(
            result.expect("panic was already checked above").is_err(),
            "canonical deserialize must reject malformed malformed artifact secret material"
        );
    }

    // 29/30
    #[test]
    fn test_029_malformed_artifact_does_not_poison_later_valid_generation(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let secret =
            repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(malformed_secret_artifact_seed_bytes());

        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::from_secret(secret)
        }));

        prop_assert!(rejected.is_ok(), "bad artifact path must not panic");
        prop_assert!(rejected.expect("panic was already checked above").is_err(), "bad artifact must be rejected");

        let valid = fresh_keypair();

        prop_assert!(
            valid.validate_self().is_ok(),
            "valid generation must still work after rejecting malformed malformed artifact"
        );

        prop_assert!(valid.get_signing_key().is_ok());
        prop_assert!(valid.get_verifying_key().is_ok());
    }

    // 30/30
    #[test]
    fn test_030_repeated_rotated_fuzz_artifacts_release_guard_and_fail_closed(
        shift in 0usize..malformed_secret_artifact_seed_bytes().len()
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let secret =
            rotated_repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                malformed_secret_artifact_seed_bytes(),
                shift,
            );

        let result = assert_finishes_quickly(
            "rotated malformed artifact from_secret regression",
            Duration::from_secs(10),
            || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                MlDsa65Keypair::from_secret(secret)
            })),
        );

        prop_assert!(
            result.is_ok(),
            "from_secret must not panic on rotated malformed artifact shift {shift}"
        );

        prop_assert!(
            result.expect("panic was already checked above").is_err(),
            "from_secret must reject rotated malformed malformed artifact shift {shift}"
        );

        let valid = fresh_keypair();

        prop_assert!(
            valid.validate_self().is_ok(),
            "valid generation must still work after rotated malformed secret rejection"
        );
    }

    // 31/45
    #[test]
    fn test_031_get_signing_key_never_panics_on_valid_generated_keys(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let kp = fresh_keypair();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            kp.get_signing_key()
        }));

        prop_assert!(
            result.is_ok(),
            "get_signing_key must not panic for valid generated keypairs"
        );

        prop_assert!(
            result.expect("panic already checked").is_ok(),
            "get_signing_key must succeed for valid generated keypairs"
        );
    }

    // 32/45
    #[test]
    fn test_032_from_secret_malformed_repeated_secret_bytes_fail_closed(
        shift in 0usize..25usize,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let malformed_secret =
            v3_rotate_malformed_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                v3_malformed_secret_artifact_seed_bytes(),
                shift,
            );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::from_secret(malformed_secret)
        }));

        prop_assert!(
            result.is_ok(),
            "from_secret must not panic for malformed repeated secret bytes at shift {shift}"
        );

        prop_assert!(
            result.expect("panic already checked").is_err(),
            "from_secret must fail closed for malformed repeated secret bytes at shift {shift}"
        );
    }

    // 33/45
    #[test]
    fn test_033_raw_exact_length_arbitrary_bytes_never_panic_or_stall_shape(
        seed in proptest::collection::vec(any::<u8>(), 1..96)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let raw = v3_repeat_malformed_seed_to_array::<{ MlDsa65Keypair::RAW_SERIALIZED_LEN }>(&seed);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::deserialize(&raw)
        }));

        prop_assert!(
            result.is_ok(),
            "raw exact-length arbitrary bytes must not panic"
        );

        if let Ok(kp) = result.expect("panic already checked") {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if arbitrary exact-length raw bytes are accepted, keypair must validate"
            );
        }
    }

    // 34/45
    #[test]
    fn test_034_canonical_exact_length_valid_header_arbitrary_body_never_panic_or_stall_shape(
        seed in proptest::collection::vec(any::<u8>(), 1..96)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let mut canonical =
            v3_repeat_malformed_seed_to_array::<{ MlDsa65Keypair::CANONICAL_SERIALIZED_LEN }>(&seed);

        canonical[0..4].copy_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical[4] = MlDsa65Keypair::CANONICAL_VERSION;
        canonical[5] = MlDsa65Keypair::CANONICAL_FLAGS;
        canonical[6..8].copy_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::deserialize_canonical(&canonical)
        }));

        prop_assert!(
            result.is_ok(),
            "canonical exact-length valid-header arbitrary body must not panic"
        );

        if let Ok(kp) = result.expect("panic already checked") {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if arbitrary valid-header canonical bytes are accepted, keypair must validate"
            );
        }
    }

    // 35/45
    #[test]
    fn test_035_bad_parse_artifact_does_not_poison_later_valid_generation_and_signing_key_parse(
        shift in 0usize..25usize,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let malformed_secret =
            v3_rotate_malformed_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                v3_malformed_secret_artifact_seed_bytes(),
                shift,
            );

        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::from_secret(malformed_secret)
        }));

        prop_assert!(
            rejected.is_ok(),
            "bad parse artifact must not panic at shift {shift}"
        );

        prop_assert!(
            rejected.expect("panic already checked").is_err(),
            "bad parse artifact must fail closed at shift {shift}"
        );

        let valid = fresh_keypair();

        prop_assert!(
            valid.validate_self().is_ok(),
            "bad parse artifact must not poison later valid key generation"
        );

        let signing_key = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            valid.get_signing_key()
        }));

        prop_assert!(
            signing_key.is_ok(),
            "bad parse artifact must not poison later valid get_signing_key"
        );

        prop_assert!(
            signing_key.expect("panic already checked").is_ok(),
            "later valid get_signing_key must still succeed"
        );
    }

    // 36/45
    #[test]
    fn test_036_current_public_contract_has_exact_sizes_and_bounded_validation_budget(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        prop_assert_eq!(MlDsa65Keypair::SECRET_LEN, 4_032);
        prop_assert_eq!(MlDsa65Keypair::PUBLIC_LEN, 1_952);
        prop_assert_eq!(MlDsa65Keypair::RAW_SERIALIZED_LEN, 5_984);
        prop_assert_eq!(
            MlDsa65Keypair::SERIALIZED_LEN,
            MlDsa65Keypair::RAW_SERIALIZED_LEN
        );
        prop_assert_eq!(MlDsa65Keypair::CANONICAL_HEADER_LEN, 8);
        prop_assert_eq!(
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::RAW_SERIALIZED_LEN
        );
        prop_assert_eq!(MlDsa65Keypair::CANONICAL_MAGIC, *b"M65K");
        prop_assert_eq!(MlDsa65Keypair::CANONICAL_VERSION, 1);
        prop_assert_eq!(MlDsa65Keypair::CANONICAL_FLAGS, 0);
        prop_assert_eq!(MlDsa65Keypair::CANONICAL_RESERVED, [0_u8, 0_u8]);
        prop_assert!(
            MlDsa65Keypair::VALIDATE_INVARIANTS_BUDGET_MILLIS <= 2_000,
            "full invariant validation budget must not drift into multi-second stall territory"
        );
    }

    // 37/45
    #[test]
    fn test_037_malformed_secret_rejection_does_not_poison_later_valid_operations(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let malformed_secret =
            repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(malformed_secret_artifact_seed_bytes());

        let rejected = assert_finishes_quickly(
            "malformed secret import must fail closed quickly",
            Duration::from_secs(10),
            || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                MlDsa65Keypair::from_secret(malformed_secret)
            })),
        );

        prop_assert!(
            rejected.is_ok(),
            "malformed secret import must not panic"
        );

        prop_assert!(
            rejected.expect("panic was already checked above").is_err(),
            "malformed secret import must fail closed"
        );

        let valid = fresh_keypair();

        prop_assert!(
            valid.validate_self().is_ok(),
            "valid keypair must still validate after malformed import rejection"
        );

        prop_assert!(
            valid.get_signing_key().is_ok(),
            "valid signing-key parse must still work after malformed import rejection"
        );

        prop_assert!(
            valid.get_verifying_key().is_ok(),
            "valid verifying-key parse must still work after malformed import rejection"
        );

        let raw = valid
            .serialize()
            .expect("valid raw serialization must still work after malformed import rejection");

        let canonical = valid
            .serialize_canonical()
            .expect("valid canonical serialization must still work after malformed import rejection");

        prop_assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);
        prop_assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        prop_assert!(
            MlDsa65Keypair::deserialize(&raw).is_ok(),
            "valid raw decode must still work after malformed import rejection"
        );

        prop_assert!(
            MlDsa65Keypair::deserialize_canonical(&canonical).is_ok(),
            "valid canonical decode must still work after malformed import rejection"
        );
    }

    // 38/45
    #[test]
    fn test_038_exact_minimized_five_byte_malformed_artifact_rejects_immediately(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        // Exact minimized libFuzzer malformed input:
        // Output of std::fmt::Debug: [226, 99, 255, 59, 208]
        //
        // Direct production decoders must reject this by length immediately.
        // It must never reach ML-DSA secret parsing or public derivation.
        let artifact = [226_u8, 99_u8, 255_u8, 59_u8, 208_u8];

        let result = assert_finishes_quickly(
            "exact 5-byte malformed artifact direct decoder rejection",
            Duration::from_millis(250),
            || {
                let raw_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&artifact)
                }));

                let canonical_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&artifact)
                }));

                (raw_result, canonical_result)
            },
        );

        let (raw_result, canonical_result) = result;

        prop_assert!(
            raw_result.is_ok(),
            "raw decoder must not panic on exact 5-byte malformed artifact"
        );

        prop_assert!(
            raw_result.expect("raw panic already checked").is_err(),
            "raw decoder must reject exact 5-byte malformed artifact"
        );

        prop_assert!(
            canonical_result.is_ok(),
            "canonical decoder must not panic on exact 5-byte malformed artifact"
        );

        prop_assert!(
            canonical_result
                .expect("canonical panic already checked")
                .is_err(),
            "canonical decoder must reject exact 5-byte malformed artifact"
        );
    }

    // 39/45
    #[test]
    fn test_039_full_size_raw_and_canonical_malformed_imports_reject_or_validate_under_budget(
        seed in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let valid_public_owner = fresh_keypair();
        let malformed_secret = v3_repeat_malformed_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(&seed);

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(malformed_secret.as_ref());
        raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        prop_assert_eq!(
            raw.len(),
            MlDsa65Keypair::RAW_SERIALIZED_LEN,
            "test setup must create exact-length raw keypair material"
        );

        let raw_result = assert_finishes_quickly(
            "full-size malformed raw import must not stall",
            Duration::from_secs(2),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&raw)
                }))
            },
        );

        prop_assert!(
            raw_result.is_ok(),
            "full-size malformed raw import must not panic"
        );

        if let Ok(kp) = raw_result.expect("raw panic already checked") {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if arbitrary exact-length raw bytes are accepted, resulting keypair must validate"
            );
        }

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(malformed_secret.as_ref());
        canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        prop_assert_eq!(
            canonical.len(),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            "test setup must create exact-length canonical keypair material"
        );

        let canonical_result = assert_finishes_quickly(
            "full-size malformed canonical import must not stall",
            Duration::from_secs(2),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&canonical)
                }))
            },
        );

        prop_assert!(
            canonical_result.is_ok(),
            "full-size malformed canonical import must not panic"
        );

        if let Ok(kp) = canonical_result.expect("canonical panic already checked") {
            prop_assert!(
                kp.validate_self().is_ok(),
                "if arbitrary exact-length canonical bytes are accepted, resulting keypair must validate"
            );
        }
    }

    // 40/45
    #[test]
    fn test_040_repeated_fuzz_artifact_imports_fail_closed_without_poisoning_valid_operations(
        shift in 0usize..25usize,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let malformed_secret =
            v3_rotate_malformed_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                v3_malformed_secret_artifact_seed_bytes(),
                shift,
            );

        let from_secret_result = assert_finishes_quickly(
            "rotated malformed artifact from_secret must fail closed quickly",
            Duration::from_secs(2),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::from_secret(malformed_secret)
                }))
            },
        );

        prop_assert!(
            from_secret_result.is_ok(),
            "from_secret must not panic on rotated malformed artifact shift {shift}"
        );

        prop_assert!(
            from_secret_result
                .expect("from_secret panic already checked")
                .is_err(),
            "from_secret must reject rotated malformed artifact shift {shift}"
        );

        let valid = fresh_keypair();

        prop_assert!(
            valid.validate_self().is_ok(),
            "valid keypair must still validate after malformed artifact rejection"
        );

        prop_assert!(
            valid.get_signing_key().is_ok(),
            "valid signing-key parse must still work after malformed artifact rejection"
        );

        prop_assert!(
            valid.get_verifying_key().is_ok(),
            "valid verifying-key parse must still work after malformed artifact rejection"
        );

        let raw = valid
            .serialize()
            .expect("valid raw serialization must still work after malformed artifact rejection");

        let canonical = valid
            .serialize_canonical()
            .expect("valid canonical serialization must still work after malformed artifact rejection");

        prop_assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);
        prop_assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        let decoded_raw = MlDsa65Keypair::deserialize(&raw)
            .expect("valid raw decode must still work after malformed artifact rejection");

        let decoded_canonical = MlDsa65Keypair::deserialize_canonical(&canonical)
            .expect("valid canonical decode must still work after malformed artifact rejection");

        prop_assert_eq!(decoded_raw.secret_bytes_slice(), valid.secret_bytes_slice());
        prop_assert_eq!(decoded_raw.public_bytes_slice(), valid.public_bytes_slice());

        prop_assert_eq!(
            decoded_canonical.secret_bytes_slice(),
            valid.secret_bytes_slice()
        );

        prop_assert_eq!(
            decoded_canonical.public_bytes_slice(),
            valid.public_bytes_slice()
        );
    }

    // 41/45
    #[test]
    fn test_041_zero_byte_input_rejects_immediately(_case in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let data: [u8; 0] = [];

        let result = assert_finishes_quickly(
            "zero-byte input must reject immediately",
            Duration::from_millis(250),
            || {
                let raw = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&data)
                }));

                let canonical = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&data)
                }));

                (raw, canonical)
            },
        );

        let (raw, canonical) = result;

        prop_assert!(raw.is_ok(), "raw zero-byte decode must not panic");
        prop_assert!(
            raw.expect("raw panic already checked").is_err(),
            "raw zero-byte decode must reject"
        );

        prop_assert!(
            canonical.is_ok(),
            "canonical zero-byte decode must not panic"
        );
        prop_assert!(
            canonical.expect("canonical panic already checked").is_err(),
            "canonical zero-byte decode must reject"
        );
    }

    // 42/45
    #[test]
    fn test_042_random_one_byte_inputs_reject_immediately(byte in any::<u8>()) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let data = [byte];

        let result = assert_finishes_quickly(
            "random one-byte input must reject immediately",
            Duration::from_millis(250),
            || {
                let raw = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&data)
                }));

                let canonical = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&data)
                }));

                (raw, canonical)
            },
        );

        let (raw, canonical) = result;

        prop_assert!(raw.is_ok(), "raw one-byte decode must not panic");
        prop_assert!(
            raw.expect("raw panic already checked").is_err(),
            "raw one-byte decode must reject"
        );

        prop_assert!(canonical.is_ok(), "canonical one-byte decode must not panic");
        prop_assert!(
            canonical.expect("canonical panic already checked").is_err(),
            "canonical one-byte decode must reject"
        );
    }

    // 43/45
    #[test]
    fn test_043_random_seven_byte_inputs_reject_immediately(
        data in proptest::collection::vec(any::<u8>(), 7..8)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let result = assert_finishes_quickly(
            "random seven-byte input must reject immediately",
            Duration::from_millis(250),
            || {
                let raw = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&data)
                }));

                let canonical = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&data)
                }));

                (raw, canonical)
            },
        );

        let (raw, canonical) = result;

        prop_assert!(raw.is_ok(), "raw seven-byte decode must not panic");
        prop_assert!(
            raw.expect("raw panic already checked").is_err(),
            "raw seven-byte decode must reject"
        );

        prop_assert!(
            canonical.is_ok(),
            "canonical seven-byte decode must not panic"
        );
        prop_assert!(
            canonical.expect("canonical panic already checked").is_err(),
            "canonical seven-byte decode must reject"
        );
    }

    // 44/45
    #[test]
    fn test_044_random_twenty_five_byte_inputs_reject_immediately(
        data in proptest::collection::vec(any::<u8>(), 25..26)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let result = assert_finishes_quickly(
            "random twenty-five-byte input must reject immediately",
            Duration::from_millis(250),
            || {
                let raw = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&data)
                }));

                let canonical = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&data)
                }));

                (raw, canonical)
            },
        );

        let (raw, canonical) = result;

        prop_assert!(
            raw.is_ok(),
            "raw twenty-five-byte decode must not panic"
        );
        prop_assert!(
            raw.expect("raw panic already checked").is_err(),
            "raw twenty-five-byte decode must reject"
        );

        prop_assert!(
            canonical.is_ok(),
            "canonical twenty-five-byte decode must not panic"
        );
        prop_assert!(
            canonical.expect("canonical panic already checked").is_err(),
            "canonical twenty-five-byte decode must reject"
        );
    }

    // 45/45
    #[test]
    fn test_045_random_tiny_wrong_length_inputs_reject_immediately(
        data in proptest::collection::vec(any::<u8>(), 0..64)
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        prop_assume!(data.len() != MlDsa65Keypair::RAW_SERIALIZED_LEN);
        prop_assume!(data.len() != MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        let result = assert_finishes_quickly(
            "random tiny wrong-length input must reject immediately",
            Duration::from_millis(250),
            || {
                let raw = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&data)
                }));

                let canonical = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&data)
                }));

                (raw, canonical)
            },
        );

        let (raw, canonical) = result;

        prop_assert!(
            raw.is_ok(),
            "raw tiny wrong-length input must not panic; len={}",
            data.len()
        );
        prop_assert!(
            raw.expect("raw panic already checked").is_err(),
            "raw tiny wrong-length input must reject; len={}",
            data.len()
        );

        prop_assert!(
            canonical.is_ok(),
            "canonical tiny wrong-length input must not panic; len={}",
            data.len()
        );
        prop_assert!(
            canonical.expect("canonical panic already checked").is_err(),
            "canonical tiny wrong-length input must reject; len={}",
            data.len()
        );
    }

    // 46/50
    #[test]
    fn test_046_repeated_malformed_imports_do_not_poison_valid_roundtrips(
        attempts in 1usize..6usize,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let valid_public_owner = fresh_keypair();

        for shift in 0..attempts {
            let malformed_secret =
                rotated_repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                    malformed_secret_artifact_seed_bytes(),
                    shift,
                );

            let from_secret_result = assert_finishes_quickly(
                "repeated malformed from_secret import must fail closed",
                Duration::from_secs(10),
                || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::from_secret(malformed_secret)
                    }))
                },
            );

            prop_assert!(
                from_secret_result.is_ok(),
                "malformed from_secret attempt {shift} must not panic"
            );

            prop_assert!(
                from_secret_result
                    .expect("from_secret panic already checked")
                    .is_err(),
                "malformed from_secret attempt {shift} must reject"
            );

            let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
            raw.extend_from_slice(malformed_secret.as_ref());
            raw.extend_from_slice(valid_public_owner.public_bytes_slice());

            prop_assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

            let raw_result = assert_finishes_quickly(
                "repeated malformed raw import must fail closed",
                Duration::from_secs(10),
                || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::deserialize(&raw)
                    }))
                },
            );

            prop_assert!(
                raw_result.is_ok(),
                "malformed raw attempt {shift} must not panic"
            );

            prop_assert!(
                raw_result.expect("raw panic already checked").is_err(),
                "malformed raw attempt {shift} must reject"
            );

            let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
            canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
            canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
            canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
            canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
            canonical.extend_from_slice(malformed_secret.as_ref());
            canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

            prop_assert_eq!(
                canonical.len(),
                MlDsa65Keypair::CANONICAL_SERIALIZED_LEN
            );

            let canonical_result = assert_finishes_quickly(
                "repeated malformed canonical import must fail closed",
                Duration::from_secs(10),
                || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::deserialize_canonical(&canonical)
                    }))
                },
            );

            prop_assert!(
                canonical_result.is_ok(),
                "malformed canonical attempt {shift} must not panic"
            );

            prop_assert!(
                canonical_result
                    .expect("canonical panic already checked")
                    .is_err(),
                "malformed canonical attempt {shift} must reject"
            );
        }

        let valid = fresh_keypair();

        let raw = valid
            .serialize()
            .expect("valid raw serialization must still work after repeated malformed imports");

        let canonical = valid
            .serialize_canonical()
            .expect("valid canonical serialization must still work after repeated malformed imports");

        let decoded_raw = MlDsa65Keypair::deserialize(&raw)
            .expect("valid raw decode must still work after repeated malformed imports");

        let decoded_canonical = MlDsa65Keypair::deserialize_canonical(&canonical)
            .expect("valid canonical decode must still work after repeated malformed imports");

        prop_assert_eq!(decoded_raw.secret_bytes_slice(), valid.secret_bytes_slice());
        prop_assert_eq!(decoded_raw.public_bytes_slice(), valid.public_bytes_slice());

        prop_assert_eq!(
            decoded_canonical.secret_bytes_slice(),
            valid.secret_bytes_slice()
        );

        prop_assert_eq!(
            decoded_canonical.public_bytes_slice(),
            valid.public_bytes_slice()
        );
    }

    // 47/50
    #[test]
    fn test_047_clone_survives_original_drop_and_api_sequence_remains_stable(
        rounds in 1usize..8usize,
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let cloned = {
            let original = fresh_keypair();
            let cloned = original.clone();

            prop_assert_eq!(cloned.secret_bytes_slice(), original.secret_bytes_slice());
            prop_assert_eq!(cloned.public_bytes_slice(), original.public_bytes_slice());

            drop(original);
            cloned
        };

        let first_raw = cloned
            .serialize()
            .expect("clone raw serialization should succeed");

        let first_canonical = cloned
            .serialize_canonical()
            .expect("clone canonical serialization should succeed");

        for round in 0..rounds {
            prop_assert!(
                cloned.validate_self().is_ok(),
                "clone must validate after original drop at round {round}"
            );

            prop_assert!(
                cloned.get_signing_key().is_ok(),
                "clone signing-key parse must work after original drop at round {round}"
            );

            prop_assert!(
                cloned.get_verifying_key().is_ok(),
                "clone verifying-key parse must work after original drop at round {round}"
            );

            let raw = cloned
                .serialize()
                .expect("clone raw serialization should remain stable");

            let canonical = cloned
                .serialize_canonical()
                .expect("clone canonical serialization should remain stable");

            prop_assert_eq!(
                raw.as_slice(),
                first_raw.as_slice(),
                "clone raw serialization changed after original drop at round {}",
                round
            );

            prop_assert_eq!(
                canonical.as_slice(),
                first_canonical.as_slice(),
                "clone canonical serialization changed after original drop at round {}",
                round
            );
        }
    }

    // 48/50
    #[test]
    fn test_048_panic_hook_is_restored_after_malformed_secret_parse(
        shift in 0usize..malformed_secret_artifact_seed_bytes().len(),
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let previous_hook = std::panic::take_hook();

        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_fired_for_hook = std::sync::Arc::clone(&hook_fired);

        std::panic::set_hook(Box::new(move |_| {
            hook_fired_for_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let malformed_secret =
            rotated_repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                malformed_secret_artifact_seed_bytes(),
                shift,
            );

        let parse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::from_secret(malformed_secret)
        }));

        let hook_probe = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            panic!("panic hook restoration probe after ML-DSA-65 malformed parse");
        }));

        let hook_was_restored = hook_fired.load(std::sync::atomic::Ordering::SeqCst);

        std::panic::set_hook(previous_hook);

        prop_assert!(
            parse_result.is_ok(),
            "malformed parse path must not panic through caller at shift {shift}"
        );

        prop_assert!(
            parse_result
                .expect("parse panic already checked")
                .is_err(),
            "malformed parse path must reject invalid secret material at shift {shift}"
        );

        prop_assert!(
            hook_probe.is_err(),
            "panic hook probe must panic inside catch_unwind"
        );

        prop_assert!(
            hook_was_restored,
            "panic hook was not restored after malformed ML-DSA-65 secret parsing"
        );
    }

    // 49/50
    #[test]
    fn test_049_exact_length_valid_header_arbitrary_canonical_body_never_panics_and_accepts_only_valid_keypairs(
        seed in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

        let mut canonical =
            v3_repeat_malformed_seed_to_array::<{ MlDsa65Keypair::CANONICAL_SERIALIZED_LEN }>(
                &seed,
            );

        canonical[0..4].copy_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical[4] = MlDsa65Keypair::CANONICAL_VERSION;
        canonical[5] = MlDsa65Keypair::CANONICAL_FLAGS;
        canonical[6..8].copy_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());

        let result = assert_finishes_quickly(
            "exact-length valid-header arbitrary canonical body must not stall",
            Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&canonical)
                }))
            },
        );

        prop_assert!(
            result.is_ok(),
            "exact-length valid-header arbitrary canonical body must not panic"
        );

        if let Ok(kp) = result.expect("panic already checked") {
            prop_assert!(
                kp.validate_self().is_ok(),
                "accepted arbitrary canonical body must produce a valid keypair"
            );

            let reserialized = kp
                .serialize_canonical()
                .expect("accepted arbitrary canonical body should reserialize canonically");

            prop_assert_eq!(
                reserialized.len(),
                MlDsa65Keypair::CANONICAL_SERIALIZED_LEN
            );

            prop_assert!(
                MlDsa65Keypair::deserialize_canonical(&reserialized).is_ok(),
                "reserialized accepted keypair must decode again"
            );
        }
    }

    // 50/50
    #[test]
    fn test_050_boundary_wrong_lengths_reject_fast_and_do_not_break_later_valid_key_use(
        index in 0usize..18usize,
        filler in any::<u8>(),
    ) {
        let _guard = enter_ml_dsa_65_prop_test_lock();

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
            63,
            MlDsa65Keypair::SECRET_LEN.saturating_sub(1),
            MlDsa65Keypair::SECRET_LEN,
            MlDsa65Keypair::SECRET_LEN.saturating_add(1),
            MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_sub(1),
            MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_add(1),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_sub(1),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(1),
        ];

        let len = boundary_lengths[index % boundary_lengths.len()];
        let data = vec![filler; len];

        if len != MlDsa65Keypair::RAW_SERIALIZED_LEN {
            let raw_result = assert_finishes_quickly(
                "boundary wrong-length raw input must reject quickly",
                Duration::from_millis(250),
                || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::deserialize(&data)
                    }))
                },
            );

            prop_assert!(
                raw_result.is_ok(),
                "boundary wrong-length raw input must not panic; len={len}"
            );

            prop_assert!(
                raw_result.expect("raw panic already checked").is_err(),
                "boundary wrong-length raw input must reject; len={len}"
            );
        }

        if len != MlDsa65Keypair::CANONICAL_SERIALIZED_LEN {
            let canonical_result = assert_finishes_quickly(
                "boundary wrong-length canonical input must reject quickly",
                Duration::from_millis(250),
                || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::deserialize_canonical(&data)
                    }))
                },
            );

            prop_assert!(
                canonical_result.is_ok(),
                "boundary wrong-length canonical input must not panic; len={len}"
            );

            prop_assert!(
                canonical_result
                    .expect("canonical panic already checked")
                    .is_err(),
                "boundary wrong-length canonical input must reject; len={len}"
            );
        }

        let valid = fresh_keypair();

        prop_assert!(
            valid.validate_self().is_ok(),
            "valid keypair must still validate after boundary wrong-length rejection"
        );

        prop_assert!(
            valid.get_signing_key().is_ok(),
            "valid signing-key parse must still work after boundary wrong-length rejection"
        );

        prop_assert!(
            valid.get_verifying_key().is_ok(),
            "valid verifying-key parse must still work after boundary wrong-length rejection"
        );

        let raw = valid
            .serialize()
            .expect("valid raw serialization must still work after boundary rejection");

        let canonical = valid
            .serialize_canonical()
            .expect("valid canonical serialization must still work after boundary rejection");

        prop_assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);
        prop_assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
    }
}
