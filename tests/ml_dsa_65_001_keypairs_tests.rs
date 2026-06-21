use fips204::traits::{SerDes, Signer};
use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use std::sync::{Mutex, OnceLock};

fn fresh_keypair() -> MlDsa65Keypair {
    MlDsa65Keypair::generate().expect("ML-DSA-65 keypair generation should succeed")
}

type TestResult = Result<(), String>;

const EXPECTED_SECRET_DEBUG_REDACTION: &str = "[REDACTED; ML-DSA-65 secret key bytes]";
const EXPECTED_PUBLIC_DEBUG_REDACTION: &str = "[REDACTED; ML-DSA-65 public key bytes]";

fn ml_dsa_65_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn run_serial_test<F>(test: F) -> TestResult
where
    F: FnOnce() -> TestResult,
{
    let _guard = match ml_dsa_65_test_lock().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    test()
}

macro_rules! serial_test {
    (fn $name:ident() -> TestResult $body:block) => {
        #[test]
        fn $name() -> TestResult {
            run_serial_test(|| -> TestResult { $body })
        }
    };

    (fn $name:ident() $body:block) => {
        #[test]
        fn $name() {
            run_serial_test(|| -> TestResult {
                $body
                Ok(())
            })
            .expect("serialized ML-DSA-65 unit test failed");
        }
    };
}

fn debug_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn assert_debug_redacts_key_material(kp: &MlDsa65Keypair) {
    let debug_output = format!("{kp:?}");
    let secret_debug = format!("{:?}", kp.secret_bytes_slice());
    let public_debug = format!("{:?}", kp.public_bytes_slice());

    assert!(debug_output.contains("MlDsa65Keypair"));
    assert!(debug_output.contains(EXPECTED_SECRET_DEBUG_REDACTION));
    assert!(debug_output.contains(EXPECTED_PUBLIC_DEBUG_REDACTION));
    assert!(!debug_output.contains(&secret_debug));
    assert!(!debug_output.contains(&public_debug));
    assert!(!debug_output.contains("secret_bytes: ["));
    assert!(!debug_output.contains("public_bytes: ["));
}

fn generate_keypair() -> Result<MlDsa65Keypair, String> {
    MlDsa65Keypair::generate().map_err(debug_err)
}

fn serialize_raw(kp: &MlDsa65Keypair) -> Result<Vec<u8>, String> {
    kp.serialize().map_err(debug_err)
}

fn serialize_canonical(kp: &MlDsa65Keypair) -> Result<Vec<u8>, String> {
    kp.serialize_canonical().map_err(debug_err)
}

fn deserialize_raw(data: &[u8]) -> Result<MlDsa65Keypair, String> {
    MlDsa65Keypair::deserialize(data).map_err(debug_err)
}

fn deserialize_canonical(data: &[u8]) -> Result<MlDsa65Keypair, String> {
    MlDsa65Keypair::deserialize_canonical(data).map_err(debug_err)
}

fn flip_byte(data: &mut [u8], position: usize) -> TestResult {
    match data.get_mut(position) {
        Some(byte) => {
            *byte ^= 0x01;
            Ok(())
        }
        None => Err(format!("byte position {position} was out of bounds")),
    }
}

fn write_range(data: &mut [u8], range: core::ops::Range<usize>, replacement: &[u8]) -> TestResult {
    let start = range.start;
    let end = range.end;
    let target = data
        .get_mut(range)
        .ok_or_else(|| format!("range {start}..{end} was out of bounds"))?;

    if target.len() != replacement.len() {
        return Err(format!(
            "replacement length mismatch: target {}, replacement {}",
            target.len(),
            replacement.len()
        ));
    }

    target.copy_from_slice(replacement);
    Ok(())
}

fn set_byte(data: &mut [u8], position: usize, value: u8) -> TestResult {
    match data.get_mut(position) {
        Some(byte) => {
            *byte = value;
            Ok(())
        }
        None => Err(format!("byte position {position} was out of bounds")),
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u8(&mut self) -> u8 {
        self.state ^= self.state.wrapping_shl(13);
        self.state ^= self.state.wrapping_shr(7);
        self.state ^= self.state.wrapping_shl(17);

        let [first, _, _, _, _, _, _, _] = self.state.to_le_bytes();
        first
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        for byte in output.iter_mut() {
            *byte = self.next_u8();
        }
    }
}

fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut output = vec![0_u8; len];
    let mut rng = XorShift64::new(seed);
    rng.fill_bytes(&mut output);
    output
}

fn generate_distinct_keypairs_for_added_tests() -> Result<(MlDsa65Keypair, MlDsa65Keypair), String>
{
    let first = generate_keypair()?;

    for _attempt in 0..8 {
        let candidate = generate_keypair()?;
        if candidate.public_bytes_slice() != first.public_bytes_slice() {
            return Ok((first, candidate));
        }
    }

    Err("could not generate distinct ML-DSA-65 keypairs".to_string())
}

fn fuzz_timeout_artifact_seed_bytes() -> &'static [u8] {
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

fn assert_finishes_quickly<T>(
    label: &'static str,
    max_elapsed: std::time::Duration,
    f: impl FnOnce() -> T,
) -> T {
    let started = std::time::Instant::now();
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

serial_test!(
    fn added_001_canonical_magic_constant_is_m65k() -> TestResult {
        assert_eq!(MlDsa65Keypair::CANONICAL_MAGIC.as_ref(), b"M65K");
        Ok(())
    }
);

serial_test!(
    fn added_002_canonical_reserved_constant_is_two_zero_bytes() -> TestResult {
        assert_eq!(MlDsa65Keypair::CANONICAL_RESERVED, [0_u8, 0_u8]);
        Ok(())
    }
);

serial_test!(
    fn added_003_canonical_header_does_not_change_across_two_serializations() -> TestResult {
        let kp = generate_keypair()?;
        let first = serialize_canonical(&kp)?;
        let second = serialize_canonical(&kp)?;

        assert_eq!(
            first.get(..MlDsa65Keypair::CANONICAL_HEADER_LEN),
            second.get(..MlDsa65Keypair::CANONICAL_HEADER_LEN)
        );

        Ok(())
    }
);

serial_test!(
    fn added_004_raw_serialization_is_stable_for_same_instance() -> TestResult {
        let kp = generate_keypair()?;
        let first = serialize_raw(&kp)?;
        let second = serialize_raw(&kp)?;

        assert_eq!(first, second);

        Ok(())
    }
);

serial_test!(
    fn added_005_canonical_serialization_is_stable_for_same_instance() -> TestResult {
        let kp = generate_keypair()?;
        let first = serialize_canonical(&kp)?;
        let second = serialize_canonical(&kp)?;

        assert_eq!(first, second);

        Ok(())
    }
);

serial_test!(
    fn added_006_raw_and_canonical_body_match_after_from_secret() -> TestResult {
        let original = generate_keypair()?;
        let rebuilt = MlDsa65Keypair::from_secret(original.to_bytes()).map_err(debug_err)?;

        let raw = serialize_raw(&rebuilt)?;
        let canonical = serialize_canonical(&rebuilt)?;

        assert_eq!(
            canonical.get(MlDsa65Keypair::CANONICAL_HEADER_LEN..),
            Some(raw.as_slice())
        );

        Ok(())
    }
);

serial_test!(
    fn added_007_deserialized_raw_revalidates_self() -> TestResult {
        let kp = generate_keypair()?;
        let raw = serialize_raw(&kp)?;
        let decoded = deserialize_raw(&raw)?;

        decoded.validate_self().map_err(debug_err)?;

        Ok(())
    }
);

serial_test!(
    fn added_008_deserialized_canonical_revalidates_self() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;
        let decoded = deserialize_canonical(&canonical)?;

        decoded.validate_self().map_err(debug_err)?;

        Ok(())
    }
);

serial_test!(
    fn added_009_from_secret_keypair_revalidates_self() -> TestResult {
        let kp = generate_keypair()?;
        let rebuilt = MlDsa65Keypair::from_secret(kp.to_bytes()).map_err(debug_err)?;

        rebuilt.validate_self().map_err(debug_err)?;

        Ok(())
    }
);

serial_test!(
    fn added_010_get_signing_key_is_repeatable_for_valid_keypair() -> TestResult {
        let kp = generate_keypair()?;

        assert!(kp.get_signing_key().is_ok());
        assert!(kp.get_signing_key().is_ok());

        Ok(())
    }
);

serial_test!(
    fn added_011_get_verifying_key_is_repeatable_for_valid_keypair() -> TestResult {
        let kp = generate_keypair()?;

        assert!(kp.get_verifying_key().is_ok());
        assert!(kp.get_verifying_key().is_ok());

        Ok(())
    }
);

serial_test!(
    fn added_012_to_bytes_equals_secret_bytes_slice() -> TestResult {
        let kp = generate_keypair()?;
        let secret_copy = kp.to_bytes();

        assert_eq!(secret_copy.as_ref(), kp.secret_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_013_public_key_bytes_equals_public_bytes_slice() -> TestResult {
        let kp = generate_keypair()?;
        let public_copy = kp.public_key_bytes();

        assert_eq!(public_copy.as_ref(), kp.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_014_canonical_deserialize_rejects_magic_byte_0_flip() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        flip_byte(&mut canonical, 0)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_015_canonical_deserialize_rejects_magic_byte_1_flip() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        flip_byte(&mut canonical, 1)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_016_canonical_deserialize_rejects_magic_byte_2_flip() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        flip_byte(&mut canonical, 2)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_017_canonical_deserialize_rejects_magic_byte_3_flip() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        flip_byte(&mut canonical, 3)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_018_canonical_deserialize_rejects_version_zero() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        set_byte(&mut canonical, 4, 0)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_019_canonical_deserialize_rejects_flags_max_value() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        set_byte(&mut canonical, 5, u8::MAX)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_020_canonical_deserialize_rejects_both_reserved_bytes_nonzero() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        set_byte(&mut canonical, 6, 1)?;
        set_byte(&mut canonical, 7, 1)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_021_canonical_rejects_valid_secret_with_wrong_public() -> TestResult {
        let (secret_owner, public_owner) = generate_distinct_keypairs_for_added_tests()?;
        let mut canonical = serialize_canonical(&secret_owner)?;

        write_range(
            &mut canonical,
            MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::SECRET_LEN
                ..MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            public_owner.public_bytes_slice(),
        )?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_022_canonical_rejects_valid_public_with_wrong_secret() -> TestResult {
        let (public_owner, secret_owner) = generate_distinct_keypairs_for_added_tests()?;
        let mut canonical = serialize_canonical(&public_owner)?;

        write_range(
            &mut canonical,
            MlDsa65Keypair::CANONICAL_HEADER_LEN
                ..MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::SECRET_LEN,
            secret_owner.secret_bytes_slice(),
        )?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_023_raw_rejects_valid_secret_with_wrong_public_at_boundary() -> TestResult {
        let (secret_owner, public_owner) = generate_distinct_keypairs_for_added_tests()?;
        let mut raw = serialize_raw(&secret_owner)?;

        write_range(
            &mut raw,
            MlDsa65Keypair::SECRET_LEN..MlDsa65Keypair::RAW_SERIALIZED_LEN,
            public_owner.public_bytes_slice(),
        )?;

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_024_raw_rejects_valid_public_with_wrong_secret_at_boundary() -> TestResult {
        let (public_owner, secret_owner) = generate_distinct_keypairs_for_added_tests()?;
        let mut raw = serialize_raw(&public_owner)?;

        write_range(
            &mut raw,
            0..MlDsa65Keypair::SECRET_LEN,
            secret_owner.secret_bytes_slice(),
        )?;

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_025_canonical_rejects_trailing_zero_byte() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        canonical.push(0);

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_026_canonical_rejects_missing_last_byte() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        canonical.truncate(canonical.len().saturating_sub(1));

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_027_raw_rejects_trailing_zero_byte() -> TestResult {
        let kp = generate_keypair()?;
        let mut raw = serialize_raw(&kp)?;

        raw.push(0);

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_028_raw_rejects_missing_last_byte() -> TestResult {
        let kp = generate_keypair()?;
        let mut raw = serialize_raw(&kp)?;

        raw.truncate(raw.len().saturating_sub(1));

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_029_raw_accepts_serialized_from_from_secret() -> TestResult {
        let original = generate_keypair()?;
        let rebuilt = MlDsa65Keypair::from_secret(original.to_bytes()).map_err(debug_err)?;
        let raw = serialize_raw(&rebuilt)?;
        let decoded = deserialize_raw(&raw)?;

        assert_eq!(decoded.secret_bytes_slice(), original.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), original.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_030_canonical_accepts_serialized_from_from_secret() -> TestResult {
        let original = generate_keypair()?;
        let rebuilt = MlDsa65Keypair::from_secret(original.to_bytes()).map_err(debug_err)?;
        let canonical = serialize_canonical(&rebuilt)?;
        let decoded = deserialize_canonical(&canonical)?;

        assert_eq!(decoded.secret_bytes_slice(), original.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), original.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_031_property_multiple_raw_serializations_have_correct_layout() -> TestResult {
        for round in 0..6 {
            let kp = generate_keypair()?;
            let raw = serialize_raw(&kp)?;

            assert_eq!(
                raw.get(..MlDsa65Keypair::SECRET_LEN),
                Some(kp.secret_bytes_slice()),
                "secret layout mismatch at round {round}"
            );
            assert_eq!(
                raw.get(MlDsa65Keypair::SECRET_LEN..),
                Some(kp.public_bytes_slice()),
                "public layout mismatch at round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn added_032_property_multiple_canonical_serializations_have_correct_layout() -> TestResult {
        for round in 0..6 {
            let kp = generate_keypair()?;
            let canonical = serialize_canonical(&kp)?;

            assert_eq!(
                canonical.get(0..4),
                Some(MlDsa65Keypair::CANONICAL_MAGIC.as_ref()),
                "magic mismatch at round {round}"
            );
            assert_eq!(
                canonical.get(4).copied(),
                Some(MlDsa65Keypair::CANONICAL_VERSION),
                "version mismatch at round {round}"
            );
            assert_eq!(
                canonical.get(5).copied(),
                Some(MlDsa65Keypair::CANONICAL_FLAGS),
                "flags mismatch at round {round}"
            );
            assert_eq!(
                canonical.get(6..8),
                Some(MlDsa65Keypair::CANONICAL_RESERVED.as_ref()),
                "reserved mismatch at round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn added_033_property_public_key_copy_matches_after_roundtrip() -> TestResult {
        for round in 0..6 {
            let kp = generate_keypair()?;
            let canonical = serialize_canonical(&kp)?;
            let decoded = deserialize_canonical(&canonical)?;

            assert_eq!(
                decoded.public_key_bytes().as_ref(),
                kp.public_bytes_slice(),
                "public copy mismatch at round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn added_034_property_secret_copy_matches_after_roundtrip() -> TestResult {
        for round in 0..6 {
            let kp = generate_keypair()?;
            let raw = serialize_raw(&kp)?;
            let decoded = deserialize_raw(&raw)?;

            assert_eq!(
                decoded.to_bytes().as_ref(),
                kp.secret_bytes_slice(),
                "secret copy mismatch at round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn added_035_deterministic_fuzz_canonical_invalid_short_lengths() -> TestResult {
        let lengths = [
            0,
            1,
            4,
            7,
            8,
            9,
            64,
            MlDsa65Keypair::CANONICAL_HEADER_LEN.saturating_add(1),
            MlDsa65Keypair::RAW_SERIALIZED_LEN,
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_sub(1),
        ];

        let mut seed = 0x65_00_00_00_00_00_00_01_u64;

        for len in lengths {
            let data = deterministic_bytes(len, seed);
            assert!(
                MlDsa65Keypair::deserialize_canonical(&data).is_err(),
                "invalid short canonical length {len} was accepted"
            );
            seed = seed.wrapping_add(0xA5A5_5A5A_0101_1010);
        }

        Ok(())
    }
);

serial_test!(
    fn added_036_deterministic_fuzz_canonical_invalid_long_lengths() -> TestResult {
        let lengths = [
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(1),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(2),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(8),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(64),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(1_024),
        ];

        let mut seed = 0x65_00_00_00_00_00_00_02_u64;

        for len in lengths {
            let data = deterministic_bytes(len, seed);
            assert!(
                MlDsa65Keypair::deserialize_canonical(&data).is_err(),
                "invalid long canonical length {len} was accepted"
            );
            seed = seed.wrapping_add(0x0101_1010_A5A5_5A5A);
        }

        Ok(())
    }
);

serial_test!(
    fn added_037_adversarial_network_sim_rejects_header_body_split_swap() -> TestResult {
        let kp = generate_keypair()?;
        let frame = serialize_canonical(&kp)?;

        let header = frame
            .get(..MlDsa65Keypair::CANONICAL_HEADER_LEN)
            .ok_or_else(|| "missing canonical header".to_string())?;
        let body = frame
            .get(MlDsa65Keypair::CANONICAL_HEADER_LEN..)
            .ok_or_else(|| "missing canonical body".to_string())?;

        let mut swapped = Vec::with_capacity(frame.len());
        swapped.extend_from_slice(body);
        swapped.extend_from_slice(header);

        assert!(MlDsa65Keypair::deserialize_canonical(&swapped).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_038_adversarial_network_sim_rejects_duplicate_header_prefix() -> TestResult {
        let kp = generate_keypair()?;
        let frame = serialize_canonical(&kp)?;

        let header = frame
            .get(..MlDsa65Keypair::CANONICAL_HEADER_LEN)
            .ok_or_else(|| "missing canonical header".to_string())?;
        let body = frame
            .get(MlDsa65Keypair::CANONICAL_HEADER_LEN..)
            .ok_or_else(|| "missing canonical body".to_string())?;

        let mut duplicated_header = Vec::with_capacity(frame.len().saturating_add(header.len()));
        duplicated_header.extend_from_slice(header);
        duplicated_header.extend_from_slice(header);
        duplicated_header.extend_from_slice(body);

        assert!(MlDsa65Keypair::deserialize_canonical(&duplicated_header).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_039_adversarial_network_sim_accepts_byte_by_byte_ordered_reassembly() -> TestResult {
        let kp = generate_keypair()?;
        let frame = serialize_canonical(&kp)?;

        let mut reassembled = Vec::with_capacity(frame.len());
        for byte in frame.iter().copied() {
            reassembled.push(byte);
        }

        let decoded = deserialize_canonical(&reassembled)?;

        assert_eq!(decoded.secret_bytes_slice(), kp.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), kp.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_040_load_test_repeated_canonical_decode_only() -> TestResult {
        let mut frames = Vec::with_capacity(10);

        for _round in 0..10 {
            let kp = generate_keypair()?;
            frames.push(serialize_canonical(&kp)?);
        }

        for frame in &frames {
            let decoded = deserialize_canonical(frame)?;
            decoded.validate_self().map_err(debug_err)?;
        }

        Ok(())
    }
);

serial_test!(
    fn added_041_clone_preserves_secret_and_public_bytes() -> TestResult {
        let kp = generate_keypair()?;
        let cloned = kp.clone();

        assert_eq!(cloned.secret_bytes_slice(), kp.secret_bytes_slice());
        assert_eq!(cloned.public_bytes_slice(), kp.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_042_clone_raw_serialization_matches_original() -> TestResult {
        let kp = generate_keypair()?;
        let cloned = kp.clone();

        assert_eq!(serialize_raw(&cloned)?, serialize_raw(&kp)?);

        Ok(())
    }
);

serial_test!(
    fn added_043_clone_canonical_serialization_matches_original() -> TestResult {
        let kp = generate_keypair()?;
        let cloned = kp.clone();

        assert_eq!(serialize_canonical(&cloned)?, serialize_canonical(&kp)?);

        Ok(())
    }
);

serial_test!(
    fn added_044_clone_survives_original_drop_and_stays_valid() -> TestResult {
        let cloned = {
            let original = generate_keypair()?;
            original.clone()
        };

        cloned.validate_self().map_err(debug_err)?;
        assert!(cloned.get_signing_key().is_ok());
        assert!(cloned.get_verifying_key().is_ok());

        Ok(())
    }
);

serial_test!(
    fn added_045_debug_output_does_not_include_full_secret_array_debug() -> TestResult {
        let kp = generate_keypair()?;

        assert_debug_redacts_key_material(&kp);

        Ok(())
    }
);

serial_test!(
    fn added_046_raw_deserialize_rejects_canonical_payload() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;

        assert!(MlDsa65Keypair::deserialize(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_047_canonical_rejects_header_only_payload() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;
        let header = canonical
            .get(..MlDsa65Keypair::CANONICAL_HEADER_LEN)
            .ok_or_else(|| "missing canonical header".to_string())?;

        assert!(MlDsa65Keypair::deserialize_canonical(header).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_048_canonical_rejects_magic_only_payload() -> TestResult {
        assert!(
            MlDsa65Keypair::deserialize_canonical(MlDsa65Keypair::CANONICAL_MAGIC.as_ref())
                .is_err()
        );

        Ok(())
    }
);

serial_test!(
    fn added_049_canonical_rejects_header_plus_one_body_byte() -> TestResult {
        let mut data = Vec::with_capacity(MlDsa65Keypair::CANONICAL_HEADER_LEN.saturating_add(1));
        data.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        data.push(MlDsa65Keypair::CANONICAL_VERSION);
        data.push(MlDsa65Keypair::CANONICAL_FLAGS);
        data.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        data.push(0);

        assert!(MlDsa65Keypair::deserialize_canonical(&data).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_050_raw_rejects_public_only_payload() -> TestResult {
        let kp = generate_keypair()?;

        assert!(MlDsa65Keypair::deserialize(kp.public_bytes_slice()).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_051_raw_rejects_secret_with_one_missing_public_byte() -> TestResult {
        let kp = generate_keypair()?;
        let raw = serialize_raw(&kp)?;
        let shortened = raw
            .get(..MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_sub(1))
            .ok_or_else(|| "missing shortened raw payload".to_string())?;

        assert!(MlDsa65Keypair::deserialize(shortened).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_052_raw_rejects_secret_with_one_extra_public_byte() -> TestResult {
        let kp = generate_keypair()?;
        let mut raw = serialize_raw(&kp)?;

        raw.push(1);

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_053_canonical_rejects_leading_extra_byte_before_magic() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;
        let mut prefixed = Vec::with_capacity(canonical.len().saturating_add(1));

        prefixed.push(0);
        prefixed.extend_from_slice(&canonical);

        assert!(MlDsa65Keypair::deserialize_canonical(&prefixed).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_054_canonical_rejects_extra_byte_between_header_and_body() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;
        let header = canonical
            .get(..MlDsa65Keypair::CANONICAL_HEADER_LEN)
            .ok_or_else(|| "missing canonical header".to_string())?;
        let body = canonical
            .get(MlDsa65Keypair::CANONICAL_HEADER_LEN..)
            .ok_or_else(|| "missing canonical body".to_string())?;

        let mut injected = Vec::with_capacity(canonical.len().saturating_add(1));
        injected.extend_from_slice(header);
        injected.push(0);
        injected.extend_from_slice(body);

        assert!(MlDsa65Keypair::deserialize_canonical(&injected).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_055_canonical_rejects_missing_first_magic_byte_even_with_trailing_padding()
    -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;
        let without_first = canonical
            .get(1..)
            .ok_or_else(|| "missing shifted canonical payload".to_string())?;

        let mut shifted = Vec::with_capacity(canonical.len());
        shifted.extend_from_slice(without_first);
        shifted.push(0);

        assert_eq!(shifted.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        assert!(MlDsa65Keypair::deserialize_canonical(&shifted).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_056_canonical_rejects_body_reversed_after_valid_header() -> TestResult {
        let (first, second) = generate_distinct_keypairs_for_added_tests()?;
        let mut canonical = serialize_canonical(&first)?;

        write_range(
            &mut canonical,
            MlDsa65Keypair::CANONICAL_HEADER_LEN
                ..MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::SECRET_LEN,
            second.secret_bytes_slice(),
        )?;

        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        assert_eq!(
            canonical.get(..MlDsa65Keypair::CANONICAL_HEADER_LEN),
            Some(
                [
                    MlDsa65Keypair::CANONICAL_MAGIC.as_ref(),
                    &[MlDsa65Keypair::CANONICAL_VERSION],
                    &[MlDsa65Keypair::CANONICAL_FLAGS],
                    MlDsa65Keypair::CANONICAL_RESERVED.as_ref(),
                ]
                .concat()
                .as_slice()
            )
        );
        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn added_057_vector_raw_serializations_for_distinct_keypairs_are_not_equal() -> TestResult {
        let (first, second) = generate_distinct_keypairs_for_added_tests()?;

        assert_ne!(serialize_raw(&first)?, serialize_raw(&second)?);

        Ok(())
    }
);

serial_test!(
    fn added_058_vector_canonical_serializations_for_distinct_keypairs_are_not_equal() -> TestResult
    {
        let (first, second) = generate_distinct_keypairs_for_added_tests()?;

        assert_ne!(serialize_canonical(&first)?, serialize_canonical(&second)?);

        Ok(())
    }
);

serial_test!(
    fn added_059_property_public_keys_are_distinct_across_small_generated_set() -> TestResult {
        let mut seen_public_keys: Vec<[u8; MlDsa65Keypair::PUBLIC_LEN]> = Vec::with_capacity(6);

        for round in 0..6 {
            let kp = generate_keypair()?;
            let public = kp.public_key_bytes();

            assert!(
                !seen_public_keys
                    .iter()
                    .any(|seen| seen.as_ref() == public.as_ref()),
                "duplicate public key at round {round}"
            );

            seen_public_keys.push(public);
        }

        Ok(())
    }
);

serial_test!(
    fn added_060_load_test_raw_and_canonical_lengths_across_generated_set() -> TestResult {
        let mut raw_total_len = 0_usize;
        let mut canonical_total_len = 0_usize;

        for _round in 0..16 {
            let kp = generate_keypair()?;
            let raw = serialize_raw(&kp)?;
            let canonical = serialize_canonical(&kp)?;

            assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);
            assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

            raw_total_len = raw_total_len.saturating_add(raw.len());
            canonical_total_len = canonical_total_len.saturating_add(canonical.len());
        }

        assert_eq!(
            raw_total_len,
            MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_mul(16)
        );
        assert_eq!(
            canonical_total_len,
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_mul(16)
        );

        Ok(())
    }
);

serial_test!(
    fn added_061_constants_vector_match_expected_ml_dsa_65_sizes() -> TestResult {
        assert_eq!(MlDsa65Keypair::SECRET_LEN, 4_032);
        assert_eq!(MlDsa65Keypair::PUBLIC_LEN, 1_952);
        assert_eq!(MlDsa65Keypair::RAW_SERIALIZED_LEN, 5_984);
        assert_eq!(
            MlDsa65Keypair::SERIALIZED_LEN,
            MlDsa65Keypair::RAW_SERIALIZED_LEN
        );
        assert_eq!(MlDsa65Keypair::CANONICAL_HEADER_LEN, 8);
        assert_eq!(
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::RAW_SERIALIZED_LEN
        );
        Ok(())
    }
);

serial_test!(
    fn added_061b_validation_budget_is_bounded_without_worker_thread_contract() -> TestResult {
        assert!(
            MlDsa65Keypair::VALIDATE_INVARIANTS_BUDGET_MILLIS <= 2_000,
            "validation budget must stay bounded for live-node responsiveness"
        );

        assert_eq!(MlDsa65Keypair::SECRET_LEN, 4_032);
        assert_eq!(MlDsa65Keypair::PUBLIC_LEN, 1_952);
        assert_eq!(MlDsa65Keypair::RAW_SERIALIZED_LEN, 5_984);
        assert_eq!(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN, 5_992);

        Ok(())
    }
);

serial_test!(
    fn added_062_generated_keypair_has_expected_accessor_lengths() -> TestResult {
        let kp = generate_keypair()?;

        assert_eq!(kp.secret_bytes_slice().len(), MlDsa65Keypair::SECRET_LEN);
        assert_eq!(kp.public_bytes_slice().len(), MlDsa65Keypair::PUBLIC_LEN);
        assert_eq!(kp.secret_bytes_ref().len(), MlDsa65Keypair::SECRET_LEN);
        assert_eq!(kp.public_bytes_ref().len(), MlDsa65Keypair::PUBLIC_LEN);

        Ok(())
    }
);

serial_test!(
    fn added_063_debug_output_redacts_secret_material() -> TestResult {
        let kp = generate_keypair()?;

        assert_debug_redacts_key_material(&kp);

        Ok(())
    }
);

serial_test!(
    fn added_064_generated_keypair_validates_self() -> TestResult {
        let kp = generate_keypair()?;
        kp.validate_self().map_err(debug_err)?;
        Ok(())
    }
);

serial_test!(
    fn added_065_generated_keypair_exposes_valid_signing_and_verifying_keys() -> TestResult {
        let kp = generate_keypair()?;

        assert!(kp.get_signing_key().is_ok());
        assert!(kp.get_verifying_key().is_ok());

        Ok(())
    }
);

serial_test!(
    fn added_066_raw_serialization_vector_has_exact_length() -> TestResult {
        let kp = generate_keypair()?;
        let raw = serialize_raw(&kp)?;

        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        Ok(())
    }
);

serial_test!(
    fn added_067_raw_serialization_vector_layout_is_secret_then_public() -> TestResult {
        let kp = generate_keypair()?;
        let raw = serialize_raw(&kp)?;

        assert_eq!(
            raw.get(..MlDsa65Keypair::SECRET_LEN),
            Some(kp.secret_bytes_slice())
        );
        assert_eq!(
            raw.get(MlDsa65Keypair::SECRET_LEN..),
            Some(kp.public_bytes_slice())
        );

        Ok(())
    }
);

serial_test!(
    fn added_068_raw_serialization_vector_roundtrips_key_material() -> TestResult {
        let kp = generate_keypair()?;
        let raw = serialize_raw(&kp)?;
        let decoded = deserialize_raw(&raw)?;

        assert_eq!(decoded.secret_bytes_slice(), kp.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), kp.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_069_canonical_serialization_vector_has_exact_length() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;

        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        Ok(())
    }
);

serial_test!(
    fn added_070_canonical_serialization_vector_header_fields_are_exact() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;

        let expected_magic: &[u8] = MlDsa65Keypair::CANONICAL_MAGIC.as_ref();
        let expected_reserved: &[u8] = MlDsa65Keypair::CANONICAL_RESERVED.as_ref();

        assert_eq!(canonical.get(0..4), Some(expected_magic));
        assert_eq!(
            canonical.get(4).copied(),
            Some(MlDsa65Keypair::CANONICAL_VERSION)
        );
        assert_eq!(
            canonical.get(5).copied(),
            Some(MlDsa65Keypair::CANONICAL_FLAGS)
        );
        assert_eq!(canonical.get(6..8), Some(expected_reserved));

        Ok(())
    }
);

serial_test!(
    fn added_071_canonical_serialization_vector_body_equals_raw_serialization() -> TestResult {
        let kp = generate_keypair()?;
        let raw = serialize_raw(&kp)?;
        let canonical = serialize_canonical(&kp)?;

        assert_eq!(
            canonical.get(MlDsa65Keypair::CANONICAL_HEADER_LEN..),
            Some(raw.as_slice())
        );

        Ok(())
    }
);

serial_test!(
    fn added_072_from_secret_vector_reconstructs_same_public_key() -> TestResult {
        let original = generate_keypair()?;
        let rebuilt = MlDsa65Keypair::from_secret(original.to_bytes()).map_err(debug_err)?;

        assert_eq!(rebuilt.secret_bytes_slice(), original.secret_bytes_slice());
        assert_eq!(rebuilt.public_bytes_slice(), original.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_073_from_secret_vector_preserves_canonical_encoding() -> TestResult {
        let original = generate_keypair()?;
        let rebuilt = MlDsa65Keypair::from_secret(original.to_bytes()).map_err(debug_err)?;

        assert_eq!(
            serialize_canonical(&rebuilt)?,
            serialize_canonical(&original)?
        );

        Ok(())
    }
);

serial_test!(
    fn added_074_secret_to_bytes_returns_copy_not_live_mutable_reference() -> TestResult {
        let kp = generate_keypair()?;
        let mut secret_copy = kp.to_bytes();

        flip_byte(&mut secret_copy, 0)?;

        let changed_copy: &[u8] = secret_copy.as_ref();
        assert_ne!(changed_copy, kp.secret_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_075_public_key_bytes_returns_copy_not_live_mutable_reference() -> TestResult {
        let kp = generate_keypair()?;
        let mut public_copy = kp.public_key_bytes();

        flip_byte(&mut public_copy, 0)?;

        let changed_copy: &[u8] = public_copy.as_ref();
        assert_ne!(changed_copy, kp.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn raw_deserialize_edge_case_rejects_empty_input() -> TestResult {
        assert!(MlDsa65Keypair::deserialize(&[]).is_err());
        Ok(())
    }
);

serial_test!(
    fn raw_deserialize_edge_case_rejects_secret_only_payload() -> TestResult {
        let data = vec![0_u8; MlDsa65Keypair::SECRET_LEN];

        assert!(MlDsa65Keypair::deserialize(&data).is_err());

        Ok(())
    }
);

serial_test!(
    fn raw_deserialize_edge_case_rejects_short_by_one() -> TestResult {
        let data = vec![0_u8; MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_sub(1)];

        assert!(MlDsa65Keypair::deserialize(&data).is_err());

        Ok(())
    }
);

serial_test!(
    fn raw_deserialize_edge_case_rejects_long_by_one() -> TestResult {
        let data = vec![0_u8; MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_add(1)];

        assert!(MlDsa65Keypair::deserialize(&data).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_edge_case_rejects_empty_input() -> TestResult {
        assert!(MlDsa65Keypair::deserialize_canonical(&[]).is_err());
        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_edge_case_rejects_raw_payload_without_header() -> TestResult {
        let kp = generate_keypair()?;
        let raw = serialize_raw(&kp)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_edge_case_rejects_short_by_one() -> TestResult {
        let data = vec![0_u8; MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_sub(1)];

        assert!(MlDsa65Keypair::deserialize_canonical(&data).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_edge_case_rejects_long_by_one() -> TestResult {
        let data = vec![0_u8; MlDsa65Keypair::CANONICAL_SERIALIZED_LEN.saturating_add(1)];

        assert!(MlDsa65Keypair::deserialize_canonical(&data).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_rejects_wrong_magic() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        write_range(&mut canonical, 0..4, b"BAD!")?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_rejects_wrong_version() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        set_byte(
            &mut canonical,
            4,
            MlDsa65Keypair::CANONICAL_VERSION.wrapping_add(1),
        )?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_rejects_wrong_flags() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        set_byte(&mut canonical, 5, 1)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_rejects_nonzero_reserved_first_byte() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        set_byte(&mut canonical, 6, 1)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn canonical_deserialize_rejects_nonzero_reserved_second_byte() -> TestResult {
        let kp = generate_keypair()?;
        let mut canonical = serialize_canonical(&kp)?;

        set_byte(&mut canonical, 7, 1)?;

        assert!(MlDsa65Keypair::deserialize_canonical(&canonical).is_err());

        Ok(())
    }
);

serial_test!(
    fn raw_deserialize_rejects_secret_byte_mutation() -> TestResult {
        let original = generate_keypair()?;
        let replacement_secret_owner = generate_keypair()?;
        let mut raw = serialize_raw(&original)?;

        write_range(
            &mut raw,
            0..MlDsa65Keypair::SECRET_LEN,
            replacement_secret_owner.secret_bytes_slice(),
        )?;

        assert_ne!(
            raw.get(..MlDsa65Keypair::SECRET_LEN),
            Some(original.secret_bytes_slice())
        );
        assert_eq!(
            raw.get(MlDsa65Keypair::SECRET_LEN..),
            Some(original.public_bytes_slice())
        );

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn raw_deserialize_rejects_public_byte_mutation() -> TestResult {
        let kp = generate_keypair()?;
        let mut raw = serialize_raw(&kp)?;

        flip_byte(&mut raw, MlDsa65Keypair::SECRET_LEN)?;

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn raw_deserialize_rejects_cross_keypair_public_secret_mismatch() -> TestResult {
        let kp_a = generate_keypair()?;
        let kp_b = generate_keypair()?;
        let mut raw = serialize_raw(&kp_a)?;

        write_range(
            &mut raw,
            MlDsa65Keypair::SECRET_LEN..MlDsa65Keypair::RAW_SERIALIZED_LEN,
            kp_b.public_bytes_slice(),
        )?;

        assert!(MlDsa65Keypair::deserialize(&raw).is_err());

        Ok(())
    }
);

serial_test!(
    fn deterministic_fuzz_rejects_invalid_raw_lengths() -> TestResult {
        let bad_lengths = [
            0,
            1,
            2,
            7,
            8,
            31,
            MlDsa65Keypair::SECRET_LEN.saturating_sub(1),
            MlDsa65Keypair::SECRET_LEN,
            MlDsa65Keypair::SECRET_LEN.saturating_add(1),
            MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_sub(2),
            MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_sub(1),
            MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_add(1),
            MlDsa65Keypair::RAW_SERIALIZED_LEN.saturating_add(16),
        ];

        let mut seed = 0xF00D_0065_D15A_1234_u64;

        for len in bad_lengths {
            let data = deterministic_bytes(len, seed);
            assert!(
                MlDsa65Keypair::deserialize(&data).is_err(),
                "invalid raw length {len} was accepted"
            );
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        }

        Ok(())
    }
);

serial_test!(
    fn deterministic_fuzz_rejects_random_canonical_payloads_by_header() -> TestResult {
        let seeds = [
            0x1000_0000_0000_0065,
            0x2000_0000_0000_0065,
            0x3000_0000_0000_0065,
            0x4000_0000_0000_0065,
            0x5000_0000_0000_0065,
            0x6000_0000_0000_0065,
            0x7000_0000_0000_0065,
            0x8000_0000_0000_0065,
        ];

        for seed in seeds {
            let data = deterministic_bytes(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN, seed);
            assert!(
                MlDsa65Keypair::deserialize_canonical(&data).is_err(),
                "random canonical-sized payload from seed {seed} was accepted"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn deterministic_fuzz_rejects_all_single_header_bit_flips() -> TestResult {
        let kp = generate_keypair()?;
        let canonical = serialize_canonical(&kp)?;

        for position in 0..MlDsa65Keypair::CANONICAL_HEADER_LEN {
            let mut corrupted = canonical.clone();
            flip_byte(&mut corrupted, position)?;

            assert!(
                MlDsa65Keypair::deserialize_canonical(&corrupted).is_err(),
                "canonical header flip at position {position} was accepted"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn property_raw_roundtrip_preserves_key_material_across_generated_keys() -> TestResult {
        for round in 0..8 {
            let kp = generate_keypair()?;
            let raw = serialize_raw(&kp)?;
            let decoded = deserialize_raw(&raw)?;

            assert_eq!(
                decoded.secret_bytes_slice(),
                kp.secret_bytes_slice(),
                "secret mismatch at round {round}"
            );
            assert_eq!(
                decoded.public_bytes_slice(),
                kp.public_bytes_slice(),
                "public mismatch at round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn property_canonical_roundtrip_preserves_key_material_across_generated_keys() -> TestResult {
        for round in 0..8 {
            let kp = generate_keypair()?;
            let canonical = serialize_canonical(&kp)?;
            let decoded = deserialize_canonical(&canonical)?;

            assert_eq!(
                decoded.secret_bytes_slice(),
                kp.secret_bytes_slice(),
                "secret mismatch at round {round}"
            );
            assert_eq!(
                decoded.public_bytes_slice(),
                kp.public_bytes_slice(),
                "public mismatch at round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn property_from_secret_derives_same_public_key_across_generated_keys() -> TestResult {
        for round in 0..8 {
            let kp = generate_keypair()?;
            let rebuilt = MlDsa65Keypair::from_secret(kp.to_bytes()).map_err(debug_err)?;

            assert_eq!(
                rebuilt.public_bytes_slice(),
                kp.public_bytes_slice(),
                "derived public key mismatch at round {round}"
            );
            assert_eq!(
                rebuilt.secret_bytes_slice(),
                kp.secret_bytes_slice(),
                "secret mismatch at round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn adversarial_network_sim_rejects_reordered_duplicated_truncated_and_concatenated_frames()
    -> TestResult {
        let kp = generate_keypair()?;
        let frame = serialize_canonical(&kp)?;

        let chunk_a = frame
            .get(..256)
            .ok_or_else(|| "missing chunk_a".to_string())?;
        let chunk_b = frame
            .get(256..1024)
            .ok_or_else(|| "missing chunk_b".to_string())?;
        let chunk_c = frame
            .get(1024..)
            .ok_or_else(|| "missing chunk_c".to_string())?;

        let mut reordered = Vec::with_capacity(frame.len());
        for chunk in [chunk_b, chunk_a, chunk_c] {
            reordered.extend_from_slice(chunk);
        }
        assert!(MlDsa65Keypair::deserialize_canonical(&reordered).is_err());

        let mut duplicated = Vec::with_capacity(frame.len().saturating_add(chunk_a.len()));
        for chunk in [chunk_a, chunk_a, chunk_b, chunk_c] {
            duplicated.extend_from_slice(chunk);
        }
        assert!(MlDsa65Keypair::deserialize_canonical(&duplicated).is_err());

        let mut truncated = frame.clone();
        truncated.truncate(frame.len().saturating_sub(17));
        assert!(MlDsa65Keypair::deserialize_canonical(&truncated).is_err());

        let mut concatenated = frame.clone();
        concatenated.extend_from_slice(&frame);
        assert!(MlDsa65Keypair::deserialize_canonical(&concatenated).is_err());

        Ok(())
    }
);

serial_test!(
    fn adversarial_network_sim_accepts_only_exact_ordered_reassembly() -> TestResult {
        let kp = generate_keypair()?;
        let frame = serialize_canonical(&kp)?;

        let chunk_a = frame
            .get(..8)
            .ok_or_else(|| "missing chunk_a".to_string())?;
        let chunk_b = frame
            .get(8..512)
            .ok_or_else(|| "missing chunk_b".to_string())?;
        let chunk_c = frame
            .get(512..4096)
            .ok_or_else(|| "missing chunk_c".to_string())?;
        let chunk_d = frame
            .get(4096..)
            .ok_or_else(|| "missing chunk_d".to_string())?;

        let mut reassembled = Vec::with_capacity(frame.len());
        for chunk in [chunk_a, chunk_b, chunk_c, chunk_d] {
            reassembled.extend_from_slice(chunk);
        }

        let decoded = deserialize_canonical(&reassembled)?;
        assert_eq!(decoded.secret_bytes_slice(), kp.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), kp.public_bytes_slice());

        let mut missing_middle = Vec::with_capacity(frame.len().saturating_sub(chunk_b.len()));
        for chunk in [chunk_a, chunk_c, chunk_d] {
            missing_middle.extend_from_slice(chunk);
        }

        assert!(MlDsa65Keypair::deserialize_canonical(&missing_middle).is_err());

        Ok(())
    }
);

serial_test!(
    fn load_test_repeated_generation_validation_serialization_and_deserialization() -> TestResult {
        for round in 0..12 {
            let kp = generate_keypair()?;
            kp.validate_self().map_err(debug_err)?;

            let raw = serialize_raw(&kp)?;
            let canonical = serialize_canonical(&kp)?;

            let raw_decoded = deserialize_raw(&raw)?;
            let canonical_decoded = deserialize_canonical(&canonical)?;

            assert_eq!(
                raw_decoded.public_bytes_slice(),
                kp.public_bytes_slice(),
                "raw public mismatch at load round {round}"
            );
            assert_eq!(
                canonical_decoded.secret_bytes_slice(),
                kp.secret_bytes_slice(),
                "canonical secret mismatch at load round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn generated_keypair_has_correct_lengths_and_validates() {
        let kp = fresh_keypair();

        assert_eq!(MlDsa65Keypair::SECRET_LEN, 4032);
        assert_eq!(MlDsa65Keypair::PUBLIC_LEN, 1952);
        assert_eq!(MlDsa65Keypair::RAW_SERIALIZED_LEN, 5984);
        assert_eq!(
            MlDsa65Keypair::SERIALIZED_LEN,
            MlDsa65Keypair::RAW_SERIALIZED_LEN
        );
        assert_eq!(MlDsa65Keypair::CANONICAL_HEADER_LEN, 8);
        assert_eq!(
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
            MlDsa65Keypair::CANONICAL_HEADER_LEN + MlDsa65Keypair::RAW_SERIALIZED_LEN
        );

        assert_eq!(kp.secret_bytes_slice().len(), MlDsa65Keypair::SECRET_LEN);
        assert_eq!(kp.public_bytes_slice().len(), MlDsa65Keypair::PUBLIC_LEN);

        kp.validate_self()
            .expect("generated keypair must satisfy internal invariants");
    }
);

serial_test!(
    fn raw_serialization_roundtrip_preserves_secret_and_public_bytes() {
        let original = fresh_keypair();

        let raw = original
            .serialize()
            .expect("raw serialization should succeed");

        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        let decoded =
            MlDsa65Keypair::deserialize(&raw).expect("raw deserialization should succeed");

        decoded
            .validate_self()
            .expect("decoded keypair should validate");

        assert_eq!(decoded.secret_bytes_slice(), original.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), original.public_bytes_slice());
    }
);

serial_test!(
    fn canonical_serialization_roundtrip_preserves_secret_and_public_bytes() {
        let original = fresh_keypair();

        let canonical = original
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        assert_eq!(&canonical[0..4], b"M65K");
        assert_eq!(canonical[4], MlDsa65Keypair::CANONICAL_VERSION);
        assert_eq!(canonical[5], MlDsa65Keypair::CANONICAL_FLAGS);
        assert_eq!(
            &canonical[6..8],
            MlDsa65Keypair::CANONICAL_RESERVED.as_slice()
        );

        let decoded = MlDsa65Keypair::deserialize_canonical(&canonical)
            .expect("canonical deserialization should succeed");

        decoded
            .validate_self()
            .expect("decoded canonical keypair should validate");

        assert_eq!(decoded.secret_bytes_slice(), original.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), original.public_bytes_slice());
    }
);

serial_test!(
    fn from_secret_reconstructs_same_public_key() {
        let original = fresh_keypair();

        let secret = original.to_bytes();

        let reconstructed = MlDsa65Keypair::from_secret(secret)
            .expect("from_secret should reconstruct a valid keypair");

        reconstructed
            .validate_self()
            .expect("reconstructed keypair should validate");

        assert_eq!(
            reconstructed.secret_bytes_slice(),
            original.secret_bytes_slice()
        );

        assert_eq!(
            reconstructed.public_bytes_slice(),
            original.public_bytes_slice()
        );
    }
);

serial_test!(
    fn signing_key_derived_public_key_matches_stored_public_key() {
        let kp = fresh_keypair();

        let signing_key = kp
            .get_signing_key()
            .expect("stored secret bytes should parse as private key");

        let derived_public = signing_key.get_public_key();
        let derived_public_bytes = derived_public.into_bytes();

        assert_eq!(&derived_public_bytes[..], kp.public_bytes_slice());

        let _verifying_key = kp
            .get_verifying_key()
            .expect("stored public bytes should parse as public key");
    }
);

serial_test!(
    fn public_key_bytes_matches_public_bytes_slice() {
        let kp = fresh_keypair();

        let public_copy = kp.public_key_bytes();

        assert_eq!(&public_copy[..], kp.public_bytes_slice());
        assert_eq!(public_copy.len(), MlDsa65Keypair::PUBLIC_LEN);
    }
);

serial_test!(
    fn secret_to_bytes_matches_secret_bytes_slice() {
        let kp = fresh_keypair();

        let secret_copy = kp.to_bytes();

        assert_eq!(&secret_copy[..], kp.secret_bytes_slice());
        assert_eq!(secret_copy.len(), MlDsa65Keypair::SECRET_LEN);
    }
);

serial_test!(
    fn debug_output_redacts_secret_key_material() {
        let kp = fresh_keypair();

        assert_debug_redacts_key_material(&kp);
    }
);

serial_test!(
    fn raw_deserialize_rejects_secret_public_mismatch() {
        let kp_a = fresh_keypair();
        let kp_b = fresh_keypair();

        let mut mixed = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        mixed.extend_from_slice(kp_a.secret_bytes_slice());
        mixed.extend_from_slice(kp_b.public_bytes_slice());

        let result = MlDsa65Keypair::deserialize(&mixed);

        assert!(
            result.is_err(),
            "raw decoder must reject secret/public mismatch"
        );
    }
);

serial_test!(
    fn canonical_deserialize_rejects_raw_format_without_header() {
        let kp = fresh_keypair();

        let raw = kp.serialize().expect("raw serialization should succeed");

        let result = MlDsa65Keypair::deserialize_canonical(&raw);

        assert!(
            result.is_err(),
            "canonical decoder must reject legacy raw bytes without canonical header"
        );
    }
);

serial_test!(
    fn regression_raw_corrupted_secret_byte_returns_err_not_panic() {
        let kp = fresh_keypair();

        let mut raw = kp.serialize().expect("raw serialization should succeed");

        raw[0] = raw[0].wrapping_add(1);

        let result = std::panic::catch_unwind(|| MlDsa65Keypair::deserialize(&raw));

        assert!(
            result.is_ok(),
            "raw deserialization of corrupted secret bytes must not panic"
        );

        assert!(
            result.unwrap().is_err(),
            "raw deserialization of corrupted secret bytes must return Err"
        );
    }
);

serial_test!(
    fn regression_canonical_corrupted_secret_byte_returns_err_not_panic() {
        let kp = fresh_keypair();

        let mut canonical = kp
            .serialize_canonical()
            .expect("canonical serialization should succeed");

        let first_secret_byte = MlDsa65Keypair::CANONICAL_HEADER_LEN;
        canonical[first_secret_byte] = canonical[first_secret_byte].wrapping_add(1);

        let result = std::panic::catch_unwind(|| MlDsa65Keypair::deserialize_canonical(&canonical));

        assert!(
            result.is_ok(),
            "canonical deserialization of corrupted secret bytes must not panic"
        );

        assert!(
            result.unwrap().is_err(),
            "canonical deserialization of corrupted secret bytes must return Err"
        );
    }
);

serial_test!(
    fn added_113_regression_fuzz_artifact_from_secret_returns_err_not_panic() -> TestResult {
        let secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let result = assert_finishes_quickly(
            "from_secret fuzz timeout artifact regression",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::from_secret(secret)
                }))
            },
        );

        assert!(
            result.is_ok(),
            "from_secret must not panic on fuzz timeout artifact"
        );
        assert!(
            result.unwrap().is_err(),
            "from_secret must reject fuzz timeout artifact secret material"
        );

        Ok(())
    }
);

serial_test!(
    fn added_114_regression_fuzz_artifact_raw_deserialize_returns_err_not_panic() -> TestResult {
        let valid_public_owner = generate_keypair()?;
        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(malformed_secret.as_ref());
        raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        let result = assert_finishes_quickly(
            "raw deserialize fuzz timeout artifact regression",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&raw)
                }))
            },
        );

        assert!(
            result.is_ok(),
            "raw deserialize must not panic on fuzz timeout artifact"
        );
        assert!(
            result.unwrap().is_err(),
            "raw deserialize must reject malformed fuzz artifact secret material"
        );

        Ok(())
    }
);

serial_test!(
    fn added_115_regression_fuzz_artifact_canonical_deserialize_returns_err_not_panic() -> TestResult
    {
        let valid_public_owner = generate_keypair()?;
        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(malformed_secret.as_ref());
        canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        let result = assert_finishes_quickly(
            "canonical deserialize fuzz timeout artifact regression",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&canonical)
                }))
            },
        );

        assert!(
            result.is_ok(),
            "canonical deserialize must not panic on fuzz timeout artifact"
        );
        assert!(
            result.unwrap().is_err(),
            "canonical deserialize must reject malformed fuzz artifact secret material"
        );

        Ok(())
    }
);

serial_test!(
    fn added_116_regression_fuzz_artifact_does_not_poison_later_valid_generation() -> TestResult {
        let secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::from_secret(secret)
        }));

        assert!(rejected.is_ok(), "bad artifact path must not panic");
        assert!(rejected.unwrap().is_err(), "bad artifact must be rejected");

        let valid = generate_keypair()?;
        valid.validate_self().map_err(debug_err)?;

        assert!(valid.get_signing_key().is_ok());
        assert!(valid.get_verifying_key().is_ok());

        Ok(())
    }
);

serial_test!(
    fn added_117_regression_fuzz_artifact_repeated_attempts_do_not_poison_later_valid_use()
    -> TestResult {
        for attempt in 0..3 {
            let secret = rotated_repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                fuzz_timeout_artifact_seed_bytes(),
                attempt,
            );

            let result = assert_finishes_quickly(
                "repeated fuzz artifact from_secret attempt",
                std::time::Duration::from_secs(10),
                || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::from_secret(secret)
                    }))
                },
            );

            assert!(
                result.is_ok(),
                "from_secret attempt {attempt} must not panic"
            );
            assert!(
                result.unwrap().is_err(),
                "from_secret attempt {attempt} must reject malformed secret"
            );
        }

        let valid = generate_keypair()?;
        valid.validate_self().map_err(debug_err)?;

        Ok(())
    }
);

serial_test!(
    fn added_118_regression_corrupted_valid_secret_returns_err_not_panic() -> TestResult {
        let valid_secret_owner = generate_keypair()?;
        let valid_public_owner = generate_keypair()?;

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(valid_secret_owner.secret_bytes_slice());
        raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        // Corrupt secret bytes while keeping public bytes parseable. This forces the
        // invariant path to reject instead of panic/timeout.
        flip_byte(&mut raw, 0)?;
        flip_byte(&mut raw, MlDsa65Keypair::SECRET_LEN / 2)?;
        flip_byte(&mut raw, MlDsa65Keypair::SECRET_LEN - 1)?;

        let result = assert_finishes_quickly(
            "corrupted valid secret raw deserialize regression",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&raw)
                }))
            },
        );

        assert!(
            result.is_ok(),
            "corrupted valid secret raw deserialize must not panic"
        );
        assert!(
            result.unwrap().is_err(),
            "corrupted valid secret raw deserialize must reject"
        );

        Ok(())
    }
);

serial_test!(
    fn added_119_regression_fuzz_artifact_canonical_rejects_and_valid_roundtrip_still_works()
    -> TestResult {
        let valid_public_owner = generate_keypair()?;
        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let mut bad_canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        bad_canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        bad_canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        bad_canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        bad_canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        bad_canonical.extend_from_slice(malformed_secret.as_ref());
        bad_canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert!(
            MlDsa65Keypair::deserialize_canonical(&bad_canonical).is_err(),
            "bad canonical fuzz artifact frame must be rejected"
        );

        let valid = generate_keypair()?;
        let good_canonical = serialize_canonical(&valid)?;
        let decoded = deserialize_canonical(&good_canonical)?;

        assert_eq!(decoded.secret_bytes_slice(), valid.secret_bytes_slice());
        assert_eq!(decoded.public_bytes_slice(), valid.public_bytes_slice());

        Ok(())
    }
);

serial_test!(
    fn added_120_regression_fuzz_artifact_import_paths_all_fail_closed() -> TestResult {
        let valid_public_owner = generate_keypair()?;
        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let from_secret_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::from_secret(malformed_secret)
        }));

        assert!(
            from_secret_result.is_ok(),
            "from_secret path must not panic"
        );
        assert!(
            from_secret_result.unwrap().is_err(),
            "from_secret path must fail closed"
        );

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(malformed_secret.as_ref());
        raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        let raw_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::deserialize(&raw)
        }));

        assert!(raw_result.is_ok(), "raw deserialize path must not panic");
        assert!(
            raw_result.unwrap().is_err(),
            "raw deserialize path must fail closed"
        );

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(malformed_secret.as_ref());
        canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        let canonical_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::deserialize_canonical(&canonical)
        }));

        assert!(
            canonical_result.is_ok(),
            "canonical deserialize path must not panic"
        );
        assert!(
            canonical_result.unwrap().is_err(),
            "canonical deserialize path must fail closed"
        );

        Ok(())
    }
);

// ─────────────────────────────────────────────────────────────────────────────
// Regression tests for v3 malformed secret parse artifact
// Tests 121..125
// ─────────────────────────────────────────────────────────────────────────────

fn v3_parse_timeout_artifact_seed_bytes() -> &'static [u8] {
    &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfb,
    ]
}

fn v3_repeat_seed_to_array<const N: usize>(seed: &[u8]) -> [u8; N] {
    assert!(!seed.is_empty(), "seed must not be empty");

    let mut out = [0_u8; N];

    for i in 0..N {
        out[i] = seed[i % seed.len()];
    }

    out
}

fn v3_assert_finishes_quickly<T>(
    label: &'static str,
    max_elapsed: std::time::Duration,
    f: impl FnOnce() -> T,
) -> T {
    let started = std::time::Instant::now();
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

serial_test!(
    fn added_121_get_signing_key_valid_generated_key_still_works_after_v3() -> TestResult {
        let kp = generate_keypair()?;

        let result = v3_assert_finishes_quickly(
            "valid get_signing_key after v3",
            std::time::Duration::from_secs(10),
            || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kp.get_signing_key())),
        );

        assert!(
            result.is_ok(),
            "get_signing_key must not panic for a valid generated keypair"
        );
        assert!(
            result.unwrap().is_ok(),
            "get_signing_key must succeed for a valid generated keypair"
        );

        Ok(())
    }
);

serial_test!(
    fn added_122_repeated_get_signing_key_calls_do_not_poison_later_valid_use() -> TestResult {
        let kp = generate_keypair()?;

        for round in 0..8 {
            let result = v3_assert_finishes_quickly(
                "repeated valid get_signing_key after v3",
                std::time::Duration::from_secs(10),
                || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kp.get_signing_key())),
            );

            assert!(
                result.is_ok(),
                "get_signing_key round {round} must not panic"
            );
            assert!(
                result.unwrap().is_ok(),
                "get_signing_key round {round} must succeed"
            );
        }

        let later_valid = generate_keypair()?;
        assert!(
            later_valid.get_signing_key().is_ok(),
            "repeated valid signing-key parses must not poison later valid keypairs"
        );

        Ok(())
    }
);

serial_test!(
    fn added_123_malformed_from_secret_parse_timeout_artifact_returns_err_not_panic() -> TestResult
    {
        let malformed_secret = v3_repeat_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            v3_parse_timeout_artifact_seed_bytes(),
        );

        let result = v3_assert_finishes_quickly(
            "v3 from_secret parse-timeout artifact",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::from_secret(malformed_secret)
                }))
            },
        );

        assert!(
            result.is_ok(),
            "from_secret must not panic on v3 parse-timeout artifact"
        );
        assert!(
            result.unwrap().is_err(),
            "from_secret must reject v3 parse-timeout artifact"
        );

        Ok(())
    }
);

serial_test!(
    fn added_124_malformed_raw_deserialize_parse_timeout_artifact_returns_err_not_panic()
    -> TestResult {
        let valid_public_owner = generate_keypair()?;
        let malformed_secret = v3_repeat_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            v3_parse_timeout_artifact_seed_bytes(),
        );

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(malformed_secret.as_ref());
        raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        let result = v3_assert_finishes_quickly(
            "v3 raw deserialize parse-timeout artifact",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&raw)
                }))
            },
        );

        assert!(
            result.is_ok(),
            "raw deserialize must not panic on v3 parse-timeout artifact"
        );
        assert!(
            result.unwrap().is_err(),
            "raw deserialize must reject v3 parse-timeout artifact"
        );

        Ok(())
    }
);

serial_test!(
    fn added_125_malformed_canonical_deserialize_parse_timeout_artifact_returns_err_not_panic()
    -> TestResult {
        let valid_public_owner = generate_keypair()?;
        let malformed_secret = v3_repeat_seed_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            v3_parse_timeout_artifact_seed_bytes(),
        );

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(malformed_secret.as_ref());
        canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        let result = v3_assert_finishes_quickly(
            "v3 canonical deserialize parse-timeout artifact",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&canonical)
                }))
            },
        );

        assert!(
            result.is_ok(),
            "canonical deserialize must not panic on v3 parse-timeout artifact"
        );
        assert!(
            result.unwrap().is_err(),
            "canonical deserialize must reject v3 parse-timeout artifact"
        );

        Ok(())
    }
);

// ─────────────────────────────────────────────────────────────────────────────
// Regression tests for cleaned production import/validation hardening
// Tests 127..130
// ─────────────────────────────────────────────────────────────────────────────

serial_test!(
    fn added_127_no_worker_timeout_contract_and_validation_budget_is_bounded() -> TestResult {
        assert!(
            MlDsa65Keypair::VALIDATE_INVARIANTS_BUDGET_MILLIS <= 2_000,
            "validation budget must not drift toward multi-second stalls"
        );

        let valid = generate_keypair()?;
        valid.validate_self().map_err(debug_err)?;
        assert!(valid.get_signing_key().is_ok());
        assert!(valid.get_verifying_key().is_ok());

        Ok(())
    }
);

serial_test!(
    fn added_128_serialization_is_bounded_byte_copy_not_revalidation_loop() -> TestResult {
        let kp = generate_keypair()?;

        // Prove the key is valid once. After that, serialization should be a
        // bounded byte-copy operation and should not repeatedly parse/derive.
        kp.validate_self().map_err(debug_err)?;

        let result = assert_finishes_quickly(
            "repeated raw/canonical serialization should be bounded byte-copy",
            std::time::Duration::from_secs(2),
            || -> TestResult {
                for round in 0..256 {
                    let raw = serialize_raw(&kp)?;
                    let canonical = serialize_canonical(&kp)?;

                    assert_eq!(
                        raw.len(),
                        MlDsa65Keypair::RAW_SERIALIZED_LEN,
                        "raw length mismatch at round {round}"
                    );

                    assert_eq!(
                        canonical.len(),
                        MlDsa65Keypair::CANONICAL_SERIALIZED_LEN,
                        "canonical length mismatch at round {round}"
                    );

                    assert_eq!(
                        canonical.get(MlDsa65Keypair::CANONICAL_HEADER_LEN..),
                        Some(raw.as_slice()),
                        "canonical body must match raw body at round {round}"
                    );
                }

                Ok(())
            },
        );

        result
    }
);

serial_test!(
    fn added_129_exact_five_byte_timeout_artifact_is_rejected_immediately_by_decoders() -> TestResult
    {
        // This is the exact minimized libFuzzer timeout input:
        // Output of std::fmt::Debug: [226, 99, 255, 59, 208]
        //
        // Direct decoders must reject it by length immediately. It must never
        // reach private-key parse/derive.
        let artifact = [226_u8, 99_u8, 255_u8, 59_u8, 208_u8];

        let result = assert_finishes_quickly(
            "exact 5-byte timeout artifact direct decode",
            std::time::Duration::from_millis(100),
            || {
                let raw_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&artifact)
                }));

                let canonical_result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::deserialize_canonical(&artifact)
                    }));

                (raw_result, canonical_result)
            },
        );

        let (raw_result, canonical_result) = result;

        assert!(
            raw_result.is_ok(),
            "raw deserialize must not panic on exact 5-byte timeout artifact"
        );
        assert!(
            raw_result.unwrap().is_err(),
            "raw deserialize must reject exact 5-byte timeout artifact"
        );

        assert!(
            canonical_result.is_ok(),
            "canonical deserialize must not panic on exact 5-byte timeout artifact"
        );
        assert!(
            canonical_result.unwrap().is_err(),
            "canonical deserialize must reject exact 5-byte timeout artifact"
        );

        Ok(())
    }
);

serial_test!(
    fn added_130_full_size_fuzz_artifact_import_rejects_fast_and_valid_key_still_works()
    -> TestResult {
        let valid_public_owner = generate_keypair()?;
        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let mut raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        raw.extend_from_slice(malformed_secret.as_ref());
        raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        let raw_result = assert_finishes_quickly(
            "full-size fuzz artifact raw import should reject fast",
            std::time::Duration::from_secs(2),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&raw)
                }))
            },
        );

        assert!(
            raw_result.is_ok(),
            "full-size fuzz artifact raw import must not panic"
        );
        assert!(
            raw_result.unwrap().is_err(),
            "full-size fuzz artifact raw import must reject malformed key material"
        );

        let mut canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        canonical.extend_from_slice(malformed_secret.as_ref());
        canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(canonical.len(), MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);

        let canonical_result = assert_finishes_quickly(
            "full-size fuzz artifact canonical import should reject fast",
            std::time::Duration::from_secs(2),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&canonical)
                }))
            },
        );

        assert!(
            canonical_result.is_ok(),
            "full-size fuzz artifact canonical import must not panic"
        );
        assert!(
            canonical_result.unwrap().is_err(),
            "full-size fuzz artifact canonical import must reject malformed key material"
        );

        // After rejecting bad imported key material, normal valid key operations
        // must still work.
        let valid = generate_keypair()?;
        valid.validate_self().map_err(debug_err)?;

        let valid_raw = serialize_raw(&valid)?;
        let valid_canonical = serialize_canonical(&valid)?;

        let decoded_raw = deserialize_raw(&valid_raw)?;
        let decoded_canonical = deserialize_canonical(&valid_canonical)?;

        assert_eq!(decoded_raw.secret_bytes_slice(), valid.secret_bytes_slice());
        assert_eq!(decoded_raw.public_bytes_slice(), valid.public_bytes_slice());

        assert_eq!(
            decoded_canonical.secret_bytes_slice(),
            valid.secret_bytes_slice()
        );
        assert_eq!(
            decoded_canonical.public_bytes_slice(),
            valid.public_bytes_slice()
        );

        Ok(())
    }
);

serial_test!(
    fn added_131_malformed_secret_import_does_not_poison_later_from_secret() -> TestResult {
        let valid = generate_keypair()?;
        let valid_secret = valid.to_bytes();

        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let rejected = assert_finishes_quickly(
            "malformed secret import must fail closed without poisoning later from_secret",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::from_secret(malformed_secret)
                }))
            },
        );

        assert!(
            rejected.is_ok(),
            "malformed from_secret path must not panic"
        );
        assert!(
            rejected.unwrap().is_err(),
            "malformed from_secret path must reject invalid secret material"
        );

        let rebuilt = MlDsa65Keypair::from_secret(valid_secret).map_err(debug_err)?;

        assert_eq!(rebuilt.secret_bytes_slice(), valid.secret_bytes_slice());
        assert_eq!(rebuilt.public_bytes_slice(), valid.public_bytes_slice());

        rebuilt.validate_self().map_err(debug_err)?;

        Ok(())
    }
);

serial_test!(
    fn added_132_malformed_raw_and_canonical_imports_do_not_poison_later_valid_decodes()
    -> TestResult {
        let valid = generate_keypair()?;
        let valid_public_owner = generate_keypair()?;

        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let mut bad_raw = Vec::with_capacity(MlDsa65Keypair::RAW_SERIALIZED_LEN);
        bad_raw.extend_from_slice(malformed_secret.as_ref());
        bad_raw.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(bad_raw.len(), MlDsa65Keypair::RAW_SERIALIZED_LEN);

        let bad_raw_result = assert_finishes_quickly(
            "malformed raw import must fail closed without poisoning later raw decode",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize(&bad_raw)
                }))
            },
        );

        assert!(bad_raw_result.is_ok(), "bad raw import must not panic");
        assert!(
            bad_raw_result.unwrap().is_err(),
            "bad raw import must reject"
        );

        let mut bad_canonical = Vec::with_capacity(MlDsa65Keypair::CANONICAL_SERIALIZED_LEN);
        bad_canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_MAGIC.as_ref());
        bad_canonical.push(MlDsa65Keypair::CANONICAL_VERSION);
        bad_canonical.push(MlDsa65Keypair::CANONICAL_FLAGS);
        bad_canonical.extend_from_slice(MlDsa65Keypair::CANONICAL_RESERVED.as_ref());
        bad_canonical.extend_from_slice(malformed_secret.as_ref());
        bad_canonical.extend_from_slice(valid_public_owner.public_bytes_slice());

        assert_eq!(
            bad_canonical.len(),
            MlDsa65Keypair::CANONICAL_SERIALIZED_LEN
        );

        let bad_canonical_result = assert_finishes_quickly(
            "malformed canonical import must fail closed without poisoning later canonical decode",
            std::time::Duration::from_secs(10),
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    MlDsa65Keypair::deserialize_canonical(&bad_canonical)
                }))
            },
        );

        assert!(
            bad_canonical_result.is_ok(),
            "bad canonical import must not panic"
        );
        assert!(
            bad_canonical_result.unwrap().is_err(),
            "bad canonical import must reject"
        );

        let good_raw = serialize_raw(&valid)?;
        let good_canonical = serialize_canonical(&valid)?;

        let decoded_raw = deserialize_raw(&good_raw)?;
        let decoded_canonical = deserialize_canonical(&good_canonical)?;

        assert_eq!(decoded_raw.secret_bytes_slice(), valid.secret_bytes_slice());
        assert_eq!(decoded_raw.public_bytes_slice(), valid.public_bytes_slice());

        assert_eq!(
            decoded_canonical.secret_bytes_slice(),
            valid.secret_bytes_slice()
        );
        assert_eq!(
            decoded_canonical.public_bytes_slice(),
            valid.public_bytes_slice()
        );

        Ok(())
    }
);

serial_test!(
    fn added_133_repeated_malformed_secret_attempts_do_not_disable_valid_key_operations()
    -> TestResult {
        for shift in 0..6 {
            let malformed_secret = rotated_repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
                fuzz_timeout_artifact_seed_bytes(),
                shift,
            );

            let rejected = assert_finishes_quickly(
                "rotated malformed secret import must fail closed",
                std::time::Duration::from_secs(10),
                || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        MlDsa65Keypair::from_secret(malformed_secret)
                    }))
                },
            );

            assert!(
                rejected.is_ok(),
                "malformed from_secret attempt {shift} must not panic"
            );
            assert!(
                rejected.unwrap().is_err(),
                "malformed from_secret attempt {shift} must reject"
            );
        }

        let valid = generate_keypair()?;

        for round in 0..6 {
            assert!(
                valid.validate_self().is_ok(),
                "valid keypair must still validate after malformed attempts; round {round}"
            );
            assert!(
                valid.get_signing_key().is_ok(),
                "valid get_signing_key must still work after malformed attempts; round {round}"
            );
            assert!(
                valid.get_verifying_key().is_ok(),
                "valid get_verifying_key must still work after malformed attempts; round {round}"
            );
        }

        Ok(())
    }
);

serial_test!(
    fn added_134_wrong_length_inputs_reject_immediately_and_valid_operations_still_work()
    -> TestResult {
        let bad_lengths = [
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

        for len in bad_lengths {
            let data = vec![0xA5_u8; len];

            if len != MlDsa65Keypair::RAW_SERIALIZED_LEN {
                let raw_result = assert_finishes_quickly(
                    "wrong-length raw input must reject immediately",
                    std::time::Duration::from_millis(250),
                    || {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            MlDsa65Keypair::deserialize(&data)
                        }))
                    },
                );

                assert!(
                    raw_result.is_ok(),
                    "raw wrong-length input must not panic; len={len}"
                );
                assert!(
                    raw_result.unwrap().is_err(),
                    "raw wrong-length input must reject; len={len}"
                );
            }

            if len != MlDsa65Keypair::CANONICAL_SERIALIZED_LEN {
                let canonical_result = assert_finishes_quickly(
                    "wrong-length canonical input must reject immediately",
                    std::time::Duration::from_millis(250),
                    || {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            MlDsa65Keypair::deserialize_canonical(&data)
                        }))
                    },
                );

                assert!(
                    canonical_result.is_ok(),
                    "canonical wrong-length input must not panic; len={len}"
                );
                assert!(
                    canonical_result.unwrap().is_err(),
                    "canonical wrong-length input must reject; len={len}"
                );
            }
        }

        let valid = generate_keypair()?;
        valid.validate_self().map_err(debug_err)?;
        assert!(valid.get_signing_key().is_ok());
        assert!(valid.get_verifying_key().is_ok());

        Ok(())
    }
);

serial_test!(
    fn added_135_panic_hook_is_restored_after_malformed_secret_parse() -> TestResult {
        let previous_hook = std::panic::take_hook();

        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_fired_for_hook = std::sync::Arc::clone(&hook_fired);

        std::panic::set_hook(Box::new(move |_| {
            hook_fired_for_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let malformed_secret = repeat_bytes_to_array::<{ MlDsa65Keypair::SECRET_LEN }>(
            fuzz_timeout_artifact_seed_bytes(),
        );

        let parse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlDsa65Keypair::from_secret(malformed_secret)
        }));

        let hook_probe = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            panic!("panic hook restoration probe after ML-DSA-65 malformed parse");
        }));

        let hook_was_restored = hook_fired.load(std::sync::atomic::Ordering::SeqCst);

        std::panic::set_hook(previous_hook);

        assert!(
            parse_result.is_ok(),
            "malformed parse path must not panic through the caller"
        );
        assert!(
            parse_result.unwrap().is_err(),
            "malformed parse path must reject invalid secret material"
        );
        assert!(
            hook_probe.is_err(),
            "panic hook probe must panic inside catch_unwind"
        );
        assert!(
            hook_was_restored,
            "panic hook was not restored after ML-DSA-65 malformed secret parsing"
        );

        Ok(())
    }
);
