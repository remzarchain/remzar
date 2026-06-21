#![no_main]

use libfuzzer_sys::fuzz_target;

// ─────────────────────────────────────────────────────────────────────────────
// network stubs
// ─────────────────────────────────────────────────────────────────────────────

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// utility stubs
// ─────────────────────────────────────────────────────────────────────────────

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const GENESIS_PREV_HASH_HEX: &'static str =
                "0000000000000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000000000000000";

            pub const GENESIS_MERKLE_ROOT_HEX: &'static str =
                "29f984fad3389b577d75f22c4c849b1a848fb2ae9e458778ea36bd1765a79dab\
                 29f984fad3389b577d75f22c4c849b1a848fb2ae9e458778ea36bd1765a79dab";

            // Keep this smaller than production so pad_to_max_size is fuzz-fast.
            pub const MAX_BLOCK_SIZE: u64 = 7_500;

            pub const MIN_TIMESTAMP_SECS: u64 = 1;
            pub const MAX_FUTURE_DRIFT_SECS: u64 = 2 * 60 * 60;

            // Required by the real src/utility/time_policy.rs.
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
            pub const MAX_FUTURE_SKEW_SECS: u64 = 2 * 60 * 60;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
            TimestampError {
                message: String,
                details: String,
                source: Option<std::time::SystemTimeError>,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, tx_id } => {
                        write!(f, "validation error: {message}; tx_id={tx_id:?}")
                    }
                    Self::SerializationError { details } => {
                        write!(f, "serialization error: {details}")
                    }
                    Self::TimestampError {
                        message,
                        details,
                        source,
                    } => {
                        write!(
                            f,
                            "timestamp error: {message}; {details}; source={source:?}"
                        )
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod time_policy {
        pub use crate::real_time_policy::*;
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        pub fn decode_hex_to_64(hex_str: &str) -> Result<[u8; 64], ErrorDetection> {
            let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();

            let bytes = hex::decode(&cleaned).map_err(|e| ErrorDetection::ValidationError {
                message: format!("Invalid hex in configuration: {e:?}"),
                tx_id: None,
            })?;

            if bytes.len() != 64 {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Expected 64-byte value in configuration, got {} bytes",
                        bytes.len()
                    ),
                    tx_id: None,
                });
            }

            let mut out = [0u8; 64];
            out.copy_from_slice(&bytes);
            Ok(out)
        }

        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            if !b[1..]
                .iter()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }

        pub fn parse_wallet_address(id: &str) -> Result<(), ErrorDetection> {
            canon_wallet_id_checked(id).map(|_| ())
        }
    }

    pub mod hash_system_remzarhash {
        pub struct RemzarHash;

        impl RemzarHash {
            pub fn compute_bytes_hash(bytes: &[u8]) -> [u8; 64] {
                let mut hasher = blake3::Hasher::new();
                hasher.update(bytes);

                let mut out = [0u8; 64];
                hasher.finalize_xof().fill(&mut out);
                out
            }

            pub fn compute_dummy_hash() -> String {
                hex::encode(Self::compute_bytes_hash(b"REMZAR_DUMMY_BATCH_KEY"))
            }
        }
    }
}

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

// ─────────────────────────────────────────────────────────────────────────────
// REAL FILE UNDER TEST
// ─────────────────────────────────────────────────────────────────────────────

#[path = "../../src/blockchain/genesis_001_block.rs"]
mod genesis_001_block;

use genesis_001_block::GenesisBlock;

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz helpers
// ─────────────────────────────────────────────────────────────────────────────

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

fn fuzz_hash(data: &[u8], salt: usize) -> [u8; 64] {
    let mut out = [0u8; 64];

    for i in 0..64 {
        out[i] = byte_at(data, salt + i, i as u8)
            ^ byte_at(data, salt + i.wrapping_mul(7), 0xA5)
            ^ (salt as u8)
            ^ (i as u8);
    }

    if out == [0u8; 64] {
        out[0] = 1;
    }

    out
}

fn canonical_wallet(data: &[u8], salt: usize) -> String {
    format!("r{}", hex::encode(fuzz_hash(data, salt)))
}

fn maybe_wallet(data: &[u8], salt: usize) -> String {
    match byte_at(data, salt, 0) % 7 {
        0 => String::new(),
        1 => "not-a-wallet".to_string(),
        2 => "r1234".to_string(),
        3 => format!("x{}", hex::encode(fuzz_hash(data, salt + 1))),
        4 => canonical_wallet(data, salt + 2).to_ascii_uppercase(),
        5 => format!(" {} ", canonical_wallet(data, salt + 3)),
        _ => canonical_wallet(data, salt + 4),
    }
}

fn make_data_string(data: &[u8]) -> String {
    match byte_at(data, 0, 0) % 8 {
        0 => String::new(),
        1 => "   ".to_string(),
        2 => "Remzar Genesis".to_string(),
        3 => String::from_utf8_lossy(&data[..data.len().min(256)]).to_string(),
        4 => "A".repeat(1024),
        5 => "B".repeat(1025),
        6 => {
            let len = usize::from(byte_at(data, 8, 32)).min(128);
            (0..len)
                .map(|i| {
                    let b = byte_at(data, 16 + i, b'X');
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        'G'
                    }
                })
                .collect()
        }
        _ => format!("genesis-{}", hex::encode(&data[..data.len().min(32)])),
    }
}

fn mutate_json(json: String, data: &[u8]) -> String {
    match byte_at(data, 300, 0) % 6 {
        0 => json,
        1 => json.replace("\"genesis_hash\"", "\"bad_genesis_hash\""),
        2 => json.replace('0', "z"),
        3 => format!("{json}\n{{"),
        4 => json.replace("\"founder_wallet\"", "\"founder_wallet_extra\""),
        _ => data
            .iter()
            .take(512)
            .map(|b| {
                if b.is_ascii() {
                    *b as char
                } else {
                    'x'
                }
            })
            .collect(),
    }
}

fn exercise_valid_block(data: &[u8]) {
    let genesis_data = make_data_string(data);
    let ts = match byte_at(data, 1, 0) % 5 {
        0 => 0,
        1 => 1,
        2 => read_u64(data, 32),
        3 => 946_684_800,
        _ => u64::MAX.saturating_sub(read_u64(data, 40) % 1024),
    };

    let miner = maybe_wallet(data, 64);

    let g = GenesisBlock::new_with_timestamp_and_miner(&genesis_data, ts, &miner);

    let Ok(block) = g else {
        return;
    };

    // Core validation.
    let _ = block.validate();

    let now = match byte_at(data, 2, 0) % 4 {
        0 => 1,
        1 => block.timestamp,
        2 => block.timestamp.saturating_sub(read_u64(data, 96) % 10_000),
        _ => block.timestamp.saturating_add(read_u64(data, 104) % 10_000),
    };
    let _ = block.validate_against_now(now);

    // Founder wallet/miner helpers.
    let _ = block.founder_wallet();
    let _ = block.miner_for_genesis_block();

    // Hash helper.
    let hex_hash = block.genesis_hash_hex();
    assert_eq!(hex_hash.len(), 128);

    // Binary postcard roundtrip.
    if let Ok(encoded) = block.serialize() {
        if let Ok(decoded) = GenesisBlock::deserialize(&encoded) {
            assert_eq!(decoded.genesis_hash, block.genesis_hash);
            assert_eq!(decoded.merkle_root, block.merkle_root);
            assert_eq!(decoded.prev_hash, block.prev_hash);
            assert_eq!(decoded.data, block.data);
            assert_eq!(decoded.founder_wallet, block.founder_wallet);
            let _ = decoded.validate();
        }

        // Exact storage serialization.
        let _ = block.serialize_for_storage();

        // Zero-padding must be accepted.
        let mut zero_padded = encoded.clone();
        zero_padded.extend(std::iter::repeat(0u8).take(usize::from(byte_at(data, 120, 0) % 64)));
        let _ = GenesisBlock::deserialize(&zero_padded);

        // Non-zero trailing junk should be rejected when appended after a valid postcard.
        let mut junk = encoded;
        junk.push(byte_at(data, 121, 1).max(1));
        let _ = GenesisBlock::deserialize(&junk);
    }

    // Fix size padded storage path.
    if byte_at(data, 122, 0) & 1 == 1 {
        if let Ok(padded) = block.pad_to_max_size() {
            assert_eq!(
                padded.len(),
                utility::alpha_001_global_configuration::GlobalConfiguration::MAX_BLOCK_SIZE
                    as usize
            );

            let _ = GenesisBlock::deserialize(&padded);
        }
    }

    // JSON roundtrip and malformed JSON input.
    if let Ok(json) = block.to_json() {
        if let Ok(decoded) = GenesisBlock::from_json(&json) {
            assert_eq!(decoded.genesis_hash, block.genesis_hash);
            let _ = decoded.validate();
        }

        let mutated = mutate_json(json, data);
        let _ = GenesisBlock::from_json(&mutated);
    }

    // File JSON roundtrip using a temp file.
    if byte_at(data, 123, 0) & 1 == 1 {
        let path = std::env::temp_dir().join(format!(
            "remzar_genesis_fuzz_{}_{}.json",
            std::process::id(),
            hex::encode(&fuzz_hash(data, 700)[..8])
        ));

        if let Some(path_str) = path.to_str() {
            if block.to_json_file(path_str).is_ok() {
                let _ = GenesisBlock::from_json_file(path_str);
                let _ = std::fs::remove_file(path_str);
            }
        }
    }
}

fn exercise_raw_deserialize(data: &[u8]) {
    // Feed arbitrary bytes into strict postcard deserializer.
    let _ = GenesisBlock::deserialize(data);

    // Feed arbitrary bytes into JSON parser as well.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = GenesisBlock::from_json(s);
    }
}

fn exercise_manual_corruption(data: &[u8]) {
    let Ok(mut block) =
        GenesisBlock::new_with_timestamp_and_miner("Remzar Genesis", 946_684_800, "")
    else {
        return;
    };

    match byte_at(data, 500, 0) % 8 {
        0 => block.genesis_hash = [0u8; 64],
        1 => block.merkle_root = [0u8; 64],
        2 => block.prev_hash = block.genesis_hash,
        3 => block.merkle_root = block.prev_hash,
        4 => block.data.clear(),
        5 => block.data = "X".repeat(1025),
        6 => block.timestamp = 0,
        _ => block.founder_wallet = Some(maybe_wallet(data, 520)),
    }

    let _ = block.validate();

    if let Ok(json) = block.to_json() {
        let _ = GenesisBlock::from_json(&json);
    }

    if let Ok(bytes) = block.serialize() {
        let _ = GenesisBlock::deserialize(&bytes);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz entry
// ─────────────────────────────────────────────────────────────────────────────

fuzz_target!(|data: &[u8]| {
    exercise_valid_block(data);
    exercise_raw_deserialize(data);
    exercise_manual_corruption(data);

    // Also hit the current-time constructor path.
    if byte_at(data, 900, 0) & 1 == 1 {
        let s = make_data_string(data);
        let _ = GenesisBlock::new(&s);
    }

    if byte_at(data, 901, 0) & 1 == 1 {
        let s = make_data_string(data);
        let _ = GenesisBlock::new_with_timestamp(&s, read_u64(data, 920));
    }
});