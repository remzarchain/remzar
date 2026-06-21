#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
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
            TimestampError {
                message: String,
                details: String,
                source: Option<std::time::SystemTimeError>,
            },
            SerializationError {
                details: String,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    ErrorDetection::ValidationError { message, tx_id } => {
                        write!(f, "Validation error: {message}, tx_id={tx_id:?}")
                    }
                    ErrorDetection::TimestampError {
                        message,
                        details,
                        source,
                    } => {
                        write!(
                            f,
                            "Timestamp error: {message}; {details}; source={source:?}"
                        )
                    }
                    ErrorDetection::SerializationError { details } => {
                        write!(f, "Serialization error: {details}")
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
        use super::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_BODY_LEN: usize = 128;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        #[inline]
        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            // Accept R/r and uppercase/lowercase hex at input boundaries.
            // Return canonical lowercase "r" + 128 lowercase hex.
            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            if !b.get(1..).is_some_and(|body| {
                body.len() == REMZAR_WALLET_BODY_LEN
                    && body
                        .iter()
                        .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            }) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }
    }
}

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

#[path = "../../src/blockchain/transaction_002_tx_register.rs"]
mod register_node_tx;

use register_node_tx::RegisterNodeTx;

const WALLET_LEN: usize = 129;
const UNIX_2000: u64 = 946_684_800;
const DETERMINISTIC_NOW: u64 = 1_776_000_000;

fuzz_target!(|data: &[u8]| {
    // 1) Treat arbitrary input as hostile wire bytes.
    // These must never panic, even for nonsense data.
    let _ = RegisterNodeTx::deserialize(data);
    let _ = RegisterNodeTx::deserialize_for_mempool(data);
    let _ = RegisterNodeTx::new_from_bytes(data);

    // 2) Deterministic valid wallet from fuzz input.
    let wallet = wallet_from_input(0xA5, data);

    // 3) Replay-safe structural roundtrip with deterministic timestamp.
    fuzz_structural_roundtrip(data, &wallet);

    // 4) Runtime/mempool behavior using caller-provided deterministic `now`.
    fuzz_runtime_mempool_checks(&wallet);

    // 5) Constructor and byte constructor input coverage.
    fuzz_constructors(data, &wallet);

    // 6) Wire-level mutation:
    // trailing bytes, bad timestamps, malformed wallets, canonicalization behavior.
    fuzz_wire_transactions(data, &wallet);
});

fn fuzz_structural_roundtrip(data: &[u8], wallet: &str) {
    let timestamp = valid_structural_timestamp(data, 0);

    let tx = RegisterNodeTx {
        wallet_address: wallet_to_arr(wallet),
        timestamp,
    };

    tx.validate()
        .expect("deterministic structural RegisterNodeTx must validate");

    let wallet_str = tx
        .wallet_str()
        .expect("deterministic wallet must be valid UTF-8");

    assert_eq!(wallet_str, wallet);

    let encoded = tx
        .serialize()
        .expect("deterministic RegisterNodeTx must serialize");

    let decoded = RegisterNodeTx::deserialize(&encoded)
        .expect("serialized valid RegisterNodeTx must deserialize structurally");

    assert_eq!(decoded, tx);

    decoded
        .validate()
        .expect("decoded RegisterNodeTx must validate structurally");

    assert_eq!(
        decoded.wallet_str().expect("decoded wallet string must work"),
        wallet
    );

    let _ = RegisterNodeTx::deserialize_for_mempool(&encoded);
}

fn fuzz_runtime_mempool_checks(wallet: &str) {
    let max_skew =
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_FUTURE_SKEW_SECS;

    let exact_now = RegisterNodeTx {
        wallet_address: wallet_to_arr(wallet),
        timestamp: DETERMINISTIC_NOW,
    };

    exact_now
        .validate_for_mempool_at(DETERMINISTIC_NOW)
        .expect("timestamp equal to now must pass mempool validation");

    let max_allowed = RegisterNodeTx {
        wallet_address: wallet_to_arr(wallet),
        timestamp: DETERMINISTIC_NOW.saturating_add(max_skew),
    };

    max_allowed
        .validate_for_mempool_at(DETERMINISTIC_NOW)
        .expect("timestamp at max future skew must pass mempool validation");

    let too_future = RegisterNodeTx {
        wallet_address: wallet_to_arr(wallet),
        timestamp: DETERMINISTIC_NOW
            .saturating_add(max_skew)
            .saturating_add(1),
    };

    assert!(
        too_future
            .validate_for_mempool_at(DETERMINISTIC_NOW)
            .is_err(),
        "mempool validation accepted timestamp beyond allowed future skew"
    );

    // Structural replay validation must not compare to local wall clock.
    too_future
        .validate()
        .expect("structural validation should accept valid UNIX-range future timestamp");
}

fn fuzz_constructors(data: &[u8], wallet: &str) {
    // Runtime constructors use wall-clock internally.
    // If construction succeeds, all structural invariants must hold.
    let selector = data.get(8).copied().unwrap_or(0);
    let wallet_input = mutate_wallet_string(wallet, selector);

    if let Ok(tx) = RegisterNodeTx::new(wallet_input) {
        tx.validate()
            .expect("RegisterNodeTx::new returned Ok but structural validate failed");

        let encoded = tx
            .serialize()
            .expect("RegisterNodeTx::new returned Ok but serialize failed");

        let decoded = RegisterNodeTx::deserialize(&encoded)
            .expect("RegisterNodeTx::new returned Ok but deserialize failed");

        decoded
            .validate()
            .expect("RegisterNodeTx::new decoded result failed validation");

        // No hard assertion on deserialize_for_mempool because it uses runtime clock.
        let _ = RegisterNodeTx::deserialize_for_mempool(&encoded);
    }

    fuzz_new_from_bytes(data, wallet);
}

fn fuzz_new_from_bytes(data: &[u8], wallet: &str) {
    // Exact canonical bytes.
    let exact = wallet.as_bytes();

    let tx = RegisterNodeTx::new_from_bytes(exact)
        .expect("canonical wallet bytes must construct");

    tx.validate()
        .expect("new_from_bytes exact canonical result must validate");

    // Trailing NUL padding should be trimmed by register_node_tx.rs.
    let mut padded = exact.to_vec();
    let pad_len = usize::from(data.first().copied().unwrap_or(0) % 32);
    padded.extend(std::iter::repeat(0).take(pad_len));

    let padded_tx = RegisterNodeTx::new_from_bytes(&padded)
        .expect("trailing NUL-padded wallet bytes must construct");

    padded_tx
        .validate()
        .expect("trailing NUL-padded result must validate");

    assert_eq!(
        padded_tx
            .wallet_str()
            .expect("padded wallet string must work"),
        wallet
    );

    // Uppercase / R-prefix should canonicalize back to lowercase.
    let upper_wallet = fixed_wallet_with_letters().to_ascii_uppercase();

    let upper_tx = RegisterNodeTx::new_from_bytes(upper_wallet.as_bytes())
        .expect("uppercase canonicalizable wallet bytes must construct");

    upper_tx
        .validate()
        .expect("uppercase canonicalized result must validate");

    assert_eq!(
        upper_tx
            .wallet_str()
            .expect("uppercase canonicalized wallet string must work"),
        fixed_wallet_with_letters()
    );

    // Embedded NUL must be rejected.
    let mut embedded_nul = exact.to_vec();
    if embedded_nul.len() > 10 {
        embedded_nul[10] = 0;
    }

    assert!(
        RegisterNodeTx::new_from_bytes(&embedded_nul).is_err(),
        "new_from_bytes accepted embedded NUL"
    );

    // Invalid UTF-8 must be rejected.
    let mut invalid_utf8 = exact.to_vec();
    if invalid_utf8.len() > 20 {
        invalid_utf8[20] = 0xff;
    }

    assert!(
        RegisterNodeTx::new_from_bytes(&invalid_utf8).is_err(),
        "new_from_bytes accepted invalid UTF-8"
    );

    // Random short slice should not panic.
    let short_len = usize::from(data.get(1).copied().unwrap_or(0)) % WALLET_LEN;
    let _ = RegisterNodeTx::new_from_bytes(&exact[..short_len]);

    // Fully arbitrary fuzz bytes should not panic.
    let _ = RegisterNodeTx::new_from_bytes(data);
}

fn fuzz_wire_transactions(data: &[u8], wallet: &str) {
    let base = RegisterNodeTx {
        wallet_address: wallet_to_arr(wallet),
        timestamp: valid_structural_timestamp(data, 16),
    };

    let valid_bytes = base
        .serialize()
        .expect("base valid RegisterNodeTx must serialize");

    RegisterNodeTx::deserialize(&valid_bytes)
        .expect("base valid RegisterNodeTx must deserialize structurally");

    // Runtime mempool deserialize uses local wall-clock.
    // Exercise it as no-panic only.
    let _ = RegisterNodeTx::deserialize_for_mempool(&valid_bytes);

    // Trailing bytes must be rejected.
    let mut trailing = valid_bytes.clone();
    trailing.push(data.get(3).copied().unwrap_or(0));

    assert!(
        RegisterNodeTx::deserialize(&trailing).is_err(),
        "structural deserializer accepted trailing bytes"
    );

    let _ = RegisterNodeTx::deserialize_for_mempool(&trailing);

    // Timestamp before year 2000 must be rejected structurally.
    let mut too_old = base.clone();
    too_old.timestamp = UNIX_2000 - 1;

    let too_old_bytes = postcard::to_allocvec(&too_old)
        .expect("manual postcard encode of too-old timestamp should work");

    assert!(
        RegisterNodeTx::deserialize(&too_old_bytes).is_err(),
        "deserializer accepted timestamp before year 2000"
    );

    assert!(
        RegisterNodeTx::deserialize_for_mempool(&too_old_bytes).is_err(),
        "mempool deserializer accepted timestamp before year 2000"
    );

    // Runtime future skew must be rejected by deterministic mempool validation.
    // Structural deserialize is replay-safe and must not compare to local wall clock.
    let max_skew =
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_FUTURE_SKEW_SECS;

    let mut too_future = base.clone();
    too_future.timestamp = DETERMINISTIC_NOW
        .saturating_add(max_skew)
        .saturating_add(1);

    assert!(
        too_future
            .validate_for_mempool_at(DETERMINISTIC_NOW)
            .is_err(),
        "deterministic mempool validation accepted timestamp beyond allowed future skew"
    );

    let too_future_bytes = postcard::to_allocvec(&too_future)
        .expect("manual postcard encode of too-future timestamp should work");

    let structural = RegisterNodeTx::deserialize(&too_future_bytes);

    assert!(
        structural.is_ok(),
        "structural deserialize should accept valid UNIX-range future timestamp"
    );

    // Runtime mempool deserialize uses real now. Exercise only as no-panic.
    let _ = RegisterNodeTx::deserialize_for_mempool(&too_future_bytes);

    // Malformed stored wallet bytes must be rejected on deserialize.
    let mut bad_wallet = base.clone();

    match data.get(4).copied().unwrap_or(0) % 5 {
        0 => bad_wallet.wallet_address[0] = b'x',           // wrong prefix
        1 => bad_wallet.wallet_address[1] = b'g',           // non-hex
        2 => bad_wallet.wallet_address[10] = 0,             // embedded NUL
        3 => bad_wallet.wallet_address[50] = 0xff,          // invalid UTF-8
        _ => bad_wallet.wallet_address = [0u8; WALLET_LEN], // empty after trim
    }

    let bad_wallet_bytes = postcard::to_allocvec(&bad_wallet)
        .expect("manual postcard encode of malformed wallet should work");

    assert!(
        RegisterNodeTx::deserialize(&bad_wallet_bytes).is_err(),
        "deserializer accepted malformed wallet bytes"
    );

    assert!(
        RegisterNodeTx::deserialize_for_mempool(&bad_wallet_bytes).is_err(),
        "mempool deserializer accepted malformed wallet bytes"
    );

    let upper_wallet = fixed_wallet_with_letters().to_ascii_uppercase();

    let mut upper_stored = RegisterNodeTx {
        wallet_address: wallet_to_arr(fixed_wallet_with_letters()),
        timestamp: UNIX_2000,
    };

    upper_stored
        .wallet_address
        .copy_from_slice(upper_wallet.as_bytes());

    assert!(
        upper_stored.validate().is_err(),
        "validate accepted uppercase non-canonical stored wallet bytes"
    );

    let upper_bytes = postcard::to_allocvec(&upper_stored)
        .expect("manual postcard encode of uppercase stored wallet must work");

    let decoded = RegisterNodeTx::deserialize(&upper_bytes)
        .expect("deserialize should canonicalize uppercase wallet bytes");

    assert_eq!(
        decoded
            .wallet_str()
            .expect("decoded canonical wallet must be UTF-8"),
        fixed_wallet_with_letters()
    );

    decoded
        .validate()
        .expect("canonicalized decoded tx must validate");
}

fn valid_structural_timestamp(data: &[u8], offset: usize) -> u64 {
    let raw = read_u64(data, offset);
    UNIX_2000.saturating_add(raw % (365 * 24 * 60 * 60 * 20))
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-register-node-wallet-v1");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

fn wallet_to_arr(wallet: &str) -> [u8; WALLET_LEN] {
    let mut arr = [0u8; WALLET_LEN];
    let bytes = wallet.as_bytes();
    let len = bytes.len().min(WALLET_LEN);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

fn fixed_wallet_with_letters() -> &'static str {
    // 1 prefix + 128 hex chars.
    "rabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
}

fn mutate_wallet_string(wallet: &str, selector: u8) -> String {
    match selector % 10 {
        // Valid canonical.
        0 => wallet.to_owned(),

        // Valid canonicalizable uppercase.
        1 => wallet.to_ascii_uppercase(),

        // Valid canonicalizable with whitespace.
        2 => format!(" \n{wallet}\t "),

        // Invalid: too short.
        3 => wallet.get(1..).unwrap_or("").to_owned(),

        // Invalid: too long.
        4 => format!("{wallet}00"),

        // Invalid: wrong prefix.
        5 => {
            let mut v = wallet.as_bytes().to_vec();

            if let Some(first) = v.first_mut() {
                *first = b'x';
            }

            String::from_utf8_lossy(&v).into_owned()
        }

        // Invalid: non-hex body.
        6 => {
            let mut v = wallet.as_bytes().to_vec();

            if v.len() > 1 {
                v[1] = b'g';
            }

            String::from_utf8_lossy(&v).into_owned()
        }

        // Invalid: embedded NUL.
        7 => {
            let mut v = wallet.as_bytes().to_vec();

            if v.len() > 10 {
                v[10] = 0;
            }

            String::from_utf8_lossy(&v).into_owned()
        }

        // Invalid: empty.
        8 => String::new(),

        // Invalid-ish malformed visible string from bad UTF-8 replacement.
        _ => {
            let mut v = wallet.as_bytes().to_vec();

            if v.len() > 5 {
                v[5] = 0xff;
            }

            String::from_utf8_lossy(&v).into_owned()
        }
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for (i, slot) in out.iter_mut().enumerate() {
        *slot = data.get(offset + i).copied().unwrap_or(0);
    }

    u64::from_le_bytes(out)
}