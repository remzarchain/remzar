#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        use crate::utility::helper::UNIT_DIVISOR;

        pub struct GlobalConfiguration;

        impl GlobalConfiguration {

            pub const MAX_BLOCK_REWARD: u64 = 20 * UNIT_DIVISOR;

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
                    Self::ValidationError { message, tx_id } => {
                        write!(f, "Validation error: {message}, tx_id={tx_id:?}")
                    }
                    Self::TimestampError {
                        message,
                        details,
                        source,
                    } => write!(
                        f,
                        "Timestamp error: {message}; {details}; source={source:?}"
                    ),
                    Self::SerializationError { details } => {
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

        pub const UNIT_DIVISOR: u64 = 100_000_000;
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

        #[inline]
        pub fn parse_wallet_address_bytes(
            bytes: &[u8; REMZAR_WALLET_LEN],
        ) -> Result<String, ErrorDetection> {
            if bytes.iter().any(|&b| b == 0) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address contains NUL byte".into(),
                    tx_id: None,
                });
            }

            let s = core::str::from_utf8(bytes).map_err(|_| ErrorDetection::ValidationError {
                message: "Wallet address bytes are not valid UTF-8".into(),
                tx_id: None,
            })?;

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            let b = s.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            // Existing stored RewardTx bytes must already be canonical lowercase.
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

            Ok(s.to_string())
        }

        #[inline]
        pub fn from_micro_units(amount: u64) -> f64 {
            let whole = amount / UNIT_DIVISOR;
            let frac = amount % UNIT_DIVISOR;
            let s = format!("{whole}.{frac:08}");
            s.parse::<f64>().unwrap_or(0.0)
        }
    }
}

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

#[path = "../../src/blockchain/transaction_003_tx_reward.rs"]
mod transaction_003_tx_reward;

use transaction_003_tx_reward::RewardTx;
use utility::alpha_001_global_configuration::GlobalConfiguration;

const WALLET_LEN: usize = 129;
const UNIX_2000: u64 = 946_684_800;
const DETERMINISTIC_NOW: u64 = 1_776_000_000;
const STRUCTURAL_WINDOW_SECS: u64 = 365 * 24 * 60 * 60 * 20;

fuzz_target!(|data: &[u8]| {
    // 1) Raw hostile wire bytes. Must never panic.
    let _ = RewardTx::deserialize(data);

    // 2) Deterministic valid receiver and bounded valid values.
    let receiver = wallet_from_input(0xA5, data);
    let amount = valid_amount_from_input(data, 0);
    let block_height = read_u64(data, 8).max(1);
    let timestamp = valid_structural_timestamp(data, 16);

    // 3) Preferred constructor: explicit block timestamp.
    fuzz_explicit_timestamp_roundtrip(&receiver, amount, block_height, timestamp);

    // 4) Backward-compatible runtime constructor.
    fuzz_runtime_constructor(data, &receiver, amount, block_height);

    // 5) Boundary and invalid constructor behavior.
    fuzz_constructor_boundaries(data, &receiver, block_height, timestamp);

    // 6) Wire-level malformed structs encoded with postcard directly.
    fuzz_wire_transactions(data, &receiver, amount, block_height, timestamp);

    // 7) Runtime-only and block-time timestamp checks.
    fuzz_runtime_and_block_timestamp_checks(&receiver, amount, block_height, timestamp);
});

fn fuzz_explicit_timestamp_roundtrip(
    receiver: &str,
    amount: u64,
    block_height: u64,
    timestamp: u64,
) {
    let tx = RewardTx::new_with_timestamp(receiver.to_owned(), amount, block_height, timestamp)
        .expect("deterministic valid RewardTx::new_with_timestamp must construct");

    assert_eq!(tx.amount, amount);
    assert_eq!(tx.block_height, block_height);
    assert_eq!(tx.timestamp, timestamp);
    assert_eq!(tx.receiver, wallet_to_arr(receiver));

    tx.validate()
        .expect("fresh deterministic RewardTx must validate structurally");

    let encoded = tx
        .serialize()
        .expect("fresh deterministic RewardTx must serialize");

    let decoded = RewardTx::deserialize(&encoded)
        .expect("serialized valid RewardTx must deserialize structurally");

    assert_eq!(decoded, tx);

    decoded
        .validate()
        .expect("decoded RewardTx must validate structurally");

    assert_eq!(decoded.amount_as_remzar(), tx.amount_as_remzar());
}

fn fuzz_runtime_constructor(data: &[u8], receiver: &str, amount: u64, block_height: u64) {
    let selector = data.get(24).copied().unwrap_or(0);
    let receiver_input = mutate_wallet_string(receiver, selector);

    let amount_input = match selector % 5 {
        0 => amount,
        1 => 1,
        2 => GlobalConfiguration::MAX_BLOCK_REWARD,
        3 => 0,
        _ => GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(1),
    };

    let block_height_input = if selector & 0b1000_0000 != 0 {
        0
    } else {
        block_height
    };

    let result = RewardTx::new(receiver_input, amount_input, block_height_input);

    if let Ok(tx) = result {
        tx.validate()
            .expect("RewardTx::new returned Ok but validate failed");

        assert!(tx.amount > 0);
        assert!(tx.amount <= GlobalConfiguration::MAX_BLOCK_REWARD);
        assert!(tx.block_height > 0);

        let encoded = tx
            .serialize()
            .expect("RewardTx::new returned Ok but serialize failed");

        let decoded = RewardTx::deserialize(&encoded)
            .expect("RewardTx::new returned Ok but deserialize failed");

        decoded
            .validate()
            .expect("RewardTx::new decoded result failed validation");
    }
}

fn fuzz_constructor_boundaries(data: &[u8], receiver: &str, block_height: u64, timestamp: u64) {
    // Canonicalizable receiver should be accepted by constructor and stored lowercase.
    let uppercase = receiver.to_ascii_uppercase();
    let upper_tx = RewardTx::new_with_timestamp(uppercase, 1, block_height, timestamp)
        .expect("uppercase canonicalizable receiver should construct");
    assert_eq!(upper_tx.receiver, wallet_to_arr(receiver));

    let trimmed = format!(" \n{receiver}\t ");
    let trimmed_tx = RewardTx::new_with_timestamp(trimmed, 1, block_height, timestamp)
        .expect("whitespace-trimmed canonicalizable receiver should construct");
    assert_eq!(trimmed_tx.receiver, wallet_to_arr(receiver));

    // Minimum and maximum valid amount should pass.
    RewardTx::new_with_timestamp(receiver.to_owned(), 1, block_height, timestamp)
        .expect("minimum valid reward amount must construct")
        .validate()
        .expect("minimum valid reward amount must validate");

    RewardTx::new_with_timestamp(
        receiver.to_owned(),
        GlobalConfiguration::MAX_BLOCK_REWARD,
        block_height,
        timestamp,
    )
    .expect("maximum valid reward amount must construct")
    .validate()
    .expect("maximum valid reward amount must validate");

    // Invalid constructor inputs should return Err, not panic.
    assert!(RewardTx::new_with_timestamp(receiver.to_owned(), 0, block_height, timestamp).is_err());
    assert!(RewardTx::new_with_timestamp(
        receiver.to_owned(),
        GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(1),
        block_height,
        timestamp,
    )
    .is_err());
    assert!(RewardTx::new_with_timestamp(receiver.to_owned(), 1, 0, timestamp).is_err());
    assert!(RewardTx::new_with_timestamp(receiver.to_owned(), 1, block_height, UNIX_2000 - 1)
        .is_err());

    for selector in 0u8..10 {
        let mutated = mutate_wallet_string(receiver, selector ^ data.first().copied().unwrap_or(0));
        let _ = RewardTx::new_with_timestamp(mutated, 1, block_height, timestamp);
    }

    // Exact UNIX_2000 should pass.
    RewardTx::new_with_timestamp(receiver.to_owned(), 1, block_height, UNIX_2000)
        .expect("exact UNIX_2000 timestamp must construct");
}

fn fuzz_wire_transactions(
    data: &[u8],
    receiver: &str,
    amount: u64,
    block_height: u64,
    timestamp: u64,
) {
    let base = RewardTx::new_with_timestamp(receiver.to_owned(), amount, block_height, timestamp)
        .expect("base valid RewardTx must construct");

    let valid_bytes = base
        .serialize()
        .expect("base valid RewardTx must serialize");

    RewardTx::deserialize(&valid_bytes).expect("base valid RewardTx must deserialize");

    // Trailing bytes must be rejected by canonical deserialize.
    let mut trailing = valid_bytes.clone();
    trailing.push(data.get(25).copied().unwrap_or(0));
    assert!(
        RewardTx::deserialize(&trailing).is_err(),
        "deserializer accepted trailing bytes"
    );

    // Important: bypass serialize() for malformed structs, because serialize()
    // intentionally refuses malformed existing transactions before bytes exist.
    let mut zero_amount = base.clone();
    zero_amount.amount = 0;
    assert_deserialize_rejects_manual_postcard(&zero_amount, "zero reward amount");

    let mut too_large_amount = base.clone();
    too_large_amount.amount = GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(1);
    assert_deserialize_rejects_manual_postcard(&too_large_amount, "reward amount above max");

    let mut zero_height = base.clone();
    zero_height.block_height = 0;
    assert_deserialize_rejects_manual_postcard(&zero_height, "zero block height");

    let mut too_old = base.clone();
    too_old.timestamp = UNIX_2000 - 1;
    assert_deserialize_rejects_manual_postcard(&too_old, "timestamp before UNIX_2000");

    let mut bad_receiver = base.clone();
    match data.get(26).copied().unwrap_or(0) % 6 {
        0 => bad_receiver.receiver[0] = b'x',           // wrong prefix
        1 => bad_receiver.receiver[1] = b'g',           // non-hex
        2 => bad_receiver.receiver[1] = b'A',           // uppercase stored hex is non-canonical
        3 => bad_receiver.receiver[10] = 0,             // NUL byte
        4 => bad_receiver.receiver[50] = 0xff,          // invalid UTF-8
        _ => bad_receiver.receiver = [0u8; WALLET_LEN], // empty/NUL-filled
    }
    assert_deserialize_rejects_manual_postcard(&bad_receiver, "malformed receiver bytes");

    // Direct validate() must reject uppercase stored receiver bytes.
    let upper_wallet = fixed_wallet_with_letters().to_ascii_uppercase();
    let mut upper_stored = RewardTx::new_with_timestamp(
        fixed_wallet_with_letters().to_owned(),
        1,
        1,
        UNIX_2000,
    )
    .expect("fixed wallet RewardTx must construct");
    upper_stored.receiver.copy_from_slice(upper_wallet.as_bytes());

    assert!(
        upper_stored.validate().is_err(),
        "validate accepted uppercase non-canonical stored receiver bytes"
    );
    assert_deserialize_rejects_manual_postcard(
        &upper_stored,
        "uppercase non-canonical stored receiver bytes",
    );
}

fn fuzz_runtime_and_block_timestamp_checks(
    receiver: &str,
    amount: u64,
    block_height: u64,
    timestamp: u64,
) {
    let max_skew = GlobalConfiguration::MAX_FUTURE_SKEW_SECS;

    let exact_now = RewardTx::new_with_timestamp(
        receiver.to_owned(),
        amount,
        block_height,
        DETERMINISTIC_NOW,
    )
    .expect("exact-now reward must construct");
    exact_now
        .validate_for_runtime_at(DETERMINISTIC_NOW)
        .expect("timestamp equal to now must pass runtime validation");

    let max_allowed = RewardTx::new_with_timestamp(
        receiver.to_owned(),
        amount,
        block_height,
        DETERMINISTIC_NOW.saturating_add(max_skew),
    )
    .expect("max-skew reward must construct structurally");
    max_allowed
        .validate_for_runtime_at(DETERMINISTIC_NOW)
        .expect("timestamp at max future skew must pass runtime validation");

    let too_future = RewardTx::new_with_timestamp(
        receiver.to_owned(),
        amount,
        block_height,
        DETERMINISTIC_NOW.saturating_add(max_skew).saturating_add(1),
    )
    .expect("too-future reward must construct structurally");
    assert!(
        too_future.validate_for_runtime_at(DETERMINISTIC_NOW).is_err(),
        "runtime validation accepted timestamp beyond allowed future skew"
    );

    // Replay-safe structural serialize/deserialize should not compare to local clock.
    let too_future_bytes = too_future
        .serialize()
        .expect("structurally valid future reward must serialize");
    RewardTx::deserialize(&too_future_bytes)
        .expect("structural deserialize must accept valid UNIX-range future timestamp");

    let block_time_tx = RewardTx::new_with_timestamp(
        receiver.to_owned(),
        amount,
        block_height,
        timestamp,
    )
    .expect("block-time reward must construct");

    block_time_tx
        .validate_against_block_timestamp(timestamp, 0)
        .expect("exact matching block timestamp must pass");

    block_time_tx
        .validate_against_block_timestamp(timestamp.saturating_add(5), 5)
        .expect("timestamp exactly inside allowed block window must pass");

    assert!(
        block_time_tx
            .validate_against_block_timestamp(timestamp.saturating_add(6), 5)
            .is_err(),
        "block timestamp window accepted a timestamp outside allowed delta"
    );
}

fn assert_deserialize_rejects_manual_postcard(tx: &RewardTx, label: &str) {
    let bytes = postcard::to_allocvec(tx).expect("manual postcard encode should work");
    assert!(
        RewardTx::deserialize(&bytes).is_err(),
        "deserializer accepted malformed RewardTx: {label}"
    );
}

fn valid_amount_from_input(data: &[u8], offset: usize) -> u64 {
    let max = GlobalConfiguration::MAX_BLOCK_REWARD;
    let raw = read_u64(data, offset);
    (raw % max).saturating_add(1)
}

fn valid_structural_timestamp(data: &[u8], offset: usize) -> u64 {
    let raw = read_u64(data, offset);
    UNIX_2000.saturating_add(raw % STRUCTURAL_WINDOW_SECS)
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-reward-tx-wallet-v2");
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
        0 => wallet.to_owned(),
        1 => wallet.to_ascii_uppercase(),
        2 => format!(" \n{wallet}\t "),
        3 => wallet.get(1..).unwrap_or("").to_owned(),
        4 => format!("{wallet}00"),
        5 => {
            let mut v = wallet.as_bytes().to_vec();
            if let Some(first) = v.first_mut() {
                *first = b'x';
            }
            String::from_utf8_lossy(&v).into_owned()
        }
        6 => {
            let mut v = wallet.as_bytes().to_vec();
            if v.len() > 1 {
                v[1] = b'g';
            }
            String::from_utf8_lossy(&v).into_owned()
        }
        7 => {
            let mut v = wallet.as_bytes().to_vec();
            if v.len() > 10 {
                v[10] = 0;
            }
            String::from_utf8_lossy(&v).into_owned()
        }
        8 => String::new(),
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
