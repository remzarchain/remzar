#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
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
        pub fn to_micro_units_str(s: &str) -> u64 {
            const SCALE: u64 = 100_000_000;
            const MAX_INPUT_LEN: usize = 64;

            let s = s.trim();

            if s.is_empty() || s.len() > MAX_INPUT_LEN {
                return 0;
            }

            if s.starts_with('-') || s.starts_with('+') {
                return 0;
            }

            if s.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
                return 0;
            }

            if s.contains('e') || s.contains('E') {
                return 0;
            }

            let (whole_part, frac_part) = match s.split_once('.') {
                Some((w, f)) => {
                    if f.contains('.') {
                        return 0;
                    }
                    (w, f)
                }
                None => (s, ""),
            };

            if whole_part.is_empty() && frac_part.is_empty() {
                return 0;
            }

            let whole_str = if whole_part.is_empty() {
                "0"
            } else {
                whole_part
            };

            if !whole_str.as_bytes().iter().all(|b| b.is_ascii_digit()) {
                return 0;
            }

            if !frac_part.as_bytes().iter().all(|b| b.is_ascii_digit()) {
                return 0;
            }

            if frac_part.len() > 8 {
                return 0;
            }

            let whole = match whole_str.parse::<u64>() {
                Ok(v) => v,
                Err(_) => return 0,
            };

            let mut frac: u64 = 0;

            for &b in frac_part.as_bytes() {
                let digit = match b.checked_sub(b'0') {
                    Some(d) => u64::from(d),
                    None => return 0,
                };

                frac = match frac.checked_mul(10).and_then(|v| v.checked_add(digit)) {
                    Some(v) => v,
                    None => return 0,
                };
            }

            for _ in frac_part.len()..8 {
                frac = match frac.checked_mul(10) {
                    Some(v) => v,
                    None => return 0,
                };
            }

            let whole_scaled = match whole.checked_mul(SCALE) {
                Some(v) => v,
                None => return 0,
            };

            whole_scaled.checked_add(frac).unwrap_or_default()
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

#[path = "../../src/blockchain/transaction_001_tx.rs"]
mod transaction_001_tx;

use transaction_001_tx::Transaction;

const WALLET_LEN: usize = 129;
const UNIX_2000: u64 = 946_684_800;
const DETERMINISTIC_NOW: u64 = 1_776_000_000;
const TWENTY_YEARS_SECS: u64 = 365 * 24 * 60 * 60 * 20;
const MAX_REASONABLE_TX_AMOUNT: u64 = 10_000_000_000_000_000;
const MAX_OPS: usize = 48;

// ─────────────────────────────────────────────────────────────
// Main target
// ─────────────────────────────────────────────────────────────

fuzz_target!(|data: &[u8]| {
    // 1) Raw hostile wire bytes must never panic.
    let _ = Transaction::deserialize(data);
    let _ = Transaction::deserialize_for_mempool(data);

    // 2) Always exercise known-good paths once per input.
    let sender = wallet_from_input(0xA5, data);
    let receiver = wallet_from_input(0x5A, data);
    let amount = bounded_nonzero_amount(read_u64_at(data, 0));

    fuzz_structural_roundtrip(data, &sender, &receiver, amount);
    fuzz_deterministic_mempool_checks(&sender, &receiver, amount);
    fuzz_constructor_canonicalization(data, &sender, &receiver, amount);
    fuzz_fixed_amount_conversions(&sender, &receiver);
    fuzz_invalid_canonical_cases(data, &sender, &receiver, amount);

    // 3) Then drive many input-selected operation cases.
    let mut r = Reader::new(data);
    let op_count = 1 + r.usize(MAX_OPS);

    for _ in 0..op_count {
        let op = r.byte() % 12;
        let sender = wallet_from_reader(&mut r, 0x10);
        let receiver = wallet_from_reader(&mut r, 0x20);
        let amount = bounded_nonzero_amount(r.u64());

        match op {
            0 => fuzz_raw_slice(&mut r),
            1 => fuzz_generated_struct(&mut r, &sender, &receiver, amount),
            2 => fuzz_constructor_matrix(&mut r, &sender, &receiver, amount),
            3 => fuzz_remzar_constructor_matrix(&mut r, &sender, &receiver),
            4 => fuzz_malformed_postcard_structs(&mut r, &sender, &receiver, amount),
            5 => fuzz_timestamp_edges(&mut r, &sender, &receiver, amount),
            6 => fuzz_wallet_byte_edges(&mut r, &sender, &receiver, amount),
            7 => fuzz_trailing_and_canonical_bytes(&mut r, &sender, &receiver, amount),
            8 => fuzz_id_and_amount_views(&mut r, &sender, &receiver, amount),
            9 => fuzz_alias_constructor(&mut r, &sender, &receiver),
            10 => fuzz_cross_roundtrip_mutation(&mut r, &sender, &receiver, amount),
            _ => fuzz_helper_amount_strings(&mut r),
        }
    }
});

// ─────────────────────────────────────────────────────────────
// Core invariants
// ─────────────────────────────────────────────────────────────

fn fuzz_structural_roundtrip(data: &[u8], sender: &str, receiver: &str, amount: u64) {
    let tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: valid_structural_timestamp(read_u64_at(data, 16)),
    };

    tx.validate()
        .expect("deterministic valid transaction must validate");

    let encoded = tx
        .serialize()
        .expect("deterministic valid transaction must serialize");

    let decoded = Transaction::deserialize(&encoded)
        .expect("serialized valid transaction must deserialize structurally");

    assert_eq!(decoded, tx);
    assert_eq!(decoded.amount, amount);
    assert_eq!(decoded.sender, wallet_to_arr(sender));
    assert_eq!(decoded.receiver, wallet_to_arr(receiver));

    let id = decoded.id().expect("valid transaction id must hash");
    assert_eq!(id.len(), 64);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));

    let _ = decoded.amount_as_remzar();
    let _ = decoded.amount_as_aos();

    // Runtime mempool deserialize uses local wall clock. Exercise as no-panic only.
    let _ = Transaction::deserialize_for_mempool(&encoded);
}

fn fuzz_deterministic_mempool_checks(sender: &str, receiver: &str, amount: u64) {
    let max_skew =
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_FUTURE_SKEW_SECS;

    let exact_now = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: DETERMINISTIC_NOW,
    };

    exact_now
        .validate_for_mempool_at(DETERMINISTIC_NOW)
        .expect("timestamp equal to now must pass mempool validation");

    let max_allowed = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: DETERMINISTIC_NOW.saturating_add(max_skew),
    };

    max_allowed
        .validate_for_mempool_at(DETERMINISTIC_NOW)
        .expect("timestamp at max future skew must pass mempool validation");

    let too_future = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
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

fn fuzz_constructor_canonicalization(data: &[u8], sender: &str, receiver: &str, amount: u64) {
    let selector = data.first().copied().unwrap_or(0);

    let sender_input = mutate_wallet_string(sender, selector);
    let receiver_input = if selector & 0b0010_0000 != 0 {
        sender_input.clone()
    } else {
        mutate_wallet_string(receiver, selector.rotate_left(1))
    };

    let amount_input = if selector & 0b0100_0000 != 0 {
        0
    } else {
        amount
    };

    let result = Transaction::new(sender_input, receiver_input, amount_input);

    if let Ok(tx) = result {
        tx.validate()
            .expect("Transaction::new returned Ok but structural validate failed");

        assert!(tx.amount > 0);

        let encoded = tx
            .serialize()
            .expect("Transaction::new returned Ok but serialize failed");

        let decoded = Transaction::deserialize(&encoded)
            .expect("Transaction::new returned Ok but canonical deserialize failed");

        assert_eq!(decoded, tx);

        // Runtime mempool deserialize uses local clock. No hard assertion.
        let _ = Transaction::deserialize_for_mempool(&encoded);
    }
}

fn fuzz_fixed_amount_conversions(sender: &str, receiver: &str) {
    let one_micro = Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), 0.00000001)
        .expect("one micro REMZAR should construct");
    assert_eq!(one_micro.amount, 1);

    let one_remzar = Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), 1.0)
        .expect("one REMZAR should construct");
    assert_eq!(one_remzar.amount, 100_000_000);

    let exact = Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), 1.23456789)
        .expect("8-decimal REMZAR value should construct exactly");
    assert_eq!(exact.amount, 123_456_789);

    for tx in [one_micro, one_remzar, exact] {
        tx.validate().expect("fixed conversion tx must validate");
        let encoded = tx.serialize().expect("fixed conversion tx must serialize");
        let decoded = Transaction::deserialize(&encoded).expect("fixed conversion tx must decode");
        assert_eq!(decoded, tx);
    }

    assert!(Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), 0.0).is_err());
    assert!(Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), -1.0).is_err());
    assert!(Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), f64::NAN).is_err());
    assert!(
        Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), f64::INFINITY)
            .is_err()
    );
}

fn fuzz_invalid_canonical_cases(data: &[u8], sender: &str, receiver: &str, amount: u64) {
    let base = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: valid_structural_timestamp(read_u64_at(data, 32)),
    };

    let valid_bytes = base
        .serialize()
        .expect("base valid tx must serialize");

    Transaction::deserialize(&valid_bytes)
        .expect("base valid tx must deserialize");

    // Trailing bytes must be rejected by canonical byte equality.
    let mut trailing = valid_bytes.clone();
    trailing.push(data.get(2).copied().unwrap_or(0));

    assert!(
        Transaction::deserialize(&trailing).is_err(),
        "deserializer accepted trailing bytes"
    );

    let _ = Transaction::deserialize_for_mempool(&trailing);

    // Same sender/receiver must be rejected.
    let mut same_party = base.clone();
    same_party.receiver = same_party.sender;

    let same_party_bytes = postcard::to_allocvec(&same_party)
        .expect("manual postcard encode of same-party tx should work");

    assert!(
        Transaction::deserialize(&same_party_bytes).is_err(),
        "deserializer accepted same sender/receiver"
    );

    // Zero amount must be rejected.
    let mut zero_amount = base.clone();
    zero_amount.amount = 0;

    let zero_amount_bytes = postcard::to_allocvec(&zero_amount)
        .expect("manual postcard encode of zero-amount tx should work");

    assert!(
        Transaction::deserialize(&zero_amount_bytes).is_err(),
        "deserializer accepted zero amount"
    );

    // Timestamp before year 2000 must be rejected structurally.
    let mut too_old = base.clone();
    too_old.timestamp = UNIX_2000 - 1;

    let too_old_bytes = postcard::to_allocvec(&too_old)
        .expect("manual postcard encode of too-old timestamp tx should work");

    assert!(
        Transaction::deserialize(&too_old_bytes).is_err(),
        "deserializer accepted timestamp before year 2000"
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
        .expect("manual postcard encode of too-future tx should work");

    assert!(
        Transaction::deserialize(&too_future_bytes).is_ok(),
        "structural deserialize should accept valid UNIX-range future timestamp"
    );

    let _ = Transaction::deserialize_for_mempool(&too_future_bytes);
}

// ─────────────────────────────────────────────────────────────
// Operation-driven fuzz paths
// ─────────────────────────────────────────────────────────────

fn fuzz_raw_slice(r: &mut Reader<'_>) {
    let bytes = r.bytes(512, true);
    let _ = Transaction::deserialize(&bytes);
    let _ = Transaction::deserialize_for_mempool(&bytes);

    let mut extended = bytes.clone();
    extended.extend_from_slice(&r.bytes(16, true));
    let _ = Transaction::deserialize(&extended);
    let _ = Transaction::deserialize_for_mempool(&extended);
}

fn fuzz_generated_struct(r: &mut Reader<'_>, sender: &str, receiver: &str, amount: u64) {
    let tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: valid_structural_timestamp(r.u64()),
    };

    tx.validate().expect("generated valid tx should validate");

    let bytes = tx.serialize().expect("generated valid tx should serialize");
    let decoded = Transaction::deserialize(&bytes).expect("generated valid tx should decode");

    assert_eq!(decoded, tx);
    assert_eq!(decoded.id().expect("id must hash").len(), 64);
}

fn fuzz_constructor_matrix(r: &mut Reader<'_>, sender: &str, receiver: &str, amount: u64) {
    let sender_input = mutate_wallet_string(sender, r.byte());
    let receiver_input = match r.byte() % 5 {
        0 => mutate_wallet_string(receiver, r.byte()),
        1 => sender_input.clone(),
        2 => receiver.to_ascii_uppercase(),
        3 => format!(" \t{receiver}\n"),
        _ => r.ascii_string("r", 160),
    };

    let amount_input = match r.byte() % 6 {
        0 => 0,
        1 => 1,
        2 => amount,
        3 => u64::MAX,
        4 => MAX_REASONABLE_TX_AMOUNT,
        _ => r.u64(),
    };

    let result = Transaction::new(sender_input, receiver_input, amount_input);

    if let Ok(tx) = result {
        tx.validate()
            .expect("constructor returned valid-looking tx that failed validate");
        assert!(tx.amount > 0);
        assert_ne!(tx.sender, tx.receiver);

        let encoded = tx.serialize().expect("constructed tx should serialize");
        let decoded = Transaction::deserialize(&encoded).expect("constructed tx should decode");
        assert_eq!(decoded, tx);
    }
}

fn fuzz_remzar_constructor_matrix(r: &mut Reader<'_>, sender: &str, receiver: &str) {
    let amount_remzar = match r.byte() % 18 {
        0 => f64::NAN,
        1 => f64::INFINITY,
        2 => f64::NEG_INFINITY,
        3 => 0.0,
        4 => -1.0,
        5 => f64::MIN_POSITIVE,
        6 => 0.00000001,
        7 => 1.0,
        8 => 1.23456789,
        9 => {
            let n = r.u32() % 1_000_000;
            f64::from(n) / 100_000_000.0 + 0.00000001
        }
        10 => {
            let n = r.u32() % 1_000_000_000;
            f64::from(n) + 0.12345678
        }
        11 => 184_467_440_737.0,
        12 => 184_467_440_738.0,
        13 => 999_999_999_999.99999999,
        14 => 1e13,
        _ => f64::from_bits(r.u64()),
    };

    let result = Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), amount_remzar);

    if let Ok(tx) = result {
        tx.validate()
            .expect("new_from_remzar returned Ok but validate failed");
        assert!(tx.amount > 0);

        let encoded = tx.serialize().expect("new_from_remzar tx should serialize");
        let decoded = Transaction::deserialize(&encoded).expect("new_from_remzar tx should decode");
        assert_eq!(decoded, tx);

        let _ = tx.amount_as_remzar();
        let _ = tx.amount_as_aos();
        let _ = tx.id();
    }
}

fn fuzz_malformed_postcard_structs(
    r: &mut Reader<'_>,
    sender: &str,
    receiver: &str,
    amount: u64,
) {
    let mut tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: valid_structural_timestamp(r.u64()),
    };

    match r.byte() % 12 {
        0 => tx.sender[0] = b'x',
        1 => tx.receiver[0] = b'R',
        2 => tx.sender[1] = b'g',
        3 => tx.receiver[1] = b'G',
        4 => tx.sender[10] = 0,
        5 => tx.receiver[50] = 0xff,
        6 => tx.receiver = tx.sender,
        7 => tx.amount = 0,
        8 => tx.timestamp = 0,
        9 => tx.timestamp = UNIX_2000 - 1,
        10 => tx.timestamp = u64::MAX,
        _ => {
            tx.sender[1] = b'A';
        }
    }

    let bytes = postcard::to_allocvec(&tx).expect("manual postcard encode should work");
    let _ = Transaction::deserialize(&bytes);
    let _ = Transaction::deserialize_for_mempool(&bytes);

    if tx.validate().is_ok() {
        let decoded = Transaction::deserialize(&bytes).expect("valid manual tx should decode");
        assert_eq!(decoded, tx);
    } else {
        assert!(
            Transaction::deserialize(&bytes).is_err(),
            "deserialize accepted a structurally invalid manual tx"
        );
    }
}

fn fuzz_timestamp_edges(r: &mut Reader<'_>, sender: &str, receiver: &str, amount: u64) {
    let max_skew =
        utility::alpha_001_global_configuration::GlobalConfiguration::MAX_FUTURE_SKEW_SECS;

    let timestamp = match r.byte() % 10 {
        0 => 0,
        1 => UNIX_2000 - 1,
        2 => UNIX_2000,
        3 => UNIX_2000 + 1,
        4 => DETERMINISTIC_NOW,
        5 => DETERMINISTIC_NOW + max_skew,
        6 => DETERMINISTIC_NOW + max_skew + 1,
        7 => valid_structural_timestamp(r.u64()),
        8 => 253_402_300_799, // 9999-12-31T23:59:59Z
        _ => u64::MAX,
    };

    let tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp,
    };

    let structural = tx.validate();

    if structural.is_ok() {
        let bytes = tx.serialize().expect("structurally valid timestamp should serialize");
        let decoded = Transaction::deserialize(&bytes).expect("structurally valid tx should decode");
        assert_eq!(decoded, tx);
    } else {
        assert!(tx.serialize().is_err());
        let bytes = postcard::to_allocvec(&tx).expect("manual timestamp tx encode should work");
        assert!(Transaction::deserialize(&bytes).is_err());
    }

    let deterministic_mempool = tx.validate_for_mempool_at(DETERMINISTIC_NOW);
    if timestamp <= DETERMINISTIC_NOW.saturating_add(max_skew)
        && timestamp >= UNIX_2000
        && structural.is_ok()
    {
        assert!(
            deterministic_mempool.is_ok(),
            "deterministic mempool rejected timestamp inside allowed window"
        );
    }
}

fn fuzz_wallet_byte_edges(r: &mut Reader<'_>, sender: &str, receiver: &str, amount: u64) {
    let mut tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: valid_structural_timestamp(r.u64()),
    };

    let target_sender = r.byte() & 1 == 0;
    let index = r.usize(WALLET_LEN);
    let new_byte = match r.byte() % 9 {
        0 => b'r',
        1 => b'R',
        2 => b'0',
        3 => b'9',
        4 => b'a',
        5 => b'f',
        6 => b'g',
        7 => 0,
        _ => 0xff,
    };

    if target_sender {
        tx.sender[index] = new_byte;
    } else {
        tx.receiver[index] = new_byte;
    }

    let bytes = postcard::to_allocvec(&tx).expect("manual wallet mutation encode should work");
    let decoded = Transaction::deserialize(&bytes);

    if decoded.is_ok() {
        let tx2 = decoded.unwrap();
        tx2.validate().expect("decoded tx must validate");
        assert_eq!(
            tx2.serialize().expect("decoded valid tx serializes"),
            bytes,
            "decoded tx must be canonical"
        );
    }
}

fn fuzz_trailing_and_canonical_bytes(
    r: &mut Reader<'_>,
    sender: &str,
    receiver: &str,
    amount: u64,
) {
    let tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: valid_structural_timestamp(r.u64()),
    };

    let mut bytes = tx.serialize().expect("base tx should serialize");
    let base = bytes.clone();

    match r.byte() % 5 {
        0 => bytes.push(r.byte()),
        1 => bytes.extend_from_slice(&r.bytes(32, false)),
        2 => {
            if !bytes.is_empty() {
                let idx = r.usize(bytes.len());
                bytes[idx] ^= 1 << (r.byte() % 8);
            }
        }
        3 => {
            if !bytes.is_empty() {
                bytes.truncate(r.usize(bytes.len()));
            }
        }
        _ => bytes = base.clone(),
    }

    let result = Transaction::deserialize(&bytes);

    if bytes == base {
        assert_eq!(result.expect("base canonical tx should decode"), tx);
    } else {
        // Mutations are allowed to accidentally create another valid canonical tx.
        // The invariant is no panic and, if Ok, the returned tx reserializes exactly.
        if let Ok(decoded) = result {
            decoded.validate().expect("decoded mutated tx must validate");
            assert_eq!(
                decoded.serialize().expect("decoded mutated tx serializes"),
                bytes,
                "accepted mutated tx must be canonical"
            );
        }
    }
}

fn fuzz_id_and_amount_views(r: &mut Reader<'_>, sender: &str, receiver: &str, amount: u64) {
    let tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount: match r.byte() % 6 {
            0 => 1,
            1 => 99_999_999,
            2 => 100_000_000,
            3 => u64::MAX,
            4 => MAX_REASONABLE_TX_AMOUNT,
            _ => amount,
        },
        timestamp: valid_structural_timestamp(r.u64()),
    };

    if tx.validate().is_ok() {
        let id1 = tx.id().expect("valid tx id should work");
        let id2 = tx.id().expect("valid tx id should be stable");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);

        let remzar = tx.amount_as_remzar();
        let aos = tx.amount_as_aos();
        assert_eq!(remzar.to_bits(), aos.to_bits());
    }
}

fn fuzz_alias_constructor(r: &mut Reader<'_>, sender: &str, receiver: &str) {
    let amount = match r.byte() % 10 {
        0 => f64::NAN,
        1 => f64::INFINITY,
        2 => f64::NEG_INFINITY,
        3 => 0.0,
        4 => -1.0,
        5 => 0.00000001,
        6 => 1.0,
        7 => 42.12345678,
        _ => f64::from_bits(r.u64()),
    };

    let remzar = Transaction::new_from_remzar(sender.to_owned(), receiver.to_owned(), amount);
    let aos = Transaction::new_from_aos(sender.to_owned(), receiver.to_owned(), amount);

    assert_eq!(remzar.is_ok(), aos.is_ok());

    if let Ok(tx) = remzar {
        tx.validate().expect("new_from_remzar alias case must validate");
    }

    if let Ok(tx) = aos {
        tx.validate().expect("new_from_aos alias case must validate");
    }
}

fn fuzz_cross_roundtrip_mutation(
    r: &mut Reader<'_>,
    sender: &str,
    receiver: &str,
    amount: u64,
) {
    let tx = Transaction {
        sender: wallet_to_arr(sender),
        receiver: wallet_to_arr(receiver),
        amount,
        timestamp: valid_structural_timestamp(r.u64()),
    };

    let mut bytes = tx.serialize().expect("cross mutation base must serialize");

    for _ in 0..r.usize(8) {
        if bytes.is_empty() {
            break;
        }
        let idx = r.usize(bytes.len());
        match r.byte() % 4 {
            0 => bytes[idx] = r.byte(),
            1 => bytes[idx] = bytes[idx].wrapping_add(1),
            2 => bytes[idx] ^= 0x80,
            _ => {
                bytes.remove(idx);
            }
        }
    }

    let _ = Transaction::deserialize(&bytes);
    let _ = Transaction::deserialize_for_mempool(&bytes);
}

fn fuzz_helper_amount_strings(r: &mut Reader<'_>) {
    use utility::helper::{from_micro_units, to_micro_units_str};

    let s = match r.byte() % 16 {
        0 => "",
        1 => "0",
        2 => "0.00000000",
        3 => "0.00000001",
        4 => "1",
        5 => "1.00000000",
        6 => "1.23456789",
        7 => "1.234567891",
        8 => "-1",
        9 => "+1",
        10 => "1e8",
        11 => "184467440737.00000000",
        12 => "184467440737.00000001",
        13 => "999999999999999999999999999999999999999999",
        14 => " .1",
        _ => {
            let random = r.ascii_string("", 64);
            let _ = to_micro_units_str(&random);
            return;
        }
    };

    let amount = to_micro_units_str(s);
    let human = from_micro_units(amount);

    assert!(human.is_finite() || amount == u64::MAX);
}

// ─────────────────────────────────────────────────────────────
// Reader and helpers
// ─────────────────────────────────────────────────────────────

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }
        usize::from(self.byte()) % max_exclusive
    }

    fn u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        for b in &mut out {
            *b = self.byte();
        }
        u32::from_le_bytes(out)
    }

    fn u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        for b in &mut out {
            *b = self.byte();
        }
        u64::from_le_bytes(out)
    }

    fn bytes(&mut self, max_len: usize, allow_empty: bool) -> Vec<u8> {
        let mut len = self.usize(max_len.saturating_add(1));
        if !allow_empty && len == 0 {
            len = 1;
        }

        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.byte());
        }
        out
    }

    fn ascii_string(&mut self, prefix: &str, max_len: usize) -> String {
        let len = self.usize(max_len.saturating_add(1));
        let mut out = String::with_capacity(prefix.len() + len);
        out.push_str(prefix);

        for _ in 0..len {
            let c = match self.byte() % 48 {
                0..=9 => b'0' + (self.byte() % 10),
                10..=35 => b'a' + (self.byte() % 26),
                36..=45 => b'A' + (self.byte() % 26),
                46 => b'.',
                _ => b' ',
            };
            out.push(char::from(c));
        }

        out
    }
}

fn bounded_nonzero_amount(raw: u64) -> u64 {
    (raw % MAX_REASONABLE_TX_AMOUNT).max(1)
}

fn valid_structural_timestamp(raw: u64) -> u64 {
    // Keep generated timestamps comfortably inside replay-safe UNIX bounds.
    UNIX_2000.saturating_add(raw % TWENTY_YEARS_SECS)
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-transaction-wallet-v3");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

fn wallet_from_reader(r: &mut Reader<'_>, domain: u8) -> String {
    let mut seed = [0u8; 32];
    for b in &mut seed {
        *b = r.byte();
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-transaction-wallet-reader-v3");
    hasher.update(&[domain]);
    hasher.update(&seed);

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

fn mutate_wallet_string(wallet: &str, selector: u8) -> String {
    match selector % 16 {
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
        9 => {
            let mut v = wallet.as_bytes().to_vec();
            if v.len() > 5 {
                v[5] = 0xff;
            }
            String::from_utf8_lossy(&v).into_owned()
        }
        10 => "r".to_string(),
        11 => format!("r{}", "0".repeat(127)),
        12 => format!("r{}", "0".repeat(129)),
        13 => format!("R{}", &wallet[1..]),
        14 => format!("r{}", "g".repeat(128)),
        _ => format!("r{}", "f".repeat(128)),
    }
}

fn read_u64_at(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for (i, slot) in out.iter_mut().enumerate() {
        *slot = data.get(offset + i).copied().unwrap_or(0);
    }

    u64::from_le_bytes(out)
}
