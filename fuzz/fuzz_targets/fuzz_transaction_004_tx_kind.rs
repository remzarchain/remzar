#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        use crate::utility::helper::UNIT_DIVISOR;

        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_BLOCK_REWARD: u64 = 20 * UNIT_DIVISOR;

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
                        write!(f, "Validation error: {message}, Transaction ID: {tx_id:?}")
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

            // Boundary inputs may be uppercase/canonicalizable.
            // Stored output must be lowercase canonical.
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
        pub fn parse_wallet_address_bytes(bytes: &[u8]) -> Result<String, ErrorDetection> {
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

            // Stored wallet bytes must already be canonical lowercase:
            // lowercase 'r' + 128 lowercase hex chars.
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

        // Needed by the NFT shim because TxKind serializes NFT variants.
        pub mod serde_u8_array_64 {
            use core::fmt;
            use serde::de::{Error as DeError, SeqAccess, Visitor};
            use serde::ser::SerializeTuple;
            use serde::{Deserializer, Serializer};

            pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut tup = serializer.serialize_tuple(64)?;

                for b in arr.iter() {
                    tup.serialize_element(b)?;
                }

                tup.end()
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
            where
                D: Deserializer<'de>,
            {
                struct Arr64Visitor;

                impl<'de> Visitor<'de> for Arr64Visitor {
                    type Value = [u8; 64];

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(f, "a 64-byte array")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let mut out = [0u8; 64];

                        for (i, slot) in out.iter_mut().enumerate() {
                            *slot = seq
                                .next_element::<u8>()?
                                .ok_or_else(|| DeError::invalid_length(i, &self))?;
                        }

                        if let Some(_extra) = seq.next_element::<u8>()? {
                            return Err(DeError::invalid_length(65, &self));
                        }

                        Ok(out)
                    }
                }

                deserializer.deserialize_tuple(64, Arr64Visitor)
            }
        }
    }
}

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

mod tokens {
    pub mod nft_001 {
        use blake3::Hasher;
        use serde::{Deserialize, Serialize};

        pub type Hash = [u8; 64];

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct NftMintTx {
            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub nft_id: Hash,

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub content_hash: Hash,

            pub title: String,
            pub description: String,
        }

        impl NftMintTx {
            pub fn from_content_bytes(
                nft_id: Hash,
                title: String,
                description: String,
                content_bytes: &[u8],
            ) -> Self {
                let mut hasher = Hasher::new();
                hasher.update(content_bytes);

                let mut content_hash: Hash = [0u8; 64];
                let mut reader = hasher.finalize_xof();
                reader.fill(&mut content_hash);

                Self {
                    nft_id,
                    content_hash,
                    title,
                    description,
                }
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct NftTransferTx {
            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub nft_id: Hash,

            pub new_owner_wallet: String,
        }
    }
}

mod blockchain {
    pub mod transaction_001_tx {
        include!("../../src/blockchain/transaction_001_tx.rs");
    }

    pub mod transaction_002_tx_register {
        include!("../../src/blockchain/transaction_002_tx_register.rs");
    }

    pub mod transaction_003_tx_reward {
        include!("../../src/blockchain/transaction_003_tx_reward.rs");
    }

    pub mod transaction_004_tx_kind {
        include!("../../src/blockchain/transaction_004_tx_kind.rs");
    }
}

use blockchain::transaction_001_tx::Transaction;
use blockchain::transaction_002_tx_register::RegisterNodeTx;
use blockchain::transaction_003_tx_reward::RewardTx;
use blockchain::transaction_004_tx_kind::{normalize_address_bytes, TxKind};
use tokens::nft_001::{NftMintTx, NftTransferTx};

const WALLET_LEN: usize = 129;
const MAX_BLOCK_REWARD: u64 = utility::alpha_001_global_configuration::GlobalConfiguration::MAX_BLOCK_REWARD;
const MAX_TRANSFER_AMOUNT: u64 = 10_000_000_000_000_000;
const UNIX_2000: u64 = 946_684_800;
const DETERMINISTIC_NOW: u64 = 1_776_000_000;

fuzz_target!(|data: &[u8]| {
    // 1) Hostile raw TxKind wire bytes.
    // Must never panic.
    let _ = TxKind::deserialize(data);
    fuzz_manual_wire_shapes(data);

    // 2) Deterministic valid wallets.
    let sender = wallet_from_input(0xA1, data);
    let receiver = wallet_from_input(0xB2, data);
    let nft_owner = wallet_from_input(0xC3, data);

    let transfer_amount = {
        let raw = read_u64(data, 0);
        let bounded = raw % MAX_TRANSFER_AMOUNT;
        bounded.max(1)
    };

    let reward_amount = {
        let raw = read_u64(data, 8);
        let bounded = raw % MAX_BLOCK_REWARD;
        bounded.saturating_add(1)
    };

    let block_height = read_u64(data, 16).max(1);

    // 3) Valid variants.
    fuzz_valid_transfer(&sender, &receiver, transfer_amount);
    fuzz_valid_register_node(&sender);
    fuzz_valid_reward(&receiver, reward_amount, block_height);
    fuzz_valid_nft_mint(data);
    fuzz_valid_nft_transfer(data, &nft_owner);

    // 4) Invalid inner payloads wrapped as TxKind.
    fuzz_invalid_transfer(&sender, &receiver, transfer_amount);
    fuzz_invalid_reward(&receiver, reward_amount, block_height);
    fuzz_invalid_nft_transfer(data);

    // 5) Helper behavior.
    fuzz_helpers(data, &sender, &receiver);
});

fn fuzz_valid_transfer(sender: &str, receiver: &str, amount: u64) {
    let transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), amount)
        .expect("valid transfer must construct");

    let kind = TxKind::Transfer(transfer.clone());

    kind.validate()
        .expect("valid transfer TxKind must validate");

    assert_eq!(kind.tag(), "transfer");
    assert_eq!(kind.normalized_sender().as_deref(), Some(sender));
    assert_eq!(kind.normalized_receiver().as_deref(), Some(receiver));

    let touched = kind.touched_addresses();
    assert_eq!(touched.len(), 2);
    assert!(touched.contains(&sender.to_string()));
    assert!(touched.contains(&receiver.to_string()));

    roundtrip_tx_kind(kind);
}

fn fuzz_valid_register_node(wallet: &str) {
    let register = RegisterNodeTx::new(wallet.to_owned())
        .expect("valid RegisterNodeTx must construct");

    let kind = TxKind::RegisterNode(register);

    kind.validate()
        .expect("valid RegisterNode TxKind must validate");

    assert_eq!(kind.tag(), "register_node");
    assert_eq!(kind.normalized_sender(), None);
    assert_eq!(kind.normalized_receiver(), None);
    assert!(kind.touched_addresses().is_empty());

    roundtrip_tx_kind(kind);
}

fn fuzz_valid_reward(receiver: &str, amount: u64, block_height: u64) {
    let reward = RewardTx::new_with_timestamp(
        receiver.to_owned(),
        amount,
        block_height,
        UNIX_2000.saturating_add(block_height % 100_000),
    )
    .expect("valid RewardTx must construct");

    let kind = TxKind::Reward(reward);

    kind.validate()
        .expect("valid Reward TxKind must validate");

    assert_eq!(kind.tag(), "reward");
    assert_eq!(kind.normalized_sender(), None);
    assert_eq!(kind.normalized_receiver().as_deref(), Some(receiver));

    let touched = kind.touched_addresses();
    assert_eq!(touched.len(), 1);
    assert!(touched.contains(&receiver.to_string()));

    if let TxKind::Reward(reward) = &kind {
        reward
            .validate_for_runtime_at(DETERMINISTIC_NOW)
            .expect("deterministic reward runtime validation should pass");
    }

    roundtrip_tx_kind(kind);
}

fn fuzz_valid_nft_mint(data: &[u8]) {
    let nft_id = hash64_from_input(0x11, data);

    let mint = NftMintTx::from_content_bytes(
        nft_id,
        bounded_string(data, 24, 64),
        bounded_string(data, 88, 128),
        data,
    );

    let kind = TxKind::NftMint(mint);

    kind.validate()
        .expect("NftMint TxKind should structurally validate");

    assert_eq!(kind.tag(), "nft_mint");
    assert_eq!(kind.normalized_sender(), None);
    assert_eq!(kind.normalized_receiver(), None);
    assert!(kind.touched_addresses().is_empty());

    roundtrip_tx_kind(kind);
}

fn fuzz_valid_nft_transfer(data: &[u8], new_owner_wallet: &str) {
    let transfer = NftTransferTx {
        nft_id: hash64_from_input(0x22, data),
        new_owner_wallet: new_owner_wallet.to_owned(),
    };

    let kind = TxKind::NftTransfer(transfer);

    kind.validate()
        .expect("valid NftTransfer TxKind must validate");

    assert_eq!(kind.tag(), "nft_transfer");
    assert_eq!(kind.normalized_sender(), None);
    assert_eq!(kind.normalized_receiver(), None);
    assert!(kind.touched_addresses().is_empty());

    roundtrip_tx_kind(kind);
}

fn fuzz_invalid_transfer(sender: &str, receiver: &str, amount: u64) {
    // Same sender/receiver must be invalid.
    let same_party = Transaction::new(sender.to_owned(), receiver.to_owned(), amount)
        .expect("base transfer must construct");

    let mut same_party = same_party;
    same_party.receiver = same_party.sender;

    let kind = TxKind::Transfer(same_party);

    assert!(
        kind.validate().is_err(),
        "TxKind accepted transfer with same sender/receiver"
    );

    assert_invalid_kind_rejected_by_deserialize(&kind, "same sender/receiver transfer");

    // Zero amount must be invalid.
    let zero_amount = Transaction::new(sender.to_owned(), receiver.to_owned(), amount)
        .expect("base transfer must construct");

    let mut zero_amount = zero_amount;
    zero_amount.amount = 0;

    let kind = TxKind::Transfer(zero_amount);

    assert!(
        kind.validate().is_err(),
        "TxKind accepted transfer with zero amount"
    );

    assert_invalid_kind_rejected_by_deserialize(&kind, "zero-amount transfer");
}

fn fuzz_invalid_reward(receiver: &str, amount: u64, block_height: u64) {
    let base = RewardTx::new_with_timestamp(
        receiver.to_owned(),
        amount,
        block_height,
        UNIX_2000.saturating_add(block_height % 100_000),
    )
    .expect("base reward must construct");

    // Zero reward amount must be invalid.
    let mut zero_amount = base.clone();
    zero_amount.amount = 0;

    let kind = TxKind::Reward(zero_amount);

    assert!(
        kind.validate().is_err(),
        "TxKind accepted reward with zero amount"
    );

    assert_invalid_kind_rejected_by_deserialize(&kind, "zero-amount reward");

    // Amount over max reward must be invalid.
    let mut too_large = base.clone();
    too_large.amount = MAX_BLOCK_REWARD.saturating_add(1);

    let kind = TxKind::Reward(too_large);

    assert!(
        kind.validate().is_err(),
        "TxKind accepted reward above max block reward"
    );

    assert_invalid_kind_rejected_by_deserialize(&kind, "oversized reward");

    // Zero block height must be invalid.
    let mut zero_height = base;
    zero_height.block_height = 0;

    let kind = TxKind::Reward(zero_height);

    assert!(
        kind.validate().is_err(),
        "TxKind accepted reward with zero block height"
    );

    assert_invalid_kind_rejected_by_deserialize(&kind, "zero-height reward");
}

fn fuzz_invalid_nft_transfer(data: &[u8]) {
    let empty_owner = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash64_from_input(0x33, data),
        new_owner_wallet: String::new(),
    });

    assert!(
        empty_owner.validate().is_err(),
        "TxKind accepted NftTransfer with empty new_owner_wallet"
    );

    assert_invalid_kind_rejected_by_deserialize(&empty_owner, "empty-owner NFT transfer");

    let bad_owner = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash64_from_input(0x44, data),
        new_owner_wallet: "not-a-remzar-wallet".to_string(),
    });

    assert!(
        bad_owner.validate().is_err(),
        "TxKind accepted NftTransfer with invalid new_owner_wallet"
    );

    assert_invalid_kind_rejected_by_deserialize(&bad_owner, "bad-owner NFT transfer");
}

fn fuzz_helpers(data: &[u8], sender: &str, receiver: &str) {
    let sender_arr = wallet_to_arr(sender);

    assert_eq!(normalize_address_bytes(&sender_arr), sender);

    let mut padded = sender.as_bytes().to_vec();
    let pad_len = usize::from(data.get(40).copied().unwrap_or(0) % 16);
    padded.extend(std::iter::repeat(0).take(pad_len));

    assert_eq!(normalize_address_bytes(&padded), sender);

    let mut embedded_nul = sender.as_bytes().to_vec();

    if embedded_nul.len() > 8 {
        embedded_nul[8] = 0;
    }

    assert_eq!(normalize_address_bytes(&embedded_nul), "");

    let mut bad_utf8 = sender.as_bytes().to_vec();

    if bad_utf8.len() > 20 {
        bad_utf8[20] = 0xff;
    }

    assert_eq!(normalize_address_bytes(&bad_utf8), "");

    let mut bad_hex = receiver.as_bytes().to_vec();

    if bad_hex.len() > 1 {
        bad_hex[1] = b'g';
    }

    assert_eq!(normalize_address_bytes(&bad_hex), "");

    let uppercase = sender.to_ascii_uppercase();
    assert_eq!(normalize_address_bytes(uppercase.as_bytes()), "");

    let wrong_prefix = format!("x{}", &sender[1..]);
    assert_eq!(normalize_address_bytes(wrong_prefix.as_bytes()), "");

    let empty: [u8; 0] = [];
    assert_eq!(normalize_address_bytes(&empty), "");
}


fn fuzz_manual_wire_shapes(data: &[u8]) {
    // Build intentionally malformed enum payloads by serializing raw structs
    // through TxKind. TxKind::deserialize must reject them because it validates
    // the decoded inner transaction before returning Ok.
    let wallet_a = wallet_from_input(0xD1, data);
    let wallet_b = wallet_from_input(0xD2, data);
    let amount = (read_u64(data, 48) % MAX_TRANSFER_AMOUNT).max(1);
    let height = read_u64(data, 56).max(1);

    let mut bad_transfer = Transaction::new(wallet_a.clone(), wallet_b.clone(), amount)
        .expect("manual base transfer must construct");
    bad_transfer.amount = 0;
    assert_invalid_kind_rejected_by_deserialize(
        &TxKind::Transfer(bad_transfer),
        "manual zero-amount transfer",
    );

    let mut bad_reward = RewardTx::new_with_timestamp(
        wallet_b.clone(),
        1,
        height,
        UNIX_2000.saturating_add(height % 100_000),
    )
    .expect("manual base reward must construct");
    bad_reward.amount = MAX_BLOCK_REWARD.saturating_add(1);
    assert_invalid_kind_rejected_by_deserialize(
        &TxKind::Reward(bad_reward),
        "manual oversized reward",
    );

    let mut bad_register = RegisterNodeTx::new(wallet_a)
        .expect("manual base register tx must construct");
    bad_register.wallet_address[1] = b'g';
    assert_invalid_kind_rejected_by_deserialize(
        &TxKind::RegisterNode(bad_register),
        "manual bad-register-wallet",
    );

    let bad_nft_wallet = match data.get(64).copied().unwrap_or(0) % 5 {
        0 => String::new(),
        1 => "not-a-remzar-wallet".to_string(),
        2 => format!("x{}", &wallet_b[1..]),
        3 => format!("{}00", wallet_b),
        _ => {
            let mut v = wallet_b.into_bytes();
            if v.len() > 1 {
                v[1] = b'g';
            }
            String::from_utf8_lossy(&v).into_owned()
        }
    };

    assert_invalid_kind_rejected_by_deserialize(
        &TxKind::NftTransfer(NftTransferTx {
            nft_id: hash64_from_input(0x55, data),
            new_owner_wallet: bad_nft_wallet,
        }),
        "manual bad-nft-transfer-wallet",
    );

    let uppercase_nft_owner = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash64_from_input(0x56, data),
        new_owner_wallet: wallet_from_input(0xD3, data).to_ascii_uppercase(),
    });
    let _ = uppercase_nft_owner.validate();
}

fn assert_invalid_kind_rejected_by_deserialize(kind: &TxKind, label: &str) {
    assert!(
        kind.validate().is_err(),
        "invalid TxKind unexpectedly validated: {label}"
    );

    let bytes = kind
        .serialize()
        .expect("TxKind postcard serialization should not validate inner payloads");

    assert!(
        TxKind::deserialize(&bytes).is_err(),
        "TxKind::deserialize accepted invalid payload: {label}"
    );
}

fn roundtrip_tx_kind(kind: TxKind) {
    let encoded = kind
        .serialize()
        .expect("valid TxKind must serialize");

    let decoded = TxKind::deserialize(&encoded)
        .expect("serialized valid TxKind must deserialize");

    assert_eq!(decoded, kind);

    decoded
        .validate()
        .expect("decoded TxKind must validate");

    // Trailing bytes must be rejected.
    let mut trailing = encoded;
    trailing.push(0);

    assert!(
        TxKind::deserialize(&trailing).is_err(),
        "TxKind::deserialize accepted trailing bytes"
    );
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-tx-kind-wallet-v1");
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

fn hash64_from_input(domain: u8, data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-tx-kind-hash64-v1");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    out
}

fn bounded_string(data: &[u8], offset: usize, max_len: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }

    let end = offset.saturating_add(max_len).min(data.len());
    let bytes = &data[offset..end];

    String::from_utf8_lossy(bytes).into_owned()
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for (i, slot) in out.iter_mut().enumerate() {
        *slot = data.get(offset + i).copied().unwrap_or(0);
    }

    u64::from_le_bytes(out)
}