#![no_main]

use libfuzzer_sys::fuzz_target;

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }
}

mod utility {
    pub mod alpha_001_global_configuration {
        use crate::utility::helper::UNIT_DIVISOR;

        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const STATE_COLUMN_NAME: &'static str = "state_data";
            pub const ACCOUNT_COLUMN_NAME: &'static str = "wallet_accounts";
            pub const TRANSACTION_BATCH_COLUMN_NAME: &'static str = "transaction_batch_data";

            pub const MAX_TX_AMOUNT: u64 = 10_000_000_000_000_000;
            pub const MAX_REWARD_SUPPLY: u64 = 200_000_000 * UNIT_DIVISOR;
            pub const MAX_SUPPLY: u64 = Self::MAX_REWARD_SUPPLY;
            pub const MAX_BLOCK_REWARD: u64 = 20 * UNIT_DIVISOR;

            pub const MAX_TXS_PER_BLOCK: u64 = 7_500;

            pub const REWARDLESS_PREFIX_BLOCKS: u64 = 1;
            pub const HALVING_INTERVAL_BLOCKS: u64 = 500_000;
            pub const REWARD_REDUCTION_SEQUENCE: &'static [u64] = &[
                20 * UNIT_DIVISOR,
                10 * UNIT_DIVISOR,
                5 * UNIT_DIVISOR,
                2 * UNIT_DIVISOR,
                UNIT_DIVISOR,
            ];
            pub const STABILIZED_BLOCK_REWARD: u64 = UNIT_DIVISOR;
            pub const TOTAL_REWARD_BLOCKS: u64 = 200_000_000;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
            StorageError {
                message: String,
            },
            NotFound {
                resource: String,
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
                    ErrorDetection::ValidationError { message, tx_id } => {
                        write!(f, "Validation error: {message}, tx_id={tx_id:?}")
                    }
                    ErrorDetection::SerializationError { details } => {
                        write!(f, "Serialization error: {details}")
                    }
                    ErrorDetection::StorageError { message } => {
                        write!(f, "Storage error: {message}")
                    }
                    ErrorDetection::NotFound { resource } => {
                        write!(f, "Not found: {resource}")
                    }
                    ErrorDetection::TimestampError {
                        message, details, ..
                    } => {
                        write!(f, "Timestamp error: {message}; {details}")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod helper {
        use super::alpha_002_error_detection_system::ErrorDetection;

        pub const UNIT_DIVISOR: u64 = 100_000_000;
        pub const STATE_KEY: &[u8] = b"__account_state__";

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
        pub fn to_micro_units(amount: f64) -> u64 {
            if !amount.is_finite() || amount <= 0.0 {
                return 0;
            }

            let s = format!("{amount:.8}");
            to_micro_units_str(&s)
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

    pub mod hash_system_remzarhash {
        use blake3::Hasher;
        use hex;
        use postcard::to_allocvec;
        use serde::Serialize;

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub struct RemzarHash;

        impl RemzarHash {
            fn blake3_xof64(bytes: &[u8]) -> [u8; 64] {
                let mut h = Hasher::new();
                h.update(bytes);

                let mut out = [0u8; 64];
                h.finalize_xof().fill(&mut out);

                out
            }

            pub fn compute_bytes_hash_hex(bytes: &[u8]) -> String {
                hex::encode(Self::blake3_xof64(bytes))
            }

            pub fn compute_dummy_hash() -> String {
                Self::compute_bytes_hash_hex(b"remzar_empty_block_mint")
            }

            pub fn compute_data_hash<T: Serialize + ?Sized>(
                data: &T,
            ) -> Result<String, ErrorDetection> {
                let bytes = to_allocvec(data).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })?;

                Ok(Self::compute_bytes_hash_hex(&bytes))
            }
        }
    }
}

mod storage {
    pub mod rocksdb_005_manager {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        use crate::blockchain::block_002_blocks::Block;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, Default)]
        pub struct RockDBManager {
            kv: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
            blocks: Arc<Mutex<HashMap<u64, Block>>>,
            batch_by_index: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
        }

        impl RockDBManager {
            pub fn new_fake() -> Self {
                Self::default()
            }

            fn key(cf: &str, key: &[u8]) -> Vec<u8> {
                let mut out = Vec::with_capacity(cf.len() + 1 + key.len());
                out.extend_from_slice(cf.as_bytes());
                out.push(0xff);
                out.extend_from_slice(key);
                out
            }

            pub fn write(
                &self,
                cf: &str,
                key: &[u8],
                value: &[u8],
            ) -> Result<(), ErrorDetection> {
                self.kv
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake DB mutex poisoned".into(),
                    })?
                    .insert(Self::key(cf, key), value.to_vec());

                Ok(())
            }

            pub fn read(
                &self,
                cf: &str,
                key: &[u8],
            ) -> Result<Option<Vec<u8>>, ErrorDetection> {
                Ok(self
                    .kv
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake DB mutex poisoned".into(),
                    })?
                    .get(&Self::key(cf, key))
                    .cloned())
            }

            pub fn get_latest_block_index(&self) -> Result<u64, ErrorDetection> {
                Ok(self
                    .blocks
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake blocks mutex poisoned".into(),
                    })?
                    .keys()
                    .copied()
                    .max()
                    .unwrap_or(0))
            }

            pub fn get_block_by_index(
                &self,
                idx: u64,
            ) -> Result<Option<Block>, ErrorDetection> {
                Ok(self
                    .blocks
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake blocks mutex poisoned".into(),
                    })?
                    .get(&idx)
                    .cloned())
            }

            pub fn put_block_by_index(
                &self,
                idx: u64,
                block: Block,
            ) -> Result<(), ErrorDetection> {
                self.blocks
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake blocks mutex poisoned".into(),
                    })?
                    .insert(idx, block);

                Ok(())
            }

            pub fn get_batch_bytes_by_index(
                &self,
                idx: u64,
            ) -> Result<Option<Vec<u8>>, ErrorDetection> {
                Ok(self
                    .batch_by_index
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake batch mutex poisoned".into(),
                    })?
                    .get(&idx)
                    .cloned())
            }

            pub fn put_batch_bytes_by_index(
                &self,
                idx: u64,
                bytes: Vec<u8>,
            ) -> Result<(), ErrorDetection> {
                self.batch_by_index
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake batch mutex poisoned".into(),
                    })?
                    .insert(idx, bytes);

                Ok(())
            }
        }
    }
}

mod tokens {
    pub mod nft_001 {
        use std::sync::Arc;

        use serde::{Deserialize, Serialize};

        use crate::network::p2p_006_reqresp::Hash;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct NftMintTx {
            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub nft_id: Hash,

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub content_hash: Hash,

            pub title: String,
            pub description: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct NftTransferTx {
            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub nft_id: Hash,

            pub new_owner_wallet: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct NftRecord {
            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub nft_id: Hash,
            pub owner_wallet: String,
        }

        pub fn load_nft_record(
            _blockchain_db: &Arc<RockDBManager>,
            _nft_id: &Hash,
        ) -> Result<Option<NftRecord>, ErrorDetection> {
            Ok(None)
        }

        pub fn apply_nft_mint(
            _blockchain_db: &Arc<RockDBManager>,
            _tx: &NftMintTx,
            _signer_wallet: &str,
            _block_height: u64,
            _block_timestamp: u64,
        ) -> Result<(), ErrorDetection> {
            Ok(())
        }

        pub fn apply_nft_transfer(
            _blockchain_db: &Arc<RockDBManager>,
            tx: &NftTransferTx,
            _signer_wallet: &str,
            _block_height: u64,
            _block_timestamp: u64,
        ) -> Result<(), ErrorDetection> {
            if tx.new_owner_wallet.trim().is_empty() {
                return Err(ErrorDetection::ValidationError {
                    message: "NFT transfer new_owner_wallet cannot be empty".into(),
                    tx_id: None,
                });
            }

            Ok(())
        }
    }
}

mod blockchain {
    pub mod halving_schedule {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;

        pub struct RewardHalving;

        impl RewardHalving {
            pub fn remaining_reward_supply_micro_after_block(block_height: u64) -> u128 {
                let issued = (block_height as u128)
                    .saturating_mul(GlobalConfiguration::MAX_BLOCK_REWARD as u128);

                (GlobalConfiguration::MAX_REWARD_SUPPLY as u128).saturating_sub(issued)
            }

            pub fn get_block_reward(block_height: u64) -> u64 {
                if block_height < GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS {
                    0
                } else {
                    GlobalConfiguration::MAX_BLOCK_REWARD
                }
            }
        }
    }

    pub mod block_001_metadata {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct BlockMetadata {
            pub index: u64,
            pub timestamp: u64,

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub previous_hash: [u8; 64],

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub merkle_root: [u8; 64],
        }

        impl BlockMetadata {
            pub fn new(index: u64, timestamp: u64, previous_hash: [u8; 64]) -> Self {
                Self {
                    index,
                    timestamp,
                    previous_hash,
                    merkle_root: [1u8; 64],
                }
            }
        }
    }

    pub mod block_002_blocks {
        use serde::{Deserialize, Serialize};

        use crate::blockchain::block_001_metadata::BlockMetadata;
        use crate::network::p2p_006_reqresp::Hash;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct Block {
            pub metadata: BlockMetadata,
            pub batch_key: Option<String>,
            pub miner: String,

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub block_hash: Hash,

            pub reward: u64,
        }

        impl Block {
            pub fn new_for_fuzz(
                index: u64,
                previous_hash: Hash,
                miner: String,
                batch_key: Option<String>,
            ) -> Self {
                let mut preimage = Vec::new();
                preimage.extend_from_slice(&index.to_le_bytes());
                preimage.extend_from_slice(&previous_hash);
                preimage.extend_from_slice(miner.as_bytes());

                let mut hasher = blake3::Hasher::new();
                hasher.update(&preimage);

                let mut block_hash = [0u8; 64];
                hasher.finalize_xof().fill(&mut block_hash);

                Self {
                    metadata: BlockMetadata::new(index, current_unix_secs(), previous_hash),
                    batch_key,
                    miner,
                    block_hash,
                    reward: 0,
                }
            }

            pub fn miner_wallet(&self) -> &str {
                &self.miner
            }

            pub fn validate(&self, _now: Option<u64>) -> Result<(), ErrorDetection> {
                if self.metadata.index > 0 {
                    canon_wallet_id_checked(&self.miner)?;
                }

                Ok(())
            }
        }

        fn current_unix_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(946_684_800)
        }
    }

    pub mod transaction_001_tx {
        use chrono::Utc;
        use postcard::{from_bytes, to_allocvec};
        use serde::{Deserialize, Serialize};

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{
            REMZAR_WALLET_LEN, canon_wallet_id_checked, parse_wallet_address_bytes,
        };

        #[repr(C)]
        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub struct Transaction {
            #[serde(with = "serde_big_array::BigArray")]
            pub sender: [u8; REMZAR_WALLET_LEN],

            #[serde(with = "serde_big_array::BigArray")]
            pub receiver: [u8; REMZAR_WALLET_LEN],

            pub amount: u64,
            pub timestamp: u64,
        }

        impl Transaction {
            pub fn new(
                sender: String,
                receiver: String,
                amount: u64,
            ) -> Result<Self, ErrorDetection> {
                let sender_canon = canon_wallet_id_checked(&sender)?;
                let receiver_canon = canon_wallet_id_checked(&receiver)?;

                if sender_canon == receiver_canon {
                    return Err(ErrorDetection::ValidationError {
                        message: "Sender and receiver cannot be the same".into(),
                        tx_id: None,
                    });
                }

                if amount == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "Transaction amount must be greater than zero".into(),
                        tx_id: None,
                    });
                }

                let mut sender_arr = [0u8; REMZAR_WALLET_LEN];
                sender_arr.copy_from_slice(sender_canon.as_bytes());

                let mut receiver_arr = [0u8; REMZAR_WALLET_LEN];
                receiver_arr.copy_from_slice(receiver_canon.as_bytes());

                let timestamp =
                    u64::try_from(Utc::now().timestamp()).unwrap_or(946_684_800);

                Ok(Self {
                    sender: sender_arr,
                    receiver: receiver_arr,
                    amount,
                    timestamp,
                })
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                let sender = parse_wallet_address_bytes(&self.sender)?;
                let receiver = parse_wallet_address_bytes(&self.receiver)?;

                if sender == receiver {
                    return Err(ErrorDetection::ValidationError {
                        message: "Sender and receiver cannot be the same".into(),
                        tx_id: None,
                    });
                }

                if self.amount == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "Transaction amount must be greater than zero".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }

            pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
                let tx: Self = from_bytes(bytes).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })?;

                tx.validate()?;

                Ok(tx)
            }

            pub fn id(&self) -> Result<String, ErrorDetection> {
                Ok(blake3::hash(&self.serialize()?).to_hex().to_string())
            }
        }
    }

    pub mod transaction_002_tx_register {
        use chrono::Utc;
        use postcard::{take_from_bytes, to_allocvec};
        use serde::{Deserialize, Serialize};

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};

        #[repr(C)]
        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub struct RegisterNodeTx {
            #[serde(with = "serde_big_array::BigArray")]
            pub wallet_address: [u8; REMZAR_WALLET_LEN],
            pub timestamp: u64,
        }

        impl RegisterNodeTx {
            pub fn new(wallet_address: String) -> Result<Self, ErrorDetection> {
                let canon = canon_wallet_id_checked(&wallet_address)?;
                let mut wallet = [0u8; REMZAR_WALLET_LEN];
                wallet.copy_from_slice(canon.as_bytes());

                Ok(Self {
                    wallet_address: wallet,
                    timestamp: u64::try_from(Utc::now().timestamp()).unwrap_or(946_684_800),
                })
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                crate::utility::helper::parse_wallet_address_bytes(&self.wallet_address)?;
                Ok(())
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }

            pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
                let (tx, rest): (Self, &[u8]) = take_from_bytes(bytes).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })?;

                if !rest.is_empty() {
                    return Err(ErrorDetection::SerializationError {
                        details: "trailing bytes rejected".into(),
                    });
                }

                tx.validate()?;
                Ok(tx)
            }
        }
    }

    pub mod transaction_003_tx_reward {
        use chrono::Utc;
        use postcard::{from_bytes, to_allocvec};
        use serde::{Deserialize, Serialize};

        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{
            REMZAR_WALLET_LEN, canon_wallet_id_checked, parse_wallet_address_bytes,
        };

        #[repr(C)]
        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub struct RewardTx {
            #[serde(with = "serde_big_array::BigArray")]
            pub receiver: [u8; REMZAR_WALLET_LEN],
            pub amount: u64,
            pub block_height: u64,
            pub timestamp: u64,
        }

        impl RewardTx {
            pub fn new(
                receiver: String,
                amount: u64,
                block_height: u64,
            ) -> Result<Self, ErrorDetection> {
                let canon = canon_wallet_id_checked(&receiver)?;

                if amount == 0 || amount > GlobalConfiguration::MAX_BLOCK_REWARD {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid reward amount".into(),
                        tx_id: None,
                    });
                }

                if block_height == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "block height cannot be zero".into(),
                        tx_id: None,
                    });
                }

                let mut receiver_arr = [0u8; REMZAR_WALLET_LEN];
                receiver_arr.copy_from_slice(canon.as_bytes());

                Ok(Self {
                    receiver: receiver_arr,
                    amount,
                    block_height,
                    timestamp: u64::try_from(Utc::now().timestamp()).unwrap_or(946_684_800),
                })
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                if self.amount == 0 || self.amount > GlobalConfiguration::MAX_BLOCK_REWARD {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid reward amount".into(),
                        tx_id: None,
                    });
                }

                if self.block_height == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "block height cannot be zero".into(),
                        tx_id: None,
                    });
                }

                parse_wallet_address_bytes(&self.receiver)?;
                Ok(())
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }

            pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
                let tx: Self = from_bytes(bytes).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })?;

                tx.validate()?;
                Ok(tx)
            }
        }
    }

    pub mod transaction_004_tx_kind {
        use postcard::take_from_bytes;
        use serde::{Deserialize, Serialize};
        use std::collections::HashSet;

        use crate::blockchain::transaction_001_tx::Transaction;
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::blockchain::transaction_003_tx_reward::RewardTx;
        use crate::tokens::nft_001::{NftMintTx, NftTransferTx};
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{canon_wallet_id_checked, parse_wallet_address_bytes};

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub enum TxKind {
            Transfer(Transaction),
            RegisterNode(RegisterNodeTx),
            Reward(RewardTx),
            NftMint(NftMintTx),
            NftTransfer(NftTransferTx),
        }

        impl TxKind {
            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })
            }

            pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
                let (tx, rest): (Self, &[u8]) = take_from_bytes(bytes).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })?;

                if !rest.is_empty() {
                    return Err(ErrorDetection::SerializationError {
                        details: "trailing bytes rejected".into(),
                    });
                }

                tx.validate()?;
                Ok(tx)
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                match self {
                    TxKind::Transfer(tx) => tx.validate(),
                    TxKind::RegisterNode(tx) => tx.validate(),
                    TxKind::Reward(tx) => tx.validate(),
                    TxKind::NftMint(_) => Ok(()),
                    TxKind::NftTransfer(tx) => {
                        if tx.new_owner_wallet.trim().is_empty() {
                            return Err(ErrorDetection::ValidationError {
                                message: "empty nft owner".into(),
                                tx_id: None,
                            });
                        }

                        canon_wallet_id_checked(&tx.new_owner_wallet)?;
                        Ok(())
                    }
                }
            }

            pub fn touched_addresses(&self) -> Vec<String> {
                let mut set = HashSet::new();

                match self {
                    TxKind::Transfer(tx) => {
                        let s = normalize_address_bytes(&tx.sender);
                        let r = normalize_address_bytes(&tx.receiver);

                        if !s.is_empty() {
                            set.insert(s);
                        }

                        if !r.is_empty() {
                            set.insert(r);
                        }
                    }
                    TxKind::Reward(tx) => {
                        let r = normalize_address_bytes(&tx.receiver);

                        if !r.is_empty() {
                            set.insert(r);
                        }
                    }
                    TxKind::RegisterNode(_) | TxKind::NftMint(_) | TxKind::NftTransfer(_) => {}
                }

                set.into_iter().collect()
            }
        }

        pub fn normalize_address_bytes(bytes: &[u8]) -> String {
            let end = bytes
                .iter()
                .rposition(|byte| *byte != 0)
                .map_or(0, |last| last.saturating_add(1));

            let Some(trimmed) = bytes.get(..end) else {
                return String::new();
            };

            if trimmed.is_empty() || trimmed.contains(&0) {
                return String::new();
            }

            parse_wallet_address_bytes(trimmed).unwrap_or_default()
        }
    }

    pub mod transaction_005_tx_batch {
        use postcard::take_from_bytes;
        use serde::{Deserialize, Serialize};

        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
        pub struct TransactionBatch {
            pub index: u64,
            pub timestamp: u64,
            pub transactions: Vec<TxKind>,

            #[serde(default)]
            pub guardian_signature: Option<Vec<u8>>,
        }

        impl TransactionBatch {
            pub fn new(
                index: u64,
                timestamp: u64,
                transactions: Vec<TxKind>,
            ) -> Result<Self, ErrorDetection> {
                Ok(Self {
                    index,
                    timestamp,
                    transactions,
                    guardian_signature: None,
                })
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })
            }

            pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
                let (batch, rest): (Self, &[u8]) = take_from_bytes(bytes).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })?;

                if !rest.is_empty() {
                    return Err(ErrorDetection::SerializationError {
                        details: "trailing bytes rejected".into(),
                    });
                }

                Ok(batch)
            }
        }
    }

    pub mod transaction_006_tx_account_tree_guards {
        use std::collections::BTreeSet;

        use crate::blockchain::block_002_blocks::Block;
        use crate::blockchain::transaction_004_tx_kind::{normalize_address_bytes, TxKind};
        use crate::blockchain::transaction_005_tx_account_tree::InnerTree;
        use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
        use crate::network::p2p_006_reqresp::Hash;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone)]
        pub struct AccountGuard;

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum ApplyMode {
            Live,
            Replay,
        }

        #[derive(Debug, Clone)]
        pub struct ApplyContext {
            pub mode: ApplyMode,
            pub block_height: u64,
            pub block_hash: Hash,
            pub previous_hash: Hash,
            pub allow_duplicate_reward_in_batch: bool,
        }

        #[derive(Debug, Clone)]
        pub struct BatchApplyOutcome {
            pub touched_accounts: BTreeSet<String>,
            pub total_supply_micro: u64,
            pub fingerprint_hex: String,
        }

        #[derive(Debug, Clone)]
        pub struct StateFingerprint {
            pub height: u64,
            pub total_issued_micro: u64,
            pub rewards_issued_micro: u64,
            pub total_supply_micro: u64,
            pub touched_accounts: Vec<(String, u64)>,
            pub hex: String,
        }

        impl AccountGuard {
            pub fn new() -> Self {
                Self
            }

            pub fn validate_batch_structure(
                &self,
                batch: &TransactionBatch,
            ) -> Result<(), ErrorDetection> {
                if batch.transactions.len() > GlobalConfiguration::MAX_TXS_PER_BLOCK as usize {
                    return Err(ErrorDetection::ValidationError {
                        message: "too many txs in batch".into(),
                        tx_id: None,
                    });
                }

                let mut reward_count = 0usize;

                for kind in &batch.transactions {
                    kind.validate()?;

                    if matches!(kind, TxKind::Reward(_)) {
                        reward_count = reward_count.saturating_add(1);
                    }
                }

                if reward_count > 1 {
                    return Err(ErrorDetection::ValidationError {
                        message: "multiple rewards in one batch".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }

            pub fn apply_txkind_to_state(
                &self,
                state: &mut InnerTree,
                kind: &TxKind,
                _ctx: &ApplyContext,
                touched_accounts: &mut BTreeSet<String>,
            ) -> Result<(), ErrorDetection> {
                kind.validate()?;

                match kind {
                    TxKind::Transfer(tx) => {
                        let sender = normalize_address_bytes(&tx.sender);
                        let receiver = normalize_address_bytes(&tx.receiver);

                        if sender.is_empty() || receiver.is_empty() {
                            return Err(ErrorDetection::ValidationError {
                                message: "empty transfer address".into(),
                                tx_id: None,
                            });
                        }

                        if sender == receiver {
                            return Err(ErrorDetection::ValidationError {
                                message: "same sender and receiver".into(),
                                tx_id: None,
                            });
                        }

                        let sender_balance = state.balances.get(&sender).copied().unwrap_or(0);

                        if sender_balance < tx.amount {
                            return Err(ErrorDetection::ValidationError {
                                message: "insufficient balance".into(),
                                tx_id: None,
                            });
                        }

                        let receiver_balance =
                            state.balances.get(&receiver).copied().unwrap_or(0);

                        let new_receiver =
                            receiver_balance.checked_add(tx.amount).ok_or_else(|| {
                                ErrorDetection::ValidationError {
                                    message: "receiver overflow".into(),
                                    tx_id: None,
                                }
                            })?;

                        if new_receiver > GlobalConfiguration::MAX_SUPPLY {
                            return Err(ErrorDetection::ValidationError {
                                message: "receiver exceeds max supply".into(),
                                tx_id: None,
                            });
                        }

                        state
                            .balances
                            .insert(sender.clone(), sender_balance.saturating_sub(tx.amount));
                        state.balances.insert(receiver.clone(), new_receiver);

                        touched_accounts.insert(sender);
                        touched_accounts.insert(receiver);
                    }

                    TxKind::Reward(reward) => {
                        let receiver = normalize_address_bytes(&reward.receiver);

                        if receiver.is_empty() {
                            return Err(ErrorDetection::ValidationError {
                                message: "empty reward receiver".into(),
                                tx_id: None,
                            });
                        }

                        let next_total = state
                            .total_issued_micro
                            .checked_add(reward.amount)
                            .ok_or_else(|| ErrorDetection::ValidationError {
                                message: "total issued overflow".into(),
                                tx_id: None,
                            })?;

                        if next_total > GlobalConfiguration::MAX_SUPPLY {
                            return Err(ErrorDetection::ValidationError {
                                message: "max supply exceeded".into(),
                                tx_id: None,
                            });
                        }

                        let next_rewards = state
                            .rewards_issued_micro
                            .checked_add(reward.amount)
                            .ok_or_else(|| ErrorDetection::ValidationError {
                                message: "rewards issued overflow".into(),
                                tx_id: None,
                            })?;

                        if next_rewards > GlobalConfiguration::MAX_REWARD_SUPPLY {
                            return Err(ErrorDetection::ValidationError {
                                message: "reward supply exceeded".into(),
                                tx_id: None,
                            });
                        }

                        let bal = state.balances.get(&receiver).copied().unwrap_or(0);
                        let next_bal = bal.checked_add(reward.amount).ok_or_else(|| {
                            ErrorDetection::ValidationError {
                                message: "reward receiver overflow".into(),
                                tx_id: None,
                            }
                        })?;

                        if next_bal > GlobalConfiguration::MAX_SUPPLY {
                            return Err(ErrorDetection::ValidationError {
                                message: "reward receiver exceeds max supply".into(),
                                tx_id: None,
                            });
                        }

                        state.balances.insert(receiver.clone(), next_bal);
                        state.total_issued_micro = next_total;
                        state.rewards_issued_micro = next_rewards;

                        touched_accounts.insert(receiver);
                    }

                    TxKind::RegisterNode(reg) => {
                        let wallet = normalize_address_bytes(&reg.wallet_address);
                        if !wallet.is_empty() {
                            touched_accounts.insert(wallet);
                        }
                    }

                    TxKind::NftMint(_) | TxKind::NftTransfer(_) => {}
                }

                Ok(())
            }

            pub fn apply_batch_to_state(
                &self,
                state: &mut InnerTree,
                batch: &TransactionBatch,
                ctx: &ApplyContext,
            ) -> Result<BatchApplyOutcome, ErrorDetection> {
                self.validate_batch_structure(batch)?;

                let _mode_is_replay = matches!(ctx.mode, ApplyMode::Replay);
                let _ctx_hash_mix = ctx.block_hash[0] ^ ctx.previous_hash[0];
                let _duplicate_rewards_policy = ctx.allow_duplicate_reward_in_batch;

                if batch.index != ctx.block_height {
                    return Err(ErrorDetection::ValidationError {
                        message: "batch index does not match context height".into(),
                        tx_id: None,
                    });
                }

                let mut touched = BTreeSet::new();

                for kind in &batch.transactions {
                    self.apply_txkind_to_state(state, kind, ctx, &mut touched)?;
                }

                self.verify_state_invariants(state, None, None, None)?;
                let fp = self.compute_state_fingerprint(state, ctx.block_height, &touched)?;

                Ok(BatchApplyOutcome {
                    touched_accounts: touched,
                    total_supply_micro: fp.total_supply_micro,
                    fingerprint_hex: fp.hex,
                })
            }

            pub fn compute_state_fingerprint(
                &self,
                state: &InnerTree,
                height: u64,
                touched_accounts: &BTreeSet<String>,
            ) -> Result<StateFingerprint, ErrorDetection> {
                let total_supply = sum_balances_checked(&state.balances)?;

                let mut hasher = blake3::Hasher::new();
                hasher.update(&height.to_le_bytes());
                hasher.update(&state.total_issued_micro.to_le_bytes());
                hasher.update(&state.rewards_issued_micro.to_le_bytes());
                hasher.update(&total_supply.to_le_bytes());

                let mut touched = Vec::new();

                for acct in touched_accounts {
                    let bal = state.balances.get(acct).copied().unwrap_or(0);
                    hasher.update(acct.as_bytes());
                    hasher.update(&bal.to_le_bytes());
                    touched.push((acct.clone(), bal));
                }

                let mut out = [0u8; 64];
                hasher.finalize_xof().fill(&mut out);

                Ok(StateFingerprint {
                    height,
                    total_issued_micro: state.total_issued_micro,
                    rewards_issued_micro: state.rewards_issued_micro,
                    total_supply_micro: total_supply,
                    touched_accounts: touched,
                    hex: hex::encode(out),
                })
            }

            pub fn log_state_fingerprint(&self, tag: &str, fingerprint: &StateFingerprint) {
                let _ = (
                    tag.len(),
                    fingerprint.height,
                    fingerprint.total_issued_micro,
                    fingerprint.rewards_issued_micro,
                    fingerprint.total_supply_micro,
                    fingerprint.touched_accounts.len(),
                    fingerprint.hex.len(),
                );
            }

            pub fn verify_state_invariants(
                &self,
                state: &InnerTree,
                _expected_tip_height: Option<u64>,
                _expected_tip_hash: Option<Hash>,
                _expected_prev_hash: Option<Hash>,
            ) -> Result<(), ErrorDetection> {
                let total_supply = sum_balances_checked(&state.balances)?;

                if total_supply > GlobalConfiguration::MAX_SUPPLY {
                    return Err(ErrorDetection::ValidationError {
                        message: "total supply exceeds max supply".into(),
                        tx_id: None,
                    });
                }

                if state.rewards_issued_micro > state.total_issued_micro {
                    return Err(ErrorDetection::ValidationError {
                        message: "rewards issued exceeds total issued".into(),
                        tx_id: None,
                    });
                }

                if state.total_issued_micro > GlobalConfiguration::MAX_SUPPLY {
                    return Err(ErrorDetection::ValidationError {
                        message: "total issued exceeds max supply".into(),
                        tx_id: None,
                    });
                }

                if state.rewards_issued_micro > GlobalConfiguration::MAX_REWARD_SUPPLY {
                    return Err(ErrorDetection::ValidationError {
                        message: "rewards issued exceeds max reward supply".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }

            pub fn check_canonical_idempotency(
                &self,
                state: &InnerTree,
                block: &Block,
            ) -> Result<bool, ErrorDetection> {
                Ok(state
                    .blocks
                    .iter()
                    .any(|existing| {
                        existing.metadata.index == block.metadata.index
                            && existing.block_hash == block.block_hash
                    }))
            }

            pub fn dry_run_block_and_batch(
                &self,
                mut tentative_state: InnerTree,
                block: &Block,
                batch: &TransactionBatch,
            ) -> Result<(InnerTree, BatchApplyOutcome), ErrorDetection> {
                if batch.index != block.metadata.index {
                    return Err(ErrorDetection::ValidationError {
                        message: "batch index does not match block height".into(),
                        tx_id: None,
                    });
                }

                if tentative_state.has_tip && block.metadata.previous_hash != tentative_state.tip_hash {
                    return Err(ErrorDetection::ValidationError {
                        message: "block previous hash does not match tentative tip".into(),
                        tx_id: None,
                    });
                }

                tentative_state.prev_tip_hash = if tentative_state.has_tip {
                    tentative_state.tip_hash
                } else {
                    block.metadata.previous_hash
                };
                tentative_state.tip_height = block.metadata.index;
                tentative_state.tip_hash = block.block_hash;
                tentative_state.has_tip = true;
                tentative_state.blocks.push(block.clone());

                if tentative_state.blocks.len() > 512 {
                    let excess = tentative_state.blocks.len().saturating_sub(512);
                    tentative_state.blocks.drain(0..excess);
                }

                let ctx = ApplyContext {
                    mode: ApplyMode::Live,
                    block_height: block.metadata.index,
                    block_hash: block.block_hash,
                    previous_hash: block.metadata.previous_hash,
                    allow_duplicate_reward_in_batch: false,
                };

                let outcome = self.apply_batch_to_state(&mut tentative_state, batch, &ctx)?;

                Ok((tentative_state, outcome))
            }

            pub fn verify_account_cf_matches_state(
                &self,
                _db: &RockDBManager,
                _state: &InnerTree,
                _touched_accounts: &BTreeSet<String>,
            ) -> Result<(), ErrorDetection> {
                Ok(())
            }
        }

        fn sum_balances_checked(
            balances: &std::collections::HashMap<String, u64>,
        ) -> Result<u64, ErrorDetection> {
            balances
                .values()
                .copied()
                .try_fold(0u64, |acc, v| acc.checked_add(v))
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: "balance sum overflow".into(),
                    tx_id: None,
                })
        }
    }

    // It does not link the full remzar crate and does not compile RocksDB.
    pub mod transaction_005_tx_account_tree {
        include!("../../src/blockchain/transaction_005_tx_account_tree.rs");
    }
}

use blockchain::block_002_blocks::Block;
use blockchain::transaction_001_tx::Transaction;
use blockchain::transaction_003_tx_reward::RewardTx;
use blockchain::transaction_004_tx_kind::TxKind;
use blockchain::transaction_005_tx_account_tree::{AccountModelTree, ChainLogic};
use blockchain::transaction_005_tx_batch::TransactionBatch;
use storage::rocksdb_005_manager::RockDBManager;
use utility::alpha_001_global_configuration::GlobalConfiguration;

const MAX_SAFE_TRANSFER: u64 = 1_000_000_000;
const MAX_SAFE_REWARD: u64 = 50 * 100_000_000;

fuzz_target!(|data: &[u8]| {
    let _ = AccountModelTree::deserialize_state(data, RockDBManager::new_fake());

    let db = RockDBManager::new_fake();
    let mut tree = AccountModelTree::with_manager(db.clone());

    let sender = wallet_from_input(0xA1, data);
    let receiver = wallet_from_input(0xB2, data);
    let miner = wallet_from_input(0xC3, data);

    let amount = {
        let raw = read_u64(data, 0);
        let bounded = raw % MAX_SAFE_TRANSFER;
        bounded.max(1)
    };

    let reward_amount = {
        let raw = read_u64(data, 8);
        let bounded = raw % MAX_SAFE_REWARD;
        bounded.saturating_add(1)
    };

    fuzz_balance_helpers(&mut tree, data, &sender, &receiver, amount);
    fuzz_apply_transaction(&mut tree, &sender, &receiver, amount);
    fuzz_state_roundtrip(&tree, db.clone());
    fuzz_apply_batch(db.clone(), data, &sender, &receiver, reward_amount);
    fuzz_apply_block_with_batch(db.clone(), data, &sender, &receiver, &miner);
    fuzz_reload_from_db_replay(db.clone(), data, &sender, &receiver, &miner);
    fuzz_blocks_and_pending(db.clone(), data, &miner);
    fuzz_supply_helpers(&tree, data);
    fuzz_exercise_stub_api_surface(db.clone(), data, &sender, &receiver);
});

fn fuzz_balance_helpers(
    tree: &mut AccountModelTree,
    data: &[u8],
    sender: &str,
    receiver: &str,
    amount: u64,
) {
    assert_eq!(tree.latest_block_height(), 0);
    assert!(tree.get_blocks().is_empty());

    tree.set_balance(sender, amount);
    assert_eq!(tree.get_balance(sender), amount);

    tree.increment_balance(sender, 1)
        .expect("increment_balance by 1 should work");

    assert_eq!(tree.get_balance(sender), amount.saturating_add(1));

    tree.decrement_balance(sender, 1)
        .expect("decrement_balance by 1 should work");

    assert_eq!(tree.get_balance(sender), amount);

    tree.update_balance(receiver, amount)
        .expect("update_balance should work");

    assert_eq!(tree.get_balance(receiver), amount);

    assert!(
        tree.decrement_balance("missing-account", 1).is_err(),
        "decrement_balance accepted missing account"
    );

    let huge = GlobalConfiguration::MAX_SUPPLY;
    let maybe_overflow = if data.first().copied().unwrap_or(0) & 1 == 0 {
        tree.increment_balance(sender, huge)
    } else {
        tree.update_balance(sender, huge)
    };

    assert!(
        maybe_overflow.is_err(),
        "balance helper allowed account to exceed MAX_SUPPLY"
    );

    let _ = tree.get_balance_decimal(sender);
    let _ = tree.get_balances();
}

fn fuzz_apply_transaction(
    tree: &mut AccountModelTree,
    sender: &str,
    receiver: &str,
    amount: u64,
) {
    tree.set_balance(sender, amount.saturating_mul(2));

    let tx = Transaction::new(sender.to_owned(), receiver.to_owned(), amount)
        .expect("valid transfer tx must construct");

    let sender_before = tree.get_balance(sender);
    let receiver_before = tree.get_balance(receiver);

    tree.apply_transaction(&tx)
        .expect("funded transfer should apply");

    assert_eq!(tree.get_balance(sender), sender_before - amount);
    assert_eq!(tree.get_balance(receiver), receiver_before + amount);

    let unfunded = Transaction::new(sender.to_owned(), receiver.to_owned(), amount)
        .expect("valid unfunded transfer tx must construct");

    tree.set_balance(sender, 0);

    assert!(
        tree.apply_transaction(&unfunded).is_err(),
        "unfunded transfer was accepted"
    );

    let mut zero_amount = unfunded.clone();
    zero_amount.amount = 0;

    assert!(
        tree.apply_transaction(&zero_amount).is_err(),
        "zero-amount transfer was accepted"
    );

    let mut same_party = unfunded;
    same_party.receiver = same_party.sender;

    assert!(
        tree.apply_transaction(&same_party).is_err(),
        "same sender/receiver transfer was accepted"
    );
}

fn fuzz_state_roundtrip(tree: &AccountModelTree, db: RockDBManager) {
    tree.commit().expect("commit should write state to fake DB");

    let encoded = tree
        .serialize_state()
        .expect("serialize_state should work");

    let decoded = AccountModelTree::deserialize_state(&encoded, db.clone())
        .expect("deserialize_state should work");

    let original_balances = tree.get_balances();

    assert_eq!(decoded.get_balances(), original_balances);

    let balance_sum = original_balances
        .values()
        .copied()
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .expect("balance sum should not overflow in fuzz roundtrip");

    let original_total_issued = tree.total_issued_micro();
    let expected_total_issued = if original_total_issued == 0 && !original_balances.is_empty() {
        balance_sum
    } else {
        original_total_issued
    };

    let original_rewards_issued = tree.rewards_issued_micro();
    let expected_rewards_issued = if original_rewards_issued == 0 && expected_total_issued > 0 {
        expected_total_issued
    } else {
        original_rewards_issued
    };

    assert_eq!(decoded.total_issued_micro(), expected_total_issued);
    assert_eq!(decoded.rewards_issued_micro(), expected_rewards_issued);

    let loaded = AccountModelTree::load_state(db)
        .expect("load_state should read committed fake DB state");

    assert_eq!(loaded.get_balances(), original_balances);
    assert_eq!(loaded.total_issued_micro(), expected_total_issued);
    assert_eq!(loaded.rewards_issued_micro(), expected_rewards_issued);

    let mut trailing = encoded;
    trailing.push(0);

    assert!(
        AccountModelTree::deserialize_state(&trailing, RockDBManager::new_fake()).is_err(),
        "deserialize_state accepted trailing bytes"
    );
}

fn fuzz_apply_batch(
    db: RockDBManager,
    data: &[u8],
    sender: &str,
    receiver: &str,
    reward_amount: u64,
) {
    let mut tree = AccountModelTree::with_manager(db);

    let transfer_amount = {
        let raw = read_u64(data, 16);
        let bounded = raw % MAX_SAFE_TRANSFER;
        bounded.max(1)
    };

    tree.set_balance(sender, transfer_amount.saturating_mul(2));

    let transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("batch transfer must construct");

    let reward_receiver = wallet_from_input(0xD4, data);

    let reward = RewardTx::new(
        reward_receiver.clone(),
        reward_amount.min(GlobalConfiguration::MAX_BLOCK_REWARD).max(1),
        1,
    )
    .expect("batch reward must construct");

    let batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![TxKind::Transfer(transfer), TxKind::Reward(reward)],
    )
    .expect("batch must construct");

    tree.apply_batch(&batch)
        .expect("funded transfer + one reward batch should apply");

    assert!(tree.get_balance(receiver) >= transfer_amount);
    assert!(tree.get_balance(&reward_receiver) >= 1);
    assert!(tree.total_issued_micro() >= 1);
    assert!(tree.rewards_issued_micro() >= 1);

    tree.flush_balances()
        .expect("flush_balances should work with fake DB");

    tree.flush_balances_for_batch(&batch)
        .expect("flush_balances_for_batch should work with fake DB");

    tree.flush_addresses(vec![sender.to_string(), receiver.to_string()])
        .expect("flush_addresses should work with fake DB");

    let bad_batch = TransactionBatch::new(
        1,
        current_unix_secs(),
        vec![
            TxKind::Reward(
                RewardTx::new(wallet_from_input(0xE1, data), 1, 1)
                    .expect("reward 1 must construct"),
            ),
            TxKind::Reward(
                RewardTx::new(wallet_from_input(0xE2, data), 1, 1)
                    .expect("reward 2 must construct"),
            ),
        ],
    )
    .expect("bad batch must construct structurally");

    assert!(
        tree.apply_batch(&bad_batch).is_err(),
        "batch with multiple rewards was accepted"
    );
}

fn fuzz_apply_block_with_batch(
    db: RockDBManager,
    data: &[u8],
    sender: &str,
    receiver: &str,
    miner: &str,
) {
    let mut tree = AccountModelTree::with_manager(db.clone());

    let genesis = Block::new_for_fuzz(0, [0u8; 64], String::new(), None);
    tree.add_block(genesis.clone())
        .expect("genesis add_block should work before apply_block");

    let amount = (read_u64(data, 32) % MAX_SAFE_TRANSFER).max(1);
    tree.set_balance(sender, amount.saturating_mul(2));

    let transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), amount)
        .expect("apply_block transfer tx must construct");

    let batch_key = format!("fuzz_apply_block_batch_{}", read_u64(data, 40));
    let batch = TransactionBatch::new(
        1,
        current_unix_secs(),
        vec![TxKind::Transfer(transfer)],
    )
    .expect("apply_block batch must construct");

    let batch_bytes = batch.serialize().expect("apply_block batch must serialize");
    db.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        batch_key.as_bytes(),
        &batch_bytes,
    )
    .expect("fake DB should store apply_block batch bytes");

    let block_1 = Block::new_for_fuzz(
        1,
        genesis.block_hash,
        miner.to_owned(),
        Some(batch_key),
    );

    let sender_before = tree.get_balance(sender);
    let receiver_before = tree.get_balance(receiver);

    tree.apply_block(&block_1)
        .expect("apply_block should dry-run, commit state, and flush touched accounts");

    assert_eq!(tree.latest_block_height(), 1);
    assert_eq!(tree.get_balance(sender), sender_before - amount);
    assert_eq!(tree.get_balance(receiver), receiver_before + amount);

    let duplicate = tree.apply_block(&block_1);
    assert!(
        duplicate.is_ok(),
        "idempotent duplicate apply_block should not crash"
    );
}

fn fuzz_reload_from_db_replay(
    db: RockDBManager,
    data: &[u8],
    _sender: &str,
    _receiver: &str,
    miner: &str,
) {
    let mut tree = AccountModelTree::with_manager(db.clone());

    let genesis = Block::new_for_fuzz(0, [0u8; 64], String::new(), None);
    db.put_block_by_index(0, genesis.clone())
        .expect("fake DB should store genesis block");

    let reward_receiver = wallet_from_input(0xF7, data);
    let reward_amount = (read_u64(data, 48) % MAX_SAFE_REWARD)
        .min(GlobalConfiguration::MAX_BLOCK_REWARD)
        .max(1);

    let reward = RewardTx::new(reward_receiver, reward_amount, 1)
        .expect("replay reward tx must construct");

    let batch = TransactionBatch::new(
        1,
        current_unix_secs(),
        vec![TxKind::Reward(reward)],
    )
    .expect("replay batch must construct");

    db.put_batch_bytes_by_index(
        1,
        batch.serialize().expect("replay batch must serialize"),
    )
    .expect("fake DB should store replay batch bytes");

    let block_1 = Block::new_for_fuzz(
        1,
        genesis.block_hash,
        miner.to_owned(),
        Some("replay_batch_1".to_string()),
    );

    db.put_block_by_index(1, block_1)
        .expect("fake DB should store replay block");

    tree.reload_from_db_to_height(1)
        .expect("reload_from_db_to_height should replay stored block + reward batch");

    assert_eq!(tree.latest_block_height(), 1);

    let mut reload_default = AccountModelTree::with_manager(db.clone());
    reload_default.reload_from_db();
    assert_eq!(reload_default.latest_block_height(), 1);

    tree.rollback_to(genesis.block_hash)
        .expect("rollback_to should reload compact state back to genesis");
    assert_eq!(tree.latest_block_height(), 0);
}


fn fuzz_blocks_and_pending(db: RockDBManager, data: &[u8], miner: &str) {
    let mut tree = AccountModelTree::with_manager(db);

    let genesis = Block::new_for_fuzz(0, [0u8; 64], String::new(), None);

    tree.add_block(genesis.clone())
        .expect("genesis add_block should work");

    assert_eq!(tree.latest_block_height(), 0);
    assert_eq!(tree.get_block_by_index(0).expect("block 0 exists"), genesis);

    let block_2 = Block::new_for_fuzz(
        2,
        hash64_from_input(0x22, data),
        miner.to_owned(),
        Some("batch_2".to_string()),
    );

    tree.add_block(block_2.clone())
        .expect("future block should queue, not fail");

    assert_eq!(tree.latest_block_height(), 0);

    let block_1 = Block::new_for_fuzz(
        1,
        genesis.block_hash,
        miner.to_owned(),
        Some("batch_1".to_string()),
    );

    tree.add_block(block_1.clone())
        .expect("block 1 should apply");

    assert_eq!(tree.latest_block_height(), 1);

    let old_duplicate = tree.add_block(genesis);
    assert!(
        old_duplicate.is_ok(),
        "old duplicate block should be ignored, not crash"
    );

    let missing = tree.get_block_by_index(99);
    assert!(missing.is_err(), "missing block lookup unexpectedly succeeded");
}

fn fuzz_supply_helpers(tree: &AccountModelTree, data: &[u8]) {
    let height = read_u64(data, 24) % 10_000;

    let _ = tree.total_issued_micro();
    let _ = tree.rewards_issued_micro();
    let _ = tree.remaining_supply_micro();
    let _ = tree.total_issued_aos();
    let _ = tree.remaining_supply_aos();
    let _ = tree.remaining_reward_supply_micro();
    let _ = tree.remaining_reward_supply_aos();
    let _ = tree.rewards_issued_aos();
    let _ = tree.remaining_reward_supply_micro_after_height_scheduled(height);
    let _ = tree.remaining_reward_supply_aos_after_height_scheduled(height);
    let _ = tree.remaining_reward_supply_micro_scheduled_now();
    let _ = tree.remaining_reward_supply_aos_scheduled_now();
}


fn fuzz_exercise_stub_api_surface(
    db: RockDBManager,
    data: &[u8],
    sender: &str,
    receiver: &str,
) {
    use blockchain::halving_schedule::RewardHalving;
    use blockchain::transaction_002_tx_register::RegisterNodeTx;
    use blockchain::transaction_006_tx_account_tree_guards::{
        AccountGuard, ApplyContext, ApplyMode,
    };
    use utility::alpha_002_error_detection_system::ErrorDetection;
    use utility::hash_system_remzarhash::RemzarHash;
    use utility::helper::{from_micro_units, to_micro_units, to_micro_units_str};

    let _ = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS;
    let _ = GlobalConfiguration::HALVING_INTERVAL_BLOCKS;
    let _ = GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len();
    let _ = GlobalConfiguration::STABILIZED_BLOCK_REWARD;
    let _ = GlobalConfiguration::TOTAL_REWARD_BLOCKS;

    let _timestamp_variant = ErrorDetection::TimestampError {
        message: "fuzz timestamp variant coverage".to_string(),
        details: "constructed intentionally by fuzz target".to_string(),
        source: None,
    };

    let whole = (read_u64(data, 56) % 1000).saturating_add(1);
    let amount_text = format!("{whole}.12345678");
    let parsed_from_str = to_micro_units_str(&amount_text);
    let parsed_from_float = to_micro_units(whole as f64);
    let _display_amount = from_micro_units(parsed_from_str.saturating_add(parsed_from_float));
    let _real_reexport_amount = blockchain::transaction_005_tx_account_tree::to_micro_units(1.25);
    let _real_reexport_display = blockchain::transaction_005_tx_account_tree::from_micro_units(125_000_000);

    let _hash_marker = RemzarHash;
    let _dummy_hash = RemzarHash::compute_dummy_hash();
    let _bytes_hash = RemzarHash::compute_bytes_hash_hex(data);
    let _data_hash = RemzarHash::compute_data_hash(&data).expect("hashing fuzz data should work");

    let _latest = db
        .get_latest_block_index()
        .expect("fake DB latest block index should be readable");
    let _scheduled_reward = RewardHalving::get_block_reward(read_u64(data, 64) % 1024);
    let _remaining_reward = RewardHalving::remaining_reward_supply_micro_after_block(
        read_u64(data, 72) % 1024,
    );

    let transfer_amount = (read_u64(data, 80) % MAX_SAFE_TRANSFER).max(1);
    let tx = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("stub surface transfer should construct");
    let tx_bytes = tx.serialize().expect("transfer serialize should work");
    let tx_roundtrip = Transaction::deserialize(&tx_bytes).expect("transfer deserialize should work");
    let _tx_id = tx_roundtrip.id().expect("transfer id should hash");

    let reg = RegisterNodeTx::new(sender.to_owned()).expect("register tx should construct");
    let reg_bytes = reg.serialize().expect("register serialize should work");
    let _reg_roundtrip = RegisterNodeTx::deserialize(&reg_bytes).expect("register deserialize should work");

    let reward = RewardTx::new(
        receiver.to_owned(),
        GlobalConfiguration::MAX_BLOCK_REWARD.min(MAX_SAFE_REWARD).max(1),
        1,
    )
    .expect("reward tx should construct");
    let reward_bytes = reward.serialize().expect("reward serialize should work");
    let _reward_roundtrip = RewardTx::deserialize(&reward_bytes).expect("reward deserialize should work");

    let transfer_kind = TxKind::Transfer(tx_roundtrip.clone());
    let kind_bytes = transfer_kind.serialize().expect("txkind serialize should work");
    let _kind_roundtrip = TxKind::deserialize(&kind_bytes).expect("txkind deserialize should work");

    let guard = AccountGuard::new();
    let mut state = blockchain::transaction_005_tx_account_tree::InnerTree::empty();
    state
        .balances
        .insert(sender.to_string(), transfer_amount.saturating_mul(2));

    let batch = TransactionBatch::new(0, current_unix_secs(), vec![transfer_kind])
        .expect("guard batch should construct");
    let ctx = ApplyContext {
        mode: ApplyMode::Live,
        block_height: 0,
        block_hash: hash64_from_input(0x44, data),
        previous_hash: [0u8; 64],
        allow_duplicate_reward_in_batch: false,
    };

    let outcome = guard
        .apply_batch_to_state(&mut state, &batch, &ctx)
        .expect("guard apply_batch_to_state should apply funded transfer");

    assert!(outcome.touched_accounts.contains(sender));
    assert!(outcome.touched_accounts.contains(receiver));
    assert!(outcome.total_supply_micro >= transfer_amount.saturating_mul(2));
    assert_eq!(outcome.fingerprint_hex.len(), 128);

    let fingerprint = guard
        .compute_state_fingerprint(&state, 0, &outcome.touched_accounts)
        .expect("state fingerprint should compute");
    assert_eq!(fingerprint.height, 0);
    assert!(fingerprint.total_supply_micro >= transfer_amount.saturating_mul(2));
    assert!(fingerprint.total_issued_micro <= GlobalConfiguration::MAX_SUPPLY);
    assert!(fingerprint.rewards_issued_micro <= GlobalConfiguration::MAX_REWARD_SUPPLY);
    assert!(!fingerprint.touched_accounts.is_empty());
    assert_eq!(fingerprint.hex.len(), 128);
    guard.log_state_fingerprint("fuzz_surface", &fingerprint);
    guard
        .verify_account_cf_matches_state(&db, &state, &outcome.touched_accounts)
        .expect("fake ACCOUNT CF verification should succeed");
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-account-tree-wallet-v1");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

fn hash64_from_input(domain: u8, data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-account-tree-hash64-v1");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    out
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(946_684_800)
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for (i, slot) in out.iter_mut().enumerate() {
        *slot = data.get(offset + i).copied().unwrap_or(0);
    }

    u64::from_le_bytes(out)
}