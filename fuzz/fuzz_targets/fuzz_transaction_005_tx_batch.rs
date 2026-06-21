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
            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
            pub const MIN_BLOCK_SIZE: u64 = 1;
            pub const MAX_BLOCK_REWARD: u64 = 20 * UNIT_DIVISOR;
            pub const MAX_TX_AMOUNT: u64 = 10_000_000_000_000_000;
            pub const MAX_BATCH_SERIALIZED_OVERHEAD: usize = 2048;
            pub const TRANSACTION_BATCH_COLUMN_NAME: &'static str = "transaction_batch_data";

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
            StorageError {
                message: String,
            },
            NotFound {
                resource: String,
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
                    ErrorDetection::StorageError { message } => {
                        write!(f, "Storage error: {message}")
                    }
                    ErrorDetection::NotFound { resource } => {
                        write!(f, "Resource not found: {resource}")
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

        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub struct Hash64(pub [u8; 64]);

        impl Hash64 {
            pub fn from_bytes(bytes: [u8; 64]) -> Self {
                Hash64(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 64] {
                &self.0
            }
        }

        pub type InclusionProof = Hash64;

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

            pub fn compute_data_hash<T: Serialize + ?Sized>(
                data: &T,
            ) -> Result<String, ErrorDetection> {
                let bytes = to_allocvec(data).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })?;

                Ok(hex::encode(Self::blake3_xof64(&bytes)))
            }

            pub fn compute_merkle_root<T: Serialize + Send + Sync>(
                transactions: &[T],
            ) -> Result<String, ErrorDetection> {
                let mut h = Hasher::new();

                if transactions.is_empty() {
                    h.update(b"EMPTY_MERKLE_ROOT");
                } else {
                    for tx in transactions {
                        let bytes =
                            to_allocvec(tx).map_err(|e| ErrorDetection::SerializationError {
                                details: e.to_string(),
                            })?;

                        h.update(&bytes);
                    }
                }

                let mut out = [0u8; 64];
                h.finalize_xof().fill(&mut out);

                Ok(hex::encode(out))
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

mod storage {
    pub mod rocksdb_003_batches {
        #[derive(Debug, Clone)]
        pub struct FakeDb;

        impl FakeDb {
            pub fn cf_handle(&self, _name: &str) -> Option<u32> {
                Some(0)
            }

            pub fn put_cf<K, V>(&self, _cf: u32, _key: K, _value: V) -> Result<(), String>
            where
                K: AsRef<[u8]>,
                V: AsRef<[u8]>,
            {
                Ok(())
            }
        }

        #[derive(Debug, Clone)]
        pub struct RockBatch {
            pub db: FakeDb,
        }

        impl RockBatch {
            pub fn new_fake() -> Self {
                Self { db: FakeDb }
            }
        }
    }
}

mod cryptography {
    pub mod ml_dsa_65_003_batch_signature {
        use fips204::ml_dsa_65;
        use fips204::ml_dsa_65::PrivateKey as SigningKey;

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub struct MlDsa65BatchSignature;

        impl MlDsa65BatchSignature {
            pub fn sign_batch(
                _sk: &SigningKey,
                refs: &[&[u8]],
            ) -> Result<Vec<u8>, ErrorDetection> {
                let mut sig = vec![0u8; ml_dsa_65::SIG_LEN];

                for (i, chunk) in refs.iter().enumerate() {
                    let idx = i % sig.len();
                    sig[idx] ^= chunk.len() as u8;
                }

                Ok(sig)
            }
        }
    }
}

mod blockchain {
    pub mod block_001_metadata {
        use fips204::ml_dsa_65;
        use serde::{Deserialize, Serialize};
        use serde_big_array::BigArray;

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct BlockMetadata {
            pub index: u64,
            pub timestamp: u64,

            #[serde(with = "BigArray")]
            pub previous_hash: [u8; 64],

            #[serde(with = "BigArray")]
            pub merkle_root: [u8; 64],

            #[serde(with = "BigArray")]
            pub guardian_signature: [u8; ml_dsa_65::SIG_LEN],

            pub size: u64,
        }

        impl BlockMetadata {
            pub fn new(
                index: u64,
                timestamp: u64,
                previous_hash: [u8; 64],
                merkle_root: [u8; 64],
                guardian_signature: [u8; ml_dsa_65::SIG_LEN],
                _puzzle_proof: Option<()>,
                size: u64,
            ) -> Self {
                Self {
                    index,
                    timestamp,
                    previous_hash,
                    merkle_root,
                    guardian_signature,
                    size,
                }
            }
        }
    }

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

    pub mod transaction_005_tx_batch {
        include!("../../src/blockchain/transaction_005_tx_batch.rs");
    }
}

use blockchain::transaction_001_tx::Transaction;
use blockchain::transaction_002_tx_register::RegisterNodeTx;
use blockchain::transaction_003_tx_reward::RewardTx;
use blockchain::transaction_004_tx_kind::TxKind;
use blockchain::transaction_005_tx_batch::TransactionBatch;
use storage::rocksdb_003_batches::RockBatch;
use utility::alpha_001_global_configuration::GlobalConfiguration;
use tokens::nft_001::{NftMintTx, NftTransferTx};

const MAX_FUZZ_TXS_PER_CASE: usize = 5;
const MAX_NFT_TITLE_BYTES: usize = 64;
const MAX_NFT_DESCRIPTION_BYTES: usize = 128;

fuzz_target!(|data: &[u8]| {
    // 1) Hostile raw TransactionBatch wire bytes.
    // This must never panic.
    let _ = TransactionBatch::deserialize(data);

    // 2) Deterministic valid batch.
    let txs = build_tx_kinds(data);

    let index = read_u64(data, 0);
    let timestamp = current_unix_secs().saturating_add(read_u64(data, 8) % 30);

    fuzz_valid_batch(index, timestamp, txs.clone());
    fuzz_empty_batch(index, timestamp);
    fuzz_reward_only(index, timestamp, data);
    fuzz_reward_boundaries(index, timestamp, data);
    fuzz_batch_wire_mutations(index, timestamp, txs);
});

fn fuzz_valid_batch(index: u64, timestamp: u64, transactions: Vec<TxKind>) {
    let batch = TransactionBatch::new(index, timestamp, transactions)
        .expect("TransactionBatch::new should construct");

    let total_size = batch
        .total_size()
        .expect("valid batch total_size must work");

    let serialized_len = batch
        .serialized_len()
        .expect("valid batch serialized_len must work");

    let encoded = batch
        .serialize()
        .expect("valid batch serialize must work");

    assert_eq!(serialized_len, encoded.len());

    let storage_bytes = batch
        .serialize_for_storage()
        .expect("valid batch serialize_for_storage must work");

    assert_eq!(storage_bytes, encoded);

    let decoded = TransactionBatch::deserialize(&encoded)
        .expect("valid batch deserialize must work");

    assert_eq!(decoded, batch);

    fuzz_tx_kind_roundtrip(&batch.transactions);

    let merkle = batch
        .compute_merkle_root()
        .expect("valid batch merkle root must compute");

    assert_eq!(merkle.len(), 64);

    if !batch.transactions.is_empty() {
        for i in 0..batch.transactions.len() {
            let proof = batch
                .inclusion_proof(i)
                .expect("valid inclusion proof index must work");

            // A one-leaf tree has an empty proof. Larger trees have siblings.
            if batch.transactions.len() > 1 {
                assert!(!proof.is_empty());
            }
        }

        assert!(
            batch.inclusion_proof(batch.transactions.len()).is_err(),
            "inclusion_proof accepted out-of-bounds leaf index"
        );
    }

    let fake_db = RockBatch::new_fake();

    batch
        .store_in_db(&fake_db)
        .expect("fake DB store_in_db should work");

    let _ = total_size;
}

fn fuzz_empty_batch(index: u64, timestamp: u64) {
    let batch = TransactionBatch::new(index, timestamp, Vec::new())
        .expect("empty TransactionBatch::new should construct");

    assert_eq!(
        batch.total_size().expect("empty total_size should work"),
        0
    );

    let encoded = batch
        .serialize()
        .expect("empty batch serialize should work");

    let decoded = TransactionBatch::deserialize(&encoded)
        .expect("empty batch deserialize should work");

    assert_eq!(decoded, batch);

    fuzz_tx_kind_roundtrip(&batch.transactions);

    let merkle = batch
        .compute_merkle_root()
        .expect("empty batch merkle root should compute");

    assert_eq!(merkle.len(), 64);

    assert!(
        batch.inclusion_proof(0).is_err(),
        "empty batch accepted inclusion proof index 0"
    );
}

fn fuzz_reward_only(index: u64, timestamp: u64, data: &[u8]) {
    let receiver = wallet_from_input(0xD1, data);

    let amount = valid_reward_amount(read_u64(data, 16));

    let block_height = read_u64(data, 24).max(1);

    let reward = RewardTx::new(receiver, amount, block_height)
        .expect("reward-only RewardTx must construct");

    let batch = TransactionBatch::from_reward_only(index, timestamp, reward)
        .expect("from_reward_only must construct");

    assert_eq!(batch.transactions.len(), 1);

    let encoded = batch
        .serialize()
        .expect("reward-only batch serialize must work");

    let decoded = TransactionBatch::deserialize(&encoded)
        .expect("reward-only batch deserialize must work");

    assert_eq!(decoded, batch);

    let root = batch
        .compute_merkle_root()
        .expect("reward-only merkle root must compute");

    assert_eq!(root.len(), 64);

    let proof = batch
        .inclusion_proof(0)
        .expect("reward-only inclusion proof at index 0 must work");

    assert!(proof.is_empty());
}

fn fuzz_reward_boundaries(index: u64, timestamp: u64, data: &[u8]) {
    let receiver = wallet_from_input(0xD2, data);
    let block_height = read_u64(data, 64).max(1);

    let max_reward = GlobalConfiguration::MAX_BLOCK_REWARD;

    let reward_at_max = RewardTx::new(receiver.clone(), max_reward, block_height)
        .expect("RewardTx must allow exactly MAX_BLOCK_REWARD");

    let batch = TransactionBatch::from_reward_only(index, timestamp, reward_at_max)
        .expect("from_reward_only must allow exactly MAX_BLOCK_REWARD");

    assert_eq!(batch.transactions.len(), 1);

    let encoded = batch
        .serialize()
        .expect("max-reward batch serialize must work");

    let decoded = TransactionBatch::deserialize(&encoded)
        .expect("max-reward batch deserialize must work");

    assert_eq!(decoded, batch);

    let above_max = max_reward.saturating_add(1);

    assert!(
        RewardTx::new(receiver, above_max, block_height).is_err(),
        "RewardTx accepted amount above GlobalConfiguration::MAX_BLOCK_REWARD"
    );
}

fn fuzz_batch_wire_mutations(index: u64, timestamp: u64, transactions: Vec<TxKind>) {
    let mut batch = TransactionBatch::new(index, timestamp, transactions)
        .expect("base batch must construct");

    let encoded = batch
        .serialize()
        .expect("base batch serialize must work");

    TransactionBatch::deserialize(&encoded)
        .expect("base batch deserialize must work");

    // Trailing bytes must be rejected.
    let mut trailing = encoded.clone();
    trailing.push(0);

    assert!(
        TransactionBatch::deserialize(&trailing).is_err(),
        "TransactionBatch::deserialize accepted trailing bytes"
    );

    batch.guardian_signature = Some(vec![1, 2, 3]);

    let bad_sig_encoded = batch
        .serialize()
        .expect("batch with short guardian signature still serializes");

    let decoded = TransactionBatch::deserialize(&bad_sig_encoded)
        .expect("structural batch deserialize should allow short guardian signature");

    assert_eq!(decoded.guardian_signature.as_deref(), Some(&[1, 2, 3][..]));

    batch.guardian_signature = Some(vec![0xAB; fips204::ml_dsa_65::SIG_LEN]);

    let good_sig_encoded = batch
        .serialize()
        .expect("batch with exact guardian signature length must serialize");

    let decoded_good_sig = TransactionBatch::deserialize(&good_sig_encoded)
        .expect("structural batch deserialize should allow exact guardian signature");

    assert_eq!(
        decoded_good_sig.guardian_signature.as_ref().map(Vec::len),
        Some(fips204::ml_dsa_65::SIG_LEN)
    );
}

fn fuzz_tx_kind_roundtrip(transactions: &[TxKind]) {
    for tx in transactions {
        let encoded = tx.serialize().expect("generated TxKind must serialize");
        let decoded = TxKind::deserialize(&encoded).expect("generated TxKind must deserialize");

        assert_eq!(decoded, tx.clone());

        // These accessors should be total/non-panicking for every generated variant.
        let _ = tx.tag();
        let _ = tx.normalized_sender();
        let _ = tx.normalized_receiver();
        let _ = tx.touched_addresses();
    }
}

fn build_tx_kinds(data: &[u8]) -> Vec<TxKind> {
    let sender = wallet_from_input(0xA1, data);
    let receiver = wallet_from_input(0xB2, data);
    let nft_owner = wallet_from_input(0xC3, data);

    let transfer_amount = valid_transfer_amount(read_u64(data, 32));

    let reward_amount = valid_reward_amount(read_u64(data, 40));

    let reward_height = read_u64(data, 48).max(1);

    let transfer = Transaction::new(sender.clone(), receiver.clone(), transfer_amount)
        .expect("valid transfer must construct");

    let register = RegisterNodeTx::new(sender)
        .expect("valid register-node tx must construct");

    let reward = RewardTx::new(receiver, reward_amount, reward_height)
        .expect("valid reward tx must construct");

    let nft_mint = NftMintTx::from_content_bytes(
        hash64_from_input(0x11, data),
        bounded_string(data, 56, MAX_NFT_TITLE_BYTES),
        bounded_string(data, 120, MAX_NFT_DESCRIPTION_BYTES),
        data,
    );

    let nft_transfer = NftTransferTx {
        nft_id: hash64_from_input(0x22, data),
        new_owner_wallet: nft_owner,
    };

    let mut out = Vec::new();

    let selector = data.first().copied().unwrap_or(0);

    out.push(TxKind::Transfer(transfer));

    if selector & 0b0000_0001 != 0 {
        out.push(TxKind::RegisterNode(register));
    }

    if selector & 0b0000_0010 != 0 {
        out.push(TxKind::Reward(reward));
    }

    if selector & 0b0000_0100 != 0 {
        out.push(TxKind::NftMint(nft_mint));
    }

    if selector & 0b0000_1000 != 0 {
        out.push(TxKind::NftTransfer(nft_transfer));
    }

    // Keep fuzz case cost bounded.
    if out.len() > MAX_FUZZ_TXS_PER_CASE {
        out.truncate(MAX_FUZZ_TXS_PER_CASE);
    }

    out
}

fn valid_reward_amount(raw: u64) -> u64 {
    let max = GlobalConfiguration::MAX_BLOCK_REWARD;

    debug_assert!(max > 0);

    (raw % max).saturating_add(1)
}

fn valid_transfer_amount(raw: u64) -> u64 {
    let max = GlobalConfiguration::MAX_TX_AMOUNT;

    debug_assert!(max > 0);

    (raw % max).max(1)
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-tx-batch-wallet-v1");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

fn hash64_from_input(domain: u8, data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-tx-batch-hash64-v1");
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