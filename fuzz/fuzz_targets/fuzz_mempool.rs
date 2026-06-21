#![no_main]

use libfuzzer_sys::fuzz_target;
use postcard::to_allocvec;
use std::collections::{BTreeMap, HashMap, HashSet};

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
            pub const BLOCK_OVERHEAD_RESERVE: usize = 16 * 1024;
            pub const TRANSACTION_BUFFER_LIMIT: u64 = 2 * 1024 * 1024;
            pub const MAX_TXS_PER_BLOCK: u64 = 7_500;
            pub const MAX_BATCH_ITEMS: usize = 256;
            pub const MAX_ITEM_BYTES: usize = 4096;
            pub const MAX_TX_AMOUNT: u64 = 10_000_000_000_000_000;
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
            pub const MAX_FUTURE_SKEW_SECS: u64 = 2 * 60 * 60;
        }
    }

    pub mod alpha_002_error_detection_system {
        use std::fmt;

        #[derive(Debug)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
            DoubleSpending {
                tx_id: Option<String>,
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
                    Self::DoubleSpending { tx_id } => {
                        write!(f, "double spend: {tx_id:?}")
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
        pub const REMZAR_WALLET_BODY_LEN: usize = 128;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';
        pub const UNIT_DIVISOR: u64 = 100_000_000;

        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let lower = id.trim().to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.len() != REMZAR_WALLET_LEN || b.first() != Some(&REMZAR_WALLET_PREFIX) {
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

        pub fn parse_wallet_address_bytes(bytes: &[u8]) -> Result<String, ErrorDetection> {
            if bytes.iter().any(|&b| b == 0) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address contains NUL byte".into(),
                    tx_id: None,
                });
            }

            let s = std::str::from_utf8(bytes).map_err(|_| ErrorDetection::ValidationError {
                message: "Wallet address bytes invalid utf8".into(),
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

            if !b[1..]
                .iter()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            Ok(s.to_string())
        }

        pub fn to_micro_units_str(s: &str) -> u64 {
            const SCALE: u64 = 100_000_000;

            let s = s.trim();
            if s.is_empty()
                || s.len() > 64
                || s.starts_with('-')
                || s.starts_with('+')
                || s.contains('e')
                || s.contains('E')
                || s.as_bytes().iter().any(|b| b.is_ascii_whitespace())
            {
                return 0;
            }

            let (whole, frac) = match s.split_once('.') {
                Some((w, f)) if !f.contains('.') => (w, f),
                Some(_) => return 0,
                None => (s, ""),
            };

            let whole = if whole.is_empty() { "0" } else { whole };

            if !whole.bytes().all(|b| b.is_ascii_digit())
                || !frac.bytes().all(|b| b.is_ascii_digit())
                || frac.len() > 8
            {
                return 0;
            }

            let whole = match whole.parse::<u64>() {
                Ok(v) => v,
                Err(_) => return 0,
            };

            let mut frac_num = 0u64;

            for b in frac.bytes() {
                frac_num = match frac_num
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u64::from(b - b'0')))
                {
                    Some(v) => v,
                    None => return 0,
                };
            }

            for _ in frac.len()..8 {
                frac_num = match frac_num.checked_mul(10) {
                    Some(v) => v,
                    None => return 0,
                };
            }

            whole
                .checked_mul(SCALE)
                .and_then(|v| v.checked_add(frac_num))
                .unwrap_or(0)
        }

        pub fn from_micro_units(amount: u64) -> f64 {
            let whole = amount / UNIT_DIVISOR;
            let frac = amount % UNIT_DIVISOR;
            format!("{whole}.{frac:08}").parse::<f64>().unwrap_or(0.0)
        }
    }

    pub mod hash_system_remzarhash {
        use blake3::Hasher;

        pub struct RemzarHash;

        impl RemzarHash {
            pub fn compute_bytes_hash(bytes: &[u8]) -> [u8; 64] {
                let mut h = Hasher::new();
                h.update(bytes);

                let mut out = [0u8; 64];
                h.finalize_xof().fill(&mut out);

                out
            }

            pub fn compute_bytes_hash_hex(bytes: &[u8]) -> String {
                hex::encode(Self::compute_bytes_hash(bytes))
            }
        }
    }
}

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }
}

mod tokens {
    pub mod nft_001 {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
        pub struct NftMintTx {
            pub collection: String,
            pub token_id: String,
            pub owner_wallet: String,
            pub metadata: Vec<u8>,
        }

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
        pub struct NftTransferTx {
            pub token_id: String,
            pub old_owner_wallet: String,
            pub new_owner_wallet: String,
        }
    }
}

#[path = "../../src/blockchain/transaction_001_tx.rs"]
mod real_transaction_001_tx;

#[path = "../../src/blockchain/transaction_004_tx_kind.rs"]
mod real_transaction_004_tx_kind;

mod blockchain {
    pub mod transaction_001_tx {
        pub use crate::real_transaction_001_tx::*;
    }

    pub mod transaction_002_tx_register {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
        pub struct RegisterNodeTx {
            pub node_id: String,
            pub wallet: String,
        }

        impl RegisterNodeTx {
            pub fn validate(&self) -> Result<(), ErrorDetection> {
                if self.node_id.len() > 4096 || self.wallet.len() > 4096 {
                    return Err(ErrorDetection::ValidationError {
                        message: "RegisterNodeTx field too large".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }
        }
    }

    pub mod transaction_003_tx_reward {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{parse_wallet_address_bytes, REMZAR_WALLET_LEN};
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub struct RewardTx {
            #[serde(with = "serde_big_array::BigArray")]
            pub receiver: [u8; REMZAR_WALLET_LEN],
            pub amount: u64,
        }

        impl RewardTx {
            pub fn validate(&self) -> Result<(), ErrorDetection> {
                parse_wallet_address_bytes(&self.receiver)?;

                if self.amount == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "Reward amount must be greater than zero".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }
        }
    }

    pub mod transaction_004_tx_kind {
        pub use crate::real_transaction_004_tx_kind::*;
    }

    pub mod transaction_005_tx_batch {
        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub struct TransactionBatch {
            pub transactions: Vec<TxKind>,
        }
    }
}

use blockchain::transaction_001_tx::Transaction;
use blockchain::transaction_004_tx_kind::TxKind;
use blockchain::transaction_005_tx_batch::TransactionBatch;
use network::p2p_006_reqresp::Hash;
use utility::alpha_001_global_configuration::GlobalConfiguration;
use utility::alpha_002_error_detection_system::ErrorDetection;
use utility::hash_system_remzarhash::RemzarHash;

#[derive(Default)]
struct MemoryMempool {
    by_key: BTreeMap<Vec<u8>, Vec<u8>>,
    by_hash: HashMap<Hash, Vec<u8>>,
    bytes_used: u64,
    nonce: u64,
}

impl MemoryMempool {
    fn max_batch_txs() -> usize {
        usize::try_from(GlobalConfiguration::MAX_TXS_PER_BLOCK)
            .unwrap_or(usize::MAX)
            .min(GlobalConfiguration::MAX_BATCH_ITEMS)
    }

    fn batch_budget_bytes() -> usize {
        usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
            .unwrap_or(usize::MAX)
            .saturating_sub(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE)
    }

    fn canonical_txkind_bytes(kind: &TxKind) -> Result<Vec<u8>, ErrorDetection> {
        to_allocvec(kind).map_err(|e| ErrorDetection::SerializationError {
            details: format!("TxKind serialize failed: {e}"),
        })
    }

    fn check_entry_size_bound(len: usize) -> Result<(), ErrorDetection> {
        if len > GlobalConfiguration::MAX_ITEM_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!("Mempool entry too large: {len}"),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn collect_existing_ids(&self) -> HashSet<String> {
        self.by_key
            .values()
            .filter_map(|v| {
                Self::check_entry_size_bound(v.len()).ok()?;
                TxKind::deserialize(v).ok()
            })
            .filter_map(|kind| match kind {
                TxKind::Transfer(tx) => tx.id().ok(),
                _ => None,
            })
            .collect()
    }

    fn add_transaction(&mut self, tx: &Transaction) -> Result<(), ErrorDetection> {
        self.add_tx_kind(&TxKind::Transfer(tx.clone()))
    }

    fn add_tx_kind(&mut self, kind: &TxKind) -> Result<(), ErrorDetection> {
        kind.validate()?;

        let serialized = Self::canonical_txkind_bytes(kind)?;
        Self::check_entry_size_bound(serialized.len())?;

        let budget = Self::batch_budget_bytes();

        if serialized.len() > budget {
            return Err(ErrorDetection::ValidationError {
                message: "Transaction too large to ever fit".into(),
                tx_id: match kind {
                    TxKind::Transfer(tx) => tx.id().ok(),
                    _ => None,
                },
            });
        }

        let new_total = self
            .bytes_used
            .checked_add(serialized.len() as u64)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Overflow while computing mempool capacity".into(),
                tx_id: None,
            })?;

        if new_total > GlobalConfiguration::TRANSACTION_BUFFER_LIMIT {
            return Err(ErrorDetection::ValidationError {
                message: "Mempool full".into(),
                tx_id: None,
            });
        }

        if let TxKind::Transfer(tx) = kind {
            let tx_id = tx.id()?;

            if self.collect_existing_ids().contains(&tx_id) {
                return Err(ErrorDetection::DoubleSpending {
                    tx_id: Some(tx_id),
                });
            }
        }

        let hash = RemzarHash::compute_bytes_hash(&serialized);

        if self.by_hash.contains_key(&hash) {
            return Err(ErrorDetection::ValidationError {
                message: "Duplicate transaction hash".into(),
                tx_id: match kind {
                    TxKind::Transfer(tx) => tx.id().ok(),
                    _ => None,
                },
            });
        }

        self.nonce = self.nonce.wrapping_add(1);
        let key = self.nonce.to_be_bytes().to_vec();

        self.by_key.insert(key, serialized.clone());
        self.by_hash.insert(hash, serialized);
        self.bytes_used = new_total;

        Ok(())
    }

    fn fetch_transactions_for_block(&self) -> Result<Vec<(Vec<u8>, TxKind)>, ErrorDetection> {
        let mut entries = Vec::new();
        let mut total_size = 0usize;
        let max_count = Self::max_batch_txs();
        let budget = Self::batch_budget_bytes();

        for (key, value) in &self.by_key {
            Self::check_entry_size_bound(value.len())?;

            let Ok(kind) = TxKind::deserialize(value) else {
                continue;
            };

            let Ok(canonical) = Self::canonical_txkind_bytes(&kind) else {
                continue;
            };

            let size = canonical.len();

            if size > budget {
                continue;
            }

            if total_size.saturating_add(size) > budget {
                continue;
            }

            if entries.len() >= max_count {
                break;
            }

            total_size = total_size.saturating_add(size);
            entries.push((key.clone(), kind));
        }

        Ok(entries)
    }

    fn remove_transactions(&mut self, tx_keys: &[Vec<u8>]) {
        for key in tx_keys {
            if let Some(value) = self.by_key.remove(key) {
                self.bytes_used = self.bytes_used.saturating_sub(value.len() as u64);
                let hash = RemzarHash::compute_bytes_hash(&value);
                self.by_hash.remove(&hash);
            }
        }
    }

    fn remove_transactions_in_batch(
        &mut self,
        batch: &TransactionBatch,
    ) -> Result<(), ErrorDetection> {
        let mut wanted = HashSet::new();

        for kind in &batch.transactions {
            let bytes = Self::canonical_txkind_bytes(kind)?;
            wanted.insert(RemzarHash::compute_bytes_hash(&bytes));
        }

        if wanted.is_empty() {
            return Ok(());
        }

        let keys = self
            .by_key
            .iter()
            .filter_map(|(key, value)| {
                let hash = RemzarHash::compute_bytes_hash(value);
                wanted.contains(&hash).then(|| key.clone())
            })
            .collect::<Vec<_>>();

        self.remove_transactions(&keys);
        Ok(())
    }

    fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, ErrorDetection> {
        let Some(bytes) = self.by_hash.get(hash) else {
            return Ok(None);
        };

        Self::check_entry_size_bound(bytes.len())?;

        match TxKind::deserialize(bytes)? {
            TxKind::Transfer(tx) => Ok(Some(tx)),
            _ => Ok(None),
        }
    }

    fn mempool_size(&self) -> usize {
        self.by_key.len()
    }

    fn poison_entry(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.bytes_used = self.bytes_used.saturating_add(value.len() as u64);
        self.by_key.insert(key, value);
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    result.ok()
}

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

fn bounded_count(data: &[u8], offset: usize, max: usize) -> usize {
    if max == 0 {
        0
    } else {
        usize::from(byte_at(data, offset, 0)) % max
    }
}

fn fuzz_hash(data: &[u8], salt: usize) -> [u8; 64] {
    let mut out = [0u8; 64];

    if data.is_empty() {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(salt as u8).wrapping_add(1);
        }

        return out;
    }

    for i in 0..64 {
        let a = data[(i + salt) % data.len()];
        let b = data[(i.wrapping_mul(7).wrapping_add(salt)) % data.len()];
        out[i] = a ^ b ^ (i as u8).wrapping_add(salt as u8);
    }

    out
}

fn canonical_wallet(data: &[u8], salt: usize) -> String {
    format!("r{}", hex::encode(fuzz_hash(data, salt)))
}

fn canonical_wallet_arr(data: &[u8], salt: usize) -> [u8; utility::helper::REMZAR_WALLET_LEN] {
    let wallet = canonical_wallet(data, salt);
    let mut out = [0u8; utility::helper::REMZAR_WALLET_LEN];
    out.copy_from_slice(wallet.as_bytes());
    out
}

fn valid_amount(data: &[u8], salt: usize) -> u64 {
    (read_u64(data, salt) % GlobalConfiguration::MAX_TX_AMOUNT.saturating_sub(1)).saturating_add(1)
}

fn make_valid_transfer(data: &[u8], salt: usize) -> Option<Transaction> {
    let sender = canonical_wallet(data, salt);
    let mut receiver = canonical_wallet(data, salt.wrapping_add(97));

    if sender == receiver {
        receiver = canonical_wallet(data, salt.wrapping_add(193));
    }

    touch_result(Transaction::new(
        sender,
        receiver,
        valid_amount(data, salt.wrapping_add(211)),
    ))
}

fn make_direct_transfer_shape(data: &[u8], salt: usize) -> Transaction {
    let mut sender = canonical_wallet_arr(data, salt);
    let mut receiver = canonical_wallet_arr(data, salt.wrapping_add(11));

    match byte_at(data, salt.wrapping_add(23), 0) % 6 {
        0 => receiver = sender,
        1 => sender[0] = b'x',
        2 => sender[5] = 0,
        3 => receiver[10] = b'z',
        _ => {}
    }

    let amount = match byte_at(data, salt.wrapping_add(31), 0) % 5 {
        0 => 0,
        _ => valid_amount(data, salt.wrapping_add(37)),
    };

    Transaction {
        sender,
        receiver,
        amount,
        timestamp: read_u64(data, salt.wrapping_add(43)),
    }
}

fn mutate_bytes(buf: &mut [u8], data: &[u8], salt: usize) {
    if buf.is_empty() {
        return;
    }

    if data.is_empty() {
        let idx = salt % buf.len();
        buf[idx] ^= 0xA5;
        return;
    }

    let stride = usize::from(data[0] % 31).saturating_add(1);

    for (i, byte) in data.iter().enumerate() {
        let idx = i
            .wrapping_mul(stride)
            .wrapping_add(salt)
            .wrapping_rem(buf.len());

        buf[idx] ^= *byte;
    }
}

fn mutate_length(mut buf: Vec<u8>, data: &[u8], salt: usize) -> Vec<u8> {
    match byte_at(data, salt, 0) % 8 {
        0 => buf.clear(),
        1 => {
            let new_len = bounded_count(data, salt.wrapping_add(1), buf.len().saturating_add(1));
            buf.truncate(new_len);
        }
        2 => buf.push(byte_at(data, salt.wrapping_add(2), 0)),
        3 => buf.extend_from_slice(data),
        4 => {
            if !buf.is_empty() {
                let idx = bounded_count(data, salt.wrapping_add(3), buf.len());
                buf.remove(idx);
            }
        }
        5 => {
            let remove = bounded_count(data, salt.wrapping_add(4), 64).saturating_add(1);
            let new_len = buf.len().saturating_sub(remove);
            buf.truncate(new_len);
        }
        6 => {
            let extra = bounded_count(data, salt.wrapping_add(5), 256);
            buf.extend(std::iter::repeat(byte_at(data, salt.wrapping_add(6), 0)).take(extra));
        }
        _ => {}
    }

    buf
}

fn exercise_raw_txkind_deserialize(data: &[u8]) {
    let _ = TxKind::deserialize(data);

    if let Some(tx) = make_valid_transfer(data, 11) {
        let kind = TxKind::Transfer(tx);

        if let Ok(encoded) = kind.serialize() {
            let _ = TxKind::deserialize(&encoded);

            let mut mutated = encoded.clone();
            mutate_bytes(&mut mutated, data, 101);
            let _ = TxKind::deserialize(&mutated);

            let resized = mutate_length(encoded, data, 113);
            let _ = TxKind::deserialize(&resized);
        }
    }
}

fn exercise_mempool(data: &[u8]) {
    let mut mempool = MemoryMempool::default();

    exercise_raw_txkind_deserialize(data);

    let rounds = bounded_count(data, 0, 64).saturating_add(1);
    let mut remembered_keys: Vec<Vec<u8>> = Vec::new();

    for round in 0..rounds {
        let mode = byte_at(data, round.wrapping_mul(13).wrapping_add(1), 0) % 10;

        match mode {
            0 => {
                if let Some(tx) = make_valid_transfer(data, round.wrapping_mul(97).wrapping_add(7))
                {
                    let _ = mempool.add_transaction(&tx);
                }
            }

            1 => {
                let tx = make_direct_transfer_shape(data, round.wrapping_mul(131).wrapping_add(17));
                let _ = mempool.add_transaction(&tx);
            }

            2 => {
                if let Some(tx) = make_valid_transfer(data, round.wrapping_mul(149).wrapping_add(19))
                {
                    let kind = TxKind::Transfer(tx);
                    let _ = mempool.add_tx_kind(&kind);
                }
            }

            3 => {
                let fetched = mempool.fetch_transactions_for_block().unwrap_or_default();

                assert!(
                    fetched.len()
                        <= GlobalConfiguration::MAX_BATCH_ITEMS.min(
                            usize::try_from(GlobalConfiguration::MAX_TXS_PER_BLOCK)
                                .unwrap_or(usize::MAX)
                        )
                );

                for (key, kind) in &fetched {
                    remembered_keys.push(key.clone());

                    let _ = kind.validate();

                    let Ok(bytes) = MemoryMempool::canonical_txkind_bytes(kind) else {
                        continue;
                    };

                    assert!(bytes.len() <= GlobalConfiguration::MAX_ITEM_BYTES);

                    let hash = RemzarHash::compute_bytes_hash(&bytes);
                    let _ = mempool.get_transaction(&hash);
                }
            }

            4 => {
                let fetched = mempool.fetch_transactions_for_block().unwrap_or_default();

                let keys = fetched
                    .iter()
                    .map(|(key, _)| key.clone())
                    .take(bounded_count(data, round.wrapping_add(3), 8))
                    .collect::<Vec<_>>();

                mempool.remove_transactions(&keys);
            }

            5 => {
                let mut bogus = Vec::new();
                let bogus_count = bounded_count(data, round.wrapping_add(5), 8);

                for i in 0..bogus_count {
                    let len = bounded_count(data, round.wrapping_add(i), 128);
                    let mut key = Vec::with_capacity(len);

                    for j in 0..len {
                        key.push(byte_at(data, round.wrapping_add(i).wrapping_add(j), j as u8));
                    }

                    bogus.push(key);
                }

                mempool.remove_transactions(&bogus);
            }

            6 => {
                let fetched = mempool.fetch_transactions_for_block().unwrap_or_default();

                let transactions = fetched
                    .into_iter()
                    .map(|(_, kind)| kind)
                    .take(bounded_count(data, round.wrapping_add(9), 16))
                    .collect::<Vec<_>>();

                let batch = TransactionBatch { transactions };
                let _ = mempool.remove_transactions_in_batch(&batch);
            }

            7 => {
                let hash = fuzz_hash(data, round.wrapping_mul(181).wrapping_add(29));
                let _ = mempool.get_transaction(&hash);
            }

            8 => {
                let key = format!("poison_{round}_{}", byte_at(data, round, 0)).into_bytes();
                let mut value = data.to_vec();

                if byte_at(data, round.wrapping_add(1), 0) & 1 == 0 {
                    mutate_bytes(&mut value, data, round.wrapping_add(17));
                } else {
                    value = mutate_length(value, data, round.wrapping_add(29));
                }

                mempool.poison_entry(key, value);

                let _ = mempool.fetch_transactions_for_block();
                let _ = mempool.mempool_size();
            }

            _ => {
                let _ = mempool.mempool_size();
            }
        }
    }

    if !remembered_keys.is_empty() {
        let keep = bounded_count(data, 777, remembered_keys.len().saturating_add(1));
        remembered_keys.truncate(keep);
        mempool.remove_transactions(&remembered_keys);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_mempool(data);
});