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
            pub const ACCOUNT_COLUMN_NAME: &'static str = "wallet_accounts";

            pub const MAX_TX_AMOUNT: u64 = 10_000_000_000_000_000;
            pub const MAX_BLOCK_REWARD: u64 = 20 * UNIT_DIVISOR;
            pub const MAX_REWARD_SUPPLY: u64 = 200_000_000 * UNIT_DIVISOR;
            pub const MAX_SUPPLY: u64 = Self::MAX_REWARD_SUPPLY;

            pub const MAX_TXS_PER_BLOCK: u64 = 7_500;
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
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
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

mod storage {
    pub mod rocksdb_005_manager {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, Default)]
        pub struct RockDBManager {
            kv: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
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
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Minimal NFT payloads used by TxKind.
// ─────────────────────────────────────────────────────────────

mod tokens {
    pub mod nft_001 {
        use serde::{Deserialize, Serialize};

        use crate::network::p2p_006_reqresp::Hash;

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
    }
}

// ─────────────────────────────────────────────────────────────
// Blockchain shims plus the REAL account guard file.
// ─────────────────────────────────────────────────────────────

mod blockchain {
    pub mod block_001_metadata {
        use serde::{Deserialize, Serialize};

        use crate::network::p2p_006_reqresp::Hash;

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct BlockMetadata {
            pub index: u64,

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub previous_hash: Hash,
        }
    }

    pub mod block_002_blocks {
        use serde::{Deserialize, Serialize};

        use crate::blockchain::block_001_metadata::BlockMetadata;
        use crate::network::p2p_006_reqresp::Hash;

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct Block {
            pub metadata: BlockMetadata,

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub block_hash: Hash,
        }

        impl Block {
            pub fn new_for_fuzz(index: u64, previous_hash: Hash) -> Self {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"remzar-fuzz-account-guard-block-v1");
                hasher.update(&index.to_le_bytes());
                hasher.update(&previous_hash);

                let mut block_hash = [0u8; 64];
                hasher.finalize_xof().fill(&mut block_hash);

                Self {
                    metadata: BlockMetadata {
                        index,
                        previous_hash,
                    },
                    block_hash,
                }
            }
        }
    }

    pub mod transaction_001_tx {
        use postcard::to_allocvec;
        use serde::{Deserialize, Serialize};

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{
            canon_wallet_id_checked, REMZAR_WALLET_LEN,
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
                let sender = canon_wallet_id_checked(&sender)?;
                let receiver = canon_wallet_id_checked(&receiver)?;

                if sender == receiver {
                    return Err(ErrorDetection::ValidationError {
                        message: "sender and receiver cannot be same".into(),
                        tx_id: None,
                    });
                }

                if amount == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "amount cannot be zero".into(),
                        tx_id: None,
                    });
                }

                let mut sender_arr = [0u8; REMZAR_WALLET_LEN];
                sender_arr.copy_from_slice(sender.as_bytes());

                let mut receiver_arr = [0u8; REMZAR_WALLET_LEN];
                receiver_arr.copy_from_slice(receiver.as_bytes());

                Ok(Self {
                    sender: sender_arr,
                    receiver: receiver_arr,
                    amount,
                    timestamp: 1,
                })
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }

            pub fn id(&self) -> Result<String, ErrorDetection> {
                let bytes = self.serialize()?;

                let mut hasher = blake3::Hasher::new();
                hasher.update(&bytes);

                let mut out = [0u8; 64];
                hasher.finalize_xof().fill(&mut out);

                Ok(hex::encode(out))
            }
        }
    }

    pub mod transaction_002_tx_register {
        use serde::{Deserialize, Serialize};

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{
            canon_wallet_id_checked, REMZAR_WALLET_LEN,
        };

        #[repr(C)]
        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub struct RegisterNodeTx {
            #[serde(with = "serde_big_array::BigArray")]
            pub wallet_address: [u8; REMZAR_WALLET_LEN],
            pub timestamp: u64,
        }

        impl RegisterNodeTx {
            pub fn new(wallet_address: String) -> Result<Self, ErrorDetection> {
                let wallet = canon_wallet_id_checked(&wallet_address)?;

                let mut wallet_address = [0u8; REMZAR_WALLET_LEN];
                wallet_address.copy_from_slice(wallet.as_bytes());

                Ok(Self {
                    wallet_address,
                    timestamp: 1,
                })
            }
        }
    }

    pub mod transaction_003_tx_reward {
        use serde::{Deserialize, Serialize};

        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{
            canon_wallet_id_checked, REMZAR_WALLET_LEN,
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
                let receiver = canon_wallet_id_checked(&receiver)?;

                if amount == 0 || amount > GlobalConfiguration::MAX_BLOCK_REWARD {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid reward amount".into(),
                        tx_id: None,
                    });
                }

                let mut receiver_arr = [0u8; REMZAR_WALLET_LEN];
                receiver_arr.copy_from_slice(receiver.as_bytes());

                Ok(Self {
                    receiver: receiver_arr,
                    amount,
                    block_height,
                    timestamp: 1,
                })
            }
        }
    }

    pub mod transaction_004_tx_kind {
        use serde::{Deserialize, Serialize};

        use crate::blockchain::transaction_001_tx::Transaction;
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::blockchain::transaction_003_tx_reward::RewardTx;
        use crate::tokens::nft_001::{NftMintTx, NftTransferTx};

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub enum TxKind {
            Transfer(Transaction),
            RegisterNode(RegisterNodeTx),
            Reward(RewardTx),
            NftMint(NftMintTx),
            NftTransfer(NftTransferTx),
        }
    }

    pub mod transaction_005_tx_batch {
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
        }
    }

    pub mod transaction_005_tx_account_tree {
        use std::collections::HashMap;

        use serde::{Deserialize, Serialize};

        use crate::blockchain::block_002_blocks::Block;

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub(crate) struct InnerTree {
            pub balances: HashMap<String, u64>,
            pub blocks: Vec<Block>,

            #[serde(default)]
            pub total_issued_micro: u64,

            #[serde(default)]
            pub rewards_issued_micro: u64,

            #[serde(default)]
            pub reserved_issued_micro: u64,
        }

        impl InnerTree {
            pub fn empty() -> Self {
                Self {
                    balances: HashMap::new(),
                    blocks: Vec::new(),
                    total_issued_micro: 0,
                    rewards_issued_micro: 0,
                    reserved_issued_micro: 0,
                }
            }
        }
    }
}

#[path = "../../src/blockchain/transaction_006_tx_account_tree_guards.rs"]
mod transaction_006_tx_account_tree_guards;

use std::collections::BTreeSet;

use blockchain::block_002_blocks::Block;
use blockchain::transaction_001_tx::Transaction;
use blockchain::transaction_002_tx_register::RegisterNodeTx;
use blockchain::transaction_003_tx_reward::RewardTx;
use blockchain::transaction_004_tx_kind::TxKind;
use blockchain::transaction_005_tx_account_tree::InnerTree;
use blockchain::transaction_005_tx_batch::TransactionBatch;
use transaction_006_tx_account_tree_guards::{
    AccountGuard, ApplyContext, ApplyMode, GuardConfig,
};
use storage::rocksdb_005_manager::RockDBManager;
use utility::alpha_001_global_configuration::GlobalConfiguration;

// Keep generated transfers small enough that repeated invariant checks stay fast,
// but always keep the cap within the production transaction maximum.
const MAX_SAFE_TRANSFER: u64 = 1_000_000_000;

#[inline]
fn valid_transfer_amount(raw: u64) -> u64 {
    let max = MAX_SAFE_TRANSFER.min(GlobalConfiguration::MAX_TX_AMOUNT);
    debug_assert!(max > 0);
    (raw % max).saturating_add(1)
}

#[inline]
fn valid_reward_amount(raw: u64) -> u64 {
    let max = GlobalConfiguration::MAX_BLOCK_REWARD;
    debug_assert!(max > 0);
    (raw % max).saturating_add(1)
}

fuzz_target!(|data: &[u8]| {
    // 1) Hostile postcard batch bytes. This is not the main target, but it
    // cheaply explores TxKind/TransactionBatch shapes before guard validation.
    if let Ok((batch, _remaining)) = postcard::take_from_bytes::<TransactionBatch>(data) {
        let guard = AccountGuard::new();
        let _ = guard.validate_batch_structure(&batch);
    }

    let sender = wallet_from_input(0xA1, data);
    let receiver = wallet_from_input(0xB2, data);
    let reward_receiver = wallet_from_input(0xC3, data);
    let register_wallet = wallet_from_input(0xD4, data);

    let transfer_amount = valid_transfer_amount(read_u64(data, 0));
    let reward_amount = valid_reward_amount(read_u64(data, 8));

    fuzz_reward_boundaries(&reward_receiver);

    fuzz_validate_batch_structure(
        data,
        &sender,
        &receiver,
        &reward_receiver,
        &register_wallet,
        transfer_amount,
        reward_amount,
    );

    fuzz_apply_valid_batch(
        data,
        &sender,
        &receiver,
        &reward_receiver,
        transfer_amount,
        reward_amount,
    );

    fuzz_apply_txkind_direct(
        data,
        &sender,
        &receiver,
        &reward_receiver,
        transfer_amount,
        reward_amount,
    );

    fuzz_reward_supply_cap_rejection(&reward_receiver, reward_amount);

    fuzz_state_invariants(data, &sender, &receiver, transfer_amount);
    fuzz_fingerprint(data, &sender, &receiver, transfer_amount);
    fuzz_idempotency_and_dry_run(data, &sender, &receiver, transfer_amount);
    fuzz_account_cf_check(data, &sender, transfer_amount);
});

fn fuzz_reward_boundaries(reward_receiver: &str) {
    let max_reward = GlobalConfiguration::MAX_BLOCK_REWARD;
    assert!(max_reward > 0, "MAX_BLOCK_REWARD must be non-zero");

    RewardTx::new(reward_receiver.to_owned(), 1, 1)
        .expect("minimum non-zero reward must construct");

    RewardTx::new(reward_receiver.to_owned(), max_reward, 1)
        .expect("MAX_BLOCK_REWARD reward must construct");

    assert!(
        RewardTx::new(reward_receiver.to_owned(), 0, 1).is_err(),
        "zero reward amount was accepted"
    );

    if let Some(over_max) = max_reward.checked_add(1) {
        assert!(
            RewardTx::new(reward_receiver.to_owned(), over_max, 1).is_err(),
            "reward above MAX_BLOCK_REWARD was accepted"
        );
    }
}

fn fuzz_validate_batch_structure(
    data: &[u8],
    sender: &str,
    receiver: &str,
    reward_receiver: &str,
    register_wallet: &str,
    transfer_amount: u64,
    reward_amount: u64,
) {
    let guard = AccountGuard::new();

    let transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("valid transfer must construct");

    let reward = RewardTx::new(reward_receiver.to_owned(), reward_amount, 1)
        .expect("valid reward must construct");

    let register = RegisterNodeTx::new(register_wallet.to_owned())
        .expect("valid register-node tx must construct");

    let good_batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![
            TxKind::Transfer(transfer.clone()),
            TxKind::RegisterNode(register),
            TxKind::Reward(reward.clone()),
        ],
    )
    .expect("good batch must construct");

    guard
        .validate_batch_structure(&good_batch)
        .expect("valid batch structure should pass");

    let duplicate_transfer = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![
            TxKind::Transfer(transfer.clone()),
            TxKind::Transfer(transfer),
        ],
    )
    .expect("duplicate-transfer batch must construct");

    assert!(
        guard.validate_batch_structure(&duplicate_transfer).is_err(),
        "duplicate transfer IDs were accepted"
    );

    let two_rewards = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![
            TxKind::Reward(reward.clone()),
            TxKind::Reward(reward),
        ],
    )
    .expect("two-reward batch must construct");

    assert!(
        guard.validate_batch_structure(&two_rewards).is_err(),
        "batch with two rewards was accepted"
    );

    let max_reward = RewardTx::new(
        reward_receiver.to_owned(),
        GlobalConfiguration::MAX_BLOCK_REWARD,
        1,
    )
    .expect("MAX_BLOCK_REWARD reward must construct");

    let max_reward_batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![TxKind::Reward(max_reward.clone())],
    )
    .expect("max-reward batch must construct");

    guard
        .validate_batch_structure(&max_reward_batch)
        .expect("MAX_BLOCK_REWARD batch should pass");

    let mut zero_reward = max_reward.clone();
    zero_reward.amount = 0;

    let zero_reward_batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![TxKind::Reward(zero_reward)],
    )
    .expect("zero-reward batch must construct");

    assert!(
        guard.validate_batch_structure(&zero_reward_batch).is_err(),
        "zero reward amount was accepted by batch structure validation"
    );

    if let Some(over_max_reward_amount) = GlobalConfiguration::MAX_BLOCK_REWARD.checked_add(1) {
        let mut over_max_reward = max_reward;
        over_max_reward.amount = over_max_reward_amount;

        let over_max_reward_batch = TransactionBatch::new(
            0,
            current_unix_secs(),
            vec![TxKind::Reward(over_max_reward)],
        )
        .expect("over-max-reward batch must construct");

        assert!(
            guard.validate_batch_structure(&over_max_reward_batch).is_err(),
            "reward above MAX_BLOCK_REWARD was accepted by batch structure validation"
        );
    }

    let mut zero_amount = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("valid transfer must construct");

    zero_amount.amount = 0;

    let zero_batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![TxKind::Transfer(zero_amount)],
    )
    .expect("zero transfer batch must construct");

    assert!(
        guard.validate_batch_structure(&zero_batch).is_err(),
        "zero-amount transfer was accepted"
    );

    let mut too_large = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("valid transfer must construct");

    too_large.amount = GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(1);

    let too_large_batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![TxKind::Transfer(too_large)],
    )
    .expect("too-large transfer batch must construct");

    assert!(
        guard.validate_batch_structure(&too_large_batch).is_err(),
        "transfer over MAX_TX_AMOUNT was accepted"
    );

    // Arbitrary small constructed batches should not panic.
    let selector = data.get(16).copied().unwrap_or(0);

    let arbitrary_batch = if selector & 1 == 0 {
        TransactionBatch::new(0, current_unix_secs(), Vec::new())
            .expect("empty batch must construct")
    } else {
        TransactionBatch::new(
            0,
            current_unix_secs(),
            vec![TxKind::Reward(
                RewardTx::new(reward_receiver.to_owned(), 1, 1)
                    .expect("small reward must construct"),
            )],
        )
        .expect("small reward batch must construct")
    };

    let _ = guard.validate_batch_structure(&arbitrary_batch);
}

fn fuzz_apply_valid_batch(
    data: &[u8],
    sender: &str,
    receiver: &str,
    reward_receiver: &str,
    transfer_amount: u64,
    reward_amount: u64,
) {
    let guard = AccountGuard::new();

    let genesis = Block::new_for_fuzz(0, [0u8; 64]);
    let block_hash = genesis.block_hash;

    let mut state = InnerTree::empty();
    state.blocks.push(genesis);
    state.balances.insert(sender.to_string(), transfer_amount * 2);
    state.total_issued_micro = transfer_amount * 2;
    state.rewards_issued_micro = transfer_amount * 2;

    let transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("valid transfer must construct");

    let reward = RewardTx::new(reward_receiver.to_owned(), reward_amount, 1)
        .expect("valid reward must construct");

    let batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![TxKind::Transfer(transfer), TxKind::Reward(reward)],
    )
    .expect("valid batch must construct");

    let ctx = ApplyContext {
        mode: if data.get(17).copied().unwrap_or(0) & 1 == 0 {
            ApplyMode::Live
        } else {
            ApplyMode::Replay
        },
        block_height: 0,
        block_hash,
        previous_hash: [0u8; 64],
        allow_duplicate_reward_in_batch: false,
    };

    let outcome = guard
        .apply_batch_to_state(&mut state, &batch, &ctx)
        .expect("funded transfer + reward batch should apply");

    assert!(outcome.touched_accounts.contains(sender));
    assert!(outcome.touched_accounts.contains(receiver));
    assert!(outcome.touched_accounts.contains(reward_receiver));
    assert_eq!(outcome.total_supply_micro, state.total_issued_micro);
    assert!(!outcome.fingerprint_hex.is_empty());

    assert_eq!(state.balances.get(sender).copied().unwrap_or(0), transfer_amount);
    assert_eq!(state.balances.get(receiver).copied().unwrap_or(0), transfer_amount);
    assert_eq!(
        state.balances.get(reward_receiver).copied().unwrap_or(0),
        reward_amount
    );

    let wrong_ctx = ApplyContext {
        block_height: 1,
        ..ctx
    };

    let mut wrong_state = state.clone();

    assert!(
        guard
            .apply_batch_to_state(&mut wrong_state, &batch, &wrong_ctx)
            .is_err(),
        "batch index mismatch was accepted"
    );
}

fn fuzz_apply_txkind_direct(
    _data: &[u8],
    sender: &str,
    receiver: &str,
    reward_receiver: &str,
    transfer_amount: u64,
    reward_amount: u64,
) {
    let guard = AccountGuard::new();

    let genesis = Block::new_for_fuzz(0, [0u8; 64]);

    let ctx = ApplyContext {
        mode: ApplyMode::Live,
        block_height: 0,
        block_hash: genesis.block_hash,
        previous_hash: [0u8; 64],
        allow_duplicate_reward_in_batch: false,
    };

    let mut state = InnerTree::empty();
    state.blocks.push(genesis);
    state.balances.insert(sender.to_string(), transfer_amount * 2);
    state.total_issued_micro = transfer_amount * 2;
    state.rewards_issued_micro = transfer_amount * 2;

    let transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("valid transfer must construct");

    let mut touched = BTreeSet::new();

    guard
        .apply_txkind_to_state(&mut state, &TxKind::Transfer(transfer), &ctx, &mut touched)
        .expect("direct transfer apply should work");

    assert!(touched.contains(sender));
    assert!(touched.contains(receiver));

    let reward = RewardTx::new(reward_receiver.to_owned(), reward_amount, 1)
        .expect("valid reward must construct");

    guard
        .apply_txkind_to_state(&mut state, &TxKind::Reward(reward), &ctx, &mut touched)
        .expect("direct reward apply should work");

    assert!(touched.contains(reward_receiver));

    let mut unfunded = InnerTree::empty();
    unfunded.blocks = state.blocks.clone();

    let bad_transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), transfer_amount)
        .expect("valid transfer must construct");

    assert!(
        guard
            .apply_txkind_to_state(
                &mut unfunded,
                &TxKind::Transfer(bad_transfer),
                &ctx,
                &mut BTreeSet::new(),
            )
            .is_err(),
        "direct unfunded transfer was accepted"
    );
}

fn fuzz_reward_supply_cap_rejection(reward_receiver: &str, reward_amount: u64) {
    let guard = AccountGuard::new();
    let genesis = Block::new_for_fuzz(0, [0u8; 64]);

    let ctx = ApplyContext {
        mode: ApplyMode::Live,
        block_height: 0,
        block_hash: genesis.block_hash,
        previous_hash: [0u8; 64],
        allow_duplicate_reward_in_batch: false,
    };

    let mut state = InnerTree::empty();
    state.blocks.push(genesis);

    // Put issuance close enough to MAX_SUPPLY that applying this otherwise-valid
    // reward must be rejected by the mint-cap guard.
    state.total_issued_micro = GlobalConfiguration::MAX_SUPPLY
        .saturating_sub(reward_amount)
        .saturating_add(1);
    state.rewards_issued_micro = state.total_issued_micro;

    let reward = RewardTx::new(reward_receiver.to_owned(), reward_amount, 1)
        .expect("valid cap-test reward must construct");

    assert!(
        guard
            .apply_txkind_to_state(
                &mut state,
                &TxKind::Reward(reward),
                &ctx,
                &mut BTreeSet::new(),
            )
            .is_err(),
        "reward mint above MAX_SUPPLY was accepted"
    );
}

fn fuzz_state_invariants(data: &[u8], sender: &str, receiver: &str, amount: u64) {
    let strict_guard = AccountGuard::new();

    let relaxed_guard = AccountGuard::with_config(GuardConfig {
        enforce_no_burn_supply_equality: false,
    });

    let genesis = Block::new_for_fuzz(0, [0u8; 64]);

    let mut good = InnerTree::empty();
    good.blocks.push(genesis.clone());
    good.balances.insert(sender.to_string(), amount);
    good.balances.insert(receiver.to_string(), amount);
    good.total_issued_micro = amount * 2;
    good.rewards_issued_micro = amount * 2;

    strict_guard
        .verify_state_invariants(&good, Some(0), Some(genesis.block_hash), Some([0u8; 64]))
        .expect("good state invariants should pass");

    let mut supply_mismatch = good.clone();

    supply_mismatch.total_issued_micro = amount;
    supply_mismatch.rewards_issued_micro = 0;

    assert!(
        strict_guard
            .verify_state_invariants(&supply_mismatch, Some(0), Some(genesis.block_hash), None)
            .is_err(),
        "strict guard accepted total_supply != total_issued"
    );

    relaxed_guard
        .verify_state_invariants(&supply_mismatch, Some(0), Some(genesis.block_hash), None)
        .expect("relaxed guard should allow supply mismatch when rewards <= total issued");

    let mut rewards_gt_total = good.clone();
    rewards_gt_total.rewards_issued_micro = rewards_gt_total
        .total_issued_micro
        .saturating_add(1);

    assert!(
        strict_guard
            .verify_state_invariants(&rewards_gt_total, Some(0), Some(genesis.block_hash), None)
            .is_err(),
        "guard accepted rewards_issued > total_issued"
    );

    let mut non_contiguous = good.clone();
    let bad_prev = hash64_from_input(0x99, data);
    non_contiguous
        .blocks
        .push(Block::new_for_fuzz(2, bad_prev));

    assert!(
        strict_guard
            .verify_state_invariants(&non_contiguous, None, None, None)
            .is_err(),
        "guard accepted non-contiguous block indexes"
    );

    let mut bad_prev_hash = good.clone();
    let wrong_prev = hash64_from_input(0x42, data);
    bad_prev_hash
        .blocks
        .push(Block::new_for_fuzz(1, wrong_prev));

    assert!(
        strict_guard
            .verify_state_invariants(&bad_prev_hash, None, None, None)
            .is_err(),
        "guard accepted previous_hash mismatch"
    );
}

fn fuzz_fingerprint(data: &[u8], sender: &str, receiver: &str, amount: u64) {
    let guard = AccountGuard::new();

    let genesis = Block::new_for_fuzz(0, [0u8; 64]);

    let mut state = InnerTree::empty();
    state.blocks.push(genesis);
    state.balances.insert(sender.to_string(), amount);
    state.balances.insert(receiver.to_string(), amount);
    state.total_issued_micro = amount * 2;
    state.rewards_issued_micro = amount * 2;

    let mut touched = BTreeSet::new();
    touched.insert(sender.to_string());
    touched.insert(receiver.to_string());

    let height = read_u64(data, 24) % 1_000;

    let fp1 = guard
        .compute_state_fingerprint(&state, height, &touched)
        .expect("fingerprint should compute");

    let fp2 = guard
        .compute_state_fingerprint(&state, height, &touched)
        .expect("fingerprint should compute deterministically");

    assert_eq!(fp1.hex, fp2.hex);
    assert_eq!(fp1.height, height);
    assert_eq!(fp1.total_supply_micro, amount * 2);
    assert_eq!(fp1.total_issued_micro, amount * 2);
    assert_eq!(fp1.rewards_issued_micro, amount * 2);
    assert_eq!(fp1.touched_accounts.len(), 2);

    assert!(!fp1.hex.is_empty());
}

fn fuzz_idempotency_and_dry_run(data: &[u8], sender: &str, receiver: &str, amount: u64) {
    let guard = AccountGuard::new();

    let genesis = Block::new_for_fuzz(0, [0u8; 64]);

    let mut state = InnerTree::empty();
    state.blocks.push(genesis.clone());
    state.balances.insert(sender.to_string(), amount * 2);
    state.total_issued_micro = amount * 2;
    state.rewards_issued_micro = amount * 2;

    assert!(
        guard
            .check_canonical_idempotency(&state, &genesis)
            .expect("idempotency check should work"),
        "existing identical block should be idempotent"
    );

    let conflicting = Block {
        block_hash: hash64_from_input(0x55, data),
        ..genesis.clone()
    };

    assert!(
        guard
            .check_canonical_idempotency(&state, &conflicting)
            .is_err(),
        "conflicting block at same height was accepted"
    );

    let missing = Block::new_for_fuzz(1, genesis.block_hash);

    assert!(
        !guard
            .check_canonical_idempotency(&state, &missing)
            .expect("missing future block should return false"),
        "missing block was incorrectly treated as idempotent"
    );

    let transfer = Transaction::new(sender.to_owned(), receiver.to_owned(), amount)
        .expect("dry-run transfer must construct");

    let batch = TransactionBatch::new(
        0,
        current_unix_secs(),
        vec![TxKind::Transfer(transfer)],
    )
    .expect("dry-run batch must construct");

    let mut tentative = state.clone();

    let outcome = guard
        .dry_run_block_and_batch(&mut tentative, &genesis, &batch)
        .expect("dry-run funded batch should work");

    assert!(outcome.touched_accounts.contains(sender));
    assert!(outcome.touched_accounts.contains(receiver));
}

fn fuzz_account_cf_check(data: &[u8], sender: &str, amount: u64) {
    let guard = AccountGuard::new();
    let db = RockDBManager::new_fake();

    let mut state = InnerTree::empty();
    state.balances.insert(sender.to_string(), amount);
    state.total_issued_micro = amount;
    state.rewards_issued_micro = amount;

    let mut touched = BTreeSet::new();
    touched.insert(sender.to_string());

    let encoded = postcard::to_allocvec(&amount)
        .expect("balance postcard encode should work");

    db.write(GlobalConfiguration::ACCOUNT_COLUMN_NAME, sender.as_bytes(), &encoded)
        .expect("fake DB write should work");

    guard
        .verify_account_cf_matches_state(&db, &state, &touched)
        .expect("matching account CF should verify");

    let bad_amount = amount.saturating_add(1);
    let bad_encoded = postcard::to_allocvec(&bad_amount)
        .expect("bad balance postcard encode should work");

    let bad_db = RockDBManager::new_fake();

    bad_db
        .write(
            GlobalConfiguration::ACCOUNT_COLUMN_NAME,
            sender.as_bytes(),
            &bad_encoded,
        )
        .expect("fake bad DB write should work");

    assert!(
        guard
            .verify_account_cf_matches_state(&bad_db, &state, &touched)
            .is_err(),
        "mismatched account CF was accepted"
    );

    let missing_db = RockDBManager::new_fake();

    assert!(
        guard
            .verify_account_cf_matches_state(&missing_db, &state, &touched)
            .is_err(),
        "missing account CF was accepted"
    );

    // Arbitrary extra touched account should fail cleanly, never panic.
    let mut extra_touched = touched;
    extra_touched.insert(wallet_from_input(0xEE, data));

    let _ = guard.verify_account_cf_matches_state(&db, &state, &extra_touched);
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-account-guards-wallet-v1");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

fn hash64_from_input(domain: u8, data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-account-guards-hash64-v1");
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