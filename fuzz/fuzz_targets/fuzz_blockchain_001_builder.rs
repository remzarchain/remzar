#![no_main]

use fips204::traits::KeyGen;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }
}

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
            pub const BLOCK_OVERHEAD_RESERVE: usize = 16 * 1024;
            pub const MAX_TXS_PER_BLOCK: u64 = 7_500;
            pub const REWARD_DELAY_BLOCKS: usize = 1;
            pub const MAX_BLOCK_REWARD: u64 = 5_000_000_000;
            pub const TRANSACTION_BATCH_COLUMN_NAME: &'static str = "transaction_batch";

            // Required by the real src/utility/time_policy.rs.
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
            pub const MAX_FUTURE_SKEW_SECS: u64 = 2 * 60 * 60;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
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
            DatabaseError {
                details: String,
            },
            CryptographicError {
                message: String,
            },
            TimestampError {
                message: String,
                details: String,
                source: Option<String>,
            },
            NotFound {
                resource: String,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, .. } => write!(f, "{message}"),
                    Self::SerializationError { details } => write!(f, "{details}"),
                    Self::StorageError { message } => write!(f, "{message}"),
                    Self::DatabaseError { details } => write!(f, "{details}"),
                    Self::CryptographicError { message } => write!(f, "{message}"),
                    Self::TimestampError { message, details, .. } => {
                        write!(f, "{message}: {details}")
                    }
                    Self::NotFound { resource } => write!(f, "{resource} not found"),
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    // Required by the real src/blockchain/blockchain_001_builder.rs.
    //
    // The real builder imports:
    // crate::utility::time_policy::TimePolicy
    pub mod time_policy {
        pub use crate::real_time_policy::*;
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;

        pub fn canon_wallet_id_checked(s: &str) -> Result<String, ErrorDetection> {
            let s = s.trim().to_ascii_lowercase();

            if s.len() != REMZAR_WALLET_LEN || !s.starts_with('r') {
                return Err(ErrorDetection::ValidationError {
                    message: "invalid wallet".into(),
                    tx_id: None,
                });
            }

            if !s.as_bytes()[1..]
                .iter()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(ErrorDetection::ValidationError {
                    message: "invalid wallet hex".into(),
                    tx_id: None,
                });
            }

            Ok(s)
        }
    }

    pub mod alpha_003_detection_system {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::collections::HashSet;

        #[derive(Debug, Clone, Default)]
        pub struct DetectionSystem {
            participants: HashSet<String>,
        }

        impl DetectionSystem {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn add_participant(&mut self, wallet: &str) -> Result<(), ErrorDetection> {
                self.participants.insert(wallet.to_string());
                Ok(())
            }

            pub fn update_participant_activity(&self, _wallet: &str) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn detect_double_spend<I>(&self, ids: I) -> Result<(), ErrorDetection>
            where
                I: IntoIterator<Item = String>,
            {
                let mut seen = HashSet::new();

                for id in ids {
                    if !seen.insert(id) {
                        return Err(ErrorDetection::ValidationError {
                            message: "double spend".into(),
                            tx_id: None,
                        });
                    }
                }

                Ok(())
            }

            pub fn detect_replay<I>(&self, pairs: I) -> Result<(), ErrorDetection>
            where
                I: IntoIterator<Item = (String, Vec<u8>)>,
            {
                let mut seen = HashSet::new();

                for (id, _sig) in pairs {
                    if !seen.insert(id) {
                        return Err(ErrorDetection::ValidationError {
                            message: "replay".into(),
                            tx_id: None,
                        });
                    }
                }

                Ok(())
            }

            pub fn check_block_size(&self, size: usize) -> Result<(), ErrorDetection> {
                if size
                    > crate::utility::alpha_001_global_configuration::GlobalConfiguration::MAX_BLOCK_SIZE
                        as usize
                {
                    return Err(ErrorDetection::ValidationError {
                        message: "block too large".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }
        }
    }
}

// Import the real time policy once, then expose it through crate::utility::time_policy.
#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

mod cryptography {
    pub mod ml_dsa_65_004_guardian_signature {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use fips204::ml_dsa_65;

        pub struct GuardianSignature;

        impl GuardianSignature {
            pub fn sign_batch(
                _sk: &ml_dsa_65::PrivateKey,
                slices: &[&[u8]],
            ) -> Result<Vec<u8>, ErrorDetection> {
                let mut sig = vec![0xAB; ml_dsa_65::SIG_LEN];
                let sig_len = sig.len();

                for (i, s) in slices.iter().enumerate() {
                    if !s.is_empty() {
                        let idx = i % sig_len;
                        sig[idx] ^= s[0];
                    }
                }

                Ok(sig)
            }
        }
    }
}

mod consensus {
    pub mod por_000_ephemeral_registration {
        #[derive(Debug, Clone, Default)]
        pub struct RegistryData;
    }

    pub mod por_004_puzzle_proof {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct PorPuzzleProof {
            pub height: u64,
            pub validator: String,
            #[serde(with = "serde_big_array::BigArray")]
            pub prev_block_hash: [u8; 64],
            pub output: u128,
        }
    }

    pub mod por_005_time_management {
        #[derive(Debug, Clone, Default)]
        pub struct TimeManager;
    }
}

mod storage {
    pub mod rocksdb_005_manager {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::collections::BTreeMap;
        use std::sync::Mutex;

        #[derive(Debug)]
        pub struct RockDBManager {
            tip_height: Mutex<u64>,
            latest_hash: Mutex<[u8; 64]>,
            blocks_by_index: Mutex<BTreeMap<u64, Vec<u8>>>,
            blocks_by_hash: Mutex<BTreeMap<[u8; 64], Vec<u8>>>,
            writes: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
            advance_tip_on_hash_check: Mutex<bool>,
            change_hash_on_hash_check: Mutex<bool>,
        }

        impl RockDBManager {
            pub fn new_for_fuzz(
                tip_height: u64,
                latest_hash: [u8; 64],
                advance_tip_on_hash_check: bool,
                change_hash_on_hash_check: bool,
            ) -> Self {
                Self {
                    tip_height: Mutex::new(tip_height),
                    latest_hash: Mutex::new(latest_hash),
                    blocks_by_index: Mutex::new(BTreeMap::new()),
                    blocks_by_hash: Mutex::new(BTreeMap::new()),
                    writes: Mutex::new(BTreeMap::new()),
                    advance_tip_on_hash_check: Mutex::new(advance_tip_on_hash_check),
                    change_hash_on_hash_check: Mutex::new(change_hash_on_hash_check),
                }
            }

            pub fn get_tip_height(&self) -> Result<u64, ErrorDetection> {
                Ok(*self.tip_height.lock().unwrap())
            }

            pub fn get_latest_block_hash(&self) -> Result<[u8; 64], ErrorDetection> {
                let mut flip_tip = self.advance_tip_on_hash_check.lock().unwrap();

                if *flip_tip {
                    *flip_tip = false;
                    *self.tip_height.lock().unwrap() += 1;
                }

                let mut flip_hash = self.change_hash_on_hash_check.lock().unwrap();

                if *flip_hash {
                    *flip_hash = false;
                    let mut h = self.latest_hash.lock().unwrap();
                    h[0] ^= 0x55;
                }

                Ok(*self.latest_hash.lock().unwrap())
            }

            pub fn get_block_bytes_by_index(
                &self,
                index: u64,
            ) -> Result<Option<Vec<u8>>, ErrorDetection> {
                Ok(self.blocks_by_index.lock().unwrap().get(&index).cloned())
            }

            pub fn get_block_by_hash(&self, hash: &[u8; 64]) -> Option<Vec<u8>> {
                self.blocks_by_hash.lock().unwrap().get(hash).cloned()
            }

            pub fn store_latest_block(
                &self,
                block_bytes: &[u8],
                index: u64,
            ) -> Result<(), ErrorDetection> {
                self.blocks_by_index
                    .lock()
                    .unwrap()
                    .insert(index, block_bytes.to_vec());

                Ok(())
            }

            pub fn index_block_by_hash(
                &self,
                block_hash: &[u8; 64],
                block_bytes: &[u8],
            ) -> Result<(), ErrorDetection> {
                self.blocks_by_hash
                    .lock()
                    .unwrap()
                    .insert(*block_hash, block_bytes.to_vec());

                Ok(())
            }

            pub fn write(&self, _cf: &str, key: &[u8], value: &[u8]) -> Result<(), ErrorDetection> {
                self.writes
                    .lock()
                    .unwrap()
                    .insert(key.to_vec(), value.to_vec());

                Ok(())
            }

            pub fn set_latest_block_index(&self, height: u64) -> Result<(), ErrorDetection> {
                *self.tip_height.lock().unwrap() = height;
                Ok(())
            }

            pub fn set_tip_height(&self, height: u64) -> Result<(), ErrorDetection> {
                *self.tip_height.lock().unwrap() = height;
                Ok(())
            }
        }
    }
}

mod blockchain {
    pub mod transaction_002_tx_register {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{canon_wallet_id_checked, REMZAR_WALLET_LEN};
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct RegisterNodeTx {
            #[serde(with = "serde_big_array::BigArray")]
            pub wallet_address: [u8; REMZAR_WALLET_LEN],
            pub timestamp: u64,
        }

        impl RegisterNodeTx {
            pub fn new(wallet: String) -> Result<Self, ErrorDetection> {
                let wallet = canon_wallet_id_checked(&wallet)?;

                let mut arr = [0u8; REMZAR_WALLET_LEN];
                arr.copy_from_slice(wallet.as_bytes());

                Ok(Self {
                    wallet_address: arr,
                    timestamp: 946_684_800,
                })
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                let s = std::str::from_utf8(&self.wallet_address).map_err(|_| {
                    ErrorDetection::ValidationError {
                        message: "register wallet utf8".into(),
                        tx_id: None,
                    }
                })?;

                canon_wallet_id_checked(s)?;
                Ok(())
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }
        }
    }

    pub mod transaction_003_tx_reward {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{canon_wallet_id_checked, REMZAR_WALLET_LEN};
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

                if amount == 0
                    || amount > GlobalConfiguration::MAX_BLOCK_REWARD
                    || block_height == 0
                {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid reward".into(),
                        tx_id: None,
                    });
                }

                let mut arr = [0u8; REMZAR_WALLET_LEN];
                arr.copy_from_slice(receiver.as_bytes());

                Ok(Self {
                    receiver: arr,
                    amount,
                    block_height,
                    timestamp: 946_684_800,
                })
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                if self.amount == 0 || self.block_height == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid reward".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }
        }
    }

    pub mod transaction_004_tx_kind {
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::blockchain::transaction_003_tx_reward::RewardTx;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct FuzzTransferTx {
            pub id_bytes: Vec<u8>,
            pub amount: u64,
        }

        impl FuzzTransferTx {
            pub fn id(&self) -> Result<String, ErrorDetection> {
                Ok(hex::encode(&self.id_bytes))
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub enum TxKind {
            Transfer(FuzzTransferTx),
            RegisterNode(RegisterNodeTx),
            Reward(RewardTx),
        }

        impl TxKind {
            pub fn validate(&self) -> Result<(), ErrorDetection> {
                match self {
                    Self::Transfer(tx) => {
                        if tx.amount == 0 {
                            return Err(ErrorDetection::ValidationError {
                                message: "zero transfer".into(),
                                tx_id: None,
                            });
                        }

                        Ok(())
                    }
                    Self::RegisterNode(tx) => tx.validate(),
                    Self::Reward(tx) => tx.validate(),
                }
            }
        }
    }

    pub mod transaction_005_tx_batch {
        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct TransactionBatch {
            pub index: u64,
            pub timestamp: u64,
            pub transactions: Vec<TxKind>,
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
                })
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }
        }
    }

    pub mod block_003_puzzleproof {
        use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct BlockPuzzleProof {
            pub height: u64,
            pub validator: String,
            #[serde(with = "serde_big_array::BigArray")]
            pub prev_block_hash: [u8; 64],
            pub output: u128,
        }

        impl BlockPuzzleProof {
            pub fn from_gossip(proof: &PorPuzzleProof) -> Result<Self, ErrorDetection> {
                let out = Self {
                    height: proof.height,
                    validator: canon_wallet_id_checked(&proof.validator)?,
                    prev_block_hash: proof.prev_block_hash,
                    output: proof.output,
                };

                out.validate_structural()?;
                Ok(out)
            }

            pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
                canon_wallet_id_checked(&self.validator)?;

                if self.output == 0 || self.prev_block_hash == [0u8; 64] {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid block puzzle proof".into(),
                        tx_id: None,
                    });
                }

                Ok(())
            }
        }
    }

    pub mod block_001_metadata {
        use crate::blockchain::block_003_puzzleproof::BlockPuzzleProof;
        use fips204::ml_dsa_65;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct BlockMetadata {
            pub index: u64,
            pub timestamp: u64,
            #[serde(with = "serde_big_array::BigArray")]
            pub previous_hash: [u8; 64],
            #[serde(with = "serde_big_array::BigArray")]
            pub merkle_root: [u8; 64],
            pub guardian_signature: Vec<u8>,
            pub puzzle_proof: Option<BlockPuzzleProof>,
            pub size: u64,
        }

        impl BlockMetadata {
            pub fn new(index: u64, timestamp: u64, previous_hash: [u8; 64]) -> Self {
                let mut merkle = [0x22u8; 64];
                merkle[0] ^= index as u8;

                Self {
                    index,
                    timestamp,
                    previous_hash,
                    merkle_root: merkle,
                    guardian_signature: vec![0u8; ml_dsa_65::SIG_LEN],
                    puzzle_proof: None,
                    size: 1024,
                }
            }

            pub fn set_puzzle_proof(&mut self, proof: Option<BlockPuzzleProof>) {
                self.puzzle_proof = proof;
            }

            pub fn set_guardian_signature(&mut self, sig: [u8; ml_dsa_65::SIG_LEN]) {
                self.guardian_signature = sig.to_vec();
            }
        }
    }

    pub mod block_002_blocks {
        use crate::blockchain::block_001_metadata::BlockMetadata;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct Block {
            pub metadata: BlockMetadata,
            pub batch_key: Option<String>,
            pub miner: String,
            #[serde(with = "serde_big_array::BigArray")]
            pub block_hash: [u8; 64],
            pub reward: u64,
        }

        impl Block {
            pub fn new(
                metadata: BlockMetadata,
                batch_key: Option<String>,
                miner: String,
                reward: u64,
            ) -> Result<Self, ErrorDetection> {
                let miner = canon_wallet_id_checked(&miner)?;

                let mut block_hash = [0u8; 64];
                block_hash[..8].copy_from_slice(&metadata.index.to_be_bytes());
                block_hash[8] = miner.as_bytes()[1];

                Ok(Self {
                    metadata,
                    batch_key,
                    miner,
                    block_hash,
                    reward,
                })
            }

            pub fn serialize_for_storage(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }
        }
    }

    pub mod validatorstate {
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::collections::BTreeSet;

        #[derive(Debug, Clone, Default)]
        pub struct ValidatorState {
            known: BTreeSet<String>,
        }

        impl ValidatorState {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn seed(&mut self, wallet: &str) {
                if let Ok(w) = canon_wallet_id_checked(wallet) {
                    self.known.insert(w);
                }
            }

            pub fn is_canonically_known(&self, wallet: &str) -> Result<bool, ErrorDetection> {
                let wallet = canon_wallet_id_checked(wallet)?;
                Ok(self.known.contains(&wallet))
            }

            pub fn apply_register_tx(&mut self, tx: &RegisterNodeTx) {
                if let Ok(s) = std::str::from_utf8(&tx.wallet_address) {
                    if let Ok(w) = canon_wallet_id_checked(s) {
                        self.known.insert(w);
                    }
                }
            }
        }
    }

    pub mod halving_schedule {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;

        pub struct RewardHalving;

        impl RewardHalving {
            pub fn get_block_reward(height: u64) -> u64 {
                if height == 0 {
                    0
                } else {
                    GlobalConfiguration::MAX_BLOCK_REWARD
                }
            }
        }
    }

    pub mod validation {
        use crate::blockchain::block_001_metadata::BlockMetadata;
        use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::alpha_003_detection_system::DetectionSystem;
        use fips204::ml_dsa_65;

        pub struct BlockchainValidation;

        impl BlockchainValidation {
            pub fn validate_transaction_batch(
                batch: &mut TransactionBatch,
                _sk: &ml_dsa_65::PrivateKey,
                prev_hash: [u8; 64],
                _detection: &DetectionSystem,
            ) -> Result<BlockMetadata, ErrorDetection> {
                for tx in &batch.transactions {
                    tx.validate()?;
                }

                Ok(BlockMetadata::new(batch.index, batch.timestamp, prev_hash))
            }
        }
    }

    pub mod mempool {
        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Mutex;

        #[derive(Debug)]
        pub struct MemPool {
            entries: Mutex<Vec<(Vec<u8>, TxKind)>>,
            removed: Mutex<Vec<Vec<u8>>>,
        }

        impl MemPool {
            pub fn new_for_fuzz(entries: Vec<(Vec<u8>, TxKind)>) -> Self {
                Self {
                    entries: Mutex::new(entries),
                    removed: Mutex::new(Vec::new()),
                }
            }

            pub fn fetch_transactions_for_block(
                &self,
            ) -> Result<Vec<(Vec<u8>, TxKind)>, ErrorDetection> {
                Ok(self.entries.lock().unwrap().clone())
            }

            pub fn remove_transactions(&self, keys: &[Vec<u8>]) -> Result<(), ErrorDetection> {
                self.removed.lock().unwrap().extend_from_slice(keys);
                Ok(())
            }

            pub fn removed_len(&self) -> usize {
                self.removed.lock().unwrap().len()
            }
        }
    }

    pub mod blockchain_000_consensus {
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::blockchain::validatorstate::ValidatorState;
        use crate::consensus::por_000_ephemeral_registration::RegistryData;
        use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
        use crate::consensus::por_005_time_management::TimeManager;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::sync::Arc;

        #[derive(Debug, Clone)]
        pub struct BlockchainConsensus {
            local_wallet: String,
            validator_state: ValidatorState,
            pending: Option<PorPuzzleProof>,
            register_on_collect: Option<String>,
            fail_gate: bool,
            _db: Arc<RockDBManager>,
            _tm: Arc<TimeManager>,
        }

        impl BlockchainConsensus {
            pub fn new(
                db: Arc<RockDBManager>,
                local_wallet: String,
                tm: Arc<TimeManager>,
            ) -> Result<Self, ErrorDetection> {
                let local_wallet = canon_wallet_id_checked(&local_wallet)?;

                let mut validator_state = ValidatorState::new();
                validator_state.seed(&local_wallet);

                Ok(Self {
                    local_wallet,
                    validator_state,
                    pending: None,
                    register_on_collect: None,
                    fail_gate: false,
                    _db: db,
                    _tm: tm,
                })
            }

            pub fn local_wallet(&self) -> &String {
                &self.local_wallet
            }

            pub fn validator_state(&self) -> &ValidatorState {
                &self.validator_state
            }

            pub fn validator_state_mut(&mut self) -> &mut ValidatorState {
                &mut self.validator_state
            }

            pub fn set_registry(&mut self, _reg: RegistryData) {}

            pub fn pending_puzzle_proof(&self) -> Option<&PorPuzzleProof> {
                self.pending.as_ref()
            }

            pub fn take_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> {
                self.pending.take()
            }

            pub fn on_puzzle_proof(&mut self, proof: &PorPuzzleProof) -> bool {
                self.pending = Some(proof.clone());
                true
            }

            pub fn assert_can_build_block(
                &mut self,
                height: u64,
                prev_hash: [u8; 64],
                bypass_leader: bool,
            ) -> Result<(), ErrorDetection> {
                if self.fail_gate && !bypass_leader {
                    return Err(ErrorDetection::ValidationError {
                        message: "consensus gate closed".into(),
                        tx_id: None,
                    });
                }

                self.pending = Some(PorPuzzleProof {
                    height,
                    validator: self.local_wallet.clone(),
                    prev_block_hash: prev_hash,
                    output: 123,
                });

                Ok(())
            }

            pub fn reward_eligible_at(&self, wallet: &str, _height: u64) -> bool {
                self.validator_state
                    .is_canonically_known(wallet)
                    .unwrap_or(false)
            }

            pub fn collect_register_node_txs_for_block(&self, _height: u64) -> Vec<RegisterNodeTx> {
                self.register_on_collect
                    .as_ref()
                    .and_then(|w| RegisterNodeTx::new(w.clone()).ok())
                    .into_iter()
                    .collect()
            }

            pub fn gc_puzzle_pool_below(&mut self, _height: u64) {}

            pub fn fuzz_set_register_on_collect(&mut self, wallet: Option<String>) {
                self.register_on_collect = wallet;
            }

            pub fn fuzz_set_fail_gate(&mut self, fail: bool) {
                self.fail_gate = fail;
            }

            pub fn fuzz_set_pending(&mut self, proof: Option<PorPuzzleProof>) {
                self.pending = proof;
            }
        }
    }
}

#[path = "../../src/blockchain/blockchain_001_builder.rs"]
mod blockchain_001_builder;

use blockchain::mempool::MemPool;
use blockchain::transaction_004_tx_kind::{FuzzTransferTx, TxKind};
use blockchain_001_builder::BlockchainBuilder;
use consensus::por_004_puzzle_proof::PorPuzzleProof;
use consensus::por_005_time_management::TimeManager;
use fips204::ml_dsa_65;
use storage::rocksdb_005_manager::RockDBManager;
use utility::helper::canon_wallet_id_checked;

fn byte_at(data: &[u8], idx: usize) -> u8 {
    if data.is_empty() {
        idx as u8
    } else {
        data[idx % data.len()]
    }
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];

    for i in 0..8 {
        b[i] = byte_at(data, off + i);
    }

    u64::from_le_bytes(b)
}

fn hash64(data: &[u8], salt: usize) -> [u8; 64] {
    let mut h = [0u8; 64];

    for i in 0..64 {
        h[i] = byte_at(data, salt + i)
            .wrapping_add(i as u8)
            .wrapping_add(1);
    }

    if h == [0u8; 64] {
        h[0] = 1;
    }

    h
}

fn wallet(data: &[u8], salt: usize) -> String {
    format!("r{}", hex::encode(hash64(data, salt)))
}

fn bad_or_good_wallet(data: &[u8], salt: usize) -> String {
    match byte_at(data, salt) % 5 {
        0 => String::new(),
        1 => "r1234".to_string(),
        2 => format!("x{}", hex::encode(hash64(data, salt + 1))),
        _ => wallet(data, salt + 2),
    }
}

fn make_entries(data: &[u8]) -> Vec<(Vec<u8>, TxKind)> {
    let count = usize::from(byte_at(data, 5) % 32);
    let duplicate = byte_at(data, 6) & 1 == 1;

    let mut entries = Vec::new();

    for i in 0..count {
        let key = vec![i as u8, byte_at(data, 20 + i)];
        let id_seed = if duplicate && i > 0 { 0 } else { i };

        let mut id = vec![
            id_seed as u8;
            usize::from(byte_at(data, 50 + i) % 16).saturating_add(1)
        ];
        id.push(byte_at(data, 80 + i));

        let amount = (read_u64(data, 100 + i) % 1_000_000).saturating_add(1);

        entries.push((
            key,
            TxKind::Transfer(FuzzTransferTx {
                id_bytes: id,
                amount,
            }),
        ));
    }

    entries
}

fn make_signing_key(data: &[u8]) -> ml_dsa_65::PrivateKey {
    let mut seed = [0u8; 32];

    for i in 0..32 {
        seed[i] = byte_at(data, 1200 + i);
    }

    let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    sk
}

fn touch_result<T>(r: Result<T, utility::alpha_002_error_detection_system::ErrorDetection>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            let _ = e.to_string();
            None
        }
    }
}

fn exercise_builder(data: &[u8]) {
    let local_wallet = wallet(data, 200);
    let latest_hash = hash64(data, 300);
    let tip = read_u64(data, 400) % 32;

    let advance_tip_on_hash_check = byte_at(data, 10) % 16 == 0;
    let change_hash_on_hash_check = byte_at(data, 11) % 16 == 0;

    let db = Arc::new(RockDBManager::new_for_fuzz(
        tip,
        latest_hash,
        advance_tip_on_hash_check,
        change_hash_on_hash_check,
    ));
    let mempool = Arc::new(MemPool::new_for_fuzz(make_entries(data)));
    let tm = Arc::new(TimeManager::default());
    let sk = Arc::new(make_signing_key(data));

    let mut builder =
        match BlockchainBuilder::new(db.clone(), mempool.clone(), local_wallet.clone(), tm, sk) {
            Ok(b) => b,
            Err(_) => return,
        };

    builder.heartbeat();

    let is_synced = byte_at(data, 13) % 4 != 0;
    let bypass_leader = byte_at(data, 14) % 2 == 0;

    if byte_at(data, 15) % 5 == 0 {
        builder.consensus_mut().fuzz_set_fail_gate(true);
    }

    if byte_at(data, 16) % 4 == 0 {
        let reg_wallet = if byte_at(data, 17) % 2 == 0 {
            local_wallet.clone()
        } else {
            wallet(data, 500)
        };

        builder
            .consensus_mut()
            .fuzz_set_register_on_collect(Some(reg_wallet));
    }

    if byte_at(data, 18) % 4 == 0 {
        let proof = PorPuzzleProof {
            height: tip.saturating_add(1),
            validator: if byte_at(data, 19) % 2 == 0 {
                local_wallet.clone()
            } else {
                bad_or_good_wallet(data, 600)
            },
            prev_block_hash: latest_hash,
            output: u128::from(read_u64(data, 700)).saturating_add(1),
        };

        let _ = builder.on_puzzle_proof(&proof);
    }

    let result = builder.create_new_block_with_bypass(is_synced, bypass_leader);

    if !is_synced {
        assert!(result.is_err(), "builder must reject minting before sync");
        return;
    }

    if let Some(block) = touch_result(result) {
        assert_eq!(block.metadata.index, tip.saturating_add(1));
        if !change_hash_on_hash_check {
            assert_eq!(block.metadata.previous_hash, latest_hash);
        }
        assert_eq!(block.miner, local_wallet);
        assert!(block.batch_key.is_some());

        if let Some(proof) = block.metadata.puzzle_proof {
            assert_eq!(proof.height, block.metadata.index);
            assert_eq!(proof.prev_block_hash, block.metadata.previous_hash);
            assert!(proof.validator.eq_ignore_ascii_case(&local_wallet));
            assert_ne!(proof.output, 0);
        }

        assert!(
            mempool.removed_len() <= 32,
            "builder must only remove fetched bounded mempool txs"
        );
    }
}

fn exercise_constructor_edges(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz(
        0,
        hash64(data, 900),
        false,
        false,
    ));
    let mempool = Arc::new(MemPool::new_for_fuzz(Vec::new()));
    let tm = Arc::new(TimeManager::default());
    let sk = Arc::new(make_signing_key(data));

    let maybe_bad = bad_or_good_wallet(data, 950);
    let result = BlockchainBuilder::new(db, mempool, maybe_bad.clone(), tm, sk);

    if canon_wallet_id_checked(&maybe_bad).is_err() {
        assert!(result.is_err(), "invalid local wallet must not construct builder");
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_constructor_edges(data);
    exercise_builder(data);
});