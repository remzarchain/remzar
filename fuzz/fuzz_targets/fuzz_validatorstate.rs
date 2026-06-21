#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const STATE_COLUMN_NAME: &'static str = "state_data";

            pub const VALIDATOR_ACTIVATION_DELAY_BLOCKS: u64 = 2;
            pub const REWARD_DELAY_BLOCKS: usize = 2;
            pub const CANONICAL_LEASE_BLOCKS: u64 = 20;

            // Needed by real time_policy.rs.
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
            pub const MAX_FUTURE_SKEW_SECS: u64 = 2 * 60 * 60;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone)]
        pub enum ErrorDetection {
            TimestampError {
                message: String,
                details: String,
                source: Option<String>,
            },
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
                    ErrorDetection::TimestampError {
                        message,
                        details,
                        source,
                    } => {
                        write!(
                            f,
                            "Timestamp error: {message}, details={details}, source={source:?}"
                        )
                    }
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

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

// ─────────────────────────────────────────────────────────────
// Minimal network hash alias.
// ─────────────────────────────────────────────────────────────

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }
}

// ─────────────────────────────────────────────────────────────
// Minimal blockchain shims needed by ValidatorState.
// ─────────────────────────────────────────────────────────────

mod blockchain {
    pub mod block_001_metadata {
        use serde::{Deserialize, Serialize};

        use crate::network::p2p_006_reqresp::Hash;

        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct BlockMetadata {
            pub index: u64,
            pub timestamp: u64,

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
            pub miner: String,

            #[serde(with = "crate::utility::helper::serde_u8_array_64")]
            pub block_hash: Hash,
        }

        impl Block {
            pub fn new_for_fuzz(index: u64, previous_hash: Hash, miner: String) -> Self {
                let timestamp = current_unix_secs();

                let mut hasher = blake3::Hasher::new();
                hasher.update(b"remzar-fuzz-validatorstate-block-v1");
                hasher.update(&index.to_le_bytes());
                hasher.update(&timestamp.to_le_bytes());
                hasher.update(&previous_hash);
                hasher.update(miner.as_bytes());

                let mut block_hash = [0u8; 64];
                hasher.finalize_xof().fill(&mut block_hash);

                Self {
                    metadata: BlockMetadata {
                        index,
                        timestamp,
                        previous_hash,
                    },
                    miner,
                    block_hash,
                }
            }
        }

        fn current_unix_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(946_684_800)
        }
    }

    pub mod transaction_002_tx_register {
        use serde::{Deserialize, Serialize};

        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::{canon_wallet_id_checked, REMZAR_WALLET_LEN};

        #[repr(C)]
        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub struct RegisterNodeTx {
            #[serde(with = "serde_big_array::BigArray")]
            pub wallet_address: [u8; REMZAR_WALLET_LEN],
            pub timestamp: u64,
        }

        impl RegisterNodeTx {
            pub fn new(wallet_address: String, timestamp: u64) -> Result<Self, ErrorDetection> {
                let wallet = canon_wallet_id_checked(&wallet_address)?;

                let mut wallet_address = [0u8; REMZAR_WALLET_LEN];
                wallet_address.copy_from_slice(wallet.as_bytes());

                Ok(Self {
                    wallet_address,
                    timestamp,
                })
            }

            pub fn wallet_str(&self) -> Result<&str, ErrorDetection> {
                let s = core::str::from_utf8(&self.wallet_address).map_err(|_| {
                    ErrorDetection::ValidationError {
                        message: "RegisterNodeTx wallet bytes are not valid UTF-8".into(),
                        tx_id: None,
                    }
                })?;

                Ok(s.trim_end_matches('\0'))
            }
        }
    }

    pub mod transaction_004_tx_kind {
        use serde::{Deserialize, Serialize};

        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
        pub enum TxKind {
            RegisterNode(RegisterNodeTx),
            Other,
        }
    }

    pub mod transaction_005_tx_batch {
        use postcard::{take_from_bytes, to_allocvec};
        use serde::{Deserialize, Serialize};

        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
        pub struct TransactionBatch {
            pub index: u64,
            pub timestamp: u64,
            pub transactions: Vec<TxKind>,
        }

        impl TransactionBatch {
            pub fn new(index: u64, timestamp: u64, transactions: Vec<TxKind>) -> Self {
                Self {
                    index,
                    timestamp,
                    transactions,
                }
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }

            pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
                let (batch, rest): (Self, &[u8]) =
                    take_from_bytes(bytes).map_err(|e| {
                        ErrorDetection::SerializationError {
                            details: e.to_string(),
                        }
                    })?;

                if !rest.is_empty() {
                    return Err(ErrorDetection::SerializationError {
                        details: "TransactionBatch trailing bytes rejected".into(),
                    });
                }

                Ok(batch)
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
            batches: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
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

            pub fn get_block_by_index(
                &self,
                index: u64,
            ) -> Result<Option<Block>, ErrorDetection> {
                Ok(self
                    .blocks
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake block DB mutex poisoned".into(),
                    })?
                    .get(&index)
                    .cloned())
            }

            pub fn put_block_by_index(
                &self,
                index: u64,
                block: Block,
            ) -> Result<(), ErrorDetection> {
                self.blocks
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake block DB mutex poisoned".into(),
                    })?
                    .insert(index, block);

                Ok(())
            }

            pub fn get_tx_batch_bytes_by_index(
                &self,
                index: u64,
            ) -> Result<Option<Vec<u8>>, ErrorDetection> {
                Ok(self
                    .batches
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake batch DB mutex poisoned".into(),
                    })?
                    .get(&index)
                    .cloned())
            }

            pub fn put_tx_batch_bytes_by_index(
                &self,
                index: u64,
                bytes: Vec<u8>,
            ) -> Result<(), ErrorDetection> {
                self.batches
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake batch DB mutex poisoned".into(),
                    })?
                    .insert(index, bytes);

                Ok(())
            }

            pub fn get_tip_height(&self) -> Result<u64, ErrorDetection> {
                Ok(self
                    .blocks
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "fake block DB mutex poisoned".into(),
                    })?
                    .keys()
                    .copied()
                    .max()
                    .unwrap_or(0))
            }
        }
    }
}

#[path = "../../src/consensus/por_008_validator_lifecycle.rs"]
mod real_por_008_validator_lifecycle;

mod consensus {
    pub mod por_008_validator_lifecycle {
        pub use crate::real_por_008_validator_lifecycle::*;
    }
}

#[path = "../../src/blockchain/validatorstate.rs"]
mod validatorstate;

use blockchain::block_002_blocks::Block;
use blockchain::transaction_002_tx_register::RegisterNodeTx;
use blockchain::transaction_004_tx_kind::TxKind;
use blockchain::transaction_005_tx_batch::TransactionBatch;
use storage::rocksdb_005_manager::RockDBManager;
use utility::alpha_001_global_configuration::GlobalConfiguration;
use validatorstate::ValidatorState;

const VALIDATOR_STATE_KEY: &[u8] = b"validator_state_v1";
const MULTI_VALIDATOR_EVER_SEEN_KEY: &[u8] = b"validator_multi_validator_ever_seen_v1";

fuzz_target!(|data: &[u8]| {
    // 1) Hostile persisted state bytes.
    // Must never panic even if load_state/load_or_new rejects them.
    fuzz_hostile_snapshot(data);

    let db = RockDBManager::new_fake();

    let founder = wallet_from_input(0xA1, data);
    let validator_1 = wallet_from_input(0xB2, data);
    let validator_2 = wallet_from_input(0xC3, data);
    let invalid_wallet = invalid_wallet_from_input(&validator_1, data.first().copied().unwrap_or(0));

    let now = current_unix_secs();

    // 2) Founder seeding, commit/load, canonical membership queries.
    fuzz_founder_and_commit(db.clone(), &founder, now);

    // 3) Register/renew/apply block behavior.
    fuzz_register_and_apply_block(
        db.clone(),
        data,
        &founder,
        &validator_1,
        &validator_2,
        &invalid_wallet,
        now,
    );

    // 4) Canonical replay/rebuild from fake chain data.
    fuzz_rebuild_from_chain(db.clone(), data, &founder, &validator_1, &validator_2, now);

    // 5) Exit/proposable/active/reward-eligible query paths.
    fuzz_queries_and_exit(db, data, &founder, &validator_1, now);
});

fn fuzz_hostile_snapshot(data: &[u8]) {
    let db = RockDBManager::new_fake();

    db.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        VALIDATOR_STATE_KEY,
        data,
    )
    .expect("fake DB write should work");

    let _ = ValidatorState::load_state(db.clone());
    let _ = ValidatorState::load_or_new(db);
}

fn fuzz_founder_and_commit(db: RockDBManager, founder: &str, now: u64) {
    let mut state = ValidatorState::with_manager(db.clone());

    assert!(state.is_empty());
    assert_eq!(state.len(), 0);
    assert!(state.all().is_empty());

    state
        .seed_genesis_founder(founder, now)
        .expect("valid founder seed must work");

    assert_eq!(state.len(), 1);
    assert!(state.is_canonically_known(founder).expect("known query works"));
    assert_eq!(state.join_height(founder), Some(0));
    assert!(state.meta_for(founder).is_some());
    assert!(state.is_active_at(founder, 0));
    assert!(state.reward_eligible_at(founder, 0));

    state.commit().expect("validator state commit must work");

    let loaded = ValidatorState::load_state(db.clone())
        .expect("committed validator state must load");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.join_height(founder), Some(0));

    let loaded_or_new = ValidatorState::load_or_new(db)
        .expect("load_or_new should load committed state");

    assert_eq!(loaded_or_new.len(), 1);
}

fn fuzz_register_and_apply_block(
    db: RockDBManager,
    data: &[u8],
    founder: &str,
    validator_1: &str,
    validator_2: &str,
    invalid_wallet: &str,
    now: u64,
) {
    let mut state = ValidatorState::with_manager(db.clone());

    state
        .seed_genesis_founder(founder, now)
        .expect("founder seed must work");

    let height_1 = (read_u64(data, 0) % 100).saturating_add(1);
    let height_2 = height_1.saturating_add(1);

    let block_1 = Block::new_for_fuzz(
        height_1,
        hash64_from_input(0x31, data),
        founder.to_owned(),
    );

    db.put_block_by_index(height_1, block_1)
        .expect("put containing block for validator_1 register should work");

    let reg_1 = RegisterNodeTx::new(validator_1.to_owned(), now)
        .expect("validator 1 register tx must construct");

    state
        .apply_register_tx(height_1, &reg_1)
        .expect("valid register tx with containing block must apply");

    assert!(state.is_canonically_known(validator_1).unwrap_or(false));
    assert_eq!(state.join_height(validator_1), Some(height_1));

    // Duplicate/same-height register should be a no-change or safe renew, not a crash.
    state
        .apply_register_tx(height_1, &reg_1)
        .expect("duplicate register with containing block should be safe");

    let reg_2 = RegisterNodeTx::new(validator_2.to_owned(), now.saturating_add(1))
        .expect("validator 2 register tx must construct");

    let block_2 = Block::new_for_fuzz(
        height_2,
        hash64_from_input(0x44, data),
        founder.to_owned(),
    );

    let batch = TransactionBatch::new(
        height_2,
        now,
        vec![
            TxKind::Other,
            TxKind::RegisterNode(reg_2.clone()),
            TxKind::Other,
        ],
    );

    state
        .apply_block(&block_2, &batch)
        .expect("block with valid RegisterNodeTx should apply");

    assert!(state.is_canonically_known(validator_2).unwrap_or(false));

    // After more than one validator is seen, the persistent latch should become true.
    assert!(
        state
            .multi_validator_ever_seen()
            .expect("multi-validator latch query should work"),
        "multi-validator latch should be true after adding validators"
    );

    let invalid_height = height_2.saturating_add(1);

    let invalid_block = Block::new_for_fuzz(
        invalid_height,
        hash64_from_input(0x45, data),
        founder.to_owned(),
    );

    db.put_block_by_index(invalid_height, invalid_block)
        .expect("put containing block for invalid register should work");

    let bad_tx = make_register_tx_raw(invalid_wallet.as_bytes(), now);

    assert!(
        state.apply_register_tx(invalid_height, &bad_tx).is_err(),
        "invalid register wallet was accepted"
    );

    // Invalid external query should return false/None-style behavior.
    assert!(!state.is_active_at(invalid_wallet, height_2));
    assert!(!state.reward_eligible_at(invalid_wallet, height_2));
    assert!(state.meta_for(invalid_wallet).is_none());
    assert!(state.join_height(invalid_wallet).is_none());

    // Directly corrupt latch bytes; query must not panic.
    db.write(
        GlobalConfiguration::STATE_COLUMN_NAME,
        MULTI_VALIDATOR_EVER_SEEN_KEY,
        &[data.first().copied().unwrap_or(0)],
    )
    .expect("fake latch write should work");

    let _ = state.multi_validator_ever_seen();
}

fn fuzz_rebuild_from_chain(
    db: RockDBManager,
    data: &[u8],
    founder: &str,
    validator_1: &str,
    validator_2: &str,
    now: u64,
) {
    let genesis = Block::new_for_fuzz(0, [0u8; 64], founder.to_owned());
    db.put_block_by_index(0, genesis.clone())
        .expect("put genesis block should work");

    let block_1 = Block::new_for_fuzz(1, genesis.block_hash, founder.to_owned());
    db.put_block_by_index(1, block_1)
        .expect("put block 1 should work");

    let reg_1 = RegisterNodeTx::new(validator_1.to_owned(), now)
        .expect("validator 1 tx must construct");

    let reg_2 = RegisterNodeTx::new(validator_2.to_owned(), now.saturating_add(1))
        .expect("validator 2 tx must construct");

    let selector = data.get(8).copied().unwrap_or(0);

    let txs = if selector & 1 == 0 {
        vec![TxKind::RegisterNode(reg_1), TxKind::RegisterNode(reg_2)]
    } else {
        vec![TxKind::Other, TxKind::RegisterNode(reg_1)]
    };

    let batch = TransactionBatch::new(1, now, txs);

    let batch_bytes = batch
        .serialize()
        .expect("replay batch serialization should work");

    db.put_tx_batch_bytes_by_index(1, batch_bytes)
        .expect("put batch bytes should work");

    let mut state = ValidatorState::with_manager(db.clone());

    state
        .rebuild_from_chain(Some(1))
        .expect("canonical rebuild from fake chain should work");

    assert!(state.is_canonically_known(founder).unwrap_or(false));
    assert_eq!(state.join_height(founder), Some(0));
    assert!(state.len() >= 2);

    let loaded = ValidatorState::load_or_new(db)
        .expect("load_or_new should work after rebuild");

    assert!(!loaded.is_empty());
}

fn fuzz_queries_and_exit(
    db: RockDBManager,
    data: &[u8],
    founder: &str,
    validator_1: &str,
    now: u64,
) {
    let mut state = ValidatorState::with_manager(db.clone());

    state
        .seed_genesis_founder(founder, now)
        .expect("founder seed should work");

    let join_height = (read_u64(data, 16) % 100).saturating_add(1);

    let join_block = Block::new_for_fuzz(
        join_height,
        hash64_from_input(0x71, data),
        founder.to_owned(),
    );

    db.put_block_by_index(join_height, join_block)
        .expect("put containing block for query/exit register should work");

    let reg_1 = RegisterNodeTx::new(validator_1.to_owned(), now.saturating_add(1))
        .expect("validator tx must construct");

    state
        .apply_register_tx(join_height, &reg_1)
        .expect("validator register with containing block must apply");

    let delay = read_u64(data, 24) % 10;
    let before = join_height.saturating_sub(1);
    let at = join_height;
    let after = join_height.saturating_add(delay).saturating_add(1);

    let _ = state.active_at(before);
    let _ = state.active_at(at);
    let _ = state.active_at(after);

    let proposable = state.proposable_at(after, delay);
    assert!(
        proposable.windows(2).all(|w| w[0] <= w[1]),
        "proposable_at output must be sorted"
    );

    let _ = state.reward_eligible_at(validator_1, before);
    let _ = state.reward_eligible_at(validator_1, after);

    let exit_height = join_height.saturating_add(2);

    state
        .mark_exit(validator_1, exit_height)
        .expect("mark_exit on existing validator should work");

    assert!(!state.is_active_at(validator_1, exit_height));

    // Exiting a missing valid wallet should be a clean no-op, not a crash.
    let missing = wallet_from_input(0xEE, data);

    state
        .mark_exit(&missing, exit_height.saturating_add(1))
        .expect("mark_exit on missing valid wallet should be safe");

    // Invalid wallet should be rejected cleanly.
    assert!(
        state.mark_exit("not-a-wallet", exit_height).is_err(),
        "mark_exit accepted invalid wallet"
    );
}

fn make_register_tx_raw(bytes: &[u8], timestamp: u64) -> RegisterNodeTx {
    let mut wallet_address = [0u8; utility::helper::REMZAR_WALLET_LEN];
    let len = bytes.len().min(wallet_address.len());
    wallet_address[..len].copy_from_slice(&bytes[..len]);

    RegisterNodeTx {
        wallet_address,
        timestamp,
    }
}

fn invalid_wallet_from_input(wallet: &str, selector: u8) -> String {
    match selector % 5 {

        0 => wallet.get(1..).unwrap_or("").to_owned(),

        1 => {
            let mut v = wallet.as_bytes().to_vec();

            if let Some(first) = v.first_mut() {
                *first = b'x';
            }

            String::from_utf8_lossy(&v).into_owned()
        }

        // Invalid: non-hex body inside the first 129 bytes.
        2 => {
            let mut v = wallet.as_bytes().to_vec();

            if v.len() > 1 {
                v[1] = b'g';
            }

            String::from_utf8_lossy(&v).into_owned()
        }

        // Invalid: empty.
        3 => String::new(),

        // Invalid: embedded NUL inside the first 129 bytes.
        _ => {
            let mut v = wallet.as_bytes().to_vec();

            if v.len() > 10 {
                v[10] = 0;
            }

            String::from_utf8_lossy(&v).into_owned()
        }
    }
}

fn mutate_wallet_string(wallet: &str, selector: u8) -> String {
    match selector % 8 {
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
        _ => String::new(),
    }
}

fn wallet_from_input(domain: u8, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-validatorstate-wallet-v1");
    hasher.update(&[domain]);
    hasher.update(data);

    let mut out = [0u8; 64];
    hasher.finalize_xof().fill(&mut out);

    format!("r{}", hex::encode(out))
}

fn hash64_from_input(domain: u8, data: &[u8]) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-fuzz-validatorstate-hash64-v1");
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