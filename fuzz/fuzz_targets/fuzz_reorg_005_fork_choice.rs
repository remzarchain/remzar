#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

mod utility {
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
            BlockchainError {
                details: String,
            },
            NotFound {
                resource: String,
            },
            TimestampError {
                message: String,
                details: String,
                source: Option<String>,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, .. } => write!(f, "{message}"),
                    Self::SerializationError { details } => write!(f, "{details}"),
                    Self::StorageError { message } => write!(f, "{message}"),
                    Self::DatabaseError { details } => write!(f, "{details}"),
                    Self::BlockchainError { details } => write!(f, "{details}"),
                    Self::NotFound { resource } => write!(f, "{resource} not found"),
                    Self::TimestampError { message, details, .. } => {
                        write!(f, "{message}: {details}")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod time_policy {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::time::{SystemTime, UNIX_EPOCH};

        pub struct TimePolicy;

        impl TimePolicy {
            #[inline]
            pub fn now_unix_secs_runtime() -> Result<u64, ErrorDetection> {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .map_err(|e| ErrorDetection::TimestampError {
                        message: "Timestamp error".into(),
                        details: e.to_string(),
                        source: None,
                    })
            }
        }
    }
}

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }
}

mod blockchain {
    pub mod block_002_blocks {
        use crate::network::p2p_006_reqresp::Hash;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use serde::{Deserialize, Serialize};
        use serde_big_array::BigArray;

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct BlockMetadata {
            pub index: u64,
            #[serde(with = "BigArray")]
            pub previous_hash: Hash,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct Block {
            pub metadata: BlockMetadata,
            #[serde(with = "BigArray")]
            pub block_hash: Hash,
        }

        impl Block {
            pub fn new(index: u64, previous_hash: Hash, block_hash: Hash) -> Self {
                Self {
                    metadata: BlockMetadata {
                        index,
                        previous_hash,
                    },
                    block_hash,
                }
            }

            pub fn serialize_for_storage(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: format!("serialize mock block failed: {e}"),
                })
            }

            pub fn deserialize_from_storage(data: &[u8]) -> Result<Self, ErrorDetection> {
                postcard::from_bytes(data).map_err(|e| ErrorDetection::SerializationError {
                    details: format!("deserialize mock block failed: {e}"),
                })
            }
        }
    }
}

mod consensus {
    pub mod por_004_puzzle_proof {
        use crate::network::p2p_006_reqresp::Hash;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct PorPuzzleProof {
            pub height: u64,
            pub validator: String,
            pub prev_block_hash: Hash,
        }
    }
}

mod storage {
    pub mod rocksdb_005_manager {
        use crate::blockchain::block_002_blocks::Block;
        use crate::network::p2p_006_reqresp::Hash;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::collections::BTreeMap;
        use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum ReorgBlockStatus {
            Canonical,
            SideBranch,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct ReorgBlockMeta {
            pub height: u64,
            pub parent_hash: Hash,
            pub cumulative_score: u128,
            pub status: ReorgBlockStatus,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct CanonicalTipView {
            pub tip_hash: Hash,
            pub tip_height: u64,
        }

        #[derive(Debug, Default)]
        struct MockDb {
            blocks_by_hash: BTreeMap<Hash, Block>,
            block_bytes_by_hash: BTreeMap<Hash, Vec<u8>>,
            block_meta_by_hash: BTreeMap<Hash, ReorgBlockMeta>,
            canonical_height_to_hash: BTreeMap<u64, Hash>,
            canonical_tip: Option<CanonicalTipView>,
            legacy_tip_height: u64,
            canonical_blocks_by_height: BTreeMap<u64, Block>,
        }

        #[derive(Debug, Clone, Default)]
        pub struct RockDBManager {
            inner: Arc<RwLock<MockDb>>,
        }

        impl RockDBManager {
            pub fn new_for_fuzz() -> Self {
                Self::default()
            }

            fn read(&self) -> Result<RwLockReadGuard<'_, MockDb>, ErrorDetection> {
                self.inner.read().map_err(|_| ErrorDetection::StorageError {
                    message: "mock reorg db read lock poisoned".into(),
                })
            }

            fn write(&self) -> Result<RwLockWriteGuard<'_, MockDb>, ErrorDetection> {
                self.inner.write().map_err(|_| ErrorDetection::StorageError {
                    message: "mock reorg db write lock poisoned".into(),
                })
            }

            pub fn insert_block_with_meta(
                &self,
                block: Block,
                parent_hash: Hash,
                cumulative_score: u128,
                canonical: bool,
            ) -> Result<(), ErrorDetection> {
                let bytes = block.serialize_for_storage()?;
                let hash = block.block_hash;
                let height = block.metadata.index;
                let status = if canonical {
                    ReorgBlockStatus::Canonical
                } else {
                    ReorgBlockStatus::SideBranch
                };

                let mut db = self.write()?;
                db.block_bytes_by_hash.insert(hash, bytes);
                db.blocks_by_hash.insert(hash, block.clone());
                db.block_meta_by_hash.insert(
                    hash,
                    ReorgBlockMeta {
                        height,
                        parent_hash,
                        cumulative_score,
                        status,
                    },
                );

                if canonical {
                    db.canonical_height_to_hash.insert(height, hash);
                    db.canonical_blocks_by_height.insert(height, block);
                    if db
                        .canonical_tip
                        .map(|tip| height >= tip.tip_height)
                        .unwrap_or(true)
                    {
                        db.canonical_tip = Some(CanonicalTipView {
                            tip_hash: hash,
                            tip_height: height,
                        });
                        db.legacy_tip_height = height;
                    }
                }

                Ok(())
            }

            pub fn remove_block_by_hash(&self, hash: &Hash) -> Result<(), ErrorDetection> {
                let mut db = self.write()?;
                db.blocks_by_hash.remove(hash);
                db.block_bytes_by_hash.remove(hash);
                Ok(())
            }

            pub fn remove_meta_by_hash(&self, hash: &Hash) -> Result<(), ErrorDetection> {
                self.write()?.block_meta_by_hash.remove(hash);
                Ok(())
            }

            pub fn get_block_by_hash(&self, hash: &Hash) -> Option<Block> {
                self.read()
                    .ok()
                    .and_then(|db| db.blocks_by_hash.get(hash).cloned())
            }

            pub fn has_block_by_hash(&self, hash: &Hash) -> bool {
                self.read()
                    .map(|db| db.blocks_by_hash.contains_key(hash))
                    .unwrap_or(false)
            }

            pub fn put_block_bytes_by_hash(
                &self,
                hash: &Hash,
                bytes: &[u8],
            ) -> Result<(), ErrorDetection> {
                let mut db = self.write()?;
                db.block_bytes_by_hash.insert(*hash, bytes.to_vec());
                if let Ok(block) = Block::deserialize_from_storage(bytes) {
                    db.blocks_by_hash.insert(*hash, block);
                }
                Ok(())
            }

            pub fn get_block_meta_by_hash(
                &self,
                hash: &Hash,
            ) -> Result<Option<ReorgBlockMeta>, ErrorDetection> {
                Ok(self.read()?.block_meta_by_hash.get(hash).cloned())
            }

            pub fn has_meta_by_hash(&self, hash: &Hash) -> Result<bool, ErrorDetection> {
                Ok(self.read()?.block_meta_by_hash.contains_key(hash))
            }

            pub fn mark_meta_status(
                &self,
                hash: &Hash,
                status: ReorgBlockStatus,
            ) -> Result<(), ErrorDetection> {
                let mut db = self.write()?;
                if let Some(meta) = db.block_meta_by_hash.get_mut(hash) {
                    meta.status = status;
                }
                Ok(())
            }

            pub fn get_block_by_index(&self, height: u64) -> Result<Option<Block>, ErrorDetection> {
                Ok(self.read()?.canonical_blocks_by_height.get(&height).cloned())
            }

            pub fn store_latest_block(
                &self,
                bytes: &[u8],
                height: u64,
            ) -> Result<(), ErrorDetection> {
                let block = Block::deserialize_from_storage(bytes)?;
                let hash = block.block_hash;
                let mut db = self.write()?;
                db.canonical_blocks_by_height.insert(height, block.clone());
                db.blocks_by_hash.insert(hash, block);
                db.block_bytes_by_hash.insert(hash, bytes.to_vec());
                db.canonical_height_to_hash.insert(height, hash);
                db.legacy_tip_height = db.legacy_tip_height.max(height);
                Ok(())
            }

            pub fn get_tip_height(&self) -> Result<u64, ErrorDetection> {
                Ok(self.read()?.legacy_tip_height)
            }

            pub fn set_canonical_hash_at_height(
                &self,
                height: u64,
                hash: &Hash,
            ) -> Result<(), ErrorDetection> {
                let mut db = self.write()?;
                db.canonical_height_to_hash.insert(height, *hash);
                if let Some(block) = db.blocks_by_hash.get(hash).cloned() {
                    db.canonical_blocks_by_height.insert(height, block);
                }
                Ok(())
            }

            pub fn get_canonical_hash_at_height(
                &self,
                height: u64,
            ) -> Result<Option<Hash>, ErrorDetection> {
                Ok(self.read()?.canonical_height_to_hash.get(&height).copied())
            }

            pub fn delete_canonical_hash_range(
                &self,
                from_height: u64,
                to_height: u64,
            ) -> Result<(), ErrorDetection> {
                if from_height > to_height {
                    return Ok(());
                }

                let mut db = self.write()?;
                for height in from_height..=to_height {
                    db.canonical_height_to_hash.remove(&height);
                    db.canonical_blocks_by_height.remove(&height);
                }
                Ok(())
            }

            pub fn set_canonical_tip(
                &self,
                tip_hash: &Hash,
                tip_height: u64,
            ) -> Result<(), ErrorDetection> {
                let mut db = self.write()?;
                db.canonical_tip = Some(CanonicalTipView {
                    tip_hash: *tip_hash,
                    tip_height,
                });
                db.legacy_tip_height = tip_height;
                Ok(())
            }

            pub fn get_canonical_tip(&self) -> Result<Option<CanonicalTipView>, ErrorDetection> {
                Ok(self.read()?.canonical_tip)
            }

            pub fn get_canonical_tip_hash(&self) -> Result<Option<Hash>, ErrorDetection> {
                Ok(self.read()?.canonical_tip.map(|tip| tip.tip_hash))
            }

            pub fn get_canonical_tip_height(&self) -> Result<Option<u64>, ErrorDetection> {
                Ok(self.read()?.canonical_tip.map(|tip| tip.tip_height))
            }
        }
    }
}

mod reorganization {
    pub mod reorg_001_block_index {
        use crate::blockchain::block_002_blocks::Block;
        use crate::network::p2p_006_reqresp::Hash;
        use crate::storage::rocksdb_005_manager::{
            ReorgBlockMeta, ReorgBlockStatus, RockDBManager,
        };
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Arc;

        #[derive(Clone)]
        pub struct ReorgBlockIndex {
            db: Arc<RockDBManager>,
        }

        impl ReorgBlockIndex {
            pub fn new(db: Arc<RockDBManager>) -> Self {
                Self { db }
            }

            pub fn has_block(&self, hash: &Hash) -> bool {
                self.db.has_block_by_hash(hash)
            }

            pub fn get_block(&self, hash: &Hash) -> Result<Option<Block>, ErrorDetection> {
                Ok(self.db.get_block_by_hash(hash))
            }

            pub fn put_block_bytes(
                &self,
                hash: &Hash,
                bytes: &[u8],
            ) -> Result<(), ErrorDetection> {
                self.db.put_block_bytes_by_hash(hash, bytes)
            }

            pub fn get_meta(&self, hash: &Hash) -> Result<Option<ReorgBlockMeta>, ErrorDetection> {
                self.db.get_block_meta_by_hash(hash)
            }

            pub fn has_meta(&self, hash: &Hash) -> Result<bool, ErrorDetection> {
                self.db.has_meta_by_hash(hash)
            }

            pub fn mark_side_branch(&self, hash: &Hash) -> Result<(), ErrorDetection> {
                self.db.mark_meta_status(hash, ReorgBlockStatus::SideBranch)
            }

            pub fn mark_canonical(&self, hash: &Hash) -> Result<(), ErrorDetection> {
                self.db.mark_meta_status(hash, ReorgBlockStatus::Canonical)
            }
        }
    }

    pub mod reorg_002_chain_view {
        use crate::blockchain::block_002_blocks::Block;
        use crate::network::p2p_006_reqresp::Hash;
        use crate::storage::rocksdb_005_manager::{CanonicalTipView, RockDBManager};
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Arc;

        pub type BlockHash = Hash;

        #[derive(Clone)]
        pub struct ReorgChainView {
            db: Arc<RockDBManager>,
        }

        impl ReorgChainView {
            pub fn new(db: Arc<RockDBManager>) -> Self {
                Self { db }
            }

            pub fn set_hash_at_height(
                &self,
                height: u64,
                hash: &BlockHash,
            ) -> Result<(), ErrorDetection> {
                self.db.set_canonical_hash_at_height(height, hash)
            }

            pub fn get_hash_at_height(
                &self,
                height: u64,
            ) -> Result<Option<BlockHash>, ErrorDetection> {
                self.db.get_canonical_hash_at_height(height)
            }

            pub fn delete_height_range(
                &self,
                from_height: u64,
                to_height: u64,
            ) -> Result<(), ErrorDetection> {
                self.db.delete_canonical_hash_range(from_height, to_height)
            }

            pub fn set_tip(
                &self,
                tip_hash: &BlockHash,
                tip_height: u64,
            ) -> Result<(), ErrorDetection> {
                self.db.set_canonical_tip(tip_hash, tip_height)
            }

            pub fn get_tip(&self) -> Result<Option<CanonicalTipView>, ErrorDetection> {
                self.db.get_canonical_tip()
            }

            pub fn get_tip_with_legacy_fallback(
                &self,
            ) -> Result<Option<CanonicalTipView>, ErrorDetection> {
                if let Some(view) = self.get_tip()? {
                    return Ok(Some(view));
                }

                let legacy_height = self.db.get_tip_height()?;
                match self.db.get_block_by_index(legacy_height)? {
                    Some(block) => Ok(Some(CanonicalTipView {
                        tip_hash: block.block_hash,
                        tip_height: block.metadata.index,
                    })),
                    None => Ok(None),
                }
            }

            pub fn canonical_block_at_height(
                &self,
                height: u64,
            ) -> Result<Option<Block>, ErrorDetection> {
                let Some(hash) = self.get_hash_at_height(height)? else {
                    return Ok(None);
                };
                Ok(self.db.get_block_by_hash(&hash))
            }
        }
    }

    pub mod reorg_003_branch_score {
        use crate::network::p2p_006_reqresp::Hash;

        pub type BlockHash = Hash;

        #[derive(Clone, Debug)]
        pub struct BranchScoreConfig {
            pub mode: BranchScoreMode,
            pub allow_equal_height_tiebreak: bool,
            pub prefer_lower_hash_on_tie: bool,
        }

        impl Default for BranchScoreConfig {
            fn default() -> Self {
                Self {
                    mode: BranchScoreMode::HeightOnly,
                    allow_equal_height_tiebreak: false,
                    prefer_lower_hash_on_tie: true,
                }
            }
        }

        #[derive(Clone, Debug)]
        pub enum BranchScoreMode {
            HeightOnly,
            CumulativePor,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct BranchCandidate {
            pub tip_hash: BlockHash,
            pub height: u64,
            pub cumulative_por: u128,
        }

        impl BranchCandidate {
            pub fn new(tip_hash: BlockHash, height: u64, cumulative_por: u128) -> Self {
                Self {
                    tip_hash,
                    height,
                    cumulative_por,
                }
            }
        }

        #[derive(Clone, Debug)]
        pub struct ReorgBranchScorer {
            cfg: BranchScoreConfig,
        }

        impl ReorgBranchScorer {
            pub fn new(cfg: BranchScoreConfig) -> Self {
                Self { cfg }
            }

            pub fn choose_tip(
                &self,
                current: BranchCandidate,
                candidate: BranchCandidate,
            ) -> Option<BlockHash> {
                let candidate_beats = match self.cfg.mode {
                    BranchScoreMode::HeightOnly => {
                        candidate.height > current.height
                            || (candidate.height == current.height
                                && self.cfg.allow_equal_height_tiebreak
                                && Self::tie_break(
                                    candidate.tip_hash,
                                    current.tip_hash,
                                    self.cfg.prefer_lower_hash_on_tie,
                                ))
                    }
                    BranchScoreMode::CumulativePor => {
                        candidate.cumulative_por > current.cumulative_por
                            || (candidate.cumulative_por == current.cumulative_por
                                && (candidate.height > current.height
                                    || (candidate.height == current.height
                                        && self.cfg.allow_equal_height_tiebreak
                                        && Self::tie_break(
                                            candidate.tip_hash,
                                            current.tip_hash,
                                            self.cfg.prefer_lower_hash_on_tie,
                                        ))))
                    }
                };

                if candidate_beats {
                    return Some(candidate.tip_hash);
                }

                let current_beats = match self.cfg.mode {
                    BranchScoreMode::HeightOnly => {
                        current.height > candidate.height
                            || (current.height == candidate.height
                                && self.cfg.allow_equal_height_tiebreak
                                && Self::tie_break(
                                    current.tip_hash,
                                    candidate.tip_hash,
                                    self.cfg.prefer_lower_hash_on_tie,
                                ))
                    }
                    BranchScoreMode::CumulativePor => {
                        current.cumulative_por > candidate.cumulative_por
                            || (current.cumulative_por == candidate.cumulative_por
                                && (current.height > candidate.height
                                    || (current.height == candidate.height
                                        && self.cfg.allow_equal_height_tiebreak
                                        && Self::tie_break(
                                            current.tip_hash,
                                            candidate.tip_hash,
                                            self.cfg.prefer_lower_hash_on_tie,
                                        ))))
                    }
                };

                if current_beats {
                    Some(current.tip_hash)
                } else {
                    None
                }
            }

            fn tie_break(a: BlockHash, b: BlockHash, prefer_lower_hash: bool) -> bool {
                if a == b {
                    return false;
                }
                if prefer_lower_hash { a < b } else { a > b }
            }
        }
    }
}

#[path = "../../src/reorganization/reorg_005_fork_choice.rs"]
mod reorg_005_fork_choice;

use blockchain::block_002_blocks::Block;
use consensus::por_004_puzzle_proof::PorPuzzleProof;
use network::p2p_006_reqresp::Hash;
use reorg_005_fork_choice::{ForkAction, ReFork, ReForkConfig, ReorgPlan, ReorgStep};
use reorganization::reorg_002_chain_view::ReorgChainView;
use storage::rocksdb_005_manager::{ReorgBlockStatus, RockDBManager};
use utility::alpha_002_error_detection_system::ErrorDetection;

fn touch_error(error: &ErrorDetection) {
    let _ = error.to_string();
    match error {
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            let _ = tx_id.as_ref().map(|s| s.len());
        }
        ErrorDetection::SerializationError { details }
        | ErrorDetection::DatabaseError { details }
        | ErrorDetection::BlockchainError { details } => {
            let _ = details.len();
        }
        ErrorDetection::StorageError { message } => {
            let _ = message.len();
        }
        ErrorDetection::NotFound { resource } => {
            let _ = resource.len();
        }
        ErrorDetection::TimestampError {
            message,
            details,
            source,
        } => {
            let _ = message.len();
            let _ = details.len();
            let _ = source.as_ref().map(|s| s.len());
        }
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            touch_error(&error);
            None
        }
    }
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

fn read_u128(data: &[u8], offset: usize) -> u128 {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = byte_at(data, offset + i, i as u8);
    }
    u128::from_le_bytes(out)
}

fn hash_from(data: &[u8], salt: usize) -> Hash {
    let mut out = [0u8; 64];

    for i in 0..64 {
        let a = byte_at(data, salt.wrapping_add(i), i as u8);
        let b = byte_at(
            data,
            salt.wrapping_add(i.wrapping_mul(17)).wrapping_add(7),
            (i as u8).wrapping_mul(3),
        );
        let c = byte_at(
            data,
            salt.wrapping_add(i.wrapping_mul(31)).wrapping_add(19),
            (i as u8).wrapping_mul(11),
        );
        out[i] = a ^ b.rotate_left(1) ^ c.rotate_right(1) ^ (salt as u8).wrapping_add(i as u8);
    }

    if out == [0u8; 64] {
        out[0] = 1;
    }

    out
}

fn unique_hash(data: &[u8], salt: usize, height: u64) -> Hash {
    let mut h = hash_from(data, salt);
    let height_bytes = height.to_le_bytes();
    for (i, b) in height_bytes.iter().enumerate() {
        h[i] ^= *b;
        h[63 - i] ^= b.wrapping_mul(17);
    }
    if h == [0u8; 64] {
        h[0] = 1;
    }
    h
}

fn make_block(data: &[u8], salt: usize, height: u64, parent_hash: Hash) -> Block {
    let hash = unique_hash(data, salt, height);
    Block::new(height, parent_hash, hash)
}

fn insert_chain(
    db: &RockDBManager,
    data: &[u8],
    start_salt: usize,
    tip_height: u64,
) -> Vec<Block> {
    let mut out = Vec::new();
    let mut parent = [0u8; 64];

    for height in 0..=tip_height {
        let mut block = make_block(data, start_salt + height as usize * 11, height, parent);

        if height == 0 {
            block.metadata.previous_hash = [0u8; 64];
        }

        let score = u128::from(height).saturating_add(1);
        let _ = db.insert_block_with_meta(block.clone(), block.metadata.previous_hash, score, true);
        parent = block.block_hash;
        out.push(block);
    }

    out
}

fn insert_side_branch(
    db: &RockDBManager,
    data: &[u8],
    canonical: &[Block],
    fork_height: u64,
    branch_len: u64,
    start_salt: usize,
    cumulative_bonus: u128,
) -> Vec<Block> {
    let fork_idx = usize::try_from(fork_height).unwrap_or(0).min(canonical.len().saturating_sub(1));
    let mut parent = canonical[fork_idx].block_hash;
    let mut out = Vec::new();

    for offset in 1..=branch_len {
        let height = fork_height.saturating_add(offset);
        let block = make_block(data, start_salt + offset as usize * 13, height, parent);
        let score = u128::from(height)
            .saturating_add(1)
            .saturating_add(cumulative_bonus);
        let _ = db.insert_block_with_meta(block.clone(), parent, score, false);
        parent = block.block_hash;
        out.push(block);
    }

    out
}

fn bounded_tip_height(data: &[u8], offset: usize) -> u64 {
    read_u64(data, offset) % 8
}

fn bounded_depth(data: &[u8], offset: usize) -> u64 {
    (read_u64(data, offset) % 8).saturating_add(1)
}

fn config_from_data(data: &[u8], salt: usize) -> ReForkConfig {
    ReForkConfig {
        max_reorg_depth: bounded_depth(data, salt),
        allow_equal_height_reorg: byte_at(data, salt + 8, 0) & 1 == 1,
        prefer_cumulative_por: byte_at(data, salt + 9, 0) & 1 == 1,
    }
}

fn touch_plan(plan: &ReorgPlan) {
    let _ = plan.is_noop();
    let detach_heights = plan.detach_heights();
    let attach_heights = plan.attach_heights();
    let _ = detach_heights.len().saturating_add(attach_heights.len());

    // Reorg contract: detach should walk downward; attach should walk upward.
    for w in plan.detach.windows(2) {
        assert!(w[0].height >= w[1].height);
    }
    for w in plan.attach.windows(2) {
        assert!(w[0].height <= w[1].height);
    }
}

fn touch_action(action: &ForkAction) {
    match action {
        ForkAction::Stay => {}
        ForkAction::NeedMoreData {
            missing_hash,
            context,
        } => {
            let _ = missing_hash[0];
            let _ = context.len();
        }
        ForkAction::Reorg(plan) => touch_plan(plan),
    }
}


fn assert_tip_apis_agree(db: &Arc<RockDBManager>) {
    let view = ReorgChainView::new(Arc::clone(db));

    let db_tip = db
        .get_canonical_tip()
        .expect("mock db canonical tip lookup must not fail");
    let db_tip_hash = db
        .get_canonical_tip_hash()
        .expect("mock db canonical tip hash lookup must not fail");
    let db_tip_height = db
        .get_canonical_tip_height()
        .expect("mock db canonical tip height lookup must not fail");
    let view_tip = view
        .get_tip()
        .expect("chain view tip lookup must not fail");
    let fallback_tip = view
        .get_tip_with_legacy_fallback()
        .expect("chain view fallback tip lookup must not fail");

    assert_eq!(db_tip, view_tip);

    if let Some(tip) = db_tip {
        assert_eq!(db_tip_hash, Some(tip.tip_hash));
        assert_eq!(db_tip_height, Some(tip.tip_height));
        assert_eq!(fallback_tip, Some(tip));
    }
}

fn assert_canonical_projection(
    db: &Arc<RockDBManager>,
    expected_tip_hash: Hash,
    expected_tip_height: u64,
) {
    let view = ReorgChainView::new(Arc::clone(db));

    assert_tip_apis_agree(db);

    let tip = view
        .get_tip_with_legacy_fallback()
        .expect("canonical tip fallback lookup must not fail")
        .expect("canonical tip must exist");

    assert_eq!(tip.tip_hash, expected_tip_hash);
    assert_eq!(tip.tip_height, expected_tip_height);
    assert_eq!(db.get_canonical_tip_hash().unwrap(), Some(expected_tip_hash));
    assert_eq!(db.get_canonical_tip_height().unwrap(), Some(expected_tip_height));

    let mut previous_hash: Option<Hash> = None;

    for height in 0..=expected_tip_height {
        let db_hash = db
            .get_canonical_hash_at_height(height)
            .expect("canonical hash lookup through db must not fail");
        let view_hash = view
            .get_hash_at_height(height)
            .expect("canonical hash lookup through chain view must not fail");

        assert_eq!(db_hash, view_hash);

        let hash = db_hash.expect("canonical chain must not have height gaps");
        let block = view
            .canonical_block_at_height(height)
            .expect("canonical block lookup through chain view must not fail")
            .expect("canonical hash must resolve to a block");

        assert_eq!(block.metadata.index, height);
        assert_eq!(block.block_hash, hash);

        let legacy_block = db
            .get_block_by_index(height)
            .expect("legacy canonical block lookup must not fail")
            .expect("legacy canonical block projection must exist");
        assert_eq!(legacy_block, block);

        let meta = db
            .get_block_meta_by_hash(&hash)
            .expect("canonical meta lookup must not fail")
            .expect("canonical block must have metadata");
        assert_eq!(meta.height, height);
        assert_eq!(meta.status, ReorgBlockStatus::Canonical);

        match previous_hash {
            Some(parent_hash) => assert_eq!(block.metadata.previous_hash, parent_hash),
            None => assert_eq!(height, 0),
        }

        previous_hash = Some(hash);
    }
}

fn assert_plan_structural_invariants(db: &Arc<RockDBManager>, plan: &ReorgPlan) {
    touch_plan(plan);

    assert!(plan.common_ancestor_height <= plan.old_tip_height);
    assert!(plan.common_ancestor_height <= plan.new_tip_height);

    if let Some(first_detach) = plan.detach.first() {
        assert_eq!(first_detach.height, plan.old_tip_height);
        assert_eq!(first_detach.hash, plan.old_tip_hash);
    }

    if let Some(last_attach) = plan.attach.last() {
        assert_eq!(last_attach.height, plan.new_tip_height);
        assert_eq!(last_attach.hash, plan.new_tip_hash);
    }

    let view = ReorgChainView::new(Arc::clone(db));

    for step in &plan.detach {
        let canonical_hash = view
            .get_hash_at_height(step.height)
            .expect("canonical hash lookup for detach step must not fail")
            .expect("detach step must point at existing canonical height before apply");
        assert_eq!(canonical_hash, step.hash);
    }

    let mut expected_parent = plan.common_ancestor_hash;
    let mut expected_height = plan.common_ancestor_height.saturating_add(1);

    for step in &plan.attach {
        assert_eq!(step.height, expected_height);

        let block = db
            .get_block_by_hash(&step.hash)
            .expect("attach step must point at a persisted side-branch block");
        assert_eq!(block.metadata.index, step.height);
        assert_eq!(block.metadata.previous_hash, expected_parent);

        let meta = db
            .get_block_meta_by_hash(&step.hash)
            .expect("attach meta lookup must not fail")
            .expect("attach step must have metadata");
        assert_eq!(meta.height, step.height);
        assert_eq!(meta.parent_hash, expected_parent);

        expected_parent = step.hash;
        expected_height = expected_height.saturating_add(1);
    }
}

fn assert_reorg_callback_order(
    plan: &ReorgPlan,
    reverted: &[(u64, Hash)],
    applied: &[(u64, Hash)],
) {
    let expected_reverted: Vec<(u64, Hash)> = plan
        .detach
        .iter()
        .map(|step| (step.height, step.hash))
        .collect();
    let expected_applied: Vec<(u64, Hash)> = plan
        .attach
        .iter()
        .map(|step| (step.height, step.hash))
        .collect();

    assert_eq!(reverted, expected_reverted.as_slice());
    assert_eq!(applied, expected_applied.as_slice());
}

fn exercise_error_variants(data: &[u8]) {
    let validation = ErrorDetection::ValidationError {
        message: format!("validation-{}", byte_at(data, 700, 0)),
        tx_id: Some(format!("tx-{}", byte_at(data, 701, 0))),
    };
    let database = ErrorDetection::DatabaseError {
        details: format!("database-{}", byte_at(data, 702, 0)),
    };

    touch_error(&validation);
    touch_error(&database);
}

fn exercise_direct_extension(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let canonical_tip = bounded_tip_height(data, 0).max(1);
    let canonical = insert_chain(&db, data, 100, canonical_tip);
    let old_tip = canonical.last().cloned().unwrap();

    let fork = ReFork::new(
        Arc::clone(&db),
        ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        },
    );

    let extending = make_block(data, 900, old_tip.metadata.index.saturating_add(1), old_tip.block_hash);
    let action = touch_result(fork.on_new_block(&extending));
    if let Some(action) = action {
        touch_action(&action);
        assert!(matches!(action, ForkAction::Stay));
    }
}

fn exercise_complete_reorg(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let old_tip_height = 2 + (read_u64(data, 20) % 5);
    let canonical = insert_chain(&db, data, 1_000, old_tip_height);

    let fork_height = read_u64(data, 28) % old_tip_height.max(1);
    let branch_len = old_tip_height.saturating_sub(fork_height).saturating_add(1);
    let side = insert_side_branch(&db, data, &canonical, fork_height, branch_len, 2_000, 0);
    let Some(candidate_tip) = side.last().cloned() else {
        return;
    };

    let fork = ReFork::new(
        Arc::clone(&db),
        ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        },
    );

    let Some(action) = touch_result(fork.on_new_block(&candidate_tip)) else {
        return;
    };
    touch_action(&action);

    if let ForkAction::Reorg(plan) = action {
        assert_eq!(plan.new_tip_hash, candidate_tip.block_hash);
        assert_eq!(plan.new_tip_height, candidate_tip.metadata.index);
        assert!(plan.common_ancestor_height <= old_tip_height);
        assert!(!plan.attach.is_empty());
        assert_plan_structural_invariants(&db, &plan);

        let mut reverted = Vec::<(u64, Hash)>::new();
        let mut applied = Vec::<(u64, Hash)>::new();

        let result = fork.apply_reorg(
            &plan,
            |height, hash| {
                reverted.push((height, hash));
                Ok(())
            },
            |height, hash| {
                applied.push((height, hash));
                Ok(())
            },
        );

        if touch_result(result).is_some() {
            assert_reorg_callback_order(&plan, &reverted, &applied);
            assert_canonical_projection(&db, plan.new_tip_hash, plan.new_tip_height);
        }
    }
}

fn exercise_equal_height_and_cumulative_score(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let old_tip_height = 2 + (read_u64(data, 100) % 5);
    let canonical = insert_chain(&db, data, 3_000, old_tip_height);

    let fork_height = old_tip_height.saturating_sub(1);
    let side = insert_side_branch(
        &db,
        data,
        &canonical,
        fork_height,
        1,
        4_000,
        read_u128(data, 108).saturating_add(1_000),
    );
    let Some(candidate_tip) = side.last().cloned() else {
        return;
    };

    let fork = ReFork::new(
        Arc::clone(&db),
        ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: true,
            prefer_cumulative_por: true,
        },
    );

    let Some(action) = touch_result(fork.on_new_block(&candidate_tip)) else {
        return;
    };
    touch_action(&action);

    if let ForkAction::Reorg(plan) = action {
        assert_plan_structural_invariants(&db, &plan);
        if touch_result(fork.apply_reorg(&plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()))).is_some() {
            assert_canonical_projection(&db, plan.new_tip_hash, plan.new_tip_height);
        }
    }
}

fn exercise_missing_branch_data(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let old_tip_height = 2 + (read_u64(data, 200) % 5);
    let canonical = insert_chain(&db, data, 5_000, old_tip_height);

    let fork_height = read_u64(data, 208) % old_tip_height.max(1);
    let branch_len = old_tip_height.saturating_sub(fork_height).saturating_add(2);
    let side = insert_side_branch(&db, data, &canonical, fork_height, branch_len, 6_000, 0);
    let Some(candidate_tip) = side.last().cloned() else {
        return;
    };

    match byte_at(data, 216, 0) % 3 {
        0 => {
            // Missing candidate metadata.
            let _ = db.remove_meta_by_hash(&candidate_tip.block_hash);
        }
        1 => {
            // Missing parent block.
            if side.len() >= 2 {
                let parent = side[side.len() - 2].block_hash;
                let _ = db.remove_block_by_hash(&parent);
            }
        }
        _ => {
            // Missing parent metadata.
            if side.len() >= 2 {
                let parent = side[side.len() - 2].block_hash;
                let _ = db.remove_meta_by_hash(&parent);
            }
        }
    }

    let fork = ReFork::new(
        Arc::clone(&db),
        ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        },
    );

    let Some(action) = touch_result(fork.on_new_block(&candidate_tip)) else {
        return;
    };
    touch_action(&action);
    assert!(matches!(action, ForkAction::NeedMoreData { .. } | ForkAction::Stay));
}

fn exercise_depth_bound(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let old_tip_height = 5 + (read_u64(data, 300) % 5);
    let canonical = insert_chain(&db, data, 7_000, old_tip_height);

    let fork_height = 0;
    let branch_len = old_tip_height.saturating_add(2);
    let side = insert_side_branch(&db, data, &canonical, fork_height, branch_len, 8_000, 0);
    let Some(candidate_tip) = side.last().cloned() else {
        return;
    };

    let tiny_depth = 1 + (read_u64(data, 308) % 2);
    let fork = ReFork::new(
        Arc::clone(&db),
        ReForkConfig {
            max_reorg_depth: tiny_depth,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        },
    );

    let Some(action) = touch_result(fork.on_new_block(&candidate_tip)) else {
        return;
    };
    touch_action(&action);
    assert!(matches!(
        action,
        ForkAction::Stay | ForkAction::NeedMoreData { .. }
    ));
}

fn exercise_manual_apply_plans(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let canonical = insert_chain(&db, data, 9_000, 3);
    let fork = ReFork::mainnet_default(Arc::clone(&db));

    let genesis = canonical[0].clone();
    let tip = canonical.last().cloned().unwrap();

    let noop = ReorgPlan {
        old_tip_height: tip.metadata.index,
        old_tip_hash: tip.block_hash,
        new_tip_height: tip.metadata.index,
        new_tip_hash: tip.block_hash,
        common_ancestor_height: tip.metadata.index,
        common_ancestor_hash: tip.block_hash,
        detach: Vec::new(),
        attach: Vec::new(),
    };
    assert!(noop.is_noop());
    let _ = touch_result(fork.apply_reorg(&noop, |_h, _hash| Ok(()), |_h, _hash| Ok(())));

    let bad_hash = unique_hash(data, 10_000, 44);
    let bad_plan = ReorgPlan {
        old_tip_height: tip.metadata.index,
        old_tip_hash: tip.block_hash,
        new_tip_height: 44,
        new_tip_hash: bad_hash,
        common_ancestor_height: genesis.metadata.index,
        common_ancestor_hash: genesis.block_hash,
        detach: vec![ReorgStep {
            height: tip.metadata.index,
            hash: tip.block_hash,
        }],
        attach: vec![ReorgStep {
            height: 44,
            hash: bad_hash,
        }],
    };
    touch_plan(&bad_plan);
    let _ = touch_result(fork.apply_reorg(&bad_plan, |_h, _hash| Ok(()), |_h, _hash| Ok(())));
}


fn exercise_chain_view_projection_apis(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let tip_height = 1 + (read_u64(data, 500) % 7);
    let canonical = insert_chain(&db, data, 12_000, tip_height);
    let tip = canonical.last().cloned().unwrap();

    assert_canonical_projection(&db, tip.block_hash, tip.metadata.index);

    let view = ReorgChainView::new(Arc::clone(&db));
    let missing_height = tip.metadata.index.saturating_add(1);
    assert_eq!(view.get_hash_at_height(missing_height).unwrap(), None);
    assert_eq!(view.canonical_block_at_height(missing_height).unwrap(), None);
}

fn exercise_equal_height_reorg_disabled(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let old_tip_height = 2 + (read_u64(data, 520) % 5);
    let canonical = insert_chain(&db, data, 13_000, old_tip_height);

    let fork_height = old_tip_height.saturating_sub(1);
    let side = insert_side_branch(
        &db,
        data,
        &canonical,
        fork_height,
        1,
        14_000,
        read_u128(data, 528).saturating_add(10_000),
    );
    let Some(candidate_tip) = side.last().cloned() else {
        return;
    };

    let original_tip = canonical.last().cloned().unwrap();
    let fork = ReFork::new(
        Arc::clone(&db),
        ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        },
    );

    let Some(action) = touch_result(fork.on_new_block(&candidate_tip)) else {
        return;
    };
    touch_action(&action);
    assert!(matches!(action, ForkAction::Stay));
    assert_canonical_projection(&db, original_tip.block_hash, original_tip.metadata.index);
}

fn exercise_apply_callback_errors(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let canonical = insert_chain(&db, data, 15_000, 4);
    let side = insert_side_branch(&db, data, &canonical, 2, 3, 16_000, 0);
    let Some(candidate_tip) = side.last().cloned() else {
        return;
    };

    let original_tip = canonical.last().cloned().unwrap();
    let fork = ReFork::new(
        Arc::clone(&db),
        ReForkConfig {
            max_reorg_depth: 64,
            allow_equal_height_reorg: false,
            prefer_cumulative_por: false,
        },
    );

    let Some(action) = touch_result(fork.on_new_block(&candidate_tip)) else {
        return;
    };

    if let ForkAction::Reorg(plan) = action {
        assert_plan_structural_invariants(&db, &plan);

        let fail_on_revert = byte_at(data, 560, 0) & 1 == 0;
        let result = fork.apply_reorg(
            &plan,
            |_height, _hash| {
                if fail_on_revert {
                    Err(ErrorDetection::DatabaseError {
                        details: "intentional fuzz revert failure".into(),
                    })
                } else {
                    Ok(())
                }
            },
            |_height, _hash| {
                if !fail_on_revert {
                    Err(ErrorDetection::ValidationError {
                        message: "intentional fuzz apply failure".into(),
                        tx_id: None,
                    })
                } else {
                    Ok(())
                }
            },
        );

        assert!(result.is_err());
        if let Err(error) = result {
            touch_error(&error);
        }

        let current_tip_hash = db.get_canonical_tip_hash().unwrap();
        assert_ne!(current_tip_hash, Some(plan.new_tip_hash));
        assert_eq!(current_tip_hash, Some(original_tip.block_hash));
    }
}

fn exercise_apply_height_mismatch(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let canonical = insert_chain(&db, data, 17_000, 3);
    let side = insert_side_branch(&db, data, &canonical, 1, 2, 18_000, 0);
    let fork = ReFork::mainnet_default(Arc::clone(&db));

    let genesis = canonical[0].clone();
    let tip = canonical.last().cloned().unwrap();
    let Some(attach_block) = side.last().cloned() else {
        return;
    };

    let wrong_height = attach_block.metadata.index.saturating_add(1 + (read_u64(data, 580) % 4));
    let bad_plan = ReorgPlan {
        old_tip_height: tip.metadata.index,
        old_tip_hash: tip.block_hash,
        new_tip_height: wrong_height,
        new_tip_hash: attach_block.block_hash,
        common_ancestor_height: genesis.metadata.index,
        common_ancestor_hash: genesis.block_hash,
        detach: vec![ReorgStep {
            height: tip.metadata.index,
            hash: tip.block_hash,
        }],
        attach: vec![ReorgStep {
            height: wrong_height,
            hash: attach_block.block_hash,
        }],
    };

    let result = fork.apply_reorg(&bad_plan, |_h, _hash| Ok(()), |_h, _hash| Ok(()));
    assert!(result.is_err());
    if let Err(error) = result {
        touch_error(&error);
    }

    let original_tip = canonical.last().cloned().unwrap();
    assert_eq!(db.get_canonical_tip_hash().unwrap(), Some(original_tip.block_hash));
    assert_eq!(db.get_canonical_tip_height().unwrap(), Some(original_tip.metadata.index));
}

fn exercise_empty_db_and_config(data: &[u8]) {
    let db = Arc::new(RockDBManager::new_for_fuzz());
    let cfg = config_from_data(data, 400);
    let fork = ReFork::new(Arc::clone(&db), cfg);

    let block = make_block(data, 11_000, bounded_tip_height(data, 410), hash_from(data, 420));
    let _ = touch_result(fork.on_new_block(&block));

    let proof = PorPuzzleProof {
        height: read_u64(data, 430),
        validator: format!("validator-{}", byte_at(data, 438, 0)),
        prev_block_hash: hash_from(data, 439),
    };
    fork.on_puzzle_proof_for_branch(&proof);
}

fuzz_target!(|data: &[u8]| {
    exercise_error_variants(data);
    exercise_empty_db_and_config(data);
    exercise_chain_view_projection_apis(data);
    exercise_direct_extension(data);
    exercise_complete_reorg(data);
    exercise_equal_height_reorg_disabled(data);
    exercise_equal_height_and_cumulative_score(data);
    exercise_missing_branch_data(data);
    exercise_depth_bound(data);
    exercise_apply_callback_errors(data);
    exercise_apply_height_mismatch(data);
    exercise_manual_apply_plans(data);
});
