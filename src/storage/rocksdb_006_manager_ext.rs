//! rocksdb_006_manager_ext.rs

use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use rust_rocksdb::WriteBatch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkBlockStatus {
    HeaderOnly = 0,
    BlockStored = 1,
    Validated = 2,
    Canonical = 3,
    SideBranch = 4,
    Orphan = 5,
}

impl ForkBlockStatus {
    pub fn from_u8(v: u8) -> Result<Self, ErrorDetection> {
        match v {
            0 => Ok(Self::HeaderOnly),
            1 => Ok(Self::BlockStored),
            2 => Ok(Self::Validated),
            3 => Ok(Self::Canonical),
            4 => Ok(Self::SideBranch),
            5 => Ok(Self::Orphan),
            _ => Err(ErrorDetection::StorageError {
                message: format!("Invalid ForkBlockStatus value: {}", v),
            }),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Durable metadata for a block in the fork graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkBlockMeta {
    pub parent_hash: Hash,
    pub height: u64,
    pub cumulative_score: u128,
    pub status: ForkBlockStatus,
    pub received_at_unix_secs: u64,
}

impl ForkBlockMeta {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(97);
        out.extend_from_slice(&self.parent_hash);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.cumulative_score.to_be_bytes());
        out.push(self.status.as_u8());
        out.extend_from_slice(&self.received_at_unix_secs.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        const EXPECTED_LEN: usize = 97;

        if bytes.len() != EXPECTED_LEN {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "Invalid ForkBlockMeta length: expected {}, got {}",
                    EXPECTED_LEN,
                    bytes.len()
                ),
            });
        }

        let mut parent_hash = [0u8; 64];
        parent_hash.copy_from_slice(bytes.get(0..64).ok_or_else(|| {
            ErrorDetection::StorageError {
                message: "Missing parent_hash bytes in ForkBlockMeta".to_string(),
            }
        })?);

        let mut height_arr = [0u8; 8];
        height_arr.copy_from_slice(bytes.get(64..72).ok_or_else(|| {
            ErrorDetection::StorageError {
                message: "Missing height bytes in ForkBlockMeta".to_string(),
            }
        })?);
        let height = u64::from_be_bytes(height_arr);

        let mut score_arr = [0u8; 16];
        score_arr.copy_from_slice(bytes.get(72..88).ok_or_else(|| {
            ErrorDetection::StorageError {
                message: "Missing cumulative_score bytes in ForkBlockMeta".to_string(),
            }
        })?);
        let cumulative_score = u128::from_be_bytes(score_arr);

        let status = ForkBlockStatus::from_u8(*bytes.get(88).ok_or_else(|| {
            ErrorDetection::StorageError {
                message: "Missing status byte in ForkBlockMeta".to_string(),
            }
        })?)?;

        let mut received_arr = [0u8; 8];
        received_arr.copy_from_slice(bytes.get(89..97).ok_or_else(|| {
            ErrorDetection::StorageError {
                message: "Missing received_at_unix_secs bytes in ForkBlockMeta".to_string(),
            }
        })?);
        let received_at_unix_secs = u64::from_be_bytes(received_arr);

        Ok(Self {
            parent_hash,
            height,
            cumulative_score,
            status,
            received_at_unix_secs,
        })
    }
}

/// Canonical tip view persisted in the canonical_chain_view CF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTipView {
    pub tip_hash: Hash,
    pub tip_height: u64,
}

impl CanonicalTipView {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72);
        out.extend_from_slice(&self.tip_hash);
        out.extend_from_slice(&self.tip_height.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        const EXPECTED_LEN: usize = 72;

        if bytes.len() != EXPECTED_LEN {
            return Err(ErrorDetection::StorageError {
                message: format!(
                    "Invalid CanonicalTipView length: expected {}, got {}",
                    EXPECTED_LEN,
                    bytes.len()
                ),
            });
        }

        let mut tip_hash = [0u8; 64];
        tip_hash.copy_from_slice(
            bytes
                .get(0..64)
                .ok_or_else(|| ErrorDetection::StorageError {
                    message: "Missing tip_hash bytes in CanonicalTipView".to_string(),
                })?,
        );

        let mut height_arr = [0u8; 8];
        height_arr.copy_from_slice(bytes.get(64..72).ok_or_else(|| {
            ErrorDetection::StorageError {
                message: "Missing tip_height bytes in CanonicalTipView".to_string(),
            }
        })?);
        let tip_height = u64::from_be_bytes(height_arr);

        Ok(Self {
            tip_hash,
            tip_height,
        })
    }
}

impl RockDBManager {
    // ─────────────────────────────────────────────────────────────────
    // 20) BLOCK META BY HASH
    // ─────────────────────────────────────────────────────────────────

    /// Persist block metadata under its block hash.
    pub fn store_block_meta_by_hash(
        &self,
        block_hash: &Hash,
        meta: &ForkBlockMeta,
    ) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME
                ),
            })?;

        let bytes = meta.to_bytes();
        let mut wb = WriteBatch::default();
        wb.put_cf(cf, block_hash, &bytes);

        db.write_opt(&wb, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store block meta by hash: {}", e),
            })
    }

    /// Fetch block metadata by block hash.
    pub fn get_block_meta_by_hash(
        &self,
        block_hash: &Hash,
    ) -> Result<Option<ForkBlockMeta>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME
                ),
            })?;

        let pinned =
            db.get_pinned_cf(cf, block_hash)
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!("Failed to read block meta by hash: {}", e),
                })?;

        match pinned {
            Some(bytes) => Ok(Some(ForkBlockMeta::from_bytes(bytes.as_ref())?)),
            None => Ok(None),
        }
    }

    /// Return true if metadata exists for this block hash.
    pub fn has_block_meta_by_hash(&self, block_hash: &Hash) -> Result<bool, ErrorDetection> {
        Ok(self.get_block_meta_by_hash(block_hash)?.is_some())
    }

    /// Update only the status of an existing block meta record.
    pub fn set_block_meta_status(
        &self,
        block_hash: &Hash,
        new_status: ForkBlockStatus,
    ) -> Result<(), ErrorDetection> {
        let mut meta =
            self.get_block_meta_by_hash(block_hash)?
                .ok_or_else(|| ErrorDetection::NotFound {
                    resource: "block_meta_by_hash".to_string(),
                })?;

        meta.status = new_status;
        self.store_block_meta_by_hash(block_hash, &meta)
    }

    // ─────────────────────────────────────────────────────────────────
    // 21) BATCH BY BLOCK HASH
    // ─────────────────────────────────────────────────────────────────

    /// Persist the exact tx batch bytes for a specific block hash.
    pub fn store_batch_by_block_hash(
        &self,
        block_hash: &Hash,
        batch_bytes: &[u8],
    ) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME
                ),
            })?;

        let mut wb = WriteBatch::default();
        wb.put_cf(cf, block_hash, batch_bytes);

        db.write_opt(&wb, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to store batch by block hash: {}", e),
            })
    }

    /// Fetch batch bytes by block hash.
    pub fn get_batch_by_block_hash(
        &self,
        block_hash: &Hash,
    ) -> Result<Option<Vec<u8>>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME
                ),
            })?;

        let pinned =
            db.get_pinned_cf(cf, block_hash)
                .map_err(|e| ErrorDetection::StorageError {
                    message: format!("Failed to read batch by block hash: {}", e),
                })?;

        Ok(pinned.map(|b| b.to_vec()))
    }

    pub fn has_batch_by_block_hash(&self, block_hash: &Hash) -> Result<bool, ErrorDetection> {
        Ok(self.get_batch_by_block_hash(block_hash)?.is_some())
    }

    // ─────────────────────────────────────────────────────────────────
    // 22) CANONICAL HEIGHT -> HASH VIEW
    // ─────────────────────────────────────────────────────────────────

    /// Canonical mapping key format.
    #[inline]
    fn canonical_height_key(height: u64) -> [u8; 8] {
        height.to_be_bytes()
    }

    /// Set the canonical block hash for a given height.
    pub fn set_canonical_hash_at_height(
        &self,
        height: u64,
        block_hash: &Hash,
    ) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
                ),
            })?;

        let key = Self::canonical_height_key(height);
        let mut wb = WriteBatch::default();
        wb.put_cf(cf, key, block_hash);

        db.write_opt(&wb, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to set canonical hash at height {}: {}", height, e),
            })
    }

    /// Read the canonical block hash for a given height.
    pub fn get_canonical_hash_at_height(
        &self,
        height: u64,
    ) -> Result<Option<Hash>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
                ),
            })?;

        let key = Self::canonical_height_key(height);
        let pinned = db
            .get_pinned_cf(cf, key)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to get canonical hash at height {}: {}", height, e),
            })?;

        match pinned {
            Some(bytes) => {
                if bytes.len() != 64 {
                    return Err(ErrorDetection::StorageError {
                        message: format!(
                            "Invalid canonical hash length at height {}: expected 64, got {}",
                            height,
                            bytes.len()
                        ),
                    });
                }

                let mut hash = [0u8; 64];
                hash.copy_from_slice(bytes.as_ref());
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Remove canonical mappings from `from_height` through `to_height` inclusive.
    pub fn delete_canonical_hash_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), ErrorDetection> {
        if from_height > to_height {
            return Ok(());
        }

        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
                ),
            })?;

        let mut wb = WriteBatch::default();
        for h in from_height..=to_height {
            wb.delete_cf(cf, Self::canonical_height_key(h));
        }

        db.write_opt(&wb, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!(
                    "Failed deleting canonical hash range {}..={}: {}",
                    from_height, to_height, e
                ),
            })
    }

    // ─────────────────────────────────────────────────────────────────
    // 23) CANONICAL CHAIN VIEW (TIP HASH / TIP HEIGHT)
    // ─────────────────────────────────────────────────────────────────

    const CANONICAL_TIP_VIEW_KEY: &'static [u8] = b"canonical_tip_view";

    /// Persist the canonical tip hash + height.
    pub fn set_canonical_tip(
        &self,
        tip_hash: &Hash,
        tip_height: u64,
    ) -> Result<(), ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME
                ),
            })?;

        let view = CanonicalTipView {
            tip_hash: *tip_hash,
            tip_height,
        };

        let bytes = view.to_bytes();
        let mut wb = WriteBatch::default();
        wb.put_cf(cf, Self::CANONICAL_TIP_VIEW_KEY, &bytes);

        db.write_opt(&wb, &Self::sync_write_options())
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to set canonical tip: {}", e),
            })?;

        // Keep legacy tip metadata in sync with existing code paths.
        self.set_tip_height(tip_height)?;
        self.set_latest_block_index(tip_height)
    }

    /// Read the canonical tip hash + height.
    pub fn get_canonical_tip(&self) -> Result<Option<CanonicalTipView>, ErrorDetection> {
        let db = self.open_db_blockchain()?;
        let cf = db
            .cf_handle(GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column family '{}' not found",
                    GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME
                ),
            })?;

        let pinned = db
            .get_pinned_cf(cf, Self::CANONICAL_TIP_VIEW_KEY)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to get canonical tip view: {}", e),
            })?;

        match pinned {
            Some(bytes) => Ok(Some(CanonicalTipView::from_bytes(bytes.as_ref())?)),
            None => Ok(None),
        }
    }

    /// Convenience: canonical tip hash only.
    pub fn get_canonical_tip_hash(&self) -> Result<Option<Hash>, ErrorDetection> {
        Ok(self.get_canonical_tip()?.map(|v| v.tip_hash))
    }

    /// Convenience: canonical tip height only.
    pub fn get_canonical_tip_height(&self) -> Result<Option<u64>, ErrorDetection> {
        Ok(self.get_canonical_tip()?.map(|v| v.tip_height))
    }

    // ─────────────────────────────────────────────────────────────────
    // 24) COMBINED INGEST HELPERS
    // ─────────────────────────────────────────────────────────────────

    /// Store a fully-known validated fork-graph node:
    pub fn ingest_fork_block(
        &self,
        block_hash: &Hash,
        block_bytes: &[u8],
        meta: &ForkBlockMeta,
        maybe_batch_bytes: Option<&[u8]>,
    ) -> Result<(), ErrorDetection> {
        self.index_block_by_hash(block_hash, block_bytes)?;
        self.store_block_meta_by_hash(block_hash, meta)?;

        if let Some(batch_bytes) = maybe_batch_bytes {
            self.store_batch_by_block_hash(block_hash, batch_bytes)?;
        }

        Ok(())
    }

    /// Mark a block as canonical in the fork graph and in the canonical view.
    pub fn promote_block_to_canonical(
        &self,
        height: u64,
        block_hash: &Hash,
    ) -> Result<(), ErrorDetection> {
        self.set_canonical_hash_at_height(height, block_hash)?;
        self.set_block_meta_status(block_hash, ForkBlockStatus::Canonical)?;
        self.set_canonical_tip(block_hash, height)
    }

    // ─────────────────────────────────────────────────────────────────
    // 25) REORG WALK HELPERS
    // ─────────────────────────────────────────────────────────────────

    /// Walk backward by metadata parent hashes until genesis or missing metadata.
    pub fn build_hash_ancestry_path(
        &self,
        start_hash: &Hash,
        max_depth: usize,
    ) -> Result<Vec<Hash>, ErrorDetection> {
        let mut out = Vec::new();
        let mut current = *start_hash;

        for _ in 0..max_depth {
            out.push(current);

            let meta = match self.get_block_meta_by_hash(&current)? {
                Some(m) => m,
                None => break,
            };

            // Stop when parent is all-zero genesis prev style.
            if meta.parent_hash.iter().all(|b| *b == 0) {
                break;
            }

            current = meta.parent_hash;
        }

        Ok(out)
    }

    /// Find common ancestor hash by walking metadata-backed ancestry paths.
    pub fn find_common_ancestor_hash(
        &self,
        a_tip: &Hash,
        b_tip: &Hash,
        max_depth: usize,
    ) -> Result<Option<Hash>, ErrorDetection> {
        let a_path = self.build_hash_ancestry_path(a_tip, max_depth)?;
        let b_path = self.build_hash_ancestry_path(b_tip, max_depth)?;

        for a in &a_path {
            if b_path.iter().any(|b| b == a) {
                return Ok(Some(*a));
            }
        }

        Ok(None)
    }
}
