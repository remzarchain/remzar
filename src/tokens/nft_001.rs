// src/tokens/nft_001.rs

use std::sync::Arc;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

const NFT_META_PREFIX: &str = "nft::";

fn nft_meta_key(nft_id: &Hash) -> String {
    format!("{}{}", NFT_META_PREFIX, hex::encode(nft_id))
}

/// On-chain NFT record stored in RocksDB metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftRecord {
    /// Unique id / serial for this NFT (you choose how to generate it).
    #[serde(with = "crate::utility::helper::serde_u8_array_64")]
    pub nft_id: Hash,

    /// Who originally minted it.
    pub creator_wallet: String,

    /// Who currently owns it.
    pub owner_wallet: String,

    /// Hash of the content (image or metadata JSON).
    /// 64-byte BLAKE3 XOF digest (first 64 bytes).
    #[serde(with = "crate::utility::helper::serde_u8_array_64")]
    pub content_hash: Hash,

    /// Short human title, ex: "Golden Dog #1".
    pub title: String,

    /// Optional text, can be empty or short description.
    pub description: String,

    /// Block height where it was first minted.
    pub minted_height: u64,

    /// Block timestamp when it was minted (ms since epoch).
    pub minted_time: u64,
}

/// Transaction payload to mint a new NFT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NftMintTx {
    /// Unique id for this NFT (should not collide with existing ones).
    #[serde(with = "crate::utility::helper::serde_u8_array_64")]
    pub nft_id: Hash,

    /// Hash of the content (image bytes or metadata file).
    #[serde(with = "crate::utility::helper::serde_u8_array_64")]
    pub content_hash: Hash,

    /// Human readable title.
    pub title: String,

    /// Optional description (can be empty).
    pub description: String,
}

impl NftMintTx {
    /// Convenience helper to build a `NftMintTx` from a content blob.
    pub fn from_content_bytes(
        nft_id: Hash,
        title: String,
        description: String,
        content_bytes: &[u8],
    ) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(content_bytes);

        // 64-byte hash via BLAKE3 XOF (keeps "blake3-only" requirement)
        let mut hash_bytes: Hash = [0u8; 64];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut hash_bytes);

        NftMintTx {
            nft_id,
            content_hash: hash_bytes,
            title,
            description,
        }
    }
}

/// Transaction payload to transfer ownership of an existing NFT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NftTransferTx {
    /// ID of the NFT being transferred.
    #[serde(with = "crate::utility::helper::serde_u8_array_64")]
    pub nft_id: Hash,

    /// New owner wallet address (p+64-hex format enforced by CLI).
    pub new_owner_wallet: String,
}

/* ───────────────────── DB helpers ───────────────────── */

/// Store an NftRecord into RocksDB metadata.
/// Key: "nft::<nft_id_hex>"
pub fn store_nft_record(
    blockchain_db: &Arc<RockDBManager>,
    record: &NftRecord,
) -> Result<(), ErrorDetection> {
    let key = nft_meta_key(&record.nft_id);

    let bytes = serde_json::to_vec(record).map_err(|e| ErrorDetection::SerializationError {
        details: format!("failed to serialize NftRecord as JSON: {e}"),
    })?;

    blockchain_db
        .store_metadata(&key, &bytes)
        .map_err(|e| ErrorDetection::StorageError {
            message: format!("store_metadata({key}) failed for NftRecord: {e}"),
        })
}

/// Load an NftRecord by its id.
pub fn load_nft_record(
    blockchain_db: &Arc<RockDBManager>,
    nft_id: &Hash,
) -> Result<Option<NftRecord>, ErrorDetection> {
    let key = nft_meta_key(nft_id);

    let maybe_bytes =
        blockchain_db
            .get_metadata(&key)
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("get_metadata({key}) failed for NftRecord: {e}"),
            })?;

    let Some(bytes) = maybe_bytes else {
        return Ok(None);
    };

    let record: NftRecord =
        serde_json::from_slice(&bytes).map_err(|e| ErrorDetection::SerializationError {
            details: format!("failed to deserialize NftRecord JSON: {e}"),
        })?;

    Ok(Some(record))
}

/* ───────────────────── apply logic ───────────────────── */

pub fn apply_nft_mint(
    blockchain_db: &Arc<RockDBManager>,
    tx: &NftMintTx,
    signer_wallet: &str,
    block_height: u64,
    block_timestamp: u64,
) -> Result<(), ErrorDetection> {
    if load_nft_record(blockchain_db, &tx.nft_id)?.is_some() {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "NFT id already exists (duplicate mint): {}",
                hex::encode(tx.nft_id)
            ),
            tx_id: None,
        });
    }

    let record = NftRecord {
        nft_id: tx.nft_id,
        creator_wallet: signer_wallet.to_string(),
        owner_wallet: signer_wallet.to_string(),
        content_hash: tx.content_hash,
        title: tx.title.clone(),
        description: tx.description.clone(),
        minted_height: block_height,
        minted_time: block_timestamp,
    };

    store_nft_record(blockchain_db, &record)
}

pub fn apply_nft_transfer(
    blockchain_db: &Arc<RockDBManager>,
    tx: &NftTransferTx,
    signer_wallet: &str,
    block_height: u64,
    block_timestamp: u64,
) -> Result<(), ErrorDetection> {
    let _ = (block_height, block_timestamp);

    let maybe_record = load_nft_record(blockchain_db, &tx.nft_id)?;
    let mut record = match maybe_record {
        Some(r) => r,
        None => {
            return Err(ErrorDetection::ValidationError {
                message: format!("NFT id not found for transfer: {}", hex::encode(tx.nft_id)),
                tx_id: None,
            });
        }
    };

    if record.owner_wallet == tx.new_owner_wallet {
        return Ok(());
    }

    if record.owner_wallet != signer_wallet {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "NFT transfer denied: signer {} is not current owner {}",
                signer_wallet, record.owner_wallet
            ),
            tx_id: None,
        });
    }

    if tx.new_owner_wallet.trim().is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: "NFT transfer new_owner_wallet cannot be empty".into(),
            tx_id: None,
        });
    }

    record.owner_wallet = tx.new_owner_wallet.clone();

    store_nft_record(blockchain_db, &record)
}
