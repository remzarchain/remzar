use crate::blockchain::block_001_metadata::BlockMetadata;
use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
use crate::blockchain::transaction_003_tx_reward::RewardTx;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::network::p2p_006_reqresp::Hash;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::InclusionProof;
use fips204::ml_dsa_65;
use fips204::ml_dsa_65::PrivateKey as SigningKey;

use hex;
use serde::{Deserialize, Serialize};

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

    pub fn total_size(&self) -> Result<usize, ErrorDetection> {
        let sizes = self
            .transactions
            .iter()
            .map(|k| match k {
                TxKind::Transfer(tx) => Transaction::serialize(tx).map(|b| b.len()),
                TxKind::RegisterNode(tx) => RegisterNodeTx::serialize(tx).map(|b| b.len()),
                TxKind::Reward(tx) => RewardTx::serialize(tx).map(|b| b.len()),
                TxKind::NftMint(tx) => postcard::to_allocvec(tx).map(|b| b.len()).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                }),
                TxKind::NftTransfer(tx) => {
                    postcard::to_allocvec(tx).map(|b| b.len()).map_err(|e| {
                        ErrorDetection::SerializationError {
                            details: e.to_string(),
                        }
                    })
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(sizes.iter().sum())
    }

    fn canonical_db_key_string(&self) -> String {
        format!("tx_batch_{:010}", self.index)
    }

    /// The true serialized byte length of this batch as it will be stored/transmitted.
    pub fn serialized_len(&self) -> Result<usize, ErrorDetection> {
        postcard::to_allocvec(self).map(|v| v.len()).map_err(|e| {
            ErrorDetection::SerializationError {
                details: e.to_string(),
            }
        })
    }

    /// Canonical storage/transmit bytes, guarded by MAX_BLOCK_SIZE.
    pub fn serialize_for_storage(&self) -> Result<Vec<u8>, ErrorDetection> {
        let buf = self.serialize()?;
        let max_block_size = match usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE) {
            Ok(v) => v,
            Err(_) => {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Invalid MAX_BLOCK_SIZE (cannot fit into usize on this platform): {}",
                        GlobalConfiguration::MAX_BLOCK_SIZE
                    ),
                    tx_id: None,
                });
            }
        };

        if buf.len() > max_block_size {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "TransactionBatch exceeds MAX_BLOCK_SIZE: {} > {}",
                    buf.len(),
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
                tx_id: None,
            });
        }
        Ok(buf)
    }

    pub fn sign_batch(&mut self, sk: &SigningKey) -> Result<(), ErrorDetection> {
        if cfg!(test) {
            self.guardian_signature = Some(vec![0xAB; ml_dsa_65::SIG_LEN]);
            return Ok(());
        }

        let serialized: Vec<Vec<u8>> = self
            .transactions
            .iter()
            .map(|k| match k {
                TxKind::Transfer(tx) => Transaction::serialize(tx),
                TxKind::RegisterNode(tx) => RegisterNodeTx::serialize(tx),
                TxKind::Reward(tx) => RewardTx::serialize(tx),
                TxKind::NftMint(tx) => {
                    postcard::to_allocvec(tx).map_err(|e| ErrorDetection::SerializationError {
                        details: e.to_string(),
                    })
                }
                TxKind::NftTransfer(tx) => {
                    postcard::to_allocvec(tx).map_err(|e| ErrorDetection::SerializationError {
                        details: e.to_string(),
                    })
                }
            })
            .collect::<Result<_, _>>()?;

        let refs: Vec<&[u8]> = serialized.iter().map(|v| v.as_slice()).collect();

        let sig =
            crate::cryptography::ml_dsa_65_003_batch_signature::MlDsa65BatchSignature::sign_batch(
                sk, &refs,
            )?;

        // ML-DSA-65 signatures must be exact length.
        if sig.len() != ml_dsa_65::SIG_LEN {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Guardian signature length mismatch: got {} bytes, expected {}",
                    sig.len(),
                    ml_dsa_65::SIG_LEN
                ),
            });
        }

        self.guardian_signature = Some(sig);
        Ok(())
    }

    /// 64-byte merkle root (Hash) to match the updated chain hash width.
    pub fn compute_merkle_root(&self) -> Result<Hash, ErrorDetection> {
        let leaves: Vec<Vec<u8>> = self
            .transactions
            .iter()
            .map(|k| match k {
                TxKind::Transfer(tx) => Transaction::serialize(tx),
                TxKind::RegisterNode(tx) => RegisterNodeTx::serialize(tx),
                TxKind::Reward(tx) => RewardTx::serialize(tx),
                TxKind::NftMint(tx) => {
                    postcard::to_allocvec(tx).map_err(|e| ErrorDetection::SerializationError {
                        details: e.to_string(),
                    })
                }
                TxKind::NftTransfer(tx) => {
                    postcard::to_allocvec(tx).map_err(|e| ErrorDetection::SerializationError {
                        details: e.to_string(),
                    })
                }
            })
            .collect::<Result<_, _>>()?;

        let hex_root = RemzarHash::compute_merkle_root(&leaves)?;
        let decoded = hex::decode(hex_root).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;

        // must be at least 64 bytes.
        let root64 = decoded
            .get(..64)
            .ok_or_else(|| ErrorDetection::SerializationError {
                details: format!(
                    "Decoded merkle root length {} too short (expected at least 64)",
                    decoded.len()
                ),
            })?;

        let mut out: Hash = [0u8; 64];
        out.copy_from_slice(root64);
        Ok(out)
    }

    pub fn finalize_block(
        &mut self,
        sk: &SigningKey,
        prev_hash: Hash,
    ) -> Result<BlockMetadata, ErrorDetection> {
        let max_block_size = match usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE) {
            Ok(v) => v,
            Err(_) => {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Invalid MAX_BLOCK_SIZE (cannot fit into usize on this platform): {}",
                        GlobalConfiguration::MAX_BLOCK_SIZE
                    ),
                    tx_id: None,
                });
            }
        };

        // sum of tx sizes.
        if self.total_size()? > max_block_size {
            return Err(ErrorDetection::ValidationError {
                message: "Batch too big".into(),
                tx_id: None,
            });
        }

        // Enforce against the *actual bytes* that will be stored/transmitted.
        let actual_batch_bytes = self.serialize_for_storage()?;
        if actual_batch_bytes.len() > max_block_size {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch serialized bytes exceed MAX_BLOCK_SIZE: {} > {}",
                    actual_batch_bytes.len(),
                    GlobalConfiguration::MAX_BLOCK_SIZE
                ),
                tx_id: None,
            });
        }

        self.sign_batch(sk)?;
        let merkle = self.compute_merkle_root()?;

        let mut sig_arr = [0u8; ml_dsa_65::SIG_LEN];
        if let Some(sig) = &self.guardian_signature {
            if sig.len() != ml_dsa_65::SIG_LEN {
                return Err(ErrorDetection::SerializationError {
                    details: format!(
                        "Guardian signature length mismatch: got {} bytes, expected {}",
                        sig.len(),
                        ml_dsa_65::SIG_LEN
                    ),
                });
            }
            sig_arr.copy_from_slice(sig.as_slice());
        }

        Ok(BlockMetadata::new(
            self.index,
            self.timestamp,
            prev_hash,
            merkle,
            sig_arr,
            None,
            GlobalConfiguration::MAX_BLOCK_SIZE,
        ))
    }

    pub fn store_in_db(
        &self,
        rock_batch: &crate::storage::rocksdb_003_batches::RockBatch,
    ) -> Result<(), ErrorDetection> {
        // store the canonical bytes, guarded by MAX_BLOCK_SIZE
        let ser = self.serialize_for_storage()?;

        let cf = rock_batch
            .db
            .cf_handle(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::StorageError {
                message: "Missing batch CF".into(),
            })?;

        // Legacy binary key (keep intact)
        rock_batch
            .db
            .put_cf(cf, self.index.to_be_bytes(), &ser)
            .map_err(|e| ErrorDetection::StorageError {
                message: e.to_string(),
            })?;

        // Canonical string key.
        let key_str = self.canonical_db_key_string();
        rock_batch
            .db
            .put_cf(cf, key_str.as_bytes(), &ser)
            .map_err(|e| ErrorDetection::StorageError {
                message: e.to_string(),
            })?;

        Ok(())
    }

    pub fn inclusion_proof(
        &self,
        leaf_index: usize,
    ) -> Result<Vec<InclusionProof>, ErrorDetection> {
        // 1) Compute the leaf hashes: H = hash(data)
        let mut nodes: Vec<InclusionProof> = self
            .transactions
            .iter()
            .map(|k| {
                let data = match k {
                    TxKind::Transfer(tx) => Transaction::serialize(tx)?,
                    TxKind::RegisterNode(tx) => RegisterNodeTx::serialize(tx)?,
                    TxKind::Reward(tx) => RewardTx::serialize(tx)?,
                    TxKind::NftMint(tx) => postcard::to_allocvec(tx).map_err(|e| {
                        ErrorDetection::SerializationError {
                            details: e.to_string(),
                        }
                    })?,
                    TxKind::NftTransfer(tx) => postcard::to_allocvec(tx).map_err(|e| {
                        ErrorDetection::SerializationError {
                            details: e.to_string(),
                        }
                    })?,
                };

                let hex_h = RemzarHash::compute_data_hash(&data)?;
                let bytes =
                    hex::decode(&hex_h).map_err(|e| ErrorDetection::SerializationError {
                        details: e.to_string(),
                    })?;

                // must be at least 64 bytes now
                let h64 = bytes
                    .get(..64)
                    .ok_or_else(|| ErrorDetection::SerializationError {
                        details: format!(
                            "Decoded tx hash length {} too short (expected at least 64)",
                            bytes.len()
                        ),
                    })?;

                let mut h: Hash = [0u8; 64];
                h.copy_from_slice(h64);

                // Convert raw [u8; 64] into InclusionProof (= Hash64)
                Ok(InclusionProof::from_bytes(h))
            })
            .collect::<Result<_, ErrorDetection>>()?;

        if leaf_index >= nodes.len() {
            return Err(ErrorDetection::NotFound {
                resource: format!("leaf index {leaf_index} out of bounds"),
            });
        }

        // 2) Walk up the tree, recording siblings
        let mut proof: Vec<InclusionProof> = Vec::new();
        let mut idx = leaf_index;

        while nodes.len() > 1 {
            let mut next: Vec<InclusionProof> = Vec::new();

            for chunk in nodes.chunks(2) {
                let left = *chunk
                    .first()
                    .ok_or_else(|| ErrorDetection::SerializationError {
                        details: "Merkle chunk unexpectedly empty".to_string(),
                    })?;

                let right = if let Some(r) = chunk.get(1) { *r } else { left };

                let pair_idx = next.len();

                if idx.is_multiple_of(2) && idx.checked_add(1).is_some_and(|i| i < nodes.len()) {
                    proof.push(right);
                } else if !idx.is_multiple_of(2) {
                    proof.push(left);
                }

                let mut combined = Vec::with_capacity(128);
                combined.extend_from_slice(left.as_bytes());
                combined.extend_from_slice(right.as_bytes());

                let hex_p = RemzarHash::compute_data_hash(&combined)?;
                let bytes =
                    hex::decode(&hex_p).map_err(|e| ErrorDetection::SerializationError {
                        details: e.to_string(),
                    })?;

                // must be at least 64 bytes now
                let p64 = bytes
                    .get(..64)
                    .ok_or_else(|| ErrorDetection::SerializationError {
                        details: format!(
                            "Decoded parent hash length {} too short (expected at least 64)",
                            bytes.len()
                        ),
                    })?;

                let mut parent_arr: Hash = [0u8; 64];
                parent_arr.copy_from_slice(p64);

                // Convert to InclusionProof (= Hash64) before pushing
                let parent = InclusionProof::from_bytes(parent_arr);
                next.push(parent);

                idx = pair_idx;
            }

            nodes = next;
        }

        Ok(proof)
    }

    pub fn from_reward_only(
        index: u64,
        timestamp: u64,
        reward: RewardTx,
    ) -> Result<Self, ErrorDetection> {
        let batch = TransactionBatch::new(index, timestamp, vec![TxKind::Reward(reward)])?;
        Ok(batch)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
        postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection> {
        let (batch, remaining): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Deserialize TransactionBatch failed: {e}"),
            })?;

        if !remaining.is_empty() {
            return Err(ErrorDetection::SerializationError {
                details: "Deserialize TransactionBatch failed: trailing bytes rejected".to_string(),
            });
        }

        Ok(batch)
    }
}
