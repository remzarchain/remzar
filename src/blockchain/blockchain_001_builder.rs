//! blockchain_001_builder.rs

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use crate::blockchain::blockchain_000_consensus::BlockchainConsensus;
use crate::blockchain::halving_schedule::RewardHalving;
use crate::blockchain::mempool::MemPool;
use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
use crate::blockchain::transaction_003_tx_reward::RewardTx;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::blockchain::validation::BlockchainValidation;
use crate::blockchain::validatorstate::ValidatorState;
use crate::consensus::por_000_ephemeral_registration::RegistryData;
use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
use crate::consensus::por_005_time_management::TimeManager;
use crate::cryptography::ml_dsa_65_004_guardian_signature::GuardianSignature;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::alpha_003_detection_system::DetectionSystem;
use crate::utility::time_policy::TimePolicy;

use chrono::DateTime;
use fips204::ml_dsa_65;
use postcard::to_allocvec;
use std::sync::Arc;

type SigningKey = ml_dsa_65::PrivateKey;

/// Entry-point builder that calls `BlockchainConsensus` and then assembles.
pub struct BlockchainBuilder {
    db_manager: Arc<RockDBManager>,
    mempool: Arc<MemPool>,
    consensus: BlockchainConsensus,
    detection: DetectionSystem,
    signing_key: Arc<SigningKey>,
}

impl BlockchainBuilder {
    #[must_use = "BlockchainBuilder::new returns a builder instance that should be retained by the orchestration layer"]
    pub fn new(
        db_manager: Arc<RockDBManager>,
        mempool: Arc<MemPool>,
        local_wallet: String,
        tm: Arc<TimeManager>,
        signing_key: Arc<SigningKey>,
    ) -> Result<Self, ErrorDetection> {
        let consensus = BlockchainConsensus::new(db_manager.clone(), local_wallet, tm)?;

        let mut detection = DetectionSystem::new();
        _ = detection.add_participant(consensus.local_wallet());

        Ok(Self {
            db_manager,
            mempool,
            consensus,
            detection,
            signing_key,
        })
    }

    pub fn consensus(&self) -> &BlockchainConsensus {
        &self.consensus
    }

    pub fn consensus_mut(&mut self) -> &mut BlockchainConsensus {
        &mut self.consensus
    }

    /// Immutable access to the canonical validator registry (for diagnostics / tooling).
    pub fn validator_state(&self) -> &ValidatorState {
        self.consensus.validator_state()
    }

    /// Mutable access so the orchestration loop can apply committed blocks.
    pub fn validator_state_mut(&mut self) -> &mut ValidatorState {
        self.consensus.validator_state_mut()
    }

    /// Refresh the in-memory runtime registry snapshot (called by orchestration each tick).
    pub fn set_registry(&mut self, reg: RegistryData) {
        self.consensus.set_registry(reg);
    }

    /// Peek at the most recent POR puzzle proof, if any.
    pub fn pending_puzzle_proof(&self) -> Option<&PorPuzzleProof> {
        self.consensus.pending_puzzle_proof()
    }

    /// Take and clear the most recent POR puzzle proof (for gossip).
    pub fn take_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> {
        self.consensus.take_pending_puzzle_proof()
    }

    /// Handle an incoming gossiped POR puzzle proof.
    pub fn on_puzzle_proof(&mut self, proof: &PorPuzzleProof) -> bool {
        self.consensus.on_puzzle_proof(proof)
    }

    /// Liveness heartbeat for the local validator instance.
    pub fn heartbeat(&mut self) {
        _ = self
            .detection
            .update_participant_activity(self.consensus.local_wallet());
    }

    /// Builder-side guard against re-including canonical registrations in system txs.
    fn reject_canonical_reregistration_system_txs(
        &self,
        system_kinds: &[TxKind],
        next_index: u64,
    ) -> Result<(), ErrorDetection> {
        if next_index == 0 {
            return Ok(());
        }

        for kind in system_kinds {
            if let TxKind::RegisterNode(RegisterNodeTx { wallet_address, .. }) = kind {
                let wallet_str = std::str::from_utf8(wallet_address).map_err(|_| {
                    ErrorDetection::ValidationError {
                        message: "RegisterNodeTx wallet address is not valid UTF-8".into(),
                        tx_id: None,
                    }
                })?;

                let wallet_can = crate::utility::helper::canon_wallet_id_checked(wallet_str)
                    .map_err(|e| ErrorDetection::ValidationError {
                        message: format!(
                            "RegisterNodeTx wallet address is not canonical in builder guard: {e}"
                        ),
                        tx_id: None,
                    })?;

                let is_canonically_known = self
                    .consensus
                    .validator_state()
                    .is_canonically_known(&wallet_can)?;

                if is_canonically_known {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "refusing to build block at height {}: attempted to include duplicate canonical RegisterNodeTx for wallet {}",
                            next_index, wallet_can
                        ),
                        tx_id: None,
                    });
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn create_new_block(&mut self, is_synced: bool) -> Result<Block, ErrorDetection> {
        self.create_new_block_with_bypass(is_synced, false)
    }

    #[allow(clippy::too_many_lines)]
    pub fn create_new_block_with_bypass(
        &mut self,
        is_synced: bool,
        bypass_leader: bool,
    ) -> Result<Block, ErrorDetection> {
        if !is_synced {
            return Err(ErrorDetection::ValidationError {
                message: "attempted to mint before full sync".into(),
                tx_id: None,
            });
        }

        let current_tip = self.db_manager.get_tip_height()?;
        let next_index = current_tip.saturating_add(1);
        let prev_hash: [u8; 64] = self.db_manager.get_latest_block_hash()?;

        if next_index == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "builder computed invalid next_index=0".into(),
                tx_id: None,
            });
        }

        if next_index > 0 && prev_hash == [0u8; 64] {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "refusing to mint non-genesis block at height {} with zero prev_hash",
                    next_index
                ),
                tx_id: None,
            });
        }

        let batch_timestamp = TimePolicy::now_unix_secs_runtime()?;

        tracing::debug!(
            "{} [BUILDER] preflight current_tip={} next_index={} local_wallet_present={}",
            Self::runtime_log_timestamp(),
            current_tip,
            next_index,
            !self.consensus.local_wallet().is_empty()
        );

        // Canonical leader truth + local runtime mint suppression both flow through here.
        self.consensus
            .assert_can_build_block(next_index, prev_hash, bypass_leader)?;

        let proposer = self.consensus.local_wallet().clone();

        let entries = self.mempool.fetch_transactions_for_block()?;
        let (all_tx_keys, all_user_kinds): (Vec<Vec<u8>>, Vec<TxKind>) =
            entries.into_iter().unzip();

        let max_txs_per_block =
            Self::u64_to_usize(GlobalConfiguration::MAX_TXS_PER_BLOCK, "MAX_TXS_PER_BLOCK")?;

        if all_user_kinds.len() > max_txs_per_block {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "block exceeds max-txs: {} > {}",
                    all_user_kinds.len(),
                    GlobalConfiguration::MAX_TXS_PER_BLOCK
                ),
                tx_id: None,
            });
        }

        let mut kept_user_pairs: Vec<(Vec<u8>, TxKind)> =
            all_tx_keys.into_iter().zip(all_user_kinds).collect();

        let delay = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
        let reward_tot = if next_index < delay {
            0
        } else {
            RewardHalving::get_block_reward(next_index)
        };

        let mut system_kinds: Vec<TxKind> = Vec::new();
        let mut block_reward: u64 = 0;

        if reward_tot > 0 {
            let eligible_for_reward = self.consensus.reward_eligible_at(&proposer, next_index);

            if eligible_for_reward {
                system_kinds.push(TxKind::Reward(RewardTx::new(
                    proposer.clone(),
                    reward_tot,
                    next_index,
                )?));
                block_reward = reward_tot;
            } else {
                tracing::debug!(
                    "{} [MINT][REWARD] proposer {} is not yet reward-eligible at height {}; skipping RewardTx (join_height/delay gate).",
                    Self::runtime_log_timestamp(),
                    proposer,
                    next_index
                );
            }
        }

        for reg in self
            .consensus
            .collect_register_node_txs_for_block(next_index)
        {
            system_kinds.push(TxKind::RegisterNode(reg));
        }

        self.reject_canonical_reregistration_system_txs(&system_kinds, next_index)?;

        let max_block_size =
            Self::u64_to_usize(GlobalConfiguration::MAX_BLOCK_SIZE, "MAX_BLOCK_SIZE")?;

        let tx_budget = max_block_size.saturating_sub(GlobalConfiguration::BLOCK_OVERHEAD_RESERVE);

        let txkind_len = |k: &TxKind| -> Result<usize, ErrorDetection> {
            to_allocvec(k)
                .map(|b| b.len())
                .map_err(|e| ErrorDetection::SerializationError {
                    details: format!("TxKind serialize failed: {e}"),
                })
        };

        let mut used: usize = 0;
        for k in &system_kinds {
            used = used.saturating_add(txkind_len(k)?);
        }

        let remaining = tx_budget.saturating_sub(used);

        let mut user_sizes: Vec<usize> = Vec::with_capacity(kept_user_pairs.len());
        for (_k, v) in &kept_user_pairs {
            user_sizes.push(txkind_len(v)?);
        }

        let mut user_total: usize = 0;
        for sz in &user_sizes {
            user_total = user_total.saturating_add(*sz);
        }

        while user_total > remaining {
            let popped_pair = kept_user_pairs.pop();
            let popped_sz = user_sizes.pop();
            match (popped_pair, popped_sz) {
                (Some(_), Some(sz)) => {
                    user_total = user_total.saturating_sub(sz);
                }
                _ => {
                    break;
                }
            }
        }

        let batch_key = format!("tx_batch_{next_index:010}");

        let (block, final_block_bytes, final_batch_bytes, final_tx_keys_to_remove): (
            Block,
            Vec<u8>,
            Vec<u8>,
            Vec<Vec<u8>>,
        ) = loop {
            let user_kinds: Vec<TxKind> = kept_user_pairs.iter().map(|(_k, v)| v.clone()).collect();

            if user_kinds.len().saturating_add(system_kinds.len()) > max_txs_per_block {
                if kept_user_pairs.pop().is_some() {
                    continue;
                }
                return Err(ErrorDetection::ValidationError {
                    message: "cannot build a valid batch: system txs exceed MAX_TXS_PER_BLOCK"
                        .into(),
                    tx_id: None,
                });
            }

            {
                use std::collections::HashSet;
                let mut seen = HashSet::new();
                for kind in &user_kinds {
                    if let TxKind::Transfer(tx) = kind {
                        let id = tx.id()?;
                        if !seen.insert(id) {
                            return Err(ErrorDetection::ValidationError {
                                message: "duplicate transaction detected".into(),
                                tx_id: None,
                            });
                        }
                    }
                }
            }

            let mut ids: Vec<String> = Vec::new();
            for kind in &user_kinds {
                if let TxKind::Transfer(tx) = kind {
                    ids.push(tx.id()?);
                }
            }
            self.detection.detect_double_spend(ids)?;

            let mut id_sig_pairs = Vec::new();
            for kind in &user_kinds {
                if let TxKind::Transfer(tx) = kind {
                    id_sig_pairs.push((tx.id()?, Vec::<u8>::new()));
                }
            }
            self.detection.detect_replay(id_sig_pairs)?;

            let mut tx_kinds: Vec<TxKind> = Vec::new();
            tx_kinds.extend(system_kinds.clone());
            tx_kinds.extend(user_kinds);

            let mut batch = TransactionBatch::new(next_index, batch_timestamp, tx_kinds)?;
            let mut meta = BlockchainValidation::validate_transaction_batch(
                &mut batch,
                self.signing_key.as_ref(),
                prev_hash,
                &self.detection,
            )?;

            if batch.index != next_index {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "batch index invariant failed: batch.index={} expected={}",
                        batch.index, next_index
                    ),
                    tx_id: None,
                });
            }

            if let Some(gossip_proof) = self.consensus.pending_puzzle_proof() {
                let block_proof = BlockPuzzleProof::from_gossip(gossip_proof)?;
                block_proof.validate_structural()?;

                if block_proof.height != next_index {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "staged puzzle proof height mismatch: proof.height={} expected_block_height={}",
                            block_proof.height, next_index
                        ),
                        tx_id: None,
                    });
                }

                if block_proof.prev_block_hash != prev_hash {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "staged puzzle proof prev_hash mismatch for h={}",
                            next_index
                        ),
                        tx_id: None,
                    });
                }

                if !block_proof.validator.eq_ignore_ascii_case(&proposer) {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "staged puzzle proof validator does not match local proposer at h={}",
                            next_index
                        ),
                        tx_id: None,
                    });
                }

                let validator_local = block_proof.validator.eq_ignore_ascii_case(&proposer);
                let height_match = block_proof.height == next_index;
                let prev_match = block_proof.prev_block_hash == prev_hash;

                tracing::debug!(
                    "{} [POR][BLOCK] proof_attached=true block_h={} proof_h={} validator_local={} height_match={} prev_match={}",
                    Self::runtime_log_timestamp(),
                    next_index,
                    block_proof.height,
                    validator_local,
                    height_match,
                    prev_match,
                );

                meta.set_puzzle_proof(Some(block_proof));
            } else {
                meta.set_puzzle_proof(None);
            }

            let slices: Vec<Vec<u8>> = batch
                .transactions
                .iter()
                .map(|k| {
                    to_allocvec(k).map_err(|e| ErrorDetection::SerializationError {
                        details: format!("TxKind serialize failed: {e}"),
                    })
                })
                .collect::<Result<_, _>>()?;
            let slice_refs: Vec<&[u8]> = slices.iter().map(Vec::as_slice).collect();

            let sig_vec = GuardianSignature::sign_batch(self.signing_key.as_ref(), &slice_refs)?;
            if sig_vec.len() != ml_dsa_65::SIG_LEN {
                return Err(ErrorDetection::CryptographicError {
                    message: format!(
                        "guardian signature length {} != expected {}",
                        sig_vec.len(),
                        ml_dsa_65::SIG_LEN
                    ),
                });
            }
            let mut sig = [0u8; ml_dsa_65::SIG_LEN];
            sig.copy_from_slice(&sig_vec[..]);
            meta.set_guardian_signature(sig);

            let block = Block::new(
                meta,
                Some(batch_key.clone()),
                proposer.clone(),
                block_reward,
            )?;
            let block_bytes = block.serialize_for_storage()?;
            let batch_bytes = batch.serialize()?;

            let total_bytes = block_bytes.len().saturating_add(batch_bytes.len());

            if total_bytes <= max_block_size {
                self.detection.check_block_size(total_bytes)?;
                _ = self.detection.update_participant_activity(&proposer);

                let tx_keys_to_remove: Vec<Vec<u8>> =
                    kept_user_pairs.iter().map(|(k, _)| k.clone()).collect();

                tracing::debug!(
                    "{} [BUILDER] finalized candidate h={} proposer_local={} user_txs={} system_txs={} batch_key={} total_bytes={}",
                    Self::runtime_log_timestamp(),
                    next_index,
                    !proposer.is_empty(),
                    kept_user_pairs.len(),
                    system_kinds.len(),
                    batch_key,
                    total_bytes
                );

                break (block, block_bytes, batch_bytes, tx_keys_to_remove);
            }

            if kept_user_pairs.pop().is_some() {
                continue;
            }

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Block+Batch exceeds MAX_BLOCK_SIZE even with zero user txs: block_bytes={} batch_bytes={} total={} > {} (h={})",
                    block_bytes.len(),
                    batch_bytes.len(),
                    total_bytes,
                    max_block_size,
                    next_index
                ),
                tx_id: None,
            });
        };

        // Final concurrent-parent guard before persistence.
        let tip_check = self.db_manager.get_tip_height()?;
        if tip_check != current_tip {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "parent tip advanced concurrently ({} -> {}), aborting mint",
                    current_tip, tip_check
                ),
                tx_id: None,
            });
        }

        let latest_hash_check = self.db_manager.get_latest_block_hash()?;
        if latest_hash_check != prev_hash {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "parent hash changed concurrently while building h={} (captured={} current={})",
                    next_index,
                    hex::encode(prev_hash),
                    hex::encode(latest_hash_check),
                ),
                tx_id: None,
            });
        }

        self.store_new_block(&final_block_bytes, next_index, &block.block_hash)?;

        self.db_manager.write(
            GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
            batch_key.as_bytes(),
            &final_batch_bytes,
        )?;

        self.db_manager.set_latest_block_index(next_index)?;
        self.db_manager.set_tip_height(next_index)?;

        self.consensus
            .gc_puzzle_pool_below(next_index.saturating_sub(16));

        self.mempool.remove_transactions(&final_tx_keys_to_remove)?;

        tracing::debug!(
            "{} [BUILDER] committed block h={} batch_key={} removed_mempool_txs={}",
            Self::runtime_log_timestamp(),
            next_index,
            batch_key,
            final_tx_keys_to_remove.len()
        );

        Ok(block)
    }

    fn store_new_block(
        &self,
        block_bytes: &[u8],
        index: u64,
        block_hash: &[u8; 64],
    ) -> Result<(), ErrorDetection> {
        if self.db_manager.get_block_bytes_by_index(index)?.is_some() {
            return Err(ErrorDetection::ValidationError {
                message: format!("block #{} already exists – refusing to overwrite", index),
                tx_id: None,
            });
        }

        if self.db_manager.get_block_by_hash(block_hash).is_some() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "block hash already exists for height {} – refusing duplicate persist",
                    index
                ),
                tx_id: None,
            });
        }

        self.db_manager.store_latest_block(block_bytes, index)?;
        self.db_manager
            .index_block_by_hash(block_hash, block_bytes)?;
        Ok(())
    }

    /// Runtime-only UTC timestamp for builder logs.
    fn runtime_log_timestamp() -> String {
        match TimePolicy::now_unix_secs_runtime() {
            Ok(now_unix) => {
                let Some(now_i64) = i64::try_from(now_unix).ok() else {
                    return format!("unix:{now_unix}");
                };

                DateTime::from_timestamp(now_i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| format!("unix:{now_unix}"))
            }
            Err(_) => "time_unavailable".to_string(),
        }
    }

    /// Convert u64 -> usize with a consensus-safe error if it doesn't fit.
    fn u64_to_usize(v: u64, what: &str) -> Result<usize, ErrorDetection> {
        usize::try_from(v).map_err(|_| ErrorDetection::ValidationError {
            message: format!("{what} does not fit in usize: {v}"),
            tx_id: None,
        })
    }
}
